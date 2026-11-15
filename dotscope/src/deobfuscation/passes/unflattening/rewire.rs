//! Rewiring dispatcher edges, and repairing the values the rewiring disturbs.
//!
//! # What a rewire disturbs
//!
//! A rewire replaces the path `from -> old ... -> dispatcher -> ... -> exit ->
//! new` with one edge `from -> new`. Every path of the rewired graph is a path
//! of the original with the bypassed blocks taken back out, so a block that
//! dominated another still does unless it is one of the bypassed blocks. The
//! values the rewiring can cut off from their reads are therefore exactly the
//! values the bypassed blocks define: the dispatcher's phis, which carry every
//! value the cases pass each other, and whatever the chain and the dispatch
//! machinery compute. Nothing else needs reconstructing.
//!
//! # What the new edge carries
//!
//! The edge runs what the bypassed blocks ran on its behalf. Walking the old
//! path from `from`, each bypassed phi takes the operand its incoming edge
//! carried, and each instruction whose value is read past the bypass - with
//! what it reads in turn - is replayed at the end of the edge under a fresh
//! name. The dispatch machinery itself is read only inside the dispatch, and
//! is not replayed. Every bypassed value then has a definition on the edge: the
//! value the old path left it holding. A phi of `new` gets the operand the old
//! path's last block supplied, read the same way.
//!
//! Phis assign in parallel: the values a case hands the next one are all read
//! before any is written, which is what keeps `x, y = y, x` a swap. A value the
//! edge hands on that is itself one of the bypassed values is therefore read
//! by a copy at the end of the edge. A read there resolves to the definition
//! reaching the edge's entry, before the definition the edge states for its
//! end, which is exactly the parallel reading.
//!
//! A definition holds for every successor of the block that states it. When
//! `from` has other successors the edge gets a block of its own, so a
//! successor that keeps reading a bypassed value is not handed the value meant
//! for `new`.
//!
//! The values are then reconstructed together
//! ([`SsaFunction::reconstruct_values`]), inside the edit session that
//! rewires the edges. A value read past the bypassed blocks with no definition
//! on some path refuses the reconstruction, and the session restores the
//! function as it was: the method stays flattened rather than being left
//! wrong.
//!
//! [`SsaFunction::reconstruct_values`]: analyssa::ir::function::SsaFunction::reconstruct_values

use std::collections::{BTreeMap, BTreeSet};

use analyssa::{
    ir::function::{SsaEditOptions, SsaEditor, SsaRollbackPolicy, StorageSlots, ValueUpdate},
    BitSet,
};

use crate::{
    analysis::{
        CilTarget, DefSite, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId,
        VariableOrigin,
    },
    deobfuscation::passes::unflattening::resolve::{Rewire, MAX_CHAIN_LEN, MAX_OVERFLOW_CHAIN},
};

/// One rewire, planned against the function before any edit.
struct Plan {
    /// The edge being rewired.
    rewire: Rewire,
    /// Whether the edge needs a block of its own: `from` has other
    /// successors, which must not see what the edge defines.
    split: bool,
    /// What the edge runs, in order: the replayed instructions, then the
    /// copies of bypassed values it hands on.
    replay: Vec<SsaOp>,
    /// For each value the bypassed blocks define, what the edge leaves it
    /// holding; a value the old path passed through unchanged is absent.
    holds: BTreeMap<SsaVarId, SsaVarId>,
    /// The operand each phi of `rewire.new` takes on the edge, by phi index.
    operands: Vec<(usize, SsaVarId)>,
}

/// Rewires the resolved edges past the dispatcher and repairs the values the
/// rewiring disturbed, in one edit session.
///
/// An edge whose path cannot be replayed - a bypassed instruction with an
/// effect whose value is read past it, a phi with no operand for the edge
/// taken, a block of its own that would leave an exception region - keeps
/// routing through the dispatcher, which is correct, only still flattened.
///
/// # Arguments
///
/// * `ssa` - The function to rewire.
/// * `rewires` - The resolved edges.
/// * `dispatchers` - The dispatcher blocks, where a bypassed chain ends.
///
/// # Returns
///
/// The number of edges rewired.
///
/// # Errors
///
/// Returns an error, leaving `ssa` as it was, when a value read past the
/// bypassed blocks has no definition on some path of the rewired graph, or
/// when the rewired function fails verification.
pub fn apply_rewires(
    ssa: &mut SsaFunction,
    rewires: &[Rewire],
    dispatchers: &BTreeSet<usize>,
) -> analyssa::Result<usize> {
    let mut applied = 0usize;
    ssa.edit(
        SsaEditOptions::new()
            .with_verify(true)
            .with_rollback(SsaRollbackPolicy::OnFailure),
        |editor| {
            let before = editor.function().clone();
            let (plans, dead) = plan_rewires(editor, &before, rewires, dispatchers);
            if plans.is_empty() {
                return Ok(());
            }
            // The state the cases compute for the dispatcher goes nowhere once
            // the edges that carried it are gone; left in place, it would read
            // the dispatcher's values on paths that no longer pass it.
            for (block_idx, instr_idx) in dead {
                editor.nop_instruction(block_idx, instr_idx)?;
            }
            let mut updates: BTreeMap<SsaVarId, Vec<(usize, SsaVarId)>> = BTreeMap::new();
            for plan in &plans {
                let site = apply_plan(editor, plan)?;
                for (&value, &held) in &plan.holds {
                    updates.entry(value).or_default().push((site, held));
                }
            }
            applied = plans.len();

            // The phis the bypassed blocks keep still name the edges that left
            // them; those edges are gone.
            let blocks = editor.function().block_count();
            let _ = editor.prune_phi_operands(&BitSet::full(blocks));
            let updates: Vec<ValueUpdate> = updates
                .into_iter()
                .map(|(value, definitions)| ValueUpdate { value, definitions })
                .collect();
            editor.reconstruct_values(&updates)?;
            editor.declare_repaired();
            Ok(())
        },
    )?;
    Ok(applied)
}

/// Plans every rewire whose path can be replayed, and the instructions the
/// rewiring leaves dead.
///
/// Two plans must not edit one another's blocks: a rewire leaving from a block
/// another rewire bypasses is dropped, and keeps its dispatcher edge, and an
/// edge is rewired once. Which values an edge must define depends on which
/// edges are rewired, and an edge that cannot define them is dropped, so the
/// set is narrowed until every edge left can be replayed; only then are the
/// replays' fresh names created.
///
/// # Arguments
///
/// * `editor` - The session, for the fresh names a replay defines.
/// * `before` - The function as the session found it.
/// * `rewires` - The resolved edges.
/// * `dispatchers` - The dispatcher blocks.
///
/// # Returns
///
/// The plans, and the `(block, instruction)` sites the rewiring leaves dead.
fn plan_rewires(
    editor: &mut SsaEditor<'_, CilTarget>,
    before: &SsaFunction,
    rewires: &[Rewire],
    dispatchers: &BTreeSet<usize>,
) -> (Vec<Plan>, Vec<(usize, usize)>) {
    let routed: Vec<(Rewire, Vec<usize>)> = rewires
        .iter()
        .filter_map(|rewire| Some((*rewire, route(before, rewire, dispatchers)?)))
        .collect();
    let bypassed: BTreeSet<usize> = routed
        .iter()
        .flat_map(|(_, route)| route.iter().copied())
        .collect();
    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut accepted: Vec<(Rewire, Vec<usize>)> = routed
        .into_iter()
        .filter(|(rewire, route)| {
            !bypassed.contains(&rewire.from)
                && !route.contains(&rewire.new)
                && edges.insert((rewire.from, rewire.old))
        })
        .collect();

    loop {
        let bypass = Bypass::of(before, &accepted);
        let replayable: Vec<(Rewire, Vec<usize>)> = accepted
            .iter()
            .filter(|(rewire, route)| {
                replay(before, *rewire, route, &bypass, &mut |_| {
                    SsaVarId::PLACEHOLDER
                })
                .is_some()
            })
            .cloned()
            .collect();
        if replayable.len() == accepted.len() {
            if accepted.is_empty() {
                return (Vec::new(), Vec::new());
            }
            let mut fresh = |like: SsaVarId| fresh_like(editor, before, like);
            let plans = accepted
                .iter()
                .filter_map(|(rewire, route)| replay(before, *rewire, route, &bypass, &mut fresh))
                .collect();
            return (plans, bypass.dead);
        }
        accepted = replayable;
    }
}

/// What a set of rewires bypasses, and what the rest of the function still
/// reads once they are made.
struct Bypass {
    /// Every value a bypassed block defines.
    disturbed: BTreeSet<SsaVarId>,
    /// The bypassed values live code past the bypass reads: what each new
    /// edge must define.
    live_past: BTreeSet<SsaVarId>,
    /// The pure instructions outside the bypass nothing live reads once the
    /// edges are rewired: the state the cases compute for the dispatcher.
    dead: Vec<(usize, usize)>,
    /// The slots the function reads as storage, so that a definition of one
    /// is a write a later read through the slot sees, not a value only its SSA
    /// readers see.
    slots: StorageSlots,
}

/// Where a value is defined.
#[derive(Clone, Copy)]
enum Site {
    /// By the phi at `(block, phi)`.
    Phi(usize, usize),
    /// By the instruction at `(block, instruction)`.
    Instruction(usize, usize),
}

impl Bypass {
    /// Decides what `accepted` bypasses and what stays live.
    ///
    /// A value is live as the program goes on reading it with the edges
    /// rewired. Two readings differ for a bypassed value: past the bypass,
    /// where the new edge must define it, and inside it, where a dispatcher
    /// some edges still enter goes on computing it. The operand a rewired edge
    /// carried into a bypassed phi is read only if that phi is live past the
    /// bypass - it is what the new edge hands on - and an instruction outside
    /// the bypass with no effect, all of whose values go unread, is dead.
    ///
    /// # Arguments
    ///
    /// * `before` - The function as the session found it.
    /// * `accepted` - The rewires and the blocks each bypasses.
    fn of(before: &SsaFunction, accepted: &[(Rewire, Vec<usize>)]) -> Self {
        let bypassed: BTreeSet<usize> = accepted
            .iter()
            .flat_map(|(_, route)| route.iter().copied())
            .collect();
        // The edges the rewiring removes, as `(block entered, predecessor)`.
        let vanishing: BTreeSet<(usize, usize)> = accepted
            .iter()
            .filter_map(|(rewire, route)| Some((*route.first()?, rewire.from)))
            .collect();
        // The edges between bypassed blocks a replay walks, which stay for the
        // paths that still take them.
        let walked: BTreeSet<(usize, usize)> = accepted
            .iter()
            .flat_map(|(_, route)| {
                route.windows(2).filter_map(|pair| match pair {
                    &[from, to] => Some((to, from)),
                    _ => None,
                })
            })
            .collect();

        let mut sites: BTreeMap<SsaVarId, Site> = BTreeMap::new();
        for (block_idx, block) in before.blocks().iter().enumerate() {
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                sites.insert(phi.result(), Site::Phi(block_idx, phi_idx));
            }
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for def in instr.op().defs() {
                    sites.insert(def, Site::Instruction(block_idx, instr_idx));
                }
            }
        }
        let in_bypass = |site: Option<&Site>| {
            site.is_some_and(|site| match site {
                Site::Phi(block, _) | Site::Instruction(block, _) => bypassed.contains(block),
            })
        };
        let disturbed: BTreeSet<SsaVarId> = sites
            .iter()
            .filter(|(_, site)| in_bypass(Some(site)))
            .map(|(value, _)| *value)
            .collect();
        let slots = before.storage_slots();
        let writes_slot = |instr: &SsaInstruction| slots.written_by(before, instr.op());
        // An instruction outside the bypass that may be dead. One writing a
        // slot the function reads as storage is not, whatever its SSA readers.
        let candidate = |block_idx: usize, instr: &SsaInstruction| {
            !bypassed.contains(&block_idx)
                && !instr.is_terminator()
                && !matches!(instr.op(), SsaOp::Nop)
                && instr.is_pure()
                && !writes_slot(instr)
        };

        let mut liveness = Liveness::default();
        for (block_idx, block) in before.blocks().iter().enumerate() {
            let inside = bypassed.contains(&block_idx);
            if !inside {
                for phi in block.phi_nodes() {
                    for operand in phi.operands() {
                        liveness.read(operand.value(), false, &disturbed);
                    }
                }
            }
            for instr in block.instructions() {
                let machinery =
                    inside && instr.is_pure() && !instr.is_terminator() && !writes_slot(instr);
                if candidate(block_idx, instr) || machinery {
                    continue;
                }
                for used in instr.op().uses() {
                    liveness.read(used, inside, &disturbed);
                }
            }
        }

        let mut live_instructions: BTreeSet<(usize, usize)> = BTreeSet::new();
        while let Some((value, reading)) = liveness.pending.pop() {
            let Some(&site) = sites.get(&value) else {
                continue;
            };
            match (site, reading) {
                (Site::Instruction(block_idx, instr_idx), _) => {
                    let Some(instr) = before
                        .block(block_idx)
                        .and_then(|block| block.instruction(instr_idx))
                    else {
                        continue;
                    };
                    let inside = bypassed.contains(&block_idx);
                    if !inside {
                        live_instructions.insert((block_idx, instr_idx));
                    }
                    for used in instr.op().uses() {
                        // A bypassed instruction read past the bypass is
                        // replayed there, reading what it reads past it too;
                        // inside, it reads as the dispatcher runs it.
                        let past = !inside || reading == Reading::Past;
                        liveness.read(used, !past, &disturbed);
                        if inside && reading == Reading::Past {
                            liveness.read(used, true, &disturbed);
                        }
                    }
                }
                (Site::Phi(block_idx, phi_idx), _) => {
                    let Some(phi) = before
                        .block(block_idx)
                        .and_then(|block| block.phi_nodes().get(phi_idx))
                    else {
                        continue;
                    };
                    if !bypassed.contains(&block_idx) {
                        // Outside the bypass every operand was read already.
                        continue;
                    }
                    for operand in phi.operands() {
                        let edge = (block_idx, operand.predecessor());
                        let normal = !operand.is_exceptional();
                        let past = reading == Reading::Past;
                        if normal && vanishing.contains(&edge) {
                            // What the new edge hands on, read past the bypass.
                            if past {
                                liveness.read(operand.value(), false, &disturbed);
                            }
                            continue;
                        }
                        // A replay reads the operands its walk passes as it
                        // hands them on; the dispatch reads every edge it keeps.
                        if past && normal && walked.contains(&edge) {
                            liveness.read(operand.value(), false, &disturbed);
                        }
                        liveness.read(operand.value(), true, &disturbed);
                    }
                }
            }
        }

        let dead = before
            .blocks()
            .iter()
            .enumerate()
            .flat_map(|(block_idx, block)| {
                block
                    .instructions()
                    .iter()
                    .enumerate()
                    .filter(move |(_, instr)| candidate(block_idx, instr))
                    .map(move |(instr_idx, _)| (block_idx, instr_idx))
            })
            .filter(|site| !live_instructions.contains(site))
            .collect();
        Self {
            disturbed,
            live_past: liveness.past,
            dead,
            slots,
        }
    }
}

/// How a value is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// By the program past the bypass, or by an instruction outside it.
    Past,
    /// By the dispatch machinery an unrewired edge still runs.
    Inside,
}

/// The values found live so far, and those still to follow.
#[derive(Default)]
struct Liveness {
    /// Values outside the bypass, and bypassed values the dispatch still reads.
    live: BTreeSet<(SsaVarId, bool)>,
    /// Bypassed values read past the bypass.
    past: BTreeSet<SsaVarId>,
    /// Values marked and not yet followed, with how they were read.
    pending: Vec<(SsaVarId, Reading)>,
}

impl Liveness {
    /// Records that `value` is read, by a reader inside the bypass or not.
    ///
    /// # Arguments
    ///
    /// * `value` - The value read.
    /// * `inside` - Whether the reader is the dispatch machinery.
    /// * `disturbed` - The values the bypassed blocks define.
    fn read(&mut self, value: SsaVarId, inside: bool, disturbed: &BTreeSet<SsaVarId>) {
        if disturbed.contains(&value) && !inside {
            if self.past.insert(value) {
                self.pending.push((value, Reading::Past));
            }
            return;
        }
        let reading = if inside {
            Reading::Inside
        } else {
            Reading::Past
        };
        if self.live.insert((value, inside)) {
            self.pending.push((value, reading));
        }
    }
}

/// The blocks `rewire` bypasses, in the order the old path ran them: the chain
/// from `old` to the dispatcher, the dispatcher, and the overflow-check links
/// up to `exit`.
///
/// `None` when the path is not the one the rewire names: a chain block that
/// does not jump on, a link that is not one, or an exit with no edge to `new`.
///
/// # Arguments
///
/// * `ssa` - The function as the session found it.
/// * `rewire` - The edge being rewired.
/// * `dispatchers` - The dispatcher blocks.
fn route(ssa: &SsaFunction, rewire: &Rewire, dispatchers: &BTreeSet<usize>) -> Option<Vec<usize>> {
    let names_old = ssa
        .block(rewire.from)
        .and_then(SsaBlock::control_terminator)
        .is_some_and(|op| op.successors().contains(&rewire.old));
    if !names_old {
        return None;
    }

    let mut route = Vec::new();
    let mut current = rewire.old;
    while !dispatchers.contains(&current) {
        if route.len() >= MAX_CHAIN_LEN {
            return None;
        }
        let Some(SsaOp::Jump { target }) = ssa.block(current).and_then(SsaBlock::last_op) else {
            return None;
        };
        route.push(current);
        current = *target;
    }
    let dispatcher = current;
    route.push(dispatcher);

    if rewire.exit != dispatcher {
        let Some(SsaOp::Switch { default, .. }) =
            ssa.block(dispatcher).and_then(SsaBlock::control_terminator)
        else {
            return None;
        };
        let mut link = *default;
        let mut walked = 0usize;
        loop {
            if walked >= MAX_OVERFLOW_CHAIN || route.contains(&link) {
                return None;
            }
            walked = walked.saturating_add(1);
            route.push(link);
            if link == rewire.exit {
                break;
            }
            let Some(SsaOp::BranchCmp { false_target, .. }) =
                ssa.block(link).and_then(SsaBlock::control_terminator)
            else {
                return None;
            };
            link = *false_target;
        }
    }

    let exit_reaches_new = ssa
        .block(rewire.exit)
        .and_then(SsaBlock::control_terminator)
        .is_some_and(|op| op.successors().contains(&rewire.new));
    (route.last() == Some(&rewire.exit) && exit_reaches_new).then_some(route)
}

/// Replays `route` for `rewire`: what the edge runs, what it leaves each
/// bypassed value holding, and the operands it gives `rewire.new`'s phis.
///
/// `None` when the path cannot be replayed: a bypassed instruction with an
/// effect whose value is read past the bypass; a phi with no operand for the
/// edge taken; or an edge needing a block of its own where one would leave an
/// exception region.
///
/// # Arguments
///
/// * `before` - The function as the session found it.
/// * `rewire` - The edge being rewired.
/// * `route` - The blocks it bypasses ([`route`]).
/// * `bypass` - What every rewire bypasses, and what the rest reads.
/// * `fresh` - Names a fresh value shaped like the one it is given; a check
///   that only asks whether the path can be replayed names none.
fn replay(
    before: &SsaFunction,
    rewire: Rewire,
    route: &[usize],
    bypass: &Bypass,
    fresh: &mut dyn FnMut(SsaVarId) -> SsaVarId,
) -> Option<Plan> {
    let disturbed = &bypass.disturbed;
    let needed = &bypass.live_past;
    let successors = before
        .block(rewire.from)?
        .control_terminator()?
        .successors();
    let split = successors.iter().any(|&successor| successor != rewire.old);
    if split && (in_any_clause(before, rewire.from) || in_any_clause(before, rewire.new)) {
        return None;
    }

    let mut renamed: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();
    let mut replay: Vec<SsaOp> = Vec::new();
    let mut defined: Vec<SsaVarId> = Vec::new();
    let mut previous = rewire.from;
    for &block_idx in route {
        let block = before.block(block_idx)?;
        // A block's phis read their operands together, as the block is entered:
        // one reading another's result reads what it held before, which is what
        // keeps a swap a swap.
        let mut entered: Vec<(SsaVarId, SsaVarId)> = Vec::new();
        for phi in block.phi_nodes() {
            let operand = phi
                .operands()
                .iter()
                .find(|operand| operand.predecessor() == previous && !operand.is_exceptional())?;
            let value = renamed
                .get(&operand.value())
                .copied()
                .unwrap_or(operand.value());
            entered.push((phi.result(), value));
        }
        for (result, value) in entered {
            renamed.insert(result, value);
            defined.push(result);
        }
        for instr in block.instructions() {
            // A slot write the edge skips is one a later read through the slot
            // would miss, and a fresh name for it is no write at all.
            if bypass.slots.written_by(before, instr.op()) {
                return None;
            }
            if instr.is_terminator() || !instr.op().defs().any(|def| needed.contains(&def)) {
                continue;
            }
            // Skipping an effect the program relies on would drop it.
            if !instr.is_pure() {
                return None;
            }
            for def in instr.op().defs() {
                let fresh = fresh(def);
                renamed.insert(def, fresh);
                defined.push(def);
            }
            replay.push(instr.op().remap_variables(|var| renamed.get(&var).copied()));
        }
        previous = block_idx;
    }

    // A value handed on that is itself a bypassed value is read by a copy, so
    // it is read as the edge is entered.
    let mut copies: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();
    let mut hand_on = |value: SsaVarId, replay: &mut Vec<SsaOp>| -> SsaVarId {
        if !disturbed.contains(&value) {
            return value;
        }
        *copies.entry(value).or_insert_with(|| {
            let dest = fresh(value);
            replay.push(SsaOp::Copy { dest, src: value });
            dest
        })
    };

    let mut holds = BTreeMap::new();
    for value in defined {
        // Nothing past the bypass reads it, so the edge need not define it.
        if !needed.contains(&value) {
            continue;
        }
        let Some(&held) = renamed.get(&value) else {
            continue;
        };
        // The old path passed the value through unchanged: whatever reaches
        // the edge is what it holds.
        if held == value {
            continue;
        }
        holds.insert(value, hand_on(held, &mut replay));
    }

    let mut operands = Vec::new();
    for (phi_idx, phi) in before.block(rewire.new)?.phi_nodes().iter().enumerate() {
        let operand = phi
            .operands()
            .iter()
            .find(|operand| operand.predecessor() == rewire.exit && !operand.is_exceptional())?;
        let value = renamed
            .get(&operand.value())
            .copied()
            .unwrap_or(operand.value());
        operands.push((phi_idx, hand_on(value, &mut replay)));
    }

    Some(Plan {
        rewire,
        split,
        replay,
        holds,
        operands,
    })
}

/// Rewires one planned edge, and returns the block the edge's definitions are
/// stated at: `from`, or the block the edge got of its own.
///
/// # Arguments
///
/// * `editor` - The session.
/// * `plan` - The planned rewire.
///
/// # Errors
///
/// Returns an error when an edit the plan was made for no longer applies.
fn apply_plan(editor: &mut SsaEditor<'_, CilTarget>, plan: &Plan) -> analyssa::Result<usize> {
    let rewire = plan.rewire;
    let site = if plan.split {
        let site = editor.function().block_count();
        let mut block = SsaBlock::new(site);
        for op in &plan.replay {
            block.add_instruction(SsaInstruction::synthetic(op.clone()));
        }
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Jump {
            target: rewire.new,
        }));
        editor.append_block(block)?;
        editor.redirect_terminator_target(rewire.from, rewire.old, site)?;
        site
    } else {
        for op in &plan.replay {
            editor.insert_before_terminator(rewire.from, SsaInstruction::synthetic(op.clone()))?;
        }
        editor.redirect_terminator_target(rewire.from, rewire.old, rewire.new)?;
        rewire.from
    };
    for &(phi_idx, value) in &plan.operands {
        editor.add_phi_operand(rewire.new, phi_idx, value, site)?;
    }
    Ok(site)
}

/// A fresh temporary with `like`'s type, defined where the edge's replay puts
/// it.
///
/// A temporary rather than `like`'s own storage: codegen gives a slot origin
/// its slot, and a copy handed on for another value would write that slot
/// while the values the edge reads in parallel are still being read.
///
/// # Arguments
///
/// * `editor` - The session.
/// * `before` - The function as the session found it.
/// * `like` - The value the fresh one replays.
fn fresh_like(
    editor: &mut SsaEditor<'_, CilTarget>,
    before: &SsaFunction,
    like: SsaVarId,
) -> SsaVarId {
    let var_type = before
        .variable(like)
        .map_or(SsaType::Unknown, |variable| variable.var_type().clone());
    editor.create_fresh_variable(VariableOrigin::Phi, 0, DefSite::entry(), var_type)
}

/// Whether `block` lies in any part of any exception clause, where a block
/// appended past the function's end could not join it.
///
/// # Arguments
///
/// * `ssa` - The function whose exception table decides.
/// * `block` - The block to test.
fn in_any_clause(ssa: &SsaFunction, block: usize) -> bool {
    ssa.exception_handlers()
        .iter()
        .any(|handler| handler.parts().any(|(_, range)| range.contains(block)))
}

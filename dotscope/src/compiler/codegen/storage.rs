//! Where each SSA value lives in the generated code.
//!
//! Three decisions, made once per method and from one model of the emitted
//! order, so nothing downstream has to predict another part of the generator:
//!
//! 1. **Which values have no row.** A value read once is emitted at its use
//!    when [`FoldForest`] says the move is unobservable: pure code anywhere in
//!    its block, a load across code that neither traps nor writes what it
//!    reads, a call or store across pure code only. A constant read more than
//!    once is materialised at each use. Neither needs a place.
//! 2. **Which values share a place.** [`Gathering`] joins values that are
//!    never live at once over the listing the emission actually produces, the
//!    folds' late reads included: the versions of each argument and local
//!    first, then every other value first-fit, which is greedy colouring. The
//!    values a throw hands to a handler share one place unconditionally, since
//!    no copy runs on an exceptional edge.
//! 3. **What each place is and is typed as.** A web holding an argument's
//!    entry value is that argument's slot; one holding an address-taken local
//!    is the local's declared slot; the first web of each local keeps its
//!    declaration; everything else gets a fresh local typed by its members.
//!
//! A place never holds two values of different store widths: a slot narrower
//! than four bytes truncates what is stored in it, so sub-word types share only
//! with the identical type.

use std::collections::{BTreeMap, BTreeSet};

use analyssa::{
    analysis::{
        folding::{FoldForest, FoldPolicy},
        webs::{Conflicts, Gathered, Gathering, Group},
    },
    PointerSize,
};
use rustc_hash::FxHashMap;

use crate::{
    analysis::{
        ConstValue, DefUseIndex, RuntimeValueKind, SsaFunction, SsaOp, SsaType, SsaVarId,
        TypeClass, VariableOrigin,
    },
    Error, Result,
};

/// A value's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    /// An argument slot.
    Arg(u16),
    /// A local slot.
    Local(u16),
}

/// How a value without a place is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Materialise {
    /// Emitted at its single use as an expression tree.
    Folded,
    /// A constant emitted again at each use.
    Constant,
}

/// Everything emission needs to know about storage.
pub struct Storage {
    /// By value index: the place a value is stored in and read from.
    place: Vec<Option<Place>>,
    /// Values that are also written to an address-taken slot, because a
    /// pointer reads the slot, while their own place shadows it: they are
    /// read after something may have written the slot through its address.
    also_store: BTreeMap<SsaVarId, Place>,
    /// By value index: how a value with no place is produced.
    materialise: Vec<Option<Materialise>>,
    /// By value index: how many times a value is read, phi operands included.
    uses: Vec<usize>,
    /// Exception objects a handler only discards: popped where the runtime
    /// pushed them, with no place, and their `Pop`s emit nothing.
    discarded: BTreeSet<SsaVarId>,
    /// The phi copies, as `(predecessor, phi result, operand)`.
    phi_copies: Vec<(usize, SsaVarId, SsaVarId)>,
    /// Phi results written through a temporary, with the temporary's slot.
    staged: BTreeMap<SsaVarId, u16>,
    /// The type of every local slot, declared ones included.
    local_types: Vec<SsaType>,
    /// By slot: the method's own local the slot is, which keeps its original
    /// declaration in the signature; `None` for a slot the generator added.
    declared: Vec<Option<u16>>,
}

/// What decides whether a value may share a place with another: its type, the
/// argument it is fixed in on entry, whether it is a local's entry value, the
/// address-taken local it versions and whether a finally resumes into it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Placement {
    /// The type the value is stored as.
    ty: Option<SsaType>,
    /// The argument a value arriving on entry is fixed in.
    home: Option<u16>,
    /// Whether the value is a local's entry value, zero-initialised there.
    entry_local: bool,
    /// The address-taken local whose slot holds the value.
    taken: Option<u16>,
    /// Whether the value is a phi copied before an `endfinally`.
    resumes: bool,
}

impl Placement {
    /// Whether a value placed as `self` and one placed as `other` may not
    /// share a place.
    fn conflicts(&self, other: &Self) -> bool {
        let (Some(ta), Some(tb)) = (&self.ty, &other.ty) else {
            return true;
        };
        if !slot_compatible(ta, tb) {
            return true;
        }
        // Two fixed homes, or a fixed home and a zero-initialised entry.
        if self.home.is_some() && other.home.is_some() && self.home != other.home {
            return true;
        }
        if (self.home.is_some() && other.entry_local) || (other.home.is_some() && self.entry_local)
        {
            return true;
        }
        // An address-taken local's slot holds its versions and nothing else.
        if self.taken != other.taken {
            return true;
        }
        // A phi copied before an `endfinally` is written on every way out of
        // the finally, while an exception unwinds through it included.
        self.resumes || other.resumes
    }
}

/// dotscope's folding decisions on top of the generic rules.
struct CilFolds<'a> {
    pinned: &'a BTreeSet<SsaVarId>,
}

impl FoldPolicy<crate::analysis::CilTarget> for CilFolds<'_> {
    fn pinned(&self, value: SsaVarId) -> bool {
        self.pinned.contains(&value)
    }

    fn may_fold(&self, op: &SsaOp) -> bool {
        // A decrypted array is a new array each time it is emitted; folded it
        // is still emitted once, so it may fold, but it is never rematerialised.
        !matches!(op, SsaOp::Phi { .. })
    }

    fn moves_effects(&self) -> bool {
        true
    }

    fn folds_across_blocks(&self) -> bool {
        false
    }

    fn max_depth(&self) -> Option<u32> {
        // The evaluation stack a tree needs grows with its depth.
        Some(64)
    }
}

impl Storage {
    /// Decides the storage of every value of `ssa`.
    ///
    /// # Errors
    ///
    /// Returns an error when a value's type admits no slot, or when a version
    /// of an address-taken local is read after something may have written the
    /// local through its address, which needs a copy this generator does not
    /// make.
    pub fn build(ssa: &SsaFunction) -> Result<Self> {
        let count = ssa.var_id_capacity();
        let defuse = DefUseIndex::build_with_ops(ssa);
        let address_taken = ssa.address_taken_slots();
        let mut uses: Vec<usize> = (0..count)
            .map(|index| {
                defuse
                    .uses_of(SsaVarId::from_index(index))
                    .map_or(0, <[_]>::len)
            })
            .collect();

        // Values that must be stored where they are defined: versions of a
        // local or argument whose address is taken (a pointer reads the slot),
        // and the values a throw hands to a handler (the handler reads the
        // slot the protected code wrote).
        let webs = ssa.exceptional_webs();
        let mut pinned: BTreeSet<SsaVarId> = BTreeSet::new();
        for variable in ssa.variables() {
            let taken = match variable.origin() {
                VariableOrigin::Local(idx) => address_taken.local(idx),
                VariableOrigin::Argument(idx) => address_taken.argument(idx),
                VariableOrigin::Phi | VariableOrigin::EntryLiveIn => false,
            };
            if taken {
                pinned.insert(variable.id());
            }
        }
        for web in &webs {
            pinned.extend(web.values.iter().copied());
        }

        // An exception object whose every read is a `Pop` in its own handler
        // block is dropped where it arrives: it is read by nothing that needs
        // it, so it needs no place.
        let mut discarded = BTreeSet::new();
        for block in ssa.blocks() {
            for instr in block.instructions() {
                let SsaOp::RuntimeValue {
                    dest,
                    kind: RuntimeValueKind::ExceptionObject,
                } = instr.op()
                else {
                    continue;
                };
                if pinned.contains(dest) {
                    continue;
                }
                let pops = block
                    .instructions()
                    .iter()
                    .filter(|other| matches!(other.op(), SsaOp::Pop { value } if value == dest))
                    .count();
                if let Some(read) = uses.get_mut(dest.index()) {
                    if *read == pops {
                        *read = 0;
                        discarded.insert(*dest);
                    }
                }
            }
        }

        let forest = FoldForest::compute(
            ssa,
            &defuse,
            &CilFolds { pinned: &pinned },
            PointerSize::Bit64,
            None,
        );

        let mut materialise: Vec<Option<Materialise>> = vec![None; count];
        for (index, slot) in materialise.iter_mut().enumerate() {
            if forest.is_folded(SsaVarId::from_index(index)) {
                *slot = Some(Materialise::Folded);
            }
        }
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Const { dest, value } = instr.op() {
                    let compound = matches!(value, ConstValue::DecryptedArray { .. });
                    if !compound && !pinned.contains(dest) {
                        if let Some(slot) = materialise.get_mut(dest.index()) {
                            slot.get_or_insert(Materialise::Constant);
                        }
                    }
                }
            }
        }
        let rowless: Vec<bool> = materialise.iter().map(Option::is_some).collect();

        // Which values need a place: read, or pinned to one.
        let needs_place = |var: SsaVarId| -> bool {
            !rowless.get(var.index()).copied().unwrap_or(false)
                && (uses.get(var.index()).copied().unwrap_or(0) > 0 || pinned.contains(&var))
        };

        let types: Vec<SsaType> = (0..count)
            .map(|index| infer_type(ssa, SsaVarId::from_index(index)).unwrap_or(SsaType::Unknown))
            .collect();
        let entry_arg: BTreeMap<SsaVarId, u16> = ssa
            .variables()
            .iter()
            .filter_map(|var| match var.origin() {
                VariableOrigin::Argument(idx) if is_entry(ssa, var.id()) => Some((var.id(), idx)),
                _ => None,
            })
            .collect();
        let entry_local: BTreeSet<SsaVarId> = ssa
            .variables()
            .iter()
            .filter(|var| {
                matches!(var.origin(), VariableOrigin::Local(_)) && is_entry(ssa, var.id())
            })
            .map(|var| var.id())
            .collect();
        let taken_local = |var: SsaVarId| -> Option<u16> {
            ssa.variable(var)
                .and_then(|variable| match variable.origin() {
                    VariableOrigin::Local(idx) if address_taken.local(idx) => Some(idx),
                    _ => None,
                })
        };
        let resume_phis = finally_resume_phis(ssa);

        // What keeps two values out of one place is a question of what each
        // is - its type, its fixed home, whether it is an address-taken
        // local's or a phi a finally resumes into - so each distinct answer is
        // one kind, and the gathering compares places by the few kinds they
        // hold.
        let mut interned: FxHashMap<Placement, u32> = FxHashMap::default();
        let mut placements: Vec<Placement> = Vec::new();
        let kinds: Vec<u32> = (0..count)
            .map(|index| {
                let var = SsaVarId::from_index(index);
                let placement = Placement {
                    ty: types.get(index).cloned(),
                    home: entry_arg.get(&var).copied(),
                    entry_local: entry_local.contains(&var),
                    taken: taken_local(var),
                    resumes: resume_phis.contains(&var),
                };
                *interned.entry(placement.clone()).or_insert_with(|| {
                    placements.push(placement);
                    u32::try_from(placements.len().saturating_sub(1)).unwrap_or(u32::MAX)
                })
            })
            .collect();
        let conflict = |a: u32, b: u32| -> bool {
            match (placements.get(a as usize), placements.get(b as usize)) {
                (Some(a), Some(b)) => a.conflicts(b),
                _ => true,
            }
        };
        let conflicts = Conflicts {
            kinds: &kinds,
            conflict: &conflict,
        };

        // Groups: each argument's and local's versions, entry value first; then
        // every other value that needs a place, first-fit.
        let mut by_slot: BTreeMap<(bool, u16), Vec<usize>> = BTreeMap::new();
        let mut others: Vec<usize> = Vec::new();
        for var in ssa.variables() {
            let id = var.id();
            if !needs_place(id) {
                continue;
            }
            match var.origin() {
                VariableOrigin::Argument(idx) => {
                    by_slot.entry((true, idx)).or_default().push(id.index())
                }
                VariableOrigin::Local(idx) => {
                    by_slot.entry((false, idx)).or_default().push(id.index())
                }
                VariableOrigin::Phi | VariableOrigin::EntryLiveIn => others.push(id.index()),
            }
        }
        let mut groups: Vec<Group> = Vec::new();
        for ((is_arg, idx), mut values) in by_slot {
            values.sort_by_key(|&value| !is_entry(ssa, SsaVarId::from_index(value)));
            let in_memory = if is_arg {
                address_taken.argument(idx)
            } else {
                address_taken.local(idx)
            };
            groups.push(Group { values, in_memory });
        }
        groups.push(Group {
            values: others,
            in_memory: false,
        });

        let must_share: Vec<Vec<usize>> = webs
            .iter()
            .map(|web| web.values.iter().map(|value| value.index()).collect())
            .collect();

        let gathered: Gathered = Gathering {
            rowless: &rowless,
            groups,
            conflicts: Some(conflicts),
            must_share: &must_share,
            // Nothing is anchored: another value may take an argument's slot after the
            // argument's last read (`starg` writes it), which CIL allows, since the
            // slot is typed by the signature and the conflicts keep a value of another
            // kind out of it
            anchored: &[],
        }
        // A phi operand without a row is produced on the edge and has no place
        // to share: offered to the result's web, the copy that writes the
        // result would be dropped as one that reads and writes one variable.
        .run(ssa, &defuse, |_, _, operand| {
            !rowless.get(operand).copied().unwrap_or(false)
        });

        // A version of an address-taken slot read after something may have
        // written the slot through its address is no longer what the slot
        // holds there. It is kept in a place of its own, and still written to
        // the slot, which is what a pointer reads.
        let detached: BTreeSet<SsaVarId> = gathered
            .detached
            .iter()
            .enumerate()
            .filter(|(index, detached)| **detached && needs_place(SsaVarId::from_index(*index)))
            .map(|(index, _)| SsaVarId::from_index(index))
            .collect();
        let taken_place = |var: SsaVarId| -> Option<Place> {
            ssa.variable(var)
                .and_then(|variable| match variable.origin() {
                    VariableOrigin::Local(idx) if address_taken.local(idx) => {
                        Some(Place::Local(idx))
                    }
                    VariableOrigin::Argument(idx) if address_taken.argument(idx) => {
                        Some(Place::Arg(idx))
                    }
                    _ => None,
                })
        };

        // Webs to places.
        let declared_locals = ssa
            .original_local_types()
            .map_or(ssa.num_locals(), <[_]>::len)
            .max(ssa.num_locals());
        let mut local_types: Vec<SsaType> = (0..declared_locals)
            .map(|idx| {
                u16::try_from(idx).map_or(SsaType::Unknown, |idx| {
                    ssa.origin_type(VariableOrigin::Local(idx))
                })
            })
            .collect();

        let mut members: BTreeMap<usize, Vec<SsaVarId>> = BTreeMap::new();
        for var in ssa.variables() {
            if needs_place(var.id()) {
                members
                    .entry(gathered.representative(var.id().index()))
                    .or_default()
                    .push(var.id());
            }
        }

        let mut place: Vec<Option<Place>> = vec![None; count];
        let mut claimed: BTreeSet<Place> = BTreeSet::new();
        // Order: webs holding a fixed home first, so a later web cannot take it.
        let mut ordered: Vec<(usize, Vec<SsaVarId>)> = members.into_iter().collect();
        ordered.sort_by_key(|(_, web)| {
            let fixed = web
                .iter()
                .any(|var| entry_arg.contains_key(var) || taken_local(*var).is_some());
            (!fixed, web.first().map_or(usize::MAX, |var| var.index()))
        });
        let mut also_store: BTreeMap<SsaVarId, Place> = BTreeMap::new();
        for (_, web) in ordered {
            // A second web of one address-taken slot (two of its versions are
            // live at once) cannot also be the slot.
            let shadowed = web.iter().any(|var| detached.contains(var))
                || web
                    .iter()
                    .filter_map(|var| taken_place(*var))
                    .any(|slot| claimed.contains(&slot));
            if shadowed {
                for var in &web {
                    if let Some(slot) = taken_place(*var) {
                        also_store.insert(*var, slot);
                    }
                }
            }
            let chosen = if shadowed {
                None
            } else {
                Self::choose_place(
                    ssa,
                    &web,
                    &types,
                    &entry_arg,
                    &taken_local,
                    &claimed,
                    &local_types,
                )
            };
            let place_for_web = match chosen {
                Some(place) => place,
                None => {
                    let slot = u16::try_from(local_types.len()).map_err(|_| {
                        Error::CodegenFailed("the method needs more than 65535 locals".to_string())
                    })?;
                    local_types.push(web_type(&web, &types)?);
                    Place::Local(slot)
                }
            };
            claimed.insert(place_for_web);
            for var in web {
                if let Some(slot) = place.get_mut(var.index()) {
                    *slot = Some(place_for_web);
                }
            }
        }

        // Phi copies for every phi something reads.
        let phi_copies: Vec<(usize, SsaVarId, SsaVarId)> = gathered
            .phi_copies(ssa)
            .into_iter()
            .filter(|(_, result, _)| needs_place(*result))
            .collect();
        let mut staged = BTreeMap::new();
        for (_, result, _) in &phi_copies {
            if gathered.is_staged(result.index()) && !staged.contains_key(result) {
                let slot = u16::try_from(local_types.len()).map_err(|_| {
                    Error::CodegenFailed("the method needs more than 65535 locals".to_string())
                })?;
                local_types.push(web_type(&[*result], &types)?);
                staged.insert(*result, slot);
            }
        }

        // Only the slots something uses are declared: a declared local nothing
        // lives in any more (an obfuscator's, whose code is gone) would keep its
        // type, and what that type imports, in the signature. The kept ones are
        // renumbered in order, the method's own first.
        let mut used = vec![false; local_types.len()];
        let mut mark = |slot: u16| {
            if let Some(used) = used.get_mut(usize::from(slot)) {
                *used = true;
            }
        };
        for slot in place.iter().flatten().chain(also_store.values()) {
            if let Place::Local(slot) = slot {
                mark(*slot);
            }
        }
        for slot in staged.values() {
            mark(*slot);
        }
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::LoadLocal { local_index, .. }
                | SsaOp::LoadLocalAddr { local_index, .. } = instr.op()
                {
                    mark(*local_index);
                }
            }
        }
        let mut renumbered: Vec<Option<u16>> = vec![None; local_types.len()];
        let mut kept_types = Vec::new();
        let mut declared = Vec::new();
        for (slot, ty) in local_types.into_iter().enumerate() {
            if !used.get(slot).copied().unwrap_or(false) {
                continue;
            }
            let new = u16::try_from(kept_types.len()).map_err(|_| {
                Error::CodegenFailed("the method needs more than 65535 locals".to_string())
            })?;
            if let Some(entry) = renumbered.get_mut(slot) {
                *entry = Some(new);
            }
            kept_types.push(ty);
            declared.push(
                (slot < declared_locals)
                    .then(|| u16::try_from(slot).ok())
                    .flatten(),
            );
        }
        let moved = |place: Place| match place {
            Place::Local(slot) => renumbered
                .get(usize::from(slot))
                .copied()
                .flatten()
                .map(Place::Local),
            Place::Arg(_) => Some(place),
        };
        let place = place.into_iter().map(|slot| slot.and_then(moved)).collect();
        let also_store = also_store
            .into_iter()
            .filter_map(|(var, slot)| moved(slot).map(|slot| (var, slot)))
            .collect();
        let staged = staged
            .into_iter()
            .filter_map(|(var, slot)| {
                renumbered
                    .get(usize::from(slot))
                    .copied()
                    .flatten()
                    .map(|slot| (var, slot))
            })
            .collect();

        Ok(Self {
            place,
            also_store,
            materialise,
            uses,
            discarded,
            phi_copies,
            staged,
            local_types: kept_types,
            declared,
        })
    }

    /// The fixed or declared place a web takes, or `None` for a fresh local.
    fn choose_place(
        ssa: &SsaFunction,
        web: &[SsaVarId],
        types: &[SsaType],
        entry_arg: &BTreeMap<SsaVarId, u16>,
        taken_local: &impl Fn(SsaVarId) -> Option<u16>,
        claimed: &BTreeSet<Place>,
        local_types: &[SsaType],
    ) -> Option<Place> {
        if let Some(idx) = web.iter().find_map(|var| entry_arg.get(var)) {
            return Some(Place::Arg(*idx));
        }
        if let Some(idx) = web.iter().find_map(|var| taken_local(*var)) {
            return Some(Place::Local(idx));
        }
        // The first web of an argument or local keeps its slot, when every
        // member fits the slot's type.
        for var in web {
            let candidate = match ssa.variable(*var).map(|v| v.origin()) {
                Some(VariableOrigin::Argument(idx)) => Place::Arg(idx),
                Some(VariableOrigin::Local(idx)) => Place::Local(idx),
                _ => continue,
            };
            if claimed.contains(&candidate) {
                continue;
            }
            let slot_type = match candidate {
                Place::Local(idx) => local_types.get(usize::from(idx)).cloned(),
                Place::Arg(idx) => Some(ssa.origin_type(VariableOrigin::Argument(idx))),
            };
            let fits = slot_type.is_some_and(|slot_type| {
                web.iter().all(|member| {
                    types
                        .get(member.index())
                        .is_some_and(|member_type| slot_compatible(&slot_type, member_type))
                })
            });
            if fits {
                return Some(candidate);
            }
        }
        None
    }

    /// The place `var` is stored in.
    pub fn place(&self, var: SsaVarId) -> Option<Place> {
        self.place.get(var.index()).copied().flatten()
    }

    /// The address-taken slot `var` is also written to, when its own place
    /// shadows that slot.
    pub fn also_store(&self, var: SsaVarId) -> Option<Place> {
        self.also_store.get(&var).copied()
    }

    /// How `var` is produced when it has no place.
    pub fn materialise(&self, var: SsaVarId) -> Option<Materialise> {
        self.materialise.get(var.index()).copied().flatten()
    }

    /// Whether `var` is an exception object its handler only discards.
    pub fn discarded(&self, var: SsaVarId) -> bool {
        self.discarded.contains(&var)
    }

    /// How many times `var` is read.
    pub fn uses(&self, var: SsaVarId) -> usize {
        self.uses.get(var.index()).copied().unwrap_or(0)
    }

    /// The phi copies owed on the edge `from -> to`, as `(result, operand)`.
    pub fn copies_on(
        &self,
        ssa: &SsaFunction,
        from: usize,
        to: usize,
    ) -> Vec<(SsaVarId, SsaVarId)> {
        let Some(block) = ssa.block(to) else {
            return Vec::new();
        };
        let results: BTreeSet<SsaVarId> =
            block.phi_nodes().iter().map(|phi| phi.result()).collect();
        self.phi_copies
            .iter()
            .filter(|(pred, result, _)| *pred == from && results.contains(result))
            .map(|(_, result, operand)| (*result, *operand))
            .collect()
    }

    /// The temporary a staged phi result is written through.
    pub fn staged(&self, result: SsaVarId) -> Option<u16> {
        self.staged.get(&result).copied()
    }

    /// The staged phi results of `block`, with their temporaries.
    pub fn staged_in(&self, ssa: &SsaFunction, block: usize) -> Vec<(SsaVarId, u16)> {
        ssa.block(block)
            .map(|block| {
                block
                    .phi_nodes()
                    .iter()
                    .filter_map(|phi| self.staged(phi.result()).map(|temp| (phi.result(), temp)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The type of every local slot.
    pub fn local_types(&self) -> &[SsaType] {
        &self.local_types
    }

    /// By slot: the method's own local the slot is, if it is one.
    pub fn declared(&self) -> &[Option<u16>] {
        &self.declared
    }
}

/// Whether `var` is an entry value: defined by nothing in the function.
fn is_entry(ssa: &SsaFunction, var: SsaVarId) -> bool {
    ssa.get_definition(var).is_none() && ssa.find_phi_defining(var).is_none()
}

/// Whether two values of these types may share one slot without the slot
/// changing either: identical types always; integers and floats of one full
/// width; never a sub-word type with anything else, since storing into a slot
/// narrower than four bytes truncates; never a reference type with another
/// (the slot's declared type is what `ldloc` pushes); never an unknown type.
pub fn slot_compatible(a: &SsaType, b: &SsaType) -> bool {
    if a.is_unknown() || b.is_unknown() {
        return false;
    }
    if a == b {
        return true;
    }
    let narrow = |ty: &SsaType| {
        matches!(
            ty,
            SsaType::Bool | SsaType::Char | SsaType::I8 | SsaType::U8 | SsaType::I16 | SsaType::U16
        )
    };
    if narrow(a) || narrow(b) {
        return false;
    }
    a.storage_class() == b.storage_class()
        && matches!(
            a.storage_class(),
            TypeClass::Int32
                | TypeClass::Int64
                | TypeClass::NativeInt
                | TypeClass::Float32
                | TypeClass::Float64
        )
}

/// Whether a local can be declared with type `ty`: not `void`, and a type
/// rather than the absence of one, which a signature could only spell as a
/// guess.
pub fn is_slot_type(ty: &SsaType) -> bool {
    !matches!(ty, SsaType::Void | SsaType::Unknown | SsaType::Varying)
}

/// The type of a fresh slot holding `web`: the members' common type, or the
/// full-width type of their storage class.
fn web_type(web: &[SsaVarId], types: &[SsaType]) -> Result<SsaType> {
    let mut found: Option<SsaType> = None;
    for var in web {
        let ty = types.get(var.index()).cloned().unwrap_or(SsaType::Unknown);
        if !is_slot_type(&ty) {
            return Err(Error::CodegenFailed(format!(
                "{var} has type {ty:?}, which no slot holds"
            )));
        }
        found = Some(match found {
            None => ty,
            Some(existing) if existing == ty => existing,
            Some(existing) => match existing.storage_class() {
                TypeClass::Int32 => SsaType::I32,
                TypeClass::Int64 => SsaType::I64,
                TypeClass::NativeInt => SsaType::NativeInt,
                _ => {
                    return Err(Error::CodegenFailed(format!(
                        "{var} shares a slot with a value of another type"
                    )))
                }
            },
        });
    }
    found.ok_or_else(|| Error::CodegenFailed("a slot holds no value".to_string()))
}

/// Phi results that take an operand from a block ending in `endfinally`.
fn finally_resume_phis(ssa: &SsaFunction) -> BTreeSet<SsaVarId> {
    ssa.blocks()
        .iter()
        .flat_map(|block| block.phi_nodes())
        .filter(|phi| {
            phi.normal_operands().any(|operand| {
                ssa.block(operand.predecessor()).is_some_and(|predecessor| {
                    matches!(predecessor.control_terminator(), Some(SsaOp::EndFinally))
                })
            })
        })
        .map(|phi| phi.result())
        .collect()
}

/// The type of `var`: its declared type, else its defining instruction's
/// result type, else what its operation implies, else its copy source's or its
/// phi operands'.
///
/// # Errors
///
/// Returns an error when none of these knows a type: a slot for such a value
/// could only be guessed, and a guessed slot type is a wrong `stloc` waiting
/// to happen.
pub fn infer_type(ssa: &SsaFunction, var: SsaVarId) -> Result<SsaType> {
    let mut visited = BTreeSet::new();
    infer_type_inner(ssa, var, &mut visited)
}

fn infer_type_inner(
    ssa: &SsaFunction,
    var: SsaVarId,
    visited: &mut BTreeSet<SsaVarId>,
) -> Result<SsaType> {
    if !visited.insert(var) {
        return Err(Error::CodegenFailed(format!(
            "circular type dependency for variable {var:?}"
        )));
    }
    if let Some(v) = ssa.variable(var) {
        if !v.var_type().is_unknown() {
            return Ok(v.var_type().clone());
        }
    }
    if let Some(def_instr) = ssa.get_definition_instruction(var) {
        if let Some(rt) = def_instr.result_type() {
            if !rt.is_unknown() {
                return Ok(rt.clone());
            }
        }
        if let Some(inferred) = def_instr.op().infer_result_type() {
            return Ok(inferred);
        }
        // Arithmetic computes in its operands' type (ECMA-335 III.1.5).
        let binary = match def_instr.op() {
            SsaOp::Add { left, right, .. }
            | SsaOp::AddOvf { left, right, .. }
            | SsaOp::Sub { left, right, .. }
            | SsaOp::SubOvf { left, right, .. } => Some((*left, *right, true)),
            SsaOp::Mul { left, right, .. }
            | SsaOp::MulOvf { left, right, .. }
            | SsaOp::Div { left, right, .. }
            | SsaOp::Rem { left, right, .. }
            | SsaOp::And { left, right, .. }
            | SsaOp::Or { left, right, .. }
            | SsaOp::Xor { left, right, .. } => Some((*left, *right, false)),
            _ => None,
        };
        if let Some((left, right, additive)) = binary {
            let left = infer_type_inner(ssa, left, visited)?;
            let right = infer_type_inner(ssa, right, visited)?;
            return SsaType::binary_numeric(&left, &right, additive).ok_or_else(|| {
                Error::CodegenFailed(format!(
                    "{var:?} computes on {left:?} and {right:?}, which no arithmetic combines"
                ))
            });
        }
        if let SsaOp::Shl { value: operand, .. }
        | SsaOp::Shr { value: operand, .. }
        | SsaOp::Neg { operand, .. }
        | SsaOp::Not { operand, .. } = def_instr.op()
        {
            let operand = *operand;
            let ty = infer_type_inner(ssa, operand, visited)?;
            return ty.unary_numeric().ok_or_else(|| {
                Error::CodegenFailed(format!("{var:?} computes on {ty:?}, which is no number"))
            });
        }
        if let SsaOp::Copy { src, .. } = def_instr.op() {
            let src = *src;
            return infer_type_inner(ssa, src, visited);
        }
        return Err(Error::CodegenFailed(format!(
            "cannot determine type for variable {var:?}: defining op has no type inference rule: {:?}",
            def_instr.op()
        )));
    }
    if let Some((_block, phi)) = ssa.find_phi_defining(var) {
        for operand in phi.operands() {
            if let Ok(ty) = infer_type_inner(ssa, operand.value(), visited) {
                return Ok(ty);
            }
        }
        return Err(Error::CodegenFailed(format!(
            "cannot determine type for phi {var:?}: all operands unknown"
        )));
    }
    Err(Error::CodegenFailed(format!(
        "cannot determine type for variable {var:?}: no definition found"
    )))
}

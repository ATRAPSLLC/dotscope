//! Neutralization pass for removing protection code from methods.
//!
//! This pass surgically removes instructions that reference removed tokens
//! (methods, types, fields) from method bodies, while preserving any legitimate
//! initialization code. This is critical for handling module `.cctor` methods
//! that contain both protection initialization AND user initialization.
//!
//! # Problem
//!
//! When obfuscator infrastructure is removed (decryptor types, anti-tamper methods),
//! methods like the module `.cctor` may still contain calls to those removed entities.
//! Simply removing the `.cctor` would break the assembly if it contains legitimate
//! initialization. We need to:
//!
//! 1. Identify instructions referencing removed tokens
//! 2. Trace all dependent code via taint analysis
//! 3. Remove only tainted instructions
//! 4. Preserve legitimate initialization code
//!
//! # Algorithm
//!
//! For each method passed to the pass:
//! - Scan all instructions for references to removed tokens
//! - Mark those instructions as taint sources
//! - Run bidirectional taint propagation to find all dependent code
//! - Replace tainted instructions with `Nop`
//!
//! Subsequent passes (DCE, block merging) will clean up the `Nop`s.
//!
//! # Example
//!
//! The `tests::test_neutralization_removes_tainted_instructions` test in this module runs
//! the pass on a method whose call to a removed method feeds an addition.

use std::collections::{BTreeSet, HashMap, HashSet};

use analyssa::{
    analysis::WorkBudget,
    events::Event,
    ir::function::SsaEditOptions,
    scheduling::{FunctionPass, PassEnv},
};

use crate::{
    analysis::{
        find_token_dependencies, CilTarget, ConstValue, SsaFunction, SsaInstruction, SsaOp,
    },
    compiler::{EventKind, ModificationScope},
    metadata::token::Token,
};

/// Action to perform on a tainted instruction during neutralization.
enum InstrAction {
    /// Replace the instruction with a `Nop` (used for non-terminator instructions).
    Nop,
    /// Replace a conditional branch with an unconditional `Jump` to the given block.
    Jump(usize),
}

/// Pass that neutralizes protection code by removing instructions that
/// reference removed tokens.
///
/// This pass is designed to run BEFORE code generation, after we know which
/// tokens will be removed by cleanup. It modifies the SSA to remove all
/// instructions that depend on those tokens.
///
/// The engine decides which methods to process - this pass simply processes
/// whatever method is passed to it.
pub struct NeutralizationPass<'a> {
    /// Tokens that are being removed (methods, types, fields).
    removed_tokens: &'a HashSet<Token>,
}

impl<'a> NeutralizationPass<'a> {
    /// Creates a new neutralization pass.
    ///
    /// # Arguments
    ///
    /// * `removed_tokens` - Tokens that will be removed by cleanup.
    #[must_use]
    pub fn new(removed_tokens: &'a HashSet<Token>) -> Self {
        Self { removed_tokens }
    }

    /// Whether this pass has a neutralized form for the instruction.
    ///
    /// Everything that is not a terminator becomes a `Nop`, and a conditional
    /// branch becomes a jump to whichever arm survives. The other terminators
    /// have no such form: a `ret` still has to return and a `throw` still has
    /// to throw, so they are left as they are.
    ///
    /// Which makes them survivors, and that is the point of asking. The removal
    /// set is what [`SsaFunction::retain_unread_removals`] reads as *these
    /// definitions are going*, and a `ret` counted as going stops rescuing the
    /// value it returns. The definition is then NOPed out from under a `ret`
    /// that stays, leaving a method whose reconstruction fails on an undefined
    /// use - one method of `mkaring_normal.exe` reduced to `ret v5` with nothing
    /// defining `v5`.
    ///
    /// # Arguments
    ///
    /// * `instr` - The instruction to judge.
    fn is_rewritable(instr: &SsaInstruction) -> bool {
        !instr.is_terminator()
            || matches!(instr.op(), SsaOp::Branch { .. } | SsaOp::BranchCmp { .. })
    }

    /// Checks if a block is "fully tainted" - all PHIs and instructions are tainted.
    ///
    /// A fully tainted block contains only protection code and no legitimate
    /// instructions. This is used to determine branch targets when neutralizing
    /// conditional branches.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function containing the block.
    /// * `block_idx` - Index of the block to check.
    /// * `tainted_instrs` - Set of tainted instruction locations as `(block, instr_idx)`.
    /// * `tainted_phis` - Set of tainted PHI node locations as `(block, phi_idx)`.
    ///
    /// # Returns
    ///
    /// `true` if all PHIs and instructions in the block are tainted (or if the
    /// block is empty/non-existent), `false` if any legitimate code remains.
    fn is_block_fully_tainted(
        ssa: &SsaFunction,
        block_idx: usize,
        tainted_instrs: &HashSet<(usize, usize)>,
        tainted_phis: &HashSet<(usize, usize)>,
    ) -> bool {
        if let Some(block) = ssa.block(block_idx) {
            // Check all PHIs are tainted
            for phi_idx in 0..block.phi_nodes().len() {
                if !tainted_phis.contains(&(block_idx, phi_idx)) {
                    return false;
                }
            }
            // Check all instructions are tainted
            for instr_idx in 0..block.instructions().len() {
                if !tainted_instrs.contains(&(block_idx, instr_idx)) {
                    return false;
                }
            }
            // Empty blocks are considered fully tainted (nothing legitimate)
            true
        } else {
            true // Non-existent block is "fully tainted"
        }
    }

    /// Finds blocks that can reach an exit (Return/Throw) via reverse reachability.
    ///
    /// Performs a backwards BFS from all exit blocks to find which blocks have
    /// a valid path to method termination. This is used as a fallback when
    /// choosing branch targets during neutralization.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    ///
    /// # Returns
    ///
    /// Set of block indices that can reach a `Return` or `Throw` instruction.
    fn find_blocks_reaching_exit(ssa: &SsaFunction) -> HashSet<usize> {
        // Build predecessor map
        let mut predecessors: HashMap<usize, Vec<usize>> = HashMap::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for succ in block.successors() {
                predecessors.entry(succ).or_default().push(block_idx);
            }
        }

        // Find exit blocks
        let mut can_reach_exit = HashSet::new();
        let mut worklist: Vec<usize> = Vec::new();
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Return { .. } | SsaOp::Throw { .. }) {
                    worklist.push(block_idx);
                    break;
                }
            }
        }

        // BFS backwards
        while let Some(block_idx) = worklist.pop() {
            if can_reach_exit.insert(block_idx) {
                if let Some(preds) = predecessors.get(&block_idx) {
                    worklist.extend(preds.iter().filter(|p| !can_reach_exit.contains(p)));
                }
            }
        }

        can_reach_exit
    }

    /// Chooses which branch target to use when neutralizing a tainted branch.
    ///
    /// When a conditional branch's condition depends on tainted code, the branch
    /// must be replaced with an unconditional jump. This method determines which
    /// target to jump to, preferring paths that lead to legitimate code.
    ///
    /// # Priority
    ///
    /// 1. If one target is fully tainted and the other isn't, choose the non-tainted one
    /// 2. If neither is fully tainted, choose the one that can reach an exit
    /// 3. Fallback to `true_target` (often the forward/exit path)
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function containing the branch.
    /// * `true_target` - Block index of the branch's true target.
    /// * `false_target` - Block index of the branch's false target.
    /// * `tainted_instrs` - Set of tainted instruction locations.
    /// * `tainted_phis` - Set of tainted PHI node locations.
    /// * `can_reach_exit` - Set of blocks that can reach a method exit.
    ///
    /// # Returns
    ///
    /// The block index to jump to (either `true_target` or `false_target`).
    fn choose_branch_target(
        ssa: &SsaFunction,
        true_target: usize,
        false_target: usize,
        tainted_instrs: &HashSet<(usize, usize)>,
        tainted_phis: &HashSet<(usize, usize)>,
        can_reach_exit: &HashSet<usize>,
    ) -> usize {
        let true_tainted =
            Self::is_block_fully_tainted(ssa, true_target, tainted_instrs, tainted_phis);
        let false_tainted =
            Self::is_block_fully_tainted(ssa, false_target, tainted_instrs, tainted_phis);

        match (true_tainted, false_tainted) {
            (true, false) => false_target, // True target is tainted, go to false
            (false, true) => true_target,  // False target is tainted, go to true
            _ => {
                // Neither or both fully tainted - use exit reachability
                let true_reaches = can_reach_exit.contains(&true_target);
                let false_reaches = can_reach_exit.contains(&false_target);
                match (true_reaches, false_reaches) {
                    (false, true) => false_target,
                    _ => true_target, // Both or neither - prefer true (often forward path)
                }
            }
        }
    }

    /// Neutralizes a method by removing instructions that reference removed tokens.
    ///
    /// Uses bidirectional taint analysis to identify all instructions that depend
    /// on the removed tokens, then surgically removes them while preserving
    /// legitimate code.
    ///
    /// # Behavior
    ///
    /// - **Regular instructions**: Replaced with `Nop`
    /// - **PHI nodes**: Removed entirely (their result becomes undefined)
    /// - **Conditional branches**: Replaced with unconditional jumps toward exit paths
    /// - **Other terminators**: Left unchanged (`Return`, `Throw`, etc.)
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to neutralize. Modified in place.
    /// * `budget` - The work budget the taint propagation runs under.
    ///
    /// # Returns
    ///
    /// The number of elements neutralized (instructions + PHIs + branch conversions).
    fn neutralize_method(&self, ssa: &mut SsaFunction, budget: &WorkBudget) -> usize {
        if self.removed_tokens.is_empty() {
            return 0;
        }

        // Run taint analysis to find all instructions dependent on removed tokens
        let taint = find_token_dependencies(ssa, self.removed_tokens.iter().copied(), budget);
        if taint.tainted_instr_count() == 0 && taint.tainted_phis().is_empty() {
            return 0;
        }

        // Collect tainted sets for block analysis. Never neutralize
        // `DecryptedString` constants - they are recovered user data, not
        // protection infrastructure. Bidirectional taint reaches them through
        // shared data flow (e.g. a `String.Concat` over both a decrypted string
        // and a value from a removed decryptor), but the string itself is
        // legitimate. Excluding them here rather than at rewrite time keeps the
        // candidate set equal to what is actually removed, which both the
        // branch-target choice and the liveness closure below depend on.
        let tainted_instrs: HashSet<(usize, usize)> = taint
            .tainted_instructions()
            .iter()
            .copied()
            .filter(|&(block_idx, instr_idx)| {
                !ssa.block(block_idx)
                    .and_then(|b| b.instructions().get(instr_idx))
                    .is_some_and(|instr| {
                        matches!(
                            instr.op(),
                            SsaOp::Const {
                                value: ConstValue::DecryptedString(_),
                                ..
                            }
                        )
                    })
            })
            .collect();
        let tainted_phis_set: HashSet<(usize, usize)> =
            taint.tainted_phis().iter().copied().collect();

        // Refuse to destroy a definition something still reads. Dropping a phi
        // makes its result undefined, and NOPing an instruction makes its
        // destination undefined; either leaves a read the SSA verifier rejects,
        // failing the whole method rather than the one rewrite.
        // Two questions, two sets, and conflating them is a miscompile.
        //
        // *Is this block protection code?* is what decides which arm of a
        // branch survives, and it is answered by the taint: a block whose every
        // instruction is tainted is protection, whatever the rewrite then does
        // about it.
        //
        // *Will this instruction be removed?* is what decides whether the
        // definitions it reads may go, and it is answered by the removal set
        // after the guard has kept everything that must stay.
        //
        // Answering the first question with the second makes the branch choice
        // depend on which definitions happened to be rescued, and the arm
        // holding the user's code gets dropped.
        // Exit reachability, needed to judge a branch whose arms are both
        // protection; computed here because the removal set below depends on
        // that judgement.
        let can_reach_exit = Self::find_blocks_reaching_exit(ssa);

        let mut removable_instrs: BTreeSet<(usize, usize)> = tainted_instrs
            .iter()
            .copied()
            .filter(|&(block_idx, instr_idx)| {
                ssa.block(block_idx)
                    .and_then(|b| b.instructions().get(instr_idx))
                    .is_some_and(Self::is_rewritable)
            })
            .collect();
        let mut removable_phis: BTreeSet<(usize, usize)> =
            tainted_phis_set.iter().copied().collect();

        ssa.retain_unread_removals(&mut removable_instrs, &mut removable_phis);
        if removable_instrs.is_empty() && removable_phis.is_empty() {
            return 0;
        }

        // PHIs to remove (block_idx, phi_idx) in reverse order, so removing
        // one does not shift the index of another still to go.
        let tainted_phis: Vec<(usize, usize)> = removable_phis.iter().rev().copied().collect();

        // 2. Handle tainted instructions (including terminators)
        // First pass: collect what operations to apply (to avoid borrow conflicts)
        let mut actions: Vec<(usize, usize, InstrAction)> = Vec::new();

        for &(block_idx, instr_idx) in &removable_instrs {
            if let Some(block) = ssa.block(block_idx) {
                if let Some(instr) = block.instructions().get(instr_idx) {
                    let action = match instr.op() {
                        SsaOp::Branch {
                            true_target,
                            false_target,
                            ..
                        }
                        | SsaOp::BranchCmp {
                            true_target,
                            false_target,
                            ..
                        } => {
                            let target = Self::choose_branch_target(
                                ssa,
                                *true_target,
                                *false_target,
                                &tainted_instrs,
                                &tainted_phis_set,
                                &can_reach_exit,
                            );
                            Some(InstrAction::Jump(target))
                        }
                        _ if !instr.is_terminator() => Some(InstrAction::Nop),
                        // [`Self::is_rewritable`] keeps these out of the
                        // removal set; the arm is what makes that the only
                        // place the question is answered.
                        _ => None,
                    };

                    if let Some(action) = action {
                        actions.push((block_idx, instr_idx, action));
                    }
                }
            }
        }

        // Second pass: apply everything in one edit session, which repairs
        // what the edits actually changed. Removing an unread definition or a
        // phi is an instruction edit, and folding a branch to one of its own
        // arms only removes an edge, with the phi operands it orphans pruned:
        // none of it needs the function reconstructed, which reads a
        // transformed function's versions back through its rename groups and
        // is not faithful to one.
        let mut count: usize = 0;
        let result = ssa.edit(SsaEditOptions::new(), |editor| {
            for (block_idx, phi_idx) in &tainted_phis {
                editor.remove_phi(*block_idx, *phi_idx)?;
                count = count.saturating_add(1);
            }
            for (block_idx, instr_idx, action) in &actions {
                match action {
                    InstrAction::Nop => editor.nop_instruction(*block_idx, *instr_idx)?,
                    InstrAction::Jump(target) => {
                        editor.fold_terminator_pruning_phis(
                            *block_idx,
                            SsaOp::Jump { target: *target },
                        )?;
                    }
                }
                count = count.saturating_add(1);
            }
            Ok(())
        });
        if result.is_err() {
            // Restored or recorded by the session; reported as no change so the
            // caller's transaction keeps the function it had.
            return 0;
        }

        count
    }
}

impl FunctionPass<CilTarget> for NeutralizationPass<'_> {
    fn name(&self) -> &'static str {
        "neutralization"
    }

    fn description(&self) -> &'static str {
        "Removes instructions referencing removed protection infrastructure"
    }

    /// Folding a branch to one arm removes an edge.
    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::CfgModifying
    }

    /// The rewrite runs in an edit session that repairs what it changed.
    fn repairs_ssa(&self) -> bool {
        true
    }

    fn run(&self, ssa: &mut SsaFunction, env: &PassEnv<'_, CilTarget>) -> analyssa::Result<bool> {
        let neutralized = self.neutralize_method(ssa, env.context().budget());

        if neutralized > 0 {
            // Pushed rather than built through the fluent recorder: an
            // environment hands a pass the sink as a trait object, so the pass
            // does not depend on which sink a host chose.
            env.events().push(Event {
                kind: EventKind::InstructionRemoved,
                method: Some(*env.method()),
                location: None,
                message: format!(
                    "Neutralized {neutralized} instructions referencing removed tokens"
                ),
                pass: Some(FunctionPass::name(self).to_string()),
            });
        }

        Ok(neutralized > 0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        analysis::{
            CallData, Callee, ConstValue, MethodRef, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaType, SsaVarId, WorkBudget,
        },
        deobfuscation::passes::NeutralizationPass,
        metadata::token::Token,
    };

    /// Creates a simple SSA function with instructions referencing tokens.
    fn create_test_ssa() -> (SsaFunction, Token, Token) {
        let mut ssa = SsaFunction::new(0, 1);

        let method_token = Token::new(0x06000001);
        let field_token = Token::new(0x04000001);

        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);

        // Block 0:
        //   v0 = const 42
        //   v1 = call method_token()  <- references method_token
        //   v2 = add v0, v1            <- depends on v1, should be tainted
        //   ret v0                     <- returns the untainted constant
        //
        // The return takes `v0` rather than `v2` so that the tainted chain has
        // no surviving reader. A `ret` is never rewritten, so returning `v2`
        // would keep the whole chain alive - which is its own test below.
        let mut b0 = SsaBlock::new(0);

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));

        // Create a call instruction referencing the method token
        let method_ref = MethodRef::new(method_token);

        b0.add_instruction(
            SsaInstruction::synthetic(
                CallData::new(Some(v1), Callee::Direct(method_ref), vec![]).into(),
            )
            .with_result_type(SsaType::I32),
        );

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
            flags: None,
        }));

        b0.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(v0))));

        ssa.add_block(b0);

        (ssa, method_token, field_token)
    }

    #[test]
    fn test_neutralization_removes_tainted_instructions() {
        let (mut ssa, method_token, _) = create_test_ssa();

        let mut removed = HashSet::new();
        removed.insert(method_token);

        let pass = NeutralizationPass::new(&removed);
        let count = pass.neutralize_method(&mut ssa, &WorkBudget::DEFAULT);

        // Should have neutralized the call and the add (which depends on call result)
        // The const and return should remain (const is independent, return is terminator)
        assert!(
            count >= 2,
            "Expected at least 2 instructions neutralized, got {}",
            count
        );

        // The call and the add it fed are gone; the constant the return reads
        // and the return itself are what is left.
        let block = ssa.block(0).unwrap();
        let ops: Vec<&SsaOp> = block
            .instructions()
            .iter()
            .map(SsaInstruction::op)
            .filter(|op| !matches!(op, SsaOp::Nop))
            .collect();
        assert!(
            matches!(ops.as_slice(), [SsaOp::Const { .. }, SsaOp::Return { .. }]),
            "{ops:?}"
        );
    }

    /// A `ret` this pass cannot rewrite keeps the value it returns alive.
    ///
    /// Only a non-terminator becomes a `Nop` and only a conditional branch
    /// becomes a `Jump`, so a `ret` always survives. Counting it as removed
    /// while it stays is what let the definition it reads be NOPed out from
    /// under it, leaving a method whose reconstruction fails on an undefined
    /// use - `mkaring_normal.exe` had one reduced to `ret v5` with nothing
    /// defining `v5`.
    #[test]
    fn a_returned_value_survives_neutralization() {
        let (mut ssa, method_token, _) = create_test_ssa();

        // Return the tainted value instead of the constant.
        let v2 = SsaVarId::from_index(2);
        ssa.block_mut(0)
            .unwrap()
            .instruction_mut(3)
            .unwrap()
            .set_op(SsaOp::returns(Some(v2)));

        let mut removed = HashSet::new();
        removed.insert(method_token);

        let count =
            NeutralizationPass::new(&removed).neutralize_method(&mut ssa, &WorkBudget::DEFAULT);

        assert_eq!(
            count, 0,
            "nothing may be removed while a surviving `ret` reads it"
        );
        let block = ssa.block(0).unwrap();
        assert!(matches!(block.instructions()[1].op(), SsaOp::Call(_)));
        assert!(matches!(block.instructions()[2].op(), SsaOp::Add { .. }));
    }

    #[test]
    fn test_neutralization_preserves_unrelated_code() {
        let (mut ssa, _, field_token) = create_test_ssa();

        // Remove a token that isn't referenced in our test SSA
        let mut removed = HashSet::new();
        removed.insert(field_token);

        let pass = NeutralizationPass::new(&removed);
        let count = pass.neutralize_method(&mut ssa, &WorkBudget::DEFAULT);

        // Nothing should be neutralized
        assert_eq!(count, 0);

        // All instructions should still be there
        let block = ssa.block(0).unwrap();
        assert!(!matches!(block.instructions()[0].op(), SsaOp::Nop));
        assert!(!matches!(block.instructions()[1].op(), SsaOp::Nop));
        assert!(!matches!(block.instructions()[2].op(), SsaOp::Nop));
    }
}

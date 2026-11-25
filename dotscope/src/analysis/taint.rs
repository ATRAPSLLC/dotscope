//! Re-export shim — generic taint analysis lives in
//! `analyssa::analysis::taint`. This file keeps CIL-specific glue
//! (`TokenTaintBuilder`, `find_token_dependencies`) that uses
//! `op.referenced_tokens()` and the `Token` opaque-id type, both of which
//! analyssa intentionally doesn't see.

use std::collections::HashSet;

#[allow(unused_imports)]
pub use analyssa::analysis::taint::{
    cff_taint_config, find_blocks_jumping_to, PhiTaintMode, TaintAnalysis, TaintConfig, TaintStats,
};
use analyssa::analysis::WorkBudget;

use crate::{
    analysis::{SsaFunction, SsaOpCilExt},
    metadata::token::Token,
};

/// Builder for taint analysis that finds instructions referencing specific
/// CIL metadata tokens.
///
/// Convenience wrapper around the analyssa-side [`TaintAnalysis`] for the
/// common pattern of finding all instructions that reference a set of
/// tokens (methods, types, fields) and propagating taint from those
/// instructions.
#[derive(Debug)]
pub struct TokenTaintBuilder {
    /// Tokens to find references to.
    target_tokens: HashSet<Token>,
    /// Configuration for the taint analysis.
    config: TaintConfig,
}

impl TokenTaintBuilder {
    /// Creates a new token taint builder.
    #[must_use]
    pub fn new(tokens: impl IntoIterator<Item = Token>) -> Self {
        Self {
            target_tokens: tokens.into_iter().collect(),
            config: TaintConfig::bidirectional(),
        }
    }

    /// Sets the taint configuration.
    #[must_use]
    pub fn with_config(mut self, config: TaintConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds and runs the taint analysis on the given SSA function.
    ///
    /// Finds all instructions that reference the target tokens (via
    /// `SsaOpCilExt::referenced_tokens`), marks them as taint sources, and
    /// propagates to fixpoint, or until `budget`'s
    /// [`Budget::TaintRounds`](analyssa::analysis::Budget::TaintRounds) are
    /// spent.
    #[must_use]
    pub fn analyze(self, ssa: &SsaFunction, budget: &WorkBudget) -> TaintAnalysis {
        let mut taint = TaintAnalysis::new(self.config, budget);

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if instr
                .op()
                .referenced_tokens()
                .any(|token| self.target_tokens.contains(&token))
            {
                taint.add_tainted_instr(block_idx, instr_idx, ssa);
            }
        }

        taint.propagate(ssa);
        taint
    }
}

/// Find instructions referencing removed CIL tokens.
///
/// Main entry point for cleanup neutralization. Finds all instructions that
/// reference the given tokens and propagates taint to find all dependent
/// instructions.
#[must_use]
pub fn find_token_dependencies(
    ssa: &SsaFunction,
    removed_tokens: impl IntoIterator<Item = Token>,
    budget: &WorkBudget,
) -> TaintAnalysis {
    TokenTaintBuilder::new(removed_tokens).analyze(ssa, budget)
}
#[cfg(test)]
mod tests {
    use rustc_hash::FxHashSet;

    use super::*;
    use crate::analysis::{
        ConstValue, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    };

    /// Creates a simple SSA function for testing.
    ///
    /// ```text
    /// Block 0:
    ///   v0 = const 42
    ///   v1 = const 10
    ///   v2 = add v0, v1
    ///   jump block 1
    ///
    /// Block 1:
    ///   v3 = mul v2, v0
    ///   ret v3
    /// ```
    fn create_simple_ssa() -> (SsaFunction, SsaVarId, SsaVarId, SsaVarId, SsaVarId) {
        let mut ssa = SsaFunction::new(0, 0);

        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let v3 = SsaVarId::from_index(3);

        // Block 0
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(42),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(10),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2,
            left: v0,
            right: v1,
            flags: None,
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // Block 1
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Mul {
            dest: v3,
            left: v2,
            right: v0,
            flags: None,
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(v3))));
        ssa.add_block(b1);

        (ssa, v0, v1, v2, v3)
    }

    /// Creates an SSA function with a PHI node for testing.
    ///
    /// ```text
    /// Block 0:
    ///   v0 = const 1
    ///   jump block 2
    ///
    /// Block 1:
    ///   v1 = const 2
    ///   jump block 2
    ///
    /// Block 2:
    ///   v2 = phi(v0 from 0, v1 from 1)
    ///   ret v2
    /// ```
    fn create_phi_ssa() -> (SsaFunction, SsaVarId, SsaVarId, SsaVarId) {
        let mut ssa = SsaFunction::new(0, 0);

        let v0 = SsaVarId::from_index(4);
        let v1 = SsaVarId::from_index(5);
        let v2 = SsaVarId::from_index(6);

        // Block 0
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0,
            value: ConstValue::I32(1),
        }));
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b0);

        // Block 1
        let mut b1 = SsaBlock::new(1);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1,
            value: ConstValue::I32(2),
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(b1);

        // Block 2 with PHI
        let mut b2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(v2, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0, 0));
        phi.add_operand(PhiOperand::new(v1, 1));
        b2.add_phi(phi);
        b2.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(v2))));
        ssa.add_block(b2);

        (ssa, v0, v1, v2)
    }

    #[test]
    fn test_forward_propagation() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::new(TaintConfig::forward_only(), &WorkBudget::DEFAULT);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is the source
        assert!(taint.is_var_tainted(v0));
        // v1 is not tainted (independent constant)
        assert!(!taint.is_var_tainted(v1));
        // v2 uses v0, so it's tainted
        assert!(taint.is_var_tainted(v2));
        // v3 uses v2 and v0, so it's tainted
        assert!(taint.is_var_tainted(v3));

        // Instructions using tainted vars should be tainted
        assert!(taint.is_instr_tainted(0, 2)); // add v0, v1
        assert!(taint.is_instr_tainted(1, 0)); // mul v2, v0
    }

    #[test]
    fn test_backward_propagation() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::new(TaintConfig::bidirectional(), &WorkBudget::DEFAULT);
        taint.add_tainted_var(v3);
        taint.propagate(&ssa);

        // v3 is the source
        assert!(taint.is_var_tainted(v3));
        // v2 is used to compute v3, so backward taint
        assert!(taint.is_var_tainted(v2));
        // v0 is used to compute v3 and v2, so backward taint
        assert!(taint.is_var_tainted(v0));
        // v1 is used to compute v2, so backward taint
        assert!(taint.is_var_tainted(v1));
    }

    #[test]
    fn test_phi_taint_if_any_operand() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::TaintIfAnyOperand,
        };

        let mut taint = TaintAnalysis::new(config, &WorkBudget::DEFAULT);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is tainted
        assert!(taint.is_var_tainted(v0));
        // v1 is not tainted
        assert!(!taint.is_var_tainted(v1));
        // v2 should be tainted because v0 (one of its operands) is tainted
        assert!(taint.is_var_tainted(v2));
        // The PHI should be marked as tainted
        assert!(taint.is_phi_tainted(2, 0));
    }

    #[test]
    fn test_phi_taint_all_operands() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: false,
            backward: true,
            phi_mode: PhiTaintMode::TaintAllOperands,
        };

        let mut taint = TaintAnalysis::new(config, &WorkBudget::DEFAULT);
        taint.add_tainted_var(v2);
        taint.propagate(&ssa);

        // v2 is the source
        assert!(taint.is_var_tainted(v2));
        // Both v0 and v1 should be tainted (backward through PHI)
        assert!(taint.is_var_tainted(v0));
        assert!(taint.is_var_tainted(v1));
    }

    #[test]
    fn test_phi_no_propagation() {
        let (ssa, v0, _v1, v2) = create_phi_ssa();

        let config = TaintConfig {
            forward: true,
            backward: false,
            phi_mode: PhiTaintMode::NoPropagation,
        };

        let mut taint = TaintAnalysis::new(config, &WorkBudget::DEFAULT);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        // v0 is tainted
        assert!(taint.is_var_tainted(v0));
        // v2 should NOT be tainted because PHI propagation is disabled
        assert!(!taint.is_var_tainted(v2));
    }

    #[test]
    fn test_phi_from_specific_predecessors() {
        let (ssa, v0, v1, v2) = create_phi_ssa();

        // Only allow propagation from predecessor 0
        let mut preds = FxHashSet::default();
        preds.insert(0);

        let config = TaintConfig {
            forward: false,
            backward: true,
            phi_mode: PhiTaintMode::TaintFromPredecessors(preds),
        };

        let mut taint = TaintAnalysis::new(config, &WorkBudget::DEFAULT);
        taint.add_tainted_var(v2);
        taint.propagate(&ssa);

        // v2 is the source
        assert!(taint.is_var_tainted(v2));
        // v0 should be tainted (from predecessor 0)
        assert!(taint.is_var_tainted(v0));
        // v1 should NOT be tainted (from predecessor 1, not in the set)
        assert!(!taint.is_var_tainted(v1));
    }

    #[test]
    fn test_instruction_taint_source() {
        let (ssa, v0, v1, v2, v3) = create_simple_ssa();

        let mut taint = TaintAnalysis::new(TaintConfig::forward_only(), &WorkBudget::DEFAULT);
        // Mark the add instruction as a taint source
        taint.add_tainted_instr(0, 2, &ssa);
        taint.propagate(&ssa);

        // The add's result (v2) should be tainted
        assert!(taint.is_var_tainted(v2));
        // v3 uses v2, so it should be tainted
        assert!(taint.is_var_tainted(v3));
        // v0 and v1 should NOT be tainted (they're inputs, not outputs)
        assert!(!taint.is_var_tainted(v0));
        assert!(!taint.is_var_tainted(v1));
    }

    #[test]
    fn test_stats() {
        let (ssa, v0, _, _, _) = create_simple_ssa();

        let mut taint = TaintAnalysis::new(TaintConfig::forward_only(), &WorkBudget::DEFAULT);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        let stats = taint.stats();
        assert!(stats.iterations > 0);
        assert!(stats.tainted_vars > 0);
    }

    #[test]
    fn test_clear() {
        let (ssa, v0, _, _, _) = create_simple_ssa();

        let mut taint = TaintAnalysis::new(TaintConfig::forward_only(), &WorkBudget::DEFAULT);
        taint.add_tainted_var(v0);
        taint.propagate(&ssa);

        assert!(taint.tainted_var_count() > 0);

        taint.clear();

        assert_eq!(taint.tainted_var_count(), 0);
        assert_eq!(taint.tainted_instr_count(), 0);
    }
}

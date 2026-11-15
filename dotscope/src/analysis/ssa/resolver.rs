//! What earlier passes proved about a CIL function's values, loaded into
//! analyssa's demand-driven constant resolver ([`ValueResolver`]).
//!
//! The resolver composes the constant evaluator, the uniform-phi analysis
//! and, optionally, path-aware tracing; this crate adds what only CIL facts
//! say: constant propagation and the decryptors record what they proved on the
//! variable itself ([`CilVariableFacts::known_value`]).
//!
//! # Example
//!
//! ```no_run
//! use dotscope::analysis::{CilTarget, SsaFunction, ValueResolver, ValueResolverCilExt};
//!
//! # fn resolve(ssa: &SsaFunction, some_var: dotscope::analysis::SsaVarId) {
//! let mut resolver = ValueResolver::new(ssa, CilTarget::x64().machine()).with_path_aware_fallback();
//! resolver.load_known_values();
//!
//! if let Some(value) = resolver.resolve(some_var) {
//!     println!("Resolved to: {:?}", value);
//! }
//! # }
//! ```
//!
//! [`CilVariableFacts::known_value`]: crate::analysis::ssa::facts::CilVariableFacts::known_value

use crate::analysis::ssa::{target::CilTarget, ConstValue, SsaVarId, ValueResolver};

/// Loads what earlier passes proved about a CIL function's values into a
/// [`ValueResolver`].
pub trait ValueResolverCilExt {
    /// Loads what earlier passes proved about this function's values into the
    /// resolver.
    ///
    /// Read from the values themselves - constant propagation and the
    /// decryptors record what they proved on the variable - so this needs
    /// neither a method token nor a context. It cannot be asked about a
    /// function other than the one being resolved, which is the mistake a
    /// token would make possible: the context's copy of a method is not the
    /// copy a pass is transforming.
    fn load_known_values(&mut self);
}

impl ValueResolverCilExt for ValueResolver<'_, CilTarget> {
    fn load_known_values(&mut self) {
        let known: Vec<(SsaVarId, ConstValue)> = self
            .ssa()
            .variables()
            .iter()
            .filter_map(|variable| {
                variable
                    .facts()
                    .known_value()
                    .map(|value| (variable.id(), value.clone()))
            })
            .collect();
        for (var, value) in known {
            self.set_known(var, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{
        ssa::{
            ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction, SsaInstruction, SsaOp,
            SsaType, SsaVarId, VariableOrigin,
        },
        CilTarget,
    };

    #[test]
    fn test_resolve_const() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let var_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: var_id,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(var_id), Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_resolve_arithmetic_chain() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        // v0 = 10
        let v0_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        // v1 = 3
        let v1_id = ssa.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            SsaType::Unknown,
        );

        // v2 = v0 + v1
        let v2_id = ssa.create_variable(
            VariableOrigin::Local(2),
            0,
            DefSite::instruction(0, 2),
            SsaType::Unknown,
        );

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(10),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(3),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: v2_id,
            left: v0_id,
            right: v1_id,
            flags: None,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(v2_id), Some(ConstValue::I32(13)));
    }

    #[test]
    fn test_resolve_phi_uniform() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 0);

        // Block 0: v0 = 42, jump to block 2
        let v0_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block0);

        // Block 1: v1 = 42, jump to block 2
        let v1_id = ssa.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(42),
        }));
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block1);

        // Block 2: phi(v0, v1) - both are 42
        let phi_result_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::phi(2),
            SsaType::Unknown,
        );

        let mut block2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(phi_result_id, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0_id, 0));
        phi.add_operand(PhiOperand::new(v1_id, 1));
        block2.add_phi(phi);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
        ssa.add_block(block2);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(phi_result_id), Some(ConstValue::I32(42)));
    }

    #[test]
    fn test_resolve_phi_non_uniform() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 0);

        // v0 = 42
        let v0_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        let mut block0 = SsaBlock::new(0);
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(42),
        }));
        block0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block0);

        // v1 = 99 (different)
        let v1_id = ssa.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(1, 0),
            SsaType::Unknown,
        );

        let mut block1 = SsaBlock::new(1);
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(99),
        }));
        block1.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 2 }));
        ssa.add_block(block1);

        // phi(v0, v1) - different values
        let phi_result_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::phi(2),
            SsaType::Unknown,
        );

        let mut block2 = SsaBlock::new(2);
        let mut phi = PhiNode::new(phi_result_id, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(v0_id, 0));
        phi.add_operand(PhiOperand::new(v1_id, 1));
        block2.add_phi(phi);
        block2.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
        ssa.add_block(block2);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(phi_result_id), None);
    }

    #[test]
    fn test_set_known() {
        let ssa: SsaFunction = SsaFunction::new(0, 0);
        let var_id = SsaVarId::from_index(0);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        resolver.set_known(var_id, ConstValue::I32(999));

        assert_eq!(resolver.resolve(var_id), Some(ConstValue::I32(999)));
    }

    /// What an earlier pass proved is read from the values it proved it about.
    #[test]
    fn test_load_known_values() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 2);
        let var1 = ssa.create_variable(VariableOrigin::Local(0), 0, DefSite::entry(), SsaType::I32);
        let var2 = ssa.create_variable(VariableOrigin::Local(1), 0, DefSite::entry(), SsaType::I32);
        for (var, value) in [(var1, 10), (var2, 20)] {
            if let Some(variable) = ssa.variable_mut(var) {
                variable.facts_mut().set_known_value(ConstValue::I32(value));
            }
        }

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        resolver.load_known_values();

        assert_eq!(resolver.resolve(var1), Some(ConstValue::I32(10)));
        assert_eq!(resolver.resolve(var2), Some(ConstValue::I32(20)));
    }

    #[test]
    fn test_resolve_all_success() {
        let ssa: SsaFunction = SsaFunction::new(0, 0);

        let var1 = SsaVarId::from_index(0);
        let var2 = SsaVarId::from_index(1);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        resolver.set_known(var1, ConstValue::I32(1));
        resolver.set_known(var2, ConstValue::I32(2));

        let result = resolver.resolve_all(&[var1, var2]);
        assert_eq!(result, Some(vec![ConstValue::I32(1), ConstValue::I32(2)]));
    }

    #[test]
    fn test_resolve_all_partial_failure() {
        let ssa: SsaFunction = SsaFunction::new(0, 0);

        let var1 = SsaVarId::from_index(0);
        let var2 = SsaVarId::from_index(1);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        resolver.set_known(var1, ConstValue::I32(1));
        // var2 unknown

        assert_eq!(resolver.resolve_all(&[var1, var2]), None);
    }

    #[test]
    fn test_resolve_all_empty() {
        let ssa: SsaFunction = SsaFunction::new(0, 0);
        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());

        assert_eq!(resolver.resolve_all(&[]), Some(vec![]));
    }

    #[test]
    fn test_resolve_unknown_var() {
        let ssa: SsaFunction = SsaFunction::new(0, 0);
        let unknown = SsaVarId::from_index(0);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(unknown), None);
    }

    #[test]
    fn test_resolve_xor_both_const() {
        let mut ssa: SsaFunction = SsaFunction::new(0, 0);
        let mut block = SsaBlock::new(0);

        let v0_id = ssa.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            SsaType::Unknown,
        );

        let v1_id = ssa.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            SsaType::Unknown,
        );

        let v2_id = ssa.create_variable(
            VariableOrigin::Local(2),
            0,
            DefSite::instruction(0, 2),
            SsaType::Unknown,
        );

        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v0_id,
            value: ConstValue::I32(0xFF),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: v1_id,
            value: ConstValue::I32(0x0F),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Xor {
            dest: v2_id,
            left: v0_id,
            right: v1_id,
            flags: None,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
        ssa.add_block(block);

        let mut resolver = ValueResolver::new(&ssa, CilTarget::x64().machine());
        assert_eq!(resolver.resolve(v2_id), Some(ConstValue::I32(0xF0)));
    }
}

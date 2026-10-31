use std::{collections::BTreeMap, sync::Arc};

use crate::{
    analysis::{
        CallGraph, CmpKind, ConstValue, ConstValueCilExt, FieldRef, MethodRef, SsaFunction,
        SsaFunctionBuilder, SsaOp, SsaType, SsaVarId, SsaVerifier, VerifierError, VerifyLevel,
    },
    compiler::{
        passes::constants::{AlgebraicResult, ConstantPropagationPass, StringFoldOp},
        CompilerContext, EventLog, SsaPass,
    },
    metadata::{token::Token, typesystem::PointerSize},
    testkit::{
        helpers::{method_token, mono_mscorlib, test_assembly_arc},
        passes::run_verified,
    },
};

/// Creates a test compiler context with the standard test assembly
/// pre-attached. The analyssa pass scheduler reaches the assembly through
/// [`CompilerContext::assembly`], so passes that need it will fail
/// without this setup.
fn test_context() -> CompilerContext {
    let call_graph = Arc::new(CallGraph::new());
    let ctx = CompilerContext::new(call_graph);
    ctx.set_assembly(test_assembly_arc());
    ctx
}

#[test]
fn test_pass_creation() {
    let pass = ConstantPropagationPass::new(10);
    assert_eq!(pass.name(), "constant-propagation");
    assert!(!pass.description().is_empty());
}

#[test]
fn test_pass_default() {
    let pass = ConstantPropagationPass::new(10);
    assert_eq!(pass.name(), "constant-propagation");
}

#[test]
fn test_conv_i32_to_i8() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::I8, false, 8),
        Some(ConstValue::I8(42))
    );
}

#[test]
fn test_conv_i32_to_i8_truncate() {
    let operand: ConstValue = ConstValue::I32(1000);
    // 1000 truncated to i8 is -24 (1000 & 0xFF = 232, as signed = -24)
    assert_eq!(
        operand.convert_to(&SsaType::I8, false, 8),
        Some(ConstValue::I8(-24))
    );
}

#[test]
fn test_conv_i32_to_i64() {
    let operand: ConstValue = ConstValue::I32(-42);
    assert_eq!(
        operand.convert_to(&SsaType::I64, false, 8),
        Some(ConstValue::I64(-42))
    );
}

#[test]
fn test_conv_to_bool_nonzero() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::Bool, false, 8),
        Some(ConstValue::True)
    );
}

#[test]
fn test_conv_to_bool_zero() {
    let operand: ConstValue = ConstValue::I32(0);
    assert_eq!(
        operand.convert_to(&SsaType::Bool, false, 8),
        Some(ConstValue::False)
    );
}

#[test]
fn test_conv_to_f32() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::F32, false, 8),
        Some(ConstValue::from(42.0_f32))
    );
}

#[test]
fn test_conv_ovf_in_range() {
    let operand: ConstValue = ConstValue::I32(100);
    assert_eq!(
        operand.convert_to_checked(&SsaType::I8, false, 8),
        Some(ConstValue::I8(100))
    );
}

#[test]
fn test_conv_ovf_out_of_range() {
    let operand: ConstValue = ConstValue::I32(1000);
    assert_eq!(operand.convert_to_checked(&SsaType::I8, false, 8), None); // Would overflow
}

#[test]
fn test_conv_u8() {
    let operand: ConstValue = ConstValue::I32(200);
    assert_eq!(
        operand.convert_to(&SsaType::U8, false, 8),
        Some(ConstValue::U8(200))
    );
}

#[test]
fn test_conv_u16() {
    let operand: ConstValue = ConstValue::I32(50000);
    assert_eq!(
        operand.convert_to(&SsaType::U16, false, 8),
        Some(ConstValue::U16(50000))
    );
}

#[test]
fn test_conv_u32() {
    let operand: ConstValue = ConstValue::I64(3_000_000_000);
    assert_eq!(
        operand.convert_to(&SsaType::U32, false, 8),
        Some(ConstValue::U32(3_000_000_000))
    );
}

#[test]
fn test_conv_u64() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::U64, false, 8),
        Some(ConstValue::U64(42))
    );
}

#[test]
fn test_conv_f64() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::F64, false, 8),
        Some(ConstValue::from(42.0_f64))
    );
}

#[test]
fn test_conv_native_int() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::NativeInt, false, 8),
        Some(ConstValue::NativeInt(42))
    );
}

#[test]
fn test_conv_native_uint() {
    let operand: ConstValue = ConstValue::I32(42);
    assert_eq!(
        operand.convert_to(&SsaType::NativeUInt, false, 8),
        Some(ConstValue::NativeUInt(42))
    );
}

#[test]
fn test_conv_char() {
    let operand: ConstValue = ConstValue::I32(65); // 'A'
    assert_eq!(
        operand.convert_to(&SsaType::Char, false, 8),
        Some(ConstValue::U16(65))
    );
}

#[test]
fn test_identity_add_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Add {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    // Result should be a Copy to v0 (since v0 has value 42, not a zero)
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_mul_one() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(1));

    let op = SsaOp::Mul {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_and_minus_one() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(-1));

    let op = SsaOp::And {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_absorbing_mul_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Mul {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(0));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_absorbing_and_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::And {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(0));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_absorbing_or_minus_one() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(-1));

    let op = SsaOp::Or {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Constant { dest, value }) => {
            assert_eq!(dest, v2);
            assert_eq!(value, ConstValue::I32(-1));
        }
        _ => panic!("Expected Constant result"),
    }
}

#[test]
fn test_add_ovf_no_overflow() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(100));
    constants.insert(v1, ConstValue::I32(50));

    let op = SsaOp::AddOvf {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
        flags: None,
    };

    let result = ConstantPropagationPass::check_overflow_op(&op, &constants, PointerSize::Bit64);
    assert!(result.is_some());
}

#[test]
fn test_mul_ovf_with_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(100));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::MulOvf {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
        flags: None,
    };

    // x * 0 = 0, even with overflow check
    let result = ConstantPropagationPass::check_overflow_op(&op, &constants, PointerSize::Bit64);
    assert_eq!(result, Some((v2, ConstValue::I32(0))));
}

#[test]
fn test_pass_empty_function() {
    let pass = ConstantPropagationPass::new(10);
    let mut ssa = SsaFunctionBuilder::new(0, 0).build_with(|_f| {}).unwrap();
    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_pass_simple_folding() {
    let pass = ConstantPropagationPass::new(10);
    // Create a block with: v0 = 5, v1 = 3, v2 = add v0, v1
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(5);
                let v1 = b.const_i32(3);
                let _v2 = b.add(v0, v1);
                b.ret();
            });
        })
        .unwrap();

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that v2 was folded to constant 8
    let changed = result.unwrap();
    assert!(changed);

    // Verify the instruction was replaced
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::Const { value, .. } = instr.op() {
        assert_eq!(*value, ConstValue::I32(8));
    } else {
        panic!("Expected Const instruction");
    }
}

#[test]
fn test_pass_branch_simplification() {
    let pass = ConstantPropagationPass::new(10);
    // Block 0: v0 = true, branch v0, B1, B2
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_true();
                b.branch(cond, 1, 2);
            });
            f.block(1, |b| b.ret());
            f.block(2, |b| b.ret());
        })
        .unwrap();

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that branch was simplified to jump
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.control_terminator() {
        assert_eq!(*target, 1);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_pass_switch_simplification() {
    let pass = ConstantPropagationPass::new(10);
    // Block 0: v0 = 1, switch v0, [B1, B2, B3], default=B4
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(1);
                b.switch(v0, vec![1, 2, 3], 4);
            });
            // Blocks 1-4: return
            f.block(1, |b| b.ret());
            f.block(2, |b| b.ret());
            f.block(3, |b| b.ret());
            f.block(4, |b| b.ret());
        })
        .unwrap();

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that switch was simplified to jump to target 2 (index 1)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.control_terminator() {
        assert_eq!(*target, 2);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_constants_cached_in_context() {
    let pass = ConstantPropagationPass::new(10);
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    v0_out = v0;
                    b.ret_val(v0);
                });
            })
            .unwrap();
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // What the pass proved is recorded on the value it proved it about, in the
    // function the pass was handed - not in a table beside it, which would
    // describe whichever value inherited the id after the next renumbering.
    assert_eq!(
        ssa.variable(v0)
            .and_then(|variable| variable.facts().known_value()),
        Some(&ConstValue::I32(42))
    );
}

#[test]
fn test_identity_shl_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Shl {
        dest: v2,
        value: v0,
        amount: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_shr_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Shr {
        dest: v2,
        value: v0,
        amount: v1,
        unsigned: false,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_xor_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Xor {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_div_one() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(1));

    let op = SsaOp::Div {
        dest: v2,
        left: v0,
        right: v1,
        unsigned: false,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_identity_sub_zero() {
    let mut constants = BTreeMap::new();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);
    constants.insert(v0, ConstValue::I32(42));
    constants.insert(v1, ConstValue::I32(0));

    let op = SsaOp::Sub {
        dest: v2,
        left: v0,
        right: v1,
        flags: None,
    };

    let result =
        ConstantPropagationPass::check_algebraic_identity(&op, &constants, Some(&SsaType::I32));
    match result {
        Some(AlgebraicResult::Copy { dest, src }) => {
            assert_eq!(dest, v2);
            assert_eq!(src, v0);
        }
        _ => panic!("Expected Copy result"),
    }
}

#[test]
fn test_chained_constant_folding() {
    let pass = ConstantPropagationPass::new(10);
    // v0 = 2, v1 = 3, v2 = v0 + v1, v3 = 2, v4 = v2 * v3, v5 = 0, v6 = v4 + v5
    let (mut ssa, v4) = {
        let mut v4_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(2);
                    let v1 = b.const_i32(3);
                    let v2 = b.add(v0, v1); // v2 = 5
                    let v3 = b.const_i32(2);
                    let v4 = b.mul(v2, v3); // v4 = 10
                    v4_out = v4;
                    let v5 = b.const_i32(0);
                    // Now add v4 + 0 (identity) - should fold to 10
                    let v6 = b.add(v4, v5);
                    b.ret_val(v6);
                });
            })
            .unwrap();
        (ssa, v4_out)
    };

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that v4 was folded to 10, on the value itself.
    assert_eq!(
        ssa.variable(v4)
            .and_then(|variable| variable.facts().known_value()),
        Some(&ConstValue::I32(10))
    );
}

#[test]
fn test_branch_false_condition() {
    let pass = ConstantPropagationPass::new(10);
    // Block 0: v0 = false, branch v0, B1, B2
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let cond = b.const_false();
                b.branch(cond, 1, 2);
            });
            f.block(1, |b| b.ret());
            f.block(2, |b| b.ret());
        })
        .unwrap();

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that branch was simplified to jump to false branch (target 2)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.control_terminator() {
        assert_eq!(*target, 2);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_switch_out_of_range_uses_default() {
    let pass = ConstantPropagationPass::new(10);
    // Block 0: v0 = 100 (out of range), switch v0, [B1, B2, B3], default=B4
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let v0 = b.const_i32(100); // Out of range
                b.switch(v0, vec![1, 2, 3], 4);
            });
            // Blocks 1-4: return
            f.block(1, |b| b.ret());
            f.block(2, |b| b.ret());
            f.block(3, |b| b.ret());
            f.block(4, |b| b.ret());
        })
        .unwrap();

    let method_token = Token::new(0x0600_0001);
    let ctx = test_context();

    let result = run_verified(&pass, &mut ssa, &MethodRef::from(method_token), &ctx);
    assert!(result.is_ok());

    // Check that switch was simplified to jump to default (target 4)
    let block = ssa.block(0).unwrap();
    if let Some(SsaOp::Jump { target }) = block.control_terminator() {
        assert_eq!(*target, 4);
    } else {
        panic!("Expected Jump instruction");
    }
}

#[test]
fn test_types_match_identical() {
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::I64
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::F32,
        &SsaType::F32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::F64,
        &SsaType::F64
    ));
}

#[test]
fn test_types_match_stack_equivalence() {
    // Small integers promote to I32 on the stack
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I8,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U8,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I16,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U16,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::Bool,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::Char,
        &SsaType::I32
    ));

    // U32 and I32 are interchangeable
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U32,
        &SsaType::I32
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::U32
    ));

    // I64 and U64 are interchangeable
    assert!(ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::U64
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::U64,
        &SsaType::I64
    ));

    // Native int types
    assert!(ConstantPropagationPass::types_match(
        &SsaType::NativeInt,
        &SsaType::NativeUInt
    ));
    assert!(ConstantPropagationPass::types_match(
        &SsaType::NativeUInt,
        &SsaType::NativeInt
    ));
}

#[test]
fn test_types_no_match() {
    // Floats don't match integers
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::F32,
        &SsaType::I32
    ));
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::F32
    ));

    // Different sizes don't match
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I32,
        &SsaType::I64
    ));
    assert!(!ConstantPropagationPass::types_match(
        &SsaType::I64,
        &SsaType::I32
    ));
}

#[test]
fn test_is_safe_widening_chain_same_sign() {
    // Unsigned widening: source <= inner < outer
    // conv.u32(conv.u8(x)) where x is u8 - both conversions widen
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U8,  // inner target (same as source - no-op)
        &SsaType::U32, // outer target
        true,
        true
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U16, // inner target
        &SsaType::U64, // outer target
        true,
        true
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U16, // source
        &SsaType::U32, // inner target
        &SsaType::U64, // outer target
        true,
        true
    ));

    // Signed widening: source <= inner < outer
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I8,  // inner target
        &SsaType::I32, // outer target
        false,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I16, // inner target
        &SsaType::I64, // outer target
        false,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I16, // source
        &SsaType::I32, // inner target
        &SsaType::I64, // outer target
        false,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_unsigned_to_signed() {
    // unsigned to signed widening is safe (zero extend then reinterpret)
    // conv.i32(conv.u8(x)) where x is u8
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U8,  // inner target
        &SsaType::I32, // outer target
        true,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U16, // inner target
        &SsaType::I64, // outer target
        true,
        false
    ));
    assert!(ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U16, // source
        &SsaType::U32, // inner target
        &SsaType::I64, // outer target
        true,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_signed_to_unsigned() {
    // signed to unsigned widening is NOT safe (sign extend vs zero extend)
    // conv.u32(conv.i8(x)) where x is i8 - inner is signed, outer is unsigned
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I8,  // inner target
        &SsaType::U32, // outer target
        false,
        true
    ));
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I8,  // source
        &SsaType::I16, // inner target
        &SsaType::U64, // outer target
        false,
        true
    ));
}

#[test]
fn test_is_safe_widening_chain_narrowing_rejected() {
    // Outer narrowing is NOT safe - inner >= outer means data loss
    // conv.i32(conv.i64(x)) where x is i32 - outer narrows from i64 to i32
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source
        &SsaType::I64, // inner target
        &SsaType::I32, // outer target (narrowing!)
        false,
        false
    ));
    // conv.u8(conv.u32(x)) where x is u8 - outer narrows from u32 to u8
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::U8,  // source
        &SsaType::U32, // inner target
        &SsaType::U8,  // outer target (narrowing!)
        true,
        true
    ));

    // Inner narrowing is also NOT safe - source > inner means truncation
    // conv.i32(conv.u1(x)) where x is i32 - inner truncates i32 to u8
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source (larger than inner!)
        &SsaType::U8,  // inner target (truncates source)
        &SsaType::I32, // outer target
        true,
        false
    ));
}

#[test]
fn test_is_safe_widening_chain_float_rejected() {
    // Float conversions are NOT safe - precision loss
    // conv.f64(conv.f32(x)) - float widening can lose precision
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::F32, // source
        &SsaType::F32, // inner target
        &SsaType::F64, // outer target
        false,
        false
    ));
    // conv.f64(conv.i32(x)) - int to float conversion
    assert!(!ConstantPropagationPass::is_safe_widening_chain(
        &SsaType::I32, // source
        &SsaType::I32, // inner target
        &SsaType::F64, // outer target
        false,
        false
    ));
}

#[test]
fn test_duplicate_conversion_elimination() {
    // conv.i4(conv.i4(v0)) should become conv.i4(v0)
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // v0 = some value (simulated by const for simplicity)
                    let v0 = b.const_i64(42);
                    v0_out = v0;
                    // v1 = conv.i4 v0
                    let v1 = b.conv(v0, SsaType::I32);
                    // v2 = conv.i4 v1 (duplicate!)
                    let v2 = b.conv(v1, SsaType::I32);
                    b.ret_val(v2);
                });
            })
            .unwrap();
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should now be conv.i4(v0), not conv.i4(v1)
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::IntConv { operand, .. }
    | SsaOp::IntToPtr { operand, .. }
    | SsaOp::PtrToInt { operand, .. }
    | SsaOp::IntToFloat { operand, .. }
    | SsaOp::FloatToInt { operand, .. }
    | SsaOp::FloatConv { operand, .. } = instr.op()
    {
        assert_eq!(
            *operand, v0,
            "Duplicate conversion should use original operand"
        );
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_widening_chain_elimination() {
    // conv.i8(conv.i4(v0)) should become conv.i8(v0) when unsigned
    let (mut ssa, v0) = {
        let mut v0_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // v0 = some value
                    let v0 = b.const_val(ConstValue::U8(42));
                    v0_out = v0;
                    // v1 = conv.u4 v0 (u8 -> u32)
                    let v1 = b.conv_un(v0, SsaType::U32);
                    // v2 = conv.u8 v1 (u32 -> u64 widening chain)
                    let v2 = b.conv_un(v1, SsaType::U64);
                    b.ret_val(v2);
                });
            })
            .unwrap();
        (ssa, v0_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should now be conv.u8(v0), not conv.u8(v1)
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::IntConv {
        operand, target, ..
    } = instr.op()
    {
        assert_eq!(*operand, v0, "Widening chain should use original operand");
        assert_eq!(*target, SsaType::U64);
    } else {
        panic!("Expected IntConv instruction");
    }
}

#[test]
fn test_overflow_checked_conversion_not_eliminated() {
    // conv.ovf.i4(conv.i4(v0)) should NOT eliminate the outer conversion
    let (mut ssa, v1) = {
        let mut v1_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i64(42);
                    // v1 = conv.i4 v0
                    let v1 = b.conv(v0, SsaType::I32);
                    v1_out = v1;
                    // v2 = conv.ovf.i4 v1 (overflow check!)
                    let v2 = b.conv_ovf(v1, SsaType::I32);
                    b.ret_val(v2);
                });
            })
            .unwrap();
        (ssa, v1_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should still be conv.ovf.i4(v1), not modified
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::IntConv {
        operand,
        overflow_check,
        ..
    } = instr.op()
    {
        assert_eq!(
            *operand, v1,
            "Overflow-checked conversion should not be modified"
        );
        assert!(*overflow_check);
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_float_widening_not_eliminated() {
    // conv.r8(conv.r4(v0)) should NOT be simplified (precision loss)
    let (mut ssa, v1) = {
        let mut v1_out = SsaVarId::from_index(0);
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(42);
                    // v1 = conv.r4 v0 (int -> float32)
                    let v1 = b.conv(v0, SsaType::F32);
                    v1_out = v1;
                    // v2 = conv.r8 v1 (float32 -> float64, can lose precision info!)
                    let v2 = b.conv(v1, SsaType::F64);
                    b.ret_val(v2);
                });
            })
            .unwrap();
        (ssa, v1_out)
    };

    let method_token = Token::new(0x0600_0001);
    let mut changes = EventLog::new();

    ConstantPropagationPass::eliminate_redundant_conversions(&mut ssa, method_token, &mut changes);

    // v2 should still use v1, not v0
    let block = ssa.block(0).unwrap();
    let instr = &block.instructions()[2];
    if let SsaOp::IntConv { operand, .. }
    | SsaOp::IntToPtr { operand, .. }
    | SsaOp::PtrToInt { operand, .. }
    | SsaOp::IntToFloat { operand, .. }
    | SsaOp::FloatToInt { operand, .. }
    | SsaOp::FloatConv { operand, .. } = instr.op()
    {
        assert_eq!(
            *operand, v1,
            "Float conversion chain should not be simplified"
        );
    } else {
        panic!("Expected Conv instruction");
    }
}

#[test]
fn test_try_fold_concat2_decrypted_strings() {
    let assembly = test_assembly_arc();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);

    let mut constants = BTreeMap::new();
    constants.insert(v0, ConstValue::DecryptedString("Hello".into()));
    constants.insert(v1, ConstValue::DecryptedString(", World".into()));

    // Use a fake token — identify_string_op will fail to resolve it through the
    // assembly, so we test the folding logic indirectly through fold_string_operations.
    // Instead, test the concat logic directly.
    let strings: Option<Vec<String>> = [v0, v1]
        .iter()
        .map(|arg| {
            constants
                .get(arg)
                .and_then(|v| v.as_string_content(&assembly))
        })
        .collect();
    let result = strings.unwrap().concat();
    assert_eq!(result, "Hello, World");
}

#[test]
fn test_try_fold_concat_with_non_constant_arg() {
    let assembly = test_assembly_arc();
    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);

    let mut constants = BTreeMap::new();
    constants.insert(v0, ConstValue::DecryptedString("Hello".into()));
    // v1 is NOT in constants — simulates a non-constant argument

    let strings: Option<Vec<String>> = [v0, v1]
        .iter()
        .map(|arg| {
            constants
                .get(arg)
                .and_then(|v| v.as_string_content(&assembly))
        })
        .collect();
    assert!(strings.is_none(), "Should fail when an arg is not constant");
}

#[test]
fn test_fold_string_operations_with_decrypted_concat() {
    let assembly = test_assembly_arc();
    let method_token = Token::new(0x06000001);

    let v0 = SsaVarId::from_index(0);
    let v1 = SsaVarId::from_index(1);
    let v2 = SsaVarId::from_index(2);

    // Build an SSA with two DecryptedString consts and a call to an unknown method
    // (the call won't resolve through the test assembly, but we still test the
    // infrastructure doesn't crash)
    let mut ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                b.op(SsaOp::Const {
                    dest: v0,
                    value: ConstValue::DecryptedString("Sys".into()),
                });
                b.op(SsaOp::Const {
                    dest: v1,
                    value: ConstValue::DecryptedString("tem".into()),
                });
                b.op(SsaOp::Call {
                    dest: Some(v2),
                    method: MethodRef::new(Token::new(0x0A000099)), // fake MemberRef
                    args: vec![v0, v1],
                    effects: None,
                });
                b.ret();
            });
        })
        .unwrap();

    let mut constants = BTreeMap::new();
    constants.insert(v0, ConstValue::DecryptedString("Sys".into()));
    constants.insert(v1, ConstValue::DecryptedString("tem".into()));

    let mut changes = EventLog::new();

    // This won't actually fold (the fake token won't resolve through assembly),
    // but it exercises the code path without panicking.
    ConstantPropagationPass::fold_string_operations(
        &mut ssa,
        &mut constants,
        method_token,
        &mut changes,
        &assembly,
    );

    // v2 should NOT be in constants (fake method token didn't resolve to System.String)
    assert!(
        !constants.contains_key(&v2),
        "Unresolvable method should not fold"
    );
}

/// A function returning `left rem right` (`rem.un` when `unsigned`), and the
/// remainder it returns.
fn remainder_function(
    left: ConstValue,
    right: ConstValue,
    unsigned: bool,
) -> (SsaFunction, SsaVarId) {
    let mut remainder = None;
    let ssa = SsaFunctionBuilder::new(0, 0)
        .build_with(|f| {
            f.block(0, |b| {
                let (l, r) = (b.const_val(left), b.const_val(right));
                let v = if unsigned {
                    b.rem_un(l, r)
                } else {
                    b.rem(l, r)
                };
                remainder = Some(v);
                b.ret_val(v);
            });
        })
        .unwrap();
    (ssa, remainder.unwrap())
}

/// The constant `remainder` is defined as, if any.
fn folded(ssa: &SsaFunction, remainder: SsaVarId) -> Option<ConstValue> {
    match ssa.get_definition(remainder) {
        Some(SsaOp::Const { value, .. }) => Some(value.clone()),
        _ => None,
    }
}

/// What the pass folds `left rem right` to, or `None` when it leaves the
/// remainder in place.
fn folded_rem(left: ConstValue, right: ConstValue, unsigned: bool) -> Option<ConstValue> {
    let (mut ssa, remainder) = remainder_function(left, right, unsigned);
    run_verified(
        &ConstantPropagationPass::new(10),
        &mut ssa,
        &MethodRef::from(Token::new(0x0600_0001)),
        &test_context(),
    )
    .unwrap();
    folded(&ssa, remainder)
}

/// `rem.un` reads its operands as unsigned at their own width: `-1 rem.un 7`
/// is `0xFFFF_FFFF % 7`, 3, where a sign-extending read gives 1. Modulus with
/// a key is the canonical decryptor shape. Signed, the remainder takes the
/// dividend's sign, in Rust and CIL alike.
#[test]
fn rem_un_treats_i32_operands_as_unsigned_32_bit() {
    assert_eq!(
        folded_rem(ConstValue::I32(-1), ConstValue::I32(7), true),
        Some(ConstValue::I32(3))
    );
    assert_eq!(
        folded_rem(ConstValue::I32(-1), ConstValue::I32(7), false),
        Some(ConstValue::I32(-1))
    );
}

/// The folded constant keeps the operands' width: a 64-bit remainder
/// narrowed to `I32` would be emitted as `ldc.i4` where the stack holds an
/// `int64`, which fails verification.
#[test]
fn rem_keeps_the_operand_width() {
    assert_eq!(
        folded_rem(
            ConstValue::I64(0x1_0000_0000 + 5),
            ConstValue::I64(0x1_0000_0000),
            false
        ),
        Some(ConstValue::I64(5))
    );
}

/// What the runtime turns into an exception is not folded away.
#[test]
fn rem_refuses_to_fold_faulting_cases() {
    let (one, zero) = (ConstValue::I32(1), ConstValue::I32(0));
    assert_eq!(folded_rem(one.clone(), zero.clone(), false), None);
    assert_eq!(folded_rem(one, zero, true), None);
    assert_eq!(
        folded_rem(ConstValue::I32(i32::MIN), ConstValue::I32(-1), false),
        None
    );
}

/// A remainder of an `int32` by an `int64` is unverifiable IL: the verifier
/// rejects it before any pass runs, and the pass handed it regardless leaves
/// it in place.
#[test]
fn rem_of_mixed_widths_is_rejected_and_left_unfolded() {
    let (mut ssa, remainder) = remainder_function(ConstValue::I32(7), ConstValue::I64(2), false);
    let findings = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
    assert!(
        findings
            .iter()
            .any(|finding| matches!(finding, VerifierError::InvalidOperandWidths { .. })),
        "{findings:?}"
    );
    ConstantPropagationPass::new(10)
        .run_on_method(
            &mut ssa,
            &MethodRef::from(Token::new(0x0600_0001)),
            &test_context(),
        )
        .unwrap();
    assert_eq!(folded(&ssa, remainder), None);
}

/// An overflow-checked op must test overflow at the operands' width, signed or unsigned.
///
/// Two 32-bit values can never overflow the 64-bit range, so reading them through a
/// sign-extending accessor reports success for a case that must raise `OverflowException`,
/// and yields an `I64` where the stack holds an `int32`. The unsigned half of this was fixed
/// first; the signed half kept the `as_i64` shape and is the regression this pins.
#[test]
fn overflow_checks_use_the_operand_width() {
    let ptr = PointerSize::Bit64;
    let one: ConstValue = ConstValue::I32(1);
    let two: ConstValue = ConstValue::I32(2);
    let wide_one: ConstValue = ConstValue::I64(1);

    // Unsigned: 0xFFFF_FFFF + 1 overflows int32, so this must not fold.
    let all_ones: ConstValue = ConstValue::I32(-1);
    assert_eq!(all_ones.add_checked(&one, true, ptr), None);

    // Signed: i32::MAX + 1 overflows int32. Under `as_i64` both operands widened to 64 bits,
    // no overflow was reported, and the wrapping `add` folded this to `i32::MIN` — turning a
    // throwing path into a wrong constant.
    let max: ConstValue = ConstValue::I32(i32::MAX);
    let min: ConstValue = ConstValue::I32(i32::MIN);
    assert_eq!(max.add_checked(&one, false, ptr), None);
    assert_eq!(min.sub_checked(&one, false, ptr), None);
    assert_eq!(max.mul_checked(&two, false, ptr), None);

    // In range, and the result keeps the 32-bit width.
    assert_eq!(
        two.add_checked(&one, true, ptr),
        Some(ConstValue::I32(3)),
        "an in-range unsigned add must fold at int32 width"
    );
    assert_eq!(
        two.add_checked(&one, false, ptr),
        Some(ConstValue::I32(3)),
        "an in-range signed add must fold at int32 width"
    );

    // The same values at 64-bit width do fit.
    let wide: ConstValue = ConstValue::I64(0xFFFF_FFFF);
    assert_eq!(
        wide.add_checked(&wide_one, true, ptr),
        Some(ConstValue::I64(0x1_0000_0000))
    );
}

/// A multiply by zero folds through the ordinary overflow check, at the operands' width.
///
/// The `x * 0 == 0` short-circuit that used to precede the check returned the *zero operand's
/// own* variant, so the result width depended on which side happened to be zero.
#[test]
fn mul_ovf_by_zero_folds_at_the_operand_width() {
    let ptr = PointerSize::Bit64;

    let hundred: ConstValue = ConstValue::I32(100);
    let zero: ConstValue = ConstValue::I32(0);
    assert_eq!(
        hundred.mul_checked(&zero, false, ptr),
        Some(ConstValue::I32(0))
    );

    let wide_zero: ConstValue = ConstValue::I64(0);
    let wide_hundred: ConstValue = ConstValue::I64(100);
    assert_eq!(
        wide_zero.mul_checked(&wide_hundred, false, ptr),
        Some(ConstValue::I64(0))
    );
}

#[test]
fn chained_involution_chains_resolve_to_the_innermost_value() {
    // `b = not(not(neg(neg x)))`: two even chains, the second reading the
    // first's result. Each cancels, and `b`'s use must end at `x` rather than
    // at the removed `neg(neg x)`.
    let mut x_out = SsaVarId::from_index(0);
    let mut ssa = SsaFunctionBuilder::new(1, 0)
        .build_with(|f| {
            let x = f.arg(0, SsaType::I32);
            x_out = x;
            f.block(0, |b| {
                let n1 = b.neg(x);
                let n2 = b.neg(n1);
                let c1 = b.not(n2);
                let c2 = b.not(c1);
                b.ret_val(c2);
            });
        })
        .unwrap();

    let mut changes = EventLog::new();
    ConstantPropagationPass::simplify_involutory_ops(
        &mut ssa,
        Token::new(0x0600_0001),
        &mut changes,
    );

    let returned = ssa
        .block(0)
        .unwrap()
        .instructions()
        .iter()
        .find_map(|instr| match instr.op() {
            SsaOp::Return { value } => *value,
            _ => None,
        })
        .expect("a return");
    assert_eq!(returned, x_out, "not(not(neg(neg x))) is x");
    assert!(
        ssa.blocks()
            .iter()
            .flat_map(|b| b.instructions())
            .all(|i| matches!(i.op(), SsaOp::Nop | SsaOp::Return { .. })),
        "every chain member is gone"
    );
}

#[test]
fn an_odd_chain_after_an_even_one_reads_the_resolved_operand() {
    // `b = not(not(not(neg(neg x))))`: the even `neg` chain cancels to `x`,
    // and the odd `not` chain keeps one `not`, which must read `x`.
    let mut x_out = SsaVarId::from_index(0);
    let mut ssa = SsaFunctionBuilder::new(1, 0)
        .build_with(|f| {
            let x = f.arg(0, SsaType::I32);
            x_out = x;
            f.block(0, |b| {
                let n1 = b.neg(x);
                let n2 = b.neg(n1);
                let c1 = b.not(n2);
                let c2 = b.not(c1);
                let c3 = b.not(c2);
                b.ret_val(c3);
            });
        })
        .unwrap();

    let mut changes = EventLog::new();
    ConstantPropagationPass::simplify_involutory_ops(
        &mut ssa,
        Token::new(0x0600_0001),
        &mut changes,
    );

    let survivors: Vec<&SsaOp> = ssa
        .blocks()
        .iter()
        .flat_map(|b| b.instructions())
        .map(|i| i.op())
        .filter(|op| !matches!(op, SsaOp::Nop | SsaOp::Return { .. }))
        .collect();
    assert!(
        matches!(survivors.as_slice(), [SsaOp::Not { operand, .. }] if *operand == x_out),
        "one `not x` remains: {survivors:?}"
    );
}

#[test]
fn a_call_that_writes_a_static_is_not_replaced_by_its_result() {
    // `int F(int x) { Counter = x; return x + 1; }` evaluates to `x + 1`, but a
    // call to it also sets `Counter`. Folding the call would lose the write.
    let writes = SsaFunctionBuilder::new(1, 0)
        .build_with(|f| {
            let x = f.arg(0, SsaType::I32);
            f.block(0, |b| {
                b.op(SsaOp::StoreStaticField {
                    field: FieldRef::new(Token::new(0x0400_0001)),
                    value: x,
                });
                let one = b.const_i32(1);
                let result = b.add(x, one);
                b.ret_val(result);
            });
        })
        .unwrap();
    assert_eq!(
        ConstantPropagationPass::evaluate_pure_function(
            &writes,
            &[ConstValue::I32(4)],
            PointerSize::Bit64
        ),
        None
    );

    // The same arithmetic without the write is a value, and folds.
    let pure = SsaFunctionBuilder::new(1, 0)
        .build_with(|f| {
            let x = f.arg(0, SsaType::I32);
            f.block(0, |b| {
                let one = b.const_i32(1);
                let result = b.add(x, one);
                b.ret_val(result);
            });
        })
        .unwrap();
    assert_eq!(
        ConstantPropagationPass::evaluate_pure_function(
            &pure,
            &[ConstValue::I32(4)],
            PointerSize::Bit64
        ),
        Some(ConstValue::I32(5))
    );
}

/// Only `System.String`'s own methods are string operations to fold.
/// `StringBuilder.Replace(string, string)` has `String.Replace`'s name and
/// arity, and its declaring type's name contains `String`; the substring test
/// this replaced took it for `String.Replace`.
#[test]
fn only_system_string_methods_are_string_operations() {
    let mscorlib = mono_mscorlib();
    let string_replace = method_token(&mscorlib, "System.String", "Replace", 2);
    let builder_replace = method_token(&mscorlib, "System.Text.StringBuilder", "Replace", 2);
    assert!(matches!(
        ConstantPropagationPass::identify_string_op(&MethodRef::new(string_replace), 3, &mscorlib),
        Some(StringFoldOp::Replace)
    ));
    assert!(
        ConstantPropagationPass::identify_string_op(&MethodRef::new(builder_replace), 3, &mscorlib)
            .is_none(),
        "StringBuilder.Replace is not String.Replace"
    );
}

/// A compare-and-branch on constants folds as the runtime compares: `-1 <
/// 1` read unsigned is `0xFFFF_FFFF < 1`, false, and two floats compare as
/// floats. Each pair was left unfolded when the comparison went through a
/// 64-bit integer reading of its operands.
#[test]
fn constant_compares_fold_at_their_own_width_and_kind() {
    let fold = |left: ConstValue, right: ConstValue, unsigned: bool| {
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let (v0, v1) = (b.const_val(left), b.const_val(right));
                    b.op(SsaOp::BranchCmp {
                        left: v0,
                        right: v1,
                        cmp: CmpKind::Lt,
                        unsigned,
                        true_target: 1,
                        false_target: 2,
                    });
                });
                f.block(1, |b| b.ret());
                f.block(2, |b| b.ret());
            })
            .unwrap();
        run_verified(
            &ConstantPropagationPass::new(10),
            &mut ssa,
            &MethodRef::from(Token::new(0x0600_0001)),
            &test_context(),
        )
        .unwrap();
        match ssa.block(0).unwrap().control_terminator() {
            Some(SsaOp::Jump { target }) => Some(*target),
            _ => None,
        }
    };
    assert_eq!(fold(ConstValue::I32(-1), ConstValue::I32(1), true), Some(2));
    assert_eq!(
        fold(ConstValue::I32(-1), ConstValue::I32(1), false),
        Some(1)
    );
    assert_eq!(
        fold(ConstValue::from(0.5_f64), ConstValue::from(0.75_f64), false),
        Some(1)
    );
}

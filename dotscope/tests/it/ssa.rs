#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! SSA (Static Single Assignment) integration tests.
//!
//! These tests verify the complete SSA pipeline using the public API:
//! 1. Build CIL bytecode using `InstructionAssembler`
//! 2. Decode to basic blocks
//! 3. Build control flow graph
//! 4. Construct SSA form
//! 5. Verify SSA properties (phi nodes, variable versions, def-use chains)
//! 6. Test symbolic evaluation on SSA

use std::collections::BTreeSet;

use dotscope::{
    analysis::{
        ConstValue, FloatFormat, SsaExceptionHandlerCilExt, SsaFunction, SsaOp, SsaType, SsaVarId,
        SymbolicEvaluator, SymbolicExpr,
    },
    assembly::{Immediate, InstructionAssembler, Operand},
    metadata::{
        method::ExceptionHandlerFlags, signatures::CALLING_CONVENTION, token::Token,
        typesystem::PointerSize, validation::ValidationConfig,
    },
    testkit::{build_cfg, build_ssa, build_ssa_with_handlers, fixture, TestTypeProvider},
    CilObject, Result,
};
use rustc_hash::FxHashMap;

/// Build SSA directly from an assembler for convenience.
fn ssa_from_asm(
    assembler: InstructionAssembler,
    num_args: usize,
    num_locals: usize,
) -> Result<SsaFunction> {
    let (_bytecode, cfg) = build_cfg(assembler)?;
    build_ssa(&cfg, &TestTypeProvider::all_i32(num_args, num_locals))
}

/// Get the SSA variable ID for argument N (version 0).
/// This finds the variable by origin instead of assuming a specific index.
fn arg_var_id(ssa: &SsaFunction, arg_index: u16) -> SsaVarId {
    ssa.variables_from_argument(arg_index)
        .find(|v| v.version() == 0)
        .expect("Argument variable not found")
        .id()
}

#[test]
fn test_ssa_simple_arithmetic() -> Result<()> {
    // ldarg.0 + ldarg.1 -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Verify basic structure
    assert_eq!(ssa.block_count(), 1, "Expected 1 block");
    assert!(
        ssa.variable_count() >= 2,
        "Expected at least 2 variables for args"
    );
    assert_eq!(ssa.phi_count(), 0, "No phi nodes expected");

    Ok(())
}

#[test]
fn test_ssa_constant_loading() -> Result<()> {
    // ldc.i4 42 + ldc.i4 100 -> add -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(42)?.ldc_i4(100)?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // Check that we have Const operations in the SSA
    let block = ssa.block(0).expect("Expected block 0");
    let mut found_const = false;
    for instr in block.instructions() {
        if let SsaOp::Const { value, .. } = instr.op() {
            if value == &ConstValue::I32(42) || value == &ConstValue::I32(100) {
                found_const = true;
            }
        }
    }
    assert!(found_const, "Expected to find Const operations");

    Ok(())
}

#[test]
fn test_ssa_local_variable() -> Result<()> {
    // ldarg.0 -> stloc.0 -> ldloc.0 -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.stloc_0()?.ldloc_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 1)?;

    assert_eq!(ssa.block_count(), 1);
    // Should have variables for arg and local (at least 2)
    assert!(ssa.variable_count() >= 2);

    Ok(())
}

#[test]
fn test_ssa_diamond_phi_nodes() -> Result<()> {
    // if (arg0) { local0 = 1; } else { local0 = 0; } return local0;
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else")?
        .ldc_i4_1()?
        .stloc_0()?
        .br_s("merge")?
        .label("else")?
        .ldc_i4_0()?
        .stloc_0()?
        .label("merge")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 1)?;

    // Should have 4 blocks: entry, then, else, merge
    assert_eq!(ssa.block_count(), 4, "Expected 4 blocks for diamond");

    // Should have at least one phi node for the merge point
    assert!(ssa.phi_count() > 0, "Expected phi node(s) at merge point");

    Ok(())
}

#[test]
fn test_ssa_loop_phi_nodes() -> Result<()> {
    // i = 0; while (i < arg0) { i++; } return i;
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?
        .stloc_0()? // i = 0
        .label("loop_header")?
        .ldloc_0()?
        .ldarg_0()?
        .bge_s("loop_exit")? // if (i >= arg0) exit
        .ldloc_0()?
        .ldc_i4_1()?
        .add()?
        .stloc_0()? // i++
        .br_s("loop_header")?
        .label("loop_exit")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 1)?;

    // Should have multiple blocks
    assert!(
        ssa.block_count() >= 2,
        "Expected at least 2 blocks for loop"
    );

    // Loop header should have a phi node for the loop variable
    // (value coming from initialization and from loop body)
    let has_phi = (0..ssa.block_count()).any(|i| ssa.block(i).is_some_and(|b| b.phi_count() > 0));
    assert!(has_phi, "Expected at least one phi node in loop header");

    Ok(())
}

#[test]
fn test_ssa_conditional_both_return() -> Result<()> {
    // if (arg0) { return 1; } return 0;
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else")?
        .ldc_i4_1()?
        .ret()?
        .label("else")?
        .ldc_i4_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Should have 3 blocks: entry, then, else
    assert_eq!(ssa.block_count(), 3);

    // No phi nodes needed (no merge point)
    assert_eq!(ssa.phi_count(), 0);

    Ok(())
}

#[test]
fn test_symbolic_eval_constant() -> Result<()> {
    // ldc.i4 42 -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(42)?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Evaluate block 0
    eval.evaluate_block(0);

    // Should have at least one expression computed
    assert!(!eval.expressions().is_empty());

    Ok(())
}

#[test]
fn test_symbolic_eval_arithmetic() -> Result<()> {
    // ldarg.0 + ldarg.1 -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Set symbolic values for arguments (look up by origin, not index)
    eval.set_symbolic(arg_var_id(&ssa, 0), "arg0");
    eval.set_symbolic(arg_var_id(&ssa, 1), "arg1");

    eval.evaluate_block(0);

    // Check that we have expressions
    assert!(!eval.expressions().is_empty());

    Ok(())
}

#[test]
fn test_symbolic_eval_constant_folding() -> Result<()> {
    // ldc.i4 10 + ldc.i4 32 -> ret (should fold to 42)
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(10)?.ldc_i4(32)?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.evaluate_block(0);

    // Check that we have a constant result
    for expr in eval.expressions().values() {
        if let SymbolicExpr::Constant(val) = expr {
            if val.as_i32() == Some(42) {
                return Ok(());
            }
        }
    }

    panic!("Expected constant 42 from symbolic evaluation of 6*7")
}

#[test]
fn test_symbolic_eval_with_set_constant() -> Result<()> {
    // Set a variable to constant and verify
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Set arg0 to constant 100
    eval.set_constant(SsaVarId::from_index(0), ConstValue::I32(100));

    let expr = eval.get_expression(SsaVarId::from_index(0));
    assert!(expr.is_some());
    if let Some(SymbolicExpr::Constant(val)) = expr {
        assert_eq!(val.as_i32(), Some(100));
    }

    Ok(())
}

#[test]
fn test_ssa_variable_versions() -> Result<()> {
    // local0 = 1; local0 = 2; local0 = 3; return local0;
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?
        .stloc_0()? // local0_v0 = 1
        .ldc_i4_2()?
        .stloc_0()? // local0_v1 = 2
        .ldc_i4_3()?
        .stloc_0()? // local0_v2 = 3
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 0, 1)?;

    // Multiple definitions of the same local should create multiple SSA variables
    // The initial version + 3 stores = at least 4 versions of local0
    // But actually it depends on SSA construction details

    // At minimum, we should have several variables
    assert!(
        ssa.variable_count() >= 4,
        "Expected at least 4 SSA variable versions from 3 stores to local0"
    );

    Ok(())
}

#[test]
fn test_ssa_nested_conditionals() -> Result<()> {
    // if (arg0) { if (arg1) { local0 = 1; } else { local0 = 2; } } else { local0 = 3; } return local0;
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("outer_else")?
        // Inner if
        .ldarg_1()?
        .brfalse_s("inner_else")?
        .ldc_i4_1()?
        .stloc_0()?
        .br_s("inner_merge")?
        .label("inner_else")?
        .ldc_i4_2()?
        .stloc_0()?
        .label("inner_merge")?
        .br_s("outer_merge")?
        .label("outer_else")?
        .ldc_i4_3()?
        .stloc_0()?
        .label("outer_merge")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 2, 1)?;

    // Should have multiple blocks for nested control flow
    assert!(ssa.block_count() >= 4);

    // Should have phi nodes at merge points
    assert!(ssa.phi_count() > 0);

    Ok(())
}

#[test]
fn test_ssa_switch_statement() -> Result<()> {
    // switch(arg0) { case 0: return 10; case 1: return 20; default: return 30; }
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .switch(&["case0", "case1"])?
        // Default case
        .ldc_i4(30)?
        .ret()?
        .label("case0")?
        .ldc_i4(10)?
        .ret()?
        .label("case1")?
        .ldc_i4(20)?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Should have multiple blocks for switch cases
    assert!(ssa.block_count() >= 3);

    Ok(())
}

#[test]
fn test_ssa_bitwise_operations() -> Result<()> {
    // ldarg.0 & ldarg.1 | ldc.i4 0xFF ^ ldarg.0
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldarg_1()?
        .and()?
        .ldc_i4(0xFF)?
        .or()?
        .ldarg_0()?
        .xor()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Should successfully construct SSA
    assert_eq!(ssa.block_count(), 1);

    // Check that we have And, Or, Xor operations
    let block = ssa.block(0).unwrap();
    let mut found_and = false;
    let mut found_or = false;
    let mut found_xor = false;

    for instr in block.instructions() {
        match instr.op() {
            SsaOp::And { .. } => found_and = true,
            SsaOp::Or { .. } => found_or = true,
            SsaOp::Xor { .. } => found_xor = true,
            _ => {}
        }
    }

    assert!(found_and, "Expected And operation");
    assert!(found_or, "Expected Or operation");
    assert!(found_xor, "Expected Xor operation");

    Ok(())
}

#[test]
fn test_ssa_comparison_operations() -> Result<()> {
    // ldarg.0 < ldarg.1
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.clt()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // Check for Clt operation
    let block = ssa.block(0).unwrap();
    let mut found_clt = false;
    for instr in block.instructions() {
        if matches!(instr.op(), SsaOp::Clt { .. }) {
            found_clt = true;
        }
    }
    assert!(found_clt, "Expected Clt operation");

    Ok(())
}

#[test]
fn test_ssa_shift_operations() -> Result<()> {
    // ldarg.0 << 4
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4(4)?.shl()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // Check for Shl operation
    let block = ssa.block(0).unwrap();
    let mut found_shl = false;
    for instr in block.instructions() {
        if matches!(instr.op(), SsaOp::Shl { .. }) {
            found_shl = true;
        }
    }
    assert!(found_shl, "Expected Shl operation");

    Ok(())
}

#[test]
fn test_ssa_empty_method() -> Result<()> {
    // Just return
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    assert_eq!(ssa.block_count(), 1);
    assert_eq!(ssa.phi_count(), 0);

    Ok(())
}

#[test]
fn test_ssa_dup_operation() -> Result<()> {
    // ldarg.0 -> dup -> add -> ret (arg0 + arg0)
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.dup()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // Dup creates a Copy operation in SSA
    let block = ssa.block(0).unwrap();
    let mut found_copy = false;
    for instr in block.instructions() {
        if matches!(instr.op(), SsaOp::Copy { .. }) {
            found_copy = true;
        }
    }
    assert!(found_copy, "Expected Copy operation from dup");

    Ok(())
}

#[test]
fn test_ssa_pop_operation() -> Result<()> {
    // ldarg.0 -> pop -> ldarg.1 -> ret
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.pop()?.ldarg_1()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // Pop creates a Pop operation in SSA
    let block = ssa.block(0).unwrap();
    let mut found_pop = false;
    for instr in block.instructions() {
        if matches!(instr.op(), SsaOp::Pop { .. }) {
            found_pop = true;
        }
    }
    assert!(found_pop, "Expected Pop operation");

    Ok(())
}

#[test]
fn test_ssa_invalid_block_access() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Block 0 should exist
    assert!(ssa.block(0).is_some());

    // Block 999 should not exist
    assert!(ssa.block(999).is_none());

    Ok(())
}

#[test]
fn test_ssa_invalid_variable_access() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Access with an out-of-bounds ID should return None
    assert!(ssa.variable(SsaVarId::from_index(999999)).is_none());

    Ok(())
}

#[test]
fn test_ssa_many_locals() -> Result<()> {
    // Test with many local variables
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(42)?
        .stloc_s(100)? // Store to local 100
        .ldloc_s(100)? // Load from local 100
        .ret()?;

    let ssa = ssa_from_asm(asm, 0, 101)?; // 101 locals (0-100)

    assert_eq!(ssa.block_count(), 1);
    assert!(ssa.num_locals() == 101);

    Ok(())
}

#[test]
fn test_ssa_many_arguments() -> Result<()> {
    // Test with multiple arguments
    let mut asm = InstructionAssembler::new();
    asm.ldarg_s(5)? // Load arg 5
        .ldarg_s(10)? // Load arg 10
        .add()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 11, 0)?; // 11 arguments (0-10)

    assert_eq!(ssa.block_count(), 1);
    assert!(ssa.num_args() == 11);

    Ok(())
}

#[test]
fn test_ssa_conversion_operations() -> Result<()> {
    // Test type conversion operations
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .conv_i8()? // Convert to int8
        .conv_i4()? // Convert back to int32
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    assert_eq!(ssa.block_count(), 1);

    // `conv.i8`/`conv.i4` are integer→integer conversions, which lower to
    // `IntConv`: analyssa 0.3 split the old `Conv` into a domain-typed family
    // (see `conv_op_for_target`), so only a float or pointer target produces
    // `IntToFloat`/`IntToPtr`.
    let block = ssa.block(0).unwrap();
    let conv_count = block
        .instructions()
        .iter()
        .filter(|instr| matches!(instr.op(), SsaOp::IntConv { .. }))
        .count();
    assert!(conv_count >= 2, "Expected at least 2 IntConv operations");

    Ok(())
}

#[test]
fn test_ssa_negation_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.neg()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Check for Neg operation
    let block = ssa.block(0).unwrap();
    let has_neg = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Neg { .. }));
    assert!(has_neg, "Expected Neg operation");

    Ok(())
}

#[test]
fn test_ssa_multiplication_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.mul()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for Mul operation
    let block = ssa.block(0).unwrap();
    let has_mul = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Mul { .. }));
    assert!(has_mul, "Expected Mul operation");

    Ok(())
}

#[test]
fn test_ssa_division_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.div()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for Div operation
    let block = ssa.block(0).unwrap();
    let has_div = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Div { .. }));
    assert!(has_div, "Expected Div operation");

    Ok(())
}

#[test]
fn test_ssa_remainder_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.rem()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for Rem operation
    let block = ssa.block(0).unwrap();
    let has_rem = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Rem { .. }));
    assert!(has_rem, "Expected Rem operation");

    Ok(())
}

#[test]
fn test_ssa_not_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.not()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Check for Not operation
    let block = ssa.block(0).unwrap();
    let has_not = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Not { .. }));
    assert!(has_not, "Expected Not operation");

    Ok(())
}

#[test]
fn test_ssa_shr_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4(4)?.shr()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Check for Shr operation
    let block = ssa.block(0).unwrap();
    let has_shr = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Shr { .. }));
    assert!(has_shr, "Expected Shr operation");

    Ok(())
}

#[test]
fn test_ssa_ceq_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.ceq()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for Ceq operation
    let block = ssa.block(0).unwrap();
    let has_ceq = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Ceq { .. }));
    assert!(has_ceq, "Expected Ceq operation");

    Ok(())
}

#[test]
fn test_ssa_cgt_operation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.cgt()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for Cgt operation
    let block = ssa.block(0).unwrap();
    let has_cgt = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Cgt { .. }));
    assert!(has_cgt, "Expected Cgt operation");

    Ok(())
}

#[test]
fn test_ssa_function_is_empty() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Function is not empty - it has at least one block
    assert!(!ssa.is_empty());
    assert!(ssa.block_count() > 0);

    Ok(())
}

#[test]
fn test_ssa_total_instruction_count() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?.ldc_i4_2()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Should have multiple instructions
    assert!(ssa.instruction_count() >= 4);

    Ok(())
}

#[test]
fn test_ssa_dead_variables() -> Result<()> {
    // Store a value to a local but never load it back
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(42)?.stloc_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 1)?;

    // The stored-but-never-loaded local creates a dead variable
    assert!(
        ssa.dead_variable_count() >= 1,
        "Expected at least 1 dead variable from unused local store"
    );

    Ok(())
}

#[test]
fn test_ssa_all_instructions_iterator() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else")?
        .ldc_i4_1()?
        .ret()?
        .label("else")?
        .ldc_i4_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Iterate over all instructions across all blocks
    let instr_count: usize = ssa.all_instructions().count();
    assert!(instr_count >= 4);

    Ok(())
}

#[test]
fn test_ssa_all_phi_nodes_iterator() -> Result<()> {
    // Create a diamond pattern that requires phi nodes
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else")?
        .ldc_i4_1()?
        .stloc_0()?
        .br_s("merge")?
        .label("else")?
        .ldc_i4_0()?
        .stloc_0()?
        .label("merge")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 1)?;

    // There should be at least one phi node
    let phi_count: usize = ssa.all_phi_nodes().count();
    assert!(phi_count > 0);

    Ok(())
}

#[test]
fn test_symbolic_eval_undefined_variable() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Variable that was never set should return None
    assert!(eval.get_expression(SsaVarId::from_index(999)).is_none());

    Ok(())
}

#[test]
fn test_symbolic_eval_get_simplified() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(10)?.ldc_i4(5)?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Set a constant
    eval.set_constant(SsaVarId::from_index(0), ConstValue::I32(42));

    // get_simplified should work
    let simplified = eval.get_simplified(SsaVarId::from_index(0));
    assert!(simplified.is_some());

    // Undefined variable should return None
    assert!(eval.get_simplified(SsaVarId::from_index(999)).is_none());

    Ok(())
}

#[test]
fn test_symbolic_eval_multiple_blocks() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else")?
        .ldc_i4(10)?
        .ret()?
        .label("else")?
        .ldc_i4(20)?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Evaluate multiple blocks
    eval.evaluate_blocks(&[0, 1, 2]);

    // Should have evaluated something
    assert!(!eval.expressions().is_empty());

    Ok(())
}

#[test]
fn test_symbolic_eval_invalid_block() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    // Evaluating invalid block should not panic
    eval.evaluate_block(999);

    Ok(())
}

#[test]
fn test_symbolic_eval_negation() -> Result<()> {
    // neg(5) = -5
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(5)?.neg()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.evaluate_block(0);

    // Find the negation result - should be constant -5 after simplification
    let has_neg_result = eval.expressions().values().any(|expr| {
        let simplified = expr.simplify(PointerSize::Bit64);
        simplified.as_constant().and_then(ConstValue::as_i32) == Some(-5)
    });
    assert!(has_neg_result, "Expected neg(5) to simplify to -5");

    Ok(())
}

#[test]
fn test_symbolic_eval_division() -> Result<()> {
    // a / b with a=20, b=4 should yield 5
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.div()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "a");
    eval.set_symbolic(arg_var_id(&ssa, 1), "b");

    eval.evaluate_block(0);

    // Find an expression that references both 'a' and 'b'
    let has_div_expr = eval.expressions().values().any(|expr| {
        let vars = expr.named_variables();
        vars.contains("a") && vars.contains("b")
    });
    assert!(has_div_expr, "Expected expression with both 'a' and 'b'");

    // Evaluate with concrete values: 20 / 4 = 5
    let bindings: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(20)), ("b", ConstValue::I32(4))]
            .into_iter()
            .collect();
    let div_result = eval.expressions().values().find_map(|expr| {
        let vars = expr.named_variables();
        if vars.contains("a") && vars.contains("b") {
            expr.evaluate_named(&bindings, PointerSize::Bit64)
        } else {
            None
        }
    });
    assert_eq!(
        div_result.and_then(|v| v.as_i32()),
        Some(5),
        "Expected 20 / 4 = 5"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_comparison() -> Result<()> {
    // ceq returns 1 when equal, 0 when not equal
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.ceq()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");
    eval.set_symbolic(arg_var_id(&ssa, 1), "y");

    eval.evaluate_block(0);

    // Find the comparison expression
    let ceq_expr = eval.expressions().values().find(|expr| {
        let vars = expr.named_variables();
        vars.contains("x") && vars.contains("y")
    });
    assert!(
        ceq_expr.is_some(),
        "Expected comparison expression with x and y"
    );

    let expr = ceq_expr.unwrap();

    // Test: x=5, y=5 -> should return 1 (equal)
    let equal_bindings: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(5)), ("y", ConstValue::I32(5))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&equal_bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(1),
        "5 == 5 should be 1"
    );

    // Test: x=5, y=10 -> should return 0 (not equal)
    let unequal_bindings: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(5)), ("y", ConstValue::I32(10))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&unequal_bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0),
        "5 == 10 should be 0"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_xor_pattern() -> Result<()> {
    // XOR is commonly used in obfuscation: x ^ k ^ k = x
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldc_i4(0x12345678)?
        .xor()?
        .ldc_i4(0x12345678)?
        .xor()? // XOR twice with same key cancels out
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "input");

    eval.evaluate_block(0);

    // Find the expression for the return value (result of second XOR).
    // With proper XOR simplification, (input ^ k) ^ k simplifies to just `input`.
    // This means the final expression has depth 0 (just the named variable),
    // NOT depth 2 (nested XORs). We find expressions containing "input" and
    // verify that at least one simplifies correctly.
    let exprs_with_input: Vec<_> = eval
        .expressions()
        .values()
        .filter(|expr| expr.named_variables().contains("input"))
        .collect();
    assert!(
        !exprs_with_input.is_empty(),
        "Expected expression with 'input'"
    );

    // The XOR simplification should produce an expression that equals the input.
    // Check that at least one expression evaluates to the input value (proving
    // the cancellation worked).
    let bindings: FxHashMap<&str, ConstValue> =
        [("input", ConstValue::I32(42))].into_iter().collect();

    let any_correct = exprs_with_input.iter().any(|expr| {
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32())
            == Some(42)
    });
    assert!(any_correct, "x ^ k ^ k should simplify to x (expected 42)");

    // Verify with different values
    let bindings2: FxHashMap<&str, ConstValue> = [("input", ConstValue::I32(0x7FFFFFFF))]
        .into_iter()
        .collect();
    let any_correct2 = exprs_with_input.iter().any(|expr| {
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32())
            == Some(0x7FFFFFFF)
    });
    assert!(any_correct2, "XOR self-inverse property should hold");

    // Test with negative value
    let bindings3: FxHashMap<&str, ConstValue> =
        [("input", ConstValue::I32(-1))].into_iter().collect();
    let any_correct3 = exprs_with_input.iter().any(|expr| {
        expr.evaluate_named(&bindings3, PointerSize::Bit64)
            .and_then(|v| v.as_i32())
            == Some(-1)
    });
    assert!(any_correct3, "XOR with -1 should return -1");

    Ok(())
}

#[test]
fn test_symbolic_eval_copy_operation() -> Result<()> {
    // dup creates a copy: x + x = 2*x
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.dup()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");

    eval.evaluate_block(0);

    // Find the addition expression (x + x)
    let add_expr = eval
        .expressions()
        .values()
        .find(|expr| expr.named_variables().contains("x") && !expr.is_variable());
    assert!(add_expr.is_some(), "Expected expression with 'x'");

    let expr = add_expr.unwrap();

    // Test: x + x should equal 2*x
    let bindings: FxHashMap<&str, ConstValue> = [("x", ConstValue::I32(7))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(14),
        "7 + 7 = 14"
    );

    let bindings2: FxHashMap<&str, ConstValue> = [("x", ConstValue::I32(-5))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(-10),
        "-5 + -5 = -10"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_shift_operations() -> Result<()> {
    // (x << 2) >> 1 = x << 1 = x * 2
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldc_i4(2)?
        .shl()? // x << 2 = x * 4
        .ldc_i4(1)?
        .shr()? // (x << 2) >> 1 = x * 2
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");

    eval.evaluate_block(0);

    // Find the deepest expression (most nested = final result)
    let shift_expr = eval
        .expressions()
        .values()
        .filter(|expr| expr.named_variables().contains("x") && !expr.is_variable())
        .max_by_key(|expr| expr.depth());
    assert!(shift_expr.is_some(), "Expected shift expression");

    let expr = shift_expr.unwrap();

    // Test: (10 << 2) >> 1 = 40 >> 1 = 20
    let bindings: FxHashMap<&str, ConstValue> = [("x", ConstValue::I32(10))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(20),
        "(10 << 2) >> 1 = 20"
    );

    // Test: (3 << 2) >> 1 = 12 >> 1 = 6
    let bindings2: FxHashMap<&str, ConstValue> = [("x", ConstValue::I32(3))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(6),
        "(3 << 2) >> 1 = 6"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_bitwise_and_or() -> Result<()> {
    // (x & 0xFF) | 0x100 - masks lower byte and sets bit 8
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldc_i4(0xFF)?
        .and()? // x & 0xFF (keep lower byte only)
        .ldc_i4(0x100)?
        .or()? // (x & 0xFF) | 0x100 (set bit 8)
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");

    eval.evaluate_block(0);

    // Find the deepest expression (most nested = final result)
    let bitwise_expr = eval
        .expressions()
        .values()
        .filter(|expr| expr.named_variables().contains("x") && !expr.is_variable())
        .max_by_key(|expr| expr.depth());
    assert!(bitwise_expr.is_some(), "Expected bitwise expression");

    let expr = bitwise_expr.unwrap();

    // Test: (0x1234 & 0xFF) | 0x100 = 0x34 | 0x100 = 0x134
    let bindings: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(0x1234))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0x134),
        "(0x1234 & 0xFF) | 0x100 = 0x134"
    );

    // Test: (0xAB & 0xFF) | 0x100 = 0xAB | 0x100 = 0x1AB
    let bindings2: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(0xAB))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0x1AB),
        "(0xAB & 0xFF) | 0x100 = 0x1AB"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_remainder() -> Result<()> {
    // n % 7
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4(7)?.rem()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "n");

    eval.evaluate_block(0);

    // Find the remainder expression
    let rem_expr = eval
        .expressions()
        .values()
        .find(|expr| expr.named_variables().contains("n") && !expr.is_variable());
    assert!(rem_expr.is_some(), "Expected remainder expression");

    let expr = rem_expr.unwrap();

    // Test: 23 % 7 = 2
    let bindings: FxHashMap<&str, ConstValue> = [("n", ConstValue::I32(23))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(2),
        "23 % 7 = 2"
    );

    // Test: 14 % 7 = 0
    let bindings2: FxHashMap<&str, ConstValue> = [("n", ConstValue::I32(14))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0),
        "14 % 7 = 0"
    );

    // Test: -10 % 7 = -3 (C-style signed remainder)
    let bindings3: FxHashMap<&str, ConstValue> =
        [("n", ConstValue::I32(-10))].into_iter().collect();
    assert_eq!(
        expr.evaluate_named(&bindings3, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(-3),
        "-10 % 7 = -3"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_conversion() -> Result<()> {
    // Conv operations pass through the value in symbolic evaluation
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.conv_i8()?.conv_i4()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");

    eval.evaluate_block(0);

    // Find an expression that still references 'x' (conversions preserve the variable)
    let has_x = eval
        .expressions()
        .values()
        .any(|expr| expr.named_variables().contains("x"));
    assert!(has_x, "Conversion should preserve variable reference");

    // The symbolic evaluator treats conv as identity for expression tracking
    // So we should be able to find 'x' being passed through
    let conversion_result = eval
        .expressions()
        .values()
        .find(|expr| expr.named_variables().contains("x"));
    assert!(conversion_result.is_some());

    // Evaluate: should pass through the value
    let bindings: FxHashMap<&str, ConstValue> = [("x", ConstValue::I32(42))].into_iter().collect();
    let result = conversion_result
        .unwrap()
        .evaluate_named(&bindings, PointerSize::Bit64)
        .and_then(|v| v.as_i32());
    assert_eq!(
        result,
        Some(42),
        "Conversion should pass through value symbolically"
    );

    Ok(())
}

#[test]
fn test_ssa_deeply_nested_conditionals() -> Result<()> {
    // 3-level nested if/else
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else1")?
        .ldarg_1()?
        .brfalse_s("else2")?
        .ldarg_2()?
        .brfalse_s("else3")?
        .ldc_i4(1)?
        .ret()?
        .label("else3")?
        .ldc_i4(2)?
        .ret()?
        .label("else2")?
        .ldc_i4(3)?
        .ret()?
        .label("else1")?
        .ldc_i4(4)?
        .ret()?;

    let ssa = ssa_from_asm(asm, 3, 0)?;

    // Should have multiple blocks for the nested structure
    assert!(ssa.block_count() >= 4);

    Ok(())
}

#[test]
fn test_ssa_switch_with_many_cases() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .switch(&["case0", "case1", "case2", "case3"])?
        .ldc_i4(-1)? // default
        .ret()?
        .label("case0")?
        .ldc_i4(0)?
        .ret()?
        .label("case1")?
        .ldc_i4(1)?
        .ret()?
        .label("case2")?
        .ldc_i4(2)?
        .ret()?
        .label("case3")?
        .ldc_i4(3)?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Should have blocks for each case plus default
    assert!(ssa.block_count() >= 5);

    Ok(())
}

#[test]
fn test_ssa_nested_loops() -> Result<()> {
    // Outer loop with inner loop
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?
        .stloc_0()? // i = 0
        .label("outer")?
        .ldloc_0()?
        .ldc_i4_s(10)?
        .bge_s("done")? // if i >= 10, done
        // inner loop
        .ldc_i4_0()?
        .stloc_1()? // j = 0
        .label("inner")?
        .ldloc_1()?
        .ldc_i4_5()?
        .bge_s("inner_done")? // if j >= 5, inner_done
        .ldloc_1()?
        .ldc_i4_1()?
        .add()?
        .stloc_1()? // j++
        .br_s("inner")?
        .label("inner_done")?
        .ldloc_0()?
        .ldc_i4_1()?
        .add()?
        .stloc_0()? // i++
        .br_s("outer")?
        .label("done")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 0, 2)?;

    // Should have multiple blocks and phi nodes for loops
    assert!(ssa.block_count() >= 3);

    Ok(())
}

#[test]
fn test_ssa_variable_defined_in_multiple_branches() -> Result<()> {
    // Variable assigned in 3 different branches, merged at one point
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldc_i4_0()?
        .blt_s("neg")?
        .ldarg_0()?
        .ldc_i4_0()?
        .bgt_s("pos")?
        // zero case
        .ldc_i4_0()?
        .stloc_0()?
        .br_s("done")?
        .label("neg")?
        .ldc_i4_m1()? // -1
        .stloc_0()?
        .br_s("done")?
        .label("pos")?
        .ldc_i4_1()?
        .stloc_0()?
        .label("done")?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 1)?;

    // Should have phi nodes at the merge point
    assert!(ssa.phi_count() > 0);

    Ok(())
}

#[test]
fn test_ssa_load_i8_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i8(0x123456789ABCDEF0i64)?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Check for I64 constant
    let block = ssa.block(0).unwrap();
    let has_i64_const = block.instructions().iter().any(|instr| {
        matches!(
            instr.op(),
            SsaOp::Const {
                value: ConstValue::I64(_),
                ..
            }
        )
    });
    assert!(has_i64_const, "Expected I64 constant");

    Ok(())
}

#[test]
fn test_ssa_load_r4_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_r4(std::f32::consts::PI)?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Check for F32 constant
    let block = ssa.block(0).unwrap();
    let has_f32_const = block.instructions().iter().any(|instr| {
        matches!(
            instr.op(),
            SsaOp::Const {
                value: ConstValue::Float(bits),
                ..
            } if bits.format() == FloatFormat::Single
        )
    });
    assert!(has_f32_const, "Expected F32 constant");

    Ok(())
}

#[test]
fn test_ssa_load_r8_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_r8(std::f64::consts::E)?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Check for F64 constant
    let block = ssa.block(0).unwrap();
    let has_f64_const = block.instructions().iter().any(|instr| {
        matches!(
            instr.op(),
            SsaOp::Const {
                value: ConstValue::Float(bits),
                ..
            } if bits.format() == FloatFormat::Double
        )
    });
    assert!(has_f64_const, "Expected F64 constant");

    Ok(())
}

#[test]
fn test_ssa_load_null() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldnull()?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Check for Null constant
    let block = ssa.block(0).unwrap();
    let has_null_const = block.instructions().iter().any(|instr| {
        matches!(
            instr.op(),
            SsaOp::Const {
                value: ConstValue::Null,
                ..
            }
        )
    });
    assert!(has_null_const, "Expected Null constant");

    Ok(())
}

#[test]
fn test_ssa_has_xor_operations() -> Result<()> {
    // Method with XOR operation
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.xor()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    assert!(ssa.has_xor_operations());

    Ok(())
}

#[test]
fn test_ssa_no_xor_operations() -> Result<()> {
    // Method without XOR operation
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    assert!(!ssa.has_xor_operations());

    Ok(())
}

#[test]
fn test_ssa_largest_switch_target_count() -> Result<()> {
    // Method with a switch
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .switch(&["case0", "case1", "case2"])?
        .ldc_i4_m1()?
        .ret()?
        .label("case0")?
        .ldc_i4_0()?
        .ret()?
        .label("case1")?
        .ldc_i4_1()?
        .ret()?
        .label("case2")?
        .ldc_i4_2()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Switch has 3 targets
    let largest = ssa.largest_switch_target_count();
    assert!(largest.is_some());
    assert!(largest.unwrap() >= 3);

    Ok(())
}

#[test]
fn test_ssa_no_switch_operations() -> Result<()> {
    // Method without switch
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    assert!(ssa.largest_switch_target_count().is_none());

    Ok(())
}

#[test]
fn test_ssa_is_void_return() -> Result<()> {
    // Void method
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Check for void return (no value on stack)
    assert!(ssa.is_void_return());

    Ok(())
}

#[test]
fn test_ssa_is_not_void_return() -> Result<()> {
    // Method returning a value
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(42)?.ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // This returns a value, so technically not void
    // But checking the Return instruction reveals it has a value
    let has_value_return = ssa
        .all_instructions()
        .any(|instr| matches!(instr.op(), SsaOp::Return { value: Some(_) }));
    assert!(has_value_return);

    Ok(())
}

#[test]
fn test_ssa_is_parameter_used() -> Result<()> {
    // Method that uses parameter 0 but not parameter 1
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Parameter 0 should be used (loaded and returned)
    // Note: The exact semantics depend on SSA construction
    let param0_count = ssa.parameter_use_count(0);
    let param1_count = ssa.parameter_use_count(1);

    // param0 should have more uses than param1
    assert!(param0_count >= param1_count);

    Ok(())
}

#[test]
fn test_ssa_instruction_count() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?
        .ldc_i4_2()?
        .ldc_i4_3()?
        .add()?
        .add()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 0, 0)?;

    // Should have 6+ instructions (3 loads, 2 adds, 1 ret)
    assert!(ssa.instruction_count() >= 6);

    Ok(())
}

#[test]
fn test_ssa_parameter_count() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.ldarg_2()?.add()?.add()?.ret()?;

    let ssa = ssa_from_asm(asm, 3, 0)?;

    assert_eq!(ssa.num_args(), 3);

    Ok(())
}

#[test]
fn test_ssa_unsigned_division() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.div_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for unsigned Div operation
    let block = ssa.block(0).unwrap();
    let has_div_un = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Div { unsigned: true, .. }));
    assert!(has_div_un, "Expected unsigned Div operation");

    Ok(())
}

#[test]
fn test_ssa_unsigned_remainder() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.rem_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for unsigned Rem operation
    let block = ssa.block(0).unwrap();
    let has_rem_un = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Rem { unsigned: true, .. }));
    assert!(has_rem_un, "Expected unsigned Rem operation");

    Ok(())
}

#[test]
fn test_ssa_unsigned_shift_right() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4(4)?.shr_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // Check for unsigned Shr operation
    let block = ssa.block(0).unwrap();
    let has_shr_un = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Shr { unsigned: true, .. }));
    assert!(has_shr_un, "Expected unsigned Shr operation");

    Ok(())
}

#[test]
fn test_ssa_cgt_unsigned() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.cgt_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for unsigned Cgt operation
    let block = ssa.block(0).unwrap();
    let has_cgt_un = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Cgt { unsigned: true, .. }));
    assert!(has_cgt_un, "Expected unsigned Cgt operation");

    Ok(())
}

#[test]
fn test_ssa_clt_unsigned() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.clt_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for unsigned Clt operation
    let block = ssa.block(0).unwrap();
    let has_clt_un = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::Clt { unsigned: true, .. }));
    assert!(has_clt_un, "Expected unsigned Clt operation");

    Ok(())
}

#[test]
fn test_ssa_add_overflow() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add_ovf()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for AddOvf operation (separate variant)
    let block = ssa.block(0).unwrap();
    let has_add_ovf = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::AddOvf { .. }));
    assert!(has_add_ovf, "Expected AddOvf operation");

    Ok(())
}

#[test]
fn test_ssa_sub_overflow() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.sub_ovf()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for SubOvf operation (separate variant)
    let block = ssa.block(0).unwrap();
    let has_sub_ovf = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::SubOvf { .. }));
    assert!(has_sub_ovf, "Expected SubOvf operation");

    Ok(())
}

#[test]
fn test_ssa_mul_overflow() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.mul_ovf()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;

    // Check for MulOvf operation (separate variant)
    let block = ssa.block(0).unwrap();
    let has_mul_ovf = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::MulOvf { .. }));
    assert!(has_mul_ovf, "Expected MulOvf operation");

    Ok(())
}

#[test]
fn test_ssa_conv_unsigned() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.conv_u4()?.ret()?;

    let ssa = ssa_from_asm(asm, 1, 0)?;

    // `conv.u4` targets uint32 — an integer→integer conversion, so it lowers to
    // `IntConv`, which retains the opcode's `unsigned` flag.
    let block = ssa.block(0).unwrap();
    let has_conv_u = block
        .instructions()
        .iter()
        .any(|instr| matches!(instr.op(), SsaOp::IntConv { unsigned: true, .. }));
    assert!(has_conv_u, "Expected unsigned IntConv operation");

    Ok(())
}

#[test]
fn test_symbolic_expr_complex_computation() -> Result<()> {
    // Complex expression: ((x + 1) * 2) - (y / 3)
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldc_i4_1()?
        .add()? // x + 1
        .ldc_i4_2()?
        .mul()? // (x + 1) * 2
        .ldarg_1()?
        .ldc_i4_3()?
        .div()? // y / 3
        .sub()? // ((x + 1) * 2) - (y / 3)
        .ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "x");
    eval.set_symbolic(arg_var_id(&ssa, 1), "y");

    eval.evaluate_block(0);

    // Find the final expression that uses both x and y
    let complex_expr = eval.expressions().values().find(|expr| {
        let vars = expr.named_variables();
        vars.contains("x") && vars.contains("y")
    });
    assert!(
        complex_expr.is_some(),
        "Expected expression with both x and y"
    );

    let expr = complex_expr.unwrap();

    // Test: x=5, y=9 -> ((5 + 1) * 2) - (9 / 3) = (6 * 2) - 3 = 12 - 3 = 9
    let bindings: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(5)), ("y", ConstValue::I32(9))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(9),
        "((5+1)*2) - (9/3) = 9"
    );

    // Test: x=0, y=0 -> ((0 + 1) * 2) - (0 / 3) = 2 - 0 = 2
    let bindings2: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(0)), ("y", ConstValue::I32(0))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(2),
        "((0+1)*2) - (0/3) = 2"
    );

    // Test: x=10, y=30 -> ((10 + 1) * 2) - (30 / 3) = 22 - 10 = 12
    let bindings3: FxHashMap<&str, ConstValue> =
        [("x", ConstValue::I32(10)), ("y", ConstValue::I32(30))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings3, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(12),
        "((10+1)*2) - (30/3) = 12"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_cgt_unsigned() -> Result<()> {
    // cgt.un: unsigned greater-than comparison
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.cgt_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "a");
    eval.set_symbolic(arg_var_id(&ssa, 1), "b");

    eval.evaluate_block(0);

    // Find the comparison expression
    let cmp_expr = eval.expressions().values().find(|expr| {
        let vars = expr.named_variables();
        vars.contains("a") && vars.contains("b")
    });
    assert!(cmp_expr.is_some(), "Expected comparison expression");

    let expr = cmp_expr.unwrap();

    // Test: 10 >u 5 -> 1
    let bindings1: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(10)), ("b", ConstValue::I32(5))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings1, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(1),
        "10 >u 5 should be 1"
    );

    // Test: 5 >u 10 -> 0
    let bindings2: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(5)), ("b", ConstValue::I32(10))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0),
        "5 >u 10 should be 0"
    );

    // Test: -1 (0xFFFFFFFF as unsigned) >u 1 -> 1 (unsigned comparison)
    let bindings3: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(-1)), ("b", ConstValue::I32(1))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings3, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(1),
        "-1 >u 1 should be 1 (unsigned)"
    );

    Ok(())
}

#[test]
fn test_symbolic_eval_clt_unsigned() -> Result<()> {
    // clt.un: unsigned less-than comparison
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.clt_un()?.ret()?;

    let ssa = ssa_from_asm(asm, 2, 0)?;
    let mut eval = SymbolicEvaluator::new(&ssa, PointerSize::Bit64);

    eval.set_symbolic(arg_var_id(&ssa, 0), "a");
    eval.set_symbolic(arg_var_id(&ssa, 1), "b");

    eval.evaluate_block(0);

    // Find the comparison expression
    let cmp_expr = eval.expressions().values().find(|expr| {
        let vars = expr.named_variables();
        vars.contains("a") && vars.contains("b")
    });
    assert!(cmp_expr.is_some(), "Expected comparison expression");

    let expr = cmp_expr.unwrap();

    // Test: 5 <u 10 -> 1
    let bindings1: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(5)), ("b", ConstValue::I32(10))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings1, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(1),
        "5 <u 10 should be 1"
    );

    // Test: 10 <u 5 -> 0
    let bindings2: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(10)), ("b", ConstValue::I32(5))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings2, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(0),
        "10 <u 5 should be 0"
    );

    // Test: 1 <u -1 (0xFFFFFFFF) -> 1 (unsigned comparison)
    let bindings3: FxHashMap<&str, ConstValue> =
        [("a", ConstValue::I32(1)), ("b", ConstValue::I32(-1))]
            .into_iter()
            .collect();
    assert_eq!(
        expr.evaluate_named(&bindings3, PointerSize::Bit64)
            .and_then(|v| v.as_i32()),
        Some(1),
        "1 <u -1 should be 1 (unsigned)"
    );

    Ok(())
}

#[test]
fn test_ssa_exception_handler_preservation() -> Result<()> {
    // Build a method with try/catch structure:
    // try {
    //     nop          // Some code that might throw
    //     leave.s handler_end
    // }
    // catch (System.Object) {
    //     pop          // Pop the exception object pushed by CLR
    //     leave.s handler_end
    // }
    // handler_end:
    //     ldc.i4.0     // Return value pushed after leave (since leave clears stack)
    //     ret

    let exception_type = Token::new(0x01000001); // System.Object token
    let mut asm = InstructionAssembler::new();
    asm.try_start("try1")?
        .nop()? // Some code in try block (doesn't leave value on stack before leave)
        .leave_s("handler_end")?
        .try_end("try1")?
        .catch_start("try1", exception_type)?
        .pop()? // Pop the exception object pushed by CLR
        .leave_s("handler_end")?
        .catch_end("try1")?
        .label("handler_end")?
        .ldc_i4_0()? // Push return value AFTER handler_end (leave clears stack)
        .ret()?;

    let (bytecode, _max_stack, handlers) = asm.finish()?;
    let ssa = build_ssa_with_handlers(&bytecode, &handlers, &TestTypeProvider::all_i32(1, 0))?;

    // Verify exception handlers are preserved
    assert!(
        ssa.has_exception_handlers(),
        "SSA should have exception handlers"
    );
    assert_eq!(
        ssa.exception_handlers().len(),
        1,
        "Expected 1 exception handler"
    );

    let eh = &ssa.exception_handlers()[0];
    assert_eq!(eh.flags, ExceptionHandlerFlags::EXCEPTION);
    assert_eq!(eh.protected_range.map(|range| range.start()), Some(0));
    assert_eq!(eh.handler_range.map(|range| range.start()), Some(1));
    assert!(
        eh.has_block_mapping(),
        "Handler should have block mapping set"
    );

    Ok(())
}

#[test]
fn test_ssa_finally_handler() -> Result<()> {
    // Build a method with try/finally structure:
    // try {
    //     nop          // Some code in try block
    //     leave.s finally_end
    // }
    // finally {
    //     ldc.i4.1     // cleanup code
    //     pop
    //     endfinally
    // }
    // finally_end:
    //     ldc.i4.0     // Return value (leave clears stack)
    //     ret

    let mut asm = InstructionAssembler::new();
    asm.try_start("try1")?
        .nop()? // Some code in try block
        .leave_s("finally_end")?
        .try_end("try1")?
        .finally_start("try1")?
        .ldc_i4_1()? // cleanup code
        .pop()?
        .endfinally()?
        .finally_end("try1")?
        .label("finally_end")?
        .ldc_i4_0()? // Return value (leave clears stack)
        .ret()?;

    let (bytecode, _max_stack, handlers) = asm.finish()?;
    let ssa = build_ssa_with_handlers(&bytecode, &handlers, &TestTypeProvider::all_i32(1, 0))?;

    assert!(ssa.has_exception_handlers());
    let eh = &ssa.exception_handlers()[0];
    assert_eq!(eh.flags, ExceptionHandlerFlags::FINALLY);
    assert!(
        eh.class_token().is_none(),
        "Finally handler has no class token"
    );

    Ok(())
}

#[test]
fn test_ssa_nested_exception_handlers() -> Result<()> {
    // Test that multiple exception handlers are correctly preserved:
    // try (outer) {
    //     try (inner) {
    //         nop
    //         leave.s inner_end
    //     }
    //     catch (inner) { pop; leave.s inner_end; }
    //     inner_end:
    //     leave.s outer_end
    // }
    // catch (outer) { pop; leave.s outer_end; }
    // outer_end:
    //     ldc.i4.0
    //     ret

    let inner_exception = Token::new(0x01000002); // Inner exception type
    let outer_exception = Token::new(0x01000001); // Outer exception type

    let mut asm = InstructionAssembler::new();
    asm.try_start("outer")?
        .try_start("inner")?
        .nop()?
        .leave_s("inner_end")?
        .try_end("inner")?
        .catch_start("inner", inner_exception)?
        .pop()?
        .leave_s("inner_end")?
        .catch_end("inner")?
        .label("inner_end")?
        .leave_s("outer_end")?
        .try_end("outer")?
        .catch_start("outer", outer_exception)?
        .pop()?
        .leave_s("outer_end")?
        .catch_end("outer")?
        .label("outer_end")?
        .ldc_i4_0()?
        .ret()?;

    let (bytecode, _max_stack, handlers) = asm.finish()?;
    let ssa = build_ssa_with_handlers(&bytecode, &handlers, &TestTypeProvider::all_i32(1, 0))?;

    assert_eq!(ssa.exception_handlers().len(), 2);

    // Verify both handlers exist with correct exception types
    let handlers = ssa.exception_handlers();
    // Note: The assembler generates handlers in the order they are defined
    // Inner handler should have class_token 0x01000002
    // Outer handler should have class_token 0x01000001
    let inner_token = handlers
        .iter()
        .find(|h| h.class_token_or_filter == 0x01000002);
    let outer_token = handlers
        .iter()
        .find(|h| h.class_token_or_filter == 0x01000001);
    assert!(
        inner_token.is_some(),
        "Inner handler should exist with token 0x01000002"
    );
    assert!(
        outer_token.is_some(),
        "Outer handler should exist with token 0x01000001"
    );

    Ok(())
}

/// Test that exception handlers from a real assembly are preserved through SSA pipeline.
///
/// This test verifies that Method::ssa() properly populates exception handlers by checking:
/// - Offset information matches the original method body
/// - Block indices are mapped correctly
/// - Class tokens are preserved for catch handlers
#[test]
fn test_ssa_pipeline_preserves_exception_handlers() {
    // Load the TestApp which has DecryptSecret method with try/catch
    let assembly = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe"))
        .expect("Should load TestApp.exe");

    // Find a method with exception handlers
    let mut found_method_with_handlers = false;

    for entry in assembly.methods().iter() {
        let method = entry.value();

        // Check if method has exception handlers
        if let Some(body) = method.body.get() {
            if !body.exception_handlers.is_empty() {
                found_method_with_handlers = true;

                // Build SSA using Method::ssa() which populates exception handlers
                let ssa = method
                    .ssa(&assembly)
                    .expect("SSA build should succeed for methods with exception handlers");

                // Verify handler count matches
                assert_eq!(
                    ssa.exception_handlers().len(),
                    body.exception_handlers.len(),
                    "SSA handler count should match method body handler count for '{}'",
                    method.name
                );

                // Verify each handler's properties are preserved
                for (i, (ssa_eh, body_eh)) in ssa
                    .exception_handlers()
                    .iter()
                    .zip(body.exception_handlers.iter())
                    .enumerate()
                {
                    // Verify offset information is preserved exactly
                    assert_eq!(
                        ssa_eh.try_offset, body_eh.try_offset,
                        "Handler {} try_offset mismatch in '{}'",
                        i, method.name
                    );
                    assert_eq!(
                        ssa_eh.try_length, body_eh.try_length,
                        "Handler {} try_length mismatch in '{}'",
                        i, method.name
                    );
                    assert_eq!(
                        ssa_eh.handler_offset, body_eh.handler_offset,
                        "Handler {} handler_offset mismatch in '{}'",
                        i, method.name
                    );
                    assert_eq!(
                        ssa_eh.handler_length, body_eh.handler_length,
                        "Handler {} handler_length mismatch in '{}'",
                        i, method.name
                    );
                    assert_eq!(
                        ssa_eh.flags, body_eh.flags,
                        "Handler {} flags mismatch in '{}'",
                        i, method.name
                    );

                    // Verify block ranges are set (not None)
                    assert!(
                        ssa_eh.protected_range.is_some(),
                        "Handler {} protected_range should be mapped in '{}'",
                        i,
                        method.name
                    );
                    assert!(
                        ssa_eh.handler_range.is_some(),
                        "Handler {} handler_range should be mapped in '{}'",
                        i,
                        method.name
                    );

                    // For catch handlers, verify class token is preserved
                    if body_eh.flags == ExceptionHandlerFlags::EXCEPTION {
                        if let Some(handler_type) = &body_eh.handler {
                            assert_eq!(
                                ssa_eh.class_token_or_filter,
                                handler_type.token.value(),
                                "Handler {} class token mismatch in '{}'",
                                i,
                                method.name
                            );
                        }
                    }
                }

                break;
            }
        }
    }

    assert!(
        found_method_with_handlers,
        "TestApp.exe should have at least one method with exception handlers"
    );
}

#[test]
fn test_decrypt_secret_handler_content() {
    // Load the TestApp which has DecryptSecret method with try/catch
    let assembly = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe"))
        .expect("Should load TestApp.exe");

    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == "DecryptSecret" {
            println!("\n=== DecryptSecret Method ===");

            // Show CFG blocks
            if let Some(cfg) = method.cfg() {
                println!("\nCFG Blocks:");
                for node_id in cfg.node_ids() {
                    if let Some(block) = cfg.block(node_id) {
                        println!(
                            "  Block {}: offset={}, size={}, handler_entry={:?}",
                            block.id, block.offset, block.size, block.handler_entry
                        );
                        for instr in &block.instructions {
                            println!("    {}", instr.mnemonic);
                        }
                    }
                }
            }

            // Show SSA blocks
            if let Ok(ssa) = method.ssa(&assembly) {
                println!("\nSSA Blocks:");
                for (idx, block) in ssa.iter_blocks() {
                    println!("  Block {} ({} phis):", idx, block.phi_count());
                    // Show phis
                    for phi_idx in 0..block.phi_count() {
                        if let Some(phi) = block.phi(phi_idx) {
                            println!(
                                "    PHI: result={:?}, origin={:?}, operands={:?}",
                                phi.result(),
                                phi.origin(),
                                phi.operands()
                            );
                        }
                    }
                    for instr in block.instructions() {
                        println!("    {:?}", instr.op());
                    }
                }

                println!("\nException handlers:");
                for (i, eh) in ssa.exception_handlers().iter().enumerate() {
                    println!(
                        "  EH {}: flags={:?}, protected={:?}, handler={:?}",
                        i, eh.flags, eh.protected_range, eh.handler_range
                    );
                }

                // Verify handler block has content
                if let Some(eh) = ssa.exception_handlers().first() {
                    if let Some(handler_block_idx) = eh.handler_range.map(|range| range.start()) {
                        let handler_block = ssa
                            .block(handler_block_idx)
                            .expect("Handler block should exist");
                        let op_count = handler_block.instructions().len();
                        println!("\nHandler block {} has {} ops", handler_block_idx, op_count);
                        assert!(op_count > 0, "Handler block should have instructions");
                    }
                }
            }
            return;
        }
    }
    panic!("DecryptSecret method not found");
}

/// Regression test for try region block decoding.
///
/// This test verifies that methods with try/finally blocks are properly decoded.
/// Previously, the block decoder only added the try region start to entry_points
/// but didn't create a block for it, causing the entire try region body to be
/// missing from the decoded blocks.
#[test]
fn test_try_region_block_decoding() {
    let assembly = CilObject::from_path_with_validation(
        fixture("packers/confuserex/1.6.0/mkaring_resources.exe"),
        ValidationConfig::analysis(),
    )
    .expect("Failed to open resources sample");

    // Find a method with try/finally (DemoLockAndUsing uses lock + using statements)
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == "DemoLockAndUsing" {
            // Verify method has exception handlers
            let body = method.body.get().expect("Method has no body");
            assert!(
                !body.exception_handlers.is_empty(),
                "Expected at least one exception handler"
            );

            let eh = &body.exception_handlers[0];
            assert!(
                eh.try_offset > 0,
                "Try region should not start at method entry"
            );

            // Verify basic blocks cover the try region
            let blocks: Vec<_> = method.blocks().collect();

            // Previously this would be only 4 blocks (prologue + handler only)
            // After the fix, we should have many more blocks covering the try region
            assert!(
                blocks.len() >= 10,
                "Expected at least 10 basic blocks, got {} (try region not decoded?)",
                blocks.len()
            );

            // Verify there's a block starting at the try region offset
            let try_region_start = body
                .exception_handlers
                .first()
                .map(|h| h.try_offset as usize)
                .unwrap();
            let method_offset = blocks.first().map(|(_, b)| b.offset).unwrap_or(0);
            let try_block_offset = method_offset + try_region_start;

            let has_try_block = blocks
                .iter()
                .any(|(_, block)| block.offset == try_block_offset);
            assert!(
                has_try_block,
                "No block found at try region start offset {:#x}",
                try_block_offset
            );

            // Verify SSA conversion succeeds and has proper exception handler mapping
            let ssa = method.ssa(&assembly).expect("SSA conversion failed");

            assert!(
                ssa.has_exception_handlers(),
                "SSA should have exception handlers"
            );
            assert!(
                !ssa.exception_handlers().is_empty(),
                "SSA should have exception handlers"
            );

            let ssa_eh = &ssa.exception_handlers()[0];
            assert!(
                ssa_eh.protected_range.is_some(),
                "Protected range should be mapped"
            );
            assert!(
                ssa_eh.handler_range.is_some(),
                "Handler range should be mapped"
            );

            // Verify try block has actual content
            if let Some(try_start) = ssa_eh.protected_range.map(|range| range.start()) {
                let try_block = ssa.block(try_start).expect("Try block should exist");
                assert!(
                    !try_block.instructions().is_empty(),
                    "Try block should have instructions"
                );
            }

            return;
        }
    }
    panic!("Main method not found");
}

/// A local whose address is taken keeps its loads.
///
/// `ldloca` hands out a pointer, and a write through that pointer is invisible
/// to the value graph: no `stloc` records it and no definition of the slot
/// appears. Construction resolves a slot's read to the definition that reaches
/// it, and for this slot the only one is the zero `.locals init` wrote - so a
/// load collapsed to that reaching definition reads zero, and the five stored
/// through the pointer is lost.
///
/// The load has to survive as a load, which is what marking the slot
/// address-taken buys: it is a read of memory, not a value construction can
/// trace. This is the `ldloca` miscompile, and it is silent - the method still
/// builds and still verifies, it just returns the wrong number.
#[test]
fn address_taken_local_keeps_its_load() -> Result<()> {
    const LDLOCA_S: u16 = 0x12;
    const STIND_I4: u16 = 0x54;

    // ldloca.s 0; ldc.i4.5; stind.i4; ldloc.0; ret
    let mut asm = InstructionAssembler::new();
    asm.emit_opcode(LDLOCA_S, Some(Operand::Immediate(Immediate::UInt8(0))))?
        .ldc_i4_5()?
        .emit_opcode(STIND_I4, None)?
        .ldloc_0()?
        .ret()?;

    let ssa = ssa_from_asm(asm, 0, 1)?;

    let has_load = ssa
        .iter_instructions()
        .any(|(_, _, instr)| matches!(instr.op(), SsaOp::LoadLocal { local_index: 0, .. }));
    assert!(
        has_load,
        "the load of an address-taken local was collapsed to a reaching definition, \
         so the value written through the pointer is lost:\n{ssa}"
    );

    Ok(())
}

/// A finally reads the local its try region wrote.
///
/// A throw leaves a protected block from wherever it happened, so the value a
/// handler finds in a slot is the join over every point in the region the throw
/// could have come from - the value on entry to the try, and every version the
/// try wrote before the throw. That is what an exceptional phi operand states.
///
/// Modelled with ordinary predecessors instead, the handler is a block whose
/// only edges are the ones a terminator names, which for a handler is none: its
/// phis have no operands to fill, and the read falls back to the value the slot
/// held on entry to the method. The cleanup then runs on the wrong value, and
/// nothing about the IR looks wrong while it does.
#[test]
fn finally_reads_the_local_its_try_wrote() -> Result<()> {
    // try { ldc.i4.7; stloc.0; leave END }
    // finally { ldloc.0; pop; endfinally }
    // END: ldloc.0; ret
    let mut asm = InstructionAssembler::new();
    asm.try_start("t")?
        .ldc_i4(7)?
        .stloc_0()?
        .leave_s("end")?
        .try_end("t")?
        .finally_start("t")?
        .ldloc_0()?
        .pop()?
        .endfinally()?
        .finally_end("t")?
        .label("end")?
        .ldloc_0()?
        .ret()?;

    let (bytecode, _max_stack, handlers) = asm.finish()?;
    let ssa = build_ssa_with_handlers(&bytecode, &handlers, &TestTypeProvider::all_i32(0, 1))?;

    // The handler's phi for the local, and what a throw may bring to it.
    let exceptional: Vec<SsaVarId> = ssa
        .block(1)
        .expect("handler block")
        .phi_nodes()
        .iter()
        .flat_map(|phi| phi.exceptional_operands().map(|op| op.value()))
        .collect();

    assert!(
        !exceptional.is_empty(),
        "the handler's phi names no value a throw could bring, so the \
         cleanup reads whatever reached the block by normal flow:\n{ssa}"
    );

    // More than one distinct value is the property under test. One would mean
    // only the value on entry to the try survived; the second is the version
    // the try wrote before the throw, which is what the handler has to see.
    let distinct: BTreeSet<SsaVarId> = exceptional.iter().copied().collect();
    assert!(
        distinct.len() >= 2,
        "the handler joins only {} value(s) from the protected region, so the \
         write inside the try is not among them:\n{ssa}",
        distinct.len()
    );

    // And one of them is that write: the constant the try stored.
    let wrote_seven = distinct.iter().any(|&operand| {
        let mut current = Some(operand);
        for _ in 0..4 {
            let Some(var) = current else { break };
            let Some((_, _, instr)) = ssa
                .iter_instructions()
                .find(|(_, _, instr)| instr.op().dest() == Some(var))
            else {
                break;
            };
            match instr.op() {
                SsaOp::Const { value, .. } => return *value == ConstValue::I32(7),
                SsaOp::Copy { src, .. } => current = Some(*src),
                _ => break,
            }
        }
        false
    });
    assert!(
        wrote_seven,
        "none of the values the handler joins is the one the try stored:\n{ssa}"
    );

    Ok(())
}

/// The SSA of the method `token` names in the corpus assembly at `path`.
fn lift(path: &str, token: u32) -> SsaFunction {
    let assembly = CilObject::from_path(fixture(path)).unwrap();
    let method = assembly.methods().get(&Token::new(token)).unwrap();
    let ssa = method.value().ssa(&assembly);
    ssa.unwrap_or_else(|error| panic!("{path} {token:#010x}: {error}"))
}

/// The type of argument `index` on entry.
fn arg_type(ssa: &SsaFunction, index: u16) -> SsaType {
    ssa.variable(arg_var_id(ssa, index))
        .unwrap()
        .var_type()
        .clone()
}

/// A function pointer is a value of its own type, its calling convention kept: here
/// `FSEventStreamCreate`'s callback, a `delegate* unmanaged`, and a static of that type that
/// `TryOpenMsQuic` merges with another.
#[test]
fn function_pointers_are_typed() {
    let ssa = lift("dotnet_10.0/System.IO.FileSystem.Watcher.dll", 0x0600_0017);
    match arg_type(&ssa, 1) {
        SsaType::FnPtr(signature) => {
            assert_eq!(signature.call_conv, CALLING_CONVENTION::UNMANAGED);
            assert_eq!(signature.params.len(), 6);
        }
        other => panic!("the callback is typed {other:?}"),
    }
    lift("dotnet_10.0/System.Net.Quic.dll", 0x0600_0110);
}

/// A value type's constructor called through `newobj` leaves the value, not a reference to
/// an object: `SqlMoney + SqlMoney` merges one with a `SqlMoney` field's value.
#[test]
fn a_value_type_built_by_its_own_constructor_is_a_value() {
    let ssa = lift("dotnet_10.0/System.Data.Common.dll", 0x0600_11AD);
    let money = arg_type(&ssa, 0);
    assert!(matches!(money, SsaType::ValueType(_)));
    // `new SqlMoney(long, int)` is the body's only constructor call on `SqlMoney`; the other
    // builds the `OverflowException`.
    let built: Vec<SsaType> = ssa
        .blocks()
        .iter()
        .flat_map(|block| block.instructions())
        .filter_map(|instruction| match instruction.op() {
            SsaOp::NewObj { dest, .. } => ssa.variable(*dest).map(|v| v.var_type().clone()),
            _ => None,
        })
        .collect();
    assert!(built.contains(&money), "newobj results: {built:?}");
}

/// `this` in a value type's instance method is a managed pointer to the value.
#[test]
fn this_in_a_value_type_is_a_managed_pointer() {
    // `SqlMoney.CompareTo(SqlMoney)`, an instance method of a struct
    let assembly = CilObject::from_path(fixture("dotnet_10.0/System.Data.Common.dll")).unwrap();
    let method = assembly
        .methods()
        .iter()
        .map(|entry| entry.value().clone())
        .find(|method| {
            method.name == "CompareTo"
                && method.signature.has_this
                && method
                    .declaring_type_rc()
                    .is_some_and(|owner| owner.name == "SqlMoney")
        })
        .unwrap();
    let ssa = method.ssa(&assembly).unwrap();
    assert!(matches!(
        arg_type(&ssa, 0),
        SsaType::ByRef(inner) if matches!(*inner, SsaType::ValueType(_))
    ));
}

/// `ref` parameters and `ref` returns are managed pointers: `AwaitOnCompleted(ref TAwaiter,
/// ref TStateMachine)` and `SequenceCompareTo`, whose `Unsafe.Add` returns `ref T`.
#[test]
fn ref_parameters_and_returns_are_managed_pointers() {
    let ssa = lift("dotnet_10.0/System.Private.CoreLib.dll", 0x0600_7E93);
    assert!(matches!(arg_type(&ssa, 0), SsaType::ByRef(_)));
    assert!(matches!(arg_type(&ssa, 1), SsaType::ByRef(_)));
    lift("dotnet_10.0/System.Private.CoreLib.dll", 0x0600_1D9F);
    lift("mono_4.5/mscorlib.dll", 0x0600_66D6);
}

/// A `calli` through an unmanaged function pointer finds its signature: COM's
/// `QueryInterface` calls through the vtable's `delegate* unmanaged`.
#[test]
fn an_unmanaged_calli_site_resolves() {
    lift("dotnet_10.0/System.Private.CoreLib.dll", 0x0600_7844);
}

/// `System.ValueType` and `System.Enum` are classes, though what derives from them is not:
/// `this` in `Enum.HasFlag` is a reference, and `HasFlag`'s argument a reference too.
#[test]
fn the_bases_of_value_types_are_classes() {
    let assembly = CilObject::from_path(fixture("dotnet_10.0/System.Private.CoreLib.dll")).unwrap();
    let has_flag = assembly
        .methods()
        .iter()
        .map(|entry| entry.value().clone())
        .find(|method| {
            method.name == "HasFlag"
                && method
                    .declaring_type_rc()
                    .is_some_and(|owner| owner.fullname().as_ref() == "System.Enum")
        })
        .unwrap();
    let ssa = has_flag.ssa(&assembly).unwrap();
    assert!(
        matches!(arg_type(&ssa, 0), SsaType::Class(_)),
        "{:?}",
        arg_type(&ssa, 0)
    );
    assert!(
        matches!(arg_type(&ssa, 1), SsaType::Class(_)),
        "{:?}",
        arg_type(&ssa, 1)
    );

    let flavor = |name: &str| {
        assembly
            .types()
            .iter()
            .find(|entry| entry.value().fullname().as_ref() == name)
            .unwrap()
            .value()
            .flavor()
            .clone()
    };
    assert!(!flavor("System.ValueType").is_value_type());
    assert!(!flavor("System.Enum").is_value_type());
    assert!(flavor("System.DayOfWeek").is_value_type());
    assert!(flavor("System.DateTime").is_value_type());
}

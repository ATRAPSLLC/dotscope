//! Unit tests for the CIL interpreter.
//!
//! This module contains tests for the interpreter's instruction execution,
//! verifying correct behavior for:
//! - Stack operations (nop, dup, pop)
//! - Load constant instructions (ldc.i4.*, ldc.i8, ldc.r4, ldc.r8)
//! - Arithmetic operations (add, sub, mul, div, rem, neg)
//! - Bitwise operations (and, or, xor, not, shl, shr)
//! - Control flow (branch instructions, return)
//! - Local variable access (ldloc, stloc)
//! - Argument access (ldarg)
//! - Type conversions (conv.*)
//! - Execution limits and statistics

use std::sync::Arc;

use crate::{
    assembly::{FlowType, Immediate, Instruction, InstructionCategory, Operand, StackBehavior},
    cilassembly::CilAssembly,
    emulation::{
        engine::{interpreter::Interpreter, result::StepResult},
        memory::AddressSpace,
        ConversionType, EmValue, EmulationThread, ManagedPointer, ThreadId,
    },
    metadata::{
        tables::{FieldAttributes, FieldBuilder, TableId, TypeAttributes, TypeDefBuilder},
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    testkit::{
        emulation::{
            create_test_context, create_test_context_with, create_test_thread, emulation_limits,
        },
        fixture,
    },
    CilObject,
};

fn create_test_interpreter() -> (Interpreter, Arc<AddressSpace>) {
    let ctx = create_test_context();
    let limits = emulation_limits();
    let address_space = Arc::clone(&ctx.address_space);
    (
        Interpreter::new(limits, Arc::clone(&address_space), PointerSize::Bit64),
        address_space,
    )
}

fn create_test_thread_with_locals(local_types: Vec<CilFlavor>) -> EmulationThread {
    let ctx = create_test_context();
    let mut thread = EmulationThread::new(ThreadId::MAIN, ctx);
    thread.start_method(Token::new(0x06000001), local_types, vec![], false);
    thread
}

fn create_test_thread_with_args(
    args: Vec<(EmValue, CilFlavor)>,
    local_types: Vec<CilFlavor>,
) -> EmulationThread {
    let ctx = create_test_context();
    let mut thread = EmulationThread::new(ThreadId::MAIN, ctx);
    thread.start_method(Token::new(0x06000001), local_types, args, false);
    thread
}

fn make_instruction(opcode: u8, mnemonic: &'static str) -> Instruction {
    Instruction {
        rva: 0,
        offset: 0,
        size: 1,
        opcode,
        prefix: 0,
        mnemonic,
        category: InstructionCategory::Misc,
        flow_type: FlowType::Sequential,
        operand: Operand::None,
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![],
    }
}

fn make_instruction_with_operand(
    opcode: u8,
    mnemonic: &'static str,
    operand: Operand,
) -> Instruction {
    Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode,
        prefix: 0,
        mnemonic,
        category: InstructionCategory::Misc,
        flow_type: FlowType::Sequential,
        operand,
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![],
    }
}

#[test]
fn test_nop() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x00, "nop");

    // Create a minimal context - we won't actually use it for nop
    // In real usage, this would be a proper EmulationContext
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_ldc_i4_constants() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test ldc.i4.0 through ldc.i4.8
    for (opcode, expected) in [
        (0x16, 0),
        (0x17, 1),
        (0x18, 2),
        (0x19, 3),
        (0x1A, 4),
        (0x1B, 5),
        (0x1C, 6),
        (0x1D, 7),
        (0x1E, 8),
    ] {
        thread.stack_mut().clear();
        let instr = make_instruction(opcode, "ldc.i4.*");
        interpreter.execute_standard(&mut thread, &instr).unwrap();

        let value = thread.pop().unwrap();
        assert_eq!(value, EmValue::I32(expected));
    }
}

#[test]
fn test_ldc_i4_m1() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x15, "ldc.i4.m1");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let value = thread.pop().unwrap();
    assert_eq!(value, EmValue::I32(-1));
}

#[test]
fn test_ldnull() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x14, "ldnull");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let value = thread.pop().unwrap();
    assert_eq!(value, EmValue::Null);
}

#[test]
fn test_dup() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x25, "dup");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert_eq!(thread.stack().depth(), 2);
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_pop() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(100)).unwrap();

    let instr = make_instruction(0x26, "pop");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert_eq!(thread.stack().depth(), 1);
    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_add() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(10)).unwrap();
    thread.push(EmValue::I32(20)).unwrap();

    let instr = make_instruction(0x58, "add");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_sub() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(50)).unwrap();
    thread.push(EmValue::I32(20)).unwrap();

    let instr = make_instruction(0x59, "sub");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_mul() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(5)).unwrap();
    thread.push(EmValue::I32(6)).unwrap();

    let instr = make_instruction(0x5A, "mul");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(30));
}

#[test]
fn test_neg() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x65, "neg");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-42));
}

#[test]
fn test_ldloc_stloc() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread_with_locals(vec![CilFlavor::I4, CilFlavor::I4]);

    // Store 42 in local 0
    thread.push(EmValue::I32(42)).unwrap();
    let stloc0 = make_instruction(0x0A, "stloc.0");
    interpreter.execute_standard(&mut thread, &stloc0).unwrap();

    // Load local 0
    let ldloc0 = make_instruction(0x06, "ldloc.0");
    interpreter.execute_standard(&mut thread, &ldloc0).unwrap();

    assert_eq!(thread.pop().unwrap(), EmValue::I32(42));
}

#[test]
fn test_branch_brtrue() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test brtrue with non-zero value (should branch)
    thread.push(EmValue::I32(1)).unwrap();
    let brtrue = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2D,
        prefix: 0,
        mnemonic: "brtrue.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 1,
            pushes: 0,
            net_effect: -1,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &brtrue).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // Test brtrue with zero value (should not branch)
    thread.push(EmValue::I32(0)).unwrap();
    let result = interpreter.execute_standard(&mut thread, &brtrue).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_branch_brfalse() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test brfalse with zero value (should branch)
    thread.push(EmValue::I32(0)).unwrap();
    let brfalse = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2C,
        prefix: 0,
        mnemonic: "brfalse.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 1,
            pushes: 0,
            net_effect: -1,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &brfalse).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // Test brfalse with non-zero value (should not branch)
    thread.push(EmValue::I32(1)).unwrap();
    let result = interpreter.execute_standard(&mut thread, &brfalse).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_conv_i8() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6A, "conv.i8");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(42));
}

#[test]
fn test_execution_stats() {
    let limits = emulation_limits().with_max_instructions(10);
    let ctx = create_test_context();
    let mut interpreter =
        Interpreter::new(limits, Arc::clone(&ctx.address_space), PointerSize::Bit64);
    interpreter.start();

    // Manually increment the counter to simulate executing instructions
    for _ in 0..5 {
        interpreter.stats_mut().increment_instructions();
    }

    assert_eq!(interpreter.stats().instructions_executed, 5);
}

#[test]
fn test_instruction_limit() {
    let limits = emulation_limits().with_max_instructions(5);
    let ctx = create_test_context();
    let mut interpreter =
        Interpreter::new(limits, Arc::clone(&ctx.address_space), PointerSize::Bit64);
    interpreter.start();

    // Manually increment the counter to simulate executing instructions
    for _ in 0..5 {
        interpreter.stats_mut().increment_instructions();
    }

    // Check that limits are exceeded (pass call depth 0 - testing instruction limit)
    assert!(interpreter.check_limits(0).is_err());
}

#[test]
fn test_div() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(100)).unwrap();
    thread.push(EmValue::I32(5)).unwrap();

    let instr = make_instruction(0x5B, "div");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(20));
}

#[test]
fn test_rem() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(17)).unwrap();
    thread.push(EmValue::I32(5)).unwrap();

    let instr = make_instruction(0x5D, "rem");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(2));
}

#[test]
fn test_and() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b1010_1010)).unwrap();

    let instr = make_instruction(0x5F, "and");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b1010_0000));
}

#[test]
fn test_or() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b0000_1111)).unwrap();

    let instr = make_instruction(0x60, "or");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b1111_1111));
}

#[test]
fn test_xor() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0b1111_0000)).unwrap();
    thread.push(EmValue::I32(0b1010_1010)).unwrap();

    let instr = make_instruction(0x61, "xor");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(0b0101_1010));
}

#[test]
fn test_not() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(0)).unwrap();

    let instr = make_instruction(0x66, "not");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-1)); // Bitwise NOT of 0 is all 1s = -1
}

#[test]
fn test_shl() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(1)).unwrap();
    thread.push(EmValue::I32(4)).unwrap();

    let instr = make_instruction(0x62, "shl");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(16)); // 1 << 4 = 16
}

#[test]
fn test_shr() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(64)).unwrap();
    thread.push(EmValue::I32(2)).unwrap();

    let instr = make_instruction(0x63, "shr");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(16)); // 64 >> 2 = 16
}

#[test]
fn test_ret() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x2A, "ret");
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Return { value: None }));
}

#[test]
fn test_break() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction(0x01, "break");
    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();

    assert!(matches!(result, StepResult::Breakpoint));
}

#[test]
fn test_br_s() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2B,
        prefix: 0,
        mnemonic: "br.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::UnconditionalBranch,
        operand: Operand::Target(0x50),
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: vec![0x50],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x50 }));
}

#[test]
fn test_ldc_i4_s() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr =
        make_instruction_with_operand(0x1F, "ldc.i4.s", Operand::Immediate(Immediate::Int8(-42)));
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(-42));
}

#[test]
fn test_ldc_i4() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr =
        make_instruction_with_operand(0x20, "ldc.i4", Operand::Immediate(Immediate::Int32(123456)));
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(123456));
}

#[test]
fn test_ldc_i8() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x21,
        "ldc.i8",
        Operand::Immediate(Immediate::Int64(0x1234_5678_9ABC_DEF0)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(0x1234_5678_9ABC_DEF0));
}

#[test]
fn test_ldc_r4() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x22,
        "ldc.r4",
        Operand::Immediate(Immediate::Float32(std::f32::consts::PI)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F32(f) = result {
        assert!((f - std::f32::consts::PI).abs() < 0.001);
    } else {
        panic!("Expected F32, got {:?}", result);
    }
}

#[test]
fn test_ldc_r8() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    let instr = make_instruction_with_operand(
        0x23,
        "ldc.r8",
        Operand::Immediate(Immediate::Float64(std::f64::consts::PI)),
    );
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - std::f64::consts::PI).abs() < 0.0000001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_ldarg_0_through_3() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread_with_args(
        vec![
            (EmValue::I32(100), CilFlavor::I4),
            (EmValue::I32(200), CilFlavor::I4),
            (EmValue::I32(300), CilFlavor::I4),
            (EmValue::I32(400), CilFlavor::I4),
        ],
        vec![], // no locals
    );

    // ldarg.0
    let instr = make_instruction(0x02, "ldarg.0");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(100));

    // ldarg.1
    let instr = make_instruction(0x03, "ldarg.1");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(200));

    // ldarg.2
    let instr = make_instruction(0x04, "ldarg.2");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(300));

    // ldarg.3
    let instr = make_instruction(0x05, "ldarg.3");
    interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(400));
}

#[test]
fn test_conv_r4() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6B, "conv.r4");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F32(f) = result {
        assert!((f - 42.0).abs() < 0.001);
    } else {
        panic!("Expected F32, got {:?}", result);
    }
}

#[test]
fn test_conv_r8() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();

    let instr = make_instruction(0x6C, "conv.r8");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - 42.0).abs() < 0.0001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_conv_i4() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I64(0x1_0000_002A)).unwrap(); // Value > i32::MAX

    let instr = make_instruction(0x69, "conv.i4");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I32(42)); // Truncated to lower 32 bits
}

#[test]
fn test_float_arithmetic() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test add with floats
    thread.push(EmValue::F64(1.5)).unwrap();
    thread.push(EmValue::F64(2.5)).unwrap();

    let instr = make_instruction(0x58, "add");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    if let EmValue::F64(f) = result {
        assert!((f - 4.0).abs() < 0.0001);
    } else {
        panic!("Expected F64, got {:?}", result);
    }
}

#[test]
fn test_i64_arithmetic() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // Test mul with i64
    thread.push(EmValue::I64(0x1_0000_0000)).unwrap();
    thread.push(EmValue::I64(2)).unwrap();

    let instr = make_instruction(0x5A, "mul");
    interpreter.execute_standard(&mut thread, &instr).unwrap();

    let result = thread.pop().unwrap();
    assert_eq!(result, EmValue::I64(0x2_0000_0000));
}

#[test]
fn test_beq_s_branches_when_equal() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(42)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2E,
        prefix: 0,
        mnemonic: "beq.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));
}

#[test]
fn test_beq_s_continues_when_not_equal() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    thread.push(EmValue::I32(42)).unwrap();
    thread.push(EmValue::I32(100)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x2E,
        prefix: 0,
        mnemonic: "beq.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_bgt_s() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // 50 > 30 should branch
    thread.push(EmValue::I32(50)).unwrap();
    thread.push(EmValue::I32(30)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x30,
        prefix: 0,
        mnemonic: "bgt.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));

    // 30 > 50 should not branch
    thread.push(EmValue::I32(30)).unwrap();
    thread.push(EmValue::I32(50)).unwrap();

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Continue));
}

#[test]
fn test_blt_s() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();

    // 30 < 50 should branch
    thread.push(EmValue::I32(30)).unwrap();
    thread.push(EmValue::I32(50)).unwrap();

    let instr = Instruction {
        rva: 0,
        offset: 0,
        size: 2,
        opcode: 0x32,
        prefix: 0,
        mnemonic: "blt.s",
        category: InstructionCategory::ControlFlow,
        flow_type: FlowType::ConditionalBranch,
        operand: Operand::Target(0x100),
        stack_behavior: StackBehavior {
            pops: 2,
            pushes: 0,
            net_effect: -2,
        },
        branch_targets: vec![0x100],
    };

    let result = interpreter.execute_standard(&mut thread, &instr).unwrap();
    assert!(matches!(result, StepResult::Branch { target: 0x100 }));
}

/// Every overflow-checked conversion, by its single-byte opcode, converts as ECMA-335
/// Partition III names it: `0x82`-`0x8B` read their source as unsigned
/// (`conv.ovf.<to>.un`), `0xB3`-`0xBA` and `0xD4`/`0xD5` as signed. The table below is the
/// specification's opcode list; each opcode must produce exactly what that conversion does
/// to the value, an overflow included.
#[test]
fn every_overflow_checked_conversion_converts_as_its_opcode_names() {
    let opcodes: [(u8, &str, ConversionType); 20] = [
        (0x82, "conv.ovf.i1.un", ConversionType::I1OvfUn),
        (0x83, "conv.ovf.i2.un", ConversionType::I2OvfUn),
        (0x84, "conv.ovf.i4.un", ConversionType::I4OvfUn),
        (0x85, "conv.ovf.i8.un", ConversionType::I8OvfUn),
        (0x86, "conv.ovf.u1.un", ConversionType::U1OvfUn),
        (0x87, "conv.ovf.u2.un", ConversionType::U2OvfUn),
        (0x88, "conv.ovf.u4.un", ConversionType::U4OvfUn),
        (0x89, "conv.ovf.u8.un", ConversionType::U8OvfUn),
        (0x8A, "conv.ovf.i.un", ConversionType::IOvfUn),
        (0x8B, "conv.ovf.u.un", ConversionType::UOvfUn),
        (0xB3, "conv.ovf.i1", ConversionType::I1Ovf),
        (0xB4, "conv.ovf.u1", ConversionType::U1Ovf),
        (0xB5, "conv.ovf.i2", ConversionType::I2Ovf),
        (0xB6, "conv.ovf.u2", ConversionType::U2Ovf),
        (0xB7, "conv.ovf.i4", ConversionType::I4Ovf),
        (0xB8, "conv.ovf.u4", ConversionType::U4Ovf),
        (0xB9, "conv.ovf.i8", ConversionType::I8Ovf),
        (0xBA, "conv.ovf.u8", ConversionType::U8Ovf),
        (0xD4, "conv.ovf.i", ConversionType::IOvf),
        (0xD5, "conv.ovf.u", ConversionType::UOvf),
    ];
    let values = [
        EmValue::I32(0),
        EmValue::I32(100),
        EmValue::I32(300),
        EmValue::I32(-1),
        EmValue::I32(i32::MIN),
        EmValue::I64(i64::from(u32::MAX)),
        EmValue::I64(-1),
        EmValue::I64(i64::MAX),
    ];
    let (mut interpreter, _address_space) = create_test_interpreter();
    for (opcode, mnemonic, conversion) in opcodes {
        for value in &values {
            let mut thread = create_test_thread();
            thread.push(value.clone()).unwrap();
            let stepped = interpreter
                .execute_standard(&mut thread, &make_instruction(opcode, mnemonic))
                .map(|_| thread.pop().unwrap());
            let expected = value.convert(conversion, PointerSize::Bit64);
            match (&stepped, &expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{mnemonic} of {value:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{mnemonic} of {value:?}: {stepped:?}, expected {expected:?}"),
            }
        }
    }
}

/// `no.` lets the next instruction skip the checks it names; the interpreter runs it as a
/// prefix that keeps them, and the `0xFE` table holds no conversion opcodes.
#[test]
fn the_no_prefix_continues_and_fe_holds_no_conversions() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();
    let mut no = make_instruction(0x19, "no.");
    no.prefix = 0xFE;
    no.operand = Operand::Immediate(Immediate::UInt8(0x01));
    assert!(matches!(
        interpreter.execute_fe_prefixed(&mut thread, &no).unwrap(),
        StepResult::Continue
    ));
    assert!(no.is_prefix());

    for opcode in (0x82..=0x8Bu8).chain(0xB3..=0xBC) {
        let mut instruction = make_instruction(opcode, "?");
        instruction.prefix = 0xFE;
        let mut thread = create_test_thread();
        thread.push(EmValue::I32(1)).unwrap();
        assert!(
            interpreter
                .execute_fe_prefixed(&mut thread, &instruction)
                .is_err(),
            "0xFE 0x{opcode:02X} is no instruction"
        );
    }
}

/// An array index is an `int32` or a `native int`; an object is no index. The interpreter read
/// one out of a boxed integer or the first integer among an object's fields, so it computed an
/// element the program never asked for where the runtime rejects the program.
#[test]
fn an_object_is_no_array_index() {
    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = create_test_thread();
    let array = thread
        .heap()
        .alloc_array_with_values(CilFlavor::I4, vec![EmValue::I32(10), EmValue::I32(20)])
        .unwrap();
    let boxed = thread
        .heap()
        .alloc_boxed(Token::new(0x0100_0001), EmValue::I32(1))
        .unwrap();
    let ldelem = make_instruction(0x94, "ldelem.i4");

    thread.push(EmValue::ObjectRef(array)).unwrap();
    thread.push(EmValue::ObjectRef(boxed)).unwrap();
    assert!(interpreter.execute_standard(&mut thread, &ldelem).is_err());

    // An integer index reads the element
    thread.push(EmValue::ObjectRef(array)).unwrap();
    thread.push(EmValue::I32(1)).unwrap();
    interpreter.execute_standard(&mut thread, &ldelem).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(20));
}

/// A pointer to an object's field (`ldflda`) points at the value the field holds: `ldfld` and
/// `stfld` through it read and write a field of the struct stored there. Both went to the object
/// holding the field instead, so a struct field of an object could not be read or set through
/// its address.
#[test]
fn a_field_pointer_reaches_the_struct_in_the_field() {
    // `Pair { int a; int b; }`
    let mut builder = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
    let pair = TypeDefBuilder::new()
        .name("Pair")
        .namespace("Ptr")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::SEQUENTIAL_LAYOUT)
        .build(&mut builder)
        .unwrap();
    let mut fields = Vec::new();
    for name in ["a", "b"] {
        let field = FieldBuilder::new()
            .name(name)
            .flags(FieldAttributes::PUBLIC)
            .signature(&[0x06, 0x08])
            .build(&mut builder)
            .unwrap();
        fields.push(Token::from_parts(
            TableId::Field,
            field.token().unwrap().row(),
        ));
    }
    let pair = Token::from_parts(TableId::TypeDef, pair.token().unwrap().row());
    let assembly = Arc::new(CilObject::from_mem(builder.to_memory().unwrap()).unwrap());

    let (mut interpreter, _address_space) = create_test_interpreter();
    let mut thread = EmulationThread::new(ThreadId::MAIN, create_test_context_with(Some(assembly)));
    thread.start_method(Token::new(0x06000001), vec![], vec![], false);
    // An object whose field `holder_field` holds a `Pair { a = 5, b = 7 }`
    let holder_field = Token::new(0x0400_0001);
    let holder = thread.heap().alloc_object(Token::new(0x0200_0002)).unwrap();
    thread
        .heap()
        .set_field(
            holder,
            holder_field,
            EmValue::ValueType {
                type_token: pair,
                fields: vec![EmValue::I32(5), EmValue::I32(7)],
            },
        )
        .unwrap();
    let pointer = EmValue::ManagedPtr(ManagedPointer::to_object_field(holder, holder_field));

    thread.push(pointer.clone()).unwrap();
    let ldfld = make_instruction_with_operand(0x7B, "ldfld", Operand::Token(fields[1]));
    interpreter.execute_standard(&mut thread, &ldfld).unwrap();
    assert_eq!(thread.pop().unwrap(), EmValue::I32(7));

    thread.push(pointer).unwrap();
    thread.push(EmValue::I32(9)).unwrap();
    let stfld = make_instruction_with_operand(0x7D, "stfld", Operand::Token(fields[0]));
    interpreter.execute_standard(&mut thread, &stfld).unwrap();
    assert_eq!(
        thread.heap().get_field(holder, holder_field).unwrap(),
        EmValue::ValueType {
            type_token: pair,
            fields: vec![EmValue::I32(9), EmValue::I32(7)],
        }
    );
}

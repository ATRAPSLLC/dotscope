//! CIL instruction interpreter and execution engine.
//!
//! This module provides the core execution engine for emulating CIL bytecode.
//! It implements instruction dispatch, execution control, and state management
//! for controlled bytecode execution.
//!
//! # Architecture
//!
//! The engine module is organized into several sub-modules:
//!
//! - [`callresolver`] - Call resolution pipeline: hook dispatch, virtual dispatch,
//!   delegate dispatch, P/Invoke, frame creation, and type initialization
//! - [`context`] - Execution context providing access to assembly metadata
//! - [`controller`] - High-level execution loop orchestrating calls, returns,
//!   and exception handling
//! - [`dispatch`] - Virtual and interface method dispatch with caching
//! - [`error`] - Emulation error types, synthetic exception tokens, and result
//!   handling
//! - [`exceptions`] - Synthetic exception type hierarchy for catch discrimination
//! - [`exhandler`] - Exception handler search, finally scheduling, and stack
//!   unwinding
//! - [`generics`] - Generic type/method instantiation tracking
//! - [`interpreter`] - Core instruction interpreter with opcode dispatch
//! - [`pointer`] - Instruction pointer and position tracking
//! - [`resolution`] - Call and newobj resolution result types
//! - [`result`] - Step and emulation result types
//! - [`stats`] - Execution statistics and limit tracking
//! - [`typeops`] - Type operations (box, unbox, cast, sizeof, static fields)
//!
//! # Key Components
//!
//! ## Execution Control
//!
//! - [`InstructionPointer`] - Tracks current execution position
//! - [`crate::emulation::process::EmulationLimits`] - Configurable limits for safe execution
//! - [`StepResult`] - Result of executing a single instruction
//!
//! ## Interpreter
//!
//! - [`Interpreter`] - Core instruction dispatch and execution
//! - [`CallFrame`] - Method call stack frame
//!
//! ## Error Handling
//!
//! - [`EmulationError`] - Comprehensive error types for emulation failures
//!
//! # Usage Example
//!
//! ```
//! use std::sync::{Arc, RwLock};
//! use dotscope::assembly::decode_stream;
//! use dotscope::emulation::{EmulationLimits, EmulationThread, Interpreter, StepResult, ThreadId};
//! use dotscope::metadata::{token::Token, typesystem::PointerSize};
//! use dotscope::Parser;
//! # use dotscope::emulation::{
//! #     AddressSpace, CaptureContext, EmulationConfig, RuntimeState, SharedFakeObjects,
//! #     ThreadContext, VirtualFs,
//! # };
//! # let address_space = Arc::new(AddressSpace::new());
//! # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
//! # let context = Arc::new(ThreadContext::new(
//! #     Arc::clone(&address_space),
//! #     Arc::new(RwLock::new(RuntimeState::new())),
//! #     Arc::new(CaptureContext::new()),
//! #     Arc::new(EmulationConfig::default()),
//! #     None,
//! #     fake_objects,
//! #     Arc::new(VirtualFs::new()),
//! # ));
//!
//! // Create interpreter with limits, and a thread running a method
//! let limits = EmulationLimits::default();
//! let mut interpreter = Interpreter::new(limits, address_space, PointerSize::Bit64);
//! let mut thread = EmulationThread::new(ThreadId::MAIN, context);
//! thread.start_method(Token::new(0x0600_0001), vec![], vec![], false);
//!
//! // The method body: `ldc.i4.1; ret`
//! let il = [0x17, 0x2A];
//! let instructions = decode_stream(&mut Parser::new(&il), 0x2050)?;
//!
//! // Execute instructions one at a time
//! for instruction in &instructions {
//!     match interpreter.step(&mut thread, instruction)? {
//!         StepResult::Continue => continue,
//!         StepResult::Return { value } => {
//!             println!("returned {:?}", value);
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

mod callresolver;
mod cctors;
mod context;
mod controller;
mod dispatch;
mod error;
mod exceptions;
mod exhandler;
mod generics;
mod interpreter;
mod pointer;
mod resolution;
mod result;
mod stats;
mod typeops;

pub use context::{EmulationContext, SyntheticMethodBody};
pub use controller::EmulationController;
pub use error::{synthetic_exception, EmulationError};
pub use interpreter::Interpreter;
pub use pointer::InstructionPointer;
pub use result::{EmulationOutcome, StepResult};
pub use stats::LimitExceeded;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dashmap::DashMap;

    use crate::{
        assembly::{decode_stream, InstructionAssembler},
        emulation::{
            exception::{ExceptionInfo, InstructionLocation},
            process::EmulationLimits,
            EmValue, EmulationContext, EmulationThread, HeapObject, HeapRef, Interpreter,
            ManagedHeap, StepResult, ThreadExceptionState, ThreadId,
        },
        file::parser::Parser,
        metadata::{token::Token, typesystem::CilFlavor},
        prelude::PointerSize,
        project::ProjectLoader,
        testkit::{
            emulation::{
                create_test_context, create_test_thread, emulation_limits, process_builder,
            },
            fixture,
        },
        Result,
    };

    /// Helper to assemble bytecode, decode it, and execute it through the interpreter.
    /// Returns the final thread state after execution.
    fn execute_assembled_code<F>(
        assembler_fn: F,
        args: Vec<(EmValue, CilFlavor)>,
        locals: Vec<CilFlavor>,
    ) -> Result<EmulationThread>
    where
        F: FnOnce(&mut InstructionAssembler) -> Result<()>,
    {
        // Generate bytecode
        let mut assembler = InstructionAssembler::new();
        assembler_fn(&mut assembler)?;
        let (bytecode, _max_stack, _) = assembler.finish()?;

        // Decode bytecode into instructions
        let mut parser = Parser::new(&bytecode);
        let instructions = decode_stream(&mut parser, 0)?;

        // Set up interpreter and thread
        let ctx = create_test_context();
        let limits = emulation_limits();
        let mut interpreter =
            Interpreter::new(limits, Arc::clone(&ctx.address_space), PointerSize::Bit64);
        let mut thread = EmulationThread::new(ThreadId::MAIN, ctx);

        // Start a method with the given args and locals
        thread.start_method(Token::new(0x06000001), locals, args, false);

        // Execute instructions until we hit a return or branch
        for instruction in &instructions {
            // Use appropriate execution method based on prefix
            let result = if instruction.prefix == 0xFE {
                interpreter.execute_fe_prefixed(&mut thread, instruction)?
            } else {
                interpreter.execute_standard(&mut thread, instruction)?
            };

            match result {
                StepResult::Return { value: _ } => break,
                StepResult::Continue => continue,
                StepResult::Branch { target: _ } => break,
                _ => {}
            }
        }

        Ok(thread)
    }

    #[test]
    fn test_assembler_add_two_constants() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(10)?.ldc_i4_const(20)?.add()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(30));
        Ok(())
    }

    #[test]
    fn test_assembler_sub_two_constants() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(50)?.ldc_i4_const(20)?.sub()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(30));
        Ok(())
    }

    #[test]
    fn test_assembler_mul_two_constants() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(6)?.ldc_i4_const(7)?.mul()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_div_two_constants() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(100)?.ldc_i4_const(4)?.div()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(25));
        Ok(())
    }

    #[test]
    fn test_assembler_rem_two_constants() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(17)?.ldc_i4_const(5)?.rem()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(2));
        Ok(())
    }

    #[test]
    fn test_assembler_neg_constant() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.neg()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(-42));
        Ok(())
    }

    #[test]
    fn test_assembler_and_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0xFF)?.ldc_i4_const(0x0F)?.and()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0x0F));
        Ok(())
    }

    #[test]
    fn test_assembler_or_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0xF0)?.ldc_i4_const(0x0F)?.or()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0xFF));
        Ok(())
    }

    #[test]
    fn test_assembler_xor_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0xFF)?.ldc_i4_const(0xAA)?.xor()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0x55));
        Ok(())
    }

    #[test]
    fn test_assembler_not_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0)?.not()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(-1)); // !0 = -1 (all bits set)
        Ok(())
    }

    #[test]
    fn test_assembler_shl_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(1)?.ldc_i4_const(4)?.shl()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(16)); // 1 << 4 = 16
        Ok(())
    }

    #[test]
    fn test_assembler_shr_operation() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(64)?.ldc_i4_const(2)?.shr()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(16)); // 64 >> 2 = 16
        Ok(())
    }

    #[test]
    fn test_assembler_local_store_load() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.stloc_0()?.ldloc_0()?.ret()?;
                Ok(())
            },
            vec![],
            vec![CilFlavor::I4],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_multiple_locals() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(10)?
                    .stloc_0()? // local[0] = 10
                    .ldc_i4_const(20)?
                    .stloc_1()? // local[1] = 20
                    .ldloc_0()? // push 10
                    .ldloc_1()? // push 20
                    .add()? // 10 + 20 = 30
                    .ret()?;
                Ok(())
            },
            vec![],
            vec![CilFlavor::I4, CilFlavor::I4],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(30));
        Ok(())
    }

    #[test]
    fn test_assembler_load_arg() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldarg_0()?.ret()?;
                Ok(())
            },
            vec![(EmValue::I32(42), CilFlavor::I4)],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_add_two_args() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                Ok(())
            },
            vec![
                (EmValue::I32(15), CilFlavor::I4),
                (EmValue::I32(27), CilFlavor::I4),
            ],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_store_arg() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(100)?
                    .starg_s(0)? // arg[0] = 100
                    .ldarg_0()? // Load modified arg
                    .ret()?;
                Ok(())
            },
            vec![(EmValue::I32(0), CilFlavor::I4)],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(100));
        Ok(())
    }

    #[test]
    fn test_assembler_dup() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.dup()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 2);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        assert_eq!(thread.stack().peek_at(1)?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_pop() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(1)?
                    .ldc_i4_const(2)?
                    .pop()? // Remove 2
                    .ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(1));
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_i4_m1() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_m1()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;
        assert_eq!(thread.stack().peek()?, &EmValue::I32(-1));
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_i4_0() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_0()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0));
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_i4_1_to_8() -> Result<()> {
        for (expected, value) in [
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 4),
            (5, 5),
            (6, 6),
            (7, 7),
            (8, 8),
        ] {
            let thread = execute_assembled_code(
                |asm| {
                    match value {
                        1 => asm.ldc_i4_1()?,
                        2 => asm.ldc_i4_2()?,
                        3 => asm.ldc_i4_3()?,
                        4 => asm.ldc_i4_4()?,
                        5 => asm.ldc_i4_5()?,
                        6 => asm.ldc_i4_6()?,
                        7 => asm.ldc_i4_7()?,
                        8 => asm.ldc_i4_8()?,
                        _ => unreachable!(),
                    };
                    asm.ret()?;
                    Ok(())
                },
                vec![],
                vec![],
            )?;
            assert_eq!(
                thread.stack().peek()?,
                &EmValue::I32(expected),
                "Failed for ldc.i4.{}",
                value
            );
        }
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_i8() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i8(0x123456789ABCDEFi64)?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I64(0x123456789ABCDEFi64));
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_r4() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_r4(std::f32::consts::PI)?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F32(v) => assert!((v - std::f32::consts::PI).abs() < 0.001),
            other => panic!("Expected F32, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_ldc_r8() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_r8(std::f64::consts::E)?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F64(v) => assert!((v - std::f64::consts::E).abs() < 0.00001),
            other => panic!("Expected F64, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_ldnull() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldnull()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::Null);
        Ok(())
    }

    #[test]
    fn test_assembler_conv_i1() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0x1234)?.conv_i1()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        // 0x1234 truncated to i8 = 0x34 = 52, sign-extended to i32
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0x34));
        Ok(())
    }

    #[test]
    fn test_assembler_conv_i2() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(0x12345678)?.conv_i2()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        // 0x12345678 truncated to i16 = 0x5678 = 22136, sign-extended to i32
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0x5678));
        Ok(())
    }

    #[test]
    fn test_assembler_conv_i4() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i8(0x123456789ABCDEFi64)?.conv_i4()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        // Truncated to lower 32 bits
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0x89ABCDEFu32 as i32));
        Ok(())
    }

    #[test]
    fn test_assembler_conv_i8() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.conv_i8()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I64(42));
        Ok(())
    }

    #[test]
    fn test_assembler_conv_r4() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.conv_r4()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F32(v) => assert!((v - 42.0).abs() < 0.001),
            other => panic!("Expected F32, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_conv_r8() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.conv_r8()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F64(v) => assert!((v - 42.0).abs() < 0.001),
            other => panic!("Expected F64, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_ceq_equal() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.ldc_i4_const(42)?.ceq()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(1));
        Ok(())
    }

    #[test]
    fn test_assembler_ceq_not_equal() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(42)?.ldc_i4_const(43)?.ceq()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(0));
        Ok(())
    }

    #[test]
    fn test_assembler_clt() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(10)?.ldc_i4_const(20)?.clt()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(1)); // 10 < 20
        Ok(())
    }

    #[test]
    fn test_assembler_cgt() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i4_const(20)?.ldc_i4_const(10)?.cgt()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(1)); // 20 > 10
        Ok(())
    }

    #[test]
    fn test_assembler_quadratic_expression() -> Result<()> {
        // Compute: (x^2 + 2*x + 1) where x = 5
        // Expected: 25 + 10 + 1 = 36
        let thread = execute_assembled_code(
            |asm| {
                // x^2
                asm.ldarg_0()?.ldarg_0()?.mul()?; // 5*5 = 25

                // 2*x
                asm.ldc_i4_const(2)?.ldarg_0()?.mul()?; // 2*5 = 10

                // x^2 + 2*x
                asm.add()?; // 25 + 10 = 35

                // + 1
                asm.ldc_i4_1()?.add()?; // 35 + 1 = 36

                asm.ret()?;
                Ok(())
            },
            vec![(EmValue::I32(5), CilFlavor::I4)],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(36));
        Ok(())
    }

    #[test]
    fn test_assembler_fibonacci_style_computation() -> Result<()> {
        // Compute next fibonacci step: fib(n) = fib(n-1) + fib(n-2)
        // Given args: arg0 = fib(n-1) = 8, arg1 = fib(n-2) = 5
        // Result: 8 + 5 = 13
        let thread = execute_assembled_code(
            |asm| {
                asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                Ok(())
            },
            vec![
                (EmValue::I32(8), CilFlavor::I4),
                (EmValue::I32(5), CilFlavor::I4),
            ],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(13));
        Ok(())
    }

    #[test]
    fn test_assembler_swap_values() -> Result<()> {
        // Swap two values using locals
        // Input: arg0 = 10, arg1 = 20
        // Output: arg1, arg0 on stack (20, 10)
        let thread = execute_assembled_code(
            |asm| {
                // Store args to locals (swap order)
                asm.ldarg_1()?.stloc_0()?; // local[0] = 20
                asm.ldarg_0()?.stloc_1()?; // local[1] = 10
                                           // Load in original order
                asm.ldloc_0()?; // push 20
                asm.ldloc_1()?; // push 10
                asm.ret()?;
                Ok(())
            },
            vec![
                (EmValue::I32(10), CilFlavor::I4),
                (EmValue::I32(20), CilFlavor::I4),
            ],
            vec![CilFlavor::I4, CilFlavor::I4],
        )?;

        assert_eq!(thread.stack().depth(), 2);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(10)); // Top
        assert_eq!(thread.stack().peek_at(1)?, &EmValue::I32(20)); // Below top
        Ok(())
    }

    #[test]
    fn test_assembler_absolute_value_style() -> Result<()> {
        // For a positive number, abs(x) = x
        // This tests: dup, neg, and we keep the original
        let thread = execute_assembled_code(
            |asm| {
                asm.ldarg_0()? // Load x
                    .dup()? // Duplicate (x, x)
                    .neg()? // Negate top (-x, x)
                    .pop()? // Remove negated (just x)
                    .ret()?;
                Ok(())
            },
            vec![(EmValue::I32(42), CilFlavor::I4)],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I32(42));
        Ok(())
    }

    #[test]
    fn test_assembler_float_add() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_r4(1.5)?.ldc_r4(2.5)?.add()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F32(v) => assert!((v - 4.0).abs() < 0.001),
            other => panic!("Expected F32, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_float_mul() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_r8(2.5)?.ldc_r8(4.0)?.mul()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        match thread.stack().peek()? {
            EmValue::F64(v) => assert!((v - 10.0).abs() < 0.001),
            other => panic!("Expected F64, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_assembler_i64_add() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i8(0x100000000i64)?
                    .ldc_i8(0x200000000i64)?
                    .add()?
                    .ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I64(0x300000000i64));
        Ok(())
    }

    #[test]
    fn test_assembler_i64_mul() -> Result<()> {
        let thread = execute_assembled_code(
            |asm| {
                asm.ldc_i8(0x10000i64)?.ldc_i8(0x10000i64)?.mul()?.ret()?;
                Ok(())
            },
            vec![],
            vec![],
        )?;

        assert_eq!(thread.stack().depth(), 1);
        assert_eq!(thread.stack().peek()?, &EmValue::I64(0x100000000i64));
        Ok(())
    }

    #[test]
    fn test_heap_array_operations() {
        let heap = ManagedHeap::default();

        // Allocate array
        let array_ref = heap.alloc_array(CilFlavor::I4, 5).unwrap();

        // Verify length
        match heap.get(array_ref).unwrap() {
            HeapObject::Array { elements, .. } => {
                assert_eq!(elements.len(), 5);
            }
            _ => panic!("Expected array"),
        }

        // Set elements
        heap.set_array_element(array_ref, 0, EmValue::I32(10))
            .unwrap();
        heap.set_array_element(array_ref, 1, EmValue::I32(20))
            .unwrap();
        heap.set_array_element(array_ref, 2, EmValue::I32(30))
            .unwrap();

        // Verify elements
        assert_eq!(
            heap.get_array_element(array_ref, 0).unwrap(),
            EmValue::I32(10)
        );
        assert_eq!(
            heap.get_array_element(array_ref, 1).unwrap(),
            EmValue::I32(20)
        );
        assert_eq!(
            heap.get_array_element(array_ref, 2).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_heap_string_operations() {
        let heap = ManagedHeap::default();

        // Allocate string
        let str_ref = heap.alloc_string("Test String").unwrap();

        // Verify string content
        assert_eq!(&*heap.get_string(str_ref).unwrap(), "Test String");

        // Allocate another string
        let str_ref2 = heap.alloc_string("Another String").unwrap();

        // Verify both strings exist
        assert_eq!(&*heap.get_string(str_ref).unwrap(), "Test String");
        assert_eq!(&*heap.get_string(str_ref2).unwrap(), "Another String");
    }

    #[test]
    fn test_heap_byte_array_operations() {
        let heap = ManagedHeap::default();

        // Allocate byte array (stored as Array internally)
        let bytes: Vec<u8> = vec![1, 2, 3, 4, 5];
        let byte_array_ref = heap.alloc_byte_array(&bytes).unwrap();

        // Verify byte array content using get_byte_array
        let result = heap
            .get_byte_array(byte_array_ref)
            .expect("Should get byte array");
        assert_eq!(result, Some(bytes));
    }

    #[test]
    fn test_heap_boxed_value() {
        let heap = ManagedHeap::default();
        let type_token = Token::new(0x02000001);

        // Box an integer
        let boxed_ref = heap.alloc_boxed(type_token, EmValue::I32(42)).unwrap();

        // Unbox
        let value = heap.get_boxed_value(boxed_ref).unwrap();
        assert_eq!(value, EmValue::I32(42));
    }

    #[test]
    fn test_heap_object_with_fields() {
        let heap = ManagedHeap::default();
        let type_token = Token::new(0x02000001);
        let field_token = Token::new(0x04000001);

        // Allocate object
        let obj_ref = heap.alloc_object(type_token).unwrap();

        // Set field
        heap.set_field(obj_ref, field_token, EmValue::I32(100))
            .unwrap();

        // Get field
        let value = heap.get_field(obj_ref, field_token).unwrap();
        assert_eq!(value, EmValue::I32(100));
    }

    #[test]
    fn test_throw_instruction_basic() {
        // Create a thread with an exception object on the stack
        let mut thread = create_test_thread();

        // Allocate an exception-like object
        let type_token = Token::new(0x02000001);
        let exc_ref = thread.heap().alloc_object(type_token).unwrap();
        thread
            .stack_mut()
            .push(EmValue::ObjectRef(exc_ref))
            .unwrap();

        // Pop and verify we'd get the throw step result
        let exception = thread.stack_mut().pop().unwrap();
        let step_result = StepResult::Throw { exception };

        match step_result {
            StepResult::Throw { exception } => {
                assert!(matches!(exception, EmValue::ObjectRef(_)));
            }
            _ => panic!("Expected Throw"),
        }
    }

    #[test]
    fn test_step_result_leave() {
        let step_result = StepResult::Leave { target: 0x100 };

        match step_result {
            StepResult::Leave { target } => {
                assert_eq!(target, 0x100);
            }
            _ => panic!("Expected Leave"),
        }
    }

    #[test]
    fn test_step_result_end_finally() {
        let step_result = StepResult::EndFinally;

        assert!(matches!(step_result, StepResult::EndFinally));
    }

    #[test]
    fn test_exception_state() {
        let mut state = ThreadExceptionState::new();

        // Initially no exception
        assert!(!state.has_exception());

        // Set exception using structured API
        let heap_ref = HeapRef::new(42);
        let throw_loc = InstructionLocation::new(Token::new(0x06000001), 10);
        let exception_info = ExceptionInfo::new(heap_ref, Token::new(0x02000001), throw_loc);
        state.set_exception(exception_info);
        assert!(state.has_exception());

        // Take exception using unified method
        let exc = state.take_exception_as_value();
        assert!(exc.is_some());
        assert!(matches!(exc, Some(EmValue::ObjectRef(_))));
        assert!(!state.has_exception());

        // Test finally stack
        let method = Token::new(0x06000001);
        state.push_finally(method, 0x50, Some(0x100));

        let pending = state.pop_finally().unwrap();
        assert_eq!(pending.method, method);
        assert_eq!(pending.handler_offset, 0x50);
        assert_eq!(pending.leave_target, Some(0x100));
    }

    #[test]
    fn test_emulation_limits_builder() {
        let limits = EmulationLimits::new()
            .with_max_instructions(1000)
            .with_max_call_depth(10);

        assert_eq!(limits.max_instructions, 1000);
        assert_eq!(limits.max_call_depth, 10);
    }

    /// Loads crafted_2.exe with its mono_4.8 dependencies through ProjectLoader.
    fn load_crafted_2_assembly() -> Arc<crate::CilObject> {
        ProjectLoader::new()
            .primary_file(fixture("crafted_2.exe"))
            .and_then(|loader| loader.with_search_path(fixture("mono_4.8")))
            .map(|loader| loader.auto_discover(true))
            .and_then(|loader| loader.build())
            .expect("crafted_2.exe loads with its dependencies")
            .project
            .get_primary()
            .expect("the project has its primary assembly")
    }

    /// Tests loading a real assembly and using EmulationContext to find methods.
    #[test]
    fn test_real_assembly_method_lookup() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly, Arc::new(DashMap::new()));

        // Test finding the Program.Main method
        let main_token = context.find_static_method("", "Program", "Main");
        assert!(
            main_token.is_some(),
            "Should find Program.Main static method"
        );

        // Verify we can get the method
        let main_method = context
            .get_method(main_token.unwrap())
            .expect("Should retrieve Main method");
        assert_eq!(main_method.name, "Main");

        // Test finding methods in a namespace
        let base_class_method = context.find_method("", "BaseClass", "VirtualMethod");
        assert!(
            base_class_method.is_some(),
            "Should find BaseClass.VirtualMethod"
        );

        // Test finding constructors
        let ctor_token = context.find_constructor("", "DerivedClass");
        assert!(ctor_token.is_some(), "Should find DerivedClass constructor");

        // Test finding multiple overloaded methods
        let ctors = context.find_constructors("", "Person");
        assert!(
            !ctors.is_empty(),
            "Should find at least one Person constructor"
        );
    }

    /// Tests that we can retrieve method metadata from a real assembly.
    #[test]
    fn test_real_assembly_method_metadata() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly, Arc::new(DashMap::new()));

        // Find a method with known characteristics
        let token = context
            .find_method("", "BaseClass", "ComplexMethod")
            .expect("Should find ComplexMethod");

        // Verify we can get method info
        let is_static = context
            .is_static_method(token)
            .expect("Should get static flag");
        assert!(!is_static, "ComplexMethod is not static");

        let is_virtual = context
            .is_virtual_method(token)
            .expect("Should get virtual flag");
        assert!(is_virtual, "ComplexMethod is virtual");

        let returns_value = context
            .method_returns_value(token)
            .expect("Should check return type");
        assert!(returns_value, "ComplexMethod returns int");
    }

    /// Tests that we can get instructions from a real method.
    #[test]
    fn test_real_assembly_get_instructions() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly, Arc::new(DashMap::new()));

        // Find the Main method
        let main_token = context
            .find_static_method("", "Program", "Main")
            .expect("Should find Main");

        // Get instructions - this validates the IL is decodable
        let instructions = context
            .get_instructions(main_token)
            .expect("Should get instructions for Main");

        // Main should have a reasonable number of instructions
        assert!(
            !instructions.is_empty(),
            "Main method should have instructions"
        );

        // Verify we can also get individual instructions by index
        let first = context
            .get_instruction_by_index(main_token, 0)
            .expect("Should get first instruction");
        assert!(
            first.rva > 0 || first.offset == 0,
            "First instruction should have valid RVA or offset 0"
        );
    }

    /// Tests type resolution and compatibility checking with real types.
    #[test]
    fn test_real_assembly_type_compatibility() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly, Arc::new(DashMap::new()));

        // Find types for compatibility testing
        let base_type = context
            .get_type_by_name("", "BaseClass")
            .expect("Should find BaseClass");

        let derived_type = context
            .get_type_by_name("", "DerivedClass")
            .expect("Should find DerivedClass");

        // Test that DerivedClass is compatible with BaseClass (inheritance)
        let compatible = context.is_type_compatible(derived_type.token, base_type.token);
        assert!(
            compatible,
            "DerivedClass should be compatible with BaseClass"
        );

        // Same type is always compatible
        let self_compatible = context.is_type_compatible(base_type.token, base_type.token);
        assert!(self_compatible, "Type should be compatible with itself");
    }

    /// Tests virtual method resolution with a real inheritance hierarchy.
    #[test]
    fn test_real_assembly_virtual_dispatch() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly, Arc::new(DashMap::new()));

        // Get base class virtual method
        let base_method = context
            .find_method("", "BaseClass", "VirtualMethod")
            .expect("Should find base VirtualMethod");

        // Get derived class type
        let derived_type = context
            .get_type_by_name("", "DerivedClass")
            .expect("Should find DerivedClass");

        // Resolve virtual call - should get DerivedClass's override
        let resolved = context.resolve_virtual_call(base_method, derived_type.token);

        // The resolved token should be from DerivedClass (different from base)
        // or the same if no override exists in our lookup
        let resolved_method = context
            .get_method(resolved)
            .expect("Should get resolved method");
        assert_eq!(
            resolved_method.name, "VirtualMethod",
            "Should resolve to a VirtualMethod"
        );
    }

    /// Tests creating an EmulationProcess and preparing to emulate a method.
    #[test]
    fn test_real_assembly_process_setup() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly.clone(), Arc::new(DashMap::new()));

        // Create process using ProcessBuilder
        let process = process_builder()
            .name("test")
            .build()
            .expect("Should build process");

        // Verify hooks are registered by default (BCL + native)
        assert!(
            !process.runtime().read().unwrap().hooks().is_empty(),
            "Default hooks should be registered"
        );

        // Find a simple method token to prepare for emulation
        let main_token = context
            .find_static_method("", "Program", "Main")
            .expect("Should find Main");

        // Verify we can check method properties
        assert!(
            context.is_static_method(main_token).unwrap(),
            "Main should be static"
        );

        // The process is ready to emulate - actual execution would
        // require handling all the external calls Main makes
        let _ = process; // Use process
        let _ = main_token; // Use token
    }

    // Note: Integration tests that emulate actual methods should use EmulationProcess::execute_method()
    // instead of manually setting up MemoryState. See tests/emulation.rs for examples.

    /// Test that we can find methods from crafted_2.exe and get their IL.
    /// This validates the metadata lookup and instruction decoding works correctly.
    #[test]
    fn test_real_method_il_structure() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly.clone(), Arc::new(DashMap::new()));

        // Test Extensions::GetReference IL structure
        // Expected from monodis: nop, ldarg.0, ldarg.1, ldelem.i4, stloc.0, br.s, ldloc.0, ret
        let get_ref_token = context
            .find_static_method("", "Extensions", "GetReference")
            .expect("Should find Extensions::GetReference");

        let instructions = context
            .get_instructions(get_ref_token)
            .expect("Should get instructions");

        // Verify we have the expected instruction sequence
        assert!(
            instructions.len() >= 7,
            "GetReference should have at least 7 instructions"
        );

        // Verify key opcodes are present
        let opcodes: Vec<u8> = instructions.iter().map(|i| i.opcode).collect();

        // Should have ldarg.0 (0x02), ldarg.1 (0x03), ldelem.i4 (0x94), stloc.0 (0x0A), etc.
        assert!(
            opcodes.contains(&0x02) || opcodes.contains(&0x03),
            "Should have ldarg instructions"
        );
        assert!(opcodes.contains(&0x94), "Should have ldelem.i4 (0x94)");
        assert!(opcodes.contains(&0x2A), "Should have ret (0x2A)");
    }

    /// Test that Person class methods can be found and have expected structure.
    #[test]
    fn test_person_method_structure() {
        let assembly = load_crafted_2_assembly();
        let context = EmulationContext::new(assembly.clone(), Arc::new(DashMap::new()));

        // Find Person::get_Age method
        let get_age_token = context
            .find_method("", "Person", "get_Age")
            .expect("Should find Person::get_Age");

        let instructions = context
            .get_instructions(get_age_token)
            .expect("Should get get_Age instructions");

        // get_Age should be simple: ldarg.0, ldfld, ret (3 instructions)
        assert!(
            instructions.len() >= 2,
            "get_Age should have at least 2 instructions (ldfld, ret)"
        );

        // Find Person::set_Age method
        let set_age_token = context
            .find_method("", "Person", "set_Age")
            .expect("Should find Person::set_Age");

        let set_instructions = context
            .get_instructions(set_age_token)
            .expect("Should get set_Age instructions");

        // set_Age should be: ldarg.0, ldarg.1, stfld, ret (4 instructions)
        assert!(
            set_instructions.len() >= 3,
            "set_Age should have at least 3 instructions (ldarg.0, ldarg.1, stfld, ret)"
        );

        // Verify stfld (0x7D) is present in set_Age
        let set_opcodes: Vec<u8> = set_instructions.iter().map(|i| i.opcode).collect();
        assert!(
            set_opcodes.contains(&0x7D),
            "set_Age should have stfld (0x7D)"
        );
    }
}

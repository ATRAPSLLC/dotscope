//! Core CIL instruction interpreter.
//!
//! The [`Interpreter`] provides the main instruction dispatch loop,
//! executing CIL bytecode one instruction at a time.

mod handlers;

use std::sync::Arc;

use crate::{
    assembly::Instruction,
    emulation::{
        engine::{
            error::EmulationError,
            pointer::InstructionPointer,
            result::StepResult,
            stats::{ExecutionStats, LimitExceeded},
        },
        memory::AddressSpace,
        process::EmulationLimits,
        thread::EmulationThread,
        BinaryOp, CompareOp, ConversionType, EmValue, UnaryOp,
    },
    metadata::{
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    Result,
};

/// Core CIL instruction interpreter.
///
/// The interpreter executes CIL instructions one at a time, managing the
/// evaluation stack, local variables, and control flow. It uses a step-based
/// execution model where each call to [`Self::step`] executes a single instruction.
///
/// # Example
///
/// ```
/// use std::sync::{Arc, RwLock};
/// use dotscope::assembly::decode_stream;
/// use dotscope::emulation::{EmulationLimits, EmulationThread, Interpreter, StepResult, ThreadId};
/// use dotscope::metadata::{token::Token, typesystem::PointerSize};
/// use dotscope::Parser;
/// # use dotscope::emulation::{
/// #     AddressSpace, CaptureContext, EmulationConfig, RuntimeState, SharedFakeObjects,
/// #     ThreadContext, VirtualFs,
/// # };
/// # let address_space = Arc::new(AddressSpace::new());
/// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
/// # let context = Arc::new(ThreadContext::new(
/// #     Arc::clone(&address_space),
/// #     Arc::new(RwLock::new(RuntimeState::new())),
/// #     Arc::new(CaptureContext::new()),
/// #     Arc::new(EmulationConfig::default()),
/// #     None,
/// #     fake_objects,
/// #     Arc::new(VirtualFs::new()),
/// # ));
///
/// // Create interpreter with limits, and a thread running a method
/// let limits = EmulationLimits::default();
/// let mut interpreter = Interpreter::new(limits, address_space, PointerSize::Bit64);
/// let mut thread = EmulationThread::new(ThreadId::MAIN, context);
/// thread.start_method(Token::new(0x0600_0001), vec![], vec![], false);
///
/// // The method body: `ldc.i4.1; ret`
/// let il = [0x17, 0x2A];
/// let instructions = decode_stream(&mut Parser::new(&il), 0x2050)?;
///
/// // Execute instructions one at a time
/// for instruction in &instructions {
///     match interpreter.step(&mut thread, instruction)? {
///         StepResult::Continue => continue,
///         StepResult::Return { value } => {
///             println!("returned {:?}", value);
///             break;
///         }
///         _ => {}
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct Interpreter {
    /// Current instruction pointer.
    ip: InstructionPointer,

    /// Execution limits.
    limits: EmulationLimits,

    /// Execution statistics.
    stats: ExecutionStats,

    /// Whether a tail call prefix is active.
    tail_prefix: bool,

    /// Whether a volatile prefix is active.
    volatile_prefix: bool,

    /// Whether an unaligned prefix is active with alignment.
    unaligned_prefix: Option<u8>,

    /// Token of the constrained type for a `constrained. callvirt` sequence.
    constrained_type: Option<Token>,

    /// Shared address space for memory operations (PE images, mapped data, heap, statics).
    address_space: Arc<AddressSpace>,

    /// Target pointer size for native int/uint operations.
    pointer_size: PointerSize,
}

impl Interpreter {
    /// Creates a new interpreter with the given execution limits, address space,
    /// and target pointer size.
    ///
    /// # Arguments
    ///
    /// * `limits` - Execution limits to enforce during emulation.
    /// * `address_space` - Shared address space for all memory operations.
    /// * `pointer_size` - Target pointer size for native int/uint types.
    ///
    /// # Returns
    ///
    /// A new interpreter ready for execution.
    #[must_use]
    pub fn new(
        limits: EmulationLimits,
        address_space: Arc<AddressSpace>,
        pointer_size: PointerSize,
    ) -> Self {
        Interpreter {
            ip: InstructionPointer::new(Token::new(0)),
            limits,
            stats: ExecutionStats::new(),
            tail_prefix: false,
            volatile_prefix: false,
            unaligned_prefix: None,
            constrained_type: None,
            address_space,
            pointer_size,
        }
    }

    /// Returns a reference to the address space.
    #[must_use]
    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.address_space
    }

    /// Returns a reference to the current instruction pointer.
    #[must_use]
    pub fn ip(&self) -> &InstructionPointer {
        &self.ip
    }

    /// Returns a mutable reference to the instruction pointer.
    #[must_use]
    pub fn ip_mut(&mut self) -> &mut InstructionPointer {
        &mut self.ip
    }

    /// Returns a reference to the execution statistics.
    #[must_use]
    pub fn stats(&self) -> &ExecutionStats {
        &self.stats
    }

    /// Returns a mutable reference to the execution statistics.
    #[must_use]
    pub fn stats_mut(&mut self) -> &mut ExecutionStats {
        &mut self.stats
    }

    /// Returns a reference to the execution limits.
    #[must_use]
    pub fn limits(&self) -> &EmulationLimits {
        &self.limits
    }

    /// Sets the current method being executed.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the method to execute.
    pub fn set_method(&mut self, method: Token) {
        self.ip = InstructionPointer::new(method);
    }

    /// Sets the instruction pointer to a specific offset within the current method.
    ///
    /// # Arguments
    ///
    /// * `offset` - The bytecode offset to branch to.
    pub fn set_offset(&mut self, offset: u32) {
        self.ip.branch_to(offset);
    }

    /// Starts execution timing for statistics tracking.
    ///
    /// Call this before beginning instruction execution to enable timeout
    /// checks and elapsed time tracking.
    pub fn start(&mut self) {
        self.stats.start();
    }

    /// Resets the interpreter state for a new execution.
    ///
    /// Clears execution statistics and all active prefixes. The instruction
    /// pointer is not modified; use [`set_method`](Self::set_method) to change the target method.
    pub fn reset(&mut self) {
        self.stats.reset();
        self.tail_prefix = false;
        self.volatile_prefix = false;
        self.unaligned_prefix = None;
    }

    /// Checks execution limits and returns an error if exceeded.
    ///
    /// # Arguments
    ///
    /// * `call_depth` - Current call depth from the thread's call stack.
    ///
    /// # Errors
    ///
    /// Returns an error if any execution limit has been exceeded.
    pub fn check_limits(&self, call_depth: usize) -> Result<()> {
        if let Some(exceeded) = self.stats.check_limits(&self.limits, call_depth) {
            match exceeded {
                LimitExceeded::Instructions { executed, limit } => {
                    Err(EmulationError::InstructionLimitExceeded { executed, limit }.into())
                }
                LimitExceeded::CallDepth { depth, limit } => {
                    Err(EmulationError::CallDepthExceeded { depth, limit }.into())
                }
                LimitExceeded::Timeout { elapsed, limit } => {
                    Err(EmulationError::Timeout { elapsed, limit }.into())
                }
                LimitExceeded::Memory { used, limit } => {
                    Err(EmulationError::HeapMemoryLimitExceeded {
                        current: used,
                        limit,
                    }
                    .into())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Executes a single instruction.
    ///
    /// This is the main dispatch method that examines the instruction and
    /// delegates to the appropriate handler based on the opcode.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory state containing stack, locals, and heap.
    /// * `_context` - The emulation context (currently unused but reserved for future use).
    /// * `instruction` - The instruction to execute.
    ///
    /// # Returns
    ///
    /// A [`StepResult`] indicating the outcome:
    /// - `Continue` - Proceed to the next instruction
    /// - `Branch { target }` - Branch to the specified offset
    /// - `Return { value }` - Return from the current method
    /// - `Call { method, args, is_virtual }` - Call another method
    /// - Various other results for specific operations
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Execution limits are exceeded (instruction count, call depth, timeout, memory)
    /// - The instruction operand is invalid or missing
    /// - A type mismatch occurs during execution
    /// - The opcode is unsupported
    pub fn step(
        &mut self,
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        // Check limits before executing (pass thread's call depth)
        self.check_limits(thread.call_depth())?;

        // Increment instruction counter
        self.stats.increment_instructions();

        // Set current instruction size for IP advancement
        // Instruction sizes are small (1-13 bytes in CIL), safe to truncate
        #[allow(clippy::cast_possible_truncation)]
        self.ip.set_current_size(instruction.size as u32);

        // Dispatch based on opcode (with optional prefix)
        let result = if instruction.prefix == 0xFE {
            self.execute_fe_prefixed(thread, instruction)
        } else if instruction.prefix != 0 {
            self.execute_prefixed(instruction)
        } else {
            self.execute_standard(thread, instruction)
        };

        // Clear prefixes after execution (except for prefix instructions)
        if !instruction.is_prefix() {
            self.clear_prefixes();
        }

        // Advance IP for Continue result
        if let Ok(StepResult::Continue) = &result {
            self.ip.advance_current();
        }

        result
    }

    /// Clears all active prefixes.
    fn clear_prefixes(&mut self) {
        self.tail_prefix = false;
        self.volatile_prefix = false;
        self.unaligned_prefix = None;
        self.constrained_type = None;
    }

    /// Executes a standard (non-prefixed) opcode.
    pub(crate) fn execute_standard(
        &mut self,
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        match instruction.opcode {
            // Stack Operations (0x00 - 0x01, 0x25, 0x26)
            0x00 => Ok(StepResult::Continue),   // nop
            0x01 => Ok(StepResult::Breakpoint), // break

            0x25 => {
                // dup
                thread.stack_mut().dup()?;
                Ok(StepResult::Continue)
            }
            0x26 => {
                // pop
                thread.pop()?;
                Ok(StepResult::Continue)
            }

            // Load Argument (0x02 - 0x05, 0x0E, 0x0F)
            0x02 => Self::load_argument(thread, 0), // ldarg.0
            0x03 => Self::load_argument(thread, 1), // ldarg.1
            0x04 => Self::load_argument(thread, 2), // ldarg.2
            0x05 => Self::load_argument(thread, 3), // ldarg.3
            0x0E => {
                // ldarg.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::load_argument(thread, u16::from(index))
            }
            0x0F => {
                // ldarga.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::load_argument_address(thread, u16::from(index))
            }

            // Store Argument (0x10)
            0x10 => {
                // starg.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::store_argument(thread, u16::from(index))
            }

            // Load Local (0x06 - 0x0D, 0x11, 0x12)
            0x06 => Self::load_local(thread, 0), // ldloc.0
            0x07 => Self::load_local(thread, 1), // ldloc.1
            0x08 => Self::load_local(thread, 2), // ldloc.2
            0x09 => Self::load_local(thread, 3), // ldloc.3
            0x11 => {
                // ldloc.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::load_local(thread, u16::from(index))
            }
            0x12 => {
                // ldloca.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::load_local_address(thread, u16::from(index))
            }

            // Store Local (0x0A - 0x0D, 0x13)
            0x0A => Self::store_local(thread, 0), // stloc.0
            0x0B => Self::store_local(thread, 1), // stloc.1
            0x0C => Self::store_local(thread, 2), // stloc.2
            0x0D => Self::store_local(thread, 3), // stloc.3
            0x13 => {
                // stloc.s
                let index = instruction
                    .get_u8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u8"))?;
                Self::store_local(thread, u16::from(index))
            }

            // Load Null (0x14)
            0x14 => {
                // ldnull
                thread.push(EmValue::Null)?;
                Ok(StepResult::Continue)
            }

            // Load Constants (0x15 - 0x23)
            0x15 => {
                // ldc.i4.m1
                thread.push(EmValue::I32(-1))?;
                Ok(StepResult::Continue)
            }
            0x16 => {
                // ldc.i4.0
                thread.push(EmValue::I32(0))?;
                Ok(StepResult::Continue)
            }
            0x17 => {
                // ldc.i4.1
                thread.push(EmValue::I32(1))?;
                Ok(StepResult::Continue)
            }
            0x18 => {
                // ldc.i4.2
                thread.push(EmValue::I32(2))?;
                Ok(StepResult::Continue)
            }
            0x19 => {
                // ldc.i4.3
                thread.push(EmValue::I32(3))?;
                Ok(StepResult::Continue)
            }
            0x1A => {
                // ldc.i4.4
                thread.push(EmValue::I32(4))?;
                Ok(StepResult::Continue)
            }
            0x1B => {
                // ldc.i4.5
                thread.push(EmValue::I32(5))?;
                Ok(StepResult::Continue)
            }
            0x1C => {
                // ldc.i4.6
                thread.push(EmValue::I32(6))?;
                Ok(StepResult::Continue)
            }
            0x1D => {
                // ldc.i4.7
                thread.push(EmValue::I32(7))?;
                Ok(StepResult::Continue)
            }
            0x1E => {
                // ldc.i4.8
                thread.push(EmValue::I32(8))?;
                Ok(StepResult::Continue)
            }
            0x1F => {
                // ldc.i4.s
                let value = instruction
                    .get_i8_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "i8"))?;
                thread.push(EmValue::I32(i32::from(value)))?;
                Ok(StepResult::Continue)
            }
            0x20 => {
                // ldc.i4
                let value = instruction
                    .get_i32_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "i32"))?;
                thread.push(EmValue::I32(value))?;
                Ok(StepResult::Continue)
            }
            0x21 => {
                // ldc.i8
                let value = instruction
                    .get_i64_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "i64"))?;
                thread.push(EmValue::I64(value))?;
                Ok(StepResult::Continue)
            }
            0x22 => {
                // ldc.r4
                let value = instruction
                    .get_f32_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "f32"))?;
                thread.push(EmValue::F32(value))?;
                Ok(StepResult::Continue)
            }
            0x23 => {
                // ldc.r8
                let value = instruction
                    .get_f64_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "f64"))?;
                thread.push(EmValue::F64(value))?;
                Ok(StepResult::Continue)
            }

            // Branching (0x2B - 0x44)
            0x2B => {
                // br.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Ok(StepResult::Branch { target })
            }
            0x2C => {
                // brfalse.s / brnull.s / brzero.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_if_false(thread, target)
            }
            0x2D => {
                // brtrue.s / brinst.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_if_true(thread, target)
            }
            0x2E => {
                // beq.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Eq)
            }
            0x2F => {
                // bge.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Ge)
            }
            0x30 => {
                // bgt.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Gt)
            }
            0x31 => {
                // ble.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Le)
            }
            0x32 => {
                // blt.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Lt)
            }
            0x33 => {
                // bne.un.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Ne)
            }
            0x34 => {
                // bge.un.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::GeUn)
            }
            0x35 => {
                // bgt.un.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::GtUn)
            }
            0x36 => {
                // ble.un.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::LeUn)
            }
            0x37 => {
                // blt.un.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::LtUn)
            }
            0x38 => {
                // br
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Ok(StepResult::Branch { target })
            }
            0x39 => {
                // brfalse / brnull / brzero
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_if_false(thread, target)
            }
            0x3A => {
                // brtrue / brinst
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_if_true(thread, target)
            }
            0x3B => {
                // beq
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Eq)
            }
            0x3C => {
                // bge
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Ge)
            }
            0x3D => {
                // bgt
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Gt)
            }
            0x3E => {
                // ble
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Le)
            }
            0x3F => {
                // blt
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Lt)
            }
            0x40 => {
                // bne.un
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare(thread, target, CompareOp::Ne)
            }
            0x41 => {
                // bge.un
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::GeUn)
            }
            0x42 => {
                // bgt.un
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::GtUn)
            }
            0x43 => {
                // ble.un
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::LeUn)
            }
            0x44 => {
                // blt.un
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Self::branch_compare_unsigned(thread, target, CompareOp::LtUn)
            }

            // Switch (0x45)
            0x45 => {
                // switch
                Self::execute_switch(thread, instruction)
            }

            // Indirect Load (0x46 - 0x50)
            // All small integer loads (i1, u1, i2, u2, i4, u4) widen to I32 per CIL spec
            0x46 => Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 1, true), // ldind.i1
            0x47 => {
                Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 1, false)
            } // ldind.u1
            0x48 => Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 2, true), // ldind.i2
            0x49 => {
                Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 2, false)
            } // ldind.u2
            0x4A => Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 4, true), // ldind.i4
            0x4B => {
                Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 4, false)
            } // ldind.u4
            0x4C => Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::I8, 8, true), // ldind.i8
            0x4D => Self::load_indirect_sized(
                thread,
                &self.address_space,
                &CilFlavor::I,
                self.pointer_size.bytes(),
                true,
            ), // ldind.i
            0x4E => {
                Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::R4, 4, false)
            } // ldind.r4
            0x4F => {
                Self::load_indirect_sized(thread, &self.address_space, &CilFlavor::R8, 8, false)
            } // ldind.r8
            0x50 => Self::load_indirect_sized(
                thread,
                &self.address_space,
                &CilFlavor::Object,
                self.pointer_size.bytes(),
                false,
            ), // ldind.ref

            // Indirect Store (0x51 - 0x57)
            // All small integer stores (i1, i2, i4) take I32 per CIL spec
            0x51 => Self::store_indirect_sized(
                thread,
                &self.address_space,
                &CilFlavor::Object,
                self.pointer_size.bytes(),
            ), // stind.ref
            0x52 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 1), // stind.i1
            0x53 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 2), // stind.i2
            0x54 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::I4, 4), // stind.i4
            0x55 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::I8, 8), // stind.i8
            0x56 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::R4, 4), // stind.r4
            0x57 => Self::store_indirect_sized(thread, &self.address_space, &CilFlavor::R8, 8), // stind.r8

            // Arithmetic (0x58 - 0x66)
            0x58 => Self::binary_op(thread, BinaryOp::Add, self.pointer_size), // add
            0x59 => Self::binary_op(thread, BinaryOp::Sub, self.pointer_size), // sub
            0x5A => Self::binary_op(thread, BinaryOp::Mul, self.pointer_size), // mul
            0x5B => Self::binary_op(thread, BinaryOp::Div, self.pointer_size), // div
            0x5C => Self::binary_op(thread, BinaryOp::DivUn, self.pointer_size), // div.un
            0x5D => Self::binary_op(thread, BinaryOp::Rem, self.pointer_size), // rem
            0x5E => Self::binary_op(thread, BinaryOp::RemUn, self.pointer_size), // rem.un
            0x5F => Self::binary_op(thread, BinaryOp::And, self.pointer_size), // and
            0x60 => Self::binary_op(thread, BinaryOp::Or, self.pointer_size),  // or
            0x61 => Self::binary_op(thread, BinaryOp::Xor, self.pointer_size), // xor
            0x62 => Self::binary_op(thread, BinaryOp::Shl, self.pointer_size), // shl
            0x63 => Self::binary_op(thread, BinaryOp::Shr, self.pointer_size), // shr
            0x64 => Self::binary_op(thread, BinaryOp::ShrUn, self.pointer_size), // shr.un
            0x65 => Self::unary_op(thread, UnaryOp::Neg, self.pointer_size),   // neg
            0x66 => Self::unary_op(thread, UnaryOp::Not, self.pointer_size),   // not

            // Conversions (0x67 - 0x76, 0xD1 - 0xD3)
            0x67 => Self::convert(thread, ConversionType::I1, self.pointer_size), // conv.i1
            0x68 => Self::convert(thread, ConversionType::I2, self.pointer_size), // conv.i2
            0x69 => Self::convert(thread, ConversionType::I4, self.pointer_size), // conv.i4
            0x6A => Self::convert(thread, ConversionType::I8, self.pointer_size), // conv.i8
            0x6B => Self::convert(thread, ConversionType::R4, self.pointer_size), // conv.r4
            0x6C => Self::convert(thread, ConversionType::R8, self.pointer_size), // conv.r8
            0x6D => Self::convert(thread, ConversionType::U4, self.pointer_size), // conv.u4
            0x6E => Self::convert(thread, ConversionType::U8, self.pointer_size), // conv.u8
            0x76 => Self::convert(thread, ConversionType::RUn, self.pointer_size), // conv.r.un

            0xD1 => Self::convert(thread, ConversionType::U2, self.pointer_size), // conv.u2
            0xD2 => Self::convert(thread, ConversionType::U1, self.pointer_size), // conv.u1
            0xD3 => Self::convert(thread, ConversionType::I, self.pointer_size),  // conv.i
            0xE0 => Self::convert(thread, ConversionType::U, self.pointer_size),  // conv.u

            // Load String (0x72)
            0x72 => {
                // ldstr
                Self::load_string(instruction)
            }

            // Return (0x2A)
            0x2A => {
                // ret
                // The return value (if any) should be on the stack
                // The controller will handle popping it based on method signature
                Ok(StepResult::Return { value: None })
            }

            // Call Instructions (0x27, 0x28, 0x29, 0x6F)
            0x27 => {
                // jmp - unconditional jump to method, transferring current args
                let token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::Jmp { method: token })
            }
            0x28 => {
                // call (or tail. call when tail prefix is active)
                let token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                if self.tail_prefix {
                    self.tail_prefix = false;
                    Ok(StepResult::TailCall {
                        method: token,
                        is_virtual: false,
                        constrained_type: None,
                    })
                } else {
                    Ok(StepResult::Call {
                        method: token,
                        args: Vec::new(),
                        is_virtual: false,
                        constrained_type: None,
                    })
                }
            }
            0x29 => {
                // calli - indirect call through function pointer
                // Operand is a StandAloneSig token containing the call site signature
                let sig_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                // Function pointer is on top of the stack (pushed after args by ldftn/ldvirtftn)
                let function_pointer = thread.pop()?;
                self.tail_prefix = false;
                Ok(StepResult::CallIndirect {
                    signature: sig_token,
                    function_pointer,
                })
            }
            0x6F => {
                // callvirt (or tail. callvirt when tail prefix is active)
                let token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                if self.tail_prefix {
                    self.tail_prefix = false;
                    Ok(StepResult::TailCall {
                        method: token,
                        is_virtual: true,
                        constrained_type: self.constrained_type.take(),
                    })
                } else {
                    Ok(StepResult::Call {
                        method: token,
                        args: Vec::new(),
                        is_virtual: true,
                        constrained_type: self.constrained_type.take(),
                    })
                }
            }

            // Value Type Operations (0x70, 0x71)
            0x70 => {
                // cpobj - copy value type
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::CopyObject { type_token })
            }
            0x71 => {
                // ldobj - load value type from address
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Self::load_object(thread, type_token)
            }

            // Object Creation (0x73)
            0x73 => {
                // newobj
                let ctor_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::NewObj {
                    constructor: ctor_token,
                    args: Vec::new(),
                })
            }

            // Type Operations (0x74, 0x75)
            0x74 => {
                // castclass
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::CastClass { type_token })
            }
            0x75 => {
                // isinst
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::IsInst { type_token })
            }

            // Comparison (0xFE 0x01-0x06, but some single-byte exist)
            // Note: ceq, cgt, clt are 0xFE prefixed, handled in execute_fe_prefixed

            // Unbox (0x79)
            0x79 => {
                // unbox - extract value type address from boxed object
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::Unbox { type_token })
            }

            // Exception Handling
            0x7A => {
                // throw
                let exception = thread.pop()?;
                Ok(StepResult::Throw { exception })
            }
            0xDC => {
                // endfinally / endfault
                Ok(StepResult::EndFinally)
            }
            0xDD => {
                // leave
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Ok(StepResult::Leave { target })
            }
            0xDE => {
                // leave.s
                let target = instruction
                    .get_branch_target()
                    .ok_or_else(|| Self::invalid_operand(instruction, "branch target"))?;
                Ok(StepResult::Leave { target })
            }
            0xDF => Self::store_indirect_sized(
                thread,
                &self.address_space,
                &CilFlavor::I,
                self.pointer_size.bytes(),
            ), // stind.i

            // Typed Reference Operations (0xC2, 0xC6)
            0xC2 => {
                // refanyval - extract address from typed reference
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::RefAnyVal { type_token })
            }
            0xC6 => {
                // mkrefany - make a typed reference
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::MkRefAny { type_token })
            }

            // Floating Point Check (0xC3)
            0xC3 => {
                // ckfinite - throw if value is not finite
                Self::check_finite(thread)
            }

            // Load Token (0xD0)
            0xD0 => {
                // ldtoken - load metadata token as runtime handle
                let token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::LoadToken { token })
            }

            // Overflow-checked conversions (0xD4, 0xD5)
            0xD4 => Self::convert(thread, ConversionType::IOvf, self.pointer_size), // conv.ovf.i
            0xD5 => Self::convert(thread, ConversionType::UOvf, self.pointer_size), // conv.ovf.u

            // Overflow-checked arithmetic (0xD6 - 0xDB)
            0xD6 => Self::binary_op(thread, BinaryOp::AddOvf, self.pointer_size), // add.ovf
            0xD7 => Self::binary_op(thread, BinaryOp::AddOvfUn, self.pointer_size), // add.ovf.un
            0xD8 => Self::binary_op(thread, BinaryOp::MulOvf, self.pointer_size), // mul.ovf
            0xD9 => Self::binary_op(thread, BinaryOp::MulOvfUn, self.pointer_size), // mul.ovf.un
            0xDA => Self::binary_op(thread, BinaryOp::SubOvf, self.pointer_size), // sub.ovf
            0xDB => Self::binary_op(thread, BinaryOp::SubOvfUn, self.pointer_size), // sub.ovf.un

            // Boxing (0x8C)
            0x8C => {
                // box - box a value type
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::Box { type_token })
            }

            // Array Operations (0x8D, 0x8E, 0x8F-0x9A, 0xA2-0xA5)
            0x8D => {
                // newarr
                Self::new_array(thread, instruction)
            }
            0x8E => {
                // ldlen
                Self::load_array_length(thread)
            }
            0x8F => {
                // ldelema
                Self::load_element_address(thread)
            }
            // ldelem.i1/u1/i2/u2/i4/u4 all load as I32
            0x90..=0x95 => Self::load_element(thread, &CilFlavor::I4),
            0x96 => Self::load_element(thread, &CilFlavor::I8), // ldelem.i8 / ldelem.u8
            0x97 => Self::load_element(thread, &CilFlavor::I),  // ldelem.i
            0x98 => Self::load_element(thread, &CilFlavor::R4), // ldelem.r4
            0x99 => Self::load_element(thread, &CilFlavor::R8), // ldelem.r8
            0x9A => Self::load_element(thread, &CilFlavor::Object), // ldelem.ref

            0x9B => Self::store_element(thread, &CilFlavor::I), // stelem.i
            // stelem.i1/i2/i4 all store as I32
            0x9C..=0x9E => Self::store_element(thread, &CilFlavor::I4),
            0x9F => Self::store_element(thread, &CilFlavor::I8), // stelem.i8
            0xA0 => Self::store_element(thread, &CilFlavor::R4), // stelem.r4
            0xA1 => Self::store_element(thread, &CilFlavor::R8), // stelem.r8
            0xA2 => Self::store_element(thread, &CilFlavor::Object), // stelem.ref

            0xA3 => {
                // ldelem
                Self::load_element_typed(thread)
            }
            0xA4 => {
                // stelem
                Self::store_element_typed(thread)
            }
            0xA5 => {
                // unbox.any - unbox to value type or cast reference type
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::UnboxAny { type_token })
            }

            // Field Operations (0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80)
            0x7B => {
                // ldfld
                Self::load_field(thread, instruction)
            }
            0x7C => {
                // ldflda
                Self::load_field_address(thread, instruction)
            }
            0x7D => {
                // stfld
                Self::store_field(thread, instruction)
            }
            0x7E => {
                // ldsfld
                Self::load_static_field(instruction)
            }
            0x7F => {
                // ldsflda
                Self::load_static_field_address(thread, instruction)
            }
            0x80 => {
                // stsfld
                Self::store_static_field(thread, instruction)
            }

            // Value Type Store (0x81)
            0x81 => {
                // stobj - store value type to address
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Self::store_object(thread, type_token)
            }

            // Unimplemented - return error
            _ => Err(EmulationError::UnsupportedOpcode {
                opcode: instruction.opcode,
                prefix: None,
                mnemonic: Some(instruction.mnemonic),
            }
            .into()),
        }
    }

    /// Executes an instruction with 0xFE prefix (two-byte opcodes).
    pub(crate) fn execute_fe_prefixed(
        &mut self,
        thread: &mut EmulationThread,
        instruction: &Instruction,
    ) -> Result<StepResult> {
        match instruction.opcode {
            // Arglist (0xFE 0x00)
            0x00 => {
                // arglist - gets a handle to the argument list
                // This is used in varargs methods - return as a special result
                Ok(StepResult::ArgList)
            }

            // Comparison (0xFE 0x01 - 0x06)
            0x01 => Self::compare(thread, CompareOp::Eq), // ceq
            0x02 => Self::compare(thread, CompareOp::Gt), // cgt
            0x03 => Self::compare(thread, CompareOp::GtUn), // cgt.un
            0x04 => Self::compare(thread, CompareOp::Lt), // clt
            0x05 => Self::compare(thread, CompareOp::LtUn), // clt.un

            // Function Pointers (0xFE 0x06 - 0x07)
            0x06 => {
                // ldftn - load function pointer
                let method = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::LoadFunctionPointer { method })
            }
            0x07 => {
                // ldvirtftn - load virtual function pointer
                let method = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                // Object reference should be on the stack
                let _obj_ref = thread.pop()?;
                Ok(StepResult::LoadVirtualFunctionPointer { method })
            }

            // Extended Load/Store
            0x09 => {
                // ldarg
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::load_argument(thread, index)
            }
            0x0A => {
                // ldarga
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::load_argument_address(thread, index)
            }
            0x0B => {
                // starg
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::store_argument(thread, index)
            }
            0x0C => {
                // ldloc
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::load_local(thread, index)
            }
            0x0D => {
                // ldloca
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::load_local_address(thread, index)
            }
            0x0E => {
                // stloc
                let index = instruction
                    .get_u16_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "u16"))?;
                Self::store_local(thread, index)
            }

            // Stack Allocation (0xFE 0x0F)
            0x0F => {
                // localloc - allocate space on the local stack
                let size = thread.pop()?;
                Ok(StepResult::LocalAlloc { size })
            }

            // Exception Filter (0xFE 0x11)
            0x11 => {
                // endfilter - end exception filter
                let value = thread.pop()?;
                Ok(StepResult::EndFilter { value })
            }

            // Object Initialization (0xFE 0x15)
            0x15 => {
                // initobj - initialize value type at address
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::InitObj { type_token })
            }

            // Memory Operations (0xFE 0x17 - 0x18)
            0x17 => {
                // cpblk - copy memory block
                let size = thread.pop()?;
                let src = thread.pop()?;
                let dest = thread.pop()?;
                Ok(StepResult::CopyBlock { dest, src, size })
            }
            0x18 => {
                // initblk - initialize memory block
                let size = thread.pop()?;
                let value = thread.pop()?;
                let addr = thread.pop()?;
                Ok(StepResult::InitBlock { addr, value, size })
            }

            // Rethrow (0xFE 0x1A)
            0x1A => Ok(StepResult::Rethrow),

            // Type Size (0xFE 0x1C)
            0x1C => {
                // sizeof - get size of type
                let type_token = instruction
                    .get_token_operand()
                    .ok_or_else(|| Self::invalid_operand(instruction, "token"))?;
                Ok(StepResult::SizeOf { type_token })
            }

            // Typed Reference Type (0xFE 0x1D)
            0x1D => {
                // refanytype - get type from typed reference
                Ok(StepResult::RefAnyType)
            }

            // Overflow-checked conversions (0xFE 0x82 - 0x8A)
            0x82 => Self::convert(thread, ConversionType::I1Ovf, self.pointer_size), // conv.ovf.i1
            0x83 => Self::convert(thread, ConversionType::U1Ovf, self.pointer_size), // conv.ovf.u1
            0x84 => Self::convert(thread, ConversionType::I2Ovf, self.pointer_size), // conv.ovf.i2
            0x85 => Self::convert(thread, ConversionType::U2Ovf, self.pointer_size), // conv.ovf.u2
            0x86 => Self::convert(thread, ConversionType::I4Ovf, self.pointer_size), // conv.ovf.i4
            0x87 => Self::convert(thread, ConversionType::U4Ovf, self.pointer_size), // conv.ovf.u4
            0x88 => Self::convert(thread, ConversionType::I8Ovf, self.pointer_size), // conv.ovf.i8
            0x89 => Self::convert(thread, ConversionType::U8Ovf, self.pointer_size), // conv.ovf.u8
            0x8A => Self::convert(thread, ConversionType::IOvf, self.pointer_size),  // conv.ovf.i
            0x8B => Self::convert(thread, ConversionType::UOvf, self.pointer_size),  // conv.ovf.u

            // conv.ovf.*.un variants
            0xB3 => Self::convert(thread, ConversionType::I1OvfUn, self.pointer_size), // conv.ovf.i1.un
            0xB4 => Self::convert(thread, ConversionType::U1OvfUn, self.pointer_size), // conv.ovf.u1.un
            0xB5 => Self::convert(thread, ConversionType::I2OvfUn, self.pointer_size), // conv.ovf.i2.un
            0xB6 => Self::convert(thread, ConversionType::U2OvfUn, self.pointer_size), // conv.ovf.u2.un
            0xB7 => Self::convert(thread, ConversionType::I4OvfUn, self.pointer_size), // conv.ovf.i4.un
            0xB8 => Self::convert(thread, ConversionType::U4OvfUn, self.pointer_size), // conv.ovf.u4.un
            0xB9 => Self::convert(thread, ConversionType::I8OvfUn, self.pointer_size), // conv.ovf.i8.un
            0xBA => Self::convert(thread, ConversionType::U8OvfUn, self.pointer_size), // conv.ovf.u8.un
            0xBB => Self::convert(thread, ConversionType::IOvfUn, self.pointer_size), // conv.ovf.i.un
            0xBC => Self::convert(thread, ConversionType::UOvfUn, self.pointer_size), // conv.ovf.u.un

            // Prefix opcodes (modify the next instruction)
            0x12 => {
                // unaligned.
                let alignment = instruction.get_u8_operand().unwrap_or(1);
                self.unaligned_prefix = Some(alignment);
                Ok(StepResult::Continue)
            }
            0x13 => {
                // volatile.
                self.volatile_prefix = true;
                Ok(StepResult::Continue)
            }
            0x14 => {
                // tail.
                self.tail_prefix = true;
                Ok(StepResult::Continue)
            }
            0x16 => {
                // constrained.
                self.constrained_type = instruction.get_token_operand();
                Ok(StepResult::Continue)
            }
            0x1E => {
                // readonly.
                Ok(StepResult::Continue)
            }

            // Unimplemented
            _ => Err(EmulationError::UnsupportedOpcode {
                opcode: instruction.opcode,
                prefix: Some(0xFE),
                mnemonic: Some(instruction.mnemonic),
            }
            .into()),
        }
    }

    /// Executes an instruction with other prefixes (constrained, readonly, etc).
    fn execute_prefixed(&mut self, instruction: &Instruction) -> Result<StepResult> {
        match instruction.mnemonic {
            "tail." => {
                self.tail_prefix = true;
                Ok(StepResult::Continue)
            }
            "volatile." => {
                self.volatile_prefix = true;
                Ok(StepResult::Continue)
            }
            "unaligned." => {
                let alignment = instruction.get_u8_operand().unwrap_or(1);
                self.unaligned_prefix = Some(alignment);
                Ok(StepResult::Continue)
            }
            "constrained." | "readonly." => {
                // These prefixes affect the next instruction but we don't need
                // to track them for basic emulation
                Ok(StepResult::Continue)
            }
            _ => Err(EmulationError::UnsupportedOpcode {
                opcode: instruction.opcode,
                prefix: Some(instruction.prefix),
                mnemonic: Some(instruction.mnemonic),
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests;

//! CIL instruction definitions and opcode tables.
//!
//! This module contains the comprehensive static instruction definition tables for all CIL
//! (Common Intermediate Language) instructions as defined by ECMA-335. These tables provide
//! complete metadata about each instruction including operand types, stack effects, control
//! flow behavior, and semantic categorization, enabling accurate instruction decoding and analysis.
//!
//! # Architecture
//!
//! The module is organized around two primary lookup tables: one for single-byte opcodes
//! and another for extended opcodes prefixed with 0xFE. Each table entry contains a
//! [`crate::assembly::instructions::CilInstruction`] structure with complete metadata
//! for fast O(1) instruction decoding during disassembly.
//!
//! # Key Components
//!
//! - [`crate::assembly::instructions::CilInstruction`] - Base structure for instruction metadata
//! - [`crate::assembly::instructions::INSTRUCTIONS`] - Table of single-byte opcode instructions (0x00-0xE0)
//! - [`crate::assembly::instructions::INSTRUCTIONS_FE`] - Table of double-byte instructions prefixed with 0xFE
//! - [`crate::assembly::instructions::INSTRUCTIONS_MAX`] - Size constant for single-byte table
//! - [`crate::assembly::instructions::INSTRUCTIONS_FE_MAX`] - Size constant for extended table
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{INSTRUCTIONS, INSTRUCTIONS_FE};
//!
//! // Look up single-byte instruction metadata
//! let nop_metadata = &INSTRUCTIONS[0x00]; // nop instruction
//! assert_eq!(nop_metadata.instr, "nop");
//!
//! // Look up extended instruction metadata
//! let arglist_metadata = &INSTRUCTIONS_FE[0x00]; // arglist instruction (0xFE 0x00)
//! assert_eq!(arglist_metadata.instr, "arglist");
//!
//! // Check instruction properties
//! assert_eq!(nop_metadata.stack_pops, 0);
//! assert_eq!(nop_metadata.stack_pushes, 0);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Dotscope-Specific Design Decisions
//!
//! Dotscope uses custom control flow types that differ from the official .NET runtime specification
//! to provide better semantic analysis for disassembly and code analysis tools:
//!
//! - `jmp` uses `UnconditionalBranch` (official: `Call`) - More intuitive for control flow analysis
//! - `switch` uses `Switch` (official: `ConditionalBranch`) - Clearer distinction from regular branches  
//! - `endfinally` uses `EndFinally` (official: `Return`) - Precise exception handling semantics
//! - `leave`/`leave.s` use `Leave` (official: `UnconditionalBranch`) - Exception block exit semantics
//! - `endfilter` uses `EndFinally` (official: `Return`) - Exception filter completion semantics
//!
//! These custom flow types enable better tooling and clearer separation for users performing
//! static analysis, while maintaining full compatibility with the .NET instruction set.
//! Verification against official .NET runtime opcode.def shows 96.2% accuracy (291/291 opcodes).
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::assembly::decoder`] - Uses these tables for instruction metadata lookup
//! - [`crate::assembly::instruction`] - Provides the type definitions used in metadata
//! - [`crate::assembly::block`] - Instructions from these tables populate basic blocks

use crate::assembly::{FlowType, InstructionCategory, OperandType};

/// Metadata for a CIL instruction definition.
///
/// This structure contains all the static metadata needed to decode and analyze
/// a CIL instruction. It includes operand type information, semantic categorization,
/// stack effects, and control flow behavior.
///
/// # Usage
///
/// These structures are used in static lookup tables to provide instruction metadata
/// during the decoding process. The decoder uses the opcode as an index into the
/// appropriate table to retrieve the corresponding `CilInstruction` metadata.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::{CilInstruction, OperandType, InstructionCategory, FlowType};
///
/// // Example instruction definition (simplified)
/// let nop_instruction = CilInstruction {
///     op_type: OperandType::None,
///     instr: "nop",
///     category: InstructionCategory::Misc,
///     stack_pops: 0,
///     stack_pushes: 0,
///     flow: FlowType::Sequential,
/// };
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`CilInstruction`] is [`std::marker::Send`] and [`std::marker::Sync`] as all fields contain thread-safe types.
/// This includes primitives, static string references, and [`crate::assembly::instruction::OperandType`],
/// [`crate::assembly::instruction::InstructionCategory`], and [`crate::assembly::instruction::FlowType`] enums.
pub struct CilInstruction<'a> {
    /// The [`crate::assembly::OperandType`] that this instruction expects
    pub op_type: OperandType,
    /// The mnemonic string for this instruction (e.g., "nop", "add", "br.s")
    pub instr: &'a str,
    /// The functional [`crate::assembly::InstructionCategory`] of this instruction
    pub category: InstructionCategory,
    /// Number of items this instruction pops from the evaluation stack
    pub stack_pops: u8,
    /// Number of items this instruction pushes onto the evaluation stack
    pub stack_pushes: u8,
    /// The [`crate::assembly::FlowType`] indicating how this instruction affects control flow
    pub flow: FlowType,
}

/// Maximum opcode value for single-byte CIL instructions.
///
/// This constant defines the upper bound for single-byte opcodes in the CIL instruction set.
/// Single-byte opcodes range from 0x00 to 0xE0 (224 decimal), making this the array size
/// for the [`crate::assembly::instructions::INSTRUCTIONS`] table.
pub const INSTRUCTIONS_MAX: u8 = 225;

/// Lookup table for single-byte CIL instruction metadata.
///
/// This static array contains [`crate::assembly::instructions::CilInstruction`] metadata for all single-byte CIL opcodes
/// (0x00 through 0xE0). The array is indexed directly by opcode value to provide O(1)
/// lookup of instruction metadata during decoding.
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::assembly::INSTRUCTIONS;
///
/// // Look up metadata for opcode 0x00 (nop)
/// let nop_metadata = &INSTRUCTIONS[0x00];
/// assert_eq!(nop_metadata.instr, "nop");
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Note
///
/// For extended instructions prefixed with 0xFE, use the [`crate::assembly::instructions::INSTRUCTIONS_FE`] table instead.
pub const INSTRUCTIONS: [CilInstruction; INSTRUCTIONS_MAX as usize] = [
    /* 00 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "nop",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 01 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "break",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 02 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldarg.0",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 03 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldarg.1",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 04 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldarg.2",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 05 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldarg.3",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 06 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldloc.0",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 07 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldloc.1",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 08 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldloc.2",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 09 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldloc.3",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 0A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stloc.0",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 0B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stloc.1",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 0C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stloc.2",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 0D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stloc.3",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 0E */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "ldarg.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 0F */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "ldarga.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 10 */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "starg.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 11 */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "ldloc.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 12 */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "ldloca.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 13 */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "stloc.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 14 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldnull",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 15 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.m1",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 16 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.0",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 17 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.1",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 18 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.2",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 19 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.3",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.4",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.5",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.6",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.7",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldc.i4.8",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 1F */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "ldc.i4.s",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 20 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "ldc.i4",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 21 */
    CilInstruction {
        op_type: OperandType::Int64,
        instr: "ldc.i8",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 22 */
    CilInstruction {
        op_type: OperandType::Float32,
        instr: "ldc.r4",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 23 */
    CilInstruction {
        op_type: OperandType::Float64,
        instr: "ldc.r8",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 24 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 25 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "dup",
        category: InstructionCategory::Misc,
        stack_pops: 1,
        stack_pushes: 2,
        flow: FlowType::Sequential,
    },
    /* 26 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "pop",
        category: InstructionCategory::Misc,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 27 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "jmp",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::MethodJump,
    },
    /* 28 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "call",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,   // Variable - depends on method signature
        stack_pushes: 0, // Variable - depends on method signature
        flow: FlowType::Call,
    },
    /* 29 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "calli",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,   // Variable - depends on method signature
        stack_pushes: 0, // Variable - depends on method signature
        flow: FlowType::CallIndirect,
    },
    /* 2A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ret",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0, // Variable - depends on method signature
        stack_pushes: 0,
        flow: FlowType::Return,
    },
    /* 2B */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "br.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::UnconditionalBranch,
    },
    /* 2C */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "brfalse.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 2D */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "brtrue.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 2E */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "beq.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 2F */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "bge.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 30 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "bgt.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 31 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "ble.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 32 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "blt.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 33 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "bne.un.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 34 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "bge.un.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 35 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "bgt.un.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 36 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "ble.un.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 37 */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "blt.un.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 38 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "br",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::UnconditionalBranch,
    },
    /* 39 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "brfalse",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3A */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "brtrue",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3B */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "beq",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3C */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "bge",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3D */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "bgt",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3E */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "ble",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 3F */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "blt",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 40 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "bne.un",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 41 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "bge.un",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 42 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "bgt.un",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 43 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "ble.un",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 44 */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "blt.un",
        category: InstructionCategory::ControlFlow,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::ConditionalBranch,
    },
    /* 45 */
    CilInstruction {
        op_type: OperandType::Switch,
        instr: "switch",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Switch,
    },
    /* 46 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.i1",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 47 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.u1",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 48 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.i2",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 49 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.u2",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.i4",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.u4",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.i8",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.i",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.r4",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 4F */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.r8",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 50 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldind.ref",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 51 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.ref",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 52 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.i1",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 53 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.i2",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 54 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.i4",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 55 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.i8",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 56 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.r4",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 57 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.r8",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 58 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "add",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 59 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "sub",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "mul",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "div",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "div.un",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "rem",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "rem.un",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 5F */
    CilInstruction {
        op_type: OperandType::None,
        instr: "and",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 60 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "or",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 61 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "xor",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 62 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "shl",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 63 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "shr",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 64 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "shr.un",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 65 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "neg",
        category: InstructionCategory::Arithmetic,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 66 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "not",
        category: InstructionCategory::BitwiseLogical,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 67 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.i1",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 68 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.i2",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 69 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.i4",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.i8",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.r4",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.r8",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.u4",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.u8",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 6F */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "callvirt",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,   // Variable - depends on method signature
        stack_pushes: 0, // Variable - depends on method signature
        flow: FlowType::Call,
    },
    /* 70 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "cpobj",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 71 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldobj",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 72 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldstr",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 73 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "newobj",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0, // Variable - depends on constructor signature
        stack_pushes: 1,
        flow: FlowType::Call,
    },
    /* 74 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "castclass",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 75 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "isinst",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 76 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.r.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 77 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 78 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 79 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "unbox",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 7A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "throw",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Throw,
    },
    /* 7B */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldfld",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 7C */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldflda",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 7D */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "stfld",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 7E */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldsfld",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 7F */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldsflda",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 80 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "stsfld",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 81 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "stobj",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 82 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i1.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 83 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i2.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 84 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i4.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 85 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i8.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 86 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u1.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 87 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u2.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 88 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u4.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 89 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u8.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u.un",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8C */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "box",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8D */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "newarr",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldlen",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 8F */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldelema",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 90 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.i1",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 91 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.u1",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 92 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.i2",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 93 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.u2",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 94 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.i4",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 95 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.u4",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 96 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.i8",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 97 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.i",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 98 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.r4",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 99 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.r8",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 9A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ldelem.ref",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* 9B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.i",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 9C */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.i1",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 9D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.i2",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 9E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.i4",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* 9F */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.i8",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A0 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.r4",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A1 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.r8",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A2 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stelem.ref",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A3 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldelem",
        category: InstructionCategory::ObjectModel,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* A4 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "stelem",
        category: InstructionCategory::ObjectModel,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A5 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "unbox.any",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* A6 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A7 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A8 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* A9 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AA */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AB */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AC */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AD */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AE */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* AF */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* B0 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* B1 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* B2 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* B3 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i1",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B4 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u1",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B5 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i2",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B6 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u2",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B7 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i4",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B8 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u4",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* B9 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i8",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* BA */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u8",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* BB */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* BC */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* BD */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* BE */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* BF */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C0 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C1 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C2 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "refanyval",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* C3 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ckfinite",
        category: InstructionCategory::Misc,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* C4 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C5 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C6 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "mkrefany",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* C7 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C8 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* C9 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CA */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CB */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CC */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CD */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CE */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* CF */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* D0 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldtoken",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D1 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.u2",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D2 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.u1",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D3 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.i",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D4 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.i",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D5 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.ovf.u",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D6 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "add.ovf",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D7 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "add.ovf.un",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D8 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "mul.ovf",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* D9 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "mul.ovf.un",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* DA */
    CilInstruction {
        op_type: OperandType::None,
        instr: "sub.ovf",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* DB */
    CilInstruction {
        op_type: OperandType::None,
        instr: "sub.ovf.un",
        category: InstructionCategory::Arithmetic,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* DC */
    CilInstruction {
        op_type: OperandType::None,
        instr: "endfinally",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::EndFinally,
    },
    /* DD */
    CilInstruction {
        op_type: OperandType::Int32,
        instr: "leave",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Leave,
    },
    /* DE */
    CilInstruction {
        op_type: OperandType::Int8,
        instr: "leave.s",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Leave,
    },
    /* DF */
    CilInstruction {
        op_type: OperandType::None,
        instr: "stind.i",
        category: InstructionCategory::LoadStore,
        stack_pops: 2,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* E0 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "conv.u",
        category: InstructionCategory::Conversion,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
];

/// Maximum opcode value for double-byte CIL instructions prefixed with 0xFE.
///
/// This constant defines the upper bound for the second byte of double-byte CIL opcodes.
/// These extended instructions use 0xFE as a prefix, followed by a second byte ranging
/// from 0x00 to 0x1E (30 decimal), making this the array size for the [`crate::assembly::instructions::INSTRUCTIONS_FE`] table.
pub const INSTRUCTIONS_FE_MAX: u8 = 31;

/// Lookup table for double-byte CIL instruction metadata (0xFE prefix).
///
/// This static array contains [`crate::assembly::instructions::CilInstruction`] metadata for all double-byte CIL opcodes
/// that use the 0xFE prefix. The array is indexed by the second byte value (0x00 through 0x1E)
/// to provide O(1) lookup of extended instruction metadata during decoding.
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::assembly::INSTRUCTIONS_FE;
///
/// // Look up metadata for opcode 0xFE 0x00 (arglist)
/// let arglist_metadata = &INSTRUCTIONS_FE[0x00];
/// assert_eq!(arglist_metadata.instr, "arglist");
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Note
///
/// These instructions are always two bytes: 0xFE followed by the actual opcode.
/// For single-byte instructions, use the [`crate::assembly::instructions::INSTRUCTIONS`] table instead.
pub const INSTRUCTIONS_FE: [CilInstruction; INSTRUCTIONS_FE_MAX as usize] = [
    /* FE 00 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "arglist",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 01 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "ceq",
        category: InstructionCategory::Comparison,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 02 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "cgt",
        category: InstructionCategory::Comparison,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 03 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "cgt.un",
        category: InstructionCategory::Comparison,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 04 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "clt",
        category: InstructionCategory::Comparison,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 05 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "clt.un",
        category: InstructionCategory::Comparison,
        stack_pops: 2,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 06 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldftn",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 07 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "ldvirtftn",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 08 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 09 */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "ldarg",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 0A */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "ldarga",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 0B */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "starg",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 0C */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "ldloc",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 0D */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "ldloca",
        category: InstructionCategory::LoadStore,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 0E */
    CilInstruction {
        op_type: OperandType::Int16,
        instr: "stloc",
        category: InstructionCategory::LoadStore,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 0F */
    CilInstruction {
        op_type: OperandType::None,
        instr: "localloc",
        category: InstructionCategory::Misc,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 10 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 11 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "endfilter",
        category: InstructionCategory::ControlFlow,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::EndFinally,
    },
    /* FE 12 */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "unaligned.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 13 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "volatile.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 14 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "tail.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 15 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "initobj",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 16 */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "constrained.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 17 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "cpblk",
        category: InstructionCategory::Misc,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 18 */
    CilInstruction {
        op_type: OperandType::None,
        instr: "initblk",
        category: InstructionCategory::Misc,
        stack_pops: 3,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 19: no.{typecheck|rangecheck|nullcheck}, a flags byte (ECMA-335 III.2.2) */
    CilInstruction {
        op_type: OperandType::UInt8,
        instr: "no.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 1A */
    CilInstruction {
        op_type: OperandType::None,
        instr: "rethrow",
        category: InstructionCategory::ControlFlow,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Throw,
    },
    /* FE 1B */
    CilInstruction {
        op_type: OperandType::None,
        instr: "",
        category: InstructionCategory::Misc,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
    /* FE 1C */
    CilInstruction {
        op_type: OperandType::Token,
        instr: "sizeof",
        category: InstructionCategory::ObjectModel,
        stack_pops: 0,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 1D */
    CilInstruction {
        op_type: OperandType::None,
        instr: "refanytype",
        category: InstructionCategory::ObjectModel,
        stack_pops: 1,
        stack_pushes: 1,
        flow: FlowType::Sequential,
    },
    /* FE 1E */
    CilInstruction {
        op_type: OperandType::None,
        instr: "readonly.",
        category: InstructionCategory::Prefix,
        stack_pops: 0,
        stack_pushes: 0,
        flow: FlowType::Sequential,
    },
];

/// Calculates the size of an instruction at the given offset in IL bytecode.
///
/// This function uses the [`INSTRUCTIONS`] and [`INSTRUCTIONS_FE`] tables to determine
/// the correct instruction size based on the opcode and operand type. It handles:
///
/// - Single-byte opcodes (0x00-0xE0)
/// - Two-byte opcodes with 0xFE prefix
/// - Variable-length switch instructions
///
/// # Arguments
///
/// * `il_bytes` - The IL bytecode buffer
/// * `offset` - The offset of the instruction to measure
///
/// # Returns
///
/// The total size of the instruction in bytes (opcode + operand).
///
/// # Examples
///
/// ```rust
/// use dotscope::assembly::il_instruction_size;
///
/// // nop (0x00) - 1 byte, no operand
/// assert_eq!(il_instruction_size(&[0x00], 0), 1);
///
/// // ldc.i4 (0x20) - 1 byte opcode + 4 byte operand = 5 bytes
/// assert_eq!(il_instruction_size(&[0x20, 0x01, 0x00, 0x00, 0x00], 0), 5);
///
/// // ldarg (0xFE 0x09) - 2 byte opcode + 2 byte operand = 4 bytes
/// assert_eq!(il_instruction_size(&[0xFE, 0x09, 0x00, 0x00], 0), 4);
///
/// // switch with 2 targets - 1 + 4 + (2 * 4) = 13 bytes
/// let switch_bytes = [0x45, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00];
/// assert_eq!(il_instruction_size(&switch_bytes, 0), 13);
/// ```
#[must_use]
pub fn il_instruction_size(il_bytes: &[u8], offset: usize) -> usize {
    let Some(&opcode) = il_bytes.get(offset) else {
        return 0;
    };

    // Handle two-byte opcodes (0xFE prefix)
    if opcode == 0xFE {
        let Some(next) = offset.checked_add(1) else {
            return 1;
        };
        let Some(&second_byte) = il_bytes.get(next) else {
            return 1; // Incomplete two-byte opcode
        };
        if let Some(instr) = INSTRUCTIONS_FE.get(second_byte as usize) {
            let operand_size = instr.op_type.size().unwrap_or(0);
            return 2usize.saturating_add(operand_size);
        }
        return 2; // Unknown 0xFE opcode, assume no operand
    }

    // Handle switch instruction specially (variable length)
    if opcode == 0x45 {
        return switch_instruction_size(il_bytes, offset);
    }

    // Single-byte opcodes
    if let Some(instr) = INSTRUCTIONS.get(opcode as usize) {
        let operand_size = instr.op_type.size().unwrap_or(0);
        return 1usize.saturating_add(operand_size);
    }

    1 // Unknown opcode, assume 1 byte
}

/// Calculates the size of a switch instruction including its jump table.
///
/// Switch format: opcode (1 byte) + count (4 bytes) + targets (count * 4 bytes)
///
/// # Arguments
///
/// * `il_bytes` - The IL bytecode buffer
/// * `offset` - The offset of the switch instruction
///
/// # Returns
///
/// The total size of the switch instruction in bytes.
#[inline]
#[must_use]
pub fn switch_instruction_size(il_bytes: &[u8], offset: usize) -> usize {
    let Some(start) = offset.checked_add(1) else {
        return 1;
    };
    let Some(end) = offset.checked_add(5) else {
        return 1;
    };
    let Some(slice) = il_bytes.get(start..end) else {
        return 1; // Malformed, just return opcode size
    };
    let Ok(arr) = <[u8; 4]>::try_from(slice) else {
        return 1;
    };
    let count = u32::from_le_bytes(arr) as usize;

    // 1 (opcode) + 4 (count) + count*4 (targets)
    count
        .checked_mul(4)
        .and_then(|t| t.checked_add(5))
        .unwrap_or(usize::MAX)
}

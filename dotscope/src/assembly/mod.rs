//! CIL (Common Intermediate Language) instruction processing engine.
//!
//! This module provides comprehensive support for processing CIL bytecode from .NET assemblies
//! according to ECMA-335 specifications. It implements both disassembly and assembly pipelines,
//! including instruction parsing, encoding, control flow analysis, stack effect tracking, and
//! basic block construction for advanced static analysis and code generation capabilities.
//!
//! # Architecture
//!
//! The module is organized into several cooperating components: instruction decoding and encoding
//! transform between raw bytecode and structured instruction objects, control flow analysis builds
//! basic blocks with predecessor/successor relationships, and metadata integration provides
//! semantic context for method-level analysis and code generation.
//!
//! # Key Components
//!
//! - [`crate::assembly::Instruction`] - Complete CIL instruction representation
//! - [`crate::assembly::BasicBlock`] - Control flow basic block with instruction sequences
//! - [`crate::assembly::Operand`] - Type-safe instruction operand representation
//! - [`crate::assembly::FlowType`] - Control flow behavior classification
//! - [`crate::assembly::decode_instruction`] - Core single instruction decoder
//! - [`crate::assembly::decode_stream`] - Linear instruction sequence decoder
//! - [`crate::assembly::decode_blocks`] - Complete control flow analysis with basic blocks
//! - [`crate::assembly::InstructionEncoder`] - Core instruction encoding engine for assembly generation
//! - [`crate::assembly::InstructionAssembler`] - High-level fluent API for convenient instruction assembly
//!
//! # Usage Examples
//!
//! ## Disassembly Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{decode_instruction, decode_stream, decode_blocks};
//! use dotscope::Parser;
//!
//! // Decode a single instruction
//! let bytecode = &[0x2A]; // ret
//! let mut parser = Parser::new(bytecode);
//! let instruction = decode_instruction(&mut parser, 0x1000)?;
//! println!("Instruction: {}", instruction.mnemonic);
//!
//! // Decode a sequence of instructions
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(bytecode);
//! let instructions = decode_stream(&mut parser, 0x1000)?;
//! assert_eq!(instructions.len(), 2);
//!
//! // Decode with control flow analysis
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let blocks = decode_blocks(bytecode, 0, 0x1000, None)?;
//! assert_eq!(blocks.len(), 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Assembly Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{InstructionAssembler, InstructionEncoder};
//! use dotscope::assembly::{Operand, Immediate};
//!
//! // High-level fluent API
//! let mut assembler = InstructionAssembler::new();
//! assembler
//!     .ldarg_0()?
//!     .ldarg_1()?
//!     .add()?
//!     .ret()?;
//! let (bytecode, max_stack, handlers) = assembler.finish()?;
//!
//! // Low-level encoder API
//! let mut encoder = InstructionEncoder::new();
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_instruction("ldarg.1", None)?;
//! encoder.emit_instruction("add", None)?;
//! encoder.emit_instruction("ret", None)?;
//! let (bytecode2, _, _) = encoder.finalize()?;
//!
//! assert_eq!(bytecode, bytecode2); // Both produce identical IL bytecode
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All public types in this module are designed to be thread-safe where appropriate.
//! [`crate::assembly::Instruction`], [`crate::assembly::BasicBlock`], and related types
//! implement [`std::marker::Send`] and [`std::marker::Sync`] as they contain only
//! thread-safe data. The decoder functions can be called concurrently from different threads
//! with separate parser instances.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::method`] - Provides method-level disassembly and caching
//! - [`crate::metadata::token`] - Resolves metadata token references in operands

mod block;
mod builder;
mod decoder;
mod encoder;
mod instruction;
mod instructions;
pub mod opcodes;

pub use block::{BasicBlock, HandlerEntryInfo};
pub use builder::{FinishedWithLabels, InstructionAssembler};
pub(crate) use decoder::decode_method;
pub use decoder::{
    decode_blocks, decode_blocks_with_handlers, decode_instruction, decode_stream, DecodedBodies,
};
pub use encoder::{InstructionEncoder, LabelFixup};
pub use instruction::{
    FlowType, Immediate, Instruction, InstructionCategory, Operand, OperandType, StackBehavior,
};
pub use instructions::*;

// Copyright 2025-2026 Johann Kempter
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#![doc(html_no_source)]
// The `missing_docs`, `clippy::unwrap_used`, `clippy::expect_used`,
// `clippy::panic`, `clippy::arithmetic_side_effects`, and
// `clippy::indexing_slicing` lints are declared in `Cargo.toml` under
// `[lints]` so they enforce on every build regardless of the consuming
// workspace. dotscope is used in malware-analysis pipelines where every
// input byte is adversarial and the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]
#![allow(dead_code)]
// The crate's trusted computing base is exactly one `unsafe` block, and it carries a targeted
// `#[allow(unsafe_code)]` with its own SAFETY note:
//
// - `cilassembly/writer/output.rs` - `Mmap::map_mut` over the output file.
//
// The deny lint does not reach through dependencies, so note the other mapping here: `cowfile`'s
// `map_copy`, which the primary load path routes its mmap through.
#![deny(unsafe_code)]
// A broken intra-doc link renders as plain text on docs.rs, so a `# Errors` contract naming a
// variant that no longer exists still reads as authoritative. Denying the lint is what keeps
// the documented error taxonomy tied to the real one; CI sets `RUSTDOCFLAGS: -Dwarnings` so it
// is enforced on the doc build too.
#![deny(rustdoc::broken_intra_doc_links)]

//! # dotscope
//!
//! [![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
//! [![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
//! [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/ATRAPSLLC/dotscope/blob/main/LICENSE)
//!
//! A cross-platform framework for analyzing, deobfuscating, emulating, and modifying .NET PE executables.
//! Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language)
//! bytecode, metadata structures, disassembling, and transforming .NET assemblies without requiring Windows or the .NET runtime.
//!
//! # Architecture
//!
//! The library is organized into several key modules that work together to provide complete .NET assembly analysis:
//!
//! - **File Layer**: Memory-mapped file access and binary parsing
//! - **Metadata Layer**: ECMA-335 metadata parsing and type system representation
//! - **Assembly Layer**: CIL instruction processing with complete disassembly and assembly capabilities
//! - **Analysis Layer**: SSA form, control flow graphs, data flow analysis, and call graphs
//! - **Compiler Layer**: SSA optimization passes, code generation (SSA → CIL), and pass scheduling
//! - **Deobfuscation Layer**: Technique-based detection and transformation with ConfuserEx, BitMono, JIEJIE.NET, and Obfuscar support
//! - **Emulation Layer**: CIL bytecode interpreter with BCL stubs for runtime value computation
//! - **Validation Layer**: Configurable validation and integrity checking
//!
//! ## Key Components
//!
//! - [`crate::CilObject`] - Main entry point for .NET assembly analysis
//! - [`crate::metadata`] - Complete ECMA-335 metadata parsing and type system
//! - [`crate::assembly`] - Complete CIL instruction processing: disassembly, analysis, and assembly
//! - [`crate::analysis`] - Program analysis with SSA, CFG, data flow, and call graphs
//! - [`crate::compiler`] - SSA optimization passes, code generation, and pass scheduling
//! - [`crate::deobfuscation`] - Deobfuscation engine with detection and obfuscator-specific handling
//! - [`crate::emulation`] - CIL bytecode emulation with BCL method stubs
//! - [`crate::prelude`] - Convenient re-exports of commonly used types
//! - [`crate::Error`] and [`crate::Result`] - Comprehensive error handling
//!
//! # Features
//!
//! - **Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
//! - **CIL processing** - Complete instruction decoding, encoding, and control flow analysis
//! - **Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
//! - **Memory safe** - Built in Rust with comprehensive error handling
//! - **Rich type system** - Full support for generics, signatures, and complex .NET types
//! - **Static analysis** - SSA form, control flow graphs, data flow analysis, call graphs
//! - **Deobfuscation** - 30 passes, 35 techniques, ConfuserEx/BitMono/JIEJIE.NET/Obfuscar support, string decryption, control flow recovery
//! - **CIL emulation** - Bytecode interpreter with 600+ BCL stubs and copy-on-write memory
//! - **Extensible architecture** - Modular design for custom analysis and tooling
//!
//! # Usage Examples
//!
//! ## Quick Start
//!
//! Add `dotscope` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! dotscope = "0.9"
//! ```
//!
//! ### Using the Prelude
//!
//! For convenient access to the most commonly used types, import the prelude:
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! // Load and analyze a .NET assembly  
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! println!("Found {} methods", assembly.methods().len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ### Basic Assembly Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::cilobject::CilObject;
//! use std::path::Path;
//!
//! // Load and parse a .NET assembly
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Access metadata
//! if let Some(module) = assembly.module() {
//!     println!("Module: {}", module.name);
//! }
//!
//! // Iterate through types and methods
//! let methods = assembly.methods();
//! println!("Found {} methods", methods.len());
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Memory-based Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::cilobject::CilObject;
//!
//! // Analyze from memory buffer
//! let binary_data: Vec<u8> = std::fs::read("assembly.dll")?;
//! let assembly = CilObject::from_mem(binary_data)?;
//!
//! // Same API as file-based analysis
//! println!("Assembly loaded from memory");
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Custom Analysis with Validation
//!
//! ```rust,no_run
//! use dotscope::{CilObject, ValidationConfig};
//!
//! fn analyze_assembly(path: &str) -> dotscope::Result<()> {
//!     // Use minimal validation for best performance
//!     let assembly = CilObject::from_path_with_validation(
//!         std::path::Path::new(path),
//!         ValidationConfig::minimal()
//!     )?;
//!     
//!     // Access imports and exports
//!     let imports = assembly.imports();
//!     let exports = assembly.exports();
//!     
//!     println!("Imports: {} items", imports.total_count());
//!     println!("Exports: {} items", exports.total_count());
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### CIL Instruction Processing
//!
//! The assembly module provides comprehensive CIL instruction processing with both disassembly
//! (bytecode to instructions) and assembly (instructions to bytecode) capabilities.
//!
//! #### Disassembly
//! ```rust,no_run
//! use dotscope::{assembly::decode_instruction, Parser};
//!
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(bytecode);
//! let instruction = decode_instruction(&mut parser, 0x1000)?;
//!
//! println!("Mnemonic: {}", instruction.mnemonic);
//! println!("Flow type: {:?}", instruction.flow_type);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! #### Assembly
//! ```rust,no_run
//! use dotscope::assembly::InstructionAssembler;
//!
//! let mut asm = InstructionAssembler::new();
//! asm.ldarg_0()?      // Load first argument
//!    .ldarg_1()?      // Load second argument
//!    .add()?          // Add them together
//!    .ret()?;         // Return result
//! let (bytecode, max_stack, handlers) = asm.finish()?; // Returns [0x02, 0x03, 0x58, 0x2A]
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! The instruction processing seamlessly integrates with the metadata system. The [`crate::CilObject`] provides
//! access to both metadata and method bodies for comprehensive analysis workflows, while the assembly
//! system uses the same instruction metadata to ensure perfect consistency between disassembly and assembly.
//!
//! ### Metadata-Driven Disassembly
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Access raw metadata tables
//! if let Some(tables) = assembly.tables() {
//!     println!("Metadata tables present: {}", tables.table_count());
//! }
//!
//! // Access metadata heaps with indexed access and iteration
//! if let Some(strings) = assembly.strings() {
//!     let name = strings.get(1)?; // Indexed access
//!     
//!     // Iterate through all entries
//!     for (offset, string) in strings.iter() {
//!         println!("String at {}: '{}'", offset, string);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Standards Compliance
//!
//! `dotscope` implements the **ECMA-335 specification** (6th edition) for the Common Language Infrastructure.
//! All metadata structures, CIL instructions, and type system features conform to this standard.
//!
//! ### References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Official CLI specification
//! - [.NET Runtime](https://github.com/dotnet/runtime) - Microsoft's reference implementation
//!
//! # Error Handling
//!
//! All operations return [`Result<T, Error>`](Result) with comprehensive error information:
//!
//! ```rust,no_run
//! use dotscope::{Error, metadata::cilobject::CilObject};
//!
//! match CilObject::from_path(std::path::Path::new("tests/samples/crafted_2.exe")) {
//!     Ok(assembly) => println!("Successfully loaded assembly"),
//!     Err(Error::NotSupported) => println!("File format not supported"),
//!     Err(Error::Parse(parse_err)) => println!("Malformed file: {}", parse_err),
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! # Thread Safety
//!
//! All public types are [`std::marker::Send`] and [`std::marker::Sync`] unless explicitly documented otherwise. The library
//! is designed for safe concurrent access across multiple threads.
//!
//! # Development and Testing

#[macro_use]
pub(crate) mod macros;

#[macro_use]
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod utils;

/// Test support shared by the unit and integration tests: builders, factories, fixtures,
/// the sample harness. Unstable and outside the semver surface; integration tests reach it
/// through the `testkit` feature.
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit;

/// ILDasm-compatible CIL disassembly formatter.
///
/// Produces text output matching the style of Microsoft's ILDasm tool. The formatter
/// supports configurable output including instruction bytes, metadata tokens, and
/// IL offset labels.
///
/// # Key Components
///
/// - [`formatting::IlFormatter`] - Main entry point for formatting assemblies, types, and methods
/// - [`formatting::FormatterOptions`] - Configuration options controlling output detail level
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::formatting::{IlFormatter, FormatterOptions};
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
/// let formatter = IlFormatter::new(FormatterOptions::default());
///
/// let mut output = Vec::new();
/// formatter.format_assembly(&mut output, &assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub mod formatting;

/// Readers and writers for the binary encodings .NET metadata uses:
/// endian integers, ECMA-335 compressed integers and blob strings.
pub mod io;

/// Convenient re-exports of the most commonly used types and traits.
///
/// This module provides a curated selection of the most frequently used types
/// from across the dotscope library, allowing for convenient glob imports.
///
/// # Architecture
///
/// The prelude follows Rust's standard library pattern, re-exporting the most commonly
/// used types and traits from various modules for convenient access.
///
/// # Key Components
///
/// - [`crate::CilObject`] - Main entry point for .NET assembly analysis
/// - [`crate::Error`] and [`crate::Result`] - Error handling types
/// - Core metadata types and validation configuration
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// // Now you have access to the most common types
/// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
/// let methods = assembly.methods();
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// All re-exported types maintain their original thread safety guarantees.
pub mod prelude;

/// CIL instruction processing: disassembly, analysis, and assembly based on ECMA-335.
///
/// This module provides comprehensive CIL (Common Intermediate Language) instruction processing
/// capabilities, including both disassembly (bytecode to instructions) and assembly (instructions
/// to bytecode). It implements the complete ECMA-335 instruction set with support for control flow
/// analysis, stack effect tracking, and bidirectional instruction processing.
///
/// # Architecture
///
/// The assembly module is built around several core concepts:
/// - **Instruction Decoding**: Binary CIL bytecode to structured instruction representation
/// - **Instruction Encoding**: Structured instructions back to binary CIL bytecode
/// - **Control Flow Analysis**: Building basic blocks and analyzing program flow
/// - **Stack Effect Analysis**: Tracking how instructions affect the evaluation stack
/// - **Label Resolution**: Automatic resolution of branch targets and labels
/// - **Type Safety**: Compile-time validation of instruction operand types
///
/// # Key Components
///
/// ## Disassembly Components
/// - [`crate::assembly::decode_instruction`] - Decode a single instruction
/// - [`crate::assembly::decode_stream`] - Decode a sequence of instructions  
/// - [`crate::assembly::decode_blocks`] - Build basic blocks from instruction stream
///
/// ## Assembly Components  
/// - [`crate::assembly::InstructionEncoder`] - Low-level instruction encoding (supports all 220 CIL instructions)
/// - [`crate::assembly::InstructionAssembler`] - High-level fluent API for common instruction patterns
/// - [`crate::assembly::LabelFixup`] - Label resolution system for branch instructions
///
/// ## Shared Components
/// - [`crate::assembly::Instruction`] - Represents a decoded CIL instruction
/// - [`crate::assembly::BasicBlock`] - A sequence of instructions with single entry/exit
/// - [`crate::assembly::Operand`] - Instruction operands (immediates, tokens, targets)
/// - [`crate::assembly::FlowType`] - How instructions affect control flow
///
/// # Usage Examples
///
/// ## Disassembly
/// ```rust,no_run
/// use dotscope::{assembly::decode_instruction, Parser};
///
/// let bytecode = &[0x00, 0x2A]; // nop, ret
/// let mut parser = Parser::new(bytecode);
/// let instruction = decode_instruction(&mut parser, 0x1000)?;
///
/// println!("Mnemonic: {}", instruction.mnemonic);
/// println!("Flow type: {:?}", instruction.flow_type);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## High-Level Assembly
/// ```rust,no_run
/// use dotscope::assembly::InstructionAssembler;
///
/// let mut asm = InstructionAssembler::new();
/// asm.ldarg_0()?      // Load first argument
///    .ldarg_1()?      // Load second argument
///    .add()?          // Add them together
///    .ret()?;         // Return result
/// let (bytecode, max_stack, handlers) = asm.finish()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Low-Level Assembly
/// ```rust,no_run
/// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
///
/// let mut encoder = InstructionEncoder::new();
/// encoder.emit_instruction("nop", None)?;
/// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(1))))?;
/// encoder.emit_instruction("ret", None)?;
/// let bytecode = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Integration
///
/// The assembly module integrates with the metadata system to resolve tokens and provide
/// rich semantic information about method calls, field access, and type operations. The
/// encoder and assembler use the same instruction metadata as the disassembler, ensuring
/// perfect consistency between assembly and disassembly operations.
///
/// # Thread Safety
///
/// All assembly types are [`std::marker::Send`] and [`std::marker::Sync`] for safe concurrent processing.
pub mod assembly;

/// Program analysis infrastructure for .NET assemblies.
///
/// This module provides foundational analysis capabilities for understanding and
/// transforming .NET CIL code, including control flow graphs, SSA form, data flow
/// analysis, and inter-procedural call graphs.
///
/// # Key Components
///
/// ## Control Flow Graph (CFG)
/// - [`analysis::ControlFlowGraph`] - CFG built from basic blocks with lazy dominator computation
/// - [`analysis::CfgEdge`] / [`analysis::CfgEdgeKind`] - Edge representation with control flow semantics
/// - [`analysis::LoopAnalyzer`] / [`analysis::LoopForest`] - Loop detection and analysis
///
/// ## Static Single Assignment (SSA)
/// - [`analysis::SsaFunction`] - Method in SSA form with explicit def-use chains
/// - [`analysis::SsaConverter`] - Constructs SSA from CFG via dominance frontiers
/// - [`analysis::SsaBlock`] / [`analysis::SsaOp`] - SSA blocks and operations
/// - [`analysis::PhiNode`] - Phi functions at control flow merge points
///
/// ## Data Flow Analysis
/// - [`analysis::ConstantPropagation`] - Sparse Conditional Constant Propagation (SCCP)
/// - [`analysis::LiveVariables`] - Liveness analysis
/// - [`analysis::ReachingDefinitions`] - Reaching definitions analysis
/// - [`analysis::DataFlowSolver`] - Generic fixpoint solver
///
/// ## Call Graph
/// - [`analysis::CallGraph`] - Inter-procedural call relationships
/// - [`analysis::CallResolver`] - Virtual call resolution via Class Hierarchy Analysis
///
/// # Usage Example
///
/// ```no_run
/// use dotscope::analysis::{ControlFlowGraph, SsaConverter};
/// use dotscope::assembly::decode_blocks;
///
/// // Build CFG from method body
/// let blocks = decode_blocks(data, offset, rva, Some(size))?;
/// let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
///
/// // Convert to SSA form
/// let ssa = SsaConverter::build(&cfg, num_args, num_locals, resolver, Vec::new())?;
///
/// // Analyze loops
/// for loop_info in cfg.loops() {
///     println!("Loop at block {:?}, depth {}", loop_info.header, loop_info.depth);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub mod analysis;

/// Deobfuscation framework and transformation passes.
///
/// This module provides infrastructure for detecting and removing code obfuscation
/// from .NET assemblies. It combines an SSA-based pass architecture with a
/// technique-based detection and transformation system that supports multiple
/// obfuscators including ConfuserEx, BitMono, JIEJIE.NET, and Obfuscar.
///
/// # Key Components
///
/// ## Engine
/// - [`crate::deobfuscation::DeobfuscationEngine`] - Main entry point for deobfuscation
/// - [`crate::deobfuscation::EngineConfig`] - Engine configuration options
/// - [`crate::compiler::PassScheduler`] - Manages pass execution and fixpoint iteration
/// - [`crate::deobfuscation::AnalysisContext`] - Shared interprocedural analysis data
///
/// ## Technique System
/// - [`crate::deobfuscation::Technique`] - Unified trait for detection and transformation (35 built-in techniques)
/// - [`crate::deobfuscation::TechniqueRegistry`] - Manages registered techniques with confidence-scored detection
/// - [`crate::deobfuscation::TechniqueCategory`] - Categorization (anti-debug, anti-dump, string encryption, etc.)
/// - [`crate::deobfuscation::Detection`] / [`crate::deobfuscation::Evidence`] - Detection results with evidence
///
/// ## Built-in Passes
///
/// Value propagation and folding:
/// - [`crate::compiler::ConstantPropagationPass`] - SCCP-based constant propagation
/// - [`crate::compiler::CopyPropagationPass`] - Eliminates redundant copies and phi nodes
/// - [`crate::compiler::GlobalValueNumberingPass`] - Common subexpression elimination
/// - [`crate::compiler::StrengthReductionPass`] - Replaces expensive ops with cheaper equivalents
///
/// Control flow recovery:
/// - [`crate::compiler::ControlFlowSimplificationPass`] - Jump threading, branch simplification
/// - [`crate::deobfuscation::CffReconstructionPass`] - Z3-backed dispatcher analysis and CFG reconstruction
/// - [`crate::compiler::LoopCanonicalizationPass`] - Ensures single preheaders and latches
///
/// Dead code elimination:
/// - [`crate::compiler::DeadCodeEliminationPass`] - Removes unreachable blocks
/// - [`crate::compiler::DeadMethodEliminationPass`] - Identifies methods with no callers
///
/// Memory:
/// - [`crate::compiler::MemoryOptimizationPass`] - Forwards stores to loads, drops
///   redundant loads, removes dead stores, each gated on an alias proof
///
/// Other passes:
/// - [`crate::compiler::OpaquePredicatePass`] - Removes always-true/false conditions
/// - [`crate::deobfuscation::DecryptionPass`] - Decrypts values via emulation
/// - [`crate::compiler::InliningPass`] - Inlines small methods
///
/// # Usage Example
///
/// ```no_run
/// use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
///
/// let config = EngineConfig::default();
/// let engine = DeobfuscationEngine::new(config);
///
/// let (deobfuscated, result) = engine.process_file("obfuscated.exe")?;
/// println!("{}", result.summary());
/// println!("{} methods remain", deobfuscated.methods().len());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[cfg(feature = "deobfuscation")]
pub mod deobfuscation;

/// Compiler infrastructure for SSA-based code transformations.
///
/// Provides SSA optimization passes, code generation (SSA → CIL), and
/// pass scheduling with fixpoint iteration. This is the middle layer between
/// [`analysis`] (CIL → SSA) and [`deobfuscation`] (orchestration).
#[cfg(feature = "compiler")]
pub mod compiler;

/// CIL emulation engine for .NET bytecode execution.
///
/// This module provides a controlled execution environment for .NET CIL bytecode.
/// The emulation engine is essential for deobfuscation as many obfuscators rely on
/// runtime computation of values and dynamic string decryption.
///
/// # Key Components
///
/// ## Process Model
/// - [`emulation::ProcessBuilder`] - Fluent API for configuring emulation processes
/// - [`emulation::EmulationProcess`] - Central coordinator for emulation execution
/// - [`emulation::EmulationConfig`] - Configuration with presets (`for_extraction`, `for_analysis`, etc.)
///
/// ## Value System
/// - [`emulation::EmValue`] - Runtime value representation for all CIL types
/// - [`emulation::SymbolicValue`] - Tracks unknown/unresolved values during partial emulation
/// - [`emulation::HeapRef`] - Reference to heap-allocated objects
///
/// ## Memory Model
/// - [`emulation::EvaluationStack`] - CIL evaluation stack with overflow protection
/// - [`emulation::LocalVariables`] - Method local variable storage
/// - [`emulation::ManagedHeap`] - Simulated managed heap for object allocation
/// - [`emulation::AddressSpace`] - Unified address space for heap, statics, and mapped regions
///
/// ## Execution Engine
/// - [`emulation::Interpreter`] - Core CIL instruction interpreter
/// - [`emulation::EmulationController`] - High-level execution control with limits
/// - [`emulation::StepResult`] - Result of executing a single instruction
/// - [`emulation::EmulationOutcome`] - Final result of method execution (return value, exception, or limit)
///
/// ## Hook System
/// - [`emulation::Hook`] - Builder for creating method hooks with matching criteria
/// - [`emulation::HookManager`] - Registry for method interception hooks
/// - [`emulation::PreHookResult`] - Pre-hook result: `Continue` or `Bypass(value)`
/// - [`emulation::PostHookResult`] - Post-hook result: `Keep` or `Replace(value)`
///
/// ## Result Capture
/// - [`emulation::CaptureContext`] - Automatic result collection during emulation
/// - [`emulation::CapturedAssembly`] - Captured `Assembly.Load` data
/// - [`emulation::CapturedString`] - Captured decrypted strings
///
/// # Usage Examples
///
/// ## Value Arithmetic
///
/// ```rust
/// # #[cfg(feature = "emulation")]
/// # fn main() {
/// use dotscope::emulation::{EmValue, BinaryOp};
/// use dotscope::metadata::typesystem::{CilFlavor, PointerSize};
///
/// // CIL values follow ECMA-335 widening rules (I1/I2 → I32)
/// let a = EmValue::I32(10);
/// let b = EmValue::I32(3);
///
/// let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
/// assert_eq!(sum, EmValue::I32(13));
/// assert_eq!(sum.cil_flavor(), CilFlavor::I4);
///
/// // Division, bitwise, and comparison operations
/// let div = a.binary_op(&b, BinaryOp::Div, PointerSize::Bit64).unwrap();
/// assert_eq!(div, EmValue::I32(3));
///
/// let xor = a.binary_op(&b, BinaryOp::Xor, PointerSize::Bit64).unwrap();
/// assert_eq!(xor, EmValue::I32(10 ^ 3));
/// # }
/// # #[cfg(not(feature = "emulation"))]
/// # fn main() {}
/// ```
///
/// ## Building an Emulation Process
///
/// [`emulation::ProcessBuilder`] provides a fluent API with configuration presets:
///
/// ```rust,no_run
/// use dotscope::emulation::ProcessBuilder;
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// # fn main() -> dotscope::Result<()> {
/// let assembly = CilObject::from_path(Path::new("target.exe"))?;
/// let pe_bytes = std::fs::read("target.exe")?;
///
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .map_pe_image(&pe_bytes, "target.exe")
///     .for_extraction()           // 50M instruction limit, capture enabled
///     .capture_assemblies()       // Capture Assembly.Load calls
///     .capture_strings()          // Capture decrypted strings
///     .with_timeout_ms(30_000)    // 30 second wall-clock timeout
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// Available presets: `for_extraction()` (unpacking), `for_analysis()` (symbolic tracking),
/// `for_full_emulation()` (100M instructions), `for_minimal()` (constant folding, 10K instructions).
///
/// ## Executing a Method and Reading Results
///
/// ```rust,no_run
/// use dotscope::emulation::{EmValue, EmulationOutcome, ProcessBuilder};
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// # fn main() -> dotscope::Result<()> {
/// # let assembly = CilObject::from_path(Path::new("target.exe"))?;
/// # let process = ProcessBuilder::new().assembly(assembly).for_minimal().build()?;
/// // Find and execute a specific method by type/method name
/// if let Some(token) = process.find_method("MyNamespace.MyClass", "Decrypt") {
///     let outcome = process.execute_method(token, vec![EmValue::I32(42)])?;
///
///     match outcome {
///         EmulationOutcome::Completed { return_value, instructions } => {
///             println!("Completed in {} instructions", instructions);
///             if let Some(value) = return_value {
///                 println!("Returned: {:?}", value);
///             }
///         }
///         EmulationOutcome::LimitReached { limit, .. } => {
///             println!("Hit limit: {:?}", limit);
///         }
///         EmulationOutcome::UnhandledException { exception, .. } => {
///             println!("Exception: {:?}", exception);
///         }
///         _ => {}
///     }
/// }
///
/// // Retrieve captured data after execution
/// for asm in process.captured_assemblies() {
///     if let Some(name) = &asm.name {
///         std::fs::write(name, &asm.data)?;
///     }
/// }
/// for s in process.captured_strings() {
///     println!("Decrypted string: {}", s.value);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Method Hooks
///
/// Hooks intercept method calls during emulation. Use them to stub BCL methods,
/// bypass protection checks, or capture intermediate values:
///
/// ```rust,no_run
/// use dotscope::emulation::{Hook, PreHookResult, EmValue, ProcessBuilder};
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// # fn main() -> dotscope::Result<()> {
/// # let assembly = CilObject::from_path(Path::new("target.exe"))?;
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .for_analysis()
///     // Bypass Environment.Exit so emulation continues
///     .hook(
///         Hook::new("bypass-exit")
///             .match_name("System", "Environment", "Exit")
///             .pre(|_ctx, _thread| PreHookResult::Bypass(None))
///     )
///     // Intercept DateTime.Now to return a fixed value
///     .hook(
///         Hook::new("fixed-time")
///             .match_name("System", "DateTime", "get_Now")
///             .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I64(0))))
///     )
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Process Forking
///
/// Forking creates a lightweight copy of the emulation state, allowing you
/// to run the same setup against many different inputs efficiently:
///
/// ```rust,no_run
/// use dotscope::emulation::{EmValue, ProcessBuilder};
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// # fn main() -> dotscope::Result<()> {
/// # let assembly = CilObject::from_path(Path::new("target.exe"))?;
/// # let pe_bytes = std::fs::read("target.exe")?;
/// // Expensive setup: load assembly, map PE, configure hooks
/// let base_process = ProcessBuilder::new()
///     .assembly(assembly)
///     .map_pe_image(&pe_bytes, "target.exe")
///     .for_extraction()
///     .build()?;
///
/// // Cheap forks share the base state via copy-on-write
/// if let Some(decryptor) = base_process.find_method("Decryptor", "Decrypt") {
///     for key in 0..100i32 {
///         let fork = base_process.fork()?;
///         let outcome = fork.execute_method(decryptor, vec![EmValue::I32(key)])?;
///         // Each fork runs independently without affecting the base process
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "emulation")]
pub mod emulation;

/// .NET metadata parsing, loading, and type system based on ECMA-335.
///
/// This module implements the complete ECMA-335 metadata system for .NET assemblies.
/// It provides comprehensive parsing and access to all metadata tables, streams, and
/// type system constructs defined in the Common Language Infrastructure specification.
///
/// # Architecture
///
/// The metadata system is organized into several layers:
/// - **Physical Layer**: Raw binary data access and stream parsing
/// - **Logical Layer**: Structured access to metadata tables and heaps
/// - **Type System Layer**: High-level representation of .NET types and signatures
/// - **Validation Layer**: Configurable validation and integrity checking
///
/// # Key Components
///
/// ## Assembly Analysis
/// - [`crate::CilObject`] - Main entry point for assembly analysis
/// - [`crate::metadata::cor20header`] - CLR 2.0 header information
/// - [`crate::metadata::root`] - Metadata root and stream directory
///
/// ## Type System
/// - [`crate::metadata::typesystem`] - Complete .NET type system representation
/// - [`crate::metadata::signatures`] - Method and field signatures, generics support
/// - [`crate::metadata::token`] - Metadata tokens for cross-references
///
/// ## Method Body Analysis
/// - [`crate::metadata::method`] - Method body parsing and analysis
///
/// ## Metadata Streams
/// - [`crate::metadata::streams`] - All ECMA-335 metadata tables and heaps
/// - [`crate::Strings`], [`crate::Guid`], [`crate::Blob`], [`crate::UserStrings`] - String, GUID, Blob, and UserString heaps
/// - [`crate::TablesHeader`], [`crate::StreamHeader`] - Metadata tables and stream headers
///
/// ## Metadata Tables
/// - [`crate::metadata::tables`] - Assembly, Type, Method, Field, and other metadata tables
///
/// ## Import/Export Analysis  
/// - [`crate::metadata::imports`] - Analysis of imported types and methods
/// - [`crate::metadata::exports`] - Analysis of exported types and methods
/// - [`crate::metadata::resources`] - Embedded resources and manifests
///
/// ## Security and Identity
/// - [`crate::metadata::security`] - Code Access Security (CAS) permissions
/// - [`crate::metadata::identity`] - Assembly identity and verification
/// - [`crate::metadata::marshalling`] - P/Invoke and COM interop marshalling
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// // Load assembly and examine metadata
/// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Access basic information
/// if let Some(module) = assembly.module() {
///     println!("Module: {}", module.name);
/// }
///
/// // Examine metadata tables
/// if let Some(tables) = assembly.tables() {
///     println!("Tables present: {}", tables.table_count());
/// }
///
/// // Access type system
/// let methods = assembly.methods();
/// println!("Methods found: {}", methods.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Integration
///
/// The metadata system provides the foundation for the disassembler module, supplying
/// token resolution, type information, and method body access for comprehensive analysis.
///
/// # Thread Safety
///
/// All metadata types are [`std::marker::Send`] and [`std::marker::Sync`] for safe concurrent access.
pub mod metadata;

/// Multi-assembly project management and loading.
///
/// The `project` module provides the [`crate::project::CilProject`] container for managing
/// collections of related .NET assemblies with automatic dependency resolution and
/// cross-assembly analysis capabilities. It includes both legacy APIs and the new
/// [`crate::project::ProjectLoader`] builder-style API.
///
/// # Key Components
///
/// - [`project::CilProject`] - Main multi-assembly container
/// - [`project::ProjectLoader`] - Builder-style loading API with flexible configuration
/// - [`project::ProjectResult`] - Unified result type with loading statistics
/// - `ProjectContext` - Internal coordination for parallel loading (crate-internal)
///
/// # Examples
///
/// ## New ProjectLoader API (Recommended)
///
/// ```no_run
/// use dotscope::project::ProjectLoader;
///
/// // Single assembly loading
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
///
/// // Multi-assembly with dependencies
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_dependency("MyLib.dll")?
///     .auto_discover(true)
///     .build()?;
///
/// // With automatic discovery
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_search_path("./dependencies")?
///     .auto_discover(true)
///     .build()?;
///
/// println!("Loaded {} assemblies", result.success_count());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Legacy CilProject API
///
/// ```no_run
/// use dotscope::project::CilProject;
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let project = CilProject::new();
/// let assembly = CilObject::from_path(Path::new("MyApp.exe"))?;
/// project.add_assembly(assembly, true)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub mod project;

/// `dotscope` Result type.
///
/// A type alias for `std::result::Result<T, Error>` where the error type is always [`crate::Error`].
/// This is used consistently throughout the crate for all fallible operations.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Result, CilObject};
///
/// fn load_assembly(path: &str) -> Result<CilObject> {
///     CilObject::from_path(std::path::Path::new(path))
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

/// Mutable assembly for editing and modification operations.
///
/// `CilAssembly` provides a mutable layer on top of [`CilAssemblyView`] that enables
/// editing of .NET assembly metadata while tracking changes efficiently. It uses a
/// copy-on-write strategy to minimize memory usage and provides high-level APIs
/// for adding, modifying, and deleting metadata elements.
///
/// # Key Features
///
/// - **Change Tracking**: Efficiently tracks modifications without duplicating unchanged data
/// - **High-level APIs**: Builder patterns for creating types, methods, fields, etc.
/// - **Binary Generation**: Write modified assemblies back to disk
/// - **Validation**: Optional validation of metadata consistency
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilAssemblyView, CilAssembly};
///
/// // Load and convert to mutable assembly
/// let view = CilAssemblyView::from_path(std::path::Path::new("assembly.dll"))?;
/// let mut assembly = view.to_owned();
///
/// // Add a new string to the heap
/// let string_index = assembly.string_add("Hello, World!")?;
///
/// // Write changes back to file
/// assembly.to_file("modified_assembly.dll")?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use cilassembly::{
    ChangeRefKind, ChangeRefRc, CilAssembly, CleanupRequest, Conflict, ConflictResolver,
    LastWriteWinsResolver, MethodBodyBuilder, MethodBuilder, OperationResolution, Resolution,
};
/// `dotscope` Error type.
///
/// The main error type for all operations in this crate. Provides detailed error information
/// for file parsing, metadata validation, and disassembly operations.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Error, CilObject};
///
/// match CilObject::from_path(std::path::Path::new("tests/samples/crafted_2.exe")) {
///     Ok(assembly) => println!("Loaded successfully"),
///     Err(Error::NotSupported) => println!("File format not supported"),
///     Err(Error::Parse(parse_err)) => println!("Malformed: {}", parse_err),
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
pub use error::{
    Error, HeapKind, MethodLookupError, ParseFailure, ParseStage, Referrer, StreamKind,
};
/// Raw assembly view for editing and modification operations.
///
/// `CilAssemblyView` provides direct access to .NET assembly metadata structures
/// while maintaining a 1:1 mapping with the underlying file format. Unlike [`CilObject`]
/// which provides processed and resolved metadata optimized for analysis, `CilAssemblyView`
/// preserves the raw structure to enable future editing capabilities.
///
/// # Key Features
///
/// - **Raw Structure Access**: Direct access to metadata tables and streams as they appear in the file
/// - **No Validation**: Pure parsing without format validation or compliance checks
/// - **Memory Efficient**: Self-referencing pattern avoids data duplication
/// - **Thread Safe**: Immutable design enables safe concurrent access
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilAssemblyView;
/// use std::path::Path;
///
/// // Load assembly for raw metadata access
/// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
///
/// // Access raw metadata tables
/// if let Some(tables) = view.tables() {
///     println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
/// }
///
/// // Access string heaps directly
/// if let Some(strings) = view.strings() {
///     if let Ok(name) = strings.get(0x123) {
///         println!("Raw string: {}", name);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Converting to Mutable Assembly
///
/// `CilAssemblyView` can be converted to a mutable [`CilAssembly`] for editing operations:
///
/// ```rust,no_run
/// use dotscope::{CilAssemblyView, CilAssembly};
/// let view = CilAssemblyView::from_path(std::path::Path::new("assembly.dll"))?;
/// let mut assembly = view.to_owned(); // Convert to mutable CilAssembly
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::cilassemblyview::CilAssemblyView;
mod cilassembly;

/// Provides access to low-level file and memory parsing utilities.
///
/// The [`crate::Parser`] type is used for decoding CIL bytecode and metadata streams.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{Parser, assembly::decode_instruction};
/// let code = [0x2A]; // ret
/// let mut parser = Parser::new(&code);
/// let instr = decode_instruction(&mut parser, 0x1000)?;
/// assert_eq!(instr.mnemonic, "ret");
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use file::{
    parser::Parser,
    pe::{
        CoffHeader, DataDirectories, DataDirectory, DataDirectoryType, DosHeader,
        Export as PeExport, ExportHeader as PeExportHeader, Import as PeImport, Machine,
        OptionalHeader, Pe, PeCharacteristics, SectionTable, StandardFields, Subsystem,
        WindowsFields,
    },
    repair::{repair_pe, RepairAction, RepairResult},
    sectionmap::{RvaMapping, SectionMap},
    File,
};
/// Main entry point for working with .NET assemblies.
///
/// See [`crate::metadata::cilobject::CilObject`] for high-level analysis and metadata access.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// let assembly = CilObject::from_path(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
/// println!("Found {} methods", assembly.methods().len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::cilobject::CilObject;
/// Composable query builders for filtering types and methods.
///
/// `TypeQuery` and `MethodQuery` provide a fluent API for searching and filtering
/// types and methods in .NET assemblies without manual iteration boilerplate.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
///
/// // Find all public defined types
/// let types = assembly.query_types().defined().public().find_all();
///
/// // Find static constructors
/// let cctors = assembly.query_methods().static_constructors().find_all();
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::query::{MethodQuery, TypeQuery};
/// Metadata streams and heaps for direct access to ECMA-335 data structures.
///
/// These types provide low-level access to the metadata structures:
/// - [`crate::Blob`] - Binary blob heap for signatures and complex data
/// - [`crate::Guid`] - GUID heap for type and assembly identifiers  
/// - [`crate::Strings`] - String heap for names and identifiers
/// - [`crate::UserStrings`] - User string heap for string literals
/// - [`crate::TablesHeader`] - Metadata tables header information
/// - [`crate::StreamHeader`] - Individual stream header information
///
/// All heaps provide both indexed access via `get()` methods and iterator support
/// for efficient sequential traversal of all entries.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilObject, Strings};
/// let assembly = CilObject::from_path(std::path::Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Access metadata heaps with indexed access and iteration
/// if let Some(strings) = assembly.strings() {
///     let name = strings.get(1)?; // Indexed access
///     
///     // Iterate through all entries
///     for (offset, string) in strings.iter() {
///         println!("String at {}: '{}'", offset, string);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// See the [`crate::metadata::streams`] module for comprehensive examples of all heap types and iterators.
pub use metadata::streams::{
    Blob, BlobIterator, Guid, GuidIterator, StreamHeader, StringEntries, Strings, StringsIterator,
    TablesHeader, UserStrings, UserStringsIterator,
};
/// Configuration for metadata validation during assembly loading.
///
/// Controls which validation checks are performed when loading .NET assemblies.
/// Different presets are available for various use cases.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::{CilObject, ValidationConfig};
///
/// // Use minimal validation for best performance
/// let assembly = CilObject::from_path_with_validation(
///     std::path::Path::new("tests/samples/WindowsBase.dll"),
///     ValidationConfig::minimal()
/// )?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub use metadata::validation::{ValidationConfig, ValidationEngine};

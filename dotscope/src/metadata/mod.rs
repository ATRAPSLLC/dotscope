//! Metadata parsing and representation for .NET assemblies.
//!
//! This module contains the core metadata parsing infrastructure for .NET PE files,
//! providing comprehensive support for parsing metadata tables, streams, type systems,
//! and IL code according to the ECMA-335 standard. It serves as the foundation for
//! all .NET assembly analysis capabilities in dotscope.
//!
//! # Architecture Overview
//!
//! The metadata system is organized into several interconnected layers:
//!
//! ## Core Assembly Representation
//! - **Assembly Loading**: [`crate::metadata::cilobject`] provides the main [`crate::metadata::cilobject::CilObject`] type for loaded assemblies
//! - **PE Structure**: [`crate::metadata::cor20header`] handles the .NET-specific PE header information
//! - **Root Metadata**: [`crate::metadata::root`] manages the fundamental metadata directory structure
//!
//! ## Type System and Signatures
//! - **Type Resolution**: [`crate::metadata::typesystem`] provides complete .NET type system representation
//! - **Signature Parsing**: [`crate::metadata::signatures`] handles method and type signature decoding
//! - **Token Management**: [`crate::metadata::token`] provides metadata table row reference system
//!
//! ## Method and Code Analysis
//! - **Method Representation**: [`crate::metadata::method`] offers comprehensive method analysis with IL disassembly
//! - **Custom Attributes**: [`crate::metadata::customattributes`] handles .NET attribute parsing and representation
//! - **Security Model**: [`crate::metadata::security`] implements .NET declarative security parsing
//!
//! ## Metadata Streams and Tables
//! - **Stream Management**: [`crate::metadata::streams`] handles all metadata heap types (strings, blobs, GUIDs, user strings)
//! - **Table Processing**: [`crate::metadata::tables`] provides access to all ECMA-335 metadata tables
//! - **Data Loading**: Internal loader implements the metadata loading and caching infrastructure
//!
//! ## Interoperability and Resources
//! - **P/Invoke Support**: [`crate::metadata::imports`] and [`crate::metadata::exports`] handle native code interop
//! - **Type Marshalling**: [`crate::metadata::marshalling`] manages native type conversion specifications
//! - **Resource Access**: [`crate::metadata::resources`] provides .NET resource extraction and parsing
//!
//! ## Quality and Validation
//! - **Assembly Verification**: [`crate::metadata::identity`] handles strong name and authenticode validation
//! - **Metadata Validation**: [`crate::metadata::validation`] provides comprehensive metadata consistency checking
//!
//! # Key Components
//!
//! ## Primary Assembly Interface
//! - [`crate::metadata::cilobject::CilObject`] - Main assembly representation with metadata and IL code
//! - [`crate::metadata::method::Method`] - Complete method analysis with IL disassembly and control flow
//! - [`crate::metadata::typesystem::TypeRegistry`] - Comprehensive .NET type system representation
//!
//! ## Core Infrastructure
//! - [`crate::metadata::token::Token`] - Metadata table row references used throughout .NET
//! - [`crate::metadata::signatures`] - Method and type signature parsing infrastructure
//! - [`crate::metadata::streams`] - Metadata stream parsing (strings, blobs, GUIDs, etc.)
//!
//! # Usage Patterns
//!
//! ## Basic Assembly Loading and Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! // Load and parse a .NET assembly
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Access basic assembly information
//! if let Some(assembly_info) = assembly.assembly() {
//!     println!("Assembly: {} (Version: {}.{})",
//!              assembly_info.name, assembly_info.major_version, assembly_info.minor_version);
//! }
//!
//! // Get counts of major metadata elements
//! println!("Methods: {}", assembly.methods().len());
//! println!("Types: {}", assembly.types().len());
//! if let Some(module) = assembly.module() {
//!     println!("Module name: {}", module.name);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Method Analysis and IL Code Inspection
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Analyze methods with IL code
//! for entry in assembly.methods().iter().take(10) {
//!     let method = entry.value();
//!     
//!     if method.instruction_count() > 0 {
//!         println!("Method: {} ({} instructions)",
//!                  method.name, method.instruction_count());
//!         
//!         // Examine method characteristics
//!         if method.flags_modifiers.contains(
//!             dotscope::metadata::method::MethodModifiers::VIRTUAL) {
//!             println!("  - Virtual method");
//!         }
//!         
//!         if method.flags_modifiers.contains(
//!             dotscope::metadata::method::MethodModifiers::STATIC) {
//!             println!("  - Static method");
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Type System Exploration
//!
//! ```no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Explore the type system
//! for entry in assembly.types().iter().take(10) {
//!     let type_def = entry.value();
//!     
//!     println!("Type: {} (Namespace: {})",
//!              type_def.name, type_def.namespace);
//!     
//!     // Show type characteristics using flags
//!     if type_def.flags_visibility.contains(TypeVisibility::PUBLIC) {
//!         println!("  - Public visibility");
//!     }
//!     
//!     if type_def.flags_layout.contains(TypeLayout::ABSTRACT) {
//!         println!("  - Abstract type");
//!     }
//!     
//!     if type_def.flags_layout.contains(TypeLayout::SEALED) {
//!         println!("  - Sealed type");
//!     }
//!     
//!     println!("  - {} methods, {} fields",
//!              type_def.methods.len(), type_def.fields.len());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All metadata types are designed for safe concurrent access:
//! - **Immutable Data**: Most metadata structures are read-only after parsing
//! - **Arc-based Sharing**: Reference counting enables safe multi-threaded access
//! - **Lazy Initialization**: `OnceLock` ensures thread-safe lazy loading
//!
//! # Error Handling
//!
//! The metadata system provides comprehensive error handling for malformed assemblies:
//! - **Format Validation**: ECMA-335 compliance checking
//! - **Bounds Checking**: Safe access to all metadata structures
//! - **Graceful Degradation**: Partial parsing when possible
//! - **Detailed Diagnostics**: Clear error messages for debugging
//!
//! # References
//!
//! - ECMA-335 6th Edition - Common Language Infrastructure (CLI)
//! - Microsoft .NET Framework PE Format Specification
//! - Windows PE/COFF Specification

/// Implementation of a raw assembly view for editing operations
pub mod cilassemblyview;
/// Implementation of a loaded + parsed CIL binary
pub mod cilobject;
/// Implementation of the Header of CIL
pub mod cor20header;
/// Implementation of custom attribute parsing and representation
pub mod customattributes;
/// Implementation of custom debug information parsing for Portable PDB format
pub mod customdebuginformation;
/// Multi-assembly dependency tracking and analysis system
pub mod dependencies;
/// Diagnostics collection for assembly loading and analysis
pub mod diagnostics;
/// Implementation of 'Exports' by the loaded binary
pub mod exports;
/// Assembly identity and cryptographic verification system
pub mod identity;
/// Implementation of methods that are imported from other binaries (native or .net)
pub mod imports;
/// Implementation of import scope parsing for Portable PDB format
pub mod importscope;
/// Implementation of our `MetaDataTable` loader
pub(crate) mod loader;
/// Implementation of the type marshalling for native code invokations
pub mod marshalling;
/// Implementation of the MethodHeader of CIL
pub mod method;

/// Portable PDB metadata: standalone `.pdb` files and PDBs embedded in images.
pub mod pdb;
/// Composable query system for types and methods
pub mod query;
/// ReadyToRun images: the header, the methods compiled ahead of time, and the import cells
pub mod readytorun;
/// Cross-table token resolver for metadata normalization
pub mod resolver;
/// Implementation of the .NET resources
pub mod resources;
/// Implementation of the root metadata structure
pub mod root;
/// Implementation of the .NET security model
pub mod security;
/// Implementation of sequence points in methods
pub mod sequencepoints;
/// Implementation of method and type signatures
pub mod signatures;
/// Implementation of all metadata streams (tables, heaps, etc.)
pub mod streams;
/// Table field layout definitions for heap references
pub mod tablefields;
/// Implementation of the .NET metadata tables
pub mod tables;
/// Commonly used metadata token type
pub mod token;
/// Implementation of the .NET type system
pub mod typesystem;
/// Metadata validation utilities
pub mod validation;
/// VTable fixup directory parsing for mixed-mode and COM interop assemblies
pub mod vtfixup;

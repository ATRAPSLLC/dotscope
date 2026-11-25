//! Analysis and representation of exported types in .NET assemblies.
//!
//! This module provides comprehensive functionality for tracking and analyzing all types
//! exported by a .NET assembly, including those made available to other assemblies,
//! COM clients, and external consumers. Essential for dependency analysis, interoperability
//! scenarios, and assembly metadata inspection workflows.
//!
//! # Architecture
//!
//! The module implements a thread-safe container for exported type metadata using
//! lock-free concurrent data structures. The architecture provides:
//!
//! - **Efficient Lookups**: O(log n) token-based access with concurrent safety
//! - **Name-based Searching**: Linear search capabilities by type name and namespace
//! - **Iterator Support**: Complete traversal of all exported types
//! - **Memory Management**: Reference counting for efficient memory usage
//!
//! # Key Components
//!
//! - [`crate::metadata::exports::Exports`] - Main container for exported type metadata
//! - [`crate::metadata::tables::ExportedTypeRc`] - Reference-counted exported type instances
//! - [`crate::metadata::tables::ExportedTypeMap`] - Thread-safe concurrent map implementation
//!
//! # Use Cases
//!
//! - **Dependency Analysis**: Identify types exposed by referenced assemblies
//! - **COM Interop**: Track types exported for COM visibility
//! - **Metadata Inspection**: Enumerate all publicly available types
//! - **Assembly Loading**: Resolve type references across assembly boundaries
//! - **Type Resolution**: Cross-assembly type lookup and validation
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::exports::Exports;
//! use dotscope::metadata::token::Token;
//!
//! let exports = Exports::new();
//!
//! // Find exported type by name and namespace
//! if let Some(exported_type) = exports.find_by_name("String", Some("System")) {
//!     println!("Found exported type: {} in namespace System", exported_type.name);
//! }
//!
//! // Iterate through all exported types
//! for entry in &exports {
//!     let token = entry.key();
//!     let exported_type = entry.value();
//!     println!("Token: {}, Type: {}", token, exported_type.name);
//! }
//! ```
//!
//! # Thread Safety
//!
//! The module uses concurrent data structures for thread-safe access:
//!
//! - **Concurrent Reads**: Multiple threads can read simultaneously
//! - **Atomic Updates**: All modifications are performed atomically
//! - **Lock-Free Design**: No blocking operations in read paths
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - For metadata table access and token resolution
//! - [`crate::CilAssembly`] - For assembly-level export coordination
//! - [`crate::metadata::imports`] - For cross-assembly reference resolution

pub use builder::NativeExportsBuilder;
pub use cil::*;
pub use container::{
    ExportEntry, ExportSource, ExportTarget, ExportedFunction, NativeExportRef,
    UnifiedExportContainer,
};
pub use native::{ExportDirectory, ExportForwarder, ExportFunction, NativeExports};

mod builder;
mod cil;
mod container;
mod native;

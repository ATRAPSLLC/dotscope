//! Import scope parsing and representation for Portable PDB debugging metadata.
//!
//! This module provides comprehensive parsing capabilities for import declarations used in
//! Portable PDB files. Import scopes define the set of namespaces, types, and assemblies
//! that are accessible within a lexical scope for debugging purposes, enabling debuggers
//! to correctly resolve symbols and provide accurate debugging information.
//!
//! # Architecture
//!
//! The module implements a multi-stage parsing pipeline that handles the complex binary
//! format used to encode import declarations in Portable PDB files. The architecture
//! separates format-specific parsing from type-safe representation and provides
//! comprehensive error handling for malformed import data.
//!
//! ## Core Components
//!
//! - **Binary Parsing**: Low-level blob parsing with format validation
//! - **Type Safety**: Strong typing for different import declaration kinds
//! - **Scope Management**: Hierarchical scope representation for lexical analysis
//! - **Integration**: Seamless integration with metadata resolution systems
//!
//! # Key Components
//!
//! ## Primary Types
//!
//! - [`crate::metadata::importscope::ImportDeclaration`] - Individual import declaration with typed variants
//! - [`crate::metadata::importscope::ImportKind`] - Classification of different import types
//! - [`crate::metadata::importscope::ImportsInfo`] - Complete import scope with all declarations
//! - [`crate::metadata::importscope::parse_imports_blob`] - Main parsing function for imports blob
//!
//! ## Import Declaration Types
//!
//! - **Namespace Imports**: Using statements for entire namespaces
//! - **Type Imports**: Direct imports of specific types from assemblies
//! - **Assembly References**: Implicit assembly imports for type resolution
//! - **Alias Declarations**: Type aliases and namespace aliases for scoped resolution
//!
//! # Import Declaration Format
//!
//! Import declarations are encoded in a compact binary format within the ImportScope table's
//! imports blob according to the Portable PDB specification. The format supports multiple
//! declaration types with efficient encoding for common debugging scenarios.
//!
//! ## Binary Format Structure
//!
//! ```text
//! ImportsBlob ::= ImportDeclaration*
//! ImportDeclaration ::= ImportKind [TargetNamespace | TargetType | Alias]
//! ImportKind ::= CompressedUInt32
//! TargetNamespace ::= Utf8String
//! TargetType ::= TypeDefOrRef | TypeSpec
//! Alias ::= Utf8String TargetReference
//! ```
//!
//! # Usage Examples
//!
//! ## Basic Import Scope Parsing
//!
//! ```no_run
//! use dotscope::metadata::importscope::{parse_imports_blob, ImportDeclaration};
//! use dotscope::metadata::streams::Blob;
//!
//! # fn get_imports_blob() -> (&'static [u8], &'static Blob) {
//! #     (b"", &Blob::new())
//! # }
//! let (blob_data, blobs_heap) = get_imports_blob();
//!
//! // Parse imports blob from ImportScope table
//! let imports = parse_imports_blob(blob_data, blobs_heap)?;
//!
//! // Process import declarations by type
//! for declaration in &imports.declarations {
//!     match declaration {
//!         ImportDeclaration::ImportNamespace { namespace } => {
//!             println!("Using namespace: {}", namespace);
//!         }
//!         ImportDeclaration::ImportType { type_ref } => {
//!             println!("Import type: {:?}", type_ref);
//!         }
//!         ImportDeclaration::ImportAssemblyReference { assembly_ref } => {
//!             println!("Reference assembly: {:?}", assembly_ref);
//!         }
//!         ImportDeclaration::ImportModuleReference { module_ref } => {
//!             println!("Reference module: {:?}", module_ref);
//!         }
//!         _ => println!("Other import declaration type"),
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Debugging Context Resolution
//!
//! ```no_run
//! use dotscope::metadata::importscope::{parse_imports_blob, ImportDeclaration};
//! use dotscope::CilObject;
//!
//! # fn get_assembly() -> dotscope::Result<CilObject> { todo!() }
//! let assembly = get_assembly()?;
//!
//! # fn get_import_scope_data() -> (&'static [u8], &'static dotscope::metadata::streams::Blob) {
//! #     (b"", &dotscope::metadata::streams::Blob::new())
//! # }
//! let (imports_blob, blob_heap) = get_import_scope_data();
//! let import_scope = parse_imports_blob(imports_blob, blob_heap)?;
//!
//! // Build debugging context for symbol resolution
//! let mut available_namespaces = Vec::new();
//! let mut imported_types = Vec::new();
//!
//! for declaration in &import_scope.declarations {
//!     match declaration {
//!         ImportDeclaration::ImportNamespace { namespace } => {
//!             available_namespaces.push(namespace.clone());
//!         }
//!         ImportDeclaration::ImportType { type_ref } => {
//!             imported_types.push(type_ref.clone());
//!         }
//!         _ => {}
//!     }
//! }
//!
//! println!("Available namespaces for debugging: {:?}", available_namespaces);
//! println!("Directly imported types: {}", imported_types.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Import Analysis
//!
//! ```no_run
//! use dotscope::metadata::importscope::{parse_imports_blob, ImportDeclaration, ImportKind};
//!
//! # fn analyze_import_scope(blob_data: &[u8], blob_heap: &dotscope::metadata::streams::Blob) -> dotscope::Result<()> {
//! let imports = parse_imports_blob(blob_data, blob_heap)?;
//!
//! // Analyze import patterns for debugging optimization
//! let mut namespace_count = 0;
//! let mut type_count = 0;
//! let mut assembly_count = 0;
//!
//! for declaration in &imports.declarations {
//!     match declaration {
//!         ImportDeclaration::ImportNamespace { .. } => namespace_count += 1,
//!         ImportDeclaration::ImportType { .. } => type_count += 1,
//!         ImportDeclaration::ImportAssemblyReference { .. } => assembly_count += 1,
//!         _ => {}
//!     }
//! }
//!
//! println!("Import scope analysis:");
//! println!("  Namespace imports: {}", namespace_count);
//! println!("  Type imports: {}", type_count);
//! println!("  Assembly references: {}", assembly_count);
//! println!("  Total declarations: {}", imports.declarations.len());
//! # Ok(())
//! # }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The parsing system provides comprehensive error handling for various failure scenarios:
//! - **Invalid Format**: Malformed import declaration encoding
//! - **Missing References**: Unresolvable type or assembly references
//! - **Truncated Data**: Incomplete import declaration data
//!
//! Note: Invalid UTF-8 sequences in aliases and namespaces are handled using lossy
//! conversion (replacement with U+FFFD) rather than returning errors, as
//! System.Reflection.Metadata reads them (the oracle tier compares the two).
//!
//! # Performance Considerations
//!
//! - **Parsed when loaded**: an ImportScope row's imports are decoded when the assembly's
//!   Portable PDB is read ([`crate::CilObject::pdb`]), once per row
//! - **Bounded work**: each declaration reads a fixed number of compressed integers and blob
//!   lookups, so decoding is linear in the blob's size
//! - **Owned strings**: aliases and namespaces are copied out of the `#Blob` heap, one string
//!   each
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe. The import parsing functions
//! and data structures implement [`std::marker::Send`] and [`std::marker::Sync`], enabling
//! safe concurrent access and processing of import declarations across multiple threads.
//! Reference-counted data structures ensure memory safety during concurrent access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - ImportScope table processing and metadata navigation
//! - [`crate::metadata::streams::Blob`] - Binary data parsing for imports blob format
//! - [`crate::metadata::streams::Strings`] - String heap resolution for namespace and type names
//! - [`crate::metadata::token`] - Token-based type reference resolution and validation
//! - [`crate::metadata::typesystem`] - Type system integration for import resolution
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: Full compliance with Portable PDB import scope specification
//! - **ECMA-335**: Compatible with .NET metadata standards for debugging information
//! - **UTF-8 Encoding**: Proper handling of Unicode namespace and type names
//! - **Binary Format**: Correct interpretation of compressed integer and string encoding

mod parser;
mod types;

pub use parser::{encode_import_records, parse_import_records, parse_imports_blob, ImportRecord};
pub use types::{ImportDeclaration, ImportKind, ImportsInfo};

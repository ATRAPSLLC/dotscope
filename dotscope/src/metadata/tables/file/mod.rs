//! `File` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `File` metadata table,
//! which lists files in a multi-file assembly. Each entry contains metadata about files
//! that are part of the assembly but stored separately from the main manifest.
//!
//! # Overview
//! The `File` table enables multi-file assembly scenarios:
//! - **Multi-module assemblies**: Additional .netmodule files containing code
//! - **Resource files**: Binary data files (.resources, images, data)
//! - **Native libraries**: Unmanaged DLLs for P/Invoke operations
//! - **Documentation**: Associated help files and XML documentation
//! - **Satellite assemblies**: Localization and culture-specific resources
//!
//! # Components
//! - [`FileRaw`]: Raw file data read directly from metadata tables
//! - [`File`]: Owned file data with resolved references and complete metadata
//! - [`FileLoader`](crate::metadata::loader::tables::FileLoader): Processes and loads file metadata
//! - [`FileMap`]: Thread-safe collection of files indexed by token
//! - [`FileList`]: Vector-based collection of files
//! - [`FileRc`]: Reference-counted file for shared ownership
//!
//! # Table Structure
//! Each `File` entry contains:
//! - **Flags**: File attributes indicating type and characteristics
//! - **Name**: String reference to the file name
//! - **`HashValue`**: Cryptographic hash for integrity verification
//!
//! # File Types
//! Files can be categorized by their purpose:
//! ```text
//! ┌─────────────────┬──────────────────────────────────────┐
//! │ Type            │ Description                          │
//! ├─────────────────┼──────────────────────────────────────┤
//! │ Module          │ .netmodule with executable code      │
//! │ Resource        │ .resources with binary data          │
//! │ Native Library  │ .dll with unmanaged code            │
//! │ Documentation   │ .xml with API documentation          │
//! │ Data File       │ Configuration or content files       │
//! └─────────────────┴──────────────────────────────────────┘
//! ```
//!
//!
//! # File Attributes
//! The [`FileAttributes`] module defines flags for file classification:
//! - **`CONTAINS_META_DATA`**: File contains .NET metadata (executable modules)
//! - **`CONTAINS_NO_META_DATA`**: Resource files without metadata
//!
//! # Hash Verification
//! Each file includes a cryptographic hash for security:
//! - **SHA-1 or SHA-256**: Algorithm depends on assembly version
//! - **Integrity checking**: Verifies file hasn't been tampered with
//! - **Loading validation**: Runtime can verify file authenticity
//! - **Security assurance**: Prevents malicious file substitution
//!
//! # Import Integration
//! Files can participate in import resolution through [`crate::metadata::imports::UnifiedImportContainer`]:
//! - Module files can export types and members
//! - Import analysis traverses file dependencies
//! - Cross-file reference resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the complete File table specification.

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::{
    imports::{ImportContainer, ImportRc, Imports},
    token::Token,
};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of file entries indexed by file token.
///
/// This skip list-based map provides efficient concurrent access to file metadata,
/// allowing multiple threads to resolve file information during assembly loading
/// and multi-file analysis.
pub type FileMap = SkipMap<Token, FileRc>;

/// Thread-safe vector of file entries.
///
/// This collection provides ordered access to file entries, useful for sequential
/// processing and bulk operations during assembly analysis and file enumeration.
pub type FileList = Arc<boxcar::Vec<FileRc>>;

/// Reference-counted file entry.
///
/// Provides shared ownership of [`File`] instances, enabling efficient sharing
/// of file metadata across multiple data structures and threads.
pub type FileRc = Arc<File>;

metadata_flags! {
    /// File attribute flags for the `File.Flags` field (ECMA-335 §II.22.19).
    ///
    /// Strongly-typed wrapper around the 4-byte `File.Flags` bitmask that indicates
    /// the type and characteristics of files in multi-file assemblies, particularly
    /// whether the file contains .NET metadata or is a resource file.
    ///
    /// ## ECMA-335 Reference
    /// See ECMA-335, Partition II, §22.19 for File table flag specifications.
    pub struct FileAttributes(u32);
}

impl FileAttributes {
    /// File contains .NET metadata.
    ///
    /// This flag indicates the file is an executable module (.netmodule or .exe/.dll)
    /// that contains .NET metadata and can define types, methods, and other constructs.
    /// Files with this flag are processed by the CLR loader.
    pub const CONTAINS_META_DATA: Self = Self(0x0000);

    /// File contains no .NET metadata.
    ///
    /// This flag indicates the file is a resource file or other non-metadata file
    /// such as images, configuration data, or unmanaged libraries. These files
    /// are not processed by the CLR metadata loader.
    pub const CONTAINS_NO_META_DATA: Self = Self(0x0001);
}

/// Import container implementation for File entries.
///
/// This implementation allows files to participate in import resolution by providing
/// access to imports defined within or referenced by the file. This is particularly
/// useful for multi-module assemblies where imports span multiple files.
impl ImportContainer for Arc<File> {
    /// Get all imports associated with this file.
    ///
    /// Returns a vector of import references that are defined within or
    /// associated with this file, enabling cross-file import analysis.
    ///
    /// # Arguments
    /// * `imports` - The imports collection to query
    ///
    /// # Returns
    /// A vector of [`ImportRc`] containing all imports from this file.
    ///
    /// [`ImportRc`]: crate::metadata::imports::ImportRc
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_file(self)
    }
}

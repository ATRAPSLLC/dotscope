//! `ExportedType` metadata table implementation.
//!
//! This module provides comprehensive support for the ECMA-335 `ExportedType` metadata table (0x27),
//! which defines types that are exported from assemblies for visibility to other assemblies.
//! `ExportedType` entries enable cross-assembly type access, type forwarding during assembly
//! refactoring, and public interface definition for complex assembly structures. It includes raw
//! table access, resolved data structures, and integration with the broader metadata system.
//!
//! # Architecture
//!
//! This module follows the dual variant pattern for metadata table representation:
//! - **Raw Layer**: [`crate::metadata::tables::exportedtype::raw::ExportedTypeRaw`] provides direct binary access
//! - **Owned Layer**: [`crate::metadata::tables::exportedtype::owned::ExportedType`] offers resolved, validated data
//!
//! # Key Components
//!
//! - **Raw Representation**: [`crate::metadata::tables::exportedtype::raw::ExportedTypeRaw`] - Direct binary table format with unresolved indexes
//! - **Owned Data**: [`crate::metadata::tables::exportedtype::owned::ExportedType`] - Resolved entries with owned data and cross-references  
//! - **Loading Infrastructure**: [`crate::metadata::loader::tables::ExportedTypeLoader`] - Processes raw entries during metadata loading
//! - **Type Aliases**: Collection types for managing `ExportedType` entries efficiently
//!
//! # Integration
//!
//! - Raw entries are processed by [`crate::metadata::loader::tables::ExportedTypeLoader`] during metadata loading
//! - Integrates with [`crate::metadata::streams::Strings`] for name resolution
//! - References [`crate::metadata::tables::file`] and [`crate::metadata::tables::assemblyref`] tables for implementation resolution
//! # `ExportedType` Table Structure
//!
//! Each `ExportedType` entry contains:
//! - **Flags** (4 bytes): Type visibility and export attributes
//! - **`TypeDefId`** (4 bytes): Type identifier for forwarded types
//! - **`TypeName`** (2/4 bytes): String heap index for the type name
//! - **`TypeNamespace`** (2/4 bytes): String heap index for the type namespace
//! - **Implementation** (2/4 bytes): Implementation coded index (File or `AssemblyRef`)
//!
//! The Implementation field determines where the type is actually defined, supporting
//! both multi-module assemblies and type forwarding scenarios.
//!
//! # Implementation Resolution
//!
//! The Implementation coded index can point to:
//! - **`File`**: Type defined in another file within this assembly
//! - **`AssemblyRef`**: Type forwarded to a different assembly
//! - **`ExportedType`**: Nested type export (rare)
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of metadata tokens to `ExportedType` entries
///
/// Provides efficient concurrent access to `ExportedType` entries indexed by their
/// metadata tokens. Uses a lock-free skip list implementation for high-performance
/// concurrent reads and writes during metadata loading.
pub type ExportedTypeMap = SkipMap<Token, ExportedTypeRc>;

/// Thread-safe vector of `ExportedType` entries
///
/// Provides a growable collection of `ExportedType` entries with thread-safe append
/// operations. Used for collecting entries during parallel processing phases
/// of metadata loading.
pub type ExportedTypeList = Arc<boxcar::Vec<ExportedTypeRc>>;

/// Reference-counted pointer to an `ExportedType` entry
///
/// Provides shared ownership of [`ExportedType`] instances across multiple
/// threads and data structures. Enables efficient memory usage and safe
/// concurrent access to `ExportedType` metadata.
pub type ExportedTypeRc = Arc<ExportedType>;

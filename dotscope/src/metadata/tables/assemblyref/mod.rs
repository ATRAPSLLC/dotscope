//! `AssemblyRef` table module.
//!
//! This module provides complete support for the ECMA-335 `AssemblyRef` metadata table (0x23),
//! which contains references to external assemblies required by the current assembly. It includes
//! raw table access, resolved data structures, collection types, and cryptographic hash support
//! for dependency analysis and verification.
//!
//! # Architecture
//!
//! The `AssemblyRef` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved heap indexes, while owned entries
//! provide fully resolved strings and blob data for immediate use.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyref::raw::AssemblyRefRaw`] - Raw table structure with unresolved heap indexes
//! - [`crate::metadata::tables::assemblyref::owned::AssemblyRef`] - Owned variant with resolved strings/blobs
//! - [`crate::metadata::tables::assemblyref::assemblyrefhash::AssemblyRefHash`] - Hash information for verification
//! - [`crate::metadata::loader::tables::AssemblyRefLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::assemblyref::AssemblyRefMap`] - Token-based lookup map
//! - [`crate::metadata::tables::assemblyref::AssemblyRefList`] - Collection type for assembly references
//! - [`crate::metadata::tables::assemblyref::AssemblyRefRc`] - Reference-counted pointer
//!
//! # `AssemblyRef` Table Structure
//!
//! The `AssemblyRef` table contains dependency information with these fields:
//! - **Version**: Four-part version number (Major.Minor.Build.Revision)
//! - **Flags**: Assembly attributes (see [`crate::metadata::tables::assembly::AssemblyFlags`])
//! - **`PublicKeyOrToken`**: Strong name verification data
//! - **Name**: Simple assembly name (e.g., "mscorlib")
//! - **Culture**: Localization culture (empty for culture-neutral assemblies)
//! - **`HashValue`**: Optional hash of the referenced assembly
//!
//! # Dependency Resolution
//!
//! `AssemblyRef` entries are fundamental for understanding assembly dependencies and are used
//! during runtime assembly loading. Each entry provides the minimum information needed for
//! the .NET runtime to locate and verify external assemblies.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::imports`] - Import resolution and dependency tracking
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//!
//! # References
//!
//! - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::{
    imports::{ImportContainer, ImportRc, Imports},
    token::Token,
};

mod assemblyrefhash;
mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use assemblyrefhash::*;
pub use builder::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assemblyref::AssemblyRef`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved assembly references by their metadata tokens.
pub type AssemblyRefMap = SkipMap<Token, AssemblyRefRc>;

/// A vector that holds a list of [`crate::metadata::tables::assemblyref::AssemblyRef`] references
///
/// Thread-safe append-only vector for storing assembly reference collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type AssemblyRefList = Arc<boxcar::Vec<AssemblyRefRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::assemblyref::AssemblyRef`]
///
/// Provides shared ownership and automatic memory management for assembly reference instances.
/// Multiple references can safely point to the same assembly reference data across threads.
pub type AssemblyRefRc = Arc<AssemblyRef>;

impl ImportContainer for AssemblyRefRc {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_assembly_ref(self)
    }
}

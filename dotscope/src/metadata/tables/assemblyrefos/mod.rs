//! `AssemblyRefOS` table module.
//!
//! This module provides complete support for the ECMA-335 `AssemblyRefOS` metadata table (0x25),
//! which contains operating system compatibility information for external assembly references.
//! It includes raw table access, resolved data structures, collection types, and integration
//! with the broader assembly reference system.
//!
//! # Architecture
//!
//! The `AssemblyRefOS` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved table indexes, while owned entries
//! provide fully resolved references integrated with assembly reference data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::assemblyrefos::owned::AssemblyRefOs`] - Owned variant with resolved references
//! - [`crate::metadata::loader::tables::AssemblyRefOsLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::assemblyrefos::AssemblyRefOsMap`] - Token-based lookup map
//! - [`crate::metadata::tables::assemblyrefos::AssemblyRefOsList`] - Collection type
//! - [`crate::metadata::tables::assemblyrefos::AssemblyRefOsRc`] - Reference-counted pointer
//!
//! # `AssemblyRefOS` Table Structure
//!
//! The `AssemblyRefOS` table contains zero or more rows with these fields:
//! - **`OSPlatformId`**: Operating system platform identifier
//! - **`OSMajorVersion`**: Major version number of the target operating system
//! - **`OSMinorVersion`**: Minor version number of the target operating system  
//! - **`AssemblyRef`**: Reference to the corresponding `AssemblyRef` table entry
//!
//! # Usage Context
//!
//! The `AssemblyRefOS` table is rarely used in modern .NET assemblies and is considered legacy.
//! It was designed for scenarios where external assembly references needed explicit operating
//! system version requirements. Most modern assemblies rely on platform-neutral deployment.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//!
//! # References
//!
//! - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification

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

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assemblyrefos::AssemblyRefOs`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `AssemblyRefOS` entries indexed by their metadata tokens.
pub type AssemblyRefOsMap = SkipMap<Token, AssemblyRefOsRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::assemblyrefos::AssemblyRefOs`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `AssemblyRefOS` collections.
pub type AssemblyRefOsList = Arc<boxcar::Vec<AssemblyRefOsRc>>;

/// Reference-counted smart pointer to an [`crate::metadata::tables::assemblyrefos::AssemblyRefOs`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `AssemblyRefOS` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type AssemblyRefOsRc = Arc<AssemblyRefOs>;

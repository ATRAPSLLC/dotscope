//! `AssemblyOS` table module
//!
//! Provides complete support for the ECMA-335 `AssemblyOS` metadata table (0x22), which contains
//! operating system platform information for assemblies. This module includes raw table access,
//! collection types, and platform identification utilities.
//!
//! # Components
//!
//! - [`crate::metadata::tables::assemblyos::AssemblyOsRaw`]: Raw table structure (no heap resolution needed)
//! - [`crate::metadata::tables::assemblyos::AssemblyOs`]: Type alias to Raw since all data is self-contained
//! - [`crate::metadata::loader::tables::AssemblyOsLoader`]: Internal loader for processing `AssemblyOS` table data
//! - Type aliases for efficient collections and reference management
//!
//! # `AssemblyOS` Table Structure
//!
//! The `AssemblyOS` table contains platform targeting information:
//! - **`OSPlatformId`**: Operating system platform identifier (4 bytes)
//! - **`OSMajorVersion`**: Major version number of the target OS (4 bytes)
//! - **`OSMinorVersion`**: Minor version number of the target OS (4 bytes)
//!
//! # Historical Context
//!
//! This table was designed for early .NET Framework scenarios where assemblies might need
//! to specify explicit OS compatibility. Modern .NET applications typically rely on runtime
//! platform abstraction and conditional compilation instead of metadata-level OS targeting.
//!
//! # Reference
//! - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assemblyos::AssemblyOs`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `AssemblyOS` entries by their metadata tokens.
pub type AssemblyOsMap = SkipMap<Token, AssemblyOsRc>;

/// A vector that holds a list of [`crate::metadata::tables::assemblyos::AssemblyOs`] references
///
/// Thread-safe append-only vector for storing `AssemblyOS` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type AssemblyOsList = Arc<boxcar::Vec<AssemblyOsRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::assemblyos::AssemblyOs`]
///
/// Provides shared ownership and automatic memory management for `AssemblyOS` instances.
/// Multiple references can safely point to the same `AssemblyOS` data across threads.
pub type AssemblyOsRc = Arc<AssemblyOs>;

/// Operating system targeting information for assemblies
///
/// Type alias to [`crate::metadata::tables::assemblyos::AssemblyOsRaw`] since the `AssemblyOS` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `AssemblyOS` table specifies which operating systems this assembly is designed to run on,
/// though this information is rarely used in modern .NET applications which rely on runtime
/// platform abstraction instead.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `AssemblyOS` contains
/// only integer values, making the "raw" and "owned" representations identical.
///
/// # Reference
/// - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification (Table ID = 0x22)
pub type AssemblyOs = AssemblyOsRaw;

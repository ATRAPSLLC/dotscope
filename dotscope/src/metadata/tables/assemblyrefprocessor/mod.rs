//! `AssemblyRefProcessor` table module.
//!
//! This module provides complete support for the ECMA-335 `AssemblyRefProcessor` metadata table (0x24),
//! which contains processor architecture compatibility information for external assembly references.
//! It includes raw table access, resolved data structures, collection types, and integration
//! with the broader assembly reference system.
//!
//! # Architecture
//!
//! The `AssemblyRefProcessor` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved table indexes, while owned entries
//! provide fully resolved references integrated with assembly reference data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::assemblyrefprocessor::owned::AssemblyRefProcessor`] - Owned variant with resolved references
//! - [`crate::metadata::loader::tables::AssemblyRefProcessorLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorMap`] - Token-based lookup map
//! - [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorList`] - Collection type
//! - [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorRc`] - Reference-counted pointer
//!
//! # `AssemblyRefProcessor` Table Structure
//!
//! The `AssemblyRefProcessor` table contains zero or more rows with these fields:
//! - **Processor**: Processor architecture identifier (x86, x64, ARM, etc.)
//! - **`AssemblyRef`**: Reference to the corresponding `AssemblyRef` table entry
//!
//! # Usage Context
//!
//! The `AssemblyRefProcessor` table is rarely used in modern .NET assemblies and is considered legacy.
//! It was designed for scenarios where external assembly references needed explicit processor
//! architecture requirements. Most modern assemblies rely on platform-neutral deployment and
//! runtime architecture detection.
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
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification
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

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessor`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `AssemblyRefProcessor` entries indexed by their metadata tokens.
pub type AssemblyRefProcessorMap = SkipMap<Token, AssemblyRefProcessorRc>;
/// Thread-safe vector that holds a list of [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessor`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `AssemblyRefProcessor` collections.
pub type AssemblyRefProcessorList = Arc<boxcar::Vec<AssemblyRefProcessorRc>>;
/// Reference-counted smart pointer to an [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessor`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `AssemblyRefProcessor` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type AssemblyRefProcessorRc = Arc<AssemblyRefProcessor>;

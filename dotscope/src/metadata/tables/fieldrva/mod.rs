//! `FieldRva` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `FieldRva` metadata table,
//! which specifies Relative Virtual Addresses (RVAs) for fields that have initial data stored
//! in the PE file. This enables static field initialization and constant data embedding.
//!
//! # Overview
//! The `FieldRva` table associates fields with their initial data locations:
//! - **Static field initialization**: Pre-computed initial values for static fields
//! - **Constant data**: Read-only data embedded directly in the PE file
//! - **Global variables**: Module-level data with specific initial states
//! - **Interop data**: Native data structures for P/Invoke and COM scenarios
//! - **Resource embedding**: Binary resources accessible through field references
//!
//! # Components
//! - [`crate::metadata::tables::fieldrva::raw::FieldRvaRaw`]: Raw field RVA data read directly from metadata tables
//! - [`crate::metadata::tables::fieldrva::owned::FieldRva`]: Owned field RVA data with resolved references
//! - [`crate::metadata::loader::tables::FieldRvaLoader`]: Processes and loads field RVA metadata
//! - [`crate::metadata::tables::fieldrva::FieldRVAMap`]: Thread-safe collection of field RVAs indexed by token
//! - [`crate::metadata::tables::fieldrva::FieldRVAList`]: Vector-based collection of field RVAs
//! - [`crate::metadata::tables::fieldrva::FieldRVARc`]: Reference-counted field RVA for shared ownership
//!
//! # Table Structure
//! Each `FieldRva` entry contains:
//! - **RVA**: Relative Virtual Address pointing to field data in PE file
//! - **Field**: Reference to the field in the Field table
//!
//! # RVA Resolution
//! RVAs enable data access within the PE file:
//! ```text
//! RVA + Section Base Address = File Offset
//! Field Type + File Offset = Typed Data Access
//! ```
//!
//! # Data Access Patterns
//! - **Static arrays**: Pre-initialized array data for static fields
//! - **Constant strings**: String literals embedded in the PE file
//! - **Numeric constants**: Pre-computed values for mathematical constants
//! - **Lookup tables**: Read-only data tables for algorithms
//! - **Configuration data**: Default settings and parameters
//!
//! # PE File Integration
//! `FieldRva` entries integrate with PE file structure:
//! - **Section mapping**: RVAs resolve to specific PE sections
//! - **Memory layout**: Data positioned for efficient runtime access
//! - **File alignment**: Data aligned according to PE requirements
//! - **Protection flags**: Data sections with appropriate read/write permissions
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the complete `FieldRva` table specification.

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

/// Thread-safe map of field RVA entries indexed by field token.
///
/// This skip list-based map provides efficient concurrent access to field RVA
/// information, allowing multiple threads to resolve field data locations during
/// metadata processing and static field initialization.
pub type FieldRVAMap = SkipMap<Token, FieldRVARc>;

/// Thread-safe vector of field RVA entries.
///
/// This collection provides ordered access to field RVA entries, useful for
/// sequential processing and bulk operations during metadata analysis and
/// static data initialization.
pub type FieldRVAList = Arc<boxcar::Vec<FieldRVARc>>;

/// Reference-counted field RVA entry.
///
/// Provides shared ownership of [`crate::metadata::tables::fieldrva::owned::FieldRva`] instances, enabling efficient
/// sharing of field RVA data across multiple data structures and threads.
pub type FieldRVARc = Arc<FieldRva>;

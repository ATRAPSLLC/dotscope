//! # `ModuleRef` Table Module
//!
//! This module provides comprehensive access to the `ModuleRef` metadata table (ID 0x1A),
//! which contains references to external modules that are required by the current assembly.
//! `ModuleRef` entries enable multi-module assemblies and cross-module type/method references.
//!
//! ## Overview
//!
//! The `ModuleRef` table manages external module dependencies in .NET assemblies:
//! - **Module References**: Identifies external modules by name
//! - **Cross-Module Support**: Enables references to types and methods in other modules
//! - **Multi-Module Assemblies**: Supports assemblies spanning multiple modules
//! - **Dependency Tracking**: Maintains module dependency relationships
//!
//! This table is essential for resolving cross-module references and managing
//! multi-module assembly structures.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`ModuleRefRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`ModuleRef`] - Processed data with resolved module names
//! - [`ModuleRefLoader`](crate::metadata::loader::tables::ModuleRefLoader) - Handles conversion between raw and processed representations
//! - [`ModuleRefMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`ModuleRefList`] - Thread-safe collection for sequential access
//!
//! ## Table Structure
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Name` | `u32` | Index into string heap containing module name |
//!
//! The `ModuleRef` table has a simple structure with just the module name reference,
//! making it one of the most straightforward metadata tables.
//!
//! ## Module Dependencies
//!
//! `ModuleRef` entries enable several types of cross-module references:
//!
//! 1. **Type References**: References to types defined in external modules
//! 2. **Method References**: References to methods defined in external modules
//! 3. **Assembly Structure**: Support for multi-module assembly organization
//! 4. **Import Resolution**: Foundation for resolving imported symbols
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.31** - `ModuleRef` table structure and semantics
//! - **§II.23.2.6** - `ModuleRef` metadata token format
//! - **§II.24.2.1** - String heap references
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).
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

/// Thread-safe map holding the mapping of [`crate::metadata::token::Token`] to parsed [`ModuleRef`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to `ModuleRef` entries
/// by their metadata token. Used for resolving module references during metadata processing.
pub type ModuleRefMap = SkipMap<Token, ModuleRefRc>;

/// Thread-safe vector holding a list of [`ModuleRef`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access.
/// Provides sequential access to `ModuleRef` entries for iteration and batch processing.
pub type ModuleRefList = Arc<boxcar::Vec<ModuleRefRc>>;

/// Reference-counted pointer to a [`ModuleRef`] entry.
///
/// Enables efficient sharing of `ModuleRef` data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type ModuleRefRc = Arc<ModuleRef>;

impl ImportContainer for Arc<ModuleRef> {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_module_ref(self)
    }
}

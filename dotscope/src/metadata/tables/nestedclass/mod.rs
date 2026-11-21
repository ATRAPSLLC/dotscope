//! # `NestedClass` Table Module
//!
//! This module provides comprehensive access to the **`NestedClass`** metadata table (ID 0x29),
//! which defines the hierarchical relationships between nested types and their enclosing types.
//! `NestedClass` entries establish the type containment structure essential for proper type
//! visibility and scoping in .NET assemblies.
//!
//! ## Overview
//!
//! The `NestedClass` table manages type nesting relationships in .NET assemblies:
//! - **Type Hierarchy**: Defines which types are nested within other types
//! - **Visibility Scoping**: Establishes access rules for nested types
//! - **Enclosing Context**: Links nested types to their containing types
//! - **Namespace Resolution**: Enables proper type resolution within nested contexts
//!
//! This table is crucial for understanding the complete type structure and implementing
//! correct type visibility and accessibility rules.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`NestedClassRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`NestedClass`] - Processed data with resolved type references
//! - [`NestedClassLoader`](crate::metadata::loader::tables::NestedClassLoader) - Handles conversion between raw and processed representations
//! - [`NestedClassMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`NestedClassList`] - Thread-safe collection for sequential access
//!
//! ## Table Structure
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `NestedClass` | `TypeDefOrRef` | Token of the nested type |
//! | `EnclosingClass` | `TypeDef` | Token of the enclosing type |
//!
//! The table establishes one-to-many relationships where a single enclosing type
//! can contain multiple nested types.
//!
//! ## Nesting Relationships
//!
//! `NestedClass` entries enable several important type relationships:
//!
//! 1. **Type Containment**: Defines which types are nested within others
//! 2. **Access Control**: Establishes visibility rules for nested types
//! 3. **Name Resolution**: Enables qualified name resolution within type hierarchies
//! 4. **Compilation Context**: Provides context for type compilation and loading
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.32** - `NestedClass` table structure and semantics
//! - **§II.23.2.6** - `NestedClass` metadata token format
//! - **§II.24.2.6** - `TypeDefOrRef` coded index format
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).
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

/// Thread-safe map holding the mapping of [`crate::metadata::token::Token`] to parsed [`NestedClass`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to `NestedClass` entries
/// by their metadata token. Used for resolving nested type relationships during metadata processing.
pub type NestedClassMap = SkipMap<Token, NestedClassRc>;

/// Thread-safe vector holding a list of [`NestedClass`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access.
/// Provides sequential access to `NestedClass` entries for iteration and batch processing.
pub type NestedClassList = Arc<boxcar::Vec<NestedClassRc>>;

/// Reference-counted pointer to a [`NestedClass`] entry.
///
/// Enables efficient sharing of `NestedClass` data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type NestedClassRc = Arc<NestedClass>;

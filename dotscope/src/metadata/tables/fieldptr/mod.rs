//! `FieldPtr` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `FieldPtr` metadata table,
//! which acts as an indirection mechanism for Field table access. The `FieldPtr` table is used
//! when the logical field order differs from the physical storage order in metadata.
//!
//! # Overview
//! The `FieldPtr` table provides indirection for field references in specific scenarios:
//! - **Field reordering**: When physical field order differs from logical declaration order
//! - **Metadata optimization**: Reducing metadata size through strategic field organization
//! - **Edit-and-continue**: Supporting field additions without breaking existing references
//! - **Incremental compilation**: Maintaining field references across compilation sessions
//! - **Compressed metadata**: Optimizing field access in compressed metadata streams
//!
//! # Components
//! - [`crate::metadata::tables::fieldptr::raw::FieldPtrRaw`]: Raw field pointer data read directly from metadata tables
//! - [`crate::metadata::tables::fieldptr::owned::FieldPtr`]: Owned field pointer data with resolved references
//! - [`crate::metadata::loader::tables::FieldPtrLoader`]: Processes and loads field pointer metadata
//! - [`crate::metadata::tables::fieldptr::FieldPtrMap`]: Thread-safe collection of field pointers indexed by token
//! - [`crate::metadata::tables::fieldptr::FieldPtrList`]: Vector-based collection of field pointers
//! - [`crate::metadata::tables::fieldptr::FieldPtrRc`]: Reference-counted field pointer for shared ownership
//!
//! # Dual-Variant Pattern
//! The module follows the established dual-variant pattern:
//! - **Raw variant** ([`crate::metadata::tables::fieldptr::raw::FieldPtrRaw`]): Unresolved indexes, minimal processing
//! - **Owned variant** ([`crate::metadata::tables::fieldptr::owned::FieldPtr`]): Resolved references, owned data structures
//!
//! # Table Structure
//! Each `FieldPtr` entry contains:
//! - **Field**: Index into the Field table for the actual field definition
//!
//! # Indirection Mechanism
//! When `FieldPtr` table is present:
//! ```text
//! Logical Index → FieldPtr[Logical] → Field[Physical]
//! ```
//! When `FieldPtr` table is absent:
//! ```text
//! Logical Index → Field[Logical]
//! ```
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.18 for the complete `FieldPtr` table specification.

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

/// Thread-safe map of field pointer entries indexed by `FieldPtr` token.
///
/// This skip list-based map provides efficient concurrent access to field pointer
/// information, allowing multiple threads to resolve field indirection during
/// metadata processing and type resolution operations.
pub type FieldPtrMap = SkipMap<Token, FieldPtrRc>;

/// Thread-safe vector of field pointer entries.
///
/// This collection provides ordered access to field pointer entries, useful for
/// sequential processing and bulk operations during metadata analysis and field
/// resolution operations.
pub type FieldPtrList = Arc<boxcar::Vec<FieldPtrRc>>;

/// Reference-counted field pointer entry.
///
/// Provides shared ownership of [`crate::metadata::tables::fieldptr::owned::FieldPtr`] instances, enabling efficient
/// sharing of field pointer data across multiple data structures and threads.
pub type FieldPtrRc = Arc<FieldPtr>;

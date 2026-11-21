//! `ClassLayout` table module.
//!
//! This module provides complete support for the ECMA-335 `ClassLayout` metadata table (0x0F),
//! which contains explicit memory layout information for types that require specific field
//! positioning and packing. It includes raw table access, resolved data structures, collection
//! types, and integration with the broader type system.
//!
//! # Architecture
//!
//! The `ClassLayout` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved table indexes, while owned entries
//! provide fully resolved references integrated with type definition data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::classlayout::owned::ClassLayout`] - Owned variant with resolved references
//! - [`crate::metadata::loader::tables::ClassLayoutLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::classlayout::ClassLayoutMap`] - Token-based lookup map
//! - [`crate::metadata::tables::classlayout::ClassLayoutList`] - Collection type
//! - [`crate::metadata::tables::classlayout::ClassLayoutRc`] - Reference-counted pointer
//!
//! # `ClassLayout` Table Structure
//!
//! The `ClassLayout` table contains zero or more rows with these fields:
//! - **`PackingSize`**: Byte boundary alignment for fields (powers of 2: 1, 2, 4, 8, 16, etc.)
//! - **`ClassSize`**: Total size of the type in bytes (0 indicates automatic sizing)
//! - **Parent**: Reference to the corresponding `TypeDef` table entry
//!
//! # Usage Context
//!
//! `ClassLayout` is used for types that require explicit memory layout control:
//! - **Interop scenarios**: Types that need to match native C/C++ struct layouts
//! - **Performance optimization**: Cache-friendly field alignment and padding
//! - **Platform marshalling**: Ensuring consistent layout across platforms
//! - **Sequential layout**: Enforcing field order for binary compatibility
//! - **Explicit layout**: Supporting [StructLayout(LayoutKind.Explicit)] attributes
//!
//! # Memory Layout Types
//!
//! `ClassLayout` supports three primary layout strategies:
//! - **Auto**: Runtime determines optimal field arrangement for performance
//! - **Sequential**: Fields are laid out in declaration order with automatic padding
//! - **Explicit**: Each field has an explicitly specified byte offset
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::typedef`] - Type definition table entries
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//!
//! # References
//!
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ClassLayout` table specification

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

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::classlayout::ClassLayout`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `ClassLayout` entries indexed by their metadata tokens.
pub type ClassLayoutMap = SkipMap<Token, ClassLayoutRc>;
/// Thread-safe vector that holds a list of [`crate::metadata::tables::classlayout::ClassLayout`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `ClassLayout` collections.
pub type ClassLayoutList = Arc<boxcar::Vec<ClassLayoutRc>>;
/// Reference-counted smart pointer to a [`crate::metadata::tables::classlayout::ClassLayout`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `ClassLayout` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type ClassLayoutRc = Arc<ClassLayout>;

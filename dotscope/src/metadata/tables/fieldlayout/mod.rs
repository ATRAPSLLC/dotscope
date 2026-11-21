//! `FieldLayout` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `FieldLayout` metadata table,
//! which specifies explicit field positioning within types. The `FieldLayout` table defines the
//! byte offset of fields in classes and value types, enabling precise control over memory layout.
//!
//! # Overview
//! The `FieldLayout` table is used when explicit field layout control is required, such as:
//! - **Interop scenarios**: P/Invoke, COM interop requiring specific layouts
//! - **Performance optimization**: Cache-line alignment, memory layout control
//! - **Platform compatibility**: Ensuring consistent layouts across platforms
//! - **Legacy compatibility**: Matching existing native data structure layouts
//!
//! # Components
//! - [`crate::metadata::tables::fieldlayout::raw::FieldLayoutRaw`]: Raw field layout data read directly from metadata tables
//! - [`crate::metadata::tables::fieldlayout::owned::FieldLayout`]: Owned field layout data with resolved references
//! - [`crate::metadata::loader::tables::FieldLayoutLoader`]: Processes and loads field layout metadata
//! - [`crate::metadata::tables::fieldlayout::FieldLayoutMap`]: Thread-safe collection of field layouts indexed by token
//! - [`crate::metadata::tables::fieldlayout::FieldLayoutList`]: Vector-based collection of field layouts
//! - [`crate::metadata::tables::fieldlayout::FieldLayoutRc`]: Reference-counted field layout for shared ownership
//!
//! # Table Structure
//! Each `FieldLayout` entry contains:
//! - **Offset**: 4-byte field offset within the containing type
//! - **Field**: Reference to the field in the Field table
//!
//! # Field Layout Scenarios
//! - **Sequential Layout**: Default .NET field ordering (no `FieldLayout` entries)
//! - **Explicit Layout**: Specific byte offsets defined (`FieldLayout` entries present)
//! - **Auto Layout**: Runtime-optimized positioning (no `FieldLayout` entries)
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.16 for the complete `FieldLayout` table specification.

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

/// Thread-safe map of field layout entries indexed by field token.
///
/// This skip list-based map provides efficient concurrent access to field layout
/// information, allowing multiple threads to query field offsets during metadata
/// processing and type resolution operations.
pub type FieldLayoutMap = SkipMap<Token, FieldLayoutRc>;

/// Thread-safe vector of field layout entries.
///
/// This collection provides ordered access to field layout entries, useful for
/// sequential processing and bulk operations during metadata analysis.
pub type FieldLayoutList = Arc<boxcar::Vec<FieldLayoutRc>>;

/// Reference-counted field layout entry.
///
/// Provides shared ownership of [`crate::metadata::tables::fieldlayout::owned::FieldLayout`] instances, enabling efficient
/// sharing of field layout data across multiple data structures and threads.
pub type FieldLayoutRc = Arc<FieldLayout>;

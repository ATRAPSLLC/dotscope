//! `MethodPtr` table implementation for method indirection and table reorganization.
//!
//! This module provides complete support for the `MethodPtr` metadata table, which provides
//! an additional level of indirection for accessing `MethodDef` table entries. The `MethodPtr`
//! table is primarily used in specialized scenarios requiring method table reorganization,
//! runtime method modification, or stable method references during development.
//!
//! # Module Components
//! - [`MethodPtrRaw`] - Raw table structure with unresolved indexes
//! - [`MethodPtr`] - Owned variant with resolved references and indirection information
//! - [`MethodPtrLoader`](crate::metadata::loader::tables::MethodPtrLoader) - Internal loader for processing table entries (crate-private)
//! - Type aliases for collections: [`MethodPtrMap`], [`MethodPtrList`], [`MethodPtrRc`]
//!
//! # Table Structure (ECMA-335 §22.28)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Method | `MethodDef` table index | Physical method definition reference |
//!
//! # Indirection Mechanism
//! The `MethodPtr` table establishes a logical-to-physical mapping system:
//! - **Logical method tokens**: Stable identifiers used by other metadata tables
//! - **Physical method entries**: Actual `MethodDef` table entries containing implementation
//! - **Pointer resolution**: Translation from logical tokens to physical method definitions
//! - **Table stability**: Allows `MethodDef` table reorganization without breaking references
//!
//! # Usage Scenarios
//! The `MethodPtr` table appears in specialized development and runtime scenarios:
//! - **Edit-and-continue**: Development environments supporting runtime method modification
//! - **Hot-reload systems**: Runtime environments enabling dynamic method updates
//! - **Debugging support**: Debuggers requiring method interception and modification capabilities
//! - **Incremental compilation**: Build systems performing partial assembly updates
//! - **Method versioning**: Systems requiring method replacement without reference updates
//!
//! # Resolution Process
//! Method pointer resolution follows a two-step process:
//! - **Step 1**: Map logical method token to `MethodPtr` entry
//! - **Step 2**: Map `MethodPtr` entry to physical `MethodDef` entry
//! - **Optimization**: Direct resolution when `MethodPtr` table is absent
//! - **Consistency**: All method references use same resolution mechanism
//!
//! # Table Presence Detection
//! The `MethodPtr` table is optional in .NET assemblies:
//! - **Present**: Indicates specialized scenarios requiring method indirection
//! - **Absent**: Standard assemblies use direct `MethodDef` token references
//! - **Detection**: Metadata loader checks table presence during initialization
//! - **Fallback**: Direct method resolution when indirection is unavailable
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.28: `MethodPtr` table specification
//! - ECMA-335, Partition II, §24.2.6: Metadata table organization and indirection
//! - ECMA-335, Partition II, §6.2: Method definitions and references
//!
//! [`SkipMap`]: crossbeam_skiplist::SkipMap
//! [`Arc<boxcar::Vec>`]: std::sync::Arc
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

/// Concurrent map for storing `MethodPtr` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of method pointer entries by their
/// logical tokens during metadata processing and method resolution operations.
pub type MethodPtrMap = SkipMap<Token, MethodPtrRc>;

/// Thread-safe list for storing collections of `MethodPtr` entries.
///
/// Used for maintaining ordered sequences of method pointers during metadata
/// loading and for iteration over all indirection mappings in an assembly.
pub type MethodPtrList = Arc<boxcar::Vec<MethodPtrRc>>;

/// Reference-counted pointer to a [`MethodPtr`] instance.
///
/// Enables efficient sharing of method pointer data across multiple contexts
/// without duplication, supporting concurrent access patterns in method resolution.
pub type MethodPtrRc = Arc<MethodPtr>;

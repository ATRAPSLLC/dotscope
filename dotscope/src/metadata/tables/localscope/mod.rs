//! `LocalScope` table implementation for Portable PDB format
//!
//! This module provides access to `LocalScope` table data, which defines the scope ranges
//! where local variables and constants are active within methods. Used by debuggers to
//! determine variable and constant visibility at different execution points.
//!
//! The `LocalScope` table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`LocalScopeRaw`] for raw binary data with unresolved indices
//! - [`LocalScope`] for processed data with resolved scope information
//!
//! # Architecture
//!
//! This table is part of the Portable PDB format and provides essential information
//! for debuggers to determine variable and constant visibility at different execution points.
//! Each scope defines a range of IL instructions where specific variables and constants
//! are accessible, enabling proper debugging support for block-scoped variables.
//!
//! # Key Components
//!
//! - [`LocalScopeRaw`] - Raw table structure with unresolved indices
//! - [`LocalScope`] - Owned variant with resolved references and scope information
//! - [`LocalScopeLoader`](crate::metadata::loader::tables::LocalScopeLoader) - Internal loader for processing `LocalScope` table data
//! - [`LocalScopeMap`] - Thread-safe concurrent map for caching scope entries
//! - [`LocalScopeList`] - Thread-safe append-only vector for scope collections
//! - [`LocalScopeRc`] - Reference-counted pointer for shared ownership
//!
//! # `LocalScope` Table Structure
//!
//! Each `LocalScope` table row contains these fields:
//! - **Method**: Simple index into `MethodDef` table (method containing scope)
//! - **`ImportScope`**: Simple index into `ImportScope` table (import context)
//! - **`VariableList`**: Simple index into `LocalVariable` table (first variable)
//! - **`ConstantList`**: Simple index into `LocalConstant` table (first constant)
//! - **`StartOffset`**: IL instruction offset where scope begins
//! - **Length**: Length of scope in IL instruction bytes
//!
//! # Usage Examples
//!
//! ```no_run
//! use dotscope::{
//!     metadata::tables::{LocalScopeBuilder, LocalScopeRaw},
//!     CilAssembly, CilAssemblyView,
//! };
//!
//! // A scope covering IL offsets 0x10..0x30 of the first method
//! let mut assembly = CilAssembly::from_path("app.dll")?;
//! LocalScopeBuilder::new()
//!     .method(1)
//!     .import_scope(0)
//!     .variable_list(1)
//!     .constant_list(1)
//!     .start_offset(0x10)
//!     .length(0x20)
//!     .build(&mut assembly)?;
//!
//! let view = CilAssemblyView::from_mem(assembly.to_memory()?)?;
//! if let Some(scopes) = view.tables().and_then(|t| t.table::<LocalScopeRaw>()) {
//!     for scope in scopes.iter().filter_map(Result::ok) {
//!         println!(
//!             "method {}: IL {:#x}..{:#x}",
//!             scope.method,
//!             scope.start_offset,
//!             scope.start_offset + scope.length
//!         );
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`LocalScopeMap`] and
//! [`LocalScopeList`] use lock-free concurrent data structures for efficient
//! multi-threaded access.
//!
//! # References
//!
//! - [Portable PDB Format - LocalScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localscope-table-0x32)

use std::sync::{Arc, Weak};

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

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`LocalScope`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved local scope information by their metadata tokens.
pub type LocalScopeMap = SkipMap<Token, LocalScopeRc>;

/// A vector that holds a list of [`LocalScope`] references
///
/// Thread-safe append-only vector for storing local scope collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type LocalScopeList = Arc<boxcar::Vec<LocalScopeRc>>;

/// A reference-counted pointer to a [`LocalScope`]
///
/// Provides shared ownership and automatic memory management for local scope instances.
/// Multiple references can safely point to the same local scope data across threads.
pub type LocalScopeRc = Arc<LocalScope>;

/// Weak reference to a `LocalScope` to avoid circular dependencies
///
/// Since scopes can form tree structures where parent scopes might reference
/// child scopes or vice versa, we use weak references to prevent memory leaks
/// from circular references.
#[derive(Clone)]
pub struct LocalScopeRef {
    /// Weak reference to the actual scope to avoid reference cycles
    weak_ref: Weak<LocalScope>,
}

impl LocalScopeRef {
    /// Create a new `LocalScopeRef` from a strong reference
    #[must_use]
    pub fn new(strong_ref: &LocalScopeRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Upgrade the weak reference to a strong reference if still valid
    #[must_use]
    pub fn upgrade(&self) -> Option<LocalScopeRc> {
        self.weak_ref.upgrade()
    }
}

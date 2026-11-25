//! `EventPtr` table module.
//!
//! This module provides comprehensive support for the ECMA-335 `EventPtr` metadata table (0x13),
//! which provides a level of indirection for event references. `EventPtr` tables are
//! typically present only in assemblies that have undergone edit-and-continue operations,
//! where the original event ordering may have been disrupted. It includes raw table access,
//! resolved data structures, and integration with the broader metadata system.
//!
//! # Components
//!
//! - **Raw Representation**: [`EventPtrRaw`] - Direct binary table format with unresolved indexes
//! - **Owned Data**: [`EventPtr`] - Resolved entries with owned data and direct event references
//! - **Loading Infrastructure**: [`EventPtrLoader`](crate::metadata::loader::tables::EventPtrLoader) - Processes raw entries during metadata loading
//! - **Type Aliases**: Collection types for managing `EventPtr` entries efficiently
//!
//! # `EventPtr` Table Structure
//!
//! Each `EventPtr` entry contains:
//! - **Event** (2/4 bytes): RID pointing to the actual event in the Event table
//!
//! The table provides a simple indirection mechanism where logical event indexes
//! map to physical event locations, allowing for non-contiguous event arrangements
//! while maintaining logical ordering.
//!
//! # Edit-and-Continue Support
//!
//! `EventPtr` tables are primarily used to support edit-and-continue scenarios:
//! - Original event table ordering may be disrupted during code modifications
//! - `EventPtr` provides stable logical indexes that map to potentially relocated events
//! - Enables maintaining consistent metadata references across edit sessions
//!
//! # Conditional Presence
//!
//! `EventPtr` tables are optional and only present when needed:
//! - **Not Present**: Direct event indexing is used (normal case)
//! - **Present**: Indirection through `EventPtr` is required (edit-and-continue case)
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventPtr` table specification

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

/// Thread-safe map of metadata tokens to `EventPtr` entries
///
/// Provides efficient concurrent access to `EventPtr` entries indexed by their
/// metadata tokens. Uses a lock-free skip list implementation for high-performance
/// concurrent reads and writes during metadata loading.
pub type EventPtrMap = SkipMap<Token, EventPtrRc>;

/// Thread-safe vector of `EventPtr` entries
///
/// Provides a growable collection of `EventPtr` entries with thread-safe append
/// operations. Used for collecting entries during parallel processing phases
/// of metadata loading.
pub type EventPtrList = Arc<boxcar::Vec<EventPtrRc>>;

/// Reference-counted pointer to an `EventPtr` entry
///
/// Provides shared ownership of [`EventPtr`] instances across multiple
/// threads and data structures. Enables efficient memory usage and safe
/// concurrent access to `EventPtr` metadata.
pub type EventPtrRc = Arc<EventPtr>;

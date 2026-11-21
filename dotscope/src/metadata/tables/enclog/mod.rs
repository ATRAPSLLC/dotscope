//! EncLog table implementation for Edit-and-Continue debugging support
//!
//! This module provides complete support for the ECMA-335 EncLog metadata table (0x1E), which contains
//! Edit-and-Continue log entries that track modifications made during debugging sessions.
//! The module includes raw table access, collection types, and edit operation tracking capabilities.
//!
//! # Architecture
//!
//! The EncLog table is designed to record all metadata changes made during Edit-and-Continue
//! debugging sessions. Unlike other metadata tables, the EncLog table contains only primitive
//! values (tokens and operation codes), requiring no heap resolution. This simplicity enables
//! efficient tracking of edit operations during active debugging scenarios.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::enclog::EncLogRaw`] - Raw table structure with metadata tokens and operation codes
//! - [`crate::metadata::tables::enclog::EncLog`] - Type alias to EncLogRaw since no heap resolution is needed
//! - [`crate::metadata::loader::tables::EncLogLoader`] - Internal loader for processing EncLog table data
//! - [`crate::metadata::tables::enclog::EncLogMap`] - Thread-safe concurrent map for caching EncLog entries
//! - [`crate::metadata::tables::enclog::EncLogList`] - Thread-safe append-only vector for EncLog collections
//! - [`crate::metadata::tables::enclog::EncLogRc`] - Reference-counted pointer for shared ownership
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{EncLog, EncLogMap};
//! use dotscope::metadata::token::Token;
//!
//! # fn example(enc_logs: &EncLogMap) -> dotscope::Result<()> {
//! // Get a specific EncLog entry by token
//! let token = Token::new(0x1E000001); // EncLog table token
//! if let Some(enc_log) = enc_logs.get(&token) {
//!     println!("Token: {:?}", enc_log.value().token);
//!     println!("Function Code: {}", enc_log.value().func_code);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Edit-and-Continue Operations
//!
//! The EncLog table supports three types of edit operations:
//! - **Create (0)**: New metadata element added during debugging
//! - **Update (1)**: Existing metadata element modified during debugging  
//! - **Delete (2)**: Metadata element removed during debugging
//!
//! # Error Handling
//!
//! This module handles error conditions during EncLog processing:
//! - Invalid tokens that don't correspond to valid metadata elements (returns [`crate::Error`])
//! - Malformed operation codes outside the valid range (returns [`crate::Error`])
//! - Table parsing errors when the EncLog structure is corrupted (returns [`crate::Error`])
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`crate::metadata::tables::enclog::EncLogMap`] and [`crate::metadata::tables::enclog::EncLogList`]
//! use lock-free concurrent data structures for efficient multi-threaded access during debugging sessions.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - Debugging tools that implement Edit-and-Continue functionality
//!
//! # References
//!
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - EncLog table specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::enclog::EncLog`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `EncLog` entries by their metadata tokens.
pub type EncLogMap = SkipMap<Token, EncLogRc>;

/// A vector that holds a list of [`crate::metadata::tables::enclog::EncLog`] references
///
/// Thread-safe append-only vector for storing `EncLog` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type EncLogList = Arc<boxcar::Vec<EncLogRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::enclog::EncLog`]
///
/// Provides shared ownership and automatic memory management for `EncLog` instances.
/// Multiple references can safely point to the same `EncLog` data across threads.
pub type EncLogRc = Arc<EncLog>;

/// Edit-and-Continue log entry for tracking debugging session modifications
///
/// Type alias to [`crate::metadata::tables::enclog::EncLogRaw`] since the `EncLog` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `EncLog` table records all metadata changes made during Edit-and-Continue debugging sessions,
/// enabling the runtime to understand what elements have been modified, added, or removed during
/// active debugging.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `EncLog` contains
/// only integer values (tokens and operation codes), making the "raw" and "owned"
/// representations identical.
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification (Table ID = 0x1E)
pub type EncLog = EncLogRaw;

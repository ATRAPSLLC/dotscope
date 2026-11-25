//! EncMap table implementation for Edit-and-Continue token mapping
//!
//! This module provides complete support for the ECMA-335 EncMap metadata table (0x1F), which
//! manages token mapping during Edit-and-Continue debugging operations. The EncMap table
//! correlates original metadata tokens with their updated versions after code modifications,
//! enabling debuggers to maintain proper references across edit sessions.
//!
//! # Architecture
//!
//! The EncMap table is designed to track metadata token relationships during Edit-and-Continue
//! debugging sessions. Unlike other metadata tables, the EncMap table contains only primitive
//! token values, requiring no heap resolution. This simplicity enables efficient token mapping
//! during active debugging scenarios where performance is critical.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::encmap::EncMapRaw`] - Raw table structure with original metadata tokens
//! - [`crate::metadata::tables::encmap::EncMap`] - Type alias to EncMapRaw since no heap resolution is needed
//! - [`crate::metadata::loader::tables::EncMapLoader`] - Internal loader for processing EncMap table data
//! - [`crate::metadata::tables::encmap::EncMapMap`] - Thread-safe concurrent map for caching EncMap entries
//! - [`crate::metadata::tables::encmap::EncMapList`] - Thread-safe append-only vector for EncMap collections
//! - [`crate::metadata::tables::encmap::EncMapRc`] - Reference-counted pointer for shared ownership
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{EncMap, EncMapMap};
//! use dotscope::metadata::token::Token;
//!
//! # fn example(enc_maps: &EncMapMap) -> dotscope::Result<()> {
//! // Get a specific EncMap entry by token
//! let token = Token::new(0x1F000001); // EncMap table token
//! if let Some(enc_map) = enc_maps.get(&token) {
//!     println!("Original token: {:#010x}", enc_map.value().original_token.value());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Edit-and-Continue Token Mapping
//!
//! During Edit-and-Continue debugging sessions:
//! 1. **Original Token Recording**: Original metadata tokens are stored in EncMap entries
//! 2. **Code Modification**: Developer modifies code while debugging is paused
//! 3. **New Token Generation**: Compiler generates new metadata with updated tokens
//! 4. **Token Correlation**: EncMap provides mapping between pre-edit and post-edit tokens
//! 5. **Reference Updates**: Debuggers use mappings to update breakpoints and watch expressions
//!
//! # Error Handling
//!
//! This module handles error conditions during EncMap processing:
//! - Invalid tokens that don't correspond to valid metadata elements (returns [`crate::Error`])
//! - Table parsing errors when the EncMap structure is corrupted (returns [`crate::Error`])
//! - Token mapping inconsistencies during Edit-and-Continue operations (returns [`crate::Error`])
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`crate::metadata::tables::encmap::EncMapMap`] and [`crate::metadata::tables::encmap::EncMapList`]
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
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - EncMap table specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::encmap::EncMap`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `EncMap` entries by their metadata tokens.
pub type EncMapMap = SkipMap<Token, EncMapRc>;

/// A vector that holds a list of [`crate::metadata::tables::encmap::EncMap`] references
///
/// Thread-safe append-only vector for storing `EncMap` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type EncMapList = Arc<boxcar::Vec<EncMapRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::encmap::EncMap`]
///
/// Provides shared ownership and automatic memory management for `EncMap` instances.
/// Multiple references can safely point to the same `EncMap` data across threads.
pub type EncMapRc = Arc<EncMap>;

/// Edit-and-Continue token mapping entry for debugging session operations
///
/// Type alias to [`crate::metadata::tables::encmap::EncMapRaw`] since the `EncMap` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `EncMap` table maps original metadata tokens to their updated versions after Edit-and-Continue
/// operations, enabling debuggers to maintain proper references during active debugging sessions.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `EncMap` contains
/// only integer values (tokens), making the "raw" and "owned" representations identical.
///
/// # Reference
/// - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncMap` table specification (Table ID = 0x1F)
pub type EncMap = EncMapRaw;

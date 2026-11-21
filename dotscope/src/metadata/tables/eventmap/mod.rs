//! EventMap table implementation for type-to-event relationships
//!
//! This module provides comprehensive support for the ECMA-335 EventMap metadata table (0x12),
//! which establishes the ownership relationship between types and their events. EventMap
//! entries define contiguous ranges of events that belong to specific types, enabling
//! efficient enumeration and lookup of events by owning type. The module includes raw table access,
//! resolved data structures, and integration with the broader metadata system.
//!
//! # Architecture
//!
//! The EventMap table is designed to efficiently associate types with their event definitions
//! through a range-based mapping system. The table is sorted by parent type token, and event
//! ownership is determined by ranges: events from EventList\[i\] to EventList\[i+1\]-1 belong to
//! Parent\[i\]. This design enables O(log n) type-to-event lookups and efficient enumeration
//! of all events owned by a specific type.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::eventmap::EventMapRaw`] - Raw table structure with unresolved indices  
//! - [`crate::metadata::tables::eventmap::EventMapEntry`] - Owned variant with resolved references and event mappings
//! - [`crate::metadata::loader::tables::EventMapLoader`] - Internal loader for processing EventMap table data
//! - [`crate::metadata::tables::eventmap::EventMapEntryMap`] - Thread-safe concurrent map for caching EventMap entries
//! - [`crate::metadata::tables::eventmap::EventMapEntryList`] - Thread-safe append-only vector for EventMap collections
//! - [`crate::metadata::tables::eventmap::EventMapEntryRc`] - Reference-counted pointer for shared ownership
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{EventMapEntry, EventMapEntryMap};
//! use dotscope::metadata::token::Token;
//!
//! # fn example(event_maps: &EventMapEntryMap) -> dotscope::Result<()> {
//! // Get EventMap entry for a specific type
//! let type_token = Token::new(0x02000001); // TypeDef table token
//! if let Some(event_map) = event_maps.get(&type_token) {
//!     println!("Type owns {} events", event_map.value().events.count());
//!     for (_, event) in event_map.value().events.iter() {
//!         println!("Event: {}", event.name);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Event Ownership Model
//!
//! The EventMap table establishes event ownership through:
//! - **Parent Type**: TypeDef token identifying the type that declares the events
//! - **Event Range**: Contiguous range of Event table entries owned by the parent type
//! - **Sorted Order**: Entries are sorted by parent type for efficient lookup operations
//! - **Range Resolution**: Event ownership determined by comparing adjacent EventList indices
//!
//! # Error Handling
//!
//! This module handles error conditions during EventMap processing:
//! - Parent type resolution failures when TypeDef tokens are invalid (returns [`crate::Error`])
//! - Event range calculation errors when EventList indices are out of bounds (returns [`crate::Error`])
//! - Cross-reference resolution failures when Event or EventPtr tables are inconsistent (returns [`crate::Error`])
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`crate::metadata::tables::eventmap::EventMapEntryMap`] and [`crate::metadata::tables::eventmap::EventMapEntryList`]
//! use lock-free concurrent data structures for efficient multi-threaded access during metadata analysis.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - Event table for event definition resolution
//! - EventPtr table for event pointer indirection handling
//! - TypeDef table for parent type resolution
//!
//! # References
//!
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - EventMap table specification

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

/// Thread-safe map of metadata tokens to `EventMap` entries
///
/// Provides efficient concurrent access to `EventMap` entries indexed by their
/// metadata tokens. Uses a lock-free skip list implementation for high-performance
/// concurrent reads and writes during metadata loading.
pub type EventMapEntryMap = SkipMap<Token, EventMapEntryRc>;

/// Thread-safe vector of `EventMap` entries
///
/// Provides a growable collection of `EventMap` entries with thread-safe append
/// operations. Used for collecting entries during parallel processing phases
/// of metadata loading.
pub type EventMapEntryList = Arc<boxcar::Vec<EventMapEntryRc>>;

/// Reference-counted pointer to an `EventMap` entry
///
/// Provides shared ownership of [`EventMapEntry`] instances across multiple
/// threads and data structures. Enables efficient memory usage and safe
/// concurrent access to `EventMap` metadata.
pub type EventMapEntryRc = Arc<EventMapEntry>;

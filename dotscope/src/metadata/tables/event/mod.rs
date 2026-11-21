//! Event table implementation for .NET event definitions
//!
//! This module provides complete support for the ECMA-335 Event metadata table (0x14),
//! which contains event definitions for .NET types. Events represent notification mechanisms
//! that allow objects to communicate state changes and important occurrences to interested
//! observers using the observer pattern. The module includes raw table access, resolved data structures,
//! and integration with the broader metadata system.
//!
//! # Architecture
//!
//! The Event table is designed to support .NET's event model, which provides type-safe
//! notification mechanisms for object-oriented programming. Events follow a standard pattern
//! with add/remove accessor methods and optional raise functionality. The table structure
//! includes event attributes, names, and type references that enable full compile-time and
//! runtime verification of event contracts.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::event::EventRaw`] - Raw table structure with unresolved heap indices
//! - [`crate::metadata::tables::event::Event`] - Owned variant with resolved references and parsed event metadata
//! - [`crate::metadata::loader::tables::EventLoader`] - Internal loader for processing Event table data
//! - [`crate::metadata::tables::event::EventMap`] - Thread-safe concurrent map for caching event entries
//! - [`crate::metadata::tables::event::EventList`] - Thread-safe append-only vector for event collections
//! - [`crate::metadata::tables::event::EventRc`] - Reference-counted pointer for shared ownership
//! - [`crate::metadata::tables::event::EventAttributes`] - Constants for event attribute flags
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{Event, EventMap};
//! use dotscope::metadata::token::Token;
//!
//! # fn example(events: &EventMap) -> dotscope::Result<()> {
//! // Get a specific event by token
//! let token = Token::new(0x14000001); // Event table token
//! if let Some(event) = events.get(&token) {
//!     println!("Event name: {}", event.value().name);
//!     println!("Event flags: {:#x}", event.value().flags);
//!     println!("Event type: {:?}", event.value().event_type);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Event Architecture
//!
//! .NET events provide these key capabilities:
//! - **Type Safety**: Event handler type is verified at compile time through coded indices
//! - **Multicast Support**: Multiple subscribers can be attached to a single event instance
//! - **Standard Pattern**: Consistent add/remove accessor methods with optional custom raise method
//! - **Metadata Integration**: Full reflection and debugging support through event metadata
//! - **Attribute Control**: Special naming and runtime behavior flags for advanced scenarios
//!
//! # Error Handling
//!
//! This module handles error conditions during event processing:
//! - Event name resolution failures when string heap indices are invalid (returns [`crate::Error`])
//! - Event type resolution errors when coded indices cannot be resolved (returns [`crate::Error`])
//! - Accessor method lookup failures when MethodSemantics references are broken (returns [`crate::Error`])
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`crate::metadata::tables::event::EventMap`] and [`crate::metadata::tables::event::EventList`]
//! use lock-free concurrent data structures for efficient multi-threaded access during metadata analysis.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - [`crate::metadata::streams::Strings`] - String heap for event name resolution
//! - Type system tables for event handler type resolution
//!
//! # References
//!
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{metadata::token::Token, utils::LazyList};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`Event`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved event definitions by their metadata tokens.
pub type EventMap = SkipMap<Token, EventRc>;

/// A vector that holds a list of [`Event`] references
///
/// Thread-safe append-only vector for storing event collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads. A
/// list allocates its storage on its first push: most types hold none.
pub type EventList = LazyList<EventRc>;

/// A reference-counted pointer to an [`Event`]
///
/// Provides shared ownership and automatic memory management for event instances.
/// Multiple references can safely point to the same event data across threads.
pub type EventRc = Arc<Event>;

metadata_flags! {
    /// Event attribute flags as defined in ECMA-335 (§II.23.1.4).
    ///
    /// Strongly-typed wrapper around the 2-byte `Event.EventFlags` bitmask that controls
    /// event behavior and special naming conventions. These flags indicate whether the
    /// event has special meaning or requires special handling by the runtime.
    ///
    /// ## Reference
    /// - [ECMA-335 II.23.1.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventAttributes` enumeration
    pub struct EventAttributes(u32);
}

impl EventAttributes {
    /// Event has a special name.
    ///
    /// Indicates that the event's name is special and should be treated accordingly
    /// by development tools. This is typically used for events that follow specific
    /// naming conventions or have special significance in the type system.
    pub const SPECIAL_NAME: Self = Self(0x0200);

    /// Runtime provides special behavior based on the event name.
    ///
    /// The Common Language Infrastructure provides special behavior for this event,
    /// depending upon the name of the event. This flag indicates that the runtime
    /// will recognize and handle this event in a special way.
    pub const RTSPECIAL_NAME: Self = Self(0x0400);
}

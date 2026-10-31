//! Raw Event table representation.
//!
//! This module provides the [`crate::metadata::tables::event::raw::EventRaw`] struct
//! for low-level access to Event metadata table data with unresolved heap indexes and coded indices.
//! This represents the binary format of event records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # Event Table Format
//!
//! The Event table (0x14) contains event definitions with these fields:
//! - **`EventFlags`** (2 bytes): Event attributes bitmask
//! - **Name** (2/4 bytes): String heap index for event name
//! - **`EventType`** (2/4 bytes): `TypeDefOrRef` coded index for event handler type
//!
//! Events define notification mechanisms that types can expose. They are associated
//! with accessor methods (add/remove/raise/other) through the `MethodSemantics` table.
//!
//! # Reference
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, Event, EventAttributes, EventRc, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    utils::RowList,
    Result,
};

#[derive(Clone, Debug)]
/// Raw Event table row with unresolved indexes and coded indices
///
/// Represents the binary format of an Event metadata table entry (table ID 0x14) as stored
/// in the metadata tables stream. All string references and type references are stored as
/// indexes that must be resolved using the appropriate heaps and type registry.
///
/// Events define notification mechanisms that allow objects to communicate state changes
/// to interested observers. Each event has a name, flags, and an associated delegate type
/// that defines the signature for event handlers.
///
/// # Reference
/// - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification
pub struct EventRaw {
    /// Row identifier within the Event metadata table
    ///
    /// The 1-based index of this event row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this event row
    ///
    /// Combines the table identifier (0x14 for Event) with the row ID to create
    /// a unique token. Format: `0x14000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw event data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Event flags bitmask (unresolved)
    ///
    /// 2-byte bitmask using [`crate::metadata::tables::event::EventAttributes`] constants.
    /// Controls special naming and runtime behavior for the event.
    /// See [ECMA-335 II.23.1.4] for flag definitions.
    pub flags: u32,

    /// Event name string heap index (unresolved)
    ///
    /// Index into the String heap containing the event name. Must be resolved
    /// using the String heap to obtain the actual event name string.
    pub name: u32,

    /// Event handler type coded index (unresolved)
    ///
    /// `TypeDefOrRef` coded index referencing the delegate type that defines the
    /// event handler signature. Can point to `TypeDef`, `TypeRef`, or `TypeSpec` tables.
    /// Must be resolved using the type registry to obtain the actual type reference.
    pub event_type: CodedIndex,
}

impl EventRaw {
    /// Convert to owned Event with resolved references and owned data
    ///
    /// This method converts the raw event into a fully resolved [`Event`] structure
    /// with owned data and resolved references. The resulting structure provides
    /// immediate access to event information without requiring additional heap
    /// lookups or type resolution.
    ///
    /// # Arguments
    ///
    /// * `strings` - The String heap for resolving event name
    /// * `types` - The type registry for resolving event handler type references
    ///
    /// # Returns
    ///
    /// Returns [`EventRc`] (Arc-wrapped [`Event`]) on success, providing shared ownership
    /// of the resolved event data.
    ///
    /// # Errors
    ///
    /// - The string heap lookup fails for the event name
    /// - The type registry lookup fails for the event handler type
    /// - The event type coded index cannot be resolved to a valid type
    pub fn to_owned(&self, strings: &Strings, types: &TypeRegistry) -> Result<EventRc> {
        Ok(Arc::new(Event {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: EventAttributes::new(self.flags),
            name: strings.get(self.name as usize)?.to_string(),
            event_type: match types.get(&self.event_type.token) {
                Some(parent) => parent.into(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve event type token - {}",
                        self.event_type.token.value()
                    ))
                }
            },
            fn_on_add: OnceLock::new(),
            fn_on_other: RowList::new(),
            fn_on_raise: OnceLock::new(),
            fn_on_remove: OnceLock::new(),
            custom_attributes: Default::default(),
        }))
    }

    /// Apply this event entry during metadata loading
    ///
    /// Processes the raw event entry and handles any cross-table relationships or
    /// metadata updates required during the loading phase. Events themselves don't
    /// directly modify other metadata tables, but this method provides a consistent
    /// interface for the loading framework.
    ///
    /// # Implementation Details
    ///
    /// Events define notification interfaces but don't create direct relationships
    /// with other metadata during initial loading. Event accessor methods (add/remove/raise/other)
    /// are resolved separately through the `MethodSemantics` table processing, which occurs
    /// after basic table loading is complete.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())` since events don't perform cross-table modifications
    /// during the initial loading phase.
    ///
    /// # Errors
    /// This function never returns an error.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for EventRaw {
    /// Calculate the byte size of an Event table row
    ///
    /// Computes the total size based on fixed-size fields plus variable-size heap and coded indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.13)
    /// - `flags`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (string heap index)
    /// - `event_type`: 2 or 4 bytes (`TypeDefOrRef` coded index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for heap and coded index widths
    ///
    /// # Returns
    /// Total byte size of one Event table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */      2u8
            /* name */       .saturating_add(sizes.str_bytes())
            /* event_type */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef))

        )
    }
}

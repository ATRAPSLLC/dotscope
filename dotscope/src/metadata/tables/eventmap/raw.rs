//! Raw `EventMap` table representation.
//!
//! This module provides the [`crate::metadata::tables::eventmap::raw::EventMapRaw`] struct
//! for low-level access to `EventMap` metadata table data with unresolved indexes and table references.
//! This represents the binary format of `EventMap` records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # `EventMap` Table Format
//!
//! The `EventMap` table (0x12) establishes ownership relationships between types and events
//! with these fields:
//! - **`Parent`** (2/4 bytes): `TypeDef` table index for the type that owns the events
//! - **`EventList`** (2/4 bytes): `Event` table index pointing to the first owned event
//!
//! `EventMap` entries define contiguous ranges of events owned by specific types. The range
//! for type N extends from `EventList\[N\]` to `EventList\[N+1\]`-1, enabling efficient enumeration
//! of all events belonging to a particular type.
//!
//! # Sorted Table Structure
//!
//! `EventMap` tables are sorted by Parent token for efficient binary search lookup.
//! This enables O(log n) lookup of events by owning type and efficient range-based
//! iteration through all events owned by a specific type.
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{
            EventList, EventMap, EventMapEntry, EventMapEntryRc, EventPtrMap, MemberRanges,
            TableId, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `EventMap` table row with unresolved indexes and table references
///
/// Represents the binary format of an `EventMap` metadata table entry (table ID 0x12) as stored
/// in the metadata tables stream. All type and event references are stored as table indexes
/// that must be resolved using the appropriate tables and registries.
///
/// `EventMap` entries establish ownership relationships between types and their events by
/// defining contiguous ranges in the Event table. This enables efficient enumeration
/// of all events declared by a particular type.
///
/// # Range Resolution
///
/// `EventMap` entries define event ranges implicitly:
/// - Events from `EventList`\[i\] to `EventList`\[i+1\]-1 belong to Parent\[i\]
/// - The final entry's range extends to the end of the Event table
/// - Empty ranges are valid and indicate types with no events
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification
pub struct EventMapRaw {
    /// Row identifier within the `EventMap` metadata table
    ///
    /// The 1-based index of this `EventMap` row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this `EventMap` row
    ///
    /// Combines the table identifier (0x12 for `EventMap`) with the row ID to create
    /// a unique token. Format: `0x12000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `EventMap` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Parent type table index (unresolved)
    ///
    /// Index into the `TypeDef` table identifying the type that owns the events
    /// in this range. Must be resolved using the type registry to obtain the
    /// actual type reference.
    pub parent: u32,

    /// Event list starting index (unresolved)
    ///
    /// Index into the Event table pointing to the first event owned by the parent
    /// type. The range extends to the next `EventMap` entry's `event_list` value (or
    /// end of Event table for the final entry).
    pub event_list: u32,
}

impl EventMapRaw {
    /// Resolve event list range and build the event vector
    ///
    /// This helper method resolves the contiguous range of events owned by the parent
    /// type and builds a thread-safe collection of resolved event references. The range
    /// is determined by this entry's `event_list` index and the next entry's `event_list`
    /// index (or end of Event table).
    ///
    /// # Range Calculation
    ///
    /// - **Start**: `self.event_list` (inclusive)
    /// - **End**: Next `EventMap` entry's `event_list` (exclusive) or end of Event table
    /// - **Normalization**: `ranges` holds the runs of the whole table, clamped to the Event
    ///   table and made non-overlapping (see [`MemberRanges`]), so a hostile column cannot make
    ///   a run longer than the table or two maps share events
    /// - **`EventPtr` Indirection**: Positions go through `event_ptr` when `ranges` says the
    ///   `EventPtr` table has rows
    ///
    /// # Arguments
    ///
    /// * `events` - Event table for resolving event references
    /// * `event_ptr` - `EventPtr` table for indirection resolution (if present)
    /// * `ranges` - The normalized `EventList` runs of the whole `EventMap` table
    ///   ([`TablesHeader::member_ranges`](crate::metadata::streams::TablesHeader::member_ranges)
    ///   with [`MemberList::EventMapEvents`](crate::metadata::tables::MemberList::EventMapEvents))
    ///
    /// # Returns
    ///
    /// Returns a thread-safe collection of resolved events in the specified range.
    ///
    /// # Errors
    ///
    /// - A position in the run names an `EventPtr` row that is not loaded
    /// - A position (or its `EventPtr` entry) names an event that is not loaded
    fn resolve_event_list(
        &self,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        ranges: &MemberRanges,
    ) -> Result<EventList> {
        let event_list = EventList::new();
        for event in ranges.members(self.rid, event_ptr, |ptr| ptr.event, events) {
            _ = event_list.push(event?);
        }
        Ok(event_list)
    }

    /// Convert to owned `EventMapEntry` with resolved references and owned data
    ///
    /// This method converts the raw `EventMap` entry into a fully resolved [`EventMapEntry`]
    /// structure with owned data and resolved cross-references. The resulting structure
    /// provides immediate access to the parent type and owned events without requiring
    /// additional table lookups.
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry for resolving the parent type reference
    /// * `events` - The Event table for resolving event references in the range
    /// * `event_ptr` - The `EventPtr` table for indirection resolution (if present)
    /// * `ranges` - The normalized `EventList` runs of the whole `EventMap` table (see
    ///   [`MemberRanges`])
    ///
    /// # Returns
    ///
    /// Returns [`EventMapEntryRc`] (Arc-wrapped [`EventMapEntry`]) on success, providing
    /// shared ownership of the resolved `EventMap` data.
    ///
    /// # Errors
    ///
    /// - The parent type lookup fails in the type registry
    /// - Event range resolution fails due to invalid boundaries
    /// - Event lookup fails for any event in the resolved range
    /// - `EventPtr` indirection resolution fails
    pub fn to_owned(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        ranges: &MemberRanges,
    ) -> Result<EventMapEntryRc> {
        let parent = match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(parent_type) => parent_type.into(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve parent type - {}",
                    self.parent | 0x0200_0000
                ))
            }
        };

        Ok(Arc::new(EventMapEntry {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent,
            events: self.resolve_event_list(events, event_ptr, ranges)?,
        }))
    }

    /// Apply this `EventMap` entry during metadata loading
    ///
    /// Processes the raw `EventMap` entry and establishes the ownership relationship
    /// between the parent type and its events. This method resolves the event range,
    /// looks up all events in that range, and adds them to the parent type's event
    /// collection.
    ///
    /// # Arguments
    ///
    /// * `types` - The type registry containing all parsed `TypeDef` entries
    /// * `events` - The Event table containing all parsed Event entries
    /// * `event_ptr` - The `EventPtr` table for indirection resolution (if present)
    /// * `ranges` - The normalized `EventList` runs of the whole `EventMap` table (see
    ///   [`MemberRanges`])
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful event assignment, or an error if:
    /// - Event list resolution fails due to invalid range boundaries
    /// - Event list validation fails (inconsistent with table state)
    /// - Parent type lookup fails in the type registry
    /// - Event assignment to parent type fails
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the event list is invalid, parent type lookup
    /// fails, or event assignment encounters metadata inconsistencies.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        events: &EventMap,
        event_ptr: &EventPtrMap,
        ranges: &MemberRanges,
    ) -> Result<()> {
        let event_list = self.resolve_event_list(events, event_ptr, ranges)?;

        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(event_parent) => {
                for (_, entry) in event_list.iter() {
                    _ = event_parent.events.push(entry.clone());
                }
                Ok(())
            }
            None => Err(malformed_error!(
                "Invalid parent token - {}",
                self.parent | 0x0200_0000
            )),
        }
    }
}

impl TableRow for EventMapRaw {
    /// Calculate the byte size of an EventMap table row
    ///
    /// Computes the total size based on variable-size table indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.12)
    /// - `parent`: 2 or 4 bytes (TypeDef table index)
    /// - `event_list`: 2 or 4 bytes (Event table index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one EventMap table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */     sizes.table_index_bytes(TableId::TypeDef)
            /* event_list */ .saturating_add(sizes.table_index_bytes(TableId::Event))

        )
    }
}

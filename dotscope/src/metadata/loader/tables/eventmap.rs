//! `EventMap` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::EventMapLoader`]
//! for loading `EventMap` metadata table entries during the metadata parsing process.
//! `EventMap` tables associate types with their owned events, enabling efficient enumeration
//! of events defined by a particular type, integrating this data with existing metadata entries.
//!
//! # Dependencies
//!
//! Loading requires these tables to be processed first:
//! - [`Event`](crate::metadata::tables::Event) - Event definitions  
//! - [`EventPtr`](crate::metadata::tables::EventPtr) - Event pointer indirection (if present)
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventMap` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{EventMapRaw, MemberList},
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Metadata loader for `EventMap` table entries
///
/// Handles the loading and processing of `EventMap` metadata table entries during metadata
/// parsing. `EventMap` tables define ownership relationships between types and events,
/// allowing efficient discovery of all events declared by a particular type.
pub struct EventMapLoader;

impl MetadataLoader for EventMapLoader {
    /// Load and process `EventMap` metadata table entries
    ///
    /// Processes all `EventMap` table entries, converting them from raw format to owned
    /// data structures with resolved cross-references. Each entry establishes the
    /// relationship between a type and the range of events it owns.
    ///
    /// # Arguments
    ///
    /// * `context` - The metadata loading context containing:
    ///   - `meta` - Metadata headers and table access
    ///   - `types` - Type registry for type resolution
    ///   - `event` - `Event` table for event resolution
    ///   - `event_ptr` - `EventPtr` table for indirection resolution
    ///   - `event_map` - Target collection for processed entries
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing of all entries, or an error if:
    /// - Raw entry conversion fails
    /// - Cross-reference resolution fails  
    /// - Entry registration fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<EventMapRaw>() else {
            return Ok(());
        };
        let ranges = context.member_ranges(header, MemberList::EventMapEvents);

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("event map 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(context.types, &context.event, &context.event_ptr, &ranges),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Table, token_msg)?;
                context.event_map.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for `EventMap` table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::EventMap`] (0x12) identifying this as the `EventMap` table loader.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::EventMap)
    }

    /// Returns the table dependencies required before loading `EventMap` entries
    ///
    /// `EventMap` loading requires `Event` and `EventPtr` tables to be loaded first to
    /// resolve cross-references correctly.
    ///
    /// # Returns
    ///
    /// Returns a slice containing:
    /// - [`TableId::Event`] - Required for event reference resolution
    /// - [`TableId::EventPtr`] - Required for event pointer indirection (if present)
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Event, TableId::EventPtr]
    }
}

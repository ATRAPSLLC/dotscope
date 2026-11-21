//! `EventPtr` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::EventPtrLoader`]
//! for loading `EventPtr` metadata table entries during the metadata parsing process.
//! `EventPtr` tables provide a level of indirection for event references when edit-and-continue
//! scenarios require non-contiguous event ordering in the Event table, integrating this
//! data with existing metadata entries.
//!
//! # Edit-and-Continue Support
//!
//! `EventPtr` tables are typically present only in assemblies that have undergone
//! edit-and-continue operations, where the original event ordering may have been
//! disrupted. The indirection provided by this table allows maintaining logical
//! event ordering while accommodating physical table modifications.
//!
//! # Dependencies
//!
//! `EventPtr` loading has no dependencies and can be processed early in the loading
//! sequence. Other tables (like `EventMap`) may depend on `EventPtr` for event resolution.
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EventPtr` table specification

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{EventPtrRaw, TableId},
    },
    Result,
};

/// Metadata loader for `EventPtr` table entries
///
/// Handles the loading and processing of `EventPtr` metadata table entries during metadata
/// parsing. `EventPtr` tables provide indirection for event references, primarily used
/// in edit-and-continue scenarios where the original event table ordering has been
/// modified.
pub struct EventPtrLoader;

impl MetadataLoader for EventPtrLoader {
    /// Load and process `EventPtr` metadata table entries
    ///
    /// Processes all `EventPtr` table entries, converting them from raw format to owned
    /// data structures with resolved references. Each entry establishes an indirection
    /// mapping that points to the actual event in the Event table.
    ///
    /// # Arguments
    ///
    /// * `context` - The metadata loading context containing:
    ///   - `meta` - Metadata headers and table access
    ///   - `event_ptr` - Target collection for processed entries
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing of all entries, or an error if:
    /// - Raw entry conversion fails
    /// - Entry registration fails
    ///
    /// # Edit-and-Continue Context
    ///
    /// `EventPtr` tables are typically only present in assemblies that have been
    /// modified through edit-and-continue operations. When present, they provide
    /// the necessary indirection to maintain logical event ordering.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<EventPtrRaw>() else {
            return Ok(());
        };

        for (index, row) in table.into_iter().enumerate() {
            let Some(row) = context.handle_row(row, index)? else {
                continue;
            };
            let token_msg = || format!("event ptr 0x{:08x}", row.token.value());

            let Some(owned) =
                context.handle_result(row.to_owned(), DiagnosticCategory::Table, token_msg)?
            else {
                continue;
            };

            context.event_ptr.insert(row.token, owned);
        }
        Ok(())
    }

    /// Returns the table identifier for `EventPtr` table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::EventPtr`] (0x13) identifying this as the `EventPtr` table loader.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::EventPtr)
    }

    /// Returns the table dependencies required before loading `EventPtr` entries
    ///
    /// `EventPtr` loading has no dependencies and can be processed early in the
    /// loading sequence. Other tables may depend on `EventPtr` for event indirection.
    ///
    /// # Returns
    ///
    /// Returns an empty slice, indicating no dependencies are required.
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

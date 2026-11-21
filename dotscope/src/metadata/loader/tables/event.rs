//! Event table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::EventLoader`]
//! implementation for loading event metadata from the ECMA-335 Event table (0x14).
//! The loader processes event definitions that represent .NET events, which are a special
//! kind of property used for notifications and the observer pattern in object-oriented programming,
//! integrating this data with existing metadata entries.
//!
//! # Table Structure
//!
//! The Event table contains event definitions with these fields:
//! - **`EventFlags`**: Attributes controlling event behavior (specialname, `RTSpecialName`)
//! - **Name**: Event name (string heap reference)
//! - **`EventType`**: Type of the event (`TypeDef`, `TypeRef`, or `TypeSpec` coded index)
//!
//! Events are associated with methods through the `MethodSemantics` table, which defines
//! the add, remove, and optionally raise accessor methods for each event.
//!
//! # Event Characteristics
//!
//! .NET events have these key properties:
//! - **Type Safety**: Event type is verified at compile time
//! - **Multicast Support**: Events can have multiple subscribers
//! - **Accessor Methods**: Standard add/remove pattern with optional custom methods
//! - **Metadata Integration**: Full reflection and debugging support
//!
//! # Reference
//! - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::EventRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the Event metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the Event table (0x14)
/// which contains event definitions for .NET types. Events represent notification mechanisms
/// that allow objects to communicate state changes or important occurrences to interested
/// observers.
pub struct EventLoader;

impl MetadataLoader for EventLoader {
    /// Load and process all rows from the Event metadata table
    ///
    /// This method loads event definitions from the Event table (0x14) and converts them
    /// to owned representations with resolved heap references. Events are processed in
    /// parallel for improved performance since they don't have complex interdependencies.
    ///
    /// # Arguments
    ///
    /// * `context` - The loader context containing metadata tables and storage collections
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful loading of all events, or an error if any event
    /// row cannot be processed or stored.
    ///
    /// # Errors
    ///
    /// - Returns [`crate::Error`] if heap lookups fail for event names or types
    /// - Returns [`crate::Error`] if event type coded indices cannot be resolved
    /// - Returns [`crate::Error`] if context storage operations fail
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<EventRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("event 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(strings, context.types),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.event.insert(row.token, owned.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for the Event table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::Event`] (0x14) indicating this loader processes the Event table.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Event)
    }

    /// Returns the table dependencies required before loading events
    ///
    /// Events depend on type system tables for resolving event handler types through
    /// coded indices. The `EventType` field can reference `TypeDef`, `TypeRef`, or `TypeSpec`
    /// tables, so all must be processed before event loading.
    ///
    /// # Returns
    ///
    /// Returns a slice containing the table dependencies:
    /// - [`TableId::TypeDef`]: For locally defined event handler types
    /// - [`TableId::TypeRef`]: For external event handler type references  
    /// - [`TableId::TypeSpec`]: For generic or complex event handler types
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
    }
}

//! `EncLog` table loader implementation
//!
//! Provides the [`crate::metadata::loader::tables::EncLogLoader`] implementation for loading Edit-and-Continue log entries
//! from the ECMA-335 `EncLog` table (0x1E). This loader processes debugging metadata that tracks
//! modifications made during Edit-and-Continue debugging sessions.
//!
//! # Table Structure
//!
//! The `EncLog` table contains Edit-and-Continue operation tracking information:
//! - **Token**: Metadata token identifying the affected element
//! - **`FuncCode`**: Operation code (create=0, update=1, delete=2)
//!
//! # Usage Context
//!
//! This table is only present in assemblies that have been modified during debugging
//! sessions using Edit-and-Continue functionality. It enables the runtime to understand
//! what metadata elements have been added, modified, or removed during debugging.
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{EncLogRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `EncLog` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `EncLog` table (0x1E)
/// which contains Edit-and-Continue log entries that track metadata modifications made during
/// debugging sessions. This table records all changes to help the runtime understand what
/// has been modified during active debugging.
pub struct EncLogLoader;

impl MetadataLoader for EncLogLoader {
    /// Load Edit-and-Continue log entries from the `EncLog` table
    ///
    /// Processes `EncLog` table rows (if present) and stores the Edit-and-Continue operation
    /// information in the loader context. The `EncLog` table is optional and only present
    /// in assemblies that have been modified during debugging sessions.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables and storage collections
    ///
    /// # Returns
    /// * `Ok(())` - `EncLog` entries successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or processing error
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<EncLogRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("enc log 0x{:08x}", row.token.value());

                let Some(owned) =
                    context.handle_result(row.to_owned(), DiagnosticCategory::Table, token_msg)?
                else {
                    return Ok(());
                };

                context.enc_log.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for the `EncLog` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::EncLog`] (0x1E)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::EncLog)
    }

    /// Returns the list of table dependencies
    ///
    /// The `EncLog` table has no dependencies on other metadata tables or heaps,
    /// as it contains only metadata tokens and operation codes.
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

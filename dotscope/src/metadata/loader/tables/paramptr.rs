//! # `ParamPtr` Table Loader
//!
//! This module provides loading functionality for the `ParamPtr` metadata table (ID 0x04).
//! The `ParamPtr` table is an indirection table used in optimized metadata to reference
//! parameter definitions when parameter table entries are reordered or compressed.
//!
//! ## Purpose
//!
//! The `ParamPtr` table serves as an indirection layer for parameter access:
//! - Maps logical parameter indexes to physical parameter table positions
//! - Enables metadata optimization by allowing parameter table compression
//! - Maintains parameter ordering independence from physical storage layout
//! - Supports efficient parameter lookup in optimized assemblies
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.26 - `ParamPtr` table specification
//! - [`crate::metadata::tables::ParamPtrRaw`] - Raw table entry structure
//! - [`crate::metadata::tables::ParamPtr`] - Owned table entry type
use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{ParamPtrRaw, TableId},
    },
    Result,
};

/// Loader for `ParamPtr` metadata table entries.
///
/// This loader handles the loading and processing of the `ParamPtr` table (0x04),
/// which provides indirection for parameter table access in optimized metadata.
/// It converts raw table entries to owned representations and stores them
/// for efficient lookup by metadata token.
pub struct ParamPtrLoader;

impl MetadataLoader for ParamPtrLoader {
    /// Loads all `ParamPtr` table entries from the metadata.
    ///
    /// This method processes the `ParamPtr` table if present in the metadata header,
    /// converting each raw entry to its owned representation and storing it in
    /// the loader context for subsequent access.
    ///
    /// ## Arguments
    ///
    /// * `context` - The loader context containing metadata and storage
    ///
    /// ## Returns
    ///
    /// * `Ok(())` - All entries loaded successfully
    /// * `Err(Error)` - Conversion or storage error occurred
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<ParamPtrRaw>() else {
            return Ok(());
        };

        for (index, row) in table.into_iter().enumerate() {
            let Some(row) = context.handle_row(row, index)? else {
                continue;
            };
            let token_msg = || format!("param ptr 0x{:08x}", row.token.value());

            let Some(owned) =
                context.handle_result(row.to_owned(), DiagnosticCategory::Table, token_msg)?
            else {
                continue;
            };

            context.param_ptr.insert(row.token, owned);
        }
        Ok(())
    }

    /// Returns the table identifier for the `ParamPtr` table.
    ///
    /// ## Returns
    ///
    /// * [`TableId::ParamPtr`] - The table identifier (0x04)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ParamPtr)
    }

    /// Returns the table dependencies for the `ParamPtr` table.
    ///
    /// The `ParamPtr` table has no dependencies on other tables as it provides
    /// indirection for parameter access rather than containing references.
    ///
    /// ## Returns
    ///
    /// * `&[]` - Empty slice indicating no dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

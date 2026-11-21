//! `FieldRva` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::FieldRvaLoader`] responsible for loading and processing
//! `FieldRva` metadata table entries. The `FieldRva` table specifies Relative Virtual Addresses
//! (RVAs) for fields that have initial data stored in the PE file image.
//!
//! # Purpose
//! The `FieldRva` table is used for fields with static initial data:
//! - **Static field initialization**: Initial values for static fields
//! - **Constant data**: Read-only data embedded in the PE file
//! - **Global variables**: Module-level data with specific initial values
//! - **Interop data**: Native data structures embedded in managed assemblies
//! - **Resource data**: Binary data referenced by field definitions
//!
//! # RVA Resolution
//! RVAs point to data within the PE file:
//! - **File offset calculation**: RVA + section base → file offset
//! - **Memory mapping**: RVA directly used when PE is memory-mapped
//! - **Data access**: Binary data reading from calculated positions
//! - **Size determination**: Field type determines data size
//!
//! # Table Dependencies
//! - **Field table**: Required for field reference resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the `FieldRva` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::FieldRvaRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `FieldRva` metadata table.
///
/// This loader processes `FieldRva` table entries which specify Relative Virtual Addresses
/// for fields that have initial data stored in the PE file. These RVAs point to binary
/// data that serves as initial values for static fields and constant data.
///
/// # Errors
/// - Field references cannot be resolved
/// - RVA values are invalid or out of bounds
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
/// - PE file structure is malformed
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for complete `FieldRva` table specification.
pub struct FieldRvaLoader;

impl MetadataLoader for FieldRvaLoader {
    /// Load and process all `FieldRva` table entries.
    ///
    /// This method iterates through the `FieldRva` table, resolving field references
    /// and processing RVA information for fields that have initial data stored in
    /// the PE file. Each entry associates a field with its data location.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables and collections
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Field reference resolution fails
    /// - Raw-to-owned conversion encounters issues
    /// - RVA application to fields fails
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<FieldRvaRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("field rva 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(context.field),
                    DiagnosticCategory::Field,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Field, token_msg)?;
                context.field_rva.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for the `FieldRva` table.
    ///
    /// # Returns
    /// Returns [`crate::prelude::TableId::FieldRVA`] indicating this loader handles the `FieldRva` table.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::FieldRVA)
    }

    /// Returns the table dependencies for `FieldRva` loading.
    ///
    /// The `FieldRva` table depends on the Field table since each RVA entry
    /// references a specific field and provides its data location information.
    ///
    /// # Returns
    /// Returns a slice containing [`crate::prelude::TableId::Field`] as the required dependency.
    ///
    /// # Dependency Chain
    /// - **Field**: Required for resolving field references in RVA entries
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field]
    }
}

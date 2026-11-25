//! `FieldLayout` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::FieldLayoutLoader`] responsible for loading and processing
//! `FieldLayout` metadata table entries. The `FieldLayout` table specifies explicit field
//! positioning within types, defining the byte offset of fields in classes and value types.
//!
//! # Purpose
//! The `FieldLayout` table is used when explicit field layout control is needed, such as:
//! - Interop scenarios requiring specific memory layouts
//! - Performance-critical structures with cache-line awareness  
//! - Platform-specific data structure alignment
//! - COM interop and P/Invoke marshalling
//!
//! # Table Dependencies
//! - **Field table**: Required for field reference resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.16 for the `FieldLayout` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::FieldLayoutRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `FieldLayout` metadata table.
///
/// This loader processes `FieldLayout` table entries which specify the explicit
/// byte offset of fields within their containing types. Field layout information
/// is essential for interop scenarios and performance-critical data structures
/// where precise memory layout control is required.
///
/// # Error Conditions
/// Loading may fail if:
/// - Field references cannot be resolved
/// - Invalid field offset values are encountered
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.16 for complete `FieldLayout` table specification.
pub struct FieldLayoutLoader;

impl MetadataLoader for FieldLayoutLoader {
    /// Load and process all `FieldLayout` table entries.
    ///
    /// This method iterates through the `FieldLayout` table, resolving field references
    /// and converting raw entries to owned structures. Each field layout entry specifies
    /// the explicit byte offset of a field within its containing type.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables and collections
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Field reference resolution fails
    /// - Raw-to-owned conversion encounters issues
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<FieldLayoutRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("field layout 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(context.field),
                    DiagnosticCategory::Field,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Field, token_msg)?;
                context.field_layout.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for the `FieldLayout` table.
    ///
    /// # Returns
    /// Returns [`crate::prelude::TableId::FieldLayout`] indicating this loader handles the `FieldLayout` table.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::FieldLayout)
    }

    /// Returns the table dependencies for `FieldLayout` loading.
    ///
    /// The `FieldLayout` table depends on the Field table since each layout entry
    /// references a specific field and specifies its byte offset within the containing type.
    ///
    /// # Returns
    /// Returns a slice containing [`crate::prelude::TableId::Field`] as the required dependency.
    ///
    /// # Dependency Chain
    /// - **Field**: Required for resolving field references in layout entries
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field]
    }
}

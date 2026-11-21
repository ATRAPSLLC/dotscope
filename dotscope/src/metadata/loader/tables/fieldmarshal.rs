//! `FieldMarshal` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::FieldMarshalLoader`] responsible for loading and processing
//! `FieldMarshal` metadata table entries. The `FieldMarshal` table specifies how fields and
//! parameters should be marshalled when crossing managed/unmanaged boundaries.
//!
//! # Purpose
//! The `FieldMarshal` table is essential for interop scenarios, defining:
//! - **P/Invoke marshalling**: How parameters are converted for native calls
//! - **COM interop**: Field and parameter marshalling for COM objects
//! - **Custom marshalling**: User-defined marshalling behavior
//! - **Array marshalling**: Specific handling for array types
//! - **String marshalling**: Character encoding and memory management
//!
//! # Table Dependencies
//! - **Field table**: Required for field marshalling information
//! - **Param table**: Required for parameter marshalling information
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.17 for the `FieldMarshal` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::FieldMarshalRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `FieldMarshal` metadata table.
///
/// This loader processes `FieldMarshal` table entries which specify marshalling
/// behavior for fields and parameters when crossing managed/unmanaged boundaries.
/// Marshalling information is critical for proper interop with native code and
/// COM components.
///
/// # Error Conditions
/// Loading may fail if:
/// - Coded index references cannot be resolved
/// - Blob signature parsing encounters invalid data
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
/// - Invalid marshalling specifications are encountered
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.17 for complete `FieldMarshal` table specification.
pub struct FieldMarshalLoader;

impl MetadataLoader for FieldMarshalLoader {
    /// Load and process all `FieldMarshal` table entries.
    ///
    /// This method iterates through the `FieldMarshal` table, resolving coded index references
    /// to fields or parameters and parsing marshalling information from blob signatures.
    /// Each entry specifies how a field or parameter should be marshalled during interop.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables, heaps, and collections
    ///
    /// # Coded Index Resolution
    /// The `HasFieldMarshal` coded index can reference:
    /// - **Field entries**: For field marshalling specifications
    /// - **Param entries**: For parameter marshalling specifications
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Coded index reference resolution fails
    /// - Blob signature parsing encounters invalid data
    /// - Raw-to-owned conversion encounters issues
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blob)) = (context.meta, context.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<FieldMarshalRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("field marshal 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), blob),
                    DiagnosticCategory::Field,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(res.apply(), DiagnosticCategory::Field, token_msg)?;
                context.field_marshal.insert(row.token, res);
                Ok(())
            })
    }

    /// Returns the table identifier for the `FieldMarshal` table.
    ///
    /// # Returns
    /// Returns [`crate::prelude::TableId::FieldMarshal`] indicating this loader handles the `FieldMarshal` table.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::FieldMarshal)
    }

    /// Returns the table dependencies for `FieldMarshal` loading.
    ///
    /// The `FieldMarshal` table depends on both Field and Param tables since marshal
    /// entries can reference either fields or parameters through the `HasFieldMarshal`
    /// coded index.
    ///
    /// # Returns
    /// Returns a slice containing [`crate::prelude::TableId::Field`] and [`crate::prelude::TableId::Param`] as required dependencies.
    ///
    /// # Dependency Chain
    /// - **Field**: Required for resolving field marshalling references
    /// - **Param**: Required for resolving parameter marshalling references
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field, TableId::Param]
    }
}

//! `FieldPtr` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::FieldPtrLoader`] responsible for loading and processing
//! `FieldPtr` metadata table entries. The `FieldPtr` table acts as an indirection mechanism
//! for the Field table when field ordering differs between logical and physical layout.
//!
//! # Purpose
//! The `FieldPtr` table is used in specific optimization scenarios:
//! - **Field reordering**: When physical field order differs from logical declaration order
//! - **Metadata optimization**: Reducing metadata size through indirection
//! - **Edit-and-continue**: Supporting field additions without breaking existing references
//! - **Incremental compilation**: Maintaining field references across compilation sessions
//!
//! # Table Usage
//! The `FieldPtr` table is optional and only present when field indirection is needed:
//! - **Without `FieldPtr`**: Direct indexing into Field table
//! - **With `FieldPtr`**: Indirect indexing through `FieldPtr` → Field
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.18 for the `FieldPtr` table specification.

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{FieldPtrRaw, TableId},
    },
    Result,
};

/// Loader implementation for the `FieldPtr` metadata table.
///
/// This loader processes `FieldPtr` table entries which provide indirection for field
/// references when the logical field order differs from the physical storage order.
/// The `FieldPtr` table is an optimization mechanism used in specific scenarios.
///
/// # Errors
/// - Raw-to-owned conversion encounters issues
/// - Collection insertion operations fail
/// - Memory allocation fails during processing
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.18 for complete `FieldPtr` table specification.
pub struct FieldPtrLoader;

impl MetadataLoader for FieldPtrLoader {
    /// Load and process all `FieldPtr` table entries.
    ///
    /// This method iterates through the `FieldPtr` table (if present) and converts
    /// each entry to an owned structure. `FieldPtr` entries provide indirection for
    /// field references when logical and physical field ordering differs.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables and collections
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - Raw-to-owned conversion encounters issues
    /// - Collection insertion operations fail
    /// - Memory allocation fails during processing
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<FieldPtrRaw>() else {
            return Ok(());
        };

        for (index, row) in table.into_iter().enumerate() {
            let Some(row) = context.handle_row(row, index)? else {
                continue;
            };
            let token_msg = || format!("field ptr 0x{:08x}", row.token.value());

            let Some(owned) =
                context.handle_result(row.to_owned(), DiagnosticCategory::Field, token_msg)?
            else {
                continue;
            };

            context.field_ptr.insert(row.token, owned);
        }
        Ok(())
    }

    /// Returns the table identifier for the `FieldPtr` table.
    ///
    /// # Returns
    /// Returns [`crate::metadata::tables::TableId::FieldPtr`] indicating this loader handles the `FieldPtr` table.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::FieldPtr)
    }

    /// Returns the table dependencies for `FieldPtr` loading.
    ///
    /// The `FieldPtr` table has no dependencies since it contains simple indirection
    /// pointers that don't require other tables to be loaded first. The actual
    /// field resolution happens later during the metadata resolution phase.
    ///
    /// # Returns
    /// Returns an empty slice indicating no dependencies are required.
    ///
    /// # Dependency Chain
    /// No dependencies required - `FieldPtr` is a simple indirection table.
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

//! Field metadata table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::FieldLoader`] for loading
//! Field metadata table entries during the metadata parsing process. Field tables define the
//! fields (instance variables, static variables, constants) that belong to types, providing
//! the data storage structure for .NET type definitions.
//!
//! # Field Characteristics
//!
//! Field entries define various types of data members:
//! - **Instance Fields**: Per-instance data storage with specific types
//! - **Static Fields**: Shared data storage across all instances of a type
//! - **Constants**: Compile-time constant values embedded in metadata
//! - **Literal Fields**: Named constants with specific values and types
//!
//! # Dependencies
//!
//! Field loading has no table dependencies but requires heap access:
//! - **String Heap**: Required for field name resolution
//! - **Blob Heap**: Required for field signature parsing and type information
//!
//! # Reference
//! - [ECMA-335 II.22.15](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::FieldRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Metadata loader for Field table entries
///
/// Handles the loading and processing of Field metadata table entries during metadata
/// parsing. Field tables define the data members of types including instance fields,
/// static fields, constants, and literals that provide the storage structure for
/// .NET type definitions.
pub struct FieldLoader;

impl MetadataLoader for FieldLoader {
    /// Load and process Field metadata table entries
    ///
    /// Processes all Field table entries, converting them from raw format to owned
    /// data structures with resolved heap references. Each entry defines a field
    /// (data member) that belongs to a type, including instance fields, static fields,
    /// constants, and literals.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing of all entries, or an error if:
    /// - Raw entry conversion fails
    /// - Heap reference resolution fails
    /// - Field signature parsing fails
    /// - Entry registration fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<FieldRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("field 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(blob, strings),
                    DiagnosticCategory::Field,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.field.insert(row.token, res.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for Field table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::Field`] (0x04) identifying this as the Field table loader.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Field)
    }

    /// Returns the table dependencies required before loading Field entries
    ///
    /// Field loading has no table dependencies since fields are fundamental building
    /// blocks that don't reference other metadata tables directly. However, field
    /// loading requires String and Blob heap access for name and signature resolution.
    ///
    /// # Returns
    ///
    /// Returns an empty slice, indicating no table dependencies are required.
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

//! # `NestedClass` Table Loader
//!
//! This module provides the loader implementation for the [`NestedClass`](crate::metadata::tables::NestedClass) table,
//! which defines nested type relationships between enclosing and nested types.
//! `NestedClass` entries establish the hierarchical structure of nested types in .NET assemblies.
//!
//! ## Purpose
//!
//! The [`NestedClassLoader`] processes [`crate::metadata::tables::NestedClassRaw`] entries during metadata loading,
//! converting them to owned [`NestedClass`](crate::metadata::tables::NestedClass) instances with resolved type references.
//! These entries define which types are nested within other types, enabling proper
//! type hierarchy resolution and visibility scoping.
//!
//! ## Table Dependencies
//!
//! The `NestedClass` table depends on type definition and reference tables:
//! - [`crate::metadata::tables::TableId::TypeDef`] - For locally defined types
//! - [`crate::metadata::tables::TableId::TypeRef`] - For external type references
//! - [`crate::metadata::tables::TableId::TypeSpec`] - For constructed type specifications
//!
//! These dependencies ensure that type references can be properly resolved during loading.
//!
//! ## Error Conditions
//!
//! - Type references cannot be resolved or are invalid
//! - `NestedClass` table contains malformed or corrupted data
//! - Circular nesting relationships are detected
//! - Token conflicts occur during storage
//!
use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::NestedClassRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `NestedClass` metadata table.
///
/// This loader processes [`crate::metadata::tables::NestedClassRaw`] entries, converting them to
/// owned [`crate::metadata::tables::NestedClass`] instances with resolved type references.
/// `NestedClass` entries define the hierarchical relationships between enclosing and nested types,
/// establishing proper type visibility and scoping rules.
pub struct NestedClassLoader;

impl MetadataLoader for NestedClassLoader {
    /// Loads and processes all `NestedClass` table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - Type references cannot be resolved or are invalid
    /// - `NestedClass` table contains malformed or corrupted data
    /// - Circular nesting relationships are detected during processing
    /// - Storage operations fail due to token conflicts
    ///
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<NestedClassRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| -> Result<()> {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("nested class 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(context.types),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Type, token_msg)?;
                context.nested_class.insert(row.token, owned);
                Ok(())
            })?;

        // Rebuild the fullname index now that enclosing type relationships are established.
        // `set_enclosing_type()` invalidates the cached fullname on each nested type, so
        // the next `fullname()` call will include the parent prefix (e.g. `Outer/Inner`).
        // The `types_by_fullname` index was populated at insert time with the old (bare)
        // names and must be rebuilt to reflect the correct hierarchical names.
        context.types.build_fullnames();

        Ok(())
    }

    /// Returns the table identifier for `NestedClass`.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::NestedClass`] (0x29)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::NestedClass)
    }

    /// Returns the table dependencies for `NestedClass` loading.
    ///
    /// The `NestedClass` table depends only on type definitions to resolve
    /// nested and enclosing type relationships. The table contains raw indices
    /// into the `TypeDef` table only, not `TypeDefOrRef` coded indices.
    ///
    /// ## Dependencies
    /// - [`crate::metadata::tables::TableId::TypeDef`] - Local type definitions
    ///
    /// ## Returns
    /// Array of table IDs that must be loaded before `NestedClass` processing
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef]
    }
}

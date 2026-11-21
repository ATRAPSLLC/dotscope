//! `ExportedType` metadata table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::ExportedTypeLoader`]
//! for loading `ExportedType` metadata table entries during the metadata parsing process.
//! `ExportedType` tables define types that are exported from assemblies for visibility to
//! other assemblies, enabling cross-assembly type access and assembly composition scenarios.
//!
//! # Type Export Scenarios
//!
//! `ExportedType` entries support several assembly composition patterns:
//! - **Public Type Export**: Making internal types available to other assemblies
//! - **Type Forwarding**: Redirecting type references during assembly refactoring
//! - **Multi-Module Assemblies**: Exposing types from different assembly files
//! - **Assembly Facades**: Creating simplified public interfaces over complex implementations
//!
//! # Dependencies
//!
//! Loading requires these tables to be processed first:
//! - [`crate::metadata::tables::File`] - File definitions for multi-module assemblies
//! - [`crate::metadata::tables::AssemblyRef`] - Assembly references for type forwarding
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::ExportedTypeRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Metadata loader for `ExportedType` table entries
///
/// Handles the loading and processing of `ExportedType` metadata table entries during metadata
/// parsing. `ExportedType` tables define the public interface of assemblies by specifying
/// which types are exported for visibility to other assemblies.
pub struct ExportedTypeLoader;

impl MetadataLoader for ExportedTypeLoader {
    /// Load and process `ExportedType` metadata table entries
    ///
    /// Processes all `ExportedType` table entries, converting them from raw format to owned
    /// data structures with resolved cross-references and string heap lookups. Each entry
    /// defines a type that is exported from this assembly for access by other assemblies.
    ///
    /// # Arguments
    ///
    /// * `context` - The metadata loading context containing:
    ///   - `meta` - Metadata headers and table access
    ///   - `strings` - String heap for name resolution
    ///   - `get_ref` - Function for resolving coded index references
    ///   - `exported_type` - Target collection for processed entries
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful processing of all entries, or an error if:
    /// - Raw entry conversion fails
    /// - Cross-reference resolution fails
    /// - String heap lookup fails
    /// - Entry registration fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<ExportedTypeRaw>() else {
            return Ok(());
        };

        // First pass: create exported type entries
        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| -> Result<()> {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("exported type 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), strings, true),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_result(
                    context.exported_type.insert(row.token, owned.clone()),
                    DiagnosticCategory::Type,
                    token_msg,
                )?;
                Ok(())
            })?;

        // Second pass: resolve implementations
        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("exported type impl 0x{:08x}", row.token.value());

                if let Some(implementation) =
                    row.resolve_implementation(|coded_index| context.get_ref(coded_index))
                {
                    if let Some(exported_type_entry) = context.exported_type.get(&row.token) {
                        let exported_type = exported_type_entry.value();
                        context.handle_error(
                            exported_type.set_implementation(implementation),
                            DiagnosticCategory::Type,
                            token_msg,
                        )?;
                    }
                }
                Ok(())
            })
    }

    /// Returns the table identifier for `ExportedType` table
    ///
    /// # Returns
    ///
    /// Returns [`TableId::ExportedType`] (0x27) identifying this as the `ExportedType` table loader.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ExportedType)
    }

    /// Returns the table dependencies required before loading `ExportedType` entries
    ///
    /// `ExportedType` loading requires File and `AssemblyRef` tables to be loaded first
    /// to resolve Implementation coded index references correctly.
    ///
    /// # Returns
    ///
    /// Returns a slice containing:
    /// - [`TableId::File`] - Required for multi-module assembly file resolution
    /// - [`TableId::AssemblyRef`] - Required for type forwarding assembly resolution
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::File, TableId::AssemblyRef]
    }
}

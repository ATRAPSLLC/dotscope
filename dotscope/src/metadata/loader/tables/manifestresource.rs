//! `ManifestResource` table loader implementation.
//!
//! This module provides the [`ManifestResourceLoader`] responsible for loading and processing
//! `ManifestResource` metadata table entries. The `ManifestResource` table defines resources
//! embedded in or linked to .NET assemblies, enabling access to binary data, strings,
//! and other non-code assets.
//!
//! # Purpose
//! The `ManifestResource` table is essential for resource management in .NET applications:
//! - **Embedded resources**: Binary data compiled directly into assembly files
//! - **Linked resources**: External files referenced by the assembly
//! - **Satellite assemblies**: Localized resources in separate assembly files
//! - **Resource access**: Runtime resource discovery and loading mechanisms
//! - **Globalization**: Culture-specific resource organization and fallback chains
//!
//! # Resource Types and Location
//! `ManifestResource` entries support different resource storage models:
//! - **Embedded**: Resources stored directly in the current assembly's PE file
//! - **File-based**: Resources stored in separate files referenced by `File` table
//! - **Assembly-based**: Resources located in external assemblies via `AssemblyRef`
//! - **Streaming**: Large resources accessed through streaming interfaces
//!
//! # Table Dependencies
//! - **`File`**: Required for resolving file-based resource references
//! - **`AssemblyRef`**: Required for resolving external assembly resource references
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.24 for the `ManifestResource` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::ManifestResourceRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `ManifestResource` metadata table.
///
/// This loader processes resource metadata, establishing resource location references
/// and enabling runtime resource access. It resolves implementation references, converts
/// raw table entries to owned structures, and maintains the resource collection.
pub struct ManifestResourceLoader;

impl MetadataLoader for ManifestResourceLoader {
    /// Loads `ManifestResource` table entries and establishes resource access mechanisms.
    ///
    /// This method iterates through all `ManifestResource` table entries, resolving implementation
    /// references for resource location and creating resource data access mechanisms. Each entry
    /// is converted to an owned structure for runtime resource operations.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables, strings, and file access
    ///
    /// # Returns
    /// * `Ok(())` - If all `ManifestResource` entries were processed successfully
    /// * `Err(_)` - If reference resolution or resource access setup fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<ManifestResourceRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("manifest resource 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        &context.input,
                        context.header,
                        strings,
                        table,
                    ),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.resources.insert(owned.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for `ManifestResource`.
    ///
    /// # Returns
    /// The [`TableId::ManifestResource`] identifier for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ManifestResource)
    }

    /// Returns the dependencies required for loading `ManifestResource` entries.
    ///
    /// `ManifestResource` table loading requires other tables to resolve implementation references:
    /// - [`TableId::File`] - For file-based resource references to external files
    /// - [`TableId::AssemblyRef`] - For assembly-based resource references to external assemblies
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `ManifestResource` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::File, TableId::AssemblyRef]
    }
}

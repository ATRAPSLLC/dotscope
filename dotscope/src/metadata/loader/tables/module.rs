//! # Module Table Loader
//!
//! This module provides the loader implementation for the [`Module`](crate::metadata::tables::Module) table,
//! which contains information about the current module including its name, GUID (Mvid), and generation.
//! The Module table always contains exactly one row per PE file, representing the module identity.
//!
//! ## Purpose
//!
//! The [`ModuleLoader`] processes the single [`crate::metadata::tables::ModuleRaw`] entry during metadata loading,
//! converting it to an owned [`crate::metadata::tables::Module`] instance with resolved strings and GUIDs.
//! The module entry serves as the fundamental identity for the current assembly.
//!
//! ## Table Dependencies
//!
//! The Module table has no dependencies and is one of the first tables loaded:
//! - No external table references
//! - Only depends on metadata heaps (strings, GUIDs)
//! - Serves as foundation for other table loading
//!
//! ## Error Conditions
//!
//! - No Module table is present in the metadata
//! - String heap entries are malformed or missing
//! - GUID heap entries are malformed or missing
//! - Module has already been set (duplicate loading)

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{ModuleRaw, TableId},
    },
    Result,
};

/// Loader implementation for the Module metadata table.
///
/// This loader processes the single [`crate::metadata::tables::ModuleRaw`] entry, converting it to
/// an owned [`crate::metadata::tables::Module`] instance with resolved strings and GUIDs.
/// The Module table always contains exactly one row that provides identity information
/// for the current assembly module.
pub struct ModuleLoader;

impl MetadataLoader for ModuleLoader {
    /// Loads and processes the single Module table entry.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Returns
    /// * `Ok(())` - Module successfully loaded, or skipped in lenient mode
    /// * `Err(`[`crate::Error`]`)` - Malformed data in strict mode, or duplicate module
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(tables_header), Some(strings), Some(guids)) =
            (context.meta, context.strings, context.guids)
        else {
            return context.handle_error(
                Err(malformed_error!(
                    "Module table requires metadata tables, string heap, and GUID heap"
                )),
                DiagnosticCategory::Table,
                || "module".to_string(),
            );
        };
        let Some(table) = tables_header.table::<ModuleRaw>() else {
            return context.handle_error(
                Err(malformed_error!("Module table is required but not present")),
                DiagnosticCategory::Table,
                || "module".to_string(),
            );
        };
        let Some(row) = table.get(1)? else {
            return context.handle_error(
                Err(malformed_error!(
                    "Module table is present but contains no rows"
                )),
                DiagnosticCategory::Table,
                || "module".to_string(),
            );
        };

        let token_msg = || format!("module 0x{:08x}", row.token.value());

        let Some(owned) = context.handle_result(
            row.to_owned(strings, guids),
            DiagnosticCategory::Table,
            token_msg,
        )?
        else {
            return Ok(());
        };

        context.handle_error(
            context
                .module
                .set(owned)
                .map_err(|_| malformed_error!("Module has already been set")),
            DiagnosticCategory::Table,
            token_msg,
        )
    }

    /// Returns the table identifier for Module.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::Module`] (0x00)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Module)
    }

    /// Returns the table dependencies for Module loading.
    ///
    /// The Module table has no dependencies as it only references metadata heaps
    /// (strings and GUIDs) and serves as a foundation table for other metadata loading.
    /// It is typically one of the first tables loaded in the dependency resolution process.
    ///
    /// ## Returns
    /// Empty array as Module table has no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

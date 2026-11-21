//! # Param Table Loader
//!
//! This module provides the loader implementation for the [`Param`](crate::metadata::tables::Param) table,
//! which contains information about method parameters including their names, attributes, and metadata.
//! Param entries define the signature components of methods and provide parameter-specific metadata.
//!
//! ## Purpose
//!
//! The [`ParamLoader`] processes [`crate::metadata::tables::ParamRaw`] entries during metadata loading,
//! converting them to owned [`Param`](crate::metadata::tables::Param) instances with resolved parameter names.
//! These entries provide detailed information about method parameters, including their
//! names, sequence numbers, and attributes for proper method signature construction.
//!
//! ## Table Dependencies
//!
//! The Param table has no dependencies on other metadata tables:
//! - Only depends on the string heap for parameter name resolution
//! - Can be loaded early in the dependency resolution process
//! - Serves as a foundation for method signature construction
//!
//! ## Error Conditions
//!
//! The loader may fail if:
//! - String heap entries are malformed or missing
//! - Param table contains invalid or corrupted data
//! - Token conflicts occur during storage

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::ParamRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the Param metadata table.
///
/// This loader processes [`crate::metadata::tables::ParamRaw`] entries, converting them to
/// owned [`crate::metadata::tables::Param`] instances with resolved parameter names.
/// Param entries provide detailed information about method parameters, including their
/// names, sequence numbers, and attributes for proper method signature construction.
///
/// The loader handles:
/// - Resolution of parameter names from the string heap
/// - Parallel processing of multiple Param entries
/// - Storage of processed entries in a concurrent map for token-based access
/// - Error handling for malformed string heap references
///
/// ## Thread Safety
///
/// This loader is thread-safe and uses parallel iteration with concurrent storage operations.
pub struct ParamLoader;

impl MetadataLoader for ParamLoader {
    /// Loads and processes all Param table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    /// Returns an error if:
    /// - String heap entries cannot be resolved or are malformed
    /// - Param table contains invalid or corrupted data
    /// - Storage operations fail due to token conflicts
    ///
    /// ## Thread Safety
    /// Uses parallel iteration and concurrent storage operations for thread safety.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<ParamRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("param 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(strings),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.param.insert(row.token, res.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for Param.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::Param`] (0x08)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Param)
    }

    /// Returns the table dependencies for Param loading.
    ///
    /// The Param table has no dependencies as it only references the string heap
    /// for parameter name resolution. It can be loaded early in the dependency resolution
    /// process and serves as a foundation for method signature construction.
    ///
    /// ## Returns
    /// Empty array as Param table has no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

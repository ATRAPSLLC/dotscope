//! `ImportScope` table loader for metadata processing
//!
//! This module provides the [`ImportScopeLoader`] implementation for processing
//! `ImportScope` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{ImportScopeRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `ImportScope` metadata table
///
/// Implements [`MetadataLoader`] to process the `ImportScope` table (0x35)
/// which defines the import scopes that organize imported namespaces and types
/// in Portable PDB format. Import scopes enable hierarchical organization of
/// debugging information for namespace resolution and type lookup.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle import scope entries,
/// resolving blob heap references to decode import declarations and building the
/// complete scope hierarchy for runtime debugging support.
///
/// # Dependencies
///
/// This loader depends on the #Blob heap being available in the loader context
/// for resolving import declarations and nested scope data.
///
/// # Reference
/// * [Portable PDB Format - ImportScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#importscope-table-0x35)
pub struct ImportScopeLoader;

impl MetadataLoader for ImportScopeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let (Some(header), Some(blobs)) = (pdb.meta, pdb.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<ImportScopeRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("import scope 0x{:08x}", row.token.value());

                let Some(import_scope) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(blobs),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target
                    .import_scopes
                    .insert(import_scope.token, import_scope);
                Ok(())
            })
    }

    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ImportScope)
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

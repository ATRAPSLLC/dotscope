//! `LocalScope` table loader for metadata processing
//!
//! This module provides the [`LocalScopeLoader`] implementation for processing
//! ``LocalScope`` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{LocalScopeRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `LocalScope` metadata table
///
/// Implements [`MetadataLoader`] to process the `LocalScope` table (0x32)
/// which defines the scope ranges where local variables and constants are active
/// within methods in Portable PDB format. This loader handles the conversion from
/// raw binary data to structured scope metadata for debugging support.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of local
/// scope entries, resolving table references and building the complete scope
/// metadata map for quick runtime access during debugging operations.
///
/// # Dependencies
///
/// This loader depends on several other metadata tables that must be loaded first:
/// - `MethodDef`: For method references
/// - `ImportScope`: For namespace import context
/// - `LocalVariable`: For variable list references
/// - `LocalConstant`: For constant list references
///
/// # Reference
/// * [Portable PDB Format - LocalScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localscope-table-0x32)
pub struct LocalScopeLoader;

impl MetadataLoader for LocalScopeLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let Some(header) = pdb.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<LocalScopeRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("local scope 0x{:08x}", row.token.value());

                let Some(local_scope) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(
                        context.method_def,
                        &pdb.target.import_scopes,
                        &pdb.target.local_variables,
                        &pdb.target.local_constants,
                        table,
                    ),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target
                    .local_scopes
                    .insert(local_scope.token, local_scope);
                Ok(())
            })
    }

    fn table_id(&self) -> Option<TableId> {
        Some(TableId::LocalScope)
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::ImportScope,
            TableId::LocalVariable,
            TableId::LocalConstant,
        ]
    }
}

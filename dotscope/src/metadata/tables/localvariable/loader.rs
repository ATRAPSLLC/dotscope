//! `LocalVariable` table loader for metadata processing
//!
//! This module provides the [`LocalVariableLoader`] implementation for processing
//! `LocalVariable` table data during metadata loading. The loader handles parallel
//! processing and integration with the broader loader context.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{LocalVariableRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `LocalVariable` metadata table
///
/// Implements [`MetadataLoader`] to process the `LocalVariable` table (0x33)
/// which stores information about local variables within method scopes,
/// including their names, signatures, and attributes in Portable PDB format.
/// This loader handles the conversion from raw binary data to structured variable
/// metadata for debugging support.
///
/// # Processing Strategy
///
/// The loader uses parallel processing to efficiently handle large numbers of local
/// variable entries, resolving heap references and building the complete variable
/// metadata map for quick runtime access during debugging operations.
///
/// # Dependencies
///
/// This loader depends on the #Strings heap being available in the loader context
/// for resolving variable name strings.
///
/// # Reference
/// * [Portable PDB Format - LocalVariable Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localvariable-table-0x33)
pub struct LocalVariableLoader;

impl MetadataLoader for LocalVariableLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let (Some(header), Some(strings)) = (pdb.meta, pdb.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<LocalVariableRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("local variable 0x{:08x}", row.token.value());

                let Some(local_variable) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(strings),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target
                    .local_variables
                    .insert(local_variable.token, local_variable);
                Ok(())
            })
    }

    fn table_id(&self) -> Option<TableId> {
        Some(TableId::LocalVariable)
    }

    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

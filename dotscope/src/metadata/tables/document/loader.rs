//! Document table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::document::DocumentLoader`] implementation for loading document information
//! from the Portable PDB Document table (0x30). This loader processes debugging metadata that provides information
//! about source documents referenced in the debug information, integrating this data with existing metadata entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::document::DocumentLoader`] - Main loader for processing Document table data
//!
//! # Thread Safety
//!
//! All loading operations use parallel processing with proper synchronization,
//! enabling concurrent processing of multiple document entries.

use rayon::prelude::*;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{types::TableId, DocumentRaw},
    },
    prelude::*,
};

/// Loader implementation for the Document table in Portable PDB format.
///
/// This loader processes the Document table (0x30) from Portable PDB metadata, which contains
/// information about source documents referenced in debug information. Each document entry
/// includes the document name, hash algorithm, hash value, and source language identifier.
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the Document table,
/// resolving heap indices and creating fully resolved document structures.
///
/// ## Loading Process
///
/// 1. **Table Validation**: Verifies the Document table exists and has valid row count
/// 2. **Parallel Processing**: Uses parallel iteration for efficient loading of document entries
/// 3. **Index Mapping**: Creates token-based mappings for efficient document lookups
/// 4. **Context Storage**: Stores the processed document map in the loader context
///
/// ## Usage
///
/// The loader is automatically invoked during metadata loading and populates the
/// `document` field in the [`crate::metadata::loader::LoaderContext`]. Document information can be accessed
/// through the context for debug information processing and source code mapping.
///
/// ## Reference
/// * [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)
pub struct DocumentLoader;

impl MetadataLoader for DocumentLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let (Some(header), Some(strings), Some(blob), Some(guid)) =
            (pdb.meta, pdb.strings, pdb.blobs, pdb.guids)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<DocumentRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .map(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("document 0x{:08x}", row.token.value());

                let Some(document) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(strings, blob, guid),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target.documents.insert(document.token, document);
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    /// Returns the table identifier for the Document table.
    ///
    /// # Returns
    /// [`crate::metadata::tables::types::TableId::Document`] (0x30)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Document)
    }

    /// Returns the list of table dependencies for Document loading.
    ///
    /// The Document table has no dependencies as it contains self-contained
    /// document metadata with only heap references.
    ///
    /// # Returns
    /// Empty slice - no table dependencies required
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

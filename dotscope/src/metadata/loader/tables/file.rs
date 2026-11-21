//! File table loader implementation.
//!
//! This module provides the [`FileLoader`] responsible for loading and processing
//! File metadata table entries. The File table lists files in a multi-file assembly,
//! containing metadata about each file's name, hash, and flags.
//!
//! # Purpose
//! The File table is used for multi-file assemblies and resource management:
//! - **Multi-file assemblies**: Lists all files that comprise the assembly
//! - **Module organization**: Tracks separate modules within an assembly
//! - **Resource files**: References to external resource files
//! - **Native libraries**: Unmanaged DLLs used by the assembly
//! - **Integrity verification**: Hash values for tamper detection
//!
//! # File Types
//! File entries can represent various file types:
//! - **Modules**: Additional .netmodule files in the assembly
//! - **Resources**: Binary resource files (.resources, images, etc.)
//! - **Native code**: Unmanaged DLLs for P/Invoke operations
//! - **Metadata**: Additional metadata files
//! - **Documentation**: XML documentation or help files
//!
//! # Hash Verification
//! Each file entry includes a cryptographic hash:
//! - **SHA-1 or SHA-256**: Hash algorithm depends on assembly version
//! - **Integrity checking**: Verifies file hasn't been modified
//! - **Security**: Prevents tampering with assembly files
//! - **Loading validation**: Runtime can verify file authenticity
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the File table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::FileRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the File metadata table.
///
/// This loader processes File table entries which list files in a multi-file assembly.
/// Each entry contains metadata about files that are part of the assembly but stored
/// separately from the main manifest file.
///
/// # Errors
/// Loading may fail if:
/// - String references cannot be resolved from the strings heap
/// - Hash data cannot be read from the blob heap
/// - Memory allocation fails during processing
/// - Concurrent access conflicts occur
/// - File metadata is malformed or corrupted
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for complete File table specification.
pub struct FileLoader;

impl MetadataLoader for FileLoader {
    /// Load and process all File table entries.
    ///
    /// This method iterates through the File table, resolving string and blob references
    /// to build complete file metadata structures. Each entry describes a file that is
    /// part of the multi-file assembly.
    ///
    /// # Arguments
    /// * `context` - The loader context containing metadata tables and heaps
    ///
    /// # Returns
    /// Returns `Ok(())` on successful loading, or an error if:
    /// - String reference resolution fails
    /// - Blob data reading encounters issues
    /// - Raw-to-owned conversion fails
    /// - Collection insertion operations fail
    /// - Parallel processing encounters errors
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blob), Some(strings)) =
            (context.meta, context.blobs, context.strings)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<FileRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("file 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(blob, strings),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.file.insert(row.token, res.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for the File table.
    ///
    /// # Returns
    /// Returns [`TableId::File`] indicating this loader handles the File table.
    ///
    /// [`TableId::File`]: crate::prelude::TableId::File
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::File)
    }

    /// Returns the table dependencies for File loading.
    ///
    /// The File table has no dependencies on other metadata tables since it only
    /// references heap data (strings and blobs) which are loaded before table processing.
    ///
    /// # Returns
    /// Returns an empty slice indicating no table dependencies.
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}

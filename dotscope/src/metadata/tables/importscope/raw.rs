//! Raw `ImportScope` table representation for Portable PDB format
//!
//! This module provides the [`ImportScopeRaw`] struct that represents
//! the binary format of `ImportScope` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use std::sync::Arc;

use crate::{
    metadata::{
        importscope::{parse_imports_blob, ImportsInfo},
        streams::Blob,
        tables::{ImportScope, ImportScopeRc, TableId, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw binary representation of an `ImportScope` table entry
///
/// This structure matches the exact binary layout of `ImportScope` table
/// entries in the metadata tables stream. The Parent field contains an
/// unresolved index to another `ImportScope` entry, and the Imports field contains
/// an unresolved index into the #Blob heap that must be resolved during
/// conversion to the owned [`ImportScope`] variant.
///
/// # Binary Format
///
/// Each `ImportScope` table entry consists of:
/// - Parent: Index into `ImportScope` table for parent scope (may be 0)
/// - Imports: Index into #Blob heap for import information
#[derive(Debug, Clone)]
pub struct ImportScopeRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `ImportScope` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Index into `ImportScope` table for parent scope
    ///
    /// Points to the parent import scope that encloses this scope, or 0 if
    /// this is a root-level import scope. Import scopes form a tree structure
    /// where child scopes inherit imports from their parent scopes.
    pub parent: u32,

    /// Index into #Blob heap for import information
    ///
    /// Points to the binary blob containing the import data for this scope.
    /// The blob format contains the list of imported namespaces and types
    /// that are available within this lexical scope.
    pub imports: u32,
}

impl ImportScopeRaw {
    /// Converts this raw `ImportScope` entry to an owned [`ImportScope`] instance
    ///
    /// This method resolves the raw `ImportScope` entry to create a complete `ImportScope`
    /// object by resolving the imports blob data from the #Blob heap. The parent
    /// reference is kept as an index that can be resolved through the `ImportScope` table.
    ///
    /// # Parameters
    /// - `blobs`: Reference to the #Blob heap for resolving the imports index
    ///
    /// # Returns
    /// Returns `Ok(ImportScopeRc)` with the resolved import scope data, or an error if
    /// the imports index is invalid or points to malformed data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::ImportScopeRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example(blobs: &dotscope::metadata::streams::Blob) -> dotscope::Result<()> {
    /// let scope_raw = ImportScopeRaw {
    ///     rid: 1,
    ///     token: Token::new(0x35000001),
    ///     offset: 0,
    ///     parent: 0,          // Root scope
    ///     imports: 100,       // Index into #Blob heap
    /// };
    ///
    /// let scope = scope_raw.to_owned(blobs)?;
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the blob index is invalid, the blob cannot be parsed, or memory allocation fails during conversion.
    pub fn to_owned(&self, blobs: &Blob) -> Result<ImportScopeRc> {
        let imports = if self.imports == 0 {
            ImportsInfo::new()
        } else {
            let blob_data = blobs.get(self.imports as usize)?;
            parse_imports_blob(blob_data, blobs)?
        };

        let scope = ImportScope {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent: self.parent,
            imports,
        };

        Ok(Arc::new(scope))
    }
}

impl TableRow for ImportScopeRaw {
    /// Calculate the byte size of an ImportScope table row
    ///
    /// Returns the total size of one row in the ImportScope table, including:
    /// - parent: 2 or 4 bytes (ImportScope table index)
    /// - imports: 2 or 4 bytes (Blob heap index)
    ///
    /// The index sizes depend on the metadata table and heap requirements.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */  sizes.table_index_bytes(TableId::ImportScope)
            /* imports */ .saturating_add(sizes.blob_bytes())

        )
    }
}

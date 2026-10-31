//! Raw Document table representation for Portable PDB format
//!
//! This module provides the [`crate::metadata::tables::document::raw::DocumentRaw`] struct
//! for low-level access to Document metadata table data with unresolved heap indices.
//! This represents the binary format of document records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # Document Table Format
//!
//! The Document table (0x30) contains rows with these fields:
//! - **`Name`** (2/4 bytes): Blob heap index for the document name/path
//! - **`HashAlgorithm`** (2/4 bytes): GUID heap index for the hash algorithm identifier
//! - **`Hash`** (2/4 bytes): Blob heap index for the document content hash
//! - **`Language`** (2/4 bytes): GUID heap index for the source language identifier
//!
//! # Reference
//! - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)

use std::sync::Arc;

use crate::{
    metadata::{
        pdb::document_name,
        streams::{Blob, Guid, Strings},
        tables::{Document, DocumentRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw Document table row with unresolved heap indices
///
/// Represents the binary format of a Document metadata table entry (table ID 0x30) as stored
/// in the metadata tables stream. All heap indices are stored as raw values that must be
/// resolved using the appropriate heap context to access the actual data.
///
/// The Document table associates source documents with debug information throughout the
/// assembly, providing a mechanism for mapping IL instructions back to source code locations
/// during debugging sessions.
///
/// # Reference
/// - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)
pub struct DocumentRaw {
    /// Row identifier within the Document metadata table
    ///
    /// The 1-based index of this document row within the table.
    /// Used to generate the metadata token and for table iteration.
    pub rid: u32,

    /// Metadata token for this document row
    ///
    /// Combines the table identifier (0x30 for Document) with the row ID to create
    /// a unique token. Format: `0x30000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw document data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Blob heap index for the document name/path (unresolved)
    ///
    /// Index into the blob heap containing the document name, typically a file path
    /// or URI that identifies the source document. The blob format is specific to
    /// document names and may contain path separators and components.
    pub name: u32,

    /// GUID heap index for the hash algorithm identifier (unresolved)
    ///
    /// Index into the GUID heap for the hash algorithm used to compute the document hash.
    /// Common algorithms include SHA-1, SHA-256, and others. Must be resolved using GUID heap lookup.
    pub hash_algorithm: u32,

    /// Blob heap index for the document content hash (unresolved)
    ///
    /// Index into the blob heap containing the hash value of the document content
    /// computed using the specified hash algorithm. Used for integrity verification
    /// and change detection. A value of 0 indicates no hash is available.
    pub hash: u32,

    /// GUID heap index for the source language identifier (unresolved)
    ///
    /// Index into the GUID heap for the programming language used in this document.
    /// Common languages include C#, VB.NET, F#, and others. Must be resolved using GUID heap lookup.
    pub language: u32,
}

impl DocumentRaw {
    /// Convert a raw Document to an owned Document with resolved heap data
    ///
    /// This method transforms the raw table entry into a fully usable document by:
    /// 1. Resolving the name blob to extract the document path
    /// 2. Resolving the hash algorithm GUID to identify the hash type
    /// 3. Resolving the hash blob to get the actual hash bytes
    /// 4. Resolving the language GUID to identify the programming language
    /// 5. Creating an owned Document with all resolved data
    ///
    /// The method performs comprehensive validation to ensure metadata integrity.
    ///
    /// # Arguments
    ///
    /// * `strings` - String heap for resolving string indices
    /// * `blobs` - Blob heap for resolving blob indices (name and hash)
    /// * `guids` - GUID heap for resolving GUID indices (hash algorithm and language)
    ///
    /// # Returns
    ///
    /// Returns `Ok(DocumentRc)` with the resolved document data, or an error if:
    /// - Any heap index is invalid or out of bounds
    /// - The document name blob has an invalid format
    /// - Required heap data is missing or corrupted
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Blob heap access fails for name or hash data
    /// - GUID heap access fails for hash algorithm or language GUIDs
    /// - Any heap index is out of bounds
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::DocumentRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example() -> dotscope::Result<()> {
    /// let document_raw = DocumentRaw {
    ///     rid: 1,
    ///     token: Token::new(0x30000001),
    ///     offset: 0,
    ///     name: 42,        // blob index
    ///     hash_algorithm: 1, // GUID index
    ///     hash: 100,      // blob index
    ///     language: 1,    // GUID index
    /// };
    ///
    /// // let document = document_raw.to_owned(&strings, &blobs, &guids)?;
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if heap lookups fail or if the data is malformed.
    pub fn to_owned(&self, _strings: &Strings, blobs: &Blob, guids: &Guid) -> Result<DocumentRc> {
        let name = document_name(blobs.get(self.name as usize)?, blobs)?;

        // A document may have no hash algorithm: a nil index
        let hash_algorithm_guid = if self.hash_algorithm == 0 {
            None
        } else {
            Some(guids.get(self.hash_algorithm as usize)?)
        };

        let hash_bytes = if self.hash == 0 {
            Vec::new()
        } else {
            blobs.get(self.hash as usize)?.to_vec()
        };

        let language_guid = guids.get(self.language as usize)?;

        // Create the owned Document with resolved data
        let document = Document {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name,
            hash_algorithm: hash_algorithm_guid,
            hash: hash_bytes,
            language: language_guid,
        };

        Ok(Arc::new(document))
    }
}

impl TableRow for DocumentRaw {
    /// Calculate the row size for `Document` table entries
    ///
    /// Returns the total byte size of a single `Document` table row based on the
    /// table configuration. The size varies depending on the size of heap indexes in the metadata.
    ///
    /// # Size Breakdown
    /// - `name`: 2 or 4 bytes (blob heap index for document name/path)
    /// - `hash_algorithm`: 2 or 4 bytes (GUID heap index for hash algorithm)
    /// - `hash`: 2 or 4 bytes (blob heap index for document content hash)
    /// - `language`: 2 or 4 bytes (GUID heap index for source language)
    ///
    /// Total: 8-16 bytes depending on heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* name */           sizes.blob_bytes()
            /* hash_algorithm */ .saturating_add(sizes.guid_bytes())
            /* hash */           .saturating_add(sizes.blob_bytes())
            /* language */       .saturating_add(sizes.guid_bytes())

        )
    }
}

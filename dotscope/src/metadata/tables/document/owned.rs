//! Owned Document table representation for Portable PDB format
//!
//! This module provides the [`crate::metadata::tables::document::owned::Document`] struct
//! which contains fully resolved document metadata with owned data and resolved heap references.
//! This is the primary data structure for representing Portable PDB documents in a usable form,
//! with parsed document names and resolved GUID references after the dual variant resolution phase.

use crate::metadata::{pdb::guids, token::Token};

/// Represents a Portable PDB document with fully resolved metadata and parsed data
///
/// This structure contains the complete document information from the Document
/// metadata table (0x30), with all heap indices resolved to concrete data values.
/// Unlike [`crate::metadata::tables::document::raw::DocumentRaw`], this provides
/// immediate access to structured document data without requiring additional parsing.
///
/// # Document Structure
///
/// A document consists of:
/// - **Name**: The resolved document name/path (typically a file path)
/// - **Hash Algorithm**: The GUID identifying the hash algorithm used
/// - **Hash**: The actual hash bytes computed from the document content
/// - **Language**: The GUID identifying the source programming language
///
/// # Reference
/// - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)
pub struct Document {
    /// Row identifier within the Document metadata table
    ///
    /// The 1-based index of this document row. Used to uniquely identify
    /// this specific document instance within the table.
    pub rid: u32,

    /// Metadata token for this document
    ///
    /// Combines the table identifier (0x30 for Document) with the row ID to create
    /// a unique token that can be used to reference this document from other metadata.
    pub token: Token,

    /// Byte offset of this document row within the metadata tables stream
    ///
    /// Physical location of the raw document data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Resolved document name/path
    ///
    /// The document's path, typically a file path (`/_/src/Program.cs` with a SourceLink
    /// path map) or a URI. The Name column names a DocumentNameBlob, which stores the path
    /// as a separator character followed by the `#Blob` indices of its parts; the parts are
    /// joined here by that separator, as
    /// [`document_name`](crate::metadata::pdb::document_name) decodes them.
    pub name: String,

    /// Hash algorithm identifier
    ///
    /// The GUID identifying the algorithm the document's [`hash`](Self::hash) was computed
    /// with: [`guids::HASH_SHA1`] or [`guids::HASH_SHA256`] for the compilers' documents.
    /// `None` when the HashAlgorithm column is a nil index, which the compilers write for a
    /// document they have no content for (a `#line` directive naming a file they never
    /// read); such a document has no hash either.
    pub hash_algorithm: Option<uguid::Guid>,

    /// Document content hash
    ///
    /// The actual hash bytes computed from the document content using the specified
    /// hash algorithm. Used for integrity verification and change detection during debugging.
    /// An empty vector indicates no hash is available.
    pub hash: Vec<u8>,

    /// Source language identifier
    ///
    /// The GUID identifying the programming language used in this document.
    /// Common language GUIDs include C#, VB.NET, F#, and other .NET languages.
    pub language: uguid::Guid,
}

impl Document {
    /// Create a new Document with the specified metadata
    ///
    /// # Arguments
    ///
    /// * `rid` - Row identifier within the Document table
    /// * `token` - Metadata token for this document
    /// * `offset` - Byte offset within the metadata stream
    /// * `name` - Resolved document name/path
    /// * `hash_algorithm` - Hash algorithm GUID
    /// * `hash` - Document content hash bytes
    /// * `language` - Source language GUID
    #[must_use]
    pub fn new(
        rid: u32,
        token: Token,
        offset: usize,
        name: String,
        hash_algorithm: Option<uguid::Guid>,
        hash: Vec<u8>,
        language: uguid::Guid,
    ) -> Self {
        Self {
            rid,
            token,
            offset,
            name,
            hash_algorithm,
            hash,
            language,
        }
    }

    /// Check if this document has a hash
    #[must_use]
    pub fn has_hash(&self) -> bool {
        !self.hash.is_empty()
    }

    /// Check if this is a C# document based on the language GUID
    ///
    /// C# language GUID: {3F5162F8-07C6-11D3-9053-00C04FA302A1}
    #[must_use]
    pub fn is_csharp(&self) -> bool {
        self.language == guids::LANGUAGE_CSHARP
    }

    /// Check if this is a Visual Basic document based on the language GUID
    ///
    /// VB.NET language GUID: {3A12D0B8-C26C-11D0-B442-00A0244A1DD2}
    #[must_use]
    pub fn is_visual_basic(&self) -> bool {
        self.language == guids::LANGUAGE_VISUAL_BASIC
    }

    /// Check if this is an F# document based on the language GUID
    ///
    /// F# language GUID: {AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3}
    #[must_use]
    pub fn is_fsharp(&self) -> bool {
        self.language == guids::LANGUAGE_FSHARP
    }

    /// Get a human-readable description of the hash algorithm
    ///
    /// # Returns
    ///
    /// `"SHA-1"` or `"SHA-256"` for those algorithms' GUIDs, `"None"` for a document with no
    /// hash algorithm, and `"Unknown"` for any other GUID.
    #[must_use]
    pub fn hash_algorithm_name(&self) -> &'static str {
        match self.hash_algorithm {
            Some(guids::HASH_SHA1) => "SHA-1",
            Some(guids::HASH_SHA256) => "SHA-256",
            None => "None",
            Some(_) => "Unknown",
        }
    }

    /// Get a human-readable description of the programming language
    #[must_use]
    pub fn language_name(&self) -> &'static str {
        if self.is_csharp() {
            "C#"
        } else if self.is_visual_basic() {
            "Visual Basic"
        } else if self.is_fsharp() {
            "F#"
        } else {
            "Unknown"
        }
    }
}

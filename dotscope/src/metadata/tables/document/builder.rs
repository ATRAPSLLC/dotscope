//! # Document Builder
//!
//! Provides a fluent API for building Document table entries for Portable PDB debug information.
//! The Document table stores information about source documents referenced in debug information,
//! including document names/paths, hash algorithms, content hashes, and source language identifiers.
//!
//! ## Overview
//!
//! The `DocumentBuilder` enables creation of document entries with:
//! - Document name/path specification (required)
//! - Hash algorithm GUID specification (optional)
//! - Document content hash specification (optional)
//! - Source language GUID specification (optional)
//! - Validation of document name and GUID formats
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create a document entry with basic information
//! let document_token = DocumentBuilder::new()
//!     .name("Program.cs")
//!     .csharp_language()
//!     .sha256_hash_algorithm()
//!     .hash(vec![0x12, 0x34, 0x56, 0x78]) // Example hash
//!     .build(&mut assembly)?;
//!
//! // Create a document with minimal information
//! let minimal_doc_token = DocumentBuilder::new()
//!     .name("Script.cs")
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Document name is required and validated
//! - **GUID Handling**: Provides helper methods for common language and hash algorithm GUIDs
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Heap Management**: Strings, blobs, and GUIDs are added to appropriate heaps

use crate::{
    cilassembly::{BlobComposite, ChangeRefRc, CilAssembly},
    metadata::{
        pdb::{guids, split_document_name},
        tables::{DocumentRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Document table entries.
///
/// `DocumentBuilder` provides a fluent API for creating entries in the Document
/// metadata table, which stores source document information for Portable PDB debug data.
/// Each document entry associates a source file with hash information and language metadata.
///
/// # Purpose
///
/// The Document table serves several key functions:
/// - **Source Mapping**: Associates IL instructions with source code locations
/// - **Integrity Verification**: Provides hash information for verifying document content
/// - **Language Support**: Identifies source languages for syntax highlighting and debugging
/// - **Debug Information**: Enables rich debugging experiences with proper source association
/// - **Tool Integration**: Supports IDEs, debuggers, and other development tools
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing Document entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// let document_token = DocumentBuilder::new()
///     .name("MyFile.cs")
///     .csharp_language()
///     .sha256_hash_algorithm()
///     .hash(vec![0x01, 0x02, 0x03, 0x04])
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Document Name Required**: A document name/path must be provided
/// - **Name Validation**: Document name cannot be empty
/// - **GUID Format**: Hash algorithm and language GUIDs must be 16 bytes
/// - **Hash Validation**: Document hash must be valid bytes if provided
///
/// # Integration
///
/// Document entries integrate with other debug metadata structures:
/// - **MethodDebugInformation**: References documents for sequence point mapping
/// - **LocalScope**: Associates local variable scopes with source documents
/// - **CustomDebugInformation**: Links custom debug data to source documents
/// - **Portable PDB**: Provides core document information for debug symbol files
#[derive(Debug, Clone)]
pub struct DocumentBuilder {
    /// The document name/path
    name: Option<String>,
    /// The hash algorithm GUID (16 bytes)
    hash_algorithm: Option<[u8; 16]>,
    /// The document content hash bytes
    hash: Option<Vec<u8>>,
    /// The source language GUID (16 bytes)
    language: Option<[u8; 16]>,
}

impl Default for DocumentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentBuilder {
    /// Creates a new `DocumentBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            hash_algorithm: None,
            hash: None,
            language: None,
        }
    }

    /// Sets the document name or path.
    ///
    /// The name typically represents a file path or URI that identifies
    /// the source document. This is the primary identifier for the document
    /// and is required for building the document entry.
    ///
    /// The name is stored as a DocumentNameBlob, split into parts at its separator as
    /// System.Reflection.Metadata splits it ([`split_document_name`]): each part is a blob of
    /// its own, shared with every other document that names it, and the writer encodes the
    /// name with the offsets the parts are given.
    ///
    /// # Arguments
    ///
    /// * `name` - The document name or path
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .name("Program.cs");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the hash algorithm GUID.
    ///
    /// Specifies the algorithm used to compute the document content hash.
    /// The GUID identifies the specific hash algorithm for integrity verification.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID identifying the hash algorithm, as the `#GUID` heap stores it: its
    ///   first three fields little-endian ([`uguid::Guid::to_bytes`])
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// use dotscope::metadata::pdb::guids;
    ///
    /// let builder = DocumentBuilder::new()
    ///     .hash_algorithm(&guids::HASH_SHA256.to_bytes());
    /// ```
    #[must_use]
    pub fn hash_algorithm(mut self, guid: &[u8; 16]) -> Self {
        self.hash_algorithm = Some(*guid);
        self
    }

    /// Sets the hash algorithm to SHA-1.
    ///
    /// Convenience method that sets the hash algorithm GUID to the standard
    /// SHA-1 algorithm identifier used in Portable PDB files,
    /// `{FF1816EC-AA5E-4D10-87F7-6F4963833460}` ([`guids::HASH_SHA1`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .sha1_hash_algorithm();
    /// ```
    #[must_use]
    pub fn sha1_hash_algorithm(mut self) -> Self {
        self.hash_algorithm = Some(guids::HASH_SHA1.to_bytes());
        self
    }

    /// Sets the hash algorithm to SHA-256.
    ///
    /// Convenience method that sets the hash algorithm GUID to the standard
    /// SHA-256 algorithm identifier used in Portable PDB files,
    /// `{8829D00F-11B8-4213-878B-770E8597AC16}` ([`guids::HASH_SHA256`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .sha256_hash_algorithm();
    /// ```
    #[must_use]
    pub fn sha256_hash_algorithm(mut self) -> Self {
        self.hash_algorithm = Some(guids::HASH_SHA256.to_bytes());
        self
    }

    /// Sets the document content hash.
    ///
    /// Specifies the hash bytes computed using the specified hash algorithm.
    /// This hash is used for integrity verification and change detection.
    ///
    /// # Arguments
    ///
    /// * `hash_bytes` - The computed hash bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    /// let builder = DocumentBuilder::new()
    ///     .hash(hash_bytes);
    /// ```
    #[must_use]
    pub fn hash(mut self, hash_bytes: Vec<u8>) -> Self {
        self.hash = Some(hash_bytes);
        self
    }

    /// Sets the source language GUID.
    ///
    /// Specifies the programming language used in this document.
    /// The GUID identifies the specific language for syntax highlighting
    /// and debugging support.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID identifying the source language, as the `#GUID` heap stores it:
    ///   its first three fields little-endian ([`uguid::Guid::to_bytes`])
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// use dotscope::metadata::pdb::guids;
    ///
    /// let builder = DocumentBuilder::new()
    ///     .language(&guids::LANGUAGE_CSHARP.to_bytes());
    /// ```
    #[must_use]
    pub fn language(mut self, guid: &[u8; 16]) -> Self {
        self.language = Some(*guid);
        self
    }

    /// Sets the language to C#.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// C# language identifier used in Portable PDB files,
    /// `{3F5162F8-07C6-11D3-9053-00C04FA302A1}` ([`guids::LANGUAGE_CSHARP`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .csharp_language();
    /// ```
    #[must_use]
    pub fn csharp_language(mut self) -> Self {
        self.language = Some(guids::LANGUAGE_CSHARP.to_bytes());
        self
    }

    /// Sets the language to Visual Basic.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// Visual Basic language identifier used in Portable PDB files,
    /// `{3A12D0B8-C26C-11D0-B442-00A0244A1DD2}` ([`guids::LANGUAGE_VISUAL_BASIC`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .vb_language();
    /// ```
    #[must_use]
    pub fn vb_language(mut self) -> Self {
        self.language = Some(guids::LANGUAGE_VISUAL_BASIC.to_bytes());
        self
    }

    /// Sets the language to F#.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// F# language identifier used in Portable PDB files,
    /// `{AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3}` ([`guids::LANGUAGE_FSHARP`]).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .fsharp_language();
    /// ```
    #[must_use]
    pub fn fsharp_language(mut self) -> Self {
        self.language = Some(guids::LANGUAGE_FSHARP.to_bytes());
        self
    }

    /// Builds the Document entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the document name is valid,
    /// adds strings, blobs, and GUIDs to the appropriate heaps, creates the Document
    /// table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created Document entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The document name is not set
    /// - The document name is empty
    /// - There are issues adding strings/blobs/GUIDs to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    ///
    /// let document_token = DocumentBuilder::new()
    ///     .name("Program.cs")
    ///     .csharp_language()
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created Document with token: {}", document_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let document_name = self.name.ok_or_else(|| {
            Error::ModificationInvalid("Document name is required for Document".to_string())
        })?;

        if document_name.is_empty() {
            return Err(Error::ModificationInvalid(
                "Document name cannot be empty".to_string(),
            ));
        }

        // A DocumentNameBlob: the separator, then each part's blob; an empty part is index 0
        let (separator, parts) = split_document_name(&document_name);
        let parts = parts
            .into_iter()
            .map(|part| {
                if part.is_empty() {
                    Ok(None)
                } else {
                    assembly.blob_add(part.as_bytes()).map(Some)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let name_index = assembly
            .blob_add_composite(BlobComposite::DocumentName { separator, parts })
            .placeholder();

        let hash_algorithm_index = if let Some(guid) = self.hash_algorithm {
            assembly.guid_add(&guid)?.placeholder()
        } else {
            0
        };

        let hash_index = if let Some(hash_bytes) = self.hash {
            assembly.blob_add(&hash_bytes)?.placeholder()
        } else {
            0
        };

        let language_index = if let Some(guid) = self.language {
            assembly.guid_add(&guid)?.placeholder()
        } else {
            0
        };

        let document = DocumentRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            name: name_index,
            hash_algorithm: hash_algorithm_index,
            hash: hash_index,
            language: language_index,
        };

        assembly.table_row_add(TableId::Document, TableDataOwned::Document(document))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, metadata::tables::TableId,
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_document_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = DocumentBuilder::new()
            .name("Program.cs")
            .build(&mut assembly)?;

        // Verify the ref has the correct table ID
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_default() -> Result<()> {
        let builder = DocumentBuilder::default();
        assert!(builder.name.is_none());
        assert!(builder.hash_algorithm.is_none());
        assert!(builder.hash.is_none());
        assert!(builder.language.is_none());
        Ok(())
    }

    #[test]
    fn test_document_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = DocumentBuilder::new()
            .csharp_language()
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Document name is required"));

        Ok(())
    }

    #[test]
    fn test_document_builder_empty_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = DocumentBuilder::new().name("").build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Document name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_csharp_language() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = DocumentBuilder::new()
            .name("Test.cs")
            .csharp_language()
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_vb_language() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = DocumentBuilder::new()
            .name("Test.vb")
            .vb_language()
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_fsharp_language() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = DocumentBuilder::new()
            .name("Test.fs")
            .fsharp_language()
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_sha1_hash() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let ref_ = DocumentBuilder::new()
            .name("Test.cs")
            .sha1_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_sha256_hash() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let ref_ = DocumentBuilder::new()
            .name("Test.cs")
            .sha256_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    /// The convenience setters store the specification's GUIDs as the `#GUID` heap holds
    /// them: the first three fields little-endian, as a reader decodes them.
    #[test]
    fn convenience_guids_are_stored_as_the_heap_holds_them() {
        let csharp = DocumentBuilder::new().csharp_language().language.unwrap();
        assert_eq!(
            csharp,
            [
                0xF8, 0x62, 0x51, 0x3F, 0xC6, 0x07, 0xD3, 0x11, 0x90, 0x53, 0x00, 0xC0, 0x4F, 0xA3,
                0x02, 0xA1
            ]
        );
        let sha256 = DocumentBuilder::new()
            .sha256_hash_algorithm()
            .hash_algorithm
            .unwrap();
        assert_eq!(
            sha256,
            [
                0x0F, 0xD0, 0x29, 0x88, 0xB8, 0x11, 0x13, 0x42, 0x87, 0x8B, 0x77, 0x0E, 0x85, 0x97,
                0xAC, 0x16
            ]
        );
        for (stored, expected) in [
            (
                DocumentBuilder::new().sha1_hash_algorithm().hash_algorithm,
                guids::HASH_SHA1,
            ),
            (
                DocumentBuilder::new().vb_language().language,
                guids::LANGUAGE_VISUAL_BASIC,
            ),
            (
                DocumentBuilder::new().fsharp_language().language,
                guids::LANGUAGE_FSHARP,
            ),
        ] {
            assert_eq!(uguid::Guid::from_bytes(stored.unwrap()), expected);
        }
    }

    #[test]
    fn test_document_builder_full_specification() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let ref_ = DocumentBuilder::new()
            .name("MyProgram.cs")
            .csharp_language()
            .sha256_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_multiple_entries() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref1 = DocumentBuilder::new()
            .name("File1.cs")
            .csharp_language()
            .build(&mut assembly)?;

        let ref2 = DocumentBuilder::new()
            .name("File2.vb")
            .vb_language()
            .build(&mut assembly)?;

        // Verify refs are different
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::Document));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_custom_guid() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let custom_lang_guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let custom_hash_guid = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];

        let ref_ = DocumentBuilder::new()
            .name("CustomDoc.txt")
            .language(&custom_lang_guid)
            .hash_algorithm(&custom_hash_guid)
            .hash(vec![0x99, 0x88, 0x77, 0x66])
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test fluent API chaining
        let ref_ = DocumentBuilder::new()
            .name("FluentTest.cs")
            .csharp_language()
            .sha256_hash_algorithm()
            .hash(vec![0xaa, 0xbb, 0xcc, 0xdd])
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Document));

        Ok(())
    }

    #[test]
    fn test_document_builder_clone() {
        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78];
        let builder1 = DocumentBuilder::new()
            .name("Test.cs")
            .csharp_language()
            .hash(hash_bytes.clone());
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.language, builder2.language);
        assert_eq!(builder1.hash, builder2.hash);
    }

    #[test]
    fn test_document_builder_debug() {
        let builder = DocumentBuilder::new().name("Debug.cs").csharp_language();
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("DocumentBuilder"));
    }
}

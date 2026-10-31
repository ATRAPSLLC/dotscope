//! Binary codec for import declarations in Portable PDB debugging metadata.
//!
//! This module provides the parsing and encoding of the imports blob format. See the parent
//! module [`crate::metadata::importscope`] for the complete binary format specification and
//! usage examples.
//!
//! # Overview
//!
//! An imports blob is a sequence of declarations, each its kind followed by the fields that
//! kind has, in this order: an alias (a `#Blob` index of UTF-8 text), an assembly (an
//! AssemblyRef row), a namespace (a `#Blob` index of UTF-8 text) and a type (a
//! `TypeDefOrRefOrSpecEncoded` token).
//!
//! The codec works at two levels:
//!
//! - [`parse_import_records`] and [`encode_import_records`] read and write the declarations as
//!   the blob stores them ([`ImportRecord`]): blob indices and rows, not the text and tokens
//!   they name. This is the level a writer works at, renumbering what the blob points at.
//! - [`parse_imports_blob`] resolves the records against the `#Blob` heap into typed
//!   [`ImportDeclaration`] values with their text.
//!
//! # Error Handling
//!
//! Parsing returns errors for:
//! - **Invalid Kind Values**: Import kind values outside the valid 1-9 range
//! - **Truncated Data**: Insufficient data for expected import parameters
//! - **Blob Resolution Failures**: Invalid blob heap indices
//! - **Token Encoding Errors**: Malformed compressed token encoding
//!
//! Encoding fails for a type token that is not a TypeDef, TypeRef or TypeSpec, and for an
//! index past what a compressed integer holds.

use crate::{
    file::parser::Parser,
    metadata::{
        importscope::types::{ImportDeclaration, ImportKind, ImportsInfo},
        signatures::encode_type_def_or_ref_coded_index,
        streams::Blob,
        tables::TableId,
        token::Token,
    },
    utils::write_compressed_uint,
    Result,
};

/// An import declaration as its blob stores it: its kind, and the blob indices, AssemblyRef
/// row and type token the kind has.
///
/// A field the kind does not have is 0 (`None` for the type). Index 0 of a field the kind has
/// is the empty blob, which reads as empty text.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::importscope::{
///     encode_import_records, parse_import_records, ImportKind, ImportRecord,
/// };
///
/// // `using Alias = <namespace at blob 8>;`
/// let blob = [0x07, 0x01, 0x08];
/// let records = parse_import_records(&blob)?;
/// assert_eq!(
///     records,
///     [ImportRecord {
///         kind: ImportKind::DefineNamespaceAlias,
///         alias: 1,
///         assembly: 0,
///         namespace: 8,
///         target: None,
///     }]
/// );
/// assert_eq!(encode_import_records(&records)?, blob);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportRecord {
    /// The declaration's kind
    pub kind: ImportKind,
    /// The `#Blob` index of the alias, for the kinds that define or name an alias
    pub alias: u32,
    /// The AssemblyRef row, for the kinds that name an assembly
    pub assembly: u32,
    /// The `#Blob` index of the namespace, for the kinds that name one
    pub namespace: u32,
    /// The type (a TypeDef, TypeRef or TypeSpec token), for the kinds that name one
    pub target: Option<Token>,
}

impl ImportKind {
    /// The fields a declaration of this kind has after its kind, in blob order: an alias, an
    /// assembly, a namespace, a type.
    fn fields(self) -> [bool; 4] {
        match self {
            ImportKind::ImportNamespace => [false, false, true, false],
            ImportKind::ImportAssemblyNamespace => [false, true, true, false],
            ImportKind::ImportType => [false, false, false, true],
            ImportKind::ImportXmlNamespace | ImportKind::DefineNamespaceAlias => {
                [true, false, true, false]
            }
            ImportKind::ImportAssemblyReferenceAlias => [true, false, false, false],
            ImportKind::DefineAssemblyAlias => [true, true, false, false],
            ImportKind::DefineAssemblyNamespaceAlias => [true, true, true, false],
            ImportKind::DefineTypeAlias => [true, false, false, true],
        }
    }
}

/// Reads an imports blob as its declarations are stored, without resolving their blob
/// indices.
///
/// # Arguments
///
/// * `data` - The imports blob an ImportScope row's Imports column names
///
/// # Returns
///
/// The declarations in blob order; none for an empty blob.
///
/// # Errors
///
/// Returns an error when a kind is not 1 to 9 or the blob ends inside a declaration.
pub fn parse_import_records(data: &[u8]) -> Result<Vec<ImportRecord>> {
    let mut parser = Parser::new(data);
    let mut records = Vec::new();
    while parser.has_more_data() {
        let kind_value = parser.read_compressed_uint()?;
        let kind = ImportKind::from_u32(kind_value)
            .ok_or_else(|| malformed_error!("Invalid import kind: {}", kind_value))?;
        let [alias, assembly, namespace, target] = kind.fields();
        let mut record = ImportRecord {
            kind,
            alias: 0,
            assembly: 0,
            namespace: 0,
            target: None,
        };
        if alias {
            record.alias = parser.read_compressed_uint()?;
        }
        if assembly {
            record.assembly = parser.read_compressed_uint()?;
        }
        if namespace {
            record.namespace = parser.read_compressed_uint()?;
        }
        if target {
            record.target = Some(parser.read_compressed_token()?);
        }
        records.push(record);
    }
    Ok(records)
}

/// Writes declarations as an imports blob: the inverse of [`parse_import_records`].
///
/// Each declaration writes the fields its kind has; a field it does not have is not written,
/// whatever it holds.
///
/// # Arguments
///
/// * `records` - The declarations, in blob order
///
/// # Returns
///
/// The imports blob.
///
/// # Errors
///
/// Returns an error when an index or row is past what a compressed integer holds, or a kind
/// that names a type has none or one that is not a TypeDef, TypeRef or TypeSpec token.
pub fn encode_import_records(records: &[ImportRecord]) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    for record in records {
        let [alias, assembly, namespace, target] = record.kind.fields();
        write_compressed_uint(record.kind as u32, &mut blob)?;
        if alias {
            write_compressed_uint(record.alias, &mut blob)?;
        }
        if assembly {
            write_compressed_uint(record.assembly, &mut blob)?;
        }
        if namespace {
            write_compressed_uint(record.namespace, &mut blob)?;
        }
        if target {
            let token = record
                .target
                .ok_or_else(|| malformed_error!("a {:?} import names no type", record.kind))?;
            write_compressed_uint(encode_type_def_or_ref_coded_index(token)?, &mut blob)?;
        }
    }
    Ok(blob)
}

/// Parse an imports blob into structured import declarations.
///
/// Reads the declarations ([`parse_import_records`]) and resolves each alias and namespace
/// against the `#Blob` heap. Text is read as UTF-8, an invalid sequence as U+FFFD, as
/// System.Reflection.Metadata reads it.
///
/// # Arguments
/// * `data` - The byte slice containing the imports blob to parse
/// * `blobs` - Reference to the blob heap for resolving blob indices
///
/// # Returns
/// * [`Ok`]([`ImportsInfo`]) - Successfully parsed imports information
/// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data or I/O errors
///
/// # Errors
/// This function returns an error in the following cases:
/// - **Invalid Format**: Malformed or truncated imports blob
/// - **Unknown Kind**: Unrecognized import kind value
/// - **Blob Resolution**: Blob heap references that cannot be resolved
/// - **Token Encoding**: Invalid compressed token encoding
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::{
///     importscope::{parse_imports_blob, ImportDeclaration},
///     streams::Blob,
/// };
///
/// // A heap holding "Tests" at index 1
/// let heap = [0x00, 0x05, b'T', b'e', b's', b't', b's'];
/// let blobs = Blob::from(&heap)?;
/// let imports = parse_imports_blob(&[0x01, 0x01], &blobs)?; // ImportNamespace "Tests"
///
/// assert_eq!(imports.declarations.len(), 1);
/// if let ImportDeclaration::ImportNamespace { namespace } = &imports.declarations[0] {
///     assert_eq!(namespace, "Tests");
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_imports_blob(data: &[u8], blobs: &Blob) -> Result<ImportsInfo> {
    let text = |index: u32| -> Result<String> {
        Ok(String::from_utf8_lossy(blobs.get(index as usize)?).into_owned())
    };
    let assembly_ref = |row: u32| Token::new((TableId::AssemblyRef as u32) << 24 | row);
    let type_of = |record: &ImportRecord| {
        record
            .target
            .ok_or_else(|| malformed_error!("a {:?} import names no type", record.kind))
    };
    let declarations = parse_import_records(data)?
        .iter()
        .map(|record| {
            Ok(match record.kind {
                ImportKind::ImportNamespace => ImportDeclaration::ImportNamespace {
                    namespace: text(record.namespace)?,
                },
                ImportKind::ImportAssemblyNamespace => ImportDeclaration::ImportAssemblyNamespace {
                    assembly_ref: assembly_ref(record.assembly),
                    namespace: text(record.namespace)?,
                },
                ImportKind::ImportType => ImportDeclaration::ImportType {
                    type_ref: type_of(record)?,
                },
                ImportKind::ImportXmlNamespace => ImportDeclaration::ImportXmlNamespace {
                    alias: text(record.alias)?,
                    namespace: text(record.namespace)?,
                },
                ImportKind::ImportAssemblyReferenceAlias => {
                    ImportDeclaration::ImportAssemblyReferenceAlias {
                        alias: text(record.alias)?,
                    }
                }
                ImportKind::DefineAssemblyAlias => ImportDeclaration::DefineAssemblyAlias {
                    alias: text(record.alias)?,
                    assembly_ref: assembly_ref(record.assembly),
                },
                ImportKind::DefineNamespaceAlias => ImportDeclaration::DefineNamespaceAlias {
                    alias: text(record.alias)?,
                    namespace: text(record.namespace)?,
                },
                ImportKind::DefineAssemblyNamespaceAlias => {
                    ImportDeclaration::DefineAssemblyNamespaceAlias {
                        alias: text(record.alias)?,
                        assembly_ref: assembly_ref(record.assembly),
                        namespace: text(record.namespace)?,
                    }
                }
                ImportKind::DefineTypeAlias => ImportDeclaration::DefineTypeAlias {
                    alias: text(record.alias)?,
                    type_ref: type_of(record)?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ImportsInfo::with_declarations(declarations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::streams::Blob;

    /// Creates a minimal blob heap with just the required null blob at index 0.
    fn create_empty_blob_stream() -> Blob<'static> {
        Blob::from(&[0x00]).expect("Failed to create blob stream")
    }

    /// Creates a blob heap with test strings.
    /// Layout:
    /// - Index 0: empty blob (required)
    /// - Index 1: "System" (6 bytes)
    /// - Index 8: "TestAlias" (9 bytes)
    /// - Index 18: "http://example.com" (18 bytes)
    fn create_test_blob_stream() -> Vec<u8> {
        let mut data = vec![0x00]; // Index 0: null blob

        // Index 1: "System" (length 6)
        data.push(0x06); // length = 6
        data.extend_from_slice(b"System");

        // Index 8: "TestAlias" (length 9)
        data.push(0x09); // length = 9
        data.extend_from_slice(b"TestAlias");

        // Index 18: "http://example.com" (length 18)
        data.push(0x12); // length = 18
        data.extend_from_slice(b"http://example.com");

        data
    }

    #[test]
    fn test_parse_empty_blob() {
        let blobs = create_empty_blob_stream();
        let result = parse_imports_blob(&[], &blobs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_import_namespace() {
        // ImportKind::ImportNamespace = 1, followed by blob index for namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 1 (ImportNamespace), blob index 1 ("System")
        let import_data = &[0x01, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportNamespace { namespace } => {
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_assembly_namespace() {
        // ImportKind::ImportAssemblyNamespace = 2, followed by assembly ref row ID and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 2 (ImportAssemblyNamespace), assembly ref row 3, blob index 1 ("System")
        let import_data = &[0x02, 0x03, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportAssemblyNamespace {
                assembly_ref,
                namespace,
            } => {
                assert_eq!(assembly_ref.value(), 0x23000003); // AssemblyRef table (0x23) + row 3
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportAssemblyNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_type() {
        // ImportKind::ImportType = 3, followed by compressed token
        let blobs = create_empty_blob_stream();

        // Kind 3 (ImportType), compressed token for TypeRef row 5 (0x01000005)
        // Compressed token encoding: (row << 2) | table_index
        // TypeRef table index in TypeDefOrRefOrSpecEncoded = 1
        // So encoded = (5 << 2) | 1 = 21 = 0x15
        let import_data = &[0x03, 0x15];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportType { type_ref } => {
                assert_eq!(type_ref.value(), 0x01000005); // TypeRef table (0x01) + row 5
            }
            _ => panic!("Expected ImportType declaration"),
        }
    }

    #[test]
    fn test_parse_import_xml_namespace() {
        // ImportKind::ImportXmlNamespace = 4, followed by alias and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 4 (ImportXmlNamespace), alias blob index 8 ("TestAlias"), namespace blob index 18
        let import_data = &[0x04, 0x08, 0x12];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportXmlNamespace { alias, namespace } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(namespace, "http://example.com");
            }
            _ => panic!("Expected ImportXmlNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_assembly_reference_alias() {
        // ImportKind::ImportAssemblyReferenceAlias = 5, followed by alias
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 5 (ImportAssemblyReferenceAlias), alias blob index 8 ("TestAlias")
        let import_data = &[0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
                assert_eq!(alias, "TestAlias");
            }
            _ => panic!("Expected ImportAssemblyReferenceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_assembly_alias() {
        // ImportKind::DefineAssemblyAlias = 6, followed by alias and assembly ref
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 6 (DefineAssemblyAlias), alias blob index 8 ("TestAlias"), assembly ref row 2
        let import_data = &[0x06, 0x08, 0x02];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineAssemblyAlias {
                alias,
                assembly_ref,
            } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(assembly_ref.value(), 0x23000002);
            }
            _ => panic!("Expected DefineAssemblyAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_namespace_alias() {
        // ImportKind::DefineNamespaceAlias = 7, followed by alias and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 7 (DefineNamespaceAlias), alias blob index 8 ("TestAlias"), namespace blob index 1 ("System")
        let import_data = &[0x07, 0x08, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineNamespaceAlias { alias, namespace } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected DefineNamespaceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_assembly_namespace_alias() {
        // ImportKind::DefineAssemblyNamespaceAlias = 8, followed by alias, assembly ref, and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 8, alias blob index 8 ("TestAlias"), assembly ref row 1, namespace blob index 1 ("System")
        let import_data = &[0x08, 0x08, 0x01, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineAssemblyNamespaceAlias {
                alias,
                assembly_ref,
                namespace,
            } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(assembly_ref.value(), 0x23000001);
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected DefineAssemblyNamespaceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_type_alias() {
        // ImportKind::DefineTypeAlias = 9, followed by alias and type ref token
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 9 (DefineTypeAlias), alias blob index 8 ("TestAlias"), compressed token for TypeDef row 10
        // TypeDef table index in TypeDefOrRefOrSpecEncoded = 0
        // Encoded = (10 << 2) | 0 = 40 = 0x28
        let import_data = &[0x09, 0x08, 0x28];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineTypeAlias { alias, type_ref } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(type_ref.value(), 0x0200000A); // TypeDef table (0x02) + row 10
            }
            _ => panic!("Expected DefineTypeAlias declaration"),
        }
    }

    #[test]
    fn test_parse_multiple_declarations() {
        // Test parsing multiple declarations in sequence
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Multiple declarations:
        // 1. ImportNamespace "System" (kind 1, blob index 1)
        // 2. ImportAssemblyReferenceAlias "TestAlias" (kind 5, blob index 8)
        let import_data = &[0x01, 0x01, 0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 2);

        match &result.declarations[0] {
            ImportDeclaration::ImportNamespace { namespace } => {
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportNamespace as first declaration"),
        }

        match &result.declarations[1] {
            ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
                assert_eq!(alias, "TestAlias");
            }
            _ => panic!("Expected ImportAssemblyReferenceAlias as second declaration"),
        }
    }

    #[test]
    fn test_parse_invalid_kind() {
        // Test that invalid kind values (0, 10+) return errors
        let blobs = create_empty_blob_stream();

        // Kind 0 is invalid
        let import_data = &[0x00];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // Kind 10 is invalid
        let import_data = &[0x0A];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // Kind 255 is invalid
        let import_data = &[0xFF];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_truncated_data() {
        // Test that truncated data returns errors
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // ImportAssemblyNamespace (kind 2) requires assembly ref and namespace, but only kind is provided
        let import_data = &[0x02];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // ImportAssemblyNamespace with assembly ref but missing namespace
        let import_data = &[0x02, 0x01];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());
    }

    #[test]
    fn test_imports_info_iteration() {
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        let import_data = &[0x01, 0x01, 0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        // Test iter()
        let mut count = 0;
        for _decl in result.iter() {
            count += 1;
        }
        assert_eq!(count, 2);

        // Test into_iter() for &ImportsInfo
        count = 0;
        for _decl in &result {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_assembly_ref_token_format() {
        // Verify that assembly ref tokens are correctly formatted
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Test various row IDs (single byte compressed uint values: 0x00-0x7F)
        for row_id in [1u32, 10, 50, 127] {
            let import_data = vec![0x06, 0x08, row_id as u8]; // DefineAssemblyAlias
            let result = parse_imports_blob(&import_data, &blobs).unwrap();

            match &result.declarations[0] {
                ImportDeclaration::DefineAssemblyAlias { assembly_ref, .. } => {
                    let expected = (TableId::AssemblyRef as u32) << 24 | row_id;
                    assert_eq!(assembly_ref.value(), expected);
                }
                _ => panic!("Expected DefineAssemblyAlias"),
            }
        }
    }
}

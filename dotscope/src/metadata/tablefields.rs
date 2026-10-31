//! Table field layout definitions for heap references.
//!
//! This module provides a single source of truth for which fields in each metadata
//! table reference which heaps. This information is used by:
//!
//! - **Row patching**: Remapping heap offsets when heaps are rebuilt
//! - **Placeholder resolution**: Finding and resolving ChangeRef placeholders
//! - **Reference scanning**: Detecting which heap entries are actually used
//! - **Heap validation**: Ensuring heap indices are within valid bounds
//!
//! # Background
//!
//! According to ECMA-335 §II.22, each metadata table has a specific layout where
//! certain fields reference heaps:
//!
//! - **#Strings heap**: Type names, method names, field names, etc.
//! - **#Blob heap**: Signatures, custom attribute values, marshalling info
//! - **#GUID heap**: Module identifiers (MVIDs)
//!
//! The size of heap references (2 or 4 bytes) depends on the heap size,
//! determined by flags in the tables stream header.
//!
//! # Architecture
//!
//! The [`HeapFieldDescriptor`](crate::metadata::tablefields::HeapFieldDescriptor) describes a single heap reference field within a row.
//! The [`get_heap_fields`](crate::metadata::tablefields::get_heap_fields) function returns all heap fields for a given table type,
//! computing their byte offsets based on the table's size information.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    Table Row Layout                          │
//! ├──────────┬──────────┬──────────┬──────────┬──────────────────┤
//! │  Fixed   │  Coded   │  Heap    │  Heap    │     Other        │
//! │  Fields  │  Index   │  Ref 1   │  Ref 2   │     Fields       │
//! │  (known) │ (varies) │ (varies) │ (varies) │                  │
//! └──────────┴──────────┴──────────┴──────────┴──────────────────┘
//!                        ▲          ▲
//!                        │          │
//!                   HeapFieldDescriptor describes these
//! ```
//!
//! # Usage Examples
//!
//! ```no_run
//! use dotscope::metadata::tablefields::{get_heap_fields, HeapType};
//! use dotscope::metadata::tables::TableId;
//!
//! // Get heap fields for a TypeDef row
//! let fields = get_heap_fields(TableId::TypeDef, &table_info);
//!
//! for field in fields {
//!     match field.heap_type {
//!         HeapType::String => println!("String at offset {}", field.offset),
//!         HeapType::Blob => println!("Blob at offset {}", field.offset),
//!         HeapType::Guid => println!("GUID at offset {}", field.offset),
//!     }
//! }
//! ```

use crate::metadata::tables::{CodedIndexType, TableId, TableInfoRef};

/// Type of heap being referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeapType {
    /// #Strings heap (UTF-8 null-terminated strings)
    String,
    /// #Blob heap (length-prefixed binary data)
    Blob,
    /// #GUID heap (16-byte GUIDs with 1-based index)
    Guid,
}

/// Describes a heap reference field within a table row.
#[derive(Debug, Clone, Copy)]
pub struct HeapFieldDescriptor {
    /// Byte offset of this field within the row
    pub offset: usize,
    /// Size of the field in bytes (2 or 4)
    pub size: usize,
    /// Which heap this field references
    pub heap_type: HeapType,
}

/// Returns all heap reference fields for a given table type.
///
/// This is the single source of truth for table layouts regarding heap references.
/// The returned descriptors include computed byte offsets based on the table's
/// size information (which determines coded index sizes and heap reference sizes).
///
/// # Arguments
///
/// * `table_id` - The metadata table type
/// * `table_info` - Table size information for computing field offsets
///
/// # Returns
///
/// A vector of [`HeapFieldDescriptor`]s, one for each heap reference field in the table.
/// Tables without heap references return an empty vector.
///
/// # Table Coverage
///
/// This function handles all standard ECMA-335 metadata tables plus portable PDB tables.
/// Each table's field layout is documented inline with ECMA-335 section references.
#[must_use]
pub fn get_heap_fields(table_id: TableId, table_info: &TableInfoRef) -> Vec<HeapFieldDescriptor> {
    let str_size = if table_info.is_large_str() { 4 } else { 2 };
    let blob_size = if table_info.is_large_blob() { 4 } else { 2 };
    let guid_size = if table_info.is_large_guid() { 4 } else { 2 };

    let mut fields = Vec::new();

    match table_id {
        // §II.22.30 Module
        // Generation(2) + Name(str) + Mvid(guid) + EncId(guid) + EncBaseId(guid)
        TableId::Module => {
            let mut offset = 2; // Skip Generation
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
            offset = offset.saturating_add(guid_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
            offset = offset.saturating_add(guid_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
        }

        // §II.22.38 TypeRef
        // ResolutionScope(coded) + TypeName(str) + TypeNamespace(str)
        TableId::TypeRef => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::ResolutionScope) as usize;
            let mut offset = coded_size;
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.37 TypeDef
        // Flags(4) + TypeName(str) + TypeNamespace(str) + Extends(coded) + FieldList(rid) + MethodList(rid)
        TableId::TypeDef => {
            let mut offset = 4; // Skip Flags
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.15 Field: Flags(2) + Name(str) + Signature(blob)
        // §II.22.34 Property: Flags(2) + Name(str) + Type(blob)
        TableId::Field | TableId::Property => {
            let mut offset = 2; // Skip Flags
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.26 MethodDef
        // RVA(4) + ImplFlags(2) + Flags(2) + Name(str) + Signature(blob) + ParamList(rid)
        TableId::MethodDef => {
            let mut offset = 8; // Skip RVA + ImplFlags + Flags
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.33 Param: Flags(2) + Sequence(2) + Name(str)
        // LocalVariable: Attributes(2) + Index(2) + Name(str)
        TableId::Param | TableId::LocalVariable => {
            fields.push(HeapFieldDescriptor {
                offset: 4,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.25 MemberRef
        // Class(coded) + Name(str) + Signature(blob)
        TableId::MemberRef => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::MemberRefParent) as usize;
            let mut offset = coded_size;
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.9 Constant
        // Type(1+1padding) + Parent(coded) + Value(blob)
        TableId::Constant => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::HasConstant) as usize;
            fields.push(HeapFieldDescriptor {
                offset: 2usize.saturating_add(coded_size),
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.10 CustomAttribute
        // Parent(coded) + Type(coded) + Value(blob)
        TableId::CustomAttribute => {
            let parent_size =
                table_info.coded_index_bytes(CodedIndexType::HasCustomAttribute) as usize;
            let type_size =
                table_info.coded_index_bytes(CodedIndexType::CustomAttributeType) as usize;
            fields.push(HeapFieldDescriptor {
                offset: parent_size.saturating_add(type_size),
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.17 FieldMarshal
        // Parent(coded) + NativeType(blob)
        TableId::FieldMarshal => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::HasFieldMarshal) as usize;
            fields.push(HeapFieldDescriptor {
                offset: coded_size,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.11 DeclSecurity
        // Action(2) + Parent(coded) + PermissionSet(blob)
        TableId::DeclSecurity => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::HasDeclSecurity) as usize;
            fields.push(HeapFieldDescriptor {
                offset: 2usize.saturating_add(coded_size),
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.36 StandAloneSig: Signature(blob)
        // §II.22.39 TypeSpec: Signature(blob)
        TableId::StandAloneSig | TableId::TypeSpec => {
            fields.push(HeapFieldDescriptor {
                offset: 0,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.13 Event
        // EventFlags(2) + Name(str) + EventType(coded)
        TableId::Event => {
            fields.push(HeapFieldDescriptor {
                offset: 2,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.31 ModuleRef
        // Name(str)
        TableId::ModuleRef => {
            fields.push(HeapFieldDescriptor {
                offset: 0,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.22 ImplMap
        // MappingFlags(2) + MemberForwarded(coded) + ImportName(str) + ImportScope(rid)
        TableId::ImplMap => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::MemberForwarded) as usize;
            fields.push(HeapFieldDescriptor {
                offset: 2usize.saturating_add(coded_size),
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.2 Assembly
        // HashAlgId(4) + Version(8) + Flags(4) + PublicKey(blob) + Name(str) + Culture(str)
        TableId::Assembly => {
            let mut offset = 16; // Skip to PublicKey
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
            offset = offset.saturating_add(blob_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.5 AssemblyRef
        // Version(8) + Flags(4) + PublicKeyOrToken(blob) + Name(str) + Culture(str) + HashValue(blob)
        TableId::AssemblyRef => {
            let mut offset = 12; // Skip versions + Flags
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
            offset = offset.saturating_add(blob_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.19 File
        // Flags(4) + Name(str) + HashValue(blob)
        TableId::File => {
            let mut offset = 4; // Skip Flags
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // §II.22.14 ExportedType
        // Flags(4) + TypeDefId(4) + TypeName(str) + TypeNamespace(str) + Implementation(coded)
        TableId::ExportedType => {
            let mut offset = 8; // Skip Flags + TypeDefId
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.24 ManifestResource
        // Offset(4) + Flags(4) + Name(str) + Implementation(coded)
        TableId::ManifestResource => {
            fields.push(HeapFieldDescriptor {
                offset: 8,
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.20 GenericParam
        // Number(2) + Flags(2) + Owner(coded) + Name(str)
        TableId::GenericParam => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::TypeOrMethodDef) as usize;
            fields.push(HeapFieldDescriptor {
                offset: 4usize.saturating_add(coded_size),
                size: str_size,
                heap_type: HeapType::String,
            });
        }

        // §II.22.29 MethodSpec
        // Method(coded) + Instantiation(blob)
        TableId::MethodSpec => {
            let coded_size = table_info.coded_index_bytes(CodedIndexType::MethodDefOrRef) as usize;
            fields.push(HeapFieldDescriptor {
                offset: coded_size,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // Portable PDB tables (§III in PDB spec)

        // Document: Name(blob) + HashAlgorithm(guid) + Hash(blob) + Language(guid)
        TableId::Document => {
            let mut offset = 0;
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
            offset = offset.saturating_add(blob_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
            offset = offset.saturating_add(guid_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
            offset = offset.saturating_add(blob_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
        }

        // LocalConstant: Name(str) + Signature(blob)
        TableId::LocalConstant => {
            let mut offset = 0;
            fields.push(HeapFieldDescriptor {
                offset,
                size: str_size,
                heap_type: HeapType::String,
            });
            offset = offset.saturating_add(str_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // CustomDebugInformation: Parent(coded) + Kind(guid) + Value(blob)
        TableId::CustomDebugInformation => {
            let coded_size =
                table_info.coded_index_bytes(CodedIndexType::HasCustomDebugInformation) as usize;
            let mut offset = coded_size;
            fields.push(HeapFieldDescriptor {
                offset,
                size: guid_size,
                heap_type: HeapType::Guid,
            });
            offset = offset.saturating_add(guid_size);
            fields.push(HeapFieldDescriptor {
                offset,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // MethodDebugInformation: Document(Document index) + SequencePoints(blob)
        TableId::MethodDebugInformation => {
            fields.push(HeapFieldDescriptor {
                offset: table_info.table_index_bytes(TableId::Document) as usize,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // ImportScope: Parent(ImportScope index) + Imports(blob)
        TableId::ImportScope => {
            fields.push(HeapFieldDescriptor {
                offset: table_info.table_index_bytes(TableId::ImportScope) as usize,
                size: blob_size,
                heap_type: HeapType::Blob,
            });
        }

        // Tables without heap references
        TableId::FieldPtr
        | TableId::MethodPtr
        | TableId::ParamPtr
        | TableId::InterfaceImpl
        | TableId::ClassLayout
        | TableId::FieldLayout
        | TableId::EventMap
        | TableId::EventPtr
        | TableId::PropertyMap
        | TableId::PropertyPtr
        | TableId::MethodSemantics
        | TableId::MethodImpl
        | TableId::FieldRVA
        | TableId::EncLog
        | TableId::EncMap
        | TableId::AssemblyProcessor
        | TableId::AssemblyOS
        | TableId::AssemblyRefProcessor
        | TableId::AssemblyRefOS
        | TableId::NestedClass
        | TableId::GenericParamConstraint
        | TableId::LocalScope
        | TableId::StateMachineMethod => {
            // No heap references
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock TableInfoRef for testing with small heaps
    fn mock_table_info_small() -> TableInfoRef {
        // Create a mock that returns small heap sizes
        TableInfoRef::default()
    }

    #[test]
    fn test_module_heap_fields() {
        let info = mock_table_info_small();
        let fields = get_heap_fields(TableId::Module, &info);

        assert_eq!(fields.len(), 4);

        // Name (string)
        assert_eq!(fields[0].offset, 2);
        assert_eq!(fields[0].heap_type, HeapType::String);

        // Mvid, EncId, EncBaseId (GUIDs)
        assert_eq!(fields[1].heap_type, HeapType::Guid);
        assert_eq!(fields[2].heap_type, HeapType::Guid);
        assert_eq!(fields[3].heap_type, HeapType::Guid);
    }

    #[test]
    fn test_typedef_heap_fields() {
        let info = mock_table_info_small();
        let fields = get_heap_fields(TableId::TypeDef, &info);

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].offset, 4); // After Flags
        assert_eq!(fields[0].heap_type, HeapType::String); // TypeName
        assert_eq!(fields[1].heap_type, HeapType::String); // TypeNamespace
    }

    #[test]
    fn test_methoddef_heap_fields() {
        let info = mock_table_info_small();
        let fields = get_heap_fields(TableId::MethodDef, &info);

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].offset, 8); // After RVA(4) + ImplFlags(2) + Flags(2)
        assert_eq!(fields[0].heap_type, HeapType::String); // Name
        assert_eq!(fields[1].heap_type, HeapType::Blob); // Signature
    }

    #[test]
    fn test_table_without_heap_refs() {
        let info = mock_table_info_small();

        // InterfaceImpl has no heap references
        let fields = get_heap_fields(TableId::InterfaceImpl, &info);
        assert!(fields.is_empty());

        // NestedClass has no heap references
        let fields = get_heap_fields(TableId::NestedClass, &info);
        assert!(fields.is_empty());
    }
}

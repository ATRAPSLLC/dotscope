//! Raw `CustomDebugInformation` table representation for Portable PDB format.
//!
//! This module provides the [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRaw`] struct that represents
//! the binary format of `CustomDebugInformation` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices that require
//! resolution to access actual data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRaw`] - Raw binary representation with unresolved indices
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Clone`], enabling safe sharing
//! across threads and efficient copying when needed.

use std::sync::Arc;

use crate::{
    metadata::{
        customdebuginformation::{parse_custom_debug_blob, CustomDebugKind},
        streams::{Blob, Guid},
        tables::{
            types::{CodedIndex, CodedIndexType},
            CustomDebugInformation, CustomDebugInformationRc, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw binary representation of a `CustomDebugInformation` table entry
///
/// This structure matches the exact binary layout of `CustomDebugInformation` table
/// entries in the metadata tables stream. All fields contain unresolved indices
/// that must be resolved during conversion to the owned [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] variant.
///
/// # Binary Format
///
/// Each `CustomDebugInformation` table entry consists of:
/// - **Parent** (variable bytes): `HasCustomDebugInformation` coded index to the metadata element
/// - **Kind** (variable bytes): GUID heap index identifying the type of custom debug information
/// - **Value** (variable bytes): Blob heap index containing the custom debug information data
///
/// # Coded Index: `HasCustomDebugInformation`
///
/// The Parent field uses the `HasCustomDebugInformation` coded index which can reference:
/// - `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`, `Module`
/// - `DeclSecurity`, `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`, `Assembly`
/// - `AssemblyRef`, `File`, `ExportedType`, `ManifestResource`, `GenericParam`, `GenericParamConstraint`
/// - `MethodSpec`, `Document`, `LocalScope`, `LocalVariable`, `LocalConstant`, `ImportScope`
///
/// # Custom Debug Information Types
///
/// Common Kind GUIDs include:
/// - `{6DA9A61E-F8C7-4874-BE62-68BC5630DF71}`: State Machine Hoisted Local Scopes
/// - `{83C563C4-B4F3-47D5-B824-BA5441477EA8}`: Dynamic Local Variables
/// - `{58b2eab6-209f-4e4e-a22c-b2d0f910c782}`: Default Namespace (VB)
/// - `{755F52A8-91C5-45BE-B4B8-209571E552BD}`: Edit and Continue Local Slot Map
/// - `{A643004C-0240-496F-A783-30D64F4979DE}`: Edit and Continue Lambda and Closure Map
/// - `{0E8A571B-6926-466E-B4AD-8AB04611F5FE}`: Embedded Source
/// - `{CC110556-A091-4D38-9FEC-25AB9A351A6A}`: Source Link
///
/// # Constraints
///
/// - Table must be sorted by Parent column
/// - Multiple entries can have the same Parent (different kinds of debug info for same element)
/// - Each Kind GUID defines its own Value blob format
///
/// # References
///
/// - [Portable PDB Format - CustomDebugInformation Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37)
#[derive(Debug, Clone)]
pub struct CustomDebugInformationRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `CustomDebugInformation` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// `HasCustomDebugInformation` coded index to the metadata element
    ///
    /// References the metadata element (method, type, field, etc.) that this
    /// custom debug information is associated with. The coded index allows
    /// referencing various types of metadata elements.
    pub parent: CodedIndex,

    /// Index into GUID heap for the custom debug information type identifier
    ///
    /// The GUID identifies the specific type of custom debug information,
    /// which determines how to interpret the Value blob. Well-known GUIDs
    /// are defined by Microsoft compilers for common scenarios.
    pub kind: u32,

    /// Index into Blob heap containing the custom debug information data
    ///
    /// The format of this blob is determined by the Kind GUID. Each custom
    /// debug information type defines its own binary format for the data.
    pub value: u32,
}

impl CustomDebugInformationRaw {
    /// Converts this raw `CustomDebugInformation` entry to an owned [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] instance
    ///
    /// This method resolves the raw `CustomDebugInformation` entry to create a complete `CustomDebugInformation`
    /// object by resolving indices to actual data from the provided heaps and parsing the custom debug
    /// information blob into structured data.
    ///
    /// # Processing Steps
    /// 1. **Parent Resolution**: Resolves the `HasCustomDebugInformation` coded index to a type reference
    /// 2. **GUID Resolution**: Resolves the kind index to get the debug information type GUID
    /// 3. **Blob Resolution**: Resolves the value index to get the raw debug information blob
    /// 4. **Blob Parsing**: Parses the blob according to the GUID type to create structured debug information
    ///
    /// # Parameters
    /// - `get_ref`: Function to resolve coded indices to type references
    /// - `guid_heap`: Reference to the GUID heap for resolving the kind identifier
    /// - `blob_heap`: Reference to the blob heap for resolving the custom debug information data
    ///
    /// # Returns
    /// Returns `Ok(CustomDebugInformationRc)` with the resolved and parsed custom debug information,
    /// or an error if any heap reference cannot be resolved or blob parsing fails.
    ///
    /// # Parsing Behavior
    /// - **Known GUIDs**: Parsed into structured data (`SourceLink`, `EmbeddedSource`, etc.)
    /// - **Unknown GUIDs**: Preserved as raw data in Unknown variant for future processing
    /// - **Empty Blobs**: Handled gracefully with appropriate default values
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dotscope::metadata::tables::{CustomDebugInformationRaw, CodedIndex};
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::typesystem::CilTypeReference;
    /// use dotscope::metadata::streams::{Guid, Blob};
    /// use dotscope::Result;
    ///
    /// # fn example(
    /// #     get_ref: impl Fn(&CodedIndex) -> CilTypeReference,
    /// #     guid_heap: &Guid,
    /// #     blob_heap: &Blob
    /// # ) -> Result<()> {
    /// let custom_debug_raw = CustomDebugInformationRaw {
    ///     rid: 1,
    ///     token: Token::new(0x37000001),
    ///     offset: 0,
    ///     parent: CodedIndex { tag: dotscope::metadata::tables::TableId::MethodDef, row: 6, token: Token::new(0x06000006) },  // HasCustomDebugInformation coded index
    ///     kind: 1,        // GUID heap index pointing to Source Link GUID
    ///     value: 10,      // Blob heap index pointing to JSON data
    /// };
    ///
    /// let custom_debug = custom_debug_raw.to_owned(get_ref, guid_heap, blob_heap)?;
    /// // The value field now contains parsed CustomDebugInfo::SourceLink with structured JSON
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The GUID heap index is invalid or out of bounds
    /// - The blob heap index is invalid or out of bounds
    /// - The blob data cannot be parsed for known debug info types
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        guid_heap: &Guid,
        blob_heap: &Blob,
    ) -> Result<CustomDebugInformationRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let parent_ref = get_ref(&self.parent);
        let kind_guid = guid_heap.get(self.kind as usize)?;
        let value_data = blob_heap.get(self.value as usize)?;
        let debug_kind = CustomDebugKind::from_guid(kind_guid);
        let parsed_value = parse_custom_debug_blob(value_data, debug_kind)?;

        Ok(Arc::new(CustomDebugInformation {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent: parent_ref,
            parent_token: self.parent.token,
            kind: kind_guid,
            value: parsed_value,
        }))
    }
}

impl TableRow for CustomDebugInformationRaw {
    /// Calculate the binary size of one `CustomDebugInformation` table row
    ///
    /// Returns the total byte size of a single `CustomDebugInformation` table row based on the table
    /// configuration. The size varies depending on the size of coded indexes and heap indexes.
    ///
    /// # Size Breakdown
    /// - `parent`: Variable bytes (`HasCustomDebugInformation` coded index)
    /// - `kind`: Variable bytes (GUID heap index)
    /// - `value`: Variable bytes (Blob heap index)
    ///
    /// Total: Variable size depending on table index and heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */ sizes.coded_index_bytes(CodedIndexType::HasCustomDebugInformation)
            /* kind */   .saturating_add(sizes.guid_bytes())
            /* value */  .saturating_add(sizes.blob_bytes())

        )
    }
}

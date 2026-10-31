//! # Coded Index Types Module
//!
//! This module provides types and functionality for handling coded indices in .NET metadata tables.
//! Coded indices are a space-efficient encoding mechanism used in CLI metadata to reference
//! multiple possible table types using a single value.
//!
//! ## Overview
//!
//! Coded indices combine a table identifier and row index into a single value by using the
//! lower bits to encode which table type is being referenced, and the remaining bits for
//! the actual row index. This allows metadata to reference different types of entities
//! (e.g., `TypeDef`, `TypeRef`, or `TypeSpec`) using a unified format.
//!
//! ## Key Components
//!
//! - [`crate::metadata::tables::types::CodedIndexType`]: Enumeration of all possible coded index combinations defined in ECMA-335
//! - [`crate::metadata::tables::types::CodedIndex`]: Decoded representation containing the target table, row, and computed token
//!
//! ## References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Section II.24.2.6

use strum::{EnumCount, EnumIter};

use crate::{
    metadata::{
        tables::{TableId, TableInfo, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

/// Represents all possible coded index types defined in the CLI metadata specification.
///
/// A coded index type defines which combination of metadata tables can be referenced
/// by a particular coded index field. Each variant corresponds to a specific set of
/// tables that can be encoded together, allowing for space-efficient cross-references
/// within the metadata stream.
///
/// ## Encoding Scheme
///
/// Coded indices use the lower bits to encode the table type and the remaining bits
/// for the row index. The number of bits required for the table type depends on
/// how many tables are included in the combination.
///
/// ## Examples
///
/// - `TypeDefOrRef` can reference `TypeDef`, `TypeRef`, or `TypeSpec` tables
/// - `HasConstant` can reference `Field`, `Param`, or `Property` tables
/// - `HasCustomAttribute` can reference any of 22 different table types
///
/// ## Reference
///
/// - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Section II.24.2.6
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, EnumIter, EnumCount)]
#[repr(usize)]
pub enum CodedIndexType {
    /// References `TypeDef`, `TypeRef`, or `TypeSpec` tables.
    ///
    /// Used to identify type definitions, references, or specifications
    /// in a unified manner throughout the metadata.
    TypeDefOrRef,

    /// References `Field`, `Param`, or `Property` tables.
    ///
    /// Used to identify entities that can have constant values
    /// assigned to them.
    HasConstant,

    /// References any entity that can have custom attributes attached.
    ///
    /// This is the most comprehensive coded index type, supporting references to:
    /// `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`,
    /// `Module`, `Permission`, `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`,
    /// `Assembly`, `AssemblyRef`, `File`, `ExportedType`, `ManifestResource`, `GenericParam`,
    /// `GenericParamConstraint`, `MethodSpec`.
    HasCustomAttribute,

    /// References `Field` or `Param` tables.
    ///
    /// Used to identify entities that can have marshalling information
    /// for interop scenarios.
    HasFieldMarshal,

    /// References `TypeDef`, `MethodDef`, or `Assembly` tables.
    ///
    /// Used to identify entities that can have declarative security
    /// attributes applied.
    HasDeclSecurity,

    /// References `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef`, or `TypeSpec` tables.
    ///
    /// Used as the parent reference for member references.
    MemberRefParent,

    /// References `Event` or `Property` tables.
    ///
    /// Used to identify entities that can have semantic methods
    /// (getter, setter, etc.) associated with them.
    HasSemantics,

    /// References `MethodDef` or `MemberRef` tables.
    ///
    /// Used to reference method definitions or member references
    /// in a unified manner.
    MethodDefOrRef,

    /// References `Field` or `MethodDef` tables.
    ///
    /// Used to identify members that are forwarded to other assemblies.
    MemberForwarded,

    /// References `File`, `AssemblyRef`, or `ExportedType` tables.
    ///
    /// Used to specify the implementation location for exported types.
    Implementation,

    /// References `MethodDef` or `MemberRef` tables.
    ///
    /// Used to identify the constructor methods for custom attributes.
    /// Note: Some indices (0, 1, 4) are normally unused but supported
    /// by the encoding scheme.
    CustomAttributeType,

    /// References `Module`, `ModuleRef`, `AssemblyRef`, or `TypeRef` tables.
    ///
    /// Used to specify the scope in which a type reference should be resolved.
    ResolutionScope,

    /// References `TypeDef` or `MethodDef` tables.
    ///
    /// Used to reference either type or method definitions in contexts
    /// where both are valid targets.
    TypeOrMethodDef,

    /// References any entity that can have custom debug information attached.
    ///
    /// This coded index supports references to various metadata tables for Portable PDB
    /// custom debug information. According to the Portable PDB specification, this can
    /// reference any of the following tables:
    /// `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`,
    /// `Module`, `DeclSecurity`, `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`,
    /// `Assembly`, `AssemblyRef`, `File`, `ExportedType`, `ManifestResource`, `GenericParam`,
    /// `GenericParamConstraint`, `MethodSpec`, `Document`, `LocalScope`, `LocalVariable`,
    /// `LocalConstant`, `ImportScope`.
    HasCustomDebugInformation,
}

impl CodedIndexType {
    /// Returns the array of table IDs that can be referenced by this coded index type.
    ///
    /// This method provides the lookup table that defines which metadata tables
    /// can be encoded using this particular coded index type. The order of tables
    /// in the returned slice corresponds to the encoded tag values (0, 1, 2, etc.),
    /// except for `CustomAttributeType`, whose tags 0 and 1 are unused (see
    /// [`CodedIndexType::table_for_tag`]).
    ///
    /// ## Returns
    ///
    /// A static slice containing the [`crate::metadata::tables::types::TableId`] values that can be referenced
    /// by this coded index type, in encoding order.
    #[must_use]
    pub fn tables(&self) -> &'static [TableId] {
        match self {
            CodedIndexType::TypeDefOrRef => {
                &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
            }
            CodedIndexType::HasConstant => &[TableId::Field, TableId::Param, TableId::Property],
            CodedIndexType::HasCustomAttribute => &[
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity, // In the standard PDF, this is wrongly labeled as 'Permission' (although no such table exists)
                TableId::Property,
                TableId::Event,
                TableId::StandAloneSig,
                TableId::ModuleRef,
                TableId::TypeSpec,
                TableId::Assembly,
                TableId::AssemblyRef,
                TableId::File,
                TableId::ExportedType,
                TableId::ManifestResource,
                TableId::GenericParam,
                TableId::GenericParamConstraint,
                TableId::MethodSpec,
            ],
            CodedIndexType::HasFieldMarshal => &[TableId::Field, TableId::Param],
            CodedIndexType::HasDeclSecurity => {
                &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly]
            }
            CodedIndexType::MemberRefParent => &[
                TableId::TypeDef,
                TableId::TypeRef,
                TableId::ModuleRef,
                TableId::MethodDef,
                TableId::TypeSpec,
            ],
            CodedIndexType::HasSemantics => &[TableId::Event, TableId::Property],
            CodedIndexType::MethodDefOrRef => &[TableId::MethodDef, TableId::MemberRef],
            CodedIndexType::MemberForwarded => &[TableId::Field, TableId::MethodDef],
            CodedIndexType::Implementation => {
                &[TableId::File, TableId::AssemblyRef, TableId::ExportedType]
            }
            // Tags 2 and 3; tags 0, 1 and 4 are unused (see `table_for_tag`).
            CodedIndexType::CustomAttributeType => &[TableId::MethodDef, TableId::MemberRef],
            CodedIndexType::ResolutionScope => &[
                TableId::Module,
                TableId::ModuleRef,
                TableId::AssemblyRef,
                TableId::TypeRef,
            ],
            CodedIndexType::TypeOrMethodDef => &[TableId::TypeDef, TableId::MethodDef],
            CodedIndexType::HasCustomDebugInformation => &[
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity,
                TableId::Property,
                TableId::Event,
                TableId::StandAloneSig,
                TableId::ModuleRef,
                TableId::TypeSpec,
                TableId::Assembly,
                TableId::AssemblyRef,
                TableId::File,
                TableId::ExportedType,
                TableId::ManifestResource,
                TableId::GenericParam,
                TableId::GenericParamConstraint,
                TableId::MethodSpec,
                TableId::Document,
                TableId::LocalScope,
                TableId::LocalVariable,
                TableId::LocalConstant,
                TableId::ImportScope,
            ],
        }
    }

    /// The number of tag values this coded index defines, unused ones included.
    ///
    /// Only `CustomAttributeType` has unused tags: of its five, 0, 1 and 4 name no table
    /// (ECMA-335 II.24.2.6). Every other coded index assigns its tags to
    /// [`CodedIndexType::tables`] in order.
    #[must_use]
    pub fn tag_count(&self) -> usize {
        match self {
            CodedIndexType::CustomAttributeType => 5,
            _ => self.tables().len(),
        }
    }

    /// The table `tag` names, or `None` for a tag this coded index assigns to no table.
    #[must_use]
    pub fn table_for_tag(&self, tag: u32) -> Option<TableId> {
        match self {
            CodedIndexType::CustomAttributeType => match tag {
                2 => Some(TableId::MethodDef),
                3 => Some(TableId::MemberRef),
                _ => None,
            },
            _ => self.tables().get(tag as usize).copied(),
        }
    }

    /// The tag naming `table`, or `None` if this coded index cannot name that table.
    #[must_use]
    pub fn tag_for_table(&self, table: TableId) -> Option<u32> {
        match self {
            CodedIndexType::CustomAttributeType => match table {
                TableId::MethodDef => Some(2),
                TableId::MemberRef => Some(3),
                _ => None,
            },
            _ => self
                .tables()
                .iter()
                .position(|&t| t == table)
                .and_then(|tag| u32::try_from(tag).ok()),
        }
    }

    /// The number of low bits of a stored value that hold its tag: enough for every tag,
    /// unused ones included.
    #[must_use]
    pub fn tag_bits(&self) -> u8 {
        let tags = self.tag_count();
        // Bits for values 0..tags: the position of the highest set bit of tags - 1, plus one.
        let highest = u32::try_from(tags.saturating_sub(1)).unwrap_or(u32::MAX);
        u8::try_from(u32::BITS.saturating_sub(highest.leading_zeros()))
            .unwrap_or(u8::MAX)
            .max(1)
    }
}

/// A decoded representation of a coded index value.
///
/// This structure contains the decoded components of a coded index, providing
/// direct access to the target table, row index, computed metadata token, and
/// the coded index type information. Coded indices are space-efficient encodings
/// that combine table type and row information into a single value.
///
/// ## Fields
///
/// - `tag`: The specific metadata table being referenced
/// - `row`: The 1-based row index within that table
/// - `token`: The computed metadata token for direct table access
/// - `ci_type`: The coded index type defining allowed target tables
#[derive(Clone, Debug, PartialEq)]
pub struct CodedIndex {
    /// The [`TableId`] this index is referring to.
    ///
    /// Specifies which metadata table contains the referenced entity.
    pub tag: TableId,

    /// The row ID that this `CodedIndex` is pointing to.
    ///
    /// This is a 1-based index into the specified table. Row 0 is reserved
    /// and typically indicates a null reference.
    pub row: u32,

    /// The computed metadata token for this coded index.
    ///
    /// The token combines the table type (in the upper bits) with the row index
    /// (in the lower bits) to create a unique identifier that can be used
    /// for direct table lookups.
    pub token: Token,

    /// The coded index type defining which tables are valid targets.
    ///
    /// This field provides access to the coded index type information, allowing
    /// validation code to determine which tables are valid targets by calling
    /// `ci_type.tables()` instead of manually specifying allowed tables.
    pub ci_type: CodedIndexType,

    /// The stored value, when its tag is one `ci_type` assigns to no table; `None` for an
    /// index that decodes normally.
    ///
    /// The CLR reads such an index as a null reference, and so does this one: `row` is 0.
    /// The value is kept so that validation can report it, and so that [`Self::encode`]
    /// writes back what was read; making it null is a change of its own.
    pub unassigned_tag: Option<u32>,
}

impl CodedIndex {
    /// Reads and decodes a coded index from a byte buffer.
    ///
    /// This method reads a coded index value from the provided buffer, automatically
    /// determining whether to read 2 or 4 bytes based on the table size requirements,
    /// then decodes the value into its constituent table and row components.
    ///
    /// ## Arguments
    ///
    /// * `data` - The byte buffer to read from
    /// * `offset` - Mutable reference to the current read position (updated after reading)
    /// * `info` - Table information reference for size calculations and decoding
    /// * `ci_type` - The specific coded index type to decode
    ///
    /// ## Returns
    ///
    /// Returns a [`crate::Result`] containing the decoded [`crate::metadata::tables::types::CodedIndex`] on success.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The buffer is too small to read the required bytes
    /// - The coded index value is invalid or references a non-existent table/row
    /// - The table information is inconsistent or corrupted
    pub fn read(
        data: &[u8],
        offset: &mut usize,
        info: &TableInfoRef,
        ci_type: CodedIndexType,
    ) -> Result<Self> {
        let size_needed = info.coded_index_bits(ci_type);
        let coded_index = if size_needed > 16 {
            read_le_at::<u32>(data, offset)?
        } else {
            u32::from(read_le_at::<u16>(data, offset)?)
        };

        Ok(match info.decode_coded_index(coded_index, ci_type) {
            Some((tag, row)) => CodedIndex::new(tag, row, ci_type),
            // A stored 0 is null for every coded index: for `CustomAttributeType`, whose tag 0
            // names no table, it is one with an unassigned tag, kept so it writes back as 0
            None => CodedIndex {
                unassigned_tag: Some(coded_index),
                ..CodedIndex::null(ci_type)
            },
        })
    }

    /// Creates a new `CodedIndex` with the specified table, row, and coded index type.
    ///
    /// This method constructs a new coded index by combining the table identifier,
    /// row index, and coded index type information, automatically computing the
    /// appropriate metadata token based on the ECMA-335 token encoding scheme.
    ///
    /// ## Arguments
    ///
    /// * `tag` - The [`crate::metadata::tables::types::TableId`] specifying which metadata table is being referenced
    /// * `row` - The 1-based row index within the specified table
    /// * `ci_type` - The [`crate::metadata::tables::types::CodedIndexType`] defining the valid target tables
    ///
    /// ## Returns
    ///
    /// A new [`crate::metadata::tables::types::CodedIndex`] instance with the computed token and type information.
    ///
    /// ## Token Encoding
    ///
    /// The token is computed by combining the table-specific prefix (upper 8 bits)
    /// with the row index (lower 24 bits). Each table type has a predefined token
    /// prefix as defined in the ECMA-335 specification.
    #[must_use]
    pub fn new(tag: TableId, row: u32, ci_type: CodedIndexType) -> CodedIndex {
        CodedIndex {
            tag,
            row,
            ci_type,
            token: Token::from_parts(tag, row),
            unassigned_tag: None,
        }
    }

    /// The value this index is stored as in a column `info` sizes: its table's tag and its
    /// row, or for an index read with an unassigned tag, the value it was read as.
    ///
    /// A value with an unassigned tag that does not fit the column (one read from a 4-byte
    /// column, written to a 2-byte one) keeps its tag with row 0: still a tag that names no
    /// table, still read as null.
    ///
    /// # Errors
    ///
    /// When the table is not one this coded index can name, or the row does not fit.
    pub fn encode(&self, info: &TableInfo) -> Result<u32> {
        let Some(stored) = self.unassigned_tag else {
            return info.encode_coded_index(self.tag, self.row, self.ci_type);
        };
        if info.coded_index_bits(self.ci_type) > 16 || stored <= u32::from(u16::MAX) {
            return Ok(stored);
        }
        let tag_mask = 1u32
            .checked_shl(u32::from(self.ci_type.tag_bits()))
            .map_or(u32::MAX, |bound| bound.saturating_sub(1));
        Ok(stored & tag_mask)
    }

    /// Creates a null (empty) `CodedIndex` for the specified coded index type.
    ///
    /// A null coded index represents the absence of a reference, encoded as 0 in the
    /// binary format per ECMA-335. This is commonly used for:
    /// - TypeDef.Extends field for `System.Object` and interfaces (no base class)
    /// - Optional cross-references that may not be present
    ///
    /// ## Arguments
    ///
    /// * `ci_type` - The [`CodedIndexType`] defining the context for the null reference
    ///
    /// ## Returns
    ///
    /// A [`CodedIndex`] with row 0 and the first table in the coded index type's table list
    /// as the tag, which encodes to 0 in the binary format.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use crate::metadata::tables::{CodedIndex, CodedIndexType};
    ///
    /// // Create a null TypeDefOrRef (no base class)
    /// let null_extends = CodedIndex::null(CodedIndexType::TypeDefOrRef);
    /// assert!(null_extends.is_null());
    /// ```
    #[must_use]
    pub fn null(ci_type: CodedIndexType) -> CodedIndex {
        // Row 0 is the null reference whichever table. The first table has tag 0, so the null
        // reference encodes to 0, except for `CustomAttributeType`, whose first table
        // (MethodDef) has tag 2; a stored 0 still reads as null there (see `read`).
        let first_table = ci_type
            .tables()
            .first()
            .copied()
            .unwrap_or(TableId::TypeDef);
        CodedIndex::new(first_table, 0, ci_type)
    }

    /// Returns `true` if this coded index represents a null reference.
    ///
    /// A coded index is null when its row is 0, indicating no target row.
    /// Per ECMA-335, row 0 is reserved and indicates a null/empty reference.
    ///
    /// ## Returns
    ///
    /// `true` if the row index is 0 (null reference), `false` otherwise.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.row == 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strum::IntoEnumIterator;

    use super::*;
    use crate::metadata::tables::TableInfo;

    /// A table layout with two-byte coded indices for every type.
    fn small() -> TableInfoRef {
        Arc::new(TableInfo::new_test(&[], false, false, false))
    }

    /// Reads `value` as a two-byte coded index of `ci_type`.
    fn read(value: u16, ci_type: CodedIndexType) -> CodedIndex {
        CodedIndex::read(&value.to_le_bytes(), &mut 0, &small(), ci_type).unwrap()
    }

    /// The tag widths ECMA-335 II.24.2.6 gives each coded index.
    #[test]
    fn every_coded_index_uses_the_tag_bits_ecma_335_gives_it() {
        for (ci_type, bits) in [
            (CodedIndexType::TypeDefOrRef, 2),
            (CodedIndexType::HasConstant, 2),
            (CodedIndexType::HasCustomAttribute, 5),
            (CodedIndexType::HasFieldMarshal, 1),
            (CodedIndexType::HasDeclSecurity, 2),
            (CodedIndexType::MemberRefParent, 3),
            (CodedIndexType::HasSemantics, 1),
            (CodedIndexType::MethodDefOrRef, 1),
            (CodedIndexType::MemberForwarded, 1),
            (CodedIndexType::Implementation, 2),
            (CodedIndexType::CustomAttributeType, 3),
            (CodedIndexType::ResolutionScope, 2),
            (CodedIndexType::TypeOrMethodDef, 1),
            (CodedIndexType::HasCustomDebugInformation, 5),
        ] {
            assert_eq!(ci_type.tag_bits(), bits, "{ci_type:?}");
        }
    }

    /// Every table a coded index names round-trips through its tag, at several rows.
    #[test]
    fn every_named_table_round_trips_through_its_tag() {
        let info = small();
        for ci_type in CodedIndexType::iter() {
            for &table in ci_type.tables() {
                for row in [1, 2, 0x7F] {
                    let value = info.encode_coded_index(table, row, ci_type).unwrap();
                    assert_eq!(
                        info.decode_coded_index(value, ci_type),
                        Some((table, row)),
                        "{ci_type:?} {table:?} row {row}"
                    );
                }
            }
        }
    }

    /// CustomAttributeType's tags 2 and 3 name MethodDef and MemberRef; 0, 1 and 4 name
    /// nothing (II.24.2.6).
    #[test]
    fn custom_attribute_type_tags_2_and_3_name_methoddef_and_memberref() {
        let ci_type = CodedIndexType::CustomAttributeType;
        let info = small();
        assert_eq!(
            info.encode_coded_index(TableId::MethodDef, 5, ci_type)
                .unwrap(),
            5 << 3 | 2
        );
        assert_eq!(
            info.encode_coded_index(TableId::MemberRef, 5, ci_type)
                .unwrap(),
            5 << 3 | 3
        );
        for tag in [0, 1, 4] {
            assert_eq!(
                info.decode_coded_index(5 << 3 | tag, ci_type),
                None,
                "tag {tag}"
            );
        }
    }

    /// A tag that names no table reads as the null reference, as the CLR reads it, and keeps
    /// the stored value, which it writes back: a stored 0 of `CustomAttributeType`, whose
    /// tag 0 names no table, too.
    #[test]
    fn a_tag_naming_no_table_reads_as_null_and_keeps_the_stored_value() {
        // ConfuserEx's DeclSecurity parent: HasDeclSecurity has three tables, tag 3 is unused.
        let parent = read(0x7FFF, CodedIndexType::HasDeclSecurity);
        assert_eq!(parent.row, 0);
        assert_eq!(parent.unassigned_tag, Some(0x7FFF));

        let constructor = read(5 << 3 | 4, CodedIndexType::CustomAttributeType);
        assert_eq!(constructor.row, 0);
        assert_eq!(constructor.unassigned_tag, Some(5 << 3 | 4));

        let null = read(0, CodedIndexType::CustomAttributeType);
        assert_eq!(null.row, 0);
        assert_eq!(null.unassigned_tag, Some(0));

        let info = TableInfo::new_test(&[], false, false, false);
        for (stored, ci_type) in [
            (0x7FFF, CodedIndexType::HasDeclSecurity),
            (5 << 3 | 4, CodedIndexType::CustomAttributeType),
            (0, CodedIndexType::CustomAttributeType),
        ] {
            assert_eq!(
                read(stored, ci_type).encode(&info).unwrap(),
                u32::from(stored),
                "{ci_type:?}"
            );
        }

        let named = read(5 << 3 | 2, CodedIndexType::CustomAttributeType);
        assert_eq!((named.tag, named.row), (TableId::MethodDef, 5));
        assert_eq!(named.unassigned_tag, None);
    }
}

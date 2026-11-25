//! Implementation of `RowWritable` for `MemberRefRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `MemberRef` table (ID 0x0A),
//! enabling writing of external member reference metadata back to .NET PE files. The MemberRef table
//! defines references to methods and fields that are defined in other assemblies or modules.
//!
//! ## Table Structure (ECMA-335 §II.22.25)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Class` | `MemberRefParent` coded index | Declaring type or module reference |
//! | `Name` | String heap index | Member name identifier |
//! | `Signature` | Blob heap index | Member signature (method or field) |
//!
//! ## MemberRefParent Coded Index
//!
//! The `Class` field uses the `MemberRefParent` coded index to reference:
//! - `TypeDef` (current assembly types)
//! - `TypeRef` (external assembly types)
//! - `ModuleRef` (external modules)
//! - `MethodDef` (vararg method signatures)
//! - `TypeSpec` (generic type instantiations)

use crate::{
    metadata::tables::{
        memberref::MemberRefRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for MemberRefRaw {
    /// Serialize a MemberRef table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.25 specification:
    /// - `class`: `MemberRefParent` coded index (declaring type/module)
    /// - `name`: String heap index (member name)
    /// - `signature`: Blob heap index (member signature)
    ///
    /// # Arguments
    /// * `data` - Target buffer for writing binary data
    /// * `offset` - Current write position (updated after write)
    /// * `rid` - Row identifier (unused in this implementation)
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// `Ok(())` on successful write, error on buffer overflow or encoding failure
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write MemberRefParent coded index
        let class_value = self.class.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            class_value,
            sizes.coded_index_bits(CodedIndexType::MemberRefParent) > 16,
        )?;

        // Write string heap index for name
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write blob heap index for signature
        write_le_at_dyn(data, offset, self.signature, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            memberref::MemberRefRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_memberref_row_size() {
        // Test with small heap and table sizes
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2; // MemberRefParent(2) + name(2) + signature(2)
        assert_eq!(<MemberRefRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large heap sizes
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            true,
            true,
            true,
        ));

        let expected_size_large = 2 + 4 + 4; // MemberRefParent(2) + name(4) + signature(4)
        assert_eq!(
            <MemberRefRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_memberref_row_write_small_heaps() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let member_ref = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeRef, 42, CodedIndexType::MemberRefParent), // TypeRef table, index 42
            name: 0x1234,
            signature: 0x5678,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        member_ref
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // class: TypeRef(42) encoded as (42 << 3) | 1 = 337 = 0x0151
        let expected = vec![
            0x51, 0x01, // class: 0x0151, little-endian
            0x34, 0x12, // name: 0x1234, little-endian
            0x78, 0x56, // signature: 0x5678, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_memberref_row_write_large_heaps() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            true,
            true,
            true,
        ));

        let member_ref = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeRef, 1000, CodedIndexType::MemberRefParent), // TypeRef table, large index
            name: 0x12345678,
            signature: 0xABCDEF01,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        member_ref
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // class: TypeRef(1000) encoded as (1000 << 3) | 1 = 8001 = 0x1F41
        let expected = vec![
            0x41, 0x1F, // class: 0x1F41, little-endian
            0x78, 0x56, 0x34, 0x12, // name: 0x12345678, little-endian
            0x01, 0xEF, 0xCD, 0xAB, // signature: 0xABCDEF01, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_memberref_round_trip_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let original = MemberRefRaw {
            rid: 42,
            token: Token::new(0x0A00002A),
            offset: 0,
            class: CodedIndex::new(TableId::TypeDef, 15, CodedIndexType::MemberRefParent),
            name: 0x00AA,
            signature: 0x00BB,
        };

        // Write to buffer
        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = MemberRefRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.class, read_back.class);
        assert_eq!(original.name, read_back.name);
        assert_eq!(original.signature, read_back.signature);
    }

    #[test]
    fn test_memberref_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_member = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::MemberRefParent),
            name: 0,
            signature: 0,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_member
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Should be all zeros
        assert_eq!(buffer, vec![0; buffer.len()]);

        // Test with maximum values for 2-byte indexes
        let max_member = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeDef, 0x1FFF, CodedIndexType::MemberRefParent), // Max for MemberRefParent
            name: 0xFFFF,
            signature: 0xFFFF,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_member
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // All 2-byte fields
    }

    #[test]
    fn test_memberref_different_coded_index_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        // Test TypeDef reference (tag 0)
        let typedef_ref = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(TableId::TypeDef, 10, CodedIndexType::MemberRefParent),
            name: 0x1000,
            signature: 0x2000,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        typedef_ref
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify TypeDef encoding: (10 << 3) | 0 = 80 = 0x50
        assert_eq!(buffer[0], 0x50);
        assert_eq!(buffer[1], 0x00);

        // Test TypeRef reference (tag 1)
        let typeref_ref = MemberRefRaw {
            rid: 2,
            token: Token::new(0x0A000002),
            offset: 0,
            class: CodedIndex::new(TableId::TypeRef, 10, CodedIndexType::MemberRefParent),
            name: 0x1000,
            signature: 0x2000,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        typeref_ref
            .row_write(&mut buffer, &mut offset, 2, &sizes)
            .unwrap();

        // Verify TypeRef encoding: (10 << 3) | 1 = 81 = 0x51
        assert_eq!(buffer[0], 0x51);
        assert_eq!(buffer[1], 0x00);
    }

    #[test]
    fn test_memberref_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        let member_ref = MemberRefRaw {
            rid: 1,
            token: Token::new(0x0A000001),
            offset: 0,
            class: CodedIndex::new(
                TableId::TypeRef,
                0x0101 >> 3,
                CodedIndexType::MemberRefParent,
            ), // From test data
            name: 0x0202,
            signature: 0x0303,
        };

        let mut buffer = vec![0u8; <MemberRefRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        member_ref
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test
        let expected = vec![
            0x01, 0x01, // class
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        assert_eq!(buffer, expected);
    }
}

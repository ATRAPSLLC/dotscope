//! Implementation of `RowWritable` for `CustomAttributeRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `CustomAttribute` table (ID 0x0C),
//! enabling writing of custom attribute metadata back to .NET PE files. The CustomAttribute table
//! defines custom attributes applied to various metadata elements throughout the assembly.
//!
//! ## Table Structure (ECMA-335 §II.22.10)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Parent` | `HasCustomAttribute` coded index | Target metadata element |
//! | `Type` | `CustomAttributeType` coded index | Constructor method reference |
//! | `Value` | Blob heap index | Serialized attribute arguments |
//!
//! ## Coded Index Types
//!
//! - **HasCustomAttribute**: References metadata elements that can have custom attributes
//! - **CustomAttributeType**: References the constructor method (`MethodDef` or `MemberRef`)

use crate::{
    metadata::tables::{
        customattribute::CustomAttributeRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for CustomAttributeRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent.encode(sizes)?, 0)))
    }

    /// Serialize a CustomAttribute table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.10 specification:
    /// - `parent`: `HasCustomAttribute` coded index (target element)
    /// - `constructor`: `CustomAttributeType` coded index (constructor method)
    /// - `value`: Blob heap index (serialized arguments)
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
        // Write HasCustomAttribute coded index for parent
        let parent_value = self.parent.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            parent_value,
            sizes.coded_index_bits(CodedIndexType::HasCustomAttribute) > 16,
        )?;

        // Write CustomAttributeType coded index for constructor
        let constructor_value = self.constructor.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            constructor_value,
            sizes.coded_index_bits(CodedIndexType::CustomAttributeType) > 16,
        )?;

        // Write blob heap index for value
        write_le_at_dyn(data, offset, self.value, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            customattribute::CustomAttributeRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_customattribute_row_size() {
        // Test with small heap and table sizes
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2; // HasCustomAttribute(2) + CustomAttributeType(2) + value(2)
        assert_eq!(
            <CustomAttributeRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large heap sizes
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            true,
            true,
            true,
        ));

        let expected_size_large = 2 + 2 + 4; // HasCustomAttribute(2) + CustomAttributeType(2) + value(4)
        assert_eq!(
            <CustomAttributeRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_customattribute_row_write_small_heaps() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let custom_attr = CustomAttributeRaw {
            rid: 1,
            token: Token::new(0x0C000001),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeDef, 42, CodedIndexType::HasCustomAttribute), // TypeDef table, index 42
            constructor: CodedIndex::new(
                TableId::MethodDef,
                15,
                CodedIndexType::CustomAttributeType,
            ), // MethodDef table, index 15
            value: 0x1234,
        };

        let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        custom_attr
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // parent: TypeDef(42) has HasCustomAttribute tag 3, so (42 << 5) | 3 = 1347 = 0x0543
        // constructor: MethodDef(15) has CustomAttributeType tag 2 (per ECMA-335), so (15 << 3) | 2 = 122 = 0x007A
        let expected = vec![
            0x43, 0x05, // parent: 0x0543, little-endian
            0x7A, 0x00, // constructor: 0x007A, little-endian
            0x34, 0x12, // value: 0x1234, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_customattribute_row_write_large_heaps() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            true,
            true,
            true,
        ));

        let custom_attr = CustomAttributeRaw {
            rid: 1,
            token: Token::new(0x0C000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Assembly, 5, CodedIndexType::HasCustomAttribute), // Assembly table, index 5
            constructor: CodedIndex::new(
                TableId::MemberRef,
                25,
                CodedIndexType::CustomAttributeType,
            ), // MemberRef table, index 25
            value: 0x12345678,
        };

        let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        custom_attr
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // parent: Assembly(5) has HasCustomAttribute tag 14, so (5 << 5) | 14 = 174 = 0x00AE
        // constructor: MemberRef(25) has CustomAttributeType tag 3, so (25 << 3) | 3 = 203 = 0x00CB
        let expected = vec![
            0xAE, 0x00, // parent: 0x00AE, little-endian
            0xCB, 0x00, // constructor: 0x00CB, little-endian
            0x78, 0x56, 0x34, 0x12, // value: 0x12345678, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_customattribute_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let original = CustomAttributeRaw {
            rid: 42,
            token: Token::new(0x0C00002A),
            offset: 0,
            parent: CodedIndex::new(TableId::Field, 10, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                20,
                CodedIndexType::CustomAttributeType,
            ),
            value: 0x5678,
        };

        // Write to buffer
        let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back =
            CustomAttributeRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.constructor, read_back.constructor);
        assert_eq!(original.value, read_back.value);
    }

    #[test]
    fn test_customattribute_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_attr = CustomAttributeRaw {
            rid: 1,
            token: Token::new(0x0C000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Assembly, 0, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                0,
                CodedIndexType::CustomAttributeType,
            ),
            value: 0,
        };

        let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_attr
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Parent and constructor should still encode their tags even with zero rows
        // parent: Assembly(0) has HasCustomAttribute tag 14, so (0 << 5) | 14 = 14 = 0x000E
        // constructor: MethodDef(0) has CustomAttributeType tag 2 (per ECMA-335), so (0 << 3) | 2 = 2 = 0x0002
        let expected = vec![
            0x0E, 0x00, // parent: 0x000E, little-endian
            0x02, 0x00, // constructor: 0x0002, little-endian
            0x00, 0x00, // value: 0x0000, little-endian
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_customattribute_different_coded_index_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test various parent types with HasCustomAttribute coded index
        let test_cases = vec![
            (TableId::MethodDef, 10, 0), // MethodDef: (10 << 5) | 0 = 320 = 0x0140
            (TableId::Field, 15, 1),     // Field: (15 << 5) | 1 = 481 = 0x01E1
            (TableId::TypeRef, 20, 2),   // TypeRef: (20 << 5) | 2 = 642 = 0x0282
            (TableId::TypeDef, 25, 3),   // TypeDef: (25 << 5) | 3 = 803 = 0x0323
        ];

        for (table_id, row, expected_tag) in test_cases {
            let custom_attr = CustomAttributeRaw {
                rid: 1,
                token: Token::new(0x0C000001),
                offset: 0,
                parent: CodedIndex::new(table_id, row, CodedIndexType::HasCustomAttribute),
                constructor: CodedIndex::new(
                    TableId::MethodDef,
                    5,
                    CodedIndexType::CustomAttributeType,
                ),
                value: 0x1000,
            };

            let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            custom_attr
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify parent encoding
            let expected_parent = (row << 5) | expected_tag;
            let actual_parent = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(actual_parent, expected_parent as u16);
        }
    }

    #[test]
    fn test_customattribute_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        let custom_attr = CustomAttributeRaw {
            rid: 1,
            token: Token::new(0x0C000001),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeRef, 16, CodedIndexType::HasCustomAttribute), // From test data: 0x0202 = 514 = (16 << 5) | 2
            constructor: CodedIndex::new(
                TableId::MemberRef,
                96,
                CodedIndexType::CustomAttributeType,
            ), // From test data: 0x0303 = 771 = (96 << 3) | 3
            value: 0x0404,
        };

        let mut buffer = vec![0u8; <CustomAttributeRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        custom_attr
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test
        let expected = vec![
            0x02, 0x02, // parent
            0x03, 0x03, // constructor
            0x04, 0x04, // value
        ];

        assert_eq!(buffer, expected);
    }
}

//! Implementation of `RowWritable` for `ConstantRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `Constant` table (ID 0x0B),
//! enabling writing of constant value information back to .NET PE files. The Constant table
//! stores literal constant values for fields, parameters, and properties, supporting type
//! safety and compile-time constant folding optimizations.
//!
//! ## Table Structure (ECMA-335 §II.22.9)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Type` | u8 | Element type of the constant (`ELEMENT_TYPE_*` enumeration) |
//! | `Padding` | u8 | Reserved padding byte (must be zero) |
//! | `Parent` | `HasConstant` coded index | Field, Property, or Param reference |
//! | `Value` | Blob heap index | Binary representation of the constant value |
//!
//! ## Coded Index Types
//!
//! The Parent field uses the `HasConstant` coded index which can reference:
//! - **Tag 0 (Field)**: References Field table entries for field constants
//! - **Tag 1 (Param)**: References Param table entries for parameter default values
//! - **Tag 2 (Property)**: References Property table entries for property constants

use crate::{
    metadata::tables::{
        constant::ConstantRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ConstantRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent.encode(sizes)?, 0)))
    }

    /// Serialize a Constant table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.9 specification:
    /// - `base`: 1-byte element type (`ELEMENT_TYPE_*` enumeration)
    /// - `padding`: 1-byte reserved padding (must be zero)
    /// - `parent`: `HasConstant` coded index (field, param, or property reference)
    /// - `value`: Blob heap index (binary constant value data)
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
        // Write element type (1 byte)
        write_le_at(data, offset, self.base)?;

        // Write padding byte (1 byte, zero unless the row was read with another)
        write_le_at(data, offset, self.padding)?;

        // Write HasConstant coded index for parent
        let parent_value = self.parent.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            parent_value,
            sizes.coded_index_bits(CodedIndexType::HasConstant) > 16,
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
            constant::ConstantRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_constant_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 1 + 1 + 2 + 2; // base(1) + padding(1) + parent(2) + value(2)
        assert_eq!(<ConstantRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 0x10000),
                (TableId::Param, 0x10000),
                (TableId::Property, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let expected_size_large = 1 + 1 + 4 + 4; // base(1) + padding(1) + parent(4) + value(4)
        assert_eq!(
            <ConstantRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_constant_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        let constant = ConstantRaw {
            rid: 1,
            token: Token::new(0x0B000001),
            offset: 0,
            base: 0x01,
            padding: 0,
            parent: CodedIndex::new(TableId::Property, 128, CodedIndexType::HasConstant), // Property(128) = (128 << 2) | 2 = 514
            value: 0x0303,
        };

        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        constant
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, // base: 0x01
            0x00, // padding: 0x00
            0x02,
            0x02, // parent: Property(128) -> (128 << 2) | 2 = 514 = 0x0202, little-endian
            0x03, 0x03, // value: 0x0303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_constant_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 0x10000),
                (TableId::Param, 0x10000),
                (TableId::Property, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let constant = ConstantRaw {
            rid: 1,
            token: Token::new(0x0B000001),
            offset: 0,
            base: 0x01,
            padding: 0,
            parent: CodedIndex::new(TableId::Property, 0x808080, CodedIndexType::HasConstant), // Property(0x808080) = (0x808080 << 2) | 2 = 0x2020202
            value: 0x03030303,
        };

        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        constant
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, // base: 0x01
            0x00, // padding: 0x00
            0x02, 0x02, 0x02,
            0x02, // parent: Property(0x808080) -> (0x808080 << 2) | 2 = 0x2020202, little-endian
            0x03, 0x03, 0x03, 0x03, // value: 0x03030303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_constant_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        let original = ConstantRaw {
            rid: 42,
            token: Token::new(0x0B00002A),
            offset: 0,
            base: 0x08, // ELEMENT_TYPE_I4
            padding: 0,
            parent: CodedIndex::new(TableId::Field, 25, CodedIndexType::HasConstant), // Field(25) = (25 << 2) | 0 = 100
            value: 128, // Blob index 128
        };

        // Write to buffer
        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = ConstantRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.base, read_back.base);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.value, read_back.value);
    }

    #[test]
    fn test_constant_different_parent_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        // Test different HasConstant coded index types
        let test_cases = vec![
            (TableId::Field, 1, 0x08, 0x100),    // Field reference, I4 constant
            (TableId::Param, 1, 0x0E, 0x200),    // Param reference, String constant
            (TableId::Property, 1, 0x0C, 0x300), // Property reference, R8 constant
            (TableId::Field, 50, 0x05, 0x400),   // Different field, I2 constant
            (TableId::Param, 25, 0x06, 0x500),   // Different param, I4 constant
        ];

        for (parent_tag, parent_row, element_type, blob_index) in test_cases {
            let constant = ConstantRaw {
                rid: 1,
                token: Token::new(0x0B000001),
                offset: 0,
                base: element_type,
                padding: 0,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasConstant),
                value: blob_index,
            };

            let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constant
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = ConstantRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(constant.base, read_back.base);
            assert_eq!(constant.parent, read_back.parent);
            assert_eq!(constant.value, read_back.value);
        }
    }

    #[test]
    fn test_constant_element_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        // Test different common element types for constants
        let element_type_cases = vec![
            (0x02, "ELEMENT_TYPE_BOOLEAN"),
            (0x03, "ELEMENT_TYPE_CHAR"),
            (0x04, "ELEMENT_TYPE_I1"),
            (0x05, "ELEMENT_TYPE_U1"),
            (0x06, "ELEMENT_TYPE_I2"),
            (0x07, "ELEMENT_TYPE_U2"),
            (0x08, "ELEMENT_TYPE_I4"),
            (0x09, "ELEMENT_TYPE_U4"),
            (0x0A, "ELEMENT_TYPE_I8"),
            (0x0B, "ELEMENT_TYPE_U8"),
            (0x0C, "ELEMENT_TYPE_R4"),
            (0x0D, "ELEMENT_TYPE_R8"),
            (0x0E, "ELEMENT_TYPE_STRING"),
            (0x12, "ELEMENT_TYPE_CLASS"), // For null references
        ];

        for (element_type, _description) in element_type_cases {
            let constant = ConstantRaw {
                rid: 1,
                token: Token::new(0x0B000001),
                offset: 0,
                base: element_type,
                padding: 0,
                parent: CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant),
                value: 100,
            };

            let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constant
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the element type is written correctly
            assert_eq!(buffer[0], element_type);
            // Verify padding is zero
            assert_eq!(buffer[1], 0x00);
        }
    }

    #[test]
    fn test_constant_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_constant = ConstantRaw {
            rid: 1,
            token: Token::new(0x0B000001),
            offset: 0,
            base: 0,
            padding: 0,
            parent: CodedIndex::new(TableId::Field, 0, CodedIndexType::HasConstant), // Field(0) = (0 << 2) | 0 = 0
            value: 0,
        };

        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_constant
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, // base: 0
            0x00, // padding: 0
            0x00, 0x00, // parent: Field(0) -> (0 << 2) | 0 = 0
            0x00, 0x00, // value: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_constant = ConstantRaw {
            rid: 1,
            token: Token::new(0x0B000001),
            offset: 0,
            base: 0xFF,
            padding: 0,
            parent: CodedIndex::new(TableId::Property, 0x3FFF, CodedIndexType::HasConstant), // Max for 2-byte coded index
            value: 0xFFFF,
        };

        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_constant
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // 1 + 1 + 2 + 2 bytes
    }

    #[test]
    fn test_constant_padding_always_zero() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::Param, 50),
                (TableId::Property, 25),
            ],
            false,
            false,
            false,
        ));

        // Test multiple constants to ensure padding is always written as zero
        let test_constants = vec![
            (0x08, TableId::Field, 1, 100),
            (0x0E, TableId::Param, 2, 200),
            (0x0C, TableId::Property, 3, 300),
            (0x12, TableId::Field, 4, 400),
        ];

        for (element_type, parent_tag, parent_row, blob_index) in test_constants {
            let constant = ConstantRaw {
                rid: 1,
                token: Token::new(0x0B000001),
                offset: 0,
                base: element_type,
                padding: 0,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasConstant),
                value: blob_index,
            };

            let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constant
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Always verify padding byte is zero
            assert_eq!(buffer[1], 0x00, "Padding byte must always be zero");
        }
    }

    #[test]
    fn test_constant_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));

        let constant = ConstantRaw {
            rid: 1,
            token: Token::new(0x0B000001),
            offset: 0,
            base: 0x01,
            padding: 0,
            parent: CodedIndex::new(TableId::Property, 128, CodedIndexType::HasConstant), // Property(128) = (128 << 2) | 2 = 514 = 0x0202
            value: 0x0303,
        };

        let mut buffer = vec![0u8; <ConstantRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        constant
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, // type
            0x00, // padding
            0x02, 0x02, // parent
            0x03, 0x03, // value
        ];

        assert_eq!(buffer, expected);
    }
}

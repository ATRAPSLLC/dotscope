//! Implementation of `RowWritable` for `FieldLayoutRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `FieldLayout` table (ID 0x10),
//! enabling writing of field layout information back to .NET PE files. The FieldLayout table
//! specifies explicit field positioning within types that use explicit layout, commonly used
//! for interoperability scenarios and performance-critical data structures.
//!
//! ## Table Structure (ECMA-335 §II.22.16)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Offset` | u32 | Field offset within the containing type |
//! | `Field` | Field table index | Field that this layout applies to |
//!
//! ## Layout Context
//!
//! FieldLayout entries are created for types with explicit layout control:
//! - **C# StructLayout(LayoutKind.Explicit)**: Explicitly positioned fields
//! - **P/Invoke types**: Matching native struct layouts
//! - **Performance types**: Cache-line aligned data structures

use crate::{
    metadata::tables::{
        fieldlayout::FieldLayoutRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for FieldLayoutRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.field, 0)))
    }

    ///
    /// Serialize a FieldLayout table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.16 specification:
    /// - `field_offset`: 4-byte explicit field offset within type
    /// - `field`: Field table index (field requiring explicit positioning)
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
        // Write field offset (4 bytes)
        write_le_at(data, offset, self.field_offset)?;

        // Write Field table index
        write_le_at_dyn(data, offset, self.field, sizes.is_large(TableId::Field))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            fieldlayout::FieldLayoutRaw,
            types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_fieldlayout_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let expected_size = 4 + 2; // field_offset(4) + field(2)
        assert_eq!(
            <FieldLayoutRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // field_offset(4) + field(4)
        assert_eq!(
            <FieldLayoutRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_fieldlayout_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let field_layout = FieldLayoutRaw {
            rid: 1,
            token: Token::new(0x10000001),
            offset: 0,
            field_offset: 0x01010101,
            field: 0x0202,
        };

        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // field_offset: 0x01010101, little-endian
            0x02, 0x02, // field: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldlayout_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000)],
            false,
            false,
            false,
        ));

        let field_layout = FieldLayoutRaw {
            rid: 1,
            token: Token::new(0x10000001),
            offset: 0,
            field_offset: 0x01010101,
            field: 0x02020202,
        };

        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // field_offset: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // field: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldlayout_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let original = FieldLayoutRaw {
            rid: 42,
            token: Token::new(0x1000002A),
            offset: 0,
            field_offset: 16, // 16-byte offset
            field: 25,        // Field index 25
        };

        // Write to buffer
        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = FieldLayoutRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.field_offset, read_back.field_offset);
        assert_eq!(original.field, read_back.field);
    }

    #[test]
    fn test_fieldlayout_different_offsets() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test different common field offset values
        let test_cases = vec![
            (0, 1),   // First field at offset 0
            (4, 2),   // 4-byte aligned field
            (8, 3),   // 8-byte aligned field
            (16, 4),  // 16-byte aligned field
            (32, 5),  // Cache-line aligned field
            (64, 6),  // 64-byte aligned field
            (128, 7), // Large offset
            (256, 8), // Very large offset
        ];

        for (field_offset, field_index) in test_cases {
            let field_layout = FieldLayoutRaw {
                rid: 1,
                token: Token::new(0x10000001),
                offset: 0,
                field_offset,
                field: field_index,
            };

            let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_layout
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = FieldLayoutRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(field_layout.field_offset, read_back.field_offset);
            assert_eq!(field_layout.field, read_back.field);
        }
    }

    #[test]
    fn test_fieldlayout_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_layout = FieldLayoutRaw {
            rid: 1,
            token: Token::new(0x10000001),
            offset: 0,
            field_offset: 0,
            field: 0,
        };

        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, 0x00, 0x00, // field_offset: 0
            0x00, 0x00, // field: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for the field sizes
        let max_layout = FieldLayoutRaw {
            rid: 1,
            token: Token::new(0x10000001),
            offset: 0,
            field_offset: 0xFFFFFFFF,
            field: 0xFFFF,
        };

        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // 4 + 2 bytes
    }

    #[test]
    fn test_fieldlayout_alignment_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test common alignment scenarios for explicit layout
        let alignment_cases = vec![
            (0, 1),  // No padding - starts at beginning
            (1, 2),  // Byte-aligned field
            (2, 3),  // 2-byte aligned field (Int16)
            (4, 4),  // 4-byte aligned field (Int32, float)
            (8, 5),  // 8-byte aligned field (Int64, double)
            (16, 6), // 16-byte aligned field (SIMD types)
            (32, 7), // Cache-line aligned field
            (48, 8), // Packed structure field
            (63, 9), // Odd offset for packed layout
        ];

        for (field_offset, field_index) in alignment_cases {
            let field_layout = FieldLayoutRaw {
                rid: 1,
                token: Token::new(0x10000001),
                offset: 0,
                field_offset,
                field: field_index,
            };

            let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_layout
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the field offset is written correctly
            let written_offset = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            assert_eq!(written_offset, field_offset);

            // Verify the field index is written correctly
            let written_field = u16::from_le_bytes([buffer[4], buffer[5]]);
            assert_eq!(written_field as u32, field_index);
        }
    }

    #[test]
    fn test_fieldlayout_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));

        let field_layout = FieldLayoutRaw {
            rid: 1,
            token: Token::new(0x10000001),
            offset: 0,
            field_offset: 0x01010101,
            field: 0x0202,
        };

        let mut buffer = vec![0u8; <FieldLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        field_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // field_offset
            0x02, 0x02, // field
        ];

        assert_eq!(buffer, expected);
    }
}

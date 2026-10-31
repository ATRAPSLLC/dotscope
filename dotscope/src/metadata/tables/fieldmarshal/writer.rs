//! Implementation of `RowWritable` for `FieldMarshalRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `FieldMarshal` table (ID 0x0D),
//! enabling writing of field marshalling information back to .NET PE files. The FieldMarshal table
//! specifies marshalling behavior for fields and parameters when crossing managed/unmanaged
//! boundaries during interop operations.
//!
//! ## Table Structure (ECMA-335 §II.22.17)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Parent` | `HasFieldMarshal` coded index | Field or Param reference |
//! | `NativeType` | Blob heap index | Marshalling signature |
//!
//! ## Coded Index Types
//!
//! The Parent field uses the `HasFieldMarshal` coded index which can reference:
//! - **Tag 0 (Field)**: References Field table entries for field marshalling
//! - **Tag 1 (Param)**: References Param table entries for parameter marshalling

use crate::{
    metadata::tables::{
        fieldmarshal::FieldMarshalRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for FieldMarshalRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent.encode(sizes)?, 0)))
    }

    ///
    /// Serialize a FieldMarshal table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.17 specification:
    /// - `parent`: `HasFieldMarshal` coded index (Field or Param reference)
    /// - `native_type`: Blob heap index (marshalling signature)
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
        // Write HasFieldMarshal coded index for parent
        let parent_value = self.parent.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            parent_value,
            sizes.coded_index_bits(CodedIndexType::HasFieldMarshal) > 16,
        )?;

        // Write blob heap index for native_type
        write_le_at_dyn(data, offset, self.native_type, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            fieldmarshal::FieldMarshalRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_fieldmarshal_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // parent(2) + native_type(2)
        assert_eq!(
            <FieldMarshalRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000), (TableId::Param, 0x10000)],
            true,
            true,
            true,
        ));

        let expected_size_large = 4 + 4; // parent(4) + native_type(4)
        assert_eq!(
            <FieldMarshalRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_fieldmarshal_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        let field_marshal = FieldMarshalRaw {
            rid: 1,
            token: Token::new(0x0D000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Field, 257, CodedIndexType::HasFieldMarshal), // Field(257) = (257 << 1) | 0 = 514
            native_type: 0x0303,
        };

        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_marshal
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x02, 0x02, // parent: Field(257) -> (257 << 1) | 0 = 514 = 0x0202, little-endian
            0x03, 0x03, // native_type: 0x0303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldmarshal_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000), (TableId::Param, 0x10000)],
            true,
            true,
            true,
        ));

        let field_marshal = FieldMarshalRaw {
            rid: 1,
            token: Token::new(0x0D000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Field, 0x1010101, CodedIndexType::HasFieldMarshal), // Field(0x1010101) = (0x1010101 << 1) | 0 = 0x2020202
            native_type: 0x03030303,
        };

        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_marshal
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x02, 0x02, 0x02,
            0x02, // parent: Field(0x1010101) -> (0x1010101 << 1) | 0 = 0x2020202, little-endian
            0x03, 0x03, 0x03, 0x03, // native_type: 0x03030303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldmarshal_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        let original = FieldMarshalRaw {
            rid: 42,
            token: Token::new(0x0D00002A),
            offset: 0,
            parent: CodedIndex::new(TableId::Param, 25, CodedIndexType::HasFieldMarshal), // Param(25) = (25 << 1) | 1 = 51
            native_type: 128,
        };

        // Write to buffer
        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = FieldMarshalRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.native_type, read_back.native_type);
    }

    #[test]
    fn test_fieldmarshal_different_parent_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        // Test different HasFieldMarshal coded index types
        let test_cases = vec![
            (TableId::Field, 1, 0x100),  // Field reference
            (TableId::Param, 1, 0x200),  // Param reference
            (TableId::Field, 50, 0x300), // Different field
            (TableId::Param, 25, 0x400), // Different param
        ];

        for (parent_tag, parent_row, native_type) in test_cases {
            let field_marshal = FieldMarshalRaw {
                rid: 1,
                token: Token::new(0x0D000001),
                offset: 0,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasFieldMarshal),
                native_type,
            };

            let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_marshal
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                FieldMarshalRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(field_marshal.parent, read_back.parent);
            assert_eq!(field_marshal.native_type, read_back.native_type);
        }
    }

    #[test]
    fn test_fieldmarshal_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_marshal = FieldMarshalRaw {
            rid: 1,
            token: Token::new(0x0D000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Field, 0, CodedIndexType::HasFieldMarshal), // Field(0) = (0 << 1) | 0 = 0
            native_type: 0,
        };

        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_marshal
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // parent: Field(0) -> (0 << 1) | 0 = 0
            0x00, 0x00, // native_type: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_marshal = FieldMarshalRaw {
            rid: 1,
            token: Token::new(0x0D000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Param, 0x7FFF, CodedIndexType::HasFieldMarshal), // Max for 2-byte coded index
            native_type: 0xFFFF,
        };

        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_marshal
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_fieldmarshal_marshalling_signatures() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100), (TableId::Param, 50)],
            false,
            false,
            false,
        ));

        // Test different common marshalling signature blob indexes
        let marshalling_cases = vec![
            (TableId::Field, 1, 1),   // Basic field marshalling
            (TableId::Param, 2, 100), // String marshalling
            (TableId::Field, 3, 200), // Array marshalling
            (TableId::Param, 4, 300), // Custom marshaller
            (TableId::Field, 5, 400), // COM interface marshalling
            (TableId::Param, 6, 500), // Function pointer marshalling
        ];

        for (parent_tag, parent_row, blob_index) in marshalling_cases {
            let field_marshal = FieldMarshalRaw {
                rid: 1,
                token: Token::new(0x0D000001),
                offset: 0,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasFieldMarshal),
                native_type: blob_index,
            };

            let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_marshal
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the blob index is written correctly
            let written_blob = u16::from_le_bytes([buffer[2], buffer[3]]);
            assert_eq!(written_blob as u32, blob_index);
        }
    }

    #[test]
    fn test_fieldmarshal_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::Param, 1)],
            false,
            false,
            false,
        ));

        let field_marshal = FieldMarshalRaw {
            rid: 1,
            token: Token::new(0x0D000001),
            offset: 0,
            parent: CodedIndex::new(TableId::Field, 257, CodedIndexType::HasFieldMarshal), // Field(257) = (257 << 1) | 0 = 514 = 0x0202
            native_type: 0x0303,
        };

        let mut buffer = vec![0u8; <FieldMarshalRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        field_marshal
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x02, 0x02, // parent
            0x03, 0x03, // native_type
        ];

        assert_eq!(buffer, expected);
    }
}

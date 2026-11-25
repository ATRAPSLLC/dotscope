//! Implementation of `RowWritable` for `FieldRvaRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `FieldRva` table (ID 0x1D),
//! enabling writing of field RVA (Relative Virtual Address) information back to .NET PE files.
//! The FieldRva table specifies memory locations for fields that have initial data stored
//! directly in the PE file, supporting static initialization and embedded data scenarios.
//!
//! ## Table Structure (ECMA-335 §II.22.19)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `RVA` | u32 | Relative Virtual Address pointing to field data |
//! | `Field` | Field table index | Field that has initial data at the RVA |
//!
//! ## Usage Context
//!
//! FieldRva entries are used for:
//! - **Static arrays**: Pre-initialized array data embedded in PE file
//! - **Constant data**: Read-only data embedded in executable sections
//! - **Global variables**: Module-level data with specific initial states
//! - **Resource embedding**: Binary resources accessible through field references

use crate::{
    metadata::tables::{
        fieldrva::FieldRvaRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for FieldRvaRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.field, 0)))
    }

    /// Serialize a FieldRva table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.19 specification:
    /// - `rva`: 4-byte Relative Virtual Address pointing to field data
    /// - `field`: Field table index (field that has initial data)
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
        // Write RVA (4 bytes)
        write_le_at(data, offset, self.rva)?;

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
            fieldrva::FieldRvaRaw,
            types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_fieldrva_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let expected_size = 4 + 2; // rva(4) + field(2)
        assert_eq!(<FieldRvaRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // rva(4) + field(4)
        assert_eq!(
            <FieldRvaRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_fieldrva_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let field_rva = FieldRvaRaw {
            rid: 1,
            token: Token::new(0x1D000001),
            offset: 0,
            rva: 0x01010101,
            field: 0x0202,
        };

        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_rva
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // rva: 0x01010101, little-endian
            0x02, 0x02, // field: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldrva_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 0x10000)],
            false,
            false,
            false,
        ));

        let field_rva = FieldRvaRaw {
            rid: 1,
            token: Token::new(0x1D000001),
            offset: 0,
            rva: 0x01010101,
            field: 0x02020202,
        };

        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        field_rva
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // rva: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // field: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_fieldrva_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        let original = FieldRvaRaw {
            rid: 42,
            token: Token::new(0x1D00002A),
            offset: 0,
            rva: 0x12345678, // Example RVA
            field: 25,       // Field index 25
        };

        // Write to buffer
        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = FieldRvaRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.rva, read_back.rva);
        assert_eq!(original.field, read_back.field);
    }

    #[test]
    fn test_fieldrva_different_rvas() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test different common RVA values
        let test_cases = vec![
            (0x00001000, 1), // Typical code section start
            (0x00002000, 2), // Data section start
            (0x00004000, 3), // Resource section start
            (0x12345678, 4), // Example RVA
            (0xABCDEF00, 5), // High memory RVA
            (0x00000400, 6), // Low memory RVA
            (0xFFFFFFFF, 7), // Maximum RVA value
            (0x00000000, 8), // Zero RVA (unusual but valid)
        ];

        for (rva_value, field_index) in test_cases {
            let field_rva = FieldRvaRaw {
                rid: 1,
                token: Token::new(0x1D000001),
                offset: 0,
                rva: rva_value,
                field: field_index,
            };

            let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_rva
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = FieldRvaRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(field_rva.rva, read_back.rva);
            assert_eq!(field_rva.field, read_back.field);
        }
    }

    #[test]
    fn test_fieldrva_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_rva = FieldRvaRaw {
            rid: 1,
            token: Token::new(0x1D000001),
            offset: 0,
            rva: 0,
            field: 0,
        };

        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_rva
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, 0x00, 0x00, // rva: 0
            0x00, 0x00, // field: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values
        let max_rva = FieldRvaRaw {
            rid: 1,
            token: Token::new(0x1D000001),
            offset: 0,
            rva: 0xFFFFFFFF,
            field: 0xFFFF,
        };

        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_rva
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // 4 + 2 bytes
    }

    #[test]
    fn test_fieldrva_section_alignment() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test RVAs that are typically aligned to section boundaries
        let alignment_cases = vec![
            (0x00001000, 1), // 4KB aligned (typical section alignment)
            (0x00002000, 2), // 8KB aligned
            (0x00004000, 3), // 16KB aligned
            (0x00008000, 4), // 32KB aligned
            (0x00010000, 5), // 64KB aligned (typical large section)
            (0x00020000, 6), // 128KB aligned
            (0x00040000, 7), // 256KB aligned
            (0x00080000, 8), // 512KB aligned
        ];

        for (aligned_rva, field_index) in alignment_cases {
            let field_rva = FieldRvaRaw {
                rid: 1,
                token: Token::new(0x1D000001),
                offset: 0,
                rva: aligned_rva,
                field: field_index,
            };

            let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_rva
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the RVA is written correctly
            let written_rva = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            assert_eq!(written_rva, aligned_rva);

            // Verify the field index is written correctly
            let written_field = u16::from_le_bytes([buffer[4], buffer[5]]);
            assert_eq!(written_field as u32, field_index);
        }
    }

    #[test]
    fn test_fieldrva_pe_context() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 100)],
            false,
            false,
            false,
        ));

        // Test RVAs that correspond to typical PE file scenarios
        let pe_scenarios = vec![
            (0x00001000, 1, "Code section start"),
            (0x00002000, 2, "Data section start"),
            (0x00003000, 3, "Resources section start"),
            (0x00004000, 4, "Import table location"),
            (0x00005000, 5, "Export table location"),
            (0x00010000, 6, "Large data array"),
            (0x00020000, 7, "Embedded resource"),
            (0x00040000, 8, "Debug information"),
        ];

        for (rva, field_index, _description) in pe_scenarios {
            let field_rva = FieldRvaRaw {
                rid: field_index,
                token: Token::new(0x1D000000 + field_index),
                offset: 0,
                rva,
                field: field_index,
            };

            let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            field_rva
                .row_write(&mut buffer, &mut offset, field_index, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                FieldRvaRaw::row_read(&buffer, &mut read_offset, field_index, &sizes).unwrap();

            assert_eq!(field_rva.rva, read_back.rva);
            assert_eq!(field_rva.field, read_back.field);
        }
    }

    #[test]
    fn test_fieldrva_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::FieldRVA, 1), (TableId::Field, 10)],
            false,
            false,
            false,
        ));

        let field_rva = FieldRvaRaw {
            rid: 1,
            token: Token::new(0x1D000001),
            offset: 0,
            rva: 0x01010101,
            field: 0x0202,
        };

        let mut buffer = vec![0u8; <FieldRvaRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        field_rva
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // field
        ];

        assert_eq!(buffer, expected);
    }
}

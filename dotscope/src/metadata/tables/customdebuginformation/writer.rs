//! Writer implementation for `CustomDebugInformation` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`CustomDebugInformationRaw`] struct, enabling serialization of custom debug
//! information rows back to binary format. This supports Portable PDB generation
//! and assembly modification scenarios where custom debug information needs to be
//! preserved or modified.
//!
//! # Binary Format
//!
//! Each `CustomDebugInformation` row consists of three fields:
//! - `parent` (2/4 bytes): HasCustomDebugInformation coded index for the metadata element
//! - `kind` (2/4 bytes): GUID heap index identifying the debug information type
//! - `value` (2/4 bytes): Blob heap index containing the debug information data
//!
//! # Row Layout
//!
//! `CustomDebugInformation` table rows are serialized with this binary structure:
//! - Parent coded index (2 or 4 bytes, depending on referenced table sizes)
//! - Kind GUID heap index (2 or 4 bytes, depending on GUID heap size)
//! - Value blob heap index (2 or 4 bytes, depending on blob heap size)
//! - Total row size varies based on heap and table sizes
//!
//! # Custom Debug Information Context
//!
//! Custom debug information entries store compiler-specific debugging data that
//! extends the standard Portable PDB format. Common types include source linking
//! information, embedded sources, and dynamic local variable mappings.
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual heap and table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::customdebuginformation::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        customdebuginformation::CustomDebugInformationRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for CustomDebugInformationRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent.encode(sizes)?, 0)))
    }

    /// Write a `CustomDebugInformation` table row to binary data
    ///
    /// Serializes one `CustomDebugInformation` table entry to the metadata tables stream format, handling
    /// variable-width coded indexes and heap indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this custom debug information entry (unused for `CustomDebugInformation`)
    /// * `sizes` - Table sizing information for writing coded indexes and heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized custom debug information row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Parent HasCustomDebugInformation coded index (2/4 bytes, little-endian)
    /// 2. Kind GUID heap index (2/4 bytes, little-endian)
    /// 3. Value blob heap index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write HasCustomDebugInformation coded index
        let parent_value = self.parent.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            parent_value,
            sizes.coded_index_bits(CodedIndexType::HasCustomDebugInformation) > 16,
        )?;

        // Write GUID heap index
        write_le_at_dyn(data, offset, self.kind, sizes.is_large_guid())?;

        // Write blob heap index
        write_le_at_dyn(data, offset, self.value, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        tables::{
            types::{CodedIndex, CodedIndexType, RowReadable, TableInfo, TableRow},
            TableId,
        },
        token::Token,
    };

    #[test]
    fn test_round_trip_serialization_small_heaps() {
        // Create test data with small heaps and tables
        let original_row = CustomDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3700_0001),
            offset: 0,
            parent: CodedIndex::new(
                TableId::MethodDef,
                42,
                CodedIndexType::HasCustomDebugInformation,
            ),
            kind: 15,
            value: 200,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 100),
                (TableId::MethodDef, 1000),
            ],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            CustomDebugInformationRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.parent.tag, deserialized_row.parent.tag);
        assert_eq!(original_row.parent.row, deserialized_row.parent.row);
        assert_eq!(original_row.kind, deserialized_row.kind);
        assert_eq!(original_row.value, deserialized_row.value);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_heaps() {
        // Create test data with large heaps and tables
        let original_row = CustomDebugInformationRaw {
            rid: 2,
            token: Token::new(0x3700_0002),
            offset: 0,
            parent: CodedIndex::new(
                TableId::TypeDef,
                12345,
                CodedIndexType::HasCustomDebugInformation,
            ),
            kind: 0x12345,
            value: 0x54321,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 10000),
                (TableId::TypeDef, 100000),
                (TableId::MethodDef, 100000),
            ],
            true,
            true,
            true,
        ));

        // Calculate buffer size and serialize
        let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            CustomDebugInformationRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.parent.tag, deserialized_row.parent.tag);
        assert_eq!(original_row.parent.row, deserialized_row.parent.row);
        assert_eq!(original_row.kind, deserialized_row.kind);
        assert_eq!(original_row.value, deserialized_row.value);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_heaps() {
        // Test with specific binary layout for small heaps
        let custom_debug_info = CustomDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3700_0001),
            offset: 0,
            parent: CodedIndex::new(
                TableId::MemberRef,
                0,
                CodedIndexType::HasCustomDebugInformation,
            ),
            kind: 0x0001,
            value: 0x000A,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 100),
                (TableId::MethodDef, 1000),
                (TableId::MemberRef, 1000),
            ],
            false,
            false,
            false,
        ));

        let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        custom_debug_info
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 6, "Row size should be 6 bytes for small heaps");

        // Parent coded index (0x0006) as little-endian
        assert_eq!(buffer[0], 0x06);
        assert_eq!(buffer[1], 0x00);

        // Kind GUID heap index (0x0001) as little-endian
        assert_eq!(buffer[2], 0x01);
        assert_eq!(buffer[3], 0x00);

        // Value blob heap index (0x000A) as little-endian
        assert_eq!(buffer[4], 0x0A);
        assert_eq!(buffer[5], 0x00);
    }

    #[test]
    fn test_known_binary_format_large_heaps() {
        // Test with specific binary layout for large heaps
        let custom_debug_info = CustomDebugInformationRaw {
            rid: 1,
            token: Token::new(0x3700_0001),
            offset: 0,
            parent: CodedIndex::new(
                TableId::MemberRef,
                8,
                CodedIndexType::HasCustomDebugInformation,
            ),
            kind: 0x00000101,
            value: 0x0000020A,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::CustomDebugInformation, 10000),
                (TableId::MethodDef, 100000),
                (TableId::MemberRef, 100000),
            ],
            true,
            true,
            true,
        ));

        let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        custom_debug_info
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 12, "Row size should be 12 bytes for large heaps");

        // Parent coded index (0x00000106) as little-endian
        assert_eq!(buffer[0], 0x06);
        assert_eq!(buffer[1], 0x01);
        assert_eq!(buffer[2], 0x00);
        assert_eq!(buffer[3], 0x00);

        // Kind GUID heap index (0x00000101) as little-endian
        assert_eq!(buffer[4], 0x01);
        assert_eq!(buffer[5], 0x01);
        assert_eq!(buffer[6], 0x00);
        assert_eq!(buffer[7], 0x00);

        // Value blob heap index (0x0000020A) as little-endian
        assert_eq!(buffer[8], 0x0A);
        assert_eq!(buffer[9], 0x02);
        assert_eq!(buffer[10], 0x00);
        assert_eq!(buffer[11], 0x00);
    }

    #[test]
    fn test_various_coded_index_types() {
        // Test with different types of HasCustomDebugInformation coded indices
        let test_cases = vec![
            (TableId::MethodDef, 1), // Method debug info
            (TableId::TypeDef, 5),   // Type debug info
            (TableId::Field, 10),    // Field debug info
            (TableId::Property, 15), // Property debug info
            (TableId::Event, 20),    // Event debug info
        ];

        for (table_id, row) in test_cases {
            let custom_debug_info = CustomDebugInformationRaw {
                rid: 1,
                token: Token::new(0x3700_0001),
                offset: 0,
                parent: CodedIndex::new(table_id, row, CodedIndexType::HasCustomDebugInformation),
                kind: 100,
                value: 200,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[
                    (TableId::CustomDebugInformation, 100),
                    (TableId::MethodDef, 1000),
                    (TableId::TypeDef, 1000),
                    (TableId::Field, 1000),
                    (TableId::Property, 1000),
                    (TableId::Event, 1000),
                ],
                false,
                false,
                false,
            ));
            let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            custom_debug_info
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                CustomDebugInformationRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(custom_debug_info.parent.tag, deserialized_row.parent.tag);
            assert_eq!(custom_debug_info.parent.row, deserialized_row.parent.row);
            assert_eq!(custom_debug_info.kind, deserialized_row.kind);
            assert_eq!(custom_debug_info.value, deserialized_row.value);
        }
    }

    #[test]
    fn test_common_debug_info_scenarios() {
        // Test with typical debug information scenarios
        let test_cases = vec![
            ("Source Link", 1, 100),          // Source linking information
            ("Embedded Source", 2, 500),      // Embedded source files
            ("Dynamic Locals", 3, 50),        // Dynamic local variables
            ("State Machine Scopes", 4, 150), // Async/await scope info
            ("Edit and Continue", 5, 25),     // Edit and continue data
        ];

        for (name, kind, value) in test_cases {
            let custom_debug_info = CustomDebugInformationRaw {
                rid: 1,
                token: Token::new(0x3700_0001),
                offset: 0,
                parent: CodedIndex::new(
                    TableId::MethodDef,
                    100,
                    CodedIndexType::HasCustomDebugInformation,
                ),
                kind,
                value,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[
                    (TableId::CustomDebugInformation, 100),
                    (TableId::MethodDef, 1000),
                ],
                false,
                false,
                false,
            ));

            let row_size = <CustomDebugInformationRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            custom_debug_info
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {name}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                CustomDebugInformationRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .unwrap_or_else(|_| panic!("Deserialization should succeed for {name}"));

            assert_eq!(
                custom_debug_info.kind, deserialized_row.kind,
                "Kind mismatch for {name}"
            );
            assert_eq!(
                custom_debug_info.value, deserialized_row.value,
                "Value mismatch for {name}"
            );
        }
    }
}

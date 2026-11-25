//! Implementation of `RowWritable` for `EventRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `Event` table (ID 0x14),
//! enabling writing of event definition metadata back to .NET PE files. The Event table
//! defines events that types can expose, including their names, attributes, and handler types.
//!
//! ## Table Structure (ECMA-335 §II.22.13)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `EventFlags` | `u16` | Event attributes bitmask |
//! | `Name` | String heap index | Event name identifier |
//! | `EventType` | `TypeDefOrRef` coded index | Event handler delegate type |
//!
//! ## Event Attributes
//!
//! The `EventFlags` field contains event attributes with common values:
//! - `0x0200` - `SpecialName` (event has special naming conventions)
//! - `0x0400` - `RTSpecialName` (runtime should verify name encoding)

use crate::{
    metadata::tables::{
        event::EventRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Error, Result,
};

impl RowWritable for EventRaw {
    /// Write an Event table row to binary data
    ///
    /// Serializes one Event table entry to the metadata tables stream format, handling
    /// variable-width indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `flags` - Event attributes as 2-byte little-endian value
    /// 2. `name` - String heap index (2 or 4 bytes)
    /// 3. `event_type` - `TypeDefOrRef` coded index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for Event serialization)
    /// * `sizes` - Table size information for determining index widths
    ///
    /// # Returns
    /// `Ok(())` on successful serialization, error if buffer is too small
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target buffer is too small for the row data
    /// - The coded index cannot be written
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write flags (2 bytes) - convert from u32 to u16 with range check
        let flags_u16 = u16::try_from(self.flags)
            .map_err(|_| Error::LayoutFailed("Event flags value exceeds u16 range".to_string()))?;
        write_le_at(data, offset, flags_u16)?;

        // Write name string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write event_type coded index (2 or 4 bytes)
        let encoded_index = self.event_type.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            encoded_index,
            sizes.coded_index_bits(CodedIndexType::TypeDefOrRef) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::{
        tables::{
            types::{RowReadable, TableInfo, TableRow},
            CodedIndex, TableId,
        },
        token::Token,
    };

    #[test]
    fn test_row_size() {
        // Test with small tables and heaps
        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        let size = <EventRaw as TableRow>::row_size(&table_info);
        // flags(2) + name(2) + event_type(2) = 6
        assert_eq!(size, 6);

        // Test with large tables and heaps
        let table_info_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 70000),
                (TableId::TypeRef, 70000),
                (TableId::TypeSpec, 70000),
            ],
            true,
            false,
            false,
        ));

        let size_large = <EventRaw as TableRow>::row_size(&table_info_large);
        // flags(2) + name(4) + event_type(4) = 10
        assert_eq!(size_large, 10);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = EventRaw {
            rid: 1,
            token: Token::new(0x14000001),
            offset: 0,
            flags: 0x0101,
            name: 0x0202,
            event_type: CodedIndex::new(TableId::TypeDef, 192, CodedIndexType::TypeDefOrRef),
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1000),
                (TableId::TypeRef, 1000),
                (TableId::TypeSpec, 1000),
            ],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = EventRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.event_type, original_row.event_type);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small() {
        // Test with known binary data from reader tests
        let data = vec![
            0x01, 0x01, // flags (0x0101)
            0x02, 0x02, // name (0x0202)
            0x00, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            false,
            false,
            false,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = EventRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_known_binary_format_large() {
        // Test with known binary data from reader tests (large variant)
        let data = vec![
            0x01, 0x01, // flags (0x0101)
            0x02, 0x02, 0x02, 0x02, // name (0x02020202)
            0x00, 0x03, 0x03, 0x03, // event_type (tag 0 = TypeDef, index 3)
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, 1),
                (TableId::TypeSpec, 1),
            ],
            true,
            false,
            false,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = EventRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_event_attributes() {
        // Test various event attribute combinations
        let test_cases = vec![
            (0x0000, "None"),
            (0x0200, "SpecialName"),
            (0x0400, "RTSpecialName"),
            (0x0600, "SpecialName|RTSpecialName"),
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        for (flags, description) in test_cases {
            let event_row = EventRaw {
                rid: 1,
                token: Token::new(0x14000001),
                offset: 0,
                flags,
                name: 0x100,
                event_type: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef),
            };

            let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            event_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EventRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.flags, event_row.flags,
                "Flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_coded_index_types() {
        // Test different coded index target types
        let test_cases = vec![
            (TableId::TypeDef, "TypeDef"),
            (TableId::TypeRef, "TypeRef"),
            (TableId::TypeSpec, "TypeSpec"),
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        for (table_id, description) in test_cases {
            let event_row = EventRaw {
                rid: 1,
                token: Token::new(0x14000001),
                offset: 0,
                flags: 0x0200, // SpecialName
                name: 0x100,
                event_type: CodedIndex::new(table_id, 1, CodedIndexType::TypeDefOrRef),
            };

            let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            event_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row = EventRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.event_type.tag, event_row.event_type.tag,
                "Event type tag should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = EventRaw {
            rid: 1,
            token: Token::new(0x14000001),
            offset: 0,
            flags: 0x0600, // Complex flags combination
            name: 0x123456,
            event_type: CodedIndex::new(TableId::TypeRef, 0x8000, CodedIndexType::TypeDefOrRef),
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 70000),
                (TableId::TypeRef, 70000),
                (TableId::TypeSpec, 70000),
            ],
            true,
            false,
            false,
        ));

        let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = EventRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.event_type, original_row.event_type);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (minimal event)
        let minimal_event = EventRaw {
            rid: 1,
            token: Token::new(0x14000001),
            offset: 0,
            flags: 0, // No attributes
            name: 0,  // Unnamed (null string reference)
            event_type: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef), // Use a valid row instead of 0
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        minimal_event
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Minimal event serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = EventRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Minimal event deserialization should succeed");

        assert_eq!(deserialized_row.flags, minimal_event.flags);
        assert_eq!(deserialized_row.name, minimal_event.name);
        assert_eq!(deserialized_row.event_type, minimal_event.event_type);
    }

    #[test]
    fn test_flags_range_validation() {
        // Test that large flag values are properly rejected
        let large_flags_row = EventRaw {
            rid: 1,
            token: Token::new(0x14000001),
            offset: 0,
            flags: 0x12345678, // Large value that exceeds u16 range
            name: 0x100,
            event_type: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef),
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        let row_size = <EventRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        // Should fail with range error
        let result = large_flags_row.row_write(&mut buffer, &mut offset, 1, &table_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Event flags value exceeds u16 range"));
    }
}

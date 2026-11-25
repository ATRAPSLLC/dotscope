//! Writer implementation for `StateMachineMethod` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`StateMachineMethodRaw`] struct, enabling serialization of state machine method
//! mapping rows back to binary format. This supports Portable PDB generation and
//! assembly modification scenarios where async/await and yield state machine
//! debugging information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `StateMachineMethod` row consists of two fields:
//! - `move_next_method` (2/4 bytes): MethodDef table index for the MoveNext method
//! - `kickoff_method` (2/4 bytes): MethodDef table index for the original user method
//!
//! # Row Layout
//!
//! `StateMachineMethod` table rows are serialized with this binary structure:
//! - MoveNext MethodDef index (2 or 4 bytes, depending on MethodDef table size)
//! - Kickoff MethodDef index (2 or 4 bytes, depending on MethodDef table size)
//! - Total row size varies based on table sizes
//!
//! # State Machine Context
//!
//! This table maps compiler-generated state machine methods to their original
//! user-written methods, enabling debuggers to provide proper stepping and
//! breakpoint support for async/await and yield return patterns.
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::statemachinemethod::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        statemachinemethod::StateMachineMethodRaw,
        types::{RowWritable, TableInfoRef},
        TableId,
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for StateMachineMethodRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.move_next_method, 0)))
    }

    /// Write a `StateMachineMethod` table row to binary data
    ///
    /// Serializes one `StateMachineMethod` table entry to the metadata tables stream format, handling
    /// variable-width MethodDef table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this state machine method entry (unused for `StateMachineMethod`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized state machine method row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. MoveNext MethodDef index (2/4 bytes, little-endian)
    /// 2. Kickoff MethodDef index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write both MethodDef table indices
        write_le_at_dyn(
            data,
            offset,
            self.move_next_method,
            sizes.is_large(TableId::MethodDef),
        )?;
        write_le_at_dyn(
            data,
            offset,
            self.kickoff_method,
            sizes.is_large(TableId::MethodDef),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        tables::types::{RowReadable, TableInfo, TableRow},
        token::Token,
    };

    #[test]
    fn test_round_trip_serialization_small_table() {
        // Create test data with small MethodDef table
        let original_row = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 123,
            kickoff_method: 45,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 1000)], // Small MethodDef table
            false,                                                  // small string heap
            false,                                                  // small guid heap
            false,                                                  // small blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            StateMachineMethodRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(
            original_row.move_next_method,
            deserialized_row.move_next_method
        );
        assert_eq!(original_row.kickoff_method, deserialized_row.kickoff_method);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_table() {
        // Create test data with large MethodDef table
        let original_row = StateMachineMethodRaw {
            rid: 2,
            token: Token::new(0x3600_0002),
            offset: 0,
            move_next_method: 0x1BEEF,
            kickoff_method: 0x2CAFE,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 100000)], // Large MethodDef table
            true,                                                     // large string heap
            true,                                                     // large guid heap
            true,                                                     // large blob heap
        ));

        // Calculate buffer size and serialize
        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            StateMachineMethodRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
                .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(
            original_row.move_next_method,
            deserialized_row.move_next_method
        );
        assert_eq!(original_row.kickoff_method, deserialized_row.kickoff_method);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_table() {
        // Test with specific binary layout for small table
        let state_machine_method = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 0x1234,
            kickoff_method: 0x5678,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 1000)], // Small MethodDef table (2 byte indices)
            false,                                                  // small string heap
            false,                                                  // small guid heap
            false,                                                  // small blob heap
        ));

        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        state_machine_method
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 4, "Row size should be 4 bytes for small table");

        // MoveNext MethodDef index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // Kickoff MethodDef index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);
    }

    #[test]
    fn test_known_binary_format_large_table() {
        // Test with specific binary layout for large table
        let state_machine_method = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 0x12345678,
            kickoff_method: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 100000)], // Large MethodDef table (4 byte indices)
            true,                                                     // large string heap
            true,                                                     // large guid heap
            true,                                                     // large blob heap
        ));

        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        state_machine_method
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(row_size, 8, "Row size should be 8 bytes for large table");

        // MoveNext MethodDef index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // Kickoff MethodDef index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);
    }

    #[test]
    fn test_async_method_mapping() {
        // Test typical async method pattern
        let state_machine_method = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 100, // Compiler-generated MoveNext method
            kickoff_method: 50,    // Original async method
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 1000)],
            false,
            false,
            false,
        ));

        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        state_machine_method
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            StateMachineMethodRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.move_next_method, 100);
        assert_eq!(deserialized_row.kickoff_method, 50);
    }

    #[test]
    fn test_yield_method_mapping() {
        // Test typical yield return pattern
        let state_machine_method = StateMachineMethodRaw {
            rid: 1,
            token: Token::new(0x3600_0001),
            offset: 0,
            move_next_method: 200, // Compiler-generated enumerator MoveNext
            kickoff_method: 75,    // Original yield method
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(crate::metadata::tables::TableId::MethodDef, 1000)],
            false,
            false,
            false,
        ));

        let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        state_machine_method
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            StateMachineMethodRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.move_next_method, 200);
        assert_eq!(deserialized_row.kickoff_method, 75);
    }

    #[test]
    fn test_various_method_indices() {
        // Test with different method index combinations
        let test_cases = vec![
            (1, 1),      // Simple case
            (10, 5),     // MoveNext > Kickoff
            (3, 15),     // Kickoff > MoveNext
            (1000, 999), // Large indices
        ];

        for (move_next, kickoff) in test_cases {
            let state_machine_method = StateMachineMethodRaw {
                rid: 1,
                token: Token::new(0x3600_0001),
                offset: 0,
                move_next_method: move_next,
                kickoff_method: kickoff,
            };

            let table_info = std::sync::Arc::new(TableInfo::new_test(
                &[(crate::metadata::tables::TableId::MethodDef, 2000)],
                false,
                false,
                false,
            ));

            let row_size = <StateMachineMethodRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            state_machine_method
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                StateMachineMethodRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.move_next_method, move_next);
            assert_eq!(deserialized_row.kickoff_method, kickoff);
        }
    }
}

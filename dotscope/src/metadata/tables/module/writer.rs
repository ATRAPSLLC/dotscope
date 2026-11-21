//! Module table binary writer implementation
//!
//! Provides binary serialization implementation for the Module metadata table (0x00) through
//! the [`crate::metadata::tables::types::RowWritable`] trait. This module handles the low-level
//! serialization of Module table entries to the metadata tables stream format.
//!
//! # Binary Format Support
//!
//! The writer supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for modules with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger modules)
//!
//! # Row Layout
//!
//! Module table rows are serialized with this binary structure:
//! - `generation` (2 bytes): Generation number (reserved, always 0)
//! - `name` (2/4 bytes): String heap index for module name
//! - `mvid` (2/4 bytes): GUID heap index for module version identifier
//! - `encid` (2/4 bytes): GUID heap index for Edit and Continue ID
//! - `encbaseid` (2/4 bytes): GUID heap index for Edit and Continue base ID
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. All heap references are written as
//! indexes that match the format expected by the metadata loader.
//!
//! # Thread Safety
//!
//! All serialization operations are stateless and safe for concurrent access. The writer
//! does not modify any shared state during serialization operations.
//!
//! # Integration
//!
//! This writer integrates with the metadata table infrastructure:
//! - [`crate::metadata::tables::types::RowWritable`]: Writing trait for table rows
//! - [`crate::metadata::tables::ModuleRaw`]: Raw module data structure
//! - [`crate::io`]: Low-level binary I/O operations
//!
//! # Reference
//! - [ECMA-335 II.22.30](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Module table specification

use crate::{
    metadata::tables::{
        module::ModuleRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ModuleRaw {
    /// Write a Module table row to binary data
    ///
    /// Serializes one Module table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this module entry (always 1 for Module)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized module row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Generation number (2 bytes, little-endian)
    /// 2. Name string index (2/4 bytes, little-endian)
    /// 3. Mvid GUID index (2/4 bytes, little-endian)
    /// 4. EncId GUID index (2/4 bytes, little-endian)
    /// 5. EncBaseId GUID index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write generation as u16 (the raw struct stores it as u32)
        write_le_at(
            data,
            offset,
            u16::try_from(self.generation).map_err(|_| {
                malformed_error!("Module generation out of range: {}", self.generation)
            })?,
        )?;

        // Write variable-size heap indexes
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.mvid, sizes.is_large_guid())?;
        write_le_at_dyn(data, offset, self.encid, sizes.is_large_guid())?;
        write_le_at_dyn(data, offset, self.encbaseid, sizes.is_large_guid())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::{
        tables::types::{RowReadable, TableInfo, TableRow},
        token::Token,
    };

    #[test]
    fn test_round_trip_serialization_small_heaps() {
        // Create test data with small heap indexes
        let original_row = ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0x0101,
            name: 0x0202,
            mvid: 0x0303,
            encid: 0x0404,
            encbaseid: 0x0505,
        };

        // Create table info for small heaps
        let table_info = TableInfo::new_test(&[], false, false, false);
        let table_info_ref = Arc::new(table_info);

        // Calculate buffer size and serialize
        let row_size = <ModuleRaw as TableRow>::row_size(&table_info_ref) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info_ref)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ModuleRaw::row_read(&buffer, &mut read_offset, 1, &table_info_ref)
            .expect("Deserialization should succeed");

        assert_eq!(original_row.generation, deserialized_row.generation);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.mvid, deserialized_row.mvid);
        assert_eq!(original_row.encid, deserialized_row.encid);
        assert_eq!(original_row.encbaseid, deserialized_row.encbaseid);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_round_trip_serialization_large_heaps() {
        // Create test data with large heap indexes
        let original_row = ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0x0101,
            name: 0x02020202,
            mvid: 0x03030303,
            encid: 0x04040404,
            encbaseid: 0x05050505,
        };

        // Create table info for large heaps
        let table_info = TableInfo::new_test(&[], true, true, true);
        let table_info_ref = Arc::new(table_info);

        // Calculate buffer size and serialize
        let row_size = <ModuleRaw as TableRow>::row_size(&table_info_ref) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info_ref)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ModuleRaw::row_read(&buffer, &mut read_offset, 1, &table_info_ref)
            .expect("Deserialization should succeed");

        assert_eq!(original_row.generation, deserialized_row.generation);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.mvid, deserialized_row.mvid);
        assert_eq!(original_row.encid, deserialized_row.encid);
        assert_eq!(original_row.encbaseid, deserialized_row.encbaseid);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small_heaps() {
        // Test against the known binary format from reader tests
        let module_row = ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0x0101,
            name: 0x0202,
            mvid: 0x0303,
            encid: 0x0404,
            encbaseid: 0x0505,
        };

        let table_info = TableInfo::new_test(&[], false, false, false);
        let table_info_ref = Arc::new(table_info);

        let mut buffer = vec![0u8; <ModuleRaw as TableRow>::row_size(&table_info_ref) as usize];
        let mut offset = 0;

        module_row
            .row_write(&mut buffer, &mut offset, 1, &table_info_ref)
            .expect("Serialization should succeed");

        let expected = vec![
            0x01, 0x01, // generation
            0x02, 0x02, // name
            0x03, 0x03, // mvid
            0x04, 0x04, // encid
            0x05, 0x05, // encbaseid
        ];

        assert_eq!(
            buffer, expected,
            "Binary output should match expected format"
        );
    }

    #[test]
    fn test_known_binary_format_large_heaps() {
        // Test against the known binary format from reader tests
        let module_row = ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0x0101,
            name: 0x02020202,
            mvid: 0x03030303,
            encid: 0x04040404,
            encbaseid: 0x05050505,
        };

        let table_info = TableInfo::new_test(&[], true, true, true);
        let table_info_ref = Arc::new(table_info);

        let mut buffer = vec![0u8; <ModuleRaw as TableRow>::row_size(&table_info_ref) as usize];
        let mut offset = 0;

        module_row
            .row_write(&mut buffer, &mut offset, 1, &table_info_ref)
            .expect("Serialization should succeed");

        let expected = vec![
            0x01, 0x01, // generation
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // mvid
            0x04, 0x04, 0x04, 0x04, // encid
            0x05, 0x05, 0x05, 0x05, // encbaseid
        ];

        assert_eq!(
            buffer, expected,
            "Binary output should match expected format"
        );
    }

    #[test]
    fn test_row_size_calculation() {
        // Test small heap sizes
        let table_info_small = TableInfo::new_test(&[], false, false, false);
        let table_info_small_ref = Arc::new(table_info_small);
        let small_size = <ModuleRaw as TableRow>::row_size(&table_info_small_ref);
        assert_eq!(small_size, 2 + 2 + 2 + 2 + 2); // 10 bytes

        // Test large heap sizes
        let table_info_large = TableInfo::new_test(&[], true, true, true);
        let table_info_large_ref = Arc::new(table_info_large);
        let large_size = <ModuleRaw as TableRow>::row_size(&table_info_large_ref);
        assert_eq!(large_size, 2 + 4 + 4 + 4 + 4); // 18 bytes
    }
}

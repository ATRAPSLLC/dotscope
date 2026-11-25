//! Assembly table binary writer implementation
//!
//! Provides binary serialization implementation for the Assembly metadata table (0x20) through
//! the [`crate::metadata::tables::types::RowWritable`] trait. This module handles the low-level
//! serialization of Assembly table entries to the metadata tables stream format.
//!
//! # Binary Format Support
//!
//! The writer supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for assemblies with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger assemblies)
//!
//! # Row Layout
//!
//! Assembly table rows are serialized with this binary structure:
//! - `hash_alg_id` (4 bytes): Hash algorithm identifier
//! - `major_version` (2 bytes): Major version number
//! - `minor_version` (2 bytes): Minor version number
//! - `build_number` (2 bytes): Build number
//! - `revision_number` (2 bytes): Revision number  
//! - `flags` (4 bytes): Assembly attributes bitmask
//! - `public_key` (2/4 bytes): Blob heap index for public key
//! - `name` (2/4 bytes): String heap index for assembly name
//! - `culture` (2/4 bytes): String heap index for culture
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
//! - [`crate::metadata::tables::AssemblyRaw`]: Raw assembly data structure
//! - [`crate::io`]: Low-level binary I/O operations
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification

use crate::{
    metadata::tables::{
        assembly::AssemblyRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for AssemblyRaw {
    /// Write an Assembly table row to binary data
    ///
    /// Serializes one Assembly table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this assembly entry (unused for Assembly)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Hash algorithm ID (4 bytes, little-endian)
    /// 2. Major version (2 bytes, little-endian)
    /// 3. Minor version (2 bytes, little-endian)
    /// 4. Build number (2 bytes, little-endian)
    /// 5. Revision number (2 bytes, little-endian)
    /// 6. Flags (4 bytes, little-endian)
    /// 7. Public key blob index (2/4 bytes, little-endian)
    /// 8. Name string index (2/4 bytes, little-endian)
    /// 9. Culture string index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write fixed-size fields first
        write_le_at(data, offset, self.hash_alg_id)?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.major_version).map_err(|_| {
                malformed_error!(
                    "Assembly major version out of range: {}",
                    self.major_version
                )
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.minor_version).map_err(|_| {
                malformed_error!(
                    "Assembly minor version out of range: {}",
                    self.minor_version
                )
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.build_number).map_err(|_| {
                malformed_error!("Assembly build number out of range: {}", self.build_number)
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.revision_number).map_err(|_| {
                malformed_error!(
                    "Assembly revision number out of range: {}",
                    self.revision_number
                )
            })?,
        )?;
        write_le_at(data, offset, self.flags)?;

        // Write variable-size heap indexes
        write_le_at_dyn(data, offset, self.public_key, sizes.is_large_blob())?;
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.culture, sizes.is_large_str())?;

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
    fn test_round_trip_serialization_small_heaps() {
        // Create test data with small heap indexes
        let original_row = AssemblyRaw {
            rid: 1,
            token: Token::new(0x20000001),
            offset: 0,
            hash_alg_id: 0x01010101,
            major_version: 0x0202,
            minor_version: 0x0303,
            build_number: 0x0404,
            revision_number: 0x0505,
            flags: 0x06060606,
            public_key: 0x0707,
            name: 0x0808,
            culture: 0x0909,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = AssemblyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(original_row.hash_alg_id, deserialized_row.hash_alg_id);
        assert_eq!(original_row.major_version, deserialized_row.major_version);
        assert_eq!(original_row.minor_version, deserialized_row.minor_version);
        assert_eq!(original_row.build_number, deserialized_row.build_number);
        assert_eq!(
            original_row.revision_number,
            deserialized_row.revision_number
        );
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(original_row.public_key, deserialized_row.public_key);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.culture, deserialized_row.culture);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_round_trip_serialization_large_heaps() {
        // Create test data with large heap indexes
        let original_row = AssemblyRaw {
            rid: 1,
            token: Token::new(0x20000001),
            offset: 0,
            hash_alg_id: 0x01010101,
            major_version: 0x0202,
            minor_version: 0x0303,
            build_number: 0x0404,
            revision_number: 0x0505,
            flags: 0x06060606,
            public_key: 0x07070707,
            name: 0x08080808,
            culture: 0x09090909,
        };

        // Create table info for large heaps
        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, true, true));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = AssemblyRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(original_row.hash_alg_id, deserialized_row.hash_alg_id);
        assert_eq!(original_row.major_version, deserialized_row.major_version);
        assert_eq!(original_row.minor_version, deserialized_row.minor_version);
        assert_eq!(original_row.build_number, deserialized_row.build_number);
        assert_eq!(
            original_row.revision_number,
            deserialized_row.revision_number
        );
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(original_row.public_key, deserialized_row.public_key);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.culture, deserialized_row.culture);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small_heaps() {
        // Test against the known binary format from reader tests
        let assembly_row = AssemblyRaw {
            rid: 1,
            token: Token::new(0x20000001),
            offset: 0,
            hash_alg_id: 0x01010101,
            major_version: 0x0202,
            minor_version: 0x0303,
            build_number: 0x0404,
            revision_number: 0x0505,
            flags: 0x06060606,
            public_key: 0x0707,
            name: 0x0808,
            culture: 0x0909,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));

        let mut buffer = vec![0u8; <AssemblyRaw as TableRow>::row_size(&table_info) as usize];
        let mut offset = 0;

        assembly_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // hash_alg_id
            0x02, 0x02, // major_version
            0x03, 0x03, // minor_version
            0x04, 0x04, // build_number
            0x05, 0x05, // revision_number
            0x06, 0x06, 0x06, 0x06, // flags
            0x07, 0x07, // public_key
            0x08, 0x08, // name
            0x09, 0x09, // culture
        ];

        assert_eq!(
            buffer, expected,
            "Binary output should match expected format"
        );
    }

    #[test]
    fn test_known_binary_format_large_heaps() {
        // Test against the known binary format from reader tests
        let assembly_row = AssemblyRaw {
            rid: 1,
            token: Token::new(0x20000001),
            offset: 0,
            hash_alg_id: 0x01010101,
            major_version: 0x0202,
            minor_version: 0x0303,
            build_number: 0x0404,
            revision_number: 0x0505,
            flags: 0x06060606,
            public_key: 0x07070707,
            name: 0x08080808,
            culture: 0x09090909,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(&[], true, true, true));

        let mut buffer = vec![0u8; <AssemblyRaw as TableRow>::row_size(&table_info) as usize];
        let mut offset = 0;

        assembly_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // hash_alg_id
            0x02, 0x02, // major_version
            0x03, 0x03, // minor_version
            0x04, 0x04, // build_number
            0x05, 0x05, // revision_number
            0x06, 0x06, 0x06, 0x06, // flags
            0x07, 0x07, 0x07, 0x07, // public_key
            0x08, 0x08, 0x08, 0x08, // name
            0x09, 0x09, 0x09, 0x09, // culture
        ];

        assert_eq!(
            buffer, expected,
            "Binary output should match expected format"
        );
    }

    #[test]
    fn test_row_size_calculation() {
        // Test small heap sizes
        let table_info_small = std::sync::Arc::new(TableInfo::new_test(&[], false, false, false));
        let small_size = <AssemblyRaw as TableRow>::row_size(&table_info_small);
        assert_eq!(small_size, 4 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 2); // 22 bytes

        // Test large heap sizes
        let table_info_large = std::sync::Arc::new(TableInfo::new_test(&[], true, true, true));
        let large_size = <AssemblyRaw as TableRow>::row_size(&table_info_large);
        assert_eq!(large_size, 4 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4); // 28 bytes
    }
}

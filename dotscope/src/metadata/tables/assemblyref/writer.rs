//! `AssemblyRef` table binary writer implementation
//!
//! Provides binary serialization implementation for the `AssemblyRef` metadata table (0x23) through
//! the [`crate::metadata::tables::types::RowWritable`] trait. This module handles the low-level
//! serialization of `AssemblyRef` table entries to the metadata tables stream format.
//!
//! # Binary Format Support
//!
//! The writer supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for assemblies with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger assemblies)
//!
//! # Row Layout
//!
//! `AssemblyRef` table rows are serialized with this binary structure:
//! - `major_version` (2 bytes): Major version number
//! - `minor_version` (2 bytes): Minor version number
//! - `build_number` (2 bytes): Build number
//! - `revision_number` (2 bytes): Revision number
//! - `flags` (4 bytes): Assembly attributes bitmask
//! - `public_key_or_token` (2/4 bytes): Blob heap index for public key/token
//! - `name` (2/4 bytes): String heap index for assembly name
//! - `culture` (2/4 bytes): String heap index for culture
//! - `hash_value` (2/4 bytes): Blob heap index for hash data
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
//! - [`crate::metadata::tables::assemblyref::AssemblyRefRaw`]: Raw assembly reference data structure
//! - [`crate::io`]: Low-level binary I/O operations
//!
//! # Reference
//! - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification

use crate::{
    metadata::tables::{
        assemblyref::AssemblyRefRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for AssemblyRefRaw {
    /// Write an `AssemblyRef` table row to binary data
    ///
    /// Serializes one `AssemblyRef` table entry to the metadata tables stream format, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this assembly reference entry (unused for `AssemblyRef`)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized assembly reference row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Major version (2 bytes, little-endian)
    /// 2. Minor version (2 bytes, little-endian)
    /// 3. Build number (2 bytes, little-endian)
    /// 4. Revision number (2 bytes, little-endian)
    /// 5. Flags (4 bytes, little-endian)
    /// 6. Public key or token blob index (2/4 bytes, little-endian)
    /// 7. Name string index (2/4 bytes, little-endian)
    /// 8. Culture string index (2/4 bytes, little-endian)
    /// 9. Hash value blob index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write fixed-size fields first
        write_le_at(
            data,
            offset,
            u16::try_from(self.major_version).map_err(|_| {
                malformed_error!(
                    "AssemblyRef major version out of range: {}",
                    self.major_version
                )
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.minor_version).map_err(|_| {
                malformed_error!(
                    "AssemblyRef minor version out of range: {}",
                    self.minor_version
                )
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.build_number).map_err(|_| {
                malformed_error!(
                    "AssemblyRef build number out of range: {}",
                    self.build_number
                )
            })?,
        )?;
        write_le_at(
            data,
            offset,
            u16::try_from(self.revision_number).map_err(|_| {
                malformed_error!(
                    "AssemblyRef revision number out of range: {}",
                    self.revision_number
                )
            })?,
        )?;
        write_le_at(data, offset, self.flags)?;

        // Write variable-size heap indexes
        write_le_at_dyn(
            data,
            offset,
            self.public_key_or_token,
            sizes.is_large_blob(),
        )?;
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.culture, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.hash_value, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        tables::types::{RowReadable, TableId, TableInfo, TableRow},
        token::Token,
    };

    #[test]
    fn test_round_trip_serialization_short() {
        // Create test data using same values as reader tests
        let original_row = AssemblyRefRaw {
            rid: 1,
            token: Token::new(0x23000001),
            offset: 0,
            major_version: 0x0101,
            minor_version: 0x0202,
            build_number: 0x0303,
            revision_number: 0x0404,
            flags: 0x05050505,
            public_key_or_token: 0x0606,
            name: 0x0707,
            culture: 0x0808,
            hash_value: 0x0909,
        };

        // Create minimal table info for testing (small heap)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = AssemblyRefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.major_version, deserialized_row.major_version);
        assert_eq!(original_row.minor_version, deserialized_row.minor_version);
        assert_eq!(original_row.build_number, deserialized_row.build_number);
        assert_eq!(
            original_row.revision_number,
            deserialized_row.revision_number
        );
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(
            original_row.public_key_or_token,
            deserialized_row.public_key_or_token
        );
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.culture, deserialized_row.culture);
        assert_eq!(original_row.hash_value, deserialized_row.hash_value);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_round_trip_serialization_long() {
        // Create test data using same values as reader tests (large heap)
        let original_row = AssemblyRefRaw {
            rid: 1,
            token: Token::new(0x23000001),
            offset: 0,
            major_version: 0x0101,
            minor_version: 0x0202,
            build_number: 0x0303,
            revision_number: 0x0404,
            flags: 0x05050505,
            public_key_or_token: 0x06060606,
            name: 0x07070707,
            culture: 0x08080808,
            hash_value: 0x09090909,
        };

        // Create minimal table info for testing (large heap)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            true,
            true,
            true,
        ));

        // Calculate buffer size and serialize
        let row_size = <AssemblyRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = AssemblyRefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.major_version, deserialized_row.major_version);
        assert_eq!(original_row.minor_version, deserialized_row.minor_version);
        assert_eq!(original_row.build_number, deserialized_row.build_number);
        assert_eq!(
            original_row.revision_number,
            deserialized_row.revision_number
        );
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(
            original_row.public_key_or_token,
            deserialized_row.public_key_or_token
        );
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.culture, deserialized_row.culture);
        assert_eq!(original_row.hash_value, deserialized_row.hash_value);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_short() {
        // Use same test data as reader tests to verify binary compatibility
        let expected_data = vec![
            0x01, 0x01, // major_version
            0x02, 0x02, // minor_version
            0x03, 0x03, // build_number
            0x04, 0x04, // revision_number
            0x05, 0x05, 0x05, 0x05, // flags
            0x06, 0x06, // public_key_or_token
            0x07, 0x07, // name
            0x08, 0x08, // culture
            0x09, 0x09, // hash_value
        ];

        let row = AssemblyRefRaw {
            rid: 1,
            token: Token::new(0x23000001),
            offset: 0,
            major_version: 0x0101,
            minor_version: 0x0202,
            build_number: 0x0303,
            revision_number: 0x0404,
            flags: 0x05050505,
            public_key_or_token: 0x0606,
            name: 0x0707,
            culture: 0x0808,
            hash_value: 0x0909,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            false,
            false,
            false,
        ));

        let row_size = <AssemblyRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        row.row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, expected_data,
            "Generated binary should match expected format"
        );
        assert_eq!(
            offset,
            expected_data.len(),
            "Offset should match data length"
        );
    }

    #[test]
    fn test_known_binary_format_long() {
        // Use same test data as reader tests to verify binary compatibility (large heap)
        let expected_data = vec![
            0x01, 0x01, // major_version
            0x02, 0x02, // minor_version
            0x03, 0x03, // build_number
            0x04, 0x04, // revision_number
            0x05, 0x05, 0x05, 0x05, // flags
            0x06, 0x06, 0x06, 0x06, // public_key_or_token
            0x07, 0x07, 0x07, 0x07, // name
            0x08, 0x08, 0x08, 0x08, // culture
            0x09, 0x09, 0x09, 0x09, // hash_value
        ];

        let row = AssemblyRefRaw {
            rid: 1,
            token: Token::new(0x23000001),
            offset: 0,
            major_version: 0x0101,
            minor_version: 0x0202,
            build_number: 0x0303,
            revision_number: 0x0404,
            flags: 0x05050505,
            public_key_or_token: 0x06060606,
            name: 0x07070707,
            culture: 0x08080808,
            hash_value: 0x09090909,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            true,
            true,
            true,
        ));

        let row_size = <AssemblyRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        row.row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, expected_data,
            "Generated binary should match expected format"
        );
        assert_eq!(
            offset,
            expected_data.len(),
            "Offset should match data length"
        );
    }
}

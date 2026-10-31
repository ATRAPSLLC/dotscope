//! Implementation of `RowWritable` for `FileRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `File` table (ID 0x26),
//! enabling writing of file metadata information back to .NET PE files. The File table
//! describes external files that are part of a multi-file assembly, including modules,
//! resources, and native libraries.
//!
//! ## Table Structure (ECMA-335 §II.22.19)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | u32 | File attribute flags indicating file type |
//! | `Name` | String heap index | Filename string in string heap |
//! | `HashValue` | Blob heap index | Cryptographic hash for integrity verification |
//!
//! ## File Attributes
//!
//! The Flags field contains FileAttributes values:
//! - **`CONTAINS_META_DATA` (0x0000)**: File contains .NET metadata
//! - **`CONTAINS_NO_META_DATA` (0x0001)**: Resource file without metadata
//!
//! ## Usage Context
//!
//! File entries are used for:
//! - **Multi-module assemblies**: Additional .netmodule files with executable code
//! - **Resource files**: Binary data files (.resources, images, configuration)
//! - **Native libraries**: Unmanaged DLLs for P/Invoke operations
//! - **Documentation**: XML documentation and help files
//! - **Security verification**: Hash-based integrity checking

use crate::{
    metadata::tables::{
        file::FileRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for FileRaw {
    /// Serialize a File table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.19 specification:
    /// - `flags`: File attribute flags (4 bytes)
    /// - `name`: String heap index (filename)
    /// - `hash_value`: Blob heap index (cryptographic hash)
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
        // Write file attribute flags
        write_le_at(data, offset, self.flags)?;

        // Write string heap index for filename
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write blob heap index for hash value
        write_le_at_dyn(data, offset, self.hash_value, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            file::FileRaw,
            types::{RowReadable, RowWritable, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_file_row_size() {
        // Test with small heaps
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let expected_size = 4 + 2 + 2; // flags(4) + name(2) + hash_value(2)
        assert_eq!(<FileRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large heaps
        let sizes_large = Arc::new(TableInfo::new_test(&[], true, true, false));

        let expected_size_large = 4 + 4 + 4; // flags(4) + name(4) + hash_value(4)
        assert_eq!(
            <FileRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_file_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let file = FileRaw {
            rid: 1,
            token: Token::new(0x26000001),
            offset: 0,
            flags: 0x01010101,
            name: 0x0202,
            hash_value: 0x0303,
        };

        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // flags: 0x01010101, little-endian
            0x02, 0x02, // name: 0x0202, little-endian
            0x03, 0x03, // hash_value: 0x0303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_file_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(&[], true, true, false));

        let file = FileRaw {
            rid: 1,
            token: Token::new(0x26000001),
            offset: 0,
            flags: 0x01010101,
            name: 0x02020202,
            hash_value: 0x03030303,
        };

        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // flags: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // name: 0x02020202, little-endian
            0x03, 0x03, 0x03, 0x03, // hash_value: 0x03030303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_file_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let original = FileRaw {
            rid: 42,
            token: Token::new(0x2600002A),
            offset: 0,
            flags: 0x12345678,
            name: 256,       // String index 256
            hash_value: 512, // Blob index 512
        };

        // Write to buffer
        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = FileRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.flags, read_back.flags);
        assert_eq!(original.name, read_back.name);
        assert_eq!(original.hash_value, read_back.hash_value);
    }

    #[test]
    fn test_file_different_attributes() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different file attribute scenarios
        let test_cases = vec![
            (0x00000000, 100, 200, "File contains metadata"),
            (0x00000001, 101, 201, "File contains no metadata"),
            (0x00000002, 102, 202, "Reserved flag"),
            (0x12345678, 103, 203, "Custom flags combination"),
        ];

        for (flags, name_index, hash_index, _description) in test_cases {
            let file = FileRaw {
                rid: 1,
                token: Token::new(0x26000001),
                offset: 0,
                flags,
                name: name_index,
                hash_value: hash_index,
            };

            let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = FileRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(file.flags, read_back.flags);
            assert_eq!(file.name, read_back.name);
            assert_eq!(file.hash_value, read_back.hash_value);
        }
    }

    #[test]
    fn test_file_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test with zero values
        let zero_file = FileRaw {
            rid: 1,
            token: Token::new(0x26000001),
            offset: 0,
            flags: 0,
            name: 0,
            hash_value: 0,
        };

        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_file
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, 0x00, 0x00, // flags: 0
            0x00, 0x00, // name: 0
            0x00, 0x00, // hash_value: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_file = FileRaw {
            rid: 1,
            token: Token::new(0x26000001),
            offset: 0,
            flags: 0xFFFFFFFF,
            name: 0xFFFF,
            hash_value: 0xFFFF,
        };

        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_file
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 8); // 4 + 2 + 2 bytes
    }

    #[test]
    fn test_file_heap_sizes() {
        // Test with different heap configurations
        let configurations = vec![
            (false, false, 2, 2), // Small string heap, small blob heap
            (true, false, 4, 2),  // Large string heap, small blob heap
            (false, true, 2, 4),  // Small string heap, large blob heap
            (true, true, 4, 4),   // Large string heap, large blob heap
        ];

        for (large_str, large_blob, expected_str_size, expected_blob_size) in configurations {
            let sizes = Arc::new(TableInfo::new_test(&[], large_str, large_blob, false));

            let file = FileRaw {
                rid: 1,
                token: Token::new(0x26000001),
                offset: 0,
                flags: 0x12345678,
                // An index has to fit its column: a two-byte one holds at most 0xFFFF
                name: if large_str { 0x12345678 } else { 0x1234 },
                hash_value: if large_blob { 0x12345678 } else { 0x1234 },
            };

            // Verify row size matches expected
            let expected_total_size = 4 + expected_str_size + expected_blob_size;
            assert_eq!(
                <FileRaw as TableRow>::row_size(&sizes) as usize,
                expected_total_size
            );

            let mut buffer = vec![0u8; expected_total_size];
            let mut offset = 0;
            file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

            assert_eq!(buffer.len(), expected_total_size);
            assert_eq!(offset, expected_total_size);
        }
    }

    #[test]
    fn test_file_common_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different common file scenarios
        let file_scenarios = vec![
            (0x00000000, 100, 200, "Module file with metadata"),
            (0x00000001, 101, 201, "Resource file without metadata"),
            (0x00000000, 102, 202, "Native library file"),
            (0x00000001, 103, 203, "Documentation XML file"),
            (0x00000000, 104, 204, "Configuration data file"),
            (0x00000001, 105, 205, "Satellite assembly resource"),
        ];

        for (flags, name_index, hash_index, _description) in file_scenarios {
            let file = FileRaw {
                rid: 1,
                token: Token::new(0x26000001),
                offset: 0,
                flags,
                name: name_index,
                hash_value: hash_index,
            };

            let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back = FileRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(file.flags, read_back.flags);
            assert_eq!(file.name, read_back.name);
            assert_eq!(file.hash_value, read_back.hash_value);
        }
    }

    #[test]
    fn test_file_security_hashes() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different hash scenarios
        let hash_scenarios = vec![
            (1, "SHA-1 hash (20 bytes)"),
            (100, "SHA-256 hash (32 bytes)"),
            (200, "MD5 hash (16 bytes)"),
            (300, "Custom hash algorithm"),
            (400, "Multiple hash values"),
            (500, "Empty hash (no verification)"),
            (1000, "Large hash blob"),
            (65535, "Maximum hash index for 2-byte"),
        ];

        for (hash_index, _description) in hash_scenarios {
            let file = FileRaw {
                rid: 1,
                token: Token::new(0x26000001),
                offset: 0,
                flags: 0x00000000, // Contains metadata
                name: 50,          // Filename index
                hash_value: hash_index,
            };

            let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

            // Verify the hash index is written correctly
            let written_hash = u16::from_le_bytes([buffer[6], buffer[7]]);
            assert_eq!(written_hash as u32, hash_index);
        }
    }

    #[test]
    fn test_file_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let file = FileRaw {
            rid: 1,
            token: Token::new(0x26000001),
            offset: 0,
            flags: 0x01010101,
            name: 0x0202,
            hash_value: 0x0303,
        };

        let mut buffer = vec![0u8; <FileRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        file.row_write(&mut buffer, &mut offset, 1, &sizes).unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // hash_value
        ];

        assert_eq!(buffer, expected);
    }
}

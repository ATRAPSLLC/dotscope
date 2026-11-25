//! Writer implementation for `LocalScope` metadata table.
//!
//! This module provides the [`RowWritable`] trait implementation for the
//! [`LocalScopeRaw`] struct, enabling serialization of local scope information
//! rows back to binary format. This supports Portable PDB generation and
//! assembly modification scenarios where debug information needs to be preserved.
//!
//! # Binary Format
//!
//! Each `LocalScope` row consists of six fields:
//! - `method` (2/4 bytes): Simple index into MethodDef table
//! - `import_scope` (2/4 bytes): Simple index into ImportScope table (0 = no import scope)
//! - `variable_list` (2/4 bytes): Simple index into LocalVariable table (0 = no variables)
//! - `constant_list` (2/4 bytes): Simple index into LocalConstant table (0 = no constants)
//! - `start_offset` (4 bytes): IL instruction offset where scope begins
//! - `length` (4 bytes): Length of scope in IL instruction bytes
//!
//! # Row Layout
//!
//! `LocalScope` table rows are serialized with this binary structure:
//! - Method table index (2 or 4 bytes, depending on MethodDef table size)
//! - ImportScope table index (2 or 4 bytes, depending on ImportScope table size)
//! - LocalVariable table index (2 or 4 bytes, depending on LocalVariable table size)
//! - LocalConstant table index (2 or 4 bytes, depending on LocalConstant table size)
//! - Start offset (4 bytes, little-endian)
//! - Length (4 bytes, little-endian)
//! - Total row size varies based on table sizes
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. Index sizes are determined dynamically
//! based on the actual table sizes, matching the compression scheme used in .NET metadata.
//!
//! The writer maintains strict compatibility with the [`crate::metadata::tables::localscope::reader`]
//! module, ensuring that data serialized by this writer can be correctly deserialized.

use crate::{
    metadata::tables::{
        localscope::LocalScopeRaw,
        types::{RowWritable, TableInfoRef},
        TableId,
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for LocalScopeRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.method, self.start_offset)))
    }

    /// Write a `LocalScope` table row to binary data
    ///
    /// Serializes one `LocalScope` table entry to the metadata tables stream format, handling
    /// variable-width table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `_rid` - Row identifier for this local scope entry (unused for `LocalScope`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized local scope row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by the Portable PDB specification:
    /// 1. Method table index (2/4 bytes, little-endian)
    /// 2. ImportScope table index (2/4 bytes, little-endian, 0 = no import scope)
    /// 3. LocalVariable table index (2/4 bytes, little-endian, 0 = no variables)
    /// 4. LocalConstant table index (2/4 bytes, little-endian, 0 = no constants)
    /// 5. Start offset (4 bytes, little-endian)
    /// 6. Length (4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write table indices
        write_le_at_dyn(
            data,
            offset,
            self.method,
            sizes.is_large(TableId::MethodDef),
        )?;
        write_le_at_dyn(
            data,
            offset,
            self.import_scope,
            sizes.is_large(TableId::ImportScope),
        )?;
        write_le_at_dyn(
            data,
            offset,
            self.variable_list,
            sizes.is_large(TableId::LocalVariable),
        )?;
        write_le_at_dyn(
            data,
            offset,
            self.constant_list,
            sizes.is_large(TableId::LocalConstant),
        )?;

        // Write fixed-size offset fields
        write_le_at::<u32>(data, offset, self.start_offset)?;
        write_le_at::<u32>(data, offset, self.length)?;

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
    fn test_round_trip_serialization_small_indices() {
        // Create test data with small table indices
        let original_row = LocalScopeRaw {
            rid: 1,
            token: Token::new(0x3200_0001),
            offset: 0,
            method: 5,
            import_scope: 3,
            variable_list: 10,
            constant_list: 7,
            start_offset: 0x1000,
            length: 0x500,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (crate::metadata::tables::TableId::MethodDef, 100),
                (crate::metadata::tables::TableId::ImportScope, 50),
                (crate::metadata::tables::TableId::LocalVariable, 200),
                (crate::metadata::tables::TableId::LocalConstant, 75),
            ],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <LocalScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = LocalScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.method, deserialized_row.method);
        assert_eq!(original_row.import_scope, deserialized_row.import_scope);
        assert_eq!(original_row.variable_list, deserialized_row.variable_list);
        assert_eq!(original_row.constant_list, deserialized_row.constant_list);
        assert_eq!(original_row.start_offset, deserialized_row.start_offset);
        assert_eq!(original_row.length, deserialized_row.length);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_round_trip_serialization_large_indices() {
        // Create test data with large table indices
        let original_row = LocalScopeRaw {
            rid: 2,
            token: Token::new(0x3200_0002),
            offset: 0,
            method: 0x1BEEF,
            import_scope: 0x2CAFE,
            variable_list: 0x3DEAD,
            constant_list: 0x4FACE,
            start_offset: 0x12345678,
            length: 0x9ABCDEF0,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (crate::metadata::tables::TableId::MethodDef, 100000),
                (crate::metadata::tables::TableId::ImportScope, 100000),
                (crate::metadata::tables::TableId::LocalVariable, 100000),
                (crate::metadata::tables::TableId::LocalConstant, 100000),
            ],
            true,
            true,
            true,
        ));

        // Calculate buffer size and serialize
        let row_size = <LocalScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 2, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = LocalScopeRaw::row_read(&buffer, &mut read_offset, 2, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.method, deserialized_row.method);
        assert_eq!(original_row.import_scope, deserialized_row.import_scope);
        assert_eq!(original_row.variable_list, deserialized_row.variable_list);
        assert_eq!(original_row.constant_list, deserialized_row.constant_list);
        assert_eq!(original_row.start_offset, deserialized_row.start_offset);
        assert_eq!(original_row.length, deserialized_row.length);
        assert_eq!(offset, row_size, "Offset should match expected row size");
        assert_eq!(
            read_offset, row_size,
            "Read offset should match expected row size"
        );
    }

    #[test]
    fn test_known_binary_format_small_indices() {
        // Test with specific binary layout for small indices
        let local_scope = LocalScopeRaw {
            rid: 1,
            token: Token::new(0x3200_0001),
            offset: 0,
            method: 0x1234,
            import_scope: 0x5678,
            variable_list: 0x9ABC,
            constant_list: 0xDEF0,
            start_offset: 0x11223344,
            length: 0x55667788,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (crate::metadata::tables::TableId::MethodDef, 100),
                (crate::metadata::tables::TableId::ImportScope, 100),
                (crate::metadata::tables::TableId::LocalVariable, 100),
                (crate::metadata::tables::TableId::LocalConstant, 100),
            ],
            false,
            false,
            false,
        ));

        let row_size = <LocalScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 16,
            "Row size should be 16 bytes for small indices"
        );

        // Method index (0x1234) as little-endian
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);

        // ImportScope index (0x5678) as little-endian
        assert_eq!(buffer[2], 0x78);
        assert_eq!(buffer[3], 0x56);

        // LocalVariable index (0x9ABC) as little-endian
        assert_eq!(buffer[4], 0xBC);
        assert_eq!(buffer[5], 0x9A);

        // LocalConstant index (0xDEF0) as little-endian
        assert_eq!(buffer[6], 0xF0);
        assert_eq!(buffer[7], 0xDE);

        // Start offset (0x11223344) as little-endian
        assert_eq!(buffer[8], 0x44);
        assert_eq!(buffer[9], 0x33);
        assert_eq!(buffer[10], 0x22);
        assert_eq!(buffer[11], 0x11);

        // Length (0x55667788) as little-endian
        assert_eq!(buffer[12], 0x88);
        assert_eq!(buffer[13], 0x77);
        assert_eq!(buffer[14], 0x66);
        assert_eq!(buffer[15], 0x55);
    }

    #[test]
    fn test_known_binary_format_large_indices() {
        // Test with specific binary layout for large indices
        let local_scope = LocalScopeRaw {
            rid: 1,
            token: Token::new(0x3200_0001),
            offset: 0,
            method: 0x12345678,
            import_scope: 0x9ABCDEF0,
            variable_list: 0x11223344,
            constant_list: 0x55667788,
            start_offset: 0xAABBCCDD,
            length: 0xEEFF0011,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (crate::metadata::tables::TableId::MethodDef, 100000),
                (crate::metadata::tables::TableId::ImportScope, 100000),
                (crate::metadata::tables::TableId::LocalVariable, 100000),
                (crate::metadata::tables::TableId::LocalConstant, 100000),
            ],
            true,
            true,
            true,
        ));

        let row_size = <LocalScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify the binary format matches expected layout
        assert_eq!(
            row_size, 24,
            "Row size should be 24 bytes for large indices"
        );

        // Method index (0x12345678) as little-endian
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        // ImportScope index (0x9ABCDEF0) as little-endian
        assert_eq!(buffer[4], 0xF0);
        assert_eq!(buffer[5], 0xDE);
        assert_eq!(buffer[6], 0xBC);
        assert_eq!(buffer[7], 0x9A);

        // LocalVariable index (0x11223344) as little-endian
        assert_eq!(buffer[8], 0x44);
        assert_eq!(buffer[9], 0x33);
        assert_eq!(buffer[10], 0x22);
        assert_eq!(buffer[11], 0x11);

        // LocalConstant index (0x55667788) as little-endian
        assert_eq!(buffer[12], 0x88);
        assert_eq!(buffer[13], 0x77);
        assert_eq!(buffer[14], 0x66);
        assert_eq!(buffer[15], 0x55);

        // Start offset (0xAABBCCDD) as little-endian
        assert_eq!(buffer[16], 0xDD);
        assert_eq!(buffer[17], 0xCC);
        assert_eq!(buffer[18], 0xBB);
        assert_eq!(buffer[19], 0xAA);

        // Length (0xEEFF0011) as little-endian
        assert_eq!(buffer[20], 0x11);
        assert_eq!(buffer[21], 0x00);
        assert_eq!(buffer[22], 0xFF);
        assert_eq!(buffer[23], 0xEE);
    }

    #[test]
    fn test_null_optional_indices() {
        // Test with null/zero values for optional indices
        let local_scope = LocalScopeRaw {
            rid: 1,
            token: Token::new(0x3200_0001),
            offset: 0,
            method: 1,        // Required method reference
            import_scope: 0,  // No import scope
            variable_list: 0, // No variables
            constant_list: 0, // No constants
            start_offset: 0x100,
            length: 0x50,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (crate::metadata::tables::TableId::MethodDef, 100),
                (crate::metadata::tables::TableId::ImportScope, 100),
                (crate::metadata::tables::TableId::LocalVariable, 100),
                (crate::metadata::tables::TableId::LocalConstant, 100),
            ],
            false,
            false,
            false,
        ));

        let row_size = <LocalScopeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        local_scope
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Verify that zero values are preserved
        let mut read_offset = 0;
        let deserialized_row = LocalScopeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.method, 1);
        assert_eq!(deserialized_row.import_scope, 0);
        assert_eq!(deserialized_row.variable_list, 0);
        assert_eq!(deserialized_row.constant_list, 0);
        assert_eq!(deserialized_row.start_offset, 0x100);
        assert_eq!(deserialized_row.length, 0x50);
    }
}

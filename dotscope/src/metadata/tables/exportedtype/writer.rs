//! `ExportedType` table binary writer implementation
//!
//! Provides binary serialization implementation for the `ExportedType` metadata table (0x27) through
//! the [`crate::metadata::tables::types::RowWritable`] trait. This module handles the low-level
//! serialization of `ExportedType` table entries to the metadata tables stream format.
//!
//! # Binary Format Support
//!
//! The writer supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for assemblies with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger assemblies)
//!
//! # Row Layout
//!
//! `ExportedType` table rows are serialized with this binary structure:
//! - `flags` (4 bytes): Type attributes bitmask
//! - `type_def_id` (4 bytes): TypeDef identifier hint
//! - `name` (2/4 bytes): String heap index for type name
//! - `namespace` (2/4 bytes): String heap index for type namespace
//! - `implementation` (2/4 bytes): Implementation coded index
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
//! - [`crate::metadata::tables::exportedtype::ExportedTypeRaw`]: Raw exported type data structure
//! - [`crate::file::io`]: Low-level binary I/O operations
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification

use crate::{
    metadata::tables::{
        exportedtype::ExportedTypeRaw,
        types::{RowWritable, TableInfoRef},
        CodedIndexType,
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ExportedTypeRaw {
    /// Write an `ExportedType` table row to binary data
    ///
    /// Serializes one `ExportedType` table entry to the metadata tables stream format, handling
    /// variable-width heap indexes and coded indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this exported type entry (unused for `ExportedType`)
    /// * `sizes` - Table sizing information for writing heap indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized exported type row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Flags (4 bytes, little-endian)
    /// 2. TypeDef ID (4 bytes, little-endian)
    /// 3. Name string index (2/4 bytes, little-endian)
    /// 4. Namespace string index (2/4 bytes, little-endian)  
    /// 5. Implementation coded index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write fixed-size fields first
        write_le_at(data, offset, self.flags)?;
        write_le_at(data, offset, self.type_def_id)?;

        // Write variable-size heap indexes
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;
        write_le_at_dyn(data, offset, self.namespace, sizes.is_large_str())?;

        // Write coded index
        let encoded_index = self.implementation.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            encoded_index,
            sizes.coded_index_bits(CodedIndexType::Implementation) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        tables::{
            types::{RowReadable, TableId, TableInfo, TableRow},
            CodedIndex,
        },
        token::Token,
    };

    #[test]
    fn test_round_trip_serialization_short() {
        // Create test data using same values as reader tests
        let original_row = ExportedTypeRaw {
            rid: 1,
            token: Token::new(0x27000001),
            offset: 0,
            flags: 0x01010101,
            type_def_id: 0x02020202,
            name: 0x0303,
            namespace: 0x0404,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation),
        };

        // Create minimal table info for testing (small heap)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, 1),
                (TableId::File, 10),        // Add File table
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <ExportedTypeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ExportedTypeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(original_row.type_def_id, deserialized_row.type_def_id);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.namespace, deserialized_row.namespace);
        assert_eq!(original_row.implementation, deserialized_row.implementation);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_round_trip_serialization_long() {
        // Create test data using same values as reader tests (large heap)
        let original_row = ExportedTypeRaw {
            rid: 1,
            token: Token::new(0x27000001),
            offset: 0,
            flags: 0x01010101,
            type_def_id: 0x02020202,
            name: 0x03030303,
            namespace: 0x04040404,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation),
        };

        // Create minimal table info for testing (large heap)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
            ],
            true,
            true,
            true,
        ));

        // Calculate buffer size and serialize
        let row_size = <ExportedTypeRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ExportedTypeRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.flags, deserialized_row.flags);
        assert_eq!(original_row.type_def_id, deserialized_row.type_def_id);
        assert_eq!(original_row.name, deserialized_row.name);
        assert_eq!(original_row.namespace, deserialized_row.namespace);
        assert_eq!(original_row.implementation, deserialized_row.implementation);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_short() {
        // Use same test data as reader tests to verify binary compatibility
        let expected_data = vec![
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, // name
            0x04, 0x04, // namespace
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let row = ExportedTypeRaw {
            rid: 1,
            token: Token::new(0x27000001),
            offset: 0,
            flags: 0x01010101,
            type_def_id: 0x02020202,
            name: 0x0303,
            namespace: 0x0404,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation),
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, 1),
                (TableId::File, 10),        // Add File table
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));

        let row_size = <ExportedTypeRaw as TableRow>::row_size(&table_info) as usize;
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, 0x03, 0x03, // name
            0x04, 0x04, 0x04, 0x04, // namespace
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let row = ExportedTypeRaw {
            rid: 1,
            token: Token::new(0x27000001),
            offset: 0,
            flags: 0x01010101,
            type_def_id: 0x02020202,
            name: 0x03030303,
            namespace: 0x04040404,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation),
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
            ],
            true,
            true,
            true,
        ));

        let row_size = <ExportedTypeRaw as TableRow>::row_size(&table_info) as usize;
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

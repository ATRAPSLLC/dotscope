//! `ParamPtr` table binary writer implementation
//!
//! Provides binary serialization implementation for the `ParamPtr` metadata table (0x07) through
//! the [`crate::metadata::tables::types::RowWritable`] trait. This module handles the low-level
//! serialization of `ParamPtr` table entries to the metadata tables stream format.
//!
//! # Binary Format Support
//!
//! The writer supports both small and large table index formats:
//! - **Small indexes**: 2-byte table references (for tables with < 64K entries)
//! - **Large indexes**: 4-byte table references (for larger tables)
//!
//! # Row Layout
//!
//! `ParamPtr` table rows are serialized with this binary structure:
//! - `param` (2/4 bytes): Param table index for indirection
//!
//! # Architecture
//!
//! This implementation provides efficient serialization by writing data directly to the
//! target buffer without intermediate allocations. All table references are written as
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
//! - [`crate::metadata::tables::paramptr::ParamPtrRaw`]: Raw parameter pointer data structure
//! - [`crate::io`]: Low-level binary I/O operations
//!
//! # Reference
//! - [ECMA-335 II.22.26](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ParamPtr` table specification

use crate::{
    metadata::tables::{
        paramptr::ParamPtrRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for ParamPtrRaw {
    /// Write a `ParamPtr` table row to binary data
    ///
    /// Serializes one `ParamPtr` table entry to the metadata tables stream format, handling
    /// variable-width table indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier for this parameter pointer entry (unused for `ParamPtr`)
    /// * `sizes` - Table sizing information for writing table indexes
    ///
    /// # Returns
    /// * `Ok(())` - Successfully serialized parameter pointer row
    /// * `Err(`[`crate::Error`]`)` - If buffer is too small or write fails
    ///
    /// # Binary Format
    /// Fields are written in the exact order specified by ECMA-335:
    /// 1. Param table index (2/4 bytes, little-endian)
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write the single field
        write_le_at_dyn(data, offset, self.param, sizes.is_large(TableId::Param))?;

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
        let original_row = ParamPtrRaw {
            rid: 1,
            token: Token::new(0x07000001),
            offset: 0,
            param: 0x0101,
        };

        // Create minimal table info for testing (small table)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <ParamPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ParamPtrRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.param, deserialized_row.param);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_round_trip_serialization_long() {
        // Create test data using same values as reader tests (large table)
        let original_row = ParamPtrRaw {
            rid: 1,
            token: Token::new(0x07000001),
            offset: 0,
            param: 0x01010101,
        };

        // Create minimal table info for testing (large table)
        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));

        // Calculate buffer size and serialize
        let row_size = <ParamPtrRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = ParamPtrRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        // Compare all fields
        assert_eq!(original_row.param, deserialized_row.param);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_short() {
        // Use same test data as reader tests to verify binary compatibility
        let expected_data = vec![
            0x01, 0x01, // param
        ];

        let row = ParamPtrRaw {
            rid: 1,
            token: Token::new(0x07000001),
            offset: 0,
            param: 0x0101,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            false,
            false,
            false,
        ));

        let row_size = <ParamPtrRaw as TableRow>::row_size(&table_info) as usize;
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
        // Use same test data as reader tests to verify binary compatibility (large table)
        let expected_data = vec![
            0x01, 0x01, 0x01, 0x01, // param
        ];

        let row = ParamPtrRaw {
            rid: 1,
            token: Token::new(0x07000001),
            offset: 0,
            param: 0x01010101,
        };

        let table_info = std::sync::Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));

        let row_size = <ParamPtrRaw as TableRow>::row_size(&table_info) as usize;
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

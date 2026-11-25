//! Implementation of `RowWritable` for `ClassLayoutRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `ClassLayout` table (ID 0x0F),
//! enabling writing of type layout information back to .NET PE files. The ClassLayout table
//! specifies explicit memory layout constraints for types that require specific field positioning
//! and packing, commonly used for interoperability scenarios.
//!
//! ## Table Structure (ECMA-335 §II.22.8)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `PackingSize` | u16 | Field alignment boundary in bytes (power of 2) |
//! | `ClassSize` | u32 | Total size of the type in bytes |
//! | `Parent` | TypeDef table index | Type that this layout applies to |
//!
//! ## Memory Layout Control
//!
//! ClassLayout entries provide precise control over type memory representation:
//! - **PackingSize**: Byte boundary alignment for fields (must be power of 2)
//! - **ClassSize**: Explicit type size override (0 for automatic sizing)
//! - **Parent**: Link to the type definition requiring these layout constraints

use crate::{
    metadata::tables::{
        classlayout::ClassLayoutRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ClassLayoutRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent, 0)))
    }

    /// Serialize a ClassLayout table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.8 specification:
    /// - `packing_size`: 2-byte alignment boundary (must be power of 2)
    /// - `class_size`: 4-byte explicit type size (0 for automatic)
    /// - `parent`: TypeDef table index (type requiring layout constraints)
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
        // Write packing size (2 bytes)
        write_le_at(data, offset, self.packing_size)?;

        // Write class size (4 bytes)
        write_le_at(data, offset, self.class_size)?;

        // Write TypeDef table index for parent
        write_le_at_dyn(data, offset, self.parent, sizes.is_large(TableId::TypeDef))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            classlayout::ClassLayoutRaw,
            types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_classlayout_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 4 + 2; // packing_size(2) + class_size(4) + parent(2)
        assert_eq!(
            <ClassLayoutRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 2 + 4 + 4; // packing_size(2) + class_size(4) + parent(4)
        assert_eq!(
            <ClassLayoutRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_classlayout_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let class_layout = ClassLayoutRaw {
            rid: 1,
            token: Token::new(0x0F000001),
            offset: 0,
            packing_size: 0x0101,
            class_size: 0x02020202,
            parent: 0x0303,
        };

        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        class_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // packing_size: 0x0101, little-endian
            0x02, 0x02, 0x02, 0x02, // class_size: 0x02020202, little-endian
            0x03, 0x03, // parent: 0x0303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_classlayout_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000)],
            false,
            false,
            false,
        ));

        let class_layout = ClassLayoutRaw {
            rid: 1,
            token: Token::new(0x0F000001),
            offset: 0,
            packing_size: 0x0101,
            class_size: 0x02020202,
            parent: 0x03030303,
        };

        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        class_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // packing_size: 0x0101, little-endian
            0x02, 0x02, 0x02, 0x02, // class_size: 0x02020202, little-endian
            0x03, 0x03, 0x03, 0x03, // parent: 0x03030303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_classlayout_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let original = ClassLayoutRaw {
            rid: 42,
            token: Token::new(0x0F00002A),
            offset: 0,
            packing_size: 8, // 8-byte alignment
            class_size: 64,  // 64 bytes total size
            parent: 25,      // TypeDef index 25
        };

        // Write to buffer
        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = ClassLayoutRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.packing_size, read_back.packing_size);
        assert_eq!(original.class_size, read_back.class_size);
        assert_eq!(original.parent, read_back.parent);
    }

    #[test]
    fn test_classlayout_different_layout_values() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        // Test different common layout configurations
        let test_cases = vec![
            (1, 0, 1),     // No alignment, auto size
            (2, 16, 5),    // 2-byte alignment, 16 bytes
            (4, 32, 10),   // 4-byte alignment, 32 bytes
            (8, 64, 15),   // 8-byte alignment, 64 bytes
            (16, 128, 20), // 16-byte alignment, 128 bytes
            (0, 0, 50),    // Default alignment, auto size
        ];

        for (packing, class_size, parent) in test_cases {
            let class_layout = ClassLayoutRaw {
                rid: 1,
                token: Token::new(0x0F000001),
                offset: 0,
                packing_size: packing,
                class_size,
                parent,
            };

            let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            class_layout
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = ClassLayoutRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(class_layout.packing_size, read_back.packing_size);
            assert_eq!(class_layout.class_size, read_back.class_size);
            assert_eq!(class_layout.parent, read_back.parent);
        }
    }

    #[test]
    fn test_classlayout_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_layout = ClassLayoutRaw {
            rid: 1,
            token: Token::new(0x0F000001),
            offset: 0,
            packing_size: 0,
            class_size: 0,
            parent: 0,
        };

        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // packing_size: 0
            0x00, 0x00, 0x00, 0x00, // class_size: 0
            0x00, 0x00, // parent: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values
        let max_layout = ClassLayoutRaw {
            rid: 1,
            token: Token::new(0x0F000001),
            offset: 0,
            packing_size: 0xFFFF,
            class_size: 0xFFFFFFFF,
            parent: 0xFFFF,
        };

        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 8); // 2 + 4 + 2 bytes
    }

    #[test]
    fn test_classlayout_power_of_two_packing() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        // Test valid power-of-2 packing sizes
        let valid_packing_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

        for &packing_size in &valid_packing_sizes {
            let class_layout = ClassLayoutRaw {
                rid: 1,
                token: Token::new(0x0F000001),
                offset: 0,
                packing_size,
                class_size: 32,
                parent: 10,
            };

            let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            class_layout
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the packing size is written correctly
            let written_packing = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_packing, packing_size);
        }
    }

    #[test]
    fn test_classlayout_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1)],
            false,
            false,
            false,
        ));

        let class_layout = ClassLayoutRaw {
            rid: 1,
            token: Token::new(0x0F000001),
            offset: 0,
            packing_size: 0x0101,
            class_size: 0x02020202,
            parent: 0x0303,
        };

        let mut buffer = vec![0u8; <ClassLayoutRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        class_layout
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // packing_size
            0x02, 0x02, 0x02, 0x02, // class_size
            0x03, 0x03, // parent
        ];

        assert_eq!(buffer, expected);
    }
}

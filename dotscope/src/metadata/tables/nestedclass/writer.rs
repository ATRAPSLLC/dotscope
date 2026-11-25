//! Implementation of `RowWritable` for `NestedClassRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `NestedClass` table (ID 0x29),
//! enabling writing of nested class relationships back to .NET PE files. The NestedClass table
//! defines hierarchical relationships between nested types and their enclosing types, specifying
//! type containment and scoping information.
//!
//! ## Table Structure (ECMA-335 §II.22.32)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `NestedClass` | TypeDef table index | Type that is nested within enclosing type |
//! | `EnclosingClass` | TypeDef table index | Type that contains the nested type |
//!
//! ## Type Relationships
//!
//! NestedClass entries establish containment relationships:
//! - **Containment**: The nested type is contained within the enclosing type
//! - **Scoping**: Nested types inherit accessibility from their container
//! - **Resolution**: Type names are resolved relative to the enclosing context

use crate::{
    metadata::tables::{
        nestedclass::NestedClassRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for NestedClassRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.nested_class, 0)))
    }

    /// Serialize a NestedClass table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.32 specification:
    /// - `nested_class`: TypeDef table index (type that is nested)
    /// - `enclosing_class`: TypeDef table index (type that contains the nested type)
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
        // Write TypeDef table index for nested_class
        write_le_at_dyn(
            data,
            offset,
            self.nested_class,
            sizes.is_large(TableId::TypeDef),
        )?;

        // Write TypeDef table index for enclosing_class
        write_le_at_dyn(
            data,
            offset,
            self.enclosing_class,
            sizes.is_large(TableId::TypeDef),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            nestedclass::NestedClassRaw,
            types::{RowReadable, RowWritable, TableId, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_nestedclass_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // nested_class(2) + enclosing_class(2)
        assert_eq!(
            <NestedClassRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000)],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // nested_class(4) + enclosing_class(4)
        assert_eq!(
            <NestedClassRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_nestedclass_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let nested_class = NestedClassRaw {
            rid: 1,
            token: Token::new(0x29000001),
            offset: 0,
            nested_class: 0x0101,
            enclosing_class: 0x0202,
        };

        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        nested_class
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // nested_class: 0x0101, little-endian
            0x02, 0x02, // enclosing_class: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_nestedclass_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000)],
            false,
            false,
            false,
        ));

        let nested_class = NestedClassRaw {
            rid: 1,
            token: Token::new(0x29000001),
            offset: 0,
            nested_class: 0x01010101,
            enclosing_class: 0x02020202,
        };

        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        nested_class
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // nested_class: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // enclosing_class: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_nestedclass_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        let original = NestedClassRaw {
            rid: 42,
            token: Token::new(0x2900002A),
            offset: 0,
            nested_class: 25,
            enclosing_class: 50,
        };

        // Write to buffer
        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = NestedClassRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.nested_class, read_back.nested_class);
        assert_eq!(original.enclosing_class, read_back.enclosing_class);
    }

    #[test]
    fn test_nestedclass_different_relationships() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        // Test different nesting relationships
        let test_cases = vec![
            (1, 2),   // Simple nesting
            (10, 1),  // Nested in first type
            (5, 10),  // Different ordering
            (99, 98), // High index values
        ];

        for (nested, enclosing) in test_cases {
            let nested_class = NestedClassRaw {
                rid: 1,
                token: Token::new(0x29000001),
                offset: 0,
                nested_class: nested,
                enclosing_class: enclosing,
            };

            let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            nested_class
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = NestedClassRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(nested_class.nested_class, read_back.nested_class);
            assert_eq!(nested_class.enclosing_class, read_back.enclosing_class);
        }
    }

    #[test]
    fn test_nestedclass_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_nested = NestedClassRaw {
            rid: 1,
            token: Token::new(0x29000001),
            offset: 0,
            nested_class: 0,
            enclosing_class: 0,
        };

        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_nested
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // nested_class: 0
            0x00, 0x00, // enclosing_class: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_nested = NestedClassRaw {
            rid: 1,
            token: Token::new(0x29000001),
            offset: 0,
            nested_class: 0xFFFF,
            enclosing_class: 0xFFFF,
        };

        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_nested
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_nestedclass_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::NestedClass, 1), (TableId::TypeDef, 10)],
            false,
            false,
            false,
        ));

        let nested_class = NestedClassRaw {
            rid: 1,
            token: Token::new(0x29000001),
            offset: 0,
            nested_class: 0x0101,
            enclosing_class: 0x0202,
        };

        let mut buffer = vec![0u8; <NestedClassRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        nested_class
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // nested_class
            0x02, 0x02, // enclosing_class
        ];

        assert_eq!(buffer, expected);
    }
}

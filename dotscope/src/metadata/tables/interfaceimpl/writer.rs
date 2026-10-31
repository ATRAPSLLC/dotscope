//! Implementation of `RowWritable` for `InterfaceImplRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `InterfaceImpl` table (ID 0x09),
//! enabling writing of interface implementation metadata back to .NET PE files. The InterfaceImpl table
//! defines which interfaces are implemented by which types, including both true interface
//! implementations and interface-to-interface inheritance relationships.
//!
//! ## Table Structure (ECMA-335 §II.22.23)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Class` | `TypeDef` table index | Type that implements the interface |
//! | `Interface` | `TypeDefOrRef` coded index | Interface being implemented |
//!
//! ## Interface Implementation Types
//!
//! The InterfaceImpl table handles both:
//! - **Interface Implementation**: Classes implementing interfaces
//! - **Interface Inheritance**: Interfaces extending other interfaces (compiler quirk)

use crate::{
    metadata::tables::{
        interfaceimpl::InterfaceImplRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for InterfaceImplRaw {
    // By class alone: within a class the rows stay in declaration order,
    // which is the order the type lists its interfaces in. Compilers do not
    // sort by the interface, and the format does not ask them to.
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.class, 0)))
    }

    /// Write an InterfaceImpl table row to binary data
    ///
    /// Serializes one InterfaceImpl table entry to the metadata tables stream format, handling
    /// variable-width indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `class` - `TypeDef` table index (2 or 4 bytes)
    /// 2. `interface` - `TypeDefOrRef` coded index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for InterfaceImpl serialization)
    /// * `sizes` - Table size information for determining index widths
    ///
    /// # Returns
    /// `Ok(())` on successful serialization, error if buffer is too small
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target buffer is too small for the row data
    /// - The coded index cannot be encoded
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write class TypeDef table index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.class, sizes.is_large(TableId::TypeDef))?;

        // Write interface coded index (2 or 4 bytes)
        let encoded_interface = self.interface.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            encoded_interface,
            sizes.coded_index_bits(CodedIndexType::TypeDefOrRef) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::{
        tables::{
            types::{RowReadable, TableInfo, TableRow},
            CodedIndex, TableId,
        },
        token::Token,
    };

    #[test]
    fn test_row_size() {
        // Test with small tables
        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        let size = <InterfaceImplRaw as TableRow>::row_size(&table_info);
        // class(2) + interface(2) = 4
        assert_eq!(size, 4);

        // Test with large tables
        let table_info_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 70000),
                (TableId::TypeRef, 70000),
                (TableId::TypeSpec, 70000),
            ],
            false,
            false,
            false,
        ));

        let size_large = <InterfaceImplRaw as TableRow>::row_size(&table_info_large);
        // class(4) + interface(4) = 8
        assert_eq!(size_large, 8);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = InterfaceImplRaw {
            rid: 1,
            token: Token::new(0x09000001),
            offset: 0,
            class: 0x0101,
            interface: CodedIndex::new(TableId::TypeSpec, 0x80, CodedIndexType::TypeDefOrRef),
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1000),
                (TableId::TypeRef, 1000),
                (TableId::TypeSpec, 1000),
            ],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <InterfaceImplRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            InterfaceImplRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.class, original_row.class);
        assert_eq!(deserialized_row.interface, original_row.interface);
        assert_eq!(offset, row_size, "Offset should match expected row size");
    }

    #[test]
    fn test_known_binary_format_small() {
        // Test with known binary data from reader tests
        let data = vec![
            0x01, 0x01, // class (0x0101)
            0x02, 0x02, // interface
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::InterfaceImpl, 1)],
            false,
            false,
            false,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = InterfaceImplRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_known_binary_format_large() {
        // Test with known binary data from reader tests (large variant)
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // class (0x01010101)
            0x02, 0x02, 0x02, 0x02, // interface
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 2)],
            true,
            true,
            true,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = InterfaceImplRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_coded_index_types() {
        // Test different coded index target types
        let test_cases = vec![
            (TableId::TypeDef, "TypeDef"),
            (TableId::TypeRef, "TypeRef"),
            (TableId::TypeSpec, "TypeSpec"),
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        for (table_id, description) in test_cases {
            let interface_impl_row = InterfaceImplRaw {
                rid: 1,
                token: Token::new(0x09000001),
                offset: 0,
                class: 1,
                interface: CodedIndex::new(table_id, 1, CodedIndexType::TypeDefOrRef),
            };

            let row_size = <InterfaceImplRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            interface_impl_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                InterfaceImplRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.interface.tag, interface_impl_row.interface.tag,
                "Interface type tag should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_table_serialization() {
        // Test with large tables to ensure 4-byte indexes are handled correctly
        let original_row = InterfaceImplRaw {
            rid: 1,
            token: Token::new(0x09000001),
            offset: 0,
            class: 0x12345,
            interface: CodedIndex::new(TableId::TypeRef, 0x8000, CodedIndexType::TypeDefOrRef),
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 70000),
                (TableId::TypeRef, 70000),
                (TableId::TypeSpec, 70000),
            ],
            false,
            false,
            false,
        ));

        let row_size = <InterfaceImplRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large table serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            InterfaceImplRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Large table deserialization should succeed");

        assert_eq!(deserialized_row.class, original_row.class);
        assert_eq!(deserialized_row.interface, original_row.interface);
    }

    #[test]
    fn test_edge_cases() {
        // Test with minimal values
        let minimal_interface_impl = InterfaceImplRaw {
            rid: 1,
            token: Token::new(0x09000001),
            offset: 0,
            class: 1, // First type
            interface: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef),
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::TypeRef, 100),
                (TableId::TypeSpec, 100),
            ],
            false,
            false,
            false,
        ));

        let row_size = <InterfaceImplRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        minimal_interface_impl
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Minimal interface impl serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row =
            InterfaceImplRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                .expect("Minimal interface impl deserialization should succeed");

        assert_eq!(deserialized_row.class, minimal_interface_impl.class);
        assert_eq!(deserialized_row.interface, minimal_interface_impl.interface);
    }

    #[test]
    fn test_different_table_combinations() {
        // Test with different combinations of table sizes
        let interface_impl_row = InterfaceImplRaw {
            rid: 1,
            token: Token::new(0x09000001),
            offset: 0,
            class: 0x8000,
            // TypeDefOrRef takes two tag bits: row 0x3FFF is the highest a two-byte column holds
            interface: CodedIndex::new(TableId::TypeDef, 0x3FFF, CodedIndexType::TypeDefOrRef),
        };

        // Test combinations: (large_typedef, large_other_tables, expected_size)
        let test_cases = vec![
            (1000, 1000, 4),   // small typedef, small coded: 2+2 = 4
            (70000, 1000, 8),  // large typedef, large coded (due to typedef): 4+4 = 8
            (1000, 70000, 6),  // small typedef, large coded: 2+4 = 6
            (70000, 70000, 8), // large typedef, large coded: 4+4 = 8
        ];

        for (typedef_size, other_size, expected_size) in test_cases {
            let table_info = Arc::new(TableInfo::new_test(
                &[
                    (TableId::TypeDef, typedef_size),
                    (TableId::TypeRef, other_size),
                    (TableId::TypeSpec, other_size),
                ],
                false, // string heap size doesn't matter
                false, // blob heap size doesn't matter
                false, // guid heap size doesn't matter
            ));

            let size = <InterfaceImplRaw as TableRow>::row_size(&table_info) as usize;
            assert_eq!(
                size, expected_size,
                "Row size should be {expected_size} for typedef_size={typedef_size}, other_size={other_size}"
            );

            let mut buffer = vec![0u8; size];
            let mut offset = 0;

            interface_impl_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .expect("Serialization should succeed");

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                InterfaceImplRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .expect("Deserialization should succeed");

            assert_eq!(deserialized_row.class, interface_impl_row.class);
            assert_eq!(
                deserialized_row.interface.tag,
                interface_impl_row.interface.tag
            );
            assert_eq!(
                deserialized_row.interface.row,
                interface_impl_row.interface.row
            );
        }
    }
}

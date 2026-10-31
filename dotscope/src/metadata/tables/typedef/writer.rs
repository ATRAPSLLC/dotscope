//! Implementation of `RowWritable` for `TypeDefRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `TypeDef` table (ID 0x02),
//! enabling writing of type definition metadata back to .NET PE files. The TypeDef table
//! defines all types (classes, interfaces, value types, enums) within the current module.
//!
//! ## Table Structure (ECMA-335 §II.22.37)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Flags` | `u32` | Type attributes bitmask |
//! | `TypeName` | String heap index | Simple name of the type |
//! | `TypeNamespace` | String heap index | Namespace containing the type |
//! | `Extends` | Coded index | Base type reference (`TypeDefOrRef`) |
//! | `FieldList` | Field table index | First field belonging to this type |
//! | `MethodList` | MethodDef table index | First method belonging to this type |
//!
//! ## Coded Index Encoding
//!
//! The `Extends` field uses a `TypeDefOrRef` coded index that can reference:
//! - `TypeDef` (tag 0) - Base type defined in current module
//! - `TypeRef` (tag 1) - Base type from external assembly
//! - `TypeSpec` (tag 2) - Generic or complex base type

use crate::{
    metadata::tables::{
        typedef::TypeDefRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for TypeDefRaw {
    /// Write a TypeDef table row to binary data
    ///
    /// Serializes one TypeDef table entry to the metadata tables stream format, handling
    /// variable-width heap and table indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `flags` - Type attributes as 4-byte little-endian value
    /// 2. `type_name` - String heap index (2 or 4 bytes)
    /// 3. `type_namespace` - String heap index (2 or 4 bytes)
    /// 4. `extends` - TypeDefOrRef coded index (2 or 4 bytes)
    /// 5. `field_list` - Field table index (2 or 4 bytes)
    /// 6. `method_list` - MethodDef table index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for TypeDef serialization)
    /// * `sizes` - Table size information for determining index widths
    ///
    /// # Returns
    /// `Ok(())` on successful serialization, error if buffer is too small
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target buffer is too small for the row data
    /// - Coded index encoding fails due to invalid table references
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write flags (4 bytes)
        write_le_at(data, offset, self.flags)?;

        // Write type name string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.type_name, sizes.is_large_str())?;

        // Write type namespace string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.type_namespace, sizes.is_large_str())?;

        // Write extends coded index (2 or 4 bytes)
        let extends_value = self.extends.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            extends_value,
            sizes.coded_index_bits(CodedIndexType::TypeDefOrRef) > 16,
        )?;

        // Write field list table index (2 or 4 bytes)
        write_le_at_dyn(
            data,
            offset,
            self.field_list,
            sizes.is_large(TableId::Field),
        )?;

        // Write method list table index (2 or 4 bytes)
        write_le_at_dyn(
            data,
            offset,
            self.method_list,
            sizes.is_large(TableId::MethodDef),
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
            CodedIndex, CodedIndexType,
        },
        token::Token,
    };

    #[test]
    fn test_row_size() {
        // Test with small heaps
        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        let size = <TypeDefRaw as TableRow>::row_size(&table_info);
        // flags(4) + type_name(2) + type_namespace(2) + extends(2) + field_list(2) + method_list(2) = 14
        assert_eq!(size, 14);

        // Test with large heaps
        let table_info_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 70000),
                (TableId::MethodDef, 70000),
                (TableId::TypeDef, 70000), // Make TypeDefOrRef coded index large
            ],
            true,
            false,
            false,
        ));

        let size_large = <TypeDefRaw as TableRow>::row_size(&table_info_large);
        // flags(4) + type_name(4) + type_namespace(4) + extends(4) + field_list(4) + method_list(4) = 24
        assert_eq!(size_large, 24);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = TypeDefRaw {
            rid: 1,
            token: Token::new(0x02000001),
            offset: 0,
            flags: 0x01000000,
            type_name: 0x42,
            type_namespace: 0x43,
            extends: CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef),
            field_list: 3,
            method_list: 4,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        // Calculate buffer size and serialize
        let row_size = <TypeDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = TypeDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.type_name, original_row.type_name);
        assert_eq!(deserialized_row.type_namespace, original_row.type_namespace);
        assert_eq!(deserialized_row.extends.tag, original_row.extends.tag);
        assert_eq!(deserialized_row.extends.row, original_row.extends.row);
        assert_eq!(deserialized_row.field_list, original_row.field_list);
        assert_eq!(deserialized_row.method_list, original_row.method_list);
    }

    #[test]
    fn test_known_binary_format() {
        // Test with known binary data from reader tests
        let data = vec![
            0x00, 0x00, 0x00, 0x01, // flags
            0x42, 0x00, // type_name
            0x43, 0x00, // type_namespace
            0x00, 0x02, // extends
            0x00, 0x03, // field_list
            0x00, 0x04, // method_list
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = TypeDefRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
    fn test_encode_coded_index() {
        // Test TypeDefOrRef encoding using TableInfo::encode_coded_index
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // TypeDef is index 0 in TypeDefOrRef tables, so: (5 << 2) | 0 = 20
        let encoded = table_info
            .encode_coded_index(TableId::TypeDef, 5, CodedIndexType::TypeDefOrRef)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 20);

        // TypeRef is index 1 in TypeDefOrRef tables, so: (3 << 2) | 1 = 13
        let encoded = table_info
            .encode_coded_index(TableId::TypeRef, 3, CodedIndexType::TypeDefOrRef)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 13);

        // TypeSpec is index 2 in TypeDefOrRef tables, so: (7 << 2) | 2 = 30
        let encoded = table_info
            .encode_coded_index(TableId::TypeSpec, 7, CodedIndexType::TypeDefOrRef)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 30);
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = TypeDefRaw {
            rid: 1,
            token: Token::new(0x02000001),
            offset: 0,
            flags: 0x00100001, // Public | Class
            type_name: 0x12345,
            type_namespace: 0x67890,
            extends: CodedIndex::new(TableId::TypeSpec, 0x4000, CodedIndexType::TypeDefOrRef), // Large row index
            field_list: 0x8000,
            method_list: 0x9000,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 70000),
                (TableId::MethodDef, 70000),
                (TableId::TypeDef, 70000), // Make TypeDefOrRef coded index large
            ],
            true,
            false,
            false,
        ));

        let row_size = <TypeDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = TypeDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.type_name, original_row.type_name);
        assert_eq!(deserialized_row.type_namespace, original_row.type_namespace);
        assert_eq!(deserialized_row.extends.tag, original_row.extends.tag);
        assert_eq!(deserialized_row.extends.row, original_row.extends.row);
        assert_eq!(deserialized_row.field_list, original_row.field_list);
        assert_eq!(deserialized_row.method_list, original_row.method_list);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (null references)
        let zero_row = TypeDefRaw {
            rid: 1,
            token: Token::new(0x02000001),
            offset: 0,
            flags: 0,
            type_name: 0,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef), // Null base type
            field_list: 0,
            method_list: 0,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1), (TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));

        let row_size = <TypeDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        zero_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Zero value serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = TypeDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Zero value deserialization should succeed");

        assert_eq!(deserialized_row.flags, zero_row.flags);
        assert_eq!(deserialized_row.type_name, zero_row.type_name);
        assert_eq!(deserialized_row.type_namespace, zero_row.type_namespace);
        assert_eq!(deserialized_row.extends.row, zero_row.extends.row);
        assert_eq!(deserialized_row.field_list, zero_row.field_list);
        assert_eq!(deserialized_row.method_list, zero_row.method_list);
    }
}

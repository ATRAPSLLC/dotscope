//! Implementation of `RowWritable` for `TypeRefRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `TypeRef` table (ID 0x01),
//! enabling writing of external type reference metadata back to .NET PE files. The TypeRef table
//! contains references to types defined in external assemblies or modules.
//!
//! ## Table Structure (ECMA-335 §II.22.38)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `ResolutionScope` | Coded index | Parent scope (`ResolutionScope`) |
//! | `TypeName` | String heap index | Simple name of the referenced type |
//! | `TypeNamespace` | String heap index | Namespace containing the referenced type |
//!
//! ## Coded Index Encoding
//!
//! The `ResolutionScope` field uses a `ResolutionScope` coded index that can reference:
//! - `Module` (tag 0) - Type defined in the global module
//! - `ModuleRef` (tag 1) - Type defined in an external module
//! - `AssemblyRef` (tag 2) - Type defined in an external assembly (most common)
//! - `TypeRef` (tag 3) - Nested type where the parent is also external

use crate::{
    metadata::tables::{
        typeref::TypeRefRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for TypeRefRaw {
    /// Write a TypeRef table row to binary data
    ///
    /// Serializes one TypeRef table entry to the metadata tables stream format, handling
    /// variable-width heap and coded indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `resolution_scope` - ResolutionScope coded index (2 or 4 bytes)
    /// 2. `type_name` - String heap index (2 or 4 bytes)
    /// 3. `type_namespace` - String heap index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for TypeRef serialization)
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
        // Write resolution scope coded index (2 or 4 bytes)
        let scope_value = self.resolution_scope.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            scope_value,
            sizes.coded_index_bits(CodedIndexType::ResolutionScope) > 16,
        )?;

        // Write type name string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.type_name, sizes.is_large_str())?;

        // Write type namespace string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.type_namespace, sizes.is_large_str())?;

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
        // Test with small heaps
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let size = <TypeRefRaw as TableRow>::row_size(&table_info);
        // resolution_scope(2) + type_name(2) + type_namespace(2) = 6
        assert_eq!(size, 6);

        // Test with large heaps
        let table_info_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::AssemblyRef, 70000), // Make ResolutionScope coded index large
            ],
            true,
            false,
            false,
        ));

        let size_large = <TypeRefRaw as TableRow>::row_size(&table_info_large);
        // resolution_scope(4) + type_name(4) + type_namespace(4) = 12
        assert_eq!(size_large, 12);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = TypeRefRaw {
            rid: 1,
            token: Token::new(0x01000001),
            offset: 0,
            resolution_scope: CodedIndex::new(
                TableId::AssemblyRef,
                1,
                CodedIndexType::ResolutionScope,
            ),
            type_name: 0x0202,
            type_namespace: 0x0303,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Calculate buffer size and serialize
        let row_size = <TypeRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = TypeRefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(
            deserialized_row.resolution_scope.tag,
            original_row.resolution_scope.tag
        );
        assert_eq!(
            deserialized_row.resolution_scope.row,
            original_row.resolution_scope.row
        );
        assert_eq!(deserialized_row.type_name, original_row.type_name);
        assert_eq!(deserialized_row.type_namespace, original_row.type_namespace);
    }

    #[test]
    fn test_known_binary_format() {
        // Test with known binary data from reader tests
        let data = vec![
            0x01, 0x01, // resolution_scope
            0x02, 0x02, // type_name
            0x03, 0x03, // type_namespace
        ];

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = TypeRefRaw::row_read(&data, &mut read_offset, 1, &table_info)
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
    fn test_encode_resolution_scope() {
        // Test ResolutionScope encoding using TableInfo::encode_coded_index
        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Module is index 0 in ResolutionScope tables, so: (5 << 2) | 0 = 20
        let encoded = table_info
            .encode_coded_index(TableId::Module, 5, CodedIndexType::ResolutionScope)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 20);

        // ModuleRef is index 1 in ResolutionScope tables, so: (3 << 2) | 1 = 13
        let encoded = table_info
            .encode_coded_index(TableId::ModuleRef, 3, CodedIndexType::ResolutionScope)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 13);

        // AssemblyRef is index 2 in ResolutionScope tables, so: (7 << 2) | 2 = 30
        let encoded = table_info
            .encode_coded_index(TableId::AssemblyRef, 7, CodedIndexType::ResolutionScope)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 30);

        // TypeRef is index 3 in ResolutionScope tables, so: (4 << 2) | 3 = 19
        let encoded = table_info
            .encode_coded_index(TableId::TypeRef, 4, CodedIndexType::ResolutionScope)
            .expect("Encoding should succeed");
        assert_eq!(encoded, 19);
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = TypeRefRaw {
            rid: 1,
            token: Token::new(0x01000001),
            offset: 0,
            resolution_scope: CodedIndex::new(
                TableId::AssemblyRef,
                0x4000,
                CodedIndexType::ResolutionScope,
            ), // Large row index
            type_name: 0x12345,
            type_namespace: 0x67890,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[
                (TableId::AssemblyRef, 70000), // Make ResolutionScope coded index large
            ],
            true,
            false,
            false,
        ));

        let row_size = <TypeRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = TypeRefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(
            deserialized_row.resolution_scope.tag,
            original_row.resolution_scope.tag
        );
        assert_eq!(
            deserialized_row.resolution_scope.row,
            original_row.resolution_scope.row
        );
        assert_eq!(deserialized_row.type_name, original_row.type_name);
        assert_eq!(deserialized_row.type_namespace, original_row.type_namespace);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (null references)
        let zero_row = TypeRefRaw {
            rid: 1,
            token: Token::new(0x01000001),
            offset: 0,
            resolution_scope: CodedIndex::new(TableId::Module, 0, CodedIndexType::ResolutionScope), // Null scope
            type_name: 0,
            type_namespace: 0,
        };

        let table_info = Arc::new(TableInfo::new_test(&[], false, false, false));

        let row_size = <TypeRefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        zero_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Zero value serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = TypeRefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Zero value deserialization should succeed");

        assert_eq!(
            deserialized_row.resolution_scope.row,
            zero_row.resolution_scope.row
        );
        assert_eq!(deserialized_row.type_name, zero_row.type_name);
        assert_eq!(deserialized_row.type_namespace, zero_row.type_namespace);
    }
}

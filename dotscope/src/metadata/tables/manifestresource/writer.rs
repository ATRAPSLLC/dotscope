//! Implementation of `RowWritable` for `ManifestResourceRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `ManifestResource` table (ID 0x28),
//! enabling writing of resource metadata information back to .NET PE files. The ManifestResource
//! table describes resources embedded in or associated with the assembly, supporting embedded
//! resources, external resource files, and resources from referenced assemblies.
//!
//! ## Table Structure (ECMA-335 §II.22.24)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Offset` | u32 | Resource data offset (0 for external resources) |
//! | `Flags` | u32 | Resource visibility and access control attributes |
//! | `Name` | String heap index | Resource identifier name |
//! | `Implementation` | Implementation coded index | Resource location reference |
//!
//! ## Coded Index Types
//!
//! The Implementation field uses the `Implementation` coded index which can reference:
//! - **Tag 0 (File)**: References File table entries for external resource files
//! - **Tag 1 (AssemblyRef)**: References AssemblyRef table entries for external assembly resources
//! - **Tag 2 (ExportedType)**: References ExportedType table entries (rarely used for resources)
//! - **Row 0**: Special case indicating embedded resource in current assembly
//!
//! ## Usage Context
//!
//! ManifestResource entries are used for:
//! - **Embedded resources**: Binary data (.resources, images, configuration) within the assembly
//! - **External resource files**: Resources stored in separate files referenced by File table
//! - **Satellite assemblies**: Localized resources in referenced assemblies
//! - **Resource management**: Runtime resource lookup and access control

use crate::{
    metadata::tables::{
        manifestresource::ManifestResourceRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ManifestResourceRaw {
    /// Serialize a ManifestResource table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.24 specification:
    /// - `offset_field`: Resource data offset (4 bytes)
    /// - `flags`: Resource attribute flags (4 bytes)
    /// - `name`: String heap index (resource name)
    /// - `implementation`: Implementation coded index (resource location)
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
        // Write resource data offset
        write_le_at(data, offset, self.offset_field)?;

        // Write resource attribute flags
        write_le_at(data, offset, self.flags)?;

        // Write string heap index for resource name
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write Implementation coded index for resource location
        let implementation_value = self.implementation.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            implementation_value,
            sizes.coded_index_bits(CodedIndexType::Implementation) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            manifestresource::ManifestResourceRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_manifestresource_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 4 + 4 + 2 + 2; // offset_field(4) + flags(4) + name(2) + implementation(2)
        assert_eq!(
            <ManifestResourceRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 0x10000),
                (TableId::AssemblyRef, 0x10000),
                (TableId::ExportedType, 0x10000),
            ],
            true,
            false,
            false,
        ));

        let expected_size_large = 4 + 4 + 4 + 4; // offset_field(4) + flags(4) + name(4) + implementation(4)
        assert_eq!(
            <ManifestResourceRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_manifestresource_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        let manifest_resource = ManifestResourceRaw {
            rid: 1,
            token: Token::new(0x28000001),
            offset: 0,
            offset_field: 0x01010101,
            flags: 0x02020202,
            name: 0x0303,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation), // File(1) = (1 << 2) | 0 = 4
        };

        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        manifest_resource
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // offset_field: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // flags: 0x02020202, little-endian
            0x03, 0x03, // name: 0x0303, little-endian
            0x04, 0x00, // implementation: File(1) -> (1 << 2) | 0 = 4, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_manifestresource_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 0x10000),
                (TableId::AssemblyRef, 0x10000),
                (TableId::ExportedType, 0x10000),
            ],
            true,
            false,
            false,
        ));

        let manifest_resource = ManifestResourceRaw {
            rid: 1,
            token: Token::new(0x28000001),
            offset: 0,
            offset_field: 0x01010101,
            flags: 0x02020202,
            name: 0x03030303,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation), // File(1) = (1 << 2) | 0 = 4
        };

        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        manifest_resource
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // offset_field: 0x01010101, little-endian
            0x02, 0x02, 0x02, 0x02, // flags: 0x02020202, little-endian
            0x03, 0x03, 0x03, 0x03, // name: 0x03030303, little-endian
            0x04, 0x00, 0x00,
            0x00, // implementation: File(1) -> (1 << 2) | 0 = 4, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_manifestresource_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        let original = ManifestResourceRaw {
            rid: 42,
            token: Token::new(0x2800002A),
            offset: 0,
            offset_field: 0x12345678,
            flags: 0x87654321,
            name: 256, // String index 256
            implementation: CodedIndex::new(
                TableId::AssemblyRef,
                5,
                CodedIndexType::Implementation,
            ), // AssemblyRef(5) = (5 << 2) | 1 = 21
        };

        // Write to buffer
        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back =
            ManifestResourceRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.offset_field, read_back.offset_field);
        assert_eq!(original.flags, read_back.flags);
        assert_eq!(original.name, read_back.name);
        assert_eq!(original.implementation, read_back.implementation);
    }

    #[test]
    fn test_manifestresource_different_implementations() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        // Test different Implementation coded index types
        let test_cases = vec![
            (TableId::File, 1, 100, "External file resource"),
            (TableId::AssemblyRef, 2, 200, "External assembly resource"),
            (TableId::ExportedType, 3, 300, "Exported type resource"),
            (TableId::File, 0, 0, "Embedded resource (special case)"),
        ];

        for (impl_tag, impl_row, offset_field, _description) in test_cases {
            let manifest_resource = ManifestResourceRaw {
                rid: 1,
                token: Token::new(0x28000001),
                offset: 0,
                offset_field,
                flags: 0x00000001, // Public visibility
                name: 100,
                implementation: CodedIndex::new(impl_tag, impl_row, CodedIndexType::Implementation),
            };

            let mut buffer =
                vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            manifest_resource
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                ManifestResourceRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(manifest_resource.implementation, read_back.implementation);
            assert_eq!(manifest_resource.offset_field, read_back.offset_field);
        }
    }

    #[test]
    fn test_manifestresource_resource_attributes() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        // Test different ManifestResourceAttributes scenarios
        let attribute_cases = vec![
            (0x00000001, "Public resource"),
            (0x00000002, "Private resource"),
            (0x00000000, "Default visibility"),
            (0x12345678, "Custom attribute combination"),
        ];

        for (flags, _description) in attribute_cases {
            let manifest_resource = ManifestResourceRaw {
                rid: 1,
                token: Token::new(0x28000001),
                offset: 0,
                offset_field: 1024, // Resource at offset 1024
                flags,
                name: 100,
                implementation: CodedIndex::new(TableId::File, 0, CodedIndexType::Implementation), // Embedded resource
            };

            let mut buffer =
                vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            manifest_resource
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                ManifestResourceRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(manifest_resource.flags, read_back.flags);
        }
    }

    #[test]
    fn test_manifestresource_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_resource = ManifestResourceRaw {
            rid: 1,
            token: Token::new(0x28000001),
            offset: 0,
            offset_field: 0,
            flags: 0,
            name: 0,
            implementation: CodedIndex::new(TableId::File, 0, CodedIndexType::Implementation),
        };

        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_resource
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, 0x00, 0x00, // offset_field: 0
            0x00, 0x00, 0x00, 0x00, // flags: 0
            0x00, 0x00, // name: 0
            0x00, 0x00, // implementation: File(0) -> (0 << 2) | 0 = 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_resource = ManifestResourceRaw {
            rid: 1,
            token: Token::new(0x28000001),
            offset: 0,
            offset_field: 0xFFFFFFFF,
            flags: 0xFFFFFFFF,
            name: 0xFFFF,
            implementation: CodedIndex::new(
                TableId::ExportedType,
                0x3FFF,
                CodedIndexType::Implementation,
            ), // Max for 2-byte coded index
        };

        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_resource
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 12); // 4 + 4 + 2 + 2 bytes
    }

    #[test]
    fn test_manifestresource_heap_sizes() {
        // Test with different string heap configurations
        let configurations = vec![
            (false, 2), // Small string heap, 2-byte indexes
            (true, 4),  // Large string heap, 4-byte indexes
        ];

        for (large_str, expected_str_size) in configurations {
            let sizes = Arc::new(TableInfo::new_test(
                &[
                    (TableId::File, 100),
                    (TableId::AssemblyRef, 50),
                    (TableId::ExportedType, 25),
                ],
                large_str,
                false,
                false,
            ));

            let manifest_resource = ManifestResourceRaw {
                rid: 1,
                token: Token::new(0x28000001),
                offset: 0,
                offset_field: 0x12345678,
                flags: 0x87654321,
                // An index has to fit its column: a two-byte one holds at most 0xFFFF
                name: if large_str { 0x12345678 } else { 0x1234 },
                implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation),
            };

            // Verify row size includes correct string index size
            let expected_total_size = 4 + 4 + expected_str_size + 2; // offset_field(4) + flags(4) + name(variable) + implementation(2)
            assert_eq!(
                <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize,
                expected_total_size
            );

            let mut buffer = vec![0u8; expected_total_size];
            let mut offset = 0;
            manifest_resource
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            assert_eq!(buffer.len(), expected_total_size);
            assert_eq!(offset, expected_total_size);
        }
    }

    #[test]
    fn test_manifestresource_resource_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 100),
                (TableId::AssemblyRef, 50),
                (TableId::ExportedType, 25),
            ],
            false,
            false,
            false,
        ));

        // Test different common resource scenarios
        let resource_scenarios = vec![
            (
                1024,
                0x00000001,
                TableId::File,
                0,
                "Embedded .resources file",
            ),
            (0, 0x00000001, TableId::File, 1, "External .resources file"),
            (
                0,
                0x00000001,
                TableId::AssemblyRef,
                2,
                "Satellite assembly resource",
            ),
            (
                2048,
                0x00000002,
                TableId::File,
                0,
                "Private embedded resource",
            ),
            (0, 0x00000001, TableId::File, 3, "Image resource file"),
            (
                4096,
                0x00000001,
                TableId::File,
                0,
                "Configuration data resource",
            ),
        ];

        for (offset_field, flags, impl_tag, impl_row, _description) in resource_scenarios {
            let manifest_resource = ManifestResourceRaw {
                rid: 1,
                token: Token::new(0x28000001),
                offset: 0,
                offset_field,
                flags,
                name: 100,
                implementation: CodedIndex::new(impl_tag, impl_row, CodedIndexType::Implementation),
            };

            let mut buffer =
                vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            manifest_resource
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                ManifestResourceRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(manifest_resource.offset_field, read_back.offset_field);
            assert_eq!(manifest_resource.flags, read_back.flags);
            assert_eq!(manifest_resource.implementation, read_back.implementation);
        }
    }

    #[test]
    fn test_manifestresource_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::File, 10),
                (TableId::AssemblyRef, 10),
                (TableId::ExportedType, 10),
            ],
            false,
            false,
            false,
        ));

        let manifest_resource = ManifestResourceRaw {
            rid: 1,
            token: Token::new(0x28000001),
            offset: 0,
            offset_field: 0x01010101,
            flags: 0x02020202,
            name: 0x0303,
            implementation: CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation), // File(1) = (1 << 2) | 0 = 4
        };

        let mut buffer = vec![0u8; <ManifestResourceRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        manifest_resource
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // offset_field
            0x02, 0x02, 0x02, 0x02, // flags
            0x03, 0x03, // name
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        assert_eq!(buffer, expected);
    }
}

//! Implementation of `RowWritable` for `MethodSpecRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `MethodSpec` table (ID 0x2B),
//! enabling writing of generic method instantiation information back to .NET PE files. The
//! MethodSpec table defines instantiations of generic methods with concrete type arguments,
//! enabling runtime generic method dispatch and specialization.
//!
//! ## Table Structure (ECMA-335 §II.22.29)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Method` | `MethodDefOrRef` coded index | Generic method being instantiated |
//! | `Instantiation` | Blob heap index | Signature containing type arguments |
//!
//! ## Coded Index Types
//!
//! The Method field uses the `MethodDefOrRef` coded index which can reference:
//! - **Tag 0 (MethodDef)**: References MethodDef table entries for internal generic methods
//! - **Tag 1 (MemberRef)**: References MemberRef table entries for external generic methods
//!
//! ## Usage Context
//!
//! MethodSpec entries are used for:
//! - **Generic method calls**: Instantiating generic methods with specific type arguments
//! - **Method specialization**: Creating specialized versions of generic methods
//! - **Type argument binding**: Associating concrete types with generic parameters
//! - **Runtime dispatch**: Enabling efficient generic method resolution

use crate::{
    metadata::tables::{
        methodspec::MethodSpecRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for MethodSpecRaw {
    /// Serialize a MethodSpec table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.29 specification:
    /// - `method`: `MethodDefOrRef` coded index (generic method reference)
    /// - `instantiation`: Blob heap index (type argument signature)
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
        // Write MethodDefOrRef coded index for method
        let method_value = self.method.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            method_value,
            sizes.coded_index_bits(CodedIndexType::MethodDefOrRef) > 16,
        )?;

        // Write blob heap index for instantiation
        write_le_at_dyn(data, offset, self.instantiation, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            methodspec::MethodSpecRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_methodspec_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // method(2) + instantiation(2)
        assert_eq!(<MethodSpecRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 0x10000), (TableId::MemberRef, 0x10000)],
            false,
            true,
            false,
        ));

        let expected_size_large = 4 + 4; // method(4) + instantiation(4)
        assert_eq!(
            <MethodSpecRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_methodspec_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let method_spec = MethodSpecRaw {
            rid: 1,
            token: Token::new(0x2B000001),
            offset: 0,
            method: CodedIndex::new(TableId::MemberRef, 0, CodedIndexType::MethodDefOrRef), // MemberRef(0) = (0 << 1) | 1 = 1
            instantiation: 0x0202,
        };

        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x00, // method: MemberRef(0) -> (0 << 1) | 1 = 1, little-endian
            0x02, 0x02, // instantiation: 0x0202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodspec_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 0x10000), (TableId::MemberRef, 0x10000)],
            false,
            true,
            false,
        ));

        let method_spec = MethodSpecRaw {
            rid: 1,
            token: Token::new(0x2B000001),
            offset: 0,
            method: CodedIndex::new(TableId::MemberRef, 0, CodedIndexType::MethodDefOrRef), // MemberRef(0) = (0 << 1) | 1 = 1
            instantiation: 0x02020202,
        };

        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x00, 0x00, 0x00, // method: MemberRef(0) -> (0 << 1) | 1 = 1, little-endian
            0x02, 0x02, 0x02, 0x02, // instantiation: 0x02020202, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodspec_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        let original = MethodSpecRaw {
            rid: 42,
            token: Token::new(0x2B00002A),
            offset: 0,
            method: CodedIndex::new(TableId::MethodDef, 25, CodedIndexType::MethodDefOrRef), // MethodDef(25) = (25 << 1) | 0 = 50
            instantiation: 128, // Blob index 128
        };

        // Write to buffer
        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = MethodSpecRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.method, read_back.method);
        assert_eq!(original.instantiation, read_back.instantiation);
    }

    #[test]
    fn test_methodspec_different_method_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test different MethodDefOrRef coded index types
        let test_cases = vec![
            (TableId::MethodDef, 1, 100, "Internal generic method"),
            (TableId::MemberRef, 1, 200, "External generic method"),
            (TableId::MethodDef, 50, 300, "Different internal method"),
            (TableId::MemberRef, 25, 400, "Different external method"),
            (TableId::MethodDef, 10, 500, "Generic constructor"),
        ];

        for (method_tag, method_row, blob_index, _description) in test_cases {
            let method_spec = MethodSpecRaw {
                rid: 1,
                token: Token::new(0x2B000001),
                offset: 0,
                method: CodedIndex::new(method_tag, method_row, CodedIndexType::MethodDefOrRef),
                instantiation: blob_index,
            };

            let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            method_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = MethodSpecRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(method_spec.method, read_back.method);
            assert_eq!(method_spec.instantiation, read_back.instantiation);
        }
    }

    #[test]
    fn test_methodspec_generic_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test different common generic method instantiation scenarios
        let scenarios = vec![
            (TableId::MethodDef, 1, 100, "List<T>.Add<int>()"),
            (
                TableId::MemberRef,
                2,
                200,
                "Dictionary<TKey,TValue>.TryGetValue<string,object>()",
            ),
            (
                TableId::MethodDef,
                3,
                300,
                "Array.ConvertAll<TInput,TOutput>()",
            ),
            (
                TableId::MemberRef,
                4,
                400,
                "Enumerable.Select<TSource,TResult>()",
            ),
            (TableId::MethodDef, 5, 500, "Task.FromResult<T>()"),
            (TableId::MemberRef, 6, 600, "Activator.CreateInstance<T>()"),
        ];

        for (method_tag, method_row, blob_index, _description) in scenarios {
            let method_spec = MethodSpecRaw {
                rid: method_row,
                token: Token::new(0x2B000000 + method_row),
                offset: 0,
                method: CodedIndex::new(method_tag, method_row, CodedIndexType::MethodDefOrRef),
                instantiation: blob_index,
            };

            let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            method_spec
                .row_write(&mut buffer, &mut offset, method_row, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                MethodSpecRaw::row_read(&buffer, &mut read_offset, method_row, &sizes).unwrap();

            assert_eq!(method_spec.method, read_back.method);
            assert_eq!(method_spec.instantiation, read_back.instantiation);
        }
    }

    #[test]
    fn test_methodspec_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_spec = MethodSpecRaw {
            rid: 1,
            token: Token::new(0x2B000001),
            offset: 0,
            method: CodedIndex::new(TableId::MethodDef, 0, CodedIndexType::MethodDefOrRef), // MethodDef(0) = (0 << 1) | 0 = 0
            instantiation: 0,
        };

        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // method: MethodDef(0) -> (0 << 1) | 0 = 0
            0x00, 0x00, // instantiation: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_spec = MethodSpecRaw {
            rid: 1,
            token: Token::new(0x2B000001),
            offset: 0,
            method: CodedIndex::new(TableId::MemberRef, 0x7FFF, CodedIndexType::MethodDefOrRef), // Max for 2-byte coded index
            instantiation: 0xFFFF,
        };

        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_methodspec_instantiation_signatures() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
            false,
            false,
            false,
        ));

        // Test different common instantiation signature scenarios
        let signature_cases = vec![
            (TableId::MethodDef, 1, 1, "Single type argument"),
            (TableId::MemberRef, 2, 100, "Multiple type arguments"),
            (TableId::MethodDef, 3, 200, "Complex generic types"),
            (TableId::MemberRef, 4, 300, "Nested generic arguments"),
            (TableId::MethodDef, 5, 400, "Value type arguments"),
            (TableId::MemberRef, 6, 500, "Reference type arguments"),
            (TableId::MethodDef, 7, 600, "Array type arguments"),
            (TableId::MemberRef, 8, 700, "Pointer type arguments"),
        ];

        for (method_tag, method_row, blob_index, _description) in signature_cases {
            let method_spec = MethodSpecRaw {
                rid: 1,
                token: Token::new(0x2B000001),
                offset: 0,
                method: CodedIndex::new(method_tag, method_row, CodedIndexType::MethodDefOrRef),
                instantiation: blob_index,
            };

            let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            method_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the blob index is written correctly
            let written_blob = u16::from_le_bytes([buffer[2], buffer[3]]);
            assert_eq!(written_blob as u32, blob_index);
        }
    }

    #[test]
    fn test_methodspec_heap_sizes() {
        // Test with different blob heap configurations
        let configurations = vec![
            (false, 2), // Small blob heap, 2-byte indexes
            (true, 4),  // Large blob heap, 4-byte indexes
        ];

        for (large_blob, expected_blob_size) in configurations {
            let sizes = Arc::new(TableInfo::new_test(
                &[(TableId::MethodDef, 100), (TableId::MemberRef, 50)],
                false,
                large_blob,
                false,
            ));

            let method_spec = MethodSpecRaw {
                rid: 1,
                token: Token::new(0x2B000001),
                offset: 0,
                method: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef),
                // An index has to fit its column: a two-byte one holds at most 0xFFFF
                instantiation: if large_blob { 0x12345678 } else { 0x1234 },
            };

            // Verify row size includes correct blob index size
            let expected_total_size = 2 + expected_blob_size; // method(2) + instantiation(variable)
            assert_eq!(
                <MethodSpecRaw as TableRow>::row_size(&sizes) as usize,
                expected_total_size
            );

            let mut buffer = vec![0u8; expected_total_size];
            let mut offset = 0;
            method_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            assert_eq!(buffer.len(), expected_total_size);
            assert_eq!(offset, expected_total_size);
        }
    }

    #[test]
    fn test_methodspec_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 10), (TableId::MemberRef, 10)],
            false,
            false,
            false,
        ));

        let method_spec = MethodSpecRaw {
            rid: 1,
            token: Token::new(0x2B000001),
            offset: 0,
            method: CodedIndex::new(TableId::MemberRef, 0, CodedIndexType::MethodDefOrRef), // MemberRef(0) = (0 << 1) | 1 = 1
            instantiation: 0x0202,
        };

        let mut buffer = vec![0u8; <MethodSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        method_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x00, // method
            0x02, 0x02, // instantiation
        ];

        assert_eq!(buffer, expected);
    }
}

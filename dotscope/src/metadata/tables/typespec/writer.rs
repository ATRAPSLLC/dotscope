//! Implementation of `RowWritable` for `TypeSpecRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `TypeSpec` table (ID 0x1B),
//! enabling writing of type specification information back to .NET PE files. The TypeSpec
//! table defines complex type specifications through signatures stored in the blob heap,
//! supporting generic type instantiation, array definitions, pointer types, and complex
//! type composition.
//!
//! ## Table Structure (ECMA-335 §II.22.39)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Signature` | Blob heap index | Type specification signature data |
//!
//! ## Usage Context
//!
//! TypeSpec entries are used for:
//! - **Generic Instantiations**: `List<T>`, `Dictionary<K,V>`, custom generic types
//! - **Array Types**: Single and multi-dimensional arrays with bounds
//! - **Pointer Types**: Managed and unmanaged pointers, reference types  
//! - **Modified Types**: Types with `const`, `volatile`, and other modifiers
//! - **Constructed Types**: Complex compositions of primitive and defined types
//! - **Function Pointers**: Method signatures as type specifications

use crate::{
    metadata::tables::{
        types::{RowWritable, TableInfoRef},
        typespec::TypeSpecRaw,
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for TypeSpecRaw {
    /// Serialize a TypeSpec table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.39 specification:
    /// - `signature`: Blob heap index (type specification signature)
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
        // Write blob heap index for signature
        write_le_at_dyn(data, offset, self.signature, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            types::{RowReadable, RowWritable, TableInfo, TableRow},
            typespec::TypeSpecRaw,
        },
        token::Token,
    };

    #[test]
    fn test_typespec_row_size() {
        // Test with small blob heap
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let expected_size = 2; // signature(2)
        assert_eq!(<TypeSpecRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large blob heap
        let sizes_large = Arc::new(TableInfo::new_test(&[], false, true, false));

        let expected_size_large = 4; // signature(4)
        assert_eq!(
            <TypeSpecRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_typespec_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let type_spec = TypeSpecRaw {
            rid: 1,
            token: Token::new(0x1B000001),
            offset: 0,
            signature: 0x0101,
        };

        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        type_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // signature: 0x0101, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_typespec_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, true, false));

        let type_spec = TypeSpecRaw {
            rid: 1,
            token: Token::new(0x1B000001),
            offset: 0,
            signature: 0x01010101,
        };

        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        type_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // signature: 0x01010101, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_typespec_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let original = TypeSpecRaw {
            rid: 42,
            token: Token::new(0x1B00002A),
            offset: 0,
            signature: 256, // Blob index 256
        };

        // Write to buffer
        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = TypeSpecRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.signature, read_back.signature);
    }

    #[test]
    fn test_typespec_different_signatures() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different common type specification scenarios
        let test_cases = vec![
            1,     // First type spec
            100,   // Generic instantiation
            200,   // Array type specification
            300,   // Pointer type specification
            400,   // Modified type specification
            500,   // Function pointer type
            1000,  // Complex type composition
            65535, // Maximum for 2-byte index
        ];

        for signature_index in test_cases {
            let type_spec = TypeSpecRaw {
                rid: 1,
                token: Token::new(0x1B000001),
                offset: 0,
                signature: signature_index,
            };

            let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            type_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = TypeSpecRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(type_spec.signature, read_back.signature);
        }
    }

    #[test]
    fn test_typespec_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test with zero signature index
        let zero_spec = TypeSpecRaw {
            rid: 1,
            token: Token::new(0x1B000001),
            offset: 0,
            signature: 0,
        };

        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // signature: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum value for 2-byte index
        let max_spec = TypeSpecRaw {
            rid: 1,
            token: Token::new(0x1B000001),
            offset: 0,
            signature: 0xFFFF,
        };

        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 2); // Single 2-byte field
    }

    #[test]
    fn test_typespec_type_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different type specification scenarios
        let type_scenarios = vec![
            (1, "Generic type instantiation (List<T>)"),
            (50, "Multi-dimensional array (T[,])"),
            (100, "Pointer type (T*)"),
            (150, "Reference type (T&)"),
            (200, "Modified type (const T)"),
            (250, "Function pointer"),
            (300, "Complex generic (Dictionary<K,V>)"),
            (400, "Nested generic type"),
        ];

        for (sig_index, _description) in type_scenarios {
            let type_spec = TypeSpecRaw {
                rid: sig_index,
                token: Token::new(0x1B000000 + sig_index),
                offset: 0,
                signature: sig_index,
            };

            let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            type_spec
                .row_write(&mut buffer, &mut offset, sig_index, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                TypeSpecRaw::row_read(&buffer, &mut read_offset, sig_index, &sizes).unwrap();

            assert_eq!(type_spec.signature, read_back.signature);
        }
    }

    #[test]
    fn test_typespec_blob_heap_sizes() {
        // Test with different blob heap configurations
        let configurations = vec![
            (false, 2), // Small blob heap, 2-byte indexes
            (true, 4),  // Large blob heap, 4-byte indexes
        ];

        for (large_blob, expected_size) in configurations {
            let sizes = Arc::new(TableInfo::new_test(&[], false, large_blob, false));

            let type_spec = TypeSpecRaw {
                rid: 1,
                token: Token::new(0x1B000001),
                offset: 0,
                // An index has to fit its column: a two-byte one holds at most 0xFFFF
                signature: if large_blob { 0x12345678 } else { 0x1234 },
            };

            // Verify row size matches expected
            assert_eq!(
                <TypeSpecRaw as TableRow>::row_size(&sizes) as usize,
                expected_size
            );

            let mut buffer = vec![0u8; expected_size];
            let mut offset = 0;
            type_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            assert_eq!(buffer.len(), expected_size);
            assert_eq!(offset, expected_size);
        }
    }

    #[test]
    fn test_typespec_generic_instantiations() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different generic instantiation scenarios
        let generic_cases = vec![
            (100, "List<string>"),
            (200, "Dictionary<string, object>"),
            (300, "IEnumerable<T>"),
            (400, "Task<TResult>"),
            (500, "Func<T, TResult>"),
            (600, "Action<T1, T2>"),
            (700, "Nullable<T>"),
            (800, "Array<T>"),
        ];

        for (blob_index, _description) in generic_cases {
            let type_spec = TypeSpecRaw {
                rid: 1,
                token: Token::new(0x1B000001),
                offset: 0,
                signature: blob_index,
            };

            let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            type_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the blob index is written correctly
            let written_blob = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_blob as u32, blob_index);
        }
    }

    #[test]
    fn test_typespec_array_and_pointer_types() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different array and pointer type scenarios
        let array_pointer_cases = vec![
            (50, "Single-dimensional array (T[])"),
            (100, "Multi-dimensional array (T[,])"),
            (150, "Array with bounds (T[0..10])"),
            (200, "Jagged array (T[][])"),
            (250, "Pointer type (T*)"),
            (300, "Reference type (T&)"),
            (350, "Managed pointer"),
            (400, "Unmanaged pointer"),
        ];

        for (blob_index, _description) in array_pointer_cases {
            let type_spec = TypeSpecRaw {
                rid: 1,
                token: Token::new(0x1B000001),
                offset: 0,
                signature: blob_index,
            };

            let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            type_spec
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the signature is preserved
            let mut read_offset = 0;
            let read_back = TypeSpecRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();
            assert_eq!(type_spec.signature, read_back.signature);
        }
    }

    #[test]
    fn test_typespec_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let type_spec = TypeSpecRaw {
            rid: 1,
            token: Token::new(0x1B000001),
            offset: 0,
            signature: 0x0101,
        };

        let mut buffer = vec![0u8; <TypeSpecRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        type_spec
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // signature
        ];

        assert_eq!(buffer, expected);
    }
}

//! Implementation of `RowWritable` for `StandAloneSigRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `StandAloneSig` table (ID 0x11),
//! enabling writing of standalone signature information back to .NET PE files. The StandAloneSig
//! table stores standalone signatures that are not directly associated with specific methods,
//! fields, or properties but are referenced from CIL instructions or used in complex signature
//! scenarios.
//!
//! ## Table Structure (ECMA-335 §II.22.39)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Signature` | Blob heap index | Signature data in blob heap |
//!
//! ## Usage Context
//!
//! StandAloneSig entries are used for:
//! - **Method Signatures**: Function pointer signatures with calling conventions
//! - **Local Variable Signatures**: Method local variable type declarations
//! - **Field Signatures**: Standalone field type specifications
//! - **Generic Signatures**: Generic type and method instantiation signatures
//! - **CIL Instruction References**: Signatures referenced by call/calli instructions

use crate::{
    metadata::tables::{
        standalonesig::StandAloneSigRaw,
        types::{RowWritable, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for StandAloneSigRaw {
    /// Serialize a StandAloneSig table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.39 specification:
    /// - `signature`: Blob heap index (signature data)
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
            standalonesig::StandAloneSigRaw,
            types::{RowReadable, RowWritable, TableInfo, TableRow},
        },
        token::Token,
    };

    #[test]
    fn test_standalonesig_row_size() {
        // Test with small blob heap
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let expected_size = 2; // signature(2)
        assert_eq!(
            <StandAloneSigRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large blob heap
        let sizes_large = Arc::new(TableInfo::new_test(&[], true, true, true));

        let expected_size_large = 4; // signature(4)
        assert_eq!(
            <StandAloneSigRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_standalonesig_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let standalone_sig = StandAloneSigRaw {
            rid: 1,
            token: Token::new(0x11000001),
            offset: 0,
            signature: 0x0101,
        };

        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        standalone_sig
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
    fn test_standalonesig_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(&[], true, true, true));

        let standalone_sig = StandAloneSigRaw {
            rid: 1,
            token: Token::new(0x11000001),
            offset: 0,
            signature: 0x01010101,
        };

        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        standalone_sig
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
    fn test_standalonesig_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let original = StandAloneSigRaw {
            rid: 42,
            token: Token::new(0x1100002A),
            offset: 0,
            signature: 256, // Blob index 256
        };

        // Write to buffer
        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = StandAloneSigRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.signature, read_back.signature);
    }

    #[test]
    fn test_standalonesig_different_signatures() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different common signature blob indexes
        let test_cases = vec![
            1,     // First signature blob
            100,   // Method signature
            200,   // Local variable signature
            300,   // Field signature
            400,   // Generic signature
            500,   // Complex signature
            1000,  // Large signature index
            65535, // Maximum for 2-byte index
        ];

        for signature_index in test_cases {
            let standalone_sig = StandAloneSigRaw {
                rid: 1,
                token: Token::new(0x11000001),
                offset: 0,
                signature: signature_index,
            };

            let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            standalone_sig
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                StandAloneSigRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(standalone_sig.signature, read_back.signature);
        }
    }

    #[test]
    fn test_standalonesig_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test with zero signature index
        let zero_sig = StandAloneSigRaw {
            rid: 1,
            token: Token::new(0x11000001),
            offset: 0,
            signature: 0,
        };

        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_sig
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // signature: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum value for 2-byte index
        let max_sig = StandAloneSigRaw {
            rid: 1,
            token: Token::new(0x11000001),
            offset: 0,
            signature: 0xFFFF,
        };

        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_sig
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 2); // Single 2-byte field
    }

    #[test]
    fn test_standalonesig_signature_types() {
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        // Test different signature type scenarios
        let signature_scenarios = vec![
            (1, "Method pointer signature"),
            (50, "Local variable signature"),
            (100, "Field signature"),
            (150, "Generic method signature"),
            (200, "Function pointer signature"),
            (250, "Property signature"),
            (300, "Pinvoke signature"),
            (400, "Complex generic signature"),
        ];

        for (sig_index, _description) in signature_scenarios {
            let standalone_sig = StandAloneSigRaw {
                rid: sig_index,
                token: Token::new(0x11000000 + sig_index),
                offset: 0,
                signature: sig_index,
            };

            let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            standalone_sig
                .row_write(&mut buffer, &mut offset, sig_index, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                StandAloneSigRaw::row_read(&buffer, &mut read_offset, sig_index, &sizes).unwrap();

            assert_eq!(standalone_sig.signature, read_back.signature);
        }
    }

    #[test]
    fn test_standalonesig_blob_heap_sizes() {
        // Test with different blob heap configurations
        let configurations = vec![
            (false, 2), // Small blob heap, 2-byte indexes
            (true, 4),  // Large blob heap, 4-byte indexes
        ];

        for (large_blob, expected_size) in configurations {
            let sizes = Arc::new(TableInfo::new_test(&[], false, large_blob, false));

            let standalone_sig = StandAloneSigRaw {
                rid: 1,
                token: Token::new(0x11000001),
                offset: 0,
                // An index has to fit its column: a two-byte one holds at most 0xFFFF
                signature: if large_blob { 0x12345678 } else { 0x1234 },
            };

            // Verify row size matches expected
            assert_eq!(
                <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize,
                expected_size
            );

            let mut buffer = vec![0u8; expected_size];
            let mut offset = 0;
            standalone_sig
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            assert_eq!(buffer.len(), expected_size);
            assert_eq!(offset, expected_size);
        }
    }

    #[test]
    fn test_standalonesig_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));

        let standalone_sig = StandAloneSigRaw {
            rid: 1,
            token: Token::new(0x11000001),
            offset: 0,
            signature: 0x0101,
        };

        let mut buffer = vec![0u8; <StandAloneSigRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        standalone_sig
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // signature
        ];

        assert_eq!(buffer, expected);
    }
}

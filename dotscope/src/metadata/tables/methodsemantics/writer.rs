//! Implementation of `RowWritable` for `MethodSemanticsRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `MethodSemantics` table (ID 0x18),
//! enabling writing of method semantic relationships back to .NET PE files. The MethodSemantics table
//! defines relationships between methods and properties/events, specifying which methods serve as
//! getters, setters, event handlers, etc.
//!
//! ## Table Structure (ECMA-335 §II.22.28)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Semantics` | u16 | Semantic relationship bitmask |
//! | `Method` | MethodDef table index | Method implementing the semantic |
//! | `Association` | `HasSemantics` coded index | Associated property or event |
//!
//! ## Semantic Types
//!
//! - **Property Semantics**: SETTER (0x0001), GETTER (0x0002), OTHER (0x0004)
//! - **Event Semantics**: ADD_ON (0x0008), REMOVE_ON (0x0010), FIRE (0x0020), OTHER (0x0004)

use crate::{
    metadata::tables::{
        methodsemantics::MethodSemanticsRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for MethodSemanticsRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.association.encode(sizes)?, 0)))
    }

    /// Serialize a MethodSemantics table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.28 specification:
    /// - `semantics`: 2-byte bitmask of semantic attributes
    /// - `method`: MethodDef table index (method implementing the semantic)
    /// - `association`: `HasSemantics` coded index (property or event)
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
        // Write semantics bitmask (2 bytes)
        write_le_at(
            data,
            offset,
            u16::try_from(self.semantics).map_err(|_| {
                malformed_error!("MethodSemantics semantics out of range: {}", self.semantics)
            })?,
        )?;

        // Write MethodDef table index
        write_le_at_dyn(
            data,
            offset,
            self.method,
            sizes.is_large(TableId::MethodDef),
        )?;

        // Write HasSemantics coded index for association
        let association_value = self.association.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            association_value,
            sizes.coded_index_bits(CodedIndexType::HasSemantics) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            methodsemantics::MethodSemanticsRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_methodsemantics_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 100),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2; // semantics(2) + method(2) + association(2)
        assert_eq!(
            <MethodSemanticsRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 0x10000),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        let expected_size_large = 2 + 4 + 2; // semantics(2) + method(4) + association(2)
        assert_eq!(
            <MethodSemanticsRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_methodsemantics_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 100),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        let method_semantics = MethodSemanticsRaw {
            rid: 1,
            token: Token::new(0x18000001),
            offset: 0,
            semantics: 0x0002, // GETTER
            method: 42,
            association: CodedIndex::new(TableId::Property, 15, CodedIndexType::HasSemantics), // Property table, index 15
        };

        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_semantics
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // semantics: 0x0002, little-endian
        // method: 42, little-endian
        // association: Property(15) has HasSemantics tag 1, so (15 << 1) | 1 = 31 = 0x001F
        let expected = vec![
            0x02, 0x00, // semantics: 0x0002, little-endian
            0x2A, 0x00, // method: 42, little-endian
            0x1F, 0x00, // association: 0x001F, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodsemantics_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 0x10000),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        let method_semantics = MethodSemanticsRaw {
            rid: 1,
            token: Token::new(0x18000001),
            offset: 0,
            semantics: 0x0008, // ADD_ON
            method: 0x8000,
            association: CodedIndex::new(TableId::Event, 25, CodedIndexType::HasSemantics), // Event table, index 25
        };

        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_semantics
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        // semantics: 0x0008, little-endian
        // method: 0x8000, little-endian (4 bytes)
        // association: Event(25) has HasSemantics tag 0, so (25 << 1) | 0 = 50 = 0x0032
        let expected = vec![
            0x08, 0x00, // semantics: 0x0008, little-endian
            0x00, 0x80, 0x00, 0x00, // method: 0x8000, little-endian (4 bytes)
            0x32, 0x00, // association: 0x0032, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodsemantics_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 100),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        let original = MethodSemanticsRaw {
            rid: 42,
            token: Token::new(0x1800002A),
            offset: 0,
            semantics: 0x0001, // SETTER
            method: 55,
            association: CodedIndex::new(TableId::Property, 10, CodedIndexType::HasSemantics),
        };

        // Write to buffer
        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back =
            MethodSemanticsRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.semantics, read_back.semantics);
        assert_eq!(original.method, read_back.method);
        assert_eq!(original.association, read_back.association);
    }

    #[test]
    fn test_methodsemantics_different_semantic_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 100),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        // Test different semantic types
        let test_cases = vec![
            (0x0001u32, "SETTER"),
            (0x0002u32, "GETTER"),
            (0x0004u32, "OTHER"),
            (0x0008u32, "ADD_ON"),
            (0x0010u32, "REMOVE_ON"),
            (0x0020u32, "FIRE"),
        ];

        for (semantic_value, _name) in test_cases {
            let method_semantics = MethodSemanticsRaw {
                rid: 1,
                token: Token::new(0x18000001),
                offset: 0,
                semantics: semantic_value,
                method: 10,
                association: CodedIndex::new(TableId::Property, 5, CodedIndexType::HasSemantics),
            };

            let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            method_semantics
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify semantics field is written correctly
            let written_semantics = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(u32::from(written_semantics), semantic_value);
        }
    }

    #[test]
    fn test_methodsemantics_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 100),
                (TableId::Event, 50),
                (TableId::Property, 30),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_semantics = MethodSemanticsRaw {
            rid: 1,
            token: Token::new(0x18000001),
            offset: 0,
            semantics: 0,
            method: 0,
            association: CodedIndex::new(TableId::Event, 0, CodedIndexType::HasSemantics),
        };

        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_semantics
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // association: Event(0) has HasSemantics tag 0, so (0 << 1) | 0 = 0
        let expected = vec![
            0x00, 0x00, // semantics: 0x0000
            0x00, 0x00, // method: 0
            0x00, 0x00, // association: 0x0000
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values
        let max_semantics = MethodSemanticsRaw {
            rid: 1,
            token: Token::new(0x18000001),
            offset: 0,
            semantics: 0xFFFF,
            method: 0xFFFF,
            association: CodedIndex::new(TableId::Property, 0x7FFF, CodedIndexType::HasSemantics), // Max for 2-byte coded index
        };

        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_semantics
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // All 2-byte fields
    }

    #[test]
    fn test_methodsemantics_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDef, 1),
                (TableId::Event, 1),
                (TableId::Property, 1),
            ],
            false,
            false,
            false,
        ));

        let method_semantics = MethodSemanticsRaw {
            rid: 1,
            token: Token::new(0x18000001),
            offset: 0,
            semantics: 0x0101,
            method: 0x0202,
            association: CodedIndex::new(TableId::Event, 1, CodedIndexType::HasSemantics), // Event(1) = (1 << 1) | 0 = 2 = 0x0002
        };

        let mut buffer = vec![0u8; <MethodSemanticsRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        method_semantics
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // semantics
            0x02, 0x02, // method
            0x02, 0x00, // association (Event(1) -> (1 << 1) | 0 = 2)
        ];

        assert_eq!(buffer, expected);
    }
}

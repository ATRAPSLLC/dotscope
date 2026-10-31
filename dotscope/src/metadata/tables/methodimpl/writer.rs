//! Implementation of `RowWritable` for `MethodImplRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `MethodImpl` table (ID 0x19),
//! enabling writing of method implementation mappings back to .NET PE files. The MethodImpl table
//! defines relationships between method implementations and their declarations, specifying which
//! concrete methods implement interface methods or override virtual methods.
//!
//! ## Table Structure (ECMA-335 §II.22.27)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Class` | TypeDef table index | Type containing the implementation mapping |
//! | `MethodBody` | `MethodDefOrRef` coded index | Concrete method implementation |
//! | `MethodDeclaration` | `MethodDefOrRef` coded index | Method declaration being implemented |
//!
//! ## Coded Index Resolution
//!
//! Both `method_body` and `method_declaration` use `MethodDefOrRef` coded index encoding:
//! - **Tag 0**: `MethodDef` table (methods defined in current assembly)
//! - **Tag 1**: `MemberRef` table (methods referenced from external assemblies)

use crate::{
    metadata::tables::{
        methodimpl::MethodImplRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for MethodImplRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.class, 0)))
    }

    /// Serialize a MethodImpl table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.27 specification:
    /// - `class`: TypeDef table index (class containing the implementation)
    /// - `method_body`: `MethodDefOrRef` coded index (concrete implementation method)
    /// - `method_declaration`: `MethodDefOrRef` coded index (method declaration being implemented)
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
        // Write TypeDef table index for class
        write_le_at_dyn(data, offset, self.class, sizes.is_large(TableId::TypeDef))?;

        // Write MethodDefOrRef coded index for method_body
        let method_body_value = self.method_body.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            method_body_value,
            sizes.coded_index_bits(CodedIndexType::MethodDefOrRef) > 16,
        )?;

        // Write MethodDefOrRef coded index for method_declaration
        let method_declaration_value = self.method_declaration.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            method_declaration_value,
            sizes.coded_index_bits(CodedIndexType::MethodDefOrRef) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            methodimpl::MethodImplRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_methodimpl_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2; // class(2) + method_body(2) + method_declaration(2)
        assert_eq!(<MethodImplRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4 + 4; // class(4) + method_body(4) + method_declaration(4)
        assert_eq!(
            <MethodImplRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_methodimpl_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        let method_impl = MethodImplRaw {
            rid: 1,
            token: Token::new(0x19000001),
            offset: 0,
            class: 0x0101,
            method_body: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef), // MethodDef(1) = (1 << 1) | 0 = 2
            method_declaration: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MethodDefOrRef,
            ), // MethodDef(1) = (1 << 1) | 0 = 2
        };

        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_impl
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // class: 0x0101, little-endian
            0x02, 0x00, // method_body: MethodDef(1) -> (1 << 1) | 0 = 2, little-endian
            0x02, 0x00, // method_declaration: MethodDef(1) -> (1 << 1) | 0 = 2, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodimpl_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        let method_impl = MethodImplRaw {
            rid: 1,
            token: Token::new(0x19000001),
            offset: 0,
            class: 0x01010101,
            method_body: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef), // MethodDef(1) = (1 << 1) | 0 = 2
            method_declaration: CodedIndex::new(
                TableId::MemberRef,
                10,
                CodedIndexType::MethodDefOrRef,
            ), // MemberRef(10) = (10 << 1) | 1 = 21
        };

        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        method_impl
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // class: 0x01010101, little-endian
            0x02, 0x00, 0x00,
            0x00, // method_body: MethodDef(1) -> (1 << 1) | 0 = 2, little-endian
            0x15, 0x00, 0x00,
            0x00, // method_declaration: MemberRef(10) -> (10 << 1) | 1 = 21, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_methodimpl_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        let original = MethodImplRaw {
            rid: 42,
            token: Token::new(0x1900002A),
            offset: 0,
            class: 55,
            method_body: CodedIndex::new(TableId::MethodDef, 25, CodedIndexType::MethodDefOrRef),
            method_declaration: CodedIndex::new(
                TableId::MemberRef,
                15,
                CodedIndexType::MethodDefOrRef,
            ),
        };

        // Write to buffer
        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = MethodImplRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.class, read_back.class);
        assert_eq!(original.method_body, read_back.method_body);
        assert_eq!(original.method_declaration, read_back.method_declaration);
    }

    #[test]
    fn test_methodimpl_different_coded_indexes() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        // Test different combinations of MethodDefOrRef coded indexes
        let test_cases = vec![
            (TableId::MethodDef, 1, TableId::MethodDef, 2),
            (TableId::MethodDef, 5, TableId::MemberRef, 3),
            (TableId::MemberRef, 10, TableId::MethodDef, 8),
            (TableId::MemberRef, 15, TableId::MemberRef, 12),
        ];

        for (body_tag, body_row, decl_tag, decl_row) in test_cases {
            let method_impl = MethodImplRaw {
                rid: 1,
                token: Token::new(0x19000001),
                offset: 0,
                class: 10,
                method_body: CodedIndex::new(body_tag, body_row, CodedIndexType::MethodDefOrRef),
                method_declaration: CodedIndex::new(
                    decl_tag,
                    decl_row,
                    CodedIndexType::MethodDefOrRef,
                ),
            };

            let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            method_impl
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = MethodImplRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(method_impl.class, read_back.class);
            assert_eq!(method_impl.method_body, read_back.method_body);
            assert_eq!(method_impl.method_declaration, read_back.method_declaration);
        }
    }

    #[test]
    fn test_methodimpl_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::MemberRef, 30),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_impl = MethodImplRaw {
            rid: 1,
            token: Token::new(0x19000001),
            offset: 0,
            class: 0,
            method_body: CodedIndex::new(TableId::MethodDef, 0, CodedIndexType::MethodDefOrRef),
            method_declaration: CodedIndex::new(
                TableId::MethodDef,
                0,
                CodedIndexType::MethodDefOrRef,
            ),
        };

        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_impl
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Both MethodDef indexes with row 0: (0 << 1) | 0 = 0
        let expected = vec![
            0x00, 0x00, // class: 0
            0x00, 0x00, // method_body: MethodDef(0) -> (0 << 1) | 0 = 0
            0x00, 0x00, // method_declaration: MethodDef(0) -> (0 << 1) | 0 = 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_impl = MethodImplRaw {
            rid: 1,
            token: Token::new(0x19000001),
            offset: 0,
            class: 0xFFFF,
            method_body: CodedIndex::new(
                TableId::MemberRef,
                0x7FFF,
                CodedIndexType::MethodDefOrRef,
            ), // Max for 2-byte coded index
            method_declaration: CodedIndex::new(
                TableId::MethodDef,
                0x7FFF,
                CodedIndexType::MethodDefOrRef,
            ),
        };

        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_impl
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // All 2-byte fields
    }

    #[test]
    fn test_methodimpl_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodImpl, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
                (TableId::MemberRef, 10),
            ],
            false,
            false,
            false,
        ));

        let method_impl = MethodImplRaw {
            rid: 1,
            token: Token::new(0x19000001),
            offset: 0,
            class: 0x0101,
            method_body: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef), // MethodDef(1) = (1 << 1) | 0 = 2
            method_declaration: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MethodDefOrRef,
            ), // MethodDef(1) = (1 << 1) | 0 = 2
        };

        let mut buffer = vec![0u8; <MethodImplRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        method_impl
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // class
            0x02, 0x00, // method_body (tag 0 = MethodDef, index = 1)
            0x02, 0x00, // method_declaration (tag 0 = MethodDef, index = 1)
        ];

        assert_eq!(buffer, expected);
    }
}

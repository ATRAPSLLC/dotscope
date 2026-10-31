//! Implementation of `RowWritable` for `ImplMapRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `ImplMap` table (ID 0x1C),
//! enabling writing of Platform Invoke (P/Invoke) mapping information back to .NET PE files.
//! The ImplMap table specifies how managed methods map to unmanaged functions in native
//! libraries, essential for interoperability scenarios.
//!
//! ## Table Structure (ECMA-335 §II.22.22)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `MappingFlags` | u16 | P/Invoke attribute flags |
//! | `MemberForwarded` | `MemberForwarded` coded index | Method or field being forwarded |
//! | `ImportName` | String heap index | Name of target function in native library |
//! | `ImportScope` | ModuleRef table index | Target module containing the native function |
//!
//! ## Coded Index Types
//!
//! The MemberForwarded field uses the `MemberForwarded` coded index which can reference:
//! - **Tag 0 (Field)**: References Field table entries (not typically used)
//! - **Tag 1 (MethodDef)**: References MethodDef table entries (standard case for P/Invoke)

use crate::{
    metadata::tables::{
        implmap::ImplMapRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for ImplMapRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.member_forwarded.encode(sizes)?, 0)))
    }

    /// Serialize an ImplMap table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.22 specification:
    /// - `mapping_flags`: 2-byte P/Invoke attribute flags
    /// - `member_forwarded`: `MemberForwarded` coded index (method or field being forwarded)
    /// - `import_name`: String heap index (name of target function)
    /// - `import_scope`: ModuleRef table index (target native library)
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
        // Write mapping flags (2 bytes)
        write_le_at(
            data,
            offset,
            u16::try_from(self.mapping_flags).map_err(|_| {
                malformed_error!("ImplMap mapping flags out of range: {}", self.mapping_flags)
            })?,
        )?;

        // Write MemberForwarded coded index
        let member_forwarded_value = self.member_forwarded.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            member_forwarded_value,
            sizes.coded_index_bits(CodedIndexType::MemberForwarded) > 16,
        )?;

        // Write string heap index for import_name
        write_le_at_dyn(data, offset, self.import_name, sizes.is_large_str())?;

        // Write ModuleRef table index for import_scope
        write_le_at_dyn(
            data,
            offset,
            self.import_scope,
            sizes.is_large(TableId::ModuleRef),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            implmap::ImplMapRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_implmap_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2 + 2; // mapping_flags(2) + member_forwarded(2) + import_name(2) + import_scope(2)
        assert_eq!(<ImplMapRaw as TableRow>::row_size(&sizes), expected_size);

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::ModuleRef, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let expected_size_large = 2 + 4 + 4 + 4; // mapping_flags(2) + member_forwarded(4) + import_name(4) + import_scope(4)
        assert_eq!(
            <ImplMapRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_implmap_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let impl_map = ImplMapRaw {
            rid: 1,
            token: Token::new(0x1C000001),
            offset: 0,
            mapping_flags: 0x0101,
            member_forwarded: CodedIndex::new(TableId::Field, 1, CodedIndexType::MemberForwarded), // Field(1) = (1 << 1) | 0 = 2
            import_name: 0x0303,
            import_scope: 0x0404,
        };

        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        impl_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // mapping_flags: 0x0101, little-endian
            0x02, 0x00, // member_forwarded: Field(1) -> (1 << 1) | 0 = 2, little-endian
            0x03, 0x03, // import_name: 0x0303, little-endian
            0x04, 0x04, // import_scope: 0x0404, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_implmap_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::ModuleRef, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let impl_map = ImplMapRaw {
            rid: 1,
            token: Token::new(0x1C000001),
            offset: 0,
            mapping_flags: 0x0101,
            member_forwarded: CodedIndex::new(TableId::Field, 1, CodedIndexType::MemberForwarded), // Field(1) = (1 << 1) | 0 = 2
            import_name: 0x03030303,
            import_scope: 0x04040404,
        };

        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        impl_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // mapping_flags: 0x0101, little-endian
            0x02, 0x00, 0x00,
            0x00, // member_forwarded: Field(1) -> (1 << 1) | 0 = 2, little-endian
            0x03, 0x03, 0x03, 0x03, // import_name: 0x03030303, little-endian
            0x04, 0x04, 0x04, 0x04, // import_scope: 0x04040404, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_implmap_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let original = ImplMapRaw {
            rid: 42,
            token: Token::new(0x1C00002A),
            offset: 0,
            mapping_flags: 0x0001, // NoMangle
            member_forwarded: CodedIndex::new(
                TableId::MethodDef,
                25,
                CodedIndexType::MemberForwarded,
            ), // MethodDef(25) = (25 << 1) | 1 = 51
            import_name: 128,
            import_scope: 5,
        };

        // Write to buffer
        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = ImplMapRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.mapping_flags, read_back.mapping_flags);
        assert_eq!(original.member_forwarded, read_back.member_forwarded);
        assert_eq!(original.import_name, read_back.import_name);
        assert_eq!(original.import_scope, read_back.import_scope);
    }

    #[test]
    fn test_implmap_different_member_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        // Test different MemberForwarded coded index types
        let test_cases = vec![
            (TableId::Field, 1, "Field reference"),
            (TableId::MethodDef, 1, "MethodDef reference"),
            (TableId::Field, 50, "Different field"),
            (TableId::MethodDef, 25, "Different method"),
        ];

        for (member_tag, member_row, _description) in test_cases {
            let impl_map = ImplMapRaw {
                rid: 1,
                token: Token::new(0x1C000001),
                offset: 0,
                mapping_flags: 0x0001,
                member_forwarded: CodedIndex::new(
                    member_tag,
                    member_row,
                    CodedIndexType::MemberForwarded,
                ),
                import_name: 100,
                import_scope: 3,
            };

            let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            impl_map
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back = ImplMapRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(impl_map.member_forwarded, read_back.member_forwarded);
            assert_eq!(impl_map.import_name, read_back.import_name);
            assert_eq!(impl_map.import_scope, read_back.import_scope);
        }
    }

    #[test]
    fn test_implmap_pinvoke_flags() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        // Test different common P/Invoke flags
        let flag_cases = vec![
            (0x0000, "Default"),
            (0x0001, "NoMangle"),
            (0x0002, "CharSetAnsi"),
            (0x0004, "CharSetUnicode"),
            (0x0006, "CharSetAuto"),
            (0x0010, "SupportsLastError"),
            (0x0100, "CallConvWinapi"),
            (0x0200, "CallConvCdecl"),
            (0x0300, "CallConvStdcall"),
            (0x0400, "CallConvThiscall"),
            (0x0500, "CallConvFastcall"),
        ];

        for (flags, _description) in flag_cases {
            let impl_map = ImplMapRaw {
                rid: 1,
                token: Token::new(0x1C000001),
                offset: 0,
                mapping_flags: flags,
                member_forwarded: CodedIndex::new(
                    TableId::MethodDef,
                    1,
                    CodedIndexType::MemberForwarded,
                ),
                import_name: 50,
                import_scope: 2,
            };

            let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            impl_map
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the flags are written correctly
            let written_flags = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_flags as u32, flags);
        }
    }

    #[test]
    fn test_implmap_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::Field, 100),
                (TableId::MethodDef, 50),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_implmap = ImplMapRaw {
            rid: 1,
            token: Token::new(0x1C000001),
            offset: 0,
            mapping_flags: 0,
            member_forwarded: CodedIndex::new(TableId::Field, 0, CodedIndexType::MemberForwarded), // Field(0) = (0 << 1) | 0 = 0
            import_name: 0,
            import_scope: 0,
        };

        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_implmap
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // mapping_flags: 0
            0x00, 0x00, // member_forwarded: Field(0) -> (0 << 1) | 0 = 0
            0x00, 0x00, // import_name: 0
            0x00, 0x00, // import_scope: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_implmap = ImplMapRaw {
            rid: 1,
            token: Token::new(0x1C000001),
            offset: 0,
            mapping_flags: 0xFFFF,
            member_forwarded: CodedIndex::new(
                TableId::MethodDef,
                0x7FFF,
                CodedIndexType::MemberForwarded,
            ), // Max for 2-byte coded index
            import_name: 0xFFFF,
            import_scope: 0xFFFF,
        };

        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_implmap
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 8); // All 2-byte fields
    }

    #[test]
    fn test_implmap_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ImplMap, 1),
                (TableId::Field, 10),
                (TableId::MethodDef, 10),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));

        let impl_map = ImplMapRaw {
            rid: 1,
            token: Token::new(0x1C000001),
            offset: 0,
            mapping_flags: 0x0101,
            member_forwarded: CodedIndex::new(TableId::Field, 1, CodedIndexType::MemberForwarded), // Field(1) = (1 << 1) | 0 = 2
            import_name: 0x0303,
            import_scope: 0x0404,
        };

        let mut buffer = vec![0u8; <ImplMapRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        impl_map
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // mapping_flags
            0x02, 0x00, // member_forwarded (tag 0 = Field, index = 1)
            0x03, 0x03, // import_name
            0x04, 0x04, // import_scope
        ];

        assert_eq!(buffer, expected);
    }
}

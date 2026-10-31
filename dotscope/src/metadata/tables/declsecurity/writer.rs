//! Implementation of `RowWritable` for `DeclSecurityRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `DeclSecurity` table (ID 0x0E),
//! enabling writing of declarative security permission information back to .NET PE files.
//! The DeclSecurity table specifies Code Access Security (CAS) declarations that are enforced
//! by the .NET runtime to control permissions for assemblies, types, and methods.
//!
//! ## Table Structure (ECMA-335 §II.22.11)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Action` | u16 | Security action enumeration value |
//! | `Parent` | `HasDeclSecurity` coded index | Target entity (Assembly, TypeDef, or MethodDef) |
//! | `PermissionSet` | Blob heap index | Serialized permission set data |
//!
//! ## Coded Index Types
//!
//! The Parent field uses the `HasDeclSecurity` coded index which can reference:
//! - **Tag 0 (TypeDef)**: References TypeDef table entries for type-level security
//! - **Tag 1 (MethodDef)**: References MethodDef table entries for method-level security
//! - **Tag 2 (Assembly)**: References Assembly table entries for assembly-level security
//!
//! ## Security Actions
//!
//! Common security action values include:
//! - **1 (Request)**: Request specific permissions
//! - **2 (Demand)**: Demand specific permissions from callers
//! - **3 (Assert)**: Assert specific permissions are available
//! - **4 (Deny)**: Deny specific permissions to callers
//! - **5 (PermitOnly)**: Allow only specific permissions

use crate::{
    metadata::tables::{
        declsecurity::DeclSecurityRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for DeclSecurityRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.parent.encode(sizes)?, 0)))
    }

    /// Serialize a DeclSecurity table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.11 specification:
    /// - `action`: 2-byte security action enumeration value
    /// - `parent`: `HasDeclSecurity` coded index (assembly, type, or method reference)
    /// - `permission_set`: Blob heap index (serialized permission data)
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
        // Write security action (2 bytes)
        write_le_at(data, offset, self.action)?;

        // Write HasDeclSecurity coded index for parent
        let parent_value = self.parent.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            parent_value,
            sizes.coded_index_bits(CodedIndexType::HasDeclSecurity) > 16,
        )?;

        // Write blob heap index for permission_set
        write_le_at_dyn(data, offset, self.permission_set, sizes.is_large_blob())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            declsecurity::DeclSecurityRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_declsecurity_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2; // action(2) + parent(2) + permission_set(2)
        assert_eq!(
            <DeclSecurityRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::Assembly, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let expected_size_large = 2 + 4 + 4; // action(2) + parent(4) + permission_set(4)
        assert_eq!(
            <DeclSecurityRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_declsecurity_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        let decl_security = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 0x0101,
            parent: CodedIndex::new(TableId::Assembly, 128, CodedIndexType::HasDeclSecurity), // Assembly(128) = (128 << 2) | 2 = 514
            permission_set: 0x0303,
        };

        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        decl_security
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // action: 0x0101, little-endian
            0x02,
            0x02, // parent: Assembly(128) -> (128 << 2) | 2 = 514 = 0x0202, little-endian
            0x03, 0x03, // permission_set: 0x0303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_declsecurity_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 0x10000),
                (TableId::MethodDef, 0x10000),
                (TableId::Assembly, 0x10000),
            ],
            true,
            true,
            true,
        ));

        let decl_security = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 0x0101,
            parent: CodedIndex::new(TableId::Assembly, 0x808080, CodedIndexType::HasDeclSecurity), // Assembly(0x808080) = (0x808080 << 2) | 2 = 0x2020202
            permission_set: 0x03030303,
        };

        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        decl_security
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // action: 0x0101, little-endian
            0x02, 0x02, 0x02,
            0x02, // parent: Assembly(0x808080) -> (0x808080 << 2) | 2 = 0x2020202, little-endian
            0x03, 0x03, 0x03, 0x03, // permission_set: 0x03030303, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_declsecurity_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        let original = DeclSecurityRaw {
            rid: 42,
            token: Token::new(0x0E00002A),
            offset: 0,
            action: 2, // Demand security action
            parent: CodedIndex::new(TableId::TypeDef, 25, CodedIndexType::HasDeclSecurity), // TypeDef(25) = (25 << 2) | 0 = 100
            permission_set: 128, // Blob index 128
        };

        // Write to buffer
        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = DeclSecurityRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.action, read_back.action);
        assert_eq!(original.parent, read_back.parent);
        assert_eq!(original.permission_set, read_back.permission_set);
    }

    #[test]
    fn test_declsecurity_different_parent_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        // Test different HasDeclSecurity coded index types
        let test_cases = vec![
            (TableId::TypeDef, 1, 1, 0x100), // TypeDef reference, Request action
            (TableId::MethodDef, 1, 2, 0x200), // MethodDef reference, Demand action
            (TableId::Assembly, 1, 3, 0x300), // Assembly reference, Assert action
            (TableId::TypeDef, 50, 4, 0x400), // Different type, Deny action
            (TableId::MethodDef, 25, 5, 0x500), // Different method, PermitOnly action
        ];

        for (parent_tag, parent_row, action, blob_index) in test_cases {
            let decl_security = DeclSecurityRaw {
                rid: 1,
                token: Token::new(0x0E000001),
                offset: 0,
                action,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasDeclSecurity),
                permission_set: blob_index,
            };

            let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            decl_security
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                DeclSecurityRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(decl_security.action, read_back.action);
            assert_eq!(decl_security.parent, read_back.parent);
            assert_eq!(decl_security.permission_set, read_back.permission_set);
        }
    }

    #[test]
    fn test_declsecurity_security_actions() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        // Test different common security action values
        let action_cases = vec![
            (1, "Request"),
            (2, "Demand"),
            (3, "Assert"),
            (4, "Deny"),
            (5, "PermitOnly"),
            (6, "LinkDemand"),
            (7, "InheritanceDemand"),
            (8, "RequestMinimum"),
            (9, "RequestOptional"),
            (10, "RequestRefuse"),
        ];

        for (action_value, _description) in action_cases {
            let decl_security = DeclSecurityRaw {
                rid: 1,
                token: Token::new(0x0E000001),
                offset: 0,
                action: action_value,
                parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasDeclSecurity),
                permission_set: 100,
            };

            let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            decl_security
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the action is written correctly
            let written_action = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_action, action_value);
        }
    }

    #[test]
    fn test_declsecurity_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_security = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 0,
            parent: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::HasDeclSecurity), // TypeDef(0) = (0 << 2) | 0 = 0
            permission_set: 0,
        };

        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_security
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // action: 0
            0x00, 0x00, // parent: TypeDef(0) -> (0 << 2) | 0 = 0
            0x00, 0x00, // permission_set: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_security = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 0xFFFF,
            parent: CodedIndex::new(TableId::Assembly, 0x3FFF, CodedIndexType::HasDeclSecurity), // Max for 2-byte coded index
            permission_set: 0xFFFF,
        };

        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_security
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 6); // 2 + 2 + 2 bytes
    }

    #[test]
    fn test_declsecurity_permission_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 100),
                (TableId::MethodDef, 50),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        // Test different permission set scenarios
        let permission_cases = vec![
            (TableId::Assembly, 1, 2, 1),    // Assembly-level demand
            (TableId::TypeDef, 2, 4, 100),   // Type-level deny
            (TableId::MethodDef, 3, 3, 200), // Method-level assert
            (TableId::TypeDef, 4, 5, 300),   // Type-level permit only
            (TableId::MethodDef, 5, 6, 400), // Method-level link demand
            (TableId::Assembly, 1, 1, 500),  // Assembly-level request
        ];

        for (parent_tag, parent_row, action, blob_index) in permission_cases {
            let decl_security = DeclSecurityRaw {
                rid: 1,
                token: Token::new(0x0E000001),
                offset: 0,
                action,
                parent: CodedIndex::new(parent_tag, parent_row, CodedIndexType::HasDeclSecurity),
                permission_set: blob_index,
            };

            let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            decl_security
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the blob index is written correctly
            let written_blob = u16::from_le_bytes([buffer[4], buffer[5]]);
            assert_eq!(written_blob as u32, blob_index);
        }
    }

    #[test]
    fn test_declsecurity_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::TypeDef, 1),
                (TableId::MethodDef, 1),
                (TableId::Assembly, 1),
            ],
            false,
            false,
            false,
        ));

        let decl_security = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 0x0101,
            parent: CodedIndex::new(TableId::Assembly, 128, CodedIndexType::HasDeclSecurity), // Assembly(128) = (128 << 2) | 2 = 514 = 0x0202
            permission_set: 0x0303,
        };

        let mut buffer = vec![0u8; <DeclSecurityRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        decl_security
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // action
            0x02, 0x02, // parent
            0x03, 0x03, // permission_set
        ];

        assert_eq!(buffer, expected);
    }
}

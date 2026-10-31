//! Implementation of `RowWritable` for `GenericParamRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `GenericParam` table (ID 0x2A),
//! enabling writing of generic parameter information back to .NET PE files. The GenericParam
//! table defines generic type and method parameters for .NET generic programming support,
//! including constraint specifications and variance annotations.
//!
//! ## Table Structure (ECMA-335 §II.22.20)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Number` | u16 | Ordinal position of the parameter (0-based) |
//! | `Flags` | u16 | `GenericParamAttributes` bitmask |
//! | `Owner` | `TypeOrMethodDef` coded index | Generic type or method that owns this parameter |
//! | `Name` | String heap index | Parameter name for reflection and debugging |
//!
//! ## Coded Index Types
//!
//! The Owner field uses the `TypeOrMethodDef` coded index which can reference:
//! - **Tag 0 (TypeDef)**: References TypeDef table entries for type-level generic parameters
//! - **Tag 1 (MethodDef)**: References MethodDef table entries for method-level generic parameters
//!
//! ## Generic Parameter Attributes
//!
//! Common flag values include:
//! - **0x0000 (None)**: No special constraints or variance
//! - **0x0001 (Covariant)**: Enables assignment compatibility in output positions
//! - **0x0002 (Contravariant)**: Enables assignment compatibility in input positions
//! - **0x0004 (ReferenceTypeConstraint)**: Parameter must be a reference type
//! - **0x0008 (NotNullableValueTypeConstraint)**: Parameter must be a value type
//! - **0x0010 (DefaultConstructorConstraint)**: Parameter must have a parameterless constructor

use crate::{
    metadata::tables::{
        genericparam::GenericParamRaw,
        types::{CodedIndexType, RowWritable, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for GenericParamRaw {
    fn sort_key(&self, sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.owner.encode(sizes)?, self.number)))
    }

    /// Serialize a GenericParam table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.20 specification:
    /// - `number`: 2-byte ordinal position of the parameter (0-based)
    /// - `flags`: 2-byte `GenericParamAttributes` bitmask
    /// - `owner`: `TypeOrMethodDef` coded index (type or method reference)
    /// - `name`: String heap index (parameter name)
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
        // Write parameter number (2 bytes)
        write_le_at(
            data,
            offset,
            u16::try_from(self.number).map_err(|_| {
                malformed_error!("GenericParam number out of range: {}", self.number)
            })?,
        )?;

        // Write parameter flags (2 bytes)
        write_le_at(
            data,
            offset,
            u16::try_from(self.flags)
                .map_err(|_| malformed_error!("GenericParam flags out of range: {}", self.flags))?,
        )?;

        // Write TypeOrMethodDef coded index for owner
        let owner_value = self.owner.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            owner_value,
            sizes.coded_index_bits(CodedIndexType::TypeOrMethodDef) > 16,
        )?;

        // Write string heap index for name
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            genericparam::GenericParamRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_genericparam_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2 + 2 + 2; // number(2) + flags(2) + owner(2) + name(2)
        assert_eq!(
            <GenericParamRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::MethodDef, 0x10000)],
            true,
            false,
            false,
        ));

        let expected_size_large = 2 + 2 + 4 + 4; // number(2) + flags(2) + owner(4) + name(4)
        assert_eq!(
            <GenericParamRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_genericparam_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        let generic_param = GenericParamRaw {
            rid: 1,
            token: Token::new(0x2A000001),
            offset: 0,
            number: 0x0101,
            flags: 0x0202,
            owner: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef), // TypeDef(1) = (1 << 1) | 0 = 2
            name: 0x0404,
        };

        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        generic_param
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // number: 0x0101, little-endian
            0x02, 0x02, // flags: 0x0202, little-endian
            0x02, 0x00, // owner: TypeDef(1) -> (1 << 1) | 0 = 2, little-endian
            0x04, 0x04, // name: 0x0404, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_genericparam_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 0x10000), (TableId::MethodDef, 0x10000)],
            true,
            false,
            false,
        ));

        let generic_param = GenericParamRaw {
            rid: 1,
            token: Token::new(0x2A000001),
            offset: 0,
            number: 0x0101,
            flags: 0x0202,
            owner: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef), // TypeDef(1) = (1 << 1) | 0 = 2
            name: 0x04040404,
        };

        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        generic_param
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // number: 0x0101, little-endian
            0x02, 0x02, // flags: 0x0202, little-endian
            0x02, 0x00, 0x00, 0x00, // owner: TypeDef(1) -> (1 << 1) | 0 = 2, little-endian
            0x04, 0x04, 0x04, 0x04, // name: 0x04040404, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_genericparam_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        let original = GenericParamRaw {
            rid: 42,
            token: Token::new(0x2A00002A),
            offset: 0,
            number: 1,     // Second parameter (0-based)
            flags: 0x0004, // ReferenceTypeConstraint
            owner: CodedIndex::new(TableId::MethodDef, 25, CodedIndexType::TypeOrMethodDef), // MethodDef(25) = (25 << 1) | 1 = 51
            name: 128, // String index 128
        };

        // Write to buffer
        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back = GenericParamRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.number, read_back.number);
        assert_eq!(original.flags, read_back.flags);
        assert_eq!(original.owner, read_back.owner);
        assert_eq!(original.name, read_back.name);
    }

    #[test]
    fn test_genericparam_different_owner_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        // Test different TypeOrMethodDef coded index types
        let test_cases = vec![
            (TableId::TypeDef, 1, 0, 0x0000, 100),    // Type parameter T
            (TableId::MethodDef, 1, 1, 0x0001, 200),  // Method parameter U with covariance
            (TableId::TypeDef, 50, 2, 0x0002, 300),   // Type parameter V with contravariance
            (TableId::MethodDef, 25, 3, 0x0004, 400), // Method parameter W with reference constraint
            (TableId::TypeDef, 10, 0, 0x0008, 500),   // Type parameter X with value type constraint
        ];

        for (owner_tag, owner_row, param_number, param_flags, name_index) in test_cases {
            let generic_param = GenericParamRaw {
                rid: 1,
                token: Token::new(0x2A000001),
                offset: 0,
                number: param_number,
                flags: param_flags,
                owner: CodedIndex::new(owner_tag, owner_row, CodedIndexType::TypeOrMethodDef),
                name: name_index,
            };

            let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            generic_param
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                GenericParamRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(generic_param.number, read_back.number);
            assert_eq!(generic_param.flags, read_back.flags);
            assert_eq!(generic_param.owner, read_back.owner);
            assert_eq!(generic_param.name, read_back.name);
        }
    }

    #[test]
    fn test_genericparam_constraint_flags() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        // Test different common generic parameter constraint flags
        let flag_cases = vec![
            (0x0000, "None - No constraints"),
            (0x0001, "Covariant - Output positions"),
            (0x0002, "Contravariant - Input positions"),
            (0x0004, "ReferenceTypeConstraint - Must be reference type"),
            (
                0x0008,
                "NotNullableValueTypeConstraint - Must be value type",
            ),
            (
                0x0010,
                "DefaultConstructorConstraint - Must have parameterless constructor",
            ),
            (0x0005, "Covariant + ReferenceType"),
            (0x0006, "Contravariant + ReferenceType"),
            (0x0018, "ValueType + DefaultConstructor"),
        ];

        for (flags, _description) in flag_cases {
            let generic_param = GenericParamRaw {
                rid: 1,
                token: Token::new(0x2A000001),
                offset: 0,
                number: 0,
                flags,
                owner: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef),
                name: 100,
            };

            let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            generic_param
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the flags are written correctly
            let written_flags = u16::from_le_bytes([buffer[2], buffer[3]]);
            assert_eq!(written_flags as u32, flags);
        }
    }

    #[test]
    fn test_genericparam_parameter_positions() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        // Test different parameter positions (ordinals)
        let position_cases = vec![
            (0, "First parameter - T"),
            (1, "Second parameter - U"),
            (2, "Third parameter - V"),
            (3, "Fourth parameter - W"),
            (10, "Eleventh parameter"),
            (255, "Large parameter index"),
            (65535, "Maximum parameter index"),
        ];

        for (position, _description) in position_cases {
            let generic_param = GenericParamRaw {
                rid: 1,
                token: Token::new(0x2A000001),
                offset: 0,
                number: position,
                flags: 0,
                owner: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef),
                name: 100,
            };

            let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            generic_param
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the position is written correctly
            let written_number = u16::from_le_bytes([buffer[0], buffer[1]]);
            assert_eq!(written_number as u32, position);
        }
    }

    #[test]
    fn test_genericparam_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_param = GenericParamRaw {
            rid: 1,
            token: Token::new(0x2A000001),
            offset: 0,
            number: 0,
            flags: 0,
            owner: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeOrMethodDef), // TypeDef(0) = (0 << 1) | 0 = 0
            name: 0,
        };

        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_param
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // number: 0
            0x00, 0x00, // flags: 0
            0x00, 0x00, // owner: TypeDef(0) -> (0 << 1) | 0 = 0
            0x00, 0x00, // name: 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte fields
        let max_param = GenericParamRaw {
            rid: 1,
            token: Token::new(0x2A000001),
            offset: 0,
            number: 0xFFFF,
            flags: 0xFFFF,
            owner: CodedIndex::new(TableId::MethodDef, 0x7FFF, CodedIndexType::TypeOrMethodDef), // Max for 2-byte coded index
            name: 0xFFFF,
        };

        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_param
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 8); // All 2-byte fields
    }

    #[test]
    fn test_genericparam_generic_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 100), (TableId::MethodDef, 50)],
            false,
            false,
            false,
        ));

        // Test different common generic programming scenarios
        let scenarios = vec![
            (TableId::TypeDef, 1, 0, 0x0000, 100, "class List<T>"),
            (
                TableId::TypeDef,
                2,
                1,
                0x0001,
                200,
                "interface IEnumerable<out T>",
            ),
            (
                TableId::TypeDef,
                3,
                0,
                0x0002,
                300,
                "interface IComparer<in T>",
            ),
            (
                TableId::TypeDef,
                4,
                0,
                0x0004,
                400,
                "class Dictionary<TKey, TValue> where TKey : class",
            ),
            (
                TableId::MethodDef,
                1,
                0,
                0x0008,
                500,
                "T Method<T>() where T : struct",
            ),
            (
                TableId::MethodDef,
                2,
                1,
                0x0010,
                600,
                "T Create<T>() where T : new()",
            ),
            (
                TableId::TypeDef,
                5,
                2,
                0x0014,
                700,
                "class Collection<T> where T : class, new()",
            ),
        ];

        for (owner_tag, owner_row, param_pos, flags, name_idx, _description) in scenarios {
            let generic_param = GenericParamRaw {
                rid: param_pos + 1,
                token: Token::new(0x2A000000 + param_pos + 1),
                offset: 0,
                number: param_pos,
                flags,
                owner: CodedIndex::new(owner_tag, owner_row, CodedIndexType::TypeOrMethodDef),
                name: name_idx,
            };

            let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            generic_param
                .row_write(&mut buffer, &mut offset, param_pos + 1, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                GenericParamRaw::row_read(&buffer, &mut read_offset, param_pos + 1, &sizes)
                    .unwrap();

            assert_eq!(generic_param.number, read_back.number);
            assert_eq!(generic_param.flags, read_back.flags);
            assert_eq!(generic_param.owner, read_back.owner);
            assert_eq!(generic_param.name, read_back.name);
        }
    }

    #[test]
    fn test_genericparam_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 10), (TableId::MethodDef, 10)],
            false,
            false,
            false,
        ));

        let generic_param = GenericParamRaw {
            rid: 1,
            token: Token::new(0x2A000001),
            offset: 0,
            number: 0x0101,
            flags: 0x0202,
            owner: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef), // TypeDef(1) = (1 << 1) | 0 = 2
            name: 0x0404,
        };

        let mut buffer = vec![0u8; <GenericParamRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        generic_param
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, // name
        ];

        assert_eq!(buffer, expected);
    }
}

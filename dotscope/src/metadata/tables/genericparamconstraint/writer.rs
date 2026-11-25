//! Implementation of `RowWritable` for `GenericParamConstraintRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `GenericParamConstraint` table (ID 0x2C),
//! enabling writing of generic parameter constraint information back to .NET PE files. The
//! GenericParamConstraint table defines constraints that apply to generic parameters, specifying
//! type requirements that must be satisfied by type arguments.
//!
//! ## Table Structure (ECMA-335 §II.22.21)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Owner` | GenericParam table index | Generic parameter being constrained |
//! | `Constraint` | `TypeDefOrRef` coded index | Type that serves as the constraint |
//!
//! ## Coded Index Types
//!
//! The Constraint field uses the `TypeDefOrRef` coded index which can reference:
//! - **Tag 0 (TypeDef)**: References TypeDef table entries for internal constraint types
//! - **Tag 1 (TypeRef)**: References TypeRef table entries for external constraint types
//! - **Tag 2 (TypeSpec)**: References TypeSpec table entries for complex constraint types
//!
//! ## Constraint Types
//!
//! Common constraint scenarios include:
//! - **Base class constraints**: `where T : BaseClass` (inheritance requirement)
//! - **Interface constraints**: `where T : IInterface` (implementation requirement)
//! - **Multiple constraints**: Parameters can have multiple constraint entries
//! - **Generic constraints**: `where T : IComparable<T>` (generic interface constraints)

use crate::{
    metadata::tables::{
        genericparamconstraint::GenericParamConstraintRaw,
        types::{CodedIndexType, RowWritable, TableId, TableInfoRef},
    },
    utils::write_le_at_dyn,
    Result,
};

impl RowWritable for GenericParamConstraintRaw {
    fn sort_key(&self, _sizes: &TableInfoRef) -> Result<Option<(u32, u32)>> {
        Ok(Some((self.owner, 0)))
    }

    /// Serialize a GenericParamConstraint table row to binary format
    ///
    /// Writes the row data according to ECMA-335 §II.22.21 specification:
    /// - `owner`: GenericParam table index (parameter being constrained)
    /// - `constraint`: `TypeDefOrRef` coded index (constraint type reference)
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
        // Write GenericParam table index for owner
        write_le_at_dyn(
            data,
            offset,
            self.owner,
            sizes.is_large(TableId::GenericParam),
        )?;

        // Write TypeDefOrRef coded index for constraint
        let constraint_value = self.constraint.encode(sizes)?;
        write_le_at_dyn(
            data,
            offset,
            constraint_value,
            sizes.coded_index_bits(CodedIndexType::TypeDefOrRef) > 16,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::{
        tables::{
            genericparamconstraint::GenericParamConstraintRaw,
            types::{
                CodedIndex, CodedIndexType, RowReadable, RowWritable, TableId, TableInfo, TableRow,
            },
        },
        token::Token,
    };

    #[test]
    fn test_genericparamconstraint_row_size() {
        // Test with small tables
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        let expected_size = 2 + 2; // owner(2) + constraint(2)
        assert_eq!(
            <GenericParamConstraintRaw as TableRow>::row_size(&sizes),
            expected_size
        );

        // Test with large tables
        let sizes_large = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 0x10000),
                (TableId::TypeDef, 0x10000),
                (TableId::TypeRef, 0x10000),
                (TableId::TypeSpec, 0x10000),
            ],
            false,
            false,
            false,
        ));

        let expected_size_large = 4 + 4; // owner(4) + constraint(4)
        assert_eq!(
            <GenericParamConstraintRaw as TableRow>::row_size(&sizes_large),
            expected_size_large
        );
    }

    #[test]
    fn test_genericparamconstraint_row_write_small() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        let constraint = GenericParamConstraintRaw {
            rid: 1,
            token: Token::new(0x2C000001),
            offset: 0,
            owner: 0x0101,
            constraint: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef), // TypeDef(2) = (2 << 2) | 0 = 8
        };

        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        constraint
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, // owner: 0x0101, little-endian
            0x08, 0x00, // constraint: TypeDef(2) -> (2 << 2) | 0 = 8, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_genericparamconstraint_row_write_large() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 0x10000),
                (TableId::TypeDef, 0x10000),
                (TableId::TypeRef, 0x10000),
                (TableId::TypeSpec, 0x10000),
            ],
            false,
            false,
            false,
        ));

        let constraint = GenericParamConstraintRaw {
            rid: 1,
            token: Token::new(0x2C000001),
            offset: 0,
            owner: 0x01010101,
            constraint: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef), // TypeDef(2) = (2 << 2) | 0 = 8
        };

        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;

        constraint
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Verify the written data
        let expected = vec![
            0x01, 0x01, 0x01, 0x01, // owner: 0x01010101, little-endian
            0x08, 0x00, 0x00,
            0x00, // constraint: TypeDef(2) -> (2 << 2) | 0 = 8, little-endian
        ];

        assert_eq!(buffer, expected);
        assert_eq!(offset, expected.len());
    }

    #[test]
    fn test_genericparamconstraint_round_trip() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        let original = GenericParamConstraintRaw {
            rid: 42,
            token: Token::new(0x2C00002A),
            offset: 0,
            owner: 25, // GenericParam index 25
            constraint: CodedIndex::new(TableId::TypeRef, 10, CodedIndexType::TypeDefOrRef), // TypeRef(10) = (10 << 2) | 1 = 41
        };

        // Write to buffer
        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        original
            .row_write(&mut buffer, &mut offset, 42, &sizes)
            .unwrap();

        // Read back
        let mut read_offset = 0;
        let read_back =
            GenericParamConstraintRaw::row_read(&buffer, &mut read_offset, 42, &sizes).unwrap();

        // Verify round-trip
        assert_eq!(original.rid, read_back.rid);
        assert_eq!(original.token, read_back.token);
        assert_eq!(original.owner, read_back.owner);
        assert_eq!(original.constraint, read_back.constraint);
    }

    #[test]
    fn test_genericparamconstraint_different_constraint_types() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        // Test different TypeDefOrRef coded index types
        let test_cases = vec![
            (1, TableId::TypeDef, 1, "Base class constraint"),
            (2, TableId::TypeRef, 5, "External interface constraint"),
            (3, TableId::TypeSpec, 2, "Generic type constraint"),
            (
                1,
                TableId::TypeDef,
                10,
                "Multiple constraints on same parameter",
            ),
            (4, TableId::TypeRef, 15, "Different parameter constraint"),
        ];

        for (owner_idx, constraint_tag, constraint_row, _description) in test_cases {
            let constraint = GenericParamConstraintRaw {
                rid: 1,
                token: Token::new(0x2C000001),
                offset: 0,
                owner: owner_idx,
                constraint: CodedIndex::new(
                    constraint_tag,
                    constraint_row,
                    CodedIndexType::TypeDefOrRef,
                ),
            };

            let mut buffer =
                vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constraint
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Round-trip test
            let mut read_offset = 0;
            let read_back =
                GenericParamConstraintRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(constraint.owner, read_back.owner);
            assert_eq!(constraint.constraint, read_back.constraint);
        }
    }

    #[test]
    fn test_genericparamconstraint_constraint_scenarios() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        // Test different common constraint scenarios
        let scenarios = vec![
            (1, TableId::TypeDef, 1, "where T : BaseClass"),
            (1, TableId::TypeRef, 2, "where T : IInterface"),
            (2, TableId::TypeSpec, 1, "where U : IComparable<U>"),
            (3, TableId::TypeDef, 5, "where V : Enum"),
            (4, TableId::TypeRef, 10, "where W : IDisposable"),
            (1, TableId::TypeRef, 15, "T : second interface constraint"),
            (2, TableId::TypeDef, 20, "U : class constraint"),
        ];

        for (param_idx, constraint_tag, constraint_row, _description) in scenarios {
            let constraint = GenericParamConstraintRaw {
                rid: param_idx,
                token: Token::new(0x2C000000 + param_idx),
                offset: 0,
                owner: param_idx,
                constraint: CodedIndex::new(
                    constraint_tag,
                    constraint_row,
                    CodedIndexType::TypeDefOrRef,
                ),
            };

            let mut buffer =
                vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constraint
                .row_write(&mut buffer, &mut offset, param_idx, &sizes)
                .unwrap();

            // Round-trip validation
            let mut read_offset = 0;
            let read_back =
                GenericParamConstraintRaw::row_read(&buffer, &mut read_offset, param_idx, &sizes)
                    .unwrap();

            assert_eq!(constraint.owner, read_back.owner);
            assert_eq!(constraint.constraint, read_back.constraint);
        }
    }

    #[test]
    fn test_genericparamconstraint_multiple_constraints() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        // Test multiple constraints on the same parameter (common scenario)
        let constraints = vec![
            (1, TableId::TypeDef, 1),  // T : BaseClass
            (1, TableId::TypeRef, 2),  // T : IInterface1
            (1, TableId::TypeRef, 3),  // T : IInterface2
            (1, TableId::TypeSpec, 1), // T : IComparable<T>
        ];

        for (param_idx, constraint_tag, constraint_row) in constraints {
            let constraint = GenericParamConstraintRaw {
                rid: 1,
                token: Token::new(0x2C000001),
                offset: 0,
                owner: param_idx,
                constraint: CodedIndex::new(
                    constraint_tag,
                    constraint_row,
                    CodedIndexType::TypeDefOrRef,
                ),
            };

            let mut buffer =
                vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constraint
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify each constraint is written correctly
            let mut read_offset = 0;
            let read_back =
                GenericParamConstraintRaw::row_read(&buffer, &mut read_offset, 1, &sizes).unwrap();

            assert_eq!(constraint.owner, read_back.owner);
            assert_eq!(constraint.constraint, read_back.constraint);
        }
    }

    #[test]
    fn test_genericparamconstraint_edge_cases() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        // Test with zero values
        let zero_constraint = GenericParamConstraintRaw {
            rid: 1,
            token: Token::new(0x2C000001),
            offset: 0,
            owner: 0,
            constraint: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef), // TypeDef(0) = (0 << 2) | 0 = 0
        };

        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        zero_constraint
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        let expected = vec![
            0x00, 0x00, // owner: 0
            0x00, 0x00, // constraint: TypeDef(0) -> (0 << 2) | 0 = 0
        ];

        assert_eq!(buffer, expected);

        // Test with maximum values for 2-byte indexes
        let max_constraint = GenericParamConstraintRaw {
            rid: 1,
            token: Token::new(0x2C000001),
            offset: 0,
            owner: 0xFFFF,
            constraint: CodedIndex::new(TableId::TypeSpec, 0x3FFF, CodedIndexType::TypeDefOrRef), // Max for 2-byte coded index
        };

        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        max_constraint
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        assert_eq!(buffer.len(), 4); // Both 2-byte fields
    }

    #[test]
    fn test_genericparamconstraint_type_references() {
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 100),
                (TableId::TypeDef, 50),
                (TableId::TypeRef, 25),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        // Test different type reference patterns
        let type_refs = vec![
            (TableId::TypeDef, 1, "Internal class"),
            (TableId::TypeDef, 10, "Internal interface"),
            (TableId::TypeRef, 1, "External class (System.Object)"),
            (TableId::TypeRef, 5, "External interface (IDisposable)"),
            (TableId::TypeSpec, 1, "Generic type (IComparable<T>)"),
            (TableId::TypeSpec, 3, "Array type (T[])"),
        ];

        for (constraint_tag, constraint_row, _description) in type_refs {
            let constraint = GenericParamConstraintRaw {
                rid: 1,
                token: Token::new(0x2C000001),
                offset: 0,
                owner: 1,
                constraint: CodedIndex::new(
                    constraint_tag,
                    constraint_row,
                    CodedIndexType::TypeDefOrRef,
                ),
            };

            let mut buffer =
                vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
            let mut offset = 0;
            constraint
                .row_write(&mut buffer, &mut offset, 1, &sizes)
                .unwrap();

            // Verify the constraint type is encoded correctly
            let expected_constraint_value = match constraint_tag {
                TableId::TypeDef => constraint_row << 2,
                TableId::TypeRef => (constraint_row << 2) | 1,
                TableId::TypeSpec => (constraint_row << 2) | 2,
                _ => panic!("Unexpected constraint tag"),
            };

            let written_constraint = u16::from_le_bytes([buffer[2], buffer[3]]) as u32;
            assert_eq!(written_constraint, expected_constraint_value);
        }
    }

    #[test]
    fn test_genericparamconstraint_known_binary_format() {
        // Test with known binary data from reader tests
        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 10),
                (TableId::TypeDef, 10),
                (TableId::TypeRef, 10),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));

        let constraint = GenericParamConstraintRaw {
            rid: 1,
            token: Token::new(0x2C000001),
            offset: 0,
            owner: 0x0101,
            constraint: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef), // TypeDef(2) = (2 << 2) | 0 = 8
        };

        let mut buffer =
            vec![0u8; <GenericParamConstraintRaw as TableRow>::row_size(&sizes) as usize];
        let mut offset = 0;
        constraint
            .row_write(&mut buffer, &mut offset, 1, &sizes)
            .unwrap();

        // Expected data based on reader test format
        let expected = vec![
            0x01, 0x01, // owner
            0x08, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        assert_eq!(buffer, expected);
    }
}

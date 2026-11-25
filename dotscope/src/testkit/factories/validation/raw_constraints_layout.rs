//! Factory methods for raw constraints layout validation testing.
//!
//! Contains helper methods migrated from raw constraints layout validation source files
//! for creating test assemblies with various layout constraint validation scenarios.

use crate::{
    metadata::{
        tables::{
            ClassLayoutRaw, FieldAttributes, FieldBuilder, FieldLayoutRaw, TableDataOwned, TableId,
            TypeAttributes, TypeDefBuilder,
        },
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_wb, Expect, TestAssembly},
    Result,
};

/// Test factory for RawLayoutConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all layout constraint validation rules:
/// 1. Clean assembly (should pass)
/// 2. Null field reference in FieldLayout
/// 3. Invalid field offset - exceeding 0x7FFFFFFF
/// 4. Invalid packing size - not power of 2
/// 5. Excessive class size - exceeding 0x7FFFFFFF
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that should trigger validation failures in the raw validation stage.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn raw_layout_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_wb();

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. Null field reference in FieldLayout - should definitely fail
    assemblies.push(create_assembly_with_null_field_reference()?);

    // 3. Invalid field offset - exceeding 0x7FFFFFFF
    assemblies.push(create_assembly_with_invalid_field_offset()?);

    // 4. Invalid packing size - not power of 2
    assemblies.push(create_assembly_with_invalid_packing_size()?);

    // 5. Excessive class size - exceeding 0x7FFFFFFF
    assemblies.push(create_assembly_with_excessive_class_size()?);

    Ok(assemblies)
}

/// Creates an assembly with invalid packing size (not power of 2) to test class layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_invalid_packing_size() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("has invalid packing size 3 - must be 0 or a power of 2"),
        |assembly| {
            let typedef_token = TypeDefBuilder::new()
                .name("InvalidPackingType")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT)
                .build(assembly)?;

            // Create class layout with invalid packing size directly
            let class_layout = ClassLayoutRaw {
                packing_size: 3, // Invalid - not power of 2
                class_size: 16,
                parent: typedef_token.placeholder(),
                rid: 1,
                token: Token::new(0x0F000001), // ClassLayout table token
                offset: 0,
            };

            assembly.table_row_update(
                TableId::ClassLayout,
                1,
                TableDataOwned::ClassLayout(class_layout),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with excessive class size to test class layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_excessive_class_size() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("has invalid class size 2147483648 exceeding maximum"),
        |assembly| {
            let typedef_token = TypeDefBuilder::new()
                .name("ExcessiveSizeType")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT)
                .build(assembly)?;

            // Create class layout with excessive size directly
            let class_layout = ClassLayoutRaw {
                packing_size: 1,
                class_size: 0x80000000, // Exceeds maximum allowed (0x7FFFFFFF)
                parent: typedef_token.placeholder(),
                rid: 1,
                token: Token::new(0x0F000001), // ClassLayout table token
                offset: 0,
            };

            assembly.table_row_update(
                TableId::ClassLayout,
                1,
                TableDataOwned::ClassLayout(class_layout),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with invalid field offset to test field layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_invalid_field_offset() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("has invalid field offset 2147483648 exceeding maximum"),
        |assembly| {
            let _typedef_token = TypeDefBuilder::new()
                .name("InvalidOffsetType")
                .namespace("Test")
                .flags(
                    TypeAttributes::BEFORE_FIELD_INIT
                        | TypeAttributes::SEALED
                        | TypeAttributes::SEQUENTIAL_LAYOUT,
                ) // Explicit layout
                .build(assembly)?;

            let field_token = FieldBuilder::new()
                .name("InvalidField")
                .flags(FieldAttributes::PRIVATE)
                .signature(&[0x06, 0x08])
                .build(assembly)?;

            // Create field layout with invalid field offset directly
            let field_layout = FieldLayoutRaw {
                field_offset: 0x80000000, // Exceeds maximum allowed (0x7FFFFFFF)
                field: field_token.placeholder(),
                rid: 1,
                token: Token::new(0x10000001), // FieldLayout table token
                offset: 0,                     // Metadata stream offset
            };

            assembly.table_row_update(
                TableId::FieldLayout,
                1,
                TableDataOwned::FieldLayout(field_layout),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with null field reference to test field layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_null_field_reference() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("FieldLayout RID 1 has null field reference"),
        |assembly| {
            let _typedef_token = TypeDefBuilder::new()
                .name("NullFieldRefType")
                .namespace("Test")
                .flags(
                    TypeAttributes::BEFORE_FIELD_INIT
                        | TypeAttributes::SEALED
                        | TypeAttributes::SEQUENTIAL_LAYOUT,
                ) // Explicit layout
                .build(assembly)?;

            // Create field layout with null field reference directly
            let field_layout = FieldLayoutRaw {
                field_offset: 0,
                field: 0, // Null field reference - should cause error
                rid: 1,
                token: Token::new(0x10000001), // FieldLayout table token
                offset: 0,
            };

            assembly.table_row_update(
                TableId::FieldLayout,
                1,
                TableDataOwned::FieldLayout(field_layout),
            )?;

            Ok(())
        },
    )
}

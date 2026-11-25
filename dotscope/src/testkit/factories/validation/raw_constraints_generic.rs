//! Factory methods for raw constraints generic validation testing.
//!
//! Contains helper methods migrated from raw constraints generic validation source files
//! for creating test assemblies with various generic constraint validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamAttributes, GenericParamBuilder,
            GenericParamConstraintRaw, TableDataOwned, TableId, TypeAttributes, TypeDefBuilder,
        },
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_wb, Expect, TestAssembly},
    Result,
};

/// Test factory for RawGenericConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all generic constraint validation rules:
/// 1. Clean assembly (should pass)
/// 2. Generic parameter with invalid flags (both covariant and contravariant)
/// 3. Generic parameter constraint with null owner reference
/// 4. Generic parameter constraint with owner exceeding table bounds
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that should trigger validation failures in the raw validation stage.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn raw_generic_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_wb();

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Generic parameter with invalid flags (both covariant and contravariant)
    assemblies.push(create_assembly_with_invalid_parameter_flags()?);

    // 3. NEGATIVE: Generic parameter constraint with null owner reference
    assemblies.push(create_assembly_with_null_constraint_owner()?);

    // 4. NEGATIVE: Generic parameter constraint with owner exceeding table bounds
    assemblies.push(create_assembly_with_constraint_owner_exceeding_bounds()?);

    Ok(assemblies)
}

/// Creates an assembly with a generic parameter constraint with null owner reference.
/// Uses raw table manipulation to create an invalid constraint with owner = 0.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_null_constraint_owner() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("GenericParamConstraint RID 1 has null owner reference"),
        |assembly| {
            // Create a valid generic parameter first
            let typedef_token = TypeDefBuilder::new()
                .name("GenericType")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT)
                .build(assembly)?;

            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token.placeholder(),
                CodedIndexType::TypeOrMethodDef,
            );

            let _generic_param_token = GenericParamBuilder::new()
                .number(0)
                .flags(GenericParamAttributes::ZERO)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            // Create GenericParamConstraint with null owner using raw table manipulation
            let invalid_constraint = GenericParamConstraintRaw {
                owner: 0, // Invalid: null owner reference
                constraint: CodedIndex::new(
                    TableId::TypeDef,
                    typedef_token.placeholder(),
                    CodedIndexType::TypeDefOrRef,
                ),
                rid: 1,
                token: Token::new(0x2C000001), // GenericParamConstraint table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::GenericParamConstraint,
                TableDataOwned::GenericParamConstraint(invalid_constraint),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a generic parameter constraint where owner exceeds table bounds.
/// Uses raw table manipulation to create an invalid constraint reference.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_constraint_owner_exceeding_bounds() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("references GenericParam RID 65535 but table only has"),
        |assembly| {
            // Create a valid generic parameter first
            let typedef_token = TypeDefBuilder::new()
                .name("GenericType")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT)
                .build(assembly)?;

            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token.placeholder(),
                CodedIndexType::TypeOrMethodDef,
            );

            let _generic_param_token = GenericParamBuilder::new()
                .number(0)
                .flags(GenericParamAttributes::ZERO)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            // Create GenericParamConstraint with owner exceeding GenericParam table bounds
            let invalid_constraint = GenericParamConstraintRaw {
                owner: 0xFFFF, // Invalid: far exceeds any realistic GenericParam table size
                constraint: CodedIndex::new(
                    TableId::TypeDef,
                    typedef_token.placeholder(),
                    CodedIndexType::TypeDefOrRef,
                ),
                rid: 1,
                token: Token::new(0x2C000001), // GenericParamConstraint table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::GenericParamConstraint,
                TableDataOwned::GenericParamConstraint(invalid_constraint),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with generic parameter having conflicting variance flags.
/// This tests whether the validator catches flag combinations the builder allows.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_invalid_parameter_flags() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("has both covariant and contravariant flags set"),
        |assembly| {
            let typedef_builder = TypeDefBuilder::new()
                .name("GenericType")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT);

            let typedef_token = typedef_builder.build(assembly)?;

            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token.placeholder(),
                CodedIndexType::TypeOrMethodDef,
            );

            GenericParamBuilder::new()
                .number(0)
                .flags(GenericParamAttributes::new(0x0003))
                .owner(owner)
                .name("T")
                .build(assembly)?;

            Ok(())
        },
    )
}

//! Factory methods for constraints types validation testing.
//!
//! Contains helper methods migrated from constraints types validation source files
//! for creating test assemblies with various type constraint validation scenarios.

use crate::{
    metadata::tables::{
        CodedIndex, CodedIndexType, GenericParamAttributes, GenericParamBuilder,
        GenericParamConstraintBuilder, InterfaceImplBuilder, TableId, TypeAttributes,
        TypeDefBuilder,
    },
    testkit::{create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly},
    Result,
};

/// Test factory for OwnedTypeConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all validation rules:
/// 1. Clean assembly (should pass)
/// 2. Assembly with conflicting generic parameter attributes (covariant + contravariant)
/// 3. Assembly with conflicting constraint types (reference type + value type)
/// 4. Assembly with unresolved constraint references (broken constraint reference)
/// 5. Assembly with empty constraint type names (unresolved constraint)
/// 6. Assembly with non-interface implemented as interface
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the constraint violations that the owned
/// validator should detect in the resolved metadata structures.
pub fn owned_type_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. Clean assembly - should pass all constraint validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. Assembly with conflicting variance attributes (covariant + contravariant)
    assemblies.push(create_assembly_with_conflicting_variance()?);

    // 3. Assembly with conflicting constraint types (reference + value type)
    assemblies.push(create_assembly_with_conflicting_constraints()?);

    // 4. Assembly with broken constraint references (invalid RID)
    assemblies.push(create_assembly_with_broken_constraint_reference()?);

    // 5. Assembly with empty constraint type name (unresolved constraint)
    assemblies.push(create_assembly_with_empty_constraint_name()?);

    // 6. Assembly with non-interface implemented as interface
    assemblies.push(create_assembly_with_fake_interface_implementation()?);

    Ok(assemblies)
}

/// Creates an assembly with conflicting generic parameter variance attributes.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// both COVARIANT and CONTRAVARIANT flags set, which violates ECMA-335 constraints.
/// When loaded by CilObject, this should trigger validation failure in the owned validator.
fn create_assembly_with_conflicting_variance() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("cannot be both covariant and contravariant"),
        |assembly| {
            // Create a generic type definition
            let typedef_token = TypeDefBuilder::new()
                .name("ConflictingVarianceType`1")
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic
                .build(assembly)?;

            // Create GenericParam with conflicting variance flags (COVARIANT | CONTRAVARIANT)
            let conflicting_flags =
                GenericParamAttributes::COVARIANT | GenericParamAttributes::CONTRAVARIANT;

            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeOrMethodDef,
            );

            GenericParamBuilder::new()
                .number(0)
                .flags(conflicting_flags)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with conflicting constraint type attributes.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// both REFERENCE_TYPE_CONSTRAINT and NOT_NULLABLE_VALUE_TYPE_CONSTRAINT flags set,
/// which is invalid according to ECMA-335. When loaded by CilObject, this should
/// trigger validation failure in the owned validator.
fn create_assembly_with_conflicting_constraints() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("cannot have both reference type and value type constraints"),
        |assembly| {
            // Create a generic type definition
            let typedef_token = TypeDefBuilder::new()
                .name("ConflictingConstraintsType`1")
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic
                .build(assembly)?;

            // Create GenericParam with conflicting constraint flags (class + struct)
            let conflicting_flags = GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT
                | GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT;

            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeOrMethodDef,
            );

            GenericParamBuilder::new()
                .number(0)
                .flags(conflicting_flags)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with broken constraint references.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// a constraint reference pointing to an invalid/non-existent type RID. When the
/// metadata is resolved by CilObject, this should result in broken constraint references
/// that trigger validation failure in the owned validator.
fn create_assembly_with_broken_constraint_reference() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        // The loader resolves constraint types and refuses one it cannot (0x01000001).
        Expect::refused("Failed to resolve constraint type token - 16777217"),
        |assembly| {
            // Create a generic type definition
            let typedef_token = TypeDefBuilder::new()
                .name("BrokenConstraintType`1")
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic
                .build(assembly)?;

            // Create a GenericParam
            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeOrMethodDef,
            );

            let generic_param_token = GenericParamBuilder::new()
                .number(0)
                .flags(GenericParamAttributes::ZERO)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            // Create a GenericParamConstraint with invalid constraint reference (out-of-bounds TypeRef RID)
            let invalid_constraint = CodedIndex::new(
                TableId::TypeRef,
                1, // mscorlib has no TypeRef rows
                CodedIndexType::TypeDefOrRef,
            );

            GenericParamConstraintBuilder::new()
                .owner(
                    generic_param_token
                        .token()
                        .expect("GenericParam token should be resolved")
                        .row(),
                )
                .constraint(invalid_constraint)
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with empty constraint type names.
///
/// This creates a raw assembly where constraint types have empty names,
/// simulating unresolved constraints that should trigger validation failure.
fn create_assembly_with_empty_constraint_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("in type 'EmptyConstraintType`1' has unresolved constraint"),
        |assembly| {
            // Create a generic type definition
            let typedef_token = TypeDefBuilder::new()
                .name("EmptyConstraintType`1")
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic
                .build(assembly)?;

            // Create a constraint type with empty name (simulating unresolved type)
            let constraint_typedef_token = TypeDefBuilder::new()
                .name("") // Empty name - this should trigger the validation error
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC)
                .build(assembly)?;

            // Create a GenericParam
            let owner = CodedIndex::new(
                TableId::TypeDef,
                typedef_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeOrMethodDef,
            );

            let generic_param_token = GenericParamBuilder::new()
                .number(0)
                .flags(GenericParamAttributes::ZERO)
                .owner(owner)
                .name("T")
                .build(assembly)?;

            // Create a GenericParamConstraint referencing the empty-named type
            let constraint_ref = CodedIndex::new(
                TableId::TypeDef,
                constraint_typedef_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeDefOrRef,
            );

            GenericParamConstraintBuilder::new()
                .owner(
                    generic_param_token
                        .token()
                        .expect("GenericParam token should be resolved")
                        .row(),
                )
                .constraint(constraint_ref)
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with a class implementing a non-interface as an interface.
///
/// This creates a raw assembly containing a class that implements another class
/// (not an interface) as if it were an interface, which should trigger validation
/// failure when the owned validator checks interface implementation constraints.
fn create_assembly_with_fake_interface_implementation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'ImplementingClass' implements non-interface type 'NotAnInterface'"),
        |assembly| {
            // Create a regular class (NOT an interface) that will be "implemented" as an interface
            let fake_interface_token = TypeDefBuilder::new()
                .name("NotAnInterface") // Name doesn't suggest interface
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic - NOT an interface (missing INTERFACE flag)
                .build(assembly)?;

            // Create a class that "implements" the non-interface
            let implementing_class_token = TypeDefBuilder::new()
                .name("ImplementingClass")
                .namespace("Test")
                .flags(TypeAttributes::NOT_PUBLIC) // Class, NotPublic
                .build(assembly)?;

            // Create InterfaceImpl that makes the class "implement" the non-interface
            let fake_interface_ref = CodedIndex::new(
                TableId::TypeDef,
                fake_interface_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeDefOrRef,
            );

            InterfaceImplBuilder::new()
                .class(
                    implementing_class_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                )
                .interface(fake_interface_ref)
                .build(assembly)?;

            Ok(())
        },
    )
}

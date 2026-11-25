//! Factory methods for dependency validation testing.
//!
//! Contains helper methods migrated from dependency validation source files
//! for creating test assemblies with various dependency validation scenarios.

use crate::{
    metadata::tables::{
        CodedIndex, CodedIndexType, InterfaceImplBuilder, NestedClassBuilder, TableId,
        TypeAttributes, TypeDefBuilder,
    },
    testkit::{create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly},
    Result,
};

/// Main factory method for creating dependency validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn owned_dependency_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all dependency validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE TEST: Type with base type that has empty name
    assemblies.push(create_assembly_with_empty_name_base_type()?);

    // 3. NEGATIVE TEST: Type that implements an interface with empty name
    assemblies.push(create_assembly_with_empty_name_interface()?);

    // 4. NEGATIVE TEST: Type with a nested type that has empty name
    assemblies.push(create_assembly_with_empty_name_nested_type()?);

    Ok(assemblies)
}

/// Creates an assembly where a type extends a base type with an empty name.
///
/// This triggers the validator check: "Type 'X' has broken base type dependency (empty name)"
pub fn create_assembly_with_empty_name_base_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'DerivedType' has broken base type dependency (empty name)"),
        |assembly| {
            // Create a base type with empty name
            let empty_base = TypeDefBuilder::new()
                .name("") // Empty name triggers the validator
                .namespace("Test.Dependency")
                .flags(TypeAttributes::CLASS)
                .build(assembly)?;

            // Create a derived type that extends the empty-named base
            TypeDefBuilder::new()
                .name("DerivedType")
                .namespace("Test.Dependency")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    empty_base
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly where a type has a nested type with an empty name.
///
/// This triggers the validator check: "Type 'X' has broken nested type dependency (empty name)"
pub fn create_assembly_with_empty_name_nested_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'EnclosingType' has broken nested type dependency (empty name)"),
        |assembly| {
            // Create an enclosing type
            let enclosing_type = TypeDefBuilder::new()
                .name("EnclosingType")
                .namespace("Test.Dependency")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .build(assembly)?;

            // Create a nested type with empty name
            let empty_nested = TypeDefBuilder::new()
                .name("") // Empty name triggers the validator
                .namespace("Test.Dependency")
                .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
                .build(assembly)?;

            // Add NestedClass entry
            NestedClassBuilder::new()
                .nested_class(empty_nested.placeholder())
                .enclosing_class(enclosing_type.placeholder())
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly where a type implements an interface with an empty name.
///
/// This triggers the validator check: "Type 'X' has broken interface dependency (empty name)"
pub fn create_assembly_with_empty_name_interface() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'ImplementingClass' has broken interface dependency (empty name)"),
        |assembly| {
            // Create an interface with empty name
            let empty_interface = TypeDefBuilder::new()
                .name("") // Empty name triggers the validator
                .namespace("Test.Dependency")
                .flags(TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT)
                .build(assembly)?;

            // Create a class that implements the empty-named interface
            let implementing_class = TypeDefBuilder::new()
                .name("ImplementingClass")
                .namespace("Test.Dependency")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .build(assembly)?;

            // Add InterfaceImpl entry
            InterfaceImplBuilder::new()
                .class(
                    implementing_class
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                )
                .interface(CodedIndex::new(
                    TableId::TypeDef,
                    empty_interface
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

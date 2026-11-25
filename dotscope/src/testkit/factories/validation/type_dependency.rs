//! Factory methods for type dependency validation testing.
//!
//! Contains helper methods migrated from type dependency validation source files
//! for creating test assemblies with various type dependency validation scenarios.

use crate::{
    metadata::{tables::*, token::Token},
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly,
        MSCORLIB_OBJECT_CTOR_RVA, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Main factory method for type dependency validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn owned_type_dependency_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all type dependency validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Type with unresolved base type dependency
    match create_assembly_with_unresolved_base_type() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with unresolved base type: {e}"
            )));
        }
    }

    // 3. NEGATIVE: Type with broken interface dependency reference
    match create_assembly_with_broken_interface_reference() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with broken interface reference: {e}"
            )));
        }
    }

    // 4. NEGATIVE: Method whose parameter type does not resolve
    assemblies.push(create_assembly_with_missing_parameter_type()?);

    // 5. NEGATIVE: Type with unresolved nested type dependency (testing)
    match create_assembly_with_unresolved_nested_type() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with unresolved nested type: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates an assembly with a type that has an unresolved base type dependency.
/// Uses raw table manipulation to create a type with a base type that has an empty name,
/// triggering the "unresolved base type dependency" validation error.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_unresolved_base_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'DerivedClass' (token 0x0200060D) has unresolved base type dependency"),
        |assembly| {
            // Create a type with a valid base type reference
            let base_typedef_token = TypeDefBuilder::new()
                .name("BaseClass")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let base_rid = base_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            let _derived_typedef_token = TypeDefBuilder::new()
                .name("DerivedClass")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT) // Public class
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    base_rid,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            // Corrupt the base type by setting its name to an empty string (index 0)
            // This simulates an unresolved base type dependency
            let corrupted_base_type = TypeDefRaw {
                flags: TypeAttributes::BEFORE_FIELD_INIT.bits(),
                type_name: 0,      // Empty name - this will trigger the validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
                rid: base_rid,
                token: Token::new(0x02000000 | base_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                base_rid,
                TableDataOwned::TypeDef(corrupted_base_type),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a type that has a broken interface dependency reference.
/// This simulates a scenario where an interface reference cannot be resolved.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_broken_interface_reference() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'TestClass' (token 0x0200060D) has unresolved interface dependency"),
        |assembly| {
            // Create an interface type
            let interface_typedef_token = TypeDefBuilder::new()
                .name("ITestInterface")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT | TypeAttributes::INTERFACE) // Public + Interface
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let interface_rid = interface_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create a type that implements the interface
            let implementing_typedef_token = TypeDefBuilder::new()
                .name("TestClass")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let implementing_rid = implementing_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Add interface implementation
            let interface_impl = InterfaceImplRaw {
                class: implementing_rid,
                interface: CodedIndex::new(
                    TableId::TypeDef,
                    interface_rid,
                    CodedIndexType::TypeDefOrRef,
                ),
                rid: 1,
                token: Token::new(0x09000001), // InterfaceImpl table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::InterfaceImpl,
                TableDataOwned::InterfaceImpl(interface_impl),
            )?;

            // Corrupt the interface type by setting its name to empty (index 0)
            // This will cause the interface dependency to appear unresolved
            let corrupted_interface_type = TypeDefRaw {
                flags: (TypeAttributes::BEFORE_FIELD_INIT | TypeAttributes::INTERFACE).bits(), // Public + Interface
                type_name: 0,      // Empty name - this will trigger the validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
                rid: interface_rid,
                token: Token::new(0x02000000 | interface_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                interface_rid,
                TableDataOwned::TypeDef(corrupted_interface_type),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a type that has an unresolved nested type dependency.
/// This simulates a nested type with an empty name that cannot be resolved.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_unresolved_nested_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Type 'ContainingClass' (token 0x0200060C) has unresolved nested type dependency",
        ),
        |assembly| {
            // Create a containing type
            let containing_typedef_token = TypeDefBuilder::new()
                .name("ContainingClass")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let containing_rid = containing_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create a nested type
            let nested_typedef_token = TypeDefBuilder::new()
                .name("NestedClass")
                .namespace("Test")
                .flags(TypeAttributes::BEFORE_FIELD_INIT | TypeAttributes::SEQUENTIAL_LAYOUT) // Public + Nested
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let nested_rid = nested_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create the corrupted nested type with empty name to trigger validation error
            // This simulates a nested type that cannot be resolved during validation
            let corrupted_nested_type = TypeDefRaw {
                flags: (TypeAttributes::BEFORE_FIELD_INIT | TypeAttributes::SEQUENTIAL_LAYOUT)
                    .bits(), // Public + Nested
                type_name: 0, // Empty name at index 0 - this should trigger validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
                rid: nested_rid,
                token: Token::new(0x02000000 | nested_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                nested_rid,
                TableDataOwned::TypeDef(corrupted_nested_type),
            )?;

            // Create nested class relationship - this will create a dependency on the corrupted type
            let nested_class = NestedClassRaw {
                nested_class: nested_rid,
                enclosing_class: containing_rid,
                rid: 1,
                token: Token::new(0x29000001), // NestedClass table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::NestedClass,
                TableDataOwned::NestedClass(nested_class),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a method whose parameter is a class no row defines (TypeRef 1:
/// mscorlib has no TypeRefs). It has no Param row, so the loader never types it: the
/// validator reads the parameter from the signature.
pub fn create_assembly_with_missing_parameter_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Method 'Take' parameter 0 has unresolved type dependency 0x01000001"),
        |assembly| {
            TypeDefBuilder::new()
                .name("TypeWithMissingParameterType")
                .namespace("Test.Dependency")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;
            MethodDefBuilder::new()
                .name("Take")
                .flags(0x0016) // Public, Static
                .impl_flags(0x0000) // IL
                // DEFAULT, one parameter, VOID, CLASS TypeRef 1 ((1 << 2) | TypeRef tag)
                .signature(&[0x00, 0x01, 0x01, 0x12, 0x05])
                .rva(MSCORLIB_OBJECT_CTOR_RVA)
                .build(assembly)?;
            Ok(())
        },
    )
}

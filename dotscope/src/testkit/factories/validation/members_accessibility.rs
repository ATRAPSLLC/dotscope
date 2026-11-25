//! Factory methods for members accessibility validation testing.
//!
//! Contains helper methods migrated from members accessibility validation source files
//! for creating test assemblies with various accessibility validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, FieldAttributes, FieldBuilder, FieldRaw, MethodDefRaw,
            NestedClassRaw, TableDataOwned, TableId, TypeAttributes, TypeDefBuilder, TypeDefRaw,
        },
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_crafted2, Expect, TestAssembly},
    Result,
};

/// Main factory method for members accessibility validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn owned_accessibility_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_crafted2();

    // 1. REQUIRED: Clean assembly - should pass all accessibility validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test sealed interface (interfaces can't be sealed)
    assemblies.push(create_assembly_with_sealed_interface()?);

    // 3. NEGATIVE: Test interface with non-static field
    assemblies.push(create_assembly_with_interface_instance_field()?);

    // 4. ACCEPTED: An interface with a static field that is not a constant
    assemblies.push(create_assembly_with_interface_non_constant_field()?);

    // 5. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 6. NEGATIVE: Test literal field that's not static
    assemblies.push(create_assembly_with_literal_non_static_field()?);

    // 7. NEGATIVE: Test nested type with top-level visibility instead of nested visibility
    assemblies.push(create_assembly_with_nested_accessibility_violation()?);

    Ok(assemblies)
}

/// Creates an assembly with a sealed interface - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_sealed_interface() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_crafted2,
        Expect::fail("Interface 'InvalidSealedInterface' cannot be sealed"),
        |assembly| {
            let name_index = assembly.string_add("InvalidSealedInterface")?;

            let next_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

            // Create interface with SEALED flag (0x0100) - this should be invalid
            let invalid_interface = TypeDefRaw {
                rid: next_rid,
                token: Token::new(0x02000000 + next_rid),
                offset: 0,
                flags: (TypeAttributes::INTERFACE | TypeAttributes::SEALED).bits(), // Interface + Sealed - invalid combination
                type_name: name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_interface))?;

            Ok(())
        },
    )
}

/// Creates an assembly with interface containing non-static field - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_interface_instance_field() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_crafted2,
        Expect::fail(
            "Interface 'InterfaceWithInstanceField' contains non-static field 'InstanceField'",
        ),
        |assembly| {
            // Get the next RIDs for TypeDef and Field
            let interface_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let field_rid = assembly.original_table_row_count(TableId::Field) + 1;

            // Create interface type name
            let interface_name_index = assembly.string_add("InterfaceWithInstanceField")?;

            // Create field name and signature
            let field_name_index = assembly.string_add("InstanceField")?;

            let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
            let signature_index = assembly.blob_add(&signature_bytes)?;

            // Create the interface type first, with field_list pointing to our field
            let interface_type = TypeDefRaw {
                rid: interface_rid,
                token: Token::new(0x02000000 + interface_rid),
                offset: 0,
                flags: (TypeAttributes::INTERFACE | TypeAttributes::PUBLIC).bits(),
                type_name: interface_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                field_list: field_rid, // Point to the field we'll create
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            // Create the field with non-static flag (invalid in interface)
            let invalid_field = FieldRaw {
                rid: field_rid,
                token: Token::new(0x04000000 + field_rid),
                offset: 0,
                flags: FieldAttributes::PUBLIC.bits(), // Missing STATIC flag - invalid in interface
                name: field_name_index.placeholder(),
                signature: signature_index.placeholder(),
            };

            // Add both to the assembly
            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_type))?;

            assembly.table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))?;

            Ok(())
        },
    )
}

/// Creates an assembly with an interface holding a static field that is not a constant, which
/// ECMA-335 II.12 allows: an interface may have static fields, only no instance fields.
pub fn create_assembly_with_interface_non_constant_field() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_crafted2, Expect::Pass, |assembly| {
        // A static field without LITERAL
        let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
        let field_token = FieldBuilder::new()
            .name("NonConstantField")
            .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC)
            .signature(&signature_bytes)
            .build(assembly)?;

        // Create interface type and explicitly associate the field with it
        let _interface_token = TypeDefBuilder::new()
            .name("InterfaceWithNonConstantField")
            .namespace("")
            .flags(TypeAttributes::INTERFACE | TypeAttributes::PUBLIC)
            .field_list(
                field_token
                    .token()
                    .expect("Field token should be resolved")
                    .row(),
            ) // Explicitly associate field with this type
            .build(assembly)?;

        Ok(())
    })
}

/// Creates an assembly with method having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_crafted2,
        Expect::fail("Method in type 'TypeWithEmptyMethodName' has empty name"),
        |assembly| {
            // Create type
            let type_name_index = assembly.string_add("TypeWithEmptyMethodName")?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create method with empty name - invalid
            let empty_name_index = assembly.string_add("")?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // Method signature: DEFAULT calling convention, 0 args, void return
            let signature_index = assembly.blob_add(&signature_bytes)?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006,                        // Public
                name: empty_name_index.placeholder(), // Empty name - invalid
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))?;

            assembly.table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with literal field that's not static - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_literal_non_static_field() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_crafted2,
        Expect::fail("Literal field 'LiteralInstanceField' in type 'TypeWithLiteralInstanceField' must be static"),
        |assembly| {
            // Create literal field without static flag - invalid per ECMA-335
            let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
            let field_token = FieldBuilder::new()
                .name("LiteralInstanceField")
                .flags(FieldAttributes::PUBLIC | FieldAttributes::LITERAL) // LITERAL without STATIC - invalid
                .signature(&signature_bytes)
                .build(assembly)?;

            // Create type and explicitly associate the field with it
            let _type_token = TypeDefBuilder::new()
                .name("TypeWithLiteralInstanceField")
                .namespace("")
                .flags(TypeAttributes::PUBLIC)
                .field_list(
                    field_token
                        .token()
                        .expect("Field token should be resolved")
                        .row(),
                ) // Explicitly associate field with this type
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with nested type accessibility violation
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
/// Moved to accessibility validator as it tests accessibility, not ownership.
pub fn create_assembly_with_nested_accessibility_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_crafted2,
        Expect::fail("Nested type 'InternalContainer' has invalid visibility flags: 0x00"),
        |assembly| {
            // Create non-public container type
            let container_name_index = assembly.string_add("InternalContainer")?;

            let container_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let container_type = TypeDefRaw {
                rid: container_rid,
                token: Token::new(0x02000000 + container_rid),
                offset: 0,
                flags: TypeAttributes::NOT_PUBLIC.bits(), // Not public container
                type_name: container_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(container_type))?;

            // Create nested type with top-level visibility instead of nested visibility - should trigger validation failure
            let nested_name_index = assembly.string_add("InternalContainer+InvalidNested")?;

            let nested_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let nested_type = TypeDefRaw {
                rid: nested_rid,
                token: Token::new(0x02000000 + nested_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(), // Using top-level PUBLIC instead of NESTED_PUBLIC - should trigger validation failure
                type_name: nested_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(nested_type))?;

            // Create NestedClass entry to establish the ownership relationship
            let nested_class_rid = assembly.original_table_row_count(TableId::NestedClass) + 1;
            let nested_class = NestedClassRaw {
                rid: nested_class_rid,
                token: Token::new(0x29000000 + nested_class_rid),
                offset: 0,
                nested_class: nested_rid,
                enclosing_class: container_rid,
            };

            assembly.table_row_add(
                TableId::NestedClass,
                TableDataOwned::NestedClass(nested_class),
            )?;

            Ok(())
        },
    )
}

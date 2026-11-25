//! Factory methods for members method validation testing.
//!
//! Contains helper methods migrated from members method validation source files
//! for creating test assemblies with various method validation scenarios.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodDefRaw, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly,
        MSCORLIB_OBJECT_CTOR_RVA, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Test factory for OwnedMethodValidator following the golden pattern.
///
/// Creates test assemblies covering all method validation rules:
/// 1. Clean assembly (should pass)
/// 2. Method with empty name
/// 3. Abstract method not marked as virtual
/// 4. Static method marked as virtual
/// 5. Instance constructor without RTSPECIAL_NAME flag
/// 6. Abstract method with RVA present
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the method violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn owned_method_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all method validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 3. NEGATIVE: Test abstract method not marked as virtual
    assemblies.push(create_assembly_with_abstract_non_virtual_method()?);

    // 4. NEGATIVE: Test static method marked as virtual
    assemblies.push(create_assembly_with_static_virtual_method()?);

    // 5. NEGATIVE: Test instance constructor without RTSPECIAL_NAME flag
    assemblies.push(create_assembly_with_invalid_instance_constructor()?);

    // 6. NEGATIVE: Test abstract method with RVA present
    assemblies.push(create_assembly_with_abstract_method_with_rva()?);

    Ok(assemblies)
}

/// Creates an assembly with a method having an empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Method with token 0x060036ED has empty name"),
        |assembly| {
            // Create type to contain the method
            let type_name_index = assembly
                .string_add("TypeWithEmptyMethodName")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000001, // Public
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create method with empty name
            let empty_name_index = assembly
                .string_add("")
                .map_err(|e| Error::Other(format!("Failed to add empty method name: {e}")))?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // DEFAULT, no parameters, VOID return
            let signature_index = assembly
                .blob_add(&signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006,                        // Public
                name: empty_name_index.placeholder(), // Empty name - should trigger validation failure
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            assembly
                .table_row_add(
                    TableId::MethodDef,
                    TableDataOwned::MethodDef(invalid_method),
                )
                .map_err(|e| Error::Other(format!("Failed to add invalid method: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with an abstract method not marked as virtual - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn create_assembly_with_abstract_non_virtual_method() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Abstract method 'AbstractNonVirtualMethod' must also be virtual"),
        |assembly| {
            // Create abstract type to contain the method
            let type_name_index = assembly
                .string_add("AbstractTypeWithNonVirtualMethod")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000081, // Public | Abstract
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create method name
            let method_name_index = assembly
                .string_add("AbstractNonVirtualMethod")
                .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // DEFAULT, no parameters, VOID return
            let signature_index = assembly
                .blob_add(&signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0406, // Public | Abstract (missing Virtual) - should trigger validation failure
                name: method_name_index.placeholder(),
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            assembly
                .table_row_add(
                    TableId::MethodDef,
                    TableDataOwned::MethodDef(invalid_method),
                )
                .map_err(|e| Error::Other(format!("Failed to add invalid method: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with a static method marked as virtual - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn create_assembly_with_static_virtual_method() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Static method 'StaticVirtualMethod' cannot be virtual"),
        |assembly| {
            // Create type to contain the method
            let type_name_index = assembly
                .string_add("TypeWithStaticVirtualMethod")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000001, // Public
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create method name
            let method_name_index = assembly
                .string_add("StaticVirtualMethod")
                .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // DEFAULT, no parameters, VOID return
            let signature_index = assembly
                .blob_add(&signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0056, // Public | Static | Virtual - should trigger validation failure
                name: method_name_index.placeholder(),
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            assembly
                .table_row_add(
                    TableId::MethodDef,
                    TableDataOwned::MethodDef(invalid_method),
                )
                .map_err(|e| Error::Other(format!("Failed to add invalid method: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with an instance constructor without RTSPECIAL_NAME flag - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn create_assembly_with_invalid_instance_constructor() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Instance constructor '.ctor' must have RTSPECIAL_NAME flag"),
        |assembly| {
            // Create type to contain the constructor
            let type_name_index = assembly
                .string_add("TypeWithInvalidConstructor")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000001, // Public
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create constructor name (.ctor)
            let ctor_name_index = assembly
                .string_add(".ctor")
                .map_err(|e| Error::Other(format!("Failed to add constructor name: {e}")))?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // DEFAULT, no parameters, VOID return
            let signature_index = assembly
                .blob_add(&signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: MSCORLIB_OBJECT_CTOR_RVA, // Has implementation
                impl_flags: 0,
                flags: 0x0806, // Public | SpecialName, without RTSpecialName (0x1000)
                name: ctor_name_index.placeholder(),
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            assembly
                .table_row_add(
                    TableId::MethodDef,
                    TableDataOwned::MethodDef(invalid_method),
                )
                .map_err(|e| Error::Other(format!("Failed to add invalid method: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with an abstract method that has RVA present - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/method.rs`
pub fn create_assembly_with_abstract_method_with_rva() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Abstract method 'AbstractMethodWithRVA' should not have implementation (RVA)",
        ),
        |assembly| {
            // Create abstract type to contain the method
            let type_name_index = assembly
                .string_add("AbstractTypeWithRVAMethod")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

            let type_def = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000081, // Public | Abstract
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid,
            };

            // Create method name
            let method_name_index = assembly
                .string_add("AbstractMethodWithRVA")
                .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

            let signature_bytes = vec![0x00, 0x00, 0x01]; // DEFAULT, no parameters, VOID return
            let signature_index = assembly
                .blob_add(&signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: MSCORLIB_OBJECT_CTOR_RVA, // Has RVA - should trigger validation failure for abstract method
                impl_flags: 0,
                flags: 0x0446, // Public | Abstract | Virtual
                name: method_name_index.placeholder(),
                signature: signature_index.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            assembly
                .table_row_add(
                    TableId::MethodDef,
                    TableDataOwned::MethodDef(invalid_method),
                )
                .map_err(|e| Error::Other(format!("Failed to add invalid method: {e}")))?;

            Ok(())
        },
    )
}

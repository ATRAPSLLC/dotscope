//! Factory methods for signature validation testing.
//!
//! Contains helper methods migrated from signature validation source files
//! for creating test assemblies with various signature validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, MethodDefRaw, ParamRaw, TableDataOwned, TableId, TypeDefRaw,
        },
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Test factory for OwnedSignatureValidator following the golden pattern.
///
/// Creates test assemblies covering all signature validation rules:
/// 1. Clean assembly (should pass)
/// 2. Method with empty name
/// 3. Parameter with excessively long name (>255 characters)
/// 4. Method with unresolved return type
/// 5. Method with unresolved parameter type
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the signature violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn owned_signature_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all signature validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 3. NEGATIVE: Test parameter with excessively long name (>255 characters)
    assemblies.push(create_assembly_with_long_parameter_name()?);

    // 4. NEGATIVE: Test method with unresolved return type
    assemblies.push(create_assembly_with_unresolved_return_type()?);

    // 5. NEGATIVE: Test method with unresolved parameter type
    assemblies.push(create_assembly_with_unresolved_parameter_type()?);

    // Note: Other test cases (excessive custom attributes, generic parameter issues,
    // excessive overloads) require additional table manipulation and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with a method having an empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
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

/// A parameter with a 300-character name: ECMA-335 sets no limit, so it is valid.
pub fn create_assembly_with_long_parameter_name() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        // Create type to contain the method
        let type_name_index = assembly
            .string_add("TypeWithLongParameterName")
            .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

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
            .string_add("MethodWithLongParam")
            .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

        // Create signature with one parameter
        let signature_bytes = vec![0x00, 0x01, 0x01, 0x08]; // 1 parameter, void return, I4 parameter
        let signature_index = assembly
            .blob_add(&signature_bytes)
            .map_err(|e| Error::Other(format!("Failed to add signature: {e}")))?;

        let method_def = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public
            name: method_name_index.placeholder(),
            signature: signature_index.placeholder(),
            param_list: param_rid,
        };

        // Create parameter with excessively long name (>255 characters)
        let long_param_name = "a".repeat(300); // 300 characters - should trigger validation failure
        let long_param_name_index = assembly
            .string_add(&long_param_name)
            .map_err(|e| Error::Other(format!("Failed to add long parameter name: {e}")))?;

        let invalid_param = ParamRaw {
            rid: param_rid,
            token: Token::new(0x08000000 + param_rid),
            offset: 0,
            flags: 0x0000, // In
            sequence: 1,
            name: long_param_name_index.placeholder(), // Excessively long name - should trigger validation failure
        };

        assembly
            .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
            .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

        assembly
            .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_def))
            .map_err(|e| Error::Other(format!("Failed to add method: {e}")))?;

        assembly
            .table_row_add(TableId::Param, TableDataOwned::Param(invalid_param))
            .map_err(|e| Error::Other(format!("Failed to add invalid parameter: {e}")))?;

        Ok(())
    })
}

/// Creates an assembly with a method having unresolved return type - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_unresolved_return_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Method 'MethodWithUnresolvedReturnType' has unresolved return type 0x01000001",
        ),
        |assembly| {
            // Create type to contain the method
            let type_name_index = assembly
                .string_add("TypeWithUnresolvedReturnType")
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
                .string_add("MethodWithUnresolvedReturnType")
                .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

            // Create invalid signature blob with unresolved return type
            // Format: [calling_convention, param_count, return_type, ...params]
            let invalid_signature_bytes = vec![
                0x00, // DEFAULT calling convention
                0x00, // 0 parameters
                0x12, // ELEMENT_TYPE_CLASS (indicates a class type follows)
                0x05, // TypeRef row 1, which mscorlib does not have: (1 << 2) | TypeRef tag
            ];
            let signature_index = assembly
                .blob_add(&invalid_signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add invalid signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006, // Public
                name: method_name_index.placeholder(),
                signature: signature_index.placeholder(), // Invalid signature with unresolved return type
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

/// Creates an assembly with a method having unresolved parameter type - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_unresolved_parameter_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        // The loader types parameters while it reads the body and refuses one whose type
        // does not resolve; the return type it leaves to the validator.
        Expect::refused("Failed to find type in TypeSystem - 0x01000001"),
        |assembly| {
            // Create type to contain the method
            let type_name_index = assembly
                .string_add("TypeWithUnresolvedParamType")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

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
                .string_add("MethodWithUnresolvedParamType")
                .map_err(|e| Error::Other(format!("Failed to add method name: {e}")))?;

            // Create invalid signature blob with unresolved parameter type
            // Format: [calling_convention, param_count, return_type, param1_type, ...]
            let invalid_signature_bytes = vec![
                0x00, // DEFAULT calling convention
                0x01, // 1 parameter
                0x01, // Return type: ELEMENT_TYPE_VOID
                0x12, // Parameter type: ELEMENT_TYPE_CLASS (indicates a class type follows)
                0x05, // TypeRef row 1, which mscorlib does not have: (1 << 2) | TypeRef tag
            ];
            let signature_index = assembly
                .blob_add(&invalid_signature_bytes)
                .map_err(|e| Error::Other(format!("Failed to add invalid signature: {e}")))?;

            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006, // Public
                name: method_name_index.placeholder(),
                signature: signature_index.placeholder(), // Invalid signature with unresolved parameter type
                param_list: param_rid,
            };

            // Create parameter with name (the signature is what has the unresolved type)
            let param_name_index = assembly
                .string_add("unresolvedParam")
                .map_err(|e| Error::Other(format!("Failed to add parameter name: {e}")))?;

            let param = ParamRaw {
                rid: param_rid,
                token: Token::new(0x08000000 + param_rid),
                offset: 0,
                flags: 0x0001, // In
                sequence: 1,
                name: param_name_index.placeholder(),
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

            assembly
                .table_row_add(TableId::Param, TableDataOwned::Param(param))
                .map_err(|e| Error::Other(format!("Failed to add parameter: {e}")))?;

            Ok(())
        },
    )
}

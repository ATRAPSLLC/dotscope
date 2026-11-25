//! Factory methods for ownership validation testing.
//!
//! Contains helper methods migrated from ownership validation source files
//! for creating test assemblies with various ownership validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, MethodDefRaw, TableDataOwned, TableId, TypeAttributes,
            TypeDefRaw,
        },
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_TYPEDEF,
    },
    Result,
};

/// Main factory method for creating ownership validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn owned_ownership_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all ownership validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test broken method ownership reference
    assemblies.push(create_assembly_with_broken_method_ownership()?);

    // 3. NEGATIVE: Test invalid method accessibility
    assemblies.push(create_assembly_with_invalid_method_accessibility()?);

    // 4. NEGATIVE: Test invalid static constructor
    assemblies.push(create_assembly_with_invalid_static_constructor()?);

    Ok(assemblies)
}

/// Creates an assembly with broken method ownership reference
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_broken_method_ownership() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'TestType' owns method with empty name"),
        |assembly| {
            // Create method with empty name to trigger validation failure
            let empty_method_name_index = assembly.string_add("")?;

            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let signature = assembly.blob_add(&[0x00, 0x00, 0x01])?; // DEFAULT, no parameters, VOID return
            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006,                               // Public
                name: empty_method_name_index.placeholder(), // Empty name - should trigger validation failure
                signature: signature.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly.table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )?;

            // Create type that owns the method with empty name
            let type_name_index = assembly.string_add("TestType")?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let invalid_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: method_rid, // Reference to method with empty name - should trigger validation failure
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))?;

            Ok(())
        },
    )
}

/// Creates an assembly with invalid method accessibility
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_method_accessibility() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Method 'TestMethod' in type 'TestType' has invalid visibility value: 0x07"),
        |assembly| {
            // Create method with invalid visibility flags
            let method_name_index = assembly.string_add("TestMethod")?;

            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let signature = assembly.blob_add(&[0x00, 0x00, 0x01])?; // DEFAULT, no parameters, VOID return
            let invalid_method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0007, // Access 7: the 3-bit access field defines 0-6 only
                name: method_name_index.placeholder(),
                signature: signature.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly.table_row_add(
                TableId::MethodDef,
                TableDataOwned::MethodDef(invalid_method),
            )?;

            let type_name_index = assembly.string_add("TestType")?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let test_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
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

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))?;

            Ok(())
        },
    )
}

/// Creates an assembly with invalid static constructor flags
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_static_constructor() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Static constructor '.cctor' in type 'TestType' must be static"),
        |assembly| {
            // Create static constructor (.cctor) without static flag
            let cctor_name_index = assembly.string_add(".cctor")?;

            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let signature = assembly.blob_add(&[0x00, 0x00, 0x01])?; // DEFAULT, no parameters, VOID return
            let invalid_cctor = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x0006, // Public (0x0006) but missing static flag (0x0010) - should trigger validation failure
                name: cctor_name_index.placeholder(),
                signature: signature.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly.table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(invalid_cctor))?;

            let type_name_index = assembly.string_add("TestType")?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let test_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
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

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))?;

            Ok(())
        },
    )
}

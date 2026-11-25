//! Factory methods for type ownership validation testing.
//!
//! Contains helper methods migrated from type ownership validation source files
//! for creating test assemblies with various type ownership validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, FieldRaw, MethodDefRaw, TableDataOwned, TableId,
            TypeAttributes, TypeDefRaw,
        },
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Main factory method for type ownership validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn owned_type_ownership_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all ownership validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 3. NEGATIVE: Test field with empty name
    assemblies.push(create_assembly_with_empty_field_name()?);

    // 4. NEGATIVE: Test field with invalid visibility flags
    assemblies.push(create_assembly_with_invalid_field_visibility()?);

    Ok(assemblies)
}

/// Creates an assembly with method having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Method owned by type 'TestType' has empty name"),
        |assembly| {
            // Create type to contain the method
            let type_name_index = assembly
                .string_add("TestType")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let typedef = TypeDefRaw {
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
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            // Create method with empty name
            let empty_name_index = assembly
                .string_add("")
                .map_err(|e| Error::Other(format!("Failed to add empty method name: {e}")))?;

            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let signature = assembly.blob_add(&[0x00, 0x00, 0x01])?; // DEFAULT, no parameters, VOID return
            let method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0,
                flags: 0x00000006,                    // Public
                name: empty_name_index.placeholder(), // Empty name - should trigger validation failure
                signature: signature.placeholder(),
                param_list: assembly.next_rid(TableId::Param)?,
            };

            assembly
                .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method))
                .map_err(|e| Error::Other(format!("Failed to add method: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with field having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_empty_field_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Field owned by type 'TestType' has empty name"),
        |assembly| {
            // Create type to contain the field
            let type_name_index = assembly
                .string_add("TestType")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let typedef = TypeDefRaw {
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
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            // Create field with empty name
            let empty_name_index = assembly
                .string_add("")
                .map_err(|e| Error::Other(format!("Failed to add empty field name: {e}")))?;

            let field_rid = assembly.original_table_row_count(TableId::Field) + 1;
            let signature = assembly.blob_add(&[0x06, 0x08])?; // FIELD, ELEMENT_TYPE_I4
            let field = FieldRaw {
                rid: field_rid,
                token: Token::new(0x04000000 + field_rid),
                offset: 0,
                flags: 0x00000006,                    // Public
                name: empty_name_index.placeholder(), // Empty name - should trigger validation failure
                signature: signature.placeholder(),
            };

            assembly
                .table_row_add(TableId::Field, TableDataOwned::Field(field))
                .map_err(|e| Error::Other(format!("Failed to add field: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with field having invalid visibility flags - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_invalid_field_visibility() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Field 'InvalidField' owned by type 'TestType' has invalid visibility: 0x07"),
        |assembly| {
            // Create type to contain the field
            let type_name_index = assembly
                .string_add("TestType")
                .map_err(|e| Error::Other(format!("Failed to add type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let typedef = TypeDefRaw {
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
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
                .map_err(|e| Error::Other(format!("Failed to add type: {e}")))?;

            // Create field with invalid visibility flags
            let field_name_index = assembly
                .string_add("InvalidField")
                .map_err(|e| Error::Other(format!("Failed to add field name: {e}")))?;

            let field_rid = assembly.original_table_row_count(TableId::Field) + 1;
            let signature = assembly.blob_add(&[0x06, 0x08])?; // FIELD, ELEMENT_TYPE_I4
            let field = FieldRaw {
                rid: field_rid,
                token: Token::new(0x04000000 + field_rid),
                offset: 0,
                flags: 0x0007, // Access 7: the 3-bit access field defines 0-6 only
                name: field_name_index.placeholder(),
                signature: signature.placeholder(),
            };

            assembly
                .table_row_add(TableId::Field, TableDataOwned::Field(field))
                .map_err(|e| Error::Other(format!("Failed to add field: {e}")))?;

            Ok(())
        },
    )
}

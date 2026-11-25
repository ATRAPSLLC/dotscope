//! Factory methods for type definition validation testing.
//!
//! Contains helper methods migrated from type definition validation source files
//! for creating test assemblies with various type definition validation scenarios.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Main factory method for type definition validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn owned_type_definition_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all type definition validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test type with empty name
    assemblies.push(create_assembly_with_empty_type_name()?);

    // A NUL inside a type name or namespace cannot be written: `#Strings` entries end at
    // the first NUL.

    // 5. NEGATIVE: Test malformed special name pattern
    assemblies.push(create_assembly_with_malformed_special_name()?);

    // Note: Other test cases (invalid attribute combinations, inconsistent type flavors)
    // require more complex setup and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with a type having an empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_empty_type_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("has empty name"),
        |assembly| {
            // Create type with empty name
            let empty_name_index = assembly
                .string_add("")
                .map_err(|e| Error::Other(format!("Failed to add empty type name: {e}")))?;

            // Create a regular namespace (not "<Module>") to ensure validation triggers
            let namespace_index = assembly
                .string_add("TestNamespace")
                .map_err(|e| Error::Other(format!("Failed to add namespace: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

            let invalid_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000001,                             // Public
                type_name: empty_name_index.placeholder(), // Empty name - should trigger validation failure
                type_namespace: namespace_index.placeholder(), // Regular namespace (not "<Module>")
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
                .map_err(|e| Error::Other(format!("Failed to add invalid type: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly with a malformed special name pattern - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_malformed_special_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type '<InvalidSpecialName' has malformed special name pattern"),
        |assembly| {
            // Create type name with malformed special pattern (starts with < but doesn't end with >)
            let malformed_name = "<InvalidSpecialName";
            let malformed_name_index = assembly
                .string_add(malformed_name)
                .map_err(|e| Error::Other(format!("Failed to add malformed type name: {e}")))?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

            let invalid_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: 0x00000001,                             // Public
                type_name: malformed_name_index.placeholder(), // Malformed special name - should trigger validation failure
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
                .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
                .map_err(|e| Error::Other(format!("Failed to add invalid type: {e}")))?;

            Ok(())
        },
    )
}

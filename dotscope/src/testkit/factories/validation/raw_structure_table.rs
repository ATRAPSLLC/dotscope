//! Factory methods for raw structure table validation testing.
//!
//! Contains helper methods migrated from raw structure table validation source files
//! for creating test assemblies with various table validation scenarios.

use crate::{
    metadata::{
        tables::{AssemblyRaw, CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_TYPEDEF,
    },
    Error, Result,
};

/// Test factory for RawTableValidator following the golden pattern.
///
/// Creates test assemblies covering basic table validation scenarios.
/// Tests required table presence, cross-table dependencies, and table structure integrity.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn raw_table_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. Multiple Assembly rows - create assembly with >1 Assembly table rows
    assemblies.push(create_assembly_with_multiple_assembly_rows()?);

    // 3. Cross-table dependency violation - TypeDef field list exceeding Field table bounds
    assemblies.push(create_assembly_with_field_list_violation()?);

    // 4. Cross-table dependency violation - TypeDef method list exceeding MethodDef table bounds
    assemblies.push(create_assembly_with_method_list_violation()?);

    // 5. Required table presence - Module table with 0 rows
    assemblies.push(create_assembly_with_empty_module_table()?);

    Ok(assemblies)
}

/// Creates a modified assembly with empty Module table (0 rows).
///
/// This deletes the Module table row entirely, creating an empty Module table
/// which violates ECMA-335 requirement of exactly 1 Module row.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_empty_module_table() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Module table is required but not present"),
        |assembly| {
            // Delete the Module table row entirely - this will reduce row_count to 0
            match assembly.table_row_remove(TableId::Module, 1) {
                Ok(()) => {
                    // Module row deletion succeeded
                    Ok(())
                }
                Err(e) => {
                    // Row deletion failed - maybe Module table is protected
                    // Fall back to just returning an error to indicate this test doesn't work
                    Err(Error::Other(format!(
                        "Cannot remove Module table row: {e} - this test case is not supported"
                    )))
                }
            }
        },
    )
}

/// Creates a modified assembly with multiple Assembly table rows.
///
/// ECMA-335 requires at most 1 row in the Assembly table. This creates
/// a second Assembly row to violate this constraint.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_multiple_assembly_rows() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Assembly table contains 2 rows but can contain at most 1 row"),
        |assembly| {
            // Create a second Assembly row which violates ECMA-335 "at most 1 row" constraint
            // Use add_table_row to actually add a second row (increasing row_count to 2)
            let duplicate_assembly = AssemblyRaw {
                rid: 2,                        // Will be set by add_table_row
                token: Token::new(0x20000002), // Assembly table token for RID 2
                offset: 0,
                hash_alg_id: 0x8004, // CALG_SHA1
                major_version: 1,
                minor_version: 0,
                build_number: 0,
                revision_number: 0,
                flags: 0,
                public_key: 0, // Assuming blob index 0
                name: 1,       // Assuming string index 1 exists
                culture: 0,    // Null culture
            };

            // Add the duplicate Assembly row - this will increase Assembly table row_count to 2
            assembly.table_row_add(
                TableId::Assembly,
                TableDataOwned::Assembly(duplicate_assembly),
            )?;

            Ok(())
        },
    )
}

/// Creates a modified assembly with TypeDef field list exceeding Field table bounds.
///
/// This creates a TypeDef that references field list starting at a RID beyond
/// what exists in the Field table, violating cross-table dependency constraints.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_field_list_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "references field list starting at RID 2958 but Field table only has 2956 rows",
        ),
        |assembly| {
            // Create a TypeDef with field_list pointing beyond Field table bounds
            let invalid_typedef = TypeDefRaw {
                rid: 1,
                token: Token::new(0x02000001),
                offset: 0,
                flags: 0x00100000, // Class, not interface
                type_name: 1,      // Assuming string index 1 exists
                type_namespace: 0, // No namespace
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: 2958, // mscorlib has 2956 fields: 2957 starts an empty list, 2958 none
                method_list: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                1,
                TableDataOwned::TypeDef(invalid_typedef),
            )?;

            Ok(())
        },
    )
}

/// Creates a modified assembly with TypeDef method list exceeding MethodDef table bounds.
///
/// This creates a TypeDef that references method list starting at a RID beyond
/// what exists in the MethodDef table, violating cross-table dependency constraints.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_method_list_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "references method list starting at RID 14062 but MethodDef table only has 14060 rows",
        ),
        |assembly| {
            // Create a TypeDef with method_list pointing beyond MethodDef table bounds
            let invalid_typedef = TypeDefRaw {
                rid: 1,
                token: Token::new(0x02000001),
                offset: 0,
                flags: 0x00100000, // Class, not interface
                type_name: 1,      // Assuming string index 1 exists
                type_namespace: 0, // No namespace
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: 0,
                method_list: 14062, // mscorlib has 14060 methods: 14061 starts an empty list, 14062 none
            };

            assembly.table_row_update(
                TableId::TypeDef,
                1,
                TableDataOwned::TypeDef(invalid_typedef),
            )?;

            Ok(())
        },
    )
}

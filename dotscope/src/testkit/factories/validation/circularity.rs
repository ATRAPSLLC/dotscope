//! Factory methods for circularity validation testing.
//!
//! Contains helper methods migrated from circularity validation source files
//! for creating test assemblies with various circularity validation scenarios.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly},
    Result,
};

/// Main factory method for creating circularity validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn owned_circularity_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all circularity validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test circular inheritance chain (A->B->A)
    assemblies.push(create_assembly_with_circular_inheritance()?);

    // 3. NEGATIVE: Test self-referential type definition
    assemblies.push(create_assembly_with_self_referential_type()?);

    // 4. NEGATIVE: Test circular interface implementation
    assemblies.push(create_assembly_with_circular_interface_implementation()?);

    Ok(assemblies)
}

/// Creates an assembly with circular inheritance (A->B->A)
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_circular_inheritance() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'TypeA'"),
        |assembly| {
            // Create type A name
            let type_a_name_index = assembly.string_add("TypeA")?;

            // Create type B name
            let type_b_name_index = assembly.string_add("TypeB")?;

            let type_a_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let type_b_rid = type_a_rid + 1;

            // Create TypeA that extends TypeB
            let type_a = TypeDefRaw {
                rid: type_a_rid,
                token: Token::new(0x02000000 + type_a_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
                type_name: type_a_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    type_b_rid,
                    CodedIndexType::TypeDefOrRef,
                ), // A extends B
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            // Create TypeB that extends TypeA - creates circular inheritance
            let type_b = TypeDefRaw {
                rid: type_b_rid,
                token: Token::new(0x02000000 + type_b_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
                type_name: type_b_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    type_a_rid,
                    CodedIndexType::TypeDefOrRef,
                ), // B extends A - circular!
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_a))?;
            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_b))?;

            Ok(())
        },
    )
}

/// Creates an assembly with self-referential type definition
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_self_referential_type() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("extends itself"),
        |assembly| {
            // Create self-referential type name
            let type_name_index = assembly.string_add("SelfReferentialType")?;

            let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

            // Create type that extends itself - direct circular inheritance
            let self_ref_type = TypeDefRaw {
                rid: type_rid,
                token: Token::new(0x02000000 + type_rid),
                offset: 0,
                flags: TypeAttributes::PUBLIC.bits(),
                type_name: type_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(TableId::TypeDef, type_rid, CodedIndexType::TypeDefOrRef), // Extends itself!
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(self_ref_type))?;

            Ok(())
        },
    )
}

/// Creates an assembly with circular interface implementation
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_circular_interface_implementation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'IInterface1'"),
        |assembly| {
            // Create interface I1 name
            let interface_i1_name_index = assembly.string_add("IInterface1")?;

            // Create interface I2 name
            let interface_i2_name_index = assembly.string_add("IInterface2")?;

            let interface_i1_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
            let interface_i2_rid = interface_i1_rid + 1;

            // Create IInterface1 that extends IInterface2
            let interface_i1 = TypeDefRaw {
                rid: interface_i1_rid,
                token: Token::new(0x02000000 + interface_i1_rid),
                offset: 0,
                flags: (TypeAttributes::INTERFACE
                    | TypeAttributes::ABSTRACT
                    | TypeAttributes::PUBLIC)
                    .bits(),
                type_name: interface_i1_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    interface_i2_rid,
                    CodedIndexType::TypeDefOrRef,
                ), // I1 extends I2
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            // Create IInterface2 that extends IInterface1 - creates circular interface implementation
            let interface_i2 = TypeDefRaw {
                rid: interface_i2_rid,
                token: Token::new(0x02000000 + interface_i2_rid),
                offset: 0,
                flags: (TypeAttributes::INTERFACE
                    | TypeAttributes::ABSTRACT
                    | TypeAttributes::PUBLIC)
                    .bits(),
                type_name: interface_i2_name_index.placeholder(),
                type_namespace: 0,
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    interface_i1_rid,
                    CodedIndexType::TypeDefOrRef,
                ), // I2 extends I1 - circular!
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_i1))?;
            assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_i2))?;

            Ok(())
        },
    )
}

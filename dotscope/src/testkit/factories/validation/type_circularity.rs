//! Factory methods for type circularity validation testing.
//!
//! Contains helper methods migrated from type circularity validation source files
//! for creating test assemblies with various type circularity validation scenarios.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, InterfaceImplRaw, NestedClassBuilder, TableDataOwned,
            TableId, TypeAttributes, TypeDefBuilder, TypeDefRaw,
        },
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly},
    Result,
};

/// File factory function for OwnedTypeCircularityValidator testing.
///
/// Creates test assemblies with different types of circular dependencies.
/// Each assembly tests a specific circularity detection scenario.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn owned_type_circularity_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();
    assemblies.push(TestAssembly::new(&clean_testfile));

    match create_assembly_with_inheritance_circularity() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => eprintln!("Warning: Could not create inheritance test assembly: {e}"),
    }

    match create_assembly_with_nested_type_circularity() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => eprintln!("Warning: Could not create nested type test assembly: {e}"),
    }

    match create_assembly_with_interface_circularity() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => eprintln!("Warning: Could not create interface test assembly: {e}"),
    }

    match create_assembly_with_depth_limit_violation() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => eprintln!("Warning: Could not create depth limit violation test: {e}"),
    }

    Ok(assemblies)
}

/// Creates an assembly with inheritance circularity.
///
/// Creates types that inherit from each other in a circular pattern:
/// ClassA -> ClassB -> ClassA
///
/// The approach is to create the circular inheritance directly in the TypeDef table
/// in a way that will be detected by the validator when the assembly is reloaded.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_inheritance_circularity() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'CircularClassA' (token 0x0200060C) inherits from itself"),
        |assembly| {
            let class_a_name_index = assembly.string_add("CircularClassA")?;
            let class_b_name_index = assembly.string_add("CircularClassB")?;
            let test_namespace_index = assembly.string_add("Test")?;
            let current_typedef_count = assembly.original_table_row_count(TableId::TypeDef);

            let class_a_row = current_typedef_count + 1;
            let class_b_row = current_typedef_count + 2;
            let class_a_token = Token::new(0x02000000 | class_a_row);
            let class_b_token = Token::new(0x02000000 | class_b_row);

            let class_a_raw = TypeDefRaw {
                rid: class_a_token.row(),
                token: class_a_token,
                offset: 0,
                flags: (TypeAttributes::PUBLIC | TypeAttributes::CLASS).bits(),
                type_name: class_a_name_index.placeholder(),
                type_namespace: test_namespace_index.placeholder(),
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    class_b_token.row(),
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            let class_b_raw = TypeDefRaw {
                rid: class_b_token.row(),
                token: class_b_token,
                offset: 0,
                flags: (TypeAttributes::PUBLIC | TypeAttributes::CLASS).bits(),
                type_name: class_b_name_index.placeholder(),
                type_namespace: test_namespace_index.placeholder(),
                extends: CodedIndex::new(
                    TableId::TypeDef,
                    class_a_token.row(),
                    CodedIndexType::TypeDefOrRef,
                ),
                field_list: assembly.next_rid(TableId::Field)?,
                method_list: assembly.next_rid(TableId::MethodDef)?,
            };

            let _actual_class_a_row =
                assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(class_a_raw))?;
            let _actual_class_b_row =
                assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(class_b_raw))?;

            Ok(())
        },
    )
}

/// Creates an assembly with nested type circularity.
///
/// Creates types that contain each other as nested types through the NestedClass table.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_nested_type_circularity() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("contains itself as nested type"),
        |assembly| {
            let outer_token = TypeDefBuilder::new()
                .name("CircularOuter")
                .namespace("Test")
                .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS)
                .build(assembly)?;

            let inner_token = TypeDefBuilder::new()
                .name("CircularInner")
                .namespace("Test")
                .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
                .build(assembly)?;

            NestedClassBuilder::new()
                .nested_class(inner_token.placeholder())
                .enclosing_class(outer_token.placeholder())
                .build(assembly)?;

            NestedClassBuilder::new()
                .nested_class(outer_token.placeholder())
                .enclosing_class(inner_token.placeholder())
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with interface implementation circularity.
///
/// Creates interfaces that implement each other through InterfaceImpl entries.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_interface_circularity() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Circular interface implementation detected: Interface implements itself"),
        |assembly| {
            let interface_a_token = TypeDefBuilder::new()
                .name("ICircularA")
                .namespace("Test")
                .flags(
                    TypeAttributes::PUBLIC | TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT,
                )
                .build(assembly)?;

            let interface_b_token = TypeDefBuilder::new()
                .name("ICircularB")
                .namespace("Test")
                .flags(
                    TypeAttributes::PUBLIC | TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT,
                )
                .build(assembly)?;

            // Create InterfaceImpl entries manually using raw table API
            let impl_a_rid = assembly.original_table_row_count(TableId::InterfaceImpl) + 1;
            let impl_a = InterfaceImplRaw {
                rid: impl_a_rid,
                token: Token::new(0x09000000 + impl_a_rid),
                offset: 0,
                class: interface_a_token.placeholder(),
                interface: CodedIndex::new(
                    TableId::TypeDef,
                    interface_b_token.placeholder(),
                    CodedIndexType::TypeDefOrRef,
                ),
            };
            assembly.table_row_add(
                TableId::InterfaceImpl,
                TableDataOwned::InterfaceImpl(impl_a),
            )?;

            let impl_b_rid = assembly.original_table_row_count(TableId::InterfaceImpl) + 1;
            let impl_b = InterfaceImplRaw {
                rid: impl_b_rid,
                token: Token::new(0x09000000 + impl_b_rid),
                offset: 0,
                class: interface_b_token.placeholder(),
                interface: CodedIndex::new(
                    TableId::TypeDef,
                    interface_a_token.placeholder(),
                    CodedIndexType::TypeDefOrRef,
                ),
            };
            assembly.table_row_add(
                TableId::InterfaceImpl,
                TableDataOwned::InterfaceImpl(impl_b),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with inheritance chain that exceeds max depth.
///
/// Creates a long inheritance chain that should trigger depth limit validation.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_depth_limit_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Inheritance chain depth exceeds maximum nesting depth limit of 100 for type 'DeepClass0'"),
        // 120 deep: past the limit of 100
        |assembly| build_deep_inheritance_chain(assembly, 120),
    )
}

/// Adds classes `Test.DeepClass0` to `Test.DeepClass{length - 1}`, each extending the one
/// before it.
pub fn build_deep_inheritance_chain(assembly: &mut CilAssembly, length: usize) -> Result<()> {
    let mut previous_token: Option<ChangeRefRc> = None;
    for i in 0..length {
        let mut builder = TypeDefBuilder::new()
            .name(format!("DeepClass{i}"))
            .namespace("Test")
            .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS);

        if let Some(parent_token) = previous_token {
            builder = builder.extends(CodedIndex::new(
                TableId::TypeDef,
                parent_token.placeholder(),
                CodedIndexType::TypeDefOrRef,
            ));
        }

        previous_token = Some(builder.build(assembly)?);
    }
    Ok(())
}

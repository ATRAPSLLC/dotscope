//! Factory methods for inheritance validation testing.
//!
//! Contains helper methods migrated from inheritance validation source files
//! for creating test assemblies with various inheritance validation scenarios.

use crate::{
    metadata::{
        signatures::TypeSignature,
        tables::{
            CodedIndex, CodedIndexType, InterfaceImplBuilder, MethodDefBuilder, TableId,
            TypeAttributes, TypeDefBuilder, TypeSpecBuilder,
        },
    },
    testkit::{
        create_test_assembly,
        factories::validation::type_circularity::build_deep_inheritance_chain,
        get_testfile_mscorlib, Expect, TestAssembly, MSCORLIB_OBJECT_CTOR_RVA,
        MSCORLIB_OBJECT_TYPEDEF,
    },
    CilAssembly, Result,
};

/// Test factory for OwnedInheritanceValidator following the golden pattern.
///
/// Creates test assemblies with specific inheritance violations that should be detected
/// by the owned validator. Each assembly targets exactly one validation rule to ensure
/// test isolation and comprehensive coverage.
///
/// # Test Coverage
///
/// The numbered comments in the body name each case: a clean assembly, the runtime's refusals
/// (sealed and interface bases, interfaces with a base, implementing a class, concrete
/// interfaces, abstract methods on concrete types, overriding a final method, too deep a
/// chain) and shapes it accepts that a stricter reading would not.
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the inheritance violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn owned_inheritance_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Sealed type inheritance violation
    assemblies.push(create_assembly_with_sealed_type_inheritance()?);

    // 3. NEGATIVE: Interface inheritance violation
    assemblies.push(create_assembly_with_interface_inheritance_violation()?);

    // 4. ACCEPTED: A public type extending an internal one (a C# rule, not the runtime's)
    assemblies.push(create_assembly_with_accessibility_violation()?);

    // 5. NEGATIVE: Abstract/concrete violation
    assemblies.push(create_assembly_with_abstract_concrete_violation()?);

    // 6. NEGATIVE: Method inheritance violation: a concrete type with an abstract method
    assemblies.push(create_assembly_with_method_inheritance_violation()?);

    // 7. NEGATIVE: An inheritance chain past the depth limit
    assemblies.push(create_assembly_with_deep_inheritance_chain()?);

    // 8. NEGATIVE: A method overriding a final one
    assemblies.push(create_assembly_overriding_a_final_method()?);

    // 9. ACCEPTED: A newslot method beside a final one of the same signature
    assemblies.push(create_assembly_with_newslot_beside_a_final_method()?);

    // 10. ACCEPTED: A multi-dimensional array of a sealed type
    assemblies.push(create_assembly_with_an_array_of_a_sealed_type()?);

    // 11. NEGATIVE: An interface extending System.Object
    assemblies.push(create_assembly_with_an_interface_extending_object()?);

    // 12. NEGATIVE: An interface extending another interface
    assemblies.push(create_assembly_with_an_interface_extending_an_interface()?);

    // 13. ACCEPTED: A public type implementing an internal interface
    assemblies.push(create_assembly_with_a_public_type_implementing_an_internal_interface()?);

    // 14. NEGATIVE: A type implementing a class
    assemblies.push(create_assembly_implementing_a_class()?);

    Ok(assemblies)
}

/// Creates an assembly with sealed type inheritance violation.
///
/// This creates a raw assembly containing a type that inherits from a sealed type
/// (not System types), which violates ECMA-335 inheritance constraints.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_sealed_type_inheritance() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'DerivedFromSealed' cannot inherit from sealed type 'SealedBaseType'"),
        |assembly| {
            let sealed_base_token = TypeDefBuilder::new()
                .name("SealedBaseType")
                .namespace("Test.Sealed")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC | TypeAttributes::SEALED)
                .build(assembly)?;

            TypeDefBuilder::new()
                .name("DerivedFromSealed")
                .namespace("Test.Sealed")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    sealed_base_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with interface inheritance violation.
///
/// This creates a raw assembly containing a class that inherits from an interface
/// (rather than implementing it), which violates ECMA-335 inheritance rules.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_interface_inheritance_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Type 'ClassInheritingFromInterface' cannot inherit from interface 'ITestInterface'",
        ),
        |assembly| {
            let interface_token = TypeDefBuilder::new()
                .name("ITestInterface")
                .namespace("Test.Interface")
                .flags(
                    TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
                )
                .build(assembly)?;

            TypeDefBuilder::new()
                .name("ClassInheritingFromInterface")
                .namespace("Test.Interface")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    interface_token
                        .token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with a public type extending an internal type of the same assembly.
///
/// C# refuses this (CS0060), the runtime does not: the base only has to be accessible from
/// the derived type, and an internal type is accessible throughout its assembly.
pub fn create_assembly_with_accessibility_violation() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        let internal_base_token = TypeDefBuilder::new()
            .name("InternalBaseType")
            .namespace("Test.Accessibility")
            .flags(TypeAttributes::CLASS | TypeAttributes::NOT_PUBLIC) // Internal visibility
            .build(assembly)?;

        TypeDefBuilder::new()
            .name("PublicDerivedType")
            .namespace("Test.Accessibility")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC) // Public visibility
            .extends(CodedIndex::new(
                TableId::TypeDef,
                internal_base_token
                    .token()
                    .expect("TypeDef token should be resolved")
                    .row(),
                CodedIndexType::TypeDefOrRef,
            ))
            .build(assembly)?;

        Ok(())
    })
}

/// Creates an assembly with abstract/concrete rule violation.
///
/// This creates a raw assembly containing an interface that is not marked as abstract,
/// which violates ECMA-335 type definition rules.
///
/// Originally from: `src/metadata/validation/validators/owned/types/inheritance.rs`
pub fn create_assembly_with_abstract_concrete_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Interface 'IConcreteInterface' must be abstract"),
        |assembly| {
            TypeDefBuilder::new()
                .name("IConcreteInterface")
                .namespace("Test.Abstract")
                .flags(TypeAttributes::INTERFACE | TypeAttributes::PUBLIC) // Missing ABSTRACT flag
                .build(assembly)?;

            Ok(())
        },
    )
}

/// Creates an assembly with a concrete class owning an abstract method, which the runtime
/// refuses to load (ECMA-335 II.10.3.1).
pub fn create_assembly_with_method_inheritance_violation() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Concrete type 'ConcreteWithAbstract' cannot have abstract method 'Run'"),
        |assembly| {
            TypeDefBuilder::new()
                .name("ConcreteWithAbstract")
                .namespace("Test.Inheritance")
                .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;
            MethodDefBuilder::new()
                .name("Run")
                .flags(0x04C6) // Public, Virtual, HideBySig, Abstract
                .impl_flags(0x0000) // IL
                .signature(&[0x20, 0x00, 0x01]) // HASTHIS, no parameters, VOID
                .build(assembly)?;
            Ok(())
        },
    )
}

/// Creates an assembly with an inheritance chain 80 classes deep, past the limit of 64 the
/// validator's test configuration sets. Which class is named depends on the walk's order, so
/// the expectation stops at the limit.
pub fn create_assembly_with_deep_inheritance_chain() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Inheritance chain depth exceeds maximum nesting depth limit of 64"),
        |assembly| build_deep_inheritance_chain(assembly, 80),
    )
}

/// Builds `DisposableBase` with `public virtual final newslot Dispose()`, the shape C# gives a
/// method that implements an interface implicitly, and `DisposableDerived` extending it with a
/// `Dispose()` of the same signature and `derived_flags`.
fn build_final_dispose_pair(assembly: &mut CilAssembly, derived_flags: u32) -> Result<()> {
    // HASTHIS, no parameters, VOID
    let signature = [0x20, 0x00, 0x01];
    let base = TypeDefBuilder::new()
        .name("DisposableBase")
        .namespace("Test.Overrides")
        .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
        .extends(CodedIndex::new(
            TableId::TypeDef,
            MSCORLIB_OBJECT_TYPEDEF,
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;
    MethodDefBuilder::new()
        .name("Dispose")
        .flags(0x01E6) // Public, Final, Virtual, HideBySig, NewSlot
        .impl_flags(0x0000)
        .signature(&signature)
        .rva(MSCORLIB_OBJECT_CTOR_RVA)
        .build(assembly)?;
    TypeDefBuilder::new()
        .name("DisposableDerived")
        .namespace("Test.Overrides")
        .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
        .extends(CodedIndex::new(
            TableId::TypeDef,
            base.token()
                .expect("TypeDef token should be resolved")
                .row(),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;
    MethodDefBuilder::new()
        .name("Dispose")
        .flags(derived_flags)
        .impl_flags(0x0000)
        .signature(&signature)
        .rva(MSCORLIB_OBJECT_CTOR_RVA)
        .build(assembly)?;
    Ok(())
}

/// Creates an assembly whose `DisposableDerived::Dispose` overrides the final
/// `DisposableBase::Dispose` (ECMA-335 II.10.3.2), which the runtime refuses.
pub fn create_assembly_overriding_a_final_method() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Cannot override final method 'Dispose'"),
        |assembly| build_final_dispose_pair(assembly, 0x00C6), // Public, Virtual, HideBySig
    )
}

/// Creates an assembly whose `DisposableDerived::Dispose` is `newslot` beside the final
/// `DisposableBase::Dispose`: it takes a new vtable slot and overrides nothing (ECMA-335
/// II.10.3.1). A class implementing an interface again beside a base that did looks like this.
pub fn create_assembly_with_newslot_beside_a_final_method() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        build_final_dispose_pair(assembly, 0x01E6) // Public, Final, Virtual, HideBySig, NewSlot
    })
}

/// Creates an assembly with a sealed class and a `SealedElement[,]` TypeSpec. An array is not
/// a subtype of its element type: only a TypeDef extends anything, so the sealed rule does not
/// apply (Microsoft.VisualBasic.Core's `VType[,]` once read as extending the sealed `VType`).
pub fn create_assembly_with_an_array_of_a_sealed_type() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        let element = TypeDefBuilder::new()
            .name("SealedElement")
            .namespace("Test.Arrays")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC | TypeAttributes::SEALED)
            .extends(CodedIndex::new(
                TableId::TypeDef,
                MSCORLIB_OBJECT_TYPEDEF,
                CodedIndexType::TypeDefOrRef,
            ))
            .build(assembly)?;
        let element = element.token().expect("TypeDef token should be resolved");
        TypeSpecBuilder::new()
            .multi_dimensional_array(TypeSignature::Class(element), 2)
            .build(assembly)?;
        Ok(())
    })
}

/// Creates an assembly with an interface whose `Extends` is `System.Object`. An interface's
/// `Extends` must be null (ECMA-335 II.22.37), and CoreCLR refuses any other value, `System.Object`
/// included.
pub fn create_assembly_with_an_interface_extending_object() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Interface 'IExtendsObject' cannot have a base type"),
        |assembly| {
            TypeDefBuilder::new()
                .name("IExtendsObject")
                .namespace("Test.Interfaces")
                .flags(
                    TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
                )
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    MSCORLIB_OBJECT_TYPEDEF,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;
            Ok(())
        },
    )
}

/// Creates an assembly with an interface whose `Extends` names another interface. Interfaces
/// inherit through InterfaceImpl rows, never `Extends`.
pub fn create_assembly_with_an_interface_extending_an_interface() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Interface 'IDerived' cannot have a base type"),
        |assembly| {
            let base = TypeDefBuilder::new()
                .name("IBase")
                .namespace("Test.Interfaces")
                .flags(
                    TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
                )
                .build(assembly)?;
            TypeDefBuilder::new()
                .name("IDerived")
                .namespace("Test.Interfaces")
                .flags(
                    TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
                )
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    base.token()
                        .expect("TypeDef token should be resolved")
                        .row(),
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;
            Ok(())
        },
    )
}

/// Builds `Implementer` in `Test.Interfaces`, implementing a new type `Implemented` with the
/// given flags.
fn build_interface_implementation(
    assembly: &mut CilAssembly,
    implementer_flags: TypeAttributes,
    implemented_flags: TypeAttributes,
) -> Result<()> {
    let implemented = TypeDefBuilder::new()
        .name("Implemented")
        .namespace("Test.Interfaces")
        .flags(implemented_flags)
        .build(assembly)?;
    let implementer = TypeDefBuilder::new()
        .name("Implementer")
        .namespace("Test.Interfaces")
        .flags(implementer_flags)
        .extends(CodedIndex::new(
            TableId::TypeDef,
            MSCORLIB_OBJECT_TYPEDEF,
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;
    InterfaceImplBuilder::new()
        .class(
            implementer
                .token()
                .expect("TypeDef token should be resolved")
                .row(),
        )
        .interface(CodedIndex::new(
            TableId::TypeDef,
            implemented
                .token()
                .expect("TypeDef token should be resolved")
                .row(),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;
    Ok(())
}

/// Creates an assembly with a public class implementing an internal interface of the same
/// assembly, which both C# and the runtime allow.
pub fn create_assembly_with_a_public_type_implementing_an_internal_interface(
) -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        build_interface_implementation(
            assembly,
            TypeAttributes::CLASS | TypeAttributes::PUBLIC,
            TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::NOT_PUBLIC,
        )
    })
}

/// Creates an assembly with a class whose InterfaceImpl row names another class, which the
/// runtime refuses to load.
pub fn create_assembly_implementing_a_class() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Type 'Implementer' tries to implement non-interface type 'Implemented'"),
        |assembly| {
            build_interface_implementation(
                assembly,
                TypeAttributes::CLASS | TypeAttributes::PUBLIC,
                TypeAttributes::CLASS | TypeAttributes::PUBLIC,
            )
        },
    )
}

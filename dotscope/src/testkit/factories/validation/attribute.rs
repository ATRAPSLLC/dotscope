//! Factory methods for attribute validation testing.
//!
//! A custom attribute loads only against a real constructor: the loader reads its value blob
//! by the constructor's signature. Each crafted case therefore defines `TestAttribute :
//! System.Attribute` in mscorlib with a constructor whose parameters fit the case, and applies
//! it once to `<Module>`, so the attribute loads and only its arguments break a rule.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        customattributes::{
            encode_custom_attribute_value, CustomAttributeArgument, CustomAttributeNamedArgument,
            CustomAttributeValue, FieldOrPropType,
        },
        tables::{
            CodedIndex, CodedIndexType, CustomAttributeBuilder, MethodDefBuilder, TableId,
            TypeAttributes, TypeDefBuilder,
        },
        typesystem::CilTypeReference,
    },
    testkit::{
        create_test_assembly, get_testfile_mscorlib, mono_mscorlib, Expect, TestAssembly,
        MSCORLIB_OBJECT_CTOR_RVA,
    },
    Error, Result,
};

/// Test factory for OwnedAttributeValidator following the golden pattern.
///
/// The clean mscorlib, then one case per attribute rule: more than 20 fixed arguments, more
/// than 50 named arguments, a duplicate named argument, an empty named argument name, a NUL
/// in a string argument, and a string argument over 10000 characters.
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn owned_attribute_validator_file_factory() -> Result<Vec<TestAssembly>> {
    Ok(vec![
        TestAssembly::new(get_testfile_mscorlib()),
        create_assembly_with_many_fixed_args()?,
        create_assembly_with_many_named_args()?,
        create_assembly_with_repeated_named_arg()?,
        create_assembly_with_empty_named_arg_name()?,
        create_assembly_with_nul_in_string_argument()?,
        create_assembly_with_long_string_argument()?,
    ])
}

/// The TypeDef row of `fullname` in [`get_testfile_mscorlib`].
pub fn mscorlib_type(fullname: &str) -> Result<u32> {
    mono_mscorlib()
        .types()
        .iter()
        .find(|entry| {
            let ty = entry.value();
            ty.token.is_table(TableId::TypeDef) && &*ty.fullname() == fullname
        })
        .map(|entry| entry.value().token.row())
        .ok_or_else(|| Error::Other(format!("mscorlib defines no {fullname}")))
}

/// Applies the attribute whose constructor is MethodDef row `constructor` to `target`, with
/// the value blob of `fixed_args` and `named_args`.
pub fn apply_attribute(
    assembly: &mut CilAssembly,
    target: CodedIndex,
    constructor: u32,
    fixed_args: Vec<CustomAttributeArgument>,
    named_args: Vec<CustomAttributeNamedArgument>,
) -> Result<()> {
    let value = encode_custom_attribute_value(&CustomAttributeValue {
        fixed_args,
        named_args,
        constructor: CilTypeReference::None,
        blob_index: 0,
    })?;
    CustomAttributeBuilder::new()
        .parent(target)
        .constructor(CodedIndex::new(
            TableId::MethodDef,
            constructor,
            CodedIndexType::CustomAttributeType,
        ))
        .value(&value)
        .build(assembly)?;
    Ok(())
}

/// Defines `TestAttribute : System.Attribute` with a constructor taking `parameters`
/// (ECMA-335 element types) and applies it to `<Module>` with `fixed_args` and `named_args`.
pub fn apply_test_attribute(
    assembly: &mut CilAssembly,
    parameters: &[u8],
    fixed_args: Vec<CustomAttributeArgument>,
    named_args: Vec<CustomAttributeNamedArgument>,
) -> Result<()> {
    TypeDefBuilder::new()
        .name("TestAttribute")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::BEFORE_FIELD_INIT)
        .extends(CodedIndex::new(
            TableId::TypeDef,
            mscorlib_type("System.Attribute")?,
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;

    // HASTHIS, the parameter count, VOID, the parameters
    let count = u8::try_from(parameters.len())
        .ok()
        .filter(|count| *count < 0x80)
        .ok_or_else(|| Error::Other("a one-byte parameter count".to_string()))?;
    let mut signature = vec![0x20, count, 0x01];
    signature.extend_from_slice(parameters);
    let constructor = MethodDefBuilder::new()
        .name(".ctor")
        .flags(0x1886) // Public, HideBySig, SpecialName, RTSpecialName
        .impl_flags(0x0000) // IL
        .signature(&signature)
        .rva(MSCORLIB_OBJECT_CTOR_RVA)
        .build(assembly)?;
    let constructor = constructor
        .token()
        .ok_or_else(|| Error::Other("the constructor's row".to_string()))?
        .row();

    apply_attribute(
        assembly,
        CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor,
        fixed_args,
        named_args,
    )
}

/// A string named property argument.
fn property(name: &str, value: &str) -> CustomAttributeNamedArgument {
    CustomAttributeNamedArgument {
        is_field: false,
        name: name.to_string(),
        arg_type: FieldOrPropType::String,
        value: CustomAttributeArgument::String(Some(value.to_string())),
    }
}

/// An attribute with 25 fixed arguments: ECMA-335 sets no limit, so it is valid.
pub fn create_assembly_with_many_fixed_args() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        apply_test_attribute(
            assembly,
            &[0x08; 25], // 25 I4 parameters
            (0..25).map(CustomAttributeArgument::I4).collect(),
            Vec::new(),
        )
    })
}

/// An attribute with 55 named arguments: ECMA-335 sets no limit, so it is valid.
pub fn create_assembly_with_many_named_args() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        apply_test_attribute(
            assembly,
            &[],
            Vec::new(),
            (0..55)
                .map(|i| property(&format!("Property{i}"), &format!("Value{i}")))
                .collect(),
        )
    })
}

/// An attribute naming one property twice: ECMA-335 does not forbid it, and the runtime
/// applies both in order.
pub fn create_assembly_with_repeated_named_arg() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        apply_test_attribute(
            assembly,
            &[],
            Vec::new(),
            vec![
                property("DuplicateName", "Value1"),
                property("DuplicateName", "Value2"),
            ],
        )
    })
}

/// An attribute with a named argument whose name is empty.
pub fn create_assembly_with_empty_named_arg_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Custom attribute has named argument with empty name"),
        |assembly| apply_test_attribute(assembly, &[], Vec::new(), vec![property("", "Value")]),
    )
}

/// An attribute whose string argument holds a NUL: a .NET string may hold any UTF-16 unit.
pub fn create_assembly_with_nul_in_string_argument() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        apply_test_attribute(
            assembly,
            &[0x0E], // a String parameter
            vec![CustomAttributeArgument::String(Some(
                "Bad\0String".to_string(),
            ))],
            Vec::new(),
        )
    })
}

/// An attribute whose string argument is 10001 characters long: ECMA-335 sets no limit.
pub fn create_assembly_with_long_string_argument() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        apply_test_attribute(
            assembly,
            &[0x0E], // a String parameter
            vec![CustomAttributeArgument::String(Some("A".repeat(10001)))],
            Vec::new(),
        )
    })
}

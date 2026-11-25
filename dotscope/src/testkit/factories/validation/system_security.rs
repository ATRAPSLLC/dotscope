//! Factory methods for system security validation testing.
//!
//! Security attributes are applied through their real mscorlib constructors, so they load
//! and the validator identifies them by type; a declarative security entry carries a
//! permission set the loader reads, so only the rule under test is broken.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, DeclSecurityRaw, TableDataOwned, TableId, TypeAttributes,
            TypeDefBuilder,
        },
        token::Token,
    },
    testkit::{
        create_test_assembly,
        factories::validation::attribute::{apply_attribute, mscorlib_type},
        get_testfile_mscorlib, method_token, mono_mscorlib, Expect, TestAssembly,
    },
    Error, Result,
};

/// A permission set the loader reads: an empty `PermissionSet`.
const PERMISSION_SET: &[u8] =
    b"<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\"/>";

/// Main factory method for system security validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn owned_security_validator_file_factory() -> Result<Vec<TestAssembly>> {
    Ok(vec![
        TestAssembly::new(get_testfile_mscorlib()),
        create_assembly_with_invalid_security_action()?,
        create_assembly_with_conflicting_security_attributes()?,
        create_assembly_with_security_transparency_violations()?,
    ])
}

/// Adds a declarative security entry on `<Module>`'s type with `action` and `permission_set`.
fn declare_security(assembly: &mut CilAssembly, action: u16, permission_set: &[u8]) -> Result<()> {
    let blob = assembly.blob_add(permission_set)?;
    let rid = assembly.next_rid(TableId::DeclSecurity)?;
    assembly.table_row_add(
        TableId::DeclSecurity,
        TableDataOwned::DeclSecurity(DeclSecurityRaw {
            rid,
            token: Token::from_parts(TableId::DeclSecurity, rid),
            offset: 0,
            action,
            parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasDeclSecurity),
            permission_set: blob.placeholder(),
        }),
    )?;
    Ok(())
}

/// Defines public class `Test.{name}` extending `base` (a TypeDef row) and returns its row.
fn define_type(assembly: &mut CilAssembly, name: &str, base: u32) -> Result<u32> {
    let ty = TypeDefBuilder::new()
        .name(name)
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::BEFORE_FIELD_INIT)
        .extends(CodedIndex::new(
            TableId::TypeDef,
            base,
            CodedIndexType::TypeDefOrRef,
        ))
        .build(assembly)?;
    Ok(ty
        .token()
        .ok_or_else(|| Error::Other(format!("{name}'s row")))?
        .row())
}

/// Applies `attribute` (a full name), through its parameterless mscorlib constructor, to the
/// type at TypeDef row `target`.
fn mark(assembly: &mut CilAssembly, target: u32, attribute: &str) -> Result<()> {
    let constructor = method_token(&mono_mscorlib(), attribute, ".ctor", 0).row();
    apply_attribute(
        assembly,
        CodedIndex::new(TableId::TypeDef, target, CodedIndexType::HasCustomAttribute),
        constructor,
        Vec::new(),
        Vec::new(),
    )
}

/// A declarative security entry whose action (99) ECMA-335 II.22.11 does not define.
pub fn create_assembly_with_invalid_security_action() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Security declaration has invalid action: 0x0063"),
        |assembly| declare_security(assembly, 99, PERMISSION_SET),
    )
}

pub fn create_assembly_with_conflicting_security_attributes() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Type 'ConflictingType' cannot be both SecurityCritical and SecurityTransparent",
        ),
        |assembly| {
            let ty = define_type(assembly, "ConflictingType", mscorlib_type("System.Object")?)?;
            mark(assembly, ty, "System.Security.SecurityCriticalAttribute")?;
            mark(assembly, ty, "System.Security.SecurityTransparentAttribute")
        },
    )
}

/// A SecurityTransparent type deriving from a SecurityCritical one.
pub fn create_assembly_with_security_transparency_violations() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail(
            "Transparent type 'TransparentDerived' cannot inherit from critical base type",
        ),
        |assembly| {
            let base = define_type(assembly, "CriticalBase", mscorlib_type("System.Object")?)?;
            mark(assembly, base, "System.Security.SecurityCriticalAttribute")?;
            let derived = define_type(assembly, "TransparentDerived", base)?;
            mark(
                assembly,
                derived,
                "System.Security.SecurityTransparentAttribute",
            )
        },
    )
}

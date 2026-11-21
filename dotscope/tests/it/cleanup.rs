#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Cleanup keeps every reference row a surviving row still names.
//!
//! A cleanup request makes every TypeRef, TypeSpec, MemberRef, ModuleRef and AssemblyRef a
//! candidate for removal, kept only when something still references it. Each test adds a row
//! that exactly one column references, runs a cleanup that deletes something unrelated, and
//! checks that the row and its referrer both reach the written assembly, which the writer
//! refuses to produce with a reference left dangling.

use dotscope::{
    assembly::Operand,
    io::write_compressed_uint,
    metadata::{
        signatures::TypeSignature,
        tables::{
            AssemblyRefBuilder, CodedIndex, CodedIndexType, CustomAttributeRaw, EventAttributes,
            EventBuilder, EventMapBuilder, ExportedTypeBuilder, ExportedTypeRaw, FieldAttributes,
            FieldBuilder, FieldRaw, ManifestResourceBuilder, ManifestResourceRaw, MemberRefBuilder,
            MethodImplBuilder, MethodImplRaw, MethodSpecBuilder, ModuleRefBuilder,
            NestedClassBuilder, StandAloneSigBuilder, TableDataOwned, TableId, TypeAttributes,
            TypeDefBuilder, TypeRefBuilder, TypeSpecBuilder,
        },
        token::Token,
        validation::ValidationConfig,
    },
    testkit::{engine, fixture},
    CilAssembly, CilObject, CleanupRequest, MethodBuilder, Result,
};

/// The sample every test extends: a small application with an assembly-level attribute to
/// delete.
const SAMPLE: &str = "packers/confuserex/1.6.0/original.exe";

/// The row a builder made.
fn row(change: &dotscope::ChangeRefRc) -> u32 {
    change.token().expect("the row has a token").row()
}

/// `blob` followed by `token` as a signature encodes it: TypeDefOrRefOrSpecEncoded
/// (ECMA-335 II.23.2.8), a compressed integer.
fn with_type_token(mut blob: Vec<u8>, token: Token) -> Vec<u8> {
    let tag = match token.table() {
        0x02 => 0,
        0x01 => 1,
        _ => 2,
    };
    write_compressed_uint((token.row() << 2) | tag, &mut blob).unwrap();
    blob
}

/// A TypeRef named `name` in mscorlib (AssemblyRef 1).
fn type_ref(assembly: &mut CilAssembly, name: &str) -> Result<u32> {
    let built = TypeRefBuilder::new()
        .name(name)
        .namespace("Kept")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            1,
            CodedIndexType::ResolutionScope,
        ))
        .build(assembly)?;
    Ok(row(&built))
}

/// `assembly`, written with the rows a test added and loaded back so they are part of the
/// input, then with one assembly-level attribute deleted by cleanup, written and loaded back.
/// Deleting anything makes every reference row of the input a cleanup candidate.
fn cleaned(mut assembly: CilAssembly) -> Result<CilObject> {
    let mut assembly = CilAssembly::from_bytes(assembly.to_memory()?)?;
    let attribute = {
        let view = assembly.view();
        let tables = view.tables().expect("tables");
        let attributes = tables.table::<CustomAttributeRaw>().expect("attributes");
        let attribute = attributes
            .iter()
            .filter_map(std::result::Result::ok)
            .find(|row| row.parent.token.is_table(TableId::Assembly))
            .expect("an assembly-level attribute");
        attribute.token
    };
    let mut request = CleanupRequest::new();
    request.add_attribute(attribute);
    assembly.add_cleanup(&request);
    let bytes = assembly.to_memory()?;
    CilObject::from_mem_with_validation(bytes, ValidationConfig::analysis())
}

/// The names of the TypeRefs in `assembly`'s namespace `Kept`.
fn kept_type_refs(assembly: &CilObject) -> Vec<String> {
    assembly
        .imports()
        .cil()
        .iter()
        .filter(|entry| entry.value().namespace == "Kept")
        .map(|entry| entry.value().name.to_string())
        .collect()
}

/// A MethodImpl whose declaration is a MemberRef keeps that MemberRef: a class implementing
/// an interface method of another assembly explicitly looks like this.
#[test]
fn a_method_impl_keeps_the_member_refs_it_names() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let interface = type_ref(&mut assembly, "IKept")?;
    let declaration = MemberRefBuilder::new()
        .class(CodedIndex::new(
            TableId::TypeRef,
            interface,
            CodedIndexType::MemberRefParent,
        ))
        .name("Declared")
        .signature(&[0x20, 0x00, 0x01])
        .build(&mut assembly)?;
    let body = MemberRefBuilder::new()
        .class(CodedIndex::new(
            TableId::TypeRef,
            interface,
            CodedIndexType::MemberRefParent,
        ))
        .name("Body")
        .signature(&[0x20, 0x00, 0x01])
        .build(&mut assembly)?;
    MethodImplBuilder::new()
        .class(2)
        .method_body_from_member_ref(row(&body))
        .method_declaration_from_member_ref(row(&declaration))
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    let tables = written.tables().unwrap();
    let method_impl = tables
        .table::<MethodImplRaw>()
        .and_then(|table| table.iter().filter_map(std::result::Result::ok).last())
        .expect("the MethodImpl survives");
    let named = |token: Token| {
        written
            .refs_members()
            .get(&token)
            .map(|entry| entry.value().name.clone())
    };
    assert_eq!(
        named(method_impl.method_declaration.token).as_deref(),
        Some("Declared")
    );
    assert_eq!(
        named(method_impl.method_body.token).as_deref(),
        Some("Body")
    );
    Ok(())
}

/// An event's type keeps its TypeRef, and a TypeSpec event type keeps that TypeSpec.
#[test]
fn an_event_keeps_its_type() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let handler = type_ref(&mut assembly, "KeptHandler")?;
    let generic = type_ref(&mut assembly, "KeptGenericHandler")?;
    let instance = TypeSpecBuilder::new()
        .generic_instantiation(
            Token::from_parts(TableId::TypeRef, generic),
            vec![TypeSignature::I4],
        )
        .build(&mut assembly)?;
    let first = EventBuilder::new()
        .name("Plain")
        .flags(EventAttributes::new(0))
        .event_type(CodedIndex::new(
            TableId::TypeRef,
            handler,
            CodedIndexType::TypeDefOrRef,
        ))
        .build(&mut assembly)?;
    EventBuilder::new()
        .name("Generic")
        .flags(EventAttributes::new(0))
        .event_type(CodedIndex::new(
            TableId::TypeSpec,
            row(&instance),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(&mut assembly)?;
    EventMapBuilder::new()
        .parent(2)
        .event_list(row(&first))
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    let mut kept = kept_type_refs(&written);
    kept.sort();
    assert_eq!(kept, ["KeptGenericHandler", "KeptHandler"]);
    Ok(())
}

/// A MemberRef on a ModuleRef (a global function of another module) keeps the ModuleRef.
#[test]
fn a_member_ref_keeps_its_module_ref() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let module = ModuleRefBuilder::new()
        .name("kept.netmodule")
        .build(&mut assembly)?;
    let global = MemberRefBuilder::new()
        .class(CodedIndex::new(
            TableId::ModuleRef,
            row(&module),
            CodedIndexType::MemberRefParent,
        ))
        .name("GlobalFunction")
        .signature(&[0x00, 0x00, 0x01])
        .build(&mut assembly)?;
    // A MethodSpec keeps the MemberRef itself.
    MethodSpecBuilder::new()
        .method(CodedIndex::new(
            TableId::MemberRef,
            row(&global),
            CodedIndexType::MethodDefOrRef,
        ))
        .simple_instantiation(0x08)
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    assert!(
        written
            .refs_module()
            .iter()
            .any(|entry| entry.value().name == "kept.netmodule"),
        "the ModuleRef survives"
    );
    Ok(())
}

/// A type forwarder keeps the AssemblyRef it forwards to, and so does a resource another
/// assembly holds.
#[test]
fn exported_types_and_resources_keep_their_assembly_refs() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let forwarded_to = AssemblyRefBuilder::new()
        .name("Kept.Forwarded")
        .version(1, 0, 0, 0)
        .build(&mut assembly)?;
    let holding = AssemblyRefBuilder::new()
        .name("Kept.Resources")
        .version(1, 0, 0, 0)
        .build(&mut assembly)?;
    ExportedTypeBuilder::new()
        .name("Forwarded")
        .namespace("Kept")
        .public()
        .implementation_assembly_ref(row(&forwarded_to))
        .build(&mut assembly)?;
    ManifestResourceBuilder::new()
        .name("Kept.resources")
        .public()
        .implementation_assembly_ref(row(&holding))
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    let names: Vec<String> = written
        .refs_assembly()
        .iter()
        .map(|entry| entry.value().name.to_string())
        .collect();
    assert!(
        names.iter().any(|name| name == "Kept.Forwarded"),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name == "Kept.Resources"),
        "{names:?}"
    );
    let tables = written.tables().unwrap();
    assert_eq!(
        tables
            .table::<ExportedTypeRaw>()
            .map_or(0, |table| table.row_count),
        1,
        "the type forwarder survives"
    );
    assert!(
        tables
            .table::<ManifestResourceRaw>()
            .is_some_and(|table| table.row_count > 0),
        "the resource row survives"
    );
    Ok(())
}

/// A generic method instantiation keeps the TypeRefs its type arguments name: `Foo<Kept>`
/// names `Kept` in the MethodSpec's own blob.
#[test]
fn a_method_spec_instantiation_keeps_its_type_arguments() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let argument = type_ref(&mut assembly, "KeptArgument")?;
    let generic = MemberRefBuilder::new()
        .class(CodedIndex::new(
            TableId::TypeRef,
            type_ref(&mut assembly, "KeptOwner")?,
            CodedIndexType::MemberRefParent,
        ))
        .name("Generic")
        .signature(&[0x10, 0x01, 0x00, 0x01])
        .build(&mut assembly)?;
    // GENERICINST, one argument: CLASS TypeRef(argument)
    MethodSpecBuilder::new()
        .method(CodedIndex::new(
            TableId::MemberRef,
            row(&generic),
            CodedIndexType::MethodDefOrRef,
        ))
        .instantiation(&with_type_token(
            vec![0x0A, 0x01, 0x12],
            Token::from_parts(TableId::TypeRef, argument),
        ))
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    let mut kept = kept_type_refs(&written);
    kept.sort();
    assert_eq!(kept, ["KeptArgument", "KeptOwner"]);
    Ok(())
}

/// A signature may name a TypeSpec (ECMA-335 II.23.2.8), which keeps it: here a field
/// reference typed by a generic instance.
#[test]
fn a_signature_keeps_the_type_specs_it_names() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let generic = type_ref(&mut assembly, "KeptGeneric")?;
    let instance = TypeSpecBuilder::new()
        .generic_instantiation(
            Token::from_parts(TableId::TypeRef, generic),
            vec![TypeSignature::I4],
        )
        .build(&mut assembly)?;
    let field = MemberRefBuilder::new()
        .class(CodedIndex::new(
            TableId::TypeRef,
            type_ref(&mut assembly, "KeptOwner")?,
            CodedIndexType::MemberRefParent,
        ))
        .name("Field")
        .signature(&with_type_token(
            vec![0x06, 0x12],
            Token::from_parts(TableId::TypeSpec, row(&instance)),
        ))
        .build(&mut assembly)?;
    MethodSpecBuilder::new()
        .method(CodedIndex::new(
            TableId::MemberRef,
            row(&field),
            CodedIndexType::MethodDefOrRef,
        ))
        .simple_instantiation(0x08)
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    let mut kept = kept_type_refs(&written);
    kept.sort();
    assert_eq!(kept, ["KeptGeneric", "KeptOwner"]);
    Ok(())
}

/// A clean assembly whose classes implement interface methods through MemberRefs
/// deobfuscates: cleanup keeps the MemberRefs its MethodImpl rows name.
#[test]
fn an_assembly_with_member_ref_method_impls_deobfuscates() {
    let method_impls = |assembly: &CilObject| {
        assembly
            .tables()
            .and_then(|tables| tables.table::<MethodImplRaw>())
            .map_or(0, |table| table.row_count)
    };
    let input = CilObject::from_path(fixture("crafted_2.exe")).unwrap();
    let (output, _) = engine()
        .process_file(fixture("crafted_2.exe"))
        .expect("deobfuscates");
    assert!(method_impls(&input) > 0);
    assert_eq!(method_impls(&output), method_impls(&input));
    CilObject::from_mem_with_validation(
        output.file().data().to_vec(),
        ValidationConfig::production(),
    )
    .expect("the output passes production validation");
}

/// A `calli` signature keeps the TypeRefs it names: the StandAloneSig a `calli` operand
/// names is a method signature, not a local variable list.
#[test]
fn a_calli_signature_keeps_its_types() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let returned = type_ref(&mut assembly, "KeptReturn")?;
    // DEFAULT, no parameters, returning CLASS KeptReturn
    let signature = StandAloneSigBuilder::new()
        .signature(&with_type_token(
            vec![0x00, 0x00, 0x12],
            Token::from_parts(TableId::TypeRef, returned),
        ))
        .build(&mut assembly)?;
    let signature = Token::from_parts(TableId::StandAloneSig, row(&signature));
    MethodBuilder::new("CallsThroughAPointer")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldnull()?
                    .emit_opcode(0x29, Some(Operand::Token(signature)))?
                    .pop()?
                    .ret()?;
                Ok(())
            })
        })
        .build(&mut assembly)?;

    let written = cleaned(assembly)?;
    assert_eq!(kept_type_refs(&written), ["KeptReturn"]);
    Ok(())
}

/// A row that is updated and then deleted names nothing: its signature does not hold the type
/// it names when that type is deleted too. ConfuserEx's constants data field, updated before
/// cleanup removes it with the sized struct that types it, looks like this.
#[test]
fn a_row_updated_then_deleted_names_nothing() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let gone = TypeDefBuilder::new()
        .name("Gone")
        .namespace("Kept")
        .flags(TypeAttributes::CLASS | TypeAttributes::NOT_PUBLIC)
        .build(&mut assembly)?;
    let gone = Token::from_parts(TableId::TypeDef, row(&gone));
    TypeDefBuilder::new()
        .name("Holder")
        .namespace("Kept")
        .flags(TypeAttributes::CLASS | TypeAttributes::NOT_PUBLIC)
        .build(&mut assembly)?;
    let data = FieldBuilder::new()
        .name("Data")
        .flags(FieldAttributes::STATIC | FieldAttributes::ASSEMBLY)
        .signature(&with_type_token(vec![0x06, 0x12], gone))
        .build(&mut assembly)?;
    let data = Token::from_parts(TableId::Field, row(&data));

    let mut assembly = CilAssembly::from_bytes(assembly.to_memory()?)?;
    let updated = {
        let view = assembly.view();
        let fields = view.tables().unwrap().table::<FieldRaw>().unwrap();
        let mut field = fields.get(data.row())?.expect("the field");
        field.flags |= FieldAttributes::INIT_ONLY.bits();
        field
    };
    assembly.table_row_update(TableId::Field, data.row(), TableDataOwned::Field(updated))?;
    let mut request = CleanupRequest::new();
    request.add_field(data);
    request.add_type(gone);
    assembly.add_cleanup(&request);
    let written =
        CilObject::from_mem_with_validation(assembly.to_memory()?, ValidationConfig::analysis())?;
    assert!(written
        .types()
        .iter()
        .all(|entry| entry.value().name != "Gone"));
    Ok(())
}

/// A TypeDef `name` in namespace `Nest`, nested (`NestedPrivate`) when `nested`; the methods
/// built after it belong to it.
fn class(assembly: &mut CilAssembly, name: &str, nested: bool) -> Result<Token> {
    let visibility = if nested {
        TypeAttributes::NESTED_PRIVATE
    } else {
        TypeAttributes::NOT_PUBLIC
    };
    let built = TypeDefBuilder::new()
        .name(name)
        .namespace(if nested { "" } else { "Nest" })
        .flags(TypeAttributes::CLASS | visibility)
        .build(assembly)?;
    Ok(Token::from_parts(TableId::TypeDef, row(&built)))
}

/// Records `nested` as nested in `enclosing`.
fn nest(assembly: &mut CilAssembly, nested: Token, enclosing: Token) -> Result<()> {
    NestedClassBuilder::new()
        .nested_class(nested.row())
        .enclosing_class(enclosing.row())
        .build(assembly)?;
    Ok(())
}

/// A static method `name` of the last type built, whose body loads `token` with `ldtoken`
/// (naming it) or does nothing.
fn method(assembly: &mut CilAssembly, name: &str, names: Option<Token>) -> Result<()> {
    MethodBuilder::new(name)
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                if let Some(token) = names {
                    asm.emit_opcode(0xD0, Some(Operand::Token(token)))?.pop()?;
                }
                asm.ret()?;
                Ok(())
            })
        })
        .build(assembly)?;
    Ok(())
}

/// `assembly` written and loaded back so its rows are input, then cleaned with `request`
/// (built against the reloaded rows), written and loaded back.
fn cleaned_with(
    assembly: CilAssembly,
    request: impl FnOnce(&CilAssembly) -> CleanupRequest,
) -> Result<CilObject> {
    let mut assembly = assembly;
    let mut assembly = CilAssembly::from_bytes(assembly.to_memory()?)?;
    let request = request(&assembly);
    assembly.add_cleanup(&request);
    CilObject::from_mem_with_validation(assembly.to_memory()?, ValidationConfig::analysis())
}

/// The names of `written`'s types in `Nest` and nested in them, each with the name of the
/// type it is nested in.
fn nest_types(written: &CilObject) -> Vec<(String, Option<String>)> {
    let mut types: Vec<_> = written
        .types()
        .iter()
        .filter(|entry| {
            let ty = entry.value();
            // The outermost type of the enclosing chain is in `Nest`
            let mut outermost = ty.clone();
            while let Some(outer) = outermost.enclosing_type() {
                outermost = outer;
            }
            ty.token.is_table(TableId::TypeDef) && outermost.namespace == "Nest"
        })
        .map(|entry| {
            let ty = entry.value();
            (
                ty.name.to_string(),
                ty.enclosing_type().map(|outer| outer.name.to_string()),
            )
        })
        .collect();
    types.sort();
    types
}

/// Whether `written` has a method named `name`.
fn has_method(written: &CilObject, name: &str) -> bool {
    written
        .methods()
        .iter()
        .any(|entry| entry.value().name == name)
}

/// Deleting a type deletes what is nested in it at every depth, with their members: a nested
/// type cannot outlive its enclosing type, and one left behind would be a top-level type.
#[test]
fn deleting_a_type_deletes_its_nested_types_at_every_depth() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let outer = class(&mut assembly, "Outer", false)?;
    method(&mut assembly, "OuterWork", None)?;
    let middle = class(&mut assembly, "Middle", true)?;
    method(&mut assembly, "MiddleWork", None)?;
    let leaf = class(&mut assembly, "Leaf", true)?;
    method(&mut assembly, "LeafWork", None)?;
    nest(&mut assembly, middle, outer)?;
    nest(&mut assembly, leaf, middle)?;

    let written = cleaned_with(assembly, |_| {
        let mut request = CleanupRequest::new();
        request.add_type(outer);
        request
    })?;
    assert_eq!(nest_types(&written), Vec::<(String, Option<String>)>::new());
    assert!(!has_method(&written, "LeafWork"));
    Ok(())
}

/// A requested type that surviving code still needs stays, whole: a method elsewhere names
/// its nested type, so the nested type stays, the type enclosing it stays with it, and the
/// enclosing type keeps its members instead of surviving as an emptied shell.
#[test]
fn a_type_enclosing_a_named_type_stays_whole() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let outer = class(&mut assembly, "Outer", false)?;
    method(&mut assembly, "OuterWork", None)?;
    let inner = class(&mut assembly, "Inner", true)?;
    method(&mut assembly, "InnerWork", None)?;
    nest(&mut assembly, inner, outer)?;
    class(&mut assembly, "User", false)?;
    method(&mut assembly, "NamesInner", Some(inner))?;

    let written = cleaned_with(assembly, |_| {
        let mut request = CleanupRequest::new();
        request.add_type(outer);
        request
    })?;
    assert_eq!(
        nest_types(&written),
        [
            ("Inner".to_string(), Some("Outer".to_string())),
            ("Outer".to_string(), None),
            ("User".to_string(), None),
        ]
    );
    assert!(has_method(&written, "OuterWork"));
    assert!(has_method(&written, "InnerWork"));
    Ok(())
}

/// A protected nested type keeps the type it is nested in, even when that type is requested.
#[test]
fn a_protected_nested_type_keeps_its_enclosing_type() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let outer = class(&mut assembly, "Outer", false)?;
    method(&mut assembly, "OuterWork", None)?;
    let inner = class(&mut assembly, "Inner", true)?;
    method(&mut assembly, "InnerWork", None)?;
    nest(&mut assembly, inner, outer)?;

    let written = cleaned_with(assembly, |_| {
        let mut request = CleanupRequest::new();
        request.add_type(outer);
        request.protect_token(inner);
        request
    })?;
    assert_eq!(
        nest_types(&written),
        [
            ("Inner".to_string(), Some("Outer".to_string())),
            ("Outer".to_string(), None),
        ]
    );
    Ok(())
}

/// An enclosing type with no members of its own is not an empty type to remove while a type
/// nested in it stays: removing it would make the nested type a top-level type.
#[test]
fn an_empty_enclosing_type_stays_with_its_nested_type() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(SAMPLE))?;
    let outer = class(&mut assembly, "Outer", false)?;
    let inner = class(&mut assembly, "Inner", true)?;
    method(&mut assembly, "InnerWork", None)?;
    nest(&mut assembly, inner, outer)?;

    let written = cleaned(assembly)?;
    assert_eq!(
        nest_types(&written),
        [
            ("Inner".to_string(), Some("Outer".to_string())),
            ("Outer".to_string(), None),
        ]
    );
    Ok(())
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! The Portable PDB of an assembly holds what its sources say.
//!
//! The probes (`tests/samples/factory/generators/PdbProbe` and `PdbProbeVb`) are built by the
//! C# and Visual Basic compilers with a row of every PDB table and a record of every custom
//! debug information kind they write; each source file says which records it is there for.
//! Their sources are the oracle here: each embedded source is the file as written, each
//! constant holds the value its declaration gives, each `#line` directive moves the sequence
//! points it names, and the build records the Source Link map and references the project
//! gives. The tables themselves are checked against System.Reflection.Metadata by the oracle
//! tier (`full::oracle`).

use std::{fs, path::PathBuf};

use sha2::{Digest, Sha256};

use dotscope::{
    metadata::{
        customdebuginformation::{AsyncAwait, CustomDebugInfo, CustomDebugKind},
        importscope::{ImportDeclaration, ImportsInfo},
        pdb::{
            guids, GeneralValue, LocalConstantSig, LocalConstantValue, PdbOrigin, PortablePdb,
            PrimitiveConstant,
        },
        sequencepoints::{SequencePoint, SequencePoints},
        tables::{
            CodedIndex, CodedIndexType, CustomDebugInformationBuilder, CustomDebugInformationRaw,
            DocumentBuilder, ImportScopeBuilder, LocalConstantBuilder,
            MethodDebugInformationBuilder, TableId,
        },
        token::Token,
    },
    testkit::{fixture, fixture_bytes},
    CilAssembly, CilAssemblyView, CilObject,
};

/// A probe source file, as written.
fn source(project: &str, path: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples/factory/generators")
        .join(project)
        .join(path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The C# probe with the PDB it embeds.
fn embedded_probe() -> CilObject {
    CilObject::from_path(fixture("pdb/embedded/PdbProbe.dll")).unwrap()
}

/// The token of the method `name` of the type `type_name`.
fn method(assembly: &CilObject, type_name: &str, name: &str) -> Token {
    assembly
        .methods()
        .iter()
        .find(|entry| {
            let method = entry.value();
            method.name == name
                && method
                    .declaring_type
                    .get()
                    .and_then(|declaring| declaring.name())
                    .is_some_and(|declaring| declaring == type_name)
        })
        .unwrap_or_else(|| panic!("{type_name}.{name}"))
        .value()
        .token
}

/// The document whose path ends with `suffix`.
fn document(pdb: &PortablePdb, suffix: &str) -> u32 {
    pdb.documents()
        .iter()
        .find(|entry| entry.value().name.ends_with(suffix))
        .unwrap_or_else(|| panic!("no document ends with {suffix}"))
        .value()
        .rid
}

/// Every source file the project embeds reads back as written: the C# compiler embeds them
/// all (`EmbedAllSources`), deflated when that is smaller.
#[test]
fn every_source_is_embedded_as_written() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    assert_eq!(pdb.origin(), PdbOrigin::Embedded);
    for file in [
        "Program.cs",
        "Constants.cs",
        "Scopes.cs",
        "Async.cs",
        "Locals.cs",
        "Lines.cs",
        "Primary.cs",
        "Nested/Deeper/Deep.cs",
    ] {
        let rid = document(pdb, &format!("/{file}"));
        let text = pdb
            .embedded_source(rid)
            .unwrap_or_else(|| panic!("{file} is not embedded"))
            .unwrap();
        assert_eq!(text, source("PdbProbe", file), "{file}");

        let document = pdb.document(rid).unwrap();
        assert!(document.is_csharp(), "{file}");
        assert_eq!(document.hash_algorithm, Some(guids::HASH_SHA256), "{file}");
        assert_eq!(document.hash.len(), 32, "{file}");
    }
}

/// The module records the Source Link map beside the project, the C# compiler's options, and
/// the reference to the library under its extern alias.
#[test]
fn the_module_records_its_build() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    let module = assembly.module().unwrap().token;
    let records = pdb.custom_debug_info_of(module);

    let source_link = records
        .iter()
        .find_map(|record| match &record.value {
            CustomDebugInfo::SourceLink(json) => Some(json.clone()),
            _ => None,
        })
        .expect("a Source Link record");
    assert_eq!(
        source_link.trim_end(),
        source("PdbProbe", "sourcelink.json").trim_end()
    );

    let options = records
        .iter()
        .find_map(|record| match &record.value {
            CustomDebugInfo::CompilationOptions(options) => Some(options.clone()),
            _ => None,
        })
        .expect("a CompilationOptions record");
    assert!(
        options
            .iter()
            .any(|(name, value)| name == "language" && value == "C#"),
        "{options:?}"
    );

    let references = records
        .iter()
        .find_map(|record| match &record.value {
            CustomDebugInfo::CompilationMetadataReferences(references) => Some(references.clone()),
            _ => None,
        })
        .expect("a CompilationMetadataReferences record");
    let library = references
        .iter()
        .find(|reference| reference.file_name == "PdbProbeLib.dll")
        .expect("the library is referenced");
    assert_eq!(library.aliases, ["probelib"]);
}

/// Each constant local holds the type and value its declaration gives.
#[test]
fn constants_hold_their_source_values() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    let constant = |name: &str| -> LocalConstantSig {
        pdb.local_constants()
            .iter()
            .find(|entry| entry.value().name == name)
            .unwrap_or_else(|| panic!("no constant {name}"))
            .value()
            .signature
            .clone()
    };
    let primitive = |name: &str| match constant(name).value {
        LocalConstantValue::Primitive(value) => value,
        other => panic!("{name}: {other:?}"),
    };
    assert_eq!(primitive("flag"), PrimitiveConstant::Boolean(true));
    assert_eq!(
        primitive("letter"),
        PrimitiveConstant::Char(u16::from(b'Z'))
    );
    assert_eq!(primitive("tiny"), PrimitiveConstant::I1(-8));
    assert_eq!(primitive("small"), PrimitiveConstant::U1(200));
    assert_eq!(primitive("shortValue"), PrimitiveConstant::I2(-300));
    assert_eq!(primitive("ushortValue"), PrimitiveConstant::U2(60000));
    assert_eq!(primitive("intValue"), PrimitiveConstant::I4(-123_456));
    assert_eq!(primitive("uintValue"), PrimitiveConstant::U4(4_000_000_000));
    assert_eq!(
        primitive("longValue"),
        PrimitiveConstant::I8(-9_000_000_000)
    );
    assert_eq!(
        primitive("ulongValue"),
        PrimitiveConstant::U8(18_000_000_000_000_000_000)
    );
    assert_eq!(primitive("single"), PrimitiveConstant::R4(1.5));
    assert_eq!(primitive("real"), PrimitiveConstant::R8(-2.25));
    assert_eq!(
        primitive("text"),
        PrimitiveConstant::String(Some("constant text".encode_utf16().collect()))
    );
    assert_eq!(primitive("nothing"), PrimitiveConstant::String(None));
    // C# writes `nint` and `nuint` constants as I4 and U4
    assert_eq!(primitive("native"), PrimitiveConstant::I4(-5));
    assert_eq!(primitive("unative"), PrimitiveConstant::U4(5));

    let decimal = |name: &str| match constant(name).value {
        LocalConstantValue::General {
            value_type: true,
            value,
            ..
        } => value,
        other => panic!("{name}: {other:?}"),
    };
    assert_eq!(
        decimal("money"),
        GeneralValue::Decimal {
            negative: false,
            scale: 4,
            words: [123_456_789, 0, 0],
        }
    );
    assert_eq!(
        decimal("negative"),
        GeneralValue::Decimal {
            negative: true,
            scale: 3,
            words: [1, 0, 0],
        }
    );
    assert_eq!(constant("none").value, LocalConstantValue::NullObject);

    // An enum of the assembly's own, and one of the framework's
    let LocalConstantValue::Enum { value, enum_type } = constant("colour").value else {
        panic!("colour is an enum constant");
    };
    assert_eq!(value, PrimitiveConstant::I2(7));
    assert_eq!(enum_type.table(), TableId::TypeDef as u8);
    let LocalConstantValue::Enum { value, enum_type } = constant("comparison").value else {
        panic!("comparison is an enum constant");
    };
    assert_eq!(value, PrimitiveConstant::I4(4));
    assert_eq!(enum_type.table(), TableId::TypeRef as u8);
}

/// A method's scopes name the locals it declares, and the locals' records say which are
/// `dynamic` and what their tuple elements are called.
#[test]
fn locals_carry_their_dynamic_and_tuple_records() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    let scopes = pdb.method_scopes(method(&assembly, "Locals", "DynamicAndTuples"));
    let variables: Vec<_> = scopes
        .iter()
        .flat_map(|scope| {
            scope
                .variables
                .iter()
                .map(|(_, v)| v.clone())
                .collect::<Vec<_>>()
        })
        .collect();
    let local = |name: &str| {
        variables
            .iter()
            .find(|variable| variable.name == name)
            .unwrap_or_else(|| panic!("no local {name}"))
            .token
    };
    for name in ["value", "values", "list", "pair", "deep", "named", "total"] {
        local(name);
    }

    let records = |token| {
        pdb.custom_debug_info_of(token)
            .into_iter()
            .map(|record| record.value.clone())
            .collect::<Vec<_>>()
    };
    let dynamic = |name: &str| {
        records(local(name))
            .into_iter()
            .find(|record| matches!(record, CustomDebugInfo::DynamicLocalVariables(_)))
            .unwrap_or_else(|| panic!("{name} has no dynamic flags"))
    };
    // `dynamic`; `dynamic[]` (the element); `List<dynamic>` (the type argument)
    assert!(dynamic("value").is_dynamic(0));
    let values = dynamic("values");
    assert!(!values.is_dynamic(0) && values.is_dynamic(1));
    let list = dynamic("list");
    assert!(!list.is_dynamic(0) && list.is_dynamic(1));

    let names = |name: &str| {
        records(local(name))
            .into_iter()
            .find_map(|record| match record {
                CustomDebugInfo::TupleElementNames(names) => Some(names),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{name} has no tuple names"))
    };
    let named = |names: &[&str]| -> Vec<Option<String>> {
        names.iter().map(|name| Some((*name).to_string())).collect()
    };
    assert_eq!(names("pair"), named(&["first", "second"]));
    assert_eq!(names("deep"), named(&["a", "nested", "b", "c"]));
    assert_eq!(names("named"), named(&["key", "name"]));
}

/// The async method, the iterator and the async iterator are state machines: each MoveNext
/// names its kickoff method, and the async MoveNext records where it suspends and resumes.
#[test]
fn state_machines_name_their_kickoff_methods() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    let kickoffs: Vec<String> = pdb
        .state_machine_methods()
        .iter()
        .map(|entry| entry.value().kickoff_method.name.clone())
        .collect();
    for name in ["Compute", "Iterate", "Stream"] {
        assert!(
            kickoffs.iter().any(|kickoff| kickoff == name),
            "{kickoffs:?}"
        );
    }

    let compute = pdb
        .state_machine_methods()
        .iter()
        .find(|entry| entry.value().kickoff_method.name == "Compute")
        .unwrap()
        .value()
        .move_next_method
        .token;
    let stepping = pdb
        .custom_debug_info_of(compute)
        .into_iter()
        .find_map(|record| match &record.value {
            CustomDebugInfo::AsyncMethodSteppingInformation { awaits, .. } => Some(awaits.clone()),
            _ => None,
        })
        .expect("Compute's MoveNext has stepping information");
    // One `await Task.Yield()`, resuming after it suspends, in MoveNext itself
    let [await_point] = stepping.as_slice() else {
        panic!("Compute has one await: {stepping:?}");
    };
    assert!(await_point.resume_offset > await_point.yield_offset);
    assert_eq!(await_point.method, compute.row());
}

/// `#line` directives move the sequence points they cover: to another document and line,
/// out of sight (`hidden`), and to a span of a third document. The compiler hashes the file a
/// plain `#line` names, and writes no hash for the one the span form names.
#[test]
fn line_directives_move_sequence_points() {
    let assembly = embedded_probe();
    let pdb = assembly.pdb().unwrap();
    let lines = document(pdb, "/Lines.cs");
    let mapped = document(pdb, "Generated/Mapped.razor");
    let spans = document(pdb, "Generated/Spans.razor");

    let points = pdb
        .sequence_points(method(&assembly, "Lines", "Mapped"))
        .unwrap()
        .points;
    assert!(points.iter().any(|point| point.document == lines));
    assert!(points
        .iter()
        .any(|point| point.document == mapped && point.start_line == 500));
    assert!(points.iter().any(|point| point.is_hidden));
    // `#line (10, 5) - (12, 20) 3`: the statement at column 13 maps to the span's first line
    // from column 5 + (13 - 1 - 3), and its 12 characters end at column 26
    assert!(points.iter().any(|point| point.document == spans
        && point.start_line == 10
        && point.start_col == 14
        && point.end_line == 10
        && point.end_col == 26));

    let mapped = pdb.document(mapped).unwrap();
    assert_eq!(mapped.hash_algorithm, Some(guids::HASH_SHA256));
    assert_eq!(
        mapped.hash,
        Sha256::digest(source("PdbProbe", "Generated/Mapped.razor").as_bytes()).as_slice()
    );
    let spans = pdb.document(spans).unwrap();
    assert_eq!(spans.hash_algorithm, None);
    assert!(spans.hash.is_empty());
}

/// The Visual Basic probe's standalone PDB records its root namespace, its documents'
/// language, and its file-level imports: a namespace, an alias and an XML namespace.
#[test]
fn the_visual_basic_probe_records_its_project() {
    let assembly = CilObject::from_path(fixture("pdb/vb/PdbProbeVb.dll"))
        .unwrap()
        .with_pdb(fixture("pdb/vb/PdbProbeVb.pdb"))
        .unwrap();
    let pdb = assembly.pdb().unwrap();
    assert_eq!(pdb.origin(), PdbOrigin::Standalone);

    let module = assembly.module().unwrap().token;
    assert!(pdb.custom_debug_info_of(module).iter().any(
        |record| record.value == CustomDebugInfo::DefaultNamespace("VbProbe.Root".to_string())
    ));

    let program = document(pdb, "Program.vb");
    assert!(pdb.document(program).unwrap().is_visual_basic());

    let imports: Vec<ImportDeclaration> = pdb
        .import_scopes()
        .iter()
        .flat_map(|entry| entry.value().imports.iter().cloned().collect::<Vec<_>>())
        .collect();
    assert!(imports.iter().any(|import| matches!(
        import,
        ImportDeclaration::ImportXmlNamespace { alias, namespace }
            if alias == "probe" && namespace == "http://example.invalid/probe"
    )));
    assert!(imports.iter().any(|import| matches!(
        import,
        ImportDeclaration::DefineNamespaceAlias { alias, namespace }
            if alias == "Strings" && namespace == "System.String"
    ) || matches!(
        import,
        ImportDeclaration::DefineTypeAlias { alias, .. } if alias == "Strings"
    )));
    assert!(imports.iter().any(|import| matches!(
        import,
        ImportDeclaration::ImportNamespace { namespace } if namespace == "System.Collections.Generic"
    )));
}

/// The kind of the custom debug information the write test uses as a blob placed before every
/// blob the PDB rows add, which it then lengthens so that every one of them moves.
const SPACER: uguid::Guid = uguid::guid!("01234567-89AB-CDEF-0123-456789ABCDEF");

/// What the write test's PDB rows say, as a load reads them back.
#[derive(Debug, PartialEq)]
struct WrittenPdb {
    documents: Vec<String>,
    points: Vec<(u32, u32)>,
    local_signature: u32,
    own_document: u32,
    own_points: Vec<u32>,
    constant: LocalConstantSig,
    imports: Vec<ImportDeclaration>,
    type_documents: Vec<u32>,
    awaits: Vec<u32>,
}

/// The write test's PDB rows of the assembly `bytes`, read back.
fn read_written_pdb(bytes: Vec<u8>) -> WrittenPdb {
    let assembly = CilObject::from_mem(bytes).unwrap();
    assert!(
        assembly.diagnostics().warnings().is_empty(),
        "{:?}",
        assembly.diagnostics().warnings()
    );
    let pdb = assembly.pdb().expect("the image holds debug tables");
    assert_eq!(pdb.origin(), PdbOrigin::InImage);
    let points = pdb
        .sequence_points(Token::new(0x0600_0001))
        .expect("MethodDef 1 has sequence points");
    let record = |parent: Token, kind: CustomDebugKind| {
        pdb.custom_debug_info_of(parent)
            .into_iter()
            .map(|row| row.value.clone())
            .find(|value| value.kind() == kind)
            .unwrap_or_else(|| panic!("{parent} has no {kind:?}"))
    };
    let CustomDebugInfo::TypeDefinitionDocuments(type_documents) = record(
        Token::new(0x0200_0002),
        CustomDebugKind::TypeDefinitionDocuments,
    ) else {
        unreachable!()
    };
    let CustomDebugInfo::AsyncMethodSteppingInformation { awaits, .. } = record(
        Token::new(0x0600_0001),
        CustomDebugKind::AsyncMethodSteppingInformation,
    ) else {
        unreachable!()
    };
    let own = pdb
        .method_debug_info(Token::new(0x0600_0002))
        .expect("MethodDef 2 has debug information");
    let written = WrittenPdb {
        own_document: own.document,
        own_points: own
            .sequence_points
            .as_ref()
            .expect("MethodDef 2 has sequence points")
            .points
            .iter()
            .map(|point| point.document)
            .collect(),
        documents: pdb
            .documents()
            .iter()
            .map(|entry| entry.value().name.clone())
            .collect(),
        points: points
            .points
            .iter()
            .map(|point| (point.document, point.start_line))
            .collect(),
        local_signature: points.local_signature,
        constant: pdb
            .local_constants()
            .front()
            .unwrap()
            .value()
            .signature
            .clone(),
        imports: pdb
            .import_scopes()
            .front()
            .unwrap()
            .value()
            .imports
            .iter()
            .cloned()
            .collect(),
        type_documents,
        awaits: awaits
            .iter()
            .map(|await_point| await_point.method)
            .collect(),
    };
    written
}

/// Debug tables written into an assembly hold what was built, and keep it when a later write
/// renumbers the rows and moves the blobs their blobs name.
///
/// The first write adds the rows with the builders: three documents (one that nothing names),
/// sequence points spanning two of them and a method in one named by its row's column, a
/// constant of an enum type, imports of new text, an
/// assembly and a type, and the custom debug information naming a type's documents and an
/// async method's awaits. The documents are named by their rows' placeholders, and the names
/// and imports are blobs naming blobs the same write adds. The second write deletes the first
/// document, so the others renumber, and lengthens a blob placed before every blob the rows
/// added, so all of them move: the Document columns, the sequence points, the type's
/// documents, the names and the imports must follow.
#[test]
fn debug_tables_keep_what_they_name_across_writes() {
    let mut assembly = CilAssembly::new(
        CilAssemblyView::from_mem(fixture_bytes("pdb/portable/PdbProbe.dll").to_vec()).unwrap(),
    );
    let module = CodedIndex::new(
        TableId::Module,
        1,
        CodedIndexType::HasCustomDebugInformation,
    );
    let spacer_kind = assembly.guid_add(&SPACER.to_bytes()).unwrap().placeholder();
    CustomDebugInformationBuilder::new()
        .parent(module)
        .kind(spacer_kind)
        .value(&[0xAB; 4])
        .build(&mut assembly)
        .unwrap();

    let mut rows = Vec::new();
    for name in ["/_/unused.cs", "/_/src/Program.cs", r"C:\src\Other.cs"] {
        rows.push(
            DocumentBuilder::new()
                .name(name)
                .csharp_language()
                .sha256_hash_algorithm()
                .hash(Sha256::digest(name.as_bytes()).to_vec())
                .build(&mut assembly)
                .unwrap()
                .placeholder(),
        );
    }
    // The rows of the three documents, by placeholder
    let [_, program, other]: [u32; 3] = rows.try_into().unwrap();
    let point = |il_offset: u32, line: u32, document: u32| {
        let mut point = SequencePoint::new(il_offset, line, 5, line, 20).unwrap();
        point.document = document;
        point
    };
    MethodDebugInformationBuilder::new()
        .sequence_points_parsed(SequencePoints {
            local_signature: 1,
            points: vec![point(0, 10, program), point(4, 20, other)],
        })
        .build(&mut assembly)
        .unwrap();
    // A method in one document, named by its row's Document column
    MethodDebugInformationBuilder::new()
        .document(other)
        .sequence_points_parsed(SequencePoints {
            local_signature: 0,
            points: vec![point(0, 30, other), point(2, 31, other)],
        })
        .build(&mut assembly)
        .unwrap();
    let constant = LocalConstantSig {
        modifiers: Vec::new(),
        value: LocalConstantValue::Enum {
            value: PrimitiveConstant::I2(7),
            enum_type: Token::new(0x0100_0001),
        },
    };
    LocalConstantBuilder::new()
        .name("colour")
        .signature_parsed(constant.clone())
        .build(&mut assembly)
        .unwrap();
    let imports = vec![
        ImportDeclaration::ImportNamespace {
            namespace: "System.Collections.Generic".to_string(),
        },
        ImportDeclaration::DefineAssemblyNamespaceAlias {
            alias: "probe".to_string(),
            assembly_ref: Token::new(0x2300_0001),
            namespace: "Probe.Library".to_string(),
        },
        ImportDeclaration::ImportType {
            type_ref: Token::new(0x0100_0001),
        },
    ];
    ImportScopeBuilder::new()
        .parent(0)
        .declarations(ImportsInfo::with_declarations(imports.clone()))
        .build(&mut assembly)
        .unwrap();
    CustomDebugInformationBuilder::new()
        .parent(CodedIndex::new(
            TableId::TypeDef,
            2,
            CodedIndexType::HasCustomDebugInformation,
        ))
        .value_parsed(CustomDebugInfo::TypeDefinitionDocuments(vec![other]))
        .build(&mut assembly)
        .unwrap();
    CustomDebugInformationBuilder::new()
        .parent(CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        ))
        .value_parsed(CustomDebugInfo::AsyncMethodSteppingInformation {
            catch_handler: None,
            awaits: vec![AsyncAwait {
                yield_offset: 2,
                resume_offset: 6,
                method: 1,
            }],
        })
        .build(&mut assembly)
        .unwrap();

    let first = assembly.to_memory().unwrap();
    let built = WrittenPdb {
        documents: vec![
            "/_/unused.cs".to_string(),
            "/_/src/Program.cs".to_string(),
            r"C:\src\Other.cs".to_string(),
        ],
        points: vec![(2, 10), (3, 20)],
        local_signature: 1,
        own_document: 3,
        own_points: vec![3, 3],
        constant,
        imports,
        type_documents: vec![3],
        awaits: vec![1],
    };
    assert_eq!(read_written_pdb(first.clone()), built);

    // The spacer's blob, which every blob the rows added follows
    let view = CilAssemblyView::from_mem(first).unwrap();
    let spacer = {
        let guid_heap = view.guids().unwrap();
        view.tables()
            .unwrap()
            .table::<CustomDebugInformationRaw>()
            .unwrap()
            .iter()
            .map(Result::unwrap)
            .find(|row| guid_heap.get(row.kind as usize).unwrap() == SPACER)
            .unwrap()
            .value
    };
    let mut assembly = CilAssembly::new(view);
    assembly.blob_update(spacer, &[0xAB; 300]).unwrap();
    assembly.table_row_remove(TableId::Document, 1).unwrap();
    let second = assembly.to_memory().unwrap();
    assert_eq!(
        read_written_pdb(second),
        WrittenPdb {
            documents: built.documents.iter().skip(1).cloned().collect(),
            points: vec![(1, 10), (2, 20)],
            own_document: 2,
            own_points: vec![2, 2],
            type_documents: vec![2],
            ..built
        }
    );
}

//! The fuzz targets' entry points.
//!
//! Each `fuzz/fuzz_targets/<name>.rs` is a one-line wrapper over the function of that name
//! here, and `tests/fuzz_regressions.rs` replays every input committed under
//! `tests/samples/fuzz-regressions/<name>/` through the same function, so a regression is
//! checked through the entry point that found it. An entry point returns normally on any
//! input it can make nothing of; it panics only when a property it checks fails, which the
//! fuzzer reports as a crash.
//!
//! The properties are the codecs' and the readers' own: what a decoder reads, its encoder
//! writes back to the same value; an RVA the section map places in the file reads that
//! file byte; an assembly written back unchanged holds what it held; code generated from SSA
//! computes what the SSA computes. The work an input can cause is bounded by counts
//! (instructions, emulations, methods), never by time, so a replay's verdict does not depend
//! on how busy the machine is.
//!
//! Fuzzing runs on a developer's machine (`make fuzz`), never in CI; CI replays the committed
//! inputs as ordinary tests.

use std::sync::OnceLock;

use crate::{
    analysis::{SsaVerifier, VerifyLevel},
    assembly::{decode_blocks, decode_blocks_with_handlers},
    cilassembly::CilAssembly,
    deobfuscation::EngineConfig,
    emulation::EmValue,
    file::{pe::relocate_resource_section, sectionmap::RvaMapping, File},
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        customattributes::{
            encode_custom_attribute_value, parse_custom_attribute_data, CustomAttributeValue,
        },
        customdebuginformation::{
            encode_custom_debug_blob, parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
        },
        identity::AssemblyIdentity,
        importscope::parse_imports_blob,
        marshalling::{
            encode_marshalling_descriptor, parse_marshalling_descriptor, MarshallingInfo,
        },
        method::{encode_method_body_header, MethodBody},
        pdb::{document_name, LocalConstantSig},
        resources::{parse_dotnet_resource, parse_dotnet_resource_ref},
        security::{encode_permission_set, PermissionSet, PermissionSetFormat},
        sequencepoints::parse_sequence_points,
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_method_spec_signature, encode_property_signature, encode_typespec_signature,
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
        },
        streams::Blob,
        tables::{MethodDefRaw, ParamList, TableDataOwned, TableId},
        token::Token,
        typesystem::CilTypeReference,
    },
    testkit::{
        arb,
        dump::CanonicalDump,
        emulation::process_builder,
        engine_with,
        equivalence::{regenerate_and_compare, Equivalence},
        fixture_bytes, TestTypeProvider,
    },
    Result,
};

/// The most instructions an emulated method runs.
const MAX_INSTRUCTIONS: u64 = 20_000;

/// The deepest an emulated call stack grows.
const MAX_CALL_DEPTH: usize = 32;

/// How many methods an emulation input runs.
const MAX_METHODS: usize = 8;

/// The most code bytes a method body target decodes.
const MAX_DECODE_BYTES: usize = 64 * 1024;

/// The most emulations a bounded deobfuscation run performs.
const MAX_EMULATIONS: usize = 64;

/// The assembly `emulate_template` splices its code into: real metadata, so the code's
/// tokens and the arguments it is given meet real types.
const TEMPLATE: &str = "crafted_2.exe";

/// A target's entry point: it runs one input, and fails by panicking.
pub type Target = fn(&[u8]);

/// Every target, by name: the directory its regressions live in, and its entry point.
pub const TARGETS: &[(&str, Target)] = &[
    ("assembly_identity", assembly_identity),
    ("assemblyview", assemblyview),
    ("cdi_blob", cdi_blob),
    ("cilobject", cilobject),
    ("codec_method_body", codec_method_body),
    ("codec_named_arguments", codec_named_arguments),
    ("codec_native_type", codec_native_type),
    ("codec_permissions", codec_permissions),
    ("codec_signatures", codec_signatures),
    ("customattributes", customattributes),
    ("deobfuscate_bounded", deobfuscate_bounded),
    ("emulate_template", emulate_template),
    ("emulation", emulation),
    ("il_pipeline", il_pipeline),
    ("marshal", marshal),
    ("methodbody", methodbody),
    ("methodbody_eh", methodbody_eh),
    ("pdb_blobs", pdb_blobs),
    ("pe_file", pe_file),
    ("permission_set", permission_set),
    ("resources", resources),
    ("signatures", signatures),
    ("writer_roundtrip", writer_roundtrip),
];

/// An input loaded as a [`CilAssemblyView`].
pub fn assemblyview(data: &[u8]) {
    let _ = CilAssemblyView::from_mem(data.to_vec());
}

/// An input loaded as a [`CilObject`], and what loading leaves to be computed when asked:
/// each method's control flow graph and each embedded resource's entries.
pub fn cilobject(data: &[u8]) {
    let Ok(assembly) = CilObject::from_mem(data.to_vec()) else {
        return;
    };
    for entry in assembly.methods().iter() {
        let _ = entry.value().cfg();
    }
    let resources = assembly.resources();
    for entry in resources.iter() {
        let _ = resources.parse_dotnet_resource(entry.value());
    }
}

/// An input parsed as a custom attribute value with no constructor parameters.
pub fn customattributes(data: &[u8]) {
    let _ = parse_custom_attribute_data(data, &ParamList::new());
}

/// An input loaded as an assembly whose first methods are emulated with no arguments, within
/// an instruction and call depth budget.
pub fn emulation(data: &[u8]) {
    let Ok(assembly) = CilObject::from_mem(data.to_vec()) else {
        return;
    };
    let tokens: Vec<Token> = assembly
        .methods()
        .iter()
        .take(MAX_METHODS)
        .map(|entry| *entry.key())
        .collect();
    if tokens.is_empty() {
        return;
    }
    let Ok(process) = process_builder()
        .assembly(assembly)
        .with_max_instructions(MAX_INSTRUCTIONS)
        .with_max_call_depth(MAX_CALL_DEPTH)
        .build()
    else {
        return;
    };
    for token in tokens {
        let _ = process.execute_method(token, Vec::new());
    }
}

/// An input parsed as a method body, and decoded as code.
pub fn methodbody(data: &[u8]) {
    let _ = MethodBody::from(data);
    if !data.is_empty() {
        let limit = data.len().min(MAX_DECODE_BYTES);
        let _ = decode_blocks(data, 0, 0x2000, Some(limit));
    }
}

/// Asserts that `value`, decoded from some bytes, is what decoding `encode`'s bytes for it
/// gives, when `encode` accepts it.
fn decodes_back<T: PartialEq + std::fmt::Debug>(
    what: &str,
    value: &T,
    encode: impl Fn(&T) -> Result<Vec<u8>>,
    decode: impl Fn(&[u8]) -> Result<T>,
) {
    let Ok(bytes) = encode(value) else {
        return;
    };
    match decode(&bytes) {
        Ok(again) => assert_eq!(&again, value, "{what} encodes as {bytes:02x?}"),
        Err(error) => {
            panic!("{what} {value:?} encodes as {bytes:02x?}, which does not decode: {error}")
        }
    }
}

/// An input parsed by every signature parser, and each signature read encoded and read
/// again. The parsers share one reader, so one input reaches several, and the values are
/// dropped too, where a recursive `Drop` would fail.
pub fn signatures(data: &[u8]) {
    if let Ok(signature) = parse_method_signature(data) {
        decodes_back(
            "a method signature",
            &signature,
            encode_method_signature,
            parse_method_signature,
        );
    }
    if let Ok(signature) = parse_field_signature(data) {
        decodes_back(
            "a field signature",
            &signature,
            encode_field_signature,
            parse_field_signature,
        );
    }
    if let Ok(signature) = parse_property_signature(data) {
        decodes_back(
            "a property signature",
            &signature,
            encode_property_signature,
            parse_property_signature,
        );
    }
    if let Ok(signature) = parse_local_var_signature(data) {
        decodes_back(
            "a local variable signature",
            &signature,
            encode_local_var_signature,
            parse_local_var_signature,
        );
    }
    if let Ok(signature) = parse_type_spec_signature(data) {
        decodes_back(
            "a type specification",
            &signature,
            encode_typespec_signature,
            parse_type_spec_signature,
        );
    }
    if let Ok(signature) = parse_method_spec_signature(data) {
        decodes_back(
            "a method instantiation",
            &signature,
            encode_method_spec_signature,
            parse_method_spec_signature,
        );
    }
}

/// An input parsed as a `.resources` file, owned and borrowing: both read the same names.
pub fn resources(data: &[u8]) {
    match (parse_dotnet_resource(data), parse_dotnet_resource_ref(data)) {
        (Ok(owned), Ok(borrowed)) => assert!(
            owned.keys().eq(borrowed.keys()),
            "the owned and borrowing readers read different resource names"
        ),
        (Err(_), Err(_)) => {}
        (owned, borrowed) => panic!(
            "one reader reads the resources and the other does not: owned {:?}, borrowing {:?}",
            owned.err(),
            borrowed.err()
        ),
    }
}

/// An input read as an assembly display name: one that parses is written as a display name
/// that parses back to it.
pub fn assembly_identity(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let Ok(identity) = AssemblyIdentity::parse(&text) else {
        return;
    };
    let name = identity.display_name();
    match AssemblyIdentity::parse(&name) {
        Ok(again) => assert_eq!(again, identity, "{text:?} is written as {name:?}"),
        Err(error) => panic!("{text:?} is written as {name:?}, which does not parse: {error}"),
    }
}

/// An input loaded as a PE file, and every section's edges mapped: an RVA in the file reads
/// that file byte and maps back to itself, one in a zero-filled part reads zero, and one the
/// image does not define reads nothing. Then the `.rsrc` section is relocated as the writer
/// relocates it.
pub fn pe_file(data: &[u8]) {
    let Ok(file) = File::from_mem(data.to_vec()) else {
        return;
    };
    let map = file.section_map();
    for section in file.sections() {
        let start = section.virtual_address;
        let ends = [section.virtual_size, section.size_of_raw_data];
        let mut probes = vec![start.wrapping_sub(1), start];
        for end in ends {
            probes.push(start.wrapping_add(end).wrapping_sub(1));
            probes.push(start.wrapping_add(end));
        }
        for rva in probes {
            match map.map(rva) {
                RvaMapping::File(offset) => {
                    assert_eq!(
                        file.rva_to_offset(rva as usize).ok(),
                        Some(offset),
                        "RVA {rva:#x}"
                    );
                    let byte = file.data().get(offset).copied();
                    assert!(
                        byte.is_some(),
                        "RVA {rva:#x} maps past the file to {offset:#x}"
                    );
                    assert_eq!(
                        file.rva_slice(rva as usize, 1).ok().map(|bytes| bytes[0]),
                        byte,
                        "RVA {rva:#x}"
                    );
                    assert_eq!(
                        file.section_bounded(rva as usize)
                            .ok()
                            .and_then(|bytes| bytes.first().copied()),
                        byte,
                        "RVA {rva:#x}"
                    );
                    if let Some(back) = map.offset_to_rva(offset) {
                        assert_eq!(
                            map.map(back),
                            RvaMapping::File(offset),
                            "offset {offset:#x}"
                        );
                    }
                }
                RvaMapping::ZeroFill => {
                    assert!(file.rva_to_offset(rva as usize).is_err(), "RVA {rva:#x}");
                    assert_eq!(
                        file.rva_slice(rva as usize, 1).ok().map(|bytes| bytes[0]),
                        Some(0),
                        "RVA {rva:#x}"
                    );
                }
                RvaMapping::Unmapped => {
                    assert!(file.rva_to_offset(rva as usize).is_err(), "RVA {rva:#x}");
                    assert!(file.rva_slice(rva as usize, 1).is_err(), "RVA {rva:#x}");
                }
            }
        }
    }
    if let Some(rsrc) = file.sections().iter().find(|s| s.name.starts_with(".rsrc")) {
        let (_, bytes) = map.contents(file.data(), rsrc);
        let mut copy = bytes.to_vec();
        let _ = relocate_resource_section(
            &mut copy,
            rsrc.virtual_address,
            rsrc.virtual_address.wrapping_add(0x1000),
        );
    }
}

/// An input parsed as a marshalling descriptor, encoded and read again.
pub fn marshal(data: &[u8]) {
    if let Ok(info) = parse_marshalling_descriptor(data) {
        decodes_back(
            "a marshalling descriptor",
            &info,
            encode_marshalling_descriptor,
            parse_marshalling_descriptor,
        );
    }
}

/// An input parsed as a permission set, encoded in its own format and read again.
pub fn permission_set(data: &[u8]) {
    let Ok(set) = PermissionSet::new(data) else {
        return;
    };
    let format = *set.format();
    let Ok(bytes) = encode_permission_set(set.permissions(), format) else {
        return;
    };
    match PermissionSet::new(&bytes) {
        Ok(again) => assert_eq!(
            format!("{:?}", again.permissions()),
            format!("{:?}", set.permissions()),
            "a permission set encodes as {bytes:02x?}"
        ),
        Err(error) => {
            panic!("a permission set encodes as {bytes:02x?}, which does not decode: {error}")
        }
    }
}

/// An input parsed as each kind of custom debug information blob: a value that decodes
/// encodes back to one that decodes the same, and an embedded source inflates no further than
/// it states.
pub fn cdi_blob(data: &[u8]) {
    for kind in [
        CustomDebugKind::StateMachineHoistedLocalScopes,
        CustomDebugKind::DynamicLocalVariables,
        CustomDebugKind::DefaultNamespace,
        CustomDebugKind::EncLocalSlotMap,
        CustomDebugKind::EncLambdaAndClosureMap,
        CustomDebugKind::EncStateMachineStateMap,
        CustomDebugKind::EmbeddedSource,
        CustomDebugKind::SourceLink,
        CustomDebugKind::CompilationMetadataReferences,
        CustomDebugKind::CompilationOptions,
        CustomDebugKind::TupleElementNames,
        CustomDebugKind::TypeDefinitionDocuments,
        CustomDebugKind::AsyncMethodSteppingInformation,
        CustomDebugKind::PrimaryConstructorInformation,
        CustomDebugKind::Unknown(uguid::Guid::ZERO),
    ] {
        let Ok(info) = parse_custom_debug_blob(data, kind) else {
            continue;
        };
        if let Some(Ok(source)) = info.embedded_source_bytes() {
            if let CustomDebugInfo::EmbeddedSource { format, .. } = &info {
                assert!(*format == 0 || source.len() == format.unsigned_abs() as usize);
            }
        }
        if let Ok(encoded) = encode_custom_debug_blob(&info) {
            assert_eq!(
                parse_custom_debug_blob(&encoded, kind).ok().as_ref(),
                Some(&info),
                "{kind:?} encodes {data:02x?} as {encoded:02x?}, which decodes otherwise"
            );
        }
    }
}

/// An input parsed as each Portable PDB blob: a local constant and sequence points that
/// decode encode back to bytes that decode to the same encoding (bytes, not values, are
/// compared, since a NaN constant is not equal to itself), and a document name and imports
/// read against the input as a `#Blob` heap.
pub fn pdb_blobs(data: &[u8]) {
    if let Ok(constant) = LocalConstantSig::parse(data) {
        if let Ok(bytes) = constant.encode() {
            let again = LocalConstantSig::parse(&bytes)
                .unwrap_or_else(|e| panic!("{constant:?} encodes as {bytes:02x?}: {e}"));
            assert_eq!(again.encode().ok(), Some(bytes), "{data:02x?}");
        }
    }
    for document in [0, 1] {
        let Ok(points) = parse_sequence_points(data, document) else {
            continue;
        };
        if let Ok(bytes) = points.to_bytes(document) {
            let again = parse_sequence_points(&bytes, document)
                .unwrap_or_else(|e| panic!("{points:?} encodes as {bytes:02x?}: {e}"));
            assert_eq!(again, points, "{data:02x?} with document {document}");
        }
    }
    if let Ok(blobs) = Blob::from(data) {
        let _ = document_name(data, &blobs);
        let _ = parse_imports_blob(data, &blobs);
    }
}

/// An input parsed as a method body with its exception sections, every way the crate reads
/// one; the code decoded from each handler as well as the first instruction; and the body
/// written and read again, to the same header and clauses.
pub fn methodbody_eh(data: &[u8]) {
    let _ = MethodBody::from_lenient(data);
    let _ = MethodBody::from_raw(data);
    let Ok(body) = MethodBody::from(data) else {
        return;
    };
    let Some(code) = data.get(body.size_header..body.size_header + body.size_code) else {
        return;
    };
    let _ = decode_blocks_with_handlers(
        code,
        0,
        0x2000,
        Some(code.len().min(MAX_DECODE_BYTES)),
        &body.exception_handlers,
    );
    writes_back(&body, code);
}

/// Asserts that `body` with `code`, written, reads back as the same header and clauses, when
/// the writer accepts it.
fn writes_back(body: &MethodBody, code: &[u8]) {
    let mut bytes = Vec::new();
    if body.write_to(&mut bytes, code).is_err() {
        return;
    }
    let again = MethodBody::from(&bytes).unwrap_or_else(|error| {
        panic!("a body writes as {bytes:02x?}, which does not decode: {error}")
    });
    let header = |b: &MethodBody| {
        (
            b.is_fat,
            b.size_code,
            b.max_stack,
            b.local_var_sig_token,
            b.is_init_local,
        )
    };
    assert_eq!(
        header(&again),
        header(body),
        "a body writes as {bytes:02x?}"
    );
    let clauses = |b: &MethodBody| -> Vec<_> {
        b.exception_handlers
            .iter()
            .map(|h| {
                (
                    h.flags,
                    h.try_offset,
                    h.try_length,
                    h.handler_offset,
                    h.handler_length,
                    h.filter_offset,
                )
            })
            .collect()
    };
    assert_eq!(
        clauses(&again),
        clauses(body),
        "a body writes as {bytes:02x?}"
    );
}

/// The template's bytes and, loaded, the methods code can be spliced into.
struct Template {
    bytes: Vec<u8>,
    /// Each method's row, its local signature token and how many arguments it takes, `this`
    /// included, in row order.
    methods: Vec<(u32, u32, usize)>,
}

fn template() -> &'static Template {
    static TEMPLATE_METHODS: OnceLock<Template> = OnceLock::new();
    TEMPLATE_METHODS.get_or_init(|| {
        let bytes = fixture_bytes(TEMPLATE).to_vec();
        let assembly = CilObject::from_mem(bytes.clone()).expect("the template loads");
        let mut methods: Vec<(u32, u32, usize)> = assembly
            .methods()
            .iter()
            .filter_map(|entry| {
                let method = entry.value();
                let body = method.body.get()?;
                let arguments =
                    method.signature.params.len() + usize::from(method.signature.has_this);
                Some((method.token.row(), body.local_var_sig_token, arguments))
            })
            .collect();
        methods.sort_unstable();
        Template { bytes, methods }
    })
}

/// Fuzzed code spliced into a method of a real assembly ([`TEMPLATE`]), which is written,
/// loaded and run with fuzzed arguments within an instruction budget. The input's first two
/// bytes pick the method, then each argument takes a kind byte (`I4`, `I8`, `R8` or null) and
/// eight value bytes, and the rest is the code.
pub fn emulate_template(data: &[u8]) {
    let Template { bytes, methods } = template();
    let Some((&[low, high], mut rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let pick = usize::from(u16::from_le_bytes([low, high])) % methods.len();
    let (rid, locals, count) = methods[pick];
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let Some((&[kind, value @ ..], tail)) = rest.split_first_chunk::<9>() else {
            return;
        };
        rest = tail;
        args.push(match kind % 4 {
            0 => EmValue::I32(i64::from_le_bytes(value) as i32),
            1 => EmValue::I64(i64::from_le_bytes(value)),
            2 => EmValue::F64(f64::from_le_bytes(value)),
            _ => EmValue::Null,
        });
    }
    let code = rest;
    let Ok(code_size) = u32::try_from(code.len()) else {
        return;
    };
    let Ok(mut body) = encode_method_body_header(code_size, 16, locals, false, true) else {
        return;
    };
    body.extend_from_slice(code);
    let Ok(view) = CilAssemblyView::from_mem(bytes.clone()) else {
        return;
    };
    let Some(row) = view
        .tables()
        .and_then(|tables| tables.table::<MethodDefRaw>())
        .and_then(|table| table.get(rid).ok().flatten())
    else {
        return;
    };
    let mut assembly = CilAssembly::new(view);
    let rva = assembly.store_method_body(body);
    if assembly
        .table_row_update(
            TableId::MethodDef,
            rid,
            TableDataOwned::MethodDef(MethodDefRaw { rva, ..row }),
        )
        .is_err()
    {
        return;
    }
    let Ok(written) = assembly.to_memory() else {
        return;
    };
    let Ok(object) = CilObject::from_mem(written) else {
        return;
    };
    let Ok(process) = process_builder()
        .assembly(object)
        .with_max_instructions(MAX_INSTRUCTIONS)
        .with_max_call_depth(MAX_CALL_DEPTH)
        .build()
    else {
        return;
    };
    let _ = process.execute_method(Token::new(0x0600_0000 | rid), args);
}

/// An input loaded as an assembly and written back unchanged: the written assembly holds
/// what the input held (its canonical dump), or the write refuses it.
pub fn writer_roundtrip(data: &[u8]) {
    let Ok(view) = CilAssemblyView::from_mem(data.to_vec()) else {
        return;
    };
    // What cannot be read compares as unreadable: the reason names where the reader looked,
    // which a writer is free to move
    let before = CanonicalDump::of(&view).without_reasons();
    let Ok(written) = CilAssembly::new(view).to_memory() else {
        return;
    };
    let after = match CilAssemblyView::from_mem(written) {
        Ok(view) => CanonicalDump::of(&view).without_reasons(),
        Err(error) => panic!("the assembly writes, but the output does not read back: {error}"),
    };
    let differences = before.diff(&after);
    assert!(
        differences.is_empty(),
        "written back, the assembly holds something else:\n{}",
        differences.join("\n")
    );
}

/// An input parsed as a method body whose code is lifted to SSA, with the input's first two
/// bytes as how many arguments and locals it has (every one an `int32`): SSA that lifts
/// verifies, and code generated from it computes what it computes.
pub fn il_pipeline(data: &[u8]) {
    let Some((&[arguments, locals], body)) = data.split_first_chunk::<2>() else {
        return;
    };
    let Ok(header) = MethodBody::from(body) else {
        return;
    };
    let Some(code) = body.get(header.size_header..header.size_header + header.size_code) else {
        return;
    };
    let types = TestTypeProvider::all_i32(usize::from(arguments % 8), usize::from(locals % 8));
    let Ok(ssa) = crate::testkit::build_ssa_with_handlers(code, &header.exception_handlers, &types)
    else {
        return;
    };
    let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
    assert!(
        errors.is_empty(),
        "the code lifts to SSA the verifier rejects: {:?}\n{ssa}",
        errors.first()
    );
    if let Equivalence::Differs(difference) = regenerate_and_compare(&ssa) {
        panic!("the regenerated code computes something else: {difference}\n{ssa}");
    }
}

/// An input deobfuscated by the engine with a small budget: a few emulations of a few
/// instructions each, and one round of each fixpoint the pipeline iterates, so an input is a
/// pass over the pipeline rather than its convergence (a 248 KiB assembly took 6 minutes under
/// the default rounds with the fuzzer's instrumentation).
pub fn deobfuscate_bounded(data: &[u8]) {
    let mut config = EngineConfig::default();
    config.emulation.max_instructions = MAX_INSTRUCTIONS;
    config.emulation.max_emulations = MAX_EMULATIONS;
    config.iterations.max_ssa_iterations = 1;
    config.iterations.max_phase_iterations = 1;
    config.iterations.max_detection_rounds = 1;
    config.iterations.max_outer_iterations = 1;
    config.iterations.max_pipeline_iterations = 1;
    let _ = engine_with(config).process_bytes(data.to_vec());
}

/// Signatures generated from the input (`testkit::arb`): each encodes to what it decodes from.
pub fn codec_signatures(data: &[u8]) {
    if let Some(signature) = arb::from_bytes(&arb::method_signature(), data) {
        decodes_back(
            "a method signature",
            &signature,
            encode_method_signature,
            parse_method_signature,
        );
    }
    if let Some(signature) = arb::from_bytes(&arb::field_signature(), data) {
        decodes_back(
            "a field signature",
            &signature,
            encode_field_signature,
            parse_field_signature,
        );
    }
    if let Some(signature) = arb::from_bytes(&arb::local_var_signature(), data) {
        decodes_back(
            "a local variable signature",
            &signature,
            encode_local_var_signature,
            parse_local_var_signature,
        );
    }
    if let Some(signature) = arb::from_bytes(&arb::type_spec_signature(), data) {
        decodes_back(
            "a type specification",
            &signature,
            encode_typespec_signature,
            parse_type_spec_signature,
        );
    }
    if let Some(signature) = arb::from_bytes(&arb::method_spec_signature(), data) {
        decodes_back(
            "a method instantiation",
            &signature,
            encode_method_spec_signature,
            parse_method_spec_signature,
        );
    }
}

/// A marshalling descriptor generated from the input: it encodes to what it decodes from.
pub fn codec_native_type(data: &[u8]) {
    if let Some(primary_type) = arb::from_bytes(&arb::native_type(), data) {
        decodes_back(
            "a marshalling descriptor",
            &MarshallingInfo { primary_type },
            encode_marshalling_descriptor,
            parse_marshalling_descriptor,
        );
    }
}

/// Permissions generated from the input: in either format they encode to what they decode
/// from.
pub fn codec_permissions(data: &[u8]) {
    let Some(permissions) = arb::from_bytes(&arb::permissions(), data) else {
        return;
    };
    let Ok(bytes) = encode_permission_set(&permissions, PermissionSetFormat::Binary) else {
        return;
    };
    match PermissionSet::new(&bytes) {
        Ok(set) => assert_eq!(
            format!("{:?}", set.permissions()),
            format!("{permissions:?}"),
            "permissions encode as {bytes:02x?}"
        ),
        Err(error) => panic!("permissions encode as {bytes:02x?}, which does not decode: {error}"),
    }
}

/// Named custom attribute arguments generated from the input: they encode to what they decode
/// from.
pub fn codec_named_arguments(data: &[u8]) {
    let Some(named_args) = arb::from_bytes(
        &proptest::collection::vec(arb::named_argument(), 0..5),
        data,
    ) else {
        return;
    };
    let value = CustomAttributeValue {
        fixed_args: Vec::new(),
        named_args,
        constructor: CilTypeReference::None,
        blob_index: 0,
    };
    let Ok(bytes) = encode_custom_attribute_value(&value) else {
        return;
    };
    match parse_custom_attribute_data(&bytes, &ParamList::new()) {
        Ok(decoded) => assert_eq!(
            format!("{:?}", decoded.named_args),
            format!("{:?}", value.named_args),
            "named arguments encode as {bytes:02x?}"
        ),
        Err(error) => {
            panic!("named arguments encode as {bytes:02x?}, which do not decode: {error}")
        }
    }
}

/// A method body generated from the input: it writes to what it reads from.
pub fn codec_method_body(data: &[u8]) {
    if let Some((body, code)) = arb::from_bytes(&arb::method_body(), data) {
        writes_back(&body, &code);
    }
}

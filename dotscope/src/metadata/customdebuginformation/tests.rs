//! Custom debug information blobs the C# and Visual Basic compilers wrote for the PDB probes
//! (`tests/samples/factory/generators/PdbProbe` and `PdbProbeVb`), as System.Reflection.Metadata
//! read them: each decodes to what the probe's source says, and encodes back to its bytes.

use std::io::Write;

use super::*;

fn hex(text: &str) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split('-')
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

/// Decodes `blob` as `kind`, checks it against `expected`, and that it encodes back to `blob`.
fn round_trip(kind: CustomDebugKind, blob: &[u8], expected: &CustomDebugInfo) {
    let info = parse_custom_debug_blob(blob, kind).unwrap();
    assert_eq!(&info, expected, "{kind:?}");
    assert_eq!(info.kind(), kind);
    assert_eq!(encode_custom_debug_blob(&info).unwrap(), blob, "{kind:?}");
}

#[test]
fn the_probes_blobs_decode_to_their_source() {
    // Program.Main's local slots: the async state, then four user-declared locals
    round_trip(
        CustomDebugKind::EncLocalSlotMap,
        &hex("1F-01-01-13-01-81-56-01-33-01-78"),
        &CustomDebugInfo::EncLocalSlotMap(vec![
            Some(EncLocalSlot {
                kind: 0x1F,
                syntax_offset: 0,
                ordinal: None,
            }),
            Some(EncLocalSlot {
                kind: 1,
                syntax_offset: 18,
                ordinal: None,
            }),
            Some(EncLocalSlot {
                kind: 1,
                syntax_offset: 341,
                ordinal: None,
            }),
            Some(EncLocalSlot {
                kind: 1,
                syntax_offset: 50,
                ordinal: None,
            }),
            Some(EncLocalSlot {
                kind: 1,
                syntax_offset: 119,
                ordinal: None,
            }),
        ]),
    );
    // Async.Compute's one closure and its two lambdas
    round_trip(
        CustomDebugKind::EncLambdaAndClosureMap,
        &hex("01-01-01-01-81-2E-02-81-64-02"),
        &CustomDebugInfo::EncLambdaAndClosureMap {
            method_ordinal: 0,
            closures: vec![0],
            lambdas: vec![
                EncLambda {
                    syntax_offset: 301,
                    closure: 2,
                },
                EncLambda {
                    syntax_offset: 355,
                    closure: 2,
                },
            ],
        },
    );
    round_trip(
        CustomDebugKind::EncStateMachineStateMap,
        &hex("01-00-00-80-97"),
        &CustomDebugInfo::EncStateMachineStateMap(vec![EncStateMachineState {
            state: 0,
            syntax_offset: 151,
        }]),
    );
    round_trip(
        CustomDebugKind::SourceLink,
        b"{\"documents\":{\"/_/*\":\"https://example.invalid/dotscope/pdbprobe/*\"}}\n",
        &CustomDebugInfo::SourceLink(
            "{\"documents\":{\"/_/*\":\"https://example.invalid/dotscope/pdbprobe/*\"}}\n"
                .to_string(),
        ),
    );
    round_trip(
        CustomDebugKind::TypeDefinitionDocuments,
        &hex("05"),
        &CustomDebugInfo::TypeDefinitionDocuments(vec![5]),
    );
    // `dynamic value` and `dynamic[] values`
    round_trip(
        CustomDebugKind::DynamicLocalVariables,
        &hex("01"),
        &CustomDebugInfo::DynamicLocalVariables(vec![1]),
    );
    let array =
        parse_custom_debug_blob(&hex("02"), CustomDebugKind::DynamicLocalVariables).unwrap();
    assert!(!array.is_dynamic(0) && array.is_dynamic(1) && !array.is_dynamic(9));
    round_trip(
        CustomDebugKind::TupleElementNames,
        b"first\0second\0",
        &CustomDebugInfo::TupleElementNames(vec![
            Some("first".to_string()),
            Some("second".to_string()),
        ]),
    );
    round_trip(
        CustomDebugKind::TupleElementNames,
        b"a\0nested\0b\0c\0",
        &CustomDebugInfo::TupleElementNames(
            ["a", "nested", "b", "c"]
                .iter()
                .map(|name| Some((*name).to_string()))
                .collect(),
        ),
    );
    round_trip(
        CustomDebugKind::PrimaryConstructorInformation,
        b"",
        &CustomDebugInfo::PrimaryConstructorInformation,
    );
    round_trip(
        CustomDebugKind::AsyncMethodSteppingInformation,
        &hex("00-00-00-00-5A-00-00-00-79-00-00-00-1F"),
        &CustomDebugInfo::AsyncMethodSteppingInformation {
            catch_handler: None,
            awaits: vec![AsyncAwait {
                yield_offset: 0x5A,
                resume_offset: 0x79,
                method: 0x1F,
            }],
        },
    );
    round_trip(
        CustomDebugKind::StateMachineHoistedLocalScopes,
        &hex("20-00-00-00-57-00-00-00-29-00-00-00-2C-00-00-00"),
        &CustomDebugInfo::StateMachineHoistedLocalScopes(vec![
            HoistedLocalScope {
                start: 0x20,
                length: 0x57,
            },
            HoistedLocalScope {
                start: 0x29,
                length: 0x2C,
            },
        ]),
    );
    // The Visual Basic probe's RootNamespace
    round_trip(
        CustomDebugKind::DefaultNamespace,
        b"VbProbe.Root",
        &CustomDebugInfo::DefaultNamespace("VbProbe.Root".to_string()),
    );
}

/// Compilation options and metadata references in the formats the specification gives.
#[test]
fn compilation_records_round_trip() {
    let options = b"language\0CSharp\0compiler-version\x005.0.0-dev\0";
    round_trip(
        CustomDebugKind::CompilationOptions,
        options,
        &CustomDebugInfo::CompilationOptions(vec![
            ("language".to_string(), "CSharp".to_string()),
            ("compiler-version".to_string(), "5.0.0-dev".to_string()),
        ]),
    );

    let mut reference = b"Microsoft.CSharp.dll\0global,probelib\0\x01".to_vec();
    reference.extend_from_slice(&0xC7D2_4DD6u32.to_le_bytes());
    reference.extend_from_slice(&0x8000u32.to_le_bytes());
    reference.extend_from_slice(&[7; 16]);
    round_trip(
        CustomDebugKind::CompilationMetadataReferences,
        &reference,
        &CustomDebugInfo::CompilationMetadataReferences(vec![MetadataReferenceInfo {
            file_name: "Microsoft.CSharp.dll".to_string(),
            aliases: vec!["global".to_string(), "probelib".to_string()],
            flags: 1,
            timestamp: 0xC7D2_4DD6,
            image_size: 0x8000,
            mvid: uguid::Guid::from_bytes([7; 16]),
        }]),
    );
}

/// An embedded source keeps its deflated bytes until its text is asked for, which inflates
/// no further than the size it states.
#[test]
fn embedded_sources_inflate_to_their_stated_size() {
    let text = "using System;\n\nclass Program { }\n".repeat(20);
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(text.as_bytes()).unwrap();
    let deflated = encoder.finish().unwrap();

    let source = |format: i32| CustomDebugInfo::EmbeddedSource {
        format,
        content: deflated.clone(),
    };
    let stated = source(i32::try_from(text.len()).unwrap());
    assert_eq!(stated.embedded_source_text().unwrap().unwrap(), text);
    let blob = encode_custom_debug_blob(&stated).unwrap();
    assert_eq!(
        parse_custom_debug_blob(&blob, CustomDebugKind::EmbeddedSource).unwrap(),
        stated
    );

    // A size short of the content, or past it, is refused; a negative format is reserved
    assert!(source(10).embedded_source_bytes().unwrap().is_err());
    assert!(source(i32::try_from(text.len() + 1).unwrap())
        .embedded_source_bytes()
        .unwrap()
        .is_err());
    assert!(source(-1).embedded_source_bytes().unwrap().is_err());

    // Stored as it is, with a UTF-8 byte order mark
    let raw = CustomDebugInfo::EmbeddedSource {
        format: 0,
        content: b"\xEF\xBB\xBFclass A { }".to_vec(),
    };
    assert_eq!(raw.embedded_source_text().unwrap().unwrap(), "class A { }");
    assert!(CustomDebugInfo::SourceLink(String::new())
        .embedded_source_text()
        .is_none());
}

/// Kinds round-trip through their GUIDs, and an unknown kind keeps its blob.
#[test]
fn kinds_and_unknown_blobs() {
    for kind in [
        CustomDebugKind::StateMachineHoistedLocalScopes,
        CustomDebugKind::EncLocalSlotMap,
        CustomDebugKind::PrimaryConstructorInformation,
        CustomDebugKind::CompilationOptions,
    ] {
        assert_eq!(CustomDebugKind::from_guid(kind.guid()), kind);
    }
    assert_eq!(
        CustomDebugKind::CompilationOptions.guid(),
        uguid::guid!("B5FEEC05-8CD0-4A83-96DA-466284BB4BD8")
    );
    let other = uguid::guid!("01234567-89AB-CDEF-0123-456789ABCDEF");
    let kind = CustomDebugKind::from_guid(other);
    assert_eq!(kind, CustomDebugKind::Unknown(other));
    round_trip(
        kind,
        &[1, 2, 3],
        &CustomDebugInfo::Unknown {
            kind: other,
            data: vec![1, 2, 3],
        },
    );
}

/// Blobs out of their kind's format are refused, not read as something else.
#[test]
fn malformed_blobs_are_refused() {
    for (kind, blob) in [
        (
            CustomDebugKind::StateMachineHoistedLocalScopes,
            hex("01-00-00"),
        ),
        (
            CustomDebugKind::TupleElementNames,
            b"no terminator".to_vec(),
        ),
        (CustomDebugKind::CompilationOptions, b"name\0".to_vec()),
        (CustomDebugKind::SourceLink, hex("FF-FE")),
        (CustomDebugKind::PrimaryConstructorInformation, hex("00")),
        (CustomDebugKind::EncStateMachineStateMap, hex("02-00-00-01")),
        (
            CustomDebugKind::AsyncMethodSteppingInformation,
            hex("00-00"),
        ),
        (CustomDebugKind::EmbeddedSource, hex("00-00")),
    ] {
        assert!(
            parse_custom_debug_blob(&blob, kind).is_err(),
            "{kind:?} {blob:02x?}"
        );
    }
}

/// The summary helpers: known kinds, stored sizes, compression and display.
#[test]
fn summaries_describe_the_value() {
    let source = CustomDebugInfo::EmbeddedSource {
        format: 40,
        content: vec![0; 12],
    };
    assert!(source.is_known());
    assert_eq!(source.was_compressed(), Some(true));
    assert_eq!(source.data_size().unwrap(), 16);
    assert_eq!(
        source.to_string(),
        "EmbeddedSource(12 bytes, compressed from 40)"
    );
    assert_eq!(
        CustomDebugInfo::SourceLink(String::new()).was_compressed(),
        None
    );

    let other = uguid::guid!("01234567-89AB-CDEF-0123-456789ABCDEF");
    let unknown = CustomDebugInfo::Unknown {
        kind: other,
        data: vec![1, 2, 3],
    };
    assert!(!unknown.is_known());
    assert_eq!(unknown.data_size().unwrap(), 3);
    assert_eq!(CustomDebugKind::SourceLink.to_string(), "SourceLink");
    assert_eq!(
        CustomDebugKind::Unknown(other).to_string(),
        format!("Unknown({other})")
    );
}

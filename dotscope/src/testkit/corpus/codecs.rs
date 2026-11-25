//! Codec identities: every blob the corpus holds decodes and encodes back to its own bytes.
//!
//! A blob a writer re-encodes (a signature, after rows are renumbered) is written as its codec
//! encodes what its codec decoded. When that is not the blob, the write changes what the
//! assembly says.

use std::collections::BTreeMap;

use crate::{
    assembly::InstructionEncoder,
    cilassembly::{debug_blobs, signature_blobs, BlobKind, CilAssembly},
    metadata::{
        customattributes::encode_custom_attribute_value,
        customdebuginformation::{
            encode_custom_debug_blob, parse_custom_debug_blob, CustomDebugKind,
        },
        importscope::{encode_import_records, parse_import_records},
        marshalling::{encode_marshalling_descriptor, parse_marshalling_descriptor},
        method::{exception_structure_defects, MethodBody},
        pdb::{DocumentNameBlob, LocalConstantSig},
        security::{encode_permission_set, PermissionSet, PermissionSetFormat},
        sequencepoints::parse_sequence_points,
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_method_spec_signature, encode_property_signature, encode_typespec_signature,
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
            SIGNATURE_HEADER,
        },
        tables::{DeclSecurityRaw, FieldMarshalRaw, MethodDefRaw},
    },
    testkit::corpus::{CorpusCheck, CorpusItem},
    CilAssemblyView, Result,
};

/// How many blobs of one kind an assembly reports before it counts the rest.
const BLOBS_PER_KIND: usize = 3;

/// Every signature blob, and every Portable PDB blob whose content names rows or blobs,
/// decodes as the kind of the column that references it and encodes back to its own bytes:
/// these are the blobs a write re-encodes when the rows or blobs they name move.
pub struct Signatures;

impl CorpusCheck for Signatures {
    fn id(&self) -> &'static str {
        "codecs.signatures"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        if item.fixture.reject.is_some() {
            return Vec::new();
        }
        let Ok(view) = item
            .bytes()
            .and_then(|bytes| CilAssemblyView::from_mem(bytes).map_err(|error| error.to_string()))
        else {
            return Vec::new();
        };
        let Some(heap) = view.blobs().map(|blobs| blobs.data().to_vec()) else {
            return Vec::new();
        };
        let assembly = CilAssembly::new(view);
        let mut failing: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut typed = signature_blobs(&assembly);
        typed.extend(debug_blobs(&assembly));
        for (index, signature) in typed {
            let Ok(bytes) = blob_at(&heap, index as usize) else {
                failing
                    .entry(format!("{:?}", signature.kind))
                    .or_default()
                    .push(format!("blob {index:#x} lies past the heap"));
                continue;
            };
            let problem = match round_trip(signature.kind, bytes) {
                Err(error) => Some(format!("does not round-trip: {error}")),
                Ok(encoded) if encoded != bytes => {
                    Some(format!("{bytes:02x?} encodes back as {encoded:02x?}"))
                }
                Ok(_) => None,
            };
            if let Some(problem) = problem {
                failing
                    .entry(format!("{:?}", signature.kind))
                    .or_default()
                    .push(format!(
                        "blob {index:#x} ({}): {problem}",
                        signature.referrer
                    ));
            }
        }
        failing
            .into_iter()
            .flat_map(|(kind, mut blobs)| {
                let more = blobs.len().saturating_sub(BLOBS_PER_KIND);
                blobs.truncate(BLOBS_PER_KIND);
                if more > 0 {
                    blobs.push(format!("{more} more"));
                }
                blobs.into_iter().map(move |blob| format!("{kind} {blob}"))
            })
            .collect()
    }
}

/// Every custom attribute value encodes back to the blob it was read from.
pub struct CustomAttributes;

impl CorpusCheck for CustomAttributes {
    fn id(&self) -> &'static str {
        "codecs.custom_attributes"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Ok(assembly) = item.object() else {
            return Vec::new();
        };
        let Some(heap) = assembly.blob().map(|blobs| blobs.data()) else {
            return Vec::new();
        };
        let mut failing = Vec::new();
        for entry in assembly.custom_attributes().iter() {
            let attribute = entry.value();
            let index = attribute.value.blob_index;
            if index == 0 {
                continue;
            }
            let Ok(bytes) = blob_at(heap, index) else {
                failing.push(format!(
                    "{:?}: blob {index:#x} lies past the heap",
                    attribute.token
                ));
                continue;
            };
            match encode_custom_attribute_value(&attribute.value) {
                Err(error) => {
                    failing.push(format!("{:?}: does not encode: {error}", attribute.token))
                }
                Ok(encoded) if encoded != bytes => failing.push(format!(
                    "{:?}: {bytes:02x?} encodes back as {encoded:02x?}",
                    attribute.token
                )),
                Ok(_) => {}
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// Every marshalling descriptor (a FieldMarshal row's NativeType blob) decodes and encodes
/// back to its own bytes.
pub struct Marshalling;

impl CorpusCheck for Marshalling {
    fn id(&self) -> &'static str {
        "codecs.marshalling"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Some(metadata) = item.metadata() else {
            return Vec::new();
        };
        let (Some(tables), Some(blobs)) = (metadata.tables, metadata.blobs) else {
            return Vec::new();
        };
        let Some(table) = tables.table::<FieldMarshalRaw>() else {
            return Vec::new();
        };
        let mut failing = Vec::new();
        for row in table.iter().flatten() {
            let Ok(bytes) = blob_at(blobs.data(), row.native_type as usize) else {
                failing.push(format!(
                    "FieldMarshal[{}]: its blob lies past the heap",
                    row.rid
                ));
                continue;
            };
            match parse_marshalling_descriptor(bytes)
                .and_then(|info| encode_marshalling_descriptor(&info))
            {
                Err(error) => failing.push(format!(
                    "FieldMarshal[{}]: does not round-trip: {error}",
                    row.rid
                )),
                Ok(encoded) if encoded != bytes => failing.push(format!(
                    "FieldMarshal[{}]: {bytes:02x?} encodes back as {encoded:02x?}",
                    row.rid
                )),
                Ok(_) => {}
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// Every binary permission set (a DeclSecurity row's PermissionSet blob) decodes and encodes
/// back to its own bytes. An XML set is text, which a writer copies and never re-encodes: its
/// parse names the permissions and their values, not the text's layout.
pub struct PermissionSets;

impl CorpusCheck for PermissionSets {
    fn id(&self) -> &'static str {
        "codecs.permission_sets"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Some(metadata) = item.metadata() else {
            return Vec::new();
        };
        let (Some(tables), Some(blobs)) = (metadata.tables, metadata.blobs) else {
            return Vec::new();
        };
        let Some(table) = tables.table::<DeclSecurityRaw>() else {
            return Vec::new();
        };
        let mut failing = Vec::new();
        for row in table.iter().flatten() {
            let Ok(bytes) = blob_at(blobs.data(), row.permission_set as usize) else {
                failing.push(format!(
                    "DeclSecurity[{}]: its blob lies past the heap",
                    row.rid
                ));
                continue;
            };
            if bytes.first() != Some(&b'.') {
                continue;
            }
            let encoded = PermissionSet::new(bytes).and_then(|set| {
                encode_permission_set(set.permissions(), PermissionSetFormat::Binary)
            });
            match encoded {
                Err(error) => failing.push(format!(
                    "DeclSecurity[{}]: does not round-trip: {error}",
                    row.rid
                )),
                Ok(encoded) if encoded != bytes => failing.push(format!(
                    "DeclSecurity[{}]: {bytes:02x?} encodes back as {encoded:02x?}",
                    row.rid
                )),
                Ok(_) => {}
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// Every method body (a MethodDef row's RVA) decodes, and its header, code and exception
/// section encode back to its own bytes.
pub struct MethodBodies;

impl CorpusCheck for MethodBodies {
    fn id(&self) -> &'static str {
        "codecs.method_bodies"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        if item.fixture.reject.is_some() {
            return Vec::new();
        }
        let Ok(view) = item
            .bytes()
            .and_then(|bytes| CilAssemblyView::from_mem(bytes).map_err(|error| error.to_string()))
        else {
            return Vec::new();
        };
        let Some(table) = view
            .tables()
            .and_then(|tables| tables.table::<MethodDefRaw>())
        else {
            return Vec::new();
        };
        let file = view.file();
        let mut failing = Vec::new();
        for row in table.iter().flatten().filter(|row| row.rva != 0) {
            let Ok(data) = file.section_bounded(row.rva as usize) else {
                failing.push(format!(
                    "MethodDef[{}]: its RVA is not a byte of the image",
                    row.rid
                ));
                continue;
            };
            let encoded = MethodBody::from(data).and_then(|body| {
                let code = data
                    .get(body.size_header..body.size_header.saturating_add(body.size_code))
                    .ok_or_else(|| malformed_error!("its code runs past its section's data"))?;
                let mut encoded = Vec::new();
                body.write_to(&mut encoded, code)?;
                Ok(encoded)
            });
            match encoded {
                Err(error) => {
                    failing.push(format!(
                        "MethodDef[{}]: does not round-trip: {error}",
                        row.rid
                    ));
                }
                Ok(encoded) => {
                    let original = data.get(..encoded.len()).unwrap_or(data);
                    if let Some(at) = original
                        .iter()
                        .zip(&encoded)
                        .position(|(read, written)| read != written)
                        .or((original.len() != encoded.len()).then_some(original.len()))
                    {
                        let around = |bytes: &[u8]| {
                            bytes
                                .get(at.saturating_sub(4)..at.saturating_add(4).min(bytes.len()))
                                .map(<[u8]>::to_vec)
                                .unwrap_or_default()
                        };
                        failing.push(format!(
                            "MethodDef[{}]: byte {at} reads {:02x?}, writes {:02x?}",
                            row.rid,
                            around(original),
                            around(&encoded)
                        ));
                    }
                }
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// Every method's code encodes back to its own bytes from the instructions it decoded to:
/// each instruction at its place, branches and switches in their forms, and the bytes no
/// path reaches as they are.
pub struct BodyCode;

impl CorpusCheck for BodyCode {
    fn id(&self) -> &'static str {
        "bodies.code"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Ok(assembly) = item.object() else {
            return Vec::new();
        };
        let file = assembly.file();
        let mut failing = Vec::new();
        for entry in assembly.methods().iter() {
            let method = entry.value();
            let (Some(rva), Some(body), Some(blocks)) = (
                method.rva.filter(|rva| *rva != 0),
                method.body.get(),
                method.blocks.get(),
            ) else {
                continue;
            };
            let Some(code) = file.section_bounded(rva as usize).ok().and_then(|data| {
                data.get(body.size_header..body.size_header.checked_add(body.size_code)?)
            }) else {
                failing.push(format!(
                    "{:?}: its code lies outside its section's data",
                    method.token
                ));
                continue;
            };
            let instructions: Vec<_> = blocks
                .iter()
                .flat_map(|block| block.instructions.iter().cloned())
                .collect();
            let code_rva = u64::from(rva).saturating_add(body.size_header as u64);
            match InstructionEncoder::encode_decoded(&instructions, code, code_rva) {
                Err(error) => failing.push(format!(
                    "{:?} {}: does not encode: {error}",
                    method.token, method.name
                )),
                Ok(encoded) => {
                    if let Some(at) = code
                        .iter()
                        .zip(&encoded)
                        .position(|(read, written)| read != written)
                        .or((code.len() != encoded.len()).then_some(code.len().min(encoded.len())))
                    {
                        failing.push(format!(
                            "{:?} {}: code byte {at} reads {:02x?}, encodes as {:02x?}",
                            method.token,
                            method.name,
                            code.get(at..code.len().min(at.saturating_add(6))),
                            encoded.get(at..encoded.len().min(at.saturating_add(6)))
                        ));
                    }
                }
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// Every method's exception clauses structure its code as ECMA-335 requires (see
/// [`exception_structure_defects`]).
pub struct ExceptionStructure;

impl CorpusCheck for ExceptionStructure {
    fn id(&self) -> &'static str {
        "bodies.exception_structure"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Ok(assembly) = item.object() else {
            return Vec::new();
        };
        let mut failing = Vec::new();
        for entry in assembly.methods().iter() {
            let method = entry.value();
            let (Some(body), Some(blocks)) = (method.body.get(), method.blocks.get()) else {
                continue;
            };
            if body.exception_handlers.is_empty() {
                continue;
            }
            let instructions: Vec<_> = blocks
                .iter()
                .flat_map(|block| block.instructions.iter().cloned())
                .collect();
            for defect in exception_structure_defects(&instructions, &body.exception_handlers) {
                failing.push(format!("{:?} {}: {defect}", method.token, method.name));
            }
        }
        let more = failing.len().saturating_sub(BLOBS_PER_KIND);
        failing.truncate(BLOBS_PER_KIND);
        if more > 0 {
            failing.push(format!("{more} more"));
        }
        failing
    }
}

/// The blob at `index` of the blob heap `heap`, without its length.
fn blob_at(heap: &[u8], index: usize) -> std::result::Result<&[u8], ()> {
    let first = *heap.get(index).ok_or(())?;
    let (length, prefix) = match first {
        b if b & 0x80 == 0 => (usize::from(b), 1),
        b if b & 0xC0 == 0x80 => {
            let next = *heap.get(index + 1).ok_or(())?;
            ((usize::from(b & 0x3F) << 8) | usize::from(next), 2)
        }
        b if b & 0xE0 == 0xC0 => {
            let rest = heap.get(index + 1..index + 4).ok_or(())?;
            (
                (usize::from(b & 0x1F) << 24)
                    | (usize::from(rest[0]) << 16)
                    | (usize::from(rest[1]) << 8)
                    | usize::from(rest[2]),
                4,
            )
        }
        _ => return Err(()),
    };
    heap.get(index + prefix..index + prefix + length).ok_or(())
}

/// `bytes` decoded as `kind` and encoded again.
fn round_trip(kind: BlobKind, bytes: &[u8]) -> Result<Vec<u8>> {
    let header = bytes.first().copied();
    match (kind, header) {
        (BlobKind::Field, _) | (BlobKind::MemberRef, Some(SIGNATURE_HEADER::FIELD)) => {
            encode_field_signature(&parse_field_signature(bytes)?)
        }
        (BlobKind::StandAlone, Some(SIGNATURE_HEADER::LOCAL_SIG)) => {
            encode_local_var_signature(&parse_local_var_signature(bytes)?)
        }
        (BlobKind::StandAlone, Some(SIGNATURE_HEADER::FIELD)) => {
            encode_field_signature(&parse_field_signature(bytes)?)
        }
        (BlobKind::Method | BlobKind::MemberRef | BlobKind::StandAlone, _) => {
            encode_method_signature(&parse_method_signature(bytes)?)
        }
        (BlobKind::Property, _) => encode_property_signature(&parse_property_signature(bytes)?),
        (BlobKind::TypeSpec, _) => encode_typespec_signature(&parse_type_spec_signature(bytes)?),
        (BlobKind::MethodSpec, _) => {
            encode_method_spec_signature(&parse_method_spec_signature(bytes)?)
        }
        (BlobKind::DocumentName, _) => DocumentNameBlob::parse(bytes)?.encode(),
        (BlobKind::SequencePoints { document }, _) => {
            parse_sequence_points(bytes, document)?.to_bytes(document)
        }
        (BlobKind::LocalConstant, _) => LocalConstantSig::parse(bytes)?.encode(),
        (BlobKind::Imports, _) => encode_import_records(&parse_import_records(bytes)?),
        (BlobKind::TypeDefinitionDocuments, _) => encode_custom_debug_blob(
            &parse_custom_debug_blob(bytes, CustomDebugKind::TypeDefinitionDocuments)?,
        ),
        (BlobKind::AsyncMethodStepping, _) => encode_custom_debug_blob(&parse_custom_debug_blob(
            bytes,
            CustomDebugKind::AsyncMethodSteppingInformation,
        )?),
    }
}

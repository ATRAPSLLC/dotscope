//! JIEJIE.NET resource encryption detection and decryption.
//!
//! Detects and decrypts the resource interception infrastructure injected by
//! JIEJIE.NET, where `Assembly.GetManifestResourceStream` calls are redirected
//! through an encrypted dictionary cache.
//!
//! # Detection (SSA-based)
//!
//! Detection runs entirely in [`detect_ssa`](Technique::detect_ssa) after SSA
//! construction and CFF unflattening. This is superior to IL-level detection
//! because `SMF_GetContent` is typically CFF-obfuscated, making linear IL
//! scanning unreliable.
//!
//! The structural pattern:
//! - A **nested Stream subclass** with 10+ methods (the `Read`/`Write`/`Seek`/
//!   `Flush`/`Length`/`Position` property accessors compile to get_/set_ methods)
//! - The parent class contains **static methods** that accept `Class` (Assembly)
//!   + `String` parameters and return `Class` (Stream) — these are the
//!     interception points that replace direct resource access
//!
//! Resource entries are extracted from `SMF_GetContent`'s SSA via dataflow
//! analysis: `String.Equals` calls identify resource names, and successor
//! blocks contain `Call` to `ByteArrayDataContainer._N()` data methods.
//!
//! # Encryption Format
//!
//! Each resource is stored as an encrypted byte array accessed through
//! `ByteArrayDataContainer._N()` methods (FieldRVA-backed data):
//!
//! - `[4-byte LE gzipLen header] + [encrypted data]`
//! - If `gzipLen == 0`: data is XOR-only (no compression)
//! - If `gzipLen > 0`: data was GZip-compressed before encryption, gzipLen = original uncompressed length
//! - XOR key: single byte stored as `ldc.i4*` before `xor` in `SMF_ResStream.Read`
//!
//! # Pipeline Flow
//!
//! 1. `detect_ssa` (Phase 3.5+): structural detection, XOR key extraction,
//!    SSA-based resource entry extraction. Returns positive `Detection` with
//!    populated `ResourceFindings`.
//! 2. Engine sees new detection for a technique with `byte_transform`, sets
//!    `needs_byte_transform` flag on `AnalysisContext`.
//! 3. Pipeline iteration 2: `byte_transform` reads findings, decrypts FieldRVA
//!    data, inserts `ManifestResource` entries.

use std::{any::Any, collections::HashMap, sync::Arc};

use log::debug;

use crate::{
    analysis::{CilTarget, ConstValue, SsaFunction, SsaOp, SsaVarId},
    assembly::{Immediate, Operand},
    cilassembly::GeneratorConfig,
    compiler::{CompilerContext, EventKind, EventLog, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::jiejienet::{ResourceRestorationPass, ResourceTarget},
        techniques::{
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
        },
        utils::get_field_data_size,
    },
    error::Error,
    metadata::{
        signatures::TypeSignature,
        tables::{FieldRvaRaw, ManifestResourceAttributes, ManifestResourceBuilder},
        token::Token,
        typesystem::wellknown,
        validation::ValidationConfig,
    },
    utils::decompress_gzip,
    CilObject, Result,
};

/// Findings from resource encryption detection.
#[derive(Debug)]
pub struct ResourceFindings {
    /// Token of the class containing resource interception methods.
    pub host_type: Token,
    /// Token of the nested Stream subclass.
    pub stream_type: Token,
    /// Tokens of resource interception methods (redirect `GetManifestResourceStream`).
    pub interception_methods: Vec<Token>,
    /// Token of the `SMF_GetContent(string) -> byte[]` method.
    pub get_content_method: Option<Token>,
    /// XOR key extracted from `SMF_ResStream.Read`.
    pub xor_key: Option<u8>,
    /// Resource entries: (name, byte-array-method-token) pairs from SSA dataflow.
    pub resource_entries: Vec<ResourceEntry>,
    /// Pre-built redirect map from interception method token to original BCL target.
    pub redirects: HashMap<Token, ResourceTarget>,
}

/// A single encrypted resource entry discovered during detection.
#[derive(Debug)]
pub struct ResourceEntry {
    /// The resource name (from `String.Equals` in `SMF_GetContent` SSA).
    pub name: String,
    /// Token of the `ByteArrayDataContainer._N()` method that returns the encrypted data.
    pub data_method_token: Token,
}

/// Detects JIEJIE.NET resource encryption via SSA-based structural analysis.
pub struct JiejieNetResources;

impl Technique for JiejieNetResources {
    fn id(&self) -> &'static str {
        "jiejienet.resources"
    }

    fn name(&self) -> &'static str {
        "JIEJIE.NET Resource Encryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![
            TechniqueCapability::ByteTransform,
            TechniqueCapability::SsaPass,
        ]
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // Detection is fully SSA-based — see detect_ssa().
        // IL-level detection cannot reliably extract resource entries when
        // SMF_GetContent is CFF-obfuscated.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Structural detection: find the resource interception infrastructure
        let Some(structure) = detect_resource_structure(assembly) else {
            return Detection::new_empty();
        };

        let Some(get_content_token) = structure.get_content_method else {
            return Detection::new_empty();
        };

        // SSA-based resource entry extraction from unflattened SMF_GetContent
        let Some(ssa_ref) = ctx.ssa_functions.get(&get_content_token) else {
            return Detection::new_empty();
        };

        let entries = extract_resource_entries_ssa(&ssa_ref, assembly);
        if entries.is_empty() {
            return Detection::new_empty();
        }

        debug!(
            "JIEJIE.NET resources: SSA-detected {} resource entries in SMF_GetContent",
            entries.len()
        );

        // Collect data container types for cleanup
        let data_container_types: Vec<Token> = entries
            .iter()
            .filter_map(|entry| {
                assembly
                    .method(&entry.data_method_token)
                    .ok()
                    .and_then(|method| {
                        method
                            .declaring_type
                            .get()
                            .and_then(|type_ref| type_ref.token())
                    })
            })
            .collect();

        // Build the redirect map: interception method → original BCL call target
        let redirects = build_redirect_map(&structure.interception_methods, assembly);

        debug!(
            "JIEJIE.NET resources: built {} interception→BCL redirects during detection",
            redirects.len()
        );

        let evidence = vec![Evidence::Structural(format!(
            "Resource interception: nested Stream subclass + {} interception methods, {} resources (SSA)",
            structure.interception_methods.len(),
            entries.len(),
        ))];

        let findings = ResourceFindings {
            host_type: structure.host_type,
            stream_type: structure.stream_type,
            interception_methods: structure.interception_methods,
            get_content_method: structure.get_content_method,
            xor_key: structure.xor_key,
            resource_entries: entries,
            redirects,
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        detection.cleanup_mut().add_type(structure.stream_type);
        detection.cleanup_mut().add_type(structure.host_type);
        for type_token in data_container_types {
            detection.cleanup_mut().add_type(type_token);
        }

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<ResourceFindings>() else {
            return Some(Ok(events));
        };

        let Some(xor_key) = findings.xor_key else {
            log::warn!("JIEJIE.NET resources: no XOR key found, skipping decryption");
            return Some(Ok(events));
        };

        if findings.resource_entries.is_empty() {
            return Some(Ok(events));
        }

        // Build CilObject from current assembly bytes
        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let bytes = co.file().data().to_vec();
        let cilobject =
            match CilObject::from_mem_with_validation(bytes, ValidationConfig::analysis()) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

        // Extract and decrypt all resources
        let mut decrypted_resources = Vec::new();

        for entry in &findings.resource_entries {
            match extract_and_decrypt_resource(&cilobject, entry, xor_key) {
                Ok(data) => {
                    log::info!(
                        "JIEJIE.NET resources: decrypted '{}' ({} bytes)",
                        entry.name,
                        data.len()
                    );
                    decrypted_resources.push((entry.name.clone(), data));
                }
                Err(e) => {
                    log::warn!(
                        "JIEJIE.NET resources: failed to decrypt '{}': {}",
                        entry.name,
                        e
                    );
                }
            }
        }

        if decrypted_resources.is_empty() {
            events.record(EventKind::ArtifactRemoved).message(
                "Resource encryption detected but no resources could be decrypted".to_string(),
            );
            return Some(Ok(events));
        }

        // Insert decrypted resources into the assembly via CilAssembly
        let mut cil_assembly = cilobject.into_assembly();

        let mut inserted_count: usize = 0;
        for (name, data) in &decrypted_resources {
            let builder = ManifestResourceBuilder::new()
                .name(name)
                .flags(ManifestResourceAttributes::PUBLIC)
                .resource_data(data);

            match builder.build(&mut cil_assembly) {
                Ok(_) => {
                    inserted_count = inserted_count.saturating_add(1);
                    log::info!(
                        "JIEJIE.NET resources: inserted resource '{}' ({} bytes)",
                        name,
                        data.len()
                    );
                }
                Err(e) => {
                    log::warn!(
                        "JIEJIE.NET resources: failed to insert resource '{}': {}",
                        name,
                        e
                    );
                }
            }
        }

        if inserted_count > 0 {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Decrypted and restored {} embedded resource(s)",
                inserted_count,
            ));
        }

        // Rebuild PE with inserted resources
        let new_assembly = match cil_assembly
            .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        assembly.replace_assembly(new_assembly);

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<ResourceFindings>() else {
            return Vec::new();
        };

        if findings.interception_methods.is_empty() {
            return Vec::new();
        }

        vec![Box::new(ResourceRestorationPass::new(
            findings.redirects.clone(),
        ))]
    }
}

/// Intermediate result from structural detection (before SSA entry extraction).
struct ResourceStructure {
    host_type: Token,
    stream_type: Token,
    interception_methods: Vec<Token>,
    get_content_method: Option<Token>,
    xor_key: Option<u8>,
}

/// Builds a redirect map from interception method tokens to their original BCL targets.
///
/// Analyzes each interception method to find the `callvirt`/`call` instruction
/// that invokes the original BCL method (e.g., `Assembly.GetManifestResourceStream`).
fn build_redirect_map(
    interception_tokens: &[Token],
    assembly: &CilObject,
) -> HashMap<Token, ResourceTarget> {
    let mut redirects = HashMap::new();

    for &token in interception_tokens {
        if let Some(target) = find_original_bcl_call(assembly, token) {
            redirects.insert(token, target);
        }
    }

    redirects
}

/// Finds the original BCL method called within an SMF_* interception method.
///
/// The interception methods internally call the original BCL method (e.g.,
/// `Assembly.GetManifestResourceStream`). We find the `callvirt` instruction
/// that targets a method on `Assembly` or `Type` and return that token.
fn find_original_bcl_call(
    assembly: &CilObject,
    interception_token: Token,
) -> Option<ResourceTarget> {
    let method = assembly.method(&interception_token).ok()?;
    let instructions: Vec<_> = method.instructions().collect();

    // Look for callvirt instructions that call Assembly methods
    // The SMF_* methods wrap Assembly.GetManifestResourceStream,
    // Assembly.GetManifestResourceNames, etc.
    for instr in &instructions {
        if instr.mnemonic == "callvirt" || instr.mnemonic == "call" {
            if let Operand::Token(token) = &instr.operand {
                // Check if this calls a method on Assembly or related type
                // by looking up the MemberRef to see if it's on System.Reflection.Assembly
                if let Some(member_ref) = assembly.member_ref(token) {
                    let type_name = member_ref.declaredby.fullname().unwrap_or_default();
                    if type_name.ends_with("Assembly")
                        && (member_ref.name.starts_with("GetManifestResource")
                            || member_ref.name == "GetName"
                            || member_ref.name == "GetExecutingAssembly"
                            || member_ref.name == "GetCallingAssembly")
                    {
                        return Some(ResourceTarget {
                            target_token: *token,
                            is_virtual: instr.mnemonic == "callvirt",
                        });
                    }
                }
            }
        }
    }

    None
}

/// Detects the JIEJIE.NET resource interception infrastructure by structural pattern.
///
/// Finds the helper class with a nested Stream subclass and static interception
/// methods, plus the XOR key from the Stream.Read method. Does NOT extract
/// resource entries — that requires SSA.
fn detect_resource_structure(assembly: &CilObject) -> Option<ResourceStructure> {
    let mut best: Option<ResourceStructure> = None;
    let mut best_has_content = false;

    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Look for a class with a nested type that has 10+ methods
        // (Stream subclass: Read, Write, Seek, Flush, Length, Position, etc.)
        let mut stream_type_token: Option<Token> = None;

        for (_, nested_ref) in cil_type.nested_types.iter() {
            let Some(nested) = nested_ref.upgrade() else {
                continue;
            };

            if nested.methods.count() >= 10 {
                let has_byte_array_method = nested.methods.iter().any(|(_, method_ref)| {
                    let Some(method) = method_ref.upgrade() else {
                        return false;
                    };
                    method
                        .signature
                        .params
                        .iter()
                        .any(|p| matches!(p.base, TypeSignature::SzArray(_)))
                });

                if has_byte_array_method {
                    stream_type_token = Some(nested.token);
                    break;
                }
            }
        }

        let Some(stream_token) = stream_type_token else {
            continue;
        };

        // Check parent class for resource interception methods
        let mut interception_methods: Vec<Token> = Vec::new();
        let mut get_content_method: Option<Token> = None;

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            if method.name == wellknown::members::CTOR || method.name == wellknown::members::CCTOR {
                continue;
            }

            let sig = &method.signature;

            if !method.is_static() {
                continue;
            }

            // SMF_GetContent: static byte[](string)
            if sig.params.len() == 1
                && sig
                    .params
                    .first()
                    .is_some_and(|p| matches!(p.base, TypeSignature::String))
                && matches!(sig.return_type.base, TypeSignature::SzArray(_))
            {
                get_content_method = Some(method.token);
                continue;
            }

            // Resource interception: (Assembly, ...) -> Stream/string[]/ResourceInfo
            let returns_class_or_array = matches!(
                sig.return_type.base,
                TypeSignature::Class(_) | TypeSignature::SzArray(_)
            );
            if !returns_class_or_array {
                continue;
            }

            let has_class_param = sig
                .params
                .iter()
                .any(|p| matches!(p.base, TypeSignature::Class(_)));

            if has_class_param && !sig.params.is_empty() {
                interception_methods.push(method.token);
            }
        }

        if interception_methods.len() < 2 {
            continue;
        }

        let xor_key = extract_xor_key_from_stream(assembly, stream_token);

        let structure = ResourceStructure {
            host_type: cil_type.token,
            stream_type: stream_token,
            interception_methods,
            get_content_method,
            xor_key,
        };

        let has_content = structure.get_content_method.is_some();
        if has_content && !best_has_content {
            best = Some(structure);
            best_has_content = true;
        } else if best.is_none() {
            best = Some(structure);
        }

        if best_has_content {
            break;
        }
    }

    best
}

/// Extracts the XOR key from the `SMF_ResStream.Read` method.
///
/// The Read method contains a pattern like:
/// ```text
///   ldelem.u1
///   ldc.i4.s  <xor_key>    // or ldc.i4 <xor_key>
///   xor
///   conv.u1
/// ```
///
/// We find the `xor` instruction and look at the preceding `ldc.i4*` instruction
/// to extract the XOR key byte.
fn extract_xor_key_from_stream(assembly: &CilObject, stream_type_token: Token) -> Option<u8> {
    let stream_type = assembly.types().get(&stream_type_token)?;

    // Find the Read method in the Stream subclass
    for (_, method_ref) in stream_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };

        // Read method: instance int32(uint8[], int32, int32)
        let sig = &method.signature;
        if method.is_static()
            || sig.params.len() != 3
            || !matches!(sig.return_type.base, TypeSignature::I4)
        {
            continue;
        }

        // Check first param is byte[]
        let first_is_array = sig
            .params
            .first()
            .is_some_and(|p| matches!(p.base, TypeSignature::SzArray(_)));
        if !first_is_array {
            continue;
        }

        // Scan for `xor` instruction preceded by `ldc.i4*`
        let instructions: Vec<_> = method.instructions().collect();

        for (i, instr) in instructions.iter().enumerate() {
            if instr.mnemonic != "xor" {
                continue;
            }

            // Look backward for the nearest ldc.i4* instruction
            if i == 0 {
                continue;
            }

            for j in (0..i).rev() {
                let Some(prev) = instructions.get(j) else {
                    break;
                };
                if prev.mnemonic.starts_with("ldc.i4") {
                    if let Operand::Immediate(imm) = &prev.operand {
                        let key_value = match imm {
                            Immediate::Int8(v) => *v as u8,
                            Immediate::Int32(v) => *v as u8,
                            Immediate::UInt8(v) => *v,
                            Immediate::UInt32(v) => *v as u8,
                            _ => continue,
                        };
                        return Some(key_value);
                    }
                }
                // Don't search too far back
                if i.saturating_sub(j) > 3 {
                    break;
                }
            }
        }
    }

    None
}

/// Extracts resource name → data method mappings from `SMF_GetContent` using SSA dataflow.
///
/// After CFF unflattening, the switch-based state machine in `SMF_GetContent` is
/// reconstructed into normal control flow with a simple if-else chain:
///
/// ```text
///   Block 0: v_eq = String.Equals(arg0, "resource.name.1") → branch(v_eq, B1, B2)
///   Block 1: v_data = Call(ByteArrayDataContainer._0()) → return v_data
///   Block 2: v_eq2 = String.Equals(arg0, "resource.name.2") → branch(v_eq2, B3, B4)
///   Block 3: v_data2 = Call(ByteArrayDataContainer._1()) → return v_data2
/// ```
///
/// We find `String.Equals` calls, extract the string constant from their arguments,
/// then look at the successor block for a static `byte[]()` call.
fn extract_resource_entries_ssa(ssa: &SsaFunction, assembly: &CilObject) -> Vec<ResourceEntry> {
    let mut entries = Vec::new();
    let blocks = ssa.blocks();

    for (block_idx, block) in blocks.iter().enumerate() {
        let mut resource_name: Option<String> = None;

        for instr in block.instructions() {
            let (method_token, args) = match instr.op() {
                SsaOp::CallVirt { method, args, .. } | SsaOp::Call { method, args, .. } => {
                    (method.token(), args)
                }
                _ => continue,
            };

            if !is_string_equals(assembly, method_token) {
                continue;
            }

            for arg in args {
                if let Some(name) = trace_to_string_const(ssa, *arg, assembly) {
                    resource_name = Some(name);
                    break;
                }
            }
        }

        let Some(name) = resource_name else {
            continue;
        };

        // The true branch (next block) should contain a Call to a static byte[]() method
        let successor_idx = block_idx.saturating_add(1);
        let Some(successor) = blocks.get(successor_idx) else {
            continue;
        };
        for instr in successor.instructions() {
            let method_token = match instr.op() {
                SsaOp::Call { method, .. } => method.token(),
                _ => continue,
            };

            if let Ok(called_method) = assembly.method(&method_token) {
                if matches!(
                    called_method.signature.return_type.base,
                    TypeSignature::SzArray(_)
                ) && called_method.signature.params.is_empty()
                    && called_method.is_static()
                {
                    entries.push(ResourceEntry {
                        name: name.clone(),
                        data_method_token: method_token,
                    });
                    break;
                }
            }
        }
    }

    entries
}

/// Checks if a method token refers to `String.Equals` or `String.op_Equality`.
fn is_string_equals(assembly: &CilObject, token: Token) -> bool {
    if let Some(member_ref) = assembly.member_ref(&token) {
        if member_ref.name == "Equals" || member_ref.name == "op_Equality" {
            if let Some(type_name) = member_ref.declaredby.fullname() {
                return type_name == "System.String" || type_name.ends_with(".String");
            }
        }
    }
    false
}

/// Traces an SSA variable back through copies to find a `Const(String)` value.
fn trace_to_string_const(ssa: &SsaFunction, var: SsaVarId, assembly: &CilObject) -> Option<String> {
    const MAX_DEPTH: usize = 10;

    fn trace_impl(
        ssa: &SsaFunction,
        var: SsaVarId,
        assembly: &CilObject,
        depth: usize,
    ) -> Option<String> {
        if depth >= MAX_DEPTH {
            return None;
        }

        let def = ssa.get_definition(var)?;
        match def {
            SsaOp::Const {
                value: ConstValue::String(us_offset),
                ..
            } => assembly
                .userstrings()
                .and_then(|us| us.get(*us_offset as usize).ok())
                .map(|s| s.to_string_lossy().to_string()),
            SsaOp::Const {
                value: ConstValue::DecryptedString(s),
                ..
            } => Some(s.to_string()),
            SsaOp::Copy { src, .. } => trace_impl(ssa, *src, assembly, depth.saturating_add(1)),
            _ => None,
        }
    }

    trace_impl(ssa, var, assembly, 0)
}

/// Extracts and decrypts a single resource from its `ByteArrayDataContainer._N()` method.
fn extract_and_decrypt_resource(
    assembly: &CilObject,
    entry: &ResourceEntry,
    xor_key: u8,
) -> Result<Vec<u8>> {
    let method = assembly.method(&entry.data_method_token)?;

    let mut field_token: Option<Token> = None;
    let mut array_size: Option<usize> = None;

    let instructions: Vec<_> = method.instructions().collect();
    for instr in &instructions {
        if instr.mnemonic == "ldtoken" {
            if let Operand::Token(token) = &instr.operand {
                field_token = Some(*token);
            }
        }
        if instr.mnemonic.starts_with("ldc.i4") {
            if let Operand::Immediate(imm) = &instr.operand {
                let size = match imm {
                    Immediate::Int32(v) => *v as usize,
                    Immediate::UInt32(v) => *v as usize,
                    Immediate::Int8(v) => *v as usize,
                    Immediate::UInt8(v) => *v as usize,
                    _ => continue,
                };
                array_size = Some(size);
            }
        }
    }

    let field_token = field_token.ok_or_else(|| {
        Error::Deobfuscation(format!(
            "No ldtoken found in data method 0x{:08X}",
            entry.data_method_token.value()
        ))
    })?;

    let tables = assembly
        .tables()
        .ok_or_else(|| Error::Deobfuscation("No metadata tables".to_string()))?;

    let fieldrva_table = tables
        .table::<FieldRvaRaw>()
        .ok_or_else(|| Error::Deobfuscation("No FieldRVA table".to_string()))?;

    let field_rid = field_token.row();

    let rva_entry = fieldrva_table
        .iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|row| row.field == field_rid)
        .ok_or_else(|| {
            Error::Deobfuscation(format!("No FieldRVA entry for field RID 0x{:X}", field_rid))
        })?;

    let data_size = get_field_data_size(assembly, field_rid)
        .or(array_size)
        .ok_or_else(|| {
            Error::Deobfuscation(format!(
                "Cannot determine data size for field RID 0x{:X}",
                field_rid
            ))
        })?;

    let raw_data = assembly
        .file()
        .rva_slice(rva_entry.rva as usize, data_size)?;

    if raw_data.len() < 4 {
        return Err(Error::Deobfuscation(format!(
            "Resource data too short ({} bytes) for '{}'",
            raw_data.len(),
            entry.name
        )));
    }

    let header: [u8; 4] = raw_data
        .get(..4)
        .ok_or_else(|| {
            Error::Deobfuscation(format!(
                "Resource data missing 4-byte length header for '{}'",
                entry.name
            ))
        })?
        .try_into()
        .map_err(|_| {
            Error::Deobfuscation(format!(
                "Resource data missing 4-byte length header for '{}'",
                entry.name
            ))
        })?;
    let gzip_len = u32::from_le_bytes(header);
    let payload = raw_data.get(4..).ok_or_else(|| {
        Error::Deobfuscation(format!(
            "Resource data has no payload after header for '{}'",
            entry.name
        ))
    })?;

    let content = if gzip_len > 0 {
        let decompressed = decompress_gzip(payload).map_err(|e| {
            Error::Deobfuscation(format!(
                "GZip decompression failed for '{}': {}",
                entry.name, e
            ))
        })?;
        xor_decrypt(&decompressed, xor_key)
    } else {
        xor_decrypt(payload, xor_key)
    };

    Ok(content)
}

/// XOR decrypts data with a single-byte key.
fn xor_decrypt(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            jiejienet::resources::{
                detect_resource_structure, extract_xor_key_from_stream, JiejieNetResources,
            },
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_returns_empty() {
        // detect() returns empty — all detection is SSA-based
        let asm = load_sample("packers/jiejie/source/jiejie_resources_only.exe");
        let technique = JiejieNetResources;
        let detection = technique.detect(&asm);

        assert!(!detection.is_detected(), "detect() should return empty");
    }

    #[test]
    fn test_structural_detection() {
        let asm = load_sample("packers/jiejie/source/jiejie_resources_only.exe");
        let structure = detect_resource_structure(&asm);

        assert!(structure.is_some(), "Should find resource structure");
        let structure = structure.unwrap();

        assert!(
            structure.interception_methods.len() >= 2,
            "Should find at least 2 interception methods, found {}",
            structure.interception_methods.len()
        );
        assert!(
            structure.get_content_method.is_some(),
            "Should find SMF_GetContent method"
        );
    }

    #[test]
    fn test_xor_key_extraction() {
        let asm = load_sample("packers/jiejie/source/jiejie_resources_only.exe");
        let structure = detect_resource_structure(&asm).expect("Should find structure");

        let xor_key = extract_xor_key_from_stream(&asm, structure.stream_type);
        assert!(xor_key.is_some(), "Should extract XOR key");
    }

    #[test]
    fn test_detect_negative_controlflow_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_controlflow_only.exe");
        let structure = detect_resource_structure(&asm);

        assert!(
            structure.is_none(),
            "Should not detect resources in controlflow-only sample"
        );
    }

    #[test]
    fn test_detect_negative_original() {
        let asm = load_sample("packers/jiejie/source/original.exe");
        let structure = detect_resource_structure(&asm);

        assert!(structure.is_none(), "Should not detect in original");
    }
}

//! .NET Reactor NecroBit protection detection and decryption.
//!
//! NecroBit is .NET Reactor's most critical protection. It encrypts all method
//! bodies, replacing them with minimal stubs. Without reversing NecroBit first,
//! all other deobfuscation stages operate on encrypted bytecode.
//!
//! # Detection
//!
//! Detection is fully structural — no hardcoded type names or version-specific
//! constants. It uses a primary signal + corroboration model:
//!
//! - **Primary**: High ratio of stub methods (4-instruction `nop;nop;X;ret` pattern)
//! - **Corroborating**: .cctor fan-in (many .cctors calling the same init method),
//!   trial/time-bomb check pattern, or body patcher pattern (Marshal.Copy + ReadInt32)
//!
//! # Transform
//!
//! The decryption pipeline:
//! 1. Find `<Module>::.cctor` and trial check methods via structural analysis
//! 2. Register a hook to bypass trial checks (avoids needing DateTime BCL hooks)
//! 3. Emulate `<Module>::.cctor` — the protection's own code does the decryption,
//!    so the cipher is never reimplemented and version changes to it cost nothing
//! 4. Extract the decrypted bodies from wherever that run left them, which
//!    depends on the storage variant (see the format notes below): variant A
//!    builds a structured blob on the managed heap, variant B writes complete
//!    bodies into the image at each method's RVA
//! 5. Rebuild the assembly with restored method bodies
//!
//! Step 3 is only faithful if the emulator models the protection's dynamically
//! resolved `VirtualProtect`. Variant B's writes land in `.text`, which is mapped
//! read-only, and the return value also steers the init's control flow — a call
//! that answers without applying the protection sends it down a path that stores
//! nothing.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    cilassembly::GeneratorConfig,
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        netreactor::{helpers, hooks},
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    emulation::{EmValue, EmulationOutcome, EmulationProcess, HeapObject, ProcessBuilder},
    error::Error,
    metadata::{
        method::{ExceptionHandler, MethodBody},
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

// Minimum number of stub methods for the primary detection signal.
const MIN_STUB_COUNT: usize = 5;

// Minimum ratio of stubs to total IL methods for the primary signal.
const MIN_STUB_RATIO: f64 = 0.10;

// NecroBit decrypted data array format (reversed from .NET Reactor 7.5.0).
//
// The decrypted data has a 24-byte header followed by method body records.
// Two format variants are identified by the `group_count` field at offset 16:
//
// Variant A (`group_count > 0`): Used by necrobit-only binaries.
//   Header (24 bytes) + group entries (group_count × 8) + method_count (4) +
//   per-method records: [IL_start_RVA(4), maxstack(4), IL_byte_count(4), IL_bytes...]
//   Real bodies live exclusively on the heap; the PE image at each method's
//   RVA stays as the original on-disk fat-stub. Parsed by
//   [`parse_variant_a_blob`].
//
// Variant B (`group_count == 0`): Used by full-protection binaries.
//   Bodies are `Marshal.Copy`'d into the address space at each method's RVA
//   during emulation. The heap blob is at best incidental and not a complete
//   body table — extraction reads the address space via
//   [`extract_bodies_from_image`] instead.
//
// Header layout:
//   [0..4]   first_method_token  (table 0x06 = MethodDef)
//   [4..8]   total_size          (total size of all method body data)
//   [8..12]  reserved_1
//   [12..16] reserved_2
//   [16..20] group_count         (0 = variant B, >0 = variant A)
//   [20..24] flags

/// Findings from NecroBit detection.
#[derive(Debug)]
pub struct NecroBitFindings {
    /// Tokens of methods with NecroBit stub bodies.
    pub stub_method_tokens: Vec<Token>,
    /// Token of the init method found via .cctor fan-in analysis.
    pub init_method_token: Option<Token>,
    /// Token of the runtime type (declaring type of the init method).
    pub runtime_type_token: Option<Token>,
    /// Token of `<Module>::.cctor`.
    pub module_cctor_token: Option<Token>,
    /// Tokens of trial check methods (DateTime pattern).
    pub trial_check_tokens: Vec<Token>,
    /// Token of the body patcher method (Marshal.Copy pattern).
    pub body_patcher_token: Option<Token>,
    /// .cctors whose entire body is just the init call — safe to delete.
    pub purely_injected_cctors: Vec<Token>,
    /// .cctors with the init call prepended to original code.
    pub modified_cctors: Vec<Token>,
    /// Total number of IL methods in the assembly.
    pub total_methods: usize,
}

/// Detects and decrypts .NET Reactor NecroBit-protected method bodies.
pub struct NetReactorNecroBit;

impl Technique for NetReactorNecroBit {
    fn id(&self) -> &'static str {
        "netreactor.necrobit"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor NecroBit (Method Body Decryption)"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // Signal 1 (primary): Scan for stub methods
        let stub_scan = helpers::scan_stub_methods(assembly);
        let stub_count = stub_scan.stub_methods.len();
        let stub_ratio = if stub_scan.total_il_methods > 0 {
            stub_count as f64 / stub_scan.total_il_methods as f64
        } else {
            0.0
        };

        let primary_met = stub_count >= MIN_STUB_COUNT && stub_ratio > MIN_STUB_RATIO;

        if !primary_met {
            return Detection::new_empty();
        }

        // Signal 2 (corroborating): .cctor fan-in analysis
        let fan_in = helpers::find_cctor_fan_in_target(assembly);
        let has_fan_in = fan_in.is_some();

        // Signal 3 (corroborating): Trial/time-bomb check
        let trial_checks = helpers::find_trial_checks(assembly);
        let has_trial_on_module = trial_checks.iter().any(|t| t.is_on_module_type);
        let has_trial = !trial_checks.is_empty();

        // Signal 4 (corroborating): Body patcher pattern
        let body_patcher = helpers::find_body_patcher(assembly);
        let has_patcher = body_patcher.is_some();

        // Require at least one corroborating signal
        if !has_fan_in && !has_trial && !has_patcher {
            return Detection::new_empty();
        }

        // Build findings
        let module_cctor_token = assembly.types().module_cctor();

        let init_method_token = fan_in.as_ref().map(|f| f.target_token);
        let runtime_type_token = init_method_token.and_then(|init_token| {
            assembly
                .method(&init_token)
                .ok()
                .and_then(|m| m.declaring_type_rc())
                .map(|t| t.token)
        });

        // Classify injected .cctors
        let (purely_injected_cctors, modified_cctors) = if let Some(ref fan_in_result) = fan_in {
            let classification = helpers::classify_injected_cctors(
                assembly,
                &fan_in_result.initializers,
                &fan_in_result.calling_cctors,
            );
            (classification.purely_injected, classification.modified)
        } else {
            (Vec::new(), Vec::new())
        };

        let stub_method_tokens: Vec<Token> =
            stub_scan.stub_methods.iter().map(|(t, _)| *t).collect();

        let trial_check_tokens: Vec<Token> = trial_checks.iter().map(|t| t.method_token).collect();

        let findings = NecroBitFindings {
            stub_method_tokens,
            init_method_token,
            runtime_type_token,
            module_cctor_token,
            trial_check_tokens: trial_check_tokens.clone(),
            body_patcher_token: body_patcher,
            purely_injected_cctors: purely_injected_cctors.clone(),
            modified_cctors,
            total_methods: stub_scan.total_il_methods,
        };

        // Build evidence
        let mut evidence = Vec::new();

        evidence.push(Evidence::BytecodePattern(format!(
            "{} of {} IL methods have NecroBit stub bodies ({:.0}%)",
            stub_count,
            stub_scan.total_il_methods,
            stub_ratio * 100.0,
        )));

        if let Some(ref fan_in_result) = fan_in {
            evidence.push(Evidence::Structural(format!(
                "Init method 0x{:08X} called by {} type .cctors ({} locals, {} instructions)",
                fan_in_result.target_token.value(),
                fan_in_result.calling_cctors.len(),
                fan_in_result.target_local_count,
                fan_in_result.target_instruction_count,
            )));
        }

        if has_trial_on_module {
            evidence.push(Evidence::BytecodePattern(
                "Trial/time-bomb check on <Module> (DateTime + TimeSpan.Days + throw)".to_string(),
            ));
        } else if has_trial {
            evidence.push(Evidence::BytecodePattern(
                "Trial/time-bomb check method detected (DateTime + TimeSpan.Days + throw)"
                    .to_string(),
            ));
        }

        if has_patcher {
            evidence.push(Evidence::BytecodePattern(
                "Body patcher method (Marshal.Copy + ReadInt32/64 + IntPtr.Size)".to_string(),
            ));
        }

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Mark infrastructure for cleanup
        if let Some(rt_token) = runtime_type_token {
            detection.cleanup_mut().add_type(rt_token);
        }
        // The initializers every protected type's `.cctor` calls decrypt the
        // bodies at run time, which this deobfuscation has already done: the
        // calls go with them, from the `.cctor`s that also hold the program's
        // own initialization.
        for &initializer in fan_in.iter().flat_map(|f| &f.initializers) {
            detection.cleanup_mut().add_protection_method(initializer);
        }
        for &cctor_token in &purely_injected_cctors {
            detection.cleanup_mut().add_method(cctor_token);
        }
        for &trial_token in &trial_check_tokens {
            detection.cleanup_mut().add_protection_method(trial_token);
        }
        if let Some(patcher_token) = body_patcher {
            detection.cleanup_mut().add_protection_method(patcher_token);
        }

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<NecroBitFindings>() else {
            return Some(Ok(events));
        };

        if findings.stub_method_tokens.is_empty() {
            return Some(Ok(events));
        }

        // Step 1: Create a CilObject from the current assembly bytes for emulation.
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
        let cilobject_arc = Arc::new(cilobject);

        // Step 2: Find the module .cctor to emulate.
        let module_cctor = match findings.module_cctor_token.ok_or_else(|| {
            Error::Deobfuscation("No <Module>::.cctor found for NecroBit emulation".to_string())
        }) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Step 3: Build bypass tokens — trial checks and any other methods to skip.
        // Also bypass all injected .cctors that call the init method, since the
        // emulator's auto .cctor triggering would run them before the init method
        // gets to do its work. We want to call the init method directly.
        let mut bypass_tokens: HashSet<Token> = HashSet::new();
        for &token in &findings.trial_check_tokens {
            bypass_tokens.insert(token);
        }
        for &token in &findings.purely_injected_cctors {
            bypass_tokens.insert(token);
        }
        for &token in &findings.modified_cctors {
            bypass_tokens.insert(token);
        }

        // Step 4: Set up and run emulation.
        let mut builder = ProcessBuilder::new()
            .assembly_arc(Arc::clone(&cilobject_arc))
            .name("necrobit-emulation")
            .with_max_instructions(50_000_000)
            .with_max_call_depth(200)
            .with_timeout_ms(300_000); // 5 minutes

        // Register anti-tamper bypass (RSA VerifyHash → true).
        // Full-protection binaries verify assembly integrity via RSA signature
        // before decrypting bodies. Since our crypto stubs produce stub hashes,
        // the verification always fails — bypass it.
        builder = builder.hook(hooks::create_antitamper_bypass_hook());

        if !bypass_tokens.is_empty() {
            builder = builder.hook(hooks::create_trial_bypass_hook(bypass_tokens));
        }

        let process = match builder.build() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let outcome = match process.execute_method(module_cctor, vec![]) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let instructions_executed = match outcome {
            EmulationOutcome::Completed { instructions, .. }
            | EmulationOutcome::Breakpoint { instructions, .. } => instructions,
            EmulationOutcome::UnhandledException {
                instructions,
                exception,
                ..
            } => {
                log::info!(
                    "NecroBit emulation ended with exception after {} instructions: {:?} \
                     — extracting method bodies from emulation state",
                    instructions,
                    exception,
                );
                instructions
            }
            EmulationOutcome::LimitReached { limit, .. } => {
                log::warn!(
                    "NecroBit emulation exceeded limit ({limit:?}) \
                     — attempting body extraction from partial state",
                );
                0
            }
            EmulationOutcome::Stopped { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "NecroBit emulation stopped: {reason}"
                ))));
            }
            EmulationOutcome::RequiresSymbolic { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "NecroBit emulation requires symbolic execution: {reason}"
                ))));
            }
        };

        // Step 5: Extract method bodies.
        //
        // The two NR layouts use different storage strategies post-decryption:
        //
        // - **Variant A** (necrobit-only / `group_count > 0`): bodies live
        //   exclusively in a structured byte array on the managed heap. The PE
        //   image at each method's RVA is left as the original on-disk fat-stub.
        // - **Variant B** (full-protection / `group_count == 0`): bodies are
        //   `Marshal.Copy`'d into the address space at each method's RVA. The
        //   heap blob, if any, is incidental and not a complete body table.
        //
        // Inspect the heap to dispatch the correct extractor. Falling back to
        // image extraction when no variant-A blob is found also covers the case
        // where heap-based detection fails on a malformed run.
        let extracted_bodies = match find_variant_a_blob(&process) {
            Some(blob) => match parse_variant_a_blob(&blob, &cilobject_arc) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            },
            None => match extract_bodies_from_image(
                &process,
                &cilobject_arc,
                &findings.stub_method_tokens,
            ) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            },
        };

        drop(process);

        if extracted_bodies.is_empty() {
            return Some(Err(Error::Deobfuscation(
                "No method bodies could be extracted from heap or PE image".to_string(),
            )));
        }

        let stub_set: HashSet<Token> = findings.stub_method_tokens.iter().copied().collect();
        let restored_count = extracted_bodies
            .iter()
            .filter(|(token, _)| stub_set.contains(token))
            .count();

        log::info!(
            "NecroBit: extracted {} method bodies ({} of {} stubs restored, {} instructions)",
            extracted_bodies.len(),
            restored_count,
            findings.stub_method_tokens.len(),
            instructions_executed,
        );

        if restored_count == 0 {
            return Some(Err(Error::Deobfuscation(format!(
                "NecroBit emulation did not restore any stub methods \
                 (extracted {} bodies, {} were stubs)",
                extracted_bodies.len(),
                findings.stub_method_tokens.len(),
            ))));
        }

        for (token, _) in &extracted_bodies {
            if stub_set.contains(token) {
                events
                    .record(EventKind::MethodBodyDecrypted)
                    .method(*token)
                    .message(format!("Decrypted method body 0x{:08x}", token.value()));
            }
        }

        // Step 6: Store decrypted bodies in the assembly.
        let cilobject = match Arc::try_unwrap(cilobject_arc)
            .map_err(|_| Error::Deobfuscation("Assembly still shared after emulation".into()))
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let mut cil_assembly = cilobject.into_assembly();

        for (method_token, body_bytes) in &extracted_bodies {
            if MethodBody::from(body_bytes).is_err() {
                log::warn!(
                    "Skipping invalid decrypted body for 0x{:08X} ({} bytes)",
                    method_token.value(),
                    body_bytes.len()
                );
                continue;
            }
            let placeholder_rva = cil_assembly.store_method_body(body_bytes.clone());
            let rid = method_token.row();

            #[allow(clippy::redundant_closure_for_method_calls)]
            let existing_row = match cil_assembly
                .view()
                .tables()
                .and_then(|t| t.table::<MethodDefRaw>())
                .and_then(|table| table.get(rid).ok().flatten())
                .ok_or_else(|| Error::Deobfuscation(format!("MethodDef row {rid} not found")))
            {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let updated_row = MethodDefRaw {
                rid: existing_row.rid,
                token: existing_row.token,
                offset: existing_row.offset,
                rva: placeholder_rva,
                impl_flags: existing_row.impl_flags,
                flags: existing_row.flags,
                name: existing_row.name,
                signature: existing_row.signature,
                param_list: existing_row.param_list,
            };

            if let Err(e) = cil_assembly.table_row_update(
                TableId::MethodDef,
                rid,
                TableDataOwned::MethodDef(updated_row),
            ) {
                return Some(Err(e));
            }
        }

        events
            .record(EventKind::MethodBodyDecrypted)
            .message(format!(
                "NecroBit protection removed: {restored_count} method bodies decrypted \
                 ({instructions_executed} instructions emulated)",
            ));

        // Step 7: Regenerate PE with decrypted bodies.
        let config = GeneratorConfig::default();
        let new_assembly =
            match cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

        assembly.replace_assembly(new_assembly);

        Some(Ok(events))
    }

    /// The stub methods, which are exactly the ones whose bodies this technique
    /// exists to decrypt. When decryption fails they still hold the
    /// `nop;nop;X;ret` stub the protection wrote, and the real code is encrypted
    /// in the resource rather than gone.
    fn unrecovered_methods(&self, detection: &Detection) -> Vec<Token> {
        detection
            .findings::<NecroBitFindings>()
            .map(|findings| findings.stub_method_tokens.clone())
            .unwrap_or_default()
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Returns whether the byte slice has the shape of a NecroBit decrypted data
/// blob (24-byte header beginning with a MethodDef token, followed by either
/// variant A group entries + per-method IL records or variant B per-entry
/// bodies).
///
/// **Variant A** (`group_count > 0`): Header with group entries providing fat
/// method header metadata, followed by a method count and per-method IL
/// records. Used by necrobit-only protected binaries.
///
/// **Variant B** (`group_count == 0`): Header followed directly by per-method
/// entries containing complete method bodies. Variant B is parsed via the
/// address-space path ([`extract_bodies_from_image`]); this predicate just
/// validates the heap blob's overall shape so we don't pick a random byte
/// array as the decrypted blob.
fn is_necrobit_data_array(data: &[u8]) -> bool {
    if data.len() < 28 {
        return false;
    }

    let read_u32 = |off: usize| -> Option<u32> {
        let slice = data.get(off..off.checked_add(4)?)?;
        let arr: [u8; 4] = slice.try_into().ok()?;
        Some(u32::from_le_bytes(arr))
    };

    let Some(first_token) = read_u32(0) else {
        return false;
    };
    if first_token >> 24 != 0x06 {
        return false;
    }

    let Some(group_count) = read_u32(16) else {
        return false;
    };
    let group_count = group_count as usize;

    if group_count > 0 && group_count <= 500 {
        // Variant A: group entries + method_count + per-method IL records
        let Some(header_end) = group_count
            .checked_mul(8)
            .and_then(|n| 24_usize.checked_add(n))
        else {
            return false;
        };
        let Some(header_end_plus_4) = header_end.checked_add(4) else {
            return false;
        };
        if header_end_plus_4 > data.len() {
            return false;
        }
        let Some(method_count) = read_u32(header_end) else {
            return false;
        };
        let method_count = method_count as usize;
        if method_count == 0 || method_count > 5000 {
            return false;
        }
        let Some(lhs) = method_count
            .checked_mul(12)
            .and_then(|n| header_end_plus_4.checked_add(n))
        else {
            return false;
        };
        let Some(rhs) = method_count
            .checked_mul(8)
            .and_then(|n| data.len().checked_add(n))
        else {
            return false;
        };
        lhs <= rhs
    } else if group_count == 0 {
        // Variant B: complete method bodies start at offset 24.
        // Validate by checking if the first entry has a valid method body header.
        if data.len() < 36 {
            return false;
        }
        let Some(&body_header_byte) = data.get(32) else {
            return false;
        }; // offset 24 + 8 (RVA + v2)
        let is_fat = body_header_byte & 0x03 == 0x03;
        let is_tiny = body_header_byte & 0x03 == 0x02;
        is_fat || is_tiny
    } else {
        false
    }
}

/// Returns the largest variant-A NecroBit blob on the managed heap, or `None`
/// if no variant-A blob is present.
///
/// Variant A is identified by `group_count > 0` in the blob header. A
/// variant-B blob (group_count == 0) is ignored here even when present —
/// variant B's authoritative bodies are in the address space, not the heap,
/// and the heap blob is at best incomplete.
fn find_variant_a_blob(process: &EmulationProcess) -> Option<Vec<u8>> {
    let heap = process.address_space().managed_heap();
    let mut best: Option<Vec<u8>> = None;
    for (_href, obj) in heap.iter().ok()? {
        let HeapObject::Array { elements, .. } = &obj else {
            continue;
        };
        if elements.len() < 500 {
            continue;
        }
        let bytes: Vec<u8> = elements
            .iter()
            .filter_map(|e| match e {
                EmValue::I32(v) => Some((v & 0xFF) as u8),
                _ => None,
            })
            .collect();
        if !is_necrobit_data_array(&bytes) {
            continue;
        }
        let Some(gc_slice) = bytes.get(16..20) else {
            continue;
        };
        let Ok(gc_arr) = <[u8; 4]>::try_from(gc_slice) else {
            continue;
        };
        let group_count = u32::from_le_bytes(gc_arr) as usize;
        if group_count == 0 {
            continue; // variant B — wrong path
        }
        if best.as_ref().is_none_or(|prev| bytes.len() > prev.len()) {
            best = Some(bytes);
        }
    }
    best
}

/// Parses a variant-A NecroBit blob into per-method body bytes.
///
/// Variant A's heap blob carries IL bytes only. For fat methods that originally
/// had EH sections, the on-disk PE retains the structured EH (with try/handler
/// offsets pre-computed for the post-decryption IL) wrapped around a 4-byte
/// stub IL. We splice each method's heap IL onto its on-disk EH using
/// [`MethodBody::from_raw`] (skips bounds-checking against the stub's
/// 4-byte code_size) and [`MethodBody::write_to`] for serialization.
fn parse_variant_a_blob(data: &[u8], assembly: &CilObject) -> Result<Vec<(Token, Vec<u8>)>> {
    let read_u32 = |off: usize| -> Result<u32> {
        let end = off
            .checked_add(4)
            .ok_or_else(|| Error::Deobfuscation("offset overflow in blob read".into()))?;
        let slice = data.get(off..end).ok_or(out_of_bounds_error!())?;
        let arr: [u8; 4] = slice.try_into().map_err(|_| {
            Error::Deobfuscation("blob read: 4-byte slice conversion failed".into())
        })?;
        Ok(u32::from_le_bytes(arr))
    };

    if data.len() < 24 {
        return Err(Error::Deobfuscation(
            "Decrypted data too small for header".to_string(),
        ));
    }

    let group_count = read_u32(16)? as usize;
    let header_end = 24_usize
        .checked_add(group_count.checked_mul(8).ok_or_else(|| {
            Error::Deobfuscation("group_count * 8 overflow in variant-A header".into())
        })?)
        .ok_or_else(|| Error::Deobfuscation("header_end overflow in variant-A header".into()))?;
    if data.len()
        < header_end.checked_add(4).ok_or_else(|| {
            Error::Deobfuscation("header_end + 4 overflow in variant-A header".into())
        })?
    {
        return Err(Error::Deobfuscation(
            "Decrypted data too small for group entries".to_string(),
        ));
    }

    // Group entries provide per-method fat-header metadata:
    //   StandAloneSig token entries (top byte 0x11): patch LocalVarSig at header+8
    //   FatHdr entries (top byte != 0x11):           patch flags+maxstack at header+0
    let mut header_patches: HashMap<u32, u32> = HashMap::new();
    for i in 0..group_count {
        let entry_off = 24_usize
            .checked_add(i.checked_mul(8).ok_or_else(|| {
                Error::Deobfuscation("group entry offset overflow in variant-A blob".into())
            })?)
            .ok_or_else(|| {
                Error::Deobfuscation("group entry offset overflow in variant-A blob".into())
            })?;
        let rva = read_u32(entry_off)?;
        let val = read_u32(entry_off.checked_add(4).ok_or_else(|| {
            Error::Deobfuscation("group entry val offset overflow in variant-A blob".into())
        })?)?;
        header_patches.insert(rva, val);
    }

    let method_count = read_u32(header_end)? as usize;
    let mut offset = header_end
        .checked_add(4)
        .ok_or_else(|| Error::Deobfuscation("offset overflow after header_end".into()))?;

    // RVA → MethodDef token. Variant A's per-method records reference the IL
    // start address (RVA + 1 for tiny, RVA + 12 for fat), so a hit at
    // `il_start_rva - 1` is tiny and one at `il_start_rva - 12` is fat.
    let mut rva_to_token: HashMap<u32, Token> = HashMap::new();
    for method_entry in assembly.methods().iter() {
        let method = method_entry.value();
        if let Some(rva) = method.rva.filter(|&r| r > 0) {
            rva_to_token.insert(rva, method.token);
        }
    }

    let mut bodies = Vec::new();

    for _ in 0..method_count {
        let record_end = offset.checked_add(12).ok_or_else(|| {
            Error::Deobfuscation("record offset overflow in variant-A blob".into())
        })?;
        if record_end > data.len() {
            break;
        }
        let il_start_rva = read_u32(offset)?;
        let v2 =
            read_u32(offset.checked_add(4).ok_or_else(|| {
                Error::Deobfuscation("v2 offset overflow in variant-A blob".into())
            })?)?;
        let il_size = read_u32(offset.checked_add(8).ok_or_else(|| {
            Error::Deobfuscation("il_size offset overflow in variant-A blob".into())
        })?)? as usize;
        offset = record_end;

        if il_start_rva == 0 && v2 == 0 && il_size == 0 {
            break;
        }
        let il_end = offset
            .checked_add(il_size)
            .ok_or_else(|| Error::Deobfuscation("il_end overflow in variant-A blob".into()))?;
        if il_end > data.len() {
            log::warn!(
                "NecroBit: truncated IL data at RVA 0x{il_start_rva:04X} (need {il_size}, have {})",
                data.len().saturating_sub(offset)
            );
            break;
        }

        let il_bytes = data.get(offset..il_end).ok_or(out_of_bounds_error!())?;
        offset = il_end;

        let tiny_key = il_start_rva.checked_sub(1);
        let fat_key = il_start_rva.checked_sub(12);
        let (method_token, is_fat) =
            if let Some(&token) = tiny_key.and_then(|k| rva_to_token.get(&k)) {
                (token, false)
            } else if let Some(&token) = fat_key.and_then(|k| rva_to_token.get(&k)) {
                (token, true)
            } else {
                log::warn!("NecroBit: no method found for IL start RVA 0x{il_start_rva:04X}");
                continue;
            };

        let body_bytes = if is_fat {
            let method_rva = il_start_rva.checked_sub(12).ok_or_else(|| {
                Error::Deobfuscation("method_rva underflow for fat method".into())
            })?;
            let (max_stack, is_init_local, local_var_sig_token) =
                resolve_fat_header_metadata(method_rva, v2, &header_patches)?;
            let exception_handlers = read_on_disk_exception_handlers(assembly, method_rva);

            let new_body = MethodBody {
                size_code: il_size,
                size_header: 12,
                local_var_sig_token,
                max_stack,
                is_fat: true,
                is_init_local,
                is_exception_data: !exception_handlers.is_empty(),
                exception_handlers,
                exception_format: None,
            };

            let mut buf = Vec::with_capacity(12_usize.saturating_add(il_size).saturating_add(64));
            new_body
                .write_to(&mut buf, il_bytes)
                .map_err(|e| Error::Deobfuscation(format!("encode fat body: {e}")))?;
            buf
        } else {
            if il_size > 63 {
                log::warn!(
                    "NecroBit: IL too large for tiny header at 0x{:08X} ({il_size} bytes)",
                    method_token.value()
                );
                continue;
            }
            let new_body = MethodBody {
                size_code: il_size,
                size_header: 1,
                local_var_sig_token: 0,
                max_stack: 8,
                is_fat: false,
                is_init_local: false,
                is_exception_data: false,
                exception_handlers: Vec::new(),
                exception_format: None,
            };
            let mut buf = Vec::with_capacity(1_usize.saturating_add(il_size));
            new_body
                .write_to(&mut buf, il_bytes)
                .map_err(|e| Error::Deobfuscation(format!("encode tiny body: {e}")))?;
            buf
        };

        bodies.push((method_token, body_bytes));
    }

    log::info!(
        "NecroBit: parsed {}/{method_count} method bodies from decrypted array ({} bytes)",
        bodies.len(),
        data.len()
    );

    Ok(bodies)
}

/// Resolves the (max_stack, init_locals, local_var_sig_token) tuple for a
/// variant-A fat method using the group-entry header patches and the
/// per-record `v2` fallback.
fn resolve_fat_header_metadata(
    method_rva: u32,
    v2: u32,
    header_patches: &HashMap<u32, u32>,
) -> Result<(usize, bool, u32)> {
    // StandAloneSig entries patch the LocalVarSig field (at header + 8).
    let sig_key = method_rva.checked_add(8).ok_or_else(|| {
        Error::Deobfuscation("method_rva + 8 overflow in fat header lookup".into())
    })?;
    let local_var_sig_token = header_patches
        .get(&sig_key)
        .copied()
        .filter(|v| (v >> 24) == 0x11)
        .unwrap_or(0);

    // FatHdr entries patch the flags+maxstack word (at header + 0). When
    // missing, fall back to ECMA-335 default flags (0x3013 = fat | InitLocals)
    // and use the per-record `v2` as the max_stack hint.
    let (flags_and_size, maxstack) = if let Some(&fat_hdr) = header_patches.get(&method_rva) {
        if (fat_hdr >> 24) != 0x11 {
            ((fat_hdr & 0xFFFF) as u16, (fat_hdr >> 16) as u16)
        } else {
            // StandAloneSig at offset 0 — shouldn't happen, treat as missing.
            (0x3013u16, v2 as u16)
        }
    } else {
        (0x3013u16, v2 as u16)
    };

    let is_init_local = (flags_and_size & 0x0010) != 0;
    Ok((maxstack as usize, is_init_local, local_var_sig_token))
}

/// Returns the structured exception handlers from the on-disk stub method
/// body, if any.
///
/// NetReactor's variant-A stubs on disk are `[fat_header(12)][stub_il(4)][eh_section]`
/// — the EH offsets are pre-computed for the post-decryption (flattened) IL,
/// so they reference offsets beyond the stub's 4-byte code_size. [`MethodBody::from_raw`]
/// skips bounds-checking against `code_size`, letting us extract the EH list
/// verbatim and splice it onto the larger heap-derived IL.
///
/// Returns an empty `Vec` for tiny bodies, fat bodies without MoreSects, or
/// any parse failure (callers treat that as "no EH").
fn read_on_disk_exception_handlers(assembly: &CilObject, method_rva: u32) -> Vec<ExceptionHandler> {
    let Ok(body_data) = assembly.file().section_bounded(method_rva as usize) else {
        return Vec::new();
    };
    MethodBody::from_raw(body_data)
        .ok()
        .map(|b| b.exception_handlers)
        .unwrap_or_default()
}

/// Extracts method bodies from the PE image in the address space.
///
/// In full-protection binaries, the init method writes decrypted method bodies
/// directly to the PE image at each method's RVA via `Marshal.WriteInt32`. After
/// emulation, the address space contains the patched bodies at the correct RVAs.
///
/// For each stub method, this reads a buffer from the PE image and validates it
/// as a complete method body using [`MethodBody::from`].
fn extract_bodies_from_image(
    process: &EmulationProcess,
    assembly: &CilObject,
    stub_tokens: &[Token],
) -> Result<Vec<(Token, Vec<u8>)>> {
    let image_base = process.image_base().ok_or_else(|| {
        Error::Deobfuscation("No PE image base for NecroBit extraction".to_string())
    })?;

    let image_size = assembly.file().data().len() as u64;
    let addr_space = process.address_space();
    let mut bodies = Vec::new();

    let mut read_failures = 0usize;
    let mut parse_failures = 0usize;
    let mut still_stubs = 0usize;

    for &token in stub_tokens {
        let Ok(method) = assembly.method(&token) else {
            continue;
        };
        let Some(rva) = method.rva.filter(|&r| r > 0) else {
            continue;
        };

        let addr = image_base.checked_add(u64::from(rva)).ok_or_else(|| {
            Error::Deobfuscation("addr overflow computing image_base + rva".into())
        })?;
        let available = image_size.saturating_sub(u64::from(rva)) as usize;
        if available == 0 {
            continue;
        }

        let buffer = match addr_space.read(addr, available) {
            Ok(b) => b,
            Err(_) => {
                read_failures = read_failures.saturating_add(1);
                continue;
            }
        };

        let body = match MethodBody::from(&buffer) {
            Ok(b) => b,
            Err(_) => {
                parse_failures = parse_failures.saturating_add(1);
                continue;
            }
        };

        // Skip stubs: any 4-byte code body (`nop;nop;X;ret`), tiny *or* fat.
        // Variant A keeps the original on-disk fat-stubs at each method's RVA
        // (12-byte fat header + 4-byte code), so without catching the fat case
        // here a variant-B fallback run on a variant-A binary would silently
        // overwrite real bodies with fat-wrapped stubs.
        if body.size_code == 4 {
            still_stubs = still_stubs.saturating_add(1);
            continue;
        }

        let total_size = body.size();
        let Some(body_slice) = buffer.get(..total_size) else {
            continue;
        };
        bodies.push((token, body_slice.to_vec()));
    }

    if bodies.is_empty() && !stub_tokens.is_empty() {
        log::debug!(
            "NecroBit image extraction: {} read failures, {} parse failures, \
             {} still stubs (of {} total)",
            read_failures,
            parse_failures,
            still_stubs,
            stub_tokens.len(),
        );
    }

    log::info!(
        "NecroBit: extracted {} method bodies from PE image ({} stubs checked)",
        bodies.len(),
        stub_tokens.len(),
    );

    Ok(bodies)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        deobfuscation::techniques::{Technique, WorkingAssembly},
        metadata::validation::ValidationConfig,
        testkit::fixture,
        CilObject,
    };

    fn load_sample(name: &str) -> CilObject {
        let path = fixture(&format!("packers/netreactor/7.5.0/{name}"));
        CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {name}: {e}"))
    }

    #[test]
    fn test_detect_positive() {
        let _path = fixture("packers/netreactor/7.5.0/reactor_necrobit.exe");

        let assembly = load_sample("reactor_necrobit.exe");
        let technique = NetReactorNecroBit;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "NetReactorNecroBit should detect NecroBit in reactor_necrobit.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<NecroBitFindings>()
            .expect("Should have NecroBitFindings");

        assert!(
            !findings.stub_method_tokens.is_empty(),
            "Should find stub methods"
        );
        assert!(
            findings.init_method_token.is_some(),
            "Should find init method via .cctor fan-in"
        );
        assert!(
            findings.module_cctor_token.is_some(),
            "Should find <Module>::.cctor"
        );
        assert!(
            !findings.trial_check_tokens.is_empty(),
            "Should find trial check methods"
        );
        assert!(
            findings.body_patcher_token.is_some(),
            "Should find body patcher method"
        );
    }

    /// Decrypts `sample` and returns how many of its stubs were restored.
    ///
    /// Counting matters: the transform reports success as long as it restored
    /// *something*, so asserting only that it returned `Ok` cannot tell a full
    /// recovery from a partial one — and for a whole storage variant it could
    /// not tell recovery from nothing at all.
    fn restore_stub_bodies(sample: &str) -> (usize, usize) {
        let assembly = load_sample(sample);
        let technique = NetReactorNecroBit;
        let mut detection = technique.detect(&assembly);
        assert!(detection.is_detected(), "{sample}: should detect NecroBit");

        let stub_count = detection
            .findings::<NecroBitFindings>()
            .map(|f| f.stub_method_tokens.len())
            .unwrap_or(0);

        let mut working = WorkingAssembly::new(assembly);
        let events = match technique.byte_transform(&mut working, &mut detection) {
            Some(Ok(events)) => events,
            Some(Err(e)) => panic!("{sample}: byte_transform returned error: {e}"),
            None => panic!("{sample}: byte_transform returned None (skipped)"),
        };

        let restored = events
            .iter()
            .filter(|event| event.kind == EventKind::MethodBodyDecrypted && event.method.is_some())
            .count();
        (restored, stub_count)
    }

    /// Variant A: bodies live in a structured blob on the managed heap.
    #[test]
    fn restores_every_stub_in_a_necrobit_only_binary() {
        let (restored, stubs) = restore_stub_bodies("reactor_necrobit.exe");
        assert!(stubs > 0, "the sample must actually have stubs");
        assert_eq!(
            restored, stubs,
            "every encrypted body should come back, got {restored} of {stubs}"
        );
    }

    /// Variant B: the init writes bodies into the image at each method's RVA,
    /// which only works once the dynamically-resolved `VirtualProtect` has made
    /// those pages writable. Recovering nothing here is the exact regression
    /// this asserts against — it went unnoticed while the only check was that
    /// the transform returned `Ok`.
    #[test]
    fn restores_every_stub_in_a_full_protection_binary() {
        let (restored, stubs) = restore_stub_bodies("reactor_full.exe");
        assert!(stubs > 0, "the sample must actually have stubs");
        assert_eq!(
            restored, stubs,
            "every encrypted body should come back, got {restored} of {stubs}"
        );
    }

    #[test]
    fn test_detect_negative() {
        let _path = fixture("packers/netreactor/7.5.0/original.exe");

        let assembly = load_sample("original.exe");
        let technique = NetReactorNecroBit;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "NetReactorNecroBit should not detect NecroBit in original.exe"
        );
    }
}

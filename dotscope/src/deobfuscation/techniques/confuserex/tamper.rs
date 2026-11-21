//! ConfuserEx anti-tamper protection detection and decryption.
//!
//! ConfuserEx anti-tamper encrypts method bodies in a dedicated PE section to
//! prevent static analysis. At runtime, a module initializer decrypts the
//! section using `VirtualProtect` + XOR with a key derived from DynCipher.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiTamper/AntiTamperProtection.cs` — Entry point
//! - `Confuser.Runtime/AntiTamper.Normal.cs` — Normal mode runtime
//! - `Confuser.Runtime/AntiTamper.Anti.cs` — Anti mode (with anti-debug)
//! - `Confuser.Runtime/AntiTamper.JIT.cs` — JIT mode (hooks JIT compiler)
//!
//! Anti-tamper is part of the **Maximum** preset.
//!
//! # Protection Modes
//!
//! ## Normal Mode (`Mode.Normal`)
//!
//! Creates a custom PE section, moves **both** method bodies AND the Constants
//! chunk to this section, encrypts the **entire** section using XOR. At runtime,
//! decrypts in-place using `VirtualProtect` to make it writable.
//!
//! **IMPORTANT:** The Constants section contains FieldRVA initialization data.
//! When combined with Constants protection, the LZMA-compressed constant data
//! is also encrypted by anti-tamper. Decryption must extract **both** method
//! bodies AND FieldRVA data.
//!
//! ## Anti Mode (`Mode.Anti`)
//!
//! Same as Normal mode but with integrated anti-debug checks. The decryption
//! code is interleaved with `CheckRemoteDebuggerPresent` calls that trigger
//! `Environment.FailFast` if a debugger is detected.
//!
//! ## JIT Mode (`Mode.JIT`)
//!
//! Hooks the CLR JIT compiler via `LoadLibrary("clrjit.dll")` +
//! `GetProcAddress("getJit")`. Method bodies remain encrypted until JIT-compiled.
//!
//! # Injection Point
//!
//! Anti-tamper initialization is injected at position 0 in `<Module>::.cctor`.
//!
//! # Detection
//!
//! Anti-tamper methods are characterised by:
//! - `Marshal.GetHINSTANCE(typeof(...).Module)` to get module base
//! - `VirtualProtect` P/Invoke to make sections writable
//! - Absence of `Marshal.Copy` (which distinguishes anti-dump)
//! - Method body RVAs pointing into a non-standard PE section
//!
//! The key differentiator from anti-dump:
//! - **Anti-tamper**: VirtualProtect + GetHINSTANCE + get_Module (no Marshal.Copy)
//! - **Anti-dump**: VirtualProtect + GetHINSTANCE + get_Module + Marshal.Copy
//!
//! # Transform
//!
//! The decryption pipeline:
//! 1. Load the PE into emulator memory at `ImageBase`
//! 2. Find the anti-tamper initialization method via candidate scoring
//! 3. Emulate the initializer — decrypts the section in-place in virtual memory
//! 4. Extract ALL method bodies from the decrypted virtual image
//! 5. Extract decrypted FieldRVA data (Constants section is also encrypted)
//! 6. Rebuild the assembly via `CilAssembly` with decrypted bodies in `.text`
//!
//! This approach is fully generic — the obfuscator's own decryption code does
//! the work via emulation, so we don't hardcode encryption algorithms.
//!
//! **Why FieldRVA extraction is critical:** When Constants protection is combined
//! with Anti-Tamper, the LZMA-compressed constant data (stored at a FieldRVA) is
//! encrypted. Without extracting the decrypted FieldRVA data, the Constants
//! warmup receives encrypted data instead of LZMA data, causing LZMA hook
//! failure and incorrect deobfuscation results.
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Tamper | Notes |
//! |--------|-----------------|-------|
//! | `mkaring_normal.exe` | No | Normal preset (no anti-tamper) |
//! | `mkaring_maximum.exe` | Yes | Maximum preset |

use std::{any::Any, collections::HashSet, sync::Arc};

use crate::{
    cilassembly::GeneratorConfig,
    compiler::{EventKind, EventLog},
    deobfuscation::{
        techniques::{
            confuserex::helpers, Detection, Evidence, Technique, TechniqueCapability,
            TechniqueCategory, WorkingAssembly,
        },
        utils::find_methods_calling_apis,
    },
    emulation::{EmulationOutcome, ProcessBuilder},
    error::Error,
    metadata::{
        method::MethodImplCodeType,
        tables::{FieldRvaRaw, MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    CilObject, Result,
};

/// Findings from anti-tamper detection.
#[derive(Debug)]
pub struct AntiTamperFindings {
    /// Token of the anti-tamper initialization method, if identified.
    pub initializer_token: Option<Token>,
    /// Number of method bodies that appear to be encrypted.
    pub encrypted_method_count: usize,
    /// Names of PE sections containing encrypted method bodies.
    pub encrypted_section_names: Vec<String>,
}

/// Detects and decrypts ConfuserEx anti-tamper protected method bodies.
///
/// Requires `confuserex.metadata` to have run first so that invalid metadata
/// markers are patched before attempting to locate encrypted sections.
pub struct ConfuserExAntiTamper;

impl Technique for ConfuserExAntiTamper {
    fn id(&self) -> &'static str {
        "confuserex.tamper"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Anti-Tamper Decryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn requires(&self) -> &[&'static str] {
        &["confuserex.metadata"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };

        let mut encrypted_count = 0usize;

        // Pattern indices for find_methods_calling_apis results.
        const PAT_VIRTUAL_PROTECT: usize = 0;
        const PAT_GET_HINSTANCE: usize = 1;
        const PAT_GET_MODULE: usize = 2;
        const PAT_MARSHAL_COPY: usize = 3;

        let api_hits = find_methods_calling_apis(
            assembly,
            &[
                "VirtualProtect",
                "GetHINSTANCE",
                "get_Module",
                "Marshal.Copy",
            ],
        );

        // Build a set of MethodDef tokens that have P/Invoke mappings to
        // VirtualProtect. The ImplMap table's import_name field holds the
        // real DLL export name, which is never renamed by obfuscators.
        let pinvoke_vp_tokens = helpers::resolve_pinvoke_tokens(assembly, "VirtualProtect");
        let pinvoke_callers = helpers::find_methods_calling_tokens(assembly, &pinvoke_vp_tokens);

        // Phase 1: Find anti-tamper initializer method.
        // Look for a method that calls GetHINSTANCE + VirtualProtect + get_Module
        // but NOT Marshal.Copy (that would be anti-dump).
        let initializer_token = api_hits
            .iter()
            .find(|(token, indices)| {
                let has_virtualprotect =
                    indices.contains(&PAT_VIRTUAL_PROTECT) || pinvoke_callers.contains(token);
                let has_gethinstance = indices.contains(&PAT_GET_HINSTANCE);
                let has_get_module = indices.contains(&PAT_GET_MODULE);
                let has_marshal_copy = indices.contains(&PAT_MARSHAL_COPY);
                has_virtualprotect && has_gethinstance && has_get_module && !has_marshal_copy
            })
            .map(|(token, _)| *token);

        // Phase 2: Count encrypted method bodies.
        // ConfuserEx anti-tamper moves method bodies to a custom PE section.
        // After encryption, the original RVAs become invalid or point into
        // the encrypted section. We detect this by checking for methods whose
        // RVA points outside the standard .text section.
        let mut encrypted_section_names = HashSet::new();

        if let Some(method_table) = tables.table::<MethodDefRaw>() {
            let file = assembly.file();
            let sections = file.sections();
            let text_section = sections.iter().find(|s| s.name.starts_with(".text"));

            if let Some(text) = text_section {
                let text_rva_start = text.virtual_address as usize;
                let text_rva_end = text_rva_start.saturating_add(text.virtual_size as usize);

                for row in method_table {
                    let row = match row {
                        Ok(row) => row,
                        Err(e) => {
                            log::warn!("skipping unreadable metadata row: {e}");
                            continue;
                        }
                    };
                    if row.rva == 0 {
                        continue;
                    }

                    let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
                    if matches!(
                        code_type,
                        MethodImplCodeType::NATIVE | MethodImplCodeType::RUNTIME
                    ) {
                        continue;
                    }

                    let method_rva = row.rva as usize;

                    // Method body outside .text section suggests encryption
                    if method_rva < text_rva_start || method_rva >= text_rva_end {
                        encrypted_count = encrypted_count.saturating_add(1);

                        // Identify which section this RVA falls into
                        for section in sections {
                            let sec_start = section.virtual_address as usize;
                            let sec_end = sec_start.saturating_add(section.virtual_size as usize);
                            if method_rva >= sec_start && method_rva < sec_end {
                                encrypted_section_names.insert(section.name.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Must have either the initializer or encrypted methods to detect.
        if initializer_token.is_none() && encrypted_count == 0 {
            return Detection::new_empty();
        }

        // Note: FieldRVA entries in encrypted sections are NOT marked for deletion
        // here. The byte transform extracts and re-stores all decrypted FieldRVA
        // data (including legitimate <PrivateImplementationDetails> array initializers).
        // LZMA artifact fields are handled by the ConfuserEx constants technique
        // when that protection is also detected.

        let mut evidence = Vec::new();

        if let Some(token) = initializer_token {
            evidence.push(Evidence::BytecodePattern(format!(
                "Anti-tamper initializer at 0x{:08X}",
                token.value(),
            )));
        }
        if encrypted_count > 0 {
            evidence.push(Evidence::BytecodePattern(format!(
                "{encrypted_count} method bodies in encrypted section",
            )));
        }

        // Also exclude empty-named sections — these are obfuscator artifacts.
        // ConfuserEx creates unnamed sections as part of its protection scheme.
        {
            let file = assembly.file();
            for section in file.sections() {
                if section.name.is_empty() {
                    encrypted_section_names.insert(section.name.clone());
                }
            }
        }

        let encrypted_section_names: Vec<String> = encrypted_section_names.into_iter().collect();

        let findings = AntiTamperFindings {
            initializer_token,
            encrypted_method_count: encrypted_count,
            encrypted_section_names: encrypted_section_names.clone(),
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Mark anti-tamper initializer method for cleanup.
        if let Some(token) = initializer_token {
            detection.cleanup_mut().add_method(token);
        }

        // Mark artifact PE sections for exclusion from output.
        for name in &encrypted_section_names {
            detection.cleanup_mut().exclude_section(name);
        }

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<AntiTamperFindings>() else {
            return Some(Ok(events));
        };

        if findings.encrypted_method_count == 0 {
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

        // Step 2: Use the initializer method identified during detection.
        let decryptor_method = match findings.initializer_token.ok_or_else(|| {
            Error::Deobfuscation("No anti-tamper initialization method found".to_string())
        }) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Step 3: Find encrypted methods before decryption.
        let encrypted_methods = helpers::find_encrypted_methods(&cilobject_arc);

        // Step 4: Set up and run emulation.
        // ProcessBuilder automatically maps the PE image and registers BCL stubs
        // (GetHINSTANCE, VirtualProtect, VirtualAlloc, etc.).
        let process = match ProcessBuilder::new()
            .assembly_arc(Arc::clone(&cilobject_arc))
            .name("anti-tamper-emulation")
            .with_max_instructions(10_000_000)
            .with_max_call_depth(200)
            .with_timeout_ms(120_000) // 2 minutes
            .build()
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let loaded_image = match process
            .primary_image()
            .ok_or_else(|| Error::Deobfuscation("Failed to get loaded PE image info".to_string()))
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let pe_base = loaded_image.base_address;
        #[allow(clippy::cast_possible_truncation)]
        let virtual_size = loaded_image.size_of_image as usize;

        let outcome = match process.execute_method(decryptor_method, vec![]) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let instructions_executed = match outcome {
            EmulationOutcome::Completed { instructions, .. }
            | EmulationOutcome::Breakpoint { instructions, .. } => instructions,
            EmulationOutcome::LimitReached { limit, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "Anti-tamper emulation exceeded limit: {limit:?}"
                ))));
            }
            EmulationOutcome::Stopped { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "Anti-tamper emulation stopped: {reason}"
                ))));
            }
            EmulationOutcome::UnhandledException { exception, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "Anti-tamper emulation threw exception: {exception:?}"
                ))));
            }
            EmulationOutcome::RequiresSymbolic { reason, .. } => {
                return Some(Err(Error::Deobfuscation(format!(
                    "Anti-tamper emulation requires symbolic execution: {reason}"
                ))));
            }
        };

        // Step 5: Extract decrypted virtual image from emulator memory,
        // then drop the process to release its Arc<CilObject> reference.
        let virtual_image = match process.read_memory(pe_base, virtual_size) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        drop(process);

        log::info!(
            "Anti-tamper emulation completed: {} instructions executed via method 0x{:08x}",
            instructions_executed,
            decryptor_method.value()
        );

        // Step 6: Extract ALL method bodies from the decrypted image.
        // Not just encrypted ones — section layout changes invalidate all RVAs.
        let all_methods_with_rva = helpers::find_all_methods_with_rva(&cilobject_arc);
        let (extracted_bodies, body_failures) =
            extract_decrypted_bodies(&cilobject_arc, &virtual_image, &all_methods_with_rva);

        if extracted_bodies.is_empty() {
            return Some(Err(Error::Deobfuscation(
                "No method bodies could be extracted from decrypted image".to_string(),
            )));
        }
        if body_failures > 0 {
            log::warn!(
                "Failed to extract {} method bodies from decrypted image",
                body_failures
            );
        }

        // Step 7: Extract decrypted FieldRVA data (Constants section).
        let (extracted_fields, field_failures) =
            helpers::extract_decrypted_field_data(&cilobject_arc, &virtual_image);

        if field_failures > 0 {
            log::warn!(
                "Failed to extract {} field data entries from decrypted image",
                field_failures
            );
        }

        // Log each decrypted encrypted method body.
        let encrypted_count = encrypted_methods.len();
        for &token in &encrypted_methods {
            events
                .record(EventKind::MethodBodyDecrypted)
                .method(token)
                .message(format!("Decrypted method body 0x{:08x}", token.value()));
        }

        // Step 8: Create CilAssembly and store decrypted data.
        let cilobject = match Arc::try_unwrap(cilobject_arc)
            .map_err(|_| Error::Deobfuscation("Assembly still shared after emulation".into()))
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let mut cil_assembly = cilobject.into_assembly();

        // Store each extracted method body and update MethodDef RVAs.
        for (method_token, body_bytes) in extracted_bodies {
            let placeholder_rva = cil_assembly.store_method_body(body_bytes);
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

        // Store decrypted field data and update FieldRVA rows.
        let field_count = extracted_fields.len();
        for (rid, _original_rva, data) in extracted_fields {
            let placeholder_rva = cil_assembly.store_field_data(data);

            #[allow(clippy::redundant_closure_for_method_calls)]
            let existing_row = match cil_assembly
                .view()
                .tables()
                .and_then(|t| t.table::<FieldRvaRaw>())
                .and_then(|table| table.get(rid).ok().flatten())
                .ok_or_else(|| Error::Deobfuscation(format!("FieldRVA row {rid} not found")))
            {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let updated_row = FieldRvaRaw {
                rid: existing_row.rid,
                token: existing_row.token,
                offset: existing_row.offset,
                rva: placeholder_rva,
                field: existing_row.field,
            };

            if let Err(e) = cil_assembly.table_row_update(
                TableId::FieldRVA,
                rid,
                TableDataOwned::FieldRVA(updated_row),
            ) {
                return Some(Err(e));
            }
        }

        events.record(EventKind::AntiTamperRemoved).message(format!(
            "Anti-tamper protection removed: {} method bodies, {} field data entries decrypted",
            encrypted_count, field_count,
        ));

        // Step 9: Regenerate PE with decrypted bodies in .text section.
        // skip_original_method_bodies: we stored ALL bodies from the virtual image,
        // so the original encrypted bodies are no longer needed.
        // excluded_sections: remove the encrypted PE section(s) that held the
        // encrypted method bodies — these are artifacts of the protection.
        let excluded: HashSet<String> = findings.encrypted_section_names.iter().cloned().collect();
        let config = GeneratorConfig::default()
            .with_skip_original_method_bodies(true)
            .with_excluded_sections(excluded);
        let new_assembly =
            match cil_assembly.into_cilobject_with(ValidationConfig::analysis(), config) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

        // Step 10: Replace the working assembly with the rebuilt one.
        assembly.replace_assembly(new_assembly);

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Extracts all method bodies from a decrypted virtual image.
///
/// Returns `(bodies, failure_count)` where bodies is a vec of
/// `(method_token, body_bytes)` tuples.
fn extract_decrypted_bodies(
    assembly: &CilObject,
    virtual_image: &[u8],
    methods: &[Token],
) -> (Vec<(Token, Vec<u8>)>, usize) {
    let mut bodies = Vec::new();
    let mut failed_count: usize = 0;

    for &token in methods {
        let Some(rva) = helpers::get_method_rva(assembly, token) else {
            failed_count = failed_count.saturating_add(1);
            continue;
        };

        if rva == 0 || rva as usize >= virtual_image.len() {
            failed_count = failed_count.saturating_add(1);
            continue;
        }

        match helpers::extract_method_body_at_rva(virtual_image, rva) {
            Some(body_bytes) => {
                bodies.push((token, body_bytes));
            }
            None => {
                failed_count = failed_count.saturating_add(1);
            }
        }
    }

    (bodies, failed_count)
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::tamper::{AntiTamperFindings, ConfuserExAntiTamper},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_antitamper.exe");

        let technique = ConfuserExAntiTamper;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExAntiTamper should detect anti-tamper in mkaring_antitamper.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<AntiTamperFindings>()
            .expect("Should have AntiTamperFindings");

        assert!(
            findings.encrypted_method_count > 0 || findings.initializer_token.is_some(),
            "Should have encrypted methods or an initializer"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExAntiTamper;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExAntiTamper should not detect anti-tamper in original.exe"
        );
    }
}

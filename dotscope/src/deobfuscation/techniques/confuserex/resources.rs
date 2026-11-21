//! ConfuserEx resource protection detection and decryption.
//!
//! ConfuserEx resource protection moves embedded resources to a hidden
//! temporary assembly, compresses it with LZMA, encrypts it with XOR (Normal
//! mode) or a block cipher (Dynamic mode), and stores the result in a FieldRVA.
//! At runtime, an `AssemblyResolve` event handler decrypts and loads the hidden
//! assembly via `Assembly.Load`.
//!
//! # ConfuserEx Resource Protection Pipeline
//!
//! 1. All `EmbeddedResource` entries are moved to a hidden temporary assembly
//! 2. The hidden assembly is compressed with LZMA
//! 3. Encrypted with XOR (Normal) or block cipher (Dynamic) using xorshift key
//! 4. Stored in a FieldRVA (static field with raw data)
//! 5. A runtime stub registers an `AssemblyResolve`/`ResourceResolve` handler that
//!    reads the encrypted data, decrypts it, decompresses with LZMA, and returns
//!    the hidden assembly via `Assembly.Load`
//!
//! # Detection
//!
//! Scans methods for the characteristic resource handler pattern:
//! - `AppDomain.CurrentDomain` access
//! - `add_AssemblyResolve` / `add_ResourceResolve` event registration
//! - `Assembly.Load` calls for loading hidden assemblies
//! - Decompression calls (LZMA, GZip, Deflate)
//!
//! # Transform
//!
//! The decryption pipeline:
//! 1. Find resource handler methods via candidate scoring
//! 2. Emulate each candidate with LZMA hook and assembly capture enabled
//! 3. Extract hidden assemblies from captured `Assembly.Load` calls
//! 4. Parse hidden assemblies and extract `ManifestResource` entries
//! 5. Insert recovered resources back into the original assembly
//! 6. Rebuild PE via `CilAssembly`

use std::{any::Any, sync::Arc};

use crate::{
    cilassembly::GeneratorConfig,
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        confuserex::hooks::create_lzma_hook, Detection, Evidence, Technique, TechniqueCapability,
        TechniqueCategory, WorkingAssembly,
    },
    emulation::{EmulationOutcome, ProcessBuilder},
    error::Error,
    metadata::{
        tables::{
            skip_unreadable, ManifestResourceAttributes, ManifestResourceBuilder,
            ManifestResourceRaw, TableId,
        },
        token::Token,
        validation::ValidationConfig,
    },
    prelude::FlowType,
    CilObject, Result,
};

/// Findings from resource protection detection.
#[derive(Debug)]
pub struct ResourceFindings {
    /// Tokens of methods that register AssemblyResolve/ResourceResolve handlers.
    pub handler_tokens: Vec<Token>,
}

/// Detects ConfuserEx resource protection (encrypted embedded resources).
///
/// Looks for `add_AssemblyResolve` + `Assembly.Load` patterns that indicate
/// ConfuserEx has moved embedded resources to a hidden, encrypted assembly.
pub struct ConfuserExResources;

impl Technique for ConfuserExResources {
    fn id(&self) -> &'static str {
        "confuserex.resources"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Resource Protection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut handler_tokens = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            let mut has_assembly_resolve = false;
            let mut has_resource_resolve = false;
            let mut has_assembly_load = false;
            let mut has_current_domain = false;
            let mut has_decompress = false;

            for instr in method.instructions() {
                if instr.flow_type != FlowType::Call {
                    continue;
                }

                let Some(token) = instr.get_token_operand() else {
                    continue;
                };

                let Some(name) = resolve_call_name(assembly, token) else {
                    continue;
                };

                if name.contains("AppDomain") && name.contains("CurrentDomain") {
                    has_current_domain = true;
                }
                if name.contains("add_AssemblyResolve") || name.contains("AssemblyResolve") {
                    has_assembly_resolve = true;
                }
                if name.contains("add_ResourceResolve") || name.contains("ResourceResolve") {
                    has_resource_resolve = true;
                }
                if name.contains("Assembly") && name.contains("Load") {
                    has_assembly_load = true;
                }
                if name.contains("Decompress")
                    || name.contains("Lzma")
                    || name.contains("Inflate")
                    || name.contains("GZipStream")
                    || name.contains("DeflateStream")
                {
                    has_decompress = true;
                }
            }

            // Resource handler: registers resolve event + has assembly load or decompression
            let is_handler = (has_assembly_resolve || has_resource_resolve)
                && has_current_domain
                && (has_assembly_load || has_decompress);

            if is_handler {
                handler_tokens.push(method.token);
            }
        }

        if handler_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = handler_tokens.len();

        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} resource handler method(s) with AssemblyResolve + Assembly.Load",
            ))],
            Some(Box::new(ResourceFindings {
                handler_tokens: handler_tokens.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        // Mark resource handler methods for cleanup.
        for token in &handler_tokens {
            detection.cleanup_mut().add_method(*token);
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

        if findings.handler_tokens.is_empty() {
            return Some(Ok(events));
        }

        // Step 1: Create a CilObject from current assembly bytes for emulation.
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

        // Step 2: Try emulating each handler method identified during detection.
        let mut extracted_resources = Vec::new();

        for &handler_token in &findings.handler_tokens {
            match try_emulate_resource_handler(&cilobject_arc, handler_token) {
                Ok(resources) if !resources.is_empty() => {
                    log::info!(
                        "Extracted {} resources via method 0x{:08x}",
                        resources.len(),
                        handler_token.value()
                    );
                    for res in &resources {
                        log::info!("  Resource: {} ({} bytes)", res.name, res.data.len());
                    }
                    extracted_resources = resources;
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    log::warn!(
                        "Resource emulation failed for 0x{:08x}: {}",
                        handler_token.value(),
                        e
                    );
                }
            }
        }

        if extracted_resources.is_empty() {
            events.record(EventKind::ArtifactRemoved).message(
                "Resource handler detected but no resources could be extracted".to_string(),
            );
            return Some(Ok(events));
        }

        // Step 4: Insert extracted resources into the assembly via CilAssembly.
        let cilobject = match Arc::try_unwrap(cilobject_arc)
            .map_err(|_| Error::Deobfuscation("Assembly still shared after emulation".into()))
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let mut cil_assembly = cilobject.into_assembly();

        // Remove existing ManifestResource rows with matching names.
        let names_to_insert: std::collections::HashSet<_> = extracted_resources
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        let replaced = find_manifest_resources_by_name(&cil_assembly, &names_to_insert);
        // The rows being replaced are in the application's own order, which
        // `GetManifestResourceNames` returns; the hidden assembly's order is
        // ConfuserEx's. A resource no row named goes after them, as found.
        let position = |name: &str| {
            replaced
                .iter()
                .position(|(_, replaced_name)| replaced_name == name)
                .unwrap_or(usize::MAX)
        };
        extracted_resources.sort_by_key(|resource| position(&resource.name));
        for (rid, _) in replaced {
            if let Err(e) = cil_assembly.table_row_remove(TableId::ManifestResource, rid) {
                log::warn!("Failed to remove existing ManifestResource row {rid}: {e}");
            }
        }

        // Insert each extracted resource.
        let mut inserted_count: usize = 0;
        for resource in &extracted_resources {
            let builder = ManifestResourceBuilder::new()
                .name(&resource.name)
                .flags(resource.flags)
                .resource_data(&resource.data);

            match builder.build(&mut cil_assembly) {
                Ok(_) => {
                    inserted_count = inserted_count.saturating_add(1);
                    log::info!(
                        "Inserted resource: {} ({} bytes)",
                        resource.name,
                        resource.data.len()
                    );
                }
                Err(e) => {
                    log::warn!("Failed to insert resource '{}': {}", resource.name, e);
                }
            }
        }

        if inserted_count > 0 {
            events
                .record(EventKind::ArtifactRemoved)
                .message(format!("Restored {} encrypted resource(s)", inserted_count,));
        }

        // Step 5: Rebuild PE with inserted resources.
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
}

/// A resource extracted from a hidden ConfuserEx assembly.
struct ExtractedResource {
    name: String,
    flags: ManifestResourceAttributes,
    data: Vec<u8>,
}

/// Emulates a single resource handler to extract hidden assemblies and resources.
fn try_emulate_resource_handler(
    assembly: &Arc<CilObject>,
    method_token: Token,
) -> Result<Vec<ExtractedResource>> {
    let process = ProcessBuilder::new()
        .assembly_arc(Arc::clone(assembly))
        .with_max_instructions(2_000_000)
        .with_max_call_depth(100)
        .capture_assemblies()
        .hook(create_lzma_hook())
        .build()?;

    let outcome = process.execute_method(method_token, vec![])?;
    match outcome {
        EmulationOutcome::Completed { .. } | EmulationOutcome::Breakpoint { .. } => {}
        EmulationOutcome::LimitReached { limit, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation exceeded limit: {limit:?}"
            )));
        }
        EmulationOutcome::Stopped { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation stopped: {reason}"
            )));
        }
        EmulationOutcome::UnhandledException { exception, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation threw exception: {exception:?}"
            )));
        }
        EmulationOutcome::RequiresSymbolic { reason, .. } => {
            return Err(Error::Deobfuscation(format!(
                "Resource emulation requires symbolic execution: {reason}"
            )));
        }
    }

    // Extract resources from captured hidden assemblies.
    let mut resources = Vec::new();
    for captured_asm in process.capture().assemblies().iter() {
        let data = &captured_asm.data;
        if data.first() != Some(&b'M') || data.get(1) != Some(&b'Z') {
            continue;
        }

        let Ok(hidden) =
            CilObject::from_mem_with_validation(data.clone(), ValidationConfig::disabled())
        else {
            continue;
        };

        let hidden_resources = hidden.resources();
        for entry in hidden_resources {
            let manifest = entry.value();
            if manifest.source.is_some() {
                continue;
            }
            if let Some(resource_data) = hidden_resources.get_data(manifest) {
                resources.push(ExtractedResource {
                    name: manifest.name.to_string(),
                    flags: manifest.flags,
                    data: resource_data.to_vec(),
                });
            }
        }
    }

    Ok(resources)
}

/// Finds the ManifestResource rows named by any of the given names, as
/// `(row id, name)` in table order.
fn find_manifest_resources_by_name(
    cil_assembly: &crate::cilassembly::CilAssembly,
    names: &std::collections::HashSet<&str>,
) -> Vec<(u32, String)> {
    let view = cil_assembly.view();
    let Some(strings) = view.strings() else {
        return Vec::new();
    };
    let Some(tables) = view.tables() else {
        return Vec::new();
    };
    let Some(manifest_table) = tables.table::<ManifestResourceRaw>() else {
        return Vec::new();
    };

    manifest_table
        .iter()
        .filter_map(skip_unreadable)
        .filter_map(|row| {
            strings
                .get(row.name as usize)
                .ok()
                .filter(|name| names.contains(*name))
                .map(|name| (row.rid, name.to_string()))
        })
        .collect()
}

/// Resolves a call target token to a human-readable name.
fn resolve_call_name(assembly: &CilObject, token: Token) -> Option<String> {
    let table_id = token.table();

    match table_id {
        // MethodDef
        0x06 => {
            let method = assembly.method(&token).ok()?;
            Some(method.name.to_string())
        }
        // MemberRef
        0x0A => {
            let member_ref = assembly.member_ref(&token)?;
            Some(match member_ref.declaredby.fullname() {
                Some(type_name) => format!("{type_name}::{}", member_ref.name),
                None => format!("Unknown::{}", member_ref.name),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::resources::{ConfuserExResources, ResourceFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_resources.exe");

        let technique = ConfuserExResources;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExResources should detect resource protection in mkaring_resources.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<ResourceFindings>()
            .expect("Should have ResourceFindings");

        assert!(
            !findings.handler_tokens.is_empty(),
            "Should have resource handler tokens"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExResources;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExResources should not detect resource protection in original.exe"
        );
    }
}

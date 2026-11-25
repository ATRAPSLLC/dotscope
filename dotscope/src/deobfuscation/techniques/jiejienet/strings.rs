//! JIEJIE.NET string encryption detection.
//!
//! Detects string encryption classes injected by JIEJIE.NET by their structural
//! pattern: classes containing a static method with signature
//! `string(byte[], int64)` (the `dcsoft` XOR decryptor). Detection is purely
//! structural and works when names are renamed.
//!
//! # Normal Mode
//!
//! The class (typically `_Strings<N>`) contains:
//! - Multiple `static string` fields, each holding one decrypted string
//! - A `.cctor` that calls the decryptor once per field during type initialization
//! - A single `dcsoft(byte[], int64) -> string` decryptor method
//!
//! # High-Strength Mode
//!
//! The class (typically `_HightStrings<N>`) uses per-access decryption:
//! - Per-string `static string()` accessor methods (no params, returns string)
//! - Each accessor calls the decryptor on every invocation (no field caching)
//! - A single `dcsoft(byte[], int64) -> string` decryptor method
//! - A `_Data` field holding the cached encrypted byte array
//!
//! # Detection
//!
//! 1. Scan all types for a static method with signature `string(byte[], int64)`
//! 2. Classify as normal (has string fields) or high-strength (has accessor methods)
//! 3. Separately detect the `ByteArrayDataContainer` by its ExplicitLayout nested
//!    types and `byte[]`-returning accessor methods
//! 4. Populate [`StringFindings`] with class tokens, decryptor tokens, and mode

use std::{any::Any, sync::Arc};

use crate::{
    analysis::CilTarget,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{StaticFieldResolutionPass, StringExtractor},
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
    },
    metadata::{
        signatures::TypeSignature,
        tables::TypeAttributes,
        token::Token,
        typesystem::{wellknown, CilType},
    },
    CilObject,
};

/// Findings from JIEJIE.NET string encryption detection.
#[derive(Debug)]
pub struct StringFindings {
    /// Detected string encryption classes (normal or high-strength).
    pub string_classes: Vec<StringClassInfo>,
    /// Whether high-strength mode was detected.
    pub high_strength: bool,
    /// Token of the ByteArrayDataContainer class, if found.
    pub data_container: Option<Token>,
}

/// Information about a single string encryption class.
#[derive(Debug)]
pub struct StringClassInfo {
    /// Token of the string class.
    pub type_token: Token,
    /// Token of the dcsoft decryptor method.
    pub decryptor_token: Token,
    /// Token of the .cctor method.
    pub cctor_token: Option<Token>,
    /// Tokens of string fields (normal mode) or accessor methods (high-strength).
    pub string_tokens: Vec<Token>,
    /// Whether this is a high-strength class.
    pub is_high_strength: bool,
}

/// Detects JIEJIE.NET string encryption classes by the `dcsoft` method signature.
pub struct JiejieNetStrings;

impl Technique for JiejieNetStrings {
    fn id(&self) -> &'static str {
        "jiejienet.strings"
    }

    fn name(&self) -> &'static str {
        "JIEJIE.NET String Encryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut string_classes: Vec<StringClassInfo> = Vec::new();
        let mut data_container: Option<Token> = None;
        let mut has_high_strength = false;

        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Look for the dcsoft(byte[], int64) -> string signature
            let mut dcsoft_token: Option<Token> = None;
            let mut cctor_token: Option<Token> = None;
            let mut string_fields: Vec<Token> = Vec::new();
            let mut string_accessors: Vec<Token> = Vec::new();

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };

                if method.name == wellknown::members::CCTOR {
                    cctor_token = Some(method.token);
                    continue;
                }

                if method.name == ".ctor" {
                    continue;
                }

                let sig = &method.signature;

                // Check for dcsoft signature: string(byte[], int64)
                let p0_is_szarray = sig
                    .params
                    .first()
                    .is_some_and(|p| matches!(p.base, TypeSignature::SzArray(_)));
                let p1_is_i8 = sig
                    .params
                    .get(1)
                    .is_some_and(|p| matches!(p.base, TypeSignature::I8));
                if matches!(sig.return_type.base, TypeSignature::String)
                    && sig.params.len() == 2
                    && p0_is_szarray
                    && p1_is_i8
                    && method.is_static()
                {
                    dcsoft_token = Some(method.token);
                    continue;
                }

                // Check for string accessor (high-strength): static string(), no params
                if matches!(sig.return_type.base, TypeSignature::String)
                    && sig.params.is_empty()
                    && method.is_static()
                {
                    string_accessors.push(method.token);
                }
            }

            // No dcsoft method — not a string encryption class
            let Some(decryptor_token) = dcsoft_token else {
                // Check if this might be a ByteArrayDataContainer
                // (class with nested ExplicitLayout types and byte[] accessor methods)
                if data_container.is_none() && is_byte_array_data_container(cil_type) {
                    data_container = Some(cil_type.token);
                }
                continue;
            };

            // Collect static string fields (normal mode)
            for (_, field) in cil_type.fields.iter() {
                if field.flags.is_static() && matches!(field.signature.base, TypeSignature::String)
                {
                    string_fields.push(field.token);
                }
            }

            // Determine mode: high-strength if there are accessor methods but few/no string fields
            let is_high_strength =
                string_accessors.len() > string_fields.len() && !string_accessors.is_empty();

            if is_high_strength {
                has_high_strength = true;
            }

            let string_tokens = if is_high_strength {
                string_accessors
            } else {
                string_fields
            };

            // Must have at least one string target (field or accessor)
            if string_tokens.is_empty() {
                continue;
            }

            string_classes.push(StringClassInfo {
                type_token: cil_type.token,
                decryptor_token,
                cctor_token,
                string_tokens,
                is_high_strength,
            });
        }

        if string_classes.is_empty() {
            return Detection::new_empty();
        }

        let total_strings: usize = string_classes.iter().map(|c| c.string_tokens.len()).sum();
        let mode = if has_high_strength {
            "high-strength"
        } else {
            "normal"
        };

        let evidence = vec![Evidence::Structural(format!(
            "{} string encryption class(es) with dcsoft(byte[], int64) decryptor, {} strings ({})",
            string_classes.len(),
            total_strings,
            mode,
        ))];

        let findings = StringFindings {
            string_classes,
            high_strength: has_high_strength,
            data_container,
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Pre-populate cleanup — collect all tokens before mutating
        let (type_tokens, data_container_token) = {
            let Some(findings_ref) = detection.findings::<StringFindings>() else {
                return detection;
            };
            let tokens: Vec<Token> = findings_ref
                .string_classes
                .iter()
                .map(|c| c.type_token)
                .collect();
            (tokens, findings_ref.data_container)
        };
        for token in type_tokens {
            detection.cleanup_mut().add_type(token);
        }
        if let Some(dc) = data_container_token {
            detection.cleanup_mut().add_type(dc);
        }

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<StringFindings>() else {
            return;
        };

        // Register ByteArrayDataContainer .cctor FIRST — the string class .cctors
        // depend on data container methods (_0(), _1()) which require the container's
        // .cctor to have run. Warmup executes methods in registration order.
        if let Some(dc_token) = findings.data_container {
            if let Some(dc_type) = assembly.types().get(&dc_token) {
                if let Some(cctor) = dc_type.cctor() {
                    log::info!(
                        "JIEJIE.NET strings: registering ByteArrayDataContainer .cctor (0x{:08X}) as warmup",
                        cctor.value()
                    );
                    ctx.register_warmup_method(cctor, vec![]);
                }
            }
        }

        for class in &findings.string_classes {
            // Register .cctor as warmup to ensure the emulation template pool is
            // created and the .cctor runs during warmup. This populates string
            // fields (normal mode) or the _Data field (high-strength mode).
            if let Some(cctor_token) = class.cctor_token {
                ctx.register_warmup_method(cctor_token, vec![]);
            }

            // High-strength mode: register accessor methods as decryptors
            // for the shared DecryptionPass (each accessor is a parameterless
            // method returning a decrypted string)
            if class.is_high_strength {
                for token in &class.string_tokens {
                    ctx.decryptors.register(*token);
                }
                log::info!(
                    "JIEJIE.NET strings: registered {} high-strength accessor(s) as decryptors",
                    class.string_tokens.len(),
                );
            }
        }
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<StringFindings>() else {
            return Vec::new();
        };
        let Some(pool) = ctx.template_pool.get().cloned() else {
            return Vec::new();
        };

        // Collect normal-mode string field tokens
        let mut field_tokens: Vec<Token> = Vec::new();

        for class in &findings.string_classes {
            if !class.is_high_strength {
                field_tokens.extend_from_slice(&class.string_tokens);
            }
        }

        // Only create the field pass if there are normal-mode string fields.
        // High-strength mode is handled by the shared DecryptionPass.
        if field_tokens.is_empty() {
            return Vec::new();
        }

        vec![Box::new(StaticFieldResolutionPass::new(
            "jiejie-string-fields",
            "Replaces JIEJIE.NET encrypted string field loads with decrypted string constants",
            pool,
            None,
            field_tokens,
            Box::new(StringExtractor),
            vec![],
        ))]
    }
}

/// Checks if a type is a ByteArrayDataContainer.
///
/// Structural pattern: class with nested types that have ExplicitLayout
/// and methods returning `byte[]`.
fn is_byte_array_data_container(cil_type: &CilType) -> bool {
    // Must have nested types
    if cil_type.nested_types.is_empty() {
        return false;
    }

    // Must have methods returning byte[]
    let mut has_byte_array_methods = false;
    for (_, method_ref) in cil_type.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };
        if method.name == wellknown::members::CTOR || method.name == wellknown::members::CCTOR {
            continue;
        }
        if let TypeSignature::SzArray(_) = &method.signature.return_type.base {
            has_byte_array_methods = true;
            break;
        }
    }

    if !has_byte_array_methods {
        return false;
    }

    // Check nested types for ExplicitLayout (RVA-backed data storage)
    let mut explicit_layout_count: usize = 0;
    for (_, nested_ref) in cil_type.nested_types.iter() {
        if let Some(nested) = nested_ref.upgrade() {
            if nested.flags.layout() == TypeAttributes::EXPLICIT_LAYOUT {
                explicit_layout_count = explicit_layout_count.saturating_add(1);
            }
        }
    }

    explicit_layout_count >= 1
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        deobfuscation::techniques::Technique,
        emulation::{EmValue, EmulationOutcome},
        testkit::{emulation::process_builder, helpers::load_sample},
    };

    #[test]
    fn test_detect_positive_strings_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_strings_only.exe");
        let technique = JiejieNetStrings;
        let detection = technique.detect(&asm);

        assert!(detection.is_detected(), "Should detect string encryption");

        let findings = detection
            .findings::<StringFindings>()
            .expect("Should have StringFindings");

        assert_eq!(
            findings.string_classes.len(),
            2,
            "Should find 2 string classes"
        );
        assert!(!findings.high_strength, "Should be normal mode");
        assert!(
            findings.data_container.is_some(),
            "Should find ByteArrayDataContainer"
        );
    }

    #[test]
    fn test_detect_positive_highstrings() {
        let asm = load_sample("packers/jiejie/source/jiejie_highstrings.exe");
        let technique = JiejieNetStrings;
        let detection = technique.detect(&asm);

        assert!(
            detection.is_detected(),
            "Should detect high-strength strings"
        );

        let findings = detection
            .findings::<StringFindings>()
            .expect("Should have StringFindings");

        assert!(findings.high_strength, "Should detect high-strength mode");
        assert!(
            !findings.string_classes.is_empty(),
            "Should find at least one string class"
        );
    }

    #[test]
    fn test_detect_negative_controlflow_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_controlflow_only.exe");
        let technique = JiejieNetStrings;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "Should not detect strings in controlflow-only sample"
        );
    }

    #[test]
    fn test_detect_negative_original() {
        let asm = load_sample("packers/jiejie/source/original.exe");
        let technique = JiejieNetStrings;
        let detection = technique.detect(&asm);

        assert!(!detection.is_detected(), "Should not detect in original");
    }

    /// Targeted test: emulate the string .cctor to understand why fields aren't populated.
    ///
    /// This test creates an emulation process, runs the ByteArrayDataContainer .cctor
    /// first (dependency), then the string class .cctor, and checks the results.
    #[test]
    fn test_emulate_string_cctor() {
        let asm = load_sample("packers/jiejie/source/jiejie_strings_only.exe");
        let technique = JiejieNetStrings;
        let detection = technique.detect(&asm);
        assert!(detection.is_detected());

        let findings = detection.findings::<StringFindings>().unwrap();
        assert_eq!(findings.string_classes.len(), 2);

        let class = &findings.string_classes[0]; // _Strings78
        let cctor_token = class.cctor_token.unwrap();
        eprintln!("String class type: 0x{:08X}", class.type_token.value());
        eprintln!("String class .cctor: 0x{:08X}", cctor_token.value());
        eprintln!("String class fields: {}", class.string_tokens.len());
        eprintln!(
            "Data container: {:?}",
            findings
                .data_container
                .map(|t| format!("0x{:08X}", t.value()))
        );

        // Find the ByteArrayDataContainer .cctor
        let dc_cctor = findings
            .data_container
            .and_then(|dc_token| asm.types().get(&dc_token).and_then(|t| t.cctor()));
        eprintln!(
            "DataContainer .cctor: {:?}",
            dc_cctor.map(|t| format!("0x{:08X}", t.value()))
        );

        // Create emulation process with the assembly
        let asm_arc = Arc::new(asm);
        let mut process = process_builder()
            .assembly_arc(Arc::clone(&asm_arc))
            .for_analysis()
            .with_max_instructions(1_000_000)
            .build()
            .expect("Failed to create emulation process");

        // Step 1: Run ByteArrayDataContainer .cctor first (dependency)
        if let Some(dc_cctor_token) = dc_cctor {
            eprintln!(
                "\n--- Running ByteArrayDataContainer .cctor (0x{:08X}) ---",
                dc_cctor_token.value()
            );
            let fork = process.fork().expect("Fork failed");
            match fork.execute_method(dc_cctor_token, vec![]) {
                Ok(EmulationOutcome::Completed { instructions, .. }) => {
                    eprintln!("  Completed: {} instructions", instructions);
                    process = fork; // Adopt state with container initialized
                }
                Ok(outcome) => {
                    eprintln!("  Did not complete: {}", outcome);
                    process = fork; // Adopt partial state
                }
                Err(e) => {
                    eprintln!("  Error: {}", e);
                }
            }
        }

        // Step 2: Run the string class .cctor
        eprintln!(
            "\n--- Running String .cctor (0x{:08X}) ---",
            cctor_token.value()
        );
        let fork = process.fork().expect("Fork failed");
        let outcome = fork.execute_method(cctor_token, vec![]);
        match &outcome {
            Ok(EmulationOutcome::Completed { instructions, .. }) => {
                eprintln!("  Completed: {} instructions", instructions);
            }
            Ok(EmulationOutcome::UnhandledException {
                exception,
                instructions,
                ..
            }) => {
                eprintln!(
                    "  Unhandled exception after {} instructions: {:?}",
                    instructions, exception
                );
            }
            Ok(outcome) => {
                eprintln!("  Other outcome: {}", outcome);
            }
            Err(e) => {
                eprintln!("  Error: {}", e);
            }
        }

        // Check if any string fields were populated
        let result_process = match &outcome {
            Ok(
                EmulationOutcome::Completed { .. } | EmulationOutcome::UnhandledException { .. },
            ) => &fork,
            _ => &process,
        };

        let mut found = 0;
        let mut not_found = 0;
        for (i, field_token) in class.string_tokens.iter().take(5).enumerate() {
            match result_process.get_static(*field_token) {
                Ok(Some(EmValue::ObjectRef(href))) => {
                    match result_process.address_space().get_string(href) {
                        Ok(s) => {
                            eprintln!("  field[{}] 0x{:08X} = \"{}\"", i, field_token.value(), s);
                            found += 1;
                        }
                        Err(e) => {
                            eprintln!(
                                "  field[{}] 0x{:08X} = ObjectRef but get_string failed: {}",
                                i,
                                field_token.value(),
                                e
                            );
                        }
                    }
                }
                Ok(Some(val)) => {
                    eprintln!("  field[{}] 0x{:08X} = {:?}", i, field_token.value(), val);
                }
                Ok(None) => {
                    eprintln!("  field[{}] 0x{:08X} = None", i, field_token.value());
                    not_found += 1;
                }
                Err(e) => {
                    eprintln!(
                        "  field[{}] 0x{:08X} = Error: {}",
                        i,
                        field_token.value(),
                        e
                    );
                }
            }
        }
        eprintln!(
            "\n  Summary: {} found, {} not found (of first 5)",
            found, not_found
        );

        // Also check total statics
        if let Ok(tokens) = result_process.address_space().statics().field_tokens() {
            eprintln!("  Total statics in process: {}", tokens.len());
            for (i, t) in tokens.iter().take(10).enumerate() {
                let val = result_process.get_static(*t);
                eprintln!("    static[{}]: 0x{:08X} = {:?}", i, t.value(), val);
            }
        }

        assert!(
            found > 0,
            "Expected at least some string fields to be populated after .cctor emulation"
        );
    }
}

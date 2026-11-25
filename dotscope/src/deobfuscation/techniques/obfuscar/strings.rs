//! Obfuscar string hiding detection and decryption setup.
//!
//! Detects the `<PrivateImplementationDetails>{GUID}` helper type injected by
//! Obfuscar for XOR-based string hiding, and registers accessor methods for
//! emulation-based decryption.
//!
//! # Helper Type Structure
//!
//! ```text
//! <PrivateImplementationDetails>{GUID}
//! ├── Method "6": static string(int32, int32, int32) — shared getter
//! ├── .cctor: XOR decryption loop (key byte extracted for detection)
//! ├── Per-string accessors: static string() methods — user code calls these
//! ├── Fields: Encrypted data storage
//! └── Nested ExplicitLayout struct: FieldRVA data source
//! ```
//!
//! # Detection
//!
//! Scans for types with namespace starting with `<PrivateImplementationDetails>{`.
//! Validates the structure by checking for method "6" with correct signature and
//! per-string accessor methods. Extracts the XOR key from `.cctor` for evidence.
//!
//! # Decryption Flow
//!
//! 1. Register `.cctor` as warmup method (runs XOR decryption loop)
//! 2. Register all per-string accessor methods as decryptors
//! 3. The shared `DecryptionPass` emulates each accessor to retrieve strings
//! 4. Cleanup removes the helper type and all its infrastructure

use std::any::Any;

use crate::{
    cilassembly::CleanupRequest,
    compiler::PassPhase,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
    },
    metadata::{
        signatures::TypeSignature, tables::TypeAttributes, token::Token, typesystem::wellknown,
    },
    CilObject,
};

/// Findings from Obfuscar string hiding detection.
#[derive(Debug)]
pub struct ObfuscarStringFindings {
    /// Token of the `<PrivateImplementationDetails>{GUID}` helper type.
    pub helper_type: Token,
    /// Tokens of per-string accessor methods (called from user code).
    pub accessor_methods: Vec<Token>,
    /// Token of the `.cctor` method (warmup — runs XOR decryption loop).
    pub cctor_token: Option<Token>,
    /// Tokens of infrastructure fields (encrypted data, etc.).
    pub data_fields: Vec<Token>,
    /// Tokens of nested infrastructure types.
    pub nested_types: Vec<Token>,
    /// Extracted XOR key byte from `.cctor` (for evidence/detection).
    pub xor_key: Option<u8>,
}

/// Detects Obfuscar's XOR-based string hiding and registers decryptors.
pub struct ObfuscarStrings;

impl Technique for ObfuscarStrings {
    fn id(&self) -> &'static str {
        "obfuscar.strings"
    }

    fn name(&self) -> &'static str {
        "Obfuscar String Hiding"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.strings"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Check for the characteristic namespace pattern
            if !is_obfuscar_helper_type(&cil_type.namespace) {
                continue;
            }

            // Check for method "6" (shared string getter) and accessor methods
            let mut has_method_6 = false;
            let mut accessor_methods: Vec<Token> = Vec::new();
            let mut cctor_token: Option<Token> = None;

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };

                if method.name == "6" {
                    let sig = &method.signature;
                    let returns_string = matches!(sig.return_type.base, TypeSignature::String);
                    let has_3_params = sig.params.len() == 3;
                    if returns_string && has_3_params {
                        has_method_6 = true;
                    }
                } else if method.name == wellknown::members::CCTOR {
                    cctor_token = Some(method.token);
                } else if method.name == wellknown::members::CTOR {
                    // Skip instance constructor
                } else {
                    // Potential per-string accessor method: static, returns string, no params
                    let sig = &method.signature;
                    let returns_string = matches!(sig.return_type.base, TypeSignature::String);
                    let no_params = sig.params.is_empty();
                    if returns_string && no_params {
                        accessor_methods.push(method.token);
                    }
                }
            }

            if !has_method_6 || accessor_methods.is_empty() {
                continue;
            }

            // Collect infrastructure fields and nested types
            let mut data_fields: Vec<Token> = Vec::new();
            let mut nested_types: Vec<Token> = Vec::new();
            let mut evidence = Vec::new();

            evidence.push(Evidence::TypePattern(format!(
                "Obfuscar helper type '{}.{}' with method 6 and {} accessor methods",
                cil_type.namespace,
                cil_type.name,
                accessor_methods.len()
            )));

            // Collect fields from the helper type
            for (_, field) in cil_type.fields.iter() {
                data_fields.push(field.token);
            }

            // Collect nested types and their fields
            for (_, nested_ref) in cil_type.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    nested_types.push(nested_type.token);
                    for (_, field) in nested_type.fields.iter() {
                        data_fields.push(field.token);
                    }

                    if nested_type.flags.layout() == TypeAttributes::EXPLICIT_LAYOUT {
                        evidence.push(Evidence::Structural(
                            "Nested ExplicitLayout struct (FieldRVA data source)".to_string(),
                        ));
                    }
                }
            }

            // Extract XOR key from .cctor
            let xor_key = cctor_token.and_then(|t| extract_xor_key_from_cctor(assembly, t));
            if let Some(key) = xor_key {
                evidence.push(Evidence::BytecodePattern(format!(
                    "XOR decryption loop in .cctor (key=0x{key:02X})"
                )));
            } else if cctor_token.is_some() {
                log::warn!(
                    "Obfuscar: failed to extract XOR key from .cctor — \
                     .cctor layout may differ from expected xor/ldc.i4/xor pattern"
                );
            }

            if accessor_methods.len() >= 5 {
                evidence.push(Evidence::MetadataPattern(format!(
                    "{} per-string accessor methods",
                    accessor_methods.len()
                )));
            }

            // Capture nested type tokens before moving findings into the Box
            let nested_type_tokens: Vec<Token> = nested_types.to_vec();

            let findings = ObfuscarStringFindings {
                helper_type: cil_type.token,
                accessor_methods,
                cctor_token,
                data_fields,
                nested_types,
                xor_key,
            };

            let mut detection = Detection::new_detected(
                evidence,
                Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
            );

            // Pre-populate cleanup with infrastructure tokens
            detection.cleanup_mut().add_type(cil_type.token);
            for token in &nested_type_tokens {
                detection.cleanup_mut().add_type(*token);
            }

            return detection;
        }

        Detection::new_empty()
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        _assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<ObfuscarStringFindings>() else {
            return;
        };

        // Register the .cctor as a warmup method. The .cctor runs the XOR
        // decryption loop to populate the decrypted byte array in memory.
        // This must execute before accessor methods can return strings.
        if let Some(cctor_token) = findings.cctor_token {
            log::info!(
                "Obfuscar: registering helper .cctor (0x{:08X}) as warmup",
                cctor_token.value()
            );
            ctx.register_warmup_method(cctor_token, vec![]);
        }

        // Register accessor methods as decryptors. Each accessor is a static
        // parameterless method returning string — user code calls these instead
        // of ldstr. The DecryptionPass will emulate each one to retrieve the
        // decrypted string.
        for token in &findings.accessor_methods {
            ctx.decryptors.register(*token);
        }

        log::info!(
            "Obfuscar: registered {} string accessor method(s) for emulation",
            findings.accessor_methods.len()
        );
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<ObfuscarStringFindings>()?;

        let mut request = CleanupRequest::new();

        // Remove helper type and nested types
        request.add_type(findings.helper_type);
        request.add_types(findings.nested_types.iter().copied());

        // Remove accessor methods (dead after call site replacement)
        request.add_methods(findings.accessor_methods.iter().copied());

        // Remove infrastructure fields
        request.add_fields(findings.data_fields.iter().copied());

        if request.has_deletions() {
            Some(request)
        } else {
            None
        }
    }
}

/// Checks if a type namespace matches the Obfuscar helper type pattern.
///
/// Obfuscar injects types with namespace `<PrivateImplementationDetails>{GUID}`.
fn is_obfuscar_helper_type(namespace: &str) -> bool {
    let prefix = "<PrivateImplementationDetails>{";
    namespace.starts_with(prefix) && namespace.len() > prefix.len()
}

/// Extracts the XOR key from the `.cctor` method of the helper type.
///
/// Scans for the characteristic double-XOR pattern: `xor`, `ldc.i4 <KEY>`, `xor`.
/// The constant between the two `xor` instructions is the encryption key byte.
fn extract_xor_key_from_cctor(assembly: &CilObject, cctor_token: Token) -> Option<u8> {
    let method = assembly.method(&cctor_token).ok()?;
    let instructions: Vec<_> = method.instructions().collect();

    for window in instructions.windows(3) {
        let (Some(w0), Some(w1), Some(w2)) = (window.first(), window.get(1), window.get(2)) else {
            continue;
        };
        if w0.mnemonic == "xor" && w2.mnemonic == "xor" {
            if let Some(val) = w1.get_i32_operand() {
                if (0..=255).contains(&val) {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    return Some(val as u8);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            obfuscar::strings::{is_obfuscar_helper_type, ObfuscarStringFindings, ObfuscarStrings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive_obfuscar_strings_only() {
        let asm = load_sample("packers/obfuscar/2.2.50/obfuscar_strings_only.exe");

        let technique = ObfuscarStrings;
        let detection = technique.detect(&asm);

        assert!(
            detection.is_detected(),
            "ObfuscarStrings should detect string hiding in obfuscar_strings_only.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );

        // Verify findings are populated
        let findings = detection
            .findings::<ObfuscarStringFindings>()
            .expect("Findings should be ObfuscarStringFindings");

        assert!(
            findings.helper_type.value() != 0,
            "Helper type token should be non-zero"
        );
        assert!(
            !findings.accessor_methods.is_empty(),
            "Should have at least one accessor method"
        );
        assert!(
            findings.cctor_token.is_some(),
            "Should have a .cctor token for the helper type"
        );
    }

    #[test]
    fn test_detect_negative_confuserex_original() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ObfuscarStrings;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "ObfuscarStrings should not detect anything in a ConfuserEx original sample"
        );
        assert!(
            detection.evidence().is_empty(),
            "No evidence should be present for a non-Obfuscar sample"
        );
        assert!(
            detection.findings::<ObfuscarStringFindings>().is_none(),
            "No findings should be present for a non-Obfuscar sample"
        );
    }

    #[test]
    fn test_is_obfuscar_helper_type_positive() {
        assert!(is_obfuscar_helper_type(
            "<PrivateImplementationDetails>{12345678-1234-1234-1234-123456789abc}"
        ));
        assert!(is_obfuscar_helper_type(
            "<PrivateImplementationDetails>{ABCDEF00-0000-0000-0000-000000000000}"
        ));
    }

    #[test]
    fn test_is_obfuscar_helper_type_negative() {
        assert!(!is_obfuscar_helper_type(""));
        assert!(!is_obfuscar_helper_type("SomeClass"));
        assert!(!is_obfuscar_helper_type("<PrivateImplementationDetails>"));
        // Just the prefix with opening brace but nothing after it
        assert!(!is_obfuscar_helper_type("<PrivateImplementationDetails>{"));
    }

    #[test]
    fn test_technique_metadata() {
        let technique = ObfuscarStrings;
        assert_eq!(technique.id(), "obfuscar.strings");
        assert_eq!(technique.name(), "Obfuscar String Hiding");
        assert_eq!(
            technique.category(),
            crate::deobfuscation::techniques::TechniqueCategory::Value
        );
        assert_eq!(technique.supersedes(), &["generic.strings"]);
    }
}

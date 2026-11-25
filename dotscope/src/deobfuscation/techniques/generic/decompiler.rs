//! Generic anti-decompiler artifact removal.
//!
//! Detects and removes anti-decompiler artifacts that prevent tools like dnSpy
//! and ILSpy from correctly decompiling assemblies. This includes:
//!
//! - Nested `<Module>` types with `Sealed | ExplicitLayout` flags that crash decompilers
//! - Fake obfuscator TypeRef attributes (SmartAssembly, Xenocode, Dotfuscator, etc.)
//!   injected to confuse de4dot and similar tools
//! - Malformed custom attribute blobs
//!
//! # Detection
//!
//! Scans for sealed+explicit nested types in `<Module>` and module-level custom
//! attributes referencing known fake obfuscator TypeRefs.
//!
//! # Transform
//!
//! Marks affected types and attributes for cleanup via `CleanupRequest`.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::{
        techniques::{
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
        },
        utils::resolve_custom_attr_type,
    },
    metadata::{
        tables::{CustomAttributeRaw, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
        typesystem::wellknown,
    },
    CilObject, Result,
};

/// Known fake obfuscator type names used by anti-de4dot protections.
///
/// These are injected as module-level custom attributes to confuse de4dot and
/// similar deobfuscation tools. The names reference real obfuscator products
/// to trigger false-positive detection in automated tools.
///
/// Only names specific enough to be safe against false positives on legitimate
/// code are included. Generic words like "Crypto" were removed — they are
/// already caught by the `is_garbage` heuristic (module-scoped TypeRef or
/// control characters in the name).
const FAKE_OBFUSCATOR_TYPES: &[&str] = &[
    "SmartAssembly",
    "Xenocode",
    "Goliath",
    "Dotfuscator",
    "Spices",
    "Eziriz",
    "MaxtoCode",
    "Salamander",
    "CodeWall",
    "DeepSea",
    "Skater",
    "Demeanor",
    "PostBuild",
    "TrinityObfuscator",
    "CliSecure",
    "ZYXDNGuarder",
    "ConfusedBy",
    "NineRays",
    "EMyPID",
    "ObfuscatedBy",
    "PoweredBy",
];

/// Findings from anti-decompiler detection.
#[derive(Debug)]
pub struct DecompilerFindings {
    /// Tokens of nested `<Module>` types with anti-decompiler flags.
    pub anti_decompiler_types: Vec<Token>,
    /// Tokens of fake obfuscator custom attributes.
    pub fake_attribute_tokens: Vec<Token>,
}

/// Detects and removes anti-decompiler artifacts.
pub struct GenericDecompiler;

impl Technique for GenericDecompiler {
    fn id(&self) -> &'static str {
        "generic.decompiler"
    }

    fn name(&self) -> &'static str {
        "Anti-Decompiler Artifact Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut findings = DecompilerFindings {
            anti_decompiler_types: Vec::new(),
            fake_attribute_tokens: Vec::new(),
        };
        let mut evidence = Vec::new();

        // Detect anti-decompiler nested types in <Module>
        detect_antidecompiler_types(assembly, &mut findings, &mut evidence);

        // Detect anti-de4dot fake attributes
        detect_fake_attributes(assembly, &mut findings, &mut evidence);

        let has_findings = !findings.anti_decompiler_types.is_empty()
            || !findings.fake_attribute_tokens.is_empty();

        if has_findings {
            let mut detection = Detection::new_detected(
                evidence,
                Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
            );

            // Add cleanup tokens
            if let Some(f) = detection.findings::<DecompilerFindings>() {
                let type_tokens: Vec<Token> = f.anti_decompiler_types.clone();
                let attr_tokens: Vec<Token> = f.fake_attribute_tokens.clone();
                detection.cleanup_mut().add_types(type_tokens);
                detection.cleanup_mut().add_attributes(attr_tokens);
            }

            detection
        } else {
            Detection::new_empty()
        }
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<DecompilerFindings>() else {
            return Some(Ok(events));
        };

        if !findings.anti_decompiler_types.is_empty() {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Marked {} anti-decompiler types for cleanup",
                findings.anti_decompiler_types.len()
            ));
        }
        if !findings.fake_attribute_tokens.is_empty() {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Marked {} fake obfuscator attributes for cleanup",
                findings.fake_attribute_tokens.len()
            ));
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Scans for nested `<Module>` types with Sealed | ExplicitLayout attributes.
fn detect_antidecompiler_types(
    assembly: &CilObject,
    findings: &mut DecompilerFindings,
    evidence: &mut Vec<Evidence>,
) {
    let types = assembly.types();
    let Some(module_type) = types.module_type() else {
        return;
    };

    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(typedef_table) = tables.table::<TypeDefRaw>() else {
        return;
    };

    for (_, nested_ref) in module_type.nested_types.iter() {
        let Some(nested) = nested_ref.upgrade() else {
            continue;
        };

        let row = typedef_table.get(nested.token.row()).ok().flatten();
        let Some(row) = row else {
            continue;
        };

        let flags = TypeAttributes::new(row.flags);
        let has_explicit_layout = flags.layout() == TypeAttributes::EXPLICIT_LAYOUT;
        if flags.contains(TypeAttributes::SEALED)
            && has_explicit_layout
            && nested.name != wellknown::members::MODULE_TYPE
        {
            // Skip compiler-generated data holder types
            if nested.name.starts_with("<>") || nested.name.starts_with("__Static") {
                continue;
            }
            if nested.fields.count() <= 1 {
                continue;
            }

            findings.anti_decompiler_types.push(nested.token);
        }
    }

    if !findings.anti_decompiler_types.is_empty() {
        evidence.push(Evidence::MetadataPattern(format!(
            "{} nested <Module> types with Sealed|ExplicitLayout (anti-decompiler)",
            findings.anti_decompiler_types.len()
        )));
    }
}

/// Scans for fake obfuscator custom attributes (anti-de4dot).
fn detect_fake_attributes(
    assembly: &CilObject,
    findings: &mut DecompilerFindings,
    evidence: &mut Vec<Evidence>,
) {
    let Some(tables) = assembly.tables() else {
        return;
    };
    let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
        return;
    };

    for attr in custom_attr_table {
        let attr = match attr {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        let is_module_or_assembly =
            attr.parent.tag == TableId::Module || attr.parent.tag == TableId::Assembly;
        if !is_module_or_assembly {
            continue;
        }

        let Some(resolved) = resolve_custom_attr_type(assembly, &attr) else {
            continue;
        };

        let type_name = resolved.name;
        let has_module_scope = resolved.has_module_scope;

        let full_name = if let Some(ns) = resolved.namespace {
            format!("{ns}.{type_name}")
        } else {
            type_name.to_string()
        };

        let is_fake = FAKE_OBFUSCATOR_TYPES
            .iter()
            .any(|pattern| full_name.contains(pattern));

        // Garbage: self-referencing module-scoped TypeRef, control chars in name,
        // or locally-defined attribute type with no real type body (injected stub)
        let has_control_chars = type_name.chars().any(|c| c.is_ascii_control() || c == '\0');
        let is_empty_local_type = resolved.typedef_token.is_some_and(|t| {
            assembly
                .types()
                .get(&t)
                .is_some_and(|ty| ty.methods.count() <= 1 && ty.fields.count() == 0)
        });
        let is_garbage = has_module_scope || has_control_chars || is_empty_local_type;

        if is_fake || is_garbage {
            findings.fake_attribute_tokens.push(attr.token);
        }
    }

    if !findings.fake_attribute_tokens.is_empty() {
        evidence.push(Evidence::Attribute(format!(
            "{} fake obfuscator attributes (anti-de4dot)",
            findings.fake_attribute_tokens.len()
        )));
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    #[test]
    fn test_detect_positive() {
        let asm = load_sample("packers/bitmono/0.39.0/bitmono_antide4dot.exe");
        let technique = super::GenericDecompiler;
        let detection = technique.detect(&asm);
        assert!(detection.is_detected());
        assert!(!detection.evidence().is_empty());
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericDecompiler;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

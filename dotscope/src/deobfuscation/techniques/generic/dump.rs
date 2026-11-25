//! Generic anti-dump detection.
//!
//! Detects anti-dump protections that corrupt PE headers at runtime via
//! `VirtualProtect` to prevent memory dumping. Distinguished from anti-tamper
//! by the absence of `Marshal.Copy` (anti-tamper uses Marshal.Copy for
//! method body decryption).
//!
//! # Detection
//!
//! Scans for VirtualProtect + PE header manipulation patterns without
//! Marshal.Copy.
//!
//! # Passes
//!
//! Does not create its own pass — neutralization is handled by the engine.

use std::collections::HashSet;

use crate::{
    cilassembly::CleanupRequest,
    compiler::PassPhase,
    deobfuscation::{
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
        utils::find_methods_calling_apis,
    },
    metadata::token::Token,
    CilObject,
};

/// Pattern indices for [`find_methods_calling_apis`] results.
const PAT_VIRTUAL_PROTECT: usize = 0;
const PAT_GET_HINSTANCE: usize = 1;
const PAT_GET_MODULE: usize = 2;
const PAT_MARSHAL_COPY: usize = 3;

/// API name patterns used for anti-dump detection.
const API_PATTERNS: &[&str] = &[
    "VirtualProtect",
    "GetHINSTANCE",
    "get_Module",
    "Marshal.Copy",
];

/// Findings from generic anti-dump detection.
#[derive(Debug)]
pub struct AntiDumpFindings {
    /// Tokens of methods containing anti-dump logic.
    pub method_tokens: HashSet<Token>,
}

/// Detects anti-dump protections (PE header corruption via VirtualProtect).
pub struct GenericAntiDump;

impl Technique for GenericAntiDump {
    fn id(&self) -> &'static str {
        "generic.dump"
    }

    fn name(&self) -> &'static str {
        "Generic Anti-Dump Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let api_hits = find_methods_calling_apis(assembly, API_PATTERNS);

        // Anti-dump pattern: VirtualProtect + module handle access (GetHINSTANCE
        // or get_Module), without Marshal.Copy (which indicates anti-tamper
        // method body decryption). All APIs must co-occur in the same method.
        let method_tokens: HashSet<Token> = api_hits
            .into_iter()
            .filter(|(_token, indices)| {
                let has_virtual_protect = indices.contains(&PAT_VIRTUAL_PROTECT);
                let has_module_handle =
                    indices.contains(&PAT_GET_HINSTANCE) || indices.contains(&PAT_GET_MODULE);
                let has_marshal_copy = indices.contains(&PAT_MARSHAL_COPY);
                has_virtual_protect && has_module_handle && !has_marshal_copy
            })
            .map(|(token, _)| token)
            .collect();

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = method_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with anti-dump patterns (VirtualProtect without Marshal.Copy)"
            ))],
            None,
        );

        for token in &method_tokens {
            detection.cleanup_mut().add_method(*token);
        }

        detection.set_findings(Box::new(AntiDumpFindings { method_tokens }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<AntiDumpFindings>()?;
        if findings.method_tokens.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for token in &findings.method_tokens {
            request.add_method(*token);
        }
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// ConfuserEx anti-dump uses VirtualProtect + GetHINSTANCE + Marshal.Copy,
    /// which the ConfuserEx-specific technique handles. The generic technique
    /// catches the VirtualProtect + GetHINSTANCE pattern WITHOUT Marshal.Copy,
    /// which is used by other packers. In ConfuserEx samples, the presence of
    /// Marshal.Copy causes the generic technique to correctly skip them.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");
        let technique = super::GenericAntiDump;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericAntiDump;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

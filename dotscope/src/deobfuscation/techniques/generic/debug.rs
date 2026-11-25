//! Generic anti-debug detection.
//!
//! Detects common anti-debug patterns used across multiple obfuscators:
//! `Debugger.IsAttached` checks, `Environment.FailFast` calls, `Process.GetCurrentProcess`
//! monitoring, and similar patterns.
//!
//! # Detection
//!
//! Scans methods for calls to well-known anti-debug APIs. Stores the method
//! tokens for later neutralization by the engine's neutralization phase.
//!
//! # Passes
//!
//! Does not create its own pass — neutralization is handled by the engine's
//! `NeutralizationPass` which processes all cleanup tokens.

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

/// Findings from generic anti-debug detection.
#[derive(Debug)]
pub struct AntiDebugFindings {
    /// Tokens of methods containing anti-debug checks.
    pub method_tokens: HashSet<Token>,
}

/// Detects common anti-debug patterns.
pub struct GenericAntiDebug;

impl Technique for GenericAntiDebug {
    fn id(&self) -> &'static str {
        "generic.debug"
    }

    fn name(&self) -> &'static str {
        "Generic Anti-Debug Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // Patterns use qualified names (declaring type prefix) where possible to
        // avoid matching user methods that happen to share the same name. The
        // matching uses `contains()`, so "Debugger.get_IsAttached" matches
        // "System.Diagnostics.Debugger.get_IsAttached" from MemberRef resolution.
        let patterns: &[&str] = &[
            "Debugger.get_IsAttached",
            "Environment.FailFast",
            "Process.GetCurrentProcess",
            "IsDebuggerPresent", // P/Invoke — no managed declaring type
            "Debugger.IsLogging",
        ];

        let matches = find_methods_calling_apis(assembly, patterns);
        if matches.is_empty() {
            return Detection::new_empty();
        }

        let method_tokens: HashSet<Token> = matches.keys().copied().collect();
        let count = method_tokens.len();

        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with anti-debug API calls"
            ))],
            None,
        );

        for token in &method_tokens {
            detection.cleanup_mut().add_method(*token);
        }

        detection.set_findings(Box::new(AntiDebugFindings { method_tokens }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<AntiDebugFindings>()?;
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

    #[test]
    fn test_detect_positive() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_maximum.exe");
        let technique = super::GenericAntiDebug;
        let detection = technique.detect(&asm);
        assert!(detection.is_detected());
        assert!(!detection.evidence().is_empty());
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericAntiDebug;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

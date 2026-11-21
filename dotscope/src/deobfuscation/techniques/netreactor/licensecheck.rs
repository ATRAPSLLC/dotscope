//! .NET Reactor secondary license-check removal.
//!
//! Beyond the `<Module>` trial guard ([`netreactor.antitrial`]), every .NET
//! Reactor-protected assembly carries a second trial check on a class-scoped
//! static method. Its body combines the same behavioral triplet as the
//! `<Module>` trial (DateTime construction + `TimeSpan.get_Days` + `throw`
//! with the NR-nag literal) with a single-shot `bool` field guard so it only
//! executes once per AppDomain:
//!
//! ```text
//! ldsfld <bool>; brtrue Ret;
//! ldc.i4.1; stsfld <bool>;
//! ... DateTime / TimeSpan / Math.Abs check against 14 days ...
//! ldstr "This assembly is protected..."; newobj Exception; throw;
//! Ret: ret
//! ```
//!
//! The method is typically invoked from a user-type `.cctor` or `.ctor`, so
//! after `<Module>::.cctor` is cleaned up the binary still trips on the
//! license check the first time user code instantiates one of the affected
//! types (e.g. `reactor_obfuscation` fails in `t8JubRuTexuLxLeNiE..ctor`
//! once its NecroBit bodies are restored).
//!
//! # Detection
//!
//! Pure co-occurrence gating — no hardcoded type or member names:
//!
//! 1. [`helpers::find_trial_checks`] enumerates every method matching the
//!    behavioral trial signature.
//! 2. There must be at least one `<Module>`-scoped trial (that's
//!    [`netreactor.antitrial`]'s signal — it proves the assembly is NR-protected).
//! 3. For each non-`<Module>` trial, [`helpers::has_single_shot_bool_guard`]
//!    must match — the single-shot guard is the structural differentiator
//!    from ordinary user-written date-checks.
//!
//! # Cleanup
//!
//! Marks each matched license-check method for deletion. The shared pipeline
//! handles the rest:
//!
//! 1. [`NeutralizationPass`] NOPs every `call` to the marked method from
//!    surviving methods (user `.ctor`, user `.cctor`, etc.).
//! 2. Once the method is gone and its callers have been regenerated, the
//!    containing type becomes unreferenced and is dropped by
//!    [`find_unreferenced_types`] during `build_cleanup_request`.
//!
//! [`netreactor.antitrial`]: super::antitrial
//! [`NeutralizationPass`]: crate::deobfuscation::NeutralizationPass
//! [`find_unreferenced_types`]: crate::cilassembly::find_unreferenced_types

use std::any::Any;

use crate::{
    deobfuscation::techniques::{
        netreactor::helpers, Detection, Evidence, Technique, TechniqueCategory,
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from .NET Reactor secondary license-check detection.
#[derive(Debug)]
pub struct LicenseCheckFindings {
    /// Tokens of license-check methods scheduled for removal.
    pub method_tokens: Vec<Token>,
}

/// Detects and marks .NET Reactor's secondary (class-scoped) trial/license
/// methods for cleanup.
pub struct NetReactorLicenseCheck;

impl Technique for NetReactorLicenseCheck {
    fn id(&self) -> &'static str {
        "netreactor.licensecheck"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor License Check Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn requires(&self) -> &[&'static str] {
        &["netreactor.antitrial"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let trials = helpers::find_trial_checks(assembly);

        // NR context proof: the `<Module>` trial must be present. Without it,
        // a standalone class-scoped date-check is plausibly legitimate user code.
        let has_module_trial = trials.iter().any(|t| t.is_on_module_type);
        if !has_module_trial {
            return Detection::new_empty();
        }

        let method_tokens: Vec<Token> = trials
            .into_iter()
            .filter(|t| !t.is_on_module_type)
            .map(|t| t.method_token)
            .filter(|token| helpers::has_single_shot_bool_guard(assembly, *token))
            .collect();

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = method_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} NR license-check method(s) (trial pattern + single-shot bool guard)"
            ))],
            Some(Box::new(LicenseCheckFindings {
                method_tokens: method_tokens.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        for token in &method_tokens {
            detection.cleanup_mut().add_protection_method(*token);
        }

        detection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::load_sample;

    #[test]
    fn test_detect_positive_obfuscation() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_obfuscation.exe");
        let detection = NetReactorLicenseCheck.detect(&assembly);
        assert!(
            detection.is_detected(),
            "Should detect NR license check in reactor_obfuscation.exe"
        );
        let findings = detection
            .findings::<LicenseCheckFindings>()
            .expect("Should attach findings");
        assert!(
            !findings.method_tokens.is_empty(),
            "Should record at least one license-check method"
        );
    }

    #[test]
    fn test_detect_negative_baseline() {
        let assembly = load_sample("packers/netreactor/7.5.0/original.exe");
        let detection = NetReactorLicenseCheck.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not detect a license check in unprotected original.exe"
        );
    }
}

//! .NET Reactor trial-guard removal.
//!
//! Every .NET Reactor-protected assembly carries a synthetic trial-check method
//! on the `<Module>` type. Its body constructs a `DateTime` from the protector's
//! build date, subtracts it from `DateTime.Now`, reads `TimeSpan.Days`, compares
//! against `±14`, and throws `System.Exception` ("This assembly is protected by
//! an unregistered version of Eziriz's .NET Reactor!") if the threshold is
//! exceeded. `<Module>::.cctor` calls into it on assembly load.
//!
//! Under mono the stub fails to JIT (its `.locals init` signature encodes
//! `DateTime` as `ELEMENT_TYPE_CLASS` rather than `ELEMENT_TYPE_VALUETYPE`),
//! producing a `TypeInitializationException` before any user code runs. Even
//! when it loads, the 14-day window makes every protected binary fail in CI
//! after the protection date.
//!
//! # Detection
//!
//! Reuses [`helpers::find_trial_checks`] — a behavioral pattern matcher
//! (DateTime construction + `TimeSpan.get_Days` + `throw`) — and filters to
//! methods defined on the `<Module>` type. A `<Module>`-scoped static method
//! matching this exact triplet has no legitimate compiler analogue; the gate
//! is therefore highly specific.
//!
//! # Cleanup
//!
//! Marks each detected trial method for removal. The downstream cleanup
//! pipeline does the rest:
//!
//! 1. [`NeutralizationPass`] NOPs every `call <trial>` in surviving methods
//!    (notably the `<Module>::.cctor` wrapper).
//! 2. [`sweep_empty_module_cctor`] picks up the now-empty `.cctor`.
//! 3. The cleanup executor deletes the trial method itself.
//!
//! Off-`<Module>` trial copies (e.g. the NR license-check class) are
//! deliberately left for `netreactor.licensecheck` so each artifact is
//! attributed to the technique that owns it.
//!
//! [`NeutralizationPass`]: crate::deobfuscation::NeutralizationPass
//! [`sweep_empty_module_cctor`]: crate::deobfuscation::cleanup

use std::{any::Any, collections::HashSet};

use crate::{
    deobfuscation::{
        context::AnalysisContext,
        techniques::{
            netreactor::{helpers, hooks},
            Detection, Detections, Evidence, Technique, TechniqueCategory,
        },
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from .NET Reactor trial-guard detection.
#[derive(Debug)]
pub struct AntiTrialFindings {
    /// Tokens of `<Module>` trial-guard methods scheduled for removal.
    pub trial_method_tokens: Vec<Token>,
}

/// Detects and marks .NET Reactor `<Module>` trial-guard methods for cleanup.
pub struct NetReactorAntiTrial;

impl Technique for NetReactorAntiTrial {
    fn id(&self) -> &'static str {
        "netreactor.antitrial"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor Trial Guard Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let trial_check_tokens: Vec<Token> = helpers::find_trial_checks(assembly)
            .into_iter()
            .filter(|t| t.is_on_module_type)
            .map(|t| t.method_token)
            .collect();

        if trial_check_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = trial_check_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} <Module> trial-guard method(s) (DateTime + TimeSpan.get_Days + throw)"
            ))],
            Some(Box::new(AntiTrialFindings {
                trial_method_tokens: trial_check_tokens.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        for token in &trial_check_tokens {
            detection.cleanup_mut().add_protection_method(*token);
        }

        detection
    }

    /// Bypasses every trial check in the emulation the pipeline runs (the template's warmup
    /// and the decryptors), as NecroBit's and the resource decrypter's own emulations do.
    ///
    /// The checks compare `DateTime.Now` with the protection date, two weeks either way. The
    /// emulator cannot know the time the program was protected, and the stamp of a
    /// deterministic build is a hash, not a date, so an emulated run reaching a check throws
    /// "This assembly is protected by an unregistered version of Eziriz's .NET Reactor!"
    /// and stops before the code it was run for.
    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        _detection: &Detection,
        _detections: &Detections,
    ) {
        let tokens: HashSet<Token> = helpers::find_trial_checks(assembly)
            .into_iter()
            .map(|trial| trial.method_token)
            .collect();
        if tokens.is_empty() {
            return;
        }
        ctx.register_emulation_hook("netreactor.antitrial", move || {
            hooks::create_trial_bypass_hook(tokens.clone())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::load_sample;

    #[test]
    fn test_detect_positive_obfuscation() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_obfuscation.exe");
        let detection = NetReactorAntiTrial.detect(&assembly);
        assert!(
            detection.is_detected(),
            "Should detect <Module> trial guard in reactor_obfuscation.exe"
        );
        let findings = detection
            .findings::<AntiTrialFindings>()
            .expect("Should attach findings");
        assert!(
            !findings.trial_method_tokens.is_empty(),
            "Should record at least one trial method token"
        );
        assert_eq!(
            detection.cleanup().methods_len(),
            findings.trial_method_tokens.len(),
            "Each detected trial method should be marked for cleanup"
        );
    }

    #[test]
    fn test_detect_negative_baseline() {
        let assembly = load_sample("packers/netreactor/7.5.0/original.exe");
        let detection = NetReactorAntiTrial.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not detect a trial guard in unprotected original.exe"
        );
    }
}

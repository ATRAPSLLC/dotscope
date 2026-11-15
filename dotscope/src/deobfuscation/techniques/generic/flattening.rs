//! Generic control flow flattening detection.
//!
//! Detects switch-based control flow flattening (CFF) dispatchers — the most
//! common form of control flow obfuscation. In CFF, the original control flow
//! graph is replaced with a loop containing a switch dispatcher that uses a
//! state variable to select the next block to execute.
//!
//! # Detection
//!
//! Detection is fully SSA-based via [`CffDetector`] — the same structural
//! analysis engine used by [`CffReconstructionPass`]. This gives precise,
//! junk-immune detection with confidence scoring, dominance analysis, and
//! state variable identification. Detected dispatchers are stored in
//! [`FlatteningFindings`] so the reconstruction pass can consume them directly
//! without re-running detection.
//!
//! [`CffDetector`]: crate::deobfuscation::passes::CffDetector
//! [`CffReconstructionPass`]: crate::deobfuscation::passes::CffReconstructionPass
//!
//! # Passes
//!
//! Creates a [`CffReconstructionPass`] via `create_pass()`, configured with
//! unflattening parameters from the engine config and pre-detected dispatchers
//! from the detection phase.

use std::{collections::HashMap, sync::Arc};

use crate::{
    analysis::CilTarget,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{CffDetector, CffReconstructionPass, Dispatcher, UnflattenConfig},
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from CFF detection.
///
/// Contains the pre-computed dispatcher analysis for each method where CFF
/// was detected. The [`CffReconstructionPass`](crate::deobfuscation::passes::CffReconstructionPass)
/// can consume these directly instead of re-running detection.
#[derive(Debug)]
pub struct FlatteningFindings {
    /// Pre-detected dispatchers per method token, sorted by confidence (highest first).
    /// Only includes dispatchers that passed the confidence threshold.
    pub dispatchers: HashMap<Token, Vec<Dispatcher>>,
}

/// Detects control flow flattening (CFF/switch-based dispatchers).
pub struct GenericFlattening;

impl Technique for GenericFlattening {
    fn id(&self) -> &'static str {
        "generic.flattening"
    }

    fn name(&self) -> &'static str {
        "Control Flow Flattening Reconstruction"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn requires(&self) -> &[&'static str] {
        &["generic.predicates"]
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // using CffDetector's structural analysis (dominance, SCCs, back-edges,
        // state variable identification, confidence scoring).
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // The engine's configuration, on the machine the assembly computes on.
        let config = UnflattenConfig {
            machine: CilTarget::of(assembly).machine(),
            ..ctx.config.unflattening.clone()
        };
        let min_confidence = config.min_confidence;
        let mut dispatchers_by_method: HashMap<Token, Vec<Dispatcher>> = HashMap::new();
        let mut total_dispatchers = 0usize;

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let ssa = entry.value();

            // Use the same CffDetector that CffReconstructionPass uses.
            // This gives us full structural analysis with confidence scoring,
            // dominance verification, state variable identification, etc.
            let mut detector = CffDetector::with_config(ssa, &config);
            let all_dispatchers = detector.detect_all_dispatchers();

            // Two-tier confidence filtering: high-confidence dispatchers must
            // meet the normal threshold. When a method HAS high-confidence CFF,
            // also include lower-confidence dispatchers (handler CFF in exception
            // handlers scores lower because it dominates fewer blocks). This
            // avoids leaving handler CFF switches unresolved while the main-body
            // CFF is reconstructed.
            let has_high_confidence = all_dispatchers
                .iter()
                .any(|d| d.confidence >= min_confidence);
            let effective_threshold = if has_high_confidence {
                min_confidence * 0.75
            } else {
                min_confidence
            };
            let method_dispatchers: Vec<Dispatcher> = all_dispatchers
                .into_iter()
                .filter(|d| d.confidence >= effective_threshold)
                .collect();

            if !method_dispatchers.is_empty() {
                total_dispatchers = total_dispatchers.saturating_add(method_dispatchers.len());
                dispatchers_by_method.insert(method_token, method_dispatchers);
            }
        }

        if dispatchers_by_method.is_empty() {
            return Detection::new_empty();
        }

        let method_count = dispatchers_by_method.len();
        let findings = FlatteningFindings {
            dispatchers: dispatchers_by_method,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{total_dispatchers} CFF dispatchers in {method_count} methods"
            ))],
            Some(Box::new(findings) as Box<dyn std::any::Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Structure)
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let mut cff_pass = CffReconstructionPass::new(ctx);
        if let Some(findings) = detection.findings::<FlatteningFindings>() {
            cff_pass = cff_pass.with_pre_detected(findings.dispatchers.clone());
        }

        vec![Box::new(cff_pass)]
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    /// Verify that IL-level detect() is a no-op (detection is SSA-based).
    ///
    /// Positive detection is tested through the full pipeline in integration
    /// tests and through `engine.detect()` which runs both IL + SSA phases.
    #[test]
    fn test_detect_is_noop() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_controlflow.exe");
        let technique = super::GenericFlattening;
        let detection = technique.detect(&asm);
        assert!(
            !detection.is_detected(),
            "IL-level detect() should be a no-op — detection happens in detect_ssa()"
        );
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericFlattening;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

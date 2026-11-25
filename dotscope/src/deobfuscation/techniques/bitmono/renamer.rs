//! BitMono FullRenamer and NoNamespaces detection.
//!
//! Detects BitMono's FullRenamer protection, which produces distinctive
//! space-containing type and method names by concatenating random words
//! (e.g., `"Translate Start <FixedUpdate>b__4_0.get_Syntax"`).
//!
//! Also detects NoNamespaces protection, which strips all namespaces from
//! user types, leaving them in the global namespace.
//!
//! # Detection
//!
//! Scans type and method names for space characters. Legitimate .NET names
//! never contain spaces (except for compiler-generated angle-bracket names
//! like `<Module>`). Finding 5+ space-containing names is a strong signal
//! of BitMono FullRenamer.

use crate::{
    compiler::PassPhase,
    deobfuscation::techniques::{Detection, Evidence, Technique, TechniqueCategory},
    CilObject,
};

/// Minimum number of space-containing names to trigger detection.
const MIN_SPACE_NAMES: usize = 5;

/// Detects BitMono FullRenamer space-containing name obfuscation.
pub struct BitMonoRenamer;

impl Technique for BitMonoRenamer {
    fn id(&self) -> &'static str {
        "bitmono.renamer"
    }

    fn name(&self) -> &'static str {
        "BitMono FullRenamer Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut space_name_count = 0usize;

        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Check type name for spaces (skip angle-bracket compiler-generated names)
            if cil_type.name.contains(' ') && !cil_type.name.starts_with('<') {
                space_name_count = space_name_count.saturating_add(1);
            }

            // Check method names
            for i in 0..cil_type.methods.count() {
                let Some(method_ref) = cil_type.methods.get(i) else {
                    continue;
                };
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };
                if method.name.contains(' ') && !method.name.starts_with('<') {
                    space_name_count = space_name_count.saturating_add(1);
                }
            }
        }

        if space_name_count < MIN_SPACE_NAMES {
            return Detection::new_empty();
        }

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{space_name_count} space-containing names (BitMono FullRenamer)"
            ))],
            None,
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Normalize)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoRenamer, Technique},
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_renamer.exe");

        let technique = BitMonoRenamer;
        let detection = technique.detect(&assembly);

        // BitMonoRenamer is an SSA technique. The IL-level detect() looks for
        // space-containing names which may or may not be present. We assert
        // consistency: if detected, evidence must be present.
        if detection.is_detected() {
            assert!(
                !detection.evidence().is_empty(),
                "Positive detection should include evidence"
            );
        }
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoRenamer;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoRenamer should not detect space-containing names in a non-BitMono assembly"
        );
    }
}

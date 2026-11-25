//! .NET Reactor `<PrivateImplementationDetails>{GUID}` data-container cleanup.
//!
//! NR repurposes the C# compiler's static-array-initialization helper
//! (`<PrivateImplementationDetails>`) by injecting additional containers
//! named `<PrivateImplementationDetails>{GUID}` that hold crypto material,
//! state tables, and encrypted lookup blobs consumed by NR's runtime
//! protections (string decryption, CFF, anti-tamper, NecroBit, resource
//! encryption).
//!
//! What identifies the containers and makes them safe to remove:
//!
//! - The GUID suffix is the **structural NR signal** — no production
//!   compiler emits a `<PrivateImplementationDetails>` with a GUID suffix.
//! - The naked `<PrivateImplementationDetails>` (no suffix) is
//!   compiler-generated and must be preserved.
//! - After the existing decryption passes complete (CFF reconstruction,
//!   string/constant decryption, NecroBit body restoration), no surviving
//!   method body references any field or nested subtype of the GUID
//!   container.
//! - The generic `find_unreferenced_types` orphan sweep refuses to
//!   consider these containers because they have no methods
//!   (`cleanup/analysis.rs:152-160` requires "at least one non-cctor
//!   method").
//!
//! This technique is therefore the NR-specific owner for the artifact:
//! purely structural detection by name shape, gated by NR-context
//! co-occurrence (an `<Module>` trial guard must also be present, same
//! gate as [`netreactor.licensecheck`]), and marks the container for
//! cleanup. The cleanup pipeline's [`expand_type_tokens`] cascade picks
//! up the nested `__StaticArrayInitTypeSize=N` subtypes and the
//! SHA-256-named fields automatically.
//!
//! If the upstream passes somehow fail to simplify and the container
//! still has live `ldsfld` / `ldtoken` references when cleanup runs, the
//! regenerator's metadata validator rejects the output — a loud failure,
//! not silent corruption.
//!
//! [`expand_type_tokens`]: crate::cilassembly::expand_type_tokens
//! [`netreactor.licensecheck`]: super::licensecheck

use std::any::Any;

use crate::{
    deobfuscation::techniques::{
        netreactor::helpers, Detection, Evidence, Technique, TechniqueCategory,
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from .NET Reactor GUID-suffixed `<PrivateImplementationDetails>`
/// detection.
#[derive(Debug)]
pub struct PrivateImplFindings {
    /// TypeDef tokens of NR-injected GUID-suffixed containers scheduled
    /// for removal. Nested subtypes and member fields are picked up by
    /// [`expand_type_tokens`] automatically.
    ///
    /// [`expand_type_tokens`]: crate::cilassembly::expand_type_tokens
    pub container_tokens: Vec<Token>,
}

/// Detects and marks .NET Reactor's `<PrivateImplementationDetails>{GUID}`
/// data containers (plus their nested `__StaticArrayInitTypeSize=N`
/// value-types and SHA-256-named fields) for cleanup.
pub struct NetReactorPrivateImpl;

impl Technique for NetReactorPrivateImpl {
    fn id(&self) -> &'static str {
        "netreactor.privateimpl"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor Data Container Cleanup"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn requires(&self) -> &[&'static str] {
        &["netreactor.antitrial"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // NR context gate: the `<Module>` trial guard must be present.
        // Same gate as `netreactor.licensecheck` — guarantees the sample
        // is NR-protected and prevents any hypothetical false-positive on
        // a user-defined GUID-suffixed type.
        let has_module_trial = helpers::find_trial_checks(assembly)
            .iter()
            .any(|t| t.is_on_module_type);
        if !has_module_trial {
            return Detection::new_empty();
        }

        let containers = helpers::find_nr_private_impl_containers(assembly);
        if containers.is_empty() {
            return Detection::new_empty();
        }

        let container_tokens: Vec<Token> = containers.iter().map(|c| c.container_token).collect();
        let count = container_tokens.len();

        let mut detection = Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} NR-injected <PrivateImplementationDetails>{{GUID}} container(s)"
            ))],
            Some(Box::new(PrivateImplFindings {
                container_tokens: container_tokens.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        for token in &container_tokens {
            detection.cleanup_mut().add_type(*token);
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
        let detection = NetReactorPrivateImpl.detect(&assembly);
        assert!(
            detection.is_detected(),
            "Should detect NR GUID PrivateImpl container in reactor_obfuscation.exe"
        );
        let findings = detection
            .findings::<PrivateImplFindings>()
            .expect("Should attach findings");
        assert!(
            !findings.container_tokens.is_empty(),
            "Should record at least one container token"
        );
    }

    #[test]
    fn test_detect_negative_baseline() {
        let assembly = load_sample("packers/netreactor/7.5.0/original.exe");
        let detection = NetReactorPrivateImpl.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not detect a GUID container in unprotected original.exe \
             (baseline has only the compiler-generated naked <PrivateImplementationDetails>)"
        );
    }
}

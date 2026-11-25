//! .NET Reactor anti-tamper init runtime removal.
//!
//! NR's anti-tamper stage injects a synthetic `.cctor` into every type that
//! calls a single CFF-obfuscated initialization method. That init method
//! reads an encrypted resource, AES-decrypts it, and verifies assembly
//! integrity — failing under mono before any user code runs because the
//! verification depends on metadata layout that mono lays out differently.
//!
//! The trial-guard removal ([`netreactor.antitrial`]) only neutralises the
//! `<Module>::.cctor` trial-check call; the anti-tamper init call survives
//! and continues to throw `TypeInitializationException` at assembly load.
//! This technique removes the init call too.
//!
//! # Detection
//!
//! Detection is fully structural — no hardcoded type names. Three
//! independent signals must all hold:
//!
//! 1. **NR context gate**: a `<Module>` trial-guard is present (same gate
//!    as [`netreactor.licensecheck`] and [`netreactor.privateimpl`]).
//! 2. **Primary**: [`helpers::find_cctor_fan_in_target`] reports a single
//!    method called by 5+ types' `.cctor`s. No legitimate program has
//!    this fan-in pattern.
//! 3. **Corroborating**: at least one NR-injected `<Module>{GUID}` marker
//!    type or `<PrivateImplementationDetails>{GUID}` container is
//!    present. The GUID-suffix shape is unique to NR's anti-tamper stage.
//!
//! # Cleanup
//!
//! Marks for removal:
//!
//! - The init method itself (`init_method_token`).
//! - The init method's declaring type (the NR runtime container — holds
//!   AES helpers, CFF state machines, lookup tables) — its nested types
//!   and member fields cascade via [`expand_type_tokens`].
//! - Purely-injected `.cctor`s (entire body is just `call init; ret`).
//! - `<Module>{GUID}` marker types — the orphan sweep refuses these
//!   (no non-cctor methods), so they need explicit marking.
//!
//! Modified `.cctor`s (init call prepended to original user code) are
//! left in place; [`NeutralizationPass`] NOPs the call to the
//! now-deleted init method, preserving the surrounding user code. The
//! `<PrivateImplementationDetails>{GUID}` container is owned by
//! [`netreactor.privateimpl`] and not duplicated here.
//!
//! [`netreactor.antitrial`]: super::antitrial
//! [`netreactor.licensecheck`]: super::licensecheck
//! [`netreactor.privateimpl`]: super::privateimpl
//! [`expand_type_tokens`]: crate::cilassembly::expand_type_tokens
//! [`NeutralizationPass`]: crate::deobfuscation::passes::NeutralizationPass

use std::{any::Any, sync::Arc};

use crate::{
    analysis::CilTarget,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::netreactor::TokenResolverPass,
        techniques::{netreactor::helpers, Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from .NET Reactor anti-tamper init runtime detection.
#[derive(Debug)]
pub struct AntiTampFindings {
    /// Token of the anti-tamper init method (the .cctor fan-in target).
    pub init_method_token: Token,
    /// Declaring type of the init method — the NR runtime container.
    pub runtime_type_token: Option<Token>,
    /// `.cctor`s whose entire body is `call init; ret` — safe to delete.
    pub purely_injected_cctors: Vec<Token>,
    /// `.cctor`s where the init call was prepended to original code.
    pub modified_cctors: Vec<Token>,
    /// `<Module>{GUID}` marker types injected by anti-tamper.
    pub guid_module_type_tokens: Vec<Token>,
    /// Accessor method tokens of the metadata-token resolver type, if found.
    /// Used by [`TokenResolverPass`] to fold `accessor(<const>)` calls back
    /// into `ldtoken X`. May be empty when the resolver type is absent.
    pub token_resolver_accessor_tokens: Vec<Token>,
    /// TypeDef token of the metadata-token resolver type, if found.
    pub token_resolver_type_token: Option<Token>,
    /// `ManifestResource` tokens referenced by name from NR anti-tamper
    /// runtime methods — the encrypted payloads the init method loads,
    /// AES-decrypts, and feeds to the tamper-verification loop. Marked
    /// for cleanup so the embedded bytes vanish with the runtime code.
    pub runtime_resource_tokens: Vec<Token>,
}

/// Detects and marks .NET Reactor's anti-tamper init runtime for cleanup.
pub struct NetReactorAntiTamp;

impl Technique for NetReactorAntiTamp {
    fn id(&self) -> &'static str {
        "netreactor.antitamp"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor Anti-Tamper Init Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn requires(&self) -> &[&'static str] {
        &["netreactor.antitrial"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let has_module_trial = helpers::find_trial_checks(assembly)
            .iter()
            .any(|t| t.is_on_module_type);
        if !has_module_trial {
            return Detection::new_empty();
        }

        let Some(fan_in) = helpers::find_cctor_fan_in_target(assembly) else {
            return Detection::new_empty();
        };

        let guid_module_type_tokens = helpers::find_nr_guid_module_containers(assembly);
        let private_impl_containers = helpers::find_nr_private_impl_containers(assembly);
        if guid_module_type_tokens.is_empty() && private_impl_containers.is_empty() {
            return Detection::new_empty();
        }

        let init_method_token = fan_in.target_token;
        let runtime_type_token = assembly
            .method(&init_method_token)
            .ok()
            .and_then(|m| m.declaring_type_rc())
            .map(|t| t.token);

        let classification = helpers::classify_injected_cctors(
            assembly,
            &fan_in.initializers,
            &fan_in.calling_cctors,
        );

        let resolver = helpers::find_nr_token_resolver(assembly);
        let mut accessor_tokens: Vec<Token> = Vec::new();
        let resolver_type_token = resolver.as_ref().map(|r| {
            accessor_tokens.extend(r.type_handle_accessors.iter().copied());
            accessor_tokens.extend(r.field_handle_accessors.iter().copied());
            accessor_tokens.extend(r.method_handle_accessors.iter().copied());
            r.type_token
        });

        // Scan the NR runtime container (init method's declaring type) plus all
        // its nested types for `ldstr <name>` references to manifest resources.
        // Any resource named by these methods is reachable only from anti-tamper
        // code and can be cleaned up alongside it.
        let runtime_method_tokens = collect_runtime_method_tokens(assembly, runtime_type_token);
        let runtime_resource_tokens = if runtime_method_tokens.is_empty() {
            Vec::new()
        } else {
            helpers::find_resources_referenced_by_methods(assembly, &runtime_method_tokens)
        };

        let mut evidence = vec![
            Evidence::Structural(format!(
                "Init method 0x{:08X} called by {} type .cctor(s) ({} purely-injected, {} modified)",
                init_method_token.value(),
                fan_in.calling_cctors.len(),
                classification.purely_injected.len(),
                classification.modified.len(),
            )),
            Evidence::Structural(format!(
                "{} <Module>{{GUID}} marker type(s), {} <PrivateImplementationDetails>{{GUID}} container(s)",
                guid_module_type_tokens.len(),
                private_impl_containers.len(),
            )),
        ];
        if let Some(ref r) = resolver {
            evidence.push(Evidence::Structural(format!(
                "Metadata-token resolver type 0x{:08X}: {} type-handle, {} field-handle, {} method-handle accessor(s)",
                r.type_token.value(),
                r.type_handle_accessors.len(),
                r.field_handle_accessors.len(),
                r.method_handle_accessors.len(),
            )));
        }
        if !runtime_resource_tokens.is_empty() {
            evidence.push(Evidence::Structural(format!(
                "{} manifest resource(s) referenced only from anti-tamper runtime",
                runtime_resource_tokens.len(),
            )));
        }

        let findings = AntiTampFindings {
            init_method_token,
            runtime_type_token,
            purely_injected_cctors: classification.purely_injected.clone(),
            modified_cctors: classification.modified,
            guid_module_type_tokens: guid_module_type_tokens.clone(),
            token_resolver_accessor_tokens: accessor_tokens,
            token_resolver_type_token: resolver_type_token,
            runtime_resource_tokens: runtime_resource_tokens.clone(),
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // The init calls sit in `.cctor`s that also hold the program's own
        // initialization; those calls go with the runtime.
        for &initializer in &fan_in.initializers {
            detection.cleanup_mut().add_protection_method(initializer);
        }
        if let Some(rt) = runtime_type_token {
            detection.cleanup_mut().add_type(rt);
        }
        for &cctor in &classification.purely_injected {
            detection.cleanup_mut().add_method(cctor);
        }
        for &t in &guid_module_type_tokens {
            detection.cleanup_mut().add_type(t);
        }
        if let Some(rt) = resolver_type_token {
            detection.cleanup_mut().add_type(rt);
        }
        for &res in &runtime_resource_tokens {
            detection.cleanup_mut().add_manifest_resource(res);
        }

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<AntiTampFindings>() else {
            return Vec::new();
        };
        if findings.token_resolver_accessor_tokens.is_empty() {
            return Vec::new();
        }
        vec![Box::new(TokenResolverPass::new(
            findings.token_resolver_accessor_tokens.iter().copied(),
        ))]
    }
}

/// Collects every MethodDef token of `runtime_type` plus every nested
/// type's methods (recursively).
///
/// The NR runtime container's nested types (AES helper, lookup tables,
/// string registries) carry additional `ldstr` references to encrypted
/// manifest resources. Scanning only the init method would miss those.
fn collect_runtime_method_tokens(assembly: &CilObject, runtime_type: Option<Token>) -> Vec<Token> {
    let Some(root_token) = runtime_type else {
        return Vec::new();
    };
    let Some(root_type) = assembly.types().get(&root_token) else {
        return Vec::new();
    };

    let mut stack = vec![root_type];
    let mut out = Vec::new();

    while let Some(cil_type) = stack.pop() {
        for method in cil_type.methods() {
            out.push(method.token);
        }
        for (_, nested_ref) in cil_type.nested_types.iter() {
            if let Some(nested) = nested_ref.upgrade() {
                stack.push(nested);
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::testkit::load_sample;

    #[test]
    fn test_detect_positive_antitamp() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_antitamp.exe");
        let detection = NetReactorAntiTamp.detect(&assembly);
        assert!(
            detection.is_detected(),
            "Should detect anti-tamper init in reactor_antitamp.exe"
        );
        let findings = detection
            .findings::<AntiTampFindings>()
            .expect("Should attach findings");
        assert!(
            !findings.purely_injected_cctors.is_empty(),
            "Should classify at least one purely-injected .cctor"
        );
        assert!(
            !findings.guid_module_type_tokens.is_empty(),
            "Should find a <Module>{{GUID}} marker type"
        );
    }

    /// .NET Reactor calls two initializers of its runtime from each protected
    /// type's `.cctor`. Both are protection, and both go with their call
    /// sites; taking one winner by hash order left the other's calls in place
    /// on some runs and not others.
    #[test]
    fn every_runtime_initializer_is_protection() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_full.exe");
        let initializers = [Token::new(0x0600_005C), Token::new(0x0600_0067)];

        let fan_in = helpers::find_cctor_fan_in_target(&assembly).expect("injected .cctors");
        assert_eq!(fan_in.initializers, initializers);

        let detection = NetReactorAntiTamp.detect(&assembly);
        assert!(detection.is_detected());
        for initializer in initializers {
            assert!(
                detection.cleanup().strips_call_sites(initializer),
                "{initializer:?} and its call sites stay"
            );
        }
    }

    /// .NET Reactor pads the resolver's accessors with a jump over junk
    /// bytes. Matching the laid-out instructions missed every accessor, so no
    /// `typeof` hidden behind one was restored, and the raw tokens they pass
    /// named other types once cleanup renumbered the rows.
    #[test]
    fn padded_token_accessors_are_found() {
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_full.exe");
        let resolver = helpers::find_nr_token_resolver(&assembly).expect("the token resolver");
        assert!(
            resolver
                .type_handle_accessors
                .contains(&Token::new(0x0600_0151)),
            "{:?}",
            resolver.type_handle_accessors
        );
        assert!(!resolver.field_handle_accessors.is_empty());

        let accessor = assembly
            .method(&Token::new(0x0600_0151))
            .expect("the accessor");
        let executed: Vec<&str> = helpers::executed_path(&accessor)
            .map(|instruction| instruction.mnemonic)
            .collect();
        assert_eq!(executed, ["ldsflda", "ldarg.0", "call", "ret"]);
    }

    #[test]
    fn test_detect_negative_baseline() {
        let assembly = load_sample("packers/netreactor/7.5.0/original.exe");
        let detection = NetReactorAntiTamp.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not detect anti-tamper in unprotected original.exe"
        );
    }

    #[test]
    fn test_detect_negative_no_antitamp_nr() {
        // reactor_obfuscation has only 3 .cctors — fan-in primary fails,
        // so anti-tamper detection must not fire.
        let assembly = load_sample("packers/netreactor/7.5.0/reactor_obfuscation.exe");
        let detection = NetReactorAntiTamp.detect(&assembly);
        assert!(
            !detection.is_detected(),
            "Should not fire on reactor_obfuscation.exe (only 3 .cctors, no fan-in)"
        );
    }
}

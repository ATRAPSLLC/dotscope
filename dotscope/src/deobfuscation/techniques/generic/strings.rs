//! Generic string decryptor detection.
//!
//! Identifies and registers generic string decryptor methods for emulation-based
//! decryption. Common decryptor signatures include `string(int32)`,
//! `string(uint32)`, and `string(string)` — methods called from many sites
//! that likely decrypt obfuscated strings.
//!
//! # Detection
//!
//! Scans for methods matching common string decryptor signatures that are called
//! from multiple sites. Uses call-site count thresholds to avoid false positives.
//!
//! # Passes
//!
//! Does not create its own pass — uses the shared `DecryptionPass` singleton
//! added by `create_deob_passes()`. Registers discovered decryptor methods
//! with the analysis context during `initialize()`.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use log::{debug, trace};

use crate::{
    analysis::SsaOpCilExt,
    cilassembly::CleanupRequest,
    compiler::PassPhase,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{
            netreactor::find_resources_referenced_by_methods, Detection, Detections, Evidence,
            Technique, TechniqueCategory,
        },
        utils::{
            build_call_site_counts, exclude_cross_calling_candidates, filter_by_call_threshold,
        },
    },
    emulation::EmValue,
    metadata::{
        signatures::{SignatureParameter, TypeSignature},
        tables::TableId,
        token::Token,
        typesystem::wellknown,
    },
    CilObject,
};

/// Findings from generic string decryptor detection.
#[derive(Debug)]
pub struct StringFindings {
    /// Tokens of detected string decryptor methods.
    pub decryptor_methods: HashSet<Token>,
    /// Manifest resource tokens referenced only from decryptor-owned methods.
    /// Populated during detection so cleanup can remove them when the decryptor
    /// type is fully resolved and marked for removal.
    pub encrypted_resource_tokens: Vec<Token>,
}

/// Detects generic string decryptor methods.
pub struct GenericStrings;

impl GenericStrings {
    /// Collects candidate methods matching common string decryptor signatures.
    ///
    /// Scans the MethodDef table for static methods returning `string` with
    /// parameter signatures like `(int32)`, `(uint32)`, `(string)`, or
    /// `(int32, int32)`. Excludes constructors.
    fn collect_candidates(&self, assembly: &CilObject) -> Vec<Token> {
        let mut candidates = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            if !method.is_static() {
                continue;
            }
            if !matches!(method.signature.return_type.base, TypeSignature::String) {
                continue;
            }
            if method.name == wellknown::members::CCTOR || method.name == wellknown::members::CTOR {
                continue;
            }

            let param_count = method.signature.params.len();
            let matches_signature = match param_count {
                // string(int32), string(uint32), string(string)
                1 => matches!(
                    method.signature.params.first().map(|p| &p.base),
                    Some(TypeSignature::I4 | TypeSignature::U4 | TypeSignature::String)
                ),
                // string(int32, int32) — offset+length based
                2 => method
                    .signature
                    .params
                    .iter()
                    .all(|p| matches!(p.base, TypeSignature::I4)),
                _ => false,
            };

            if matches_signature {
                candidates.push(method.token);
            }
        }

        candidates
    }

    /// Builds default arguments for a warmup call based on parameter types.
    ///
    /// Returns `Some(args)` for known decryptor signatures, `None` for
    /// unsupported signatures.
    fn default_warmup_args(params: &[SignatureParameter]) -> Option<Vec<EmValue>> {
        match params.len() {
            1 => match params.first().map(|p| &p.base) {
                Some(TypeSignature::I4 | TypeSignature::U4) => Some(vec![EmValue::I32(0)]),
                Some(TypeSignature::String) => Some(vec![EmValue::Null]),
                _ => None,
            },
            2 => {
                if params.iter().all(|p| matches!(p.base, TypeSignature::I4)) {
                    Some(vec![EmValue::I32(0), EmValue::I32(0)])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Technique for GenericStrings {
    fn id(&self) -> &'static str {
        "generic.strings"
    }

    fn name(&self) -> &'static str {
        "Generic String Decryptor Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // Phase 1: collect candidates matching common string decryptor signatures.
        let candidates = self.collect_candidates(assembly);
        if candidates.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: count call sites for all candidates in a single pass.
        let counts = build_call_site_counts(assembly, candidates.iter().copied());

        trace!("GenericStrings: {} candidates found", candidates.len());
        for (token, count) in &counts {
            if let Ok(method) = assembly.method(token) {
                trace!(
                    "  candidate {}: {}({}) → string - calls: {}",
                    token,
                    method.name,
                    method
                        .signature
                        .params
                        .iter()
                        .map(|p| format!("{:?}", p.base))
                        .collect::<Vec<_>>()
                        .join(", "),
                    count
                );
            }
        }

        // Phase 3: filter by call-site threshold.
        let decryptors = filter_by_call_threshold(candidates, &counts, 3);

        // Phase 4: exclude candidates that call other candidates (consumers, not decryptors).
        let decryptors = exclude_cross_calling_candidates(decryptors, assembly);
        if decryptors.is_empty() {
            return Detection::new_empty();
        }

        let count = decryptors.len();
        let encrypted_resource_tokens = collect_decryptor_resources(assembly, &decryptors);
        let findings = StringFindings {
            decryptor_methods: decryptors,
            encrypted_resource_tokens,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} potential string decryptor methods"
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Phase 1: collect candidates matching string decryptor signatures.
        let candidates = self.collect_candidates(assembly);
        if candidates.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: count SSA calls of these candidates.
        // This catches calls that were hidden behind delegate proxies — after
        // DelegateProxyResolutionPass resolves them, direct Call ops appear.
        let mut counts: HashMap<Token, usize> = candidates.iter().map(|&t| (t, 0)).collect();
        let mut memberref_cache: HashMap<Token, Option<Token>> = HashMap::new();

        for entry in ctx.ssa_functions.iter() {
            for block in entry.value().blocks() {
                for instr in block.instructions() {
                    let Some((token, _)) = instr.op().method_call() else {
                        continue;
                    };

                    // Direct match
                    if let Some(c) = counts.get_mut(&token) {
                        *c = c.saturating_add(1);
                        continue;
                    }

                    // MemberRef indirection
                    if token.is_table(TableId::MemberRef) {
                        let resolved = memberref_cache
                            .entry(token)
                            .or_insert_with(|| assembly.resolver().resolve_memberref_method(token));
                        if let Some(resolved_token) = resolved {
                            if let Some(c) = counts.get_mut(resolved_token) {
                                *c = c.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: filter by call-site threshold.
        let decryptors = filter_by_call_threshold(candidates, &counts, 3);

        // Phase 4: exclude candidates that call other candidates (consumers, not decryptors).
        let decryptors = exclude_cross_calling_candidates(decryptors, assembly);
        if decryptors.is_empty() {
            return Detection::new_empty();
        }

        let count = decryptors.len();
        debug!(
            "GenericStrings SSA detection: {} decryptors found ({} total call sites)",
            count,
            decryptors
                .iter()
                .map(|t| counts.get(t).unwrap_or(&0))
                .sum::<usize>()
        );

        let encrypted_resource_tokens = collect_decryptor_resources(assembly, &decryptors);
        let findings = StringFindings {
            decryptor_methods: decryptors,
            encrypted_resource_tokens,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} string decryptor methods (SSA call-site analysis)"
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<StringFindings>() else {
            return;
        };

        for token in &findings.decryptor_methods {
            ctx.decryptors.register(*token);
        }

        // Register .cctors for types that own decryptor methods as warmup methods.
        // Decryptor methods often depend on static state initialized by their
        // type's class constructor (e.g., string tables, encryption keys).
        let types = assembly.types();
        for entry in types.iter() {
            let cil_type = entry.value();
            let owns_decryptor = cil_type.methods.iter().any(|(_, method_ref)| {
                method_ref
                    .upgrade()
                    .is_some_and(|m| findings.decryptor_methods.contains(&m.token))
            });
            if owns_decryptor {
                for (_, method_ref) in cil_type.methods.iter() {
                    if let Some(m) = method_ref.upgrade() {
                        if m.is_cctor() {
                            debug!(
                                "GenericStrings: registering warmup .cctor 0x{:08X} for {}.{}",
                                m.token.value(),
                                cil_type.namespace,
                                cil_type.name
                            );
                            ctx.register_warmup_method(m.token, vec![]);
                        }
                    }
                }
            }
        }

        // Register warmup calls for decryptors that lazily initialize their
        // string table on first invocation. A single call with a default argument
        // populates the table on the template process, so forked decryption calls
        // skip the expensive initialization.
        for &token in &findings.decryptor_methods {
            if let Ok(method) = assembly.method(&token) {
                let warmup_args = Self::default_warmup_args(&method.signature.params);
                if let Some(args) = warmup_args {
                    debug!(
                        "GenericStrings: registering warmup call 0x{:08X} ({})",
                        token.value(),
                        method.name
                    );
                    ctx.register_warmup_method(token, args);
                }
            }
        }
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<StringFindings>()?;
        if findings.decryptor_methods.is_empty() {
            return None;
        }
        let mut req = CleanupRequest::new();
        for &token in &findings.decryptor_methods {
            req.add_method(token);
        }
        for &token in &findings.encrypted_resource_tokens {
            req.add_manifest_resource(token);
        }
        Some(req)
    }
}

/// Collects manifest-resource tokens referenced by name from the decryptors'
/// declaring types (and their nested types).
///
/// The NR strings protection stores the encrypted string table in a managed
/// resource whose name is loaded via `ldstr` by the decryptor (or methods in
/// the same injected type / its nested types). Once every call site is
/// resolved and the decryptor type is cleaned up, those resources become dead
/// payload. Scanning by `ldstr` name is the structural signal used here —
/// matching the pattern already used for NR anti-tamper resource cleanup.
///
/// This returns resources reachable from ANY decryptor-owned method. The
/// cleanup request marks them unconditionally; the executor's existing
/// protection for non-removable decryptors keeps the resource alive whenever
/// the decryptor itself is kept, so a partial decryption result doesn't leave
/// runtime calls referencing a removed resource.
fn collect_decryptor_resources(assembly: &CilObject, decryptors: &HashSet<Token>) -> Vec<Token> {
    let mut declaring_types: HashSet<Token> = HashSet::new();
    for &decryptor in decryptors {
        if let Ok(method) = assembly.method(&decryptor) {
            if let Some(parent) = method.declaring_type_rc() {
                declaring_types.insert(parent.token);
            }
        }
    }

    let mut method_tokens: Vec<Token> = Vec::new();
    let mut stack: Vec<Token> = declaring_types.into_iter().collect();
    let mut visited: HashSet<Token> = stack.iter().copied().collect();
    while let Some(type_token) = stack.pop() {
        let Some(cil_type) = assembly.types().get(&type_token) else {
            continue;
        };
        for method in cil_type.methods() {
            method_tokens.push(method.token);
        }
        for (_, nested_ref) in cil_type.nested_types.iter() {
            if let Some(nested) = nested_ref.upgrade() {
                if visited.insert(nested.token) {
                    stack.push(nested.token);
                }
            }
        }
    }

    if method_tokens.is_empty() {
        return Vec::new();
    }
    find_resources_referenced_by_methods(assembly, &method_tokens)
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// ConfuserEx and Obfuscar use obfuscator-specific decryptor signatures
    /// (e.g. ConfuserEx `T Get<T>(int32)`, Obfuscar XOR string hiding) that
    /// the more specific techniques handle. The generic technique catches
    /// simpler `string(int32)` / `string(string)` patterns from other packers.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_constants.exe");
        let technique = super::GenericStrings;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericStrings;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

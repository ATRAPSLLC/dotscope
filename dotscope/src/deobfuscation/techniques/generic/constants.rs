//! Generic constant decryptor detection.
//!
//! Identifies and registers generic constant decryptor methods — methods that
//! decrypt integer, float, or array constants via FieldRVA-backed data. Common
//! patterns include `T(int32)` generic decryptor methods and `int32(int32)`
//! constant accessors.
//!
//! # Detection
//!
//! Scans for methods with characteristic constant decryptor signatures and
//! FieldRVA-backed data fields.
//!
//! # Passes
//!
//! Does not create its own pass — uses the shared `DecryptionPass` from
//! `create_deob_passes()`. Registers discovered decryptor methods with the
//! analysis context during `initialize()`.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
};

use log::debug;

use crate::{
    analysis::SsaOpCilExt,
    cilassembly::CleanupRequest,
    compiler::PassPhase,
    deobfuscation::{
        context::AnalysisContext,
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
        utils::{
            build_call_site_counts, exclude_cross_calling_candidates, filter_by_call_threshold,
        },
    },
    metadata::{signatures::TypeSignature, tables::TableId, token::Token, typesystem::wellknown},
    CilObject,
};

/// Findings from generic constant decryptor detection.
#[derive(Debug)]
pub struct ConstantFindings {
    /// Tokens of detected constant decryptor methods.
    pub decryptor_methods: HashSet<Token>,
}

/// Detects generic constant decryptor methods.
pub struct GenericConstants;

impl GenericConstants {
    /// Collects candidate methods matching common constant decryptor signatures.
    ///
    /// Scans the MethodDef table for static methods with `int32(int32)` or
    /// `object(int32)` signatures. Excludes constructors.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to scan for candidate methods.
    fn collect_candidates(&self, assembly: &CilObject) -> Vec<Token> {
        let mut candidates = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            if !method.is_static() {
                continue;
            }
            if method.name == wellknown::members::CCTOR || method.name == wellknown::members::CTOR {
                continue;
            }

            let param_count = method.signature.params.len();
            let first_param_base = method.signature.params.first().map(|p| &p.base);

            // int32(int32) — integer constant accessor
            let is_int_accessor = param_count == 1
                && matches!(first_param_base, Some(TypeSignature::I4))
                && matches!(method.signature.return_type.base, TypeSignature::I4);

            // object(int32) — generic constant accessor
            let is_obj_accessor = param_count == 1
                && matches!(first_param_base, Some(TypeSignature::I4))
                && matches!(method.signature.return_type.base, TypeSignature::Object);

            if !is_int_accessor && !is_obj_accessor {
                continue;
            }

            // Exclude methods that call other user-defined methods (MethodDef).
            // Real constant decryptors are leaf functions: they do table lookups
            // or arithmetic on their argument, without calling into user code.
            // Methods like sqlite3StatusValue that call wsdStatInit() are utility
            // functions, not decryptors, and their dependencies often fail to
            // emulate (e.g., .cctor failures).
            let calls_user_methods = method.instructions().any(|instr| {
                if instr.mnemonic != "call" && instr.mnemonic != "callvirt" {
                    return false;
                }
                instr
                    .get_token_operand()
                    .is_some_and(|t| t.is_table(TableId::MethodDef))
            });

            if !calls_user_methods {
                candidates.push(method.token);
            }
        }

        candidates
    }
}

impl Technique for GenericConstants {
    fn id(&self) -> &'static str {
        "generic.constants"
    }

    fn name(&self) -> &'static str {
        "Generic Constant Decryptor Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        // Phase 1: collect candidates matching constant decryptor signatures.
        let candidates = self.collect_candidates(assembly);
        if candidates.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: count call sites for all candidates in a single IL pass.
        let counts = build_call_site_counts(assembly, candidates.iter().copied());

        // Phase 3: filter by call-site threshold.
        let decryptors = filter_by_call_threshold(candidates, &counts, 3);

        // Phase 4: exclude candidates that call other candidates (consumers, not decryptors).
        let decryptors = exclude_cross_calling_candidates(decryptors, assembly);
        if decryptors.is_empty() {
            return Detection::new_empty();
        }

        let count = decryptors.len();
        let findings = ConstantFindings {
            decryptor_methods: decryptors,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} potential constant decryptor methods"
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Phase 1: collect candidates matching constant decryptor signatures.
        let candidates = self.collect_candidates(assembly);
        if candidates.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: count SSA calls of candidates.
        // This catches calls hidden behind delegate proxies — after
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
            "GenericConstants SSA detection: {} decryptors found ({} total call sites)",
            count,
            decryptors
                .iter()
                .map(|t| counts.get(t).unwrap_or(&0))
                .sum::<usize>()
        );

        let findings = ConstantFindings {
            decryptor_methods: decryptors,
        };

        Detection::new_detected(
            vec![Evidence::Structural(format!(
                "{count} constant decryptor methods (SSA call-site analysis)"
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
        _assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<ConstantFindings>() else {
            return;
        };

        for token in &findings.decryptor_methods {
            ctx.decryptors.register(*token);
        }
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<ConstantFindings>()?;
        if findings.decryptor_methods.is_empty() {
            return None;
        }
        let mut req = CleanupRequest::new();
        for &token in &findings.decryptor_methods {
            req.add_method(token);
        }
        Some(req)
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// ConfuserEx uses a unified `T Get<T>(int32)` decryptor that the
    /// ConfuserEx-specific technique handles. The generic technique catches
    /// simpler `int32(int32)` / `object(int32)` patterns from other packers.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_constants.exe");
        let technique = super::GenericConstants;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericConstants;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

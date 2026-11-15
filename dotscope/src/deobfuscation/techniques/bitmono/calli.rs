//! BitMono CallToCalli detection.
//!
//! Detects BitMono's CallToCalli protection, which replaces direct `call`
//! instructions with an indirect `calli` sequence. The obfuscation embeds the
//! original method token as an `ldc.i4` immediate, making it fully statically
//! reversible.
//!
//! # CIL Pattern
//!
//! Each `call <MethodDef>` is replaced with a 10-instruction sequence:
//! ```text
//! ldtoken    <Module>                                 // -> SSA: LoadToken
//! call       Type::GetTypeFromHandle                  // -> SSA: Call
//! callvirt   Type::get_Module                         // -> SSA: Call (virtual)
//! ldc.i4     0x06XXXXXX                               // -> SSA: Const(I32) <- target token
//! call       Module::ResolveMethod                    // -> SSA: Call
//! callvirt   MethodBase::get_MethodHandle             // -> SSA: Call (virtual)
//! stloc      <handle_local>                           // -> SSA: StoreLocal
//! ldloca     <handle_local>                           // -> SSA: LoadLocalAddr
//! call       RuntimeMethodHandle::GetFunctionPointer  // -> SSA: Call
//! calli      <StandAloneSig>                          // -> SSA: Call (indirect)
//! ```
//!
//! # Detection
//!
//! Scans all methods for `calli` instructions preceded by the characteristic
//! `ldtoken <Module>` + `ResolveMethod` + `GetFunctionPointer` trampoline
//! pattern. Methods containing at least one such site are recorded in
//! [`CalliFindings`] for attribution and evidence.
//!
//! # SSA Reversal
//!
//! The actual reversal is handled by
//! [`ReflectionDevirtualizationPass`](crate::deobfuscation::passes::ReflectionDevirtualizationPass),
//! which absorbs the P1 (ResolveMethod + calli) pattern along with other
//! reflection-based call indirection patterns.

use std::{any::Any, collections::HashSet};

use crate::{
    deobfuscation::{
        context::AnalysisContext,
        passes::count_resolve_method_calli_sites,
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from BitMono CallToCalli detection.
#[derive(Debug)]
pub struct CalliFindings {
    /// Method tokens containing CallToCalli conversion sites.
    pub method_tokens: HashSet<Token>,
    /// Total number of CallToCalli sites across all affected methods.
    pub site_count: usize,
}

/// Detects BitMono's CallToCalli indirect call protection.
///
/// Identifies methods containing `calli` instructions preceded by the
/// `ldtoken <Module>` + `ResolveMethod` + `GetFunctionPointer` trampoline
/// pattern. This technique is detection-only — the actual reversal is
/// handled by [`ReflectionDevirtualizationPass`](crate::deobfuscation::passes::ReflectionDevirtualizationPass).
pub struct BitMonoCalli;

impl Technique for BitMonoCalli {
    fn id(&self) -> &'static str {
        "bitmono.calli"
    }

    fn name(&self) -> &'static str {
        "BitMono CallToCalli Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Structure
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut site_count = 0usize;

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let instructions: Vec<_> = method.instructions().collect();

            let mut method_sites: usize = 0;
            let mut i: usize = 0;
            while i < instructions.len() {
                let Some(instr_at_i) = instructions.get(i) else {
                    break;
                };
                if instr_at_i.mnemonic == "calli" {
                    // Walk backwards up to 12 instructions looking for the
                    // characteristic BitMono trampoline pattern:
                    //   ldtoken <Module> -> GetTypeFromHandle -> get_Module
                    //   -> ldc.i4 <token> -> ResolveMethod -> get_MethodHandle
                    //   -> GetFunctionPointer -> calli
                    let window_start = i.saturating_sub(12);
                    let window = instructions.get(window_start..i).unwrap_or(&[]);

                    let has_ldtoken = window.iter().any(|instr| instr.mnemonic == "ldtoken");
                    let has_trampoline_api = window.iter().any(|instr| {
                        instr
                            .get_token_operand()
                            .and_then(|t| assembly.resolve_method_name(t))
                            .is_some_and(|n| {
                                n.contains("ResolveMethod") || n.contains("GetFunctionPointer")
                            })
                    });

                    if has_ldtoken && has_trampoline_api {
                        method_sites = method_sites.saturating_add(1);
                    }
                }
                i = i.saturating_add(1);
            }

            if method_sites > 0 {
                method_tokens.insert(method.token);
                site_count = site_count.saturating_add(method_sites);
            }
        }

        if site_count == 0 {
            return Detection::new_empty();
        }

        let method_count = method_tokens.len();
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{site_count} CallToCalli conversion sites in {method_count} methods \
                 (ldtoken + ResolveMethod + calli)"
            ))],
            Some(Box::new(CalliFindings {
                method_tokens,
                site_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut site_count = 0usize;
        for entry in ctx.ssa_functions.iter() {
            let count = count_resolve_method_calli_sites(entry.value(), assembly);
            if count > 0 {
                site_count = site_count.saturating_add(count);
                method_tokens.insert(*entry.key());
            }
        }
        if site_count == 0 {
            return Detection::new_empty();
        }
        let method_count = method_tokens.len();
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{site_count} CallToCalli sites in {method_count} methods \
                 (SSA def-use chain confirmed)"
            ))],
            Some(Box::new(CalliFindings {
                method_tokens,
                site_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoCalli, Technique},
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_calltocalli.exe");

        let technique = BitMonoCalli;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoCalli should detect CallToCalli pattern in bitmono_calltocalli.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoCalli;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoCalli should not detect CallToCalli in a non-BitMono assembly"
        );
    }
}

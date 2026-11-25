//! BitMono AntiDebugBreakpoints detection and removal.
//!
//! Detects and removes BitMono's AntiDebugBreakpoints protection, which injects
//! timing checks into method bodies. The timing check measures execution time
//! using `DateTime.UtcNow` calls at the start and end of the method, computes
//! the difference via `op_Subtraction`, and checks `TotalMilliseconds` against
//! a threshold. If the elapsed time exceeds the threshold (indicating a debugger
//! breakpoint was hit), the method triggers a divide-by-zero crash.
//!
//! # CIL Pattern
//!
//! The injected prologue:
//! ```text
//! call       DateTime::get_UtcNow()
//! stloc      <datetime_local>
//! ```
//!
//! The injected epilogue (before the method's real return):
//! ```text
//! call       DateTime::get_UtcNow()
//! ldloc      <datetime_local>
//! call       DateTime::op_Subtraction()
//! stloc      <timespan_local>
//! ldloca     <timespan_local>
//! call       TimeSpan::get_TotalMilliseconds()
//! ldc.r8     5000.0
//! ble.un.s   <skip_label>
//! ldc.i4.1                         ; the dividend (0.39 pushes 1)
//! ldc.i4.0
//! stloc      <int_local>
//! ldloc      <int_local>
//! div                              ; divide-by-zero crash
//! pop
//! ```
//!
//! # Detection
//!
//! Scans all methods for the three sentinel API calls:
//! - `DateTime::get_UtcNow` (start and end timestamps)
//! - `DateTime::op_Subtraction` (time difference)
//! - `TimeSpan::get_TotalMilliseconds` (threshold comparison)
//!
//! A method containing all three and the divide-by-zero crash is flagged as
//! having the anti-debug pattern. The three calls alone are what any code
//! measuring elapsed time makes.
//!
//! # SSA Pass
//!
//! The removal pass is [`SentinelTaintRemovalPass`],
//! and uses forward-only taint analysis seeded from the three sentinel API calls
//! to automatically identify and remove all dependent obfuscation code.

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::CilTarget,
    assembly::Instruction,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{SentinelCondition, SentinelTaintRemovalPass},
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
        utils::find_methods_calling_apis,
    },
    metadata::{method::Method, token::Token},
    CilObject,
};

/// The local an `stloc` (`store`) or `ldloc` names, in any of its forms.
pub fn local_slot(instruction: &Instruction, store: bool) -> Option<u16> {
    let rest = instruction
        .mnemonic
        .strip_prefix(if store { "stloc" } else { "ldloc" })?;
    match rest {
        ".0" => Some(0),
        ".1" => Some(1),
        ".2" => Some(2),
        ".3" => Some(3),
        ".s" => instruction.get_u8_operand().map(u16::from),
        "" => instruction.get_u16_operand(),
        _ => None,
    }
}

/// Whether `method` holds the injection's crash: a division by a local just
/// set to zero whose result nothing reads - `ldc.i4.0; stloc x; ldloc x; div;
/// pop` after any dividend (BitMono 0.39 pushes `1`), or `ldloc x` as the
/// dividend too.
fn has_divide_by_zero_crash(method: &Method) -> bool {
    let instructions: Vec<_> = method.instructions().collect();
    (0..instructions.len()).any(|at| {
        let tail = instructions.get(at..).unwrap_or_default();
        let [zero, store, divisor, rest @ ..] = tail else {
            return false;
        };
        let slot = local_slot(store, true);
        if zero.mnemonic != "ldc.i4.0" || slot.is_none() || local_slot(divisor, false) != slot {
            return false;
        }
        let rest = match rest {
            [again, rest @ ..] if local_slot(again, false) == slot => rest,
            _ => rest,
        };
        matches!(rest, [div, pop, ..] if div.mnemonic == "div" && pop.mnemonic == "pop")
    })
}

/// Findings from BitMono AntiDebugBreakpoints detection.
#[derive(Debug)]
pub struct BmAntiDebugFindings {
    /// Tokens of methods containing the timing check anti-debug pattern.
    pub method_tokens: HashSet<Token>,
}

/// Detects BitMono's AntiDebugBreakpoints timing check pattern.
///
/// Identifies methods that contain `DateTime.UtcNow` + `op_Subtraction` +
/// `TotalMilliseconds` — the three sentinel API calls that comprise BitMono's
/// timing-based anti-debug protection. Supersedes the generic anti-debug
/// detection for BitMono-protected assemblies.
pub struct BitMonoAntiDebug;

impl Technique for BitMonoAntiDebug {
    fn id(&self) -> &'static str {
        "bitmono.debug"
    }

    fn name(&self) -> &'static str {
        "BitMono AntiDebugBreakpoints Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.debug"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let patterns = &["get_UtcNow", "op_Subtraction", "get_TotalMilliseconds"];
        let matches = find_methods_calling_apis(assembly, patterns);

        // All three sentinel APIs in one method are what any code measuring
        // elapsed time calls - mono's `System.dll` does it to pace a timer.
        // What only the injection has is its crash: a local set to zero,
        // divided by itself, the quotient dropped.
        let method_tokens: HashSet<Token> = matches
            .into_iter()
            .filter(|(_, idxs)| idxs.contains(&0) && idxs.contains(&1) && idxs.contains(&2))
            .map(|(token, _)| token)
            .filter(|token| {
                assembly
                    .methods()
                    .get(token)
                    .is_some_and(|entry| has_divide_by_zero_crash(entry.value()))
            })
            .collect();

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = method_tokens.len();
        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with BitMono AntiDebugBreakpoints timing checks \
                 (UtcNow + op_Subtraction + TotalMilliseconds)"
            ))],
            None,
        );

        detection.set_findings(Box::new(BmAntiDebugFindings { method_tokens }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<BmAntiDebugFindings>() else {
            return Vec::new();
        };
        vec![Box::new(SentinelTaintRemovalPass::new(
            "BitMonoAntiDebug",
            "Removes BitMono AntiDebugBreakpoints timing checks via taint analysis",
            findings.method_tokens.clone(),
            vec!["get_UtcNow", "op_Subtraction", "get_TotalMilliseconds"],
            SentinelCondition::All,
        ))]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoAntiDebug, Technique},
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_antidebug.exe");

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        // BitMonoAntiDebug is an SSA technique, but its IL-level detect()
        // scans for the sentinel API calls (UtcNow, op_Subtraction,
        // TotalMilliseconds) and the divide-by-zero crash they guard.
        assert!(
            detection.is_detected(),
            "the antidebug sample carries the injected timing checks"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Positive detection should include evidence"
        );
    }

    /// Code that measures elapsed time calls the same three APIs; without the
    /// injection's divide-by-zero crash it is not BitMono's. Mono's
    /// `System.dll` paces a timer that way, and the removal pass used to strip
    /// its arithmetic and force its branch.
    #[test]
    fn test_detect_elapsed_time_code_is_not_the_injection() {
        let assembly = load_sample("mono_4.5/System.dll");
        assert!(!BitMonoAntiDebug.detect(&assembly).is_detected());
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoAntiDebug;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoAntiDebug should not detect timing checks in a non-BitMono assembly"
        );
    }
}

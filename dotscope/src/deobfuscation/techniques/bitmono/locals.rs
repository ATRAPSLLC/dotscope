//! BitMono LocalVariableEncoding detection.
//!
//! LocalVariableEncoding stores every integer local of a method encoded and decodes it on
//! every load, with a key of its own per local:
//!
//! ```text
//! ldc k; xor; ldc m; mul; ldc a; add; [conv]; stloc v        // store
//! ldloc v; ldc a; sub; ldc m'; mul; ldc k; xor; [conv]       // load, m * m' == 1
//! ```
//!
//! # Detection
//!
//! A local both stored through the encode and loaded through the decode with the same key,
//! the inverse multiplier undoing the multiplier, is BitMono's: the pair is what no compiler
//! emits for a local.
//!
//! # SSA Pass
//!
//! [`LocalEncodingReversalPass`]
//! carries each encoded local's values plain.

use std::{any::Any, collections::HashSet, sync::Arc};

use crate::{
    analysis::CilTarget,
    assembly::Instruction,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::bitmono::LocalEncodingReversalPass,
        techniques::{
            bitmono::debug::local_slot, Detection, Evidence, Technique, TechniqueCategory,
        },
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from BitMono LocalVariableEncoding detection.
#[derive(Debug)]
pub struct LocalsFindings {
    /// The methods with an encoded local.
    pub method_tokens: HashSet<Token>,
    /// The number of encoded locals across them.
    pub local_count: usize,
}

/// Detects BitMono's LocalVariableEncoding.
pub struct BitMonoLocals;

/// The integer an `ldc.i4` or `ldc.i8` loads, as its 64 bits, and its width.
fn constant(instruction: &Instruction) -> Option<(u64, u32)> {
    match instruction.mnemonic {
        "ldc.i4" => instruction
            .get_i32_operand()
            .map(|v| (u64::from(v.cast_unsigned()), 32)),
        "ldc.i8" => instruction
            .get_i64_operand()
            .map(|v| (v.cast_unsigned(), 64)),
        _ => None,
    }
}

/// The width a narrowing conversion of an 8- or 16-bit local wraps at.
fn narrowing(instruction: &Instruction) -> Option<u32> {
    match instruction.mnemonic {
        "conv.i1" | "conv.u1" => Some(8),
        "conv.i2" | "conv.u2" => Some(16),
        _ => None,
    }
}

/// The encoded locals of a method's instructions: each stored as `encode` and loaded as
/// `decode` with one key.
fn encoded_locals(instructions: &[&Instruction]) -> usize {
    // (local, xor, multiplier, addend, width) of every encoded store.
    let mut stores: HashSet<(u16, u64, u64, u64, u32)> = HashSet::new();
    for window in instructions.windows(8) {
        let [k, xor, m, mul, a, add, last, after] = window else {
            continue;
        };
        if xor.mnemonic != "xor" || mul.mnemonic != "mul" || add.mnemonic != "add" {
            continue;
        }
        let (Some((k, w)), Some((m, _)), Some((a, _))) = (constant(k), constant(m), constant(a))
        else {
            continue;
        };
        let (width, store) = match narrowing(last) {
            Some(width) => (width, *after),
            None => (w, *last),
        };
        if let Some(slot) = local_slot(store, true) {
            stores.insert((slot, k, m, a, width));
        }
    }

    let mask = |width: u32| {
        if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width).wrapping_sub(1)
        }
    };
    let mut locals: HashSet<u16> = HashSet::new();
    for window in instructions.windows(7) {
        let [load, a, sub, inverse, mul, k, xor] = window else {
            continue;
        };
        if sub.mnemonic != "sub" || mul.mnemonic != "mul" || xor.mnemonic != "xor" {
            continue;
        }
        let (Some(slot), Some((a, _)), Some((inverse, _)), Some((k, _))) = (
            local_slot(load, false),
            constant(a),
            constant(inverse),
            constant(k),
        ) else {
            continue;
        };
        let paired = stores
            .iter()
            .any(|&(local, xor, multiplier, addend, width)| {
                local == slot
                    && xor & mask(width) == k & mask(width)
                    && addend & mask(width) == a & mask(width)
                    && multiplier.wrapping_mul(inverse) & mask(width) == 1
            });
        if paired {
            locals.insert(slot);
        }
    }
    locals.len()
}

impl Technique for BitMonoLocals {
    fn id(&self) -> &'static str {
        "bitmono.locals"
    }

    fn name(&self) -> &'static str {
        "BitMono LocalVariableEncoding Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut local_count = 0usize;
        for entry in assembly.methods() {
            let method = entry.value();
            let instructions: Vec<&Instruction> = method.instructions().collect();
            let locals = encoded_locals(&instructions);
            if locals > 0 {
                method_tokens.insert(method.token);
                local_count = local_count.saturating_add(locals);
            }
        }
        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        let methods = method_tokens.len();
        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{local_count} encoded locals in {methods} methods \
                 (xor/mul/add on store, sub/mul/xor with the inverse multiplier on load)"
            ))],
            Some(Box::new(LocalsFindings {
                method_tokens,
                local_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Structure)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        if detection.findings::<LocalsFindings>().is_none() {
            return Vec::new();
        }
        vec![Box::new(LocalEncodingReversalPass)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.45.0/bitmono_localvariableencoding.exe");
        let detection = BitMonoLocals.detect(&assembly);
        assert!(detection.is_detected());
        let findings = detection.findings::<LocalsFindings>().expect("findings");
        assert!(findings.local_count > 0);
    }

    #[test]
    fn test_detect_negative() {
        for sample in [
            "packers/bitmono/0.45.0/original.exe",
            "packers/bitmono/0.45.0/bitmono_maximum.exe",
            "packers/confuserex/1.6.0/mkaring_maximum.exe",
        ] {
            assert!(
                !BitMonoLocals.detect(&load_sample(sample)).is_detected(),
                "{sample}"
            );
        }
    }
}

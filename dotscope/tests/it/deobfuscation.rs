#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Deobfuscation pipeline tests with exact IL verification.
//!
//! All tests follow the same rigorous pattern:
//! 1. Build input CIL using `InstructionAssembler`
//! 2. Convert CIL → CFG → SSA
//! 3. Run `DeobfuscationEngine::process_ssa()` with full pass pipeline
//! 4. Generate CIL back from SSA using `SsaCodeGenerator`
//! 5. Verify the **exact** instruction sequence matches expectations
//!
//! This ensures we're testing the complete pipeline and catching any regressions
//! in CIL parsing, SSA construction, optimization passes, and code generation.

#![cfg(feature = "deobfuscation")]

use std::sync::Arc;

use dotscope::{
    analysis::{CallGraph, SsaFunction, SsaType},
    assembly::{decode_stream, Immediate, Instruction, InstructionAssembler, Operand},
    compiler::{DerivedStats, SsaCodeGenerator},
    deobfuscation::{AnalysisContext, EngineConfig},
    metadata::token::Token,
    testkit::{build_cfg, build_ssa, engine, engine_with, fixture, TestTypeProvider},
    CilObject, Parser, Result,
};

/// Represents a decoded CIL instruction for verification.
#[derive(Debug, Clone, PartialEq)]
struct ExpectedInstruction {
    pattern: MnemonicPattern,
    operand: Option<ExpectedOperand>,
}

/// Mnemonic matching patterns.
#[derive(Debug, Clone, PartialEq)]
enum MnemonicPattern {
    /// Exact mnemonic match
    Exact(&'static str),
    /// Match any ldloc variant (ldloc.0-3, ldloc.s, ldloc)
    AnyLdloc,
    /// Match any stloc variant (stloc.0-3, stloc.s, stloc)
    AnyStloc,
    /// Match branch instruction with any operand (both short .s and long forms)
    AnyBranch(&'static str),
    /// Match any conditional branch (brfalse/brfalse.s/brtrue/brtrue.s)
    /// Used when branch direction may be inverted by optimization
    AnyConditionalBranch,
    /// Match any ldc.i4 variant (ldc.i4.0-8, ldc.i4.m1, ldc.i4.s, ldc.i4)
    /// Used when block ordering is non-deterministic
    AnyLdcI4,
}

/// Expected operand values for verification.
#[derive(Debug, Clone, PartialEq)]
enum ExpectedOperand {
    /// Any operand is acceptable (used when we don't care about the specific value)
    Any,
    /// Specific i8 value
    I8(i8),
    /// Specific i32 value
    I32(i32),
    /// Specific i64 value
    I64(i64),
    /// Specific f32 value
    F32(f32),
    /// Specific f64 value
    F64(f64),
    /// Branch target (relative offset) - we verify it's a valid branch
    BranchTarget,
}

impl ExpectedInstruction {
    fn new(mnemonic: &'static str) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: None,
        }
    }

    fn with_i8(mnemonic: &'static str, value: i8) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::I8(value)),
        }
    }

    fn with_i32(mnemonic: &'static str, value: i32) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::I32(value)),
        }
    }

    fn with_i64(mnemonic: &'static str, value: i64) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::I64(value)),
        }
    }

    fn with_f32(mnemonic: &'static str, value: f32) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::F32(value)),
        }
    }

    fn with_f64(mnemonic: &'static str, value: f64) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::F64(value)),
        }
    }

    fn with_branch(mnemonic: &'static str) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::BranchTarget),
        }
    }

    fn with_any_operand(mnemonic: &'static str) -> Self {
        Self {
            pattern: MnemonicPattern::Exact(mnemonic),
            operand: Some(ExpectedOperand::Any),
        }
    }

    /// Match any ldloc variant (ldloc.0-3, ldloc.s, ldloc)
    fn any_ldloc() -> Self {
        Self {
            pattern: MnemonicPattern::AnyLdloc,
            operand: None,
        }
    }

    /// Match any stloc variant (stloc.0-3, stloc.s, stloc)
    fn any_stloc() -> Self {
        Self {
            pattern: MnemonicPattern::AnyStloc,
            operand: None,
        }
    }

    /// Match branch instruction (both short .s and long forms)
    /// e.g., any_branch("brfalse") matches both "brfalse" and "brfalse.s"
    fn any_branch(base_mnemonic: &'static str) -> Self {
        Self {
            pattern: MnemonicPattern::AnyBranch(base_mnemonic),
            operand: Some(ExpectedOperand::Any),
        }
    }

    /// Match any conditional branch (brfalse/brfalse.s/brtrue/brtrue.s).
    /// Used when branch direction may be inverted by optimization.
    fn any_conditional_branch() -> Self {
        Self {
            pattern: MnemonicPattern::AnyConditionalBranch,
            operand: Some(ExpectedOperand::Any),
        }
    }

    /// Match any ldc.i4 variant (ldc.i4.0-8, ldc.i4.m1, ldc.i4.s, ldc.i4).
    /// Used when block ordering is non-deterministic.
    fn any_ldc_i4() -> Self {
        Self {
            pattern: MnemonicPattern::AnyLdcI4,
            operand: None,
        }
    }

    /// Check if actual instruction matches expected.
    fn matches(&self, actual: &Instruction) -> bool {
        // First check mnemonic pattern
        let mnemonic_matches = match &self.pattern {
            MnemonicPattern::Exact(expected) => actual.mnemonic == *expected,
            MnemonicPattern::AnyLdloc => {
                actual.mnemonic == "ldloc.0"
                    || actual.mnemonic == "ldloc.1"
                    || actual.mnemonic == "ldloc.2"
                    || actual.mnemonic == "ldloc.3"
                    || actual.mnemonic == "ldloc.s"
                    || actual.mnemonic == "ldloc"
            }
            MnemonicPattern::AnyStloc => {
                actual.mnemonic == "stloc.0"
                    || actual.mnemonic == "stloc.1"
                    || actual.mnemonic == "stloc.2"
                    || actual.mnemonic == "stloc.3"
                    || actual.mnemonic == "stloc.s"
                    || actual.mnemonic == "stloc"
            }
            MnemonicPattern::AnyBranch(base) => {
                // Match both long form (e.g., "brfalse") and short form (e.g., "brfalse.s")
                actual.mnemonic == *base || actual.mnemonic == format!("{base}.s")
            }
            MnemonicPattern::AnyConditionalBranch => {
                // Match any conditional branch (direction may be inverted by optimization)
                actual.mnemonic == "brfalse"
                    || actual.mnemonic == "brfalse.s"
                    || actual.mnemonic == "brtrue"
                    || actual.mnemonic == "brtrue.s"
            }
            MnemonicPattern::AnyLdcI4 => {
                // Match any ldc.i4 variant
                actual.mnemonic == "ldc.i4.0"
                    || actual.mnemonic == "ldc.i4.1"
                    || actual.mnemonic == "ldc.i4.2"
                    || actual.mnemonic == "ldc.i4.3"
                    || actual.mnemonic == "ldc.i4.4"
                    || actual.mnemonic == "ldc.i4.5"
                    || actual.mnemonic == "ldc.i4.6"
                    || actual.mnemonic == "ldc.i4.7"
                    || actual.mnemonic == "ldc.i4.8"
                    || actual.mnemonic == "ldc.i4.m1"
                    || actual.mnemonic == "ldc.i4.s"
                    || actual.mnemonic == "ldc.i4"
            }
        };

        if !mnemonic_matches {
            return false;
        }

        // For pattern-based matches, we don't check operands (they're inherent to the variant)
        if matches!(
            self.pattern,
            MnemonicPattern::AnyLdloc
                | MnemonicPattern::AnyStloc
                | MnemonicPattern::AnyBranch(_)
                | MnemonicPattern::AnyConditionalBranch
                | MnemonicPattern::AnyLdcI4
        ) {
            return true;
        }

        match &self.operand {
            None => matches!(actual.operand, Operand::None),
            Some(ExpectedOperand::Any) => true,
            Some(ExpectedOperand::I8(expected)) => {
                matches!(actual.operand, Operand::Immediate(Immediate::Int8(v)) if v == *expected)
            }
            Some(ExpectedOperand::I32(expected)) => {
                matches!(actual.operand, Operand::Immediate(Immediate::Int32(v)) if v == *expected)
            }
            Some(ExpectedOperand::I64(expected)) => {
                matches!(actual.operand, Operand::Immediate(Immediate::Int64(v)) if v == *expected)
            }
            Some(ExpectedOperand::F32(expected)) => {
                matches!(actual.operand, Operand::Immediate(Immediate::Float32(v)) if (v - expected).abs() < f32::EPSILON)
            }
            Some(ExpectedOperand::F64(expected)) => {
                matches!(actual.operand, Operand::Immediate(Immediate::Float64(v)) if (v - expected).abs() < f64::EPSILON)
            }
            Some(ExpectedOperand::BranchTarget) => matches!(actual.operand, Operand::Target(_)),
        }
    }
}

/// Helper macros for building expected instruction sequences.
macro_rules! instr {
    ($mnemonic:literal) => {
        ExpectedInstruction::new($mnemonic)
    };
    ($mnemonic:literal, i8: $val:expr) => {
        ExpectedInstruction::with_i8($mnemonic, $val)
    };
    ($mnemonic:literal, i32: $val:expr) => {
        ExpectedInstruction::with_i32($mnemonic, $val)
    };
    ($mnemonic:literal, i64: $val:expr) => {
        ExpectedInstruction::with_i64($mnemonic, $val)
    };
    ($mnemonic:literal, f32: $val:expr) => {
        ExpectedInstruction::with_f32($mnemonic, $val)
    };
    ($mnemonic:literal, f64: $val:expr) => {
        ExpectedInstruction::with_f64($mnemonic, $val)
    };
    ($mnemonic:literal, branch) => {
        ExpectedInstruction::with_branch($mnemonic)
    };
    ($mnemonic:literal, any) => {
        ExpectedInstruction::with_any_operand($mnemonic)
    };
    // Pattern-based matches for local variable access
    (any_ldloc) => {
        ExpectedInstruction::any_ldloc()
    };
    (any_stloc) => {
        ExpectedInstruction::any_stloc()
    };
    // Match branch instruction (both short .s and long forms)
    (any_branch: $base:literal) => {
        ExpectedInstruction::any_branch($base)
    };
    // Match any conditional branch (direction may be inverted)
    (any_conditional_branch) => {
        ExpectedInstruction::any_conditional_branch()
    };
    // Match any ldc.i4 variant (block ordering may be non-deterministic)
    (any_ldc_i4) => {
        ExpectedInstruction::any_ldc_i4()
    };
}

/// Generate CIL from SSA.
fn generate_cil(ssa: &SsaFunction) -> Result<Vec<u8>> {
    let mut gen = SsaCodeGenerator::new();
    let (bytecode, _max_stack, _num_locals) = gen.generate(ssa)?;
    Ok(bytecode)
}

/// Decode bytecode into instructions.
fn decode_instructions(bytecode: &[u8]) -> Result<Vec<Instruction>> {
    decode_stream(&mut Parser::new(bytecode), 0x1000)
}

/// Loads a test assembly for use with process_ssa and context creation.
fn test_assembly() -> &'static Arc<dotscope::CilObject> {
    use std::sync::LazyLock;
    static TEST_ASSEMBLY: LazyLock<Arc<dotscope::CilObject>> = LazyLock::new(|| {
        Arc::new(
            dotscope::CilObject::from_path(fixture("crafted_2.exe"))
                .expect("Failed to load test assembly"),
        )
    });
    &TEST_ASSEMBLY
}

/// Create a minimal test context for deobfuscation.
#[allow(dead_code)]
fn create_test_context() -> AnalysisContext {
    let call_graph = Arc::new(CallGraph::new());
    AnalysisContext::new(call_graph)
}

/// Complete deobfuscation test runner.
///
/// This function:
/// 1. Builds CIL from the assembler
/// 2. Converts to CFG → SSA
/// 3. Runs the full deobfuscation engine
/// 4. Generates CIL output
/// 5. Verifies the exact instruction sequence
///
/// Returns an error with detailed diagnostics if verification fails.
fn run_deobfuscation_test(
    assembler: InstructionAssembler,
    num_args: usize,
    num_locals: usize,
    expected: &[ExpectedInstruction],
) -> Result<()> {
    run_deobfuscation_test_with_config(
        assembler,
        num_args,
        num_locals,
        expected,
        EngineConfig::default(),
    )
}

/// Complete deobfuscation test runner with custom engine config.
fn run_deobfuscation_test_with_config(
    assembler: InstructionAssembler,
    num_args: usize,
    num_locals: usize,
    expected: &[ExpectedInstruction],
    config: EngineConfig,
) -> Result<()> {
    // Step 1: Build CIL
    let (original_bytecode, cfg) = build_cfg(assembler)?;

    // Step 2: Build SSA
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(num_args, num_locals))?;

    // Step 3: Run deobfuscation engine
    let _ctx = create_test_context();
    let engine = engine_with(config);
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;

    // Step 4: Generate output CIL
    let output_bytecode = generate_cil(&ssa)?;

    // Step 5: Decode and verify
    let output_instructions = decode_instructions(&output_bytecode)?;

    verify_instructions(&original_bytecode, &output_instructions, expected)
}

/// Verify that output instructions exactly match expected sequence.
fn verify_instructions(
    original_bytecode: &[u8],
    actual: &[Instruction],
    expected: &[ExpectedInstruction],
) -> Result<()> {
    // Check length first
    if actual.len() != expected.len() {
        let actual_mnemonics: Vec<_> = actual.iter().map(format_instruction).collect();
        let expected_mnemonics: Vec<_> = expected.iter().map(format_expected).collect();

        panic!(
            "\n\nInstruction count mismatch!\n\
             Original bytecode: {:02x?}\n\n\
             Expected {} instructions:\n  {}\n\n\
             Got {} instructions:\n  {}\n",
            original_bytecode,
            expected.len(),
            expected_mnemonics.join("\n  "),
            actual.len(),
            actual_mnemonics.join("\n  "),
        );
    }

    // Check each instruction
    for (i, (actual_instr, expected_instr)) in actual.iter().zip(expected.iter()).enumerate() {
        if !expected_instr.matches(actual_instr) {
            let actual_mnemonics: Vec<_> = actual.iter().map(format_instruction).collect();
            let expected_mnemonics: Vec<_> = expected.iter().map(format_expected).collect();

            panic!(
                "\n\nInstruction mismatch at index {}!\n\
                 Original bytecode: {:02x?}\n\n\
                 Expected:\n  {}\n\n\
                 Got:\n  {}\n\n\
                 Mismatch: expected '{}' but got '{}'\n",
                i,
                original_bytecode,
                expected_mnemonics.join("\n  "),
                actual_mnemonics.join("\n  "),
                format_expected(expected_instr),
                format_instruction(actual_instr),
            );
        }
    }

    Ok(())
}

/// Format an instruction for display.
fn format_instruction(instr: &Instruction) -> String {
    match &instr.operand {
        Operand::None => instr.mnemonic.to_string(),
        Operand::Immediate(imm) => format!("{} {}", instr.mnemonic, format_immediate(imm)),
        Operand::Target(offset) => format!("{} @{}", instr.mnemonic, offset),
        _ => format!("{} {:?}", instr.mnemonic, instr.operand),
    }
}

/// Format an immediate value for display.
fn format_immediate(imm: &Immediate) -> String {
    match imm {
        Immediate::Int8(v) => format!("{v}"),
        Immediate::Int32(v) => format!("{v}"),
        Immediate::Int64(v) => format!("{v}i64"),
        Immediate::Float32(v) => format!("{v}f32"),
        Immediate::Float64(v) => format!("{v}f64"),
        _ => format!("{imm:?}"),
    }
}

/// Format an expected instruction for display.
fn format_expected(expected: &ExpectedInstruction) -> String {
    let mnemonic: std::borrow::Cow<'static, str> = match &expected.pattern {
        MnemonicPattern::Exact(m) => (*m).into(),
        MnemonicPattern::AnyLdloc => "<any ldloc>".into(),
        MnemonicPattern::AnyStloc => "<any stloc>".into(),
        MnemonicPattern::AnyBranch(base) => format!("<{} or {}.s>", base, base).into(),
        MnemonicPattern::AnyConditionalBranch => "<brfalse or brtrue>".into(),
        MnemonicPattern::AnyLdcI4 => "<any ldc.i4>".into(),
    };

    match &expected.operand {
        None => mnemonic.to_string(),
        Some(ExpectedOperand::Any) => format!("{} <any>", mnemonic),
        Some(ExpectedOperand::I8(v)) => format!("{} {}", mnemonic, v),
        Some(ExpectedOperand::I32(v)) => format!("{} {}", mnemonic, v),
        Some(ExpectedOperand::I64(v)) => format!("{} {}i64", mnemonic, v),
        Some(ExpectedOperand::F32(v)) => format!("{} {}f32", mnemonic, v),
        Some(ExpectedOperand::F64(v)) => format!("{} {}f64", mnemonic, v),
        Some(ExpectedOperand::BranchTarget) => format!("{} <branch>", mnemonic),
    }
}

//
// These tests verify that basic IL patterns survive the SSA transformation
// and code generation without corruption.

/// Test: void method with just `ret`.
///
/// Input:  ret
/// Output: ret
#[test]
fn test_roundtrip_void_return() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ret")])
}

/// Test: return constant 42.
///
/// Input:  ldc.i4.s 42, ret
/// Output: ldc.i4.s 42, ret
#[test]
fn test_roundtrip_return_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: return argument 0.
///
/// Input:  ldarg.0, ret
/// Output: ldarg.0, ret
#[test]
fn test_roundtrip_return_argument() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: return arg0 + arg1.
///
/// Input:  ldarg.0, ldarg.1, add, ret
/// Output: ldarg.0, ldarg.1, add, ret
#[test]
fn test_roundtrip_binary_add() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 - arg1.
///
/// Input:  ldarg.0, ldarg.1, sub, ret
/// Output: ldarg.0, ldarg.1, sub, ret
#[test]
fn test_roundtrip_binary_sub() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.sub()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("sub"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 * arg1.
///
/// Input:  ldarg.0, ldarg.1, mul, ret
/// Output: ldarg.0, ldarg.1, mul, ret
#[test]
fn test_roundtrip_binary_mul() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("mul"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 / arg1.
///
/// Input:  ldarg.0, ldarg.1, div, ret
/// Output: ldarg.0, ldarg.1, div, ret
#[test]
fn test_roundtrip_binary_div() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.div()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("div"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 % arg1.
///
/// Input:  ldarg.0, ldarg.1, rem, ret
/// Output: ldarg.0, ldarg.1, rem, ret
#[test]
fn test_roundtrip_binary_rem() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.rem()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("rem"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 & arg1.
///
/// Input:  ldarg.0, ldarg.1, and, ret
/// Output: ldarg.0, ldarg.1, and, ret
#[test]
fn test_roundtrip_binary_and() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.and()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("and"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 | arg1.
///
/// Input:  ldarg.0, ldarg.1, or, ret
/// Output: ldarg.0, ldarg.1, or, ret
#[test]
fn test_roundtrip_binary_or() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.or()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("or"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 ^ arg1.
///
/// Input:  ldarg.0, ldarg.1, xor, ret
/// Output: ldarg.0, ldarg.1, xor, ret
#[test]
fn test_roundtrip_binary_xor() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.xor()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("xor"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 << arg1.
///
/// Input:  ldarg.0, ldarg.1, shl, ret
/// Output: ldarg.0, ldarg.1, shl, ret
#[test]
fn test_roundtrip_binary_shl() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.shl()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 >> arg1 (signed).
///
/// Input:  ldarg.0, ldarg.1, shr, ret
/// Output: ldarg.0, ldarg.1, shr, ret
#[test]
fn test_roundtrip_binary_shr() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.shr()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("shr"),
            instr!("ret"),
        ],
    )
}

/// Test: return -arg0.
///
/// Input:  ldarg.0, neg, ret
/// Output: ldarg.0, neg, ret
#[test]
fn test_roundtrip_unary_neg() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.neg()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[instr!("ldarg.0"), instr!("neg"), instr!("ret")],
    )
}

/// Test: return ~arg0.
///
/// Input:  ldarg.0, not, ret
/// Output: ldarg.0, not, ret
#[test]
fn test_roundtrip_unary_not() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.not()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[instr!("ldarg.0"), instr!("not"), instr!("ret")],
    )
}

/// Test: return arg0 == arg1.
///
/// Input:  ldarg.0, ldarg.1, ceq, ret
/// Output: ldarg.0, ldarg.1, ceq, ret
#[test]
fn test_roundtrip_comparison_ceq() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.ceq()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("ceq"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 < arg1.
///
/// Input:  ldarg.0, ldarg.1, clt, ret
/// Output: ldarg.0, ldarg.1, clt, ret
#[test]
fn test_roundtrip_comparison_clt() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.clt()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("clt"),
            instr!("ret"),
        ],
    )
}

/// Test: return arg0 > arg1.
///
/// Input:  ldarg.0, ldarg.1, cgt, ret
/// Output: ldarg.0, ldarg.1, cgt, ret
#[test]
fn test_roundtrip_comparison_cgt() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.cgt()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("cgt"),
            instr!("ret"),
        ],
    )
}

/// Test: return (byte)arg0.
///
/// Input:  ldarg.0, conv.u1, ret
/// Output: ldarg.0, conv.u1, ret
#[test]
fn test_roundtrip_conversion_u1() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.conv_u1()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[instr!("ldarg.0"), instr!("conv.u1"), instr!("ret")],
    )
}

/// Test: return (int)arg0.
///
/// Input:  ldarg.0, conv.i4, ret
/// Output: ldarg.0, ret  (conv.i4 eliminated: arg0 is already I32)
#[test]
fn test_roundtrip_conversion_i4() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.conv_i4()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: 64-bit constant roundtrip.
///
/// Input:  ldc.i8 0x123456789ABCDEF0, ret
/// Output: ldc.i8 0x123456789ABCDEF0, ret
#[test]
fn test_roundtrip_i64_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i8(0x123456789ABCDEF0_u64 as i64)?.ret()?;

    run_deobfuscation_test(
        asm,
        0,
        0,
        &[
            instr!("ldc.i8", i64: 0x123456789ABCDEF0_u64 as i64),
            instr!("ret"),
        ],
    )
}

/// Test: float constant roundtrip.
///
/// Input:  ldc.r8 PI, ret
/// Output: ldc.r8 PI, ret
#[test]
fn test_roundtrip_f64_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_r8(std::f64::consts::PI)?.ret()?;

    run_deobfuscation_test(
        asm,
        0,
        0,
        &[instr!("ldc.r8", f64: std::f64::consts::PI), instr!("ret")],
    )
}

/// Test: dup instruction for arg0 + arg0.
///
/// Input:  ldarg.0, dup, add, ret
/// Output: ldarg.0, ldarg.0, add, ret (dup expanded to two loads)
#[test]
fn test_roundtrip_dup_expands() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.dup()?.add()?.ret()?;

    // After SSA and codegen, dup optimization preserves efficient form when
    // loading the same location twice in a row
    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("dup"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: 5 + 3 = 8.
///
/// Input:  ldc.i4.5, ldc.i4.3, add, ret
/// Output: ldc.i4.8, ret
#[test]
fn test_constant_fold_add() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?.ldc_i4_3()?.add()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.8"), instr!("ret")])
}

/// Test: 10 - 3 = 7.
///
/// Input:  ldc.i4.s 10, ldc.i4.3, sub, ret
/// Output: ldc.i4.7, ret
#[test]
fn test_constant_fold_sub() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(10)?.ldc_i4_3()?.sub()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.7"), instr!("ret")])
}

/// Test: 6 * 7 = 42.
///
/// Input:  ldc.i4.6, ldc.i4.7, mul, ret
/// Output: ldc.i4.s 42, ret
#[test]
fn test_constant_fold_mul() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_6()?.ldc_i4_7()?.mul()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: 100 / 4 = 25.
///
/// Input:  ldc.i4.s 100, ldc.i4.4, div, ret
/// Output: ldc.i4.s 25, ret
#[test]
fn test_constant_fold_div() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(100)?.ldc_i4_4()?.div()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 25), instr!("ret")])
}

/// Test: 17 % 5 = 2.
///
/// Input:  ldc.i4.s 17, ldc.i4.5, rem, ret
/// Output: ldc.i4.2, ret
#[test]
fn test_constant_fold_rem() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(17)?.ldc_i4_5()?.rem()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.2"), instr!("ret")])
}

/// Test: 0xFF00 & 0x0FF0 = 0x0F00.
///
/// Input:  ldc.i4 0xFF00, ldc.i4 0x0FF0, and, ret
/// Output: ldc.i4 0x0F00, ret
#[test]
fn test_constant_fold_and() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0xFF00)?
        .ldc_i4_const(0x0FF0)?
        .and()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 0x0F00), instr!("ret")])
}

/// Test: 0xFF00 | 0x00FF = 0xFFFF.
///
/// Input:  ldc.i4 0xFF00, ldc.i4 0x00FF, or, ret
/// Output: ldc.i4 0xFFFF, ret
#[test]
fn test_constant_fold_or() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0xFF00)?
        .ldc_i4_const(0x00FF)?
        .or()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 0xFFFF), instr!("ret")])
}

/// Test: 0xFF ^ 0xAA = 0x55.
///
/// Input:  ldc.i4.s 0xFF, ldc.i4.s 0xAA, xor, ret
/// Output: ldc.i4.s 0x55, ret
#[test]
fn test_constant_fold_xor() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0xFF)?.ldc_i4_const(0xAA)?.xor()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 0x55), instr!("ret")])
}

/// Test: 1 << 4 = 16.
///
/// Input:  ldc.i4.1, ldc.i4.4, shl, ret
/// Output: ldc.i4.s 16, ret
#[test]
fn test_constant_fold_shl() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?.ldc_i4_4()?.shl()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 16), instr!("ret")])
}

/// Test: 64 >> 2 = 16.
///
/// Input:  ldc.i4.s 64, ldc.i4.2, shr, ret
/// Output: ldc.i4.s 16, ret
#[test]
fn test_constant_fold_shr() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(64)?.ldc_i4_2()?.shr()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 16), instr!("ret")])
}

/// Test: -42 = -42.
///
/// Input:  ldc.i4.s 42, neg, ret
/// Output: ldc.i4.s -42, ret
#[test]
fn test_constant_fold_neg() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?.neg()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: -42), instr!("ret")])
}

/// Test: ~0 = -1.
///
/// Input:  ldc.i4.0, not, ret
/// Output: ldc.i4.m1, ret
#[test]
fn test_constant_fold_not() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.not()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.m1"), instr!("ret")])
}

/// Test: 5 == 5 = true (1).
///
/// Input:  ldc.i4.5, ldc.i4.5, ceq, ret
/// Output: ldc.i4.1, ret
#[test]
fn test_constant_fold_ceq_true() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?.ldc_i4_5()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: 5 == 3 = false (0).
///
/// Input:  ldc.i4.5, ldc.i4.3, ceq, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_constant_fold_ceq_false() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?.ldc_i4_3()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: 3 < 5 = true (1).
///
/// Input:  ldc.i4.3, ldc.i4.5, clt, ret
/// Output: ldc.i4.1, ret
#[test]
fn test_constant_fold_clt_true() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_3()?.ldc_i4_5()?.clt()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: 5 < 3 = false (0).
///
/// Input:  ldc.i4.5, ldc.i4.3, clt, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_constant_fold_clt_false() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?.ldc_i4_3()?.clt()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: 5 > 3 = true (1).
///
/// Input:  ldc.i4.5, ldc.i4.3, cgt, ret
/// Output: ldc.i4.1, ret
#[test]
fn test_constant_fold_cgt_true() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?.ldc_i4_3()?.cgt()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: 3 > 5 = false (0).
///
/// Input:  ldc.i4.3, ldc.i4.5, cgt, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_constant_fold_cgt_false() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_3()?.ldc_i4_5()?.cgt()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: chained folding (10 - 5) * 2 = 10.
///
/// Input:  ldc.i4.s 10, ldc.i4.5, sub, ldc.i4.2, mul, ret
/// Output: ldc.i4.s 10, ret
#[test]
fn test_constant_fold_chained() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(10)?
        .ldc_i4_5()?
        .sub()?
        .ldc_i4_2()?
        .mul()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 10), instr!("ret")])
}

/// Test: deeply chained folding ((2 * 3) + 4) / 2 = 5.
///
/// Input:  ldc.i4.2, ldc.i4.3, mul, ldc.i4.4, add, ldc.i4.2, div, ret
/// Output: ldc.i4.5, ret
#[test]
fn test_constant_fold_deeply_chained() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_2()?
        .ldc_i4_3()?
        .mul()?
        .ldc_i4_4()?
        .add()?
        .ldc_i4_2()?
        .div()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.5"), instr!("ret")])
}

/// Test: x + 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, add, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_add_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.add()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x - 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, sub, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_sub_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.sub()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x * 1 = x.
///
/// Input:  ldarg.0, ldc.i4.1, mul, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_mul_one() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_1()?.mul()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x / 1 = x.
///
/// Input:  ldarg.0, ldc.i4.1, div, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_div_one() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_1()?.div()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x ^ 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, xor, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_xor_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.xor()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x | 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, or, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_or_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.or()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x & -1 = x (AND with all bits set).
///
/// Input:  ldarg.0, ldc.i4.m1, and, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_and_all_ones() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_m1()?.and()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x << 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, shl, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_shl_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.shl()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x >> 0 = x.
///
/// Input:  ldarg.0, ldc.i4.0, shr, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_shr_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.shr()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x * 0 = 0.
///
/// Input:  ldarg.0, ldc.i4.0, mul, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_absorb_mul_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.mul()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x & 0 = 0.
///
/// Input:  ldarg.0, ldc.i4.0, and, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_absorb_and_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.and()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x | -1 = -1 (OR with all bits set).
///
/// Input:  ldarg.0, ldc.i4.m1, or, ret
/// Output: ldc.i4.m1, ret
#[test]
fn test_absorb_or_all_ones() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_m1()?.or()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.m1"), instr!("ret")])
}

/// Test: x ^ x = 0 (always zero).
///
/// Input:  ldarg.0, ldarg.0, xor, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_opaque_xor_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.xor()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x - x = 0 (always zero).
///
/// Input:  ldarg.0, ldarg.0, sub, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_opaque_sub_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.sub()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x == x = true (always true).
///
/// Input:  ldarg.0, ldarg.0, ceq, ret
/// Output: ldc.i4.1, ret
#[test]
fn test_opaque_ceq_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: x < x = false (always false).
///
/// Input:  ldarg.0, ldarg.0, clt, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_opaque_clt_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.clt()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x > x = false (always false).
///
/// Input:  ldarg.0, ldarg.0, cgt, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_opaque_cgt_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.cgt()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: x & x = x (idempotent).
///
/// Input:  ldarg.0, ldarg.0, and, ret
/// Output: ldarg.0, ret
#[test]
fn test_opaque_and_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.and()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x | x = x (idempotent).
///
/// Input:  ldarg.0, ldarg.0, or, ret
/// Output: ldarg.0, ret
#[test]
fn test_opaque_or_self() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_0()?.or()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: simple conditional branch preserved.
///
/// Input:  ldarg.0, brfalse L, ldc.i4.1, ret, L: ldc.i4.0, ret
/// Output: Same structure (branches preserved)
#[test]
fn test_controlflow_conditional_preserved() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("false_branch")?
        .ldc_i4_1()?
        .ret()?
        .label("false_branch")?
        .ldc_i4_0()?
        .ret()?;

    // Build and run, verify structure is preserved
    let (original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let _ctx = create_test_context();
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should have at least one branch and two returns
    let branch_count = output
        .iter()
        .filter(|i| i.mnemonic.starts_with("br"))
        .count();
    let ret_count = output.iter().filter(|i| i.mnemonic == "ret").count();

    assert!(
        branch_count >= 1,
        "Should have branch, got: {:?}",
        output.iter().map(|i| i.mnemonic).collect::<Vec<_>>()
    );
    assert!(
        ret_count >= 2,
        "Should have 2 returns, got: {:?}",
        output.iter().map(|i| i.mnemonic).collect::<Vec<_>>()
    );

    // Verify original bytecode for diagnostic
    let _ = original_bytecode;

    Ok(())
}

/// Test: always-true branch eliminated.
///
/// When condition is constant true, dead branch is removed.
///
/// Input:  ldc.i4.1, brfalse L, ldc.i4.s 42, ret, L: ldc.i4.s 99, ret
/// Output: ldc.i4.s 42, ret (dead code eliminated)
#[test]
fn test_controlflow_always_true_simplified() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()? // Always true
        .brfalse_s("false_branch")?
        .ldc_i4_const(42)?
        .ret()?
        .label("false_branch")?
        .ldc_i4_const(99)?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: always-false branch eliminated.
///
/// When condition is constant false, dead branch is removed.
///
/// Input:  ldc.i4.0, brtrue L, ldc.i4.s 42, ret, L: ldc.i4.s 99, ret
/// Output: ldc.i4.s 42, ret (dead code eliminated)
#[test]
fn test_controlflow_always_false_simplified() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()? // Always false
        .brtrue_s("true_branch")?
        .ldc_i4_const(42)?
        .ret()?
        .label("true_branch")?
        .ldc_i4_const(99)?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: opaque predicate with dead branch eliminated.
///
/// Input:  ldarg.0, ldarg.0, xor, brtrue L, ldc.i4.s 42, ret, L: ldc.i4.s 99, ret
/// Output: ldc.i4.s 42, ret (x^x=0, so brtrue never taken)
#[test]
fn test_controlflow_opaque_predicate_eliminated() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldarg_0()?
        .xor()? // Always 0
        .brtrue_s("dead_branch")?
        .ldc_i4_const(42)?
        .ret()?
        .label("dead_branch")?
        .ldc_i4_const(99)?
        .ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: complex obfuscation with opaque predicates, dead code, and constant folding.
///
/// This exercises:
/// 1. Constant propagation: (10 * 5) - 45 = 5
/// 2. Opaque predicate: x ^ x = 0
/// 3. Dead code elimination: unreachable branches removed
/// 4. Copy propagation: redundant copies eliminated
///
/// Input: Complex obfuscated IL
/// Output: ldarg.0, ldarg.1, add, ret
#[test]
fn test_complex_full_deobfuscation() -> Result<()> {
    let mut asm = InstructionAssembler::new();

    // Opaque predicate: arg0 ^ arg0 = 0, so brtrue never jumps
    asm.ldarg_0()?.ldarg_0()?.xor()?.brtrue_s("dead_branch")?;

    // Identity operations that should be simplified
    asm.ldarg_1()?.ldc_i4_1()?.mul()?; // arg1 * 1 = arg1
    asm.ldc_i4_0()?.add()?; // + 0 = arg1

    // Add with arg0
    asm.ldarg_0()?.add()?.ret()?;

    // Dead branch (never taken)
    asm.label("dead_branch")?.ldc_i4_const(999)?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.1"),
            instr!("ldarg.0"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: heavily nested opaque predicates.
///
/// Input: Multiple layers of x^x=0 checks
/// Output: Simple return
#[test]
fn test_complex_nested_opaque_predicates() -> Result<()> {
    let mut asm = InstructionAssembler::new();

    // First opaque: arg0 ^ arg0 = 0
    asm.ldarg_0()?.ldarg_0()?.xor()?.brtrue_s("dead1")?;

    // Second opaque: arg1 ^ arg1 = 0
    asm.ldarg_1()?.ldarg_1()?.xor()?.brtrue_s("dead2")?;

    // Third opaque: constant 5 == 5
    asm.ldc_i4_5()?.ldc_i4_5()?.ceq()?.brfalse_s("dead3")?;

    // Live path
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    // Dead branches
    asm.label("dead1")?.ldc_i4_const(111)?.ret()?;
    asm.label("dead2")?.ldc_i4_const(222)?.ret()?;
    asm.label("dead3")?.ldc_i4_const(333)?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: constant computation chain with intermediate stores.
///
/// Input:
///   loc0 = 10 * 5       // = 50
///   loc1 = loc0 - 45    // = 5
///   loc2 = loc1 * 2     // = 10
///   return loc2
///
/// Output: ldc.i4.s 10, ret
#[test]
fn test_complex_constant_chain_with_locals() -> Result<()> {
    let mut asm = InstructionAssembler::new();

    // loc0 = 10 * 5 = 50
    asm.ldc_i4_const(10)?.ldc_i4_5()?.mul()?.stloc_0()?;

    // loc1 = loc0 - 45 = 5
    asm.ldloc_0()?.ldc_i4_const(45)?.sub()?.stloc_1()?;

    // loc2 = loc1 * 2 = 10
    asm.ldloc_1()?.ldc_i4_2()?.mul()?.stloc_2()?;

    // return loc2
    asm.ldloc_2()?.ret()?;

    run_deobfuscation_test(asm, 0, 3, &[instr!("ldc.i4.s", i8: 10), instr!("ret")])
}

/// Test: mixed arguments and constants with identity operations.
///
/// Input:
///   result = ((arg0 * 1) + 0) + ((arg1 - 0) * 1)
///
/// Output: ldarg.0, ldarg.1, add, ret
#[test]
fn test_complex_identity_chain() -> Result<()> {
    let mut asm = InstructionAssembler::new();

    // (arg0 * 1) + 0
    asm.ldarg_0()?.ldc_i4_1()?.mul()?.ldc_i4_0()?.add()?;

    // (arg1 - 0) * 1
    asm.ldarg_1()?.ldc_i4_0()?.sub()?.ldc_i4_1()?.mul()?;

    // Add together
    asm.add()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: division by 1 is identity.
///
/// Input:  ldarg.0, ldc.i4.1, div, ret
/// Output: ldarg.0, ret
#[test]
fn test_edge_div_by_one() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_1()?.div()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: 0 divided by an unknown value is kept.
///
/// The quotient is 0 only when the divisor is not: with `arg == 0` the
/// division raises `DivideByZeroException`, and folding it to 0 would delete
/// the exception.
///
/// Input:  ldc.i4.0, ldarg.0, div, ret
/// Output: ldc.i4.0, ldarg.0, div, ret
#[test]
fn test_edge_zero_divided() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.div()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldc.i4.0"),
            instr!("ldarg.0"),
            instr!("div"),
            instr!("ret"),
        ],
    )
}

/// Test: 0 modulo an unknown value is kept, for the reason
/// `test_edge_zero_divided` gives.
///
/// Input:  ldc.i4.0, ldarg.0, rem, ret
/// Output: ldc.i4.0, ldarg.0, rem, ret
#[test]
fn test_edge_zero_modulo() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.rem()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldc.i4.0"),
            instr!("ldarg.0"),
            instr!("rem"),
            instr!("ret"),
        ],
    )
}

/// Test: double negation is identity.
///
/// Input:  ldarg.0, neg, neg, ret
/// Output: ldarg.0, ret
#[test]
fn test_edge_double_negation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.neg()?.neg()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: double bitwise not is identity.
///
/// Input:  ldarg.0, not, not, ret
/// Output: ldarg.0, ret
#[test]
fn test_edge_double_not() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.not()?.not()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: large constant preserved correctly.
///
/// Input:  ldc.i4 0x7FFFFFFF, ret
/// Output: ldc.i4 0x7FFFFFFF, ret
#[test]
fn test_edge_max_i32() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(i32::MAX)?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: i32::MAX), instr!("ret")])
}

/// Test: negative constant preserved correctly.
///
/// Input:  ldc.i4 -2147483648, ret
/// Output: ldc.i4 -2147483648, ret
#[test]
fn test_edge_min_i32() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(i32::MIN)?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: i32::MIN), instr!("ret")])
}

/// Test: float32 constant roundtrip.
///
/// Input:  ldc.r4 PI, ret
/// Output: ldc.r4 PI, ret
#[test]
fn test_roundtrip_f32_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_r4(std::f32::consts::PI)?.ret()?;

    run_deobfuscation_test(
        asm,
        0,
        0,
        &[instr!("ldc.r4", f32: std::f32::consts::PI), instr!("ret")],
    )
}

/// Test: branch with dynamic condition preserved (uses BranchTarget).
///
/// Input:  ldarg.0, brtrue target, ldc.i4.0, ret, target: ldc.i4.1, ret
/// Output: Same structure with branch preserved
#[test]
fn test_branch_dynamic_condition() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brtrue_s("target")?
        .ldc_i4_0()?
        .ret()?
        .label("target")?
        .ldc_i4_1()?
        .ret()?;

    // Build and run
    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should have a branch instruction (brtrue or brfalse variant)
    let has_branch = output.iter().any(|i| i.mnemonic.starts_with("br"));
    assert!(
        has_branch,
        "Expected branch instruction, got: {:?}",
        output.iter().map(|i| i.mnemonic).collect::<Vec<_>>()
    );

    // Verify using with_branch helper - the branch target can be any value
    assert!(
        output
            .iter()
            .any(|i| { ExpectedInstruction::with_branch(i.mnemonic).matches(i) }),
        "Should have valid branch with target"
    );

    Ok(())
}

/// Test: ldarg with variable index uses Any operand matching.
///
/// Input:  ldarg.s 5, ret
/// Output: ldarg.s 5, ret (index preserved)
#[test]
fn test_ldarg_with_index() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_s(5)?.ret()?;

    // Use with_any_operand to match any operand value for ldarg.s
    run_deobfuscation_test(
        asm,
        6, // Need at least 6 args for ldarg.s 5
        0,
        &[instr!("ldarg.s", any), instr!("ret")],
    )
}

/// Test: commutative identity - 0 + x = x.
///
/// Input:  ldc.i4.0, ldarg.0, add, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_zero_plus_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.add()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: commutative identity - 1 * x = x.
///
/// Input:  ldc.i4.1, ldarg.0, mul, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_one_times_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?.ldarg_0()?.mul()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: commutative identity - 0 ^ x = x.
///
/// Input:  ldc.i4.0, ldarg.0, xor, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_zero_xor_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.xor()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: commutative identity - 0 | x = x.
///
/// Input:  ldc.i4.0, ldarg.0, or, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_zero_or_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.or()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: commutative absorbing - 0 * x = 0.
///
/// Input:  ldc.i4.0, ldarg.0, mul, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_absorb_zero_times_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.mul()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: commutative absorbing - 0 & x = 0.
///
/// Input:  ldc.i4.0, ldarg.0, and, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_absorb_zero_and_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?.ldarg_0()?.and()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: commutative absorbing - -1 | x = -1.
///
/// Input:  ldc.i4.m1, ldarg.0, or, ret
/// Output: ldc.i4.m1, ret
#[test]
fn test_absorb_minus_one_or_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_m1()?.ldarg_0()?.or()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.m1"), instr!("ret")])
}

/// Test: commutative identity - -1 & x = x.
///
/// Input:  ldc.i4.m1, ldarg.0, and, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_minus_one_and_x() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_m1()?.ldarg_0()?.and()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: x * 2 could be optimized to x << 1 (strength reduction).
///
/// Input:  ldarg.0, ldc.i4.2, mul, ret
/// Output: ldarg.0, ldc.i4.2, mul, ret (or ldarg.0, ldc.i4.1, shl, ret if optimized)
#[test]
fn test_strength_mul_by_two() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_2()?.mul()?.ret()?;

    // Currently just verifies roundtrip - could be optimized to shl
    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should produce valid output (either mul or shl based)
    assert!(output.len() >= 3, "Expected at least 3 instructions");
    assert_eq!(output.last().unwrap().mnemonic, "ret");
    Ok(())
}

/// Test: x * 4 could be optimized to x << 2 (strength reduction).
///
/// Input:  ldarg.0, ldc.i4.4, mul, ret
/// Output: ldarg.0, ldc.i4.4, mul, ret (or ldarg.0, ldc.i4.2, shl, ret if optimized)
#[test]
fn test_strength_mul_by_four() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_4()?.mul()?.ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    assert!(output.len() >= 3, "Expected at least 3 instructions");
    assert_eq!(output.last().unwrap().mnemonic, "ret");
    Ok(())
}

/// Test: x / x = 1 (when x is known non-zero).
///
/// Note: This optimization requires proving x != 0, which may not always be possible.
/// Currently verifies the operation roundtrips correctly.
///
/// Input:  ldc.i4.5, dup, div, ret
/// Output: ldc.i4.1, ret (if optimized with known non-zero)
#[test]
fn test_self_div_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Use constant 5 which is definitely non-zero
    asm.ldc_i4_5()?.dup()?.div()?.ret()?;

    // 5 / 5 = 1
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: x % x = 0 (when x is known non-zero).
///
/// Input:  ldc.i4.7, dup, rem, ret
/// Output: ldc.i4.0, ret
#[test]
fn test_self_rem_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Use constant 7 which is definitely non-zero
    asm.ldc_i4_7()?.dup()?.rem()?.ret()?;

    // 7 % 7 = 0
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: redundant conversion with constant is simplified.
///
/// Input:  ldc.i8 42, conv.i4, conv.i4, ret
/// Output: ldc.i4.s 42, ret (duplicate conv eliminated, constant folded)
#[test]
fn test_redundant_conv_i4() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i8(42)?.conv_i4()?.conv_i4()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: widening conversion chain with constant.
///
/// Input:  ldc.i4.s 42, conv.i4, conv.i8, ret
/// Output: ldc.i8 42, ret (constants folded through widening chain)
#[test]
fn test_widening_conv_chain() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?.conv_i4()?.conv_i8()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i8", i64: 42), instr!("ret")])
}

/// Test: add.ovf with safe constants folds correctly.
///
/// Input:  ldc.i4.s 10, ldc.i4.s 20, add.ovf, ret
/// Output: ldc.i4.s 30, ret
#[test]
fn test_add_ovf_safe() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(10)?.ldc_i4_const(20)?.add_ovf()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 30), instr!("ret")])
}

/// Test: mul.ovf with safe constants folds correctly.
///
/// Input:  ldc.i4.3, ldc.i4.4, mul.ovf, ret
/// Output: ldc.i4.s 12, ret
#[test]
fn test_mul_ovf_safe() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_3()?.ldc_i4_4()?.mul_ovf()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 12), instr!("ret")])
}

/// Test: sub.ovf with safe constants folds correctly.
///
/// Input:  ldc.i4.s 50, ldc.i4.s 30, sub.ovf, ret
/// Output: ldc.i4.s 20, ret
#[test]
fn test_sub_ovf_safe() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(50)?.ldc_i4_const(30)?.sub_ovf()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 20), instr!("ret")])
}

/// Test: unsigned shift right roundtrip.
///
/// Input:  ldarg.0, ldarg.1, shr.un, ret
/// Output: ldarg.0, ldarg.1, shr.un, ret
#[test]
fn test_roundtrip_shr_un() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.shr_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("shr.un"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned division roundtrip.
///
/// Input:  ldarg.0, ldarg.1, div.un, ret
/// Output: ldarg.0, ldarg.1, div.un, ret
#[test]
fn test_roundtrip_div_un() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.div_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("div.un"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned remainder roundtrip.
///
/// Input:  ldarg.0, ldarg.1, rem.un, ret
/// Output: ldarg.0, ldarg.1, rem.un, ret
#[test]
fn test_roundtrip_rem_un() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.rem_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("rem.un"),
            instr!("ret"),
        ],
    )
}

/// Test: clt.un comparison roundtrip.
///
/// Input:  ldarg.0, ldarg.1, clt.un, ret
/// Output: ldarg.0, ldarg.1, clt.un, ret
#[test]
fn test_roundtrip_clt_un() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.clt_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("clt.un"),
            instr!("ret"),
        ],
    )
}

/// Test: cgt.un comparison roundtrip.
///
/// Input:  ldarg.0, ldarg.1, cgt.un, ret
/// Output: ldarg.0, ldarg.1, cgt.un, ret
#[test]
fn test_roundtrip_cgt_un() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.cgt_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("cgt.un"),
            instr!("ret"),
        ],
    )
}

/// Test: x >>> 0 = x (unsigned shift by zero is identity).
///
/// Input:  ldarg.0, ldc.i4.0, shr.un, ret
/// Output: ldarg.0, ret
#[test]
fn test_identity_shr_un_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_0()?.shr_un()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: (x + y) - y = x (algebraic cancellation).
///
/// This would require tracking that the sub operand came from an add.
/// Currently verifies roundtrip.
///
/// Input:  ldarg.0, ldarg.1, add, ldarg.1, sub, ret
/// Output: ldarg.0, ldarg.1, add, ldarg.1, sub, ret (or ldarg.0, ret if optimized)
#[test]
fn test_algebraic_add_sub_cancel() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ldarg_1()?.sub()?.ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should produce valid output
    assert_eq!(output.last().unwrap().mnemonic, "ret");
    Ok(())
}

/// Test: (x ^ y) ^ y = x (XOR cancellation).
///
/// Input:  ldarg.0, ldarg.1, xor, ldarg.1, xor, ret
/// Output: ldarg.0, ret (if optimized)
#[test]
fn test_algebraic_xor_cancel() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.xor()?.ldarg_1()?.xor()?.ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should produce valid output
    assert_eq!(output.last().unwrap().mnemonic, "ret");
    Ok(())
}

/// Test: triple negation ---x = -x.
///
/// Input:  ldarg.0, neg, neg, neg, ret
/// Output: ldarg.0, neg, ret
#[test]
fn test_triple_negation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.neg()?.neg()?.neg()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[instr!("ldarg.0"), instr!("neg"), instr!("ret")],
    )
}

/// Test: quadruple negation ----x = x.
///
/// Input:  ldarg.0, neg, neg, neg, neg, ret
/// Output: ldarg.0, ret
#[test]
fn test_quadruple_negation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.neg()?.neg()?.neg()?.neg()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: triple not ~~~x = ~x.
///
/// Input:  ldarg.0, not, not, not, ret
/// Output: ldarg.0, not, ret
#[test]
fn test_triple_not() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.not()?.not()?.not()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[instr!("ldarg.0"), instr!("not"), instr!("ret")],
    )
}

/// Test: quadruple not ~~~~x = x.
///
/// Input:  ldarg.0, not, not, not, not, ret
/// Output: ldarg.0, ret
#[test]
fn test_quadruple_not() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.not()?.not()?.not()?.not()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: switch with constant value jumps to correct target.
///
/// Input:  ldc.i4.1, switch [L0, L1, L2], ldc.i4.m1, ret, L0: ldc.i4.0, ret, L1: ldc.i4.1, ret, L2: ldc.i4.2, ret
/// Output: ldc.i4.1, ret (switch eliminated, jumps to case 1)
#[test]
fn test_switch_constant_value() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()? // Value 1 - should jump to L1
        .switch(&["L0", "L1", "L2"])?
        .ldc_i4_m1()? // Default case (fallthrough)
        .ret()?
        .label("L0")?
        .ldc_i4_0()?
        .ret()?
        .label("L1")?
        .ldc_i4_1()?
        .ret()?
        .label("L2")?
        .ldc_i4_2()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: switch with out-of-range constant falls through to default.
///
/// Input:  ldc.i4.s 99, switch [L0, L1], ldc.i4.m1, ret, L0: ldc.i4.0, ret, L1: ldc.i4.1, ret
/// Output: ldc.i4.m1, ret (switch eliminated, falls through)
#[test]
fn test_switch_out_of_range() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(99)? // Out of range - should fall through
        .switch(&["L0", "L1"])?
        .ldc_i4_m1()? // Default case
        .ret()?
        .label("L0")?
        .ldc_i4_0()?
        .ret()?
        .label("L1")?
        .ldc_i4_1()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.m1"), instr!("ret")])
}

/// Test: switch with dynamic value preserved.
///
/// Input:  ldarg.0, switch [L0, L1], ldc.i4.m1, ret, L0: ldc.i4.0, ret, L1: ldc.i4.1, ret
/// Output: Structure preserved (switch not eliminated)
#[test]
fn test_switch_dynamic_preserved() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()? // Dynamic value
        .switch(&["L0", "L1"])?
        .ldc_i4_m1()?
        .ret()?
        .label("L0")?
        .ldc_i4_0()?
        .ret()?
        .label("L1")?
        .ldc_i4_1()?
        .ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should have switch instruction preserved
    let has_switch = output.iter().any(|i| i.mnemonic == "switch");
    assert!(
        has_switch,
        "Expected switch instruction preserved, got: {:?}",
        output.iter().map(|i| i.mnemonic).collect::<Vec<_>>()
    );
    Ok(())
}

/// Test: x * 2 → x << 1 (strength reduction).
///
/// Input:  ldarg.0, ldc.i4.2, mul, ret
/// Output: ldarg.0, ldc.i4.1, shl, ret
#[test]
fn test_strength_reduction_mul_by_2() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_2()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.1"), // shift amount: 1 (since 2 = 2^1)
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: x * 8 → x << 3 (strength reduction).
///
/// Input:  ldarg.0, ldc.i4.8, mul, ret
/// Output: ldarg.0, ldc.i4.3, shl, ret
#[test]
fn test_strength_reduction_mul_by_8() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_8()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.3"), // shift amount: 3 (since 8 = 2^3)
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: x * 16 → x << 4 (strength reduction).
///
/// Input:  ldarg.0, ldc.i4.s 16, mul, ret
/// Output: ldarg.0, ldc.i4.4, shl, ret
#[test]
fn test_strength_reduction_mul_by_16() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_s(16)?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.4"), // shift amount: 4 (since 16 = 2^4)
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: x * 1024 → x << 10 (strength reduction with larger power of 2).
///
/// Input:  ldarg.0, ldc.i4 1024, mul, ret
/// Output: ldarg.0, ldc.i4.s 10, shl, ret
#[test]
fn test_strength_reduction_mul_by_1024() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4(1024)?.mul()?.ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;
    let mut ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0))?;
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;
    let output_bytecode = generate_cil(&ssa)?;
    let output = decode_instructions(&output_bytecode)?;

    // Should have shl instruction
    let has_shl = output.iter().any(|i| i.mnemonic == "shl");
    assert!(
        has_shl,
        "Expected shl instruction, got: {:?}",
        output.iter().map(|i| i.mnemonic).collect::<Vec<_>>()
    );

    // Should have shift amount 10 somewhere
    let has_10 = output.iter().any(|i| {
        matches!(
            i.operand,
            Operand::Immediate(Immediate::Int8(10)) | Operand::Immediate(Immediate::Int32(10))
        )
    });
    assert!(
        has_10,
        "Expected shift amount 10, got: {:?}",
        output
            .iter()
            .map(|i| format!("{} {:?}", i.mnemonic, i.operand))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Test: x * 3 is NOT reduced (3 is not a power of 2).
///
/// Input:  ldarg.0, ldc.i4.3, mul, ret
/// Output: ldarg.0, ldc.i4.3, mul, ret (unchanged)
#[test]
fn test_strength_reduction_mul_by_3_unchanged() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_3()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.3"),
            instr!("mul"),
            instr!("ret"),
        ],
    )
}

/// Test: 4 * x → x << 2 (constant on left side).
///
/// Input:  ldc.i4.4, ldarg.0, mul, ret
/// Output: ldarg.0, ldc.i4.2, shl, ret
#[test]
fn test_strength_reduction_mul_constant_left() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_4()?.ldarg_0()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.2"), // shift amount: 2 (since 4 = 2^2)
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned x / 4 → x >> 2 (strength reduction for unsigned division).
///
/// Input:  ldarg.0, ldc.i4.4, div.un, ret
/// Output: ldarg.0, ldc.i4.2, shr.un, ret
#[test]
fn test_strength_reduction_div_un_by_4() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_4()?.div_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.2"), // shift amount: 2 (since 4 = 2^2)
            instr!("shr.un"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned x / 8 → x >> 3 (strength reduction for unsigned division).
///
/// Input:  ldarg.0, ldc.i4.8, div.un, ret
/// Output: ldarg.0, ldc.i4.3, shr.un, ret
#[test]
fn test_strength_reduction_div_un_by_8() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_8()?.div_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.3"), // shift amount: 3 (since 8 = 2^3)
            instr!("shr.un"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned x % 16 → x & 15 (strength reduction for unsigned remainder).
///
/// Input:  ldarg.0, ldc.i4.s 16, rem.un, ret
/// Output: ldarg.0, ldc.i4.s 15, and, ret
#[test]
fn test_strength_reduction_rem_un_by_16() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_s(16)?.rem_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.s", i8: 15), // mask: 15 (since 16 - 1 = 15)
            instr!("and"),
            instr!("ret"),
        ],
    )
}

/// Test: unsigned x % 8 → x & 7 (strength reduction for unsigned remainder).
///
/// Input:  ldarg.0, ldc.i4.8, rem.un, ret
/// Output: ldarg.0, ldc.i4.7, and, ret
#[test]
fn test_strength_reduction_rem_un_by_8() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_8()?.rem_un()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.7"), // mask: 7 (since 8 - 1 = 7)
            instr!("and"),
            instr!("ret"),
        ],
    )
}

/// Test: signed x / 4 is NOT reduced (could be negative).
///
/// Input:  ldarg.0, ldc.i4.4, div, ret
/// Output: ldarg.0, ldc.i4.4, div, ret (unchanged - arg could be negative)
#[test]
fn test_strength_reduction_signed_div_unchanged() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_4()?.div()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.4"),
            instr!("div"),
            instr!("ret"),
        ],
    )
}

/// Test: signed x % 8 is NOT reduced (could be negative).
///
/// Input:  ldarg.0, ldc.i4.8, rem, ret
/// Output: ldarg.0, ldc.i4.8, rem, ret (unchanged - arg could be negative)
#[test]
fn test_strength_reduction_signed_rem_unchanged() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_8()?.rem()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.8"),
            instr!("rem"),
            instr!("ret"),
        ],
    )
}

/// Test: x * 1 is NOT strength reduced (handled by identity elimination instead).
///
/// Input:  ldarg.0, ldc.i4.1, mul, ret
/// Output: ldarg.0, ret (identity elimination removes * 1)
#[test]
fn test_strength_reduction_mul_by_1_identity() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldc_i4_1()?.mul()?.ret()?;

    // This should be handled by identity elimination, not strength reduction
    // x * 1 = x
    run_deobfuscation_test(asm, 1, 0, &[instr!("ldarg.0"), instr!("ret")])
}

/// Test: Simple copy propagation with dup (which creates a Copy in SSA).
///
/// Input:  ldarg.0, dup, add, ret
/// Output: ldarg.0, dup, add, ret (dup optimization preserves efficient form)
///
/// The `dup` instruction creates a Copy in SSA form. Copy propagation
/// replaces uses of the copied value with the original. When code
/// generation loads the same location twice in a row, dup optimization
/// emits `dup` instead of a redundant load.
#[test]
fn test_copy_propagation_simple_dup() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // ldarg.0, dup, add produces: x + x where the second x is a copy
    asm.ldarg_0()?.dup()?.add()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("dup"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: Copy propagation through local variable store/load.
///
/// Input:  ldarg.0, stloc.0, ldloc.0, ret
/// Output: ldarg.0, ret (copy through local propagated)
///
/// When we store to a local and immediately load it, this creates
/// an unnecessary copy that copy propagation can eliminate.
#[test]
fn test_copy_propagation_through_local() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Store arg to local, then load and return
    asm.ldarg_0()?.stloc_0()?.ldloc_0()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        1, // 1 local
        &[instr!("ldarg.0"), instr!("ret")],
    )
}

/// Test: Copy propagation with chained copies.
///
/// Input:  ldarg.0, stloc.0, ldloc.0, stloc.1, ldloc.1, ret
/// Output: ldarg.0, ret (all copies propagated back to original)
///
/// This tests that copy chains (a → b → c) are properly resolved
/// to the ultimate source (a).
#[test]
fn test_copy_propagation_chain() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // arg -> local0 -> local1 -> return
    asm.ldarg_0()?
        .stloc_0()?
        .ldloc_0()?
        .stloc_1()?
        .ldloc_1()?
        .ret()?;

    run_deobfuscation_test(
        asm,
        1,
        2, // 2 locals
        &[instr!("ldarg.0"), instr!("ret")],
    )
}

/// Test: Copy propagation preserves computation correctness.
///
/// Input:  ldarg.0, dup, mul, ret
/// Output: ldarg.0, ldarg.0, mul, ret (x * x preserved)
///
/// Ensures that when dup is used in a computation, the semantics
/// are preserved (we still compute x * x, not just x).
#[test]
fn test_copy_propagation_preserves_computation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // x * x using dup
    asm.ldarg_0()?.dup()?.mul()?.ret()?;

    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("dup"),
            instr!("mul"),
            instr!("ret"),
        ],
    )
}

/// Test: Copy propagation with multiple uses.
///
/// Input:  ldarg.0, stloc.0, ldloc.0, ldloc.0, add, ret
/// Output: ldarg.0, ldarg.0, add, ret (both uses propagated)
///
/// When a copied value is used multiple times, all uses should
/// be replaced with the original source.
#[test]
fn test_copy_propagation_multiple_uses() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Store to local, then use it twice in an add
    asm.ldarg_0()?
        .stloc_0()?
        .ldloc_0()?
        .ldloc_0()?
        .add()?
        .ret()?;

    run_deobfuscation_test(
        asm,
        1,
        1,
        &[
            instr!("ldarg.0"),
            instr!("dup"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: Copy propagation with intermediate computation.
///
/// Input:  ldarg.0, ldc.i4.2, mul, stloc.0, ldloc.0, ret
/// Output: ldarg.0, ldc.i4.1, shl, ret (computation preserved, copy removed)
///
/// When we store a computation result and immediately use it,
/// the copy can be eliminated. This also tests interaction with
/// strength reduction (mul by 2 → shl).
#[test]
fn test_copy_propagation_with_computation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg * 2) stored to local, then returned
    asm.ldarg_0()?
        .ldc_i4_2()?
        .mul()?
        .stloc_0()?
        .ldloc_0()?
        .ret()?;

    run_deobfuscation_test(
        asm,
        1,
        1,
        &[
            instr!("ldarg.0"),
            instr!("ldc.i4.1"), // shift amount
            instr!("shl"),
            instr!("ret"),
        ],
    )
}

/// Test: Copy propagation doesn't affect non-copy operations.
///
/// Input:  ldarg.0, ldarg.1, add, ret
/// Output: ldarg.0, ldarg.1, add, ret (unchanged)
///
/// When there are no copies, the code should remain unchanged.
#[test]
fn test_copy_propagation_no_copies() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: Copy propagation with constant and copy.
///
/// Input:  ldc.i4.5, stloc.0, ldloc.0, ret
/// Output: ldc.i4.5, ret (constant propagated through copy)
///
/// Copy propagation should work with constants as the source.
#[test]
fn test_copy_propagation_constant_source() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Store constant to local, then return local
    asm.ldc_i4_5()?.stloc_0()?.ldloc_0()?.ret()?;

    run_deobfuscation_test(asm, 0, 1, &[instr!("ldc.i4.5"), instr!("ret")])
}

/// Test: Copy propagation with multiple arguments.
///
/// Input:  ldarg.0, stloc.0, ldarg.1, stloc.1, ldloc.0, ldloc.1, add, ret
/// Output: ldarg.0, ldarg.1, add, ret (both copies eliminated)
///
/// Tests that multiple independent copies are all propagated correctly.
#[test]
fn test_copy_propagation_multiple_sources() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // Copy both args to locals, then add and return
    asm.ldarg_0()?
        .stloc_0()?
        .ldarg_1()?
        .stloc_1()?
        .ldloc_0()?
        .ldloc_1()?
        .add()?
        .ret()?;

    run_deobfuscation_test(
        asm,
        2,
        2,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: (x - y) == 0 simplified to x == y.
///
/// Input:  ldarg.0, ldarg.1, sub, ldc.i4.0, ceq, ret
/// Output: ldarg.0, ldarg.1, ceq, ret
///
/// The subtraction-based equality check is simplified to a direct comparison.
#[test]
fn test_comparison_sub_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 - arg1) == 0
    asm.ldarg_0()?.ldarg_1()?.sub()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("ceq"),
            instr!("ret"),
        ],
    )
}

/// Test: (x - y) < 0 stays a test of the difference.
///
/// Input:  ldarg.0, ldarg.1, sub, ldc.i4.0, clt, ret
/// Output: ldarg.0, ldarg.1, sub, ldc.i4.0, clt, ret
///
/// The subtraction wraps, so the sign of the difference is not the order of
/// the operands: with `x = i32::MIN + 5` and `y = 10` the difference is
/// positive while `x < y`. Reading `x < y` into it would change the result.
#[test]
fn test_comparison_sub_less_than_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 - arg1) < 0
    asm.ldarg_0()?.ldarg_1()?.sub()?.ldc_i4_0()?.clt()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("sub"),
            instr!("ldc.i4.0"),
            instr!("clt"),
            instr!("ret"),
        ],
    )
}

/// Test: (x - y) > 0 stays a test of the difference.
///
/// Input:  ldarg.0, ldarg.1, sub, ldc.i4.0, cgt, ret
/// Output: ldarg.0, ldarg.1, sub, ldc.i4.0, cgt, ret
///
/// The subtraction wraps, so the sign of the difference is not the order of
/// the operands: with `x = i32::MAX - 5` and `y = -10` the difference is
/// negative while `x > y`. Reading `x > y` into it would change the result.
#[test]
fn test_comparison_sub_greater_than_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 - arg1) > 0
    asm.ldarg_0()?.ldarg_1()?.sub()?.ldc_i4_0()?.cgt()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("sub"),
            instr!("ldc.i4.0"),
            instr!("cgt"),
            instr!("ret"),
        ],
    )
}

/// Test: (x ^ y) == 0 simplified to x == y.
///
/// Input:  ldarg.0, ldarg.1, xor, ldc.i4.0, ceq, ret
/// Output: ldarg.0, ldarg.1, ceq, ret
///
/// XOR-based equality check (values are equal iff their XOR is zero).
#[test]
fn test_comparison_xor_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 ^ arg1) == 0
    asm.ldarg_0()?.ldarg_1()?.xor()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("ceq"),
            instr!("ret"),
        ],
    )
}

/// Test: (x - x) == 0 is always true.
///
/// Input:  ldarg.0, ldarg.0, sub, ldc.i4.0, ceq, ret
/// Output: ldc.i4.1, ret
///
/// Self-subtraction is always zero, so comparing to zero is always true.
#[test]
fn test_comparison_self_sub_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 - arg0) == 0 → always true
    asm.ldarg_0()?.ldarg_0()?.sub()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: (x ^ x) == 0 is always true.
///
/// Input:  ldarg.0, ldarg.0, xor, ldc.i4.0, ceq, ret
/// Output: ldc.i4.1, ret
///
/// Self-XOR is always zero, so comparing to zero is always true.
#[test]
fn test_comparison_self_xor_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 ^ arg0) == 0 → always true
    asm.ldarg_0()?.ldarg_0()?.xor()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: Comparison simplification doesn't affect unrelated code.
///
/// Input:  ldarg.0, ldarg.1, add, ret
/// Output: ldarg.0, ldarg.1, add, ret (unchanged)
///
/// When there are no comparison patterns, the code should remain unchanged.
#[test]
fn test_comparison_no_patterns() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;

    run_deobfuscation_test(
        asm,
        2,
        0,
        &[
            instr!("ldarg.0"),
            instr!("ldarg.1"),
            instr!("add"),
            instr!("ret"),
        ],
    )
}

/// Test: (x > x) == 0 is always true (x <= x).
///
/// Input:  ldarg.0, ldarg.0, cgt, ldc.i4.0, ceq, ret
/// Output: ldc.i4.1, ret
///
/// x > x is always false, so (x > x) == 0 is always true.
#[test]
fn test_comparison_self_cgt_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 > arg0) == 0 → true (x <= x)
    asm.ldarg_0()?.ldarg_0()?.cgt()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: (x < x) == 0 is always true (x >= x).
///
/// Input:  ldarg.0, ldarg.0, clt, ldc.i4.0, ceq, ret
/// Output: ldc.i4.1, ret
///
/// x < x is always false, so (x < x) == 0 is always true.
#[test]
fn test_comparison_self_clt_equals_zero() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // (arg0 < arg0) == 0 → true (x >= x)
    asm.ldarg_0()?.ldarg_0()?.clt()?.ldc_i4_0()?.ceq()?.ret()?;

    run_deobfuscation_test(asm, 1, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: triple redundant conv.i4 chain is simplified.
///
/// Input:  ldc.i8 42, conv.i4, conv.i4, conv.i4, ret
/// Output: ldc.i4.s 42, ret (all conversions folded with constant)
#[test]
fn test_conv_triple_i4_with_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i8(42)?.conv_i4()?.conv_i4()?.conv_i4()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: unsigned widening chain with constant is fully folded.
///
/// Input:  ldc.i4.s 42, conv.u1, conv.u2, conv.u4, ret
/// Output: ldc.i4 42, ret (all conversions folded)
#[test]
fn test_conv_unsigned_widening_chain_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?
        .conv_u1()?
        .conv_u2()?
        .conv_u4()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 42), instr!("ret")])
}

/// Test: narrowing then widening conversion with constant.
///
/// Input:  ldc.i4 1000, conv.u1, conv.i4, ret
/// Output: ldc.i4 232, ret (1000 & 0xFF = 232)
#[test]
fn test_conv_narrowing_widening_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(1000)?.conv_u1()?.conv_i4()?.ret()?;

    // 1000 & 0xFF = 232 (truncation to u8)
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 232), instr!("ret")])
}

/// Test: float conversion chain with constant is folded through both conversions.
///
/// Input:  ldc.i4.s 42, conv.r4, conv.r8, ret
/// Output: ldc.r8 42.0, ret (binary32 to binary64 widens exactly)
#[test]
fn test_conv_float_chain_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?.conv_r4()?.conv_r8()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.r8", f64: 42.0), instr!("ret")])
}

/// Test: constant conversion i4 to i8 is fully folded.
///
/// Input:  ldc.i4.s 42, conv.i8, ret
/// Output: ldc.i8 42, ret (constant fully folded)
#[test]
fn test_conv_constant_fold_i8() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(42)?.conv_i8()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i8", i64: 42), instr!("ret")])
}

/// Test: constant conversion chain i4 -> i8 -> i4 is fully folded.
///
/// Input:  ldc.i4.s 100, conv.i8, conv.i4, ret
/// Output: ldc.i4.s 100, ret (constants folded through chain)
#[test]
fn test_conv_constant_fold_chain() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(100)?.conv_i8()?.conv_i4()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 100), instr!("ret")])
}

/// Test: duplicate u1 conversion with constant is folded.
///
/// Input:  ldc.i4 300, conv.u1, conv.u1, ret
/// Output: ldc.i4.s 44, ret (300 & 0xFF = 44, duplicate conv eliminated)
#[test]
fn test_conv_duplicate_u1_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(300)?.conv_u1()?.conv_u1()?.ret()?;

    // 300 & 0xFF = 44
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 44), instr!("ret")])
}

/// Test: u1 to i1 conversion with constant.
///
/// Input:  ldc.i4 200, conv.u1, conv.i1, ret
/// Output: ldc.i4.s -56, ret (200 as u8 = 200, as i8 = -56)
#[test]
fn test_conv_u1_i1_constant() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4(200)?.conv_u1()?.conv_i1()?.ret()?;

    // 200 as u8 = 200, reinterpreted as i8 = -56
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: -56), instr!("ret")])
}

/// Test: negative constant through signed conversion chain.
///
/// Input:  ldc.i4.s -10, conv.i8, conv.i4, ret
/// Output: ldc.i4.s -10, ret (sign preserved through widening/narrowing)
#[test]
fn test_conv_negative_constant_chain() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(-10)?.conv_i8()?.conv_i4()?.ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: -10), instr!("ret")])
}

/// Test: constant comparison in loop-like structure folds correctly.
///
/// Tests that a constant comparison folding works in branching context.
/// When 42 <= 100 is always true, the branch is taken.
///
/// Input:  ldc.i4.s 42, ldc.i4.s 100, ble.s taken, ldc.i4.1, ret, taken: ldc.i4.0, ret
/// Output: ldc.i4.0, ret (42 <= 100 is true, so branch taken)
#[test]
fn test_loop_constant_comparison_branch() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // 42 <= 100 ? goto taken : continue
    asm.ldc_i4_const(42)?
        .ldc_i4_const(100)?
        .ble_s("taken")?
        .ldc_i4_1()?
        .ret()?
        .label("taken")?
        .ldc_i4_0()?
        .ret()?;

    // 42 <= 100 is true, so branch is taken, returns 0
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.0"), instr!("ret")])
}

/// Test: simple conditional branch preserved.
///
/// Input:  ldarg.0, brfalse.s skip, ldc.i4.1, ret, skip: ldc.i4.0, ret
/// Output: Same structure preserved (cannot be simplified without knowing arg0)
#[test]
fn test_loop_conditional_branch_preserved() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("false_branch")?
        .ldc_i4_1()?
        .ret()?
        .label("false_branch")?
        .ldc_i4_0()?
        .ret()?;

    // Code generator may invert branch condition and swap blocks for optimization.
    // Either order is semantically equivalent:
    //   brfalse -> true_branch, false_branch  OR  brtrue -> false_branch, true_branch
    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!(any_conditional_branch),
            instr!("ldc.i4.0"),
            instr!("ret"),
            instr!("ldc.i4.1"),
            instr!("ret"),
        ],
    )
}

/// Test: loop-like diamond pattern (if-then-else merge).
///
/// Input:  ldarg.0, brfalse.s else, ldc.i4.1, br.s merge, else: ldc.i4.2, merge: ret
/// Output: Structure preserved with phi resolution - phi becomes ldloc
#[test]
fn test_loop_diamond_pattern() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .brfalse_s("else_branch")?
        .ldc_i4_1()?
        .br_s("merge")?
        .label("else_branch")?
        .ldc_i4_2()?
        .label("merge")?
        .ret()?;

    // After SSA reconstruction, phi nodes at merge points are eliminated via explicit
    // stores. Each branch stores its value to the phi result local, and the merge
    // point loads from that local.
    //
    // Code generator may invert branch condition and swap blocks for optimization.
    // The phi coalescing eliminates the temp variable — both branches store directly
    // to the phi result local.
    //
    // Output pattern (with brtrue and swapped blocks):
    //   ldarg.0              ; test condition
    //   brtrue.s true_branch ; branch if true
    //   ldc.i4.2             ; false: load 2
    //   stloc.0              ; false: store to phi result
    //   ldloc.0              ; merge: load phi result
    //   ret                  ; return
    //   ldc.i4.1             ; true: load 1
    //   stloc.0              ; true: store directly to phi result
    //   br.s merge           ; true: jump to merge
    run_deobfuscation_test(
        asm,
        1,
        3,
        &[
            instr!("ldarg.0"),
            instr!(any_conditional_branch), // may be brfalse or brtrue
            instr!("ldc.i4.2"),             // false branch: load constant 2
            instr!(any_stloc),              // false branch: store to phi result
            instr!(any_ldloc),              // merge: load phi result
            instr!("ret"),
            instr!("ldc.i4.1"),       // true branch: load constant 1
            instr!(any_stloc),        // true branch: store to phi result
            instr!(any_branch: "br"), // true branch: jump to merge
        ],
    )
}

/// Test: constant condition in if (always true) - branch eliminated.
///
/// Input:  ldc.i4.1, brfalse.s skip, ldc.i4.s 42, ret, skip: ldc.i4.0, ret
/// Output: ldc.i4.s 42, ret (dead branch eliminated)
#[test]
fn test_loop_constant_true_condition() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()?
        .brfalse_s("skip")?
        .ldc_i4_const(42)?
        .ret()?
        .label("skip")?
        .ldc_i4_0()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: constant condition in if (always false) - other branch eliminated.
///
/// Input:  ldc.i4.0, brfalse.s skip, ldc.i4.s 42, ret, skip: ldc.i4.s 99, ret
/// Output: ldc.i4.s 99, ret (dead branch eliminated)
#[test]
fn test_loop_constant_false_condition() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?
        .brfalse_s("skip")?
        .ldc_i4_const(42)?
        .ret()?
        .label("skip")?
        .ldc_i4_const(99)?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 99), instr!("ret")])
}

/// Test: unconditional jump is preserved in loop structure.
///
/// Input:  br.s target, nop, target: ldc.i4.5, ret
/// Output: ldc.i4.5, ret (jump target inlined, unreachable code removed)
#[test]
fn test_loop_unconditional_jump_simplified() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.br_s("target")?
        .nop()?
        .label("target")?
        .ldc_i4_5()?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.5"), instr!("ret")])
}

/// Test: comparison with constant that determines branch.
///
/// Input:  ldc.i4.5, ldc.i4.3, cgt, brfalse.s skip, ldc.i4.1, ret, skip: ldc.i4.0, ret
/// Output: ldc.i4.1, ret (5 > 3 is true, so first branch taken)
#[test]
fn test_loop_constant_comparison_folded() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?
        .ldc_i4_3()?
        .cgt()?
        .brfalse_s("skip")?
        .ldc_i4_1()?
        .ret()?
        .label("skip")?
        .ldc_i4_0()?
        .ret()?;

    // 5 > 3 is true (1), brfalse not taken, returns 1
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.1"), instr!("ret")])
}

/// Test: nested constant conditions both fold.
///
/// Input:  ldc.i4.1, brfalse.s a, ldc.i4.0, brfalse.s b, ldc.i4.s 10, ret, a: ldc.i4.s 20, ret, b: ldc.i4.s 30, ret
/// Output: ldc.i4.s 30, ret (first cond true, second cond false -> goto b)
#[test]
fn test_loop_nested_constant_conditions() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()? // true
        .brfalse_s("branch_a")? // not taken
        .ldc_i4_0()? // false
        .brfalse_s("branch_b")? // taken
        .ldc_i4_const(10)?
        .ret()?
        .label("branch_a")?
        .ldc_i4_const(20)?
        .ret()?
        .label("branch_b")?
        .ldc_i4_const(30)?
        .ret()?;

    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 30), instr!("ret")])
}

/// Test: switch with constant selector is folded to direct jump.
///
/// When switch selector is a constant, only the matching case is reachable.
///
/// Input:  ldc.i4.1, switch(case0, case1, case2), default: ldc.i4.0, ret,
///         case0: ldc.i4.s 10, ret, case1: ldc.i4.s 20, ret, case2: ldc.i4.s 30, ret
/// Output: ldc.i4.s 20, ret (case 1 is selected)
#[test]
fn test_unflatten_switch_constant_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_1()? // selector = 1
        .switch(&["case0", "case1", "case2"])?
        .ldc_i4_0()? // default
        .ret()?
        .label("case0")?
        .ldc_i4_const(10)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(20)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(30)?
        .ret()?;

    // Selector is constant 1, so case1 is taken, returns 20
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 20), instr!("ret")])
}

/// Test: switch with out-of-range constant falls through to default.
///
/// Input:  ldc.i4.s 10, switch(case0, case1), default: ldc.i4.s 99, ret,
///         case0: ldc.i4.0, ret, case1: ldc.i4.1, ret
/// Output: ldc.i4.s 99, ret (10 is out of range, default taken)
#[test]
fn test_unflatten_switch_out_of_range() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(10)? // selector = 10 (out of range)
        .switch(&["case0", "case1"])?
        .ldc_i4_const(99)? // default
        .ret()?
        .label("case0")?
        .ldc_i4_0()?
        .ret()?
        .label("case1")?
        .ldc_i4_1()?
        .ret()?;

    // Selector 10 is out of range [0,1], default taken
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 99), instr!("ret")])
}

/// Test: switch with negative constant falls through to default.
///
/// Input:  ldc.i4.m1, switch(case0, case1), default: ldc.i4.s 42, ret, ...
/// Output: ldc.i4.s 42, ret (negative index goes to default)
#[test]
fn test_unflatten_switch_negative_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_m1()? // selector = -1
        .switch(&["case0", "case1"])?
        .ldc_i4_const(42)? // default
        .ret()?
        .label("case0")?
        .ldc_i4_0()?
        .ret()?
        .label("case1")?
        .ldc_i4_1()?
        .ret()?;

    // Negative selector goes to default
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: computed switch selector from arithmetic.
///
/// When switch selector is computed from constants, SCCP should fold it.
///
/// Input:  ldc.i4.2, ldc.i4.1, sub, switch(...), ...
/// Output: Selects case 1 (2-1=1)
#[test]
fn test_unflatten_switch_computed_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_2()?
        .ldc_i4_1()?
        .sub()? // 2 - 1 = 1
        .switch(&["case0", "case1", "case2"])?
        .ldc_i4_0()? // default
        .ret()?
        .label("case0")?
        .ldc_i4_const(10)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(20)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(30)?
        .ret()?;

    // 2 - 1 = 1, case1 selected
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 20), instr!("ret")])
}

/// Test: switch selector from XOR encoding.
///
/// Common obfuscator pattern: state = encoded_state ^ key
///
/// Input:  ldc.i4.s 0x0F, ldc.i4.s 0x0E, xor, switch(...), ...
/// Output: Selects case 1 (0x0F ^ 0x0E = 1)
#[test]
fn test_unflatten_switch_xor_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0x0F)?
        .ldc_i4_const(0x0E)?
        .xor()? // 0x0F ^ 0x0E = 1
        .switch(&["case0", "case1", "case2"])?
        .ldc_i4_0()? // default
        .ret()?
        .label("case0")?
        .ldc_i4_const(100)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(200)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(300)?
        .ret()?;

    // 0x0F ^ 0x0E = 1, case1 selected
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 200), instr!("ret")])
}

/// Test: switch with zero selector takes first case.
///
/// Input:  ldc.i4.0, switch(case0, case1), default, case0: ..., case1: ...
/// Output: case0 code (selector 0 = first case)
#[test]
fn test_unflatten_switch_zero_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()? // selector = 0
        .switch(&["case0", "case1"])?
        .ldc_i4_const(99)? // default
        .ret()?
        .label("case0")?
        .ldc_i4_const(11)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(22)?
        .ret()?;

    // Selector 0 = first case
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 11), instr!("ret")])
}

/// Test: chained constant comparisons determine control flow.
///
/// Tests that SCCP properly propagates through multiple comparisons.
///
/// Input:  ldc.i4.5, ldc.i4.3, cgt (true), brfalse skip1,
///         ldc.i4.2, ldc.i4.2, ceq (true), brfalse skip2,
///         ldc.i4.s 42, ret, skip1: ldc.i4.1, ret, skip2: ldc.i4.2, ret
/// Output: ldc.i4.s 42, ret (both conditions true, main path taken)
#[test]
fn test_unflatten_chained_comparisons() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_5()?
        .ldc_i4_3()?
        .cgt()? // 5 > 3 = true
        .brfalse_s("skip1")?
        .ldc_i4_2()?
        .ldc_i4_2()?
        .ceq()? // 2 == 2 = true
        .brfalse_s("skip2")?
        .ldc_i4_const(42)?
        .ret()?
        .label("skip1")?
        .ldc_i4_1()?
        .ret()?
        .label("skip2")?
        .ldc_i4_2()?
        .ret()?;

    // Both comparisons are true, main path returns 42
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 42), instr!("ret")])
}

/// Test: switch with multiplication-based selector.
///
/// Input:  ldc.i4.3, ldc.i4.0, mul, switch(...), ...
/// Output: case0 (3 * 0 = 0)
#[test]
fn test_unflatten_switch_mul_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_3()?
        .ldc_i4_0()?
        .mul()? // 3 * 0 = 0
        .switch(&["case0", "case1", "case2"])?
        .ldc_i4_const(99)?
        .ret()?
        .label("case0")?
        .ldc_i4_const(10)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(20)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(30)?
        .ret()?;

    // 3 * 0 = 0, case0 selected
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 10), instr!("ret")])
}

/// Test: switch with bitwise AND selector.
///
/// Input:  ldc.i4.s 0x0F, ldc.i4.s 0x02, and, switch(...), ...
/// Output: case2 (0x0F & 0x02 = 2)
#[test]
fn test_unflatten_switch_and_selector() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0x0F)?
        .ldc_i4_2()?
        .and()? // 0x0F & 2 = 2
        .switch(&["case0", "case1", "case2", "case3"])?
        .ldc_i4_const(99)?
        .ret()?
        .label("case0")?
        .ldc_i4_const(10)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(20)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(30)?
        .ret()?
        .label("case3")?
        .ldc_i4_const(40)?
        .ret()?;

    // 0x0F & 2 = 2, case2 selected
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4.s", i8: 30), instr!("ret")])
}

/// Test: switch preserves dynamic selector from argument.
///
/// When selector is unknown (from argument), switch must be preserved.
#[test]
fn test_unflatten_switch_dynamic_preserved() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()? // dynamic selector
        .switch(&["case0", "case1"])?
        .ldc_i4_const(99)? // default
        .ret()?
        .label("case0")?
        .ldc_i4_0()?
        .ret()?
        .label("case1")?
        .ldc_i4_1()?
        .ret()?;

    // Dynamic selector - switch preserved
    // Block ordering may be non-deterministic; switch table is updated to point correctly
    run_deobfuscation_test(
        asm,
        1,
        0,
        &[
            instr!("ldarg.0"),
            instr!("switch", any),
            instr!("ldc.i4.s", i8: 99),
            instr!("ret"),
            instr!(any_ldc_i4), // case 0 or 1 (order non-deterministic)
            instr!("ret"),
            instr!(any_ldc_i4), // case 1 or 0 (order non-deterministic)
            instr!("ret"),
        ],
    )
}

/// Test: deeply nested constant propagation through switch.
///
/// Tests SCCP through multiple layers of computation.
#[test]
fn test_unflatten_deep_constant_propagation() -> Result<()> {
    let mut asm = InstructionAssembler::new();
    // ((10 - 5) * 2) / 5 = 2
    asm.ldc_i4_const(10)?
        .ldc_i4_5()?
        .sub()? // 5
        .ldc_i4_2()?
        .mul()? // 10
        .ldc_i4_5()?
        .div()? // 2
        .switch(&["case0", "case1", "case2", "case3"])?
        .ldc_i4_const(99)?
        .ret()?
        .label("case0")?
        .ldc_i4_const(100)?
        .ret()?
        .label("case1")?
        .ldc_i4_const(200)?
        .ret()?
        .label("case2")?
        .ldc_i4_const(300)?
        .ret()?
        .label("case3")?
        .ldc_i4_const(400)?
        .ret()?;

    // ((10-5)*2)/5 = 2, case2 selected
    run_deobfuscation_test(asm, 0, 0, &[instr!("ldc.i4", i32: 300), instr!("ret")])
}

/// Verifies that Fibonacci-like loop patterns are correctly preserved during deobfuscation.
///
/// This test validates the fix for cross-origin PHI operand issues that caused loop body
/// elimination. The pattern includes:
/// - Loop initialization: a=0, b=1, i=2
/// - Loop body: temp=a+b, a=b, b=temp, i++
/// - Loop condition: i <= n
/// - Return: b
///
/// Previously, copy propagation could create cross-origin PHI operand references,
/// causing `rebuild_ssa` to incorrectly classify def sites and eliminate live code.
#[test]
fn test_fibonacci_loop_body_preserved() -> Result<()> {
    let mut asm = InstructionAssembler::new();

    // Method signature: int Fib(int n)
    // Locals: a (V_0), b (V_1), i (V_2), temp (V_3)

    // Entry: check n > 0
    asm.ldarg_1()? // load n
        .ldc_i4_0()?
        .bgt("check_n_eq_1")? // if n > 0, check for n == 1
        .ldc_i4_0()?
        .ret()? // return 0 for n <= 0
        // Check n == 1
        .label("check_n_eq_1")?
        .ldarg_1()?
        .ldc_i4_1()?
        .bne_un("loop_init")? // if n != 1, go to loop init
        .ldc_i4_1()?
        .ret()? // return 1 for n == 1
        // Loop initialization
        .label("loop_init")?
        .ldc_i4_0()?
        .stloc_0()? // a = 0
        .ldc_i4_1()?
        .stloc_1()? // b = 1
        .ldc_i4_2()?
        .stloc_2()? // i = 2
        .br("loop_cond")? // jump to condition
        // Loop body
        .label("loop_body")?
        .ldloc_0()? // load a
        .ldloc_1()? // load b
        .add()? // a + b
        .stloc_3()? // temp = a + b
        .ldloc_1()? // load b
        .stloc_0()? // a = b
        .ldloc_3()? // load temp
        .stloc_1()? // b = temp
        .ldloc_2()? // load i
        .ldc_i4_1()?
        .add()? // i + 1
        .stloc_2()? // i = i + 1
        // Loop condition
        .label("loop_cond")?
        .ldloc_2()? // load i
        .ldarg_1()? // load n
        .ble("loop_body")? // if i <= n, continue loop
        // Return b
        .ldloc_1()?
        .ret()?;

    let (_original_bytecode, cfg) = build_cfg(asm)?;

    // Build SSA with 2 args (this + n) and 4 locals (a, b, i, temp)
    let mut ssa = build_ssa(
        &cfg,
        &TestTypeProvider::all_i32(2, 4).arg(0, SsaType::Object),
    )?;

    // Run deobfuscation
    let engine = engine();
    let _result = engine.process_ssa(test_assembly(), &mut ssa, Token::new(0x06000001))?;

    // Generate output CIL
    let output_bytecode = generate_cil(&ssa)?;
    let output_instrs = decode_instructions(&output_bytecode)?;

    // Verify loop body is preserved: must have 'add' instruction for temp = a + b
    let add_count = output_instrs.iter().filter(|i| i.mnemonic == "add").count();
    assert!(
        add_count >= 2,
        "Loop body was eliminated! Expected at least 2 'add' instructions (temp=a+b and i++), \
         found {}. This indicates the loop body was incorrectly removed as dead code.",
        add_count
    );

    // Verify we still have the loop structure (backward branch)
    let has_ble = output_instrs
        .iter()
        .any(|i| i.mnemonic == "ble.s" || i.mnemonic == "ble");
    assert!(
        has_ble,
        "Loop condition branch was eliminated! Expected 'ble' instruction for loop back-edge."
    );

    // Verify local variable stores are preserved (loop body updates locals)
    let stloc_count = output_instrs
        .iter()
        .filter(|i| i.mnemonic.starts_with("stloc"))
        .count();
    assert!(
        stloc_count >= 4,
        "Loop body variable stores were eliminated! Expected at least 4 stloc instructions, found {}.",
        stloc_count
    );

    Ok(())
}

/// Integration test for aggressive inlining on unobfuscated original.exe.
///
/// This test verifies that when inlining is enabled (aggressive mode):
/// 1. Simple methods like Calculator.Add, Calculator.Subtract, Calculator.Multiply
///    are inlined into Main()
/// 2. The original call instructions are replaced with inline arithmetic
/// 3. When remove_unused_methods is enabled, the inlined methods are removed
///
/// This tests the complete deobfuscation pipeline on a real assembly.
#[test]
fn test_aggressive_inlining_original_exe() {
    // First verify original.exe has the expected methods
    let assembly = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe"))
        .expect("Failed to load original.exe");

    let methods_before: Vec<_> = assembly
        .methods()
        .iter()
        .map(|e| e.value().name.clone())
        .collect();

    // Verify Calculator methods exist before inlining
    assert!(
        methods_before.iter().any(|n| n == "Add"),
        "Original should have Calculator.Add method"
    );
    assert!(
        methods_before.iter().any(|n| n == "Subtract"),
        "Original should have Calculator.Subtract method"
    );
    assert!(
        methods_before.iter().any(|n| n == "Multiply"),
        "Original should have Calculator.Multiply method"
    );

    // Now run deobfuscation with aggressive config (inlining enabled)
    let config = EngineConfig::aggressive();
    assert!(
        config.passes.inlining,
        "Aggressive config should enable inlining"
    );
    assert!(
        config.cleanup.remove_unused_methods,
        "Aggressive config should enable unused method removal"
    );

    let engine = engine_with(config);
    let result = engine.process_file(fixture("packers/confuserex/1.6.0/original.exe"));
    assert!(result.is_ok(), "Deobfuscation should succeed");

    let (_deobfuscated, result) = result.unwrap();

    // Derive stats from the event log
    let stats = DerivedStats::from_log(&result.events);

    // With aggressive inlining, we should have inlined some methods
    // Note: The actual number depends on which methods qualify for inlining
    println!("Inlining stats: {} methods inlined", stats.methods_inlined);

    // Verify inlining happened - at minimum Add/Subtract/Multiply should be inlineable
    // (they're 4 instructions each: ldarg.1, ldarg.2, add/sub/mul, ret)
    assert!(
        stats.methods_inlined >= 3,
        "Expected at least 3 methods to be inlined (Add, Subtract, Multiply), got {}",
        stats.methods_inlined
    );

    // Count methods before and after to verify unused method removal
    let original = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe"))
        .expect("Failed to load original.exe for comparison");
    let method_count_before = original.methods().len();
    let method_count_after = _deobfuscated.methods().len();

    println!(
        "Methods: {} before, {} after, {} inlined",
        method_count_before, method_count_after, stats.methods_inlined
    );

    // With aggressive mode, inlined methods with no remaining callers should be removed.
    // The Calculator methods (Add, Subtract, Multiply) are only called once each from Main,
    // so after inlining they should have no remaining callers and be removed.
    assert!(
        method_count_after < method_count_before,
        "Expected some methods to be removed after inlining (before: {}, after: {})",
        method_count_before,
        method_count_after
    );
}

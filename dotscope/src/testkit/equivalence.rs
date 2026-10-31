//! Whether generated code computes what the SSA it was generated from computes.
//!
//! The code generator checks its output against its input structurally (value flow, effect
//! order, store widths). This checks it by running both: the SSA, and the SSA lifted back
//! from the generated code, each executed by [`SsaEvaluator`] on the same concrete arguments,
//! must return the same values.
//!
//! The evaluator computes pure values: constants, arithmetic, logic, comparisons,
//! conversions, selects, argument and local slots, branches, switches and returns. A function
//! that does anything else (calls, memory, objects, exception regions, checked arithmetic) is
//! [`Equivalence::Unsupported`], which callers count and report rather than skip. A run the
//! evaluator cannot finish (a division by zero, a branch on a value it cannot know, a loop
//! past [`MAX_STEPS`] blocks) decides nothing and is counted as inconclusive.

use std::collections::BTreeMap;

use crate::{
    analysis::{
        ConstValue, ControlFlowGraph, SsaConverter, SsaEvaluator, SsaFunction, SsaOp, SsaType,
        TypeProvider, VariableOrigin,
    },
    assembly::decode_blocks,
    compiler::SsaCodeGenerator,
    metadata::{token::Token, typesystem::PointerSize},
    CilObject, Result,
};

/// The most blocks one run executes before it is inconclusive.
pub const MAX_STEPS: usize = 4096;

/// How many argument vectors each function runs on.
const RUNS: usize = 8;

/// What running generated code against the SSA it came from showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Equivalence {
    /// Every run both functions finished returned the same value.
    Equivalent {
        /// Runs both functions finished.
        conclusive: usize,
        /// Runs at least one of them could not finish.
        inconclusive: usize,
    },
    /// The function does something the evaluator does not compute: what, as text.
    Unsupported(String),
    /// The generator refused the function, which then keeps its original code: why.
    Refused(String),
    /// A run returned different values: the arguments and both results.
    Differs(String),
}

/// Generates code for `ssa`, lifts it back, and runs both on the same arguments. Generated code
/// that does not decode or lift differs from its SSA.
#[must_use]
pub fn regenerate_and_compare(ssa: &SsaFunction) -> Equivalence {
    if let Some(reason) = unsupported(ssa) {
        return Equivalence::Unsupported(reason);
    }
    let mut generator = SsaCodeGenerator::new();
    let (bytecode, num_locals) = match generator.generate(ssa) {
        Ok((bytecode, _, num_locals)) => (bytecode, num_locals),
        Err(error) => return Equivalence::Refused(error.to_string()),
    };
    let regenerated = match relift(ssa, &generator, &bytecode, num_locals) {
        Ok(regenerated) => regenerated,
        Err(error) => {
            return Equivalence::Differs(format!("the generated code does not lift: {error}"));
        }
    };
    if let Some(reason) = unsupported(&regenerated) {
        return Equivalence::Differs(format!(
            "the generated code {reason}, which the SSA it came from does not"
        ));
    }
    compare(ssa, &regenerated)
}

/// The SSA lifted from `bytecode`, which `generator` generated for `ssa`: its arguments typed
/// as `ssa`'s and its locals as the generator typed them.
fn relift(
    ssa: &SsaFunction,
    generator: &SsaCodeGenerator,
    bytecode: &[u8],
    num_locals: u16,
) -> Result<SsaFunction> {
    let blocks = decode_blocks(bytecode, 0, 0x1000, Some(bytecode.len()))?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    // By each argument's index: a function may have no variable for an argument it never
    // reads, and the rest keep their places
    let mut args = vec![SsaType::Unknown; ssa.num_args()];
    for variable in ssa.argument_variables() {
        if let VariableOrigin::Argument(index) = variable.origin() {
            if let Some(slot) = args.get_mut(usize::from(index)) {
                *slot = variable.var_type().clone();
            }
        }
    }
    let types = RegeneratedTypes {
        args,
        locals: generator.local_types(),
    };
    SsaConverter::build(
        &cfg,
        ssa.num_args(),
        usize::from(num_locals),
        &types,
        Vec::new(),
    )
}

/// What `ssa` does that the evaluator does not compute, if anything.
#[must_use]
pub fn unsupported(ssa: &SsaFunction) -> Option<String> {
    if ssa.has_exception_handlers() {
        return Some("has exception regions".to_string());
    }
    ssa.blocks()
        .iter()
        .flat_map(|block| block.instructions())
        .map(|instruction| instruction.op())
        .find(|op| !computed(op))
        .map(|op| format!("uses {}", kind(op)))
}

/// The name of `op`'s kind: `Call` for a call, whatever it calls.
fn kind(op: &SsaOp) -> String {
    let text = format!("{op:?}");
    text.split([' ', '{', '('])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Whether the evaluator computes `op` from concrete operands as CIL does.
fn computed(op: &SsaOp) -> bool {
    matches!(
        op,
        SsaOp::Const { .. }
            | SsaOp::Add { .. }
            | SsaOp::Sub { .. }
            | SsaOp::Mul { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::Neg { .. }
            | SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Not { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. }
            | SsaOp::Ceq { .. }
            | SsaOp::Clt { .. }
            | SsaOp::Cgt { .. }
            | SsaOp::IntConv { .. }
            | SsaOp::IntToFloat { .. }
            | SsaOp::FloatToInt { .. }
            | SsaOp::FloatConv { .. }
            | SsaOp::Select { .. }
            | SsaOp::Copy { .. }
            | SsaOp::LoadArg { .. }
            | SsaOp::LoadLocal { .. }
            | SsaOp::Pop { .. }
            | SsaOp::Nop
            | SsaOp::Jump { .. }
            | SsaOp::Branch { .. }
            | SsaOp::BranchCmp { .. }
            | SsaOp::Switch { .. }
            | SsaOp::Return { .. }
    )
}

/// Runs `original` and `regenerated` (whatever a transformation made of it) on the same
/// argument vectors and compares what they return.
#[must_use]
pub fn compare(original: &SsaFunction, regenerated: &SsaFunction) -> Equivalence {
    let mut conclusive = 0;
    let mut inconclusive = 0;
    for run in 0..RUNS {
        let args = arguments(original, run);
        match (execute(original, &args), execute(regenerated, &args)) {
            (Some(expected), Some(actual)) if expected == actual => conclusive += 1,
            (Some(expected), Some(actual)) => {
                return Equivalence::Differs(format!(
                    "on {args:?} the first returns {expected} and the second {actual}"
                ));
            }
            _ => inconclusive += 1,
        }
    }
    Equivalence::Equivalent {
        conclusive,
        inconclusive,
    }
}

/// The arguments of run `run`: for each argument a value of its type, taken from a list of
/// ordinary and edge values at an offset that differs per argument, so the runs combine
/// them differently. `None` for an argument whose type has no values here.
fn arguments(ssa: &SsaFunction, run: usize) -> BTreeMap<u16, ConstValue> {
    ssa.argument_variables()
        .filter_map(|variable| {
            let VariableOrigin::Argument(index) = variable.origin() else {
                return None;
            };
            let values = samples(variable.var_type());
            let pick = run.wrapping_add(usize::from(index).wrapping_mul(3)) % values.len().max(1);
            values.into_iter().nth(pick).map(|value| (index, value))
        })
        .collect()
}

/// Ordinary and edge values of `ty`: zero, small values of each sign, the extremes, and for
/// floats the special values.
fn samples(ty: &SsaType) -> Vec<ConstValue> {
    match ty {
        SsaType::Bool => vec![ConstValue::False, ConstValue::True],
        SsaType::I8 => [0, 1, -1, 2, -7, 100, i8::MIN, i8::MAX]
            .map(ConstValue::I8)
            .to_vec(),
        SsaType::U8 => [0, 1, 2, 7, 100, 0x80, u8::MAX - 1, u8::MAX]
            .map(ConstValue::U8)
            .to_vec(),
        SsaType::I16 => [0, 1, -1, 2, -7, 1000, i16::MIN, i16::MAX]
            .map(ConstValue::I16)
            .to_vec(),
        SsaType::U16 | SsaType::Char => [0, 1, 2, 7, 1000, 0x8000, u16::MAX - 1, u16::MAX]
            .map(ConstValue::U16)
            .to_vec(),
        SsaType::I32 => [0, 1, -1, 2, -7, 100_000, i32::MIN, i32::MAX]
            .map(ConstValue::I32)
            .to_vec(),
        SsaType::U32 => [0, 1, 2, 7, 100_000, 0x8000_0000, u32::MAX - 1, u32::MAX]
            .map(ConstValue::U32)
            .to_vec(),
        SsaType::I64 => [0, 1, -1, 2, -7, 1 << 40, i64::MIN, i64::MAX]
            .map(ConstValue::I64)
            .to_vec(),
        SsaType::U64 => [0, 1, 2, 7, 1 << 40, 1 << 63, u64::MAX - 1, u64::MAX]
            .map(ConstValue::U64)
            .to_vec(),
        SsaType::NativeInt => [
            0,
            1,
            -1,
            2,
            -7,
            100_000,
            i64::from(i32::MIN),
            i64::from(i32::MAX),
        ]
        .map(ConstValue::NativeInt)
        .to_vec(),
        SsaType::NativeUInt => [0, 1, 2, 7, 100_000, 0x8000_0000, u64::from(u32::MAX), 3]
            .map(ConstValue::NativeUInt)
            .to_vec(),
        SsaType::F32 => [0.0, 1.0, -1.5, 3.25, -0.0, f32::NAN, f32::INFINITY, 1e10]
            .map(ConstValue::from)
            .to_vec(),
        SsaType::F64 => [
            0.0,
            1.0,
            -1.5,
            3.25,
            -0.0,
            f64::NAN,
            f64::NEG_INFINITY,
            1e300,
        ]
        .map(ConstValue::from)
        .to_vec(),
        _ => Vec::new(),
    }
}

/// What `ssa` returns on `args`, as text (`void` for a return without a value), or `None`
/// when the evaluator cannot finish the run.
fn execute(ssa: &SsaFunction, args: &BTreeMap<u16, ConstValue>) -> Option<String> {
    let mut evaluator = SsaEvaluator::new(ssa, PointerSize::Bit64);
    for variable in ssa.argument_variables() {
        if let VariableOrigin::Argument(index) = variable.origin() {
            if let Some(value) = args.get(&index) {
                evaluator.set_concrete(variable.id(), value.clone());
            }
        }
    }
    let trace = evaluator.execute_from_entry(MAX_STEPS);
    if !trace.is_complete() {
        return None;
    }
    let last = ssa.block(trace.last_block()?)?;
    match last.control_terminator()? {
        SsaOp::Return { value: None } => Some("void".to_string()),
        // As the evaluation stack holds it, in Debug text: a NaN equals a NaN, -0.0
        // differs from 0.0
        SsaOp::Return { value: Some(value) } => evaluator
            .get_concrete(*value)
            .map(|value| format!("{:?}", on_stack(value))),
        _ => None,
    }
}

/// `value` as the evaluation stack holds it (ECMA-335 I.12.1): a bool or a narrow integer is
/// an `int32`, and an unsigned integer the signed one of its width with the same bits. A lift
/// types a value by what produced it, a constant `true` as a bool and `ldc.i4.1` as an
/// `int32`, and the two are one value.
fn on_stack(value: &ConstValue) -> ConstValue {
    match value {
        ConstValue::True => ConstValue::I32(1),
        ConstValue::False => ConstValue::I32(0),
        ConstValue::I8(v) => ConstValue::I32(i32::from(*v)),
        ConstValue::I16(v) => ConstValue::I32(i32::from(*v)),
        ConstValue::U8(v) => ConstValue::I32(i32::from(*v)),
        ConstValue::U16(v) => ConstValue::I32(i32::from(*v)),
        ConstValue::U32(v) => ConstValue::I32(i32::from_ne_bytes(v.to_ne_bytes())),
        ConstValue::U64(v) => ConstValue::I64(i64::from_ne_bytes(v.to_ne_bytes())),
        ConstValue::NativeUInt(v) => ConstValue::NativeInt(i64::from_ne_bytes(v.to_ne_bytes())),
        other => other.clone(),
    }
}

/// The types of a regenerated function's slots: its arguments' as the original SSA had them,
/// its locals' as the generator allocated them. The functions compared reference nothing in
/// an assembly, so the rest is never asked.
struct RegeneratedTypes<'a> {
    args: Vec<SsaType>,
    locals: &'a BTreeMap<u16, SsaType>,
}

impl TypeProvider for RegeneratedTypes<'_> {
    fn arg_type(&self, idx: u16) -> SsaType {
        self.args
            .get(usize::from(idx))
            .cloned()
            .unwrap_or(SsaType::Unknown)
    }

    fn local_type(&self, idx: u16) -> SsaType {
        self.locals.get(&idx).cloned().unwrap_or(SsaType::Unknown)
    }

    fn call_return_type(&self, _token: Token) -> SsaType {
        SsaType::Unknown
    }

    fn newobj_type(&self, _ctor_token: Token) -> SsaType {
        SsaType::Unknown
    }

    fn field_type(&self, _field_token: Token) -> SsaType {
        SsaType::Unknown
    }

    fn call_indirect_return_type(&self, _sig_token: Token) -> SsaType {
        SsaType::Unknown
    }

    fn assembly(&self) -> Option<&CilObject> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{DefSite, SsaBlock, SsaFunctionBuilder, SsaInstruction, SsaVarId};

    /// `a + b` over two `int32` arguments, or `a - b` when `subtract`.
    fn add_or_subtract(subtract: bool) -> SsaFunction {
        SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (a, b) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                f.block(0, |blk| {
                    let r: SsaVarId = if subtract {
                        blk.sub(a, b)
                    } else {
                        blk.add(a, b)
                    };
                    blk.ret_val(r);
                });
            })
            .unwrap()
    }

    #[test]
    fn generated_arithmetic_returns_what_its_ssa_returns() {
        let verdict = regenerate_and_compare(&add_or_subtract(false));
        assert_eq!(
            verdict,
            Equivalence::Equivalent {
                conclusive: RUNS,
                inconclusive: 0
            }
        );
    }

    /// The selected path decides the value: both arms run across the argument vectors.
    #[test]
    fn a_branch_regenerates_to_the_same_choice() {
        let ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (a, b) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                f.block(0, |blk| {
                    let less = blk.clt(a, b);
                    blk.branch(less, 1, 2);
                });
                f.block(1, |blk| {
                    let r = blk.sub(b, a);
                    blk.ret_val(r);
                });
                f.block(2, |blk| {
                    let r = blk.sub(a, b);
                    blk.ret_val(r);
                });
            })
            .unwrap();
        let verdict = regenerate_and_compare(&ssa);
        assert_eq!(
            verdict,
            Equivalence::Equivalent {
                conclusive: RUNS,
                inconclusive: 0
            }
        );
    }

    /// An argument the function has no variable for leaves no gap: the ones after it keep
    /// their types, so an `int64` second argument is not taken for the first.
    #[test]
    fn an_argument_without_a_variable_keeps_the_others_in_place() {
        let mut ssa = SsaFunction::new(2, 0);
        let second = ssa.create_variable(
            VariableOrigin::Argument(1),
            0,
            DefSite::entry(),
            SsaType::I64,
        );
        let sum = ssa.create_variable(
            VariableOrigin::Phi,
            0,
            DefSite::instruction(0, 0),
            SsaType::I64,
        );
        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: sum,
            left: second,
            right: second,
            flags: None,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(sum),
        }));
        ssa.add_block(block);
        ssa.recompute_uses();

        let verdict = regenerate_and_compare(&ssa);
        assert!(
            matches!(verdict, Equivalence::Equivalent { conclusive, .. } if conclusive > 0),
            "{verdict:?}"
        );
    }

    /// The control: a function that computes something else is told apart.
    #[test]
    fn a_function_returning_another_value_differs() {
        let verdict = compare(&add_or_subtract(false), &add_or_subtract(true));
        assert!(matches!(verdict, Equivalence::Differs(_)), "{verdict:?}");
    }

    /// A function that throws is outside what the evaluator computes: reported, not compared.
    #[test]
    fn a_throw_is_unsupported() {
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let exception = f.arg(0, SsaType::Object);
                f.block(0, |blk| blk.throw(exception));
            })
            .unwrap();
        assert_eq!(
            regenerate_and_compare(&ssa),
            Equivalence::Unsupported("uses Throw".to_string())
        );
    }
}

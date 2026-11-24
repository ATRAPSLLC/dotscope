//! Differential sweep over mixed-width integer code.
//!
//! CIL computes every integer of 32 bits or fewer as an `int32` on the evaluation stack
//! (ECMA-335 III.1.1, III.1.5): a `byte`, `sbyte`, `short`, `ushort`, `char` or `bool` loaded
//! from an argument, a local or a conversion is extended by its own signedness, a store into a
//! narrower slot truncates, and a conversion converts the extended value. The lift types each
//! value by where it came from, so the passes see narrow operands of 32-bit operations, wide
//! operands of conversions and comparisons of both, and every analysis has to read each
//! operand the way the runtime does.
//!
//! The sweep generates random straight-line methods over such values, lifts them, runs the
//! value passes of the deobfuscation pipeline, regenerates CIL and runs the original and the
//! regenerated body side by side on the same arguments. A body regenerated without passes
//! checks the code generator alone; one regenerated after the passes checks the passes. A
//! difference is a miscompile, attributed to each pass that causes it on its own.
//!
//! The interpreter here is the oracle, so it models what the runtime does with typed slots: a
//! store into a local or argument truncates to its type and a load extends it, which the
//! untyped interpreter of the code generator's tests does not.
//!
//! `DIFFERENTIAL_CASES` sets the number of methods (default 4000) and `DIFFERENTIAL_SEED` the
//! seed, for longer local runs.

use std::{collections::BTreeMap, sync::Arc};

use analyssa::{scheduling::AsSsaPass, target::Target, PointerSize};

use crate::{
    analysis::{
        CallGraph, CilTarget, ConstValue, ControlFlowGraph, MethodRef, SsaFunction, SsaOp, SsaType,
    },
    assembly::{
        decode_blocks, decode_stream, Immediate, Instruction, InstructionAssembler, Operand,
    },
    compiler::{
        AlgebraicSimplificationPass, BlockMergingPass, CompilerContext, ConstantPropagationPass,
        ControlFlowSimplificationPass, CopyPropagationPass, DeadCodeEliminationPass,
        GlobalValueNumberingPass, JumpThreadingPass, LicmPass, MemoryOptimizationPass,
        OpaquePredicatePass, ReassociationPass, SsaCodeGenerator, SsaPass, StrengthReductionPass,
        ValueRangePropagationPass,
    },
    metadata::token::Token,
    testkit::{build_ssa, helpers::test_assembly_arc, passes::run_verified, TestTypeProvider},
    Parser,
};

/// A value on the evaluation stack: the two integer kinds the sweep computes with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackValue {
    /// An `int32`.
    I4(i32),
    /// An `int64`.
    I8(i64),
}

impl StackValue {
    /// The value's bits as a 64-bit integer, an `int32` sign-extended.
    fn bits(self) -> i64 {
        match self {
            Self::I4(v) => i64::from(v),
            Self::I8(v) => v,
        }
    }
}

/// What running a method gives: the value it returns, or the exception it throws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The returned value.
    Value(StackValue),
    /// The exception thrown: `DivideByZeroException`, or `OverflowException` (which the
    /// runtime raises for a checked operation, a conversion and `MIN / -1` alike).
    Throws(&'static str),
}

/// The number a checked conversion of `value` reads: unsigned for a `.un` form.
fn checked_source(value: StackValue, unsigned: bool) -> i128 {
    match (value, unsigned) {
        (StackValue::I4(v), false) => i128::from(v),
        (StackValue::I4(v), true) => i128::from(v as u32),
        (StackValue::I8(v), false) => i128::from(v),
        (StackValue::I8(v), true) => i128::from(v as u64),
    }
}

/// `numeric` converted to the type `conv.ovf.<target>` names, when it is representable there.
fn checked_target(numeric: i128, target: &str) -> Option<StackValue> {
    let (low, high): (i128, i128) = match target {
        "i1" => (i128::from(i8::MIN), i128::from(i8::MAX)),
        "u1" => (0, i128::from(u8::MAX)),
        "i2" => (i128::from(i16::MIN), i128::from(i16::MAX)),
        "u2" => (0, i128::from(u16::MAX)),
        "i4" => (i128::from(i32::MIN), i128::from(i32::MAX)),
        "u4" => (0, i128::from(u32::MAX)),
        "i8" => (i128::from(i64::MIN), i128::from(i64::MAX)),
        _ => (0, i128::from(u64::MAX)),
    };
    if !(low..=high).contains(&numeric) {
        return None;
    }
    Some(match target {
        "i8" | "u8" => StackValue::I8(numeric as i64),
        "u4" => StackValue::I4(numeric as u32 as i32),
        _ => StackValue::I4(numeric as i32),
    })
}

/// The evaluation-stack form of `value` stored into, then loaded from, a slot of type `ty`
/// (ECMA-335 III.1.6): truncated to the slot, extended by the slot type's signedness.
fn through_slot(ty: &SsaType, value: StackValue) -> StackValue {
    let bits = value.bits();
    match ty {
        SsaType::I8 => StackValue::I4(i32::from(bits as i8)),
        SsaType::U8 | SsaType::Bool => StackValue::I4(i32::from(bits as u8)),
        SsaType::I16 => StackValue::I4(i32::from(bits as i16)),
        SsaType::U16 | SsaType::Char => StackValue::I4(i32::from(bits as u16)),
        SsaType::I32 | SsaType::U32 => StackValue::I4(bits as i32),
        SsaType::I64 | SsaType::U64 => StackValue::I8(bits),
        _ => value,
    }
}

/// The index a short-form or indexed load or store names.
fn slot_index(instr: &Instruction) -> Option<usize> {
    if let Some(digit) = instr
        .mnemonic
        .rsplit('.')
        .next()
        .and_then(|s| s.parse().ok())
    {
        return Some(digit);
    }
    match &instr.operand {
        Operand::Local(index) | Operand::Argument(index) => Some(usize::from(*index)),
        Operand::Immediate(Immediate::UInt8(index)) => Some(usize::from(*index)),
        Operand::Immediate(Immediate::UInt16(index)) => Some(usize::from(*index)),
        _ => None,
    }
}

/// Runs integer CIL with typed arguments and locals: a store truncates to the slot's type and
/// a load extends it, as the runtime does. An exception the runtime throws is an outcome; an
/// instruction it does not model is an error, never skipped, so a body never passes by an
/// instruction going unexecuted.
fn run(
    bytecode: &[u8],
    args: &[StackValue],
    arg_types: &[SsaType],
    local_types: &BTreeMap<u16, SsaType>,
) -> Result<Outcome, String> {
    let instructions =
        decode_stream(&mut Parser::new(bytecode), 0).map_err(|e| format!("decode: {e}"))?;
    let index_of = |offset: u64| {
        instructions
            .iter()
            .position(|i| i.offset == offset)
            .ok_or_else(|| format!("branch to {offset:#x}"))
    };
    let mut stack: Vec<StackValue> = Vec::new();
    let mut locals: BTreeMap<usize, StackValue> = BTreeMap::new();
    let mut args = args.to_vec();
    let mut pc = 0usize;
    let mut steps = 0usize;
    while let Some(instr) = instructions.get(pc) {
        steps += 1;
        if steps > 100_000 {
            return Err("did not terminate".into());
        }
        pc += 1;
        let m = instr.mnemonic;
        let short = m.trim_end_matches(".s");
        let target = || -> Result<usize, String> {
            index_of(
                *instr
                    .branch_targets
                    .first()
                    .ok_or("branch without target")?,
            )
        };
        let mut pop = || stack.pop().ok_or_else(|| format!("{m}: stack underflow"));
        match short {
            "br" => pc = target()?,
            "brtrue" | "brfalse" => {
                if (pop()?.bits() != 0) == (short == "brtrue") {
                    pc = target()?;
                }
            }
            "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" | "beq" | "bne.un" | "bgt" | "bgt.un"
            | "blt" | "blt.un" | "bge" | "bge.un" | "ble" | "ble.un" => {
                let (b, a) = (pop()?, pop()?);
                let (a, b, ua, ub) = match (a, b) {
                    (StackValue::I4(a), StackValue::I4(b)) => (
                        i64::from(a),
                        i64::from(b),
                        u64::from(a as u32),
                        u64::from(b as u32),
                    ),
                    (StackValue::I8(a), StackValue::I8(b)) => (a, b, a as u64, b as u64),
                    _ => return Err(format!("{m} over mixed widths")),
                };
                let holds = match short {
                    "ceq" | "beq" => a == b,
                    "bne.un" => a != b,
                    "cgt" | "bgt" => a > b,
                    "cgt.un" | "bgt.un" => ua > ub,
                    "clt" | "blt" => a < b,
                    "clt.un" | "blt.un" => ua < ub,
                    "bge" => a >= b,
                    "bge.un" => ua >= ub,
                    "ble" => a <= b,
                    _ => ua <= ub,
                };
                if m.starts_with('c') {
                    stack.push(StackValue::I4(i32::from(holds)));
                } else if holds {
                    pc = target()?;
                }
            }
            _ if m.starts_with("ldarga") || m.starts_with("ldloca") => {
                return Err(format!("unmodeled {m}"));
            }
            _ if m.starts_with("ldarg") => {
                let at = slot_index(instr).ok_or("ldarg index")?;
                stack.push(*args.get(at).ok_or("ldarg out of range")?);
            }
            _ if m.starts_with("starg") => {
                let at = slot_index(instr).ok_or("starg index")?;
                let value = pop()?;
                let ty = arg_types.get(at).ok_or("starg out of range")?;
                args[at] = through_slot(ty, value);
            }
            _ if m.starts_with("ldloc") => {
                let at = slot_index(instr).ok_or("ldloc index")?;
                stack.push(
                    *locals
                        .get(&at)
                        .ok_or_else(|| format!("local {at} read before written"))?,
                );
            }
            _ if m.starts_with("stloc") => {
                let at = slot_index(instr).ok_or("stloc index")?;
                let value = pop()?;
                let stored = u16::try_from(at)
                    .ok()
                    .and_then(|at| local_types.get(&at))
                    .map_or(value, |ty| through_slot(ty, value));
                locals.insert(at, stored);
            }
            "ldc.i4.m1" => stack.push(StackValue::I4(-1)),
            _ if m.starts_with("ldc.i4.") && m.len() == 8 && m != "ldc.i4.s" => {
                let digit = m.get(7..).and_then(|digit| digit.parse().ok());
                stack.push(StackValue::I4(digit.ok_or_else(|| m.to_string())?));
            }
            "ldc.i4" | "ldc.i8" => stack.push(match &instr.operand {
                Operand::Immediate(Immediate::Int8(v)) => StackValue::I4(i32::from(*v)),
                Operand::Immediate(Immediate::Int32(v)) => StackValue::I4(*v),
                Operand::Immediate(Immediate::Int64(v)) => StackValue::I8(*v),
                other => return Err(format!("{m} operand {other:?}")),
            }),
            "dup" => {
                let top = *stack.last().ok_or("dup on an empty stack")?;
                stack.push(top);
            }
            "pop" => {
                pop()?;
            }
            "and" | "or" | "xor" | "add" | "sub" | "mul" => {
                let (b, a) = (pop()?, pop()?);
                let op = |a: i64, b: i64| match short {
                    "and" => a & b,
                    "or" => a | b,
                    "xor" => a ^ b,
                    "add" => a.wrapping_add(b),
                    "sub" => a.wrapping_sub(b),
                    _ => a.wrapping_mul(b),
                };
                let result = match (a, b) {
                    (StackValue::I4(a), StackValue::I4(b)) => {
                        StackValue::I4(op(i64::from(a), i64::from(b)) as i32)
                    }
                    (StackValue::I8(a), StackValue::I8(b)) => StackValue::I8(op(a, b)),
                    _ => return Err(format!("{m} over mixed widths")),
                };
                stack.push(result);
            }
            "div" | "div.un" | "rem" | "rem.un" => {
                let (b, a) = (pop()?, pop()?);
                let unsigned = short.ends_with(".un");
                let divide = short.starts_with("div");
                let result = match (a, b) {
                    (StackValue::I4(_), StackValue::I4(0))
                    | (StackValue::I8(_), StackValue::I8(0)) => {
                        return Ok(Outcome::Throws("DivideByZeroException"));
                    }
                    (StackValue::I4(a), StackValue::I4(b)) if unsigned => {
                        let (a, b) = (a as u32, b as u32);
                        StackValue::I4((if divide { a / b } else { a % b }) as i32)
                    }
                    (StackValue::I4(a), StackValue::I4(b)) => {
                        if a == i32::MIN && b == -1 {
                            return Ok(Outcome::Throws("OverflowException"));
                        }
                        StackValue::I4(if divide { a / b } else { a % b })
                    }
                    (StackValue::I8(a), StackValue::I8(b)) if unsigned => {
                        let (a, b) = (a as u64, b as u64);
                        StackValue::I8((if divide { a / b } else { a % b }) as i64)
                    }
                    (StackValue::I8(a), StackValue::I8(b)) => {
                        if a == i64::MIN && b == -1 {
                            return Ok(Outcome::Throws("OverflowException"));
                        }
                        StackValue::I8(if divide { a / b } else { a % b })
                    }
                    _ => return Err(format!("{m} over mixed widths")),
                };
                stack.push(result);
            }
            "add.ovf" | "add.ovf.un" | "sub.ovf" | "sub.ovf.un" | "mul.ovf" | "mul.ovf.un" => {
                let (b, a) = (pop()?, pop()?);
                let unsigned = short.ends_with(".un");
                let (width, a, b) = match (a, b) {
                    (StackValue::I4(_), StackValue::I4(_)) => (32u32, a, b),
                    (StackValue::I8(_), StackValue::I8(_)) => (64, a, b),
                    _ => return Err(format!("{m} over mixed widths")),
                };
                let (a, b) = (checked_source(a, unsigned), checked_source(b, unsigned));
                // Exact in 128 bits, except a product of two 64-bit values past it, which
                // overflows every target anyway.
                let exact = match short.get(..3) {
                    Some("add") => a.checked_add(b),
                    Some("sub") => a.checked_sub(b),
                    _ => a.checked_mul(b),
                };
                let target = match (width, unsigned) {
                    (32, false) => "i4",
                    (32, true) => "u4",
                    (_, false) => "i8",
                    (_, true) => "u8",
                };
                match exact.and_then(|exact| checked_target(exact, target)) {
                    Some(value) => stack.push(value),
                    None => return Ok(Outcome::Throws("OverflowException")),
                }
            }
            _ if m.starts_with("conv.ovf.") => {
                let value = pop()?;
                let rest = m.strip_prefix("conv.ovf.").unwrap_or_default();
                let (target, unsigned) = match rest.strip_suffix(".un") {
                    Some(target) => (target, true),
                    None => (rest, false),
                };
                match checked_target(checked_source(value, unsigned), target) {
                    Some(value) => stack.push(value),
                    None => return Ok(Outcome::Throws("OverflowException")),
                }
            }
            "not" | "neg" => {
                let value = pop()?;
                stack.push(match (short, value) {
                    ("not", StackValue::I4(v)) => StackValue::I4(!v),
                    ("not", StackValue::I8(v)) => StackValue::I8(!v),
                    (_, StackValue::I4(v)) => StackValue::I4(v.wrapping_neg()),
                    (_, StackValue::I8(v)) => StackValue::I8(v.wrapping_neg()),
                });
            }
            "shl" | "shr" | "shr.un" => {
                let StackValue::I4(amount) = pop()? else {
                    return Err(format!("{m} count is not an int32"));
                };
                let amount = amount as u32;
                let value = pop()?;
                stack.push(match value {
                    StackValue::I4(v) if amount < 32 => StackValue::I4(match short {
                        "shl" => v << amount,
                        "shr" => v >> amount,
                        _ => ((v as u32) >> amount) as i32,
                    }),
                    StackValue::I8(v) if amount < 64 => StackValue::I8(match short {
                        "shl" => v << amount,
                        "shr" => v >> amount,
                        _ => ((v as u64) >> amount) as i64,
                    }),
                    _ => return Err(format!("{m} by {amount}, which CIL leaves unspecified")),
                });
            }
            _ if m.starts_with("conv.") => {
                let value = pop()?;
                let bits = value.bits();
                stack.push(match m {
                    "conv.i1" => StackValue::I4(i32::from(bits as i8)),
                    "conv.u1" => StackValue::I4(i32::from(bits as u8)),
                    "conv.i2" => StackValue::I4(i32::from(bits as i16)),
                    "conv.u2" => StackValue::I4(i32::from(bits as u16)),
                    "conv.i4" | "conv.u4" => StackValue::I4(bits as i32),
                    "conv.i8" => StackValue::I8(bits),
                    "conv.u8" => StackValue::I8(match value {
                        StackValue::I4(v) => i64::from(v as u32),
                        StackValue::I8(v) => v,
                    }),
                    other => return Err(format!("unmodeled {other}")),
                });
            }
            "ret" => return pop().map(Outcome::Value),
            "nop" => {}
            other => return Err(format!("unmodeled {other}")),
        }
    }
    Err("fell off the end".into())
}

/// A deterministic xorshift64* stream.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap_or(0)
    }

    fn pick<'v, V>(&mut self, values: &'v [V]) -> &'v V {
        &values[self.below(values.len())]
    }
}

/// The two evaluation-stack kinds the generator tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    I4,
    I8,
}

/// The stack kind a slot of type `ty` loads as.
fn kind_of(ty: &SsaType) -> Kind {
    match ty {
        SsaType::I64 | SsaType::U64 => Kind::I8,
        _ => Kind::I4,
    }
}

/// One generated method: its CIL, a readable listing, its slot types and its inputs.
struct Program {
    bytecode: Vec<u8>,
    listing: Vec<String>,
    arg_types: Vec<SsaType>,
    local_types: Vec<SsaType>,
    inputs: Vec<Vec<StackValue>>,
}

impl Program {
    /// The local types keyed by slot, as the interpreter takes them.
    fn locals(&self) -> BTreeMap<u16, SsaType> {
        (0u16..)
            .zip(self.local_types.iter().cloned())
            .collect::<BTreeMap<_, _>>()
    }
}

/// Emits CIL while recording a listing of it.
struct Emitter {
    asm: InstructionAssembler,
    listing: Vec<String>,
}

impl Emitter {
    fn op(&mut self, name: &str) {
        let asm = &mut self.asm;
        match name {
            "add" => asm.add(),
            "sub" => asm.sub(),
            "mul" => asm.mul(),
            "and" => asm.and(),
            "or" => asm.or(),
            "xor" => asm.xor(),
            "not" => asm.not(),
            "neg" => asm.neg(),
            "shl" => asm.shl(),
            "shr" => asm.shr(),
            "shr.un" => asm.shr_un(),
            "ceq" => asm.ceq(),
            "cgt" => asm.cgt(),
            "cgt.un" => asm.cgt_un(),
            "clt" => asm.clt(),
            "clt.un" => asm.clt_un(),
            "conv.i1" => asm.conv_i1(),
            "conv.u1" => asm.conv_u1(),
            "conv.i2" => asm.conv_i2(),
            "conv.u2" => asm.conv_u2(),
            "conv.i4" => asm.conv_i4(),
            "conv.u4" => asm.conv_u4(),
            "conv.i8" => asm.conv_i8(),
            "conv.u8" => asm.conv_u8(),
            "div" => asm.div(),
            "div.un" => asm.div_un(),
            "rem" => asm.rem(),
            "rem.un" => asm.rem_un(),
            "add.ovf" => asm.add_ovf(),
            "add.ovf.un" => asm.add_ovf_un(),
            "sub.ovf" => asm.sub_ovf(),
            "sub.ovf.un" => asm.sub_ovf_un(),
            "mul.ovf" => asm.mul_ovf(),
            "mul.ovf.un" => asm.mul_ovf_un(),
            "ret" => asm.ret(),
            other => panic!("the emitter has no {other}"),
        }
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        self.listing.push(name.to_string());
    }

    /// `conv.ovf.<target>`, `.un` when `unsigned`.
    fn conv_ovf(&mut self, target: &str, unsigned: bool) {
        let code: u16 = match (target, unsigned) {
            ("i1", false) => 0xB3,
            ("u1", false) => 0xB4,
            ("i2", false) => 0xB5,
            ("u2", false) => 0xB6,
            ("i4", false) => 0xB7,
            ("u4", false) => 0xB8,
            ("i8", false) => 0xB9,
            ("u8", false) => 0xBA,
            ("i1", true) => 0x82,
            ("i2", true) => 0x83,
            ("i4", true) => 0x84,
            ("i8", true) => 0x85,
            ("u1", true) => 0x86,
            ("u2", true) => 0x87,
            ("u4", true) => 0x88,
            _ => 0x89,
        };
        self.asm.emit_opcode(code, None).unwrap();
        self.listing.push(format!(
            "conv.ovf.{target}{}",
            if unsigned { ".un" } else { "" }
        ));
    }

    fn label(&mut self, name: &str) {
        self.asm.label(name).unwrap();
        self.listing.push(format!("{name}:"));
    }

    fn brtrue(&mut self, name: &str) {
        self.asm.brtrue(name).unwrap();
        self.listing.push(format!("brtrue {name}"));
    }

    fn br(&mut self, name: &str) {
        self.asm.br(name).unwrap();
        self.listing.push(format!("br {name}"));
    }

    fn starg(&mut self, at: usize) {
        self.asm.starg_s(u8::try_from(at).unwrap()).unwrap();
        self.listing.push(format!("starg {at}"));
    }

    fn ldarg(&mut self, at: usize) {
        self.asm.ldarg_s(u8::try_from(at).unwrap()).unwrap();
        self.listing.push(format!("ldarg {at}"));
    }

    fn ldloc(&mut self, at: usize) {
        self.asm.ldloc_s(u8::try_from(at).unwrap()).unwrap();
        self.listing.push(format!("ldloc {at}"));
    }

    fn stloc(&mut self, at: usize) {
        self.asm.stloc_s(u8::try_from(at).unwrap()).unwrap();
        self.listing.push(format!("stloc {at}"));
    }

    fn ldc_i4(&mut self, value: i32) {
        self.asm.ldc_i4(value).unwrap();
        self.listing.push(format!("ldc.i4 {value:#x}"));
    }

    fn ldc_i8(&mut self, value: i64) {
        self.asm.ldc_i8(value).unwrap();
        self.listing.push(format!("ldc.i8 {value:#x}"));
    }

    /// Converts the top of the stack from `from` to `to`, widening by a random signedness.
    fn convert_kind(&mut self, from: Kind, to: Kind, rng: &mut Stream) {
        match (from, to) {
            (Kind::I4, Kind::I8) if rng.below(2) == 0 => self.op("conv.i8"),
            (Kind::I4, Kind::I8) => self.op("conv.u8"),
            (Kind::I8, Kind::I4) => self.op("conv.i4"),
            _ => {}
        }
    }
}

/// Pushes one value of `kind` for an arm of a join: an argument of that kind when one has it
/// (a narrow one merged with whatever the other arm pushes), or a constant.
fn join_arm(
    out: &mut Emitter,
    rng: &mut Stream,
    kind: Kind,
    arg_types: &[SsaType],
    (consts4, consts8): (&[i32], &[i64]),
) {
    let fitting: Vec<usize> = (0..arg_types.len())
        .filter(|at| kind_of(&arg_types[*at]) == kind)
        .collect();
    if !fitting.is_empty() && rng.below(3) > 0 {
        out.ldarg(*rng.pick(&fitting));
    } else if kind == Kind::I8 {
        out.ldc_i8(*rng.pick(consts8));
    } else {
        out.ldc_i4(*rng.pick(consts4));
    }
}

/// A random integer method over mixed-width arguments and locals: small integers loaded,
/// stored and computed as `int32`, conversions to every width, checked and unchecked,
/// shifts by in-range counts, division, checked arithmetic, comparisons, joins of two
/// values, and 64-bit values beside them.
fn random_program(rng: &mut Stream) -> Program {
    let arg_pool = [
        SsaType::I8,
        SsaType::U8,
        SsaType::I16,
        SsaType::U16,
        SsaType::I32,
        SsaType::U32,
        SsaType::I64,
        SsaType::U64,
        SsaType::Char,
        SsaType::Bool,
    ];
    // A `bool` local only ever holds 0 or 1, which the generator cannot promise.
    let local_pool = [
        SsaType::I8,
        SsaType::U8,
        SsaType::I16,
        SsaType::U16,
        SsaType::I32,
        SsaType::U32,
        SsaType::I64,
        SsaType::U64,
        SsaType::Char,
    ];
    let consts4 = [
        0,
        1,
        -1,
        2,
        7,
        8,
        15,
        16,
        24,
        31,
        0x7F,
        0x80,
        0xFF,
        0x100,
        0x7FFF,
        0x8000,
        0xFFFF,
        0x1_0000,
        0xFF00,
        i32::MIN,
        i32::MAX,
        0x5555_5555,
    ];
    let consts8 = [
        0i64,
        1,
        -1,
        0xFF,
        0xFFFF,
        0xFFFF_FFFF,
        0x8000_0000,
        1 << 32,
        i64::MIN,
        i64::MAX,
        0x00FF_00FF_00FF_00FF,
    ];
    let arg_types: Vec<SsaType> = (0..1 + rng.below(3))
        .map(|_| rng.pick(&arg_pool).clone())
        .collect();
    let local_types: Vec<SsaType> = (0..rng.below(3))
        .map(|_| rng.pick(&local_pool).clone())
        .collect();
    let mut out = Emitter {
        asm: InstructionAssembler::new(),
        listing: Vec::new(),
    };
    let mut stack: Vec<Kind> = Vec::new();
    let mut written: Vec<usize> = Vec::new();
    let mut labels = 0usize;
    for _ in 0..3 + rng.below(14) {
        let choice = rng.below(17);
        if stack.len() < 2 || choice < 3 {
            match rng.below(8) {
                0..=4 => {
                    let at = rng.below(arg_types.len());
                    out.ldarg(at);
                    stack.push(kind_of(&arg_types[at]));
                }
                5 if !written.is_empty() => {
                    let at = *rng.pick(&written);
                    out.ldloc(at);
                    stack.push(kind_of(&local_types[at]));
                }
                5 | 6 => {
                    out.ldc_i4(*rng.pick(&consts4));
                    stack.push(Kind::I4);
                }
                _ => {
                    out.ldc_i8(*rng.pick(&consts8));
                    stack.push(Kind::I8);
                }
            }
            continue;
        }
        let top = *stack.last().unwrap();
        match choice {
            // A store into a local and a load of it back: the store truncates.
            3 if !local_types.is_empty() => {
                let at = rng.below(local_types.len());
                out.convert_kind(top, kind_of(&local_types[at]), rng);
                out.stloc(at);
                out.ldloc(at);
                if !written.contains(&at) {
                    written.push(at);
                }
                *stack.last_mut().unwrap() = kind_of(&local_types[at]);
            }
            3..=5 => {
                let op = *rng.pick(&[
                    "not", "neg", "conv.i1", "conv.u1", "conv.i2", "conv.u2", "conv.i4", "conv.u4",
                    "conv.i8", "conv.u8",
                ]);
                out.op(op);
                *stack.last_mut().unwrap() = match op {
                    "not" | "neg" => top,
                    "conv.i8" | "conv.u8" => Kind::I8,
                    _ => Kind::I4,
                };
            }
            8 => {
                let target = *rng.pick(&["i1", "u1", "i2", "u2", "i4", "u4", "i8", "u8"]);
                out.conv_ovf(target, rng.below(2) == 0);
                *stack.last_mut().unwrap() = if target.ends_with('8') {
                    Kind::I8
                } else {
                    Kind::I4
                };
            }
            // Two values of one kind joined: the one on top decides which.
            11 => {
                stack.pop();
                let kind = if rng.below(4) == 0 {
                    Kind::I8
                } else {
                    Kind::I4
                };
                let (taken, join) = (format!("taken{labels}"), format!("join{labels}"));
                labels += 1;
                out.brtrue(&taken);
                join_arm(&mut out, rng, kind, &arg_types, (&consts4, &consts8));
                out.br(&join);
                out.label(&taken);
                join_arm(&mut out, rng, kind, &arg_types, (&consts4, &consts8));
                out.label(&join);
                stack.push(kind);
            }
            // A store into an argument and a load of it back. A `bool` argument holds 0 or 1,
            // which the generator cannot promise.
            12 if arg_types.iter().any(|ty| *ty != SsaType::Bool) => {
                let at = loop {
                    let at = rng.below(arg_types.len());
                    if arg_types[at] != SsaType::Bool {
                        break at;
                    }
                };
                out.convert_kind(top, kind_of(&arg_types[at]), rng);
                out.starg(at);
                out.ldarg(at);
                *stack.last_mut().unwrap() = kind_of(&arg_types[at]);
            }
            6 | 7 => {
                let width: i32 = if top == Kind::I8 { 64 } else { 32 };
                if rng.below(3) > 0 {
                    out.ldc_i4(i32::try_from(rng.below(width as usize)).unwrap());
                } else {
                    let at = rng.below(arg_types.len());
                    out.ldarg(at);
                    out.convert_kind(kind_of(&arg_types[at]), Kind::I4, rng);
                    out.ldc_i4(width - 1);
                    out.op("and");
                }
                out.op(rng.pick(&["shl", "shr", "shr.un"]));
            }
            _ => {
                let second = stack[stack.len() - 2];
                out.convert_kind(top, second, rng);
                let op = match choice {
                    9 => *rng.pick(&["div", "div.un", "rem", "rem.un"]),
                    10 => *rng.pick(&[
                        "add.ovf",
                        "add.ovf.un",
                        "sub.ovf",
                        "sub.ovf.un",
                        "mul.ovf",
                        "mul.ovf.un",
                    ]),
                    _ => *rng.pick(&[
                        "add", "sub", "mul", "and", "or", "xor", "and", "or", "ceq", "cgt",
                        "cgt.un", "clt", "clt.un",
                    ]),
                };
                out.op(op);
                stack.pop();
                *stack.last_mut().unwrap() = if op.starts_with('c') {
                    Kind::I4
                } else {
                    second
                };
            }
        }
    }
    if stack.is_empty() {
        out.ldarg(0);
        stack.push(kind_of(&arg_types[0]));
    }
    while stack.len() > 1 {
        let top = stack.pop().unwrap();
        let second = *stack.last().unwrap();
        out.convert_kind(top, second, rng);
        out.op(rng.pick(&["add", "xor", "or", "sub"]));
    }
    out.op("ret");
    let (bytecode, _, _) = out.asm.finish().unwrap();
    let input = |rng: &mut Stream, ty: &SsaType| {
        let raw = match rng.below(6) {
            0 => 0,
            1 => -1,
            2 => 1,
            3 => i64::MIN,
            4 => i64::MAX,
            _ => rng.next() as i64,
        };
        let raw = if *ty == SsaType::Bool { raw & 1 } else { raw };
        through_slot(ty, StackValue::I8(raw))
    };
    let inputs = (0..8)
        .map(|_| arg_types.iter().map(|ty| input(rng, ty)).collect())
        .collect();
    Program {
        bytecode,
        listing: out.listing,
        arg_types,
        local_types,
        inputs,
    }
}

/// The value passes the deobfuscation pipeline schedules, in its order.
fn value_passes() -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
    vec![
        Box::new(AsSsaPass(OpaquePredicatePass::new())),
        Box::new(AsSsaPass(ValueRangePropagationPass::new())),
        Box::new(AsSsaPass(ControlFlowSimplificationPass)),
        Box::new(AsSsaPass(JumpThreadingPass::new())),
        Box::new(AsSsaPass(DeadCodeEliminationPass)),
        Box::new(AsSsaPass(BlockMergingPass)),
        Box::new(AsSsaPass(LicmPass::new())),
        Box::new(AsSsaPass(ReassociationPass::new())),
        Box::new(ConstantPropagationPass),
        Box::new(AsSsaPass(GlobalValueNumberingPass::new())),
        Box::new(CopyPropagationPass),
        Box::new(AsSsaPass(MemoryOptimizationPass)),
        Box::new(AsSsaPass(StrengthReductionPass::new())),
        Box::new(AsSsaPass(AlgebraicSimplificationPass::new())),
    ]
}

/// A constant whose value is an integer of another width than its variable's type, which code
/// generation loads as the value's width: `int64` 51 in an `int32` shift count. A truth value
/// is left out, whose 0 or 1 any integer states.
fn mistyped_constant(ssa: &SsaFunction) -> Option<String> {
    ssa.blocks()
        .iter()
        .flat_map(|block| block.instructions())
        .find_map(|instr| {
            let SsaOp::Const { dest, value } = instr.op() else {
                return None;
            };
            let (_, width) = value.integer_pattern(PointerSize::Bit64)?;
            let ty = ssa.variable(*dest)?.var_type().clone();
            let declared = CilTarget::bit_width(&ty).filter(|_| CilTarget::is_integer(&ty))?;
            (ty != SsaType::Bool && declared != width)
                .then(|| format!("{dest} = {value:?} is held in a {ty:?}:\n{ssa}"))
        })
}

/// Regenerates `ssa`, returning the body and the type of each local it declares.
fn regenerate(ssa: &SsaFunction) -> Result<(Vec<u8>, BTreeMap<u16, SsaType>), String> {
    let mut generator = SsaCodeGenerator::new();
    let (bytecode, _, _) = generator.generate(ssa).map_err(|e| e.to_string())?;
    Ok((bytecode, generator.local_types().clone()))
}

/// Lifts a generated method with its slots typed.
fn lift(program: &Program) -> Result<SsaFunction, String> {
    let blocks = decode_blocks(&program.bytecode, 0, 0x1000, Some(program.bytecode.len()))
        .map_err(|e| e.to_string())?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks).map_err(|e| e.to_string())?;
    let types = TestTypeProvider::typed(program.arg_types.clone(), program.local_types.clone());
    build_ssa(&cfg, &types).map_err(|e| e.to_string())
}

/// What each input of `program` computes run as `bytecode` with `locals`.
fn outcomes(
    program: &Program,
    bytecode: &[u8],
    locals: &BTreeMap<u16, SsaType>,
) -> Vec<Result<Outcome, String>> {
    program
        .inputs
        .iter()
        .map(|args| run(bytecode, args, &program.arg_types, locals))
        .collect()
}

/// Every random mixed-width method computes, regenerated with and without the value passes,
/// what its CIL computes.
#[test]
fn mixed_width_integer_code_survives_lifting_passes_and_regeneration() {
    let cases: usize = std::env::var("DIFFERENTIAL_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(4000);
    let seed: u64 = std::env::var("DIFFERENTIAL_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let passes = value_passes();
    let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
    ctx.set_assembly(test_assembly_arc());
    let method = MethodRef::new(Token::new(0x0600_0001));
    let mut rng = Stream(seed);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut examples: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut note = |kind: String, example: String| {
        *counts.entry(kind.clone()).or_default() += 1;
        let list = examples.entry(kind).or_default();
        list.push(example);
        list.sort_by_key(String::len);
        list.truncate(3);
    };
    for case in 0..cases {
        let program = random_program(&mut rng);
        let describe = |detail: &str| {
            format!(
                "case {case}: args {:?} locals {:?}\n  {}\n  inputs {:?}\n{detail}",
                program.arg_types,
                program.local_types,
                program.listing.join("; "),
                program.inputs
            )
        };
        let expected = outcomes(&program, &program.bytecode, &program.locals());
        if let Some(Err(error)) = expected.iter().find(|outcome| outcome.is_err()) {
            note("the reference does not run".into(), describe(error));
            continue;
        }
        let ssa = match lift(&program) {
            Ok(ssa) => ssa,
            Err(error) => {
                note("the lift fails".into(), describe(&error));
                continue;
            }
        };
        match regenerate(&ssa) {
            Ok((bytecode, locals)) => {
                let got = outcomes(&program, &bytecode, &locals);
                if got != expected {
                    note(
                        "MISCOMPILE: code generation".into(),
                        describe(&format!("  expected {expected:?}\n  got {got:?}\n{ssa}")),
                    );
                    continue;
                }
            }
            Err(error) => {
                note("code generation refuses the lift".into(), describe(&error));
                continue;
            }
        }
        if let Some(mistyped) = mistyped_constant(&ssa) {
            note("FAILURE: the lift types a constant".into(), mistyped);
        }
        let mut optimised = ssa.clone();
        for _ in 0..3 {
            for pass in &passes {
                if let Err(error) = run_verified(pass.as_ref(), &mut optimised, &method, &ctx) {
                    note(
                        format!("FAILURE: {}", pass.name()),
                        describe(&error.to_string()),
                    );
                } else if let Some(mistyped) = mistyped_constant(&optimised) {
                    note(
                        format!("FAILURE: {} types a constant", pass.name()),
                        mistyped,
                    );
                }
            }
        }
        match regenerate(&optimised) {
            Ok((bytecode, locals)) => {
                let got = outcomes(&program, &bytecode, &locals);
                if got != expected {
                    let culprits: Vec<&str> = passes
                        .iter()
                        .filter(|pass| {
                            let mut alone = ssa.clone();
                            let _ = run_verified(pass.as_ref(), &mut alone, &method, &ctx);
                            regenerate(&alone).is_ok_and(|(bytecode, locals)| {
                                outcomes(&program, &bytecode, &locals) != expected
                            })
                        })
                        .map(|pass| pass.name())
                        .collect();
                    // Where no pass alone breaks it, the first step of the pipeline after
                    // which the result differs, with the function before and after it.
                    let step = if culprits.is_empty() {
                        let mut stepped = ssa.clone();
                        let mut found = String::new();
                        'rounds: for round in 0..3 {
                            for pass in &passes {
                                let before = stepped.clone();
                                let _ = run_verified(pass.as_ref(), &mut stepped, &method, &ctx);
                                if regenerate(&stepped).is_ok_and(|(bytecode, locals)| {
                                    outcomes(&program, &bytecode, &locals) != expected
                                }) {
                                    found = format!(
                                        "FIRST BREAKING STEP: round {round} {}\nBEFORE\n{before}\nAFTER\n{stepped}",
                                        pass.name()
                                    );
                                    break 'rounds;
                                }
                            }
                        }
                        found
                    } else {
                        String::new()
                    };
                    note(
                        format!("MISCOMPILE: {culprits:?}"),
                        describe(&format!(
                            "  expected {expected:?}\n  got {got:?}\nLIFTED\n{ssa}\nOPTIMISED\n{optimised}\n{step}"
                        )),
                    );
                }
            }
            Err(error) => note(
                "code generation refuses the optimised".into(),
                describe(&error),
            ),
        }
    }
    for (kind, list) in &examples {
        eprintln!("==== {kind}: {}", counts[kind]);
        for example in list {
            eprintln!("{example}\n");
        }
    }
    let defects: Vec<(&String, &usize)> = counts
        .iter()
        .filter(|(kind, _)| {
            kind.starts_with("MISCOMPILE")
                || kind.starts_with("FAILURE")
                || kind.as_str() == "the lift fails"
        })
        .collect();
    assert!(defects.is_empty(), "{defects:#?}\nall: {counts:#?}");
}

/// A join of a `bool` and a `byte` constant 255, read through `conv.i1`, keeps its 255: the
/// phi narrowing reads the `bool`'s widening as no narrow integer to narrow the join to, so
/// the join is never typed as a truth value holding 255.
#[test]
fn a_join_of_a_truth_value_and_a_byte_keeps_the_byte() {
    let mut out = Emitter {
        asm: InstructionAssembler::new(),
        listing: Vec::new(),
    };
    out.ldarg(1);
    out.ldarg(0);
    out.brtrue("taken");
    out.ldc_i4(0xFF);
    out.br("join");
    out.label("taken");
    out.ldarg(0);
    out.label("join");
    out.op("conv.i1");
    out.op("conv.i8");
    out.op("sub");
    out.op("ret");
    let (bytecode, _, _) = out.asm.finish().unwrap();
    let program = Program {
        bytecode,
        listing: out.listing,
        arg_types: vec![SsaType::Bool, SsaType::I64],
        local_types: vec![],
        inputs: vec![
            vec![StackValue::I4(0), StackValue::I8(10)],
            vec![StackValue::I4(1), StackValue::I8(10)],
        ],
    };
    let expected = outcomes(&program, &program.bytecode, &BTreeMap::new());
    assert_eq!(
        expected,
        vec![
            Ok(Outcome::Value(StackValue::I8(11))),
            Ok(Outcome::Value(StackValue::I8(9)))
        ]
    );
    let ssa = lift(&program).unwrap();
    let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
    ctx.set_assembly(test_assembly_arc());
    let method = MethodRef::new(Token::new(0x0600_0001));
    let mut optimised = ssa.clone();
    for _ in 0..3 {
        for pass in value_passes() {
            run_verified(pass.as_ref(), &mut optimised, &method, &ctx).unwrap();
        }
    }
    for phi in optimised
        .blocks()
        .iter()
        .flat_map(|block| block.phi_nodes())
    {
        let ty = optimised
            .variable(phi.result())
            .map(|v| v.var_type().clone());
        assert_ne!(
            ty,
            Some(SsaType::Bool),
            "the join is no truth value:\n{optimised}"
        );
    }
    let (bytecode, locals) = regenerate(&optimised).unwrap();
    assert_eq!(
        outcomes(&program, &bytecode, &locals),
        expected,
        "{optimised}"
    );
}

/// `-1L < (long)flag` is true for either truth value. Narrowed to the `bool`'s width, its -1 would
/// be a `bool` constant holding 255, which no truth value is: the comparison stays as it is read.
#[test]
fn a_comparison_with_a_widened_truth_value_keeps_its_constant() {
    let mut out = Emitter {
        asm: InstructionAssembler::new(),
        listing: Vec::new(),
    };
    out.ldc_i8(-1);
    out.ldarg(0);
    out.op("conv.i8");
    out.op("clt");
    out.op("ret");
    let (bytecode, _, _) = out.asm.finish().unwrap();
    let program = Program {
        bytecode,
        listing: out.listing,
        arg_types: vec![SsaType::Bool],
        local_types: vec![],
        inputs: vec![vec![StackValue::I4(0)], vec![StackValue::I4(1)]],
    };
    let expected = outcomes(&program, &program.bytecode, &BTreeMap::new());
    assert_eq!(
        expected,
        vec![
            Ok(Outcome::Value(StackValue::I4(1))),
            Ok(Outcome::Value(StackValue::I4(1)))
        ]
    );
    let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
    ctx.set_assembly(test_assembly_arc());
    let method = MethodRef::new(Token::new(0x0600_0001));
    let mut optimised = lift(&program).unwrap();
    let pass = AsSsaPass(AlgebraicSimplificationPass::new());
    for _ in 0..3 {
        run_verified(&pass, &mut optimised, &method, &ctx).unwrap();
    }
    let (bytecode, locals) = regenerate(&optimised).unwrap();
    assert_eq!(
        outcomes(&program, &bytecode, &locals),
        expected,
        "{optimised}"
    );
}

/// `char c = 91` stored as `ldc.i4 91; stloc` keeps no conversion: the `int32` 91 is the stack
/// form of the `char` 91, so the copy the store lifts to changes nothing. 70000 is no `char`,
/// and is truncated, to 4464.
#[test]
fn a_copy_of_a_constant_in_the_narrow_range_needs_no_conversion() {
    for (constant, converts, returned) in [(91, false, 91), (70000, true, 4464)] {
        let mut out = Emitter {
            asm: InstructionAssembler::new(),
            listing: Vec::new(),
        };
        out.ldc_i4(constant);
        out.stloc(0);
        out.ldloc(0);
        out.op("ret");
        let (bytecode, _, _) = out.asm.finish().unwrap();
        let program = Program {
            bytecode,
            listing: out.listing,
            arg_types: vec![],
            local_types: vec![SsaType::Char],
            inputs: vec![vec![]],
        };
        let ssa = lift(&program).unwrap();
        let (bytecode, locals) = regenerate(&ssa).unwrap();
        let conversions = decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len()))
            .unwrap()
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|instr| instr.mnemonic.starts_with("conv"))
            .count();
        assert_eq!(conversions > 0, converts, "{constant}:\n{ssa}");
        assert_eq!(
            outcomes(&program, &bytecode, &locals),
            vec![Ok(Outcome::Value(StackValue::I4(returned)))],
            "{constant}:\n{ssa}"
        );
    }
}

/// A branch on a constant folds to a jump, and the join it no longer reaches by the dropped edge
/// keeps no phi operand for it: the SSA stays valid, and the method computes what it did. Here
/// `brfalse` on 1 falls through, and its edge to the join, which merges the argument left on the
/// stack with the 5 the fall-through pushes, is dropped.
#[test]
fn a_folded_branch_keeps_no_phi_operand_for_its_dropped_edge() {
    let mut out = Emitter {
        asm: InstructionAssembler::new(),
        listing: Vec::new(),
    };
    out.ldarg(0);
    out.ldc_i4(1);
    out.asm.brfalse("join").unwrap();
    out.asm.pop().unwrap();
    out.ldc_i4(5);
    out.label("join");
    out.op("ret");
    let (bytecode, _, _) = out.asm.finish().unwrap();
    let program = Program {
        bytecode,
        listing: out.listing,
        arg_types: vec![SsaType::I32],
        local_types: vec![],
        inputs: vec![vec![StackValue::I4(5)]],
    };
    let expected = outcomes(&program, &program.bytecode, &BTreeMap::new());
    let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
    ctx.set_assembly(test_assembly_arc());
    let method = MethodRef::new(Token::new(0x0600_0001));
    let mut optimised = lift(&program).unwrap();
    assert!(
        optimised
            .blocks()
            .iter()
            .any(|block| !block.phi_nodes().is_empty()),
        "the two arms join at a phi:\n{optimised}"
    );
    run_verified(&ConstantPropagationPass, &mut optimised, &method, &ctx)
        .expect("the folded branch leaves valid SSA");
    let (bytecode, locals) = regenerate(&optimised).unwrap();
    assert_eq!(
        outcomes(&program, &bytecode, &locals),
        expected,
        "{optimised}"
    );
}

/// A constant copied into a `byte` local is folded as a `byte`: `ldc.i4 7; stloc` into a `uint8`
/// local holds the byte 7, not an `int32` that code generation would load at its own width.
#[test]
fn a_constant_folded_into_a_narrow_local_is_of_its_type() {
    let mut out = Emitter {
        asm: InstructionAssembler::new(),
        listing: Vec::new(),
    };
    out.ldc_i4(7);
    out.stloc(0);
    out.ldloc(0);
    out.ldarg(0);
    out.op("add");
    out.op("ret");
    let (bytecode, _, _) = out.asm.finish().unwrap();
    let program = Program {
        bytecode,
        listing: out.listing,
        arg_types: vec![SsaType::I32],
        local_types: vec![SsaType::U8],
        inputs: vec![vec![StackValue::I4(1)]],
    };
    let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
    ctx.set_assembly(test_assembly_arc());
    let method = MethodRef::new(Token::new(0x0600_0001));
    let mut optimised = lift(&program).unwrap();
    run_verified(&ConstantPropagationPass, &mut optimised, &method, &ctx).unwrap();
    assert_eq!(mistyped_constant(&optimised), None);
    let bytes: Vec<ConstValue> = optimised
        .variables()
        .iter()
        .filter(|v| *v.var_type() == SsaType::U8)
        .filter_map(|v| match optimised.get_definition(v.id()) {
            Some(SsaOp::Const { value, .. }) => Some(value.clone()),
            _ => None,
        })
        .collect();
    assert!(!bytes.is_empty(), "the local's version folds:\n{optimised}");
    assert!(
        bytes.iter().all(|value| *value == ConstValue::U8(7)),
        "{optimised}"
    );
}

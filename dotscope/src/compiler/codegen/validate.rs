//! Translation validation: generated CIL checked against the SSA it came from.
//!
//! The code generator decides an emission order, which values stay on the
//! evaluation stack, which local or argument slot each value lives in, and where
//! the copies that leave SSA go. A wrong decision in any of them is a program
//! that computes something else, and nothing downstream notices: the encoder
//! checks only stack depths, and the bytes are valid CIL.
//!
//! This module checks the result instead of trusting the decisions. It runs an
//! abstract interpretation of the emitted CIL in which every stack entry, local
//! and argument holds the set of SSA values it is known to be equal to, and it
//! asks, wherever an instruction implements an SSA operation, whether the
//! operands on the stack are the ones the SSA names. It uses only the SSA, the
//! emitted bytes, the exception clauses, the layout (which emitted range is
//! which SSA block) and, for each emitted instruction, the SSA instruction it
//! implements. It does not reuse the scheduler, the slot allocation or any
//! liveness, so a defect in them cannot hide itself here.
//!
//! # What it checks
//!
//! - **Value flow.** Every operand an SSA instruction reads is, when the
//!   instruction runs, the value the SSA names: not a stale value of a slot that
//!   was overwritten, not a never-written local, not another value that happened
//!   to share the slot.
//! - **Effect order.** Within a block, every instruction that is not pure is
//!   emitted in SSA order, and each exactly once.
//! - **Storage width.** A value stored into a local or argument narrower than
//!   four bytes is one the SSA itself gives that type; otherwise the store
//!   truncates it.
//!
//! What it does not check is whether an instruction's spelling computes its
//! operation (which `conv` a conversion chose, how a rotate was expanded); that
//! is per-operation, and is tested per operation.
//!
//! # The model
//!
//! A value is identified by its copy class: a `Copy` makes its destination the
//! same value as its source, so both are named by the root of the copy chain.
//! In strict SSA that is sound: every use of a copy is dominated by the copy,
//! so its source cannot be redefined between the copy and the use without the
//! copy running again.
//!
//! When an operation runs, the value it defines starts a new dynamic instance,
//! so every place still holding the previous instance forgets it before the new
//! one is recorded. Phi results are established on control-flow edges: entering
//! an SSA block from a predecessor, every place holding the predecessor's
//! operand also holds the phi's result. A throw reaches a handler with whatever
//! the places hold at the throwing instruction; a handler phi is the version of
//! its variable current there, in SSA order.
//!
//! Locals start zero-initialized, so a never-written local holds the entry value
//! of any local and nothing else.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

use analyssa::ir::ops::SsaEffectKind;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp, SsaType, SsaVarId, VariableOrigin},
    assembly::{decode_stream, Immediate, Instruction, Operand},
    compiler::codegen::{LayoutEntry, SsaCodeGenerator},
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags, Method},
        signatures::TypeSignature,
    },
    Error, Parser, Result,
};

/// The SSA instruction a run of emitted instructions implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpTag {
    /// The SSA block.
    pub block: usize,
    /// The instruction's index within the block.
    pub instr: usize,
}

/// Emitted instructions `[start, end)`, by index in the finished body, that
/// implement one SSA instruction.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EmitGroup {
    /// Index of the first instruction.
    pub start: usize,
    /// Index one past the last instruction.
    pub end: usize,
    /// What they implement.
    pub tag: OpTag,
}

/// Everything the validator reads.
pub(crate) struct Validation<'a> {
    /// The SSA the body was generated from.
    pub ssa: &'a SsaFunction,
    /// The finished bytecode.
    pub bytecode: &'a [u8],
    /// The exception clauses, at bytecode offsets.
    pub handlers: &'a [ExceptionHandler],
    /// Every layout entry with its offset in the finished body.
    pub layout: &'a [(LayoutEntry, u32)],
    /// The tagged runs, in the order they were recorded. A run recorded first
    /// owns an instruction a later run also covers, so a run nested inside
    /// another (a constant materialised while a terminator stores its phi
    /// operands) claims its own instructions.
    pub groups: &'a [EmitGroup],
    /// Each local slot's declared type, by slot; `None` for a byref slot or one
    /// whose type is not known, which the store-width check then skips.
    pub locals: &'a [Option<TypeSignature>],
}

/// Validates a generated body against its SSA.
///
/// # Errors
///
/// Returns [`Error::CodegenFailed`] naming the offset and the disagreement when
/// the body reads a value other than the one the SSA names, reorders or drops an
/// effect, or truncates a value into a narrow slot. Returns a decoding error if
/// the bytecode does not decode.
pub(crate) fn validate(input: &Validation<'_>) -> Result<()> {
    let instructions = decode_stream(&mut Parser::new(input.bytecode), 0)?;
    validate_instructions(input, &instructions)
}

/// [`validate`] over a body already decoded, with offsets relative to its
/// start.
fn validate_instructions(input: &Validation<'_>, instructions: &[Instruction]) -> Result<()> {
    if instructions.is_empty() {
        return Ok(());
    }
    let facts = SsaFacts::of(input.ssa);
    let body = Body::of(input, instructions)?;
    check_effect_order(instructions, &facts, &body)?;
    let mut interpreter = Interpreter::new(input, instructions, &facts, &body)?;
    interpreter.run()
}

/// Checks a method's own IL against the SSA lifted from it.
///
/// The same check the code generator applies to its output, applied to the
/// input: every instruction the lift turned into an operation is that
/// operation's emitted code. A method that fails it was lifted to SSA that does
/// not compute what its IL does - or the check is wrong - so this is both a
/// translation check of the lift and the control the generator's own check is
/// calibrated against.
///
/// # Arguments
///
/// * `ssa` - The SSA [`Method::ssa`] lifted, with no pass run on it.
/// * `method` - The method it was lifted from.
///
/// # Errors
///
/// Returns [`Error::CodegenFailed`] naming the first disagreement, or an error
/// when the method has no decoded body.
pub fn validate_lift(ssa: &SsaFunction, method: &Method) -> Result<()> {
    let blocks = method
        .blocks
        .get()
        .ok_or_else(|| Error::CodegenFailed(format!("{} has no decoded body", method.name)))?;
    let mut instructions: Vec<Instruction> = blocks
        .iter()
        .flat_map(|block| block.instructions.iter().cloned())
        .collect();
    instructions.sort_by_key(|instr| instr.offset);
    instructions.dedup_by_key(|instr| instr.offset);
    // A decoded method names its branch targets by address; the body is
    // checked at offsets from its first instruction, the way the exception
    // table addresses it.
    let base = instructions.first().map_or(0, |instr| instr.offset);
    let by_rva: BTreeMap<u64, u64> = instructions
        .iter()
        .map(|instr| (instr.rva, instr.offset.saturating_sub(base)))
        .collect();
    let by_offset: BTreeMap<u64, u64> = instructions
        .iter()
        .map(|instr| (instr.offset, instr.offset.saturating_sub(base)))
        .collect();
    let targets = || {
        instructions
            .iter()
            .flat_map(|instr| instr.branch_targets.iter())
    };
    let rva_hits = targets().filter(|t| by_rva.contains_key(t)).count();
    let offset_hits = targets().filter(|t| by_offset.contains_key(t)).count();
    let by_address = if rva_hits >= offset_hits {
        by_rva
    } else {
        by_offset
    };
    for instr in &mut instructions {
        instr.offset = instr.offset.saturating_sub(base);
        for target in &mut instr.branch_targets {
            *target = by_address.get(target).copied().unwrap_or(u64::MAX);
        }
    }
    let index_at: BTreeMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(index, instr)| (instr.offset, index))
        .collect();

    // Every lifted operation is the instruction it was lifted from, except a
    // copy: `ldloc`, `ldarg` and `dup` lift to one, and they move a value onto
    // the stack rather than consume it there.
    let mut groups = Vec::new();
    let mut layout = Vec::new();
    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        let mut start: Option<u64> = None;
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            let original = instr.original();
            if original.mnemonic == "synthetic" {
                continue;
            }
            let offset = original.offset.saturating_sub(base);
            start = Some(start.map_or(offset, |start| start.min(offset)));
            if matches!(instr.op(), SsaOp::Copy { .. }) {
                continue;
            }
            if let Some(&index) = index_at.get(&offset) {
                groups.push(EmitGroup {
                    start: index,
                    end: index.saturating_add(1),
                    tag: OpTag {
                        block: block_idx,
                        instr: instr_idx,
                    },
                });
            }
        }
        if let Some(start) = start {
            layout.push((
                LayoutEntry::Block(block_idx),
                u32::try_from(start).unwrap_or(u32::MAX),
            ));
        }
    }

    // A block whose instructions the lift dropped (a `nop` merge point) still
    // starts where its basic block does, and its phis are established there.
    // SSA blocks are the basic blocks, shifted by one when construction split
    // an entry a branch targets; the shift is read off the blocks that kept
    // an instruction.
    let cfg_block_at = |offset: u64| {
        blocks.iter().position(|block| {
            let start = block.offset as u64;
            offset >= start && offset < start.saturating_add(block.size as u64)
        })
    };
    let shift = layout.iter().find_map(|(entry, offset)| match entry {
        LayoutEntry::Block(block) => cfg_block_at(u64::from(*offset).saturating_add(base))
            .and_then(|cfg| block.checked_sub(cfg)),
        LayoutEntry::SplitEdge { .. } => None,
    });
    // Every block starts where its basic block does: a leading instruction
    // the lift dropped (a `nop` a branch targets) is still the block's, and
    // a branch to it enters the block.
    if let Some(shift) = shift {
        let mut placed: BTreeMap<usize, u32> = layout
            .iter()
            .filter_map(|(entry, offset)| match entry {
                LayoutEntry::Block(block) => Some((*block, *offset)),
                LayoutEntry::SplitEdge { .. } => None,
            })
            .collect();
        for block_idx in 0..ssa.blocks().len() {
            let Some(cfg) = block_idx.checked_sub(shift).and_then(|cfg| blocks.get(cfg)) else {
                continue;
            };
            let start = (cfg.offset as u64).saturating_sub(base);
            placed.insert(block_idx, u32::try_from(start).unwrap_or(u32::MAX));
        }
        layout = placed
            .into_iter()
            .map(|(block, offset)| (LayoutEntry::Block(block), offset))
            .collect();
    }

    let handlers = method
        .body
        .get()
        .map(|body| body.exception_handlers.clone())
        .unwrap_or_default();
    let locals: Vec<Option<TypeSignature>> = ssa
        .original_local_types()
        .map(|types| {
            types
                .iter()
                .map(|local| (!local.is_byref).then(|| local.base.clone()))
                .collect()
        })
        .unwrap_or_else(|| vec![None; ssa.num_locals()]);

    validate_instructions(
        &Validation {
            ssa,
            bytecode: &[],
            handlers: &handlers,
            layout: &layout,
            groups: &groups,
            locals: &locals,
        },
        &instructions,
    )
}

/// Builds the failure every check reports.
fn failure(offset: u64, what: impl std::fmt::Display) -> Error {
    Error::CodegenFailed(format!(
        "generated code at IL_{offset:04x} is wrong: {what}"
    ))
}

/// What the validator needs to know about the SSA, computed once.
struct SsaFacts<'a> {
    /// The function.
    ssa: &'a SsaFunction,
    /// Copy-chain root per value index.
    class: Vec<u32>,
    /// Defining instruction per value index, when an instruction defines it.
    def_site: Vec<Option<(usize, usize)>>,
    /// By class root: whether a value is the entry value of a local
    /// (undefined, so the zero-initialised slot) or a constant whose bits are
    /// all zero, which is what such a slot holds.
    local_entry: Vec<bool>,
    /// Entry value classes of each argument.
    arg_entry: BTreeMap<u16, BTreeSet<u32>>,
    /// For each class, whether some member's type is exactly each narrow
    /// type, used by the store-width check.
    class_types: BTreeMap<u32, BTreeSet<Narrow>>,
}

impl<'a> SsaFacts<'a> {
    fn of(ssa: &'a SsaFunction) -> Self {
        let count = ssa.var_id_capacity();
        let mut parent: Vec<Option<usize>> = vec![None; count];
        let mut zero: Vec<usize> = Vec::new();
        let mut fits: Vec<(usize, Vec<Narrow>)> = Vec::new();
        let mut def_site: Vec<Option<(usize, usize)>> = vec![None; count];
        let mut phi_defined = vec![false; count];
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for phi in block.phi_nodes() {
                if let Some(slot) = phi_defined.get_mut(phi.result().index()) {
                    *slot = true;
                }
            }
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for dest in instr.op().defs() {
                    if let Some(slot) = def_site.get_mut(dest.index()) {
                        *slot = Some((block_idx, instr_idx));
                    }
                }
                if let SsaOp::Copy { dest, src } = instr.op() {
                    if let Some(slot) = parent.get_mut(dest.index()) {
                        *slot = Some(src.index());
                    }
                }
                if let SsaOp::Const { dest, value } = instr.op() {
                    if is_zero_bits(value) {
                        zero.push(dest.index());
                    }
                    fits.push((dest.index(), Narrow::holding_constant(value)));
                }
                if let SsaOp::Ceq { dest, .. } | SsaOp::Clt { dest, .. } | SsaOp::Cgt { dest, .. } =
                    instr.op()
                {
                    // A comparison is 0 or 1, which every narrow slot holds.
                    fits.push((dest.index(), Narrow::ALL.to_vec()));
                }
            }
        }

        let class: Vec<u32> = (0..count)
            .map(|index| {
                let mut current = index;
                // A chain is at most as long as the number of values; a cycle
                // (which strict SSA cannot form) stops at the bound.
                for _ in 0..count {
                    match parent.get(current).copied().flatten() {
                        Some(next) if next != current => current = next,
                        _ => break,
                    }
                }
                u32::try_from(current).unwrap_or(u32::MAX)
            })
            .collect();

        // Marked by class: a copy of a zero (`v9 = v2` for a `ldloc` of a
        // slot nothing stored) is that zero too.
        let mut local_entry = vec![false; count];
        let mut mark_entry = |index: usize| {
            let root = class.get(index).map_or(index, |&root| root as usize);
            if let Some(slot) = local_entry.get_mut(root) {
                *slot = true;
            }
        };
        for index in zero {
            mark_entry(index);
        }
        let mut arg_entry: BTreeMap<u16, BTreeSet<u32>> = BTreeMap::new();
        let mut class_types: BTreeMap<u32, BTreeSet<Narrow>> = BTreeMap::new();
        for variable in ssa.variables() {
            let index = variable.id().index();
            let undefined = def_site.get(index).copied().flatten().is_none()
                && !phi_defined.get(index).copied().unwrap_or(false);
            match variable.origin() {
                VariableOrigin::Local(_) if undefined => mark_entry(index),
                VariableOrigin::Argument(arg) if undefined => {
                    if let Some(&root) = class.get(index) {
                        arg_entry.entry(arg).or_default().insert(root);
                    }
                }
                _ => {}
            }
            if let (Some(narrow), Some(&root)) =
                (Narrow::of_ssa(variable.var_type()), class.get(index))
            {
                class_types.entry(root).or_default().insert(narrow);
            }
        }
        // A value whose producer bounds it fits a narrow slot whatever its type
        // says: a constant in range, a comparison.
        for (index, narrows) in fits {
            if let Some(&root) = class.get(index) {
                class_types.entry(root).or_default().extend(narrows);
            }
        }

        Self {
            ssa,
            class,
            def_site,
            local_entry,
            arg_entry,
            class_types,
        }
    }

    /// The class naming `var`.
    fn class_of(&self, var: SsaVarId) -> u32 {
        self.class
            .get(var.index())
            .copied()
            .unwrap_or_else(|| u32::try_from(var.index()).unwrap_or(u32::MAX))
    }

    /// Whether `var` is a local's entry value, or a zero that equals it.
    fn is_local_entry(&self, var: SsaVarId) -> bool {
        self.local_entry
            .get(self.class_of(var) as usize)
            .copied()
            .unwrap_or(false)
    }

    /// The operation at `tag`.
    fn op(&self, tag: OpTag) -> Option<&'a SsaOp> {
        self.ssa
            .block(tag.block)
            .and_then(|block| block.instructions().get(tag.instr))
            .map(|instr| instr.op())
    }

    /// Whether `set` holds `var`'s value.
    fn holds(&self, set: &ValSet, var: SsaVarId) -> bool {
        set.contains(Val::Class(self.class_of(var)))
            || (self.is_local_entry(var) && set.contains(Val::Zero))
    }
}

/// Whether a constant's bits are all zero: what a zero-initialised slot holds.
fn is_zero_bits(value: &ConstValue) -> bool {
    value.is_zero()
        || value.is_null()
        || matches!(value, ConstValue::Float(bits) if bits.bits() == 0)
}

/// A store width narrower than the four-byte evaluation stack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Narrow {
    Bool,
    I8,
    U8,
    I16,
    U16,
    Char,
}

impl Narrow {
    /// Every narrow width.
    const ALL: [Self; 6] = [
        Self::Bool,
        Self::I8,
        Self::U8,
        Self::I16,
        Self::U16,
        Self::Char,
    ];

    /// The narrow slots a constant fits in unchanged.
    fn holding_constant(value: &ConstValue) -> Vec<Self> {
        let integer: Option<i128> = match value {
            ConstValue::I8(v) => Some(i128::from(*v)),
            ConstValue::I16(v) => Some(i128::from(*v)),
            ConstValue::I32(v) => Some(i128::from(*v)),
            ConstValue::I64(v) | ConstValue::NativeInt(v) => Some(i128::from(*v)),
            ConstValue::U8(v) => Some(i128::from(*v)),
            ConstValue::U16(v) => Some(i128::from(*v)),
            ConstValue::U32(v) => Some(i128::from(*v)),
            ConstValue::U64(v) | ConstValue::NativeUInt(v) => Some(i128::from(*v)),
            ConstValue::True => Some(1),
            ConstValue::False => Some(0),
            _ => None,
        };
        let Some(v) = integer else {
            return Vec::new();
        };
        Self::ALL
            .into_iter()
            .filter(|narrow| {
                let (min, max) = narrow.range();
                (min..=max).contains(&v)
            })
            .collect()
    }

    /// The values a slot of this width holds.
    fn range(self) -> (i128, i128) {
        match self {
            Self::Bool => (0, 1),
            Self::I8 => (-128, 127),
            Self::U8 => (0, 255),
            Self::I16 => (-32768, 32767),
            Self::U16 | Self::Char => (0, 65535),
        }
    }

    /// Whether every value of this width is one a `slot` holds unchanged:
    /// a `char` is a `ushort`, a `byte` a `short`.
    fn within(self, slot: Self) -> bool {
        let (min, max) = self.range();
        let (slot_min, slot_max) = slot.range();
        slot_min <= min && max <= slot_max
    }

    fn of_ssa(ty: &SsaType) -> Option<Self> {
        match ty {
            SsaType::Bool => Some(Self::Bool),
            SsaType::I8 => Some(Self::I8),
            SsaType::U8 => Some(Self::U8),
            SsaType::I16 => Some(Self::I16),
            SsaType::U16 => Some(Self::U16),
            SsaType::Char => Some(Self::Char),
            _ => None,
        }
    }

    fn of_signature(ty: &TypeSignature) -> Option<Self> {
        match ty {
            TypeSignature::Boolean => Some(Self::Bool),
            TypeSignature::I1 => Some(Self::I8),
            TypeSignature::U1 => Some(Self::U8),
            TypeSignature::I2 => Some(Self::I16),
            TypeSignature::U2 => Some(Self::U16),
            TypeSignature::Char => Some(Self::Char),
            _ => None,
        }
    }
}

/// Whether an operation's place in the emission order is observable: it reads
/// or writes memory, calls, may throw, or otherwise is not pure.
fn is_effectful(op: &SsaOp) -> bool {
    !op.is_pure() || op.may_throw()
}

/// Whether two effectful operations may run in either order: neither calls,
/// fences or does something opaque, at most one may trap, and neither writes
/// memory the other reads or writes.
fn commute(a: &SsaOp, b: &SsaOp) -> bool {
    let (ea, eb) = (a.effects(), b.effects());
    let barrier = |kind: SsaEffectKind| {
        !matches!(
            kind,
            SsaEffectKind::Pure
                | SsaEffectKind::Read
                | SsaEffectKind::Write
                | SsaEffectKind::ReadWrite
        )
    };
    if barrier(ea.kind) || barrier(eb.kind) {
        return false;
    }
    if ea.may_throw && eb.may_throw {
        return false;
    }
    let reads =
        |kind: SsaEffectKind| matches!(kind, SsaEffectKind::Read | SsaEffectKind::ReadWrite);
    let writes =
        |kind: SsaEffectKind| matches!(kind, SsaEffectKind::Write | SsaEffectKind::ReadWrite);
    !((writes(ea.kind) && (reads(eb.kind) || writes(eb.kind)))
        || (writes(eb.kind) && reads(ea.kind)))
}

/// Operations whose absence from the body is not a dropped effect: control
/// transfer (checked by the edges), and operations with nothing to emit.
fn emission_optional(op: &SsaOp) -> bool {
    op.is_terminator()
        || matches!(
            op,
            SsaOp::Nop
                | SsaOp::Phi { .. }
                | SsaOp::Fence { .. }
                | SsaOp::RuntimeValue { .. }
                | SsaOp::Unreachable
                | SsaOp::InterruptReturn
        )
}

/// The finished body's structure: groups, layout, blocks and clauses.
struct Body {
    /// Group owning each instruction, by instruction index.
    group_of: Vec<Option<usize>>,
    /// Each group's tag.
    tags: Vec<OpTag>,
    /// First instruction each group owns.
    group_first: Vec<Option<usize>>,
    /// Last instruction each group owns.
    group_last: Vec<Option<usize>>,
    /// The groups opening at each instruction: those whose range starts
    /// there, outermost first, so a run that encloses another (a terminator
    /// whose phi copies materialise a constant) takes its operands before the
    /// inner run pushes anything.
    opening: BTreeMap<usize, Vec<usize>>,
    /// Layout entry each instruction belongs to.
    entry_of: Vec<Option<LayoutEntry>>,
    /// SSA block starting at each offset.
    /// The SSA blocks starting at each offset, in layout order: more than one
    /// when a block emitted nothing (a merge point with no code of its own),
    /// and control entering the offset enters the first and falls through the
    /// rest.
    block_at: BTreeMap<u64, Vec<usize>>,
    /// Instruction index at each offset.
    index_at: BTreeMap<u64, usize>,
    /// Emitted basic blocks as `[start, end)` instruction ranges.
    blocks: Vec<(usize, usize)>,
    /// Emitted block starting at each instruction index.
    block_starting: BTreeMap<usize, usize>,
    /// Locals and arguments whose address the body takes.
    address_taken_locals: BTreeSet<u16>,
    address_taken_args: BTreeSet<u16>,
}

impl Body {
    fn of(input: &Validation<'_>, instructions: &[Instruction]) -> Result<Self> {
        let count = instructions.len();
        let mut group_of: Vec<Option<usize>> = vec![None; count];
        let mut group_first: Vec<Option<usize>> = vec![None; input.groups.len()];
        let mut group_last: Vec<Option<usize>> = vec![None; input.groups.len()];
        for (group_idx, group) in input.groups.iter().enumerate() {
            for index in group.start..group.end.min(count) {
                if let Some(slot) = group_of.get_mut(index) {
                    if slot.is_none() {
                        *slot = Some(group_idx);
                        if let Some(first) = group_first.get_mut(group_idx) {
                            if first.is_none() {
                                *first = Some(index);
                            }
                        }
                        if let Some(last) = group_last.get_mut(group_idx) {
                            *last = Some(index);
                        }
                    }
                }
            }
        }
        let tags = input.groups.iter().map(|group| group.tag).collect();
        let mut opening: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (group_idx, group) in input.groups.iter().enumerate() {
            if group.start < group.end && group.start < count {
                opening.entry(group.start).or_default().push(group_idx);
            }
        }
        for groups in opening.values_mut() {
            groups.sort_by_key(|group| {
                std::cmp::Reverse(
                    input
                        .groups
                        .get(*group)
                        .map_or(0, |g| g.end.saturating_sub(g.start)),
                )
            });
        }

        let mut layout: Vec<(LayoutEntry, u32)> = input.layout.to_vec();
        layout.sort_by_key(|(_, offset)| *offset);
        let entry_of = instructions
            .iter()
            .map(|instr| {
                layout
                    .iter()
                    .rev()
                    .find(|(_, offset)| u64::from(*offset) <= instr.offset)
                    .map(|(entry, _)| *entry)
            })
            .collect();
        let mut block_at: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (entry, offset) in &layout {
            if let LayoutEntry::Block(block) = entry {
                block_at.entry(u64::from(*offset)).or_default().push(*block);
            }
        }

        let index_at: BTreeMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(index, instr)| (instr.offset, index))
            .collect();

        // Leaders: the entry, every branch target, every instruction after a
        // transfer, every layout entry, and every clause boundary.
        let mut leaders: BTreeSet<usize> = BTreeSet::new();
        leaders.insert(0);
        for (index, instr) in instructions.iter().enumerate() {
            for target in &instr.branch_targets {
                let Some(&target_index) = index_at.get(target) else {
                    return Err(failure(
                        instr.offset,
                        "branch into the middle of an instruction",
                    ));
                };
                leaders.insert(target_index);
            }
            if ends_block(instr) {
                leaders.insert(index.saturating_add(1));
            }
        }
        for (_, offset) in &layout {
            if let Some(&index) = index_at.get(&u64::from(*offset)) {
                leaders.insert(index);
            }
        }
        for clause in input.handlers {
            for offset in [
                clause.try_offset,
                clause.try_offset.saturating_add(clause.try_length),
                clause.handler_offset,
                clause.handler_offset.saturating_add(clause.handler_length),
            ] {
                if let Some(&index) = index_at.get(&u64::from(offset)) {
                    leaders.insert(index);
                }
            }
            if clause.flags == ExceptionHandlerFlags::FILTER {
                if let Some(&index) = index_at.get(&u64::from(clause.filter_offset)) {
                    leaders.insert(index);
                }
            }
        }
        leaders.retain(|&index| index < count);
        let starts: Vec<usize> = leaders.into_iter().collect();
        let blocks: Vec<(usize, usize)> = starts
            .iter()
            .enumerate()
            .map(|(position, &start)| {
                let end = starts
                    .get(position.saturating_add(1))
                    .copied()
                    .unwrap_or(count);
                (start, end)
            })
            .collect();
        let block_starting = blocks
            .iter()
            .enumerate()
            .map(|(block, (start, _))| (*start, block))
            .collect();

        let mut address_taken_locals = BTreeSet::new();
        let mut address_taken_args = BTreeSet::new();
        for instr in instructions {
            if instr.mnemonic.starts_with("ldloca") {
                if let Some(index) = place_index(instr) {
                    address_taken_locals.insert(index);
                }
            } else if instr.mnemonic.starts_with("ldarga") {
                if let Some(index) = place_index(instr) {
                    address_taken_args.insert(index);
                }
            }
        }

        Ok(Self {
            group_of,
            tags,
            group_first,
            group_last,
            opening,
            entry_of,
            block_at,
            index_at,
            blocks,
            block_starting,
            address_taken_locals,
            address_taken_args,
        })
    }

    fn group_at(&self, index: usize) -> Option<usize> {
        self.group_of.get(index).copied().flatten()
    }

    fn tag(&self, group: usize) -> Option<OpTag> {
        self.tags.get(group).copied()
    }

    /// The SSA block whose emitted code holds instruction `index`: the block
    /// itself, or the source of the edge block it is in.
    fn ssa_source(&self, index: usize) -> Option<usize> {
        match self.entry_of.get(index).copied().flatten()? {
            LayoutEntry::Block(block) => Some(block),
            LayoutEntry::SplitEdge { from, .. } => Some(from),
        }
    }
}

/// Whether control does not simply continue to the next instruction.
fn ends_block(instr: &Instruction) -> bool {
    !instr.branch_targets.is_empty()
        || matches!(
            instr.mnemonic,
            "ret" | "throw" | "rethrow" | "endfinally" | "endfilter" | "jmp" | "switch"
        )
        || instr.mnemonic.starts_with("br")
        || instr.mnemonic.starts_with("leave")
}

/// Whether control can continue to the next instruction.
fn falls_through(instr: &Instruction) -> bool {
    !(matches!(
        instr.mnemonic,
        "ret" | "throw" | "rethrow" | "endfinally" | "endfilter" | "jmp" | "br" | "br.s"
    ) || instr.mnemonic.starts_with("leave"))
}

/// The local or argument index an `ldloc`/`stloc`/`ldarg`/`starg` family
/// instruction names.
fn place_index(instr: &Instruction) -> Option<u16> {
    if let Some(digit) = instr
        .mnemonic
        .rsplit('.')
        .next()
        .and_then(|suffix| suffix.parse::<u16>().ok())
    {
        return Some(digit);
    }
    match &instr.operand {
        Operand::Local(index) | Operand::Argument(index) => Some(*index),
        Operand::Immediate(Immediate::UInt8(index)) => Some(u16::from(*index)),
        Operand::Immediate(Immediate::UInt16(index)) => Some(*index),
        Operand::Immediate(Immediate::Int8(index)) => u16::try_from(*index).ok(),
        Operand::Immediate(Immediate::Int16(index)) => u16::try_from(*index).ok(),
        Operand::Immediate(Immediate::Int32(index)) => u16::try_from(*index).ok(),
        Operand::Immediate(Immediate::UInt32(index)) => u16::try_from(*index).ok(),
        _ => None,
    }
}

/// Checks that every effectful SSA instruction is emitted exactly once and, within
/// its block, in SSA order.
fn check_effect_order(
    instructions: &[Instruction],
    facts: &SsaFacts<'_>,
    body: &Body,
) -> Result<()> {
    let emitted_blocks: BTreeSet<usize> = body.block_at.values().flatten().copied().collect();
    // Groups by first instruction: the order the body runs them in.
    let mut order: Vec<(usize, OpTag)> = body
        .group_first
        .iter()
        .zip(&body.tags)
        .filter_map(|(first, tag)| first.map(|first| (first, *tag)))
        .collect();
    order.sort_by_key(|(first, _)| *first);

    let mut seen: BTreeMap<OpTag, usize> = BTreeMap::new();
    let mut emitted: BTreeMap<usize, Vec<(usize, &SsaOp)>> = BTreeMap::new();
    for (first, tag) in &order {
        let Some(op) = facts.op(*tag) else {
            continue;
        };
        if !is_effectful(op) || matches!(op, SsaOp::Const { .. }) {
            continue;
        }
        let offset = instructions.get(*first).map_or(0, |instr| instr.offset);
        let times = seen.entry(*tag).or_insert(0);
        *times = times.saturating_add(1);
        if *times > 1 {
            return Err(failure(
                offset,
                format!("{op} in block {} is emitted more than once", tag.block),
            ));
        }
        let earlier = emitted.entry(tag.block).or_default();
        if let Some((later, _)) = earlier
            .iter()
            .find(|(other, other_op)| *other > tag.instr && !commute(op, other_op))
        {
            return Err(failure(
                offset,
                format!(
                    "{op} (B{}:{}) runs after B{}:{later}, which follows it in the SSA",
                    tag.block, tag.instr, tag.block
                ),
            ));
        }
        earlier.push((tag.instr, op));
    }

    for block_idx in &emitted_blocks {
        let Some(block) = facts.ssa.block(*block_idx) else {
            continue;
        };
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            let op = instr.op();
            if !is_effectful(op) || emission_optional(op) {
                continue;
            }
            let tag = OpTag {
                block: *block_idx,
                instr: instr_idx,
            };
            if !seen.contains_key(&tag) {
                return Err(Error::CodegenFailed(format!(
                    "generated code drops {op} (B{block_idx}:{instr_idx})"
                )));
            }
        }
    }
    Ok(())
}

/// One thing a place may be known to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Val {
    /// The current instance of a copy class.
    Class(u32),
    /// The zero a local starts with.
    Zero,
    /// The exception object a handler starts with.
    Exception,
    /// A value an instruction inside an operation's run produced, by
    /// instruction index.
    Temp(usize),
    /// A literal no SSA operation produced, by instruction index.
    Literal(usize),
}

/// The values a place is known to hold, all equal.
///
/// Kept sorted, so membership, insertion and removal of one value are binary searches and a
/// meet is a merge. A place can hold hundreds: every phi whose inputs all trace back to a
/// local's initial zero joins that local's set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ValSet(SmallVec<[Val; 2]>);

impl ValSet {
    fn one(val: Val) -> Self {
        let mut set = SmallVec::new();
        set.push(val);
        Self(set)
    }

    fn contains(&self, val: Val) -> bool {
        self.0.binary_search(&val).is_ok()
    }

    fn insert(&mut self, val: Val) {
        if let Err(at) = self.0.binary_search(&val) {
            self.0.insert(at, val);
        }
    }

    fn remove(&mut self, predicate: impl Fn(Val) -> bool) {
        self.0.retain(|val| !predicate(*val));
    }

    /// Removes every value from `low` to `high`, both included.
    fn remove_between(&mut self, low: Val, high: Val) {
        let start = self.0.partition_point(|val| *val < low);
        let end = self.0.partition_point(|val| *val <= high);
        if start < end {
            self.0.drain(start..end);
        }
    }

    /// Removes `val`, returning whether the set held it.
    fn remove_one(&mut self, val: Val) -> bool {
        match self.0.binary_search(&val) {
            Ok(at) => {
                self.0.remove(at);
                true
            }
            Err(_) => false,
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        let mut common = SmallVec::new();
        let (mut mine, mut theirs) = (self.0.iter().peekable(), other.0.iter().peekable());
        while let (Some(&&a), Some(&&b)) = (mine.peek(), theirs.peek()) {
            match a.cmp(&b) {
                Ordering::Less => {
                    mine.next();
                }
                Ordering::Greater => {
                    theirs.next();
                }
                Ordering::Equal => {
                    common.push(a);
                    mine.next();
                    theirs.next();
                }
            }
        }
        Self(common)
    }

    fn replace(&mut self, from: Val, to: Val) {
        if self.remove_one(from) {
            self.insert(to);
        }
    }
}

/// What the stack and every slot hold at one point.
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    stack: Vec<ValSet>,
    locals: Vec<ValSet>,
    args: Vec<ValSet>,
}

impl State {
    /// Every place in position order: the stack, then locals, then arguments.
    fn places(&self) -> impl Iterator<Item = &ValSet> {
        self.stack
            .iter()
            .chain(self.locals.iter())
            .chain(self.args.iter())
    }

    /// The place at `position`, counted as [`State::places`] counts.
    fn place_mut(&mut self, position: usize) -> Option<&mut ValSet> {
        let Some(position) = position.checked_sub(self.stack.len()) else {
            return self.stack.get_mut(position);
        };
        let Some(position) = position.checked_sub(self.locals.len()) else {
            return self.locals.get_mut(position);
        };
        self.args.get_mut(position)
    }

    /// Every place, for edits that apply to all of them.
    fn places_mut(&mut self) -> impl Iterator<Item = &mut ValSet> {
        self.stack
            .iter_mut()
            .chain(self.locals.iter_mut())
            .chain(self.args.iter_mut())
    }

    /// Forgets every instance of `val`.
    fn kill(&mut self, val: Val) {
        for set in self.places_mut() {
            set.remove_one(val);
        }
    }

    /// The meet of two states reaching one point.
    fn meet(&self, other: &Self, offset: u64) -> Result<Self> {
        if self.stack.len() != other.stack.len() {
            return Err(failure(
                offset,
                format!(
                    "reached with stack depths {} and {}",
                    self.stack.len(),
                    other.stack.len()
                ),
            ));
        }
        let pairwise = |a: &[ValSet], b: &[ValSet]| -> Vec<ValSet> {
            a.iter().zip(b).map(|(x, y)| x.intersect(y)).collect()
        };
        Ok(Self {
            stack: pairwise(&self.stack, &other.stack),
            locals: pairwise(&self.locals, &other.locals),
            args: pairwise(&self.args, &other.args),
        })
    }
}

/// An operation's run in progress within one emitted block.
struct OpenGroup {
    group: usize,
    /// Stack depth below the operation's operands.
    floor: usize,
    /// The last value an instruction of the run produced.
    result: Option<Val>,
    /// The place the run last stored to: an operation whose instruction is
    /// the store itself (a `stloc` into a narrow local performing the
    /// conversion the lift states) leaves its value there.
    stored: Option<Slot>,
}

/// A local or argument slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Local(u16),
    Arg(u16),
}

struct Interpreter<'a, 'b> {
    input: &'a Validation<'a>,
    instructions: &'b [Instruction],
    facts: &'b SsaFacts<'a>,
    body: &'b Body,
    /// State at each emitted block's entry, once reached.
    entry: Vec<Option<State>>,
    /// Successors of each `endfinally`, by the clause whose handler holds it.
    finally_continuations: BTreeMap<usize, BTreeSet<u64>>,
    /// The values a handler entry's stack starts with, by clause.
    handler_stack: BTreeMap<usize, ValSet>,
}

impl<'a, 'b> Interpreter<'a, 'b> {
    fn new(
        input: &'a Validation<'a>,
        instructions: &'b [Instruction],
        facts: &'b SsaFacts<'a>,
        body: &'b Body,
    ) -> Result<Self> {
        let mut finally_continuations: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
        for instr in instructions {
            if !instr.mnemonic.starts_with("leave") {
                continue;
            }
            let Some(&target) = instr.branch_targets.first() else {
                continue;
            };
            let chain = crossed_finallies(input.handlers, instr.offset, target);
            for (position, clause) in chain.iter().enumerate() {
                let next = chain
                    .get(position.saturating_add(1))
                    .map_or(target, |next| {
                        input
                            .handlers
                            .get(*next)
                            .map_or(target, |c| u64::from(c.handler_offset))
                    });
                finally_continuations
                    .entry(*clause)
                    .or_default()
                    .insert(next);
            }
        }

        let mut handler_stack = BTreeMap::new();
        for (clause_idx, clause) in input.handlers.iter().enumerate() {
            if clause.flags == ExceptionHandlerFlags::FINALLY
                || clause.flags == ExceptionHandlerFlags::FAULT
            {
                continue;
            }
            let mut set = ValSet::one(Val::Exception);
            for offset in [clause.handler_offset, clause.filter_offset] {
                for &block in body.block_at.get(&u64::from(offset)).into_iter().flatten() {
                    for var in exception_values(facts.ssa, block) {
                        set.insert(Val::Class(facts.class_of(var)));
                    }
                }
            }
            handler_stack.insert(clause_idx, set);
        }

        Ok(Self {
            input,
            instructions,
            facts,
            body,
            entry: vec![None; body.blocks.len()],
            finally_continuations,
            handler_stack,
        })
    }

    fn entry_state(&self) -> State {
        let local_count = self.input.locals.len();
        let arg_count = self.facts.ssa.num_args();
        let args = (0..arg_count)
            .map(|index| {
                let mut set = ValSet::default();
                if let Ok(index) = u16::try_from(index) {
                    for class in self.facts.arg_entry.get(&index).into_iter().flatten() {
                        set.insert(Val::Class(*class));
                    }
                }
                set
            })
            .collect();
        State {
            stack: Vec::new(),
            locals: vec![ValSet::one(Val::Zero); local_count],
            args,
        }
    }

    fn run(&mut self) -> Result<()> {
        let mut work: VecDeque<usize> = VecDeque::new();
        let mut entry = self.entry_state();
        // The function is entered through SSA block 0. When that block emits
        // nothing (construction split an entry a loop branches to), the code at
        // offset 0 is its successor's, entered from block 0.
        let chain = self.body.block_at.get(&0).cloned().unwrap_or_default();
        if let Some(&first) = chain.first() {
            if first != 0 {
                self.edge_relabel(Some(0), first, &mut entry, 0)?;
            }
        }
        self.fall_through(&chain, &mut entry, 0)?;
        self.merge_into(0, entry, &mut work)?;
        while let Some(block) = work.pop_front() {
            let Some(state) = self.entry.get(block).cloned().flatten() else {
                continue;
            };
            self.run_block(block, state, &mut work)?;
        }
        Ok(())
    }

    /// Meets `state` into emitted block `block`'s entry, queueing it if that
    /// changed anything.
    fn merge_into(&mut self, block: usize, state: State, work: &mut VecDeque<usize>) -> Result<()> {
        let offset = self
            .body
            .blocks
            .get(block)
            .and_then(|(start, _)| self.instructions.get(*start))
            .map_or(0, |instr| instr.offset);
        let Some(slot) = self.entry.get_mut(block) else {
            return Ok(());
        };
        let merged = match slot {
            Some(existing) => existing.meet(&state, offset)?,
            None => state,
        };
        if slot.as_ref() != Some(&merged) {
            *slot = Some(merged);
            if !work.contains(&block) {
                work.push_back(block);
            }
        }
        Ok(())
    }

    fn run_block(
        &mut self,
        block: usize,
        mut state: State,
        work: &mut VecDeque<usize>,
    ) -> Result<()> {
        let Some(&(start, end)) = self.body.blocks.get(block) else {
            return Ok(());
        };
        // Runs open at this point, innermost last: a constant materialised
        // while a terminator stores its phi operands is a run inside a run.
        let mut open: Vec<OpenGroup> = Vec::new();
        for index in start..end {
            let Some(instr) = self.instructions.get(index) else {
                break;
            };
            let group = self.body.group_at(index);

            for opening in self.body.opening.get(&index).cloned().unwrap_or_default() {
                open.push(self.open_group(opening, index, &state, work)?);
            }

            let current = open
                .last_mut()
                .filter(|current| Some(current.group) == group);
            self.step(index, instr, group, &mut state, current)?;

            if let Some(group) = group {
                let closes = open.last().is_some_and(|current| current.group == group)
                    && self.body.group_last.get(group).copied().flatten() == Some(index);
                if closes {
                    if let Some(finished) = open.pop() {
                        self.close_group(&finished, index, &mut state)?;
                    }
                }
            }

            if index.saturating_add(1) == end {
                for unfinished in &open {
                    let op = self
                        .body
                        .tag(unfinished.group)
                        .and_then(|tag| self.facts.op(tag));
                    if op.is_some_and(|op| !op.is_terminator()) {
                        return Err(failure(
                            instr.offset,
                            "an operation's code is split across a block boundary",
                        ));
                    }
                }
                self.leave_block(index, instr, &state, work)?;
            }
        }
        Ok(())
    }

    /// Starts an operation's run: checks its operands and records it as a
    /// throw point.
    fn open_group(
        &mut self,
        group: usize,
        index: usize,
        state: &State,
        work: &mut VecDeque<usize>,
    ) -> Result<OpenGroup> {
        let offset = self.instructions.get(index).map_or(0, |instr| instr.offset);
        let tag = self
            .body
            .tag(group)
            .ok_or_else(|| failure(offset, "an emitted run names no SSA instruction"))?;
        let op = self.facts.op(tag).ok_or_else(|| {
            failure(
                offset,
                format!("B{}:{} does not exist", tag.block, tag.instr),
            )
        })?;

        // Only what may raise hands control to a handler. A `leave` is
        // effectful but raises nothing, and the phi copies before it are
        // emitted inside its run, so its start is a state no throw sees.
        if op.may_throw() {
            self.throw_point(tag, offset, state, work)?;
        }

        let operands = SsaCodeGenerator::get_operands_in_stack_order(op);
        let depth = state.stack.len();
        let floor = depth.checked_sub(operands.len()).ok_or_else(|| {
            failure(
                offset,
                format!(
                    "{op} needs {} operands on the stack and finds {depth}",
                    operands.len()
                ),
            )
        })?;
        for (position, operand) in operands.iter().enumerate() {
            let held = state.stack.get(floor.saturating_add(position));
            if !held.is_some_and(|set| self.facts.holds(set, *operand)) {
                return Err(failure(
                    offset,
                    format!(
                        "{op} (B{}:{}) reads {operand} as operand {position}, but the stack holds {:?}",
                        tag.block, tag.instr, held
                    ),
                ));
            }
        }
        Ok(OpenGroup {
            group,
            floor,
            result: None,
            stored: None,
        })
    }

    /// Ends an operation's run: its result becomes the operation's value.
    fn close_group(&mut self, group: &OpenGroup, index: usize, state: &mut State) -> Result<()> {
        let offset = self.instructions.get(index).map_or(0, |instr| instr.offset);
        let Some(tag) = self.body.tag(group.group) else {
            return Ok(());
        };
        let Some(op) = self.facts.op(tag) else {
            return Ok(());
        };
        if op.is_terminator() {
            return Ok(());
        }
        if state.stack.len() < group.floor {
            return Err(failure(
                offset,
                format!("{op} consumed values below its operands"),
            ));
        }

        if let Some(dest) = op.dest() {
            if !matches!(op, SsaOp::Copy { .. }) {
                let class = Val::Class(self.facts.class_of(dest));
                if !matches!(op, SsaOp::Const { .. }) {
                    state.kill(class);
                }
                match group.result {
                    Some(result) => {
                        for set in state.places_mut() {
                            set.replace(result, class);
                        }
                    }
                    None if state.stack.len() == group.floor.saturating_add(1) => {
                        if let Some(top) = state.stack.last_mut() {
                            top.insert(class);
                        }
                    }
                    None => {
                        let place = match group.stored {
                            Some(Slot::Local(idx)) => state.locals.get_mut(usize::from(idx)),
                            Some(Slot::Arg(idx)) => state.args.get_mut(usize::from(idx)),
                            None => None,
                        };
                        if let Some(set) = place {
                            *set = ValSet::one(class);
                        }
                    }
                }
            }
        }

        // Intermediates of the run mean nothing outside it.
        let (start, end) = (
            self.body
                .group_first
                .get(group.group)
                .copied()
                .flatten()
                .unwrap_or(index),
            index,
        );
        for set in state.places_mut() {
            set.remove_between(Val::Temp(start), Val::Temp(end));
        }

        let expected = [group.floor, group.floor.saturating_add(1)];
        if !expected.contains(&state.stack.len()) {
            return Err(failure(
                offset,
                format!(
                    "{op} leaves the stack at depth {}, expected {} or {}",
                    state.stack.len(),
                    group.floor,
                    group.floor.saturating_add(1)
                ),
            ));
        }
        Ok(())
    }

    /// Applies one instruction.
    fn step(
        &mut self,
        index: usize,
        instr: &Instruction,
        group: Option<usize>,
        state: &mut State,
        open: Option<&mut OpenGroup>,
    ) -> Result<()> {
        let offset = instr.offset;
        let m = instr.mnemonic;
        let pop = |state: &mut State, floor: Option<usize>| -> Result<ValSet> {
            if floor.is_some_and(|floor| state.stack.len() <= floor) {
                return Err(failure(
                    offset,
                    format!("{m} consumes a value below its operation's operands"),
                ));
            }
            state
                .stack
                .pop()
                .ok_or_else(|| failure(offset, format!("{m} on an empty stack")))
        };
        let floor = open.as_ref().map(|group| group.floor);

        if m.starts_with("ldarga") || m.starts_with("ldloca") {
            if group.is_none() {
                return Err(failure(
                    offset,
                    format!("{m} implements no SSA instruction"),
                ));
            }
            let produced = Val::Temp(index);
            state.stack.push(ValSet::one(produced));
            if let Some(open) = open {
                open.result = Some(produced);
            }
            return Ok(());
        }
        if m.starts_with("ldarg") {
            let place = place_index(instr).ok_or_else(|| {
                failure(
                    offset,
                    format!("{m} names no argument index: {:?}", instr.operand),
                )
            })?;
            let set = state
                .args
                .get(usize::from(place))
                .cloned()
                .ok_or_else(|| failure(offset, format!("argument {place} does not exist")))?;
            state.stack.push(set);
            return Ok(());
        }
        if m.starts_with("ldloc") {
            let place = place_index(instr).ok_or_else(|| {
                failure(
                    offset,
                    format!("{m} names no local index: {:?}", instr.operand),
                )
            })?;
            let set = state
                .locals
                .get(usize::from(place))
                .cloned()
                .ok_or_else(|| failure(offset, format!("local {place} is not declared")))?;
            state.stack.push(set);
            return Ok(());
        }
        let converts = open
            .as_ref()
            .and_then(|group| self.body.tag(group.group))
            .and_then(|tag| self.facts.op(tag))
            .is_some_and(|op| matches!(op, SsaOp::IntConv { .. }));
        if m.starts_with("starg") {
            let place = place_index(instr).ok_or_else(|| {
                failure(
                    offset,
                    format!("{m} names no argument index: {:?}", instr.operand),
                )
            })?;
            let value = pop(state, floor)?;
            let narrow = self
                .facts
                .arg_entry
                .get(&place)
                .and_then(|classes| classes.iter().next())
                .and_then(|class| self.facts.class_types.get(class))
                .and_then(|types| types.iter().next().copied());
            if !converts {
                self.check_width(offset, narrow, &value, format!("argument {place}"))?;
            }
            if let Some(open) = open {
                open.stored = Some(Slot::Arg(place));
            }
            let slot = state
                .args
                .get_mut(usize::from(place))
                .ok_or_else(|| failure(offset, format!("argument {place} does not exist")))?;
            *slot = value;
            return Ok(());
        }
        if m.starts_with("stloc") {
            let place = place_index(instr).ok_or_else(|| {
                failure(
                    offset,
                    format!("{m} names no local index: {:?}", instr.operand),
                )
            })?;
            let value = pop(state, floor)?;
            let narrow = self
                .input
                .locals
                .get(usize::from(place))
                .and_then(Option::as_ref)
                .and_then(Narrow::of_signature);
            if !converts {
                self.check_width(offset, narrow, &value, format!("local {place}"))?;
            }
            if let Some(open) = open {
                open.stored = Some(Slot::Local(place));
            }
            let slot = state
                .locals
                .get_mut(usize::from(place))
                .ok_or_else(|| failure(offset, format!("local {place} is not declared")))?;
            *slot = value;
            return Ok(());
        }
        match m {
            "dup" => {
                let top = state
                    .stack
                    .last()
                    .cloned()
                    .ok_or_else(|| failure(offset, "dup on an empty stack"))?;
                state.stack.push(top);
                return Ok(());
            }
            "pop" => {
                pop(state, floor)?;
                return Ok(());
            }
            "nop" => return Ok(()),
            "br" | "br.s" => return Ok(()),
            "leave" | "leave.s" | "endfinally" => {
                state.stack.clear();
                return Ok(());
            }
            _ => {}
        }

        let is_literal = m.starts_with("ldc.") || m == "ldnull" || m == "ldstr";
        let Some(open) = open else {
            if group.is_none() {
                if is_literal {
                    state.stack.push(ValSet::one(Val::Literal(index)));
                    return Ok(());
                }
                if m == "ret" && index.saturating_add(1) == self.instructions.len() {
                    // The terminator the encoder appends to a body that falls
                    // off its end.
                    return Ok(());
                }
                return Err(failure(
                    offset,
                    format!("{m} implements no SSA instruction"),
                ));
            }
            // The rest of a terminator's run past the block its first
            // instruction ended (a conditional branch, then the unconditional
            // one to the other target), or of a run another nested inside.
            if !ends_block(instr) {
                return Err(failure(
                    offset,
                    format!("{m} runs outside its operation's run"),
                ));
            }
            let (pops, pushes) = fixed_arity(instr);
            for _ in 0..pops {
                pop(state, None)?;
            }
            for _ in 0..pushes {
                state.stack.push(ValSet::one(Val::Temp(index)));
            }
            return Ok(());
        };

        let tag = self.body.tag(open.group);
        let op = tag.and_then(|tag| self.facts.op(tag));
        let (pops, pushes) = if is_variable_arity(m) {
            let pops = state.stack.len().saturating_sub(open.floor);
            let pushes =
                usize::from(m != "ret" && m != "jmp" && op.is_some_and(|op| op.dest().is_some()));
            (pops, pushes)
        } else {
            fixed_arity(instr)
        };
        for _ in 0..pops {
            pop(state, Some(open.floor))?;
        }
        for _ in 0..pushes {
            let produced = Val::Temp(index);
            state.stack.push(ValSet::one(produced));
            open.result = Some(produced);
        }

        if writes_memory(m) {
            for local in &self.body.address_taken_locals {
                if let Some(set) = state.locals.get_mut(usize::from(*local)) {
                    *set = ValSet::default();
                }
            }
            for arg in &self.body.address_taken_args {
                if let Some(set) = state.args.get_mut(usize::from(*arg)) {
                    *set = ValSet::default();
                }
            }
        }
        Ok(())
    }

    /// Whether the integer the literal at `index` pushes fits `narrow`.
    fn literal_fits(&self, index: usize, narrow: Narrow) -> bool {
        let Some(instr) = self.instructions.get(index) else {
            return false;
        };
        let value: Option<i128> = match instr.mnemonic {
            "ldc.i4.m1" | "ldc.i4.M1" => Some(-1),
            "ldc.i4.s" | "ldc.i4" => match &instr.operand {
                Operand::Immediate(Immediate::Int8(v)) => Some(i128::from(*v)),
                Operand::Immediate(Immediate::Int32(v)) => Some(i128::from(*v)),
                _ => None,
            },
            m => m
                .strip_prefix("ldc.i4.")
                .and_then(|digit| digit.parse::<i128>().ok()),
        };
        let (min, max) = narrow.range();
        value.is_some_and(|v| (min..=max).contains(&v))
    }

    /// Checks a store into a slot narrower than the evaluation stack.
    fn check_width(
        &self,
        offset: u64,
        narrow: Option<Narrow>,
        value: &ValSet,
        place: String,
    ) -> Result<()> {
        let Some(narrow) = narrow else {
            return Ok(());
        };
        // A set names values the stored one equals on every path, not
        // alternatives: a member known to fit the slot is enough.
        let fits = value.0.iter().any(|val| match val {
            Val::Class(class) => self
                .facts
                .class_types
                .get(class)
                .is_some_and(|types| types.iter().any(|ty| ty.within(narrow))),
            Val::Literal(index) => self.literal_fits(*index, narrow),
            Val::Zero | Val::Temp(_) | Val::Exception => true,
        });
        if value.0.is_empty() || fits {
            return Ok(());
        }
        Err(failure(
            offset,
            format!(
                "stores a value of no {narrow:?} type into {place}, which truncates it: {value:?}"
            ),
        ))
    }

    /// Records the state at a throwing instruction as reaching every handler
    /// whose protected range holds it.
    fn throw_point(
        &mut self,
        tag: OpTag,
        offset: u64,
        state: &State,
        work: &mut VecDeque<usize>,
    ) -> Result<()> {
        let offset32 = u32::try_from(offset).unwrap_or(u32::MAX);
        let clauses: Vec<(usize, ExceptionHandler)> = self
            .input
            .handlers
            .iter()
            .enumerate()
            .filter(|(_, clause)| {
                clause.try_offset <= offset32
                    && offset32 < clause.try_offset.saturating_add(clause.try_length)
            })
            .map(|(index, clause)| (index, clause.clone()))
            .collect();
        for (clause_idx, clause) in clauses {
            let mut entries = vec![clause.handler_offset];
            if clause.flags == ExceptionHandlerFlags::FILTER {
                entries.push(clause.filter_offset);
            }
            for entry_offset in entries {
                let entry_offset = u64::from(entry_offset);
                let mut reached = State {
                    stack: Vec::new(),
                    locals: state.locals.clone(),
                    args: state.args.clone(),
                };
                if let Some(set) = self.handler_stack.get(&clause_idx) {
                    reached.stack.push(set.clone());
                }
                let chain = self
                    .body
                    .block_at
                    .get(&entry_offset)
                    .cloned()
                    .unwrap_or_default();
                if let Some(&handler_block) = chain.first() {
                    self.exceptional_relabel(tag, handler_block, &mut reached);
                }
                self.fall_through(&chain, &mut reached, entry_offset)?;
                if let Some(target) = self.emitted_block_at(entry_offset) {
                    self.merge_into(target, reached, work)?;
                }
            }
        }
        Ok(())
    }

    /// Establishes a handler's phis at a throw at `tag`: each is the version of
    /// its variable current just before the throwing instruction.
    fn exceptional_relabel(&self, tag: OpTag, handler: usize, state: &mut State) {
        let Some(block) = self.facts.ssa.block(handler) else {
            return;
        };
        let mut established = Vec::new();
        for phi in block.phi_nodes() {
            let mut best: Option<(i64, SsaVarId)> = None;
            for operand in phi.exceptional_operands() {
                if operand.predecessor() != tag.block {
                    continue;
                }
                let value = operand.value();
                let position = match self.facts.def_site.get(value.index()).copied().flatten() {
                    Some((def_block, def_instr)) if def_block == tag.block => {
                        if def_instr >= tag.instr {
                            continue;
                        }
                        i64::try_from(def_instr).unwrap_or(i64::MAX)
                    }
                    _ => -1,
                };
                if best.is_none_or(|(at, _)| position > at) {
                    best = Some((position, value));
                }
            }
            let Some((_, current)) = best else {
                continue;
            };
            established.push((Val::Class(self.facts.class_of(phi.result())), current));
        }
        self.establish(state, established);
    }

    /// Records each phi result at every place holding the version the phi takes (`result`,
    /// `current` pairs), after every earlier instance of every result is forgotten: the phis
    /// of one block take effect together.
    ///
    /// One pass over the places' contents finds every phi's places, by the class each held
    /// value stands for. A block with a phi per local, as a handler entry has, would otherwise
    /// cost phis times places at every throwing instruction.
    fn establish(&self, state: &mut State, established: Vec<(Val, SsaVarId)>) {
        if established.is_empty() {
            return;
        }
        let mut by_class: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
        let mut from_zero = Vec::new();
        for (index, (_, current)) in established.iter().enumerate() {
            by_class
                .entry(self.facts.class_of(*current))
                .or_default()
                .push(index);
            if self.facts.is_local_entry(*current) {
                from_zero.push(index);
            }
        }
        let mut positions: Vec<Vec<usize>> = vec![Vec::new(); established.len()];
        for (position, set) in state.places().enumerate() {
            for val in &set.0 {
                let phis = match val {
                    Val::Class(class) => by_class.get(class).map_or(&[][..], Vec::as_slice),
                    Val::Zero => from_zero.as_slice(),
                    _ => &[],
                };
                for &index in phis {
                    // A place holding both a phi's class and the zero it equals is one place.
                    if let Some(held) = positions.get_mut(index) {
                        if held.last() != Some(&position) {
                            held.push(position);
                        }
                    }
                }
            }
        }

        let mut results: Vec<Val> = established.iter().map(|(result, _)| *result).collect();
        results.sort_unstable();
        for set in state.places_mut() {
            set.remove(|val| results.binary_search(&val).is_ok());
        }
        for ((result, _), held) in established.into_iter().zip(positions) {
            for position in held {
                if let Some(set) = state.place_mut(position) {
                    set.insert(result);
                }
            }
        }
    }

    /// The emitted block starting at `offset`.
    fn emitted_block_at(&self, offset: u64) -> Option<usize> {
        let index = self.body.index_at.get(&offset)?;
        self.body.block_starting.get(index).copied()
    }

    /// Propagates the state at the end of an emitted block to its successors.
    fn leave_block(
        &mut self,
        index: usize,
        instr: &Instruction,
        state: &State,
        work: &mut VecDeque<usize>,
    ) -> Result<()> {
        let mut targets: Vec<u64> = Vec::new();
        if instr.mnemonic.starts_with("leave") {
            if let Some(&target) = instr.branch_targets.first() {
                let chain = crossed_finallies(self.input.handlers, instr.offset, target);
                match chain
                    .first()
                    .and_then(|clause| self.input.handlers.get(*clause))
                {
                    Some(first) => targets.push(u64::from(first.handler_offset)),
                    None => targets.push(target),
                }
            }
        } else if instr.mnemonic == "endfinally" {
            let offset32 = u32::try_from(instr.offset).unwrap_or(u32::MAX);
            let owner = self
                .input
                .handlers
                .iter()
                .enumerate()
                .filter(|(_, clause)| {
                    clause.handler_offset <= offset32
                        && offset32 < clause.handler_offset.saturating_add(clause.handler_length)
                })
                .min_by_key(|(_, clause)| clause.handler_length)
                .map(|(clause_idx, _)| clause_idx);
            if let Some(owner) = owner {
                targets.extend(
                    self.finally_continuations
                        .get(&owner)
                        .into_iter()
                        .flatten()
                        .copied(),
                );
            }
        } else {
            targets.extend(instr.branch_targets.iter().copied());
            if falls_through(instr) {
                if let Some(next) = self.instructions.get(index.saturating_add(1)) {
                    targets.push(next.offset);
                }
            }
        }

        for target in targets {
            let Some(successor) = self.emitted_block_at(target) else {
                return Err(failure(
                    instr.offset,
                    format!("transfers to IL_{target:04x}, which starts no block"),
                ));
            };
            let mut reached = state.clone();
            let chain = self.body.block_at.get(&target).cloned().unwrap_or_default();
            let source = self.body.ssa_source(index);
            // Several blocks start here when the earlier ones emitted nothing.
            // Control enters the one the source transfers to - its successor, or
            // the one whose phis name it - and falls through those after it.
            let entered = chain
                .iter()
                .position(|&block| source.is_some_and(|source| self.is_edge(source, block)))
                .unwrap_or(0);
            let rest = chain.get(entered..).unwrap_or_default();
            if let Some(&ssa_block) = rest.first() {
                self.edge_relabel(source, ssa_block, &mut reached, instr.offset)?;
            }
            self.fall_through(rest, &mut reached, instr.offset)?;
            self.merge_into(successor, reached, work)?;
        }
        Ok(())
    }

    /// Whether control passes from SSA block `from` to `to` on an edge the SSA
    /// names: a terminator successor, or a phi operand from `from`.
    fn is_edge(&self, from: usize, to: usize) -> bool {
        let Some(source) = self.facts.ssa.block(from) else {
            return false;
        };
        let mut found = false;
        source.for_each_successor(|succ| found |= succ == to);
        found
            || self.facts.ssa.block(to).is_some_and(|target| {
                target
                    .phi_nodes()
                    .iter()
                    .any(|phi| phi.operand_from(from).is_some())
            })
    }

    /// Establishes the phis of each block of a chain that emitted nothing,
    /// entered one after another.
    fn fall_through(&self, chain: &[usize], state: &mut State, offset: u64) -> Result<()> {
        for pair in chain.windows(2) {
            if let [from, to] = pair {
                self.edge_relabel(Some(*from), *to, state, offset)?;
            }
        }
        Ok(())
    }

    /// Establishes `block`'s phis on entry from `source`.
    fn edge_relabel(
        &self,
        source: Option<usize>,
        block: usize,
        state: &mut State,
        offset: u64,
    ) -> Result<()> {
        let Some(ssa_block) = self.facts.ssa.block(block) else {
            return Ok(());
        };
        if ssa_block.phi_nodes().is_empty() {
            return Ok(());
        }
        let Some(source) = source else {
            return Err(failure(
                offset,
                format!("enters B{block} from code no SSA block owns"),
            ));
        };
        let mut established = Vec::new();
        for phi in ssa_block.phi_nodes() {
            // A phi with no operand on this edge (one that only a throw
            // fills) is not established here; a read of it then fails.
            let Some(operand) = phi.operand_from(source) else {
                continue;
            };
            established.push((
                Val::Class(self.facts.class_of(phi.result())),
                operand.value(),
            ));
        }
        self.establish(state, established);
        Ok(())
    }
}

/// The values a handler block reads without defining them: the exception
/// object its first instruction settles, or the undefined operand of the `Pop`
/// that discards it.
fn exception_values(ssa: &SsaFunction, block: usize) -> Vec<SsaVarId> {
    let Some(block) = ssa.block(block) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for instr in block.instructions() {
        match instr.op() {
            SsaOp::RuntimeValue { dest, .. } => values.push(*dest),
            SsaOp::Pop { value }
                if ssa.get_definition(*value).is_none()
                    && ssa.find_phi_defining(*value).is_none() =>
            {
                values.push(*value);
            }
            _ => {}
        }
    }
    values
}

/// The finally clauses a `leave` at `from` to `to` runs, innermost first.
fn crossed_finallies(handlers: &[ExceptionHandler], from: u64, to: u64) -> Vec<usize> {
    let inside = |clause: &ExceptionHandler, offset: u64| {
        let start = u64::from(clause.try_offset);
        let end = start.saturating_add(u64::from(clause.try_length));
        (start..end).contains(&offset)
    };
    let mut chain: Vec<usize> = handlers
        .iter()
        .enumerate()
        .filter(|(_, clause)| {
            clause.flags == ExceptionHandlerFlags::FINALLY
                && inside(clause, from)
                && !inside(clause, to)
        })
        .map(|(index, _)| index)
        .collect();
    chain.sort_by_key(|index| handlers.get(*index).map_or(0, |clause| clause.try_length));
    chain
}

/// Calls, returns and jumps, whose stack effect the signature decides.
fn is_variable_arity(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call" | "callvirt" | "newobj" | "calli" | "ret" | "jmp"
    )
}

/// An instruction's fixed stack effect, as `(pops, pushes)`.
fn fixed_arity(instr: &Instruction) -> (usize, usize) {
    (
        usize::from(instr.stack_behavior.pops),
        usize::from(instr.stack_behavior.pushes),
    )
}

/// Whether an instruction may write memory a pointer to a slot reaches.
fn writes_memory(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call"
            | "callvirt"
            | "calli"
            | "newobj"
            | "stobj"
            | "initobj"
            | "cpobj"
            | "cpblk"
            | "initblk"
            | "stfld"
            | "mkrefany"
    ) || mnemonic.starts_with("stind")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every set operation agrees with a `BTreeSet` over long runs of mixed operations, sets of
    /// hundreds of values included, and the set stays sorted and free of duplicates.
    #[test]
    fn a_value_set_behaves_as_an_ordered_set() {
        // A fixed linear congruential sequence: reproducible without a dependency.
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |bound: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % bound
        };
        let val = |next: &mut dyn FnMut(u64) -> u64| match next(5) {
            0 => Val::Zero,
            1 => Val::Exception,
            2 => Val::Temp(next(300) as usize),
            3 => Val::Literal(next(300) as usize),
            _ => Val::Class(next(300) as u32),
        };
        let mut sets = [ValSet::default(), ValSet::default()];
        let mut oracle = [BTreeSet::new(), BTreeSet::new()];
        let mut largest = 0;
        for _ in 0..20_000 {
            let which = next(2) as usize;
            let v = val(&mut next);
            match next(10) {
                0..=5 => {
                    sets[which].insert(v);
                    oracle[which].insert(v);
                }
                6 => {
                    assert_eq!(sets[which].remove_one(v), oracle[which].remove(&v));
                }
                7 => {
                    let to = val(&mut next);
                    sets[which].replace(v, to);
                    if oracle[which].remove(&v) {
                        oracle[which].insert(to);
                    }
                }
                8 if next(2) == 0 => {
                    let (low, high) = (val(&mut next), val(&mut next));
                    sets[which].remove_between(low, high);
                    oracle[which].retain(|held| !(low <= *held && *held <= high));
                }
                8 => {
                    let common: Vec<Val> = oracle[0].intersection(&oracle[1]).copied().collect();
                    assert_eq!(sets[0].intersect(&sets[1]).0.to_vec(), common);
                }
                _ => {
                    assert_eq!(sets[which].contains(v), oracle[which].contains(&v));
                }
            }
            let expected: Vec<Val> = oracle[which].iter().copied().collect();
            assert_eq!(sets[which].0.to_vec(), expected);
            largest = largest.max(expected.len());
        }
        assert!(largest > 200, "the run reached only {largest} values");
    }

    #[test]
    fn a_narrow_width_fits_every_slot_holding_its_whole_range() {
        assert!(Narrow::Char.within(Narrow::U16));
        assert!(Narrow::U16.within(Narrow::Char));
        assert!(Narrow::U8.within(Narrow::I16));
        assert!(Narrow::U8.within(Narrow::Char));
        assert!(Narrow::I8.within(Narrow::I16));
        for slot in Narrow::ALL {
            assert!(Narrow::Bool.within(slot), "{slot:?}");
        }

        assert!(
            !Narrow::I8.within(Narrow::U16),
            "a negative byte is no ushort"
        );
        assert!(!Narrow::I16.within(Narrow::U16));
        assert!(!Narrow::U16.within(Narrow::I16));
        assert!(!Narrow::U8.within(Narrow::I8));
        assert!(!Narrow::Char.within(Narrow::Bool));
    }

    #[test]
    fn a_constant_fits_the_slots_that_hold_its_value() {
        let fits = Narrow::holding_constant(&ConstValue::I32(200));
        assert!(fits.contains(&Narrow::U8));
        assert!(fits.contains(&Narrow::I16));
        assert!(!fits.contains(&Narrow::I8));
        assert!(!fits.contains(&Narrow::Bool));
        assert!(Narrow::holding_constant(&ConstValue::I32(70_000)).is_empty());
    }
}

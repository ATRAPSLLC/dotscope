//! BitMono LocalVariableEncoding reversal.
//!
//! BitMono stores every integer local of a method encoded and decodes it on every load:
//!
//! ```text
//! encode(v) = conv_w(((v ^ k) * m) + a)
//! decode(y) = conv_w(((y - a) * m') ^ k)        m * m' == 1 (mod 2^w)
//! ```
//!
//! with `w` the local's width, `conv_w` the narrowing conversion of an 8- or 16-bit local
//! (none for 32 and 64 bits), and `m` odd. In SSA the local is gone: its versions form a web
//! joined by phis, defined by encodes and read by decodes. `decode(encode(v)) == conv_w(v)`
//! holds pointwise (`(x + a) - a`, `(x * m) * m'` and `(x ^ k) ^ k` cancel modulo `2^w`), and
//! so it holds across the web: when every value reaching the web is an encode with one key
//! and every read leaving it is the decode with that key, the web can carry the plain value
//! instead. Each encode becomes `conv_w` of its operand and each decode a copy of what it
//! read. The web's versions are joined by phis, and by the copies loads and stores are until
//! copy propagation. A constant reaching the web, an encode constant folding has already
//! computed, is decoded in place.
//!
//! Any other value reaching the web, or any other read of it, leaves the web as it is.

use std::collections::{BTreeSet, HashMap};

use crate::{
    analysis::{CilTarget, ConstValue, MethodRef, SsaFunction, SsaOp, SsaType, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
};

/// A local's encoding: the key of `encode` and `decode`, and the width they wrap at.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    /// The xor key `k`.
    xor: u64,
    /// The multiplier `m`; `decode` multiplies by its inverse.
    multiplier: u64,
    /// The addend `a`.
    addend: u64,
    /// The width in bits: 8, 16, 32 or 64.
    width: u32,
    /// The narrowing conversion of an 8- or 16-bit local: its target and signedness.
    narrow: Option<(SsaType, bool)>,
}

impl Key {
    /// The mask of the low `width` bits.
    fn mask(&self) -> u64 {
        if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width).wrapping_sub(1)
        }
    }

    /// Whether `inverse` undoes the multiplier modulo `2^width`.
    fn inverts(&self, inverse: u64) -> bool {
        self.multiplier.wrapping_mul(inverse) & self.mask() == 1
    }

    /// `decode(value)` for a constant reaching the web, as the value the local held.
    fn decode(&self, value: u64, inverse: u64) -> u64 {
        (value.wrapping_sub(self.addend).wrapping_mul(inverse) ^ self.xor) & self.mask()
    }
}

/// An encode: the variable it defines, the plain operand, and its key.
struct Encode {
    dest: SsaVarId,
    operand: SsaVarId,
    key: Key,
}

/// A decode: the web variable it reads, the variable it defines, the inverse multiplier,
/// and the key's other parts as it carries them.
#[derive(Clone)]
struct Decode {
    read: SsaVarId,
    dest: SsaVarId,
    /// The result before a narrowing conversion that follows: the decode's own when its local
    /// is 32 or 64 bits wide, and the conversion the program's.
    unnarrowed: SsaVarId,
    inverse: u64,
    xor: u64,
    addend: u64,
    narrow: Option<(SsaType, bool)>,
}

/// Reverses BitMono's LocalVariableEncoding in the methods it protected.
pub struct LocalEncodingReversalPass;

impl SsaPass<CilTarget, CompilerContext> for LocalEncodingReversalPass {
    fn name(&self) -> &'static str {
        "BitMonoLocalEncoding"
    }

    fn description(&self) -> &'static str {
        "Replaces BitMono's encoded locals with the values they encode"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method: &MethodRef,
        ctx: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let webs = reversible_webs(ssa);
        if webs.is_empty() {
            return Ok(false);
        }

        let locations = definition_sites(ssa);
        let mut rewritten = 0usize;
        for web in &webs {
            for encode in &web.encodes {
                // The store narrowed the value to the local's width: a value already that wide
                // is stored as it is.
                let narrow = encode.key.narrow.as_ref().filter(|(target, _)| {
                    let stored = ssa.variable(encode.operand).map(|v| v.var_type().clone());
                    !stored.is_some_and(|stored| same_width(&stored, target))
                });
                let op = match narrow {
                    Some((target, unsigned)) => SsaOp::IntConv {
                        dest: encode.dest,
                        operand: encode.operand,
                        target: target.clone(),
                        overflow_check: false,
                        unsigned: *unsigned,
                    },
                    None => SsaOp::Copy {
                        dest: encode.dest,
                        src: encode.operand,
                    },
                };
                set_definition(ssa, &locations, encode.dest, op);
            }
            for (dest, value) in &web.constants {
                let op = SsaOp::Const {
                    dest: *dest,
                    value: value.clone(),
                };
                set_definition(ssa, &locations, *dest, op);
            }
            for decode in &web.decodes {
                set_definition(
                    ssa,
                    &locations,
                    decode.dest,
                    SsaOp::Copy {
                        dest: decode.dest,
                        src: decode.read,
                    },
                );
            }
            rewritten = rewritten.saturating_add(1);
        }

        ctx.events
            .record(EventKind::ConstantDecrypted)
            .message(format!(
                "BitMonoLocalEncoding: {rewritten} encoded local(s) restored"
            ));
        Ok(true)
    }
}

/// A web of local versions the pass can carry plain, and what to rewrite in it.
struct Web {
    encodes: Vec<Encode>,
    /// Constants reaching the web, with the value they decode to.
    constants: Vec<(SsaVarId, ConstValue)>,
    decodes: Vec<Decode>,
}

/// The webs every value reaching and every read leaving is an encode and a decode of.
fn reversible_webs(ssa: &SsaFunction) -> Vec<Web> {
    let defs = Defs::of(ssa);
    let users = users(ssa);
    let joined: HashMap<SsaVarId, Vec<SsaVarId>> = joins(ssa);

    // Every decode in the method, by the variable it reads.
    let mut decodes: HashMap<SsaVarId, Vec<Decode>> = HashMap::new();
    for instr in ssa.all_instructions() {
        if let Some(decode) = decode_at(&defs, &users, instr.op()) {
            decodes.entry(decode.read).or_default().push(decode);
        }
    }

    let mut seen: BTreeSet<SsaVarId> = BTreeSet::new();
    let mut webs = Vec::new();
    let seeds: Vec<SsaVarId> = decodes.keys().copied().collect();
    for seed in seeds {
        if seen.contains(&seed) {
            continue;
        }
        // The web: every variable a phi or a copy joins with the seed, either way.
        let mut members: BTreeSet<SsaVarId> = BTreeSet::new();
        let mut work = vec![seed];
        while let Some(var) = work.pop() {
            if !members.insert(var) {
                continue;
            }
            if let Some(operands) = defs.phis.get(&var) {
                work.extend(operands.iter().copied());
            }
            if let Some(SsaOp::Copy { src, .. }) = defs.op(var) {
                work.push(*src);
            }
            if let Some(results) = joined.get(&var) {
                work.extend(results.iter().copied());
            }
        }
        seen.extend(members.iter().copied());
        if let Some(web) = web_of(&defs, &users, &members, &decodes) {
            webs.push(web);
        }
    }
    webs
}

/// The rewrite of web `members`, if every value reaching it is an encode or constant and
/// every read of it is a phi of the web or a decode, all with one key.
fn web_of(
    defs: &Defs,
    users: &HashMap<SsaVarId, Vec<Use>>,
    members: &BTreeSet<SsaVarId>,
    decodes: &HashMap<SsaVarId, Vec<Decode>>,
) -> Option<Web> {
    let ssa = defs.ssa;
    let mut key: Option<Key> = None;

    let mut encodes = Vec::new();
    let mut constant_defs = Vec::new();
    for &var in members {
        if defs.phis.contains_key(&var) || matches!(defs.op(var), Some(SsaOp::Copy { .. })) {
            continue;
        }
        if let Some(encode) = encode_of(defs, var) {
            match &key {
                Some(known) if *known != encode.key => return None,
                Some(_) => {}
                None => key = Some(encode.key.clone()),
            }
            encodes.push(encode);
        } else {
            constant_defs.push((var, defs.constant(var)?.clone()));
        }
    }

    // Every read is a phi or copy joining the web, or a decode.
    let mut web_decodes = Vec::new();
    for &var in members {
        let reads = users.get(&var).map_or(&[][..], Vec::as_slice);
        let decoded = decodes.get(&var).map_or(0, Vec::len);
        let joining = reads
            .iter()
            .filter(|read| match read {
                Use::Phi(_) => true,
                Use::Instruction(block_idx, instr_idx) => ssa
                    .block(*block_idx)
                    .and_then(|block| block.instructions().get(*instr_idx))
                    .is_some_and(|instr| matches!(instr.op(), SsaOp::Copy { .. })),
            })
            .count();
        if joining.saturating_add(decoded) != reads.len() {
            return None;
        }
        web_decodes.extend(decodes.get(&var).into_iter().flatten().cloned());
    }
    if web_decodes.is_empty() {
        return None;
    }

    // The decodes carry the key the encodes have, the inverse multiplier included. A web whose
    // values all reach it as constants takes its key from the decodes.
    let inverse = web_decodes.first()?.inverse;
    let key = match key {
        Some(key) => key,
        None => {
            // The local's own type says how wide it is: a conversion after a decode may be the
            // program's.
            let decode = web_decodes.first()?;
            let local = ssa.variable(decode.read)?.var_type().clone();
            let narrow = narrow_width(&local).map(|_| {
                (
                    local.clone(),
                    matches!(local, SsaType::U8 | SsaType::U16 | SsaType::Char),
                )
            });
            Key {
                xor: decode.xor,
                multiplier: 0,
                addend: decode.addend,
                width: width_of(narrow.clone(), ssa, decode.read)?,
                narrow,
            }
        }
    };
    // A 32- or 64-bit local's decode is followed by a conversion only when the program
    // converts the value it loaded: the decode ends before it.
    if key.narrow.is_none() {
        for decode in &mut web_decodes {
            decode.dest = decode.unnarrowed;
            decode.narrow = None;
        }
    }
    let consistent = web_decodes.iter().all(|d| {
        d.inverse == inverse && d.xor == key.xor && d.addend == key.addend && d.narrow == key.narrow
    });
    if !consistent || (key.multiplier != 0 && !key.inverts(inverse)) {
        return None;
    }

    let constants = constant_defs
        .into_iter()
        .map(|(var, value)| {
            let bits = bits(&value)?;
            Some((
                var,
                same_type(&value, key.decode(bits, inverse), key.narrow.clone())?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;

    Some(Web {
        encodes,
        constants,
        decodes: web_decodes,
    })
}

/// A read of a variable: by a phi, or by the instruction at a block and index.
#[derive(Debug, Clone, Copy)]
enum Use {
    Phi(SsaVarId),
    Instruction(usize, usize),
}

/// Every read of every variable.
fn users(ssa: &SsaFunction) -> HashMap<SsaVarId, Vec<Use>> {
    let mut users: HashMap<SsaVarId, Vec<Use>> = HashMap::new();
    for (_, _, phi) in ssa.iter_phis() {
        for operand in phi.operands() {
            users
                .entry(operand.value())
                .or_default()
                .push(Use::Phi(phi.result()));
        }
    }
    for (block_idx, block) in ssa.iter_blocks() {
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            for var in instr.uses() {
                users
                    .entry(var)
                    .or_default()
                    .push(Use::Instruction(block_idx, instr_idx));
            }
        }
    }
    users
}

/// For each variable, the results of the phis and copies reading it.
fn joins(ssa: &SsaFunction) -> HashMap<SsaVarId, Vec<SsaVarId>> {
    let mut edges: HashMap<SsaVarId, Vec<SsaVarId>> = HashMap::new();
    for (_, _, phi) in ssa.iter_phis() {
        for operand in phi.operands() {
            edges.entry(operand.value()).or_default().push(phi.result());
        }
    }
    for instr in ssa.all_instructions() {
        if let SsaOp::Copy { dest, src } = instr.op() {
            edges.entry(*src).or_default().push(*dest);
        }
    }
    edges
}

/// The variable and constant operands of a commutative binary op, the constant either side.
fn constant_operand(defs: &Defs, left: SsaVarId, right: SsaVarId) -> Option<(SsaVarId, u64)> {
    if let Some(value) = defs.bits(right) {
        return Some((left, value));
    }
    defs.bits(left).map(|value| (right, value))
}

/// The encode defining `var`: `conv_w(((x ^ k) * m) + a)`.
fn encode_of(defs: &Defs, var: SsaVarId) -> Option<Encode> {
    let (sum, narrow) = match defs.op(var)? {
        SsaOp::IntConv {
            operand,
            target,
            overflow_check: false,
            unsigned,
            ..
        } => (*operand, Some((target.clone(), *unsigned))),
        _ => (var, None),
    };
    let SsaOp::Add { left, right, .. } = defs.op(sum)? else {
        return None;
    };
    let (product, addend) = constant_operand(defs, *left, *right)?;
    let SsaOp::Mul { left, right, .. } = defs.op(product)? else {
        return None;
    };
    let (mixed, multiplier) = constant_operand(defs, *left, *right)?;
    let SsaOp::Xor { left, right, .. } = defs.op(mixed)? else {
        return None;
    };
    let (operand, xor) = constant_operand(defs, *left, *right)?;
    let width = width_of(narrow.clone(), defs.ssa, sum)?;
    let key = Key {
        xor,
        multiplier,
        addend,
        width,
        narrow,
    };
    (multiplier & 1 == 1).then_some(Encode {
        dest: var,
        operand,
        key,
    })
}

/// The decode `op` starts, if it is the `y - a` of `conv_w(((y - a) * m') ^ k)` and each step
/// is read by the next alone.
fn decode_at(
    defs: &Defs,
    users: &HashMap<SsaVarId, Vec<Use>>,
    op: &SsaOp<CilTarget>,
) -> Option<Decode> {
    let SsaOp::Sub {
        dest: difference,
        left: read,
        right,
        ..
    } = op
    else {
        return None;
    };
    let ssa = defs.ssa;
    let addend = defs.bits(*right)?;
    // The one instruction reading `var`, if nothing else reads it.
    let next = |var: SsaVarId| match users.get(&var).map(Vec::as_slice) {
        Some([Use::Instruction(block_idx, instr_idx)]) => ssa
            .block(*block_idx)
            .and_then(|block| block.instructions().get(*instr_idx))
            .map(|instr| instr.op().clone()),
        _ => None,
    };

    let SsaOp::Mul {
        dest: product,
        left,
        right,
        ..
    } = next(*difference)?
    else {
        return None;
    };
    let (_, inverse) = constant_operand(defs, left, right)?;
    let SsaOp::Xor {
        dest: mixed,
        left,
        right,
        ..
    } = next(product)?
    else {
        return None;
    };
    let (_, xor) = constant_operand(defs, left, right)?;

    // An 8- or 16-bit local's decode ends with its narrowing conversion.
    let narrowed = next(mixed).and_then(|op| match op {
        SsaOp::IntConv {
            dest,
            target,
            overflow_check: false,
            unsigned,
            ..
        } if narrow_width(&target).is_some() => Some((dest, (target, unsigned))),
        _ => None,
    });
    let (dest, narrow) = match narrowed {
        Some((dest, narrow)) => (dest, Some(narrow)),
        None => (mixed, None),
    };
    Some(Decode {
        read: *read,
        dest,
        unnarrowed: mixed,
        inverse,
        xor,
        addend,
        narrow,
    })
}

/// The width an encode or decode wraps at: its narrowing conversion's, or its value's.
fn width_of(narrow: Option<(SsaType, bool)>, ssa: &SsaFunction, var: SsaVarId) -> Option<u32> {
    if let Some((target, _)) = narrow {
        return narrow_width(&target);
    }
    match ssa.variable(var).map(|v| v.var_type().clone())? {
        SsaType::I64 | SsaType::U64 => Some(64),
        _ => Some(32),
    }
}

/// Whether a value of type `value` is already what narrowing to `target` makes it.
fn same_width(value: &SsaType, target: &SsaType) -> bool {
    matches!(
        (value, target),
        (SsaType::I8, SsaType::I8)
            | (SsaType::U8, SsaType::U8)
            | (SsaType::I16, SsaType::I16)
            | (SsaType::U16 | SsaType::Char, SsaType::U16 | SsaType::Char)
    )
}

/// The width of an 8- or 16-bit integer type.
fn narrow_width(target: &SsaType) -> Option<u32> {
    match target {
        SsaType::I8 | SsaType::U8 => Some(8),
        SsaType::I16 | SsaType::U16 | SsaType::Char => Some(16),
        _ => None,
    }
}

/// The bits of an integer constant.
fn bits(value: &ConstValue) -> Option<u64> {
    match *value {
        ConstValue::I8(v) => Some(i64::from(v).cast_unsigned()),
        ConstValue::I16(v) => Some(i64::from(v).cast_unsigned()),
        ConstValue::I32(v) => Some(i64::from(v).cast_unsigned()),
        ConstValue::I64(v) => Some(v.cast_unsigned()),
        ConstValue::U8(v) => Some(u64::from(v)),
        ConstValue::U16(v) => Some(u64::from(v)),
        ConstValue::U32(v) => Some(u64::from(v)),
        ConstValue::U64(v) => Some(v),
        _ => None,
    }
}

/// `decoded`, the low bits of a local's value, as a constant of `like`'s type, extended as the
/// local's narrowing conversion extends it.
fn same_type(
    like: &ConstValue,
    decoded: u64,
    narrow: Option<(SsaType, bool)>,
) -> Option<ConstValue> {
    #[allow(clippy::cast_possible_truncation)]
    let extended = match narrow.map(|(target, _)| target) {
        Some(SsaType::I8) => i64::from(decoded as u8 as i8).cast_unsigned(),
        Some(SsaType::I16) => i64::from(decoded as u16 as i16).cast_unsigned(),
        _ => decoded,
    };
    #[allow(clippy::cast_possible_truncation)]
    Some(match like {
        ConstValue::I32(_) => ConstValue::I32((extended as u32).cast_signed()),
        ConstValue::I64(_) => ConstValue::I64(extended.cast_signed()),
        ConstValue::U32(_) => ConstValue::U32(extended as u32),
        ConstValue::U64(_) => ConstValue::U64(extended),
        _ => return None,
    })
}

/// The instruction or phi defining each variable, read from the instructions and phis
/// themselves rather than from recorded definition sites.
struct Defs<'a> {
    ssa: &'a SsaFunction,
    sites: HashMap<SsaVarId, (usize, usize)>,
    /// Each phi's result, with the variables it merges.
    phis: HashMap<SsaVarId, Vec<SsaVarId>>,
}

impl<'a> Defs<'a> {
    fn of(ssa: &'a SsaFunction) -> Self {
        let phis = ssa
            .iter_phis()
            .map(|(_, _, phi)| {
                let operands = phi
                    .operands()
                    .iter()
                    .map(|operand| operand.value())
                    .collect();
                (phi.result(), operands)
            })
            .collect();
        Defs {
            ssa,
            sites: definition_sites(ssa),
            phis,
        }
    }

    /// The operation defining `var`, if an instruction does.
    fn op(&self, var: SsaVarId) -> Option<&'a SsaOp<CilTarget>> {
        let &(block_idx, instr_idx) = self.sites.get(&var)?;
        self.ssa
            .block(block_idx)?
            .instructions()
            .get(instr_idx)
            .map(|instr| instr.op())
    }

    /// The integer constant `var` is, as its 64 bits.
    fn bits(&self, var: SsaVarId) -> Option<u64> {
        match self.op(var)? {
            SsaOp::Const { value, .. } => bits(value),
            _ => None,
        }
    }

    /// The constant `var` is.
    fn constant(&self, var: SsaVarId) -> Option<&'a ConstValue> {
        match self.op(var)? {
            SsaOp::Const { value, .. } => Some(value),
            _ => None,
        }
    }
}

/// Where each variable an instruction defines is defined: block and index.
fn definition_sites(ssa: &SsaFunction) -> HashMap<SsaVarId, (usize, usize)> {
    let mut sites = HashMap::new();
    for (block_idx, block) in ssa.iter_blocks() {
        for (instr_idx, instr) in block.instructions().iter().enumerate() {
            if let Some(dest) = instr.op().dest() {
                sites.insert(dest, (block_idx, instr_idx));
            }
        }
    }
    sites
}

/// Replaces the instruction defining `var` with `op`.
fn set_definition(
    ssa: &mut SsaFunction,
    sites: &HashMap<SsaVarId, (usize, usize)>,
    var: SsaVarId,
    op: SsaOp<CilTarget>,
) {
    if let Some(&(block_idx, instr_idx)) = sites.get(&var) {
        if let Some(instr) = ssa
            .block_mut(block_idx)
            .and_then(|block| block.instruction_mut(instr_idx))
        {
            instr.set_op(op);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{CallGraph, SsaFunctionBuilder},
        metadata::token::Token,
        testkit::passes::run_verified,
    };

    /// A 32-bit key: the xor key, an odd multiplier and its inverse, the addend.
    const XOR: i32 = 0x5A5A_5A5A;
    const MULTIPLIER: i32 = 0x2F2F_2F2F;
    const ADDEND: i32 = 0x1234;

    /// The inverse of an odd multiplier modulo 2^32.
    fn inverse(multiplier: i32) -> i32 {
        let m = multiplier.cast_unsigned();
        let mut inverse = m;
        for _ in 0..5 {
            inverse = inverse.wrapping_mul(2u32.wrapping_sub(m.wrapping_mul(inverse)));
        }
        inverse.cast_signed()
    }

    macro_rules! encode {
        ($b:expr, $x:expr, $xor:expr) => {{
            let k = $b.const_i32($xor);
            let mixed = $b.xor($x, k);
            let m = $b.const_i32(MULTIPLIER);
            let product = $b.mul(mixed, m);
            let a = $b.const_i32(ADDEND);
            $b.add(product, a)
        }};
    }

    macro_rules! decode {
        ($b:expr, $y:expr, $xor:expr) => {{
            let a = $b.const_i32(ADDEND);
            let difference = $b.sub($y, a);
            let m = $b.const_i32(inverse(MULTIPLIER));
            let product = $b.mul(difference, m);
            let k = $b.const_i32($xor);
            $b.xor(product, k)
        }};
    }

    /// A counting loop over an encoded local: `i = 0; while (n) i = i + 1; return i;`, its
    /// versions joined by a phi. `exit_xor` keys the decode on exit; `leak` also returns the
    /// encoded value itself.
    fn counting_loop(exit_xor: i32, leak: bool) -> (SsaFunction, Vec<SsaVarId>) {
        let mut decoded = Vec::new();
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let n = f.arg(0, SsaType::I32);
                // The value the loop body stores, read by the phi on the back edge.
                let next = f.var();
                let mut first = None;
                f.block(0, |b| {
                    let zero = b.const_i32(0);
                    first = Some(encode!(b, zero, XOR));
                    b.jump(1);
                });
                let first = first.expect("block 0");
                let mut phi = None;
                f.block(1, |b| {
                    let merged = b.phi(&[(0, first), (1, next)]);
                    let i = decode!(b, merged, XOR);
                    decoded.push(i);
                    let one = b.const_i32(1);
                    let incremented = b.add(i, one);
                    let stored = encode!(b, incremented, XOR);
                    b.op(SsaOp::Copy {
                        dest: next,
                        src: stored,
                    });
                    b.branch(n, 1, 2);
                    phi = Some(merged);
                });
                let phi = phi.expect("block 1");
                f.block(2, |b| {
                    let i = decode!(b, phi, exit_xor);
                    decoded.push(i);
                    if leak {
                        b.ret_val(phi);
                    } else {
                        b.ret_val(i);
                    }
                });
            })
            .expect("builds");
        (ssa, decoded)
    }

    fn run(ssa: &mut SsaFunction) -> bool {
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        run_verified(
            &LocalEncodingReversalPass,
            ssa,
            &MethodRef::new(Token::new(0x0600_0001)),
            &ctx,
        )
        .expect("runs")
    }

    #[test]
    fn a_loop_carried_encoded_local_is_carried_plain() {
        let (mut ssa, decoded) = counting_loop(XOR, false);
        assert!(run(&mut ssa));
        for var in decoded {
            assert!(
                matches!(ssa.get_definition(var), Some(SsaOp::Copy { .. })),
                "{var:?}: {:?}",
                ssa.get_definition(var)
            );
        }
    }

    #[test]
    fn an_encoded_value_read_plain_is_left_encoded() {
        let (mut ssa, _) = counting_loop(XOR, true);
        assert!(!run(&mut ssa));
    }

    #[test]
    fn a_decode_with_another_key_is_left_encoded() {
        let (mut ssa, _) = counting_loop(XOR ^ 1, false);
        assert!(!run(&mut ssa));
    }
}

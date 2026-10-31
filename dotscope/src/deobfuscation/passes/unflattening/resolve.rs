//! Direct resolution of dispatcher edges.
//!
//! # Why this exists
//!
//! Control flow flattening replaces every original edge `A -> B` with a pair of
//! edges through a dispatcher: `A` assigns the state value that encodes `B` and
//! jumps to the dispatcher, which switches on that value and lands on `B`.
//! Undoing it means recovering, for each edge that feeds the dispatcher, the
//! state value travelling along it - and then rewiring that edge straight to the
//! block the dispatcher would have chosen.
//!
//! That is a *per-edge* question, and SSA already answers it: the state reaching
//! the dispatcher is a phi whose operands are indexed by predecessor, so the
//! value arriving from `A` is exactly the operand `A` contributes. No execution
//! path has to be explored to read it.
//!
//! The alternative - walking the method from entry and forking at every
//! conditional to see which states show up where - answers the same question by
//! enumerating paths, and there are exponentially many of those. On a flattened
//! NetReactor method that costs millions of trace nodes per dispatcher to
//! recover a few hundred edges, and it re-explores the whole method once per
//! dispatcher because the walk always restarts at entry. Reading phi operands is
//! linear in the number of edges, and each dispatcher only reads its own.
//!
//! # Merge points
//!
//! The state does not always merge at the dispatcher itself. Obfuscators route
//! it through a chain of copies, and several original edges may meet at a phi
//! one or more blocks above the switch. An operand that is not constant is
//! therefore followed to the phi that defines it, and that phi's operands are
//! resolved in turn. Rewiring then targets the edges into *that* block, which is
//! only sound when everything between it and the dispatcher is state plumbing -
//! copies and unconditional jumps - so the blocks skipped carry no program
//! behaviour. [`pure_chain_between`] enforces exactly that.
//!
//! # Partial results are safe
//!
//! An edge whose state cannot be determined is simply left alone: it keeps
//! routing through the dispatcher, which stays correct but flattened. Coverage
//! degrades, never correctness.
//!
//! Resolution itself is a pure read of the function; [`apply_rewires`] performs
//! the mutation.

use std::collections::{BTreeMap, BTreeSet};

use analyssa::analysis::consts::{destination_width, evaluate_const_op};
use rustc_hash::FxHashMap;

use crate::{
    analysis::{
        CmpKind, ConstValue, DefSite, PhiNode, SsaCfg, SsaFunction, SsaInstruction, SsaOp,
        SsaVarId, VariableOrigin,
    },
    deobfuscation::passes::unflattening::dispatcher::Dispatcher,
    metadata::{token::Token, typesystem::PointerSize},
};

/// Maximum definition-chain hops followed when folding a state value.
///
/// State encodings are short arithmetic chains - a constant, or a constant
/// combined with the previous state. A chain longer than this is not a state
/// computation, and giving up leaves the edge routed through the dispatcher.
const MAX_FOLD_DEPTH: usize = 24;

/// Maximum blocks walked along a dispatcher's overflow-check chain.
///
/// The chain has one link per state value that falls outside the switch table.
/// The bound only stops a malformed or adversarial CFG from walking forever;
/// links beyond it simply stay unresolved.
const MAX_OVERFLOW_CHAIN: usize = 4096;

/// Maximum nesting of state merge points followed above the dispatcher.
///
/// One level covers the usual "cases meet in a preheader" shape; deeper nesting
/// occurs when an obfuscator stacks several merges. Beyond this the remaining
/// edges stay unresolved.
const MAX_MERGE_DEPTH: usize = 8;

/// Maximum blocks on a state-plumbing chain between a merge point and the
/// dispatcher.
const MAX_CHAIN_LEN: usize = 16;

/// Maximum distinct states explored by the propagation fixed-point.
///
/// One state per original basic block is the norm; the bound only stops a
/// mis-detected dispatcher from enumerating an unbounded value space.
const MAX_PROPAGATED_STATES: usize = 4096;

/// Maximum blocks in one dispatched case's region.
const MAX_REGION: usize = 4096;

/// One edge to rewire so it bypasses the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rewire {
    /// Block whose terminator is edited.
    pub from: usize,
    /// Successor currently named by that terminator.
    pub old: usize,
    /// Block the dispatcher would have transferred control to.
    pub new: usize,
    /// State value travelling along the edge.
    pub state: i64,
}

/// Summary of one dispatcher's edge resolution, for reporting.
#[derive(Debug, Clone, Default)]
pub struct ResolutionStats {
    /// Edges resolved to a dispatch target.
    pub resolved: usize,
    /// Edges whose state could not be determined.
    pub unresolved: usize,
    /// Edges dropped because another edge from the same block wanted a
    /// different target.
    pub conflicts: usize,
    /// Entries recovered from the dispatcher's overflow-check chain.
    pub overflow_entries: usize,
    /// Distinct states in the dispatch table (switch table plus overflow).
    pub table_size: usize,
    /// Why edges failed to resolve, for diagnosing coverage gaps.
    pub reasons: UnresolvedReasons,
}

/// Counts of why edges could not be resolved.
#[derive(Debug, Clone, Default)]
pub struct UnresolvedReasons {
    /// The state folded, but named no block control could be sent to.
    pub no_target: usize,
    /// The state is not constant and is not defined by a phi either.
    pub not_constant: usize,
    /// The state merges at a phi, but the blocks between it and the dispatcher
    /// carry program behaviour and cannot be skipped.
    pub impure_chain: usize,
}

/// Maps a state value to the block the dispatcher transfers control to.
///
/// Built once per dispatcher from the switch table plus the chain of equality
/// checks hanging off the default arm, which is where obfuscators put states
/// whose encoded index falls outside the table.
pub struct DispatchTable {
    /// Switch targets, indexed by the value the switch operand evaluates to.
    cases: Vec<usize>,
    /// The variable the switch dispatches on.
    switch_var: SsaVarId,
    /// The phi carrying the raw state into the dispatcher.
    state_var: SsaVarId,
    /// Raw state value to target, recovered from the overflow-check chain.
    overflow: BTreeMap<i64, usize>,
    /// Block reached when nothing matches - the end of the overflow chain.
    fallthrough: Option<usize>,
    /// Whether each block still holds instructions.
    ///
    /// Unflattening runs repeatedly as the pipeline iterates, and a previous
    /// round empties the machinery it made unreachable. Those husks stay in the
    /// block list and remain named by the switch table, so a later round can
    /// resolve a state to one of them. Rewiring control into a block with no
    /// terminator produces a function that cannot be laid out, and the passes
    /// that follow mangle the surrounding branch trying to make sense of it -
    /// which is how a live case block loses its arm. A husk is therefore not a
    /// valid answer, and the edge stays with the dispatcher instead.
    executable: Vec<bool>,
}

impl DispatchTable {
    /// Builds the dispatch table for `dispatcher`.
    ///
    /// `state_var` is the phi whose value a lookup supplies; the switch operand
    /// is evaluated from it rather than from a reconstructed transform, so the
    /// index is whatever the dispatcher itself would compute.
    pub fn build(
        ssa: &SsaFunction,
        dispatcher: &Dispatcher,
        state_var: SsaVarId,
        folder: &mut StateFolder<'_>,
    ) -> Self {
        let mut table = Self {
            cases: dispatcher.cases.clone(),
            switch_var: dispatcher.switch_var,
            state_var,
            overflow: BTreeMap::new(),
            fallthrough: None,
            executable: ssa
                .blocks()
                .iter()
                .map(|block| !block.instructions().is_empty())
                .collect(),
        };
        table.walk_overflow_chain(ssa, dispatcher.default, folder);
        table
    }

    /// Whether control can be sent to `block`.
    fn is_executable(&self, block: usize) -> bool {
        self.executable.get(block).copied().unwrap_or(false)
    }

    /// Walks the equality-check chain on the dispatcher's default arm.
    ///
    /// Each link compares the state against a constant and branches to that
    /// state's real target, falling through to the next check. The walk stops at
    /// the first block that is not such a check; that block is where an
    /// unmatched state ends up.
    fn walk_overflow_chain(
        &mut self,
        ssa: &SsaFunction,
        default: usize,
        folder: &mut StateFolder<'_>,
    ) {
        let mut current = default;
        let mut seen: BTreeSet<usize> = BTreeSet::new();

        for _ in 0..MAX_OVERFLOW_CHAIN {
            if !seen.insert(current) {
                return;
            }
            let Some(block) = ssa.block(current) else {
                return;
            };
            let Some(SsaOp::BranchCmp {
                left,
                right,
                cmp: CmpKind::Eq,
                true_target,
                false_target,
                ..
            }) = block.control_terminator()
            else {
                self.fallthrough = Some(current);
                return;
            };

            // Exactly one side is the constant the state is tested against; the
            // other is the state itself. If both fold, the comparison is already
            // decided and is not a dispatch link.
            let left_const = folder.fold(*left);
            let right_const = folder.fold(*right);
            let value = match (left_const, right_const) {
                (Some(v), None) | (None, Some(v)) => v,
                _ => {
                    self.fallthrough = Some(current);
                    return;
                }
            };

            self.overflow.entry(value).or_insert(*true_target);
            current = *false_target;
        }
    }

    /// Returns the block the dispatcher sends `state` to.
    ///
    /// The case index is obtained by evaluating the dispatcher's own switch
    /// operand with the state pinned to `state`, so however the obfuscator
    /// encodes the index - a modulo, an xor and a modulo, a table lookup folded
    /// into arithmetic - the answer is the one the dispatcher would reach.
    /// Applying a separately reconstructed transform instead would silently
    /// mis-dispatch whenever detection's model of the encoding was incomplete.
    pub fn lookup(&self, folder: &mut StateFolder<'_>, state: StateValue) -> Option<usize> {
        // The overflow chain tests the raw state, so it is consulted first: its
        // entries are the states the switch table cannot express.
        let target = if let Some(&target) = self.overflow.get(&state.value) {
            target
        } else {
            let index = folder.fold_with(self.switch_var, self.state_var, state)?;
            let index = usize::try_from(index.value).ok()?;
            self.cases.get(index).copied().or(self.fallthrough)?
        };

        self.is_executable(target).then_some(target)
    }

    /// Number of distinct states this table can dispatch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cases.len().saturating_add(self.overflow.len())
    }

    /// Whether the table can dispatch no states at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty() && self.overflow.is_empty()
    }

    /// Number of entries recovered from the overflow chain.
    #[must_use]
    pub fn overflow_len(&self) -> usize {
        self.overflow.len()
    }
}

/// A folded state value together with the width its arithmetic wraps at.
///
/// CIL evaluates `int32` operands at 32 bits and wraps there. State encodings
/// lean on that: `state * 1975223132` is only the intended value once the
/// product is truncated. Folding at 64 bits instead yields a number that
/// matches no case, so the width travels with the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateValue {
    /// The value, sign-extended from its own width.
    pub value: i64,
    /// Whether arithmetic on it wraps at 64 bits rather than 32.
    pub wide: bool,
}

impl StateValue {
    /// A 32-bit value, sign-extended.
    fn narrow(value: i64) -> Self {
        Self {
            value: truncate32(value),
            wide: false,
        }
    }

    /// A 64-bit value.
    fn wide(value: i64) -> Self {
        Self { value, wide: true }
    }

    /// The constant this value is, in the type it is held as on the stack.
    #[allow(clippy::cast_possible_truncation)] // A narrow value is its low 32 bits.
    fn to_const(self) -> ConstValue {
        if self.wide {
            ConstValue::I64(self.value)
        } else {
            ConstValue::I32(self.value as i32)
        }
    }

    /// The state value a constant is, if it is an integer.
    ///
    /// Only the 64-bit kinds are wide: CIL widens every narrower integer, and a
    /// boolean, to `int32` on the stack.
    fn from_const(value: &ConstValue) -> Option<Self> {
        match value {
            ConstValue::I64(v) | ConstValue::NativeInt(v) => Some(Self::wide(*v)),
            ConstValue::U64(v) | ConstValue::NativeUInt(v) => Some(Self::wide(v.cast_signed())),
            other => other.as_i64().map(Self::narrow),
        }
    }
}

/// Sign-extends the low 32 bits of `value`, as CIL `int32` arithmetic does.
#[allow(clippy::cast_possible_truncation)]
fn truncate32(value: i64) -> i64 {
    i64::from(value as i32)
}

/// What a variable's defining instruction contributes to a fold.
///
/// Extracted before recursing so the borrow of the SSA ends before the folder
/// needs itself mutably again.
enum Folded<'s> {
    /// The definition is itself the value.
    Value(StateValue),
    /// The value passes through unchanged from one operand.
    Forward(SsaVarId),
    /// The value is an operation on its operands that a constant evaluation
    /// computes: arithmetic, bitwise, shifts, rotates, comparisons and
    /// conversions, each at the width and signedness the operation states.
    Computed(&'s SsaOp),
    /// The value is what a method returns for these arguments.
    Call(Token, Vec<SsaVarId>),
    /// Not a foldable definition.
    Opaque,
}

/// Whether `op` is an operation a constant evaluation computes from its
/// operands alone.
fn is_computed(op: &SsaOp) -> bool {
    matches!(
        op,
        SsaOp::Add { .. }
            | SsaOp::Sub { .. }
            | SsaOp::Mul { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::AddOvf { .. }
            | SsaOp::SubOvf { .. }
            | SsaOp::MulOvf { .. }
            | SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. }
            | SsaOp::Rol { .. }
            | SsaOp::Ror { .. }
            | SsaOp::BSwap { .. }
            | SsaOp::Neg { .. }
            | SsaOp::Not { .. }
            | SsaOp::Ceq { .. }
            | SsaOp::Clt { .. }
            | SsaOp::Cgt { .. }
            | SsaOp::IntConv { .. }
    )
}

/// Where a folder finds the body of a method a call names.
///
/// A state encoding may put part of itself behind a call - ConfuserEx's x86
/// control flow computes the next state in a helper - and the value is a
/// constant there as much as it is in a `mul` or an `xor`. Reading it needs the
/// callee, which the dispatcher's own function does not contain.
pub trait CalleeBodies {
    /// The callee's SSA, or `None` when this method's body is not available.
    ///
    /// # Arguments
    ///
    /// * `token` - The method whose body to read.
    fn body(&self, token: Token) -> Option<SsaFunction>;
}

/// Folds SSA values to constants by walking definition chains.
///
/// Memoized across queries for one function: a state encoding usually shares its
/// constants between many edges, and the dispatcher's overflow chain re-asks
/// about the same state variable at every link.
pub struct StateFolder<'a> {
    ssa: &'a SsaFunction,
    /// Cached folds, keyed by the binding they were computed under.
    ///
    /// A fold is only valid for the pinning it assumed, so the binding is part
    /// of the key rather than a reason to discard the cache. Resolution asks
    /// about the same variables under hundreds of different states - every
    /// dispatch lookup evaluates the switch operand afresh - and clearing
    /// between them made each one re-walk its definition chain from scratch.
    memo: FxHashMap<(Bindings, SsaVarId), Option<StateValue>>,
    /// Variable pinned to a value for the current query, and that value.
    ///
    /// Encodings that derive each state from the previous one are only constant
    /// once the previous state is known. Pinning the dispatcher's state phi to a
    /// concrete state makes the whole chain below it fold.
    bindings: Bindings,
    /// The values this function's arguments hold.
    ///
    /// Empty while folding the dispatcher's own function, where an argument is
    /// whatever the caller passed and so not a constant. Filled when the folder
    /// is evaluating a callee, which is the one place an argument has a value
    /// known here.
    arguments: Vec<StateValue>,
    /// Where to find a callee's body, when calls may be folded through.
    callees: Option<&'a dyn CalleeBodies>,
    /// How many calls deep this folder already is.
    ///
    /// A state helper calls nothing, but the bound is what stops a cycle of
    /// mutually recursive methods from folding forever.
    call_depth: usize,
    /// The width a native integer is evaluated at.
    ///
    /// A state encoding computes in `int32` and `int64`; native integers are
    /// taken at 64 bits, where they are the widest they can be.
    ptr_size: PointerSize,
}

/// How many nested calls a fold will follow.
const MAX_CALL_DEPTH: usize = 4;

/// Variables pinned for the current query.
///
/// Two slots are enough: one for the state a propagation round is exploring,
/// and one for the branch of a conditional state merge being case-split. They
/// are part of the memo key, so folds under different pinnings coexist.
type Bindings = [Option<(SsaVarId, StateValue)>; 2];

impl<'a> StateFolder<'a> {
    /// Creates a folder over `ssa`.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self {
            ssa,
            memo: FxHashMap::default(),
            bindings: [None, None],
            arguments: Vec::new(),
            callees: None,
            call_depth: 0,
            ptr_size: PointerSize::Bit64,
        }
    }

    /// Creates a folder that may read a constant out of a call.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The function whose values are folded.
    /// * `callees` - Where to find the body of a method a call names.
    #[must_use]
    pub fn with_callees(ssa: &'a SsaFunction, callees: &'a dyn CalleeBodies) -> Self {
        Self {
            callees: Some(callees),
            ..Self::new(ssa)
        }
    }

    /// The constant a method returns for these arguments, if it is one.
    ///
    /// Only where the answer depends on nothing but the arguments: a body that
    /// reads state from outside itself, or changes anything, returns something
    /// this cannot claim to know. See [`Self::depends_only_on_arguments`].
    fn fold_call(&self, method: Token, arguments: Vec<StateValue>) -> Option<StateValue> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return None;
        }
        let callee = self.callees?.body(method)?;
        if !Self::depends_only_on_arguments(&callee) {
            return None;
        }

        // The one value the method hands back. Several returns could still
        // agree, but a state helper has one and demanding it keeps this from
        // claiming a value for a method whose answer depends on which path ran.
        let mut returned = None;
        for (_, _, instr) in callee.iter_instructions() {
            if let SsaOp::Return { value: Some(value) } = instr.op() {
                if returned.replace(*value).is_some() {
                    return None;
                }
            }
        }
        let returned = returned?;

        let mut inner = StateFolder {
            ssa: &callee,
            memo: FxHashMap::default(),
            bindings: [None, None],
            arguments,
            callees: self.callees,
            call_depth: self.call_depth.saturating_add(1),
            ptr_size: self.ptr_size,
        };
        inner.fold_at(returned, 0)
    }

    /// Whether a method's result is a function of its arguments alone.
    ///
    /// The fold reads the body as arithmetic over the arguments, so anything
    /// that brings a value in from elsewhere - a field, memory, another call
    /// this cannot see through - or that leaves a mark outside the method makes
    /// the reading wrong rather than merely incomplete.
    fn depends_only_on_arguments(callee: &SsaFunction) -> bool {
        callee.iter_instructions().all(|(_, _, instr)| {
            is_computed(instr.op())
                || matches!(
                    instr.op(),
                    SsaOp::Const { .. }
                        | SsaOp::Copy { .. }
                        | SsaOp::LoadArg { .. }
                        | SsaOp::Nop
                        | SsaOp::Jump { .. }
                        | SsaOp::Return { .. }
                )
        })
    }

    /// Folds `var` to a constant, or returns `None` if it is not constant.
    pub fn fold(&mut self, var: SsaVarId) -> Option<i64> {
        self.fold_value(var).map(|v| v.value)
    }

    /// Folds `var`, keeping the width its arithmetic wraps at.
    pub fn fold_value(&mut self, var: SsaVarId) -> Option<StateValue> {
        self.bindings = [None, None];
        self.fold_at(var, 0)
    }

    /// Folds `var` under an explicit set of pinnings.
    pub fn fold_bound(&mut self, var: SsaVarId, bindings: Bindings) -> Option<StateValue> {
        self.bindings = bindings;
        self.fold_at(var, 0)
    }

    /// Folds `var` with `state_var` pinned to `state`.
    ///
    /// Used to evaluate a state-dependent encoding at one concrete state.
    pub fn fold_with(
        &mut self,
        var: SsaVarId,
        state_var: SsaVarId,
        state: StateValue,
    ) -> Option<StateValue> {
        self.bindings = [Some((state_var, state)), None];
        self.fold_at(var, 0)
    }

    fn fold_at(&mut self, var: SsaVarId, depth: usize) -> Option<StateValue> {
        if depth > MAX_FOLD_DEPTH {
            return None;
        }
        let key = (self.bindings, var);
        if let Some(&cached) = self.memo.get(&key) {
            return cached;
        }
        // Seed the memo with "not constant" before recursing. A definition chain
        // that loops back on itself then terminates instead of recursing to the
        // depth bound on every visit.
        self.memo.insert(key, None);

        let result = match self.classify(var) {
            Folded::Value(v) => Some(v),
            Folded::Forward(src) => self.fold_at(src, depth.saturating_add(1)),
            Folded::Computed(op) => {
                let mut operands: Vec<(SsaVarId, ConstValue)> = Vec::new();
                for used in op.uses() {
                    let value = self.fold_at(used, depth.saturating_add(1))?;
                    operands.push((used, value.to_const()));
                }
                let lookup = |var: SsaVarId| {
                    operands
                        .iter()
                        .find(|(operand, _)| *operand == var)
                        .map(|(_, value)| value.clone())
                };
                evaluate_const_op(op, destination_width(self.ssa, op), lookup, self.ptr_size)
                    .as_ref()
                    .and_then(StateValue::from_const)
            }
            Folded::Call(method, args) => {
                let mut values = Vec::with_capacity(args.len());
                for arg in &args {
                    values.push(self.fold_at(*arg, depth.saturating_add(1))?);
                }
                self.fold_call(method, values)
            }
            Folded::Opaque => None,
        };

        self.memo.insert(key, result);
        result
    }

    /// Follows copies from `var` to the value they ultimately name.
    ///
    /// State values reach the dispatcher through chains of copies inserted by
    /// the obfuscator; the phi that merges them sits at the end of such a chain.
    fn copy_root(&self, var: SsaVarId) -> SsaVarId {
        let mut current = var;
        for _ in 0..MAX_FOLD_DEPTH {
            match self.classify(current) {
                Folded::Forward(src) => current = src,
                _ => break,
            }
        }
        current
    }

    /// Reads the defining instruction of `var` into a [`Folded`].
    fn classify(&self, var: SsaVarId) -> Folded<'a> {
        // A pinned variable stands for its value regardless of how it is
        // defined; that is the whole point of pinning the state phi.
        for pinned in self.bindings.iter().flatten() {
            if pinned.0 == var {
                return Folded::Value(pinned.1);
            }
        }
        let Some(variable) = self.ssa.variable(var) else {
            return Folded::Opaque;
        };
        // Evaluating a callee, an argument stands for what the call passed.
        if let VariableOrigin::Argument(index) = variable.origin() {
            if let Some(&value) = self.arguments.get(index as usize) {
                return Folded::Value(value);
            }
        }
        let site = variable.def_site();
        // No instruction index means the definition is a phi or the function
        // entry; neither is a constant on its own.
        let Some(index) = site.instruction else {
            return Folded::Opaque;
        };
        let Some(op) = self
            .ssa
            .block(site.block)
            .and_then(|b| b.instructions().get(index))
            .map(|i| i.op())
        else {
            return Folded::Opaque;
        };

        match op {
            SsaOp::Const { value, .. } => value.as_i64().map_or(Folded::Opaque, |v| {
                // CIL widens every sub-word integer to int32 on the stack, so
                // only the genuinely 64-bit constants wrap at 64 bits.
                let wide = matches!(
                    value,
                    ConstValue::I64(_)
                        | ConstValue::U64(_)
                        | ConstValue::NativeInt(_)
                        | ConstValue::NativeUInt(_)
                );
                Folded::Value(if wide {
                    StateValue::wide(v)
                } else {
                    StateValue::narrow(v)
                })
            }),
            SsaOp::Copy { src, .. } => Folded::Forward(*src),
            // A call, and what it was passed. Classified the same way whether
            // or not this folder can read the callee's body: what a value is
            // made of does not depend on that, and the backward search for the
            // state phi walks these arguments to find it. Folding is where the
            // body is needed, and it declines without one.
            SsaOp::Call { method, args, .. } => Folded::Call(method.token(), args.clone()),
            // In a callee evaluation, a load of an argument is that argument.
            SsaOp::LoadArg { arg_index, .. } => self
                .arguments
                .get(*arg_index as usize)
                .map_or(Folded::Opaque, |&value| Folded::Value(value)),
            // Arithmetic and conversions, evaluated at the width and signedness
            // each states: a conversion truncates or extends, and a division
            // that would throw is no state at all.
            op if is_computed(op) => Folded::Computed(op),
            _ => Folded::Opaque,
        }
    }
}

/// Finds a phi the value depends on, anywhere in its expression.
///
/// A conditional state is rarely the phi itself. The obfuscator computes
/// `next = phi ^ key`, so the merge sits one or more operations below the value
/// on the edge. Case-splitting needs the phi wherever it is, and following only
/// copies from the top would miss it.
///
/// The search is breadth-first so the *shallowest* merge is found: that is the
/// one whose predecessors are closest to the value, and therefore the one whose
/// edges are safest to rewire.
fn dependency_phi<'s>(
    ssa: &'s SsaFunction,
    folder: &StateFolder<'_>,
    value: SsaVarId,
) -> Option<(usize, &'s PhiNode)> {
    let mut frontier = vec![value];
    let mut seen: BTreeSet<SsaVarId> = BTreeSet::new();

    for _ in 0..MAX_FOLD_DEPTH {
        let mut next = Vec::new();
        for var in frontier.drain(..) {
            if !seen.insert(var) {
                continue;
            }
            if let Some(found) = ssa.find_phi_defining(var) {
                return Some(found);
            }
            match folder.classify(var) {
                Folded::Forward(src) => next.push(src),
                Folded::Computed(op) => next.extend(op.uses()),
                // The state may reach the dispatcher through what a call was
                // passed, so the search continues into the arguments.
                Folded::Call(_, args) => next.extend(args),
                Folded::Value(_) | Folded::Opaque => {}
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    None
}

fn pure_chain_between(
    ssa: &SsaFunction,
    start: usize,
    end: usize,
    state_only: &BTreeSet<SsaVarId>,
) -> bool {
    let mut chain: Vec<usize> = Vec::new();
    let mut current = start;

    for _ in 0..MAX_CHAIN_LEN {
        if current == end {
            // Nothing on the chain may define a value that outlives it: control
            // reaching the dispatch target directly never runs these blocks, so
            // a use further on would have no definition. State encoding is
            // consumed by the dispatcher itself and dies with it, which is why
            // the usual chain passes this.
            return chain
                .iter()
                .all(|&block| defs_stay_within(ssa, block, &chain, end));
        }
        let Some(block) = ssa.block(current) else {
            return false;
        };
        let Some((terminator, body)) = block.instructions().split_last() else {
            return false;
        };
        // Only value plumbing may be skipped: constants and copies feeding the
        // state encoding, `pop` discarding the duplicate an encoding leaves on
        // the stack, and nops. Anything else could be program behaviour.
        if !body.iter().all(|instr| is_skippable(instr, state_only)) {
            return false;
        }
        match terminator.op() {
            SsaOp::Jump { target } => {
                chain.push(current);
                current = *target;
            }
            _ => return false,
        }
    }
    false
}

/// Whether an instruction can be skipped along with its block.
///
/// An instruction that produces a state-only value does nothing the program can
/// observe once the state machine is gone, whatever its opcode - the arithmetic
/// of an encoding qualifies just as much as a copy. Anything that produces a
/// value the program still uses, or that acts on the world at all, does not.
fn is_skippable(instr: &SsaInstruction, state_only: &BTreeSet<SsaVarId>) -> bool {
    match instr.def() {
        Some(def) => instr.is_pure() && state_only.contains(&def),
        None => matches!(instr.op(), SsaOp::Nop | SsaOp::Pop { .. }),
    }
}

/// Whether every value defined in `block` is only read inside the chain.
///
/// `end` is the dispatcher, which reads the state through its phi; those reads
/// disappear along with the dispatcher once its edges are rewired, so they do
/// not stop the chain from being skippable.
fn defs_stay_within(ssa: &SsaFunction, block: usize, chain: &[usize], end: usize) -> bool {
    let Some(ssa_block) = ssa.block(block) else {
        return false;
    };
    ssa_block
        .instructions()
        .iter()
        .filter_map(|instr| instr.def())
        .all(|def| {
            ssa.variable(def).is_none_or(|variable| {
                variable
                    .uses()
                    .iter()
                    .all(|site| site.block == end || chain.contains(&site.block))
            })
        })
}

/// Finds the phi at the dispatcher that carries the state value.
///
/// Prefers the phi the detector identified, then a phi defining the switch
/// operand itself - the shape when no transform is applied. Failing both, the
/// switch operand's definition chain is walked to find the phi it is computed
/// from, which is what an encoded dispatcher (`(state ^ key) % n`) looks like.
fn state_phi_at<'s>(ssa: &'s SsaFunction, dispatcher: &Dispatcher) -> Option<&'s PhiNode> {
    let block = ssa.block(dispatcher.block)?;
    if let Some(state) = dispatcher.state_phi {
        if let Some(phi) = block.phi_nodes().iter().find(|p| p.result() == state) {
            return Some(phi);
        }
    }
    if let Some(phi) = block
        .phi_nodes()
        .iter()
        .find(|p| p.result() == dispatcher.switch_var)
    {
        return Some(phi);
    }

    let folder = StateFolder::new(ssa);
    let mut frontier = vec![dispatcher.switch_var];
    let mut seen: BTreeSet<SsaVarId> = BTreeSet::new();
    for _ in 0..MAX_FOLD_DEPTH {
        let mut next = Vec::new();
        for var in frontier.drain(..) {
            if !seen.insert(var) {
                continue;
            }
            if let Some(phi) = block.phi_nodes().iter().find(|p| p.result() == var) {
                return Some(phi);
            }
            match folder.classify(var) {
                Folded::Forward(src) => next.push(src),
                Folded::Computed(op) => next.extend(op.uses()),
                // The state may reach the dispatcher through what a call was
                // passed, so the search continues into the arguments.
                Folded::Call(_, args) => next.extend(args),
                Folded::Value(_) | Folded::Opaque => {}
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    None
}

/// Values that exist only to drive the state machine.
///
/// A value is state-only when every instruction that reads it either lives in
/// the dispatcher itself or produces another state-only value. The chain ends
/// at the dispatcher's phi operands, which no instruction reads - they are
/// consumed by the merge, and the merge disappears with the dispatcher.
///
/// This is a greatest fixed point: everything is assumed state-only, and a
/// value is struck out as soon as some instruction that is *not* machinery
/// reads it. Striking one value out can strike out the values feeding it, so
/// the sweep repeats until nothing changes.
///
/// The distinction matters because ConfuserEx decodes the state inside the
/// dispatcher and has every case block read the decoded value back to compute
/// its successor. Those reads look like real uses, but they die with the state
/// machine - so the dispatcher can still be bypassed. A case block that used
/// the same value for actual work would not be struck out, and bypassing would
/// then be unsafe.
///
/// A phi operand is a read like any other, and the sweep has to follow it. A
/// user value that crosses the dispatcher does so through a phi, so leaving
/// phis out of the propagation leaves that value assumed state-only for ever:
/// the instruction computing it is then taken for state plumbing, the chain
/// holding it reads as skippable, and the rewire routes control straight past
/// the block that does the work. `DemoCharOperations` lost `consonantCount++`
/// exactly that way - both arms of the `<= 'z'` test ended up at the same
/// block, and the counter stayed zero.
fn state_only_values(ssa: &SsaFunction, dispatcher_block: usize) -> BTreeSet<SsaVarId> {
    let mut state_only: BTreeSet<SsaVarId> = ssa
        .variables()
        .iter()
        .map(|variable| variable.id())
        .collect();

    loop {
        let mut struck = false;
        for (index, block) in ssa.iter_blocks() {
            // Everything the dispatcher itself does is machinery, including
            // the merge it dispatches on.
            if index == dispatcher_block {
                continue;
            }
            for phi in block.phi_nodes() {
                if state_only.contains(&phi.result()) {
                    continue;
                }
                for operand in phi.operands() {
                    if state_only.remove(&operand.value()) {
                        struck = true;
                    }
                }
            }
            for instr in block.instructions() {
                if instr.def().is_some_and(|def| state_only.contains(&def)) {
                    continue;
                }
                for used in instr.uses() {
                    if state_only.remove(&used) {
                        struck = true;
                    }
                }
            }
        }
        if !struck {
            break;
        }
    }

    state_only
}

/// Whether the dispatcher block computes nothing the blocks after it depend on.
///
/// A bare `switch` on a merged state is transparent: control that bypasses it
/// misses no computation, so rewiring some edges while others still route
/// through it is safe.
///
/// A dispatcher that decodes the state in its own body is not. ConfuserEx's
/// `(state ^ key)` is duplicated into a local that each case block reads to
/// derive its successor, so a bypassing edge skips the definition the surviving
/// paths still use. Such a dispatcher may only be bypassed if *every* edge is
/// rewired, which makes the whole block dead and the question moot.
///
/// Phi nodes do not count: they name a merge rather than compute anything, and
/// `rebuild_ssa` re-derives them from the rewired graph.
fn dispatcher_is_transparent(
    ssa: &SsaFunction,
    dispatcher_block: usize,
    state_only: &BTreeSet<SsaVarId>,
) -> bool {
    let Some(block) = ssa.block(dispatcher_block) else {
        return false;
    };
    let Some((_terminator, body)) = block.instructions().split_last() else {
        return false;
    };
    // A definition that leaves the dispatcher is fine as long as everything it
    // feeds is state machinery, which dies along with the dispatcher. Requiring
    // the definition never to leave at all would refuse every encoded
    // dispatcher, and with it every ConfuserEx method.
    body.iter()
        .filter_map(SsaInstruction::def)
        .all(|def| state_only.contains(&def))
}

/// Blocks reachable from `start` without entering `stop`.
///
/// Used to find which edges into the dispatcher belong to one dispatched case,
/// so a state-dependent encoding is evaluated only where that state actually
/// arrives.
fn region_from(ssa: &SsaFunction, start: usize, stop: usize, budget: usize) -> BTreeSet<usize> {
    let mut seen = BTreeSet::new();
    if start == stop {
        return seen;
    }
    let mut frontier = vec![start];
    while let Some(current) = frontier.pop() {
        if current == stop || !seen.insert(current) {
            continue;
        }
        if seen.len() > budget {
            break;
        }
        if let Some(op) = ssa.block(current).and_then(|b| b.control_terminator()) {
            frontier.extend(op.successors());
        }
    }
    seen
}

/// Resolves every edge feeding `dispatcher` to the block it should reach.
///
/// Returns the rewires to apply and statistics for reporting. The SSA is only
/// read; use [`apply_rewires`] to perform the change.
pub fn resolve_dispatch_edges(
    ssa: &SsaFunction,
    dispatcher: &Dispatcher,
    callees: Option<&dyn CalleeBodies>,
) -> (Vec<Rewire>, ResolutionStats) {
    let mut folder = match callees {
        Some(callees) => StateFolder::with_callees(ssa, callees),
        None => StateFolder::new(ssa),
    };
    let mut stats = ResolutionStats::default();

    let Some(phi) = state_phi_at(ssa, dispatcher) else {
        // Without a state phi there is nothing per-edge to read: the switch
        // operand is computed inside the dispatcher from something that is not
        // merged at its entry.
        stats.unresolved = SsaCfg::from_ssa(ssa)
            .block_predecessors(dispatcher.block)
            .len();
        return (Vec::new(), stats);
    };

    let state_only = state_only_values(ssa, dispatcher.block);
    let table = DispatchTable::build(ssa, dispatcher, phi.result(), &mut folder);
    stats.overflow_entries = table.overflow_len();
    stats.table_size = table.len();

    // Pass one: read the states straight out of the phi graph. This resolves
    // encodings whose next state is a constant, following merges upward when
    // several original edges meet before the jump.
    let mut rewires: Vec<Rewire> = Vec::new();
    let mut states: Vec<StateValue> = Vec::new();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut unresolved: BTreeSet<usize> = BTreeSet::new();
    resolve_merge(
        ssa,
        &table,
        &mut folder,
        dispatcher.block,
        phi,
        dispatcher.block,
        0,
        &mut visited,
        &mut rewires,
        &mut states,
        &mut unresolved,
        &mut stats.reasons,
        None,
        None,
        &state_only,
    );

    // Pass two: encodings that derive each state from the previous one leave
    // edges no constant can be read from. Propagating concrete states through
    // the dispatcher resolves those, seeded with every state pass one proved
    // reachable - including states found behind a merge, which is the only way
    // a case block reached solely through a conditional becomes visible.
    if !unresolved.is_empty() {
        let (recovered, covered) = propagate_states(
            ssa,
            &table,
            dispatcher,
            phi,
            &mut folder,
            &states,
            &state_only,
        );
        for pred in covered {
            unresolved.remove(&pred);
        }
        rewires.extend(recovered);
    }

    let rewires = drop_conflicts(rewires, &mut stats);
    stats.unresolved = unresolved.len();

    // A dispatcher that decodes the state in its own body may only be bypassed
    // wholesale: leaving one edge routed through it means the surviving path
    // still needs the definitions a bypassing edge would skip.
    if stats.unresolved > 0 && !dispatcher_is_transparent(ssa, dispatcher.block, &state_only) {
        log::debug!(
            "CFF resolve b{}: {} edge(s) unresolved and the dispatcher decodes state \
             in its body, so none are rewired",
            dispatcher.block,
            stats.unresolved
        );
        stats.resolved = 0;
        return (Vec::new(), stats);
    }

    stats.resolved = rewires.len();
    (rewires, stats)
}

/// Resolves state-dependent encodings by propagating concrete states.
///
/// When the next state is computed from the current one - ConfuserEx's
/// `next = (state ^ key) * a ^ b` - no edge carries a constant, and the value
/// only becomes concrete once the state that reached the case block is known.
///
/// Starting from the states that *are* known, this walks the state machine the
/// way it actually runs: pin the state phi to a known state, see which case
/// block the dispatcher selects, evaluate the edges leaving that case block to
/// get the next states, and repeat until no new state appears. It is a
/// fixed-point over states - at most one iteration per original block - not an
/// enumeration of execution paths, so a method with many conditionals costs no
/// more than one with none.
///
/// An edge is only rewired when exactly one state can reach it. Sharing a tail
/// between cases, or falling through from one case into the next, puts an edge
/// in more than one state's region; the value it carries then depends on how
/// control arrived, which a single successor cannot express. Those edges keep
/// using the dispatcher rather than being wired to whichever state happened to
/// be examined last.
fn propagate_states(
    ssa: &SsaFunction,
    table: &DispatchTable,
    dispatcher: &Dispatcher,
    phi: &PhiNode,
    folder: &mut StateFolder<'_>,
    seeds: &[StateValue],
    state_only: &BTreeSet<SsaVarId>,
) -> (Vec<Rewire>, BTreeSet<usize>) {
    let state_var = phi.result();
    let operands: Vec<(usize, SsaVarId)> = phi
        .operands()
        .iter()
        .map(|op| (op.predecessor(), op.value()))
        .collect();

    // Seeds: the states already known without any context - the entry edge, and
    // whatever the detector recorded as the initial state.
    let mut worklist: Vec<StateValue> = seeds.to_vec();
    if let Some(initial) = dispatcher.initial_state {
        worklist.push(StateValue::narrow(initial));
    }
    for &(_, value) in &operands {
        if let Some(state) = folder.fold_value(value) {
            worklist.push(state);
        }
    }

    // Which states can reach each edge, and what the edge yields under each.
    let mut merged: Vec<Rewire> = Vec::new();
    // Dispatcher edges this pass accounted for, whether directly or by
    // resolving the merge that feeds them.
    let mut covered: BTreeSet<usize> = BTreeSet::new();
    let mut reaching: BTreeMap<usize, BTreeSet<i64>> = BTreeMap::new();
    let mut outcome: BTreeMap<(usize, i64), StateValue> = BTreeMap::new();
    let mut seen: BTreeSet<i64> = BTreeSet::new();

    while let Some(state) = worklist.pop() {
        if seen.len() >= MAX_PROPAGATED_STATES || !seen.insert(state.value) {
            continue;
        }
        let Some(target) = table.lookup(folder, state) else {
            continue;
        };

        let region = region_from(ssa, target, dispatcher.block, MAX_REGION);

        for &(pred, value) in &operands {
            if !region.contains(&pred) {
                continue;
            }
            reaching.entry(pred).or_default().insert(state.value);
            if let Some(next) = folder.fold_with(value, state_var, state) {
                outcome.insert((pred, state.value), next);
                worklist.push(next);
                continue;
            }

            // The edge's value is not constant even with the state pinned: an
            // original conditional inside this case picked between two
            // successors, and they meet at a phi before the jump. Its operands
            // are per-edge, and we are inside the region this state dispatches
            // to, so each one can be read under the same pinning. The edges to
            // rewire are that phi's, which is only sound when what lies between
            // it and the dispatcher is state plumbing.
            let Some((inner_block, inner_phi)) = dependency_phi(ssa, folder, value) else {
                continue;
            };
            if inner_block == dispatcher.block
                || !pure_chain_between(ssa, inner_block, dispatcher.block, state_only)
            {
                continue;
            }
            let inner: Vec<(usize, SsaVarId)> = inner_phi
                .operands()
                .iter()
                .map(|op| (op.predecessor(), op.value()))
                .collect();
            let phi_result = inner_phi.result();
            let pinned = Some((state_var, state));
            for (source, operand) in inner {
                // Read what the branch contributes, then the edge value with
                // the merge pinned to it - both under the state being explored.
                let Some(branch) = folder.fold_bound(operand, [pinned, None]) else {
                    continue;
                };
                let Some(next) = folder.fold_bound(value, [pinned, Some((phi_result, branch))])
                else {
                    continue;
                };
                let Some(target) = table.lookup(folder, next) else {
                    continue;
                };
                merged.push(Rewire {
                    from: source,
                    old: inner_block,
                    new: target,
                    state: next.value,
                });
                // The dispatcher edge is answered by rewiring the merge that
                // feeds it, even though no rewire names the edge itself.
                covered.insert(pred);
                worklist.push(next);
            }
        }
    }

    // Emit what every state reaching an edge implies for it.
    //
    // An edge reachable under several states is not by itself a problem: the
    // question is whether those states disagree about where it should go. They
    // usually do not - `region_from` is a forward reachability and over-reports,
    // so cases that share a tail all claim the same edge and all compute the
    // same successor for it. Where they genuinely disagree the edge would need
    // the block duplicated, and `drop_conflicts` removes it. Deciding here on
    // the *number* of states instead would discard the agreeing majority along
    // with the conflicting few.
    let mut rewires: Vec<Rewire> = merged;
    for (pred, states) in reaching {
        for state in states {
            let Some(&next) = outcome.get(&(pred, state)) else {
                continue;
            };
            let Some(next_target) = table.lookup(folder, next) else {
                continue;
            };
            covered.insert(pred);
            rewires.push(Rewire {
                from: pred,
                old: dispatcher.block,
                new: next_target,
                state: next.value,
            });
        }
    }

    (rewires, covered)
}

/// Combines the rewires of every dispatcher in a method into one set.
///
/// Dispatchers are resolved independently against the unmodified function, so
/// two of them can name the same edge. Conflicts are dropped here for the same
/// reason they are dropped within a single dispatcher: an edge can only go one
/// place, and guessing which is worse than leaving it flattened.
#[must_use]
pub fn merge_rewires(per_dispatcher: Vec<Vec<Rewire>>) -> (Vec<Rewire>, usize) {
    let mut stats = ResolutionStats::default();
    let combined: Vec<Rewire> = per_dispatcher.into_iter().flatten().collect();
    let merged = drop_conflicts(combined, &mut stats);
    (merged, stats.conflicts)
}

/// Resolves the operands of one state merge point.
///
/// `merge_block` is where the phi lives and therefore which edges get rewired;
/// `dispatcher_block` is the switch those edges ultimately feed, used to check
/// that everything skipped in between is state plumbing.
///
/// Failures are attributed to `root` - the edge into the dispatcher this
/// resolution ultimately serves - so a merge that only partly resolves is
/// reported against the one dispatcher edge it feeds, not against its own
/// operands.
#[allow(clippy::too_many_arguments)]
fn resolve_merge(
    ssa: &SsaFunction,
    table: &DispatchTable,
    folder: &mut StateFolder<'_>,
    merge_block: usize,
    phi: &PhiNode,
    dispatcher_block: usize,
    depth: usize,
    visited: &mut BTreeSet<usize>,
    rewires: &mut Vec<Rewire>,
    states: &mut Vec<StateValue>,
    unresolved: &mut BTreeSet<usize>,
    reasons: &mut UnresolvedReasons,
    root: Option<usize>,
    outer: Option<(SsaVarId, StateValue)>,
    state_only: &BTreeSet<SsaVarId>,
) {
    if !visited.insert(merge_block) {
        return;
    }

    // Operands are copied out so the folder can borrow the SSA again.
    let operands: Vec<(usize, SsaVarId)> = phi
        .operands()
        .iter()
        .map(|op| (op.predecessor(), op.value()))
        .collect();

    for (pred, value) in operands {
        // At the top level each operand answers for itself; inside a merge every
        // failure counts against the dispatcher edge the merge feeds.
        let blame = root.unwrap_or(pred);

        if let Some(state) = folder.fold_bound(value, [outer, None]) {
            if let Some(target) = table.lookup(folder, state) {
                states.push(state);
                rewires.push(Rewire {
                    from: pred,
                    old: merge_block,
                    new: target,
                    state: state.value,
                });
            } else {
                unresolved.insert(blame);
                reasons.no_target = reasons.no_target.saturating_add(1);
            }
            continue;
        }

        // Not constant: follow the copies to the phi that merges this value and
        // resolve that phi's operands instead. Its block becomes the new set of
        // edges to rewire, so the blocks between it and the dispatcher must be
        // skippable.
        let Some((inner_block, inner_phi)) = dependency_phi(ssa, folder, value) else {
            unresolved.insert(blame);
            reasons.not_constant = reasons.not_constant.saturating_add(1);
            continue;
        };
        if depth >= MAX_MERGE_DEPTH
            || inner_block == merge_block
            || !pure_chain_between(ssa, inner_block, dispatcher_block, state_only)
        {
            unresolved.insert(blame);
            reasons.impure_chain = reasons.impure_chain.saturating_add(1);
            continue;
        }

        // Case-split: read the value once per branch of the merge, pinning the
        // phi to what that branch contributes. When the phi *is* the value this
        // is exactly the old recursion; when it sits under an encoding it also
        // pushes the split through the arithmetic.
        let operands: Vec<(usize, SsaVarId)> = inner_phi
            .operands()
            .iter()
            .map(|op| (op.predecessor(), op.value()))
            .collect();
        let phi_result = inner_phi.result();
        let mut split_any = false;

        for (source, operand) in operands {
            let Some(branch) = folder.fold_bound(operand, [outer, None]) else {
                continue;
            };
            let Some(state) = folder.fold_bound(value, [outer, Some((phi_result, branch))]) else {
                continue;
            };
            let Some(target) = table.lookup(folder, state) else {
                continue;
            };
            states.push(state);
            rewires.push(Rewire {
                from: source,
                old: inner_block,
                new: target,
                state: state.value,
            });
            split_any = true;
        }

        if !split_any {
            unresolved.insert(blame);
            reasons.not_constant = reasons.not_constant.saturating_add(1);
        }
    }
}

/// Drops rewires that disagree about where a block should go.
///
/// One block can reach a merge point along two edges - both arms of a branch,
/// say - and SSA gives each its own phi operand. If those operands encode
/// different successors the block would need duplicating to express both, so
/// both are dropped and the block keeps using the dispatcher. Rewiring only one
/// of them would silently send the other arm to the wrong place.
fn drop_conflicts(rewires: Vec<Rewire>, stats: &mut ResolutionStats) -> Vec<Rewire> {
    let mut chosen: BTreeMap<(usize, usize), Rewire> = BTreeMap::new();
    let mut conflicted: BTreeSet<(usize, usize)> = BTreeSet::new();

    for rewire in rewires {
        let key = (rewire.from, rewire.old);
        match chosen.get(&key) {
            Some(existing) if existing.new != rewire.new => {
                conflicted.insert(key);
            }
            Some(_) => {}
            None => {
                chosen.insert(key, rewire);
            }
        }
    }

    for key in &conflicted {
        chosen.remove(key);
        stats.conflicts = stats.conflicts.saturating_add(1);
        stats.unresolved = stats.unresolved.saturating_add(1);
    }

    chosen.into_values().collect()
}

/// Whether an instruction is state machinery rather than program behaviour.
///
/// State machinery is side-effect free and carries no content an analyst would
/// look for: integer constants encoding states, the copies that move them, and
/// the control flow that dispatches on them. A string constant fails the test
/// even though it is pure - losing it loses evidence.
fn is_state_machinery(instr: &SsaInstruction) -> bool {
    if let SsaOp::Const { value, .. } = instr.op() {
        return value.as_i64().is_some();
    }
    instr.is_pure()
        || matches!(
            instr.op(),
            SsaOp::Jump { .. }
                | SsaOp::Leave { .. }
                | SsaOp::Switch { .. }
                | SsaOp::Branch { .. }
                | SsaOp::BranchCmp { .. }
        )
}

/// Empties the state machinery the rewiring made unreachable.
///
/// Once all of a dispatcher's edges bypass it, the dispatcher and the constants
/// that encoded the state can no longer execute. They are emptied rather than
/// removed so block indices stay stable for the rewires already applied;
/// `rebuild_ssa` and the dead-code passes drop the remains.
///
/// Only blocks that are *provably nothing but* state machinery are emptied.
/// Unreachability here is relative to the states resolution managed to
/// discover, and that discovery is deliberately incomplete - an edge it cannot
/// read leaves its case block looking unreachable when it is not. Emptying such
/// a block would turn a gap in coverage into lost program behaviour, so a block
/// holding a call, a store, or a string constant is left alone even when
/// nothing appears to reach it. Dead code costs a little size; deleted code
/// costs the analysis it was kept for.
///
/// Handler entry blocks are roots alongside the function entry: control reaches
/// them by a runtime exception edge, not from any terminator.
///
/// Returns the number of blocks emptied.
pub fn clear_unreachable(ssa: &mut SsaFunction) -> usize {
    let block_count = ssa.blocks().len();
    if block_count == 0 {
        return 0;
    }

    let mut roots: Vec<usize> = vec![0];
    for handler in ssa.exception_handlers() {
        roots.extend(handler.entry_blocks());
        roots.extend(handler.protected_range.map(|range| range.start()));
    }

    let mut reachable = vec![false; block_count];
    let mut frontier = roots;
    while let Some(current) = frontier.pop() {
        let Some(slot) = reachable.get_mut(current) else {
            continue;
        };
        if *slot {
            continue;
        }
        *slot = true;
        if let Some(op) = ssa.block(current).and_then(|b| b.control_terminator()) {
            frontier.extend(op.successors());
        }
    }

    let dead: Vec<usize> = (0..block_count)
        .filter(|&index| !reachable.get(index).copied().unwrap_or(true))
        .filter(|&index| {
            ssa.block(index).is_some_and(|block| {
                (!block.instructions().is_empty() || !block.phi_nodes().is_empty())
                    && block.instructions().iter().all(is_state_machinery)
            })
        })
        .collect();

    for index in &dead {
        if let Some(block) = ssa.block_mut(*index) {
            block.clear();
        }
    }
    dead.len()
}

/// Rewires resolved edges so they bypass the dispatcher.
///
/// Each edge's source has its terminator's reference to the merge point
/// replaced by the dispatch target. Predecessor lists are derived from
/// terminators, so this is the whole of the CFG change: the stale phi operands
/// and the now-dead constants that encoded the state are cleaned up by the
/// caller's `rebuild_ssa` and the ordinary dead-code passes.
///
/// An edge whose merge point is not the dispatcher (a case's two branches meeting before
/// the jump to it) skips the blocks from that merge to the dispatcher, and what they did
/// has to happen on the new edge: [`carry_skipped_chain`].
///
/// # Arguments
///
/// * `ssa` - The function, its cross-block values already given slots.
/// * `rewires` - The edges to rewire.
/// * `dispatchers` - The dispatcher blocks, where a skipped chain ends.
///
/// Returns the number of edges actually rewired.
pub fn apply_rewires(
    ssa: &mut SsaFunction,
    rewires: &[Rewire],
    dispatchers: &BTreeSet<usize>,
) -> usize {
    let mut applied: usize = 0;
    for rewire in rewires {
        if !dispatchers.contains(&rewire.old) && !carry_skipped_chain(ssa, rewire, dispatchers) {
            continue;
        }
        let changed = ssa
            .block_mut(rewire.from)
            .and_then(|block| block.instructions_mut().last_mut())
            .is_some_and(|term| term.op_mut().redirect_target(rewire.old, rewire.new));
        if changed {
            applied = applied.saturating_add(1);
        }
    }
    applied
}

/// Does at the end of `rewire.from` what the blocks it now skips did on its behalf.
///
/// The chain from `rewire.old` to the dispatcher is state plumbing (the resolver only skips
/// such a chain) plus what giving cross-block values slots wrote at its end: the values the
/// dispatcher's phis took on the chain's edge. After copy propagation that is where a case
/// hands the next case a program value, as in a loop whose case computes `lower =
/// char.ToLower(c)` and the cases after it read `lower`: skipping the chain without its
/// writes left them reading the value `lower` had on entry.
///
/// Each chain instruction is written again at the end of `from`, its definitions given fresh
/// names in their own storage groups, and each chain phi read as the operand on the edge the
/// replica stands for. The instructions are pure, so running them on every path that skips
/// the chain changes nothing else.
///
/// # Returns
///
/// `false`, leaving the function unchanged, when the chain does not end at a dispatcher,
/// holds an instruction with an effect, or has a phi with no operand for the edge taken.
fn carry_skipped_chain(
    ssa: &mut SsaFunction,
    rewire: &Rewire,
    dispatchers: &BTreeSet<usize>,
) -> bool {
    let mut chain: Vec<usize> = Vec::new();
    let mut current = rewire.old;
    while !dispatchers.contains(&current) {
        if chain.len() >= MAX_CHAIN_LEN {
            return false;
        }
        let Some(SsaOp::Jump { target }) = ssa.block(current).and_then(|b| b.last_op()) else {
            return false;
        };
        chain.push(current);
        current = *target;
    }

    // The replicas, with the names they read and write remapped: a chain phi to what its
    // edge brings, a chain definition to its replica
    let mut renamed: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();
    let mut replicas: Vec<SsaInstruction> = Vec::new();
    let mut previous = rewire.from;
    for &block_id in &chain {
        let Some(block) = ssa.block(block_id) else {
            return false;
        };
        for phi in block.phi_nodes() {
            let Some(operand) = phi
                .operands()
                .iter()
                .find(|operand| operand.predecessor() == previous && !operand.is_exceptional())
            else {
                return false;
            };
            let value = renamed
                .get(&operand.value())
                .copied()
                .unwrap_or(operand.value());
            renamed.insert(phi.result(), value);
        }
        let body: Vec<SsaInstruction> = block
            .instructions()
            .iter()
            .filter(|instruction| !instruction.is_terminator())
            .cloned()
            .collect();
        for instruction in body {
            if !instruction.is_pure() {
                return false;
            }
            for def in instruction.op().defs() {
                let Some(variable) = ssa.variable(def) else {
                    return false;
                };
                let (origin, var_type) = (variable.origin(), variable.var_type().clone());
                let group = ssa.rename_group(def);
                let fresh = ssa.create_variable(origin, 0, DefSite::entry(), var_type);
                ssa.set_rename_group(fresh, group);
                renamed.insert(def, fresh);
            }
            let op = instruction
                .op()
                .remap_variables(|var| renamed.get(&var).copied());
            replicas.push(SsaInstruction::synthetic(op));
        }
        previous = block_id;
    }

    let Some(from) = ssa.block_mut(rewire.from) else {
        return false;
    };
    let instructions = from.instructions_mut();
    let at = instructions
        .iter()
        .position(SsaInstruction::is_terminator)
        .unwrap_or(instructions.len());
    for (offset, replica) in replicas.into_iter().enumerate() {
        instructions.insert(at.saturating_add(offset), replica);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{DefSite, PhiOperand, SsaBlock, SsaInstruction, SsaType, VariableOrigin};

    /// Appends an instruction to `block`, creating its destination variable with
    /// the def site the folder needs to find it again.
    fn define(
        ssa: &mut SsaFunction,
        block: usize,
        make: impl FnOnce(SsaVarId) -> SsaOp,
    ) -> SsaVarId {
        let index = ssa.block(block).map_or(0, |b| b.instructions().len());
        let var = ssa.create_variable(
            VariableOrigin::Phi,
            0,
            DefSite::instruction(block, index),
            SsaType::I32,
        );
        let op = make(var);
        if let Some(b) = ssa.block_mut(block) {
            b.add_instruction(SsaInstruction::synthetic(op));
        }
        var
    }

    fn constant(ssa: &mut SsaFunction, block: usize, value: i32) -> SsaVarId {
        define(ssa, block, |dest| SsaOp::Const {
            dest,
            value: ConstValue::I32(value),
        })
    }

    fn terminate(ssa: &mut SsaFunction, block: usize, op: SsaOp) {
        if let Some(b) = ssa.block_mut(block) {
            b.add_instruction(SsaInstruction::synthetic(op));
        }
    }

    /// A dispatcher whose cases each end in `state = <const>; jump dispatcher`.
    ///
    /// Block 0 enters with state 1, block 2 is the dispatcher, blocks 3 and 4
    /// are its cases; case 3 moves to state 0 and case 4 exits.
    fn constant_state_cff() -> (SsaFunction, Dispatcher) {
        let mut ssa = SsaFunction::new(0, 0);
        for index in 0..5 {
            ssa.add_block(SsaBlock::new(index));
        }

        let entry_state = constant(&mut ssa, 0, 1);
        terminate(&mut ssa, 0, SsaOp::Jump { target: 2 });

        let case3_state = constant(&mut ssa, 3, 0);
        terminate(&mut ssa, 3, SsaOp::Jump { target: 2 });

        // The dispatcher's state phi: one operand per predecessor edge.
        let state = ssa.create_variable(VariableOrigin::Phi, 1, DefSite::phi(2), SsaType::I32);
        let mut phi = PhiNode::new(state, VariableOrigin::Phi);
        phi.add_operand(PhiOperand::new(entry_state, 0));
        phi.add_operand(PhiOperand::new(case3_state, 3));
        if let Some(block) = ssa.block_mut(2) {
            block.add_phi(phi);
            block.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
                value: state,
                targets: vec![4, 3],
                default: 1,
            }));
        }

        terminate(&mut ssa, 4, SsaOp::Return { value: None });
        terminate(&mut ssa, 1, SsaOp::Return { value: None });

        let dispatcher = Dispatcher::new(2, state, vec![4, 3], 1).with_state_phi(state);
        (ssa, dispatcher)
    }

    #[test]
    fn folds_arithmetic_at_32_bit_width() {
        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(SsaBlock::new(0));

        let left = constant(&mut ssa, 0, 1_975_223_132);
        let right = constant(&mut ssa, 0, 3);
        let product = define(&mut ssa, 0, |dest| SsaOp::Mul {
            dest,
            left,
            right,
            flags: None,
        });

        let mut folder = StateFolder::new(&ssa);
        // 1975223132 * 3 overflows int32; CIL wraps, and so must the folder -
        // at 64 bits the product would be 5925669396 and match no case.
        assert_eq!(folder.fold(product), Some(1_630_702_100));
    }

    /// Defines a value of `var_type`, the way the lift types a conversion's
    /// result as its target.
    fn define_typed(
        ssa: &mut SsaFunction,
        block: usize,
        var_type: SsaType,
        make: impl FnOnce(SsaVarId) -> SsaOp,
    ) -> SsaVarId {
        let var = define(ssa, block, make);
        if let Some(variable) = ssa.variable_mut(var) {
            variable.set_type(var_type);
        }
        var
    }

    #[test]
    fn a_narrowing_conversion_truncates_the_state() {
        // (int)(byte)0x1234 is 0x34: a state that round-trips through a byte
        // loses its high bits, and a folder that looks through the conversion
        // rewires the edge to the case for 0x1234.
        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(SsaBlock::new(0));
        let wide = constant(&mut ssa, 0, 0x1234);
        let byte = define_typed(&mut ssa, 0, SsaType::U8, |dest| SsaOp::IntConv {
            dest,
            operand: wide,
            target: SsaType::U8,
            overflow_check: false,
            unsigned: false,
        });

        assert_eq!(StateFolder::new(&ssa).fold(byte), Some(0x34));
    }

    #[test]
    fn widening_an_int32_to_uint64_zero_extends_it() {
        // conv.u8 reads its int32 operand as unsigned: -1 becomes 0xFFFF_FFFF,
        // not the sign-extended all-ones a transparent conversion would keep.
        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(SsaBlock::new(0));
        let minus_one = constant(&mut ssa, 0, -1);
        let widened = define_typed(&mut ssa, 0, SsaType::U64, |dest| SsaOp::IntConv {
            dest,
            operand: minus_one,
            target: SsaType::U64,
            overflow_check: false,
            unsigned: true,
        });

        assert_eq!(
            StateFolder::new(&ssa).fold_value(widened),
            Some(StateValue::wide(0xFFFF_FFFF))
        );
    }

    #[test]
    fn a_division_that_throws_is_no_state() {
        // int.MinValue / -1 throws OverflowException in CIL; there is no state to
        // dispatch on, rather than the wrapped quotient a 64-bit fold computes.
        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(SsaBlock::new(0));
        let min = constant(&mut ssa, 0, i32::MIN);
        let minus_one = constant(&mut ssa, 0, -1);
        let quotient = define(&mut ssa, 0, |dest| SsaOp::Div {
            dest,
            left: min,
            right: minus_one,
            unsigned: false,
            flags: None,
        });

        assert_eq!(StateFolder::new(&ssa).fold(quotient), None);
    }

    #[test]
    fn folds_through_copy_chains() {
        let mut ssa = SsaFunction::new(0, 0);
        ssa.add_block(SsaBlock::new(0));

        let base = constant(&mut ssa, 0, 42);
        let first = define(&mut ssa, 0, |dest| SsaOp::Copy { dest, src: base });
        let second = define(&mut ssa, 0, |dest| SsaOp::Copy { dest, src: first });

        let mut folder = StateFolder::new(&ssa);
        assert_eq!(folder.fold(second), Some(42));
        assert_eq!(folder.copy_root(second), base);
    }

    #[test]
    fn dispatch_table_reads_the_overflow_chain() {
        let mut ssa = SsaFunction::new(0, 0);
        for index in 0..10 {
            ssa.add_block(SsaBlock::new(index));
        }
        // Every target must be able to execute, or the table rejects it.
        for index in [2, 9] {
            terminate(&mut ssa, index, SsaOp::Return { value: None });
        }

        // Default arm: `if state == 700 goto 2` then fall through to block 3.
        // The state must be opaque here - a link whose both sides fold is a
        // comparison already decided, not a dispatch.
        let state =
            ssa.create_variable(VariableOrigin::Local(0), 0, DefSite::entry(), SsaType::I32);
        let probe = constant(&mut ssa, 0, 700);
        terminate(
            &mut ssa,
            0,
            SsaOp::BranchCmp {
                left: state,
                right: probe,
                cmp: CmpKind::Eq,
                unsigned: false,
                true_target: 2,
                false_target: 3,
            },
        );
        terminate(&mut ssa, 3, SsaOp::Return { value: None });

        let dispatcher = Dispatcher::new(1, state, vec![9], 0);
        let mut folder = StateFolder::new(&ssa);
        let table = DispatchTable::build(&ssa, &dispatcher, state, &mut folder);

        assert_eq!(table.overflow_len(), 1);
        // A state outside the switch table is routed by the chain, not the table.
        assert_eq!(table.lookup(&mut folder, StateValue::narrow(700)), Some(2));
        // A state inside the table still uses the table.
        assert_eq!(table.lookup(&mut folder, StateValue::narrow(0)), Some(9));
        // Anything else lands where the chain falls through.
        assert_eq!(table.lookup(&mut folder, StateValue::narrow(123)), Some(3));
    }

    #[test]
    fn resolves_constant_state_edges() {
        let (ssa, dispatcher) = constant_state_cff();
        let (rewires, stats) = resolve_dispatch_edges(&ssa, &dispatcher, None);

        assert_eq!(stats.unresolved, 0, "both edges carry a constant state");
        assert_eq!(stats.resolved, 2);

        // State 1 selects targets[1] = block 3; state 0 selects targets[0] = 4.
        let mut targets: Vec<(usize, usize)> = rewires.iter().map(|r| (r.from, r.new)).collect();
        targets.sort_unstable();
        assert_eq!(targets, vec![(0, 3), (3, 4)]);
    }

    #[test]
    fn applying_rewires_bypasses_the_dispatcher() {
        let (mut ssa, dispatcher) = constant_state_cff();
        let (rewires, _) = resolve_dispatch_edges(&ssa, &dispatcher, None);

        assert_eq!(
            apply_rewires(&mut ssa, &rewires, &BTreeSet::from([dispatcher.block])),
            2
        );
        assert!(
            SsaCfg::from_ssa(&ssa).block_predecessors(2).is_empty(),
            "no edge should still reach the dispatcher"
        );

        // With every edge rewired the dispatcher is unreachable, and being pure
        // state machinery it is emptied, taking its switch with it.
        assert_eq!(clear_unreachable(&mut ssa), 1);
        assert!(ssa.block(2).is_some_and(|b| b.instructions().is_empty()));

        // The default arm is unreachable too, but it returns - behaviour, not
        // machinery - so it is left intact rather than deleted on the strength
        // of an analysis that is allowed to be incomplete.
        assert!(ssa.block(1).is_some_and(|b| !b.instructions().is_empty()));
    }

    #[test]
    fn emptied_dispatch_targets_are_not_rewired_into() {
        let (mut ssa, dispatcher) = constant_state_cff();

        // Empty the block state 1 dispatches to, as a previous unflattening
        // round does to machinery it made unreachable. The switch table still
        // names it.
        if let Some(block) = ssa.block_mut(3) {
            block.clear();
        }

        let (rewires, stats) = resolve_dispatch_edges(&ssa, &dispatcher, None);

        assert!(
            rewires.iter().all(|r| r.new != 3),
            "no edge may be rewired into a block that cannot execute"
        );
        // Both edges are lost: one dispatches to the husk, and the other is the
        // husk's own edge, whose state the emptying took with it.
        assert_eq!(stats.unresolved, 2, "those edges keep using the dispatcher");

        apply_rewires(&mut ssa, &rewires, &BTreeSet::from([dispatcher.block]));

        // The dispatcher's own switch still names the husk - that is the input
        // condition, and leaving it is what keeps the edge safe. What must not
        // happen is a rewired block acquiring an edge into it.
        for rewire in &rewires {
            let successors = ssa
                .block(rewire.from)
                .and_then(|b| b.control_terminator())
                .map(SsaOp::successors)
                .unwrap_or_default();
            assert!(
                !successors.contains(&3),
                "rewired block b{} must not send control into an empty block",
                rewire.from
            );
        }
    }

    #[test]
    fn conflicting_edges_are_dropped() {
        let mut stats = ResolutionStats::default();
        let kept = drop_conflicts(
            vec![
                Rewire {
                    from: 5,
                    old: 2,
                    new: 7,
                    state: 1,
                },
                // Same edge, different destination: unrepresentable without
                // duplicating block 5, so neither survives.
                Rewire {
                    from: 5,
                    old: 2,
                    new: 9,
                    state: 2,
                },
                Rewire {
                    from: 6,
                    old: 2,
                    new: 7,
                    state: 1,
                },
            ],
            &mut stats,
        );

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].from, 6);
        assert_eq!(stats.conflicts, 1);
    }

    #[test]
    fn unresolved_edges_leave_the_dispatcher_in_place() {
        let (mut ssa, dispatcher) = constant_state_cff();

        // Blank out the entry block's constant. The phi operand still names the
        // variable, but its defining instruction no longer produces a value, so
        // the edge cannot be folded.
        if let Some(instr) = ssa
            .block_mut(0)
            .and_then(|block| block.instructions_mut().first_mut())
        {
            instr.set_op(SsaOp::Nop);
        }

        let (rewires, stats) = resolve_dispatch_edges(&ssa, &dispatcher, None);
        assert_eq!(stats.unresolved, 1, "the entry edge no longer folds");

        apply_rewires(&mut ssa, &rewires, &BTreeSet::from([dispatcher.block]));
        assert_eq!(
            SsaCfg::from_ssa(&ssa).block_predecessors(2),
            [0],
            "the unresolved edge keeps using the dispatcher"
        );
        assert_eq!(
            clear_unreachable(&mut ssa),
            0,
            "a reachable dispatcher is never emptied"
        );
    }
}

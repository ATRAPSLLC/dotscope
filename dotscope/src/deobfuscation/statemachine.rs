//! Generalized state machine framework for obfuscator analysis.
//!
//! This module provides a flexible state machine representation that can model
//! various obfuscator runtime state tracking mechanisms like ConfuserEx's CFGCtx.
//!
//! # Design Philosophy
//!
//! The framework is designed to be reusable across different obfuscators:
//! - **Dynamic detection**: All constants and operations are extracted from assembly IL
//! - **Variable slot count**: Not limited to a fixed number of state slots
//! - **Flexible operations**: Uses SSA operation kinds for arithmetic/bitwise ops
//! - **Runtime simulation**: Stateful execution for order-dependent decryption
//!
//! # Example: ConfuserEx CFGCtx
//!
//! ConfuserEx's CFGCtx is a state machine with 4 slots (A, B, C, D):
//!
//! ```text
//! internal struct CFGCtx {
//!     uint A, B, C, D;
//!
//!     public CFGCtx(uint seed) {
//!         A = seed *= MULTIPLIER;  // e.g., 0x21412321
//!         B = seed *= MULTIPLIER;
//!         C = seed *= MULTIPLIER;
//!         D = seed *= MULTIPLIER;
//!     }
//!
//!     public uint Next(byte flag, uint value) {
//!         // Update slot based on (flag & 0x03):
//!         //   Bit 7 (0x80): Explicit (set) vs Incremental (op)
//!         //   If explicit: slot = value
//!         //   If incremental: slot 0 ^= value, slot 1 += value, etc.
//!         // Return slot based on ((flag >> 2) & 0x03)
//!     }
//! }
//! ```
//!
//! This is represented as:
//! - `slot_count = 4`
//! - `init_constant = Some(0x21412321)`
//! - `init_ops = [Mul, Mul, Mul, Mul]`
//! - `slot_ops = [Xor, Add, Xor, Sub]` (incremental mode operations)

use std::{
    collections::HashSet,
    fmt::{self, Debug, Display, Formatter},
    sync::Arc,
};

use analyssa::graph::{algorithms::DominatorTree, NodeId};

use crate::{
    analysis::{ConstValue, InstrId, SsaFunction, SsaOp, SsaVarId},
    compiler::CompilerContext,
    metadata::token::Token,
    CilObject,
};

/// Information about a state machine update call (e.g., CFGCtx.Next()).
///
/// This captures the location and arguments of a state update call
/// in SSA form, which is used by the decryption pass to simulate
/// the state machine in execution order.
#[derive(Debug, Clone)]
pub struct StateUpdateCall {
    /// Block index where the call occurs.
    pub block_idx: usize,
    /// Instruction index within the block.
    pub instr_idx: usize,
    /// SSA variable that receives the return value.
    pub dest: SsaVarId,
    /// SSA variable containing the flag byte.
    pub flag_var: SsaVarId,
    /// SSA variable containing the increment/value.
    pub increment_var: SsaVarId,
}

/// Information about a decryptor call site that uses state machine mode.
///
/// This captures the relationship between a decryptor call and the state
/// machine that feeds its argument. The typical pattern is:
///
/// ```text
/// state_value = call StateUpdate(flag, increment)
/// encoded = const ENCODED_VALUE
/// key = xor state_value, encoded
/// result = call Decryptor(key)
/// ```
#[derive(Debug, Clone)]
pub struct StateMachineCallSite {
    /// Block index where the decryptor call occurs.
    ///
    /// Where the call *is*, for the analyses that reason about position -
    /// which state updates dominate it, which block it shares with its seed.
    /// Not an identity: the first edit above it makes it name something else.
    pub block_idx: usize,
    /// Instruction index within the block.
    pub instr_idx: usize,
    /// The call instruction's identity.
    ///
    /// What the call *is*, which is what a record about it has to be keyed by.
    /// `None` for a function whose instructions carry no identity yet, which a
    /// repair boundary fixes; such a site is processed but not remembered.
    pub instr_id: Option<InstrId>,
    /// SSA variable that receives the decrypted value.
    pub dest: SsaVarId,
    /// Token of the decryptor method being called (resolved MethodDef).
    pub decryptor: Token,
    /// Original call target token (may be MethodSpec for generic calls).
    /// Used for emulation to preserve generic type information.
    pub call_target: Token,
    /// SSA variable containing the state machine output (from update call).
    pub state_var: SsaVarId,
    /// SSA variable containing the encoded constant (XOR operand).
    pub encoded_var: SsaVarId,
    /// Index into the state updates array for the feeding update.
    pub feeding_update_idx: usize,
}

impl StateMachineCallSite {
    /// Returns the call instruction's identity, which is how a record about
    /// this call site is keyed.
    ///
    /// Position is not identity. The previous key was `block * 1000 + instr`,
    /// which fails twice over: every edit above the call renumbers it, so a
    /// record made before a rewrite describes a different call afterwards; and
    /// a block with a thousand instructions - which obfuscated code reaches -
    /// collides with the next block outright.
    #[must_use]
    pub const fn identity(&self) -> Option<InstrId> {
        self.instr_id
    }
}

/// CFG analysis information passed to state machine providers.
///
/// This bundles the control flow analysis data needed for providers to
/// determine which state updates must execute before a given call site.
pub struct CfgInfo<'a> {
    /// Dominator tree for the method's CFG.
    pub dom_tree: &'a DominatorTree,
    /// Predecessor blocks for each block (index -> predecessors).
    pub predecessors: &'a [Vec<usize>],
    /// Total number of nodes in the CFG.
    pub node_count: usize,
    /// Entry node of the CFG.
    pub entry: NodeId,
}

/// Trait for obfuscator-specific state machine behavior.
///
/// This trait abstracts the detection and simulation of state machines
/// used by different obfuscators for order-dependent constant encryption.
/// Each obfuscator implements this trait with its specific patterns.
///
/// # Design
///
/// The trait separates concerns:
/// - **Detection**: `find_initializations()` and `find_state_updates()` are
///   obfuscator-specific patterns for locating state machine usage in SSA.
/// - **Simulation**: `semantics()` provides the machine definition,
///   `StateMachineState` handles actual execution.
/// - **Key computation**: `compute_key()` handles the final decryption step.
///
/// # Example: ConfuserEx
///
/// ```text
/// impl StateMachineProvider for ConfuserExStateMachine {
///     fn applies_to_method(&self, method: Token) -> bool {
///         self.cfg_mode_methods.contains(&method)
///     }
///
///     fn find_initializations(&self, ssa: &SsaFunction, ...) -> Vec<...> {
///         // Look for CFGCtx::.ctor(seed) calls
///     }
///
///     fn find_state_updates(&self, ssa: &SsaFunction) -> Vec<StateUpdateCall> {
///         // Look for CFGCtx.Next(flag, increment) calls
///     }
/// }
/// ```
pub trait StateMachineProvider: Send + Sync + Debug {
    /// Returns the name of this state machine provider (for diagnostics).
    fn name(&self) -> &'static str;

    /// Returns the state machine semantics (slot operations, multipliers, etc.).
    fn semantics(&self) -> &StateMachineSemantics;

    /// Checks if this provider applies to a specific method.
    ///
    /// Returns true if the method uses this state machine for encryption.
    fn applies_to_method(&self, method: Token) -> bool;

    /// Returns all methods that use this state machine.
    fn methods(&self) -> Vec<Token>;

    /// Finds all state machine initializations in a method.
    ///
    /// Returns tuples of (block_idx, instr_idx, seed) for each
    /// initialization found. Methods may have multiple initializations
    /// (e.g., in exception handlers with different seeds).
    fn find_initializations(
        &self,
        ssa: &SsaFunction,
        ctx: &CompilerContext,
        method: Token,
        assembly: &CilObject,
    ) -> Vec<(usize, usize, u32)>;

    /// Finds all state update calls in a method.
    ///
    /// Returns information about each update call (e.g., CFGCtx.Next()),
    /// including its location and argument variables.
    fn find_state_updates(&self, ssa: &SsaFunction) -> Vec<StateUpdateCall>;

    /// Traces a variable to a constant value.
    ///
    /// This is used to resolve flag and increment values for state updates.
    /// Default implementation tries SSA definition lookup and known values.
    fn trace_to_constant(
        &self,
        var: SsaVarId,
        ssa: &SsaFunction,
        ctx: &CompilerContext,
        method: Token,
    ) -> Option<ConstValue> {
        // Check known_values from constant propagation
        if let Some(val) = ctx.with_known_value(method, var, Clone::clone) {
            return Some(val);
        }

        // Check if defined by a Const instruction
        if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(var) {
            return Some(value.clone());
        }

        None
    }

    /// Computes the decryption key from state value and encoded constant.
    ///
    /// Default implementation: XOR (most common pattern).
    /// Override for obfuscators using different key computation.
    fn compute_key(&self, state_value: u64, encoded: i32) -> i32 {
        // Safe: state values are 32-bit in .NET obfuscators
        #[allow(clippy::cast_possible_truncation)]
        let state_i32 = state_value as i32;
        state_i32 ^ encoded
    }

    /// Finds decryptor call sites that use this state machine.
    ///
    /// This method identifies calls to decryptor methods where the argument
    /// is computed using the state machine (e.g., via XOR with state output).
    ///
    /// The provider implements the pattern-matching logic specific to its
    /// obfuscator. For example, ConfuserEx uses:
    /// ```text
    /// state = call CFGCtx.Next(flag, inc)
    /// key = xor state, encoded
    /// result = call Decryptor(key)
    /// ```
    ///
    /// # Default Implementation
    ///
    /// Returns an empty vector. Providers that support state-machine-mode
    /// decryption should override this.
    fn find_decryptor_call_sites(
        &self,
        _ssa: &SsaFunction,
        _state_updates: &[StateUpdateCall],
        _decryptor_tokens: &HashSet<Token>,
        _assembly: &CilObject,
    ) -> Vec<StateMachineCallSite> {
        Vec::new()
    }

    /// Collects state updates that must be simulated before a call site.
    ///
    /// Given a decryptor call site, this method determines which state update
    /// calls (and in what order) must be simulated to compute the correct
    /// state value for decryption.
    ///
    /// The algorithm is obfuscator-specific. For example, ConfuserEx uses
    /// BFS path-finding to collect updates along an entry-to-target path.
    ///
    /// # Arguments
    ///
    /// * `call_site` - The decryptor call site to analyze
    /// * `all_updates` - All state update calls in the method
    /// * `cfg_info` - CFG analysis data (dominators, predecessors)
    /// * `seed_block` - Optional seed block index for filtering; only updates
    ///   at or after the seed's position on the BFS path are included
    ///
    /// # Returns
    ///
    /// Indices into `all_updates` in execution order (earliest first).
    ///
    /// # Default Implementation
    ///
    /// Returns an empty vector. Providers should override this with their
    /// specific algorithm for determining update order.
    fn collect_updates_for_call(
        &self,
        _call_site: &StateMachineCallSite,
        _all_updates: &[StateUpdateCall],
        _cfg_info: &CfgInfo<'_>,
        _seed_block: Option<usize>,
    ) -> Vec<usize> {
        Vec::new()
    }

    /// Finds the appropriate seed for a decryptor call site.
    ///
    /// Methods may have multiple state machine initializations (e.g., in
    /// exception handlers). This method determines which seed applies to
    /// a specific decryptor call.
    ///
    /// # Default Implementation
    ///
    /// Uses dominator-based analysis: prefers seeds in the same block before
    /// the call, then seeds in strictly dominating blocks (preferring deeper
    /// ones), falling back to the first seed if no dominating seed is found.
    fn find_seed_for_call(
        &self,
        seeds: &[(usize, usize, u32)],
        call_site: &StateMachineCallSite,
        cfg_info: &CfgInfo<'_>,
    ) -> Option<u32> {
        if seeds.is_empty() {
            return None;
        }

        if let [single] = seeds {
            return Some(single.2);
        }

        // Multiple seeds - find the one that dominates this decryptor
        let mut best_seed: Option<(usize, usize, u32)> = None;

        for &(seed_block, seed_instr, seed_val) in seeds {
            if seed_block >= cfg_info.node_count || call_site.block_idx >= cfg_info.node_count {
                continue;
            }

            if seed_block == call_site.block_idx && seed_instr < call_site.instr_idx {
                // Same block, before the decryptor - prefer latest
                if best_seed.is_none()
                    || best_seed.is_some_and(|(b, i, _)| b != seed_block || i < seed_instr)
                {
                    best_seed = Some((seed_block, seed_instr, seed_val));
                }
            } else if cfg_info
                .dom_tree
                .dominates(cfg_info.entry, NodeId::new(seed_block))
                && cfg_info
                    .dom_tree
                    .strictly_dominates(NodeId::new(seed_block), NodeId::new(call_site.block_idx))
            {
                // Seed's block strictly dominates - prefer deeper
                if best_seed.is_none() {
                    best_seed = Some((seed_block, seed_instr, seed_val));
                } else if let Some((best_block, _, _)) = best_seed {
                    if best_block != call_site.block_idx {
                        let best_depth = cfg_info.dom_tree.depth(NodeId::new(best_block));
                        let seed_depth = cfg_info.dom_tree.depth(NodeId::new(seed_block));
                        if seed_depth > best_depth {
                            best_seed = Some((seed_block, seed_instr, seed_val));
                        }
                    }
                }
            }
        }

        best_seed
            .map(|(_, _, v)| v)
            .or_else(|| seeds.first().map(|(_, _, v)| *v))
    }
}

/// Simplified operation kind for state machine operations.
///
/// This is a subset of SSA operations that are commonly used in state machines
/// for obfuscation. The operations are chosen to cover typical patterns seen
/// in obfuscators like ConfuserEx, .NET Reactor, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsaOpKind {
    /// XOR operation (a ^ b)
    Xor,
    /// Addition (a + b), typically wrapping
    Add,
    /// Subtraction (a - b), typically wrapping
    Sub,
    /// Multiplication (a * b), typically wrapping
    Mul,
    /// Bitwise AND (a & b)
    And,
    /// Bitwise OR (a | b)
    Or,
    /// Left shift (a << b)
    Shl,
    /// Right shift (a >> b), logical (unsigned)
    Shr,
    /// Right shift arithmetic (a >> b), signed
    ShrA,
    /// Rotate left
    Rol,
    /// Rotate right
    Ror,
    /// Bitwise NOT (~a)
    Not,
    /// Negation (-a)
    Neg,
}

impl Display for SsaOpKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xor => write!(f, "xor"),
            Self::Add => write!(f, "add"),
            Self::Sub => write!(f, "sub"),
            Self::Mul => write!(f, "mul"),
            Self::And => write!(f, "and"),
            Self::Or => write!(f, "or"),
            Self::Shl => write!(f, "shl"),
            Self::Shr => write!(f, "shr"),
            Self::ShrA => write!(f, "shr.a"),
            Self::Rol => write!(f, "rol"),
            Self::Ror => write!(f, "ror"),
            Self::Not => write!(f, "not"),
            Self::Neg => write!(f, "neg"),
        }
    }
}

/// A single operation that updates a state slot.
///
/// This represents the operation pattern detected from the assembly IL.
/// For example, in ConfuserEx's CFGCtx:
/// - Slot 0 uses XOR: `A ^= value`
/// - Slot 1 uses ADD: `B += value`
/// - Slot 2 uses XOR: `C ^= value`
/// - Slot 3 uses SUB: `D -= value`
#[derive(Debug, Clone)]
pub struct StateSlotOperation {
    /// The SSA operation type (Xor, Add, Sub, Mul, etc.)
    pub op: SsaOpKind,
    /// Whether operands are reversed (value op slot vs slot op value).
    /// For commutative ops like XOR/ADD this doesn't matter, but for
    /// SUB/SHL/SHR the order is significant.
    pub reversed: bool,
}

impl StateSlotOperation {
    /// Creates a new slot operation with default operand order.
    #[must_use]
    pub fn new(op: SsaOpKind) -> Self {
        Self {
            op,
            reversed: false,
        }
    }

    /// Creates a new slot operation with reversed operand order.
    #[must_use]
    pub fn new_reversed(op: SsaOpKind) -> Self {
        Self { op, reversed: true }
    }

    /// Creates a XOR operation.
    #[must_use]
    pub fn xor() -> Self {
        Self::new(SsaOpKind::Xor)
    }

    /// Creates an ADD operation.
    #[must_use]
    pub fn add() -> Self {
        Self::new(SsaOpKind::Add)
    }

    /// Creates a SUB operation.
    #[must_use]
    pub fn sub() -> Self {
        Self::new(SsaOpKind::Sub)
    }

    /// Creates a MUL operation.
    #[must_use]
    pub fn mul() -> Self {
        Self::new(SsaOpKind::Mul)
    }

    /// Creates an AND operation.
    #[must_use]
    pub fn and() -> Self {
        Self::new(SsaOpKind::And)
    }

    /// Creates an OR operation.
    #[must_use]
    pub fn or() -> Self {
        Self::new(SsaOpKind::Or)
    }

    /// Applies this operation to two values.
    ///
    /// Returns `a op b` or `b op a` depending on the `reversed` flag.
    #[must_use]
    pub fn apply(&self, a: u64, b: u64) -> u64 {
        let (left, right) = if self.reversed { (b, a) } else { (a, b) };
        match self.op {
            SsaOpKind::Xor => left ^ right,
            SsaOpKind::Add => left.wrapping_add(right),
            SsaOpKind::Sub => left.wrapping_sub(right),
            SsaOpKind::Mul => left.wrapping_mul(right),
            SsaOpKind::And => left & right,
            SsaOpKind::Or => left | right,
            SsaOpKind::Shl => left << (right & 63),
            SsaOpKind::Shr => left >> (right & 63),
            SsaOpKind::ShrA => (left.cast_signed() >> (right & 63)).cast_unsigned(),
            SsaOpKind::Rol => left.rotate_left((right & 63) as u32),
            SsaOpKind::Ror => left.rotate_right((right & 63) as u32),
            SsaOpKind::Not => !left,
            SsaOpKind::Neg => left.wrapping_neg(),
        }
    }

    /// Applies this operation as u32, returning result as u64.
    #[must_use]
    pub fn apply_u32(&self, a: u32, b: u32) -> u32 {
        let (left, right) = if self.reversed { (b, a) } else { (a, b) };
        match self.op {
            SsaOpKind::Xor => left ^ right,
            SsaOpKind::Add => left.wrapping_add(right),
            SsaOpKind::Sub => left.wrapping_sub(right),
            SsaOpKind::Mul => left.wrapping_mul(right),
            SsaOpKind::And => left & right,
            SsaOpKind::Or => left | right,
            SsaOpKind::Shl => left << (right & 31),
            SsaOpKind::Shr => left >> (right & 31),
            SsaOpKind::ShrA => (left.cast_signed() >> (right & 31)).cast_unsigned(),
            SsaOpKind::Rol => left.rotate_left(right & 31),
            SsaOpKind::Ror => left.rotate_right(right & 31),
            SsaOpKind::Not => !left,
            SsaOpKind::Neg => left.wrapping_neg(),
        }
    }
}

/// Detected semantics for a state machine (CFGCtx or similar).
///
/// This struct captures all the information needed to simulate a state machine
/// detected from an obfuscated assembly. It is designed to be reusable across
/// different obfuscators that use similar state machine patterns.
///
/// # Lifecycle
///
/// 1. **Detection**: Analyzer scans assembly for state machine types/methods
/// 2. **Extraction**: IL is parsed to extract constants and operations
/// 3. **Storage**: Semantics are stored in detection findings
/// 4. **Simulation**: [`StateMachineState`] uses semantics during decryption
#[derive(Debug, Clone)]
pub struct StateMachineSemantics {
    /// Type token (if from a struct/class like CFGCtx).
    pub type_token: Option<Token>,

    /// Initialization method token (constructor).
    pub init_method: Option<Token>,

    /// Next/update method token.
    pub update_method: Option<Token>,

    /// Number of state slots.
    pub slot_count: usize,

    /// Operations for each slot in incremental mode.
    ///
    /// Index corresponds to slot number. For ConfuserEx:
    /// - `slot_ops[0]` = XOR (A ^= value)
    /// - `slot_ops[1]` = ADD (B += value)
    /// - `slot_ops[2]` = XOR (C ^= value)
    /// - `slot_ops[3]` = SUB (D -= value)
    pub slot_ops: Vec<StateSlotOperation>,

    /// Initialization sequence (operations applied to seed).
    ///
    /// For ConfuserEx, all slots use MUL with the same constant:
    /// `[Mul, Mul, Mul, Mul]`
    pub init_ops: Vec<StateSlotOperation>,

    /// Initialization multiplier/constant (if applicable).
    ///
    /// For ConfuserEx this is typically `0x21412321`.
    pub init_constant: Option<u64>,

    /// Flag indicating explicit mode bit position.
    ///
    /// For ConfuserEx this is bit 7 (0x80).
    pub explicit_flag_bit: u8,

    /// Mask for update slot index in flag byte.
    ///
    /// For ConfuserEx this is 0x03 (bits 0-1).
    pub update_slot_mask: u8,

    /// Mask for get slot index in flag byte.
    ///
    /// For ConfuserEx this is 0x03 (bits 2-3 after shift).
    pub get_slot_mask: u8,

    /// Right shift amount to extract get slot from flag.
    ///
    /// For ConfuserEx this is 2.
    pub get_slot_shift: u8,
}

impl Default for StateMachineSemantics {
    fn default() -> Self {
        Self {
            type_token: None,
            init_method: None,
            update_method: None,
            slot_count: 4,
            slot_ops: Vec::new(),
            init_ops: Vec::new(),
            init_constant: None,
            explicit_flag_bit: 7,
            update_slot_mask: 0x03,
            get_slot_mask: 0x03,
            get_slot_shift: 2,
        }
    }
}

impl StateMachineSemantics {
    /// Creates semantics for ConfuserEx's CFGCtx with the specified multiplier.
    ///
    /// This is the standard ConfuserEx CFGCtx pattern:
    /// - 4 slots (A, B, C, D)
    /// - Initialization: each slot = seed *= multiplier
    /// - Incremental ops: XOR, ADD, XOR, SUB
    /// - Flag byte: bit 7 = explicit, bits 0-1 = update slot, bits 2-3 = get slot
    #[must_use]
    pub fn confuserex_cfgctx(multiplier: u32) -> Self {
        Self {
            type_token: None,
            init_method: None,
            update_method: None,
            slot_count: 4,
            slot_ops: vec![
                StateSlotOperation::xor(), // A ^= value
                StateSlotOperation::add(), // B += value
                StateSlotOperation::xor(), // C ^= value
                StateSlotOperation::sub(), // D -= value
            ],
            init_ops: vec![
                StateSlotOperation::mul(), // A = seed *= mult
                StateSlotOperation::mul(), // B = seed *= mult
                StateSlotOperation::mul(), // C = seed *= mult
                StateSlotOperation::mul(), // D = seed *= mult
            ],
            init_constant: Some(u64::from(multiplier)),
            explicit_flag_bit: 7,
            update_slot_mask: 0x03,
            get_slot_mask: 0x03,
            get_slot_shift: 2,
        }
    }

    /// Creates default ConfuserEx CFGCtx semantics with standard multiplier.
    ///
    /// Uses the default multiplier `0x21412321`.
    #[must_use]
    pub fn confuserex_default() -> Self {
        Self::confuserex_cfgctx(0x2141_2321)
    }

    /// Returns the operation for a specific slot in incremental mode.
    #[must_use]
    pub fn slot_operation(&self, slot: usize) -> Option<&StateSlotOperation> {
        self.slot_ops.get(slot)
    }

    /// Returns the initialization operation for a specific slot.
    #[must_use]
    pub fn init_operation(&self, slot: usize) -> Option<&StateSlotOperation> {
        // If we have fewer init_ops than slots, cycle through them
        let idx = slot.checked_rem(self.init_ops.len())?;
        self.init_ops.get(idx)
    }
}

/// Runtime state for a state machine with N slots.
///
/// This struct maintains the current values of all state slots and provides
/// methods to update and query them according to the detected semantics.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. Each decryption thread should have its
/// own instance with independent state.
///
/// # Example
///
/// ```text
/// use std::sync::Arc;
/// use dotscope::deobfuscation::{StateMachineSemantics, StateMachineState};
///
/// let semantics = Arc::new(StateMachineSemantics::confuserex_default());
/// let mut state = StateMachineState::from_seed(0x12345678, semantics);
///
/// // Simulate CFGCtx.Next(flag=0x04, value=0x1111) which:
/// // - Updates slot 0 (flag & 0x03 = 0) with XOR
/// // - Returns slot 1 ((flag >> 2) & 0x03 = 1)
/// let result = state.next(0x04, 0x1111);
/// println!("slot 1: {:#x}", result);
/// ```
#[derive(Debug, Clone)]
pub struct StateMachineState {
    /// State slot values (variable length).
    pub slots: Vec<u64>,
    /// Reference to semantics for operation dispatch.
    semantics: Arc<StateMachineSemantics>,
}

impl StateMachineState {
    /// Creates a new state machine with all slots initialized to zero.
    #[must_use]
    pub fn new(semantics: Arc<StateMachineSemantics>) -> Self {
        let slots = vec![0; semantics.slot_count];
        Self { slots, semantics }
    }

    /// Creates a new state machine initialized from a seed.
    ///
    /// The initialization follows the semantics' init_ops and init_constant.
    /// For ConfuserEx CFGCtx:
    /// ```text
    /// A = seed *= 0x21412321
    /// B = seed *= 0x21412321
    /// C = seed *= 0x21412321
    /// D = seed *= 0x21412321
    /// ```
    #[must_use]
    pub fn from_seed(seed: u64, semantics: Arc<StateMachineSemantics>) -> Self {
        let mut slots = Vec::with_capacity(semantics.slot_count);
        let mut current = seed;

        for i in 0..semantics.slot_count {
            if let (Some(op), Some(constant)) =
                (semantics.init_operation(i), semantics.init_constant)
            {
                current = op.apply(current, constant);
            }
            slots.push(current);
        }

        Self { slots, semantics }
    }

    /// Creates a new state machine initialized from a u32 seed.
    #[must_use]
    pub fn from_seed_u32(seed: u32, semantics: Arc<StateMachineSemantics>) -> Self {
        let mut slots = Vec::with_capacity(semantics.slot_count);
        let mut current = seed;

        for i in 0..semantics.slot_count {
            if let (Some(op), Some(constant)) =
                (semantics.init_operation(i), semantics.init_constant)
            {
                #[allow(clippy::cast_possible_truncation)]
                let const_u32 = constant as u32;
                current = op.apply_u32(current, const_u32);
            }
            slots.push(u64::from(current));
        }

        Self { slots, semantics }
    }

    /// Applies the Next operation with flag and value.
    ///
    /// This simulates the CFGCtx.Next() method:
    /// 1. Decode flag to get update_slot and get_slot indices
    /// 2. Check if explicit mode (bit 7 set)
    /// 3. Update the specified slot:
    ///    - Explicit: slot = value
    ///    - Incremental: slot = slot op value (using slot_ops)
    /// 4. Return the value from get_slot
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag byte encoding update/get slots and mode
    /// * `value` - The value to use for state update
    ///
    /// # Returns
    ///
    /// The state value from the requested slot (after update).
    #[must_use]
    pub fn next(&mut self, flag: u8, value: u64) -> u64 {
        let update_slot = (flag & self.semantics.update_slot_mask) as usize;
        let get_slot =
            ((flag >> self.semantics.get_slot_shift) & self.semantics.get_slot_mask) as usize;
        let is_explicit = (flag & (1 << self.semantics.explicit_flag_bit)) != 0;

        // Ensure slots exist
        let len = self.slots.len();
        let (Some(update_slot), Some(get_slot)) =
            (update_slot.checked_rem(len), get_slot.checked_rem(len))
        else {
            return 0;
        };

        // Update the specified slot
        if is_explicit {
            // Explicit: set slot to value
            if let Some(slot) = self.slots.get_mut(update_slot) {
                *slot = value;
            }
        } else if let Some(op) = self.semantics.slot_operation(update_slot) {
            // Incremental: apply operation
            let current = self.slots.get(update_slot).copied().unwrap_or(0);
            if let Some(slot) = self.slots.get_mut(update_slot) {
                *slot = op.apply(current, value);
            }
        }

        // Return value from requested slot
        self.slots.get(get_slot).copied().unwrap_or(0)
    }

    /// Applies the Next operation with u32 values.
    ///
    /// This is a convenience method for obfuscators that use 32-bit state.
    #[must_use]
    pub fn next_u32(&mut self, flag: u8, value: u32) -> u32 {
        let update_slot = (flag & self.semantics.update_slot_mask) as usize;
        let get_slot =
            ((flag >> self.semantics.get_slot_shift) & self.semantics.get_slot_mask) as usize;
        let is_explicit = (flag & (1 << self.semantics.explicit_flag_bit)) != 0;

        // Ensure slots exist
        let len = self.slots.len();
        let (Some(update_slot), Some(get_slot)) =
            (update_slot.checked_rem(len), get_slot.checked_rem(len))
        else {
            return 0;
        };

        // Update the specified slot
        if is_explicit {
            if let Some(slot) = self.slots.get_mut(update_slot) {
                *slot = u64::from(value);
            }
        } else if let Some(op) = self.semantics.slot_operation(update_slot) {
            #[allow(clippy::cast_possible_truncation)]
            let current = self.slots.get(update_slot).copied().unwrap_or(0) as u32;
            if let Some(slot) = self.slots.get_mut(update_slot) {
                *slot = u64::from(op.apply_u32(current, value));
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        let result = self.slots.get(get_slot).copied().unwrap_or(0) as u32;
        result
    }

    /// Gets the value of a specific state slot.
    #[must_use]
    pub fn get(&self, slot: usize) -> u64 {
        self.slots.get(slot).copied().unwrap_or(0)
    }

    /// Gets the value of a specific state slot as u32.
    #[must_use]
    pub fn get_u32(&self, slot: usize) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        self.slots.get(slot).map_or(0, |&v| v as u32)
    }

    /// Sets the value of a specific state slot.
    pub fn set(&mut self, slot: usize, value: u64) {
        if let Some(s) = self.slots.get_mut(slot) {
            *s = value;
        }
    }

    /// Returns the number of slots in this state machine.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Returns a reference to the semantics.
    #[must_use]
    pub fn semantics(&self) -> &StateMachineSemantics {
        &self.semantics
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::deobfuscation::statemachine::{
        SsaOpKind, StateMachineSemantics, StateMachineState, StateSlotOperation,
    };

    #[test]
    fn test_slot_operation_xor() {
        let op = StateSlotOperation::xor();
        assert_eq!(op.apply(0x1234, 0x5678), 0x1234 ^ 0x5678);
        assert_eq!(op.apply_u32(0x1234, 0x5678), 0x1234 ^ 0x5678);
    }

    #[test]
    fn test_slot_operation_add() {
        let op = StateSlotOperation::add();
        assert_eq!(op.apply(100, 50), 150);
        assert_eq!(op.apply_u32(u32::MAX, 1), 0); // Wrapping
    }

    #[test]
    fn test_slot_operation_sub() {
        let op = StateSlotOperation::sub();
        assert_eq!(op.apply(100, 30), 70);
        assert_eq!(op.apply_u32(0, 1), u32::MAX); // Wrapping
    }

    #[test]
    fn test_slot_operation_mul() {
        let op = StateSlotOperation::mul();
        assert_eq!(op.apply(7, 6), 42);
        assert_eq!(
            op.apply_u32(0x1234_5678, 0x2141_2321),
            0x1234_5678_u32.wrapping_mul(0x2141_2321)
        );
    }

    #[test]
    fn test_slot_operation_reversed() {
        let op = StateSlotOperation::new_reversed(SsaOpKind::Sub);
        // reversed: b - a instead of a - b
        assert_eq!(op.apply(30, 100), 70); // 100 - 30 = 70
    }

    #[test]
    fn test_confuserex_semantics() {
        let semantics = StateMachineSemantics::confuserex_default();

        assert_eq!(semantics.slot_count, 4);
        assert_eq!(semantics.init_constant, Some(0x2141_2321));
        assert_eq!(semantics.slot_ops.len(), 4);
        assert_eq!(semantics.init_ops.len(), 4);
        assert_eq!(semantics.explicit_flag_bit, 7);
        assert_eq!(semantics.update_slot_mask, 0x03);
        assert_eq!(semantics.get_slot_mask, 0x03);
        assert_eq!(semantics.get_slot_shift, 2);
    }

    #[test]
    fn test_state_from_seed() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let state = StateMachineState::from_seed_u32(0x1234_5678, semantics);

        // Verify the multiplicative chain
        let mut seed = 0x1234_5678_u32;
        seed = seed.wrapping_mul(0x2141_2321);
        assert_eq!(state.get_u32(0), seed);
        seed = seed.wrapping_mul(0x2141_2321);
        assert_eq!(state.get_u32(1), seed);
        seed = seed.wrapping_mul(0x2141_2321);
        assert_eq!(state.get_u32(2), seed);
        seed = seed.wrapping_mul(0x2141_2321);
        assert_eq!(state.get_u32(3), seed);
    }

    #[test]
    fn test_state_next_incremental() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let mut state = StateMachineState::new(Arc::clone(&semantics));

        // Set initial values
        state.set(0, 0x1000_0000);
        state.set(1, 0x2000_0000);
        state.set(2, 0x3000_0000);
        state.set(3, 0x4000_0000);

        // Incremental update slot 0 (A ^= value), get slot 1 (return B)
        // Flag: 0b00000100 = (1 << 2) | 0 = get=1, update=0
        let flag = 0b0000_0100;
        let result = state.next_u32(flag, 0x0000_1111);
        assert_eq!(state.get_u32(0), 0x1000_0000 ^ 0x0000_1111);
        assert_eq!(result, state.get_u32(1));

        // Incremental update slot 1 (B += value), get slot 2 (return C)
        // Flag: 0b00001001 = (2 << 2) | 1 = get=2, update=1
        let flag = 0b0000_1001;
        let result = state.next_u32(flag, 0x0000_2222);
        assert_eq!(state.get_u32(1), 0x2000_0000_u32.wrapping_add(0x0000_2222));
        assert_eq!(result, state.get_u32(2));
    }

    #[test]
    fn test_state_next_explicit() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let mut state = StateMachineState::new(Arc::clone(&semantics));
        state.set(0, 0x1000_0000);

        // Explicit update slot 0 (A = value), get slot 0 (return A)
        // Flag: 0x80 | 0 = explicit, update=0, get=0
        let flag = 0x80;
        let result = state.next_u32(flag, 0xDEAD_BEEF);
        assert_eq!(state.get_u32(0), 0xDEAD_BEEF);
        assert_eq!(result, 0xDEAD_BEEF);
    }

    #[test]
    fn test_state_slot_count() {
        let semantics = Arc::new(StateMachineSemantics::confuserex_default());
        let state = StateMachineState::new(semantics);
        assert_eq!(state.slot_count(), 4);
    }

    #[test]
    fn test_custom_semantics() {
        // Test a custom state machine with 2 slots and different ops
        let semantics = Arc::new(StateMachineSemantics {
            slot_count: 2,
            slot_ops: vec![StateSlotOperation::add(), StateSlotOperation::xor()],
            init_ops: vec![StateSlotOperation::mul()],
            init_constant: Some(0x1337),
            ..Default::default()
        });

        let state = StateMachineState::from_seed_u32(1, Arc::clone(&semantics));
        assert_eq!(state.slot_count(), 2);

        // First slot: 1 * 0x1337 = 0x1337
        assert_eq!(state.get_u32(0), 0x1337);
        // Second slot: 0x1337 * 0x1337
        assert_eq!(state.get_u32(1), 0x1337_u32.wrapping_mul(0x1337));
    }
}

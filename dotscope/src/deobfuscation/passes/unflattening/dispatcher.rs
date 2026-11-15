//! Dispatcher analysis for CFF patterns.
//!
//! The dispatcher is the central control point in flattened code that routes
//! execution to different case blocks based on the state variable value.
//!
//! # Dispatcher Types
//!
//! Different obfuscators use different dispatcher implementations:
//!
//! - **Switch-based**: Uses a `switch` instruction with optional state transform
//! - **If-else chain**: Uses cascading `if (state == X)` comparisons
//! - **Computed jump**: Uses indirect branching through a jump table
//!
//! This module provides representations for all these patterns and analysis
//! functions to classify them.

use crate::analysis::{InstrId, SsaFunction, SsaOp, SsaVarId};

/// A detected CFF dispatcher with all its metadata.
///
/// This struct is the primary output of dispatcher detection and contains
/// all the information needed to unflatten the control flow.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    /// Block index containing the dispatcher switch/branch.
    pub block: usize,
    /// The SSA variable used in the switch instruction.
    pub switch_var: SsaVarId,
    /// Case block targets (index = case value after transform).
    pub cases: Vec<usize>,
    /// Default/exit block.
    pub default: usize,
    /// State variable phi at the dispatcher (if identified).
    pub state_phi: Option<SsaVarId>,
    /// Transform applied to state before dispatch.
    pub transform: StateTransform,
    /// Detection confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Initial state value from the entry block, if detected.
    /// Optimization passes may remove the `ldc.i4; stloc` that set this value,
    /// so it's captured during detection when the SSA is still complete.
    pub initial_state: Option<i64>,
    /// Identity of the switch instruction this dispatcher was detected on.
    ///
    /// Detection runs in an earlier phase than the pass that uses the result,
    /// and everything in between - pruning, block merging, reconstruction -
    /// renumbers blocks. [`Self::block`] is therefore a position that expires,
    /// while an [`InstrId`] names the same instruction wherever it ends up.
    /// `None` for a dispatcher built before ids were assigned, which falls
    /// back to the recorded index.
    pub switch_instr: Option<InstrId>,
}

impl Dispatcher {
    /// Creates a new dispatcher with the given parameters.
    #[must_use]
    pub fn new(block: usize, switch_var: SsaVarId, cases: Vec<usize>, default: usize) -> Self {
        Self {
            block,
            switch_var,
            cases,
            default,
            state_phi: None,
            transform: StateTransform::Identity,
            confidence: 0.0,
            initial_state: None,
            switch_instr: None,
        }
    }

    /// Records which instruction the dispatcher switch is.
    ///
    /// # Arguments
    ///
    /// * `id` - Identity of the switch instruction.
    #[must_use]
    pub fn with_switch_instr(mut self, id: InstrId) -> Self {
        self.switch_instr = Some(id);
        self
    }

    /// Sets the state phi variable
    ///
    /// # Arguments
    ///
    /// * `state_phi` - The phi node carrying the raw state value before encoding
    ///
    /// # Returns
    ///
    /// Self with the state phi set.
    #[must_use]
    pub fn with_state_phi(mut self, phi: SsaVarId) -> Self {
        self.state_phi = Some(phi);
        self
    }

    /// Sets the initial state value.
    #[must_use]
    pub fn with_initial_state(mut self, state: i64) -> Self {
        self.initial_state = Some(state);
        self
    }

    /// Sets the state transform.
    #[must_use]
    pub fn with_transform(mut self, transform: StateTransform) -> Self {
        self.transform = transform;
        self
    }

    /// Sets the confidence score
    ///
    /// # Arguments
    ///
    /// * `confidence` - Score from 0.0 to 1.0 indicating detection confidence
    ///
    /// # Returns
    ///
    /// Self with the confidence set.
    #[must_use]
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// Returns the number of case blocks.
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    /// Returns all target blocks (cases + default).
    #[must_use]
    pub fn all_targets(&self) -> Vec<usize> {
        let mut targets = self.cases.clone();
        if !targets.contains(&self.default) {
            targets.push(self.default);
        }
        targets
    }

    /// Returns the target block for a given state value.
    #[must_use]
    pub fn target_for_state(&self, state: i32) -> usize {
        // Cast to usize for indexing - transform result is always non-negative after modulo/and operations
        #[allow(clippy::cast_sign_loss)]
        let index = self.transform.apply(state) as usize;
        self.cases.get(index).copied().unwrap_or(self.default)
    }

    /// Re-reads the dispatcher out of the current SSA.
    ///
    /// Detection runs in its own phase, and by the time the pass consumes the
    /// result the function has been through pruning, block merging and one or
    /// more reconstructions. Everything recorded as an index - the dispatcher
    /// block, its cases, its default - names a position that may now hold a
    /// different block, and every `SsaVarId` has been re-minted.
    ///
    /// So only the switch's identity is carried across, and everything else is
    /// read back off the instruction it names: the block it now sits in, the
    /// targets it now has, and the variable it now switches on. Filtering stale
    /// indices for being out of range, as this did before, keeps whichever ones
    /// happen to still be in range while silently dropping the rest - it cannot
    /// tell a case that moved from a case that went away.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The current state of the function.
    ///
    /// # Returns
    ///
    /// `None` when the switch is gone, which is what an earlier pass having
    /// already resolved the dispatch looks like.
    #[must_use]
    pub fn refresh(&self, ssa: &SsaFunction) -> Option<Self> {
        let (block_idx, instr_idx) = self.locate(ssa)?;
        let SsaOp::Switch {
            value,
            targets,
            default,
        } = ssa.block(block_idx)?.instructions().get(instr_idx)?.op()
        else {
            return None;
        };

        let mut refreshed = Self::new(block_idx, *value, targets.clone(), *default);
        if let Some(id) = self.switch_instr {
            refreshed = refreshed.with_switch_instr(id);
        }
        // The phi feeding the switch, found through the IR's backward tracer so
        // that an encoded dispatcher - `(state ^ key) % n` - resolves to the
        // same phi a plain one does.
        if let Some(phi) = ssa.trace_to_phi(*value) {
            refreshed = refreshed.with_state_phi(phi);
        }
        refreshed = refreshed
            .with_transform(self.transform.clone())
            .with_confidence(self.confidence);
        if let Some(state) = self.initial_state {
            refreshed = refreshed.with_initial_state(state);
        }

        Some(refreshed)
    }

    /// Where the dispatcher switch is now.
    ///
    /// By identity when one was recorded. Without it there is nothing to look
    /// for but the recorded position, and the first switch in that block is the
    /// best guess available - which is what every dispatcher used to rely on.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The current state of the function.
    fn locate(&self, ssa: &SsaFunction) -> Option<(usize, usize)> {
        if let Some(id) = self.switch_instr {
            return ssa.locate_instruction(id);
        }
        let block = ssa.block(self.block)?;
        let instr_idx = block
            .instructions()
            .iter()
            .position(|instr| matches!(instr.op(), SsaOp::Switch { .. }))?;
        Some((self.block, instr_idx))
    }

    /// Converts to DispatcherInfo for compatibility.
    #[must_use]
    pub fn to_info(&self) -> DispatcherInfo {
        DispatcherInfo::Switch {
            block: self.block,
            switch_var: self.switch_var,
            cases: self.cases.clone(),
            default: self.default,
            transform: self.transform.clone(),
        }
    }
}

/// Transformation applied to state before dispatch.
///
/// Many obfuscators transform the state value before using it to select
/// a case. Common transforms include:
///
/// - `(state ^ key) % N` (XOR then modulo) - ConfuserEx pattern
/// - `state % N` (modulo) - Reduces state space to N cases
/// - `state & mask` (bitwise AND) - Masks to specific bits
/// - `state >> shift` (right shift) - Extracts upper bits
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum StateTransform {
    /// No transformation - state used directly.
    #[default]
    Identity,

    /// Modulo operation: `state % divisor`.
    Modulo(u32),

    /// XOR followed by modulo: `(state ^ xor_key) % divisor`.
    ///
    /// This is the ConfuserEx pattern. The state value is XOR'd with a
    /// constant key before the modulo operation.
    XorModulo {
        /// The XOR key applied before modulo.
        xor_key: i32,
        /// The modulo divisor.
        divisor: u32,
    },

    /// Bitwise AND: `state & mask`.
    And(u32),

    /// Right shift: `state >> amount`.
    Shr(u32),
}

impl StateTransform {
    /// Applies this transform to a state value.
    #[must_use]
    pub fn apply(&self, state: i32) -> i32 {
        match self {
            Self::Identity => state,
            Self::Modulo(n) => {
                // Use unsigned modulo for consistency with CIL rem.un
                let u_state = state.cast_unsigned();
                u_state.checked_rem(*n).unwrap_or(0).cast_signed()
            }
            Self::XorModulo { xor_key, divisor } => {
                // ConfuserEx pattern: (state ^ key) % N
                let xored = state ^ xor_key;
                let u_xored = xored.cast_unsigned();
                u_xored.checked_rem(*divisor).unwrap_or(0).cast_signed()
            }
            Self::And(mask) => state & (*mask).cast_signed(),
            Self::Shr(amount) => {
                // Logical right shift (treat as unsigned)
                let u_state = state.cast_unsigned();
                (u_state >> amount).cast_signed()
            }
        }
    }

    /// Returns the divisor for modulo transforms (including XorModulo).
    #[must_use]
    pub fn modulo_divisor(&self) -> Option<u32> {
        match self {
            Self::Modulo(n) => Some(*n),
            Self::XorModulo { divisor, .. } => Some(*divisor),
            _ => None,
        }
    }

    /// Returns the XOR key if this is an XorModulo transform.
    #[must_use]
    pub fn xor_key(&self) -> Option<i32> {
        match self {
            Self::XorModulo { xor_key, .. } => Some(*xor_key),
            _ => None,
        }
    }

    /// Returns whether this is the identity transform (no-op).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        matches!(self, Self::Identity)
    }

    /// Returns whether this is an XorModulo transform (ConfuserEx pattern).
    #[must_use]
    pub fn is_xor_modulo(&self) -> bool {
        matches!(self, Self::XorModulo { .. })
    }
}

/// Information about a detected dispatcher.
///
/// This struct captures all the details needed to understand how the
/// dispatcher routes control flow based on state values.
#[derive(Debug, Clone)]
pub enum DispatcherInfo {
    /// Switch-based dispatcher.
    ///
    /// The most common pattern, using a CIL `switch` instruction:
    /// ```text
    /// ldloc state
    /// ldc.i4 N
    /// rem.un           ; optional transform
    /// switch (case0, case1, ..., caseN-1)
    /// br default       ; fallthrough to default
    /// ```
    Switch {
        /// Block containing the switch instruction.
        block: usize,
        /// Variable used in the switch (after any transform).
        switch_var: SsaVarId,
        /// Case targets indexed by case value.
        /// `cases[i]` is the target block for case value `i`.
        cases: Vec<usize>,
        /// Default target (when value is out of range).
        default: usize,
        /// Transform applied to state before switch.
        transform: StateTransform,
    },

    /// If-else chain dispatcher.
    ///
    /// Used by some obfuscators to avoid obvious switch patterns:
    /// ```text
    /// if (state == X) goto blockX
    /// if (state == Y) goto blockY
    /// ...
    /// goto default
    /// ```
    IfElseChain {
        /// Head block (first comparison).
        head_block: usize,
        /// State variable being compared.
        state_var: SsaVarId,
        /// Comparisons in order: (compare_value, target_block).
        comparisons: Vec<(i32, usize)>,
        /// Default target when no comparison matches.
        default: Option<usize>,
    },

    /// Computed jump dispatcher (indirect branching).
    ///
    /// Some obfuscators use indirect jumps through a computed address:
    /// ```text
    /// ldloc state
    /// ; compute jump target address
    /// calli target  ; or similar indirect jump
    /// ```
    ///
    /// This is the hardest pattern to analyze as targets may not be
    /// statically determinable.
    ComputedJump {
        /// Block containing the indirect jump.
        block: usize,
        /// Variable holding the computed jump target.
        target_var: SsaVarId,
        /// Known jump table entries (if resolvable).
        /// Maps state value to target block.
        jump_table: Vec<usize>,
        /// Base address used in jump computation (if known).
        base_address: Option<u64>,
    },
}

impl DispatcherInfo {
    /// Returns the dispatcher block.
    #[must_use]
    pub fn block(&self) -> usize {
        match self {
            Self::Switch { block, .. } | Self::ComputedJump { block, .. } => *block,
            Self::IfElseChain { head_block, .. } => *head_block,
        }
    }

    /// Returns the number of cases (excluding default).
    #[must_use]
    pub fn case_count(&self) -> usize {
        match self {
            Self::Switch { cases, .. } => cases.len(),
            Self::IfElseChain { comparisons, .. } => comparisons.len(),
            Self::ComputedJump { jump_table, .. } => jump_table.len(),
        }
    }

    /// Returns the target block for a given case value.
    ///
    /// For switch dispatchers, this applies the transform and indexes into cases.
    /// For if-else chains, this searches the comparison list.
    /// For computed jumps, this indexes directly into the jump table.
    #[must_use]
    pub fn target_for_case(&self, case_value: i32) -> Option<usize> {
        match self {
            Self::Switch {
                cases,
                default,
                transform,
                ..
            } => {
                // Cast to usize for indexing - transform result is always non-negative after modulo/and operations
                #[allow(clippy::cast_sign_loss)]
                let index = transform.apply(case_value) as usize;
                Some(cases.get(index).copied().unwrap_or(*default))
            }
            Self::IfElseChain {
                comparisons,
                default,
                ..
            } => {
                for (cmp_val, target) in comparisons {
                    if *cmp_val == case_value {
                        return Some(*target);
                    }
                }
                *default
            }
            Self::ComputedJump { jump_table, .. } => {
                // Cast to usize for indexing - case_value is validated to be non-negative by caller
                #[allow(clippy::cast_sign_loss)]
                let index = case_value as usize;
                jump_table.get(index).copied()
            }
        }
    }

    /// Returns all possible target blocks.
    #[must_use]
    pub fn all_targets(&self) -> Vec<usize> {
        match self {
            Self::Switch { cases, default, .. } => {
                let mut targets: Vec<usize> = cases.clone();
                if !targets.contains(default) {
                    targets.push(*default);
                }
                targets
            }
            Self::IfElseChain {
                comparisons,
                default,
                ..
            } => {
                let mut targets: Vec<usize> = comparisons.iter().map(|(_, t)| *t).collect();
                if let Some(def) = default {
                    if !targets.contains(def) {
                        targets.push(*def);
                    }
                }
                targets
            }
            Self::ComputedJump { jump_table, .. } => jump_table.clone(),
        }
    }

    /// Returns the state transform applied before dispatch.
    #[must_use]
    pub fn transform(&self) -> StateTransform {
        match self {
            Self::Switch { transform, .. } => transform.clone(),
            Self::IfElseChain { .. } | Self::ComputedJump { .. } => StateTransform::Identity,
        }
    }

    /// Returns the variable used for dispatch decisions.
    #[must_use]
    pub fn dispatch_var(&self) -> SsaVarId {
        match self {
            Self::Switch { switch_var, .. } => *switch_var,
            Self::IfElseChain { state_var, .. } => *state_var,
            Self::ComputedJump { target_var, .. } => *target_var,
        }
    }

    /// Returns true if this is a computed jump dispatcher.
    #[must_use]
    pub fn is_computed_jump(&self) -> bool {
        matches!(self, Self::ComputedJump { .. })
    }

    /// Returns the base address for computed jump dispatchers.
    #[must_use]
    pub fn base_address(&self) -> Option<u64> {
        match self {
            Self::ComputedJump { base_address, .. } => *base_address,
            _ => None,
        }
    }
}

/// Analyzes a block to determine if it's a switch-based dispatcher.
///
/// Looks for the pattern:
/// ```text
/// [optional: ldloc state; ldc.i4 N; rem.un -> transformed_var]
/// switch(var) -> targets, default
/// ```
///
/// # Arguments
///
/// * `ssa` - The SSA function containing the block
/// * `block_idx` - Index of the block to analyze
///
/// # Returns
///
/// `Some(DispatcherInfo::Switch { .. })` if the block contains a switch-based
/// dispatcher pattern, `None` otherwise.
pub fn analyze_switch_dispatcher(ssa: &SsaFunction, block_idx: usize) -> Option<DispatcherInfo> {
    let block = ssa.block(block_idx)?;

    // Find the switch instruction (terminator)
    let switch_instr = block
        .instructions()
        .iter()
        .rev()
        .find(|i| matches!(i.op(), SsaOp::Switch { .. }))?;

    let (switch_var, targets, default) = match switch_instr.op() {
        SsaOp::Switch {
            value,
            targets,
            default,
        } => (*value, targets.clone(), *default),
        _ => return None,
    };

    // Determine if there's a transform applied to the switch variable
    let transform = analyze_switch_transform(ssa, switch_var);

    Some(DispatcherInfo::Switch {
        block: block_idx,
        switch_var,
        cases: targets,
        default,
        transform,
    })
}

/// Analyzes the definition of a switch variable to detect transforms.
fn analyze_switch_transform(ssa: &SsaFunction, switch_var: SsaVarId) -> StateTransform {
    let Some(def) = ssa.get_definition(switch_var) else {
        return StateTransform::Identity;
    };

    match def {
        // Remainder (modulo): state % N or (state ^ key) % N
        SsaOp::Rem {
            left,
            right,
            unsigned: true,
            ..
        } => {
            let Some(SsaOp::Const { value, .. }) = ssa.get_definition(*right) else {
                return StateTransform::Identity;
            };
            let Some(divisor) = value.as_i32() else {
                return StateTransform::Identity;
            };

            // Check if left operand is the result of an XOR operation (ConfuserEx pattern)
            // The pattern is: switch_var = (state ^ XOR_KEY) % N
            if let Some(xor_key) = find_xor_key(ssa, *left) {
                return StateTransform::XorModulo {
                    xor_key,
                    divisor: divisor.cast_unsigned(),
                };
            }

            StateTransform::Modulo(divisor.cast_unsigned())
        }

        // Bitwise AND: state & mask
        SsaOp::And { right, .. } => {
            if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(*right) {
                if let Some(mask) = value.as_i32() {
                    return StateTransform::And(mask.cast_unsigned());
                }
            }
            StateTransform::Identity
        }

        // Right shift: state >> amount
        SsaOp::Shr { amount, .. } => {
            if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(*amount) {
                if let Some(shift) = value.as_i32() {
                    return StateTransform::Shr(shift.cast_unsigned());
                }
            }
            StateTransform::Identity
        }

        _ => StateTransform::Identity,
    }
}

/// Finds the XOR key constant if the variable is defined by an XOR operation.
///
/// The ConfuserEx pattern is: `(state ^ XOR_KEY) % N`
/// We're looking for the XOR_KEY constant in the XOR operation.
fn find_xor_key(ssa: &SsaFunction, var: SsaVarId) -> Option<i32> {
    let def = ssa.get_definition(var)?;

    match def {
        // Direct XOR: var = left ^ right
        SsaOp::Xor { left, right, .. } => {
            // Check if right operand is a constant
            if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(*right) {
                if let Some(key) = value.as_i32() {
                    return Some(key);
                }
            }
            // Check if left operand is a constant (XOR is commutative)
            if let Some(SsaOp::Const { value, .. }) = ssa.get_definition(*left) {
                if let Some(key) = value.as_i32() {
                    return Some(key);
                }
            }
            None
        }

        // Copy operation: trace through
        SsaOp::Copy { src, .. } => find_xor_key(ssa, *src),

        // DUP is often used after XOR - the source might be the XOR result
        // In SSA, dup becomes a copy, so this is handled above
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::SsaVarId,
        deobfuscation::passes::unflattening::dispatcher::{DispatcherInfo, StateTransform},
    };

    #[test]
    fn test_state_transform_identity() {
        let transform = StateTransform::Identity;
        assert_eq!(transform.apply(42), 42);
        assert_eq!(transform.apply(-5), -5);
        assert!(transform.is_identity());
    }

    #[test]
    fn test_state_transform_modulo() {
        let transform = StateTransform::Modulo(7);
        assert_eq!(transform.apply(10), 3);
        assert_eq!(transform.apply(7), 0);
        assert_eq!(transform.apply(0), 0);
        assert_eq!(transform.modulo_divisor(), Some(7));
        assert!(!transform.is_identity());
    }

    #[test]
    fn test_state_transform_and() {
        let transform = StateTransform::And(0xFF);
        assert_eq!(transform.apply(0x12345678_u32 as i32), 0x78);
        assert_eq!(transform.apply(255), 255);
    }

    #[test]
    fn test_state_transform_shr() {
        let transform = StateTransform::Shr(8);
        assert_eq!(transform.apply(0x1234), 0x12);
    }

    #[test]
    fn test_state_transform_xor_modulo() {
        // ConfuserEx pattern: (state ^ xor_key) % divisor
        // Test with xor_key = -576502913 (0xDDA3001F), divisor = 7
        let transform = StateTransform::XorModulo {
            xor_key: -576502913_i32,
            divisor: 7,
        };

        // Verify it's not identity
        assert!(!transform.is_identity());
        assert!(transform.is_xor_modulo());
        assert_eq!(transform.modulo_divisor(), Some(7));
        assert_eq!(transform.xor_key(), Some(-576502913_i32));

        // Test with a sample state value
        // state = -781784372 (0xD18CAF8C)
        // xored = -781784372 ^ -576502913 = some value
        // result = (xored as u32) % 7
        let state = -781784372_i32;
        let xored = state ^ -576502913_i32;
        let expected = ((xored as u32) % 7) as i32;
        assert_eq!(transform.apply(state), expected);
    }

    #[test]
    fn test_dispatcher_info_switch() {
        let dispatcher = DispatcherInfo::Switch {
            block: 0,
            switch_var: SsaVarId::from_index(0),
            cases: vec![1, 2, 3, 4, 5],
            default: 6,
            transform: StateTransform::Modulo(5),
        };

        assert_eq!(dispatcher.block(), 0);
        assert_eq!(dispatcher.case_count(), 5);

        // Test case routing with modulo transform
        assert_eq!(dispatcher.target_for_case(0), Some(1)); // 0 % 5 = 0 -> cases[0]
        assert_eq!(dispatcher.target_for_case(1), Some(2)); // 1 % 5 = 1 -> cases[1]
        assert_eq!(dispatcher.target_for_case(5), Some(1)); // 5 % 5 = 0 -> cases[0]
        assert_eq!(dispatcher.target_for_case(7), Some(3)); // 7 % 5 = 2 -> cases[2]
    }

    #[test]
    fn test_dispatcher_info_switch_with_xor_modulo() {
        // Test with ConfuserEx-style XorModulo transform
        // XOR key = -576502913, divisor = 7
        let dispatcher = DispatcherInfo::Switch {
            block: 1,
            switch_var: SsaVarId::from_index(0),
            cases: vec![2, 3, 4, 5, 6, 7, 8], // 7 cases (0-6)
            default: 9,
            transform: StateTransform::XorModulo {
                xor_key: -576502913_i32,
                divisor: 7,
            },
        };

        assert_eq!(dispatcher.case_count(), 7);

        // Test case routing with XorModulo transform
        // state = -781784372 should XOR with key, then modulo 7
        let state = -781784372_i32;
        let xored = state ^ -576502913_i32;
        let expected_case_idx = ((xored as u32) % 7) as usize;
        assert_eq!(
            dispatcher.target_for_case(state),
            Some(dispatcher.all_targets()[expected_case_idx])
        );
    }

    #[test]
    fn test_dispatcher_info_if_else() {
        let dispatcher = DispatcherInfo::IfElseChain {
            head_block: 0,
            state_var: SsaVarId::from_index(0),
            comparisons: vec![(10, 1), (20, 2), (30, 3)],
            default: Some(4),
        };

        assert_eq!(dispatcher.block(), 0);
        assert_eq!(dispatcher.case_count(), 3);
        assert_eq!(dispatcher.target_for_case(10), Some(1));
        assert_eq!(dispatcher.target_for_case(20), Some(2));
        assert_eq!(dispatcher.target_for_case(99), Some(4)); // Not found -> default
    }

    #[test]
    fn test_dispatcher_all_targets() {
        let dispatcher = DispatcherInfo::Switch {
            block: 0,
            switch_var: SsaVarId::from_index(0),
            cases: vec![1, 2, 2, 3], // Note: 2 appears twice
            default: 4,
            transform: StateTransform::Identity,
        };

        let targets = dispatcher.all_targets();
        assert!(targets.contains(&1));
        assert!(targets.contains(&2));
        assert!(targets.contains(&3));
        assert!(targets.contains(&4));
    }

    #[test]
    fn test_dispatcher_info_computed_jump() {
        let dispatcher = DispatcherInfo::ComputedJump {
            block: 5,
            target_var: SsaVarId::from_index(0),
            jump_table: vec![10, 20, 30, 40],
            base_address: Some(0x1000),
        };

        assert_eq!(dispatcher.block(), 5);
        assert_eq!(dispatcher.case_count(), 4);
        assert!(dispatcher.is_computed_jump());
        assert_eq!(dispatcher.base_address(), Some(0x1000));

        // Test case routing via jump table
        assert_eq!(dispatcher.target_for_case(0), Some(10));
        assert_eq!(dispatcher.target_for_case(1), Some(20));
        assert_eq!(dispatcher.target_for_case(3), Some(40));
        assert_eq!(dispatcher.target_for_case(4), None); // Out of range

        let targets = dispatcher.all_targets();
        assert_eq!(targets, vec![10, 20, 30, 40]);
    }
}

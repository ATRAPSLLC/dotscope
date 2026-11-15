//! State variable identification for CFF analysis.
//!
//! The state variable is the integer variable that controls which case block
//! executes in a flattened control flow. Identifying it correctly is critical
//! for successful unflattening.
//!
//! # Identification Strategy
//!
//! We identify state variables through dataflow analysis rather than pattern
//! matching specific opcodes. A state variable has these characteristics:
//!
//! 1. **Used in dispatcher comparison**: The variable (or a derived value)
//!    controls the dispatcher's branch/switch
//! 2. **Defined in multiple places**: Each original basic block assigns a
//!    new state value
//! 3. **Integer type**: State values are always integers (typically i32/u32)
//! 4. **Control-flow only usage**: The variable is not used for computation,
//!    only for directing control flow

use std::collections::HashSet;

use crate::analysis::{FieldRef, SsaFunction, SsaType, SsaVarId};

/// Reference to a state variable.
///
/// State variables can be stored in different locations depending on
/// the obfuscator:
///
/// - **Local**: Most common, stored in a local variable
/// - **SSA Variable**: Direct SSA variable reference
/// - **Field**: Stored in an instance or static field (rare)
/// - **ArrayElement**: Stored in an array element (lookup table obfuscation)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StateVarRef {
    /// Local variable index (corresponds to `stloc`/`ldloc` instructions).
    Local(u16),

    /// Direct SSA variable ID.
    ///
    /// This is the most precise reference, pointing to a specific
    /// versioned variable in SSA form.
    SsaVar(SsaVarId),

    /// Instance or static field.
    ///
    /// Some obfuscators store state in fields to make analysis harder.
    Field(FieldRef),

    /// Array element lookup.
    ///
    /// Some obfuscators use lookup tables to determine state values:
    /// `state = stateTable[computedIndex]`
    ArrayElement {
        /// The SSA variable holding the array reference.
        array: SsaVarId,
        /// Pattern describing how the index is computed.
        index_pattern: IndexPattern,
    },
}

/// Pattern describing how an array index is computed.
///
/// Used to understand lookup table-based state obfuscation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndexPattern {
    /// Direct SSA variable used as index.
    Variable(SsaVarId),

    /// Constant index (rare but possible).
    Constant(i32),

    /// Index computed from another variable with an operation.
    Computed {
        /// Base variable for computation.
        base: SsaVarId,
        /// Operation applied (as string description).
        operation: String,
    },
}

impl StateVarRef {
    /// Creates a reference to a local variable.
    #[must_use]
    pub fn local(index: u16) -> Self {
        Self::Local(index)
    }

    /// Creates a reference to an SSA variable.
    #[must_use]
    pub fn ssa_var(var: SsaVarId) -> Self {
        Self::SsaVar(var)
    }

    /// Creates a reference to a field.
    #[must_use]
    pub fn field(field: FieldRef) -> Self {
        Self::Field(field)
    }

    /// Creates a reference to an array element.
    #[must_use]
    pub fn array_element(array: SsaVarId, index_pattern: IndexPattern) -> Self {
        Self::ArrayElement {
            array,
            index_pattern,
        }
    }

    /// Returns the local index if this is a local variable reference.
    #[must_use]
    pub fn as_local(&self) -> Option<u16> {
        match self {
            Self::Local(idx) => Some(*idx),
            _ => None,
        }
    }

    /// Returns the SSA variable ID if this is an SSA variable reference.
    #[must_use]
    pub fn as_ssa_var(&self) -> Option<SsaVarId> {
        match self {
            Self::SsaVar(var) => Some(*var),
            _ => None,
        }
    }

    /// Returns the array element info if this is an array element reference.
    #[must_use]
    pub fn as_array_element(&self) -> Option<(SsaVarId, &IndexPattern)> {
        match self {
            Self::ArrayElement {
                array,
                index_pattern,
            } => Some((*array, index_pattern)),
            _ => None,
        }
    }

    /// Returns true if this is a local variable reference.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    /// Returns true if this is an SSA variable reference.
    #[must_use]
    pub fn is_ssa_var(&self) -> bool {
        matches!(self, Self::SsaVar(_))
    }

    /// Returns true if this is a field reference.
    #[must_use]
    pub fn is_field(&self) -> bool {
        matches!(self, Self::Field(_))
    }

    /// Returns true if this is an array element reference.
    #[must_use]
    pub fn is_array_element(&self) -> bool {
        matches!(self, Self::ArrayElement { .. })
    }
}

/// Location in the SSA function where a variable is defined or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Location {
    /// Block index.
    pub block: usize,
    /// Instruction index within the block.
    pub instruction: usize,
}

impl Location {
    /// Creates a new location.
    #[must_use]
    pub const fn new(block: usize, instruction: usize) -> Self {
        Self { block, instruction }
    }
}

/// Identified state variable with analysis metadata.
///
/// Contains information about where the state variable is defined and used,
/// which helps validate that it's actually a CFF state variable and aids
/// in understanding the control flow structure.
#[derive(Debug, Clone)]
pub struct StateVariable {
    /// The variable reference (local, SSA var, or field).
    pub var: StateVarRef,

    /// The SSA variable at the dispatcher that receives the state value.
    ///
    /// In SSA form, this is typically a phi node that merges state values
    /// from different predecessors.
    pub dispatcher_var: Option<SsaVarId>,

    /// Locations where the state variable is defined.
    ///
    /// These correspond to the state update points in original basic blocks.
    pub def_sites: Vec<Location>,

    /// Locations where the state variable is used.
    ///
    /// Should primarily be the dispatcher comparison and state updates.
    pub use_sites: Vec<Location>,

    /// Confidence that this is the correct state variable (0.0 - 1.0).
    ///
    /// Higher values indicate stronger evidence this is a CFF state variable.
    pub confidence: f64,
}

impl StateVariable {
    /// Creates a new state variable with the given reference.
    #[must_use]
    pub fn new(var: StateVarRef) -> Self {
        Self {
            var,
            dispatcher_var: None,
            def_sites: Vec::new(),
            use_sites: Vec::new(),
            confidence: 0.0,
        }
    }

    /// Creates a state variable from a local index.
    #[must_use]
    pub fn from_local(local_index: u16) -> Self {
        Self::new(StateVarRef::Local(local_index))
    }

    /// Creates a state variable from an SSA variable.
    #[must_use]
    pub fn from_ssa_var(var: SsaVarId) -> Self {
        Self::new(StateVarRef::SsaVar(var))
    }

    /// Sets the dispatcher variable (the phi node at the dispatcher).
    pub fn with_dispatcher_var(mut self, var: SsaVarId) -> Self {
        self.dispatcher_var = Some(var);
        self
    }

    /// Adds a definition site.
    pub fn add_def_site(&mut self, location: Location) {
        if !self.def_sites.contains(&location) {
            self.def_sites.push(location);
        }
    }

    /// Adds a use site.
    pub fn add_use_site(&mut self, location: Location) {
        if !self.use_sites.contains(&location) {
            self.use_sites.push(location);
        }
    }

    /// Returns the number of definition sites.
    #[must_use]
    pub fn def_count(&self) -> usize {
        self.def_sites.len()
    }

    /// Returns the number of use sites.
    #[must_use]
    pub fn use_count(&self) -> usize {
        self.use_sites.len()
    }

    /// Checks if this variable is defined in the given block.
    #[must_use]
    pub fn is_defined_in(&self, block: usize) -> bool {
        self.def_sites.iter().any(|loc| loc.block == block)
    }

    /// Checks if this variable is used in the given block.
    #[must_use]
    pub fn is_used_in(&self, block: usize) -> bool {
        self.use_sites.iter().any(|loc| loc.block == block)
    }

    /// Returns all blocks where this variable is defined.
    #[must_use]
    pub fn def_blocks(&self) -> HashSet<usize> {
        self.def_sites.iter().map(|loc| loc.block).collect()
    }

    /// Returns all blocks where this variable is used.
    #[must_use]
    pub fn use_blocks(&self) -> HashSet<usize> {
        self.use_sites.iter().map(|loc| loc.block).collect()
    }
}

/// Analyzes an SSA function to identify the state variable for a dispatcher.
///
/// This function examines variables used in the dispatcher's terminator
/// and traces back through the SSA to find the PHI node that receives
/// state values from case blocks.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze
/// * `dispatcher_block` - Index of the dispatcher block
/// * `switch_var` - The SSA variable used in the switch instruction
///
/// # Returns
///
/// `Some(StateVariable)` if a state variable was identified, containing:
/// - The variable reference
/// - Definition and use sites
/// - Confidence score
///
/// `None` if no state variable could be identified.
pub fn identify_state_variable(
    ssa: &SsaFunction,
    dispatcher_block: usize,
    switch_var: SsaVarId,
) -> Option<StateVariable> {
    // The switch_var is what's used in the switch instruction.
    // We need to trace back to find the base state variable.

    // First, check if switch_var is directly defined by a phi node at the dispatcher
    let block = ssa.block(dispatcher_block)?;

    // Look for a phi node that defines the switch variable or a variable
    // that the switch variable depends on
    // The switch may operate on a transformed value (`rem.un(xor(state_phi,
    // key), N)` under ConfuserEx), so the definition chain is traced back to
    // the phi that provides the state.
    let phi_var = ssa.trace_to_phi(switch_var)?;

    // Build the state variable
    let mut state_var = StateVariable::from_ssa_var(phi_var);
    state_var.dispatcher_var = Some(phi_var);

    // Find all definition sites by looking at phi operands
    if let Some(phi_block) = ssa.block(dispatcher_block) {
        for phi in phi_block.phi_nodes() {
            if phi.result() == phi_var {
                for operand in phi.operands() {
                    state_var.add_def_site(Location::new(operand.predecessor(), 0));
                }
            }
        }
    }

    // Add use site at dispatcher
    state_var.add_use_site(Location::new(
        dispatcher_block,
        block.instruction_count().saturating_sub(1),
    ));

    // Compute confidence based on def/use pattern
    state_var.confidence = compute_state_var_confidence(ssa, &state_var);

    Some(state_var)
}

/// Computes confidence score for a potential state variable.
fn compute_state_var_confidence(ssa: &SsaFunction, state_var: &StateVariable) -> f64 {
    let mut score: f64 = 0.0;

    // More definition sites = higher confidence (CFF has many state updates)
    let def_count = state_var.def_count();
    if def_count >= 3 {
        score += 0.3;
    }
    if def_count >= 5 {
        score += 0.2;
    }

    // Having a dispatcher var (phi) is a strong signal
    if state_var.dispatcher_var.is_some() {
        score += 0.3;
    }

    // Check if the variable type is integer (required for CFF)
    if let Some(var_id) = state_var.var.as_ssa_var() {
        if let Some(var) = ssa.variable(var_id) {
            if matches!(
                var.var_type(),
                SsaType::I32 | SsaType::U32 | SsaType::I64 | SsaType::U64
            ) {
                score += 0.2;
            }
        }
    }

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::SsaVarId,
        deobfuscation::passes::unflattening::statevar::{
            IndexPattern, Location, StateVarRef, StateVariable,
        },
    };

    #[test]
    fn test_state_var_ref_local() {
        let var_ref = StateVarRef::local(5);
        assert_eq!(var_ref.as_local(), Some(5));
        assert!(var_ref.as_ssa_var().is_none());
        assert!(var_ref.is_local());
        assert!(!var_ref.is_array_element());
    }

    #[test]
    fn test_state_var_ref_ssa() {
        let var_id = SsaVarId::from_index(0);
        let var_ref = StateVarRef::ssa_var(var_id);
        assert_eq!(var_ref.as_ssa_var(), Some(var_id));
        assert!(var_ref.as_local().is_none());
        assert!(var_ref.is_ssa_var());
    }

    #[test]
    fn test_state_var_ref_array_element() {
        let array_var = SsaVarId::from_index(0);
        let index_var = SsaVarId::from_index(1);
        let var_ref = StateVarRef::array_element(array_var, IndexPattern::Variable(index_var));

        assert!(var_ref.is_array_element());
        assert!(!var_ref.is_local());

        let (arr, pattern) = var_ref.as_array_element().unwrap();
        assert_eq!(arr, array_var);
        assert!(matches!(pattern, IndexPattern::Variable(v) if *v == index_var));
    }

    #[test]
    fn test_index_pattern_variants() {
        let var = SsaVarId::from_index(0);

        let pattern1 = IndexPattern::Variable(var);
        assert!(matches!(pattern1, IndexPattern::Variable(_)));

        let pattern2 = IndexPattern::Constant(42);
        assert!(matches!(pattern2, IndexPattern::Constant(42)));

        let pattern3 = IndexPattern::Computed {
            base: var,
            operation: "xor 0x1234".to_string(),
        };
        assert!(matches!(pattern3, IndexPattern::Computed { .. }));
    }

    #[test]
    fn test_state_variable_def_use() {
        let mut state_var = StateVariable::from_local(0);

        state_var.add_def_site(Location::new(1, 5));
        state_var.add_def_site(Location::new(2, 3));
        state_var.add_use_site(Location::new(0, 10));

        assert_eq!(state_var.def_count(), 2);
        assert_eq!(state_var.use_count(), 1);
        assert!(state_var.is_defined_in(1));
        assert!(state_var.is_defined_in(2));
        assert!(!state_var.is_defined_in(0));
        assert!(state_var.is_used_in(0));
    }

    #[test]
    fn test_state_variable_blocks() {
        let mut state_var = StateVariable::from_local(0);

        state_var.add_def_site(Location::new(1, 0));
        state_var.add_def_site(Location::new(2, 0));
        state_var.add_def_site(Location::new(1, 5)); // Same block, different instruction

        let def_blocks = state_var.def_blocks();
        assert_eq!(def_blocks.len(), 2);
        assert!(def_blocks.contains(&1));
        assert!(def_blocks.contains(&2));
    }

    #[test]
    fn test_location() {
        let loc = Location::new(5, 10);
        assert_eq!(loc.block, 5);
        assert_eq!(loc.instruction, 10);
    }
}

//! Stack simulator for converting CIL stack operations to SSA variables.
//!
//! CIL is a stack-based instruction set where operands are implicitly passed via
//! the evaluation stack. This module simulates the stack to convert implicit
//! stack operations into explicit SSA variable references.
//!
//! # Stack Simulation
//!
//! The simulator tracks:
//!
//! - **Stack slots**: Each stack position maps to an SSA variable
//! - **Arguments**: Method parameters tracked across versions
//! - **Locals**: Local variables tracked across versions
//! - **Address-taken variables**: Variables whose address is taken (via `ldarga`/`ldloca`)
//! - **Stack slot sources**: Tracks whether each slot value was defined in this block
//!   or inherited from block entry (placeholder)
//!
//! # Example
//!
//! Consider the CIL sequence:
//! ```text
//! ldarg.0     // Push arg0 onto stack
//! ldarg.1     // Push arg1 onto stack
//! add         // Pop two values, push sum
//! stloc.0     // Pop and store to local0
//! ```
//!
//! The simulator converts this to:
//! ```text
//! v0 = ldarg.0           // v0 is arg0
//! v1 = ldarg.1           // v1 is arg1
//! v2 = add v0, v1        // v2 = v0 + v1
//! stloc.0 v2             // local0 = v2
//! ```
//!
//! # Thread Safety
//!
//! The simulator is designed for single-threaded use during SSA construction.

use std::collections::HashMap;

use crate::analysis::ssa::{SsaVarId, VariableOrigin};

/// Result of simulating one instruction's stack effects.
///
/// Contains the SSA variables consumed (popped) and produced (pushed) by
/// the instruction, along with the variable defined (if any).
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// SSA variables popped from the stack (operands).
    /// Order: deepest stack element first.
    pub uses: Vec<SsaVarId>,

    /// SSA variable pushed to the stack (result), if any.
    pub def: Option<SsaVarId>,
}

impl SimulationResult {
    /// Creates a result with no uses and no def.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            uses: Vec::new(),
            def: None,
        }
    }

    /// Creates a result with only a def (no uses).
    #[must_use]
    pub fn def_only(var: SsaVarId) -> Self {
        Self {
            uses: Vec::new(),
            def: Some(var),
        }
    }

    /// Creates a result with uses and a def.
    #[must_use]
    pub fn with_def(uses: Vec<SsaVarId>, def: SsaVarId) -> Self {
        Self {
            uses,
            def: Some(def),
        }
    }

    /// Creates a result with uses but no def.
    #[must_use]
    pub fn uses_only(uses: Vec<SsaVarId>) -> Self {
        Self { uses, def: None }
    }
}

/// Information about a variable's current state during simulation.
#[derive(Debug, Clone)]
struct VariableState {
    /// Current SSA variable ID for this argument/local.
    current_var: SsaVarId,
    /// Current version number (for SSA renaming).
    version: u32,
    /// Whether this variable's address has been taken.
    address_taken: bool,
}

impl VariableState {
    fn new(initial_var: SsaVarId) -> Self {
        Self {
            current_var: initial_var,
            version: 0,
            address_taken: false,
        }
    }
}

/// Stack simulator for CIL to SSA conversion.
///
/// Tracks the evaluation stack state and converts implicit stack operations
/// into explicit SSA variable references.
///
/// # Usage
///
/// The `examples::stack_simulator_example` test in this module runs this example.
#[derive(Debug)]
pub struct StackSimulator {
    /// The virtual evaluation stack.
    stack: Vec<SsaVarId>,

    /// State for each argument variable.
    args: Vec<VariableState>,

    /// State for each local variable.
    locals: Vec<VariableState>,

    /// Counter for generating stack slot origin numbers.
    next_stack_slot: u32,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// Maps simulation variable IDs to their stack depth position at creation.
    ///
    /// Records the stack depth (slot index) when each variable was allocated
    /// by `alloc_stack_var()`. SSA construction groups the values of one
    /// stack depth by it.
    var_stack_positions: HashMap<SsaVarId, usize>,

    /// Maps simulation variable IDs to the argument or local slot they are a
    /// version of.
    ///
    /// A `stloc`/`starg` produces a new version of a storage location rather
    /// than a value on the evaluation stack, and the slot it belongs to is what
    /// says two such versions are the same variable. SSA construction needs
    /// that grouping to know where a read of the slot finds its definition;
    /// without it each store would look like an unrelated temporary.
    slot_versions: HashMap<SsaVarId, VariableOrigin>,

    /// Counter for simulation-phase variable IDs.
    ///
    /// These are temporary IDs that SSA construction replaces. They start from
    /// a high offset to avoid colliding with the dense IDs (0, 1, 2, ...)
    /// `SsaFunction::create_variable()` allocates.
    next_sim_id: usize,
}

/// Starting offset for simulation-phase variable IDs.
///
/// Simulation IDs live in a separate range from production IDs (which start at
/// 0) so that neither can be mistaken for the other while instructions still
/// name a mixture of the two.
///
/// Expressed in `u32`, because that is the width an
/// [`SsaVarId`](crate::analysis::SsaVarId) keeps:
/// [`SsaVarId::from_index`](crate::analysis::SsaVarId::from_index) truncates its
/// `usize` argument. An offset above `u32::MAX` therefore wraps back onto the
/// dense ids it was chosen to avoid - `usize::MAX / 2` truncates to `u32::MAX`,
/// which makes the first simulation id the placeholder sentinel and every one
/// after it collide with a production id, one for one.
///
/// Half the `u32` range leaves room for more variables than a method can have.
const SIMULATION_ID_OFFSET: usize = (u32::MAX / 2) as usize;

impl StackSimulator {
    /// Creates a new stack simulator.
    ///
    /// # Arguments
    ///
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    #[must_use]
    pub fn new(num_args: usize, num_locals: usize) -> Self {
        let mut next_sim_id: usize = SIMULATION_ID_OFFSET;

        let mut slot_versions = HashMap::new();

        let mut args = Vec::with_capacity(num_args);
        for index in 0..num_args {
            let var = SsaVarId::from_index(next_sim_id);
            args.push(VariableState::new(var));
            slot_versions.insert(
                var,
                VariableOrigin::Argument(u16::try_from(index).unwrap_or(u16::MAX)),
            );
            next_sim_id = next_sim_id.saturating_add(1);
        }

        let mut locals = Vec::with_capacity(num_locals);
        for index in 0..num_locals {
            let var = SsaVarId::from_index(next_sim_id);
            locals.push(VariableState::new(var));
            slot_versions.insert(
                var,
                VariableOrigin::Local(u16::try_from(index).unwrap_or(u16::MAX)),
            );
            next_sim_id = next_sim_id.saturating_add(1);
        }

        Self {
            stack: Vec::with_capacity(16),
            args,
            locals,
            next_stack_slot: 0,
            num_args,
            num_locals,
            var_stack_positions: HashMap::new(),
            slot_versions,
            next_sim_id,
        }
    }

    /// Allocates a simulation-phase variable ID.
    ///
    /// These IDs are temporary placeholders SSA construction replaces.
    fn alloc_sim_id(&mut self) -> SsaVarId {
        let id = SsaVarId::from_index(self.next_sim_id);
        self.next_sim_id = self.next_sim_id.saturating_add(1);
        id
    }

    /// Returns the current stack depth.
    #[must_use]
    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    /// Returns `true` if the stack is empty.
    #[must_use]
    pub fn is_stack_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Initializes the stack with a given number of placeholder values.
    ///
    /// This is used when a block is entered with values already on the stack
    /// (e.g., due to `dup` before a conditional branch). Each slot gets a
    /// unique stack variable.
    ///
    /// # Arguments
    ///
    /// * `depth` - Number of stack slots to initialize
    pub fn initialize_stack(&mut self, depth: usize) {
        self.stack.clear();
        for _ in 0..depth {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(var);
        }
    }

    /// Resets the stack to a specific depth for entering a new basic block.
    ///
    /// This is used when simulating multiple blocks with a shared simulator.
    /// In well-formed CIL, the stack depth at block entry is deterministic and
    /// must be consistent across all paths to that block.
    ///
    /// IMPORTANT: This method ALWAYS clears and rebuilds the stack with fresh
    /// placeholder variables. This is necessary because blocks may not be
    /// simulated in predecessor-first order (e.g., due to RPO traversal), so the
    /// simulator's current stack state may contain stale variables from
    /// unrelated blocks. SSA construction answers each placeholder with the
    /// value that reaches the block (a phi result or a reaching definition).
    ///
    /// # Arguments
    ///
    /// * `depth` - The expected stack depth at block entry
    pub fn reset_stack_to_depth(&mut self, depth: usize) {
        // Always clear and rebuild with fresh placeholders, so each block has its
        // own entry stack variables for SSA construction to answer.
        self.stack.clear();
        for _ in 0..depth {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(var);
        }
    }

    /// Returns the number of method arguments.
    #[must_use]
    pub fn num_args(&self) -> usize {
        self.num_args
    }

    /// Returns the number of local variables.
    #[must_use]
    pub fn num_locals(&self) -> usize {
        self.num_locals
    }

    /// Returns `true` if the given argument has had its address taken.
    #[must_use]
    pub fn is_arg_address_taken(&self, index: usize) -> bool {
        self.args.get(index).is_some_and(|s| s.address_taken)
    }

    /// Returns `true` if the given local has had its address taken.
    #[must_use]
    pub fn is_local_address_taken(&self, index: usize) -> bool {
        self.locals.get(index).is_some_and(|s| s.address_taken)
    }

    /// Returns the slot each simulation variable is a version of.
    ///
    /// Covers the variables a `stloc`/`starg` produces and the ones every
    /// argument and local starts with. These are versions of a storage
    /// location, not values on the evaluation stack, and the slot is what
    /// groups them: SSA construction reads it to decide which definition a
    /// read of that slot names.
    #[must_use]
    pub fn slot_versions(&self) -> &HashMap<SsaVarId, VariableOrigin> {
        &self.slot_versions
    }

    /// Returns the stack position map for all simulation variables.
    ///
    /// Maps each simulation variable ID to the stack depth position it was
    /// allocated at, which is the slot that groups the values living there.
    #[must_use]
    pub fn var_stack_positions(&self) -> &HashMap<SsaVarId, usize> {
        &self.var_stack_positions
    }

    /// Returns a snapshot of the current stack contents (variable IDs only).
    ///
    /// The returned vector contains the variables currently on the stack,
    /// from bottom to top (index 0 is bottom of stack).
    /// Used to track stack state at block exits for creating PHI nodes.
    #[must_use]
    pub fn stack_snapshot(&self) -> Vec<SsaVarId> {
        self.stack.clone()
    }

    /// Allocates a new stack slot variable with a unique ID.
    ///
    /// Stack slots are allocated as `Local(num_locals + depth)` where `depth`
    /// is the current stack depth (i.e. the position the new value will occupy).
    /// This ensures origins match the depth-based scheme used by
    /// `SsaConverter::place_stack_phi_nodes()` which creates PHIs with
    /// `Local(num_locals + slot)`.
    ///
    /// The converter calls [`total_stack_slots`](Self::total_stack_slots) after
    /// simulation to update `SsaFunction::num_locals`.
    fn alloc_stack_var(&mut self) -> (SsaVarId, VariableOrigin) {
        let var = self.alloc_sim_id();
        let depth = self.stack.len();
        #[allow(clippy::cast_possible_truncation)]
        let local_idx = (self.num_locals as u16).saturating_add(depth as u16);
        let origin = VariableOrigin::Local(local_idx);
        // Track max depth for total_stack_slots()
        let depth_count = depth.saturating_add(1) as u32;
        if depth_count > self.next_stack_slot {
            self.next_stack_slot = depth_count;
        }
        // Record the depth: SSA construction groups the values of one stack
        // depth by it, rather than by `SsaVarId::index()`
        self.var_stack_positions.insert(var, depth);
        (var, origin)
    }

    /// Returns the maximum stack depth observed during simulation.
    ///
    /// After simulation, `num_locals + total_stack_slots()` gives the total
    /// number of locals (original + synthetic) in the function.
    #[must_use]
    pub fn total_stack_slots(&self) -> u32 {
        self.next_stack_slot
    }

    /// Gets the current SSA variable for an argument.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_arg_var(&self, index: usize) -> Option<SsaVarId> {
        self.args.get(index).map(|s| s.current_var)
    }

    /// Gets the current SSA variable for a local.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_local_var(&self, index: usize) -> Option<SsaVarId> {
        self.locals.get(index).map(|s| s.current_var)
    }

    /// Simulates loading an argument onto the stack (ldarg).
    ///
    /// Allocates a new stack variable and pushes it onto the stack. The new
    /// variable has a Stack origin (from `alloc_stack_var`), NOT an Argument
    /// origin. The connection to `Argument(index)` lives in the `arg_index`
    /// field of the generated `LoadArg` op.
    ///
    /// This produces a def so that `LoadArg` is visible to SSA analysis,
    /// enabling correct data flow tracking through SSA construction.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result with the new stack variable as def, or `None` if index is invalid.
    pub fn simulate_ldarg(&mut self, index: usize) -> Option<SimulationResult> {
        if index >= self.args.len() {
            return None;
        }
        let (var, _stack_origin) = self.alloc_stack_var();
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates loading a local onto the stack (ldloc).
    ///
    /// Allocates a new stack variable and pushes it onto the stack. The new
    /// variable has a Stack origin (from `alloc_stack_var`), NOT a Local
    /// origin. The connection to `Local(index)` lives in the `local_index`
    /// field of the generated `LoadLocal` op.
    ///
    /// This produces a def so that `LoadLocal` is visible to SSA analysis,
    /// enabling correct data flow tracking through SSA construction.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result with the new stack variable as def, or `None` if index is invalid.
    pub fn simulate_ldloc(&mut self, index: usize) -> Option<SimulationResult> {
        if index >= self.locals.len() {
            return None;
        }
        let (var, _stack_origin) = self.alloc_stack_var();
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates storing to an argument (starg).
    ///
    /// Creates a new SSA version for the argument.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result with the popped value as use and the new arg variable as def,
    /// or `None` if stack is empty or index invalid.
    pub fn simulate_starg(&mut self, index: usize) -> Option<SimulationResult> {
        let slot = self.stack.pop()?;

        if index >= self.args.len() {
            self.stack.push(slot);
            return None;
        }

        let new_var = self.alloc_sim_id();
        self.slot_versions.insert(
            new_var,
            VariableOrigin::Argument(u16::try_from(index).unwrap_or(u16::MAX)),
        );

        let state = self.args.get_mut(index)?;
        state.version = state.version.saturating_add(1);
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![slot], new_var))
    }

    /// Simulates storing to a local (stloc).
    ///
    /// Creates a new SSA version for the local.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result with the popped value as use and the new local variable as def,
    /// or `None` if stack is empty or index invalid.
    pub fn simulate_stloc(&mut self, index: usize) -> Option<SimulationResult> {
        let slot = self.stack.pop()?;
        if index >= self.locals.len() {
            self.stack.push(slot);
            return None;
        }

        let new_var = self.alloc_sim_id();
        self.slot_versions.insert(
            new_var,
            VariableOrigin::Local(u16::try_from(index).unwrap_or(u16::MAX)),
        );
        let state = self.locals.get_mut(index)?;
        state.version = state.version.saturating_add(1);
        state.current_var = new_var;

        // Return new_var as def to enable Copy op generation for constant propagation
        Some(SimulationResult::with_def(vec![slot], new_var))
    }

    /// Simulates loading the address of an argument (ldarga).
    ///
    /// Marks the argument as address-taken.
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if index is invalid.
    pub fn simulate_ldarga(&mut self, index: usize) -> Option<SimulationResult> {
        let state = self.args.get_mut(index)?;
        state.address_taken = true;

        let (var, _origin) = self.alloc_stack_var();
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates loading the address of a local (ldloca).
    ///
    /// Marks the local as address-taken.
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if index is invalid.
    pub fn simulate_ldloca(&mut self, index: usize) -> Option<SimulationResult> {
        let state = self.locals.get_mut(index)?;
        state.address_taken = true;

        let (var, _origin) = self.alloc_stack_var();
        self.stack.push(var);
        Some(SimulationResult::def_only(var))
    }

    /// Simulates a generic push operation (e.g., ldc.i4, ldnull).
    ///
    /// Creates a new stack variable and pushes it, marked as `Defined`.
    ///
    /// # Returns
    ///
    /// The new variable ID and its origin.
    pub fn simulate_push(&mut self) -> (SsaVarId, VariableOrigin) {
        let (var, origin) = self.alloc_stack_var();
        self.stack.push(var);
        (var, origin)
    }

    /// Simulates popping a value from the stack.
    ///
    /// # Returns
    ///
    /// The popped variable, or `None` if stack is empty.
    pub fn simulate_pop(&mut self) -> Option<SsaVarId> {
        self.stack.pop()
    }

    /// Simulates popping multiple values from the stack.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of values to pop
    ///
    /// # Returns
    ///
    /// A vector of popped variables (deepest first), or `None` if not enough values.
    pub fn simulate_pop_n(&mut self, count: usize) -> Option<Vec<SsaVarId>> {
        if self.stack.len() < count {
            return None;
        }

        let mut result = Vec::with_capacity(count);
        let start_idx = self.stack.len().saturating_sub(count);

        for i in start_idx..self.stack.len() {
            result.push(*self.stack.get(i)?);
        }

        self.stack.truncate(start_idx);
        Some(result)
    }

    /// Simulates a binary operation (pops 2, pushes 1).
    ///
    /// Used for: add, sub, mul, div, rem, and, or, xor, shl, shr, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_binary_op(&mut self) -> Option<SimulationResult> {
        let uses = self.simulate_pop_n(2)?;
        let (def, _origin) = self.alloc_stack_var();
        self.stack.push(def);
        Some(SimulationResult::with_def(uses, def))
    }

    /// Simulates a unary operation (pops 1, pushes 1).
    ///
    /// Used for: neg, not, conv.*, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_unary_op(&mut self) -> Option<SimulationResult> {
        let operand = self.simulate_pop()?;
        let (def, _origin) = self.alloc_stack_var();
        self.stack.push(def);
        Some(SimulationResult::with_def(vec![operand], def))
    }

    /// Simulates a comparison operation (pops 2, pushes 1 boolean).
    ///
    /// Used for: ceq, cgt, clt, etc.
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_comparison(&mut self) -> Option<SimulationResult> {
        self.simulate_binary_op()
    }

    /// Simulates a dup instruction (duplicates top of stack).
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack is empty.
    pub fn simulate_dup(&mut self) -> Option<SimulationResult> {
        let top = *self.stack.last()?;
        let (new_var, _origin) = self.alloc_stack_var();
        self.stack.push(new_var);
        Some(SimulationResult::with_def(vec![top], new_var))
    }

    /// Simulates an initobj instruction.
    ///
    /// `initobj` pops an address from the stack and initializes the memory
    /// location to zero/default.
    ///
    /// # Returns
    ///
    /// The simulation result with the address as a use.
    pub fn simulate_initobj(&mut self) -> Option<SimulationResult> {
        let address = self.stack.pop()?;
        Some(SimulationResult::uses_only(vec![address]))
    }

    /// Simulates a stind (store indirect) instruction.
    ///
    /// `stind` pops a value and an address, then stores the value at the address.
    ///
    /// # Returns
    ///
    /// The simulation result with both uses.
    pub fn simulate_stind(&mut self) -> Option<SimulationResult> {
        // Pop value first (top of stack), then the address
        let value = self.stack.pop()?;
        let address = self.stack.pop()?;
        Some(SimulationResult::uses_only(vec![address, value]))
    }

    /// Simulates a ret instruction.
    ///
    /// For non-void methods, pops the return value from the stack.
    /// For void methods (empty stack), returns empty uses.
    ///
    /// # Returns
    ///
    /// The simulation result with the return value (if any) as a use.
    #[must_use]
    pub fn simulate_ret(&mut self) -> SimulationResult {
        // Pop the return value if there's something on the stack
        let uses = if let Some(slot) = self.stack.pop() {
            vec![slot]
        } else {
            vec![]
        };

        SimulationResult { uses, def: None }
    }

    /// Simulates generic stack effects based on pop/push counts.
    ///
    /// # Arguments
    ///
    /// * `pops` - Number of values to pop
    /// * `pushes` - Number of values to push
    ///
    /// # Returns
    ///
    /// The simulation result, or `None` if stack underflow.
    pub fn simulate_stack_effect(&mut self, pops: u8, pushes: u8) -> Option<SimulationResult> {
        let uses = if pops > 0 {
            self.simulate_pop_n(pops as usize)?
        } else {
            Vec::new()
        };

        let def = if pushes > 0 {
            let (var, _origin) = self.alloc_stack_var();
            self.stack.push(var);

            for _ in 1..pushes {
                let (extra_var, _) = self.alloc_stack_var();
                self.stack.push(extra_var);
            }

            Some(var)
        } else {
            None
        };

        Some(SimulationResult { uses, def })
    }

    /// Clears the stack (e.g., at block boundaries or after control flow).
    pub fn clear_stack(&mut self) {
        self.stack.clear();
    }

    /// Simulates a `leave` or `leave.s` instruction.
    ///
    /// The leave instruction:
    /// 1. Clears the evaluation stack
    /// 2. Transfers control to a target outside the protected region
    ///
    /// This is used in structured exception handling to exit try blocks.
    pub fn simulate_leave(&mut self) -> SimulationResult {
        // Collect all variables currently on the stack as "uses" before clearing
        SimulationResult::uses_only(std::mem::take(&mut self.stack))
    }

    /// Sets the stack state from a vector of variables.
    ///
    /// Used for restoring state at block entry during SSA construction.
    pub fn set_stack(&mut self, stack: Vec<SsaVarId>) {
        self.stack = stack;
    }

    /// Updates the current variable for an argument (used during SSA renaming).
    ///
    /// # Arguments
    ///
    /// * `index` - The argument index
    /// * `var` - The new SSA variable ID
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if index is invalid.
    pub fn set_arg_var(&mut self, index: usize, var: SsaVarId) -> bool {
        if let Some(state) = self.args.get_mut(index) {
            state.current_var = var;
            true
        } else {
            false
        }
    }

    /// Updates the current variable for a local (used during SSA renaming).
    ///
    /// # Arguments
    ///
    /// * `index` - The local variable index
    /// * `var` - The new SSA variable ID
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if index is invalid.
    pub fn set_local_var(&mut self, index: usize, var: SsaVarId) -> bool {
        if let Some(state) = self.locals.get_mut(index) {
            state.current_var = var;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulator_creation() {
        let sim = StackSimulator::new(2, 3);
        assert_eq!(sim.num_args(), 2);
        assert_eq!(sim.num_locals(), 3);
        assert!(sim.is_stack_empty());
        assert_eq!(sim.stack_depth(), 0);
    }

    #[test]
    fn test_initial_arg_vars() {
        let sim = StackSimulator::new(3, 0);
        // Args should exist and be distinct
        let arg0 = sim.get_arg_var(0);
        let arg1 = sim.get_arg_var(1);
        let arg2 = sim.get_arg_var(2);
        assert!(arg0.is_some());
        assert!(arg1.is_some());
        assert!(arg2.is_some());
        assert_ne!(arg0, arg1);
        assert_ne!(arg1, arg2);
        assert_ne!(arg0, arg2);
        assert_eq!(sim.get_arg_var(3), None);
    }

    #[test]
    fn test_initial_local_vars() {
        let sim = StackSimulator::new(2, 3);
        // Locals should exist and be distinct from args
        let arg0 = sim.get_arg_var(0).unwrap();
        let arg1 = sim.get_arg_var(1).unwrap();
        let loc0 = sim.get_local_var(0).unwrap();
        let loc1 = sim.get_local_var(1).unwrap();
        let loc2 = sim.get_local_var(2).unwrap();
        // All variables should be distinct
        let all_vars = [arg0, arg1, loc0, loc1, loc2];
        for i in 0..all_vars.len() {
            for j in (i + 1)..all_vars.len() {
                assert_ne!(
                    all_vars[i], all_vars[j],
                    "Variables at {} and {} should be distinct",
                    i, j
                );
            }
        }
        assert_eq!(sim.get_local_var(3), None);
    }

    #[test]
    fn test_simulate_ldarg() {
        let mut sim = StackSimulator::new(2, 0);

        let result = sim.simulate_ldarg(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some()); // ldarg now produces a new stack var def
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_ldarg(1).unwrap();
        assert!(result.def.is_some()); // ldarg now produces a new stack var def
        assert_eq!(sim.stack_depth(), 2);
    }

    #[test]
    fn test_simulate_ldloc() {
        let mut sim = StackSimulator::new(1, 2);

        let result = sim.simulate_ldloc(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some()); // ldloc now produces a new stack var def
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_starg() {
        let mut sim = StackSimulator::new(2, 0);
        let initial_arg1 = sim.get_arg_var(1).unwrap();

        // Push a value first (ldarg now produces a new stack var)
        let ldarg_result = sim.simulate_ldarg(0).unwrap();
        let pushed_var = ldarg_result.def.unwrap();
        assert_eq!(sim.stack_depth(), 1);

        // Store to arg1
        let result = sim.simulate_starg(1).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], pushed_var); // The stack var from ldarg
        assert_eq!(sim.stack_depth(), 0);

        // arg1 should now have a new variable
        let new_var = sim.get_arg_var(1).unwrap();
        assert_ne!(new_var, initial_arg1); // Should be different from initial

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_stloc() {
        let mut sim = StackSimulator::new(1, 1);
        let initial_local0 = sim.get_local_var(0).unwrap();

        // Push a value first (ldarg now produces a new stack var)
        let ldarg_result = sim.simulate_ldarg(0).unwrap();
        let pushed_var = ldarg_result.def.unwrap();

        // Store to local0
        let result = sim.simulate_stloc(0).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], pushed_var);

        // local0 should now have a new variable
        let new_var = sim.get_local_var(0).unwrap();
        assert_ne!(new_var, initial_local0); // Different from initial local0

        // def should be the new variable (for Copy op generation)
        assert_eq!(result.def, Some(new_var));
    }

    #[test]
    fn test_simulate_binary_op() {
        let mut sim = StackSimulator::new(2, 0);

        // ldarg.0, ldarg.1 (now produce new stack vars)
        let r0 = sim.simulate_ldarg(0).unwrap();
        let r1 = sim.simulate_ldarg(1).unwrap();
        let var0 = r0.def.unwrap();
        let var1 = r1.def.unwrap();
        assert_eq!(sim.stack_depth(), 2);

        // add
        let result = sim.simulate_binary_op().unwrap();
        assert_eq!(result.uses.len(), 2);
        assert_eq!(result.uses[0], var0); // Deepest first
        assert_eq!(result.uses[1], var1);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_unary_op() {
        let mut sim = StackSimulator::new(1, 0);

        let r = sim.simulate_ldarg(0).unwrap();
        let pushed_var = r.def.unwrap();
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_unary_op().unwrap();
        assert_eq!(result.uses.len(), 1);
        assert_eq!(result.uses[0], pushed_var);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_dup() {
        let mut sim = StackSimulator::new(1, 0);

        sim.simulate_ldarg(0);
        assert_eq!(sim.stack_depth(), 1);

        let result = sim.simulate_dup().unwrap();
        assert_eq!(result.uses.len(), 1);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 2);
    }

    #[test]
    fn test_simulate_pop_n() {
        let mut sim = StackSimulator::new(3, 0);

        sim.simulate_ldarg(0);
        let r1 = sim.simulate_ldarg(1).unwrap();
        let r2 = sim.simulate_ldarg(2).unwrap();
        let var1 = r1.def.unwrap();
        let var2 = r2.def.unwrap();
        assert_eq!(sim.stack_depth(), 3);

        // Pop 2
        let popped = sim.simulate_pop_n(2).unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0], var1); // Deepest of the 2
        assert_eq!(popped[1], var2); // Top
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_simulate_pop_n_underflow() {
        let mut sim = StackSimulator::new(1, 0);

        sim.simulate_ldarg(0);

        // Try to pop more than available
        assert!(sim.simulate_pop_n(2).is_none());
        assert_eq!(sim.stack_depth(), 1); // Stack unchanged
    }

    #[test]
    fn test_simulate_ldarga() {
        let mut sim = StackSimulator::new(2, 0);

        assert!(!sim.is_arg_address_taken(0));

        let result = sim.simulate_ldarga(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
        assert!(sim.is_arg_address_taken(0));
        assert!(!sim.is_arg_address_taken(1));
    }

    #[test]
    fn test_simulate_ldloca() {
        let mut sim = StackSimulator::new(0, 2);

        assert!(!sim.is_local_address_taken(0));

        let result = sim.simulate_ldloca(0).unwrap();
        assert!(result.uses.is_empty());
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
        assert!(sim.is_local_address_taken(0));
        assert!(!sim.is_local_address_taken(1));
    }

    #[test]
    fn test_simulate_stack_effect() {
        let mut sim = StackSimulator::new(3, 0);

        // Push 3 values
        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);
        sim.simulate_ldarg(2);
        assert_eq!(sim.stack_depth(), 3);

        // Simulate instruction that pops 2, pushes 1
        let result = sim.simulate_stack_effect(2, 1).unwrap();
        assert_eq!(result.uses.len(), 2);
        assert!(result.def.is_some());
        assert_eq!(sim.stack_depth(), 2);

        // Simulate instruction that pops 1, pushes 0
        let result = sim.simulate_stack_effect(1, 0).unwrap();
        assert_eq!(result.uses.len(), 1);
        assert!(result.def.is_none());
        assert_eq!(sim.stack_depth(), 1);
    }

    #[test]
    fn test_stack_snapshot_and_restore() {
        let mut sim = StackSimulator::new(2, 0);

        sim.simulate_ldarg(0);
        sim.simulate_ldarg(1);

        let snapshot = sim.stack_snapshot();
        assert_eq!(snapshot.len(), 2);

        sim.clear_stack();
        assert!(sim.is_stack_empty());

        sim.set_stack(snapshot.clone());
        assert_eq!(sim.stack_depth(), 2);
        assert_eq!(sim.stack_snapshot(), snapshot);
    }

    #[test]
    fn test_set_arg_var() {
        let mut sim = StackSimulator::new(2, 0);

        let v = SsaVarId::from_index(0);
        assert!(sim.set_arg_var(0, v));
        assert_eq!(sim.get_arg_var(0), Some(v));

        assert!(!sim.set_arg_var(5, v)); // Invalid index
    }

    #[test]
    fn test_set_local_var() {
        let mut sim = StackSimulator::new(0, 2);

        let v = SsaVarId::from_index(0);
        assert!(sim.set_local_var(0, v));
        assert_eq!(sim.get_local_var(0), Some(v));

        assert!(!sim.set_local_var(5, v)); // Invalid index
    }

    #[test]
    fn test_simulation_result_constructors() {
        let empty = SimulationResult::empty();
        assert!(empty.uses.is_empty());
        assert!(empty.def.is_none());

        let v5 = SsaVarId::from_index(0);
        let def_only = SimulationResult::def_only(v5);
        assert!(def_only.uses.is_empty());
        assert_eq!(def_only.def, Some(v5));

        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses_only = SimulationResult::uses_only(vec![v1, v2]);
        assert_eq!(uses_only.uses.len(), 2);
        assert!(uses_only.def.is_none());

        let u1 = SsaVarId::from_index(3);
        let u2 = SsaVarId::from_index(4);
        let v3 = SsaVarId::from_index(5);
        let with_def = SimulationResult::with_def(vec![u1, u2], v3);
        assert_eq!(with_def.uses.len(), 2);
        assert_eq!(with_def.def, Some(v3));
    }

    #[test]
    fn test_complex_sequence() {
        // Simulate: local0 = arg0 + arg1
        let mut sim = StackSimulator::new(2, 1);

        // ldarg.0 - now produces a new stack var def
        let r1 = sim.simulate_ldarg(0).unwrap();
        let var0 = r1.def.unwrap(); // ldarg now produces a def
        assert!(r1.uses.is_empty());

        // ldarg.1 - now produces a new stack var def
        let r2 = sim.simulate_ldarg(1).unwrap();
        let var1 = r2.def.unwrap(); // ldarg now produces a def
        assert!(r2.uses.is_empty());

        // add - pops two values, creates new definition for the result
        let r3 = sim.simulate_binary_op().unwrap();
        assert_eq!(r3.uses, vec![var0, var1]);
        let add_result = r3.def.unwrap();

        // stloc.0 - pops result, creates new SSA version for local0
        let r4 = sim.simulate_stloc(0).unwrap();
        assert_eq!(r4.uses, vec![add_result]);

        assert!(sim.is_stack_empty());
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    /// `ldarg.0`, a constant and `add`: the add pops both values, deepest first, and leaves
    /// its result.
    #[test]
    fn stack_simulator_example() -> Result<()> {
        let mut sim = StackSimulator::new(2, 3); // 2 args, 3 locals

        let ldarg = sim.simulate_ldarg(0).expect("argument 0 exists");
        assert!(ldarg.uses.is_empty());
        let argument = ldarg.def.expect("ldarg pushes a value");
        let (constant, _) = sim.simulate_push();

        let add = sim.simulate_binary_op().expect("two operands on the stack");
        assert_eq!(add.uses, vec![argument, constant]);
        assert!(add.def.is_some());
        assert_eq!(sim.stack_depth(), 1);
        Ok(())
    }
}

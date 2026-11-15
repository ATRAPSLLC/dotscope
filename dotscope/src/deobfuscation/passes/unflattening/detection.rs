//! Control flow flattening detection via structural analysis.
//!
//! This module identifies CFF patterns by analyzing graph properties rather
//! than matching specific opcodes. This makes detection robust across different
//! obfuscators.
//!
//! # Detection Strategy
//!
//! CFF creates a distinctive graph structure:
//!
//! 1. **Large SCC**: The dispatcher and all case blocks form a strongly connected
//!    component (everyone can reach everyone via the dispatcher)
//! 2. **Dominator Pattern**: The dispatcher dominates all case blocks
//! 3. **High Predecessor Count**: The dispatcher has many predecessors (back edges)
//! 4. **Dispatcher Instruction**: A switch or branching pattern controls flow
//!
//! The confidence score combines these signals to distinguish CFF from normal
//! loops or state machines.

use std::{
    cmp::Ordering,
    collections::{HashSet, VecDeque},
};

use analyssa::{
    graph::{
        algorithms::{compute_dominators, DominatorTree},
        NodeId,
    },
    BitSet,
};
use rayon::prelude::*;

use crate::{
    analysis::{
        ControlFlow, SsaCfg, SsaEvaluator, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
        VariableOrigin,
    },
    deobfuscation::passes::unflattening::{
        dispatcher::{analyze_switch_dispatcher, Dispatcher, DispatcherInfo},
        statevar::{identify_state_variable, StateVariable},
        UnflattenConfig,
    },
};

/// Entry point into a CFF region.
///
/// CFF can have multiple entry points when there are different paths into
/// the flattened region, each potentially starting with a different initial state.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    /// Index of the entry block (before/at dispatcher).
    pub block: usize,

    /// Initial state value at this entry point (if known).
    pub initial_state: Option<i64>,

    /// Condition to reach this entry (for multiple entries).
    ///
    /// When a function has multiple paths into the CFF, each may have
    /// a different condition. `None` means unconditional entry.
    pub condition: Option<EntryCondition>,

    /// SSA variable that holds the initial state (if identifiable).
    pub state_var: Option<SsaVarId>,
}

/// Condition for reaching an entry point.
#[derive(Debug, Clone)]
pub enum EntryCondition {
    /// Entry is taken when a comparison is true.
    Compare {
        /// The variable being compared.
        var: SsaVarId,
        /// The comparison value.
        value: i64,
        /// True if this is the "equals" case, false for "not equals".
        is_equal: bool,
    },

    /// Entry is a switch case value.
    SwitchCase(i64),

    /// Entry depends on a boolean variable.
    Boolean {
        /// The boolean variable.
        var: SsaVarId,
        /// True if entry when true, false if entry when false.
        when_true: bool,
    },

    /// Entry depends on an argument value.
    Argument {
        /// Argument index.
        index: u16,
        /// Expected value (if known).
        expected: Option<i64>,
    },
}

impl EntryPoint {
    /// Creates a simple entry point with just a block index.
    #[must_use]
    pub fn new(block: usize) -> Self {
        Self {
            block,
            initial_state: None,
            condition: None,
            state_var: None,
        }
    }

    /// Creates an entry point with a known initial state.
    #[must_use]
    pub fn with_state(block: usize, initial_state: i64) -> Self {
        Self {
            block,
            initial_state: Some(initial_state),
            condition: None,
            state_var: None,
        }
    }

    /// Sets the condition for this entry point.
    pub fn with_condition(mut self, condition: EntryCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// Sets the state variable for this entry point.
    pub fn with_state_var(mut self, var: SsaVarId) -> Self {
        self.state_var = Some(var);
        self
    }

    /// Returns true if this is an unconditional entry.
    #[must_use]
    pub fn is_unconditional(&self) -> bool {
        self.condition.is_none()
    }

    /// Returns true if the initial state is known.
    #[must_use]
    pub fn has_known_state(&self) -> bool {
        self.initial_state.is_some()
    }
}

/// Detected CFF pattern with analysis metadata.
#[derive(Debug, Clone)]
pub struct CffPattern {
    /// Index of the dispatcher block.
    pub dispatcher_block: usize,

    /// Dispatcher information (switch/if-else chain).
    pub dispatcher: DispatcherInfo,

    /// Identified state variable.
    pub state_var: Option<StateVariable>,

    /// Blocks that are part of the CFF structure (case blocks).
    pub case_blocks: BitSet,

    /// Entry block (before dispatcher, if separate).
    ///
    /// This is the legacy single-entry field. For new code, prefer
    /// using `entry_points` which supports multiple entries.
    pub entry_block: Option<usize>,

    /// Entry points into the CFF region.
    ///
    /// Most CFF has a single entry point, but some obfuscators create
    /// multiple entries with different initial states based on conditions.
    pub entry_points: Vec<EntryPoint>,

    /// Exit blocks (leave the CFF structure).
    pub exit_blocks: BitSet,

    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

impl CffPattern {
    /// Returns the number of case blocks.
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.dispatcher.case_count()
    }

    /// Returns true if this pattern looks like ConfuserEx.
    #[must_use]
    pub fn is_confuserex_style(&self) -> bool {
        // ConfuserEx uses switch with modulo transform
        matches!(&self.dispatcher, DispatcherInfo::Switch { transform, .. }
            if transform.modulo_divisor().is_some())
    }

    /// Returns true if this pattern has multiple entry points.
    #[must_use]
    pub fn has_multiple_entries(&self) -> bool {
        self.entry_points.len() > 1
    }

    /// Returns the number of entry points.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_points.len()
    }

    /// Returns the primary entry point (first or only entry).
    #[must_use]
    pub fn primary_entry(&self) -> Option<&EntryPoint> {
        self.entry_points.first()
    }

    /// Returns entry points with known initial states.
    #[must_use]
    pub fn entries_with_states(&self) -> Vec<&EntryPoint> {
        self.entry_points
            .iter()
            .filter(|e| e.has_known_state())
            .collect()
    }

    /// Returns all initial states from entry points.
    #[must_use]
    pub fn initial_states(&self) -> Vec<i64> {
        self.entry_points
            .iter()
            .filter_map(|e| e.initial_state)
            .collect()
    }
}

/// CFF detection engine.
pub struct CffDetector<'a> {
    ssa: &'a SsaFunction,
    /// The terminator-derived CFG relation. `SsaFunction` no longer answers
    /// predecessor or successor questions itself, so the view is built once
    /// here and shared by every query in this module.
    cfg: SsaCfg<'a>,
    config: UnflattenConfig,
    /// Cached dominator tree (computed lazily)
    dom_tree: Option<DominatorTree>,
}

impl<'a> CffDetector<'a> {
    /// Creates a new CFF detector with default configuration.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction) -> Self {
        Self {
            ssa,
            cfg: SsaCfg::from_ssa(ssa),
            config: UnflattenConfig::default(),
            dom_tree: None,
        }
    }

    /// Creates a new CFF detector with the given configuration.
    #[must_use]
    pub fn with_config(ssa: &'a SsaFunction, config: &UnflattenConfig) -> Self {
        Self {
            ssa,
            cfg: SsaCfg::from_ssa(ssa),
            config: config.clone(),
            dom_tree: None,
        }
    }

    /// Gets or computes the dominator tree.
    fn get_dom_tree(&mut self) -> &DominatorTree {
        let Self { cfg, dom_tree, .. } = self;
        dom_tree.get_or_insert_with(|| compute_dominators(cfg, NodeId::new(0)))
    }

    /// Detects the best CFF dispatcher in the function.
    ///
    /// Returns `Some(Dispatcher)` if a dispatcher is found, `None` otherwise.
    /// This is a simpler API that returns just the dispatcher information
    /// without the full CFF pattern metadata.
    pub fn detect_best(&mut self) -> Option<Dispatcher> {
        let pattern = self.detect()?;
        Self::pattern_to_dispatcher(&pattern)
    }

    /// Detects all CFF dispatchers in the function.
    ///
    /// Returns all `Dispatcher`s found, sorted by confidence (highest first).
    /// Unlike [`detect_best`](Self::detect_best) which returns only the single
    /// best dispatcher, this method returns all candidates that pass analysis.
    /// The caller is responsible for filtering by confidence threshold.
    pub fn detect_all_dispatchers(&mut self) -> Vec<Dispatcher> {
        let patterns = self.detect_all();
        let ssa = self.ssa;
        patterns
            .iter()
            .filter_map(Self::pattern_to_dispatcher)
            .map(|dispatcher| {
                // Record which instruction the switch is while the indices
                // still mean something. The pass that consumes this runs after
                // the blocks have been renumbered more than once, and only an
                // identity survives that - see `Dispatcher::refresh`.
                match ssa.block(dispatcher.block).and_then(|block| {
                    block
                        .instructions()
                        .iter()
                        .find(|instr| matches!(instr.op(), SsaOp::Switch { .. }))
                        .and_then(SsaInstruction::id)
                }) {
                    Some(id) => dispatcher.with_switch_instr(id),
                    None => dispatcher,
                }
            })
            .collect()
    }

    /// Detects all CFF patterns in the function.
    ///
    /// Returns all `CffPattern`s found, sorted by confidence (highest first).
    /// Candidate analysis is parallelized - each candidate is scored
    /// independently against a shared (pre-computed) dominator tree.
    fn detect_all(&mut self) -> Vec<CffPattern> {
        if self.ssa.block_count() < 4 {
            return Vec::new();
        }

        let candidates = self.find_dispatcher_candidates();
        if candidates.is_empty() {
            return Vec::new();
        }

        // Pre-compute the dominator tree so candidate analysis can be parallel
        let _ = self.get_dom_tree();
        let Some(dom_tree) = self.dom_tree.as_ref() else {
            return Vec::new();
        };

        let mut patterns: Vec<CffPattern> = candidates
            .into_par_iter()
            .filter_map(|block_idx| self.analyze_candidate_with_dom(block_idx, dom_tree))
            .collect();

        // Sort by confidence (highest first)
        patterns.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
        });

        patterns
    }

    /// Converts a `CffPattern` to a `Dispatcher`.
    fn pattern_to_dispatcher(pattern: &CffPattern) -> Option<Dispatcher> {
        match &pattern.dispatcher {
            DispatcherInfo::Switch {
                block,
                switch_var,
                cases,
                default,
                transform,
            } => {
                let mut dispatcher = Dispatcher::new(*block, *switch_var, cases.clone(), *default);

                if let Some(ref state_var) = pattern.state_var {
                    if let Some(phi_var) = state_var.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher
                    .with_transform(transform.clone())
                    .with_confidence(pattern.confidence);

                // Carry the initial state from the primary entry point.
                // This is critical for NETReactor CFF: optimization passes may
                // remove the `ldc.i4; stloc` that sets the initial state, so
                // we capture it during detection when the SSA is still complete.
                if let Some(state) = pattern.primary_entry().and_then(|e| e.initial_state) {
                    dispatcher = dispatcher.with_initial_state(state);
                }

                Some(dispatcher)
            }
            DispatcherInfo::IfElseChain {
                head_block,
                state_var,
                comparisons,
                default,
            } => {
                let cases: Vec<usize> = comparisons.iter().map(|(_, target)| *target).collect();
                let default_block = default.unwrap_or(*head_block);

                let mut dispatcher = Dispatcher::new(*head_block, *state_var, cases, default_block);

                if let Some(ref state_var_info) = pattern.state_var {
                    if let Some(phi_var) = state_var_info.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher.with_confidence(pattern.confidence);

                Some(dispatcher)
            }
            DispatcherInfo::ComputedJump {
                block,
                target_var,
                jump_table,
                ..
            } => {
                let default_block = jump_table.first().copied().unwrap_or(0);

                let mut dispatcher =
                    Dispatcher::new(*block, *target_var, jump_table.clone(), default_block);

                if let Some(ref state_var_info) = pattern.state_var {
                    if let Some(phi_var) = state_var_info.dispatcher_var {
                        dispatcher = dispatcher.with_state_phi(phi_var);
                    }
                }

                dispatcher = dispatcher.with_confidence(pattern.confidence);

                Some(dispatcher)
            }
        }
    }

    /// Attempts to detect CFF in the function.
    ///
    /// Returns `Some(CffPattern)` if CFF is detected, `None` otherwise.
    pub fn detect(&mut self) -> Option<CffPattern> {
        // Early exit: too few blocks for CFF
        if self.ssa.block_count() < 4 {
            return None;
        }

        // Find candidate dispatcher blocks
        let candidates = self.find_dispatcher_candidates();

        if candidates.is_empty() {
            return None;
        }

        // Pre-compute dominator tree once
        let _ = self.get_dom_tree();
        let dom_tree = self.dom_tree.as_ref()?;

        // Score each candidate and pick the best
        let mut best_pattern: Option<CffPattern> = None;
        let mut best_score = 0.0;

        for block_idx in candidates {
            if let Some(pattern) = self.analyze_candidate_with_dom(block_idx, dom_tree) {
                if pattern.confidence > best_score {
                    best_score = pattern.confidence;
                    best_pattern = Some(pattern);
                }
            }
        }

        best_pattern
    }

    /// Finds blocks that could be dispatchers.
    ///
    /// Dispatchers typically have:
    /// - Multiple predecessors (back edges from case blocks)
    /// - A switch instruction or branching pattern
    ///
    /// Each block is tested independently (read-only), so candidates are
    /// found in parallel.
    fn find_dispatcher_candidates(&self) -> Vec<usize> {
        (0..self.ssa.block_count())
            .into_par_iter()
            .filter(|&block_idx| self.is_dispatcher_candidate(block_idx))
            .collect()
    }

    /// Returns whether `var` ultimately originates from a method argument,
    /// tracing through any chain of `Copy` instructions.
    ///
    /// CIL frequently lowers `ldarg ; switch` to a `Copy` of the argument
    /// into a fresh temporary before the `switch`. The temporary's
    /// [`VariableOrigin`] is `Local` (or `Synthetic`), which would otherwise
    /// hide the underlying argument from a single-step origin check. This
    /// helper walks the `Copy` chain iteratively (with a visited set to
    /// avoid pathological cycles in malformed SSA) and reports whether any
    /// link in the chain is an `Argument`.
    fn is_argument_derived(&self, mut var: SsaVarId) -> bool {
        let mut visited: HashSet<SsaVarId> = HashSet::new();
        loop {
            if !visited.insert(var) {
                return false;
            }
            let Some(variable) = self.ssa.variable(var) else {
                return false;
            };
            if matches!(variable.origin(), VariableOrigin::Argument(_)) {
                return true;
            }
            match self.ssa.get_definition(var) {
                Some(SsaOp::Copy { src, .. }) => var = *src,
                _ => return false,
            }
        }
    }

    /// Checks if a block could be a dispatcher.
    fn is_dispatcher_candidate(&self, block_idx: usize) -> bool {
        let Some(block) = self.ssa.block(block_idx) else {
            return false;
        };

        // Must have terminator instructions
        if block.instructions().is_empty() {
            return false;
        }

        // Look for switch or multi-target branch
        let has_switch = block
            .instructions()
            .iter()
            .any(|instr| matches!(instr.op(), SsaOp::Switch { .. }));

        if has_switch {
            // Reject switches on method arguments - they are user switches
            // (e.g., switch on a parameter in DemoSwitch), not CFF dispatchers.
            // Arguments are immutable and cannot be CFF state variables.
            //
            // Trace through `Copy` chains so a switch on `v_n = v_arg`
            // (typical CIL `ldarg ; switch` lowering) is also rejected.
            // Without this, NETReactor's CFF + opaque-predicate dead arms
            // can give a user switch enough predecessors to pass the
            // candidate filter and be misclassified as a dispatcher.
            let switch_on_argument = block.instructions().iter().any(|instr| {
                let SsaOp::Switch { value, .. } = instr.op() else {
                    return false;
                };
                self.is_argument_derived(*value)
            });
            if switch_on_argument {
                return false;
            }

            // Check predecessor count (should have many back edges).
            // A switch targeting itself is a valid CFF back-edge (e.g.,
            // x86-resolved CFF where case blocks were folded into the
            // dispatcher); `SsaCfg` reports that self-edge like any other, so
            // it needs no separate accounting.
            return self.cfg.block_predecessors(block_idx).len() >= 2;
        }

        // Also consider blocks with conditional branches that could be if-else chains
        let has_branch = block
            .instructions()
            .iter()
            .any(|instr| matches!(instr.op(), SsaOp::Branch { .. }));

        if has_branch {
            let pred_count = self.cfg.block_predecessors(block_idx).len();
            // If-else dispatchers typically have even more predecessors
            return pred_count >= 3;
        }

        false
    }

    /// Analyzes a dispatcher candidate with a pre-computed dominator tree.
    ///
    /// Takes `&self` (not `&mut self`) so it can be called from parallel
    /// iterators. The dominator tree is passed explicitly instead of being
    /// lazily computed.
    fn analyze_candidate_with_dom(
        &self,
        block_idx: usize,
        dom_tree: &DominatorTree,
    ) -> Option<CffPattern> {
        // Try to identify dispatcher type
        let dispatcher = analyze_switch_dispatcher(self.ssa, block_idx)?;

        // Identify state variable
        let state_var = identify_state_variable(self.ssa, block_idx, dispatcher.dispatch_var());

        // Find case blocks (targets of the dispatcher)
        let mut case_blocks = BitSet::new(self.ssa.block_count());
        for target in dispatcher.all_targets() {
            case_blocks.insert(target);
        }

        // Find exit blocks (blocks that leave the CFF structure)
        let exit_blocks = self.find_exit_blocks(block_idx, &case_blocks);

        // Find entry block (if separate from dispatcher) - legacy
        let entry_block = self.find_entry_block(block_idx);

        // Find all entry points (including multiple entries if present)
        let entry_points = self.find_entry_points(block_idx, &case_blocks, state_var.as_ref());

        // Compute confidence score (includes dominance analysis)
        let confidence = self.compute_confidence(
            block_idx,
            &dispatcher,
            state_var.as_ref(),
            &case_blocks,
            &exit_blocks,
            dom_tree,
        );

        Some(CffPattern {
            dispatcher_block: block_idx,
            dispatcher,
            state_var,
            case_blocks,
            entry_block,
            entry_points,
            exit_blocks,
            confidence,
        })
    }

    /// Finds blocks that exit the CFF structure.
    fn find_exit_blocks(&self, dispatcher_block: usize, case_blocks: &BitSet) -> BitSet {
        let mut exits = BitSet::new(self.ssa.block_count());

        // Check successors of case blocks that don't go back to dispatcher
        for case_block in case_blocks.iter() {
            for &succ in self.cfg.block_successors(case_block) {
                if succ != dispatcher_block && !case_blocks.contains(succ) {
                    exits.insert(succ);
                }
            }
        }

        exits
    }

    /// Finds the entry block (predecessor of dispatcher that isn't a case block).
    fn find_entry_block(&self, dispatcher_block: usize) -> Option<usize> {
        let preds = self.cfg.block_predecessors(dispatcher_block);

        // Entry block is typically block 0 or the first predecessor
        // that doesn't look like it came from a case block
        for &pred in preds {
            if pred == 0 {
                return Some(pred);
            }
        }

        // If dispatcher is block 0, there's no separate entry
        if dispatcher_block == 0 {
            return None;
        }

        None
    }

    /// Finds all entry points into the CFF region.
    ///
    /// This method identifies blocks that can enter the CFF, along with
    /// any conditions on those entries. Most CFF has a single entry point,
    /// but some obfuscators create multiple entries.
    fn find_entry_points(
        &self,
        dispatcher_block: usize,
        case_blocks: &BitSet,
        state_var: Option<&StateVariable>,
    ) -> Vec<EntryPoint> {
        let mut entries = Vec::new();
        let preds = self.cfg.block_predecessors(dispatcher_block);

        // Collect non-case-block predecessors as potential entry points
        let entry_blocks: Vec<usize> = preds
            .iter()
            .filter(|&&pred| !case_blocks.contains(pred))
            .copied()
            .collect();

        if entry_blocks.is_empty() {
            let mut entry = EntryPoint::new(dispatcher_block);
            if let Some(dispatcher_var) = state_var.and_then(|sv| sv.dispatcher_var) {
                if let Some(initial) = self.initial_state_from_state_phi(dispatcher_var) {
                    entry.initial_state = Some(initial);
                }
            }
            entries.push(entry);
            return entries;
        }

        // Analyze each potential entry block
        for &entry_block in &entry_blocks {
            let mut entry = EntryPoint::new(entry_block);

            // Try to extract initial state from the entry block
            if let Some(initial) =
                self.extract_initial_state(entry_block, dispatcher_block, state_var)
            {
                entry.initial_state = Some(initial);
            }

            // If there are multiple entry blocks, check for conditions
            if entry_blocks.len() > 1 {
                if let Some(condition) = self.extract_entry_condition(entry_block, &entry_blocks) {
                    entry.condition = Some(condition);
                }
            }

            // Track state variable if known
            if let Some(sv) = state_var {
                if let Some(ssa_var) = sv.var.as_ssa_var() {
                    entry.state_var = Some(ssa_var);
                }
            }

            entries.push(entry);
        }

        entries
    }

    /// Extracts the initial state value from an entry block.
    ///
    /// Uses three strategies:
    /// 1. Direct: looks for Const/Copy to the state variable in the entry block
    /// 2. PHI operand trace: `block_idx` is a direct predecessor of the dispatcher,
    ///    so we find the dispatcher PHI operand from that predecessor and trace its
    ///    SSA definition chain back to a constant
    /// 3. Evaluator path: walks from block 0 to the dispatcher evaluating each block,
    ///    then reads the PHI result from the evaluator
    fn extract_initial_state(
        &self,
        block_idx: usize,
        dispatcher_block: usize,
        state_var: Option<&StateVariable>,
    ) -> Option<i64> {
        let block = self.ssa.block(block_idx)?;

        // Strategy 1: Look for a constant assignment to the state variable
        if let Some(sv) = state_var {
            if let Some(ssa_var) = sv.var.as_ssa_var() {
                for instr in block.instructions() {
                    match instr.op() {
                        SsaOp::Const { dest, value } if *dest == ssa_var => {
                            return value.as_i64();
                        }
                        SsaOp::Copy { dest, src } if *dest == ssa_var => {
                            if let Some(SsaOp::Const { value, .. }) = self.ssa.get_definition(*src)
                            {
                                return value.as_i64();
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Some(dispatcher_var) = sv.dispatcher_var {
                // Strategy 2: Direct PHI operand trace.
                // block_idx is a non-case predecessor of the dispatcher, so the
                // dispatcher PHI has an operand with predecessor == block_idx.
                // Trace that operand's SSA variable backward to a constant.
                if let Some(disp_block) = self.ssa.block(dispatcher_block) {
                    for phi in disp_block.phi_nodes() {
                        if phi.result() == dispatcher_var {
                            if let Some(op) = phi
                                .operands()
                                .iter()
                                .find(|op| op.predecessor() == block_idx)
                            {
                                if let Some(val) = self.trace_to_constant(op.value(), 20) {
                                    return Some(val);
                                }
                            }
                        }
                    }
                }

                // Strategy 3: Evaluate the entry-to-dispatcher path.
                if let Some(val) =
                    self.evaluate_entry_to_dispatcher(dispatcher_block, dispatcher_var)
                {
                    return Some(val);
                }
            }
        }

        None
    }

    /// Recovers the initial state from the dispatcher's state phi when the
    /// region has no distinct entry block.
    ///
    /// In nested CFF (e.g. ConfuserEx handler dispatchers), the setup block
    /// that assigns the initial state is itself one of the dispatcher's switch
    /// case targets, so it is filtered out as a "case block" and there is no
    /// separate entry to read the initial value from. The state phi at the
    /// dispatcher still distinguishes the two roles: back-edge operands trace
    /// to computed state updates (`mul`/`xor`/…), while the setup operand
    /// traces to a constant. Return that constant.
    fn initial_state_from_state_phi(&self, dispatcher_var: SsaVarId) -> Option<i64> {
        for block in self.ssa.blocks() {
            for phi in block.phi_nodes() {
                if phi.result() == dispatcher_var {
                    for op in phi.operands() {
                        if let Some(val) = self.trace_to_constant(op.value(), 20) {
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }

    /// Traces a variable backward through SSA definitions to find a constant value.
    ///
    /// Handles Const, Copy, and PHI definitions. For PHI nodes, tries each
    /// operand and returns the first constant found (handles the case where
    /// opaque predicate branches merge at the entry block, creating PHIs with
    /// one real operand and one dead/undefined operand).
    fn trace_to_constant(&self, var: SsaVarId, max_depth: usize) -> Option<i64> {
        // Iterative DFS with explicit worklist - a recursive version with no
        // visited set made NR's 667-case dispatcher hang by exploring O(N^depth)
        // paths. Here every SSA var is visited at most once, and the stack depth
        // is bounded by the worklist size, not by program call depth.
        let mut stack: Vec<(SsaVarId, usize)> = Vec::new();
        let mut visited: HashSet<SsaVarId> = HashSet::new();
        stack.push((var, max_depth));

        while let Some((v, depth)) = stack.pop() {
            if depth == 0 || !visited.insert(v) {
                continue;
            }

            // Instruction definition (Const / Copy)
            if let Some(def) = self.ssa.get_definition(v) {
                match def {
                    SsaOp::Const { value, .. } => {
                        if let Some(i) = value.as_i64() {
                            return Some(i);
                        }
                    }
                    SsaOp::Copy { src, .. } => {
                        stack.push((*src, depth.saturating_sub(1)));
                    }
                    _ => {}
                }
                continue;
            }

            // PHI definition: scan the block's phi nodes for one producing `v`
            let Some(variable) = self.ssa.variable(v) else {
                continue;
            };
            let def_site = variable.def_site();
            if def_site.instruction.is_some() {
                continue; // instruction-defined but not found - stale
            }
            let Some(block) = self.ssa.block(def_site.block) else {
                continue;
            };
            for phi in block.phi_nodes() {
                if phi.result() == v {
                    // Push operands in reverse so pops happen in original order
                    // - matches the recursive "return first constant" semantics.
                    for op in phi.operands().iter().rev() {
                        stack.push((op.value(), depth.saturating_sub(1)));
                    }
                    break;
                }
            }
        }

        None
    }

    /// Evaluates the path from block 0 to the dispatcher using `SsaEvaluator`.
    ///
    /// When the evaluator can't resolve a branch (opaque predicates with unknown
    /// field values), tries each successor block. This handles the NETReactor
    /// pattern where `ldsfld; ldfld; brfalse` creates an unresolvable branch
    /// between the initial state assignment and the dispatcher.
    fn evaluate_entry_to_dispatcher(
        &self,
        dispatcher_block: usize,
        dispatcher_var: SsaVarId,
    ) -> Option<i64> {
        let mut evaluator = SsaEvaluator::new(self.ssa, self.config.machine);
        let mut current = 0usize;
        let mut visited = BitSet::new(self.ssa.block_count());

        for _ in 0..30 {
            if visited.contains(current) {
                break;
            }
            visited.insert(current);

            evaluator.evaluate_block(current);

            if current == dispatcher_block {
                return evaluator
                    .get_concrete(dispatcher_var)
                    .and_then(|v| v.as_i64());
            }

            match evaluator.next_block(current) {
                ControlFlow::Continue(next) if !visited.contains(next) => {
                    evaluator.set_predecessor(Some(current));
                    current = next;
                }
                _ => {
                    // Can't resolve terminator or target already visited.
                    // Try each successor to find one leading to the dispatcher.
                    let Some(block) = self.ssa.block(current) else {
                        break;
                    };
                    let succs = block.successors();
                    if let Some(&next) = succs.iter().find(|&&s| !visited.contains(s)) {
                        evaluator.set_predecessor(Some(current));
                        current = next;
                    } else {
                        break;
                    }
                }
            }
        }

        None
    }

    /// Extracts the condition for reaching an entry block.
    fn extract_entry_condition(
        &self,
        entry_block: usize,
        _all_entries: &[usize],
    ) -> Option<EntryCondition> {
        // Look for blocks that branch to this entry
        let preds = self.cfg.block_predecessors(entry_block);

        for &pred in preds {
            let Some(pred_block) = self.ssa.block(pred) else {
                continue;
            };

            // Check for conditional branch to this entry
            for instr in pred_block.instructions() {
                if let SsaOp::Branch {
                    condition,
                    true_target,
                    false_target,
                } = instr.op()
                {
                    // This block branches - check if it's branching to our entry
                    let is_true_branch = *true_target == entry_block;
                    let is_false_branch = *false_target == entry_block;

                    if is_true_branch || is_false_branch {
                        // Found a conditional entry
                        // Try to get more info about the condition - check for equality comparison
                        if let Some(SsaOp::Ceq { left, right, .. }) =
                            self.ssa.get_definition(*condition)
                        {
                            // Check if comparing with a constant
                            if let Some(SsaOp::Const { value, .. }) =
                                self.ssa.get_definition(*right)
                            {
                                if let Some(val) = value.as_i64() {
                                    return Some(EntryCondition::Compare {
                                        var: *left,
                                        value: val,
                                        // Ceq produces 1 when equal, so:
                                        // if branch taken on true, is_equal matches the Ceq
                                        is_equal: is_true_branch,
                                    });
                                }
                            }
                        }

                        // Fallback: just note it's a boolean condition
                        return Some(EntryCondition::Boolean {
                            var: *condition,
                            when_true: is_true_branch,
                        });
                    }
                }
            }
        }

        None
    }

    /// Computes confidence score for a detected CFF pattern.
    ///
    /// The confidence score combines multiple signals:
    /// - Case block count (more = stronger signal)
    /// - State variable presence with phi node
    /// - Back-edge ratio (case blocks returning to dispatcher, transitively)
    /// - Dominance relationship (dispatcher dominates case blocks)
    /// - Switch instruction presence
    /// - State transform (modulo operation is a strong indicator)
    /// - Method coverage (fraction of all blocks dominated by dispatcher)
    fn compute_confidence(
        &self,
        dispatcher_block: usize,
        dispatcher: &DispatcherInfo,
        state_var: Option<&StateVariable>,
        case_blocks: &BitSet,
        exit_blocks: &BitSet,
        dom_tree: &DominatorTree,
    ) -> f64 {
        let ssa = self.ssa;

        let mut score = 0.0;
        let case_count = case_blocks.count();
        let w = &self.config.confidence_weights;

        // Signal 1: Number of case blocks (more = more likely CFF)
        if case_count >= 3 {
            score += w.case_count_base;
        }
        if case_count >= 5 {
            score += w.case_count_bonus;
        }
        if case_count >= 10 {
            score += w.case_count_bonus;
        }

        // Signal 2: Has state variable with phi node
        if let Some(sv) = state_var {
            if sv.dispatcher_var.is_some() {
                score += w.state_variable;
            }
            if sv.def_count() >= case_count.saturating_sub(1) {
                // State updated in most case blocks
                score += w.state_update_coverage;
            }
        }

        // Signal 3: Dispatcher has many predecessors (back edges)
        let pred_count = self.cfg.block_predecessors(dispatcher_block).len();
        if pred_count >= case_count / 2 {
            score += w.predecessor_ratio;
        }

        // Signal 4: Case blocks mostly reach back to dispatcher (transitively)
        //
        // PureLogs and similar obfuscators wrap case blocks in try/catch regions,
        // so case blocks reach the dispatcher through intermediate blocks (Leave
        // targets, merge blocks) rather than jumping directly. We use bounded BFS
        // within the dispatcher's dominated region to count transitive back-edges.
        let dispatcher_node = NodeId::new(dispatcher_block);
        let back_edge_count = case_blocks
            .iter()
            .filter(|&b| {
                can_reach_dispatcher(
                    &self.cfg,
                    b,
                    dispatcher_block,
                    dispatcher_node,
                    dom_tree,
                    self.config.max_backedge_depth,
                )
            })
            .count();
        // Safe: counts are small integers, precision loss is negligible for scoring
        #[allow(clippy::cast_precision_loss)]
        let back_edge_ratio = back_edge_count as f64 / case_count.max(1) as f64;
        score += back_edge_ratio * w.back_edge_ratio;

        // Signal 5: Has exit blocks (function eventually returns)
        if !exit_blocks.is_empty() {
            score += w.exit_blocks;
        }

        // Signal 6: Uses switch instruction (typical for CFF)
        if matches!(dispatcher, DispatcherInfo::Switch { .. }) {
            score += w.switch_bonus;
        }

        // Signal 7: Has state transform (modulo is very strong indicator)
        let transform = dispatcher.transform();
        if transform.modulo_divisor().is_some() {
            score += w.modulo_bonus;
        }

        // Signal 8: Dominance - dispatcher should dominate most case blocks
        let dominated_count = case_blocks
            .iter()
            .filter(|&case_block| {
                case_block == dispatcher_block
                    || dom_tree.dominates(dispatcher_node, NodeId::new(case_block))
            })
            .count();
        #[allow(clippy::cast_precision_loss)]
        let dominance_ratio = dominated_count as f64 / case_blocks.count().max(1) as f64;
        score += dominance_ratio * w.dominance_ratio;

        // Signal 9: Method coverage - fraction of ALL blocks dominated by this candidate.
        // A real CFF dispatcher dominates most of the function (it controls nearly all
        // execution paths). A nested loop only dominates a small subset.
        let total_blocks = ssa.block_count();
        if total_blocks > 0 {
            let dominated_total = (0..total_blocks)
                .filter(|&b| {
                    b == dispatcher_block || dom_tree.dominates(dispatcher_node, NodeId::new(b))
                })
                .count();
            #[allow(clippy::cast_precision_loss)]
            let coverage = dominated_total as f64 / total_blocks as f64;
            score += coverage * w.method_coverage;
        }

        score.min(1.0)
    }
}

/// Checks if a block can transitively reach the dispatcher via blocks
/// dominated by the dispatcher.
///
/// PureLogs and similar obfuscators wrap CFF case blocks in try/catch
/// regions, so case blocks don't jump directly back to the dispatcher.
/// Instead they go through intermediate blocks (`Leave` targets, merge
/// blocks) before eventually reaching the dispatcher. This function does
/// bounded BFS to detect these transitive paths.
fn can_reach_dispatcher(
    cfg: &SsaCfg,
    from: usize,
    dispatcher_block: usize,
    dispatcher_node: NodeId,
    dom_tree: &DominatorTree,
    max_depth: usize,
) -> bool {
    // Direct check first (fast path)
    if cfg.block_successors(from).contains(&dispatcher_block) {
        return true;
    }

    let mut queue = VecDeque::new();
    let mut visited = BitSet::new(cfg.block_count());

    for &succ in cfg.block_successors(from) {
        if succ != from {
            queue.push_back((succ, 1));
        }
    }
    visited.insert(from);

    while let Some((block, depth)) = queue.pop_front() {
        if block == dispatcher_block {
            return true;
        }
        if depth >= max_depth || !visited.insert(block) {
            continue;
        }
        // Only follow blocks dominated by the dispatcher (stay within the CFF region)
        if !dom_tree.dominates(dispatcher_node, NodeId::new(block)) {
            continue;
        }
        for &succ in cfg.block_successors(block) {
            if !visited.contains(succ) {
                queue.push_back((succ, depth.saturating_add(1)));
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use analyssa::BitSet;

    use super::{CffPattern, EntryCondition, EntryPoint};
    use crate::{
        analysis::SsaVarId,
        deobfuscation::passes::unflattening::dispatcher::{DispatcherInfo, StateTransform},
    };

    #[test]
    fn test_cff_pattern_case_count() {
        // Basic pattern structure test
        let pattern = CffPattern {
            dispatcher_block: 0,
            dispatcher: DispatcherInfo::Switch {
                block: 0,
                switch_var: SsaVarId::from_index(0),
                cases: vec![1, 2, 3, 4, 5],
                default: 6,
                transform: StateTransform::Modulo(5),
            },
            state_var: None,
            case_blocks: {
                let mut cb = BitSet::new(7);
                for i in [1, 2, 3, 4, 5, 6] {
                    cb.insert(i);
                }
                cb
            },
            entry_block: None,
            entry_points: vec![EntryPoint::with_state(0, 42)],
            exit_blocks: BitSet::new(7),
            confidence: 0.8,
        };

        assert_eq!(pattern.case_count(), 5);
        assert!(pattern.is_confuserex_style());
        assert_eq!(pattern.entry_count(), 1);
        assert!(!pattern.has_multiple_entries());
    }

    #[test]
    fn test_entry_point() {
        let entry = EntryPoint::new(0);
        assert!(entry.is_unconditional());
        assert!(!entry.has_known_state());

        let entry_with_state = EntryPoint::with_state(1, 100);
        assert!(entry_with_state.has_known_state());
        assert_eq!(entry_with_state.initial_state, Some(100));

        let var = SsaVarId::from_index(0);
        let entry_with_condition = EntryPoint::new(2).with_condition(EntryCondition::Boolean {
            var,
            when_true: true,
        });
        assert!(!entry_with_condition.is_unconditional());
    }

    #[test]
    fn test_cff_pattern_multiple_entries() {
        let pattern = CffPattern {
            dispatcher_block: 1,
            dispatcher: DispatcherInfo::Switch {
                block: 1,
                switch_var: SsaVarId::from_index(0),
                cases: vec![2, 3],
                default: 4,
                transform: StateTransform::Identity,
            },
            state_var: None,
            case_blocks: {
                let mut cb = BitSet::new(7);
                for i in [2, 3, 4] {
                    cb.insert(i);
                }
                cb
            },
            entry_block: None,
            entry_points: vec![EntryPoint::with_state(0, 10), EntryPoint::with_state(5, 20)],
            exit_blocks: {
                let mut eb = BitSet::new(7);
                eb.insert(6);
                eb
            },
            confidence: 0.7,
        };

        assert!(pattern.has_multiple_entries());
        assert_eq!(pattern.entry_count(), 2);
        assert_eq!(pattern.initial_states(), vec![10, 20]);

        let primary = pattern.primary_entry().unwrap();
        assert_eq!(primary.block, 0);
        assert_eq!(primary.initial_state, Some(10));
    }
}

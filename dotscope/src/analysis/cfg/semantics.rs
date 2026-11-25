//! Block and loop semantic analysis.
//!
//! This module provides semantic classification of basic blocks and loop structures,
//! identifying the functional role of each block (initialization, condition checking,
//! loop body with side effects, increment/latch, etc.).
//!
//! # Purpose
//!
//! While structural loop analysis (dominators, back-edges) tells us WHAT blocks form
//! a loop, semantic analysis tells us WHAT EACH BLOCK DOES within that loop:
//!
//! - **Init blocks**: Initialize loop variables (e.g., `i = 0`)
//! - **Condition blocks**: Test loop termination (e.g., `i < n`)
//! - **Body blocks**: Perform actual work with side effects
//! - **Latch blocks**: Update induction variables (e.g., `i++`)
//!
//! # Use Cases
//!
//! - **Deobfuscation**: Recovering original loop structure from flattened code
//! - **Optimization**: Identifying loop-invariant code, vectorization opportunities
//! - **Code comprehension**: Understanding program structure
//!
//! # Example
//!
//! ```text
//! Original code:          Flattened code:
//!
//! for (i = 0; i < 5; i++)     switch(state) {
//!     print(i);                   case 0: i = 0; state = 1; break;
//!                                 case 1: if (i < 5) state = 2; else state = 3; break;
//!                                 case 2: print(i); state = 4; break;
//!                                 case 4: i++; state = 1; break;
//!                                 case 3: return;
//!                             }
//!
//! Semantic analysis identifies:
//!   case 0 -> Init (assigns constant to i)
//!   case 1 -> Condition (Branch based on comparison)
//!   case 2 -> Body (has Call side effect)
//!   case 4 -> Latch (has Add on induction var)
//!   case 3 -> Exit (has Return)
//! ```

use std::collections::HashMap;

use analyssa::BitSet;

use crate::analysis::{
    cfg::InductionVar, CilTarget, LoopInfo, SsaFunction, SsaOp, SsaVarId, Target,
};

/// Semantic role of a basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockRole {
    /// Entry point to the function.
    Entry,
    /// Initializes variables (typically before a loop).
    Init,
    /// Tests a condition (contains Branch instruction).
    Condition,
    /// Loop body with side effects (calls, stores, etc.).
    Body,
    /// Updates induction variables (increment/decrement).
    Latch,
    /// Exits the loop or function.
    Exit,
    /// State-machine dispatcher (switch-based control).
    Dispatcher,
    /// State update block (sets next state value).
    StateUpdate,
    /// Role could not be determined.
    Unknown,
}

impl BlockRole {
    /// Returns true if this is a control flow role (not actual computation).
    #[must_use]
    pub fn is_control_flow(&self) -> bool {
        matches!(self, Self::Dispatcher | Self::StateUpdate)
    }

    /// Returns true if this role typically contains user code.
    #[must_use]
    pub fn is_user_code(&self) -> bool {
        matches!(self, Self::Init | Self::Body | Self::Latch | Self::Exit)
    }
}

/// Detailed semantic information about a single block.
#[derive(Debug, Clone)]
pub struct BlockSemantics {
    /// Block index.
    pub block: usize,
    /// Primary semantic role.
    pub role: BlockRole,
    /// Secondary roles (a block can serve multiple purposes).
    pub secondary_roles: Vec<BlockRole>,
    /// Variables initialized in this block (assigned from constants).
    pub initialized_vars: Vec<SsaVarId>,
    /// Variables updated in this block (modified from previous values).
    pub updated_vars: Vec<SsaVarId>,
    /// Whether the block has observable side effects (calls, stores).
    pub has_side_effects: bool,
    /// Whether the block contains a comparison used for branching.
    pub has_comparison: bool,
    /// Confidence score for the role classification (0.0 - 1.0).
    pub confidence: f64,
}

impl BlockSemantics {
    /// Creates a new `BlockSemantics` with unknown role.
    #[must_use]
    pub fn new(block: usize) -> Self {
        Self {
            block,
            role: BlockRole::Unknown,
            secondary_roles: Vec::new(),
            initialized_vars: Vec::new(),
            updated_vars: Vec::new(),
            has_side_effects: false,
            has_comparison: false,
            confidence: 0.0,
        }
    }

    /// Returns true if the block has any of the given roles.
    #[must_use]
    pub fn has_role(&self, role: BlockRole) -> bool {
        self.role == role || self.secondary_roles.contains(&role)
    }
}

/// Semantic structure of a loop.
///
/// This captures the semantic roles of blocks within a loop, enabling
/// correct restructuring of control flow.
#[derive(Debug, Clone)]
pub struct LoopSemantics {
    /// Blocks that initialize loop variables (before the condition).
    pub init_blocks: Vec<usize>,
    /// The block(s) that test the loop condition.
    pub condition_blocks: Vec<usize>,
    /// Blocks that form the loop body (side effects, computation).
    pub body_blocks: Vec<usize>,
    /// Blocks that update induction variables.
    pub latch_blocks: Vec<usize>,
    /// Blocks that exit the loop.
    pub exit_blocks: Vec<usize>,
    /// Induction variables identified in this loop.
    pub induction_vars: Vec<InductionVar>,
    /// Execution order of blocks within the loop.
    pub execution_order: Vec<usize>,
    /// Confidence in the overall analysis.
    pub confidence: f64,
}

impl Default for LoopSemantics {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopSemantics {
    /// Creates an empty `LoopSemantics`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            init_blocks: Vec::new(),
            condition_blocks: Vec::new(),
            body_blocks: Vec::new(),
            latch_blocks: Vec::new(),
            exit_blocks: Vec::new(),
            induction_vars: Vec::new(),
            execution_order: Vec::new(),
            confidence: 0.0,
        }
    }

    /// Returns all blocks in semantic execution order.
    ///
    /// Order: init -> condition -> body -> latch
    #[must_use]
    pub fn ordered_blocks(&self) -> Vec<usize> {
        [
            self.init_blocks.as_slice(),
            self.condition_blocks.as_slice(),
            self.body_blocks.as_slice(),
            self.latch_blocks.as_slice(),
        ]
        .concat()
    }

    /// Returns true if the analysis produced a valid loop structure.
    ///
    /// A valid loop needs at least a condition and either body or latch.
    /// Note: This includes branching structures (if/else) which have
    /// conditions and bodies but no latch - this is intentional as
    /// they need similar handling in the restructuring phase.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // A valid loop needs at least a condition and either body or latch
        !self.condition_blocks.is_empty()
            && (!self.body_blocks.is_empty() || !self.latch_blocks.is_empty())
    }

    /// Returns true if this represents a branching structure (if/else) rather than a loop.
    ///
    /// Branching structures have conditions and bodies but no latch blocks
    /// or induction variables (no loop back-edge).
    #[must_use]
    pub fn is_branching(&self) -> bool {
        !self.condition_blocks.is_empty()
            && !self.body_blocks.is_empty()
            && self.latch_blocks.is_empty()
            && self.induction_vars.is_empty()
    }
}

/// Analyzes semantic roles of blocks in an SSA function.
pub struct SemanticAnalyzer<'a, T: Target = CilTarget> {
    ssa: &'a SsaFunction<T>,
    /// Cache of block semantics.
    block_cache: HashMap<usize, BlockSemantics>,
    /// Known dispatcher blocks.
    dispatcher_blocks: BitSet,
}

impl<'a, T: Target> SemanticAnalyzer<'a, T> {
    /// Creates a new semantic analyzer for the given SSA function.
    #[must_use]
    pub fn new(ssa: &'a SsaFunction<T>) -> Self {
        Self {
            ssa,
            block_cache: HashMap::new(),
            dispatcher_blocks: BitSet::new(ssa.block_count().max(1)),
        }
    }

    /// Marks a block as a known dispatcher.
    pub fn mark_dispatcher(&mut self, block: usize) {
        if block < self.dispatcher_blocks.len() {
            self.dispatcher_blocks.insert(block);
        }
    }

    /// Analyzes a single block and returns its semantic information.
    pub fn analyze_block(&mut self, block_idx: usize) -> &BlockSemantics {
        if !self.block_cache.contains_key(&block_idx) {
            let semantics = self.compute_block_semantics(block_idx);
            self.block_cache.insert(block_idx, semantics);
        }
        // Just inserted above if missing; fall back to inserting a default if for any
        // reason the entry is gone (cannot happen with current logic, but avoids panics).
        self.block_cache
            .entry(block_idx)
            .or_insert_with(|| BlockSemantics::new(block_idx))
    }

    /// Computes semantic information for a block.
    fn compute_block_semantics(&self, block_idx: usize) -> BlockSemantics {
        let mut semantics = BlockSemantics::new(block_idx);

        let Some(block) = self.ssa.block(block_idx) else {
            return semantics;
        };

        // Check if it's a known dispatcher
        if block_idx < self.dispatcher_blocks.len() && self.dispatcher_blocks.contains(block_idx) {
            semantics.role = BlockRole::Dispatcher;
            semantics.confidence = 1.0;
            return semantics;
        }

        // Analyze instructions
        let mut const_assignments: usize = 0;
        let mut add_sub_ops: usize = 0;
        let mut call_count: usize = 0;
        let mut store_count: usize = 0;
        let mut comparison_count: usize = 0;
        let mut has_return = false;
        let mut has_branch = false;
        let mut has_switch = false;

        for instr in block.instructions() {
            match instr.op() {
                SsaOp::Const { dest, .. } => {
                    const_assignments = const_assignments.saturating_add(1);
                    semantics.initialized_vars.push(*dest);
                }
                SsaOp::Add { dest, .. } | SsaOp::Sub { dest, .. } => {
                    add_sub_ops = add_sub_ops.saturating_add(1);
                    semantics.updated_vars.push(*dest);
                }
                SsaOp::Call(_) | SsaOp::NewObj { .. } => {
                    call_count = call_count.saturating_add(1);
                    semantics.has_side_effects = true;
                }
                SsaOp::StoreField { .. }
                | SsaOp::StoreStaticField { .. }
                | SsaOp::StoreElement { .. }
                | SsaOp::StoreIndirect { .. } => {
                    store_count = store_count.saturating_add(1);
                    semantics.has_side_effects = true;
                }
                SsaOp::Clt { .. } | SsaOp::Cgt { .. } | SsaOp::Ceq { .. } => {
                    comparison_count = comparison_count.saturating_add(1);
                    semantics.has_comparison = true;
                }
                SsaOp::Branch { .. } => {
                    has_branch = true;
                }
                SsaOp::Switch { .. } => {
                    has_switch = true;
                }
                SsaOp::Return { .. } | SsaOp::Throw { .. } | SsaOp::Rethrow => {
                    has_return = true;
                }
                _ => {}
            }
        }

        // Classify based on patterns
        let total_instrs = block.instructions().len();

        // Entry block
        if block_idx == 0 {
            semantics.secondary_roles.push(BlockRole::Entry);
        }

        // Exit block (has return/throw)
        if has_return {
            semantics.role = BlockRole::Exit;
            semantics.confidence = 0.95;
            return semantics;
        }

        // Dispatcher (switch with many targets that loop back)
        if has_switch {
            if let Some(SsaOp::Switch { targets, .. }) = block.control_terminator() {
                if targets.len() >= 4 {
                    semantics.role = BlockRole::Dispatcher;
                    semantics.confidence = 0.8;
                    return semantics;
                }
            }
        }

        // Condition block (comparison + branch)
        if has_branch && (comparison_count > 0 || semantics.has_comparison) {
            semantics.role = BlockRole::Condition;
            semantics.confidence = 0.85;
            return semantics;
        }

        // Pure condition block (just branch, comparison might be in predecessor)
        if has_branch && total_instrs <= 2 {
            semantics.role = BlockRole::Condition;
            semantics.confidence = 0.7;
            return semantics;
        }

        // Init block (mostly const assignments, no side effects)
        if const_assignments > 0 && call_count == 0 && store_count == 0 && add_sub_ops == 0 {
            semantics.role = BlockRole::Init;
            semantics.confidence = 0.75;
            return semantics;
        }

        // Latch block (has add/sub, typically on induction variable)
        if add_sub_ops > 0 && call_count == 0 {
            // Check if it's incrementing by a small constant (typical latch pattern)
            let is_likely_latch = self.check_increment_pattern(block_idx);
            if is_likely_latch {
                semantics.role = BlockRole::Latch;
                semantics.confidence = 0.8;
                return semantics;
            }
        }

        // Body block (has side effects)
        if semantics.has_side_effects {
            semantics.role = BlockRole::Body;
            semantics.confidence = 0.7;
            return semantics;
        }

        // State update block (XOR with large constant, typical of obfuscation)
        if self.check_state_update_pattern(block_idx) {
            semantics.role = BlockRole::StateUpdate;
            semantics.confidence = 0.75;
            return semantics;
        }

        // Default: unknown
        semantics.role = BlockRole::Unknown;
        semantics.confidence = 0.3;
        semantics
    }

    /// Checks if a block contains a typical increment pattern (i = i + 1).
    fn check_increment_pattern(&self, block_idx: usize) -> bool {
        let Some(block) = self.ssa.block(block_idx) else {
            return false;
        };

        for instr in block.instructions() {
            if let SsaOp::Add { left, right, .. } = instr.op() {
                // Check if one operand is a small constant
                if self.is_small_constant(*left) || self.is_small_constant(*right) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a block contains state update pattern (XOR with large constant).
    fn check_state_update_pattern(&self, block_idx: usize) -> bool {
        let Some(block) = self.ssa.block(block_idx) else {
            return false;
        };

        for instr in block.instructions() {
            if let SsaOp::Xor { left, right, .. } = instr.op() {
                // Check if one operand is a large constant (typical of state encoding)
                if self.is_large_constant(*left) || self.is_large_constant(*right) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a variable is defined as a small constant (< 1000).
    fn is_small_constant(&self, var: SsaVarId) -> bool {
        if let Some(val) = self.get_constant_value(var) {
            val.abs() < 1000
        } else {
            false
        }
    }

    /// Checks if a variable is defined as a large constant (> 10000).
    fn is_large_constant(&self, var: SsaVarId) -> bool {
        if let Some(val) = self.get_constant_value(var) {
            val.abs() > 10000
        } else {
            false
        }
    }

    /// Gets the constant value of a variable if it's defined by a Const instruction.
    fn get_constant_value(&self, var: SsaVarId) -> Option<i64> {
        self.ssa.try_constant_value(var).and_then(|v| v.as_i64())
    }

    /// Analyzes semantic structure of a loop.
    ///
    /// Given structural loop information, this method classifies each block
    /// within the loop by its semantic role.
    pub fn analyze_loop(&mut self, loop_info: &LoopInfo) -> LoopSemantics {
        let mut semantics = LoopSemantics::new();

        // Find induction variables
        semantics.induction_vars = loop_info.find_induction_vars(self.ssa);

        // Collect induction variable update blocks
        let block_count = self.ssa.block_count().max(1);
        let mut iv_update_blocks = BitSet::new(block_count);
        for iv in &semantics.induction_vars {
            let idx = iv.update_block.index();
            if idx < block_count {
                iv_update_blocks.insert(idx);
            }
        }

        // Classify each block in the loop
        for block_idx in loop_info.body.iter() {
            let block_sem = self.analyze_block(block_idx);

            match block_sem.role {
                BlockRole::Init => {
                    semantics.init_blocks.push(block_idx);
                }
                BlockRole::Condition => {
                    semantics.condition_blocks.push(block_idx);
                }
                BlockRole::Body => {
                    semantics.body_blocks.push(block_idx);
                }
                BlockRole::Latch => {
                    semantics.latch_blocks.push(block_idx);
                }
                BlockRole::Exit => {
                    semantics.exit_blocks.push(block_idx);
                }
                BlockRole::Dispatcher | BlockRole::StateUpdate => {
                    // Skip control flow artifacts
                }
                BlockRole::Entry | BlockRole::Unknown => {
                    // Classify based on induction variable updates
                    if block_idx < block_count && iv_update_blocks.contains(block_idx) {
                        semantics.latch_blocks.push(block_idx);
                    } else if block_sem.has_side_effects {
                        semantics.body_blocks.push(block_idx);
                    }
                }
            }
        }

        // Look for init blocks in the preheader
        if let Some(preheader) = loop_info.preheader {
            let pre_sem = self.analyze_block(preheader.index());
            if pre_sem.role == BlockRole::Init || !pre_sem.initialized_vars.is_empty() {
                semantics.init_blocks.push(preheader.index());
            }
        }

        // If we didn't find a condition but the header has a branch, use it
        if semantics.condition_blocks.is_empty() {
            let header_sem = self.analyze_block(loop_info.header.index());
            if header_sem.has_role(BlockRole::Condition) {
                semantics.condition_blocks.push(loop_info.header.index());
            }
        }

        // Add exit blocks from loop info
        for exit in &loop_info.exits {
            if !semantics.exit_blocks.contains(&exit.exit_block.index()) {
                semantics.exit_blocks.push(exit.exit_block.index());
            }
        }

        // Compute execution order
        semantics.execution_order = self.compute_loop_execution_order(loop_info, &semantics);

        // Compute confidence
        semantics.confidence = Self::compute_loop_confidence(&semantics);

        semantics
    }

    /// Computes the execution order of blocks within a loop.
    fn compute_loop_execution_order(
        &self,
        loop_info: &LoopInfo,
        semantics: &LoopSemantics,
    ) -> Vec<usize> {
        let mut order = Vec::new();
        let block_count = self.ssa.block_count().max(1);
        let mut seen = BitSet::new(block_count);

        // 1. Init blocks first (in order found)
        for &init in &semantics.init_blocks {
            if init < block_count && !seen.contains(init) {
                seen.insert(init);
                order.push(init);
            }
        }

        // 2. Condition blocks
        for &cond in &semantics.condition_blocks {
            if cond < block_count && !seen.contains(cond) {
                seen.insert(cond);
                order.push(cond);
            }
        }

        // 3. Body blocks (order by trying to follow control flow)
        let body_order = self.order_body_blocks(loop_info, &semantics.body_blocks);
        for body in body_order {
            if body < block_count && !seen.contains(body) {
                seen.insert(body);
                order.push(body);
            }
        }

        // 4. Latch blocks last
        for &latch in &semantics.latch_blocks {
            if latch < block_count && !seen.contains(latch) {
                seen.insert(latch);
                order.push(latch);
            }
        }

        order
    }

    /// Orders body blocks by following control flow.
    fn order_body_blocks(&self, loop_info: &LoopInfo, body_blocks: &[usize]) -> Vec<usize> {
        if body_blocks.is_empty() {
            return Vec::new();
        }

        let block_count = self.ssa.block_count().max(1);
        let mut body_set = BitSet::new(block_count);
        for &b in body_blocks {
            if b < block_count {
                body_set.insert(b);
            }
        }
        let mut ordered = Vec::new();
        let mut visited = BitSet::new(block_count);

        // Start from condition block's true target if it's a body block
        if let Some(cond) = loop_info.find_condition_in_body(self.ssa) {
            if let Some(block) = self.ssa.block(cond.index()) {
                if let Some(SsaOp::Branch { true_target, .. }) = block.control_terminator() {
                    if *true_target < block_count && body_set.contains(*true_target) {
                        self.dfs_order(*true_target, &body_set, &mut visited, &mut ordered);
                    }
                }
            }
        }

        // Add any remaining body blocks
        for &block in body_blocks {
            if block < block_count && !visited.contains(block) {
                self.dfs_order(block, &body_set, &mut visited, &mut ordered);
            }
        }

        ordered
    }

    /// DFS traversal to order blocks.
    fn dfs_order(
        &self,
        block: usize,
        allowed: &BitSet,
        visited: &mut BitSet,
        order: &mut Vec<usize>,
    ) {
        if block >= allowed.len() || !allowed.contains(block) || visited.contains(block) {
            return;
        }

        visited.insert(block);
        order.push(block);

        // Follow successors that are in the allowed set
        if let Some(b) = self.ssa.block(block) {
            if let Some(op) = b.control_terminator() {
                for succ in op.successors() {
                    self.dfs_order(succ, allowed, visited, order);
                }
            }
        }
    }

    /// Computes confidence score for loop semantics.
    fn compute_loop_confidence(semantics: &LoopSemantics) -> f64 {
        let mut score = 0.0;

        // Has condition: +0.3
        if !semantics.condition_blocks.is_empty() {
            score += 0.3;
        }

        // Has body: +0.2
        if !semantics.body_blocks.is_empty() {
            score += 0.2;
        }

        // Has latch: +0.2
        if !semantics.latch_blocks.is_empty() {
            score += 0.2;
        }

        // Has induction variable: +0.2
        if !semantics.induction_vars.is_empty() {
            score += 0.2;
        }

        // Has init: +0.1
        if !semantics.init_blocks.is_empty() {
            score += 0.1;
        }

        score
    }

    /// Analyzes a set of case blocks from a flattened dispatcher.
    ///
    /// This is specifically for deobfuscation: given the case targets from a
    /// switch-based dispatcher, classify each case block by its semantic role.
    pub fn analyze_dispatcher_cases(&mut self, case_blocks: &[usize]) -> HashMap<usize, BlockRole> {
        let mut roles = HashMap::new();

        for &block in case_blocks {
            let sem = self.analyze_block(block);
            roles.insert(block, sem.role);
        }

        roles
    }

    /// Recovers loop structure from flattened dispatcher cases.
    ///
    /// Given case blocks from a flattened switch dispatcher, attempts to
    /// reconstruct the original loop structure by analyzing semantic roles.
    pub fn recover_loop_from_cases(&mut self, case_blocks: &[usize]) -> LoopSemantics {
        let mut semantics = LoopSemantics::new();

        // Classify all case blocks
        let roles = self.analyze_dispatcher_cases(case_blocks);

        // Group by role
        for (&block, &role) in &roles {
            match role {
                BlockRole::Init => semantics.init_blocks.push(block),
                BlockRole::Condition => semantics.condition_blocks.push(block),
                BlockRole::Body => semantics.body_blocks.push(block),
                BlockRole::Latch => semantics.latch_blocks.push(block),
                BlockRole::Exit => semantics.exit_blocks.push(block),
                _ => {}
            }
        }

        // Order blocks by semantic role
        semantics.execution_order = semantics.ordered_blocks();

        // Compute confidence
        semantics.confidence = Self::compute_loop_confidence(&semantics);

        semantics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{SsaFunctionBuilder, SsaType};

    #[test]
    fn test_block_role_classification() {
        // Test that BlockRole methods work correctly
        assert!(BlockRole::Dispatcher.is_control_flow());
        assert!(BlockRole::StateUpdate.is_control_flow());
        assert!(!BlockRole::Body.is_control_flow());

        assert!(BlockRole::Init.is_user_code());
        assert!(BlockRole::Body.is_user_code());
        assert!(!BlockRole::Dispatcher.is_user_code());
    }

    #[test]
    fn test_exit_block_detection() {
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.ret();
                });
            })
            .unwrap();

        let mut analyzer = SemanticAnalyzer::new(&ssa);
        let sem = analyzer.analyze_block(0);

        assert_eq!(sem.role, BlockRole::Exit);
        assert!(sem.confidence > 0.9);
    }

    #[test]
    fn test_condition_block_detection() {
        let ssa = SsaFunctionBuilder::new(0, 1)
            .build_with(|f| {
                let local = f.local(0, SsaType::I32);
                f.block(0, |b| {
                    let zero = b.const_i32(0);
                    let cmp = b.clt(local, zero);
                    b.branch(cmp, 1, 2);
                });
                f.block(1, |b| b.ret());
                f.block(2, |b| b.ret());
            })
            .unwrap();

        let mut analyzer = SemanticAnalyzer::new(&ssa);
        let sem = analyzer.analyze_block(0);

        assert_eq!(sem.role, BlockRole::Condition);
        assert!(sem.has_comparison);
    }

    #[test]
    fn test_init_block_detection() {
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(0);
                    let _ = b.const_i32(1);
                    b.jump(1);
                });
                f.block(1, |b| b.ret());
            })
            .unwrap();

        let mut analyzer = SemanticAnalyzer::new(&ssa);
        let sem = analyzer.analyze_block(0);

        assert_eq!(sem.role, BlockRole::Init);
        assert_eq!(sem.initialized_vars.len(), 2);
    }

    #[test]
    fn test_loop_semantics_validity() {
        let mut sem = LoopSemantics::new();
        assert!(!sem.is_valid()); // Empty is not valid

        sem.condition_blocks.push(1);
        assert!(!sem.is_valid()); // Condition only is not valid

        sem.body_blocks.push(2);
        assert!(sem.is_valid()); // Condition + body is valid
        assert!(sem.is_branching()); // It's also a branching structure (no latch)

        // Add a latch block
        sem.latch_blocks.push(3);
        assert!(sem.is_valid()); // Still valid
        assert!(!sem.is_branching()); // No longer just branching (has latch)
    }
}

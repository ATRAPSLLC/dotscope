//! Control flow graph construction from x86 instructions.
//!
//! This module builds a CFG from decoded x86 instructions, identifying basic blocks
//! and their successor relationships. It leverages the existing graph infrastructure
//! from [`analyssa::graph`] for efficient analysis.

use std::{collections::BTreeSet, sync::OnceLock};

use analyssa::graph::{
    algorithms::{compute_dominators, DominatorTree},
    DirectedGraph, GraphBase, NodeId, Predecessors, RootedGraph, Successors,
};
use rustc_hash::FxHashMap;

use crate::analysis::{
    cfg::has_back_edges,
    x86::types::{X86DecodedInstruction, X86EdgeKind, X86Instruction},
};

/// A basic block in the x86 CFG.
#[derive(Debug, Clone)]
pub struct X86BasicBlock {
    /// Index of this block in the function
    pub index: usize,
    /// Offset where this block starts
    pub start_offset: u64,
    /// Offset where this block ends (exclusive, start of next instruction)
    pub end_offset: u64,
    /// Instructions in this block
    pub instructions: Vec<X86DecodedInstruction>,
}

impl X86BasicBlock {
    /// Returns the terminator instruction, if any.
    #[must_use]
    pub fn terminator(&self) -> Option<&X86Instruction> {
        self.instructions.last().map(|i| &i.instruction)
    }

    /// Returns true if this block ends with a return instruction.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Ret))
    }

    /// Returns true if this block ends with an unconditional jump.
    #[must_use]
    pub fn is_unconditional_jump(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Jmp { .. }))
    }

    /// Returns true if this block ends with a conditional jump.
    #[must_use]
    pub fn is_conditional_jump(&self) -> bool {
        matches!(self.terminator(), Some(X86Instruction::Jcc { .. }))
    }

    /// Returns true if this block has any unsupported instructions.
    #[must_use]
    pub fn has_unsupported(&self) -> bool {
        self.instructions
            .iter()
            .any(|i| matches!(i.instruction, X86Instruction::Unsupported { .. }))
    }
}

/// Decoded x86 function with control flow graph.
///
/// This structure wraps a `DirectedGraph` with x86-specific functionality,
/// providing lazy-computed analysis results (dominators, etc.).
#[derive(Debug)]
pub struct X86Function {
    /// Bitness (32 or 64)
    pub bitness: u32,
    /// Base address of the function
    pub base_address: u64,
    /// The underlying directed graph
    graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind>,
    /// Entry block node ID
    entry: NodeId,
    /// Exit block node IDs (blocks ending with ret)
    exits: Vec<NodeId>,
    /// Lazily computed dominator tree
    dominators: OnceLock<DominatorTree>,
}

impl X86Function {
    /// Build a CFG from decoded instructions, entered at the first of them.
    ///
    /// This identifies basic block boundaries based on:
    /// - Jump targets (start of block)
    /// - Instructions after jumps (start of block)
    /// - Jump/ret instructions (end of block)
    ///
    /// The resulting CFG uses a directed graph internally and provides
    /// lazy-computed analysis (dominators, etc.). A linear decode
    /// ([`x86_decode_all`](crate::analysis::x86_decode_all)) starts at the entry,
    /// so its first instruction is it; a traversal decode returns its instructions
    /// by address, and is built with [`Self::with_entry`].
    #[must_use]
    pub fn new(instructions: &[X86DecodedInstruction], bitness: u32, base_address: u64) -> Self {
        let entry = instructions.first().map_or(0, |instr| instr.offset);
        Self::with_entry(instructions, bitness, base_address, entry)
    }

    /// Build a CFG from decoded instructions, entered at `entry_offset`.
    ///
    /// The block starting at the entry is block 0, whatever its address: code
    /// before the entry that a jump reaches comes after it. The other blocks
    /// follow in address order.
    ///
    /// A jump target that starts no decoded instruction (the middle of one, or an
    /// offset outside the decoded range) starts no block, and the jump has no edge
    /// there. The instructions after it stay in the block they were decoded in.
    #[must_use]
    pub fn with_entry(
        instructions: &[X86DecodedInstruction],
        bitness: u32,
        base_address: u64,
        entry_offset: u64,
    ) -> Self {
        if instructions.is_empty() {
            let graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind> = DirectedGraph::new();
            return Self {
                bitness,
                base_address,
                graph,
                entry: NodeId::new(0),
                exits: vec![],
                dominators: OnceLock::new(),
            };
        }

        // Step 1: Identify block leaders (offsets that start a basic block)
        let mut leaders = BTreeSet::new();

        // The first instruction and the entry are always leaders
        if let Some(first) = instructions.first() {
            leaders.insert(first.offset);
        }
        leaders.insert(entry_offset);

        // Find jump targets and fallthrough points
        for (i, instr) in instructions.iter().enumerate() {
            let next_idx = i.saturating_add(1);
            let next_offset = instructions.get(next_idx).map(|x| x.offset);
            match &instr.instruction {
                X86Instruction::Jmp { target } => {
                    if let Some(rel) = target.checked_sub(base_address) {
                        leaders.insert(rel);
                    }
                }
                X86Instruction::Jcc { target, .. } => {
                    if let Some(rel) = target.checked_sub(base_address) {
                        leaders.insert(rel);
                    }
                    // Fallthrough is also a leader (instruction after this one)
                    if let Some(off) = next_offset {
                        leaders.insert(off);
                    }
                }
                // Instruction after call is a leader (call returns)
                X86Instruction::Call { .. } => {
                    if let Some(off) = next_offset {
                        leaders.insert(off);
                    }
                }
                // Instruction after ret is a leader (if any)
                X86Instruction::Ret => {
                    if let Some(off) = next_offset {
                        leaders.insert(off);
                    }
                }
                _ => {}
            }
        }

        // Step 2: Build offset -> instruction index map
        let offset_to_index: FxHashMap<u64, usize> = instructions
            .iter()
            .enumerate()
            .map(|(i, instr)| (instr.offset, i))
            .collect();

        // Step 3: Create blocks, from the leaders that start a decoded instruction: a
        // block ending at one that does not would leave the instructions after it in no
        // block at all
        let leader_list: Vec<u64> = leaders
            .iter()
            .copied()
            .filter(|leader| offset_to_index.contains_key(leader))
            .collect();
        let mut blocks: Vec<X86BasicBlock> = Vec::new();
        let mut offset_to_block: FxHashMap<u64, usize> = FxHashMap::default();

        for (block_idx, &leader_offset) in leader_list.iter().enumerate() {
            // Find start instruction index
            let Some(&start_instr_idx) = offset_to_index.get(&leader_offset) else {
                continue; // Leader offset not in our instruction list
            };

            // Find end of this block (exclusive)
            let end_offset = leader_list
                .get(block_idx.saturating_add(1))
                .copied()
                .unwrap_or(u64::MAX);

            // Collect instructions for this block
            let mut block_instrs = Vec::new();
            let mut block_end_offset = leader_offset;

            for instr in instructions.iter().skip(start_instr_idx) {
                if instr.offset >= end_offset {
                    break;
                }
                block_end_offset = instr.end_offset();
                block_instrs.push(instr.clone());

                // Stop at terminator instructions
                if instr.instruction.is_terminator() {
                    break;
                }
            }

            if !block_instrs.is_empty() {
                blocks.push(X86BasicBlock {
                    index: blocks.len(),
                    start_offset: leader_offset,
                    end_offset: block_end_offset,
                    instructions: block_instrs,
                });
            }
        }

        // The entry block first, the others in address order
        if let Some(position) = blocks
            .iter()
            .position(|block| block.start_offset == entry_offset)
        {
            let entry_block = blocks.remove(position);
            blocks.insert(0, entry_block);
        }
        for (index, block) in blocks.iter_mut().enumerate() {
            block.index = index;
            offset_to_block.insert(block.start_offset, index);
        }

        // Step 4: Compute edges before building graph (to avoid borrow issues)
        let edges_to_add: Vec<(usize, Vec<(usize, X86EdgeKind)>)> = blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (idx, compute_edges(block, &offset_to_block, base_address)))
            .collect();

        // Step 5: Build the DirectedGraph
        let mut graph: DirectedGraph<'static, X86BasicBlock, X86EdgeKind> =
            DirectedGraph::with_capacity(blocks.len(), blocks.len().saturating_mul(2));

        // Add all blocks as nodes
        for block in blocks {
            graph.add_node(block);
        }

        // Step 6: Add edges between blocks
        for (src_idx, edges) in edges_to_add {
            let src_node = NodeId::new(src_idx);
            for (target_idx, edge_kind) in edges {
                let target_node = NodeId::new(target_idx);
                // Ignore errors for edges to non-existent blocks
                let _ = graph.add_edge(src_node, target_node, edge_kind);
            }
        }

        // Step 7: Find entry and exit blocks
        let entry = NodeId::new(0);
        let exits: Vec<NodeId> = graph
            .nodes()
            .filter(|(_, block)| block.is_exit())
            .map(|(id, _)| id)
            .collect();

        Self {
            bitness,
            base_address,
            graph,
            entry,
            exits,
            dominators: OnceLock::new(),
        }
    }

    /// Returns the number of blocks in this function.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns true if this function has any unsupported instructions.
    pub fn has_unsupported(&self) -> bool {
        self.graph.nodes().any(|(_, block)| block.has_unsupported())
    }

    /// Returns true if this function has loops (back edges).
    ///
    /// A back edge is an edge where the target dominates the source.
    /// Uses the shared `has_back_edges` function for consistency.
    pub fn has_loops(&self) -> bool {
        has_back_edges(&self.graph, self.dominators())
    }

    /// Returns an iterator over all instructions in the function.
    pub fn instructions(&self) -> impl Iterator<Item = &X86DecodedInstruction> {
        self.graph
            .nodes()
            .flat_map(|(_, block)| block.instructions.iter())
    }

    /// Returns the block at the given index.
    pub fn block(&self, index: usize) -> Option<&X86BasicBlock> {
        self.graph.node(NodeId::new(index))
    }

    /// Returns the entry block node ID.
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    /// Returns the exit block node IDs.
    pub fn exits(&self) -> &[NodeId] {
        &self.exits
    }

    /// Returns an iterator over successor node IDs for a block.
    pub fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.successors(node)
    }

    /// Returns an iterator over predecessor node IDs for a block.
    pub fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.predecessors(node)
    }

    /// Returns a reference to the underlying graph.
    pub fn graph(&self) -> &DirectedGraph<'static, X86BasicBlock, X86EdgeKind> {
        &self.graph
    }

    /// Returns the lazily-computed dominator tree.
    pub fn dominators(&self) -> &DominatorTree {
        self.dominators.get_or_init(|| {
            // The X86Function implements RootedGraph + Successors, so we can use it directly
            compute_dominators(self, self.entry)
        })
    }

    /// Returns an iterator over all node IDs in the graph.
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.graph.node_ids()
    }

    /// Returns an iterator over all edges with their kinds.
    pub fn edges(&self) -> impl Iterator<Item = (NodeId, NodeId, &X86EdgeKind)> + '_ {
        self.graph.edge_ids().filter_map(move |edge_id| {
            let (src, dst) = self.graph.edge_endpoints(edge_id)?;
            let kind = self.graph.edge(edge_id)?;
            Some((src, dst, kind))
        })
    }

    /// Check if the CFG is reducible (no irreducible loops).
    ///
    /// A CFG is reducible if every back edge goes to a loop header that dominates
    /// the source of the back edge.
    ///
    /// # Implementation
    ///
    /// The depth-first search is iterative, with an explicit stack carrying an enter/exit
    /// marker so `in_stack` is cleared when a node's successors are exhausted — the point a
    /// recursive version does on return.
    ///
    /// Recursion is not an option here. Its depth equals the longest simple path, which for a
    /// chain of basic blocks equals the block count, and the blocks come from decoding an
    /// attacker-supplied native region. Exhausting the stack is a SIGSEGV, which neither
    /// `deny(panic)` nor a caller's `catch_unwind` can do anything about. This function is
    /// public API, so an embedder can reach it directly with such a region.
    pub fn is_reducible(&self) -> bool {
        /// One step of the iterative walk: visit a node's successors, or leave it.
        enum Step {
            Enter(NodeId),
            Exit(NodeId),
        }

        if self.block_count() == 0 {
            return true;
        }

        let doms = self.dominators();

        // A CFG is reducible if for every back edge (n -> h), h dominates n. A back edge is
        // an edge to a node currently on the DFS stack.
        let mut visited = vec![false; self.block_count()];
        let mut in_stack = vec![false; self.block_count()];
        let mut work = vec![Step::Enter(self.entry)];

        while let Some(step) = work.pop() {
            match step {
                Step::Exit(node) => {
                    if let Some(slot) = in_stack.get_mut(node.index()) {
                        *slot = false;
                    }
                }
                Step::Enter(node) => {
                    let idx = node.index();
                    if visited.get(idx).copied().unwrap_or(false) {
                        continue;
                    }
                    if let Some(slot) = visited.get_mut(idx) {
                        *slot = true;
                    }
                    if let Some(slot) = in_stack.get_mut(idx) {
                        *slot = true;
                    }

                    // Popped only once every successor pushed below has been processed.
                    work.push(Step::Exit(node));

                    for succ in self.graph.successors(node) {
                        let succ_idx = succ.index();
                        if in_stack.get(succ_idx).copied().unwrap_or(false) {
                            if !doms.dominates(succ, node) {
                                return false;
                            }
                        } else if !visited.get(succ_idx).copied().unwrap_or(false) {
                            work.push(Step::Enter(succ));
                        }
                    }
                }
            }
        }

        true
    }
}

// Implement traits required for dominator computation
impl GraphBase for X86Function {
    fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    fn node_ids(&self) -> impl Iterator<Item = NodeId> {
        self.graph.node_ids()
    }
}

impl Successors for X86Function {
    fn successors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.graph.successors(node)
    }
}

impl Predecessors for X86Function {
    fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> {
        self.graph.predecessors(node)
    }
}

impl RootedGraph for X86Function {
    fn entry(&self) -> NodeId {
        self.entry
    }
}

/// Compute the edges (successors with edge kinds) for a block.
fn compute_edges(
    block: &X86BasicBlock,
    offset_to_block: &FxHashMap<u64, usize>,
    base_address: u64,
) -> Vec<(usize, X86EdgeKind)> {
    let mut edges = Vec::new();

    if let Some(term) = block.terminator() {
        match term {
            X86Instruction::Jmp { target } => {
                if let Some(target_offset) = target.checked_sub(base_address) {
                    if let Some(&block_idx) = offset_to_block.get(&target_offset) {
                        edges.push((block_idx, X86EdgeKind::Unconditional));
                    }
                }
            }
            X86Instruction::Jcc { target, condition } => {
                // Conditional jump: two edges
                // 1. Target (condition true)
                if let Some(target_offset) = target.checked_sub(base_address) {
                    if let Some(&block_idx) = offset_to_block.get(&target_offset) {
                        edges.push((
                            block_idx,
                            X86EdgeKind::ConditionalTrue {
                                condition: *condition,
                            },
                        ));
                    }
                }
                // 2. Fallthrough (condition false)
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((
                        block_idx,
                        X86EdgeKind::ConditionalFalse {
                            condition: *condition,
                        },
                    ));
                }
            }
            X86Instruction::Call { target } => {
                // For intraprocedural CFG, call falls through
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((block_idx, X86EdgeKind::Call { target: *target }));
                }
            }
            X86Instruction::Ret => {
                // No successors - but we mark it as a return edge to a virtual exit
                // For now, we don't add an edge since there's no successor block
            }
            _ => {
                // Non-terminator at end of block - fallthrough
                if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
                    edges.push((block_idx, X86EdgeKind::Unconditional));
                }
            }
        }
    } else if !block.instructions.is_empty() {
        // Block with no terminator - fallthrough
        if let Some(&block_idx) = offset_to_block.get(&block.end_offset) {
            edges.push((block_idx, X86EdgeKind::Unconditional));
        }
    }

    edges
}

#[cfg(test)]
mod tests {
    use analyssa::graph::NodeId;

    use crate::analysis::x86::{
        cfg::X86Function,
        decoder::x86_decode_all,
        types::{X86Condition, X86EdgeKind},
    };

    /// A jump into the middle of an instruction starts no block: the block it would have
    /// ended keeps the instructions after it. `jne 4` jumps inside the `mov` at 2; ending
    /// the block at 2 there dropped the `add` and `ret` after the `mov` from every block.
    #[test]
    fn a_jump_into_an_instruction_drops_no_code() {
        // 0: jne 4; 2: mov eax, 0x11223344; 7: add eax, 1; 10: ret
        let bytes = [
            0x75, 0x02, 0xB8, 0x44, 0x33, 0x22, 0x11, 0x83, 0xC0, 0x01, 0xC3,
        ];
        let instructions = x86_decode_all(&bytes, 32, 0).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0);
        let decoded: usize = (0..cfg.block_count())
            .filter_map(|index| cfg.block(index))
            .map(|block| block.instructions.len())
            .sum();
        assert_eq!(decoded, instructions.len());
        assert!((0..cfg.block_count())
            .filter_map(|index| cfg.block(index))
            .all(|block| block.start_offset != 4));
    }

    #[test]
    fn test_build_cfg_linear() {
        // Linear code: mov eax, 1; add eax, 2; ret
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xc0, 0x02, // add eax, 2
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.block(0).unwrap().instructions.len(), 3);
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 0);
    }

    #[test]
    fn test_build_cfg_conditional() {
        // cmp eax, 10
        // je skip
        // add eax, 5
        // skip: ret
        let bytes = [
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x74, 0x03, // je +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have 3 blocks:
        // Block 0: cmp, je
        // Block 1: add eax, 5
        // Block 2: ret
        assert_eq!(cfg.block_count(), 3);
        assert_eq!(cfg.entry(), NodeId::new(0));

        // Block 0 should have 2 successors (taken and fallthrough)
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 2);

        // Check that the CFG is reducible (simple if-then)
        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_build_cfg_unconditional_jump() {
        // jmp skip
        // nop (unreachable)
        // skip: mov eax, 1
        // ret
        let bytes = [
            0xeb, 0x01, // jmp +1
            0x90, // nop
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have blocks
        assert!(cfg.block_count() >= 2);

        // Entry block should have exactly one successor (the jump target)
        assert_eq!(cfg.successors(NodeId::new(0)).count(), 1);
    }

    #[test]
    fn test_build_cfg_loop() {
        // loop: cmp eax, 0
        //       je exit
        //       dec eax
        //       jmp loop
        // exit: ret
        let bytes = [
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x74, 0x04, // je +4 (to ret)
            0x48, // dec eax
            0xeb, 0xf8, // jmp -8 (to cmp)
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Should have a loop (back edge)
        assert!(cfg.has_loops());

        // Should be reducible (simple while loop)
        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_empty_input() {
        let cfg = X86Function::new(&[], 32, 0);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_dominators() {
        // Linear code should have simple dominator tree
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xc0, 0x02, // add eax, 2
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let doms = cfg.dominators();
        assert_eq!(doms.entry(), NodeId::new(0));
    }

    #[test]
    fn test_edge_kinds() {
        // Conditional code to test edge kinds
        let bytes = [
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x74, 0x03, // je +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        // Check that we have conditional edges
        let mut found_cond_true = false;
        let mut found_cond_false = false;

        for (_, _, kind) in cfg.edges() {
            match kind {
                X86EdgeKind::ConditionalTrue { condition } => {
                    assert_eq!(*condition, X86Condition::E);
                    found_cond_true = true;
                }
                X86EdgeKind::ConditionalFalse { condition } => {
                    assert_eq!(*condition, X86Condition::E);
                    found_cond_false = true;
                }
                _ => {}
            }
        }

        assert!(found_cond_true);
        assert!(found_cond_false);
    }
}

//! Control Flow Graph (CFG) construction and analysis.
//!
//! This module provides a proper graph abstraction over CIL basic blocks with
//! efficient traversal, dominator computation, and loop detection capabilities.
//!
//! # Architecture
//!
//! The CFG builds upon generic graph infrastructure, providing CIL-specific node
//! and edge types while leveraging shared algorithms for dominators, traversals,
//! and strongly connected components.
//!
//! # Key Components
//!
//! - [`ControlFlowGraph`] - The main CFG structure wrapping basic blocks
//! - [`CfgEdge`] / [`CfgEdgeKind`] - Edges and their control-flow classification
//! - [`LoopAnalyzer`] / [`LoopForest`] / [`LoopInfo`] - Loop detection (re-exported
//!   from `analyssa::analysis::loops` / `analyssa::analysis::loopanalyzer`)
//! - [`SemanticAnalyzer`] / [`BlockSemantics`] / [`LoopSemantics`] - Higher-level
//!   block- and loop-role classification used by deobfuscation passes
//!
//! # Edge Types
//!
//! The CFG distinguishes several types of control flow edges:
//!
//! - **Unconditional**: Direct jumps or fall-through to a single successor
//! - **Conditional True/False**: Branches based on a condition
//! - **Switch**: Multi-way branches with case values
//! - **Exception**: Edges to exception handlers
//!
//! # Lazy Computation
//!
//! Expensive analyses like dominator trees and loop information are computed
//! lazily on first access and cached for subsequent queries. This is implemented
//! using [`std::sync::OnceLock`] for thread-safe initialization.
//!
//! # Examples
//!
//! ## Building a CFG from Basic Blocks
//!
//! ```
//! use dotscope::analysis::ControlFlowGraph;
//! use dotscope::assembly::decode_blocks;
//!
//! // `nop; ret`
//! let il = [0x00u8, 0x2A];
//! let blocks = decode_blocks(&il, 0, 0x2050, Some(il.len()))?;
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! println!("CFG has {} blocks", graph.block_count());
//! println!("Entry block: {:?}", graph.entry());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Traversing the CFG
//!
//! ```
//! use dotscope::analysis::ControlFlowGraph;
//! # use dotscope::assembly::decode_blocks;
//! # let il = [0x00u8, 0x2A];
//! # let blocks = decode_blocks(&il, 0, 0x2050, Some(il.len()))?;
//!
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Iterate in reverse postorder (useful for data flow)
//! for block_id in graph.reverse_postorder() {
//!     if let Some(block) = graph.block(block_id) {
//!         println!("Block {:?} at RVA 0x{:x}", block_id, block.rva);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Computing Dominators
//!
//! ```
//! use dotscope::analysis::ControlFlowGraph;
//! # use dotscope::assembly::decode_blocks;
//! # let il = [0x00u8, 0x2A];
//! # let blocks = decode_blocks(&il, 0, 0x2050, Some(il.len()))?;
//!
//! let graph = ControlFlowGraph::from_basic_blocks(blocks)?;
//! let some_block = graph.exits()[0];
//!
//! // Check domination relationships
//! if graph.dominates(graph.entry(), some_block) {
//!     println!("Entry dominates the target block");
//! }
//!
//! // Get dominance frontiers for SSA construction
//! let frontiers = graph.dominance_frontiers();
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`ControlFlowGraph`] is [`Send`] and [`Sync`], enabling safe concurrent read
//! access after construction. The lazy-initialized dominator tree and loop info
//! use [`std::sync::OnceLock`] for thread-safe initialization.

mod edge;
mod graph;
mod semantics;

#[cfg(feature = "compiler")]
pub use analyssa::analysis::loopanalyzer::SsaLoopAnalysis;
#[cfg(feature = "x86")]
pub use analyssa::analysis::loops::has_back_edges;
pub use analyssa::analysis::loops::{detect_loops, InductionVar, LoopForest, LoopInfo};
pub use edge::{CfgEdge, CfgEdgeKind};
pub use graph::ControlFlowGraph;
pub use semantics::{BlockSemantics, LoopSemantics, SemanticAnalyzer};

// `LoopAnalyzer` and the extended-loop primitives live analyssa-side. CIL
// callers reach them through these aliases / re-exports.
use crate::analysis::ssa::CilTarget;

/// CIL-defaulted alias of [`analyssa::analysis::loopanalyzer::LoopAnalyzer`].
pub type LoopAnalyzer<'a, T = CilTarget> = analyssa::analysis::loopanalyzer::LoopAnalyzer<'a, T>;

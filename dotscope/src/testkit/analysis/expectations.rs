//! Expected analysis properties for test verification.
//!
//! This module defines the expectation types that describe what analysis
//! results we expect for each test case.

/// Expected properties of a Control Flow Graph.
#[derive(Debug, Clone, Default)]
pub struct CfgExpectation {
    /// Minimum number of basic blocks.
    pub min_blocks: usize,
    /// Maximum number of basic blocks (compilers may vary).
    pub max_blocks: usize,
    /// Whether the CFG should contain loops.
    pub has_loops: bool,
    /// Minimum number of exit blocks.
    pub min_exits: usize,
    /// Maximum number of exit blocks.
    pub max_exits: usize,
}

impl CfgExpectation {}

/// Expected properties of SSA form.
#[derive(Debug, Clone, Default)]
pub struct SsaExpectation {
    /// Number of method arguments.
    pub num_args: usize,
    /// Minimum number of local variables (debug builds may add extra).
    pub min_locals: usize,
    /// Maximum number of local variables.
    pub max_locals: usize,
    /// Whether phi nodes should be present.
    pub has_phi_nodes: bool,
    /// Minimum number of phi nodes.
    pub min_phi_count: usize,
    /// Maximum number of phi nodes (compilers may vary).
    pub max_phi_count: usize,
}

impl SsaExpectation {}

/// Expected properties of call graph nodes.
#[derive(Debug, Clone, Default)]
pub struct CallGraphExpectation {
    /// Minimum number of call sites in the method.
    pub min_call_sites: usize,
    /// Maximum number of call sites.
    pub max_call_sites: usize,
    /// Whether this method is recursive (direct or mutual).
    pub is_recursive: bool,
    /// Whether this method is a leaf (no outgoing calls).
    pub is_leaf: bool,
}

impl CallGraphExpectation {}

/// Expected properties of data flow analysis results.
#[derive(Debug, Clone, Default)]
pub struct DataFlowExpectation {
    /// Whether constant propagation should find constants.
    pub has_constants: bool,
    /// Whether there should be dead code.
    pub has_dead_code: bool,
    /// Whether all blocks should be reachable.
    pub all_blocks_reachable: bool,
}

impl DataFlowExpectation {}

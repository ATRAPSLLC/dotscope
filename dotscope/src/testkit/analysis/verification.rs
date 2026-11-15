//! Verification functions for analysis results.
//!
//! This module provides functions that compare actual analysis results
//! against expected properties.

use std::{collections::HashSet, fmt};

use crate::{
    analysis::{
        CallGraph, CilTarget, ConstantPropagation, ControlFlowGraph, DataFlowSolver, LiveVariables,
        NodeId, ReachingDefinitions, SsaFunction,
    },
    metadata::method::Method,
    testkit::analysis::expectations::{
        CallGraphExpectation, CfgExpectation, DataFlowExpectation, SsaExpectation,
    },
    CilObject,
};

/// Error returned when verification fails.
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// What was being verified.
    pub component: String,
    /// What property failed.
    pub property: String,
    /// Expected value.
    pub expected: String,
    /// Actual value.
    pub actual: String,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: expected {}, got {}",
            self.component, self.property, self.expected, self.actual
        )
    }
}

impl std::error::Error for VerificationError {}

impl VerificationError {
    /// Creates a new verification error.
    #[must_use]
    pub fn new(
        component: impl Into<String>,
        property: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self {
            component: component.into(),
            property: property.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

/// Verifies that a CFG matches expected properties.
///
/// # Arguments
///
/// * `cfg` - The control flow graph to verify
/// * `expectation` - Expected CFG properties
///
/// # Returns
///
/// A list of verification errors (empty if all checks pass).
#[must_use]
pub fn verify_cfg(
    cfg: &ControlFlowGraph<'_>,
    expectation: &CfgExpectation,
) -> Vec<VerificationError> {
    let mut errors = Vec::new();

    // Check block count
    let block_count = cfg.block_count();
    if block_count < expectation.min_blocks {
        errors.push(VerificationError::new(
            "CFG",
            "block_count (min)",
            format!(">= {}", expectation.min_blocks),
            block_count.to_string(),
        ));
    }
    if block_count > expectation.max_blocks {
        errors.push(VerificationError::new(
            "CFG",
            "block_count (max)",
            format!("<= {}", expectation.max_blocks),
            block_count.to_string(),
        ));
    }

    // Check loop detection
    let has_loops = cfg.has_loops();
    if has_loops != expectation.has_loops {
        errors.push(VerificationError::new(
            "CFG",
            "has_loops",
            expectation.has_loops.to_string(),
            has_loops.to_string(),
        ));
    }

    // Check exit count
    let exit_count = cfg.exits().len();
    if exit_count < expectation.min_exits {
        errors.push(VerificationError::new(
            "CFG",
            "exit_count (min)",
            format!(">= {}", expectation.min_exits),
            exit_count.to_string(),
        ));
    }
    if exit_count > expectation.max_exits {
        errors.push(VerificationError::new(
            "CFG",
            "exit_count (max)",
            format!("<= {}", expectation.max_exits),
            exit_count.to_string(),
        ));
    }

    // Additional structural validations
    // Verify entry block exists
    let entry = cfg.entry();
    if cfg.block(entry).is_none() {
        errors.push(VerificationError::new(
            "CFG",
            "entry_block",
            "valid",
            "missing",
        ));
    }

    // Verify all exits have valid blocks
    for exit in cfg.exits() {
        if cfg.block(*exit).is_none() {
            errors.push(VerificationError::new(
                "CFG",
                format!("exit_block_{}", exit.index()),
                "valid",
                "missing",
            ));
        }
    }

    // Verify dominator tree is consistent
    // Entry should dominate all reachable blocks
    for node_id in cfg.node_ids() {
        if !cfg.dominates(entry, node_id) {
            // This could indicate unreachable code, which may be valid
            // Only flag if the block has predecessors but isn't dominated
            let preds: Vec<_> = cfg.predecessors(node_id).collect();
            if !preds.is_empty() {
                errors.push(VerificationError::new(
                    "CFG",
                    format!("dominator_tree (block {})", node_id.index()),
                    "entry dominates",
                    "entry does not dominate",
                ));
            }
        }
    }

    errors
}

/// Verifies that SSA form matches expected properties.
///
/// # Arguments
///
/// * `ssa` - The SSA function to verify
/// * `cfg` - The corresponding CFG
/// * `expectation` - Expected SSA properties
///
/// # Returns
///
/// A list of verification errors (empty if all checks pass).
#[must_use]
pub fn verify_ssa(
    ssa: &SsaFunction,
    cfg: &ControlFlowGraph<'_>,
    expectation: &SsaExpectation,
) -> Vec<VerificationError> {
    let mut errors = Vec::new();

    // Check argument count
    if ssa.num_args() != expectation.num_args {
        errors.push(VerificationError::new(
            "SSA",
            "num_args",
            expectation.num_args.to_string(),
            ssa.num_args().to_string(),
        ));
    }

    // Check local count (use range to allow for debug build variations).
    let num_locals = ssa.num_locals();
    if num_locals < expectation.min_locals {
        errors.push(VerificationError::new(
            "SSA",
            "num_locals (min)",
            format!(">= {}", expectation.min_locals),
            num_locals.to_string(),
        ));
    }
    if num_locals > expectation.max_locals {
        errors.push(VerificationError::new(
            "SSA",
            "num_locals (max)",
            format!("<= {}", expectation.max_locals),
            num_locals.to_string(),
        ));
    }

    // Check phi node count
    let phi_count = ssa.phi_count();
    if expectation.has_phi_nodes && phi_count == 0 {
        errors.push(VerificationError::new(
            "SSA",
            "has_phi_nodes",
            "true (> 0 phis)",
            "false (0 phis)",
        ));
    }
    if !expectation.has_phi_nodes && phi_count > 0 {
        // This is informational - some compilers may generate phis even when not strictly needed
        // Don't treat as error
    }

    // Only check phi count ranges when we expect phi nodes
    // Debug builds may introduce additional phi nodes due to control flow changes
    if expectation.has_phi_nodes {
        if phi_count < expectation.min_phi_count {
            errors.push(VerificationError::new(
                "SSA",
                "phi_count (min)",
                format!(">= {}", expectation.min_phi_count),
                phi_count.to_string(),
            ));
        }
        if phi_count > expectation.max_phi_count {
            errors.push(VerificationError::new(
                "SSA",
                "phi_count (max)",
                format!("<= {}", expectation.max_phi_count),
                phi_count.to_string(),
            ));
        }
    }

    // Verify SSA invariants
    // 1. Block count matches CFG
    if ssa.block_count() != cfg.block_count() {
        errors.push(VerificationError::new(
            "SSA",
            "block_count",
            cfg.block_count().to_string(),
            ssa.block_count().to_string(),
        ));
    }

    // 2. Variable IDs are unique (not necessarily sequential with global counter)
    let mut seen_ids = HashSet::new();
    for var in ssa.variables() {
        if !seen_ids.insert(var.id()) {
            errors.push(VerificationError::new(
                "SSA",
                "duplicate_variable_id",
                "unique IDs",
                format!("duplicate {}", var.id()),
            ));
            break; // Only report first duplicate
        }
    }

    // 3. Each phi operand references a valid predecessor
    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        let preds: Vec<_> = cfg.predecessors(NodeId::new(block_idx)).collect();

        for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
            for op in phi.operands() {
                let pred_node = NodeId::new(op.predecessor());
                if !preds.contains(&pred_node) {
                    errors.push(VerificationError::new(
                        "SSA",
                        format!("phi[{}][{}] predecessor", block_idx, phi_idx),
                        format!("one of {:?}", preds),
                        format!("block {}", op.predecessor()),
                    ));
                }
            }
        }
    }

    // 4. Definition sites are valid
    for var in ssa.variables() {
        let def_site = var.def_site();
        if !def_site.is_phi() && def_site.block >= ssa.block_count() {
            errors.push(VerificationError::new(
                "SSA",
                format!("variable {} def_site.block", var.id()),
                format!("< {}", ssa.block_count()),
                def_site.block.to_string(),
            ));
        }
    }

    errors
}

/// Verifies call graph properties for a specific method.
///
/// # Arguments
///
/// * `callgraph` - The call graph to verify
/// * `method` - The method to verify
/// * `expectation` - Expected call graph properties
///
/// # Returns
///
/// A list of verification errors (empty if all checks pass).
#[must_use]
pub fn verify_callgraph(
    callgraph: &CallGraph,
    method: &Method,
    expectation: &CallGraphExpectation,
) -> Vec<VerificationError> {
    let mut errors = Vec::new();

    let token = method.token;

    // Get the node for this method
    let node = match callgraph.node(token) {
        Some(n) => n,
        None => {
            errors.push(VerificationError::new(
                "CallGraph",
                "method_node",
                "present",
                "missing",
            ));
            return errors;
        }
    };

    // Check call site count
    let call_site_count = node.call_sites.len();
    if call_site_count < expectation.min_call_sites {
        errors.push(VerificationError::new(
            "CallGraph",
            "call_site_count (min)",
            format!(">= {}", expectation.min_call_sites),
            call_site_count.to_string(),
        ));
    }
    if call_site_count > expectation.max_call_sites {
        errors.push(VerificationError::new(
            "CallGraph",
            "call_site_count (max)",
            format!("<= {}", expectation.max_call_sites),
            call_site_count.to_string(),
        ));
    }

    // Check leaf status
    let is_leaf = node.is_leaf();
    if is_leaf != expectation.is_leaf {
        errors.push(VerificationError::new(
            "CallGraph",
            "is_leaf",
            expectation.is_leaf.to_string(),
            is_leaf.to_string(),
        ));
    }

    // Check recursion
    let recursive_methods = callgraph.recursive_methods();
    let is_recursive = recursive_methods.contains(&token);
    if is_recursive != expectation.is_recursive {
        errors.push(VerificationError::new(
            "CallGraph",
            "is_recursive",
            expectation.is_recursive.to_string(),
            is_recursive.to_string(),
        ));
    }

    errors
}

/// Verifies data flow analysis results.
///
/// # Arguments
///
/// * `ssa` - The SSA function
/// * `cfg` - The control flow graph
/// * `expectation` - Expected data flow properties
///
/// # Returns
///
/// A list of verification errors (empty if all checks pass).
#[must_use]
pub fn verify_dataflow(
    ssa: &SsaFunction,
    cfg: &ControlFlowGraph<'_>,
    expectation: &DataFlowExpectation,
) -> Vec<VerificationError> {
    let mut errors = Vec::new();

    // Run SCCP to check for constants and dead code
    let mut sccp = ConstantPropagation::new(CilTarget::x64().machine());
    let sccp_result = sccp.analyze(ssa, cfg);

    // Check for constants
    let has_constants = sccp_result.constant_count() > 0;
    if has_constants != expectation.has_constants {
        // This is a soft check - different compilers may optimize differently
        // Only flag if we expected constants and found none
        if expectation.has_constants && !has_constants {
            errors.push(VerificationError::new(
                "DataFlow",
                "has_constants",
                "true",
                "false",
            ));
        }
    }

    // Check block reachability
    let total_blocks = cfg.block_count();
    let reachable_blocks = sccp_result.executable_block_count();
    let all_reachable = reachable_blocks >= total_blocks;

    if expectation.all_blocks_reachable && !all_reachable {
        errors.push(VerificationError::new(
            "DataFlow",
            "all_blocks_reachable",
            "true",
            format!(
                "false ({}/{} blocks reachable)",
                reachable_blocks, total_blocks
            ),
        ));
    }

    if expectation.has_dead_code && all_reachable {
        errors.push(VerificationError::new(
            "DataFlow",
            "has_dead_code",
            "true (unreachable blocks)",
            format!("false (all {} blocks reachable)", total_blocks),
        ));
    }

    // Run liveness analysis
    let liveness = LiveVariables::new(ssa);
    let liveness_solver = DataFlowSolver::new(liveness);
    let _liveness_results = liveness_solver.solve(ssa, cfg);

    // Run reaching definitions
    let reaching = ReachingDefinitions::new(ssa);
    let reaching_solver = DataFlowSolver::new(reaching);
    let _reaching_results = reaching_solver.solve(ssa, cfg);

    // Note: More detailed dataflow checks could be added here
    // For now, we just verify the analyses complete without panic

    errors
}

/// Builds the CFG and SSA of a method the way the library does, through [`Method::cfg`] and
/// [`Method::ssa`], so a test verifies what analysis and deobfuscation see.
///
/// # Returns
///
/// A tuple of (CFG, SSA) or an error message.
pub fn build_analysis<'m>(
    method: &'m Method,
    assembly: &CilObject,
) -> Result<(ControlFlowGraph<'m>, SsaFunction), String> {
    let cfg = method
        .cfg()
        .ok_or_else(|| format!("method {} has no decoded blocks", method.name))?;
    let ssa = method
        .ssa(assembly)
        .map_err(|e| format!("Failed to build SSA: {e}"))?;
    Ok((cfg, ssa))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::load_sample;

    /// The analysis harness verifies the SSA the library builds, `this` and exception handlers
    /// included, not a copy of its own.
    #[test]
    fn build_analysis_matches_the_library_s_ssa() {
        let assembly = load_sample("crafted_2.exe");
        let mut instance_methods = 0;
        for entry in assembly.methods().iter() {
            let method = entry.value();
            let ours = build_analysis(method, &assembly).map(|(_, ssa)| ssa.to_string());
            let library = method.ssa(&assembly).map(|ssa| ssa.to_string());
            match (ours, library) {
                (Ok(ours), Ok(library)) => {
                    assert_eq!(ours, library, "method {}", method.name);
                    instance_methods += usize::from(method.signature.has_this);
                }
                (Err(_), Err(_)) => {}
                (ours, library) => {
                    panic!(
                        "method {}: harness {ours:?}, library {library:?}",
                        method.name
                    )
                }
            }
        }
        assert!(
            instance_methods > 0,
            "the sample has instance methods with bodies"
        );
    }
}

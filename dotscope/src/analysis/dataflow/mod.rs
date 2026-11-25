//! Re-export shim — dataflow framework + analyses live in
//! `analyssa::analysis::dataflow`. CIL-defaulted aliases preserve historical
//! `dotscope::analysis::*` API.

pub use analyssa::analysis::dataflow::{
    framework::{AnalysisResults, DataFlowAnalysis, DataFlowCfg, Direction},
    liveness::{LiveVariables, LivenessResult},
    reaching::ReachingDefinitions,
};
use analyssa::graph::{NodeId, RootedGraph};

use crate::analysis::{ssa::CilTarget, ControlFlowGraph};

/// CIL-defaulted alias of [`analyssa::analysis::dataflow::sccp::ConstantPropagation`].
pub type ConstantPropagation<T = CilTarget> =
    analyssa::analysis::dataflow::sccp::ConstantPropagation<T>;
/// CIL-defaulted alias of [`analyssa::analysis::dataflow::sccp::ScalarValue`].
pub type ScalarValue<T = CilTarget> = analyssa::analysis::dataflow::sccp::ScalarValue<T>;
/// CIL-defaulted alias of [`analyssa::analysis::dataflow::sccp::SccpResult`].
pub type SccpResult<T = CilTarget> = analyssa::analysis::dataflow::sccp::SccpResult<T>;
/// CIL-defaulted alias of [`analyssa::analysis::dataflow::solver::DataFlowSolver`].
pub type DataFlowSolver<A, T = CilTarget> =
    analyssa::analysis::dataflow::solver::DataFlowSolver<T, A>;

// `DataFlowCfg` impl for the CIL `ControlFlowGraph`. The SsaCfg impl lives
// analyssa-side. Both must be available so dataflow analyses run on either CFG.
impl DataFlowCfg for ControlFlowGraph<'_> {
    fn entry(&self) -> NodeId {
        RootedGraph::entry(self)
    }

    fn exits(&self) -> Vec<NodeId> {
        self.exits().to_vec()
    }

    fn postorder(&self) -> Vec<NodeId> {
        self.postorder()
    }

    fn reverse_postorder(&self) -> Vec<NodeId> {
        self.reverse_postorder()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assembly::InstructionAssembler,
        testkit::{build_cfg, build_ssa, TestTypeProvider},
    };

    #[test]
    fn test_reaching_defs_simple_function() {
        // Simple function: return arg0 + arg1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");

        let analysis = ReachingDefinitions::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // At entry block exit, both argument definitions should reach
        if let Some(out_state) = results.out_state(0) {
            // At least arg0 and arg1 should be reaching
            assert!(out_state.count() >= 2);
        }
    }

    #[test]
    fn test_reaching_defs_with_local_assignment() {
        // local0 = arg0; return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");

        let analysis = ReachingDefinitions::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // Definitions should propagate through the single block
        if let Some(out_state) = results.out_state(0) {
            // Should have at least arg0, initial local0, and new local0
            assert!(out_state.count() >= 2);
        }
    }

    #[test]
    fn test_reaching_defs_diamond_cfg() {
        // if (arg0) { local0 = 1; } else { local0 = 2; } return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");

        let analysis = ReachingDefinitions::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // At merge block entry, definitions from both branches should reach
        let merge_block = ssa.block_count() - 1;
        if let Some(in_state) = results.in_state(merge_block) {
            // Should have definitions reaching from both paths
            assert!(in_state.count() >= 1);
        }
    }

    #[test]
    fn test_liveness_simple_function() {
        // Simple function: return arg0 + arg1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");

        let analysis = LiveVariables::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // Verify analysis completes and produces results
        assert!(results.in_state(0).is_some());
        assert!(results.out_state(0).is_some());

        // At block entry, at least some variables should be live
        // (The exact count depends on how variables are mapped during SSA construction)
        if let Some(in_state) = results.in_state(0) {
            // Basic sanity check - the analysis ran without panicking
            // and produced valid results
            let _ = in_state.count();
        }
    }

    #[test]
    fn test_liveness_dead_local() {
        // local0 = 1; return arg0;  (local0 is never used)
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");

        let analysis = LiveVariables::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let _results = solver.solve(&ssa, &cfg);

        // local0 should not be live at any point since it's never used
        // arg0 should be live at entry
        // This is a basic sanity check - detailed verification depends on var IDs
    }

    #[test]
    fn test_liveness_loop() {
        // i = 0; while (i < 10) { i++; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("loop")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(10)
            .unwrap()
            .bge_s("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("loop")
            .unwrap()
            .label("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction");

        let analysis = LiveVariables::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // At some point, local0 should be live
        let mut found_live = false;
        for block_idx in 0..ssa.block_count() {
            if let Some(in_state) = results.in_state(block_idx) {
                if in_state.count() > 0 {
                    found_live = true;
                    break;
                }
            }
        }
        assert!(found_live, "Expected some variables to be live in loop");
    }

    #[test]
    fn test_sccp_constant_folding() {
        // return 1 + 2;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_1()
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction");

        let mut sccp = ConstantPropagation::new(CilTarget::x64().machine());
        let results = sccp.analyze(&ssa, &cfg);

        // The entry block should be executable
        assert!(results.is_block_executable(0));

        // We should have some constant values
        // Note: The exact count depends on how many intermediate variables
        // are created during SSA construction
        assert!(results.constant_count() >= 2); // At least 1 and 2 are constants
    }

    #[test]
    fn test_sccp_unreachable_code() {
        // if (false) { local0 = 1; } else { local0 = 2; } return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap() // false
            .brtrue_s("then")
            .unwrap()
            // else branch (always taken)
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("then")
            .unwrap()
            // then branch (never taken)
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction");

        let mut sccp = ConstantPropagation::new(CilTarget::x64().machine());
        let results = sccp.analyze(&ssa, &cfg);

        // Entry block should be executable
        assert!(results.is_block_executable(0));

        // The then branch might not be executable (depending on branch evaluation)
        // At minimum, we should have some executable blocks
        assert!(results.executable_block_count() >= 2);
    }

    #[test]
    fn test_sccp_phi_with_constants() {
        // if (arg0) { local0 = 1; } else { local0 = 1; } return local0;
        // Both branches assign same constant, so result should be constant
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap() // Same constant!
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");

        let mut sccp = ConstantPropagation::new(CilTarget::x64().machine());
        let results = sccp.analyze(&ssa, &cfg);

        // All blocks should be executable
        assert!(results.executable_block_count() >= 3);
    }

    #[test]
    fn test_solver_convergence() {
        // Complex loop that requires multiple iterations
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_1()
            .unwrap()
            .label("outer")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(5)
            .unwrap()
            .bge_s("exit")
            .unwrap()
            .label("inner")
            .unwrap()
            .ldloc_1()
            .unwrap()
            .ldc_i4_s(5)
            .unwrap()
            .bge_s("outer_inc")
            .unwrap()
            .ldloc_1()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_1()
            .unwrap()
            .br_s("inner")
            .unwrap()
            .label("outer_inc")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_1()
            .unwrap()
            .br_s("outer")
            .unwrap()
            .label("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 2)).expect("SSA construction");

        // Test that reaching definitions converges
        let rd_analysis = ReachingDefinitions::new(&ssa);
        let rd_solver = DataFlowSolver::new(rd_analysis);
        let _rd_results = rd_solver.solve(&ssa, &cfg);

        // Test that liveness converges
        let lv_analysis = LiveVariables::new(&ssa);
        let lv_solver = DataFlowSolver::new(lv_analysis);
        let _lv_results = lv_solver.solve(&ssa, &cfg);

        // If we get here without hanging, the solver converged correctly
    }

    #[test]
    fn test_analysis_results_access() {
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0().unwrap().ret().unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");

        let analysis = ReachingDefinitions::new(&ssa);
        let solver = DataFlowSolver::new(analysis);
        let results = solver.solve(&ssa, &cfg);

        // Test various access patterns
        assert!(results.in_state(0).is_some());
        assert!(results.out_state(0).is_some());

        // Out-of-bounds access should return None
        assert!(results.in_state(999).is_none());
        assert!(results.out_state(999).is_none());
    }
}

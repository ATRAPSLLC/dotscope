//! Program analysis infrastructure for .NET assemblies.
//!
//! This module provides foundational analysis capabilities for understanding and
//! transforming .NET CIL code, including control flow graphs, SSA form, data flow
//! analysis, and inter-procedural call graphs.
//!
//! # Key Components
//!
//! ## Control Flow Graph (CFG)
//!
//! - [`ControlFlowGraph`](crate::analysis::ControlFlowGraph) - CFG built from basic blocks with lazy dominator computation
//! - [`CfgEdge`](crate::analysis::CfgEdge) / [`CfgEdgeKind`](crate::analysis::CfgEdgeKind) - Edge representation with control flow semantics
//! - [`LoopAnalyzer`](crate::analysis::LoopAnalyzer) / [`LoopForest`](crate::analysis::LoopForest) / [`LoopInfo`](crate::analysis::LoopInfo) - Loop detection and analysis
//!
//! ## Static Single Assignment (SSA)
//!
//! - [`SsaFunction`](crate::analysis::SsaFunction) - Method in SSA form with explicit def-use chains
//! - [`SsaConverter`](crate::analysis::SsaConverter) - Constructs SSA from CFG via dominance frontiers
//! - [`SsaBlock`](crate::analysis::SsaBlock) / [`SsaOp`](crate::analysis::SsaOp) / [`SsaInstruction`](crate::analysis::SsaInstruction) - SSA blocks and operations
//! - [`PhiNode`](crate::analysis::PhiNode) / [`PhiOperand`](crate::analysis::PhiOperand) - Phi functions at control flow merge points
//! - [`SsaVarId`](crate::analysis::SsaVarId) / [`SsaVariable`](crate::analysis::SsaVariable) - SSA variable identifiers and metadata
//! - [`ConstValue`](crate::analysis::ConstValue) / [`AbstractValue`](crate::analysis::AbstractValue) - Constant and abstract value representation
//!
//! ## Data Flow Analysis
//!
//! - [`ConstantPropagation`](crate::analysis::ConstantPropagation) - Sparse Conditional Constant Propagation (SCCP)
//! - [`LiveVariables`](crate::analysis::LiveVariables) / [`LivenessResult`](crate::analysis::LivenessResult) - Liveness analysis
//! - [`ReachingDefinitions`](crate::analysis::ReachingDefinitions) - Reaching definitions
//! - [`DataFlowSolver`](crate::analysis::DataFlowSolver) / [`DataFlowAnalysis`](crate::analysis::DataFlowAnalysis) - Generic fixpoint solver framework
//!
//! ## Call Graph
//!
//! - [`CallGraph`](crate::analysis::CallGraph) - Inter-procedural call relationships
//! - [`CallResolver`](crate::analysis::CallResolver) - Virtual call resolution via Class Hierarchy Analysis
//! - [`CallSite`](crate::analysis::CallSite) / [`CallTarget`](crate::analysis::CallTarget) - Call site and target information
//!
//! ## Native Code Analysis (x86)
//!
//! Feature-gated behind `#[cfg(feature = "x86")]`, this provides x86 native code analysis for
//! mixed-mode .NET assemblies that contain native method bodies (e.g., from obfuscators that
//! convert CIL to native code):
//!
//! - [`X86Function`](crate::analysis::X86Function) - Decoded x86 function with basic blocks and control flow
//! - [`X86DecodedInstruction`](crate::analysis::X86DecodedInstruction) - Decoded x86 instruction with operands
//! - [`X86ToSsaTranslator`](crate::analysis::X86ToSsaTranslator) - Translates x86 native code to SSA form
//! - Prologue/epilogue detection, traversal-based decoding, and native body size estimation
//!
//! Enable with `features = ["x86"]` in your `Cargo.toml`.
//!
//! # Usage Example
//!
//! ```no_run
//! use dotscope::analysis::{ControlFlowGraph, SsaConverter, ConstantPropagation};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from method body
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Convert to SSA form
//! let ssa = SsaConverter::build(&cfg, num_args, num_locals, resolver, Vec::new())?;
//!
//! // Run constant propagation
//! let sccp = ConstantPropagation::analyze(&ssa);
//!
//! // Analyze loops
//! for loop_info in cfg.loops() {
//!     println!("Loop at block {:?}, depth {}", loop_info.header, loop_info.depth);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

mod callgraph;
mod cfg;
mod dataflow;
mod ssa;
mod taint;

#[cfg(feature = "x86")]
mod x86;

// Re-export primary public types at module level
// Direct re-exports from analyssa for the formerly-shimmed analyses.
pub use analyssa::analysis::{algebraic::simplify_op, defuse::Location};
pub use callgraph::{
    CallGraph, CallGraphNode, CallGraphStats, CallResolver, CallSite, CallTarget, CallType,
    ResolverStats,
};
pub use cfg::{CfgEdge, CfgEdgeKind, ControlFlowGraph, LoopAnalyzer, LoopForest, LoopInfo};
pub use dataflow::{
    AnalysisResults, ConstantPropagation, DataFlowAnalysis, DataFlowSolver, Direction,
    LiveVariables, LivenessResult, ReachingDefinitions, ScalarValue, SccpResult,
};

/// CIL-defaulted alias of [`analyssa::analysis::algebraic::SimplifyResult`].
pub type SimplifyResult<T = ssa::CilTarget> = analyssa::analysis::algebraic::SimplifyResult<T>;
/// CIL-defaulted alias of [`analyssa::analysis::defuse::DefUseIndex`].
pub type DefUseIndex<T = ssa::CilTarget> = analyssa::analysis::defuse::DefUseIndex<T>;
/// CIL-defaulted alias of [`analyssa::analysis::range::ValueRange`].
pub type ValueRange = analyssa::analysis::range::ValueRange;
pub use analyssa::graph::NodeId;
// Re-export crate-internal types (used by other crate modules via crate::analysis::X)
#[cfg(feature = "compiler")]
#[allow(unused_imports)]
pub(crate) use cfg::SsaLoopAnalysis;
#[cfg(feature = "z3")]
pub use ssa::Z3Solver;
pub use ssa::{
    address, evaluate_const_op, pointsto, resolve_corelib_valuetype, AbstractValue,
    AddressTakenSlots, AliasResult, ArrayIndex, BinaryOpKind, BlockRange, BreakpointOp, CilTarget,
    CilVariableFacts, ClauseLayout, ClausePart, CmpKind, ConstEvaluator, ConstValue,
    ConstValueCilExt, Constraint, ControlFlow, DefSite, DispatcherPattern, EvaluatorMark,
    ExceptionBlocks, ExceptionTableError, ExecutionTrace, FieldRef, FloatBits, FloatFormat,
    HandlerKind, IndirectLocation, InstrId, LaidOutHandler, MemoryDefSite, MemoryLocation,
    MemoryOp, MemoryPhi, MemoryPhiOperand, MemorySsa, MemorySsaStats, MemoryVersion, MethodPurity,
    MethodRef, OpaquePredicatePattern, PathConstraint, PatternDetector, PhiAnalyzer, PhiNode,
    PhiOperand, PredicateResolution, ReturnInfo, RuntimeValueKind, SourceBlock, SsaBlock, SsaCfg,
    SsaConverter, SsaEvaluator, SsaExceptionHandler, SsaExceptionHandlerCilExt, SsaFunction,
    SsaFunctionBuilder, SsaFunctionCilExt, SsaFunctionSemanticsExt, SsaInstruction, SsaOp,
    SsaOpCilExt, SsaType, SsaVarId, SsaVariable, SsaVerifier, SymbolicEvaluator, SymbolicExpr,
    SymbolicOp, Target, TypeClass, TypeContext, TypeProvider, TypeRef, UnaryOpKind, UseSite,
    ValueResolver, VariableOrigin, VerifierError, VerifyLevel,
};
pub use taint::{
    cff_taint_config, find_token_dependencies, PhiTaintMode, TaintAnalysis, TaintConfig,
    TokenTaintBuilder,
};
#[cfg(feature = "x86")]
pub use x86::{
    is_signed_condition, is_unsigned_condition, is_zero_flag_only, x86_decode_all,
    x86_decode_single, x86_decode_traversal, x86_detect_epilogue, x86_detect_prologue,
    x86_native_body_size, X86BasicBlock, X86Condition, X86DecodedInstruction, X86EdgeKind,
    X86EpilogueInfo, X86Function, X86Instruction, X86Memory, X86Operand, X86PrologueInfo,
    X86PrologueKind, X86Register, X86ToSsaTranslator, X86TraversalDecodeResult,
};

#[cfg(test)]
mod tests {
    use analyssa::graph::NodeId;

    use crate::{
        analysis::{CfgEdgeKind, SsaFunction, SsaVerifier, VariableOrigin, VerifyLevel},
        assembly::InstructionAssembler,
        testkit::{build_cfg, build_ssa, TestTypeProvider},
    };

    /// Consolidated SSA validation - checks all standard SSA invariants.
    /// Call this instead of individual assert_* functions in most tests.
    ///
    /// The structural half is [`SsaVerifier`]'s, not re-implemented here. The
    /// two differ on more than effort: construction may renumber blocks - an
    /// entry a terminator names is split behind a fresh one - so a check that
    /// compares the result against the *pre-construction* control flow graph
    /// compares it against a numbering it no longer uses. The verifier reads
    /// the function that exists.
    fn assert_ssa_valid(ssa: &SsaFunction) {
        assert_has_arguments(ssa, ssa.num_args());
        assert_has_locals(ssa, ssa.num_locals());
        assert_single_assignment(ssa);
        let findings = SsaVerifier::new(ssa).verify(VerifyLevel::Standard);
        assert!(findings.is_empty(), "{findings:?}\n{ssa}");
    }

    /// Validates that the SSA function has all expected argument variables (version 0).
    fn assert_has_arguments(ssa: &SsaFunction, expected_args: usize) {
        let arg_vars: Vec<_> = ssa.argument_variables().collect();
        assert_eq!(
            arg_vars.len(),
            expected_args,
            "Expected {} argument variables (v0), found {}",
            expected_args,
            arg_vars.len()
        );

        for (i, var) in arg_vars.iter().enumerate() {
            assert_eq!(
                var.origin(),
                VariableOrigin::Argument(i as u16),
                "Argument {} has wrong origin: {:?}",
                i,
                var.origin()
            );
            assert_eq!(
                var.version(),
                0,
                "Argument {} should have version 0, got {}",
                i,
                var.version()
            );
        }
    }

    /// Validates that the SSA function has all expected local variables (version 0).
    fn assert_has_locals(ssa: &SsaFunction, expected_locals: usize) {
        let local_vars: Vec<_> = ssa.local_variables().collect();
        assert_eq!(
            local_vars.len(),
            expected_locals,
            "Expected {} local variables (v0), found {}",
            expected_locals,
            local_vars.len()
        );

        for (i, var) in local_vars.iter().enumerate() {
            assert_eq!(
                var.origin(),
                VariableOrigin::Local(i as u16),
                "Local {} has wrong origin: {:?}",
                i,
                var.origin()
            );
            assert_eq!(
                var.version(),
                0,
                "Local {} should have version 0, got {}",
                i,
                var.version()
            );
        }
    }

    /// Validates SSA invariant: each variable has exactly one definition.
    fn assert_single_assignment(ssa: &SsaFunction) {
        for var in ssa.variables() {
            let def_site = var.def_site();
            if !def_site.is_phi() {
                assert!(
                    def_site.block < ssa.block_count(),
                    "Variable {} defined in non-existent block {}",
                    var.id(),
                    def_site.block
                );
            }
        }
    }

    #[test]
    fn test_sequential_method() {
        // Simple method: return arg0 + arg1
        // int Add(int a, int b) { return a + b; }
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

        // CFG validation
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.entry(), NodeId::new(0));
        assert_eq!(cfg.exits().len(), 1);
        assert_eq!(cfg.exits()[0], NodeId::new(0));

        // SSA validation
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 1);
        assert_eq!(ssa.num_args(), 2);
        assert_eq!(ssa.num_locals(), 0);
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0);
        assert!(
            ssa.variable_count() >= 2,
            "Should have at least 2 variables (args)"
        );
    }

    #[test]
    fn test_nop_sequence() {
        // Method with multiple nops followed by ret
        // int Zero() { return 0; }
        let mut asm = InstructionAssembler::new();
        asm.nop()
            .unwrap()
            .nop()
            .unwrap()
            .nop()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 1);
        let block = cfg.block(cfg.entry()).unwrap();
        assert_eq!(block.instructions.len(), 5); // 3 nops + ldc.i4.0 + ret

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 1);
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0);
    }

    #[test]
    fn test_simple_if_then() {
        // if (arg0) { return 1; } return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 2);

        let edges: Vec<_> = cfg.outgoing_edges(cfg.entry()).collect();
        assert_eq!(edges.len(), 2);
        let edge_kinds: Vec<_> = edges.iter().map(|(_, _, e)| e.kind().clone()).collect();
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalTrue));
        assert!(edge_kinds.contains(&CfgEdgeKind::ConditionalFalse));

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 3);
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0); // No merge point
    }

    #[test]
    fn test_if_then_else_merge() {
        // if (arg0) { push 1; } else { push 0; } return top;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 4);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 1);

        let merge_block = cfg.exits()[0];
        let preds: Vec<_> = cfg.predecessors(merge_block).collect();
        assert_eq!(preds.len(), 2);

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 4);
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_nested_conditionals() {
        // if (a) { if (b) { return 1; } return 2; } return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("outer_else")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .brfalse_s("inner_else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("inner_else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap()
            .label("outer_else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 5);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exits().len(), 3);

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 5);
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0); // All paths return without merge
    }

    #[test]
    fn test_simple_while_loop() {
        // while (arg0 > 0) { arg0--; } return arg0;
        let mut asm = InstructionAssembler::new();
        asm.label("loop_header")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("loop_exit")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .starg_s(0)
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            .label("loop_exit")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert!(cfg.block_count() >= 2);
        assert!(cfg.has_loops());

        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, NodeId::new(0));
        assert!(!loops[0].latches.is_empty());

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_do_while_loop() {
        // do { arg0--; } while (arg0 > 0); return arg0;
        let mut asm = InstructionAssembler::new();
        asm.label("loop_body")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .starg_s(0)
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .bgt_s("loop_body")
            .unwrap()
            .ldarg_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert!(cfg.has_loops());
        assert_eq!(cfg.loops().len(), 1);
        assert_eq!(cfg.loops()[0].header, NodeId::new(0));

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_nested_loops() {
        // for (i = n; i > 0; i--) { for (j = m; j > 0; j--) { } }
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("outer_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("outer_exit")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .stloc_1()
            .unwrap()
            .label("inner_header")
            .unwrap()
            .ldloc_1()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ble_s("inner_exit")
            .unwrap()
            .ldloc_1()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_1()
            .unwrap()
            .br_s("inner_header")
            .unwrap()
            .label("inner_exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .sub()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("outer_header")
            .unwrap()
            .label("outer_exit")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert!(cfg.has_loops());
        let loops = cfg.loops();
        assert_eq!(loops.len(), 2);

        let outer_loop = loops.iter().find(|l| l.depth == 0).unwrap();
        let inner_loop = loops.iter().find(|l| l.depth == 1).unwrap();
        assert!(outer_loop.body.contains(inner_loop.header.index()));

        for node_idx in inner_loop.body.iter() {
            assert_eq!(
                cfg.innermost_loop(NodeId::new(node_idx)).unwrap().header,
                inner_loop.header
            );
        }

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 2)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_dominator_diamond() {
        // Diamond pattern: entry -> A, entry -> B, A -> merge, B -> merge
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("b_path")
            .unwrap()
            .nop()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("b_path")
            .unwrap()
            .nop()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 4);

        let entry = cfg.entry();
        for i in 0..cfg.block_count() {
            assert!(cfg.dominates(entry, NodeId::new(i)));
        }

        let merge = cfg
            .node_ids()
            .find(|&id| cfg.predecessors(id).count() == 2)
            .unwrap();
        assert_eq!(cfg.idom(merge), Some(entry));

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_eq!(ssa.block_count(), 4);
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_dominance_frontiers() {
        // Diamond pattern for phi node placement test
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let frontiers = cfg.dominance_frontiers();
        assert!(!frontiers.is_empty());
        assert!(frontiers[cfg.entry().index()].is_empty());

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_reverse_postorder_respects_edges() {
        // Build a simple diamond and verify RPO properties
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("b")
            .unwrap()
            .nop()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("b")
            .unwrap()
            .nop()
            .unwrap()
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let rpo = cfg.reverse_postorder();
        assert_eq!(rpo[0], cfg.entry());

        let entry_pos = rpo.iter().position(|&n| n == cfg.entry()).unwrap();
        for succ in cfg.successors(cfg.entry()) {
            let succ_pos = rpo.iter().position(|&n| n == succ).unwrap();
            assert!(
                entry_pos < succ_pos,
                "Entry should come before successors in RPO"
            );
        }

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_postorder_respects_edges() {
        // int Add(int a, int b) { return a + b; }
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
        let po = cfg.postorder();
        let rpo = cfg.reverse_postorder();

        assert_eq!(po.len(), rpo.len());
        for (i, node) in po.iter().enumerate() {
            assert_eq!(*node, rpo[rpo.len() - 1 - i]);
        }

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_unreachable_after_unconditional_branch() {
        // Code after unconditional branch should create separate block
        let mut asm = InstructionAssembler::new();
        asm.br_s("target")
            .unwrap()
            .nop()
            .unwrap() // "unreachable" but still encoded
            .label("target")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert!(cfg.block_count() >= 2);

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_multiple_returns() {
        // if (a) return 1; if (b) return 2; return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("check2")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("check2")
            .unwrap()
            .ldarg_1()
            .unwrap()
            .brfalse_s("default")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap()
            .label("default")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.exits().len(), 3);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0); // All paths return without merge
    }

    #[test]
    fn test_local_variable_store_load() {
        // int StoreLoad(int x) { int local = x; return local; }
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
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");
        assert_ssa_valid(&ssa);
        assert_eq!(ssa.phi_count(), 0);
    }

    #[test]
    fn test_conditional_local_assignment() {
        // int x = 0; if (cond) { x = 1; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .brfalse_s("skip")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("skip")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        assert_eq!(cfg.block_count(), 3);
        assert!(!cfg.has_loops());

        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction");
        assert_ssa_valid(&ssa);
    }

    #[test]
    fn test_dup_instruction() {
        // return x + x; using dup
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .dup()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
        assert!(
            ssa.variable_count() >= 1,
            "Should have at least the argument variable"
        );
    }

    #[test]
    fn test_comparison_instruction() {
        // return a < b;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .clt()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction");
        assert_ssa_valid(&ssa);
        assert!(
            ssa.variable_count() >= 2,
            "Should have at least the argument variables"
        );
    }
}

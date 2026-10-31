//! Control flow unflattening pass.
//!
//! This module recovers original control flow from flattened code, where
//! structured control flow (if/else, loops, switches) has been transformed
//! into a state machine with a central dispatcher.
//!
//! # Supported Patterns
//!
//! The unflattening algorithm is generic and handles various CFF implementations:
//!
//! - **ConfuserEx**: Switch-based dispatcher with arithmetic state encoding
//! - **OLLVM**: If-else chain dispatchers with XOR-based state
//! - **Custom**: Any pattern matching the structural CFF signature
//!
//! # Algorithm Overview
//!
//! 1. **Detection** ([`detection`]): Identify CFF dispatchers via structural graph
//!    analysis - dominance, predecessor counts, back-edge ratios, method coverage
//! 2. **State Variable Identification** ([`statevar`]): Trace from the switch
//!    instruction backwards through the SSA to find the PHI node carrying state
//! 3. **Dispatcher Classification** ([`dispatcher`]): Determine type (switch with
//!    optional XOR/modulo transform, if-else chain, computed jump)
//! 4. **Resolution** ([`resolve`]): Read the state travelling along each edge into
//!    the dispatcher out of the SSA phi graph, and rewire that edge straight to
//!    the block the dispatcher would have selected
//!
//! # Design Principles
//!
//! - **Structure-based detection**: Uses graph properties, not opcode patterns
//! - **Edges, not paths**: The state on an edge is a property of the edge, which
//!   SSA already records per predecessor. Recovering it costs one pass over the
//!   dispatcher's edges rather than an enumeration of execution paths, whose
//!   number grows exponentially with the method's conditionals
//! - **Graceful degradation**: An edge whose state cannot be determined keeps
//!   routing through the dispatcher, so partial recovery is always safe
//! - **Clean separation**: Each phase is isolated for testability

mod detection;
mod dispatcher;
mod resolve;
mod spill;
mod statevar;

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use dashmap::DashSet;
pub use detection::{CffDetector, CffPattern, EntryCondition, EntryPoint};
pub use dispatcher::Dispatcher;
use rayon::prelude::*;

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction},
    compiler::{CompilerContext, PassCapability, SsaPass},
    deobfuscation::{config::DetectionWeights, context::AnalysisContext},
    metadata::{token::Token, typesystem::PointerSize},
};

/// High-level API: unflatten a method by rewiring its dispatcher edges.
///
/// Detects every CFF dispatcher in the method - there may be independent ones
/// per exception handler region - resolves all of their edges against the
/// unmodified function, and applies the whole set at once so a single
/// `rebuild_ssa()` sees the final graph.
///
/// # Arguments
///
/// * `ssa` - The SSA function to unflatten.
/// * `config` - Detection thresholds and target pointer size.
///
/// # Returns
/// - `Some(ssa)` if at least one edge was rewired (patched clone)
/// - `None` if the method doesn't appear to be CFF-protected
pub fn unflatten(ssa: &SsaFunction, config: &UnflattenConfig) -> Option<SsaFunction> {
    let mut detector = CffDetector::with_config(ssa, config);
    let dispatchers: Vec<_> = detector
        .detect_all_dispatchers()
        .into_iter()
        .filter(|d| d.confidence >= config.min_confidence)
        .collect();

    unflatten_with_dispatchers(ssa, dispatchers, None)
}

/// Reads a callee's body out of the compiler context.
///
/// State folding may need the body of a method the encoding calls - ConfuserEx
/// computes the next state in an x86 helper, which this crate has already
/// translated to CIL by the time unflattening runs. The context is where those
/// bodies are, and cloning is what a borrow across the fold cannot be: the
/// bodies live behind a concurrent map that the fold cannot hold a reference
/// into while it walks.
struct ContextBodies<'a>(&'a CompilerContext);

impl resolve::CalleeBodies for ContextBodies<'_> {
    fn body(&self, token: Token) -> Option<SsaFunction> {
        self.0.with_ssa(token, Clone::clone)
    }
}

/// Unflatten a method using pre-detected dispatchers.
///
/// Like [`unflatten`], but skips the detection phase and uses the provided
/// dispatchers directly. This is used when the [`GenericFlattening`] technique
/// has already run [`CffDetector`] during `detect_ssa()` and stored the results
/// in [`FlatteningFindings`].
///
/// [`GenericFlattening`]: crate::deobfuscation::techniques::generic::GenericFlattening
/// [`FlatteningFindings`]: crate::deobfuscation::techniques::generic::flattening::FlatteningFindings
///
/// # Arguments
///
/// * `ssa` - The SSA function to unflatten.
/// * `dispatchers` - Pre-detected dispatchers (already confidence-filtered).
///
/// # Returns
/// - `Some(ssa)` if at least one edge was rewired (patched clone)
/// - `None` if no dispatchers were given or none of their edges resolved
pub fn unflatten_with_dispatchers(
    ssa: &SsaFunction,
    dispatchers: Vec<Dispatcher>,
    callees: Option<&(dyn resolve::CalleeBodies + Sync)>,
) -> Option<SsaFunction> {
    if dispatchers.is_empty() {
        return None;
    }

    // Resolve each dispatcher's edges against the unmodified function. This is
    // a pure read, so the dispatchers are independent and can run in parallel.
    let per_dispatcher: Vec<Vec<resolve::Rewire>> = dispatchers
        .par_iter()
        .map(|d| {
            let (rewires, stats) = resolve::resolve_dispatch_edges(
                ssa,
                d,
                callees.map(|c| c as &dyn resolve::CalleeBodies),
            );
            log::debug!(
                "CFF resolve b{}: {} edge(s) resolved, {} unresolved, {} conflicting \
                 (table {} incl. {} overflow)",
                d.block,
                stats.resolved,
                stats.unresolved,
                stats.conflicts,
                stats.table_size,
                stats.overflow_entries
            );
            if stats.unresolved > 0 {
                log::debug!(
                    "CFF reasons b{}: no_target={} not_constant={} impure_chain={}",
                    d.block,
                    stats.reasons.no_target,
                    stats.reasons.not_constant,
                    stats.reasons.impure_chain
                );
            }
            rewires
        })
        .collect();

    let (rewires, conflicts) = resolve::merge_rewires(per_dispatcher);
    if conflicts > 0 {
        log::debug!("CFF resolve: {conflicts} edge(s) dropped across dispatchers");
    }
    if rewires.is_empty() {
        return None;
    }

    // Give every cross-block value a storage location before the CFG changes.
    //
    // Rewiring replaces `case -> dispatcher -> next` with `case -> next`, so a
    // value that used to be merged by a phi at the dispatcher now arrives along
    // an edge no phi ever described. `rebuild_ssa` can reconstruct such a value
    // only if it has an identity independent of control flow - a local slot.
    // Promoting first is what makes the rebuild well-defined for the rewired
    // graph.
    let mut patched = ssa.clone();
    let dispatcher_blocks: BTreeSet<usize> = dispatchers.iter().map(|d| d.block).collect();
    let spilled = spill::promote_cross_block_values(&mut patched, &dispatcher_blocks);
    if spilled > 0 {
        log::debug!("Promoted {spilled} cross-block value(s) to locals before unflattening");
    }

    let applied = resolve::apply_rewires(&mut patched, &rewires, &dispatcher_blocks);
    if applied == 0 {
        return None;
    }
    let cleared = resolve::clear_unreachable(&mut patched);
    log::debug!("CFF: rewired {applied} edge(s) past the dispatcher, {cleared} block(s) now dead");

    // Dispatchers whose edges did not all resolve keep their remaining
    // predecessors and stay in the graph - partial recovery, not corruption.
    // The state constants and the dispatcher itself become unreachable once
    // every edge is rewired, and the ordinary dead-code passes remove them.
    Some(patched)
}

/// Configuration for the CFF reconstruction pass.
#[derive(Debug, Clone)]
pub struct UnflattenConfig {
    /// Minimum confidence score to attempt unflattening (0.0 - 1.0).
    ///
    /// Detection assigns confidence based on how strongly the method
    /// matches CFF patterns. Lower values catch more CFF but may
    /// produce false positives.
    pub min_confidence: f64,

    /// Maximum BFS depth for back-edge transitive reachability check.
    ///
    /// Used in confidence scoring to determine if case blocks can
    /// transitively reach the dispatcher through intermediate blocks.
    pub max_backedge_depth: usize,

    /// Confidence scoring weights for CFF dispatcher detection.
    pub confidence_weights: DetectionWeights,

    /// Target pointer size for SSA evaluation.
    ///
    /// Derived from the PE header. Used when detection evaluates the
    /// dispatcher's initial state.
    pub pointer_size: PointerSize,
}

impl Default for UnflattenConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.6,
            pointer_size: PointerSize::Bit32,
            max_backedge_depth: 10,
            confidence_weights: DetectionWeights::default(),
        }
    }
}

impl UnflattenConfig {
    /// Creates a configuration optimized for ConfuserEx samples.
    ///
    /// ConfuserEx's arithmetic encoding is always resolvable, so detection can
    /// accept a lower confidence without risking wasted work.
    ///
    /// # Returns
    ///
    /// An `UnflattenConfig` with a reduced confidence threshold.
    #[must_use]
    pub fn confuserex() -> Self {
        Self {
            min_confidence: 0.5,
            ..Self::default()
        }
    }

    /// Creates a configuration for aggressive analysis.
    ///
    /// Useful for heavily obfuscated code where detection may have lower
    /// confidence. Accepts weaker matches and looks further for back edges, at
    /// the cost of attempting more methods.
    ///
    /// # Returns
    ///
    /// An `UnflattenConfig` with a lower confidence threshold.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            min_confidence: 0.4,
            max_backedge_depth: 15,
            ..Self::default()
        }
    }
}

/// Control flow flattening reconstruction pass.
///
/// This pass detects and reverses control flow flattening, a common
/// obfuscation technique that converts structured control flow into
/// a state machine.
///
/// When detection-phase findings are available, the pass uses pre-computed
/// dispatchers directly instead of re-running detection. This avoids duplicate
/// structural analysis (dominance, SCCs, confidence scoring) for methods
/// already analyzed during the detection phase's SSA pass.
///
/// The pass itself takes no configuration: it consumes dispatchers the detection
/// phase already found and scored, and resolving their edges has no thresholds
/// to tune. [`UnflattenConfig`] belongs to detection, which is where it is now
/// applied.
#[derive(Default)]
pub struct CffReconstructionPass {
    /// Successfully unflattened dispatcher methods (shared with deob engine).
    unflattened_dispatchers: Arc<DashSet<Token>>,
    /// All detected dispatcher methods (shared with deob engine).
    dispatchers: Arc<DashSet<Token>>,
    /// Pre-detected dispatchers from the detection phase (method → dispatchers).
    /// When populated, `run_on_method` uses these instead of re-running detection.
    pre_detected: HashMap<Token, Vec<Dispatcher>>,
}

impl CffReconstructionPass {
    /// Creates a new CFF reconstruction pass from an analysis context.
    ///
    /// Captures shared references to the context's dispatcher sets so the engine
    /// can inspect which dispatchers were found and unflattened after the pipeline.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context providing shared dispatcher tracking sets.
    ///
    /// # Returns
    ///
    /// A new `CffReconstructionPass` ready for pipeline execution.
    #[must_use]
    pub fn new(ctx: &AnalysisContext) -> Self {
        Self {
            unflattened_dispatchers: Arc::clone(&ctx.unflattened_dispatchers),
            dispatchers: Arc::clone(&ctx.dispatchers),
            pre_detected: HashMap::new(),
        }
    }

    /// Sets the pre-detected dispatchers from the detection phase.
    ///
    /// When set, `run_on_method` uses these dispatchers directly instead of
    /// re-running the internal CFF detector, avoiding duplicate work.
    ///
    /// # Arguments
    ///
    /// * `pre_detected` - Map from method token to pre-detected dispatchers.
    #[must_use]
    pub fn with_pre_detected(mut self, pre_detected: HashMap<Token, Vec<Dispatcher>>) -> Self {
        self.pre_detected = pre_detected;
        self
    }

    /// Creates a pass with default configuration and standalone state.
    ///
    /// Suitable for testing or standalone usage without an analysis context.
    /// The pass uses its own internal dispatcher tracking sets rather than
    /// sharing them with an [`AnalysisContext`].
    ///
    /// # Returns
    ///
    /// A new `CffReconstructionPass` with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::default()
    }
}

impl SsaPass<CilTarget, CompilerContext> for CffReconstructionPass {
    fn name(&self) -> &'static str {
        "cff-reconstruction"
    }

    fn description(&self) -> &'static str {
        "Recovers original control flow from flattened state machine patterns"
    }

    fn repairs_ssa(&self) -> bool {
        true
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::RestoredControlFlow]
    }

    fn requires(&self) -> &[PassCapability] {
        &[PassCapability::ResolvedStaticFields]
    }

    // Folding a state can read a callee's body out of the store (see
    // `ContextBodies`). Without this the scheduler takes each method out while
    // its pass runs, so a callee being unflattened on another thread at that
    // moment reads as missing, and whether a dispatcher resolved depended on
    // thread timing.
    fn reads_peer_ssa(&self) -> bool {
        true
    }

    fn should_run(&self, method: &MethodRef, _host: &CompilerContext) -> bool {
        // Skip methods already unflattened and also skip methods that were never
        // detected as having dispatchers.
        !self.unflattened_dispatchers.contains(&method.0)
            && self
                .pre_detected
                .get(&method.0)
                .is_some_and(|d| !d.is_empty())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let ctx = host;
        let method_token = method.0;

        // Detection ran in its own phase; re-read each dispatcher out of the
        // function as it stands now. See `Dispatcher::refresh` for why nothing
        // recorded as an index survives the passes that run in between.
        let detected = self.pre_detected.get(&method_token);
        let dispatchers: Vec<Dispatcher> = detected
            .map(|pre| pre.iter().filter_map(|d| d.refresh(ssa)).collect())
            .unwrap_or_default();

        // A dispatcher that no longer resolves is not an error - an earlier
        // pass may legitimately have folded the dispatch away - but it is the
        // difference between unflattening a method and silently leaving it
        // flattened, and nothing else reports it. The counts are what say which
        // of the two happened.
        let detected_count = detected.map_or(0, Vec::len);
        if detected_count != dispatchers.len() {
            log::debug!(
                "CFF {:08x}: {} of {detected_count} dispatcher(s) still resolve;                  the rest were folded away before this pass ran",
                method_token.value(),
                dispatchers.len(),
            );
        }

        let started = std::time::Instant::now();
        let bodies = ContextBodies(ctx);
        match unflatten_with_dispatchers(ssa, dispatchers, Some(&bodies)) {
            Some(mut patched) => {
                // Rewiring can leave a value defined on a path the bypass no
                // longer takes. The guards in `resolve` exist to prevent that,
                // and `rebuild_ssa` is what proves it: it re-derives the phi
                // graph and rejects a definition that no longer reaches its
                // uses. Treat a rejection as "this method cannot be unflattened
                // safely" and leave it flattened - an unrecovered method is a
                // gap in the analysis, whereas propagating the error abandons
                // every remaining method in the assembly as well.
                if let Err(error) = patched.rebuild_ssa() {
                    log::warn!(
                        "CFF {:08x}: rewired form failed SSA validation ({error}); \
                         leaving the method flattened",
                        method_token.value()
                    );
                    return Ok(false);
                }
                log::debug!(
                    "CFF {:08x}: {} block(s), {}ms",
                    method_token.value(),
                    patched.blocks().len(),
                    started.elapsed().as_millis()
                );

                *ssa = patched;

                // Mark as successfully unflattened (kept for reporting)
                self.unflattened_dispatchers.insert(method_token);
                self.dispatchers.insert(method_token);
                ctx.no_inline.insert(method_token);

                // Clear any cached known values since SSA changed
                ctx.clear_known_values(method_token);

                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};

    use super::*;
    use crate::{
        analysis::{
            CmpKind, ConstValue, DefSite, PhiNode, PhiOperand, SsaBlock, SsaFunction,
            SsaInstruction, SsaOp, SsaType, SsaVarId, VariableOrigin,
        },
        assembly::InstructionAssembler,
        deobfuscation::{
            passes::unflattening::{detection::CffDetector, dispatcher::Dispatcher},
            DetectionWeights, EngineConfig,
        },
        metadata::token::Token,
        testkit::{
            build_cfg, build_ssa, engine, engine_with,
            equivalence::{compare, Equivalence},
            fixture, TestTypeProvider,
        },
        CilObject,
    };

    fn create_dispatcher_ssa() -> (SsaFunction, Dispatcher) {
        let mut ssa = SsaFunction::new(0, 1);
        let state_var = SsaVarId::from_index(0);
        let switch_var = SsaVarId::from_index(1);

        // B0: entry -> jump to dispatcher
        let mut b0 = SsaBlock::new(0);
        b0.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
        ssa.add_block(b0);

        // B1: dispatcher with switch
        let mut b1 = SsaBlock::new(1);
        let mut phi = PhiNode::new(state_var, VariableOrigin::Local(0));
        phi.add_operand(PhiOperand::new(state_var, 0));
        b1.add_phi(phi);
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Copy {
            dest: switch_var,
            src: state_var,
        }));
        b1.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
            value: switch_var,
            targets: vec![2, 3],
            default: 4,
        }));
        ssa.add_block(b1);

        // B2, B3: case blocks that jump back to dispatcher
        for i in 2..=3 {
            let mut b = SsaBlock::new(i);
            b.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: 1 }));
            ssa.add_block(b);
        }

        // B4: default/exit
        let mut b4 = SsaBlock::new(4);
        b4.add_instruction(SsaInstruction::synthetic(SsaOp::Return { value: None }));
        ssa.add_block(b4);

        let dispatcher = Dispatcher::new(1, switch_var, vec![2, 3], 4)
            .with_state_phi(state_var)
            .with_confidence(1.0);

        (ssa, dispatcher)
    }

    #[test]
    fn test_detect_dispatcher_finds_switch_with_back_edge() {
        let (ssa, _) = create_dispatcher_ssa();

        // Use CffDetector to detect the dispatcher
        let mut detector = CffDetector::new(&ssa);
        let detected = detector.detect_best();

        assert!(detected.is_some());
        let candidate = detected.unwrap();
        assert_eq!(candidate.block, 1);
    }

    /// Check if SSA has a switch instruction (indicates CFF dispatcher).
    fn has_switch(ssa: &SsaFunction) -> bool {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Switch { .. }) {
                    return true;
                }
            }
        }
        false
    }

    /// Count switch instructions in SSA.
    fn count_switches(ssa: &SsaFunction) -> usize {
        let mut count = 0;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if matches!(instr.op(), SsaOp::Switch { .. }) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Run the full deobfuscation pipeline on an SSA function.
    ///
    /// This uses `DeobfuscationEngine::process_ssa` to run all passes
    /// including unflattening and DCE in the proper order.
    /// The assembly SSA built here is processed against, loaded once.
    static TEST_ASSEMBLY: LazyLock<Arc<CilObject>> = LazyLock::new(|| {
        Arc::new(
            CilObject::from_path(fixture("crafted_2.exe")).expect("Failed to load test assembly"),
        )
    });

    fn run_full_deobfuscation(ssa: &mut SsaFunction) -> crate::Result<()> {
        let token = Token::new(0x06000001); // Synthetic method token
        engine().process_ssa(&TEST_ASSEMBLY, ssa, token)?;
        Ok(())
    }

    /// The flattened method of [`test_unflatten_simple_cff_pattern`]: a dispatcher computing
    /// `(state ^ 0) % 3` and switching over three cases that store 1, 2 and 3 in local 0.
    fn simple_cff() -> crate::Result<SsaFunction> {
        let mut asm = InstructionAssembler::new();
        asm
            // Entry block: push initial state (0), go to dispatcher
            .ldc_i4(0)? // state = 0 -> case 0
            .br("dispatcher")?
            // Dispatcher block
            .label("dispatcher")?
            .dup()? // duplicate state for switch
            .stloc_s(2)? // save to local 2
            .ldc_i4(0)? // XOR key = 0 (identity)
            .xor()?
            .ldc_i4(3)? // MOD 3
            .rem_un()?
            .switch(&["case0", "case1", "case2"])?
            .br("exit")? // default -> exit
            // Case 0: set local0 = 1, state = 1, jump back
            .label("case0")?
            .ldc_i4(1)?
            .stloc_0()?
            .ldc_i4(1)? // next state = 1 -> case 1
            .br("dispatcher")?
            // Case 1: set local0 = 2, state = 2, jump back
            .label("case1")?
            .ldc_i4(2)?
            .stloc_0()?
            .ldc_i4(2)? // next state = 2 -> case 2
            .br("dispatcher")?
            // Case 2: set local0 = 3, go to exit
            .label("case2")?
            .ldc_i4(3)?
            .stloc_0()?
            .br("exit")?
            // Exit
            .label("exit")?
            .ret()?;

        let (_, cfg) = build_cfg(asm)?;
        build_ssa(&cfg, &TestTypeProvider::all_i32(0, 3))
    }

    /// A flattened loop whose case updates `lower` and branches to pick the next case; the
    /// branches meet at a merge that decodes the next state and jumps to the dispatcher, and
    /// the next cases read `lower`. After copy propagation the case writes `lower` nowhere:
    /// its new value reaches the dispatcher only as the operand `lower`'s phi takes on the
    /// merge's edge, either computed before the branch (`t = a + 1`) or, when each branch
    /// computes its own, merged by a phi in the merge itself.
    ///
    /// ```text
    /// B0: lower = 0; s = 0; jump B1
    /// B1: lower' = phi(lower B0, t B6); s' = phi(s B0, next B6); switch s' [B3, B7, B8] B2
    /// B3: t = a + 1; branch t > 5 ? B5 : B4
    /// B4: k = 6; jump B6          B5: k = 5; jump B6
    /// B6: p = phi(k B4, k B5); next = p ^ 7; jump B1
    /// B7: ret lower'              B8: ret lower' + 100          B2: ret -1
    /// ```
    ///
    /// With `merged`, B4 and B5 each compute `t` (`a + 2`, `a + 3`) and B6 joins them in a phi.
    fn skipped_merge_cff(merged: bool) -> (SsaFunction, Dispatcher) {
        let mut ssa = SsaFunction::new(1, 1);
        for id in 0..9 {
            ssa.add_block(SsaBlock::new(id));
        }
        let var = |ssa: &mut SsaFunction, origin, site| {
            ssa.create_variable(origin, 0, site, SsaType::I32)
        };
        let argument = var(&mut ssa, VariableOrigin::Argument(0), DefSite::entry());
        let local = VariableOrigin::Local(0);
        let temp = VariableOrigin::Phi;
        let lower = var(&mut ssa, local, DefSite::instruction(0, 0));
        let state = var(&mut ssa, temp, DefSite::instruction(0, 1));
        let lower_merged = var(&mut ssa, local, DefSite::phi(1));
        let state_merged = var(&mut ssa, temp, DefSite::phi(1));
        let one = var(&mut ssa, temp, DefSite::instruction(3, 0));
        let computed = var(&mut ssa, temp, DefSite::instruction(3, 1));
        let five = var(&mut ssa, temp, DefSite::instruction(3, 2));
        let small = var(&mut ssa, temp, DefSite::instruction(4, 0));
        let big = var(&mut ssa, temp, DefSite::instruction(5, 0));
        let encoded = var(&mut ssa, temp, DefSite::phi(6));
        let key = var(&mut ssa, temp, DefSite::instruction(6, 0));
        let next = var(&mut ssa, temp, DefSite::instruction(6, 1));
        let hundred = var(&mut ssa, temp, DefSite::instruction(8, 0));
        let sum = var(&mut ssa, temp, DefSite::instruction(8, 1));
        let minus_one = var(&mut ssa, temp, DefSite::instruction(2, 0));
        ssa.set_rename_group(argument, 0);
        for local_version in [lower, lower_merged] {
            ssa.set_rename_group(local_version, 1);
        }

        let constant = |dest, value| SsaOp::Const {
            dest,
            value: ConstValue::I32(value),
        };
        let plus = |dest, left, right| SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        };
        let fill = |ssa: &mut SsaFunction, id: usize, ops: Vec<SsaOp>| {
            if let Some(block) = ssa.block_mut(id) {
                for op in ops {
                    block.add_instruction(SsaInstruction::synthetic(op));
                }
            }
        };
        let phi = |result, origin, operands: &[(SsaVarId, usize)]| {
            let mut phi = PhiNode::new(result, origin);
            for &(value, predecessor) in operands {
                phi.add_operand(PhiOperand::new(value, predecessor));
            }
            phi
        };

        fill(
            &mut ssa,
            0,
            vec![
                constant(lower, 0),
                constant(state, 0),
                SsaOp::Jump { target: 1 },
            ],
        );
        fill(
            &mut ssa,
            1,
            vec![SsaOp::Switch {
                value: state_merged,
                targets: vec![3, 7, 8],
                default: 2,
            }],
        );
        fill(
            &mut ssa,
            2,
            vec![
                constant(minus_one, -1),
                SsaOp::Return {
                    value: Some(minus_one),
                },
            ],
        );
        fill(
            &mut ssa,
            3,
            vec![
                constant(one, 1),
                plus(computed, argument, one),
                constant(five, 5),
                SsaOp::BranchCmp {
                    left: computed,
                    right: five,
                    cmp: CmpKind::Gt,
                    unsigned: false,
                    true_target: 5,
                    false_target: 4,
                },
            ],
        );
        // What `lower` takes on the merge's edge: the value computed before the branch, or
        // the phi joining what each branch computed
        let update = if merged {
            let joined = var(&mut ssa, temp, DefSite::phi(6));
            let (two, three) = (
                var(&mut ssa, temp, DefSite::instruction(4, 1)),
                var(&mut ssa, temp, DefSite::instruction(5, 1)),
            );
            let (in_small, in_big) = (
                var(&mut ssa, temp, DefSite::instruction(4, 2)),
                var(&mut ssa, temp, DefSite::instruction(5, 2)),
            );
            fill(
                &mut ssa,
                4,
                vec![
                    constant(small, 1 ^ 7),
                    constant(two, 2),
                    plus(in_small, argument, two),
                    SsaOp::Jump { target: 6 },
                ],
            );
            fill(
                &mut ssa,
                5,
                vec![
                    constant(big, 2 ^ 7),
                    constant(three, 3),
                    plus(in_big, argument, three),
                    SsaOp::Jump { target: 6 },
                ],
            );
            if let Some(block) = ssa.block_mut(6) {
                block.add_phi(phi(joined, temp, &[(in_small, 4), (in_big, 5)]));
            }
            joined
        } else {
            fill(
                &mut ssa,
                4,
                vec![constant(small, 1 ^ 7), SsaOp::Jump { target: 6 }],
            );
            fill(
                &mut ssa,
                5,
                vec![constant(big, 2 ^ 7), SsaOp::Jump { target: 6 }],
            );
            computed
        };
        fill(
            &mut ssa,
            6,
            vec![
                constant(key, 7),
                SsaOp::Xor {
                    dest: next,
                    left: encoded,
                    right: key,
                    flags: None,
                },
                SsaOp::Jump { target: 1 },
            ],
        );
        fill(
            &mut ssa,
            7,
            vec![SsaOp::Return {
                value: Some(lower_merged),
            }],
        );
        fill(
            &mut ssa,
            8,
            vec![
                constant(hundred, 100),
                plus(sum, lower_merged, hundred),
                SsaOp::Return { value: Some(sum) },
            ],
        );
        if let Some(block) = ssa.block_mut(1) {
            block.add_phi(phi(lower_merged, local, &[(lower, 0), (update, 6)]));
            block.add_phi(phi(state_merged, temp, &[(state, 0), (next, 6)]));
        }
        if let Some(block) = ssa.block_mut(6) {
            block.add_phi(phi(encoded, temp, &[(small, 4), (big, 5)]));
        }
        ssa.recompute_uses();
        let dispatcher =
            Dispatcher::new(1, state_merged, vec![3, 7, 8], 2).with_state_phi(state_merged);
        (ssa, dispatcher)
    }

    /// Unflattening rewires each branch straight to its next case, skipping the merge, and
    /// used to skip the update of `lower` with it: the next case read the value `lower` had
    /// on entry (ConfuserEx's `DemoCharOperations` counted no vowels). Both ways the update
    /// can cross the merge are carried onto the rewired edges.
    #[test]
    fn a_value_updated_on_a_skipped_merge_reaches_the_next_case() {
        for merged in [false, true] {
            let (ssa, dispatcher) = skipped_merge_cff(merged);
            let mut unflattened = unflatten_with_dispatchers(&ssa, vec![dispatcher], None)
                .expect("the dispatch resolves");
            unflattened.rebuild_ssa().unwrap();

            assert!(
                unflattened
                    .blocks()
                    .iter()
                    .all(|block| !matches!(block.last_op(), Some(SsaOp::Switch { .. }))),
                "the dispatcher is gone:\n{unflattened}"
            );
            let verdict = compare(&ssa, &unflattened);
            assert!(
                matches!(verdict, Equivalence::Equivalent { conclusive, .. } if conclusive > 0),
                "merged={merged}: {verdict:?}\n{unflattened}"
            );
        }
    }

    /// `process_ssa` detects flattening by the engine's configuration: with every detection
    /// weight at zero no dispatcher reaches the confidence threshold, so the switch stays.
    #[test]
    fn process_ssa_detects_flattening_by_the_engine_s_configuration() -> crate::Result<()> {
        let mut ssa = simple_cff()?;
        let mut config = EngineConfig::default();
        config.unflattening.confidence_weights = DetectionWeights {
            case_count_base: 0.0,
            case_count_bonus: 0.0,
            state_variable: 0.0,
            state_update_coverage: 0.0,
            predecessor_ratio: 0.0,
            back_edge_ratio: 0.0,
            exit_blocks: 0.0,
            switch_bonus: 0.0,
            modulo_bonus: 0.0,
            dominance_ratio: 0.0,
            method_coverage: 0.0,
        };
        engine_with(config).process_ssa(&TEST_ASSEMBLY, &mut ssa, Token::new(0x0600_0001))?;
        assert!(
            has_switch(&ssa),
            "no dispatcher is detected, so none is removed:\n{ssa}"
        );
        Ok(())
    }

    /// Test: Simple CFF pattern with 3 cases.
    ///
    /// This is a simplified version of CFF that has:
    /// - Entry block that initializes state and jumps to dispatcher
    /// - Dispatcher that computes (state ^ XOR) % 3 and switches
    /// - 3 case blocks that update state and jump back to dispatcher
    /// - Exit via default case
    ///
    /// Original semantics: sets local0 = 1, then = 2, then = 3, then returns.
    #[test]
    fn test_unflatten_simple_cff_pattern() -> crate::Result<()> {
        // Build CFF-obfuscated bytecode:
        //
        // Entry (block 0):
        //   ldc.i4 INIT_STATE  ; initial state that maps to case 0
        //   br dispatcher
        //
        // Dispatcher (block 1):
        //   dup
        //   stloc.2            ; save state in local2
        //   ldc.i4 XOR_KEY
        //   xor
        //   ldc.i4.3
        //   rem.un
        //   switch (case0, case1, case2)
        //   br exit            ; default -> exit
        //
        // Case 0: ldc.i4.1, stloc.0, compute_next_state, br dispatcher
        // Case 1: ldc.i4.2, stloc.0, compute_next_state, br dispatcher
        // Case 2: ldc.i4.3, stloc.0, br exit
        //
        // Exit: ret

        // For simplicity, use XOR_KEY = 0 so state directly maps to case index
        // This means: state 0 -> case 0, state 1 -> case 1, state 2 -> case 2
        // After unflattening, the flow should be: case0 -> case1 -> case2 -> exit

        let mut ssa = simple_cff()?;

        // Verify dispatcher is detected
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert!(initial_switch_count > 0, "Should have at least one switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoLoop - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoLoop (int32 iterations)
    /// .locals init (int32 V_0, int32 V_1, unsigned int32 V_2)
    ///
    /// Key structure:
    /// - IL_0000-IL_0001: sum = 0
    /// - IL_0002: ldc.i4 -781784372 (init state, also case5 target)
    /// - IL_0007: ldc.i4 -576502913 (XOR key - cases jump HERE)
    /// - IL_000c-IL_0011: xor, dup, stloc.2, ldc.i4.7, rem.un, switch
    /// - Cases compute next state and jump back to IL_0007
    #[test]
    fn test_unflatten_demoloop_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldc.i4.0
        // IL_0001:  stloc.0
        // IL_0002:  ldc.i4 -781784372      <- case5 jumps here
        // IL_0007:  ldc.i4 -576502913      <- dispatcher entry (cases jump here)
        // IL_000c:  xor
        // IL_000d:  dup
        // IL_000e:  stloc.2
        // IL_000f:  ldc.i4.7
        // IL_0010:  rem.un
        // IL_0011:  switch (case0, case1, case2, case3, exit, init_state, case6)
        // IL_0032:  br.s exit              (default)
        //
        // case0 (IL_0034): i++, state update, br IL_0007
        // case1 (IL_0052): i=1, state update, br IL_0007
        // case2 (IL_0078): output, state update, br IL_0007
        // case3 (IL_0047): sum+=i, new state, br IL_0007
        // case5 (IL_0002): init_state - falls through to IL_0007
        // case6 (IL_0063): loop condition, br IL_0007

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldc.i4.0
            // IL_0001: stloc.0
            .ldc_i4_0()?
            .stloc_0()?
            // IL_0002: ldc.i4 -781784372 (init_state - case5 target)
            // Falls through to dispatcher_entry
            .label("init_state")?
            .ldc_i4(-781784372_i32)?
            // IL_0007: ldc.i4 -576502913 (dispatcher entry - cases jump here)
            // IL_000c: xor
            // IL_000d: dup
            // IL_000e: stloc.2
            // IL_000f: ldc.i4.7
            // IL_0010: rem.un
            // IL_0011: switch (...)
            .label("dispatcher_entry")?
            .ldc_i4(-576502913_i32)?
            .xor()?
            .dup()?
            .stloc_s(2)?
            .ldc_i4(7)?
            .rem_un()?
            .switch(&[
                "case0",
                "case1",
                "case2",
                "case3",
                "exit",
                "init_state",
                "case6",
            ])?
            // IL_0032: br.s exit (default)
            .br_s("exit")?
            // IL_0034: case0 - i++, state update
            // ldloc.1, ldc.i4.1, add, stloc.1
            // ldloc.2, ldc.i4 1975223132, mul, ldc.i4 483589312, xor
            // br.s IL_0007
            .label("case0")?
            .ldloc_1()?
            .ldc_i4_1()?
            .add()?
            .stloc_1()?
            .ldloc_s(2)?
            .ldc_i4(1975223132_i32)?
            .mul()?
            .ldc_i4(483589312_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0047: case3 - sum += i
            // ldloc.0, ldloc.1, add, stloc.0
            // ldc.i4 -730624750
            // br.s IL_0007
            .label("case3")?
            .ldloc_0()?
            .ldloc_1()?
            .add()?
            .stloc_0()?
            .ldc_i4(-730624750_i32)?
            .br_s("dispatcher_entry")?
            // IL_0052: case1 - i = 1, state update
            // ldc.i4.1, stloc.1
            // ldloc.2, ldc.i4 -1381170983, mul, ldc.i4 -1625566633, xor
            // br.s IL_0007
            .label("case1")?
            .ldc_i4_1()?
            .stloc_1()?
            .ldloc_s(2)?
            .ldc_i4(-1381170983_i32)?
            .mul()?
            .ldc_i4(-1625566633_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0063: case6 - loop condition
            // ldloc.1, ldarg.1, bgt.s IL_006f
            // ldc.i4 -654475495, dup, br.s IL_0075
            // IL_006f: ldc.i4 -1309138752, dup
            // IL_0075: pop, br.s IL_0007
            .label("case6")?
            .ldloc_1()?
            .ldarg_1()?
            .bgt_s("case6_false")?
            .ldc_i4(-654475495_i32)?
            .dup()?
            .br_s("case6_merge")?
            .label("case6_false")?
            .ldc_i4(-1309138752_i32)?
            .dup()?
            .label("case6_merge")?
            .pop()?
            .br_s("dispatcher_entry")?
            // IL_0078: case2 - output (using nop as placeholder for ldstr/call)
            // In real IL: ldstr, ldarg.1, box, ldloc.0, box, call Format, call WriteLine
            // ldloc.2, ldc.i4 -1166059892, mul, ldc.i4 -15245519, xor
            // br IL_0007
            .label("case2")?
            .nop()? // placeholder for output operations
            .ldloc_s(2)?
            .ldc_i4(-1166059892_i32)?
            .mul()?
            .ldc_i4(-15245519_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00a5: exit - ret
            .label("exit")?
            .ret()?;

        let (_, cfg) = build_cfg(asm)?;
        // args: this, iterations
        let mut ssa = build_ssa(
            &cfg,
            &TestTypeProvider::all_i32(2, 3).arg(0, SsaType::Object),
        )?;

        // Verify initial state - should have 1 CFF dispatcher switch
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(initial_switch_count, 1, "Should have exactly 1 CFF switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoIfElse - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoIfElse (int32 value)
    /// .locals init (string V_0, unsigned int32 V_1)
    ///
    /// Key structure:
    /// - IL_0000-IL_0002: ldarg.1, ldc.i4.0, bge.s IL_0063 (check_zero)
    /// - IL_0004: ldc.i4 -1433646196 (init state for negative, case10 target)
    /// - IL_0009: ldc.i4 -2107303682 (XOR key - cases jump HERE)
    /// - IL_000e-IL_0014: xor, dup, stloc.1, ldc.i4.s 12, rem.un, switch
    /// - switch targets: output, check_zero, negative, zero, medium, exit_state, large, small, done, check_small, init_state, check_medium
    #[test]
    fn test_unflatten_demoifelse_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldarg.1
        // IL_0001:  ldc.i4.0
        // IL_0002:  bge.s IL_0063           (check_zero)
        //
        // IL_0004:  ldc.i4 -1433646196      <- init_state (case10 target)
        // IL_0009:  ldc.i4 -2107303682      <- dispatcher entry (cases jump here)
        // IL_000e:  xor
        // IL_000f:  dup
        // IL_0010:  stloc.1
        // IL_0011:  ldc.i4.s 0x0c           (12)
        // IL_0013:  rem.un
        // IL_0014:  switch (12 targets)
        // IL_0049:  br IL_0133              (default -> done)
        //
        // Cases jump back to IL_0009 (dispatcher_entry)

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldarg.1
            // IL_0001: ldc.i4.0
            // IL_0002: bge.s IL_0063 (check_zero)
            .ldarg_1()?
            .ldc_i4_0()?
            .bge_s("check_zero")?
            // IL_0004: ldc.i4 -1433646196 (init_state - case10 target)
            // Falls through to dispatcher_entry
            .label("init_state")?
            .ldc_i4(-1433646196_i32)?
            // IL_0009: ldc.i4 -2107303682 (dispatcher entry)
            // IL_000e: xor
            // IL_000f: dup
            // IL_0010: stloc.1
            // IL_0011: ldc.i4.s 12
            // IL_0013: rem.un
            // IL_0014: switch (...)
            .label("dispatcher_entry")?
            .ldc_i4(-2107303682_i32)?
            .xor()?
            .dup()?
            .stloc_1()?
            .ldc_i4(12)?
            .rem_un()?
            .switch(&[
                "output",
                "check_zero",
                "negative",
                "zero",
                "medium",
                "exit_state",
                "large",
                "small",
                "done",
                "check_small",
                "init_state",
                "check_medium",
            ])?
            // IL_0049: br IL_0133 (default -> done)
            .br("done")?
            // IL_004e: case2 - negative
            // ldstr "Negative", stloc.0
            // ldloc.1, ldc.i4 1606139385, mul, ldc.i4 -134536511, xor
            // br.s IL_0009
            .label("negative")?
            .ldc_i4(1)? // placeholder for ldstr "Negative"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(1606139385_i32)?
            .mul()?
            .ldc_i4(-134536511_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0063: case1 - check_zero
            // ldarg.1, brtrue.s IL_006e
            // ldc.i4 -61014635, dup, br.s IL_0074
            // IL_006e: ldc.i4 -1737504033, dup
            // IL_0074: pop, br.s IL_0009
            .label("check_zero")?
            .ldarg_1()?
            .brtrue_s("check_zero_nonzero")?
            .ldc_i4(-61014635_i32)?
            .dup()?
            .br_s("check_zero_merge")?
            .label("check_zero_nonzero")?
            .ldc_i4(-1737504033_i32)?
            .dup()?
            .label("check_zero_merge")?
            .pop()?
            .br_s("dispatcher_entry")?
            // IL_0077: case4 - medium positive
            // ldstr "Medium positive", stloc.0
            // ldloc.1, ldc.i4 -1112056451, mul, ldc.i4 -957501578, xor
            // br IL_0009
            .label("medium")?
            .ldc_i4(3)? // placeholder for ldstr "Medium positive"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(-1112056451_i32)?
            .mul()?
            .ldc_i4(-957501578_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_008f: case7 - small positive
            // ldstr "Small positive", stloc.0
            // ldloc.1, ldc.i4 1822600615, mul, ldc.i4 972313123, xor
            // br IL_0009
            .label("small")?
            .ldc_i4(4)? // placeholder for ldstr "Small positive"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(1822600615_i32)?
            .mul()?
            .ldc_i4(972313123_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00a7: case9 - check_small condition
            // ldarg.1, ldc.i4.s 10, blt.s IL_00b4
            // ldc.i4 -6576863, dup, br.s IL_00ba
            // IL_00b4: ldc.i4 -904275411, dup
            // IL_00ba: pop, br IL_0009
            .label("check_small")?
            .ldarg_1()?
            .ldc_i4(10)?
            .blt_s("check_small_true")?
            .ldc_i4(-6576863_i32)?
            .dup()?
            .br_s("check_small_merge")?
            .label("check_small_true")?
            .ldc_i4(-904275411_i32)?
            .dup()?
            .label("check_small_merge")?
            .pop()?
            .br("dispatcher_entry")?
            // IL_00c0: case11 - check_medium condition
            // ldarg.1, ldc.i4.s 100, bge.s IL_00cd
            // ldc.i4 -1847017906, dup, br.s IL_00d3
            // IL_00cd: ldc.i4 -1069863352, dup
            // IL_00d3: pop, br IL_0009
            .label("check_medium")?
            .ldarg_1()?
            .ldc_i4(100)?
            .bge_s("check_medium_large")?
            .ldc_i4(-1847017906_i32)?
            .dup()?
            .br_s("check_medium_merge")?
            .label("check_medium_large")?
            .ldc_i4(-1069863352_i32)?
            .dup()?
            .label("check_medium_merge")?
            .pop()?
            .br("dispatcher_entry")?
            // IL_00d9: case0 - output
            // ldstr "Value {0} is: {1}", ldarg.1, box, ldloc.0, call Format, call WriteLine
            // ldc.i4 -1184376018
            // br IL_0009
            .label("output")?
            .nop()? // placeholder for output operations
            .ldc_i4(-1184376018_i32)?
            .br("dispatcher_entry")?
            // IL_00f9: case3 - zero
            // ldstr "Zero", stloc.0
            // ldloc.1, ldc.i4 -1658452976, mul, ldc.i4 -1485570506, xor
            // br IL_0009
            .label("zero")?
            .ldc_i4(2)? // placeholder for ldstr "Zero"
            .stloc_0()?
            .ldloc_1()?
            .ldc_i4(-1658452976_i32)?
            .mul()?
            .ldc_i4(-1485570506_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_0111: case5 - exit_state (state update only)
            // ldloc.1, ldc.i4 -1339746023, mul, ldc.i4 -1565321453, xor
            // br IL_0009
            .label("exit_state")?
            .ldloc_1()?
            .ldc_i4(-1339746023_i32)?
            .mul()?
            .ldc_i4(-1565321453_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_0123: case6 - large positive
            // ldstr "Large positive", stloc.0
            // ldc.i4 -546964346
            // br IL_0009
            .label("large")?
            .ldc_i4(5)? // placeholder for ldstr "Large positive"
            .stloc_0()?
            .ldc_i4(-546964346_i32)?
            .br("dispatcher_entry")?
            // IL_0133: case8 - done (ret)
            .label("done")?
            .ret()?;

        let (_, cfg) = build_cfg(asm)?;
        // args: this, value
        let mut ssa = build_ssa(
            &cfg,
            &TestTypeProvider::all_i32(2, 2).arg(0, SsaType::Object),
        )?;

        // Verify initial state - should have 1 CFF dispatcher switch
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(initial_switch_count, 1, "Should have exactly 1 CFF switch");

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After full pipeline, the CFF dispatcher switch should be eliminated
        let final_switch_count = count_switches(&ssa);
        assert_eq!(
            final_switch_count, 0,
            "CFF switch should be eliminated after deobfuscation"
        );

        Ok(())
    }

    /// Test: DemoSwitch - EXACT 1:1 reproduction from monodis of mkaring_controlflow.exe
    ///
    /// From ControlFlowDemo::DemoSwitch (int32 choice)
    /// .locals init (string V_0, unsigned int32 V_1)
    ///
    /// This method has TWO switches:
    /// 1. Original user switch at IL_0000 (switch on arg1)
    /// 2. CFF dispatcher switch at IL_002a
    #[test]
    fn test_unflatten_demoswitch_exact() -> crate::Result<()> {
        // EXACT IL from monodis:
        // IL_0000:  ldarg.1
        // IL_0001:  switch (case0_nothing, case1_start, case2_process, case3_stop, case4_reset)
        //
        // IL_001a:  ldc.i4 1109748230       <- init_state (falls through)
        // IL_001f:  ldc.i4 1399323750       <- dispatcher entry (cases jump here)
        // IL_0024:  xor
        // IL_0025:  dup
        // IL_0026:  stloc.1
        // IL_0027:  ldc.i4.s 14
        // IL_0029:  rem.un
        // IL_002a:  switch (14 targets)
        // IL_0067:  br IL_013d              (default -> done)

        let mut asm = InstructionAssembler::new();
        asm
            // IL_0000: ldarg.1
            // IL_0001: switch (5 targets - original user switch)
            .ldarg_1()?
            .switch(&["nothing", "start", "process", "stop", "reset"])?
            // IL_001a: ldc.i4 1109748230 (init_state for default case)
            .label("init_state")?
            .ldc_i4(1109748230_i32)?
            // IL_001f: ldc.i4 1399323750 (dispatcher entry)
            .label("dispatcher_entry")?
            .ldc_i4(1399323750_i32)?
            .xor()?
            .dup()?
            .stloc_1()?
            .ldc_i4(14)?
            .rem_un()?
            .switch(&[
                "init_state",
                "state1",
                "process",
                "state3",
                "state4",
                "reset",
                "start",
                "stop",
                "state8",
                "done",
                "output",
                "nothing",
                "state12",
                "unknown",
            ])?
            .br("done")?
            // IL_006c: case7 - stop
            // ldstr "Stop", stloc.0, ldc.i4 1874087721, br.s IL_001f
            .label("stop")?
            .ldc_i4(4)? // placeholder for ldstr "Stop"
            .stloc_0()?
            .ldc_i4(1874087721_i32)?
            .br_s("dispatcher_entry")?
            // IL_0079: case3 - state update
            // ldloc.1, ldc.i4 2035784935, mul, ldc.i4 1232406471, xor, br.s IL_001f
            .label("state3")?
            .ldloc_1()?
            .ldc_i4(2035784935_i32)?
            .mul()?
            .ldc_i4(1232406471_i32)?
            .xor()?
            .br_s("dispatcher_entry")?
            // IL_0088: case11 - nothing
            // ldstr "Nothing", stloc.0, ldc.i4 1654581703, br.s IL_001f
            .label("nothing")?
            .ldc_i4(0)? // placeholder for ldstr "Nothing"
            .stloc_0()?
            .ldc_i4(1654581703_i32)?
            .br_s("dispatcher_entry")?
            // IL_0095: case10 - output
            // ldstr "Choice {0} means: {1}", ..., ldc.i4 1061947317, br IL_001f
            .label("output")?
            .nop()? // placeholder for output operations
            .ldc_i4(1061947317_i32)?
            .br("dispatcher_entry")?
            // IL_00b5: case13 - unknown
            // ldstr "Unknown", stloc.0, ldc.i4 827576000, br IL_001f
            .label("unknown")?
            .ldc_i4(6)? // placeholder for ldstr "Unknown"
            .stloc_0()?
            .ldc_i4(827576000_i32)?
            .br("dispatcher_entry")?
            // IL_00c5: case12 - state update
            .label("state12")?
            .ldloc_1()?
            .ldc_i4(1665283153_i32)?
            .mul()?
            .ldc_i4(-1691273355_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00d7: case1 - state update
            .label("state1")?
            .ldloc_1()?
            .ldc_i4(2085043702_i32)?
            .mul()?
            .ldc_i4(964678200_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00e9: case4 - state update
            .label("state4")?
            .ldloc_1()?
            .ldc_i4(355033724_i32)?
            .mul()?
            .ldc_i4(-844819946_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_00fb: case2 - process
            // ldstr "Process", stloc.0, ldc.i4 1649866638, br IL_001f
            .label("process")?
            .ldc_i4(2)? // placeholder for ldstr "Process"
            .stloc_0()?
            .ldc_i4(1649866638_i32)?
            .br("dispatcher_entry")?
            // IL_010b: case8 - state update
            .label("state8")?
            .ldloc_1()?
            .ldc_i4(1697020441_i32)?
            .mul()?
            .ldc_i4(464976312_i32)?
            .xor()?
            .br("dispatcher_entry")?
            // IL_011d: case5 - reset
            // ldstr "Reset", stloc.0, ldc.i4 588169916, br IL_001f
            .label("reset")?
            .ldc_i4(5)? // placeholder for ldstr "Reset"
            .stloc_0()?
            .ldc_i4(588169916_i32)?
            .br("dispatcher_entry")?
            // IL_012d: case6 - start
            // ldstr "Start", stloc.0, ldc.i4 1649866638, br IL_001f
            .label("start")?
            .ldc_i4(1)? // placeholder for ldstr "Start"
            .stloc_0()?
            .ldc_i4(1649866638_i32)?
            .br("dispatcher_entry")?
            // IL_013d: done (ret)
            .label("done")?
            .ret()?;

        let (_, cfg) = build_cfg(asm)?;
        // args: this, choice
        let mut ssa = build_ssa(
            &cfg,
            &TestTypeProvider::all_i32(2, 2).arg(0, SsaType::Object),
        )?;

        // This method has 2 switches: user's original switch + CFF dispatcher
        assert!(has_switch(&ssa), "Should have switch before unflattening");
        let initial_switch_count = count_switches(&ssa);
        assert_eq!(
            initial_switch_count, 2,
            "Should have exactly 2 switches (user + CFF)"
        );

        // Run full deobfuscation pipeline (includes unflattening + DCE)
        run_full_deobfuscation(&mut ssa)?;

        // After unflattening, the CFF dispatcher switch is eliminated.
        // The user's original switch may also be folded if DCE + constant
        // propagation prove all case targets are equivalent (which happens
        // here because placeholders make all cases converge to the same path).
        let final_switch_count = count_switches(&ssa);
        assert!(
            final_switch_count < initial_switch_count,
            "At least the CFF switch should be eliminated (was {initial_switch_count}, now {final_switch_count})"
        );

        Ok(())
    }

    /// Test: NETReactor-style CFF where the state variable is one of many locals.
    ///
    /// Reproduces a bug where the optimizer corrupts the initial state value.
    /// The entry block sets local4 = 10 (state var) along with several other
    /// locals (local0..3 = various values). After optimization, local4 must
    /// still evaluate to 10 at the dispatcher, not be confused with another
    /// local's value.
    ///
    /// Pattern:
    ///   B0: ldc.i4 1; stloc.0     (local0 = 1)
    ///       ldc.i4 0; stloc.1     (local1 = 0)
    ///       ldc.i4 4; stloc.2     (local2 = 4)
    ///       ldc.i4 1; stloc.3     (local3 = 1)
    ///       ldc.i4 10; stloc.s 4  (local4 = 10, the STATE variable)
    ///       br dispatcher
    ///   dispatcher:
    ///       ldloc.s 4
    ///       switch (case0..case13)  ; 14 cases, state 10 -> case10
    ///       br exit                ; default -> exit
    ///   case10:
    ///       ldloc.0               ; use local0 (value 1) as a counter
    ///       ldc.i4 3; stloc.s 4   ; next state = 3
    ///       br dispatcher
    ///   case3:
    ///       ldloc.0
    ///       ldc.i4 4; stloc.s 4   ; next state = 4
    ///       br dispatcher
    ///   case4:
    ///       br exit
    ///   (other cases: nop + br dispatcher for padding)
    ///   exit: ret
    #[test]
    fn test_initial_state_preserved_with_multiple_locals() -> crate::Result<()> {
        let mut asm = InstructionAssembler::new();

        asm
            // Entry: initialize multiple locals then state var
            .ldc_i4(1)?
            .stloc(0)? // local0 = 1
            .ldc_i4(0)?
            .stloc(1)? // local1 = 0
            .ldc_i4(4)?
            .stloc(2)? // local2 = 4
            .ldc_i4(1)?
            .stloc(3)? // local3 = 1
            .ldc_i4(10)?
            .stloc_s(4)? // local4 = 10 (STATE VAR)
            .br("dispatcher")?
            // Dispatcher: switch on state var (local4)
            .label("dispatcher")?
            .ldloc_s(4)?
            .switch(&[
                "case0", "case1", "case2", "case3", "case4", "case5", "case6", "case7", "case8",
                "case9", "case10", "case11", "case12", "case13",
            ])?
            .br("exit")? // default -> exit
            // Case 10: the FIRST executed case (initial state = 10)
            // Uses local0, then transitions to state 3
            .label("case10")?
            .ldloc(0)?
            .pop()?
            .ldc_i4(3)?
            .stloc_s(4)? // next state = 3
            .br("dispatcher")?
            // Case 3: second step, transitions to state 4
            .label("case3")?
            .ldloc(0)?
            .pop()?
            .ldc_i4(4)?
            .stloc_s(4)? // next state = 4
            .br("dispatcher")?
            // Case 4: exits
            .label("case4")?
            .br("exit")?;

        // Padding cases: just jump back to dispatcher (dead in correct trace)
        for i in [0, 1, 2, 5, 6, 7, 8, 9, 11, 12, 13] {
            asm.label(&format!("case{i}"))?
                .nop()?
                .ldc_i4(0)?
                .stloc_s(4)? // state = 0 (doesn't matter)
                .br("dispatcher")?;
        }

        // Exit
        asm.label("exit")?.ret()?;

        let (_, cfg) = build_cfg(asm)?;
        // 0 args, 5 locals (local0..local4, local4 is state)
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 5))?;

        // Verify detection finds the dispatcher with initial_state = 10
        let mut detector = CffDetector::new(&ssa);
        let detected = detector.detect_best();

        assert!(detected.is_some(), "CFF dispatcher should be detected");
        let dispatcher = detected.unwrap();

        assert_eq!(
            dispatcher.initial_state,
            Some(10),
            "Initial state must be 10 (from ldc.i4 10; stloc.s 4 in entry block). \
             If this fails, the detection or optimizer is corrupting the state variable \
             value by confusing it with another local's value (e.g., local3=1)."
        );

        // Now simulate what happens in the full pipeline:
        // 1. The opaque pred pass may modify branches in case blocks
        // 2. Optimizer runs (copy prop + DCE)
        // 3. rebuild_ssa() creates fresh SSA
        // The state variable must still be detectable with value 10.
        let mut ssa_mut = ssa;
        run_full_deobfuscation(&mut ssa_mut)?;

        // After the full pipeline, check if the CFF was properly unflattened.
        // If the initial state was corrupted (e.g., 10 → 1), the trace would
        // follow the wrong path (case 1 instead of case 10) and the switch
        // would remain.
        let remaining_switches = count_switches(&ssa_mut);
        assert_eq!(
            remaining_switches, 0,
            "CFF switch should be completely removed after unflattening. \
             If it remains, the trace likely followed the wrong initial state path. \
             The initial state should be 10 (case10 -> case3 -> case4 -> exit)."
        );

        Ok(())
    }
}

//! SSA construction, interprocedural analysis, and heuristic detection.

use std::{num::NonZeroUsize, sync::Arc};

use analyssa::{
    analysis::Budget,
    interproc::{solve, CallGraph as SummaryGraph, SummaryStore, SummaryTransfer},
};
use dashmap::DashSet;
use log::{info, warn};
use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, ConstValue, MethodPurity, SsaFunction, SsaOp, SsaOpCilExt},
    compiler::{CallSiteInfo, MethodSummary, ParameterSummary},
    deobfuscation::{context::AnalysisContext, engine::DeobfuscationEngine},
    metadata::token::Token,
    CilObject, Error, Result,
};

/// Computes one method's summary, reading its callees' where it needs them.
struct SummaryComputation<'a> {
    /// The engine, for its configuration and the summary computation itself.
    engine: &'a DeobfuscationEngine,
    /// Where the SSA and the call graph live.
    ctx: &'a AnalysisContext,
}

impl SummaryTransfer<Token, MethodSummary> for SummaryComputation<'_> {
    fn visit(
        &mut self,
        method: &Token,
        summaries: &mut SummaryStore<Token, MethodSummary>,
    ) -> bool {
        let Some(mut summary) = self.ctx.with_ssa(*method, |ssa| {
            self.engine.compute_method_summary(ssa, *method)
        }) else {
            return false;
        };

        summary.purity = self.refine_purity(*method, summary.purity, summaries);
        summary.inline_candidate = summary.purity.can_inline()
            && summary.instruction_count <= self.engine.config.passes.inline_threshold;

        // Only a change in what a caller can read is worth another round. The
        // rest of the summary is a function of this method's own body, which
        // does not move between iterations, so reporting it would make every
        // component run to the cap.
        let improved = summaries
            .get(method)
            .is_none_or(|previous| previous.purity != summary.purity);
        summaries.insert(*method, summary);
        improved
    }
}

impl SummaryComputation<'_> {
    /// Sharpens a local purity verdict with what the callees turned out to be.
    ///
    /// [`SsaFunction::purity`] answers for one body, and a body that calls
    /// anything is `Unknown` there: the call might do anything. That is the
    /// right answer without the callees and the wrong one with them - a method
    /// whose every call goes somewhere pure is pure, and it is exactly the
    /// methods an obfuscator generates, the small helpers that compute a key
    /// and return it, that this decides about.
    ///
    /// Only `Unknown` is revisited. The result is the body's own effects, its
    /// calls taken as pure ([`SsaFunction::purity`]), joined with every
    /// callee's: a body that also reads, takes an address or may raise keeps
    /// that whatever its callees are. A verdict is only ever raised, never
    /// lowered, so the fixpoint this runs in settles.
    ///
    /// # Arguments
    ///
    /// * `method` - The method being summarised.
    /// * `local` - What its own body says.
    /// * `summaries` - What the callees have been found to be so far.
    ///
    /// # Returns
    ///
    /// The purity to record.
    fn refine_purity(
        &self,
        method: Token,
        local: MethodPurity,
        summaries: &SummaryStore<Token, MethodSummary>,
    ) -> MethodPurity {
        if local != MethodPurity::Unknown {
            return local;
        }

        let callees = self.ctx.compiler.call_graph.callees(method);
        if callees.is_empty() {
            return local;
        }
        let Some(own) = self
            .ctx
            .with_ssa(method, |ssa| ssa.purity(|_| Some(MethodPurity::Pure)))
        else {
            return local;
        };

        let mut worst = own;
        for callee in callees {
            // A method calling itself says nothing new about itself.
            if callee == method {
                continue;
            }
            // No summary means the callee is outside this assembly, or its
            // component has not settled yet. Either way it is not known to be
            // pure, and claiming purity on the strength of not having looked
            // is how an impure call gets inlined away.
            let Some(callee_summary) = summaries.get(&callee) else {
                return MethodPurity::Unknown;
            };
            worst = worst.join(callee_summary.purity);
        }
        worst
    }
}

impl DeobfuscationEngine {
    /// Builds the analysis context for deobfuscation.
    ///
    /// Creates the call graph, SSA representations, and initializes the context
    /// with detection results and entry points.
    pub(crate) fn build_context(&self, assembly: &CilObject) -> Result<AnalysisContext> {
        // Build call graph
        let call_graph = Arc::new(CallGraph::build(assembly)?);
        let stats = call_graph.stats();
        info!(
            "Building analysis context: {} methods ({} external refs), {} call edges",
            stats.method_count, stats.external_refs, stats.edge_count
        );

        // Create context with engine config (important: cleanup settings!)
        let ctx = AnalysisContext::with_config(call_graph.clone(), self.config.clone());

        // Identify entry points
        Self::identify_entry_points(assembly, &ctx);

        // Build SSA for all methods
        Self::build_ssa_functions(assembly, &ctx, None)?;
        info!("Built SSA for {} methods", ctx.ssa_functions.len());

        // Initialize dirty tracking: all methods start dirty
        for entry in ctx.ssa_functions.iter() {
            ctx.processing_state.mark_method_dirty(*entry.key());
        }

        Ok(ctx)
    }

    /// Identifies entry point methods in the assembly.
    ///
    /// Entry points are methods that can be called from outside the assembly or
    /// are special runtime entry points. This includes:
    ///
    /// - Main entry point from COR20 header
    /// - Static constructors (.cctor) - called automatically by the runtime
    /// - Instance constructors (.ctor) - can be called via `new`
    /// - Public virtual/abstract methods - can be called via polymorphism
    /// - Public static methods - can be called from external code
    /// - Event handler methods - commonly used as callbacks
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CIL object containing the assembly metadata.
    /// * `ctx` - The analysis context to add entry points to.
    fn identify_entry_points(assembly: &CilObject, ctx: &AnalysisContext) {
        // 1. Main entry point from COR20 header
        let entry_token = assembly.cor20header().entry_point_token;
        if entry_token != 0 {
            ctx.add_entry_point(Token::new(entry_token));
        }

        // 2. Iterate through types and directly mark entry points for their methods
        let types = assembly.types();

        for type_entry in types.iter() {
            let cil_type = type_entry.value();
            let type_is_public = cil_type.is_public();

            // Check each method in this type using the query API
            for method in &cil_type.query_methods() {
                let method_token = method.token;

                // Static constructors are always entry points (runtime calls them)
                if method.is_cctor() {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Check method characteristics
                let is_virtual = method.is_virtual();
                let is_abstract = method.is_abstract();
                let is_public = method.is_public();
                let is_static = method.is_static();

                // Virtual/abstract methods in public types are potential entry points
                if type_is_public && is_public && (is_virtual || is_abstract) {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Instance constructors in public types
                if method.is_ctor() && type_is_public && is_public {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Public static methods in public types
                if type_is_public && is_public && is_static {
                    ctx.add_entry_point(method_token);
                    continue;
                }

                // Methods with event handler signatures
                if method.is_event_handler() {
                    ctx.add_entry_point(method_token);
                }
            }
        }
    }

    /// Builds SSA functions for methods in the assembly.
    ///
    /// When `methods` is `None`, builds SSA for all methods with CFGs (initial build).
    /// When `Some`, builds SSA only for the specified tokens (selective rebuild after
    /// byte patches or work item processing).
    ///
    /// Methods are processed in parallel using rayon for faster SSA construction.
    pub(crate) fn build_ssa_functions(
        assembly: &CilObject,
        ctx: &AnalysisContext,
        methods: Option<&DashSet<Token>>,
    ) -> Result<()> {
        // Collect method tokens that have CFGs, optionally filtered
        let method_tokens: Vec<Token> = match methods {
            None => assembly
                .methods()
                .iter()
                .filter(|entry| entry.value().cfg().is_some())
                .map(|entry| *entry.key())
                .collect(),
            Some(set) => set.iter().map(|t| *t).collect(),
        };

        // Build SSA in parallel, collecting errors per method.
        // Methods that fail SSA construction are skipped (logged) rather than
        // aborting the entire pipeline - other methods can still be deobfuscated.
        let errors: Vec<(Token, Error)> = method_tokens
            .par_iter()
            .filter_map(|&method_token| {
                let method = assembly.method(&method_token).ok()?;
                match method.ssa(assembly) {
                    Ok(ssa) => {
                        ctx.set_ssa(method_token, ssa);
                        None
                    }
                    Err(e) => Some((method_token, e)),
                }
            })
            .collect();

        if !errors.is_empty() {
            for (token, e) in &errors {
                warn!(
                    "SSA construction failed for 0x{:08X}: {e} - skipping method",
                    token.value()
                );
            }
        }

        Ok(())
    }

    /// Runs interprocedural analysis on all methods.
    ///
    /// Performs interprocedural analysis: bottom-up summary computation followed
    /// by top-down constant propagation.
    ///
    /// In the bottom-up phase, iterates methods in reverse topological order
    /// (leaves first) to compute [`MethodSummary`] for each - return info,
    /// purity, parameter analysis, inlining candidacy, and pattern detection
    /// (string decryptors, dispatchers).
    ///
    /// In the top-down phase, collects call-site information from callers and
    /// propagates constant arguments to callee parameter summaries, enabling
    /// interprocedural constant propagation during SSA optimization.
    #[allow(clippy::unnecessary_wraps)] // Returns Result for API consistency with other analysis phases
    pub(crate) fn run_interprocedural_analysis(&self, ctx: &AnalysisContext) -> Result<()> {
        // Bottom-up: compute summaries callee-first, which is what makes a
        // caller's summary able to read its callees'.
        //
        // Driven by the shared solver rather than one reverse-topological
        // sweep. The difference is recursion: a topological order does not
        // exist inside a cycle, so a sweep visits each of its methods once
        // with whatever its callees happened to have at the time and never
        // returns. The solver settles each strongly-connected component before
        // moving on, and says whether it managed to.
        let mut graph: SummaryGraph<Token> = SummaryGraph::new();
        for method_token in ctx.all_methods() {
            graph.add_method(method_token);
        }
        for method_token in ctx.methods_topological() {
            for callee in ctx.compiler.call_graph.callees(method_token) {
                graph.add_call(method_token, callee);
            }
        }

        // A cap of zero would mean "never visit anything", which is not a
        // configuration anyone wants; one round is the least that can produce
        // a summary at all.
        let iterations = NonZeroUsize::new(self.config.budget.limit(Budget::SummaryRounds))
            .unwrap_or(NonZeroUsize::MIN);
        let mut transfer = SummaryComputation { engine: self, ctx };
        let outcome = solve(&graph, &mut transfer, iterations);
        if !outcome.converged {
            log::warn!(
                "interprocedural summaries did not settle for {} method(s) after {} iterations; \
                 their summaries are whatever the last round left",
                outcome.unconverged.len(),
                outcome.iterations,
            );
        }

        for (method_token, summary) in outcome.summaries.iter() {
            if summary.is_dispatcher {
                ctx.mark_dispatcher(*method_token);
            }
            ctx.set_summary(summary.clone());
        }

        // Top-down: propagate constants from callers to callees
        let topo_order = ctx.methods_topological();
        for method_token in &topo_order {
            Self::collect_call_site_info(*method_token, ctx);
        }

        // Update parameter constants based on call sites
        Self::propagate_call_site_constants(ctx);
        Ok(())
    }

    /// Computes the [`MethodSummary`] for a single method from its SSA representation.
    ///
    /// Analyzes return behavior, side-effect purity, parameter usage, instruction
    /// count, inlining candidacy (pure + below threshold), and pattern detection
    /// for string decryptors and CFF dispatchers.
    pub(crate) fn compute_method_summary(&self, ssa: &SsaFunction, token: Token) -> MethodSummary {
        let mut summary = MethodSummary::new(token);

        summary.return_info = ssa.return_info();
        summary.purity = ssa.purity(|_| None);
        summary.parameters = Self::analyze_parameters(ssa);
        summary.instruction_count = ssa.instruction_count();
        summary.inline_candidate = summary.purity.can_inline()
            && summary.instruction_count <= self.config.passes.inline_threshold;
        summary.is_string_decryptor = Self::detect_string_decryptor_pattern(ssa);
        summary.is_dispatcher = Self::detect_dispatcher_pattern(ssa);

        summary
    }

    /// Analyzes method parameters for usage patterns.
    ///
    /// Examines how each parameter is used within the method:
    /// - Whether it's used at all (dead parameter detection)
    /// - How many times it's referenced
    /// - Whether it's only used in pure operations (foldable)
    /// - Whether it's passed through to return value unchanged
    fn analyze_parameters(ssa: &SsaFunction) -> Vec<ParameterSummary> {
        let param_count = ssa.num_args();
        let mut summaries: Vec<ParameterSummary> =
            (0..param_count).map(ParameterSummary::new).collect();

        // Pre-fill is_used and use_count from SSA metadata
        for summary in &mut summaries {
            summary.is_used = ssa.is_parameter_used(summary.index);
            summary.use_count = ssa.parameter_use_count(summary.index);
        }

        // Track pure_only per parameter - start true, set false on impure use
        let mut pure_only = vec![true; param_count];

        // Single pass over all blocks and instructions
        for block in ssa.blocks() {
            for instr in block.instructions() {
                let op = instr.op();
                let uses = op.uses();

                // Determine if this op is impure once (avoid re-matching per param)
                let is_impure = matches!(
                    op,
                    SsaOp::Call(_)
                        | SsaOp::NewObj { .. }
                        | SsaOp::StoreField { .. }
                        | SsaOp::StoreStaticField { .. }
                        | SsaOp::StoreElement { .. }
                        | SsaOp::StoreIndirect { .. }
                        | SsaOp::LoadFieldAddr { .. }
                        | SsaOp::LoadElementAddr { .. }
                );

                if is_impure {
                    for &var in &uses {
                        if let Some(param_idx) = ssa.is_parameter_variable(var) {
                            if let Some(slot) = pure_only.get_mut(param_idx) {
                                *slot = false;
                            }
                        }
                    }
                }
            }
        }

        // Finalize pure_usage_only
        for (i, summary) in summaries.iter_mut().enumerate() {
            summary.pure_usage_only = pure_only.get(i).copied().unwrap_or(false) && summary.is_used;
        }

        summaries
    }

    /// Collects call site information for a method.
    fn collect_call_site_info(caller_token: Token, ctx: &AnalysisContext) {
        let call_sites: Vec<(Token, CallSiteInfo)> = ctx
            .with_ssa(caller_token, |ssa| {
                let mut sites = Vec::new();

                for block in ssa.blocks() {
                    for instr in block.instructions() {
                        let Some((callee_token, call)) = instr.op().method_call() else {
                            continue;
                        };
                        let args = &call.args;

                        // What each argument is known to hold. This is the
                        // whole point of collecting call sites: a parameter
                        // every caller passes the same constant to is a
                        // constant inside the callee, and that is the one fact
                        // a method's own body cannot supply.
                        let arguments = args
                            .iter()
                            .map(|&arg| {
                                ssa.variable(arg)
                                    .and_then(|variable| variable.facts().known_value().cloned())
                            })
                            .collect();

                        let info = CallSiteInfo {
                            caller: caller_token,
                            site: instr.id(),
                            arguments,
                            is_live: true,
                        };

                        sites.push((callee_token, info));
                    }
                }

                sites
            })
            .unwrap_or_default();

        for (callee_token, info) in call_sites {
            ctx.add_call_site(callee_token, info);
        }
    }

    /// Propagates constants from call sites to callee parameters.
    ///
    /// A parameter is a constant inside the callee when every live call site
    /// passes the same constant for it. That is the one fact a method's own
    /// body cannot supply, and it is what makes the callee's arithmetic fold:
    /// a helper whose argument is always the same key stops being a function
    /// and becomes a value.
    ///
    /// One dissenting call site is enough to withdraw the claim, and a call
    /// site that passes something unknown dissents - it may well pass
    /// something else. A callee with no live call sites gets nothing, because
    /// "every call site agrees" is vacuously true of none and would let any
    /// claim through.
    fn propagate_call_site_constants(ctx: &AnalysisContext) {
        for entry in &ctx.call_sites {
            let callee_token = *entry.key();
            let sites = entry.value();
            let call_site_count = sites.count();

            // The value every live call site agrees on, per parameter.
            let mut agreed: Vec<Option<ConstValue>> = Vec::new();
            let mut live_sites = 0usize;
            let mut dissent = false;
            for (_, site) in sites.iter() {
                if !site.is_live {
                    continue;
                }
                live_sites = live_sites.saturating_add(1);
                if live_sites == 1 {
                    agreed = site.arguments.clone();
                    continue;
                }
                if agreed.len() != site.arguments.len() {
                    // Different arity at different call sites: nothing about
                    // one position is comparable with another's.
                    dissent = true;
                    break;
                }
                for (slot, passed) in agreed.iter_mut().zip(site.arguments.iter()) {
                    if slot.as_ref() != passed.as_ref() {
                        *slot = None;
                    }
                }
            }

            ctx.modify_summary(callee_token, |summary| {
                summary.call_site_count = call_site_count;
                if dissent || live_sites == 0 {
                    return;
                }
                for (index, value) in agreed.iter().enumerate() {
                    if let Some(parameter) = summary.parameters.get_mut(index) {
                        parameter.constant_value = value.clone();
                    }
                }
            });
        }
    }

    /// Detects if a method looks like a string decryptor.
    ///
    /// Heuristics: small method with XOR operations or array accesses.
    pub(crate) fn detect_string_decryptor_pattern(ssa: &SsaFunction) -> bool {
        if ssa.instruction_count() > 200 {
            return false;
        }
        ssa.has_xor_operations() || ssa.has_array_element_access()
    }

    /// Detects if a method looks like a dispatcher (control flow obfuscation).
    ///
    /// Heuristics: contains a switch with many cases.
    pub(crate) fn detect_dispatcher_pattern(ssa: &SsaFunction) -> bool {
        ssa.largest_switch_target_count()
            .is_some_and(|switch_targets| switch_targets >= 5)
    }
}

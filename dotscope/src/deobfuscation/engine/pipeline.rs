//! Pipeline orchestration and per-run state for the deobfuscation engine.
//!
//! All pipeline logic lives in a single [`PipelineRun`] impl block. The struct
//! is defined in the parent module ([`super`]) so that sibling modules like
//! `api` can access its fields without visibility qualifiers.

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use analyssa::scheduling::{run_pass_with_repair, PassEnv, SsaPass as AnalyssaSsaPass};
use log::{debug, info, warn};

use crate::{
    analysis::{Budget, CilTarget, MethodRef},
    cilassembly::{expand_type_tokens, CleanupRequest},
    compiler::{CompilerContext, DeadMethodEliminationPass, EventLog, PassScheduler},
    deobfuscation::{
        cleanup::{build_cleanup_request, execute_cleanup, retract_referenced_removals},
        context::AnalysisContext,
        engine::{codegen::GeneratedCode, DeobfuscationEngine, PipelineRun},
        passes::NeutralizationPass,
        result::DeobfuscationResult,
        techniques::{
            Detections, TechniqueCapability, TechniqueResult, TechniqueResults, WorkingAssembly,
        },
        workqueue::{DrainedWorkItems, WorkItem},
        EmulationTemplatePool,
    },
    metadata::token::Token,
    CilObject, Error, Result,
};

impl<'a> PipelineRun<'a> {
    /// Creates a new pipeline run backed by the given engine.
    ///
    /// All mutable state (detections, results, iteration count) starts empty.
    /// The assembly is not stored here - it flows through phase methods as
    /// an owned value.
    pub(super) fn new(engine: &'a DeobfuscationEngine) -> Self {
        Self {
            engine,
            detections: Detections::new(),
            results: TechniqueResults::new(),
            start: Instant::now(),
            transforms_applied: 0,
            failed_transforms: HashMap::new(),
            iterations: 0,
        }
    }

    /// Runs the complete deobfuscation pipeline on an assembly.
    ///
    /// Two top-level phases:
    /// 1. [`detect_and_transform`](Self::detect_and_transform) - IL detection,
    ///    byte transforms, post-transform re-detection
    /// 2. [`run_ssa_pipeline`](Self::run_ssa_pipeline) - SSA construction,
    ///    fixpoint optimization, and finalization (may loop for byte-transform
    ///    re-requests)
    pub(super) fn execute(
        mut self,
        assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let assembly = self.detect_and_transform(assembly)?;
        self.run_ssa_pipeline(assembly)
    }

    /// Runs the initial detection and byte-transform phases.
    ///
    /// Sequence:
    /// 1. IL-level detection on raw assembly
    /// 2. Byte transforms for detected techniques
    /// 3. Post-transform re-detection (reveals patterns hidden before, e.g.
    ///    ConfuserEx resource protection after anti-tamper decryption)
    /// 4. Second byte-transform pass for newly-detected techniques
    /// 5. Record all detections
    ///
    /// Called once at the start of `execute`, and reused by `process_method`.
    pub(super) fn detect_and_transform(&mut self, assembly: CilObject) -> Result<CilObject> {
        self.run_il_detection(&assembly);
        let assembly = self.run_byte_transforms(assembly)?;
        self.run_post_transform_detection(&assembly);
        let assembly = self.run_byte_transforms(assembly)?;
        self.record_detections();
        Ok(assembly)
    }

    /// SSA pipeline with optional byte-transform re-iterations.
    ///
    /// Each iteration:
    /// 1. Build SSA context (SSA detection → technique init → emulation pool →
    ///    scheduler → interprocedural analysis)
    /// 2. Run SSA fixpoint (work-queue loop → pass scheduler → detection re-scan)
    /// 3. Check `needs_byte_transform` flag
    ///    - If clear: finalize (dead method elimination → neutralization →
    ///      codegen → cleanup → attribution)
    ///    - If set: release SSA, recover assembly, re-run byte transforms
    ///
    /// Falls through to exhausted-pipeline finalization after
    /// [`MAX_PIPELINE_ITERATIONS`].
    fn run_ssa_pipeline(
        mut self,
        mut assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let max_pipeline_iterations = self.engine.config.iterations.max_pipeline_iterations;
        for pipeline_iteration in 0..max_pipeline_iterations {
            self.detections.clear_ssa_detected();

            if pipeline_iteration > 0 {
                info!(
                    "Pipeline iteration {}: ByteTransform requested, re-running byte transforms",
                    pipeline_iteration.saturating_add(1)
                );
                assembly = self.run_byte_transforms(assembly)?;
                self.record_detections();
            }

            let assembly_arc = Arc::new(assembly);
            let (ctx, mut scheduler) = self.build_ssa_context(&assembly_arc)?;
            self.run_ssa_fixpoint(&ctx, &assembly_arc, &mut scheduler)?;

            if !ctx.needs_byte_transform.load(Ordering::Acquire) {
                return self.finalize(ctx, assembly_arc, scheduler);
            }

            drop(scheduler);
            assembly = Self::unwrap_assembly(&ctx, assembly_arc)?;
        }

        info!(
            "Pipeline exhausted {} iterations without converging, running final pass",
            max_pipeline_iterations
        );
        self.detections.clear_ssa_detected();
        let assembly_arc = Arc::new(assembly);
        let (ctx, mut scheduler) = self.build_ssa_context(&assembly_arc)?;
        self.run_ssa_fixpoint(&ctx, &assembly_arc, &mut scheduler)?;
        self.finalize(ctx, assembly_arc, scheduler)
    }

    /// Runs IL-level [`Technique::detect`] on all enabled techniques.
    ///
    /// Results are collected into a temporary [`Detections`] and merged into
    /// `self.detections`, preserving any existing positive detections.
    pub(super) fn run_il_detection(&mut self, assembly: &CilObject) {
        let mut new_detections = Detections::new();
        for tech in self.engine.registry.techniques() {
            if !tech.enabled(&self.engine.config) {
                continue;
            }
            let detection = tech.detect(assembly);
            if detection.is_detected() {
                info!("[technique] IL detected: {}", tech.name());
            }
            new_detections.insert(tech.id(), detection);
        }
        self.detections.merge_all(new_detections);
    }

    /// Runs byte-level transforms for all detected techniques.
    ///
    /// Iterates techniques in dependency order ([`TechniqueRegistry::sorted_techniques`]).
    /// For each detected technique, calls [`Technique::byte_transform`]. Successful
    /// transforms are recorded in `self.results` (via [`TechniqueResults::push`],
    /// which skips dedup since a technique may produce multiple transform events).
    /// The assembly is regenerated after any transform that declares
    /// [`Technique::requires_regeneration`].
    fn run_byte_transforms(&mut self, assembly: CilObject) -> Result<CilObject> {
        let mut working = WorkingAssembly::new(assembly);
        let sorted = self.engine.registry.sorted_techniques(&self.detections);
        // Whether a transform has already rewritten the image in this round.
        let mut rewritten = false;
        for tech in sorted {
            if !self.detections.is_detected(tech.id()) {
                continue;
            }
            // Skip techniques that have already been successfully transformed.
            // Without this guard, the second byte-transform pass (after
            // post-transform re-detection) would re-run techniques like
            // ConfuserEx resource protection, corrupting resource offsets.
            if self.detections.is_transformed(tech.id()) {
                continue;
            }
            if self.failed_transforms.get(tech.id()) == Some(&self.transforms_applied) {
                continue;
            }
            // A transform that ran before this one may have changed what this
            // technique finds: NecroBit restores the bodies the others read,
            // and a detection taken while they were still encrypted describes
            // stubs. Detect again on the assembly about to be transformed.
            if rewritten {
                let fresh = tech.detect(working.cilobject()?);
                self.detections.merge(tech.id(), fresh);
            }
            let Some(detection) = self.detections.get_mut(tech.id()) else {
                continue;
            };
            let tech_start = Instant::now();
            let Some(transform_result) = tech.byte_transform(&mut working, detection) else {
                continue;
            };
            let evidence = detection.evidence().to_vec();
            match transform_result {
                Ok(events) => {
                    self.results.push(TechniqueResult {
                        id: tech.id().to_string(),
                        detected: true,
                        transformed: true,
                        evidence,
                        events,
                        duration: tech_start.elapsed(),
                    });
                    self.detections.mark_transformed(tech.id());
                    if tech.requires_regeneration() {
                        working.commit()?;
                    }
                    rewritten = true;
                    self.transforms_applied = self.transforms_applied.saturating_add(1);
                }
                Err(e) => {
                    warn!("[technique] {} transform failed: {}", tech.name(), e);
                    self.failed_transforms
                        .insert(tech.id(), self.transforms_applied);
                }
            }
        }
        working.into_cilobject()
    }

    /// Whether a detected technique still has a byte transform to run.
    ///
    /// A technique has one when it is detected, not yet transformed, declares
    /// [`TechniqueCapability::ByteTransform`], and has not already failed on the
    /// assembly as it stands: rerunning the pipeline for a transform that will
    /// fail the same way rebuilds every method's SSA for nothing.
    fn has_pending_byte_transforms(&self) -> bool {
        self.engine.registry.techniques().iter().any(|tech| {
            self.detections.is_detected(tech.id())
                && !self.detections.is_transformed(tech.id())
                && tech
                    .capabilities()
                    .contains(&TechniqueCapability::ByteTransform)
                && self.failed_transforms.get(tech.id()) != Some(&self.transforms_applied)
        })
    }

    /// Re-detects techniques on the post-transform assembly.
    ///
    /// Byte transforms (e.g. anti-tamper decryption) reveal infrastructure
    /// patterns that were invisible when method bodies were encrypted.
    /// Uses [`Detections::merge`] so existing positive detections from
    /// earlier phases are never downgraded.
    fn run_post_transform_detection(&mut self, assembly: &CilObject) {
        for tech in self.engine.registry.techniques() {
            if !tech.enabled(&self.engine.config) {
                continue;
            }
            let detection = tech.detect(assembly);
            if detection.is_detected() {
                info!("[technique] IL re-detected: {}", tech.name());
            }
            self.detections.merge(tech.id(), detection);
        }
    }

    /// Runs SSA-level detection ([`Technique::detect_ssa`]) on all enabled techniques.
    ///
    /// Called after SSA functions are built, enabling cross-block def-use chain
    /// analysis for more precise pattern matching than IL-level detection.
    /// Techniques already SSA-detected in this pipeline iteration are skipped.
    pub(super) fn run_ssa_detection(&mut self, ctx: &AnalysisContext, assembly: &CilObject) {
        for tech in self.engine.registry.techniques() {
            if !tech.enabled(&self.engine.config) {
                continue;
            }
            if self.detections.is_ssa_detected(tech.id()) {
                continue;
            }
            let ssa_det = tech.detect_ssa(ctx, assembly);
            if ssa_det.is_detected() {
                info!("[technique] SSA detected: {}", tech.name());
                self.detections.mark_ssa_detected(tech.id());
            }
            self.detections.merge(tech.id(), ssa_det);
        }
    }

    /// Records all detected techniques into `self.results` with O(1) dedup.
    ///
    /// For each detected technique, creates a detection-only [`TechniqueResult`]
    /// (no transform, no events) and passes it through [`TechniqueResults::record`],
    /// which skips insertion if the technique ID was already recorded.
    pub(super) fn record_detections(&mut self) {
        for tech in self.engine.registry.techniques() {
            if let Some(d) = self.detections.get(tech.id()) {
                if d.is_detected() {
                    self.results.record(TechniqueResult {
                        id: tech.id().to_string(),
                        detected: true,
                        transformed: false,
                        evidence: d.evidence().to_vec(),
                        events: EventLog::new(),
                        duration: Duration::ZERO,
                    });
                }
            }
        }
    }

    /// Runs engine-driven detection re-scan after the pass scheduler makes progress.
    ///
    /// Called when the inner fixpoint made changes (`round_iterations > 0`) and
    /// the detection round budget has not been exhausted. Re-runs
    /// [`Technique::detect_ssa`] for techniques not yet SSA-detected.
    ///
    /// When new techniques are found:
    /// - Initializes and creates their passes
    /// - Marks all methods dirty so the new passes process them
    /// - Signals `needs_byte_transform` if any new technique requires it
    /// - Submits `RedetectAssembly` work if passes were added
    ///
    /// Returns `true` if new work was submitted to the queue.
    fn run_detection_rescan(
        &mut self,
        ctx: &AnalysisContext,
        assembly_arc: &Arc<CilObject>,
        scheduler: &mut PassScheduler,
        detection_round: &mut usize,
        outer_iteration: usize,
    ) -> Result<bool> {
        let mut new_detections = false;
        for tech in self.engine.registry.techniques() {
            if !tech.enabled(&self.engine.config) {
                continue;
            }
            if self.detections.is_ssa_detected(tech.id()) {
                continue;
            }
            let ssa_det = tech.detect_ssa(ctx, assembly_arc);
            if !ssa_det.is_detected() {
                continue;
            }
            self.detections.mark_ssa_detected(tech.id());
            if self.detections.is_detected(tech.id()) {
                self.detections.merge(tech.id(), ssa_det);
                continue;
            }
            info!(
                "[technique] SSA re-detected (outer {}, round {}): {}",
                outer_iteration.saturating_add(1),
                detection_round.saturating_add(1),
                tech.name()
            );
            self.detections.merge(tech.id(), ssa_det);
            new_detections = true;
        }

        if !new_detections {
            return Ok(false);
        }

        *detection_round = detection_round.saturating_add(1);
        self.record_detections();

        let passes_before = scheduler.pass_count();
        self.engine
            .initialize_and_create_passes(ctx, assembly_arc, &self.detections, scheduler);
        let passes_added = scheduler.pass_count().saturating_sub(passes_before);
        self.engine.configure_no_inline(ctx);

        if passes_added > 0 {
            for entry in ctx.ssa_functions.iter() {
                ctx.processing_state.mark_method_dirty(*entry.key());
            }
        }

        if self.has_pending_byte_transforms() {
            ctx.needs_byte_transform.store(true, Ordering::Release);
        }

        let has_pending_work_items = !ctx.work_queue.is_empty();
        if !has_pending_work_items && passes_added > 0 {
            ctx.work_queue.submit(WorkItem::RedetectAssembly)?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Builds the SSA context for one pipeline iteration.
    ///
    /// Sequence:
    /// 1. Build call graph + SSA functions + entry points
    /// 2. SSA-level detection + record + technique initialization
    /// 3. Check for pending byte transforms (set flag if found)
    /// 4. Create emulation template pool (if any technique needs emulation)
    /// 5. Create pass scheduler with infrastructure + technique passes
    /// 6. Mark dispatchers/decryptors as non-inlinable
    /// 7. Run interprocedural analysis (bottom-up summaries, top-down propagation)
    fn build_ssa_context(
        &mut self,
        assembly_arc: &Arc<CilObject>,
    ) -> Result<(AnalysisContext, PassScheduler)> {
        let ctx = self.engine.build_context(assembly_arc)?;

        self.run_ssa_detection(&ctx, assembly_arc);
        self.record_detections();
        self.engine
            .initialize_techniques(&ctx, assembly_arc, &self.detections);

        if self.has_pending_byte_transforms() {
            ctx.needs_byte_transform.store(true, Ordering::Release);
        }

        if DeobfuscationEngine::needs_emulation(&ctx) {
            let original_pe_cow = assembly_arc.file().fork_cowfile()?;
            let pool = Arc::new(EmulationTemplatePool::new(
                Arc::clone(assembly_arc),
                original_pe_cow,
                Arc::clone(&ctx.emulation_hooks),
                Arc::clone(&ctx.warmup_methods),
                Arc::clone(&ctx.statemachine_providers),
                self.engine.config.clone(),
            ));
            pool.warmup()?;
            let _ = ctx.template_pool.set(pool);
        }

        let mut scheduler = self.engine.create_scheduler();
        self.engine.create_deob_passes(&ctx, &mut scheduler);
        self.engine.initialize_and_create_passes(
            &ctx,
            assembly_arc,
            &self.detections,
            &mut scheduler,
        );
        self.engine.configure_no_inline(&ctx);

        info!(
            "Interprocedural analysis on {} methods",
            ctx.ssa_functions.len()
        );
        self.engine.run_interprocedural_analysis(&ctx)?;

        Ok((ctx, scheduler))
    }

    /// Runs the inner SSA fixpoint loop.
    ///
    /// Each outer iteration:
    /// 1. Drain and apply pending work items (SSA builds, injections, re-detection)
    /// 2. Build SSA for methods needing (re)construction
    /// 3. Notify techniques of new iteration
    /// 4. Run scoped re-detection for newly detected tokens
    /// 5. Run pass scheduler to convergence (inner fixpoint)
    /// 6. Check for new work items submitted during passes
    /// 7. Engine-driven detection re-scan (only if passes made progress)
    /// 8. Convergence check - break if no pending work
    ///
    /// Accumulates pass iteration counts into `self.iterations`.
    fn run_ssa_fixpoint(
        &mut self,
        ctx: &AnalysisContext,
        assembly_arc: &Arc<CilObject>,
        scheduler: &mut PassScheduler,
    ) -> Result<()> {
        info!(
            "Running SSA fixpoint (max {} inner iterations, max {} outer iterations)",
            self.engine.config.budget.limit(Budget::PipelineRounds),
            self.engine.config.iterations.max_outer_iterations
        );
        let mut detection_round = 0;

        for outer_iteration in 0..self.engine.config.iterations.max_outer_iterations {
            let pending = ctx.drain_work_items();
            if !pending.is_empty() {
                Self::apply_work_items(pending, ctx);
            }

            if !ctx.processing_state.needs_ssa_build.is_empty() {
                DeobfuscationEngine::build_ssa_functions(
                    assembly_arc,
                    ctx,
                    Some(&ctx.processing_state.needs_ssa_build),
                )?;
                let built: Vec<Token> = ctx
                    .processing_state
                    .needs_ssa_build
                    .iter()
                    .map(|t| *t)
                    .collect();
                for token in built {
                    ctx.processing_state.mark_ssa_built(token);
                }
            }

            if outer_iteration > 0 {
                for tech in self.engine.registry.techniques() {
                    tech.on_iteration_start(ctx, assembly_arc)?;
                }
            }

            if !ctx.processing_state.newly_detected.is_empty()
                || ctx.processing_state.is_assembly_dirty()
            {
                self.run_ssa_detection(ctx, assembly_arc);
                self.record_detections();
                self.engine.initialize_and_create_passes(
                    ctx,
                    assembly_arc,
                    &self.detections,
                    scheduler,
                );
                self.engine.configure_no_inline(ctx);
                ctx.processing_state.newly_detected.clear();
                ctx.processing_state.clear_assembly_dirty();
            }

            let round_iterations =
                scheduler.run_pipeline(ctx, assembly_arc, Some(&ctx.processing_state))?;
            self.iterations = self.iterations.saturating_add(round_iterations);

            let has_pending_work_items = !ctx.work_queue.is_empty();
            let mut detection_added_work = false;
            if detection_round < self.engine.config.iterations.max_detection_rounds
                && round_iterations > 0
            {
                detection_added_work = self.run_detection_rescan(
                    ctx,
                    assembly_arc,
                    scheduler,
                    &mut detection_round,
                    outer_iteration,
                )?;
            }

            let has_work = has_pending_work_items
                || detection_added_work
                || ctx.processing_state.has_pending_work();
            if !has_work {
                debug!(
                    "SSA fixpoint reached after {} iteration(s)",
                    outer_iteration.saturating_add(1)
                );
                break;
            }
        }

        Ok(())
    }

    /// Applies drained work items to the analysis context.
    ///
    /// Processes items by category:
    /// - `BuildSsa` - marks methods in `needs_ssa_build`
    /// - `InjectSsa` - inserts externally-produced SSA, marks method dirty
    /// - `RedetectMethods` - populates `newly_detected`
    /// - `RedetectTypes` - populates `newly_detected` + marks type dirty
    /// - `RedetectAssembly` - marks assembly dirty
    fn apply_work_items(items: DrainedWorkItems, ctx: &AnalysisContext) {
        for token in items.build_ssa {
            ctx.processing_state.mark_needs_ssa_build(token);
        }
        for (token, function) in items.inject_ssa {
            ctx.set_ssa(token, *function);
            ctx.processing_state.mark_method_dirty(token);
        }
        for token in items.redetect_methods {
            ctx.processing_state.newly_detected.insert(token);
        }
        for token in items.redetect_types {
            ctx.processing_state.newly_detected.insert(token);
            ctx.processing_state.mark_type_dirty(token);
        }
        if items.redetect_assembly {
            ctx.processing_state.mark_assembly_dirty();
        }
    }

    /// Post-convergence finalization.
    ///
    /// Sequence:
    /// 1. Dead method elimination (if configured)
    /// 2. Build cleanup request from technique detections + SSA call graph
    /// 3. Neutralization - remove references to deleted protection tokens,
    ///    then re-run the pass scheduler if any changes were made
    /// 4. Canonicalize SSA and release emulation template pool
    /// 5. Code generation - emit CIL bytecode from optimized SSA
    /// 6. Cleanup - remove dead types, methods, fields, metadata artifacts
    /// 7. Build final [`DeobfuscationResult`] with attribution and timing
    fn finalize(
        mut self,
        ctx: AnalysisContext,
        assembly_arc: Arc<CilObject>,
        mut scheduler: PassScheduler,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        if ctx.config.cleanup.remove_unused_methods {
            let dead_method_pass = DeadMethodEliminationPass::new();
            // Ensure the assembly handle is set on the context so the
            // global pass can reach it via the analyssa host trait.
            ctx.compiler.set_assembly(assembly_arc.clone());
            let _ = AnalyssaSsaPass::<CilTarget, CompilerContext>::run_global(
                &dead_method_pass,
                &ctx.compiler,
            )
            .map_err(|e| Error::SsaError(e.0))?;
        }

        // Effective, not SSA-only: this graph decides what gets deleted, and a method whose
        // body never converted to SSA must read as "unknown callees", not "no callees".
        let ssa_call_graph = ctx.build_effective_call_graph(&assembly_arc);
        let mut merged_cleanup = build_cleanup_request(
            self.engine,
            &ctx,
            &self.detections,
            &assembly_arc,
            &ssa_call_graph,
        );

        self.run_neutralization(&ctx, &assembly_arc, &mut scheduler, &merged_cleanup)?;

        ctx.canonicalize_all_ssa();
        let assembly = Self::unwrap_assembly(&ctx, assembly_arc)?;

        let GeneratedCode {
            assembly: final_assembly,
            regenerated: methods_regenerated,
            protected_tokens,
            kept_original,
            ..
        } = DeobfuscationEngine::generate_code(assembly, &ctx)?;
        // The request was built on the assumption that every converted method
        // is emitted from its SSA, where neutralization stripped the calls into
        // what cleanup deletes. A method whose regenerated code was refused
        // ships its original body instead, which still calls the decryptors,
        // loads the fields and instantiates the generic methods the request is
        // about to delete.
        if !kept_original.is_empty() {
            retract_referenced_removals(
                &final_assembly,
                &mut merged_cleanup,
                &ssa_call_graph,
                &ctx,
                &kept_original,
            );
        }
        info!(
            "Code generation: {} method bodies regenerated",
            methods_regenerated
        );

        // Add codegen-created tokens to the cleanup request's protected set.
        // These are FieldDef + TypeDef entries for array initializer data that
        // must survive cleanup (they were created after build_cleanup_request).
        if !protected_tokens.is_empty() {
            info!(
                "Protecting {} codegen-created tokens from cleanup",
                protected_tokens.len()
            );
            merged_cleanup.protect_tokens(protected_tokens);
        }

        info!(
            "Cleanup request: {} types, {} methods, {} fields, {} attributes, {} manifest resources",
            merged_cleanup.types_len(),
            merged_cleanup.methods_len(),
            merged_cleanup.fields_len(),
            merged_cleanup.attributes_len(),
            merged_cleanup.manifest_resources_len(),
        );
        let cleanup_request =
            if merged_cleanup.has_deletions() || !merged_cleanup.excluded_sections().is_empty() {
                Some(merged_cleanup)
            } else {
                None
            };
        let final_assembly = execute_cleanup(final_assembly, cleanup_request, &ctx)?;

        info!(
            "Technique pipeline complete in {:.1}s",
            self.start.elapsed().as_secs_f64()
        );
        Ok((final_assembly, self.build_result(&ctx)))
    }

    /// Runs neutralization on all SSA functions.
    ///
    /// Creates a [`NeutralizationPass`] targeting tokens that will be deleted
    /// during cleanup, then applies it to every method. If any method was
    /// modified, re-runs the pass scheduler to propagate the changes
    /// (e.g. dead code elimination after neutralized calls become unreachable).
    fn run_neutralization(
        &mut self,
        ctx: &AnalysisContext,
        assembly_arc: &Arc<CilObject>,
        scheduler: &mut PassScheduler,
        merged_cleanup: &CleanupRequest,
    ) -> Result<()> {
        let all_tokens = expand_type_tokens(merged_cleanup, assembly_arc);
        if all_tokens.is_empty() {
            return Ok(());
        }

        let pass = NeutralizationPass::new(&all_tokens);
        let mut neutralized = false;
        let method_tokens: Vec<Token> = ctx.ssa_functions.iter().map(|e| *e.key()).collect();
        // Ensure the assembly handle is set on the context so passes can
        // reach it through the analyssa host trait.
        ctx.set_assembly(assembly_arc.clone());
        for method_token in &method_tokens {
            // A method cleanup deletes is discarded whole, so stripping its
            // references buys nothing - and it would leave a body that no
            // longer does what the method does for every pass that reads a
            // callee's SSA to decide what a call does.
            if all_tokens.contains(method_token) {
                continue;
            }
            if let Some(mut ssa) = ctx.ssa_functions.get_mut(method_token) {
                let method_ref = MethodRef::from(*method_token);
                // Neutralization is `CfgModifying` and runs here, outside the
                // scheduler that would otherwise repair after it. Without the
                // repair every method it touches keeps phis and definition
                // sites describing control flow it has just removed, and the
                // next pass group to read the method fails its boundary check
                // and rolls the whole method back - so the neutralization is
                // silently undone and the tokens it was meant to strip stay in
                // the output.
                //
                // What made that masking load-bearing, and no longer does: the
                // cleanup request could mark a method for removal while live
                // code still called it, and neutralization would then remove
                // every one of those calls - for a proxy that a method
                // forwards through, the entire body. `build_cleanup_request`
                // now withdraws any removal surviving code still names, so a
                // token reaching this pass is one nothing live refers to.
                let env: PassEnv<'_, CilTarget> = PassEnv::from_host(&method_ref, &**ctx);
                if run_pass_with_repair(&pass, &mut ssa, &env).map_err(|e| {
                    // The reconstruction reports what is wrong with the
                    // function but not which function it is, and one failure
                    // out of several hundred methods is not findable without
                    // the token.
                    Error::SsaError(format!("neutralizing {method_token}: {}", e.0))
                })? {
                    neutralized = true;
                    // Ensure neutralized methods get code-generated. Without this,
                    // methods modified only by neutralization keep their original IL
                    // which still references deleted tokens - causing the executor's
                    // dead definition elimination to keep those tokens alive.
                    ctx.processed_methods.insert(*method_token);
                }
            }
        }

        if neutralized {
            self.iterations = self.iterations.saturating_add(scheduler.run_pipeline(
                ctx,
                assembly_arc,
                Some(&ctx.processing_state),
            )?);
        }

        Ok(())
    }

    /// Releases the emulation template pool and unwraps the assembly from its [`Arc`].
    ///
    /// Called when transitioning from the SSA phase (which shares the assembly
    /// via `Arc`) back to owned assembly for byte transforms or code generation.
    fn unwrap_assembly(ctx: &AnalysisContext, assembly_arc: Arc<CilObject>) -> Result<CilObject> {
        if let Some(pool) = ctx.template_pool.get() {
            pool.release();
        }
        // Drop the assembly reference held by `CompilerContext` so the
        // strong-count can drop to one. The analyssa scheduler's
        // `run_pipeline` already clears it on its own exit, but nested
        // global-pass invocations (e.g. dead-method elimination outside
        // the scheduler) and re-entrant pipeline iterations can leave a
        // stray reference here.
        ctx.compiler.clear_assembly();
        Arc::try_unwrap(assembly_arc).map_err(|_| {
            Error::Deobfuscation("Cannot unwrap assembly - still has other references".into())
        })
    }

    /// Builds the final [`DeobfuscationResult`] with attribution and timing.
    ///
    /// Consumes `self` to take ownership of the accumulated technique results.
    /// Computes attribution by matching detections against known obfuscator
    /// signatures, and records the total elapsed time and iteration count.
    fn build_result(self, ctx: &AnalysisContext) -> DeobfuscationResult {
        let attribution = self.engine.matcher.compute_attribution(&self.detections);
        let attributions = self
            .engine
            .matcher
            .compute_attributions_all(&self.detections);
        let events = ctx.compiler.events.take();
        DeobfuscationResult::new_with_techniques(events, self.results.into_vec(), attribution)
            .with_attributions(attributions)
            .with_timing(self.start.elapsed(), self.iterations)
    }

    /// Builds a detection-only result without compilation events.
    ///
    /// Used by [`DeobfuscationEngine::detect`] which runs detection phases
    /// but skips transforms and SSA processing.
    pub(super) fn build_detection_result(self) -> DeobfuscationResult {
        let attribution = self.engine.matcher.compute_attribution(&self.detections);
        let attributions = self
            .engine
            .matcher
            .compute_attributions_all(&self.detections);
        DeobfuscationResult::new_with_techniques(
            EventLog::new(),
            self.results.into_vec(),
            attribution,
        )
        .with_attributions(attributions)
        .with_timing(self.start.elapsed(), 0)
    }
}

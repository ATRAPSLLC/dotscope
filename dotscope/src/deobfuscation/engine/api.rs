//! Public entry points for the deobfuscation engine.

use std::{sync::Arc, time::Instant};

use log::info;

use crate::{
    analysis::{CallGraph, SsaFunction},
    deobfuscation::{
        context::AnalysisContext,
        engine::{DeobfuscationEngine, PipelineRun},
        result::DeobfuscationResult,
        techniques::Detections,
    },
    metadata::{token::Token, validation::ValidationConfig},
    CilObject, Error, File, Result,
};

impl DeobfuscationEngine {
    /// Processes an assembly through the complete deobfuscation pipeline.
    ///
    /// This is the main entry point for deobfuscation. The pipeline follows a clean
    /// consume → produce pattern at each phase:
    ///
    /// 1. **Detection** - Identify obfuscator (borrows assembly, read-only)
    /// 2. **Byte-level deobfuscation** - Decrypt methods, unpack resources (consume → produce)
    /// 3. **SSA pipeline + code generation + postprocessing** - Optimize and regenerate (consume → produce)
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to deobfuscate (consumed).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The deobfuscated `CilObject` (clean, reloaded with strict validation)
    /// - A [`DeobfuscationResult`] with statistics, detection info, and changes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Call graph construction fails
    /// - SSA construction fails for any method
    /// - Any pass returns an error
    /// - Obfuscator deobfuscation or postprocessing fails
    /// - Final strict reload fails
    pub fn process_assembly(
        &self,
        assembly: CilObject,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        PipelineRun::new(self).execute(assembly)
    }

    /// Runs technique detection on an assembly (IL-level and SSA-level).
    ///
    /// This is a detection-only API - no transforms are applied. It runs both
    /// IL-level [`Technique::detect`](crate::deobfuscation::techniques::Technique::detect)
    /// and SSA-level [`Technique::detect_ssa`](crate::deobfuscation::techniques::Technique::detect_ssa)
    /// on each technique, catching patterns that require cross-block def-use
    /// chain analysis (e.g., BitMono string encryption, opaque field predicates,
    /// delegate proxies).
    ///
    /// SSA construction is performed internally and discarded after detection.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to detect obfuscation techniques in (read-only).
    ///
    /// # Returns
    ///
    /// A [`DeobfuscationResult`] containing per-technique detections from both
    /// IL and SSA phases, attribution, and timing information.
    ///
    /// # Errors
    ///
    /// SSA construction is best-effort: if it fails (e.g., obfuscated control
    /// flow breaks stack simulation), IL-only detection results are returned.
    #[must_use]
    pub fn detect(&self, assembly: &CilObject) -> DeobfuscationResult {
        let mut run = PipelineRun::new(self);
        run.run_il_detection(assembly);

        if let Ok(ctx) = self.build_context(assembly) {
            run.run_ssa_detection(&ctx, assembly);
        }

        run.record_detections();
        run.build_detection_result()
    }

    /// Entry point: Process assembly from file path.
    ///
    /// Loads the PE file with transparent repair and then
    /// delegates to [`process_assembly`](Self::process_assembly).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the assembly file.
    ///
    /// # Returns
    ///
    /// A tuple containing the deobfuscated assembly and results.
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails or deobfuscation fails.
    pub fn process_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(CilObject, DeobfuscationResult)> {
        let file = File::from_path(path)?;
        self.process_dotscope_file(file)
    }

    /// Entry point: Process assembly from memory buffer.
    ///
    /// Loads the PE with transparent repair, then delegates to
    /// [`process_assembly`](Self::process_assembly).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw assembly bytes.
    ///
    /// # Returns
    ///
    /// A tuple containing the deobfuscated assembly and results.
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails or deobfuscation fails.
    pub fn process_bytes(&self, bytes: Vec<u8>) -> Result<(CilObject, DeobfuscationResult)> {
        let file = File::from_mem(bytes)?;
        self.process_dotscope_file(file)
    }

    /// Internal: loads a dotscope `File` into a `CilObject` and processes it.
    fn process_dotscope_file(&self, file: File) -> Result<(CilObject, DeobfuscationResult)> {
        if !file.repairs().is_empty() {
            info!(
                "PE repair applied {} fix(es) during loading",
                file.repairs().len()
            );
        }

        let assembly =
            CilObject::from_dotscope_file_with_validation(file, ValidationConfig::analysis())?;
        self.process_assembly(assembly)
    }

    /// Processes a single method through the deobfuscation pipeline.
    ///
    /// This runs the complete deobfuscation pipeline on a single method:
    /// - Obfuscator detection
    /// - Byte-level deobfuscation (anti-tamper decryption, etc.)
    /// - Full obfuscator initialization (decryptor registration, MethodSpec mapping)
    /// - Heuristic decryptor detection
    /// - SSA optimization passes
    ///
    /// Useful for debugging or testing specific methods without processing
    /// the entire assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly containing the method (consumed).
    /// * `method_token` - The token of the method to process.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The deobfuscated SSA function
    /// - The deobfuscation result with statistics and changes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The method is not found in the assembly
    /// - SSA construction fails for the method
    /// - Any pass returns an error
    pub fn process_method(
        &self,
        assembly: CilObject,
        method_token: Token,
    ) -> Result<(SsaFunction, DeobfuscationResult)> {
        let start = Instant::now();

        // Reuse PipelineRun for detection + byte transforms
        let mut run = PipelineRun::new(self);
        let assembly = run.detect_and_transform(assembly)?;

        // Build context and initialize techniques
        let assembly = Arc::new(assembly);
        let ctx = self.build_context(&assembly)?;

        // SSA-level detection + initialization + technique passes
        run.run_ssa_detection(&ctx, &assembly);

        // Create scheduler with compiler + technique passes
        let mut scheduler = self.create_scheduler();
        self.create_deob_passes(&ctx, &mut scheduler);
        self.initialize_and_create_passes(&ctx, &assembly, &run.detections, &mut scheduler);

        // Extract just the target method's SSA, process only this method
        let target_ssa = ctx
            .ssa_functions
            .remove(&method_token)
            .map(|(_, ssa)| ssa)
            .ok_or_else(|| Error::SsaError(format!("Method not found: {method_token}")))?;

        ctx.ssa_functions.clear();
        ctx.ssa_functions.insert(method_token, target_ssa);
        ctx.entry_points.clear();
        ctx.add_entry_point(method_token);

        // Run SSA optimization passes
        let iterations = scheduler.run_pipeline(&ctx, &assembly, None)?;

        // Extract and canonicalize
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();

        let events = ctx.compiler.events.take();
        let attribution = self.matcher.compute_attribution(&run.detections);
        let attributions = self.matcher.compute_attributions_all(&run.detections);
        let result =
            DeobfuscationResult::new_with_techniques(events, run.results.into_vec(), attribution)
                .with_attributions(attributions)
                .with_timing(start.elapsed(), iterations);

        Ok((final_ssa, result))
    }

    /// Processes a standalone SSA function through the deobfuscation pipeline.
    ///
    /// This is the lowest-level API for deobfuscation. It takes an SSA function
    /// directly and runs all passes on it. Useful for testing passes or when
    /// you've already constructed the SSA externally.
    ///
    /// Note: No obfuscator detection is performed since there's no assembly context.
    /// This means obfuscator-specific passes won't be activated.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to use for context (needed for emulation).
    /// * `ssa` - The SSA function to process (will be modified in place).
    /// * `method_token` - A token to identify this method (can be synthetic).
    ///
    /// # Returns
    ///
    /// A [`DeobfuscationResult`] containing statistics and changes.
    /// The SSA is modified in place.
    ///
    /// # Errors
    ///
    /// Returns an error if any pass returns an error.
    pub fn process_ssa(
        &self,
        assembly: &Arc<CilObject>,
        ssa: &mut SsaFunction,
        method_token: Token,
    ) -> Result<DeobfuscationResult> {
        let start = Instant::now();

        // Build context and insert SSA before detection so detect_ssa can analyze it
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::with_config(call_graph, self.config.clone());
        let ssa_owned = std::mem::replace(ssa, SsaFunction::new(0, 0));
        ctx.ssa_functions.insert(method_token, ssa_owned);
        ctx.add_entry_point(method_token);

        // Run SSA detection to populate findings (CFF dispatchers, etc.)
        let mut detections = Detections::new();
        for tech in self.registry.techniques() {
            if !tech.enabled(&self.config) {
                continue;
            }
            let det = tech.detect_ssa(&ctx, assembly);
            if det.is_detected() {
                detections.insert(tech.id(), det);
            }
        }

        // Create scheduler with passes informed by detection findings
        let mut scheduler = self.create_scheduler();
        self.create_deob_passes(&ctx, &mut scheduler);
        self.initialize_and_create_passes(&ctx, assembly, &detections, &mut scheduler);

        // Run the pipeline
        let iterations = scheduler.run_pipeline(&ctx, assembly, None)?;

        // Extract and canonicalize the SSA, then return it via the mutable reference
        let (_, mut final_ssa) = ctx
            .ssa_functions
            .remove(&method_token)
            .ok_or_else(|| Error::SsaError("SSA was unexpectedly removed".to_string()))?;

        final_ssa.canonicalize();
        *ssa = final_ssa;

        let events = ctx.events.take();
        Ok(
            DeobfuscationResult::new_with_techniques(events, Vec::new(), None)
                .with_timing(start.elapsed(), iterations),
        )
    }
}

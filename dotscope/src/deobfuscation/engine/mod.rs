//! Main deobfuscation engine.
//!
//! The [`DeobfuscationEngine`] is the main entry point for deobfuscating
//! .NET assemblies. It orchestrates detection, analysis, pass execution,
//! and code generation.

mod analysis;
mod api;
mod codegen;
mod detection;
mod pipeline;
pub use codegen::GeneratedCode;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, time::Instant};

use analyssa::scheduling::AsSsaPass;

use crate::{
    compiler::{
        AlgebraicSimplificationPass, BlockMergingPass, ConstantPropagationPass,
        ControlFlowSimplificationPass, CopyPropagationPass, DeadCodeEliminationPass,
        GlobalValueNumberingPass, InliningPass, JumpThreadingPass, LicmPass,
        MemoryOptimizationPass, OpaquePredicatePass, PassPhase, PassScheduler,
        ProxyDevirtualizationPass, ReassociationPass, StrengthReductionPass,
        ValueRangePropagationPass,
    },
    deobfuscation::{
        config::EngineConfig,
        context::AnalysisContext,
        passes::DecryptionPass,
        techniques::{
            Detections, ObfuscatorMatcher, Technique, TechniqueRegistry, TechniqueResults,
        },
    },
};

/// Per-execution pipeline state.
///
/// Holds all mutable state for a single run of the deobfuscation pipeline.
/// The assembly flows as an argument/return through phase methods rather
/// than being stored on the struct, since its ownership changes form
/// (owned → Arc → unwrapped) across phases.
///
/// Defined here so that child modules (`pipeline`, `api`) can access
/// fields directly without visibility qualifiers.
struct PipelineRun<'a> {
    engine: &'a DeobfuscationEngine,
    detections: Detections,
    results: TechniqueResults,
    start: Instant,
    iterations: usize,
    /// Byte transforms that have succeeded in this run; each one changes the
    /// assembly the next transform works on.
    transforms_applied: usize,
    /// For each byte transform that failed or found nothing to do,
    /// `transforms_applied` when it did. It is not attempted again, and does not
    /// count as pending, until another transform has changed the assembly: the
    /// same input gives the same answer, some of these attempts cost a full
    /// emulation run, and a pending transform makes the pipeline run again.
    settled_transforms: HashMap<&'static str, usize>,
}

/// Main deobfuscation engine.
///
/// The engine orchestrates the complete deobfuscation pipeline:
///
/// 1. **Detection**: IL-level technique detection on the raw assembly
/// 2. **Byte transforms**: Anti-tamper decryption, PE section restoration
/// 3. **Post-transform re-detection**: IL re-detect on decrypted method bodies
/// 4. **SSA construction**: Build call graph, SSA, interprocedural analysis
/// 5. **SSA detection + initialization**: SSA-level detection, technique init
/// 6. **Pass execution**: Fixpoint scheduler with capability-based layers
/// 7. **Neutralization**: Remove references to deleted protection tokens
/// 8. **Code generation**: Emit CIL bytecode from optimized SSA
/// 9. **Cleanup**: Remove dead types, methods, fields, metadata artifacts
/// 10. **Attribution**: Identify obfuscator from technique detection signatures
///
/// # APIs
///
/// The engine provides three levels of granularity:
///
/// - [`process_file`](Self::process_file) - Load from path and run full pipeline
/// - [`process_assembly`](Self::process_assembly) - Full pipeline on a `CilObject`
/// - [`process_method`](Self::process_method) - Single method through the pipeline
/// - [`process_ssa`](Self::process_ssa) - Standalone SSA function (no detection)
///
/// # Example
///
/// ```no_run
/// use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
/// use dotscope::metadata::token::Token;
/// use dotscope::CilObject;
///
/// let config = EngineConfig::default();
/// let engine = DeobfuscationEngine::new(config);
///
/// // Process entire assembly from file
/// let (deobfuscated, result) = engine.process_file("obfuscated.dll")?;
/// println!("{}", result.summary());
///
/// // Or process a single method (consumes the assembly)
/// let assembly = CilObject::from_path("obfuscated.dll")?;
/// let method_token = Token::new(0x0600_0001);
/// let (ssa, result) = engine.process_method(assembly, method_token)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct DeobfuscationEngine {
    /// Configuration.
    config: EngineConfig,
    /// Technique-based deobfuscation registry.
    registry: TechniqueRegistry,
    /// Obfuscator attribution matcher.
    matcher: ObfuscatorMatcher,
}

impl Default for DeobfuscationEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

impl DeobfuscationEngine {
    /// Creates a new engine with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Engine configuration controlling iteration limits, thresholds, etc.
    ///
    /// # Returns
    ///
    /// A new `DeobfuscationEngine` instance ready to process assemblies.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let registry = TechniqueRegistry::with_config(config.detection_nop_threshold);
        Self {
            config,
            registry,
            matcher: ObfuscatorMatcher::default(),
        }
    }

    /// Registers a technique with the engine.
    ///
    /// Techniques are evaluated during the detection phase and, if detected,
    /// participate in byte-level transforms and SSA pass creation.
    ///
    /// # Arguments
    ///
    /// * `technique` - The technique to register. Ownership is transferred to the
    ///   engine's internal [`TechniqueRegistry`].
    pub fn register_technique(&mut self, technique: Box<dyn Technique>) {
        self.registry.register(technique);
    }

    /// Returns a reference to the technique registry.
    pub fn technique_registry(&self) -> &TechniqueRegistry {
        &self.registry
    }

    /// Creates a fresh pass scheduler configured from the engine settings.
    ///
    /// Called once per run so that each pipeline execution starts with a clean
    /// scheduler and no stale pass state.
    fn create_scheduler(&self) -> PassScheduler {
        let mut scheduler = PassScheduler::new();

        // Structure (layer 0) and Value (layer 1) passes are populated by
        // create_deob_passes() after AnalysisContext is built.

        // Simplification passes
        if self.config.passes.opaque_predicate_removal {
            scheduler.add(
                Box::new(AsSsaPass(OpaquePredicatePass::new())),
                PassPhase::Simplify,
            );
            scheduler.add(
                Box::new(AsSsaPass(ValueRangePropagationPass::new())),
                PassPhase::Simplify,
            );
        }
        if self.config.passes.control_flow_simplification {
            scheduler.add(
                Box::new(AsSsaPass(ControlFlowSimplificationPass)),
                PassPhase::Simplify,
            );
            scheduler.add(
                Box::new(AsSsaPass(JumpThreadingPass::new())),
                PassPhase::Simplify,
            );
        }

        // Inlining passes
        if self.config.passes.inlining {
            scheduler.add(
                Box::new(InliningPass::new(self.config.passes.inline_threshold)),
                PassPhase::Inline,
            );
        }

        // Normalization passes (run after each layer change in every iteration)
        // Proxy devirtualization always runs: it retargets proxy forwarders and
        // eliminates no-op calls, which is safe and exposes dead methods for DCE.
        scheduler.add(
            Box::new(ProxyDevirtualizationPass::new()),
            PassPhase::Normalize,
        );
        if self.config.passes.dead_code_elimination {
            scheduler.add(
                Box::new(AsSsaPass(DeadCodeEliminationPass)),
                PassPhase::Normalize,
            );
            scheduler.add(Box::new(AsSsaPass(BlockMergingPass)), PassPhase::Normalize);
            scheduler.add(Box::new(AsSsaPass(LicmPass::new())), PassPhase::Normalize);
        }
        if self.config.passes.constant_propagation {
            scheduler.add(
                Box::new(AsSsaPass(ReassociationPass::new())),
                PassPhase::Normalize,
            );
            scheduler.add(Box::new(ConstantPropagationPass), PassPhase::Normalize);
            scheduler.add(
                Box::new(AsSsaPass(GlobalValueNumberingPass::new())),
                PassPhase::Normalize,
            );
        }
        if self.config.passes.copy_propagation {
            scheduler.add(Box::new(CopyPropagationPass), PassPhase::Normalize);
        }
        if self.config.passes.memory_optimization {
            // Runs after copy propagation so the address expressions Memory SSA
            // decodes are already canonicalised, and before strength reduction /
            // algebraic simplification so the values it forwards out of memory
            // get folded in the same fixpoint iteration.
            scheduler.add(
                Box::new(AsSsaPass(MemoryOptimizationPass)),
                PassPhase::Normalize,
            );
        }
        if self.config.passes.strength_reduction {
            scheduler.add(
                Box::new(AsSsaPass(StrengthReductionPass::new())),
                PassPhase::Normalize,
            );
            scheduler.add(
                Box::new(AsSsaPass(AlgebraicSimplificationPass::new())),
                PassPhase::Normalize,
            );
        }

        scheduler
    }

    /// Creates infrastructure deobfuscation passes.
    ///
    /// Adds passes that are not owned by any specific technique:
    /// - [`DecryptionPass`]: shared by all string/constant decryption techniques
    ///   (ConfuserEx, BitMono, JIEJIE.NET, Obfuscar, Generic strings/constants)
    ///
    /// Technique-owned passes are created by their respective techniques via
    /// [`Technique::create_pass`] and added separately by the technique pipeline.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context.
    /// * `scheduler` - The pass scheduler to add passes to.
    fn create_deob_passes(&self, ctx: &AnalysisContext, scheduler: &mut PassScheduler) {
        if self.config.passes.string_decryption {
            scheduler.add(Box::new(DecryptionPass::new(ctx)), PassPhase::Value);
        }
    }
}

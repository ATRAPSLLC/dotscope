//! Configuration for the deobfuscation engine.
//!
//! This module provides configuration types for controlling the deobfuscation
//! pipeline, including pass selection, the work budget, the engine's own
//! rounds, and emulation settings.

use std::time::Duration;

use analyssa::analysis::{Budget, WorkBudget};

use crate::{
    deobfuscation::UnflattenConfig,
    emulation::{EmulationLimits, TracingConfig},
};

/// How many times the engine repeats its own phases: detection, the work
/// queue and the byte-transform pipeline.
///
/// These are the engine's loops around the passes, not a bound on any pass:
/// the passes, the scheduler that runs them and every analysis they read take
/// their bounds from [`EngineConfig::budget`].
#[derive(Debug, Clone)]
pub struct IterationConfig {
    /// Maximum number of detection re-scan rounds (default: 2).
    pub max_detection_rounds: usize,
    /// Maximum outer fixpoint iterations for the work queue loop (default: 10).
    pub max_outer_iterations: usize,
    /// Maximum pipeline-level iterations for byte-transform re-runs (default: 3).
    ///
    /// Each pipeline iteration rebuilds SSA from scratch, so this is intentionally
    /// small. Increase only for assemblies that require multiple SSA↔byte-transform
    /// cycles (e.g., layered protections that reveal new byte-transforms after SSA).
    pub max_pipeline_iterations: usize,
}

impl Default for IterationConfig {
    fn default() -> Self {
        Self {
            max_detection_rounds: 2,
            max_outer_iterations: 10,
            max_pipeline_iterations: 3,
        }
    }
}

/// SSA optimization pass toggles.
#[derive(Debug, Clone)]
pub struct PassConfig {
    /// Enable string decryption pass.
    pub string_decryption: bool,
    /// Enable constant propagation pass.
    pub constant_propagation: bool,
    /// Enable dead code elimination pass.
    pub dead_code_elimination: bool,
    /// Enable opaque predicate removal pass.
    pub opaque_predicate_removal: bool,
    /// Enable copy propagation pass.
    pub copy_propagation: bool,
    /// Enable the memory optimization pass (store-to-load forwarding, redundant
    /// load elimination, dead store elimination).
    ///
    /// Every rewrite is gated on a Memory SSA alias proof, so this reaches the
    /// field and array traffic that obfuscators use to keep values out of SSA
    /// registers - ConfuserEx state fields, array-backed string tables - which
    /// the register-level passes cannot see through.
    pub memory_optimization: bool,
    /// Enable strength reduction pass (mul->shl, div->shr, rem->and for powers of 2).
    pub strength_reduction: bool,
    /// Enable control flow simplification pass.
    pub control_flow_simplification: bool,
    /// Enable interprocedural analysis.
    pub interprocedural: bool,
    /// Enable method inlining.
    pub inlining: bool,
    /// Maximum instruction count for inlining candidates.
    pub inline_threshold: usize,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            string_decryption: true,
            constant_propagation: true,
            dead_code_elimination: true,
            opaque_predicate_removal: true,
            copy_propagation: true,
            memory_optimization: true,
            strength_reduction: true,
            control_flow_simplification: true,
            interprocedural: true,
            inlining: false,
            inline_threshold: 20,
        }
    }
}

/// Emulation engine limits.
#[derive(Debug, Clone)]
pub struct EmulationConfig {
    /// The limits of the template process every emulation forks from.
    ///
    /// Warmup (Module.cctor and the techniques' warmup) runs under them whole,
    /// and each per-method emulation runs under them with its own wall clock,
    /// [`timeout`](Self::timeout): a fork inherits the template's warmed heap by
    /// copy-on-write, so every other ceiling has to stay the one the template
    /// was held to (see [`execution_limits`](Self::execution_limits)).
    /// [`max_instructions`](EmulationLimits::max_instructions) bounds one
    /// emulation deterministically. The default allows 1M instructions, a call
    /// depth of 100 and a 512 MiB heap, and warmup a 60 s clock.
    pub limits: EmulationLimits,
    /// Wall-clock limit on one method's emulation; zero for none.
    ///
    /// A wall-clock limit makes the result depend on how fast the machine runs: under load
    /// an emulation stops earlier, and a value it would have decrypted is left encrypted.
    /// The instruction limit bounds emulation deterministically.
    pub timeout: Duration,
    /// Tracing configuration for emulation debugging.
    pub tracing: Option<TracingConfig>,
    /// Number of retry passes for warmup methods with dependency chains.
    pub warmup_retry_passes: usize,
    /// Maximum emulations a single deobfuscation run may perform, or 0 for unlimited.
    ///
    /// The instruction limit and [`timeout`](Self::timeout) bound one
    /// emulation. Neither bounds how many a run performs: the decryption pass emulates once
    /// per distinct call site with constant arguments, and its value cache is keyed on
    /// `(decryptor, args)`, so a loop calling a decryptor with a varying key misses the cache
    /// every iteration. This is the ceiling on the run as a whole.
    pub max_emulations: usize,
}

impl EmulationConfig {
    /// Limits for one per-method emulation: the template's
    /// [`limits`](Self::limits) whole, under the per-method
    /// [`timeout`](Self::timeout).
    ///
    /// Every per-method execution is forked from the template, and forking
    /// shares the emulator's configuration `Arc` by default, so without these
    /// applied explicitly a per-method execution would silently inherit the
    /// warmup clock. Everything but the clock stays the template's: a fork
    /// runs on the heap the template warmed, so a ceiling below the template's
    /// would fail every per-method decryption of a sample whose warmup
    /// allocated past it.
    #[must_use]
    pub fn execution_limits(&self) -> EmulationLimits {
        EmulationLimits {
            timeout_ms: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            ..self.limits.clone()
        }
    }
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            limits: EmulationLimits {
                max_instructions: 1_000_000,
                max_call_depth: 100,
                max_heap_bytes: 512 * 1024 * 1024,
                timeout_ms: 60_000,
                ..EmulationLimits::default()
            },
            timeout: Duration::from_secs(5),
            tracing: None,
            warmup_retry_passes: 5,
            max_emulations: 100_000,
        }
    }
}

/// Confidence scoring weights for CFF dispatcher detection.
///
/// Each weight corresponds to a signal used in `compute_confidence()` to assess
/// how likely a candidate basic block is a CFF dispatcher. The final score is
/// the sum of all weighted signals, capped at 1.0.
#[derive(Debug, Clone)]
pub struct DetectionWeights {
    /// Base score for having ≥3 case blocks, plus bonuses at ≥5 and ≥10.
    pub case_count_base: f64,
    /// Bonus per threshold tier for case count (≥5 and ≥10).
    pub case_count_bonus: f64,
    /// Weight for state variable with phi node present.
    pub state_variable: f64,
    /// Weight for state variable being updated in most case blocks.
    pub state_update_coverage: f64,
    /// Weight for dispatcher having many predecessors (back-edges).
    pub predecessor_ratio: f64,
    /// Weight for back-edge reachability ratio (cases that reach dispatcher).
    pub back_edge_ratio: f64,
    /// Weight for having exit blocks.
    pub exit_blocks: f64,
    /// Bonus for switch-based dispatcher (vs branch-based).
    pub switch_bonus: f64,
    /// Bonus for modulo transform presence (strong CFF indicator).
    pub modulo_bonus: f64,
    /// Weight for dominance ratio (dispatcher dominates case blocks).
    pub dominance_ratio: f64,
    /// Weight for method coverage ratio (fraction of all blocks dominated).
    pub method_coverage: f64,
}

impl Default for DetectionWeights {
    fn default() -> Self {
        Self {
            case_count_base: 0.10,
            case_count_bonus: 0.05,
            state_variable: 0.15,
            state_update_coverage: 0.10,
            predecessor_ratio: 0.10,
            back_edge_ratio: 0.10,
            exit_blocks: 0.05,
            switch_bonus: 0.10,
            modulo_bonus: 0.10,
            dominance_ratio: 0.20,
            method_coverage: 0.10,
        }
    }
}

/// Configuration for the deobfuscation engine.
///
/// Controls all aspects of the deobfuscation pipeline including the work
/// budget, the engine's own rounds, pass selection and emulation parameters.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// How much work the passes, their scheduler and the analyses they read
    /// may do: every fixpoint's rounds and every analysis's budget.
    ///
    /// [`EngineConfig::BUDGET`] by default.
    pub budget: WorkBudget,

    /// How many times the engine repeats its own phases.
    pub iterations: IterationConfig,

    /// SSA optimization pass toggles.
    pub passes: PassConfig,

    /// Emulation engine limits.
    pub emulation: EmulationConfig,

    /// CFF unflattening: detection's thresholds and weights. The machine is
    /// the assembly's, set when detection runs.
    pub unflattening: UnflattenConfig,

    /// NOP threshold for dead method detection in BitMono-style junk analysis.
    pub detection_nop_threshold: usize,

    /// Post-deobfuscation cleanup configuration.
    pub cleanup: CleanupConfig,
}

/// Configuration for post-deobfuscation cleanup.
///
/// Controls what artifacts are removed after the deobfuscation passes complete.
/// Most options default to `true` for maximum cleanup, except `remove_unused_methods`
/// which defaults to `false` to preserve exported/reflection-used methods.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Remove fully-decrypted AND dead decryptor methods.
    pub remove_decryptors: bool,

    /// Remove dead protection methods (anti-tamper, anti-debug, resource handlers).
    pub remove_protection_methods: bool,

    /// Remove types that become empty after method removal.
    pub remove_empty_types: bool,

    /// Remove orphaned Param/CustomAttribute entries for removed methods.
    pub remove_orphan_metadata: bool,

    /// Remove PE sections containing encrypted/artifact data.
    ///
    /// This removes sections that contain encrypted method bodies or other
    /// obfuscator-specific data that is no longer needed after deobfuscation.
    pub remove_artifact_sections: bool,

    /// Rename obfuscated type and method names to simple identifiers.
    ///
    /// This replaces unicode/non-printable names with sequential simple names
    /// like A, B, C, ..., AA, AB, etc. to reduce binary size and improve readability.
    pub rename_obfuscated_names: bool,

    /// Remove methods that become unused after inlining.
    ///
    /// This is disabled by default because:
    /// - DLLs may export methods that appear unused but are called via reflection
    /// - Framework methods may be invoked dynamically
    /// - Malware analysts often want to see the original structure
    ///
    /// Enable this in aggressive mode for maximum size reduction.
    pub remove_unused_methods: bool,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            remove_decryptors: true,
            remove_protection_methods: true,
            remove_empty_types: true,
            remove_orphan_metadata: true,
            remove_artifact_sections: true,
            rename_obfuscated_names: true,
            remove_unused_methods: false, // Off by default - may break reflection/exports
        }
    }
}

impl CleanupConfig {
    /// Creates a new cleanup configuration with all options enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration with all cleanup disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            remove_decryptors: false,
            remove_protection_methods: false,
            remove_empty_types: false,
            remove_orphan_metadata: false,
            remove_artifact_sections: false,
            rename_obfuscated_names: false,
            remove_unused_methods: false,
        }
    }

    /// Returns true if any cleanup is enabled.
    #[must_use]
    pub fn any_enabled(&self) -> bool {
        self.remove_decryptors
            || self.remove_protection_methods
            || self.remove_empty_types
            || self.remove_orphan_metadata
            || self.remove_artifact_sections
            || self.rename_obfuscated_names
            || self.remove_unused_methods
    }

    /// Creates a configuration for aggressive cleanup (all options enabled).
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            remove_unused_methods: true,
            ..Self::default()
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            budget: Self::BUDGET,
            iterations: IterationConfig::default(),
            passes: PassConfig::default(),
            emulation: EmulationConfig::default(),
            unflattening: UnflattenConfig::default(),
            detection_nop_threshold: 50_000,
            cleanup: CleanupConfig::default(),
        }
    }
}

impl EngineConfig {
    /// The work budget the engine runs under: analyssa's, with 20 scheduler
    /// rounds that stop after 2 that change nothing and 10 a layer, and the
    /// rewriting passes' rounds - dead code 20, copies 15, constant folding
    /// 10, block merging 50 and control flow 20.
    pub const BUDGET: WorkBudget = WorkBudget::DEFAULT
        .with_limit(Budget::PipelineRounds, 20)
        .with_limit(Budget::StableRounds, 2)
        .with_limit(Budget::PhaseRounds, 10)
        .with_limit(Budget::DeadCodeRounds, 20)
        .with_limit(Budget::CopyRounds, 15)
        .with_limit(Budget::FoldRounds, 10)
        .with_limit(Budget::BlockMergeRounds, 50)
        .with_limit(Budget::ControlFlowRounds, 20);

    /// Creates a new configuration with default settings.
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a "fast" configuration for quick processing.
    ///
    /// This configuration uses:
    /// - Fewer scheduler rounds (5 max, stopping after 1 that changes nothing)
    /// - Limited emulation (100k instructions)
    /// - No inlining
    /// - No interprocedural analysis
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` optimized for speed over thoroughness.
    #[must_use]
    pub fn fast() -> Self {
        let emulation = EmulationConfig::default();
        Self {
            budget: Self::BUDGET
                .with_limit(Budget::PipelineRounds, 5)
                .with_limit(Budget::StableRounds, 1),
            iterations: IterationConfig {
                max_detection_rounds: 1,
                ..Default::default()
            },
            passes: PassConfig {
                interprocedural: false,
                inlining: false,
                ..Default::default()
            },
            emulation: EmulationConfig {
                limits: EmulationLimits {
                    max_instructions: 100_000,
                    timeout_ms: 30_000,
                    ..emulation.limits
                },
                timeout: Duration::from_millis(500),
                warmup_retry_passes: 2,
                max_emulations: 10_000,
                ..emulation
            },
            ..Self::default()
        }
    }

    /// Creates an "aggressive" configuration for maximum deobfuscation.
    ///
    /// This configuration uses:
    /// - More scheduler rounds (50 max, stopping after 3 that change nothing)
    /// - Extended emulation limits (10M instructions)
    /// - All features enabled including inlining
    /// - Aggressive cleanup (removes unused methods after inlining)
    ///
    /// # Returns
    ///
    /// A new `EngineConfig` optimized for thoroughness over speed.
    #[must_use]
    pub fn aggressive() -> Self {
        let emulation = EmulationConfig::default();
        Self {
            budget: Self::BUDGET
                .with_limit(Budget::PipelineRounds, 50)
                .with_limit(Budget::StableRounds, 3),
            iterations: IterationConfig {
                max_detection_rounds: 3,
                ..Default::default()
            },
            passes: PassConfig {
                inlining: true,
                inline_threshold: 50,
                interprocedural: true,
                ..Default::default()
            },
            emulation: EmulationConfig {
                limits: EmulationLimits {
                    max_instructions: 10_000_000,
                    timeout_ms: 120_000,
                    ..emulation.limits
                },
                timeout: Duration::from_secs(30),
                warmup_retry_passes: 8,
                max_emulations: 1_000_000,
                ..emulation
            },
            unflattening: UnflattenConfig {
                max_backedge_depth: 15,
                ..Default::default()
            },
            cleanup: CleanupConfig::aggressive(),
            ..Self::default()
        }
    }

    /// Sets the work budget the passes, their scheduler and their analyses
    /// run under.
    ///
    /// # Arguments
    ///
    /// * `budget` - The work budget, normally [`EngineConfig::BUDGET`] with
    ///   the limits to change.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_budget(mut self, budget: WorkBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Sets emulation limits for string decryption and value resolution.
    ///
    /// # Arguments
    ///
    /// * `max_instructions` - Maximum instructions to execute per emulation,
    ///   warmup's included.
    /// * `timeout` - Maximum wall-clock time to spend on emulation per method; zero for none.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_emulation_limits(mut self, max_instructions: u64, timeout: Duration) -> Self {
        self.emulation.limits.max_instructions = max_instructions;
        self.emulation.timeout = timeout;
        self
    }

    /// Enables or disables method inlining.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable method inlining.
    /// * `threshold` - Maximum instruction count for inlining candidates.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_inlining(mut self, enable: bool, threshold: usize) -> Self {
        self.passes.inlining = enable;
        self.passes.inline_threshold = threshold;
        self
    }

    /// Enables or disables interprocedural analysis.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable interprocedural analysis.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_interprocedural(mut self, enable: bool) -> Self {
        self.passes.interprocedural = enable;
        self
    }

    /// Sets the pass configuration.
    ///
    /// # Arguments
    ///
    /// * `passes` - The pass configuration to use.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_passes(mut self, passes: PassConfig) -> Self {
        self.passes = passes;
        self
    }

    /// Checks if all core passes are enabled.
    ///
    /// # Returns
    ///
    /// `true` if all core deobfuscation passes are enabled.
    #[must_use]
    pub fn all_passes_enabled(&self) -> bool {
        self.passes.string_decryption
            && self.passes.constant_propagation
            && self.passes.dead_code_elimination
            && self.passes.opaque_predicate_removal
            && self.passes.copy_propagation
            && self.passes.strength_reduction
            && self.passes.control_flow_simplification
    }

    /// Sets the tracing configuration for emulation debugging.
    ///
    /// When set, emulation processes created during deobfuscation will write
    /// trace events to the configured output.
    ///
    /// # Arguments
    ///
    /// * `tracing` - The tracing configuration to use.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_tracing(mut self, tracing: TracingConfig) -> Self {
        self.emulation.tracing = Some(tracing);
        self
    }

    /// Sets the warmup timeout for template pool initialization.
    ///
    /// The template pool executes Module.cctor and technique warmup methods
    /// during initialization. Complex assemblies (e.g., PureLogs with ~1.88M
    /// instructions) may require longer timeouts.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum wall-clock time for warmup execution; zero for none.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_warmup_timeout(mut self, timeout: Duration) -> Self {
        self.emulation.limits.timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// Sets the number of retry passes for warmup methods.
    ///
    /// Warmup methods may have dependency chains (e.g., type A's .cctor
    /// depends on type B's .cctor). Multiple passes retry failed methods
    /// after their dependencies have been initialized.
    ///
    /// # Arguments
    ///
    /// * `passes` - Number of retry passes (each pass retries previously failed methods).
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_warmup_retry_passes(mut self, passes: usize) -> Self {
        self.emulation.warmup_retry_passes = passes;
        self
    }

    /// Sets the NOP threshold for dead method detection.
    ///
    /// Methods in `<Module>` containing more than this many `nop` instructions
    /// are flagged as BitMono BillionNops dead methods for removal.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum NOP count to classify a method as dead.
    ///
    /// # Returns
    ///
    /// The modified configuration (builder pattern).
    #[must_use]
    pub fn with_nop_threshold(mut self, threshold: usize) -> Self {
        self.detection_nop_threshold = threshold;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.budget, EngineConfig::BUDGET);
        assert_eq!(config.budget.limit(Budget::PipelineRounds), 20);
        assert!(config.passes.string_decryption);
        assert!(config.passes.interprocedural);
        assert!(!config.passes.inlining); // Disabled by default
        assert!(!config.cleanup.remove_unused_methods); // Disabled by default
        assert_eq!(config.emulation.limits.timeout_ms, 60_000);
        assert_eq!(config.emulation.warmup_retry_passes, 5);
        assert_eq!(config.unflattening.max_backedge_depth, 10);
        assert_eq!(config.detection_nop_threshold, 50_000);
    }

    #[test]
    fn test_fast_config() {
        let config = EngineConfig::fast();
        assert_eq!(config.budget.limit(Budget::PipelineRounds), 5);
        assert_eq!(config.budget.limit(Budget::StableRounds), 1);
        assert!(!config.passes.interprocedural);
        assert_eq!(config.emulation.limits.timeout_ms, 30_000);
        assert_eq!(config.emulation.limits.max_instructions, 100_000);
        assert_eq!(config.emulation.warmup_retry_passes, 2);
    }

    #[test]
    fn test_aggressive_config() {
        let config = EngineConfig::aggressive();
        assert_eq!(config.budget.limit(Budget::PipelineRounds), 50);
        assert_eq!(config.budget.limit(Budget::StableRounds), 3);
        assert!(config.passes.inlining);
        assert!(config.passes.interprocedural);
        assert!(config.cleanup.remove_unused_methods); // Enabled in aggressive mode
        assert_eq!(config.emulation.limits.timeout_ms, 120_000);
        assert_eq!(config.emulation.warmup_retry_passes, 8);
        assert_eq!(config.unflattening.max_backedge_depth, 15);
    }

    /// A preset changes the limits it names and keeps every other limit of
    /// the template, so a fast run is not also held to a smaller heap.
    #[test]
    fn a_preset_keeps_the_template_limits_it_does_not_name() {
        let template = EmulationConfig::default().limits;
        for config in [EngineConfig::fast(), EngineConfig::aggressive()] {
            let limits = &config.emulation.limits;
            assert_eq!(limits.max_call_depth, template.max_call_depth);
            assert_eq!(limits.max_heap_bytes, template.max_heap_bytes);
            assert_eq!(limits.max_unmanaged_bytes, template.max_unmanaged_bytes);
        }
    }

    #[test]
    fn test_builder_pattern() {
        let config = EngineConfig::new()
            .with_budget(EngineConfig::BUDGET.with_limit(Budget::PipelineRounds, 100));

        assert_eq!(config.budget.limit(Budget::PipelineRounds), 100);
    }

    #[test]
    fn test_detection_weights_default() {
        let w = DetectionWeights::default();
        assert!((w.case_count_base - 0.10).abs() < f64::EPSILON);
        assert!((w.state_variable - 0.15).abs() < f64::EPSILON);
        assert!((w.dominance_ratio - 0.20).abs() < f64::EPSILON);
        assert!((w.method_coverage - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn test_builder_warmup_and_nop() {
        let config = EngineConfig::new()
            .with_warmup_timeout(Duration::from_secs(120))
            .with_warmup_retry_passes(10)
            .with_nop_threshold(100_000);

        assert_eq!(config.emulation.limits.timeout_ms, 120_000);
        assert_eq!(config.emulation.warmup_retry_passes, 10);
        assert_eq!(config.detection_nop_threshold, 100_000);
    }

    /// A per-method execution must run under `timeout`, not the template's warmup clock.
    ///
    /// Forking shares the emulator's configuration `Arc`, so without applying these limits
    /// explicitly the documented per-method budget is written and never read and the method
    /// runs under the warmup budget instead.
    #[test]
    fn execution_limits_use_the_per_method_timeout() {
        let config = EmulationConfig::default();
        let limits = config.execution_limits();

        assert_eq!(
            limits.timeout_ms,
            u64::try_from(config.timeout.as_millis()).unwrap()
        );
        assert_ne!(
            limits.timeout_ms, config.limits.timeout_ms,
            "a per-method execution must not inherit the warmup budget"
        );
        assert_eq!(limits.max_instructions, config.limits.max_instructions);
    }

    /// The `fast()` preset tightens the per-method budget; the derivation must follow the
    /// configuration rather than any default.
    #[test]
    fn execution_limits_follow_the_preset() {
        let fast = EngineConfig::fast();

        assert_eq!(
            fast.emulation.execution_limits().timeout_ms,
            u64::try_from(fast.emulation.timeout.as_millis()).unwrap()
        );
        assert_eq!(
            fast.emulation.execution_limits().max_instructions,
            fast.emulation.limits.max_instructions
        );
    }

    /// Everything the per-method budget does not name must come from the template being
    /// forked, not from [`EmulationLimits::default`].
    ///
    /// The template pool builds with a call depth of 100 and a 512 MiB heap, and a fork
    /// inherits the warmed heap by copy-on-write. Defaulting the unnamed fields instead
    /// raised the depth to 1000 and *lowered* the heap to 256 MiB, so a sample whose warmup
    /// allocated past 256 MiB failed every per-method decryption on a ceiling the template
    /// had never been held to.
    #[test]
    fn execution_limits_inherit_every_unnamed_field_from_the_template() {
        let config = EmulationConfig {
            limits: EmulationLimits {
                max_unmanaged_bytes: 7 * 1024 * 1024,
                ..EmulationConfig::default().limits
            },
            ..EmulationConfig::default()
        };

        let limits = config.execution_limits();

        assert_eq!(limits.max_call_depth, 100);
        assert_eq!(limits.max_heap_bytes, 512 * 1024 * 1024);
        assert_eq!(
            limits.max_unmanaged_bytes,
            config.limits.max_unmanaged_bytes
        );
        assert_ne!(
            limits.max_heap_bytes,
            EmulationLimits::default().max_heap_bytes,
            "the template's heap ceiling must survive the derivation"
        );

        // Only the per-method clock is overridden.
        assert_eq!(limits.max_instructions, config.limits.max_instructions);
        assert_eq!(
            limits.timeout_ms,
            u64::try_from(config.timeout.as_millis()).unwrap()
        );
    }
}

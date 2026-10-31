//! Shared integration test framework for deobfuscation tests.
//!
//! Provides common types, harness functions, and assertion helpers used across
//! all obfuscator integration tests (ConfuserEx, BitMono, JIEJIE.NET, Obfuscar).

use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use crate::{
    deobfuscation::{DeobfuscationEngine, DeobfuscationResult, EngineConfig},
    metadata::{
        method::{exception_structure_defects, Method},
        validation::ValidationConfig,
    },
    testkit::{
        fixtures::fixture,
        verification::{
            assert_structural_match, inlined_away, pure_methods_of, run_pure_methods,
            verify_semantic_preservation, AssemblyStats, PureMethod, SemanticVerificationResult,
            StructuralConfig, PURE_TEST_METHODS,
        },
    },
    CilObject, Error,
};

/// `config` without the emulation wall-clock limits, so a test's result never depends on
/// how busy the machine is: emulation stays bounded by its instruction, call-depth and memory
/// limits alone. Every engine a test builds goes through this.
#[must_use]
pub fn without_wall_clock(mut config: EngineConfig) -> EngineConfig {
    config.emulation.timeout = Duration::ZERO;
    config.emulation.warmup_timeout = Duration::ZERO;
    config
}

/// An engine with the default configuration, [`without_wall_clock`].
#[must_use]
pub fn engine() -> DeobfuscationEngine {
    DeobfuscationEngine::new(without_wall_clock(EngineConfig::default()))
}

/// An engine with `config`, [`without_wall_clock`].
#[must_use]
pub fn engine_with(config: EngineConfig) -> DeobfuscationEngine {
    DeobfuscationEngine::new(without_wall_clock(config))
}

/// What [`engine`] made of one sample: the output and the run's result, or the error it
/// refused the sample with.
pub type DeobOutcome = std::result::Result<(CilObject, DeobfuscationResult), Error>;

/// `sample`, a fixture path, deobfuscated by [`engine`] through `process_file`, once per test
/// binary.
///
/// The run is the expensive part of a packer test, and several tests check the same sample.
/// The first call runs it; every later call, from any test, gets that outcome, and a call made
/// while the run is in progress waits for it.
pub fn deobfuscated(sample: &str) -> &'static DeobOutcome {
    static RUNS: OnceLock<Mutex<HashMap<String, &'static OnceLock<DeobOutcome>>>> = OnceLock::new();
    let run: &'static OnceLock<DeobOutcome> = RUNS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(sample.to_owned())
        .or_insert_with(|| Box::leak(Box::default()));
    run.get_or_init(|| engine().process_file(fixture(sample)))
}

/// A family's unprotected original, what the harness compares each of its samples against.
pub struct Original {
    /// The assembly.
    pub assembly: Arc<CilObject>,
    /// Its structure.
    pub stats: AssemblyStats,
    /// Its [`PURE_TEST_METHODS`], each with the method it is.
    pub pure_methods: Vec<(&'static PureMethod, Arc<Method>)>,
    /// What they returned, run by [`run_pure_methods`].
    pub pure_results: HashMap<&'static str, Vec<String>>,
}

impl Debug for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Original")
            .field("stats", &self.stats)
            .field("pure_results", &self.pure_results)
            .finish_non_exhaustive()
    }
}

/// The `original.exe` of `samples_dir`, a fixture directory, loaded and run once per test
/// binary.
///
/// # Panics
///
/// When it does not load: every sample family has one, and its samples are compared with it.
pub fn original(samples_dir: &str) -> &'static Original {
    static ORIGINALS: OnceLock<Mutex<HashMap<String, &'static OnceLock<Original>>>> =
        OnceLock::new();
    let slot: &'static OnceLock<Original> = ORIGINALS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(samples_dir.to_owned())
        .or_insert_with(|| Box::leak(Box::default()));
    slot.get_or_init(|| {
        let path = fixture(&format!("{samples_dir}/original.exe"));
        let assembly = Arc::new(
            load_sample(samples_dir, "original.exe")
                .unwrap_or_else(|error| panic!("{samples_dir}: {error}")),
        );
        let pure_methods = pure_methods_of(&assembly, PURE_TEST_METHODS);
        let pure_results = run_pure_methods(&assembly, &pure_methods);
        Original {
            stats: AssemblyStats::from_file(&path),
            assembly,
            pure_methods,
            pure_results,
        }
    })
}

/// Description of a sample and its expected characteristics.
///
/// Generic over `P` so each obfuscator can define its own expected-protections struct.
#[derive(Debug, Clone)]
pub struct SampleSpec<P: Clone + Debug> {
    /// Filename relative to the samples directory.
    pub filename: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Expected protections present BEFORE deobfuscation.
    pub expected_protections: P,
    /// Whether this is the unprotected original (baseline).
    pub is_original: bool,
    /// Check semantic preservation against original.exe.
    pub check_semantic_preservation: bool,
    /// Check structural match against original.exe.
    pub check_structural_match: bool,
    /// Structural match configuration overrides.
    pub structural_config: StructuralConfig,
}

/// How a sample is read before its [`deobfuscated`] run, which both modes share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMode {
    /// The sample loads as it is, and detection on it before the run joins the run's own.
    Assembly,
    /// The sample may need the PE repair `process_file` applies; detection is the run's.
    File,
}

/// Pipeline statistics extracted from deobfuscation results.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub methods_transformed: usize,
    pub constants_folded: usize,
    pub strings_decrypted: usize,
    pub branches_simplified: usize,
    pub artifacts_removed: usize,
}

/// A single technique detection result.
#[derive(Debug, Clone)]
pub struct DetectedTechnique {
    pub id: String,
    pub detected: bool,
    pub evidence_count: usize,
}

/// Aggregated detection information.
#[derive(Debug, Clone, Default)]
pub struct DetectionInfo {
    pub techniques: Vec<DetectedTechnique>,
    pub obfuscator_name: Option<String>,
    pub technique_ids: Vec<String>,
    pub supporting_matched: usize,
}

impl DetectionInfo {
    /// Build from a `DeobfuscationResult`.
    pub fn from_results(result: &DeobfuscationResult) -> Self {
        let techniques: Vec<DetectedTechnique> = result
            .techniques
            .iter()
            .map(|t| DetectedTechnique {
                id: t.id.clone(),
                detected: t.detected,
                evidence_count: t.evidence.len(),
            })
            .collect();

        let (obfuscator_name, technique_ids, supporting_matched) =
            if let Some(ref attr) = result.attribution {
                (
                    Some(attr.obfuscator_name.clone()),
                    attr.technique_ids.clone(),
                    attr.supporting_matched,
                )
            } else {
                (None, Vec::new(), 0)
            };

        Self {
            techniques,
            obfuscator_name,
            technique_ids,
            supporting_matched,
        }
    }

    /// Merge pipeline attribution into pre-detection info.
    pub fn merge(&mut self, pipeline: &DetectionInfo) {
        // Pipeline attribution is authoritative — it combines both IL and
        // SSA-detected techniques. Prefer it when present.
        if pipeline.obfuscator_name.is_some() {
            self.obfuscator_name = pipeline.obfuscator_name.clone();
            self.technique_ids = pipeline.technique_ids.clone();
            self.supporting_matched = pipeline.supporting_matched;
        }
        // Merge technique lists (pipeline may discover additional techniques)
        for pt in &pipeline.techniques {
            if !self.techniques.iter().any(|t| t.id == pt.id) {
                self.techniques.push(pt.clone());
            } else if pt.detected {
                // Upgrade existing to detected if pipeline found it
                if let Some(existing) = self.techniques.iter_mut().find(|t| t.id == pt.id) {
                    existing.detected = true;
                    existing.evidence_count = existing.evidence_count.max(pt.evidence_count);
                }
            }
        }
    }

    /// Check if a technique was detected.
    pub fn has_technique(&self, id: &str) -> bool {
        self.techniques.iter().any(|t| t.id == id && t.detected)
    }

    /// Get evidence count for a technique.
    pub fn technique_evidence_count(&self, id: &str) -> usize {
        self.techniques
            .iter()
            .find(|t| t.id == id && t.detected)
            .map_or(0, |t| t.evidence_count)
    }

    /// Confidence as a simple 0.0/1.0 based on whether attribution is present.
    pub fn confidence(&self) -> f32 {
        if self.obfuscator_name.is_some() {
            1.0
        } else {
            0.0
        }
    }
}

/// Results from deobfuscating a sample.
#[derive(Debug)]
pub struct TestResult<P: Clone + Debug> {
    pub sample: SampleSpec<P>,
    pub success: bool,
    pub error: Option<String>,
    pub methods_before: usize,
    pub methods_after: usize,
    pub assembly_valid: bool,
    pub has_valid_entry_point: bool,
    pub roundtrip_ok: bool,
    /// Pre-detection merged with pipeline detection.
    pub detection: DetectionInfo,
    /// Re-detection on deobfuscated output.
    pub post_detection: DetectionInfo,
    pub switches_remaining: usize,
    pub stats: Option<PipelineStats>,
    pub semantic_result: Option<SemanticVerificationResult>,
    pub deobfuscated_stats: Option<AssemblyStats>,
    /// The family's unprotected original, compared with.
    pub original: &'static Original,
    /// The output's methods whose exception clauses do not structure their code as ECMA-335
    /// requires, a defect each (see [`exception_structure_defects`]).
    pub structure_defects: Vec<String>,
}

/// Load sample `filename` from `samples_dir`, a fixture directory under `tests/samples`.
pub fn load_sample(samples_dir: &str, filename: &str) -> Result<CilObject, String> {
    let path = fixture(&format!("{samples_dir}/{filename}"));
    CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .map_err(|e| format!("Failed to load {}: {}", filename, e))
}

/// Run the full deobfuscation test harness on a sample in `samples_dir`, a fixture directory
/// under `tests/samples`.
pub fn run_deobfuscation_test<P: Clone + Debug>(
    spec: &SampleSpec<P>,
    samples_dir: &str,
    mode: ProcessMode,
) -> TestResult<P> {
    let mut result = TestResult {
        sample: spec.clone(),
        success: false,
        error: None,
        methods_before: 0,
        methods_after: 0,
        assembly_valid: false,
        has_valid_entry_point: false,
        roundtrip_ok: false,
        detection: DetectionInfo::default(),
        post_detection: DetectionInfo::default(),
        switches_remaining: 0,
        stats: None,
        semantic_result: None,
        deobfuscated_stats: None,
        original: original(samples_dir),
        structure_defects: Vec::new(),
    };

    let sample = format!("{samples_dir}/{}", spec.filename);

    // For File mode, try to load the assembly for pre-deobfuscation method count
    // (it may fail for PE-corrupted samples: then nothing can be said about the methods the
    // run inlined away, and the semantic check counts them as lost).
    let file_input = if mode == ProcessMode::File {
        load_sample(samples_dir, spec.filename).ok()
    } else {
        None
    };
    if let Some(input) = &file_input {
        result.methods_before = input.methods().iter().count();
    }

    // For Assembly mode, load normally
    if mode == ProcessMode::Assembly {
        let assembly = match load_sample(samples_dir, spec.filename) {
            Ok(a) => a,
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        };
        result.methods_before = assembly.methods().iter().count();

        // Run pre-detection (IL + SSA)
        let detect_engine = engine();
        let pre_det = detect_engine.detect(&assembly);
        result.detection = DetectionInfo::from_results(&pre_det);

        // Original samples: early return with success
        if spec.is_original {
            result.success = true;
            result.methods_after = result.methods_before;
            result.assembly_valid = true;
            result.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
            result.roundtrip_ok = true;
            return result;
        }

        match deobfuscated(&sample) {
            Ok((output, deob_result)) => {
                populate_success_result(&mut result, output, deob_result, spec, Some(&assembly));
            }
            Err(e) => {
                result.error = Some(format!("Deobfuscation failed: {}", e));
            }
        }
    } else {
        // File mode — original check
        if spec.is_original {
            match load_sample(samples_dir, spec.filename) {
                Ok(assembly) => {
                    result.methods_before = assembly.methods().iter().count();
                    result.methods_after = result.methods_before;
                    result.success = true;
                    result.assembly_valid = true;
                    result.has_valid_entry_point = assembly.cor20header().entry_point_token != 0;
                    result.roundtrip_ok = true;
                }
                Err(e) => result.error = Some(e),
            }
            return result;
        }

        match deobfuscated(&sample) {
            Ok((output, deob_result)) => {
                // For File mode, detection comes from the pipeline result
                result.detection = DetectionInfo::from_results(deob_result);
                populate_success_result(
                    &mut result,
                    output,
                    deob_result,
                    spec,
                    file_input.as_ref(),
                );
            }
            Err(e) => {
                result.error = Some(format!("Deobfuscation failed: {}", e));
            }
        }
    }

    result
}

/// Populate result fields after successful deobfuscation.
fn populate_success_result<P: Clone + Debug>(
    result: &mut TestResult<P>,
    output: &CilObject,
    deob_result: &DeobfuscationResult,
    spec: &SampleSpec<P>,
    input: Option<&CilObject>,
) {
    result.success = true;
    result.methods_after = output.methods().iter().count();

    // Merge pipeline attribution into detection
    let pipeline_detection = DetectionInfo::from_results(deob_result);
    result.detection.merge(&pipeline_detection);

    // Stats
    let stats = deob_result.stats();
    result.stats = Some(PipelineStats {
        methods_transformed: stats.methods_transformed,
        constants_folded: stats.constants_folded,
        strings_decrypted: stats.strings_decrypted,
        branches_simplified: stats.branches_simplified,
        artifacts_removed: stats.artifacts_removed,
    });

    // Entry point
    result.has_valid_entry_point = output.cor20header().entry_point_token != 0;

    // Re-detect on output
    let post_engine = engine();
    let post_det = post_engine.detect(output);
    result.post_detection = DetectionInfo::from_results(&post_det);

    // Roundtrip verification
    let bytes = output.file().data();
    match CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production()) {
        Ok(reloaded) => {
            result.assembly_valid = true;
            result.roundtrip_ok = output.methods().iter().count()
                == reloaded.methods().iter().count()
                && output.types().iter().count() == reloaded.types().iter().count();
        }
        Err(e) => {
            result.assembly_valid = false;
            result.roundtrip_ok = false;
            result.error = Some(format!("Roundtrip failed: {}", e));
        }
    }

    // Every rewritten body's exception clauses still structure its code
    for entry in output.methods().iter() {
        let method = entry.value();
        if let (Some(body), Some(blocks)) = (method.body.get(), method.blocks.get()) {
            let instructions: Vec<_> = blocks
                .iter()
                .flat_map(|block| block.instructions.iter().cloned())
                .collect();
            for defect in exception_structure_defects(&instructions, &body.exception_handlers) {
                result
                    .structure_defects
                    .push(format!("{:?} {}: {defect}", method.token, method.name));
            }
        }
    }

    // Collect structural stats
    let output_size = output.file().data().len() as u64;
    result.deobfuscated_stats = Some(AssemblyStats::from_assembly(output, output_size));

    // Semantic preservation: the output's pure methods run against the original's. An
    // output that does not load for it leaves no result, which the assertion reports.
    if spec.check_semantic_preservation && !spec.is_original {
        let output_bytes = output.file().data().to_vec();
        if let Ok(output_copy) =
            CilObject::from_mem_with_validation(output_bytes, ValidationConfig::analysis())
        {
            let original = result.original;
            result.semantic_result = Some(verify_semantic_preservation(
                &original.pure_methods,
                &original.pure_results,
                &Arc::new(output_copy),
                &input
                    .map(|input| inlined_away(input, deob_result))
                    .unwrap_or_default(),
            ));
        }
    }
}

/// Assert common requirements that apply to all deobfuscated samples: the output is valid,
/// round-trips and has its entry point; its exception clauses structure its code; every pure
/// method computes what the original's does, where the spec checks semantics; and the
/// structure matches the original's, where the spec checks it.
pub fn assert_common_requirements<P: Clone + Debug>(result: &TestResult<P>) {
    let filename = result.sample.filename;

    // Core: must succeed
    assert!(
        result.success,
        "{}: Deobfuscation failed - {:?}",
        filename, result.error
    );

    assert!(
        result.assembly_valid,
        "{}: Output assembly is invalid - {:?}",
        filename, result.error
    );

    assert!(
        result.has_valid_entry_point,
        "{}: Output has no valid entry point",
        filename
    );

    assert!(
        result.roundtrip_ok,
        "{}: Roundtrip structure mismatch - {:?}",
        filename, result.error
    );

    assert!(
        result.structure_defects.is_empty(),
        "{}: exception clauses misstructure the output's code:\n{}",
        filename,
        result.structure_defects.join("\n")
    );

    // Semantic preservation (skip for original/unobfuscated samples)
    if result.sample.check_semantic_preservation && !result.sample.is_original {
        let Some(semantic) = &result.semantic_result else {
            panic!("{filename}: the output does not load for the semantic check");
        };
        assert!(
            semantic.failures.is_empty() && semantic.methods_checked > 0,
            "{filename}: {}/{} pure methods compute what the original's do ({} inlined):\n{}",
            semantic.methods_preserved,
            semantic.methods_checked,
            semantic.methods_inlined,
            semantic.failures.join("\n")
        );
    }

    // Structural match against original
    if result.sample.check_structural_match {
        let Some(deobfuscated_stats) = &result.deobfuscated_stats else {
            panic!("{filename}: the output has no structural statistics");
        };
        assert_structural_match(
            &result.original.stats,
            deobfuscated_stats,
            filename,
            &result.sample.structural_config,
        );
    }
}

/// Print a summary of test results.
///
/// `extra_lines_fn` is called per-result to emit obfuscator-specific detection lines.
pub fn print_summary<P: Clone + Debug, F>(results: &[TestResult<P>], label: &str, extra_lines_fn: F)
where
    F: Fn(&TestResult<P>),
{
    eprintln!("\n================================================================================",);
    eprintln!("{} DEOBFUSCATION TEST SUMMARY", label);
    eprintln!("================================================================================\n",);

    let mut total_passed = 0;
    let mut total_failed = 0;

    for result in results {
        let status = if result.success && result.assembly_valid {
            total_passed += 1;
            "PASS"
        } else {
            total_failed += 1;
            "FAIL"
        };

        eprintln!(
            "[{}] {} ({})",
            status, result.sample.filename, result.sample.description
        );

        // Obfuscator-specific detection lines
        extra_lines_fn(result);

        // Stats line
        eprintln!(
            "       Methods: {} -> {}",
            result.methods_before, result.methods_after,
        );

        // Post-deobfuscation line
        if !result.sample.is_original {
            eprintln!(
                "       Post-deobfuscation: confidence={:.0}% techniques=[{}] valid={} roundtrip={}",
                result.post_detection.confidence() * 100.0,
                result.post_detection.technique_ids.join(", "),
                result.assembly_valid,
                result.roundtrip_ok,
            );
        }

        // Semantic preservation line
        if let Some(ref sem) = result.semantic_result {
            eprintln!(
                "       Semantic: {}/{} preserved, {} inlined into their callers",
                sem.methods_preserved, sem.methods_checked, sem.methods_inlined,
            );
            for failure in &sem.failures {
                eprintln!("         {failure}");
            }
        }

        if let Some(ref err) = result.error {
            eprintln!("       Error: {}", err);
        }
    }

    eprintln!("\n--------------------------------------------------------------------------------");
    eprintln!("TOTALS: {} passed, {} failed", total_passed, total_failed);
    eprintln!("--------------------------------------------------------------------------------\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every call for a sample, from any thread, gets the one outcome its first call produced.
    #[test]
    fn a_sample_is_deobfuscated_once() {
        const SAMPLE: &str = "packers/confuserex/1.6.0/original.exe";
        let outcomes: Vec<usize> = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| std::ptr::from_ref(deobfuscated(SAMPLE)) as usize))
                .collect();
            runs.into_iter().map(|run| run.join().unwrap()).collect()
        });
        assert!(outcomes.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(deobfuscated(SAMPLE).is_ok());
    }
}

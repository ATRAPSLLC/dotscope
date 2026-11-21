//! Result type for individual technique execution.

use std::{collections::HashSet, time::Duration};

use crate::{compiler::EventLog, deobfuscation::techniques::Evidence};

/// Outcome of running a single technique (detection + optional transform).
///
/// Each technique produces a `TechniqueResult` after its detection and
/// optional transformation phases complete. These are aggregated into
/// [`crate::deobfuscation::DeobfuscationResult`] for the final summary.
#[derive(Debug, Clone)]
pub struct TechniqueResult {
    /// Technique ID (e.g. `"confuserex.constants"`).
    pub id: String,
    /// Whether the target pattern was detected in the assembly.
    pub detected: bool,
    /// Whether a transformation was successfully applied.
    pub transformed: bool,
    /// Evidence collected during detection.
    pub evidence: Vec<Evidence>,
    /// Events produced during the technique's execution.
    pub events: EventLog,
    /// Wall-clock time for the technique's detection and transform phases.
    pub duration: Duration,
}

/// Accumulator for [`TechniqueResult`]s with O(1) deduplication.
///
/// Used by `PipelineRun` to collect per-technique results during the pipeline.
/// [`record()`](Self::record) deduplicates by technique ID (for detection-only
/// entries), while [`push()`](Self::push) skips dedup (for byte-transform events
/// that legitimately reuse the same ID).
pub struct TechniqueResults {
    results: Vec<TechniqueResult>,
    recorded_ids: HashSet<String>,
}

impl TechniqueResults {
    /// Creates an empty accumulator.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            recorded_ids: HashSet::new(),
        }
    }

    /// Records a detection result, deduplicating by ID.
    ///
    /// If a result with the same `id` was already recorded, this is a no-op.
    pub fn record(&mut self, result: TechniqueResult) {
        if self.recorded_ids.contains(&result.id) {
            return;
        }
        self.recorded_ids.insert(result.id.clone());
        self.results.push(result);
    }

    /// Pushes a result without dedup (for byte-transform events).
    pub fn push(&mut self, result: TechniqueResult) {
        self.results.push(result);
    }

    /// Consumes the accumulator and returns the collected results.
    pub fn into_vec(self) -> Vec<TechniqueResult> {
        self.results
    }
}

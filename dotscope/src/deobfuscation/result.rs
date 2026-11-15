//! Deobfuscation result types.
//!
//! This module contains the [`DeobfuscationResult`] struct which encapsulates
//! the outcome of running the deobfuscation engine on an assembly.

use std::time::Duration;

use crate::{
    compiler::{DerivedStats, EventLog},
    deobfuscation::techniques::{AttributionResult, TechniqueResult},
};

/// Result of running deobfuscation.
///
/// Contains the event log capturing all activity during deobfuscation,
/// per-technique results, and obfuscator attribution. Statistics are
/// derived from the event log on demand.
///
/// # Example
///
/// ```no_run
/// use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
///
/// let engine = DeobfuscationEngine::new(EngineConfig::default());
/// let (_deobfuscated, result) = engine.process_file("obfuscated.dll")?;
///
/// println!("Events: {}", result.events.len());
/// println!("Stats: {}", result.stats().summary());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct DeobfuscationResult {
    /// All events from the deobfuscation run.
    pub events: EventLog,
    /// Number of pass iterations.
    pub iterations: usize,
    /// Total processing time.
    pub total_time: Duration,
    /// Per-technique results from the technique pipeline.
    pub techniques: Vec<TechniqueResult>,
    /// Best obfuscator attribution from technique detections.
    pub attribution: Option<AttributionResult>,
    /// All detected obfuscators, sorted by supporting technique count (most first).
    /// Each unique obfuscator name appears at most once (best matching signature).
    pub attributions: Vec<AttributionResult>,
}

impl DeobfuscationResult {
    /// Creates a new deobfuscation result from the technique pipeline.
    #[must_use]
    pub fn new_with_techniques(
        events: EventLog,
        techniques: Vec<TechniqueResult>,
        attribution: Option<AttributionResult>,
    ) -> Self {
        Self {
            events,
            iterations: 0,
            total_time: Duration::ZERO,
            techniques,
            attribution,
            attributions: Vec::new(),
        }
    }

    /// Attaches the full multi-obfuscator attribution list.
    #[must_use]
    pub fn with_attributions(mut self, attributions: Vec<AttributionResult>) -> Self {
        self.attributions = attributions;
        self
    }

    /// Sets timing and iteration info.
    #[must_use]
    pub fn with_timing(mut self, time: Duration, iterations: usize) -> Self {
        self.total_time = time;
        self.iterations = iterations;
        self
    }

    /// Computes statistics derived from the event log.
    #[must_use]
    pub fn stats(&self) -> DerivedStats {
        DerivedStats::from_log(&self.events)
            .with_time(self.total_time)
            .with_iterations(self.iterations)
    }

    /// Generates a human-readable summary of the deobfuscation results.
    #[must_use]
    pub fn summary(&self) -> String {
        self.stats().summary()
    }

    /// Generates a detailed multi-line summary including detection info.
    #[must_use]
    pub fn detailed_summary(&self) -> String {
        let mut parts = vec![format!(
            "Deobfuscation complete: {}",
            self.stats().summary()
        )];

        if let Some(ref attr) = self.attribution {
            parts.push(format!(
                "Attribution: {} ({} technique(s), {} supporting)",
                attr.obfuscator_name,
                attr.technique_ids.len(),
                attr.supporting_matched,
            ));
        } else {
            parts.push("Detection: No obfuscator detected".to_string());
        }

        if !self.techniques.is_empty() {
            let detected: Vec<&TechniqueResult> =
                self.techniques.iter().filter(|t| t.detected).collect();
            parts.push(format!(
                "Techniques: {} detected, {} transformed",
                detected.len(),
                detected.iter().filter(|t| t.transformed).count()
            ));
        }

        parts.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        compiler::EventLog,
        deobfuscation::{
            result::DeobfuscationResult,
            techniques::{AttributionResult, Evidence, TechniqueResult},
        },
    };

    #[test]
    fn test_new_with_techniques() {
        let events = EventLog::new();
        let techniques = vec![TechniqueResult {
            id: "test.a".into(),
            detected: true,
            transformed: false,
            evidence: vec![Evidence::Attribute("marker".into())],
            events: EventLog::new(),
            duration: Duration::from_millis(10),
        }];

        let result = DeobfuscationResult::new_with_techniques(events, techniques, None);
        assert_eq!(result.techniques.len(), 1);
        assert!(result.attribution.is_none());
        assert_eq!(result.iterations, 0);
        assert_eq!(result.total_time, Duration::ZERO);
    }

    #[test]
    fn test_with_timing() {
        let result = DeobfuscationResult::new_with_techniques(EventLog::new(), vec![], None)
            .with_timing(Duration::from_secs(5), 3);
        assert_eq!(result.total_time, Duration::from_secs(5));
        assert_eq!(result.iterations, 3);
    }

    #[test]
    fn test_with_attributions() {
        let attr = AttributionResult {
            obfuscator_name: "TestObf".into(),
            technique_ids: vec!["test.a".into()],
            supporting_matched: 0,
        };
        let result = DeobfuscationResult::new_with_techniques(EventLog::new(), vec![], None)
            .with_attributions(vec![attr]);
        assert_eq!(result.attributions.len(), 1);
        assert_eq!(result.attributions[0].obfuscator_name, "TestObf");
    }

    #[test]
    fn test_summary_no_techniques() {
        let result = DeobfuscationResult::new_with_techniques(EventLog::new(), vec![], None)
            .with_timing(Duration::from_millis(42), 1);
        let summary = result.summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_detailed_summary_with_attribution() {
        let attr = AttributionResult {
            obfuscator_name: "ConfuserEx".into(),
            technique_ids: vec!["confuserex.marker".into(), "confuserex.constants".into()],
            supporting_matched: 1,
        };
        let techniques = vec![
            TechniqueResult {
                id: "confuserex.marker".into(),
                detected: true,
                transformed: true,
                evidence: vec![],
                events: EventLog::new(),
                duration: Duration::from_millis(5),
            },
            TechniqueResult {
                id: "confuserex.constants".into(),
                detected: true,
                transformed: false,
                evidence: vec![],
                events: EventLog::new(),
                duration: Duration::from_millis(10),
            },
        ];

        let result =
            DeobfuscationResult::new_with_techniques(EventLog::new(), techniques, Some(attr));
        let detail = result.detailed_summary();
        assert!(detail.contains("ConfuserEx"));
        assert!(detail.contains("2 detected"));
        assert!(detail.contains("1 transformed"));
    }

    #[test]
    fn test_detailed_summary_no_detection() {
        let result = DeobfuscationResult::new_with_techniques(EventLog::new(), vec![], None);
        let detail = result.detailed_summary();
        assert!(detail.contains("No obfuscator detected"));
    }
}

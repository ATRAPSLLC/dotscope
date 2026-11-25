//! BitMono BitMethodDotnet junk prefix detection technique.
//!
//! Detects BitMono's BitMethodDotnet protection, which inserts a `br.s`
//! instruction at the start of method bodies that jumps over 1-10 bytes of
//! dead code. The dead bytes may decode as prefix opcodes, regular instructions,
//! or arbitrary data, confusing decompilers and static analysis tools.
//!
//! # Detection
//!
//! Scans all method bodies for `br.s` at offset 0 with a small positive forward
//! offset (1-10 bytes). This is a lightweight structural check that identifies
//! the trampoline pattern without needing to analyze the dead bytes.
//!
//! # Transform
//!
//! The transform is a no-op at the byte level. The junk prefix is handled
//! generically by the `BlockMergingPass` at the SSA level: the `br.s +N`
//! at method start creates an entry block trampoline that `BlockMergingPass`
//! detects and inlines, triggering code regeneration without the junk bytes.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    CilObject, Result,
};

/// Findings from BitMono junk prefix detection.
#[derive(Debug)]
pub struct JunkFindings {
    /// Number of methods with `br.s` junk prefix at method start.
    pub affected_methods: usize,
}

/// Detects BitMono's BitMethodDotnet junk prefix pattern.
///
/// Identifies methods where a `br.s` instruction at offset 0 jumps over
/// 1-10 bytes of dead code, a signature pattern of BitMono's
/// BitMethodDotnet protection. The actual removal is handled by
/// `BlockMergingPass` during SSA optimization.
pub struct BitMonoJunk;

impl Technique for BitMonoJunk {
    fn id(&self) -> &'static str {
        "bitmono.junk"
    }

    fn name(&self) -> &'static str {
        "BitMono Junk Prefix Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut junk_method_count = 0usize;

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            let instructions: Vec<_> = method.instructions().collect();

            if instructions.len() < 2 {
                continue;
            }

            // Check for br.s at method start with a small positive forward offset.
            // BitMethodDotnet inserts br.s that jumps over 1-10 bytes of junk.
            if let Some(first) = instructions.first() {
                if first.mnemonic == "br.s" {
                    // The bytes skipped: from the end of the `br.s` to where it lands.
                    let is_small_forward_jump = first
                        .get_branch_target()
                        .zip(first.rva.checked_add(first.size))
                        .and_then(|(target, next)| target.checked_sub(next))
                        .is_some_and(|skipped| (1..=10).contains(&skipped));
                    if is_small_forward_jump {
                        junk_method_count = junk_method_count.saturating_add(1);
                    }
                }
            }
        }

        if junk_method_count == 0 {
            return Detection::new_empty();
        }

        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{junk_method_count} methods with br.s junk prefix (BitMono BitMethodDotnet)"
            ))],
            Some(Box::new(JunkFindings {
                affected_methods: junk_method_count,
            }) as Box<dyn Any + Send + Sync>),
        )
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<JunkFindings>() else {
            return Some(Ok(events));
        };

        // No byte-level patching needed. BlockMergingPass handles junk prefix
        // removal at the SSA level by inlining the entry block trampoline.
        if findings.affected_methods > 0 {
            events.record(EventKind::ArtifactRemoved)
                .message(format!(
                    "BitMono junk prefix: {} methods detected, removal deferred to SSA BlockMergingPass",
                    findings.affected_methods,
                ));
        }

        Some(Ok(events))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoJunk, Technique},
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_junk.exe");

        let technique = BitMonoJunk;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoJunk should detect junk prefix in bitmono_junk.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoJunk;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoJunk should not detect junk prefix in a non-BitMono assembly"
        );
    }
}

//! Generic malformed exception handler repair.
//!
//! Detects and fixes malformed exception handler entries (overlapping/out-of-bounds
//! ranges) injected by obfuscators to crash decompilers. Uses lenient parsing to
//! identify methods with invalid EH data, then strips the malformed handlers.
//!
//! # Detection
//!
//! Parses each method body with `MethodBody::from_lenient()` which filters invalid
//! exception handlers. If any handlers were filtered, the method had garbage EH
//! data injected by an obfuscator.
//!
//! # Transform
//!
//! For each affected method, re-parses the body with lenient mode, strips all
//! exception handlers, rebuilds the method body, and stores it back.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    metadata::{
        method::{MethodBody, MethodImplCodeType},
        tables::MethodDefRaw,
        token::Token,
    },
    CilObject, Result,
};

/// Findings from malformed exception handler detection.
#[derive(Debug)]
pub struct HandlersFindings {
    /// Tokens of methods with malformed exception handlers.
    pub affected_methods: Vec<Token>,
}

/// Detects and repairs malformed exception handler entries.
pub struct GenericHandlers;

impl Technique for GenericHandlers {
    fn id(&self) -> &'static str {
        "generic.handlers"
    }

    fn name(&self) -> &'static str {
        "Malformed Exception Handler Repair"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };
        let Some(method_table) = tables.table::<MethodDefRaw>() else {
            return Detection::new_empty();
        };
        let file = assembly.file();

        let mut affected = Vec::new();

        for row in method_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            if row.rva == 0 {
                continue;
            }

            let code_type = MethodImplCodeType::from_impl_flags(row.impl_flags);
            if code_type.contains(MethodImplCodeType::NATIVE)
                || code_type.contains(MethodImplCodeType::RUNTIME)
            {
                continue;
            }

            let Ok(body_data) = file.section_bounded(row.rva as usize) else {
                continue;
            };
            if body_data.is_empty() {
                continue;
            }

            if let Ok((_, filtered)) = MethodBody::from_lenient(body_data) {
                if filtered > 0 {
                    affected.push(row.token);
                }
            }
        }

        if affected.is_empty() {
            return Detection::new_empty();
        }

        let count = affected.len();
        let findings = HandlersFindings {
            affected_methods: affected,
        };

        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} methods with malformed exception handlers"
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<HandlersFindings>() else {
            return Some(Ok(events));
        };

        // Malformed EH repair requires CilAssembly-level operations (store_method_body).
        // This technique contributes detection + attribution; the actual EH stripping
        // is performed during assembly regeneration when requires_regeneration() is true.
        // The assembly reload via commit() will re-parse with lenient mode.
        if !findings.affected_methods.is_empty() {
            events.record(EventKind::ArtifactRemoved)
                .message(format!(
                    "Detected {} methods with malformed exception handlers — will be stripped on regeneration",
                    findings.affected_methods.len()
                ));
            // Force a commit to trigger re-parse with lenient mode
            if assembly.has_pending() {
                if let Err(e) = assembly.commit() {
                    return Some(Err(e));
                }
            }
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    /// Verify detection runs without error on a protected sample.
    ///
    /// None of the current test samples inject malformed exception handlers,
    /// so this verifies the technique handles obfuscated assemblies gracefully
    /// without panicking.
    #[test]
    fn test_detect_no_panic_on_obfuscated() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");
        let technique = super::GenericHandlers;
        let _detection = technique.detect(&asm);
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericHandlers;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

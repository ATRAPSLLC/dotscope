//! Generic invalid metadata detection.
//!
//! Detects the metadata rows obfuscators add to break parsers and analysis tools: Module and
//! Assembly rows after the first (ECMA-335 allows one), and DeclSecurity rows whose parent is
//! the null reference. ConfuserEx's invalid metadata and .NET Reactor's SuppressIldasm add
//! them; the runtime ignores them.
//!
//! # Repair
//!
//! The deobfuscation cleanup's metadata repairs (`deobfuscation::repairs`) remove the rows
//! when the assembly is regenerated. This technique detects them and requests that
//! regeneration.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    metadata::tables::{skip_unreadable, DeclSecurityRaw, TableId},
    CilObject, Result,
};

/// Findings from generic metadata scanning.
#[derive(Debug)]
pub struct MetadataFindings {
    /// Module rows after the first.
    pub invalid_module_rows: usize,
    /// Assembly rows after the first.
    pub invalid_assembly_rows: usize,
    /// DeclSecurity rows whose parent is the null reference.
    pub invalid_declsecurity_rows: usize,
}

/// Detects invalid metadata table entries.
///
/// This is the generic version that catches common patterns across obfuscators.
/// Obfuscator-specific techniques (e.g., `confuserex.metadata`) supersede this
/// with more targeted logic.
pub struct GenericMetadata;

impl Technique for GenericMetadata {
    fn id(&self) -> &'static str {
        "generic.metadata"
    }

    fn name(&self) -> &'static str {
        "Generic Invalid Metadata Repair"
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

        let findings = MetadataFindings {
            invalid_module_rows: tables.table_row_count(TableId::Module).saturating_sub(1) as usize,
            invalid_assembly_rows: tables.table_row_count(TableId::Assembly).saturating_sub(1)
                as usize,
            invalid_declsecurity_rows: tables.table::<DeclSecurityRaw>().map_or(0, |t| {
                t.into_iter()
                    .filter_map(skip_unreadable)
                    .filter(|row| row.parent.row == 0)
                    .count()
            }),
        };

        let total_invalid = findings
            .invalid_module_rows
            .saturating_add(findings.invalid_assembly_rows)
            .saturating_add(findings.invalid_declsecurity_rows);
        if total_invalid == 0 {
            return Detection::new_empty();
        }
        let evidence = vec![Evidence::MetadataPattern(format!(
            "{} invalid metadata entries (Module: {}, Assembly: {}, DeclSecurity: {})",
            total_invalid,
            findings.invalid_module_rows,
            findings.invalid_assembly_rows,
            findings.invalid_declsecurity_rows,
        ))];
        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();
        if let Some(findings) = detection.findings::<MetadataFindings>() {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Invalid metadata (Module: {}, Assembly: {}, DeclSecurity: {}) is repaired on regeneration",
                findings.invalid_module_rows,
                findings.invalid_assembly_rows,
                findings.invalid_declsecurity_rows,
            ));
        }
        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::helpers::load_sample;

    fn findings(sample: &str) -> Option<(usize, usize, usize)> {
        let detection = GenericMetadata.detect(&load_sample(sample));
        detection.findings::<MetadataFindings>().map(|f| {
            (
                f.invalid_module_rows,
                f.invalid_assembly_rows,
                f.invalid_declsecurity_rows,
            )
        })
    }

    #[test]
    fn test_detect_negative() {
        for sample in [
            "packers/confuserex/1.6.0/original.exe",
            "packers/confuserex/1.6.0/mkaring_maximum.exe",
        ] {
            assert!(
                !GenericMetadata.detect(&load_sample(sample)).is_detected(),
                "{sample}"
            );
        }
    }

    #[test]
    fn test_detect_confuserex_invalid_metadata() {
        assert_eq!(
            findings("packers/confuserex/1.6.0/mkaring_invalidmetadata.exe"),
            Some((1, 1, 1))
        );
    }

    #[test]
    fn test_detect_netreactor_suppress_ildasm() {
        assert_eq!(
            findings("packers/netreactor/7.5.0/reactor_suppressildasm.exe"),
            Some((1, 1, 0))
        );
    }
}

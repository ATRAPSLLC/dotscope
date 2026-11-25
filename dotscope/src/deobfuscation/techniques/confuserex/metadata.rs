//! ConfuserEx invalid metadata detection.
//!
//! ConfuserEx's InvalidMetadata protection adds junk to the metadata to break disassemblers
//! and analysis tools; the CLR ignores all of it. It adds (it does not modify existing rows):
//! - a second Module row and a second Assembly row, their names `0x7fff7fff`;
//! - a DeclSecurity row with action `0x7fff` whose parent's coded-index tag names no table
//!   (the CLR reads it as a null parent);
//! - ENCLog and ENCMap rows, meaningless outside an edit-and-continue delta;
//! - repeated `#GUID`, `#Strings` and `#Blob` headers after the real ones, and a `#Schema`
//!   header, which makes the CLR read the first header of each name (see
//!   [`crate::metadata::root::Root::stream`]).
//!
//! # Detection
//!
//! The rows above, by their `0x7fff` markers, non-empty ENC tables, and stream headers the
//! runtime does not read.
//!
//! # Repair
//!
//! The junk is removed when the assembly is regenerated: the deobfuscation cleanup's
//! metadata repairs (`deobfuscation::repairs`) remove the extra Module and Assembly rows, the
//! DeclSecurity rows with a null parent and the ENC rows, and the writer emits only the
//! streams the runtime reads. This technique detects the protection and requests that
//! regeneration.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    metadata::tables::{AssemblyRaw, DeclSecurityRaw, EncLogRaw, EncMapRaw, ModuleRaw},
    CilObject, Result,
};

/// ConfuserEx's marker value for invalid metadata indices, at four bytes.
const CONFUSEREX_MARKER: u32 = 0x7fff_7fff;

/// ConfuserEx's marker value at two bytes (a two-byte index column holds its low half).
const CONFUSEREX_MARKER_16: u16 = 0x7fff;

/// Findings from ConfuserEx metadata scanning.
#[derive(Debug)]
pub struct CxMetadataFindings {
    /// Rows ConfuserEx added: marked Module and Assembly rows after the first, and
    /// DeclSecurity rows with the marker action and a null parent.
    pub invalid_entries: usize,
    /// Non-empty ENC tables (ENCLog = 0x1E, ENCMap = 0x1F).
    pub enc_tables: Vec<u8>,
    /// Whether the stream directory holds headers the runtime does not read, or `#Schema`.
    pub has_duplicate_streams: bool,
}

/// Whether a name index carries ConfuserEx's marker or points past the `#Strings` heap.
fn is_marked_name(name: u32, strings_size: usize) -> bool {
    name == CONFUSEREX_MARKER
        || name == u32::from(CONFUSEREX_MARKER_16)
        || name as usize >= strings_size
}

/// Detects ConfuserEx's invalid metadata protection.
///
/// Supersedes the generic metadata technique with ConfuserEx-specific knowledge of the
/// `0x7fff` markers, ENC tables, and repeated stream headers.
pub struct ConfuserExMetadata;

impl Technique for ConfuserExMetadata {
    fn id(&self) -> &'static str {
        "confuserex.metadata"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Invalid Metadata Repair"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.metadata"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };
        let strings_size = assembly.strings().map_or(0, |s| s.data().len());

        let mut invalid_entries = 0usize;
        if let Some(modules) = tables.table::<ModuleRaw>() {
            invalid_entries = invalid_entries.saturating_add(
                modules
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|row| row.rid > 1 && is_marked_name(row.name, strings_size))
                    .count(),
            );
        }
        if let Some(assemblies) = tables.table::<AssemblyRaw>() {
            invalid_entries = invalid_entries.saturating_add(
                assemblies
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|row| row.rid > 1 && is_marked_name(row.name, strings_size))
                    .count(),
            );
        }
        if let Some(declsecurity) = tables.table::<DeclSecurityRaw>() {
            invalid_entries = invalid_entries.saturating_add(
                declsecurity
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|row| row.action == CONFUSEREX_MARKER_16 && row.parent.row == 0)
                    .count(),
            );
        }

        let mut enc_tables = Vec::new();
        if tables.table::<EncLogRaw>().is_some_and(|t| t.row_count > 0) {
            enc_tables.push(0x1E);
        }
        if tables.table::<EncMapRaw>().is_some_and(|t| t.row_count > 0) {
            enc_tables.push(0x1F);
        }

        let root = assembly.metadata_root();
        let has_duplicate_streams = root.unread_streams().next().is_some()
            || root.stream_headers.iter().any(|s| s.name == "#Schema");

        if invalid_entries == 0 && enc_tables.is_empty() && !has_duplicate_streams {
            return Detection::new_empty();
        }

        let mut evidence = Vec::new();
        if invalid_entries > 0 {
            evidence.push(Evidence::MetadataPattern(format!(
                "{invalid_entries} invalid metadata rows with the 0x7fff marker"
            )));
        }
        if !enc_tables.is_empty() {
            evidence.push(Evidence::MetadataPattern(format!(
                "Non-empty ENC tables: {enc_tables:?}"
            )));
        }
        if has_duplicate_streams {
            evidence.push(Evidence::MetadataPattern(
                "Stream headers the runtime does not read".to_string(),
            ));
        }

        let findings = CxMetadataFindings {
            invalid_entries,
            enc_tables,
            has_duplicate_streams,
        };
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
        if let Some(findings) = detection.findings::<CxMetadataFindings>() {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "ConfuserEx invalid metadata ({} rows, ENC tables {:?}, repeated streams: {}) is removed on regeneration",
                findings.invalid_entries, findings.enc_tables, findings.has_duplicate_streams,
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
    use crate::{
        deobfuscation::techniques::{
            confuserex::metadata::{ConfuserExMetadata, CxMetadataFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_negative_original() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExMetadata;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExMetadata should not detect invalid metadata in original.exe"
        );
    }

    #[test]
    fn test_detect_negative_normal() {
        // Normal preset does not include InvalidMetadata protection.
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");

        let technique = ConfuserExMetadata;
        let detection = technique.detect(&assembly);

        // InvalidMetadata is a separate ConfuserEx protection not included
        // in standard presets (Minimum, Normal, Maximum).
        // The 0x7fff marker pattern is specific to this protection.
        assert!(
            !detection.is_detected(),
            "ConfuserExMetadata should not detect in normal preset (no InvalidMetadata protection)"
        );
    }

    #[test]
    fn test_technique_properties() {
        let technique = ConfuserExMetadata;

        assert_eq!(technique.id(), "confuserex.metadata");
        assert_eq!(technique.supersedes(), &["generic.metadata"]);
        assert!(
            technique.requires_regeneration(),
            "Metadata repair requires PE regeneration"
        );
    }

    #[test]
    fn test_detect_negative_maximum() {
        // The Maximum preset does not include the InvalidMetadata protection.
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_maximum.exe");
        assert!(!ConfuserExMetadata.detect(&assembly).is_detected());
    }

    #[test]
    fn test_detect_invalidmetadata() {
        for sample in [
            "packers/confuserex/1.6.0/mkaring_invalidmetadata.exe",
            "packers/confuserex/1.6.0/mkaring_invalidmetadata_antitamper.exe",
        ] {
            let assembly = load_sample(sample);
            let detection = ConfuserExMetadata.detect(&assembly);
            assert!(detection.is_detected(), "{sample}: not detected");
            let findings = detection
                .findings::<CxMetadataFindings>()
                .expect("findings");
            // A second Module row, a second Assembly row and the DeclSecurity row.
            assert_eq!(findings.invalid_entries, 3, "{sample}: {findings:?}");
            assert_eq!(findings.enc_tables, vec![0x1E, 0x1F], "{sample}");
            assert!(findings.has_duplicate_streams, "{sample}");
        }
    }
}

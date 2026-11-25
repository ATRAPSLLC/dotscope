//! Generic SuppressIldasmAttribute removal.
//!
//! Detects and removes `SuppressIldasmAttribute` from assembly/module-level
//! custom attributes. This attribute is used by multiple obfuscators
//! (ConfuserEx, Obfuscar, BitMono) to prevent ILDasm from disassembling
//! the output.
//!
//! # Detection
//!
//! Scans the CustomAttribute table for entries whose constructor references
//! `System.Runtime.CompilerServices.SuppressIldasmAttribute` via a
//! MemberRef → TypeRef chain.
//!
//! # Transform
//!
//! Zeroes out the CustomAttribute row to effectively remove the attribute.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::{
        techniques::{
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
        },
        utils::resolve_custom_attr_type,
    },
    metadata::{
        tables::{CustomAttributeRaw, TableId},
        token::Token,
    },
    CilObject, Result,
};

/// Findings from SuppressIldasm detection.
#[derive(Debug)]
pub struct IldasmFindings {
    /// Token of the SuppressIldasmAttribute CustomAttribute row.
    pub attribute_token: Token,
    /// File offset of the CustomAttribute row for patching.
    pub row_offset: usize,
    /// Size of the CustomAttribute row in bytes.
    pub row_size: usize,
}

/// Detects and removes `SuppressIldasmAttribute`.
pub struct GenericIldasm;

impl Technique for GenericIldasm {
    fn id(&self) -> &'static str {
        "generic.ildasm"
    }

    fn name(&self) -> &'static str {
        "SuppressIldasm Attribute Removal"
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
        let Some(custom_attr_table) = tables.table::<CustomAttributeRaw>() else {
            return Detection::new_empty();
        };

        for attr in custom_attr_table {
            let attr = match attr {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            let is_module_or_assembly =
                attr.parent.tag == TableId::Module || attr.parent.tag == TableId::Assembly;
            if !is_module_or_assembly {
                continue;
            }

            let Some(resolved) = resolve_custom_attr_type(assembly, &attr) else {
                continue;
            };

            if let (name, Some(namespace)) = (resolved.name, resolved.namespace) {
                if name == "SuppressIldasmAttribute"
                    && namespace == "System.Runtime.CompilerServices"
                {
                    let findings = IldasmFindings {
                        attribute_token: attr.token,
                        row_offset: attr.offset,
                        row_size: 0, // Will be determined at transform time
                    };

                    let mut detection = Detection::new_detected(
                        vec![Evidence::Attribute(format!("{namespace}.{name}"))],
                        Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
                    );
                    detection.cleanup_mut().add_attribute(attr.token);
                    return detection;
                }
            }
        }

        Detection::new_empty()
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<IldasmFindings>() else {
            return Some(Ok(events));
        };

        // The attribute is removed via cleanup (added to detection.cleanup above).
        // No byte-level patching needed — cleanup handles CustomAttribute row removal.
        events.record(EventKind::ArtifactRemoved).message(format!(
            "Marked SuppressIldasmAttribute (0x{:08X}) for removal",
            findings.attribute_token.value()
        ));

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::{deobfuscation::techniques::Technique, testkit::helpers::load_sample};

    #[test]
    fn test_detect_positive() {
        let asm = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");
        let technique = super::GenericIldasm;
        let detection = technique.detect(&asm);
        assert!(detection.is_detected());
        assert!(!detection.evidence().is_empty());
    }

    #[test]
    fn test_detect_negative() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");
        let technique = super::GenericIldasm;
        let detection = technique.detect(&asm);
        assert!(!detection.is_detected());
    }
}

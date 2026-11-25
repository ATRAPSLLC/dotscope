//! BitMono PE-level corruption detection.
//!
//! Detects BitMono's PE-level protections — BitDotNet, BitDecompiler, and the
//! BitMono packer — by inspecting repair actions applied during PE loading.
//!
//! These protections corrupt PE headers (signature, CLR header, data directories)
//! to prevent tools from loading the assembly. The dotscope loader transparently
//! repairs these corruptions and records each fix as a [`RepairAction`]. This
//! technique converts those repair records into detection evidence with BitMono
//! attribution.
//!
//! # Detection
//!
//! Checks `assembly.file().repairs()` for BitMono-specific corruption patterns:
//! - `PeSignature { original: 0x00014550 }` → BitDotNet (+0.4)
//! - `ClrHeaderSize { original: 0 }` → BitDotNet/BitDecompiler (+0.3)
//! - `ClrHeaderVersion { original_major: 0 }` → supporting evidence (+0.1)
//! - `ClrMetadataRva` → supporting evidence (+0.1)
//! - `DataDirectoryCount { original: 0x13 }` → BitMono packer (+0.4)
//! - `DotNetDirectorySize { original: 0 }` → supporting evidence (+0.1)
//!
//! # Transform
//!
//! No transform needed — PE repairs are already applied during loading.

use crate::{
    compiler::EventLog,
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    file::repair::RepairAction,
    CilObject, Result,
};

/// Detects BitMono PE-level header corruptions.
///
/// Converts PE repair records (applied during loading) into detection evidence
/// for BitMono attribution. Covers BitDotNet, BitDecompiler, and packer modes.
pub struct BitMonoPeRepair;

impl Technique for BitMonoPeRepair {
    fn id(&self) -> &'static str {
        "bitmono.pe"
    }

    fn name(&self) -> &'static str {
        "BitMono PE Corruption Detection"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let repairs = assembly.file().repairs();
        if repairs.is_empty() {
            return Detection::new_empty();
        }

        let mut evidence = Vec::new();

        for repair in repairs {
            match repair {
                RepairAction::PeSignature { original, .. } if *original == 0x0001_4550 => {
                    evidence.push(Evidence::Structural(format!(
                        "BitDotNet PE signature corruption (0x{original:08X})"
                    )));
                }
                RepairAction::ClrHeaderSize { original, .. } if *original == 0 => {
                    evidence.push(Evidence::Structural(
                        "BitDotNet/BitDecompiler CLR header size zeroed".to_string(),
                    ));
                }
                RepairAction::ClrHeaderVersion { original_major, .. } if *original_major == 0 => {
                    evidence.push(Evidence::Structural(
                        "CLR runtime version zeroed (supporting evidence)".to_string(),
                    ));
                }
                RepairAction::ClrMetadataRva { .. } => {
                    evidence.push(Evidence::Structural(
                        "CLR metadata RVA reconstructed (supporting evidence)".to_string(),
                    ));
                }
                RepairAction::DataDirectoryCount { original, .. } if *original == 0x13 => {
                    evidence.push(Evidence::Structural(format!(
                        "BitMono packer data directory inflation (0x{original:X})"
                    )));
                }
                RepairAction::DotNetDirectorySize { original, .. } if *original == 0 => {
                    evidence.push(Evidence::Structural(
                        ".NET directory size zeroed (supporting evidence)".to_string(),
                    ));
                }
                _ => {}
            }
        }

        if evidence.is_empty() {
            return Detection::new_empty();
        }

        Detection::new_detected(evidence, None)
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        _detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        // PE repairs are applied during loading — no transform needed.
        Some(Ok(EventLog::new()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{bitmono::BitMonoPeRepair, Technique},
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_bitdecompiler.exe");

        let technique = BitMonoPeRepair;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoPeRepair should detect PE corruption in bitmono_bitdecompiler.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoPeRepair;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoPeRepair should not detect PE corruption in a non-BitMono assembly"
        );
    }
}

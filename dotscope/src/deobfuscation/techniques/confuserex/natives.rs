//! ConfuserEx native x86 helper method detection and conversion.
//!
//! When ConfuserEx is configured with `mode=x86` or `predicate=x86`, it
//! generates native x86 methods (`MethodImplCodeType::NATIVE`) that perform
//! key transformation for constant/string decryption. These methods contain
//! raw x86 machine code and cannot be emulated by the CIL emulator until
//! they are converted to equivalent CIL.
//!
//! # Detection
//!
//! Scans for methods with `MethodImplCodeType::NATIVE` that are called by
//! CIL methods (indicating they are ConfuserEx-generated helpers, not genuine
//! P/Invoke imports). Filters out true P/Invoke methods by checking the
//! ImplMap table — real DLL imports have entries there, while ConfuserEx
//! native helpers have the `PINVOKE_IMPL` flag but no ImplMap entry.
//!
//! # Transform
//!
//! Uses the [`NativeMethodConversionPass`] to convert each detected helper:
//! 1. Read x86 bytes from the method's RVA
//! 2. Decode x86 instructions, skip DynCipher prologue
//! 3. Build x86 CFG, translate to SSA
//! 4. Generate CIL bytecode from SSA
//! 5. Patch the method body and update impl flags (NATIVE → IL)
//!
//! The conversion pass operates on `CilAssembly` and produces a new PE. The
//! technique replaces the working assembly with the rebuilt result.
//!
//! # Dependency
//!
//! Requires `confuserex.tamper` to have run first, since anti-tamper
//! decryption reveals the method bodies that call native helpers.

use std::{any::Any, collections::HashSet};

use crate::{
    cilassembly::{CilAssembly, GeneratorConfig},
    compiler::{EventKind, EventLog},
    deobfuscation::{
        passes::NativeMethodConversionPass,
        techniques::{
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
        },
    },
    metadata::{tables::ImplMapRaw, token::Token, validation::ValidationConfig},
    CilObject, Result,
};

/// Findings from native helper detection.
#[derive(Debug)]
pub struct NativeFindings {
    /// Tokens of native x86 helper methods requiring conversion.
    pub helpers: Vec<Token>,
}

/// Detects ConfuserEx native x86 helper methods.
///
/// These methods contain raw x86 machine code used for key transformation
/// in the constants/string decryption pipeline. They must be converted to
/// CIL before emulation can decrypt constants.
pub struct ConfuserExNativeHelpers;

impl Technique for ConfuserExNativeHelpers {
    fn id(&self) -> &'static str {
        "confuserex.natives"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Native x86 Helper Conversion"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn requires(&self) -> &[&'static str] {
        &["confuserex.tamper"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };

        // Phase 1: Collect all native method tokens from resolved methods.
        // We use the resolved Method objects rather than raw MethodDefRaw rows
        // because the resolved `impl_code_type` is the authoritative source
        // after metadata loading and flag extraction.
        let mut native_tokens = HashSet::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();
            if method.is_code_native() && method.rva.is_some() {
                native_tokens.insert(method.token);
            }
        }

        if native_tokens.is_empty() {
            return Detection::new_empty();
        }

        // Phase 2: Find which native methods are called by CIL methods.
        // ConfuserEx native helpers are called from decryptor methods.
        let mut helpers = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            for instr in method.instructions() {
                if let Some(token) = instr.get_token_operand() {
                    if native_tokens.contains(&token) && !helpers.contains(&token) {
                        helpers.push(token);
                    }
                }
            }
        }

        // Filter out true P/Invoke methods by checking the ImplMap table.
        // Real P/Invoke methods have entries in the ImplMap table that map them
        // to external DLL functions. ConfuserEx native helpers have the
        // PINVOKE_IMPL flag set but NO ImplMap entry — their native x86 code
        // is embedded directly at the method's RVA.
        let pinvoke_methods = collect_implmap_methods(tables);
        helpers.retain(|token| !pinvoke_methods.contains(token));

        if helpers.is_empty() {
            return Detection::new_empty();
        }

        let count = helpers.len();

        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} native x86 helper methods called from CIL decryptors",
            ))],
            Some(Box::new(NativeFindings {
                helpers: helpers.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        // Mark native helper methods for cleanup.
        for token in &helpers {
            detection.cleanup_mut().add_method(*token);
        }

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<NativeFindings>() else {
            return Some(Ok(events));
        };

        if findings.helpers.is_empty() {
            return Some(Ok(events));
        }

        // Create CilAssembly from the current assembly bytes.
        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let bytes = co.file().data().to_vec();
        let mut cil_assembly =
            match CilAssembly::from_bytes_with_validation(bytes, ValidationConfig::analysis()) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

        // Set up the conversion pass with all detected native helpers.
        let mut converter = NativeMethodConversionPass::new();
        for &token in &findings.helpers {
            converter.register_target(token);
        }

        // Run the x86 → CIL conversion.
        let pe_file = co.file();
        let stats = match converter.run(&mut cil_assembly, pe_file) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        if stats.failed > 0 {
            log::warn!(
                "Converted {}/{} native x86 methods to CIL (failures: {})",
                stats.converted,
                stats.converted.saturating_add(stats.failed),
                stats.errors.join(", ")
            );
        }

        if stats.converted > 0 {
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Converted {} native x86 helper method(s) to CIL",
                stats.converted,
            ));

            // Rebuild PE with CIL method bodies replacing native ones.
            let new_assembly = match cil_assembly
                .into_cilobject_with(ValidationConfig::analysis(), GeneratorConfig::default())
            {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            assembly.replace_assembly(new_assembly);
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Collects method tokens that have real P/Invoke mappings in the ImplMap table.
///
/// Methods with ImplMap entries are genuine P/Invoke imports that call into
/// external DLLs. Methods without ImplMap entries but with NATIVE code type
/// are ConfuserEx-generated native x86 helpers with embedded machine code.
fn collect_implmap_methods(tables: &crate::metadata::streams::TablesHeader<'_>) -> HashSet<Token> {
    let mut pinvoke_methods = HashSet::new();
    if let Some(implmap_table) = tables.table::<ImplMapRaw>() {
        for row in implmap_table {
            let row = match row {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            pinvoke_methods.insert(row.member_forwarded.token);
        }
    }
    pinvoke_methods
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::natives::{ConfuserExNativeHelpers, NativeFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_constants_x86.exe");

        let technique = ConfuserExNativeHelpers;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExNativeHelpers should detect native helpers in mkaring_constants_x86.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<NativeFindings>()
            .expect("Should have NativeFindings");

        assert!(
            !findings.helpers.is_empty(),
            "Should have native helper tokens"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExNativeHelpers;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExNativeHelpers should not detect native helpers in original.exe"
        );
    }
}

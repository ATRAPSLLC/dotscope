//! .NET Reactor deobfuscation techniques.
//!
//! This module provides detection and deobfuscation for .NET Reactor protections.
//! All detection is fully generic — based on structural and behavioral patterns,
//! never on hardcoded type names or version-specific constants.
//!
//! # Techniques
//!
//! | ID | Pattern | Description |
//! |---|---------|-------------|
//! | `netreactor.necrobit` | Byte transform (C) | Method body decryption |
//! | `netreactor.antitrial` | Detection only (D) | `<Module>` trial-guard removal |
//! | `netreactor.antitamp` | Detection only (D) | Anti-tamper init runtime removal |
//! | `netreactor.licensecheck` | Detection only (D) | Class-scoped license-check removal |
//! | `netreactor.privateimpl` | Detection only (D) | `<PrivateImplementationDetails>{GUID}` data-container cleanup |
//! | `netreactor.resources` | Byte transform (C) | Resource-encryption removal + decrypted-resource injection |

mod antitamp;
mod antitrial;
mod emptyresource;
mod helpers;
mod hooks;
mod licensecheck;
mod necrobit;
mod privateimpl;
mod resources;

pub use antitamp::NetReactorAntiTamp;
pub use antitrial::NetReactorAntiTrial;
pub use emptyresource::NetReactorEmptyResource;
pub use helpers::find_resources_referenced_by_methods;
pub use licensecheck::NetReactorLicenseCheck;
pub use necrobit::NetReactorNecroBit;
pub use privateimpl::NetReactorPrivateImpl;
pub use resources::NetReactorResources;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        assembly::Operand,
        metadata::validation::ValidationConfig,
        testkit::{engine, fixture},
        CilObject,
    };

    fn load_nr_sample(name: &str) -> CilObject {
        let path = fixture(&format!("packers/netreactor/7.5.0/{name}"));
        CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {name}: {e}"))
    }

    // Collects all ldstr string literals from an assembly by walking method IL.
    // ldstr tokens have table byte 0x70 (user strings heap).
    fn collect_ldstr_strings(asm: &CilObject) -> HashSet<String> {
        let mut strings = HashSet::new();
        let us = match asm.userstrings() {
            Some(us) => us,
            None => return strings,
        };
        for method_entry in asm.methods() {
            let method = method_entry.value();
            for instr in method.instructions() {
                if instr.mnemonic == "ldstr" {
                    if let Operand::Token(token) = &instr.operand {
                        if token.table() == 0x70 {
                            if let Ok(s) = us.get(token.row() as usize) {
                                strings.insert(s.to_string_lossy());
                            }
                        }
                    }
                }
            }
        }
        strings
    }

    // Runs the full deobfuscation pipeline on the NR string-encrypted sample.
    // Validates: detection fires, strings are decrypted, decrypted strings match original.
    #[test]
    fn test_nr_string_decryption() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        // Collect all string literals from the original assembly
        let original = load_nr_sample("original.exe");
        let original_strings = collect_ldstr_strings(&original);
        eprintln!(
            "Original has {} unique string literals",
            original_strings.len()
        );
        for s in &original_strings {
            eprintln!("  original: {:?}", s);
        }

        // Run deobfuscation on the protected sample
        let assembly = load_nr_sample("reactor_strings.exe");
        let engine = engine();
        let (output, result) = engine
            .process_assembly(assembly)
            .expect("Deobfuscation should succeed");

        let stats = result.stats();
        eprintln!("\nDeobfuscation stats:");
        eprintln!("  strings_decrypted: {}", stats.strings_decrypted);
        eprintln!("  constants_folded: {}", stats.constants_folded);
        eprintln!("  methods_transformed: {}", stats.methods_transformed);
        eprintln!("  methods_regenerated: {}", stats.methods_regenerated);
        eprintln!("  iterations: {}", result.iterations);

        for t in &result.techniques {
            eprintln!(
                "  technique: {} detected={} transformed={}",
                t.id, t.detected, t.transformed
            );
        }

        // The generic.strings technique should have detected the decryptor
        let strings_technique = result.techniques.iter().find(|t| t.id == "generic.strings");
        assert!(
            strings_technique.is_some_and(|t| t.detected),
            "generic.strings should be detected"
        );

        // Verify strings were decrypted (documentation says 90 call sites)
        assert!(
            stats.strings_decrypted >= 80,
            "Expected at least 80 strings decrypted, got {}",
            stats.strings_decrypted
        );

        // Collect all string literals from the deobfuscated output
        let deobf_strings = collect_ldstr_strings(&output);
        eprintln!(
            "\nDeobfuscated has {} unique string literals",
            deobf_strings.len()
        );
        for s in &deobf_strings {
            eprintln!("  deobf: {:?}", s);
        }

        // Check that original strings appear either as exact matches or as
        // substrings of concatenated strings in the deobfuscated output.
        // Constant propagation legitimately folds "A" + "B" into "AB".
        let mut missing = Vec::new();
        let all_deobf: Vec<&String> = deobf_strings.iter().collect();
        for s in &original_strings {
            let exact_match = deobf_strings.contains(s);
            let substring_match = all_deobf
                .iter()
                .any(|ds| ds.contains(s.as_str()) && *ds != s);
            if !exact_match && !substring_match {
                missing.push(s.clone());
            }
        }
        if !missing.is_empty() {
            eprintln!("\nMISSING strings (not found even as substring):");
            for s in &missing {
                eprintln!("  MISSING: {:?}", s);
            }
        }
        // Allow a small number of missing strings due to optimization
        // (switch cases eliminated, dead code removed, etc.)
        assert!(
            missing.len() <= 5,
            "{} original strings completely missing from deobfuscated output: {:?}",
            missing.len(),
            missing
        );
    }

    // Same test but for the combined necrobit + strings sample.
    #[test]
    fn test_nr_necrobit_strings_decryption() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let assembly = load_nr_sample("reactor_necrobit_strings.exe");
        let engine = engine();
        let (_output, result) = engine
            .process_assembly(assembly)
            .expect("Deobfuscation should succeed");

        let stats = result.stats();
        eprintln!("\nNecroBit + Strings stats:");
        eprintln!("  strings_decrypted: {}", stats.strings_decrypted);
        eprintln!("  methods_transformed: {}", stats.methods_transformed);
        for t in &result.techniques {
            eprintln!(
                "  technique: {} detected={} transformed={}",
                t.id, t.detected, t.transformed
            );
        }

        assert!(
            stats.strings_decrypted >= 80,
            "Expected at least 80 strings decrypted for necrobit+strings, got {}",
            stats.strings_decrypted
        );
    }
}

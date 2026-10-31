#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! BitMono deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of BitMono-protected assemblies,
//! with comprehensive verification using engine findings.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine findings confirm expected protections
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Removal: Re-detection on output confirms artifacts removed, assembly valid, semantics preserved

#![cfg(feature = "deobfuscation")]

use std::{collections::HashSet, sync::Arc};

use dotscope::{
    deobfuscation::DeobfuscationResult,
    metadata::{
        tables::{AssemblyRefRaw, TypeRefRaw},
        validation::ValidationConfig,
    },
    testkit::{
        deobfuscated, engine, fixture,
        framework::{
            assert_common_requirements, load_sample, original, print_summary,
            run_deobfuscation_test, ProcessMode, SampleSpec, TestResult,
        },
        verification::{
            inlined_away, verify_semantic_preservation, SemanticVerificationResult,
            StructuralConfig,
        },
    },
    CilObject,
};

/// The BitMono versions with samples, each protected from the same TestApp with the same
/// configs: 0.39.0, which the techniques were written against, and 0.45.0, the current
/// release. Every test runs against each.
const VERSIONS: &[&str] = &["0.39.0", "0.45.0"];

/// The fixture directory of a BitMono version.
fn samples_dir(version: &str) -> String {
    format!("packers/bitmono/{version}")
}

/// Expected protections in a BitMono sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ExpectedProtections {
    // PE-level packers
    /// PE signature corrupted (BitDotNet).
    has_pe_corruption: bool,
    /// CLR header zeroed (BitDecompiler).
    has_clr_header_corruption: bool,
    /// Data directory count inflated (BitMono packer).
    has_data_directory_inflation: bool,

    // Reversible IL-level
    /// StringsEncryption (AES + Rfc2898DeriveBytes decryptor).
    has_string_encryption: bool,
    /// CallToCalli (ldtoken + ResolveMethod + calli pattern).
    has_call_to_calli: bool,
    /// DotNetHook (VirtualProtect + Marshal.Write infrastructure).
    has_dotnethook: bool,
    /// UnmanagedString (fake native methods in <Module>).
    has_unmanaged_string: bool,
    /// AntiDebugBreakpoints (DateTime timing checks).
    has_anti_debug: bool,

    // Cleanup targets
    /// SuppressIldasmAttribute on the module.
    has_suppress_ildasm: bool,
    /// AntiDe4dot fake obfuscator attributes.
    has_anti_de4dot: bool,
    /// BitMethodDotnet junk prefix (br.s + orphan prefix opcode).
    has_junk_prefix: bool,
    /// BillionNops dead method (> 50k nops).
    has_billion_nops: bool,

    // Lossy IL-level (detection only)
    /// FullRenamer space-containing names.
    has_renamed_names: bool,

    // Not in BitMono 0.39.0
    /// LocalVariableEncoding (locals moved into an encoded store).
    has_local_variable_encoding: bool,
}

/// All samples of a BitMono version with their expected characteristics.
fn all_samples(version: &str) -> Vec<SampleSpec<ExpectedProtections>> {
    let mut samples = vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        // PE-level packers
        SampleSpec {
            filename: "bitmono_bitdotnet.exe",
            description: "BitDotNet PE signature corruption",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_bitdecompiler.exe",
            description: "BitDecompiler CLR header zeroing",
            expected_protections: ExpectedProtections {
                has_clr_header_corruption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_packer.exe",
            description: "BitMono packer data directory inflation",
            expected_protections: ExpectedProtections {
                has_data_directory_inflation: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_pe_combined.exe",
            description: "BitDotNet + StringsEncryption combined protections",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        // Reversible IL-level
        SampleSpec {
            filename: "bitmono_strings.exe",
            description: "StringsEncryption (AES + Rfc2898DeriveBytes)",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_calltocalli.exe",
            description: "CallToCalli (ldtoken + ResolveMethod + calli)",
            expected_protections: ExpectedProtections {
                has_call_to_calli: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_dotnethook.exe",
            description: "DotNetHook (VirtualProtect + Marshal.Write hooking)",
            expected_protections: ExpectedProtections {
                has_dotnethook: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_unmanagedstring.exe",
            description: "UnmanagedString (fake native methods)",
            expected_protections: ExpectedProtections {
                has_unmanaged_string: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_antidebug.exe",
            description: "AntiDebugBreakpoints (DateTime timing checks)",
            expected_protections: ExpectedProtections {
                has_anti_debug: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        // Cleanup targets
        SampleSpec {
            filename: "bitmono_junk.exe",
            description: "BitMethodDotnet junk prefix + BillionNops",
            expected_protections: ExpectedProtections {
                has_junk_prefix: true,
                has_billion_nops: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_antide4dot.exe",
            description: "AntiDe4dot fake attributes + AntiILdasm",
            expected_protections: ExpectedProtections {
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        // Lossy IL-level
        SampleSpec {
            filename: "bitmono_renamer.exe",
            description: "FullRenamer (space-containing word-pool names)",
            expected_protections: ExpectedProtections {
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        // Combinations
        SampleSpec {
            filename: "bitmono_combined.exe",
            description: "Multiple IL protections combined",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                has_call_to_calli: true,
                has_anti_debug: true,
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_maximum_il.exe",
            description: "All IL protections enabled",
            expected_protections: ExpectedProtections {
                has_string_encryption: true,
                has_call_to_calli: true,
                has_dotnethook: true,
                has_unmanaged_string: true,
                has_anti_debug: true,
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                has_junk_prefix: true,
                has_billion_nops: true,
                has_renamed_names: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "bitmono_maximum.exe",
            description: "All PE + IL protections (maximum)",
            expected_protections: ExpectedProtections {
                has_pe_corruption: true,
                has_clr_header_corruption: true,
                has_data_directory_inflation: true,
                has_string_encryption: true,
                has_call_to_calli: true,
                has_dotnethook: true,
                has_unmanaged_string: true,
                has_anti_debug: true,
                has_suppress_ildasm: true,
                has_anti_de4dot: true,
                has_junk_prefix: true,
                has_billion_nops: true,
                has_renamed_names: true,
                has_local_variable_encoding: false,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
    ];
    if version != "0.39.0" {
        samples.push(SampleSpec {
            filename: "bitmono_localvariableencoding.exe",
            description: "LocalVariableEncoding",
            expected_protections: ExpectedProtections {
                has_local_variable_encoding: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        });
    }
    samples
}

/// Main test that runs all BitMono samples through the comprehensive deobfuscation pipeline.
/// Runs one sample of a BitMono version through the deobfuscation pipeline and checks it
/// against its description in [`all_samples`].
fn check_sample(version: &str, filename: &str) {
    let dir = samples_dir(version);
    let dir = dir.as_str();
    let sample = all_samples(version)
        .into_iter()
        .find(|sample| sample.filename == filename)
        .unwrap_or_else(|| panic!("{filename} is not a BitMono {version} sample"));

    let result = &run_deobfuscation_test(&sample, dir, ProcessMode::File);

    print_bitmono_summary(std::slice::from_ref(result));

    if result.sample.is_original {
        // Original should NOT be detected as BitMono
        let score = result.detection.supporting_matched;
        assert!(
            score < 20,
            "{}: Unprotected original should not be detected as BitMono (score: {})",
            result.sample.filename,
            score
        );
        return;
    }

    let filename = result.sample.filename;
    let expected = &result.sample.expected_protections;
    assert_common_requirements(result);

    // Detection assertions
    let has_attributed_protections = expected.has_pe_corruption
        || expected.has_clr_header_corruption
        || expected.has_data_directory_inflation
        || expected.has_string_encryption
        || expected.has_call_to_calli
        || expected.has_dotnethook
        || expected.has_unmanaged_string
        || expected.has_anti_debug
        || expected.has_junk_prefix
        || expected.has_billion_nops
        || expected.has_local_variable_encoding;

    if has_attributed_protections {
        let score = if result.detection.obfuscator_name.is_some() {
            100
        } else {
            0
        };
        assert!(
            score >= 20,
            "{}: Detection score too low for protected sample (score: {}, expected >= 20)",
            filename,
            score
        );
    }

    if expected.has_suppress_ildasm {
        assert!(
            result.detection.has_technique("generic.ildasm"),
            "{}: SuppressIldasm not detected",
            filename
        );
    }

    if expected.has_anti_de4dot {
        assert!(
            result.detection.has_technique("generic.decompiler"),
            "{}: AntiDe4dot fake attributes not detected",
            filename
        );
    }

    if expected.has_string_encryption {
        assert!(
            result.detection.has_technique("bitmono.strings"),
            "{}: String encryption decryptor not detected",
            filename
        );
    }

    if expected.has_anti_debug {
        assert!(
            result.detection.has_technique("bitmono.debug"),
            "{}: AntiDebugBreakpoints not detected",
            filename
        );
    }

    if expected.has_dotnethook {
        assert!(
            result.detection.has_technique("bitmono.hooks"),
            "{}: DotNetHook infrastructure type not detected",
            filename
        );
    }

    if expected.has_local_variable_encoding {
        assert!(
            result.detection.has_technique("bitmono.locals"),
            "{}: LocalVariableEncoding not detected",
            filename
        );
        assert!(
            !result.post_detection.has_technique("bitmono.locals"),
            "{}: LocalVariableEncoding should be removed after deobfuscation",
            filename
        );
    }

    // Removal assertions
    if expected.has_suppress_ildasm {
        assert!(
            !result.post_detection.has_technique("generic.ildasm"),
            "{}: SuppressIldasm should be removed after deobfuscation",
            filename
        );
    }

    if expected.has_anti_de4dot {
        assert!(
            !result.post_detection.has_technique("generic.decompiler"),
            "{}: AntiDe4dot fake attributes should be removed (remaining: {})",
            filename,
            result
                .post_detection
                .technique_evidence_count("generic.decompiler")
        );
    }

    if expected.has_string_encryption {
        assert!(
            !result.post_detection.has_technique("bitmono.strings"),
            "{}: String decryptor methods should be removed (remaining: {})",
            filename,
            result
                .post_detection
                .technique_evidence_count("bitmono.strings")
        );
    }

    // Post-deobfuscation should have low/zero detection score
    let post_score = result.post_detection.supporting_matched;
    assert!(
        post_score < 20,
        "{}: Post-deobfuscation detection score should be below threshold (score: {})",
        filename,
        post_score
    );
}

mod v0_39_0 {
    use super::*;

    sample_tests! {
        all_samples("0.39.0"), |file| check_sample("0.39.0", file);
        original => "original.exe",
        bitdotnet => "bitmono_bitdotnet.exe",
        bitdecompiler => "bitmono_bitdecompiler.exe",
        packer => "bitmono_packer.exe",
        pe_combined => "bitmono_pe_combined.exe",
        strings => "bitmono_strings.exe",
        calltocalli => "bitmono_calltocalli.exe",
        dotnethook => "bitmono_dotnethook.exe",
        unmanagedstring => "bitmono_unmanagedstring.exe",
        antidebug => "bitmono_antidebug.exe",
        junk => "bitmono_junk.exe",
        antide4dot => "bitmono_antide4dot.exe",
        renamer => "bitmono_renamer.exe",
        combined => "bitmono_combined.exe",
        maximum_il => "bitmono_maximum_il.exe",
        maximum => "bitmono_maximum.exe",
    }
}

mod v0_45_0 {
    use super::*;

    sample_tests! {
        all_samples("0.45.0"), |file| check_sample("0.45.0", file);
        original => "original.exe",
        bitdotnet => "bitmono_bitdotnet.exe",
        bitdecompiler => "bitmono_bitdecompiler.exe",
        packer => "bitmono_packer.exe",
        pe_combined => "bitmono_pe_combined.exe",
        strings => "bitmono_strings.exe",
        calltocalli => "bitmono_calltocalli.exe",
        dotnethook => "bitmono_dotnethook.exe",
        unmanagedstring => "bitmono_unmanagedstring.exe",
        antidebug => "bitmono_antidebug.exe",
        junk => "bitmono_junk.exe",
        antide4dot => "bitmono_antide4dot.exe",
        renamer => "bitmono_renamer.exe",
        combined => "bitmono_combined.exe",
        maximum_il => "bitmono_maximum_il.exe",
        maximum => "bitmono_maximum.exe",
        localvariableencoding => "bitmono_localvariableencoding.exe",
    }
}

/// BitMono-specific summary with detection scoring detail.
fn print_bitmono_summary(results: &[TestResult<ExpectedProtections>]) {
    print_summary(results, "BITMONO", |result| {
        if !result.sample.is_original {
            let det = &result.detection;
            let score = if det.obfuscator_name.is_some() {
                100
            } else {
                0
            };
            eprintln!(
                "       Detection: score={} suppress_ildasm={} anti_de4dot={} decryptors={} anti_debug={} infra_types={}",
                score,
                det.has_technique("generic.ildasm"),
                det.has_technique("generic.decompiler"),
                det.has_technique("bitmono.strings"),
                det.has_technique("bitmono.debug"),
                det.has_technique("bitmono.hooks"),
            );

            let post = &result.post_detection;
            eprintln!(
                "       Removal: valid={} entry={} post_score={} suppress_ildasm={} anti_de4dot={} decryptors={} infra_types={} roundtrip={}",
                result.assembly_valid,
                result.has_valid_entry_point,
                post.supporting_matched,
                post.has_technique("generic.ildasm"),
                post.has_technique("generic.decompiler"),
                post.has_technique("bitmono.strings"),
                post.has_technique("bitmono.hooks"),
                result.roundtrip_ok,
            );
        }
    });
}

/// Test that BitMono detection doesn't false-positive on ConfuserEx samples.
#[test]
fn test_bitmono_no_false_positives_on_confuserex() {
    let confuserex_samples = [
        "packers/confuserex/1.6.0/original.exe",
        "packers/confuserex/1.6.0/mkaring_normal.exe",
        "packers/confuserex/1.6.0/mkaring_maximum.exe",
    ];

    for path in &confuserex_samples {
        let assembly =
            CilObject::from_path_with_validation(fixture(path), ValidationConfig::analysis())
                .unwrap_or_else(|_| panic!("Failed to load {}", path));

        let engine = engine();
        let det = engine.detect(&assembly);
        let is_bitmono = det
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono"));

        assert!(!is_bitmono, "{}: Should not be detected as BitMono", path,);
    }
}

/// Test that BitMono detection doesn't false-positive on Obfuscar samples.
#[test]
fn test_bitmono_no_false_positives_on_obfuscar() {
    let obfuscar_samples = [
        "packers/obfuscar/2.2.50/original.exe",
        "packers/obfuscar/2.2.50/obfuscar_default.exe",
        "packers/obfuscar/2.2.50/obfuscar_maximum.exe",
    ];

    for path in &obfuscar_samples {
        let assembly =
            CilObject::from_path_with_validation(fixture(path), ValidationConfig::analysis())
                .unwrap_or_else(|_| panic!("Failed to load {}", path));

        let engine = engine();
        let det = engine.detect(&assembly);
        let is_bitmono = det
            .attribution
            .as_ref()
            .is_some_and(|a| a.obfuscator_name.contains("BitMono"));

        assert!(!is_bitmono, "{}: Should not be detected as BitMono", path,);
    }
}

/// Test detection scoring: each sample should score above threshold.
#[test]
fn test_bitmono_detection_scoring() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let il_samples: &[(&str, &str, &[&str])] = &[
            (
                "bitmono_strings.exe",
                "StringsEncryption",
                &["bitmono.strings"],
            ),
            ("bitmono_calltocalli.exe", "CallToCalli", &["bitmono.calli"]),
            ("bitmono_dotnethook.exe", "DotNetHook", &["bitmono.hooks"]),
            (
                "bitmono_antide4dot.exe",
                "AntiDe4dot + AntiILdasm",
                &["generic.decompiler", "generic.ildasm"],
            ),
            ("bitmono_combined.exe", "Combined IL", &["bitmono.calli"]),
            (
                "bitmono_maximum_il.exe",
                "Maximum IL",
                &["bitmono.calli", "generic.ildasm"],
            ),
        ];

        for (filename, description, expected_ids) in il_samples {
            let path = fixture(&format!("{dir}/{}", filename));

            let assembly =
                CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
                    .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

            let engine = engine();
            let det = engine.detect(&assembly);
            let score = det.attribution.as_ref().map_or(0, |a| a.supporting_matched);

            let detected_ids: Vec<_> = det
                .techniques
                .iter()
                .filter(|t| t.detected)
                .map(|t| t.id.as_str())
                .collect();

            eprintln!(
                "{} ({}): score={}, detected={:?}",
                filename, description, score, detected_ids,
            );

            for expected in *expected_ids {
                assert!(
                    detected_ids.contains(expected),
                    "{} ({}): Expected technique '{}' not detected (found: {:?})",
                    filename,
                    description,
                    expected,
                    detected_ids,
                );
            }
        }
    }
}

// Per-protection unit tests

/// Runs a PE-level protection test through the full deobfuscation pipeline.
fn run_pe_protection_test(
    dir: &str,
    filename: &str,
) -> (
    &'static CilObject,
    &'static DeobfuscationResult,
    Option<SemanticVerificationResult>,
) {
    let (output, deob_result) = deobfuscated(&format!("{dir}/{filename}"))
        .as_ref()
        .unwrap_or_else(|e| panic!("{}: deobfuscation failed: {}", filename, e));

    assert!(
        output.cor20header().entry_point_token != 0,
        "{}: output has no valid entry point",
        filename
    );

    let bytes = output.file().data();
    let reloaded =
        CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production())
            .unwrap_or_else(|e| panic!("{}: roundtrip failed: {}", filename, e));
    assert_eq!(
        output.methods().iter().count(),
        reloaded.methods().iter().count(),
        "{}: roundtrip method count mismatch",
        filename
    );
    assert_eq!(
        output.types().iter().count(),
        reloaded.types().iter().count(),
        "{}: roundtrip type count mismatch",
        filename
    );

    let semantic_result = {
        let original = original(dir);
        // A PE-protected input may not load as it is; then nothing vouches for the methods
        // the run inlined away, and they count as lost
        let inlined = load_sample(dir, filename)
            .map(|input| inlined_away(&input, deob_result))
            .unwrap_or_default();
        let result = verify_semantic_preservation(
            &original.pure_methods,
            &original.pure_results,
            &Arc::new(reloaded),
            &inlined,
        );
        assert!(
            result.failures.is_empty() && result.methods_checked > 0,
            "{filename}: {}/{} pure methods compute what the original's do:\n{}",
            result.methods_preserved,
            result.methods_checked,
            result.failures.join("\n")
        );
        result
    };

    (output, deob_result, Some(semantic_result))
}

/// Runs detection (IL + SSA) on a sample.
fn run_detection_test(dir: &str, filename: &str) -> DeobfuscationResult {
    let path = fixture(&format!("{dir}/{}", filename));

    let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

    let engine = engine();
    engine.detect(&assembly)
}

// PE-level protection tests (score >= 50, full pipeline)

#[test]
fn test_protection_bitdotnet() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let (_, result, _) = run_pe_protection_test(dir, "bitmono_bitdotnet.exe");
        assert!(
            result
                .attribution
                .as_ref()
                .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
            "BitDotNet not detected as BitMono (got: {:?})",
            result.attribution.as_ref().map(|a| &a.obfuscator_name)
        );
    }
}

#[test]
fn test_protection_bitdecompiler() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let (_, result, _) = run_pe_protection_test(dir, "bitmono_bitdecompiler.exe");
        assert!(
            result
                .attribution
                .as_ref()
                .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
            "BitDecompiler not detected as BitMono (got: {:?})",
            result.attribution.as_ref().map(|a| &a.obfuscator_name)
        );
    }
}

#[test]
fn test_protection_packer() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let (_, result, _) = run_pe_protection_test(dir, "bitmono_packer.exe");
        assert!(
            result
                .attribution
                .as_ref()
                .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
            "Packer not detected as BitMono (got: {:?})",
            result.attribution.as_ref().map(|a| &a.obfuscator_name)
        );
    }
}

#[test]
fn test_protection_pe_combined() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let (_, result, _) = run_pe_protection_test(dir, "bitmono_pe_combined.exe");
        assert!(
            result
                .attribution
                .as_ref()
                .is_some_and(|a| a.obfuscator_name.contains("BitMono")),
            "PE combined not detected as BitMono (got: {:?})",
            result.attribution.as_ref().map(|a| &a.obfuscator_name)
        );
        assert!(
            result
                .techniques
                .iter()
                .any(|t| t.id == "bitmono.strings" && t.detected),
            "Expected string encryption technique detected"
        );
    }
}

// IL-level protection detection tests (score < 50, detection verification)

#[test]
fn test_protection_strings() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_strings.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.strings" && t.detected),
            "StringsEncryption technique should be detected"
        );
    }
}

#[test]
fn test_protection_calltocalli() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_calltocalli.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.calli" && t.detected),
            "CallToCalli technique should be detected"
        );
    }
}

#[test]
fn test_protection_dotnethook() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_dotnethook.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.hooks" && t.detected),
            "DotNetHook technique should be detected"
        );
    }
}

#[test]
fn test_protection_unmanagedstring() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_unmanagedstring.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.unmanaged" && t.detected),
            "UnmanagedString technique should be detected"
        );
    }
}

#[test]
fn test_protection_antidebug() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_antidebug.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.debug" && t.detected),
            "AntiDebug technique should be detected"
        );
    }
}

#[test]
fn test_protection_junk() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_junk.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.junk" && t.detected),
            "Junk prefix technique should be detected"
        );
        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "bitmono.nops" && t.detected),
            "BillionNops technique should be detected"
        );
    }
}

#[test]
fn test_protection_antide4dot() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_antide4dot.exe");

        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "generic.decompiler" && t.detected),
            "Expected fake attributes detected (generic.decompiler)"
        );
        assert!(
            det.techniques
                .iter()
                .any(|t| t.id == "generic.ildasm" && t.detected),
            "Expected SuppressIldasm detected (generic.ildasm)"
        );
    }
}

#[test]
fn test_protection_renamer() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let det = run_detection_test(dir, "bitmono_renamer.exe");

        let any_detected = det.techniques.iter().any(|t| t.detected);
        assert!(
            any_detected,
            "Renamer should produce at least one technique detection"
        );
    }
}

#[test]
fn test_protection_renamer_cleanup() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let (output, _) = deobfuscated(&format!("{dir}/bitmono_renamer.exe"))
            .as_ref()
            .unwrap_or_else(|e| panic!("Deobfuscation failed: {}", e));

        let mut space_types = Vec::new();
        for entry in output.types().iter() {
            let t = entry.value();
            if t.name.contains(' ') && !(t.name.starts_with('<') && t.name.ends_with('>')) {
                space_types.push(t.name.clone());
            }
        }
        assert!(
            space_types.is_empty(),
            "Found {} type names still containing spaces after deobfuscation: {:?}",
            space_types.len(),
            &space_types[..space_types.len().min(5)]
        );

        let mut space_methods = Vec::new();
        for entry in output.methods().iter() {
            let m = entry.value();
            if m.name.contains(' ') && !(m.name.starts_with('<') && m.name.ends_with('>')) {
                space_methods.push(m.name.clone());
            }
        }
        assert!(
            space_methods.is_empty(),
            "Found {} method names still containing spaces after deobfuscation: {:?}",
            space_methods.len(),
            &space_methods[..space_methods.len().min(5)]
        );

        assert!(
            output.cor20header().entry_point_token != 0,
            "Output should have a valid entry point"
        );
        let bytes = output.file().data();
        CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::production())
            .expect("Deobfuscated assembly should pass production validation");
    }
}

#[test]
fn test_dotnethook_call_targets() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        for sample in &["bitmono_dotnethook.exe", "bitmono_maximum_il.exe"] {
            eprintln!("\n=== Testing {} ===", sample);
            test_dotnethook_call_targets_for_sample(dir, sample);
        }
    }
}

fn test_dotnethook_call_targets_for_sample(dir: &str, sample: &str) {
    let original_path = fixture(&format!("{dir}/original.exe"));
    let original =
        CilObject::from_path_with_validation(&original_path, ValidationConfig::analysis())
            .expect("Failed to load original.exe");

    let orig_build_message_name = find_method_by_name(&original, "BuildMessage");
    eprintln!("Original BuildMessage: {:?}", orig_build_message_name);

    dump_call_targets(&original, "SayHello", "ORIGINAL");
    dump_call_targets(&original, "SayGoodbye", "ORIGINAL");

    let (output, _result) = deobfuscated(&format!("{dir}/{sample}"))
        .as_ref()
        .unwrap_or_else(|e| panic!("Deobfuscation failed for {}: {}", sample, e));

    eprintln!("\n[DEOBFUSCATED] All methods and call targets:");
    for entry in output.methods().iter() {
        let m = entry.value();
        let dt = m
            .declaring_type_rc()
            .map(|t| t.name.clone())
            .unwrap_or_default();
        let calls: Vec<String> = m
            .instructions()
            .filter(|i| i.mnemonic == "call" || i.mnemonic == "callvirt" || i.mnemonic == "newobj")
            .filter_map(|i| {
                i.get_token_operand().map(|t| {
                    let target_name = output
                        .method(&t)
                        .map(|tm| {
                            let tdt = tm
                                .declaring_type_rc()
                                .map(|tt| tt.name.clone())
                                .unwrap_or_default();
                            format!("{}.{}", tdt, tm.name)
                        })
                        .unwrap_or_else(|_| format!("ext:0x{:08X}", t.value()));
                    format!("{} 0x{:08X}({})", i.mnemonic, t.value(), target_name)
                })
            })
            .collect();
        if !calls.is_empty() {
            eprintln!(
                "  0x{:08X} {}.{} -> {}",
                m.token.value(),
                dt,
                m.name,
                calls.join(", ")
            );
        }
    }

    dump_call_targets(output, "SayHello", "DEOBFUSCATED");
    dump_call_targets(output, "SayGoodbye", "DEOBFUSCATED");

    let say_hello_targets = get_call_target_names(output, "SayHello");
    let say_goodbye_targets = get_call_target_names(output, "SayGoodbye");

    eprintln!("SayHello calls: {:?}", say_hello_targets);
    eprintln!("SayGoodbye calls: {:?}", say_goodbye_targets);

    let hello_methoddef_calls: Vec<_> = get_call_target_tokens(output, "SayHello")
        .into_iter()
        .filter(|t| t.table() == 0x06)
        .collect();
    let goodbye_methoddef_calls: Vec<_> = get_call_target_tokens(output, "SayGoodbye")
        .into_iter()
        .filter(|t| t.table() == 0x06)
        .collect();

    eprintln!("SayHello MethodDef calls: {:?}", hello_methoddef_calls);
    eprintln!("SayGoodbye MethodDef calls: {:?}", goodbye_methoddef_calls);

    let say_hello_token = find_method_token(output, "SayHello");
    let say_goodbye_token = find_method_token(output, "SayGoodbye");

    if let Some(hello_tok) = say_hello_token {
        assert!(
            !hello_methoddef_calls.contains(&hello_tok),
            "SayHello should not call itself"
        );
    }
    if let Some(goodbye_tok) = say_goodbye_token {
        assert!(
            !goodbye_methoddef_calls.contains(&goodbye_tok),
            "SayGoodbye should not call itself"
        );
    }
    if let (Some(hello_tok), Some(goodbye_tok)) = (say_hello_token, say_goodbye_token) {
        assert!(
            !hello_methoddef_calls.contains(&goodbye_tok),
            "SayHello should not call SayGoodbye (off-by-one bug)"
        );
        assert!(
            !goodbye_methoddef_calls.contains(&hello_tok),
            "SayGoodbye should not call SayHello (off-by-one bug)"
        );
    }

    if !hello_methoddef_calls.is_empty() && !goodbye_methoddef_calls.is_empty() {
        let hello_build = hello_methoddef_calls
            .iter()
            .find(|t| Some(**t) != say_hello_token && Some(**t) != say_goodbye_token);
        let goodbye_build = goodbye_methoddef_calls
            .iter()
            .find(|t| Some(**t) != say_hello_token && Some(**t) != say_goodbye_token);

        if let (Some(hb), Some(gb)) = (hello_build, goodbye_build) {
            assert_eq!(
                hb, gb,
                "SayHello and SayGoodbye should call the same BuildMessage method"
            );
        }
    }
}

fn find_method_by_name(assembly: &CilObject, name: &str) -> Option<String> {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == name {
            return Some(format!("{} (0x{:08X})", method.name, method.token.value()));
        }
    }
    None
}

fn find_method_token(assembly: &CilObject, name: &str) -> Option<dotscope::metadata::token::Token> {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name == name {
            return Some(method.token);
        }
    }
    None
}

fn dump_call_targets(assembly: &CilObject, method_name: &str, label: &str) {
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        eprintln!(
            "[{}] {} (0x{:08X}) call targets:",
            label,
            method_name,
            method.token.value()
        );
        for instr in method.instructions() {
            if instr.mnemonic == "call"
                || instr.mnemonic == "callvirt"
                || instr.mnemonic == "newobj"
            {
                if let Some(target) = instr.get_token_operand() {
                    let target_name = assembly
                        .method(&target)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|_| format!("(unresolved 0x{:08X})", target.value()));
                    eprintln!(
                        "  {} 0x{:08X} -> {}",
                        instr.mnemonic,
                        target.value(),
                        target_name
                    );
                }
            }
        }
    }
}

fn get_call_target_names(assembly: &CilObject, method_name: &str) -> Vec<String> {
    let mut names = Vec::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        for instr in method.instructions() {
            if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                if let Some(target) = instr.get_token_operand() {
                    let name = assembly
                        .method(&target)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|_| format!("(external 0x{:08X})", target.value()));
                    names.push(name);
                }
            }
        }
    }
    names
}

fn get_call_target_tokens(
    assembly: &CilObject,
    method_name: &str,
) -> Vec<dotscope::metadata::token::Token> {
    let mut tokens = Vec::new();
    for entry in assembly.methods().iter() {
        let method = entry.value();
        if method.name != method_name {
            continue;
        }
        for instr in method.instructions() {
            if instr.mnemonic == "call" || instr.mnemonic == "callvirt" {
                if let Some(target) = instr.get_token_operand() {
                    tokens.push(target);
                }
            }
        }
    }
    tokens
}

/// Names of the assemblies `assembly` references.
fn assembly_ref_names(assembly: &CilObject) -> HashSet<String> {
    let strings = assembly.strings().unwrap();
    assembly
        .tables()
        .unwrap()
        .table::<AssemblyRefRaw>()
        .into_iter()
        .flatten()
        .map(|aref| {
            let aref = aref.expect("row parses");
            strings.get(aref.name as usize).unwrap().to_string()
        })
        .collect()
}

#[test]
fn test_no_obfuscator_metadata_survives() {
    for version in VERSIONS {
        let dir = samples_dir(version);
        let dir = dir.as_str();
        eprintln!("=== BitMono {version} ===");
        let original_path = fixture(&format!("{dir}/original.exe"));
        let original = CilObject::from_path(&original_path).unwrap();
        let original_refs = assembly_ref_names(&original);

        // The code BitMono injects references assemblies the program does not
        // (its own runtime library, among others). Once the injected code is
        // gone, the program must import no more than it did before protection.
        for sample in [
            "bitmono_calltocalli.exe",
            "bitmono_combined.exe",
            "bitmono_maximum.exe",
            "bitmono_maximum_il.exe",
        ] {
            let (output, _) = deobfuscated(&format!("{dir}/{sample}")).as_ref().unwrap();

            let bytes = output.file().data();
            let reloaded =
                CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::analysis())
                    .unwrap();

            let foreign: Vec<String> = assembly_ref_names(&reloaded)
                .difference(&original_refs)
                .cloned()
                .collect();
            assert!(
                foreign.is_empty(),
                "{sample}: obfuscator-injected AssemblyRefs {foreign:?} survive deobfuscation"
            );

            let tables = reloaded.tables().unwrap();
            let strings = reloaded.strings().unwrap();
            if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                for tr in typeref_table {
                    let tr = tr.expect("row parses");
                    let name = strings.get(tr.type_name as usize).unwrap_or("???");
                    assert_ne!(
                        tr.resolution_scope.tag,
                        dotscope::metadata::tables::TableId::Module,
                        "{}: TypeRef RID {} ({}) has Module resolution scope - likely an obfuscator artifact",
                        sample,
                        tr.rid,
                        name
                    );
                }
            }
        }
    }
}

/// The `xor`, `mul`, `sub` and narrowing `conv` instructions of each method of `assembly`, by
/// declaring type and name.
fn arithmetic_by_method(assembly: &CilObject) -> std::collections::BTreeMap<String, usize> {
    assembly
        .methods()
        .iter()
        .map(|entry| {
            let method = entry.value();
            let declaring = method
                .declaring_type_rc()
                .map(|t| t.fullname().to_string())
                .unwrap_or_default();
            let count = method
                .instructions()
                .filter(|i| {
                    matches!(
                        i.mnemonic,
                        "xor" | "mul" | "sub" | "conv.i1" | "conv.u1" | "conv.i2" | "conv.u2"
                    )
                })
                .count();
            (format!("{declaring}::{}", method.name), count)
        })
        .collect()
}

/// LocalVariableEncoding adds an encode to every store and a decode to every load of an
/// integer local, an 8- or 16-bit one's narrowed. Once reversed, each method computes with
/// exactly the `xor`, `mul`, `sub` and narrowing conversions the same pipeline leaves in its
/// original: loop-carried locals included, whose encodings meet at phis.
#[test]
fn local_variable_encoding_leaves_the_original_arithmetic() {
    let dir = samples_dir("0.45.0");
    let (original, _) = deobfuscated(&format!("{dir}/original.exe"))
        .as_ref()
        .unwrap();
    let (output, _) = deobfuscated(&format!("{dir}/bitmono_localvariableencoding.exe"))
        .as_ref()
        .unwrap();

    let expected = arithmetic_by_method(original);
    let restored = arithmetic_by_method(output);
    for (method, count) in &expected {
        if let Some(found) = restored.get(method) {
            assert_eq!(found, count, "{method}");
        }
    }
    assert!(
        restored
            .keys()
            .filter(|m| expected.contains_key(*m))
            .count()
            > 20,
        "methods compared"
    );
}

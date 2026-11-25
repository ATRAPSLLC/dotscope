#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! JIEJIE.NET deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of JIEJIE.NET-protected assemblies,
//! with detection verification and semantic preservation validation.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine identifies JIEJIE.NET and expected techniques
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Removal: Re-detection on output confirms artifacts removed

#![cfg(feature = "deobfuscation")]

use dotscope::{
    metadata::validation::ValidationConfig,
    testkit::{
        engine, fixture,
        framework::{
            assert_common_requirements, load_sample, print_summary, run_deobfuscation_test,
            ProcessMode, SampleSpec,
        },
        verification::StructuralConfig,
    },
    CilObject,
};

const SAMPLES_DIR: &str = "packers/jiejie/source";

/// Expected protections in a JIEJIE.NET sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct JiejieExpectedProtections {
    /// Expect Int32ValueContainer (integer constant hiding via TickCount-seeded .cctor).
    has_int32_container: bool,
    /// Expect string encryption (_Strings<N> classes with dcsoft decryptor).
    has_string_encryption: bool,
    /// Expect high-strength string mode (_HightStrings<N> per-method decryptors).
    has_high_strength_strings: bool,
    /// Expect control flow obfuscation (switch dispatchers).
    has_control_flow: bool,
    /// Expect typeof() encryption (RuntimeTypeHandleContainer).
    has_typeof_encryption: bool,
    /// Expect array init encryption (RuntimeFieldHandleContainer + MyInitializeArray).
    has_array_encryption: bool,
    /// Expect lock/using structure obfuscation (Monitor_Enter/MyDispose redirections).
    has_lock_using: bool,
    /// Expect resource encryption (SMF_* call redirections).
    has_resource_encryption: bool,
    /// Expect renaming (_jiejie/_jj prefix patterns).
    has_renaming: bool,
}

/// All JIEJIE.NET samples with their expected characteristics.
///
/// Sample configurations reflect actual JIEJIE.NET CLI switches used during
/// generation (see tests/samples/packers/jiejie/source/README.md).
///
/// Note on Int32ValueContainer: It is bundled with the ControlFlow switch.
/// Char/enum encryption, typeof, array init, and lock/using are also sub-features
/// of ControlFlow and only appear when ControlFlow is enabled.
fn all_samples() -> Vec<SampleSpec<JiejieExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: JiejieExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_strings_only.exe",
            description: "String encryption only (+strings)",
            expected_protections: JiejieExpectedProtections {
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_highstrings.exe",
            description: "High-strength string encryption (+strings,+hightstrings)",
            expected_protections: JiejieExpectedProtections {
                has_string_encryption: true,
                has_high_strength_strings: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_controlflow_only.exe",
            description: "Control flow only (+controlflow, all sub-features)",
            expected_protections: JiejieExpectedProtections {
                has_int32_container: true,
                has_control_flow: true,
                has_typeof_encryption: true,
                has_array_encryption: true,
                has_lock_using: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_controlflow_no_rename.exe",
            description: "Control flow, no rename (Int32ValueContainer verification target)",
            expected_protections: JiejieExpectedProtections {
                has_int32_container: true,
                has_control_flow: true,
                has_typeof_encryption: true,
                has_array_encryption: true,
                has_lock_using: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_rename_only.exe",
            description: "Renaming only (+rename)",
            expected_protections: JiejieExpectedProtections {
                has_renaming: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..StructuralConfig::default()
            },
        },
        SampleSpec {
            filename: "jiejie_resources_only.exe",
            description: "Resource encryption only (+resources)",
            expected_protections: JiejieExpectedProtections {
                has_resource_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_no_rename.exe",
            description: "All protections except rename (-rename)",
            expected_protections: JiejieExpectedProtections {
                has_int32_container: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_typeof_encryption: true,
                has_array_encryption: true,
                has_lock_using: true,
                has_resource_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "jiejie_default.exe",
            description: "All defaults (CF+Strings+Resources+Rename+MemberOrder+RemoveMember)",
            expected_protections: JiejieExpectedProtections {
                has_int32_container: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_typeof_encryption: true,
                has_array_encryption: true,
                has_lock_using: true,
                has_resource_encryption: true,
                has_renaming: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..StructuralConfig::default()
            },
        },
        SampleSpec {
            filename: "jiejie_maximum.exe",
            description: "Maximum protection (all + high-strength strings)",
            expected_protections: JiejieExpectedProtections {
                has_int32_container: true,
                has_string_encryption: true,
                has_high_strength_strings: true,
                has_control_flow: true,
                has_typeof_encryption: true,
                has_array_encryption: true,
                has_lock_using: true,
                has_resource_encryption: true,
                has_renaming: true,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..StructuralConfig::default()
            },
        },
    ]
}

/// Runs one JIEJIE.NET sample through the deobfuscation pipeline and checks it against its
/// description in [`all_samples`].
fn check_sample(filename: &str) {
    let sample = all_samples()
        .into_iter()
        .find(|sample| sample.filename == filename)
        .unwrap_or_else(|| panic!("{filename} is not a JIEJIE.NET sample"));

    let result = run_deobfuscation_test(&sample, SAMPLES_DIR, ProcessMode::Assembly);

    print_summary(std::slice::from_ref(&result), "JIEJIE.NET", |result| {
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection.confidence() * 100.0,
                result.detection.technique_ids.join(", "),
            );
        }
    });

    if result.sample.is_original {
        // Original should NOT be detected as JIEJIE.NET
        assert!(
            result.detection.confidence() < 0.5,
            "{}: Unprotected original should not be detected as JIEJIE.NET (confidence: {:.0}%)",
            result.sample.filename,
            result.detection.confidence() * 100.0
        );
        return;
    }
    assert_common_requirements(&result);

    // Detection: JIEJIE.NET should be identified when detectable protections
    // are present. Rename-only samples have no structural pattern to detect.
    let expected = &result.sample.expected_protections;
    let has_detectable_protection = expected.has_int32_container
        || expected.has_string_encryption
        || expected.has_typeof_encryption
        || expected.has_array_encryption
        || expected.has_resource_encryption;

    if has_detectable_protection {
        assert!(
            result.detection.confidence() > 0.0,
            "{filename}: Should be detected as JIEJIE.NET (confidence: {:.0}%)",
            result.detection.confidence() * 100.0
        );

        // Post-deobfuscation: artifacts should be removed
        assert!(
            result.post_detection.confidence() < 0.5,
            "{filename}: JIEJIE.NET artifacts should be removed after deobfuscation \
             (post-confidence: {:.0}%, remaining techniques: [{}])",
            result.post_detection.confidence() * 100.0,
            result.post_detection.technique_ids.join(", ")
        );
    }
}

sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    strings_only => "jiejie_strings_only.exe",
    highstrings => "jiejie_highstrings.exe",
    controlflow_only => "jiejie_controlflow_only.exe",
    controlflow_no_rename => "jiejie_controlflow_no_rename.exe",
    rename_only => "jiejie_rename_only.exe",
    resources_only => "jiejie_resources_only.exe",
    no_rename => "jiejie_no_rename.exe",
    default => "jiejie_default.exe",
    maximum => "jiejie_maximum.exe",
}

/// Test that all samples can be loaded and parsed by dotscope.
#[test]
fn test_jiejie_samples_loadable() {
    let samples = all_samples();
    let mut loaded = 0;

    for sample in &samples {
        let assembly = match load_sample(SAMPLES_DIR, sample.filename) {
            Ok(a) => a,
            Err(e) => panic!("{}: Failed to load sample: {}", sample.filename, e),
        };
        let method_count = assembly.methods().iter().count();
        let type_count = assembly.types().iter().count();

        eprintln!(
            "  {} — {} types, {} methods",
            sample.filename, type_count, method_count
        );

        // Protected samples should have more types than the original
        // (due to injected synthetic types like containers, etc.)
        if !sample.is_original && sample.expected_protections.has_int32_container {
            assert!(
                type_count > 7,
                "{}: Expected synthetic types from JIEJIE.NET injection (got {} types)",
                sample.filename,
                type_count
            );
        }

        loaded += 1;
    }

    eprintln!("\nLoaded {}/{} JIEJIE.NET samples", loaded, samples.len());
}

/// Test that the original sample is NOT detected as JIEJIE.NET.
#[test]
fn test_jiejie_no_false_positive_on_original() {
    let path = fixture(&format!("{}/original.exe", SAMPLES_DIR));

    let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .expect("Failed to load original");

    let engine = engine();
    let det = engine.detect(&assembly);
    let attribution = det.attribution;
    let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };

    assert!(
        confidence < 0.5,
        "Unprotected original should not be detected as any obfuscator (confidence: {:.0}%)",
        confidence * 100.0
    );
}

/// Test that JIEJIE.NET samples are NOT falsely detected as ConfuserEx.
#[test]
fn test_jiejie_no_confuserex_false_positive() {
    let jiejie_samples = [
        "jiejie_controlflow_only.exe",
        "jiejie_strings_only.exe",
        "jiejie_no_rename.exe",
    ];

    for filename in &jiejie_samples {
        let path = fixture(&format!("{}/{}", SAMPLES_DIR, filename));

        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

        let engine = engine();
        let det = engine.detect(&assembly);

        if let Some(ref attr) = det.attribution {
            assert_ne!(
                attr.obfuscator_name,
                "ConfuserEx",
                "{}: Should NOT be falsely attributed to ConfuserEx (techniques: [{}])",
                filename,
                attr.technique_ids.join(", ")
            );
        }
    }
}

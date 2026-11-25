#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Obfuscar deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of Obfuscar-protected assemblies,
//! with detection verification and string decryption validation.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine identifies Obfuscar (not ConfuserEx)
//! 2. Deobfuscation: Engine processes successfully
//! 3. Removal: Re-detection on output confirms artifacts removed

#![cfg(feature = "deobfuscation")]

use dotscope::{
    metadata::validation::ValidationConfig,
    testkit::{
        engine, fixture,
        framework::{
            assert_common_requirements, print_summary, run_deobfuscation_test, ProcessMode,
            SampleSpec,
        },
        verification::StructuralConfig,
    },
    CilObject,
};

const SAMPLES_DIR: &str = "packers/obfuscar/2.2.50";

/// Expected protections in an Obfuscar sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ObfuscarExpectedProtections {
    /// Expect SuppressIldasmAttribute on the module.
    has_suppress_ildasm: bool,
    /// Expect string hiding (`<PrivateImplementationDetails>{GUID}` helper type).
    has_string_hiding: bool,
    /// Expect null/empty parameter names from renaming.
    has_null_params: bool,
}

/// All Obfuscar samples with their expected characteristics.
///
/// Sample configs reflect actual Obfuscar defaults from Settings.cs:
/// - Default: KeepPublicApi=true, HidePrivateApi=true, RenameFields=true,
///   RenameProperties=true, RenameEvents=true, HideStrings=true,
///   SuppressIldasm=true, OptimizeMethods=true, ReuseNames=true
fn all_samples() -> Vec<SampleSpec<ObfuscarExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ObfuscarExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "obfuscar_default.exe",
            description: "True defaults (rename private + strings + SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                // SuppressIldasm defaults to true in Settings.cs, but when Obfuscar runs
                // on .NET Core/.NET 5+, SuppressIldasmAttribute doesn't exist in the
                // runtime so the attribute is silently not added.
                has_suppress_ildasm: false,
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "obfuscar_strings_only.exe",
            description: "String hiding only (no renaming, no SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false,
                has_string_hiding: true,
                has_null_params: false,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "obfuscar_rename_only.exe",
            description: "Renaming only (no strings, no SuppressIldasm)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false,
                has_string_hiding: false,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "obfuscar_unicode.exe",
            description: "Unicode name mode (defaults + UseUnicodeNames)",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false, // See obfuscar_default note
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "obfuscar_maximum.exe",
            description: "Maximum: all protections, public API also renamed",
            expected_protections: ObfuscarExpectedProtections {
                has_suppress_ildasm: false, // See obfuscar_default note
                has_string_hiding: true,
                has_null_params: true,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Runs one Obfuscar sample through the deobfuscation pipeline and checks it against its
/// description in [`all_samples`].
fn check_sample(filename: &str) {
    let sample = all_samples()
        .into_iter()
        .find(|sample| sample.filename == filename)
        .unwrap_or_else(|| panic!("{filename} is not an Obfuscar sample"));
    let result = run_deobfuscation_test(&sample, SAMPLES_DIR, ProcessMode::Assembly);

    print_summary(std::slice::from_ref(&result), "OBFUSCAR", |result| {
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection.confidence() * 100.0,
                result.detection.technique_ids.join(", "),
            );
        }
    });

    if result.sample.is_original {
        // Original should NOT be detected as Obfuscar
        assert!(
            result.detection.confidence() < 0.5,
            "{}: Unprotected original should not be detected as Obfuscar (confidence: {:.0}%)",
            result.sample.filename,
            result.detection.confidence() * 100.0
        );
        return;
    }

    let expected = &result.sample.expected_protections;

    // Common assertions: core validity, semantic preservation, structural match
    assert_common_requirements(&result);

    // Detection assertions
    if expected.has_string_hiding {
        assert!(
            result.detection.confidence() > 0.0,
            "{filename}: Detection confidence should be positive for string hiding sample (confidence: {:.0}%)",
            result.detection.confidence() * 100.0
        );
        assert!(
            !result.detection.technique_ids.is_empty(),
            "{filename}: Expected at least one detected technique for string hiding sample",
        );
    }
}

sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    default => "obfuscar_default.exe",
    strings_only => "obfuscar_strings_only.exe",
    rename_only => "obfuscar_rename_only.exe",
    unicode => "obfuscar_unicode.exe",
    maximum => "obfuscar_maximum.exe",
}

/// Test that the Obfuscar detection doesn't false-positive on ConfuserEx samples.
#[test]
fn test_obfuscar_no_false_positives_on_confuserex() {
    let confuserex_path = fixture("packers/confuserex/1.6.0/original.exe");

    let assembly =
        CilObject::from_path_with_validation(confuserex_path, ValidationConfig::analysis())
            .expect("Failed to load ConfuserEx original");

    let engine = engine();
    let det = engine.detect(&assembly);
    let attribution = det.attribution;
    let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };

    assert!(
        confidence < 0.5,
        "ConfuserEx original should not be detected as Obfuscar (confidence: {:.0}%)",
        confidence * 100.0
    );
}

/// Test detection scoring: samples with string hiding should score high.
#[test]
fn test_obfuscar_detection_scoring() {
    let samples_with_strings = [
        "obfuscar_default.exe",
        "obfuscar_strings_only.exe",
        "obfuscar_unicode.exe",
        "obfuscar_maximum.exe",
    ];

    for filename in &samples_with_strings {
        let path = fixture(&format!("{}/{}", SAMPLES_DIR, filename));

        let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load {}: {}", filename, e));

        let engine = engine();
        let det = engine.detect(&assembly);
        let attribution = det.attribution;
        let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };
        let techniques: Vec<String> = attribution
            .as_ref()
            .map_or_else(Vec::new, |a| a.technique_ids.clone());

        eprintln!(
            "{}: confidence={:.0}%, techniques=[{}]",
            filename,
            confidence * 100.0,
            techniques.join(", ")
        );

        assert!(
            confidence >= 0.6,
            "{}: Expected high detection confidence for string hiding sample (got: {:.0}%)",
            filename,
            confidence * 100.0
        );
    }
}

/// Test that rename-only samples score below the detection threshold
/// (no string hiding means no high-confidence signal).
#[test]
fn test_obfuscar_rename_only_below_threshold() {
    let path = fixture(&format!("{}/obfuscar_rename_only.exe", SAMPLES_DIR));

    let assembly = CilObject::from_path_with_validation(&path, ValidationConfig::analysis())
        .expect("Failed to load rename-only sample");

    let engine = engine();
    let det = engine.detect(&assembly);
    let attribution = det.attribution;
    let confidence = if attribution.is_some() { 1.0f64 } else { 0.0 };
    let techniques: Vec<String> = attribution
        .as_ref()
        .map_or_else(Vec::new, |a| a.technique_ids.clone());

    eprintln!(
        "rename_only: confidence={:.0}%, techniques=[{}]",
        confidence * 100.0,
        techniques.join(", ")
    );

    // Without string hiding, the only signal is null params
    // (SuppressIldasm is disabled in this config)
    // Confidence should be below 50% threshold
    assert!(
        confidence < 0.5,
        "Rename-only sample should not exceed detection threshold (confidence: {:.0}%, techniques: [{}])",
        confidence * 100.0,
        techniques.join(", ")
    );
    assert!(
        techniques.is_empty(),
        "Rename-only sample should have no detected techniques"
    );
}

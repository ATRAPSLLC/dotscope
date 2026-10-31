#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! ConfuserEx deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of ConfuserEx-protected assemblies,
//! with comprehensive verification using engine findings.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine findings confirm expected protections (including post-anti-tamper re-detection)
//! 2. Deobfuscation: Engine processes successfully with cleanup enabled
//! 3. Removal: Re-detection on output confirms artifacts removed, assembly valid, semantics preserved

#![cfg(feature = "deobfuscation")]

use dotscope::{
    metadata::tables::{ManifestResourceRaw, TableId},
    testkit::{
        deobfuscated, fixture,
        framework::{
            assert_common_requirements, print_summary, run_deobfuscation_test, ProcessMode,
            SampleSpec, TestResult,
        },
        verification::StructuralConfig,
    },
    CilObject,
};

const SAMPLES_DIR: &str = "packers/confuserex/1.6.0";

/// Expected protections in a sample.
#[derive(Debug, Clone, Default)]
struct ExpectedProtections {
    /// Expect ConfuserEx marker attributes (ConfusedByAttribute).
    has_marker_attributes: bool,
    /// Expect SuppressIldasmAttribute.
    has_suppress_ildasm: bool,
    /// Expect string/constant decryptor methods.
    has_decryptors: bool,
    /// Expect anti-debug methods.
    has_anti_debug: bool,
    /// Expect anti-tamper (encrypted method bodies).
    has_anti_tamper: bool,
    /// Expect control flow obfuscation (switch dispatchers).
    has_control_flow: bool,
    /// Expect resource encryption.
    has_resources: bool,
    /// Expect ReferenceProxy methods (call forwarding proxies).
    has_reference_proxy: bool,
    /// Expect anti-dump (the module initializer erasing its own PE headers).
    has_anti_dump: bool,
    /// Expect invalid metadata (repeated stream headers, bogus table rows).
    has_invalid_metadata: bool,
}

/// All ConfuserEx samples with their expected characteristics.
fn all_samples() -> Vec<SampleSpec<ExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_minimal.exe",
            description: "Minimal protection (marker only)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
        },
        SampleSpec {
            filename: "mkaring_normal.exe",
            description: "Normal protection (constants + anti-debug + reference proxy)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                has_decryptors: true,
                has_anti_debug: true,
                has_reference_proxy: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
        },
        SampleSpec {
            filename: "mkaring_constants.exe",
            description: "Constants encryption only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_controlflow.exe",
            description: "Control flow obfuscation only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_resources.exe",
            description: "Resource encryption",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_resources: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_maximum.exe",
            description: "Maximum protection (all features)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                has_decryptors: true,
                has_anti_debug: false, // Maximum uses anti-tamper instead
                has_anti_tamper: true,
                has_control_flow: true,
                has_resources: false,
                has_reference_proxy: true,
                has_anti_dump: true,
                has_invalid_metadata: false,
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
        },
        SampleSpec {
            filename: "mkaring_antitamper.exe",
            description: "Anti-tamper only (isolated for decryption bug testing)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_dyncyph.exe",
            description: "Constants encryption with dynamic cipher (mode=dynamic)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_cfg.exe",
            description:
                "Constants encryption with CFG mode (cfg=true, order-dependent state machine)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_controlflow_expression.exe",
            description: "Control flow obfuscation with expression predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_x86.exe",
            description: "Constants encryption with x86 native cipher",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_controlflow_x86.exe",
            description: "Control flow obfuscation with x86 native predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_x86_controlflow.exe",
            description: "Constants x86 cipher + control flow normal predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_x86_controlflow_x86.exe",
            description: "Constants x86 cipher + control flow x86 predicate",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_antitamper_controlflow.exe",
            description: "Anti-tamper + ControlFlow (combination test)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_antitamper_constants_cfg.exe",
            description: "Anti-tamper + Constants CFG mode (combination test)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_tamper: true,
                has_decryptors: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_constants_cfg_controlflow.exe",
            description: "Constants CFG + ControlFlow (combination test, no anti-tamper)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_decryptors: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_antidebug.exe",
            description: "Anti-debug only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_debug: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_antidump.exe",
            description: "Anti-dump only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_anti_dump: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_antiildasm.exe",
            description: "Anti-ILDasm only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_suppress_ildasm: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_harden.exe",
            description: "Harden only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_invalidmetadata.exe",
            description: "Invalid metadata only (issues #289, #290)",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_invalid_metadata: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_invalidmetadata_antitamper.exe",
            description: "Invalid metadata + anti-tamper",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_invalid_metadata: true,
                has_anti_tamper: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_refproxy.exe",
            description: "Reference proxy only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                has_reference_proxy: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "mkaring_rename.exe",
            description: "Renaming only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: true,
            // The original names are not in the file: renamed types are matched by count
            structural_config: StructuralConfig {
                check_type_names: false,
                ..Default::default()
            },
        },
        SampleSpec {
            filename: "mkaring_typescramble.exe",
            description: "Type scrambler only",
            expected_protections: ExpectedProtections {
                has_marker_attributes: true,
                ..Default::default()
            },
            is_original: false,
            // Not supported: the type scrambler is not reversed
            check_semantic_preservation: false,
            check_structural_match: true,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Runs one sample through the deobfuscation pipeline and checks it against its description in
/// [`all_samples`].
fn check_sample(filename: &str) {
    let sample = all_samples()
        .into_iter()
        .find(|sample| sample.filename == filename)
        .unwrap_or_else(|| panic!("{filename} is not a ConfuserEx sample"));
    let result = &run_deobfuscation_test(&sample, SAMPLES_DIR, ProcessMode::Assembly);

    print_confuserex_summary(std::slice::from_ref(result));

    if result.sample.is_original {
        return;
    }

    let filename = result.sample.filename;
    let expected = &result.sample.expected_protections;
    assert_common_requirements(result);

    // Detection assertions (engine found expected protections)
    if expected.has_marker_attributes {
        assert!(
            result.detection.has_technique("confuserex.marker"),
            "{}: markers not detected by engine",
            filename
        );
    }
    if expected.has_suppress_ildasm {
        assert!(
            result.detection.has_technique("generic.ildasm"),
            "{}: suppress_ildasm not detected",
            filename
        );
    }
    if expected.has_decryptors {
        assert!(
            result.detection.has_technique("confuserex.constants"),
            "{}: decryptors not detected",
            filename
        );
    }
    if expected.has_anti_debug {
        assert!(
            result.detection.has_technique("confuserex.debug"),
            "{}: anti-debug not detected",
            filename
        );
    }
    if expected.has_anti_tamper {
        assert!(
            result.detection.has_technique("confuserex.tamper"),
            "{}: anti-tamper not detected",
            filename
        );
    }
    if expected.has_resources {
        assert!(
            result.detection.has_technique("confuserex.resources"),
            "{}: resources not detected",
            filename
        );
    }
    if expected.has_reference_proxy {
        assert!(
            result.detection.has_technique("confuserex.proxy"),
            "{}: reference proxy not detected",
            filename
        );
    }
    if expected.has_anti_dump {
        assert!(
            result.detection.has_technique("confuserex.dump"),
            "{}: anti-dump not detected",
            filename
        );
    }
    if expected.has_invalid_metadata {
        assert!(
            result.detection.has_technique("confuserex.metadata"),
            "{}: invalid metadata not detected",
            filename
        );
    }

    // Removal assertions (output should be clean)
    if expected.has_marker_attributes {
        assert!(
            !result.post_detection.has_technique("confuserex.marker"),
            "{}: markers should be removed",
            filename
        );
    }
    if expected.has_suppress_ildasm {
        assert!(
            !result.post_detection.has_technique("generic.ildasm"),
            "{}: suppress_ildasm should be removed",
            filename
        );
    }
    if expected.has_anti_dump {
        assert!(
            !result.post_detection.has_technique("confuserex.dump"),
            "{}: anti-dump should be removed",
            filename
        );
    }
    if expected.has_invalid_metadata {
        assert!(
            !result.post_detection.has_technique("confuserex.metadata"),
            "{}: invalid metadata should be repaired",
            filename
        );
    }
    if expected.has_anti_tamper {
        assert_eq!(
            result
                .post_detection
                .technique_evidence_count("confuserex.tamper"),
            0,
            "{}: encrypted methods should be decrypted",
            filename
        );
    }

    // Decryptor verification
    if expected.has_decryptors {
        if let Some(ref stats) = result.stats {
            assert!(
                stats.constants_folded > 0 || stats.strings_decrypted > 0,
                "{}: Expected decryption activity (constants={} strings={})",
                filename,
                stats.constants_folded,
                stats.strings_decrypted
            );
        }
    }

    // Control flow verification
    if expected.has_control_flow {
        if let Some(ref stats) = result.stats {
            assert!(
                stats.branches_simplified > 0,
                "{}: Expected branches to be simplified for control flow sample (got {})",
                filename,
                stats.branches_simplified
            );
        }
    }
}

sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    minimal => "mkaring_minimal.exe",
    normal => "mkaring_normal.exe",
    constants => "mkaring_constants.exe",
    controlflow => "mkaring_controlflow.exe",
    resources => "mkaring_resources.exe",
    maximum => "mkaring_maximum.exe",
    antitamper => "mkaring_antitamper.exe",
    constants_dyncyph => "mkaring_constants_dyncyph.exe",
    constants_cfg => "mkaring_constants_cfg.exe",
    controlflow_expression => "mkaring_controlflow_expression.exe",
    constants_x86 => "mkaring_constants_x86.exe",
    controlflow_x86 => "mkaring_controlflow_x86.exe",
    constants_x86_controlflow => "mkaring_constants_x86_controlflow.exe",
    constants_x86_controlflow_x86 => "mkaring_constants_x86_controlflow_x86.exe",
    antitamper_controlflow => "mkaring_antitamper_controlflow.exe",
    antitamper_constants_cfg => "mkaring_antitamper_constants_cfg.exe",
    constants_cfg_controlflow => "mkaring_constants_cfg_controlflow.exe",
    antidebug => "mkaring_antidebug.exe",
    antidump => "mkaring_antidump.exe",
    antiildasm => "mkaring_antiildasm.exe",
    harden => "mkaring_harden.exe",
    invalidmetadata => "mkaring_invalidmetadata.exe",
    invalidmetadata_antitamper => "mkaring_invalidmetadata_antitamper.exe",
    refproxy => "mkaring_refproxy.exe",
    rename => "mkaring_rename.exe",
    typescramble => "mkaring_typescramble.exe",
}

/// ConfuserEx-specific summary with detection and stats detail.
fn print_confuserex_summary(results: &[TestResult<ExpectedProtections>]) {
    print_summary(results, "CONFUSEREX", |result| {
        // Detection line (from engine findings)
        if !result.sample.is_original {
            let expected = &result.sample.expected_protections;
            let det = &result.detection;

            let mut detected = Vec::new();
            if expected.has_marker_attributes && det.has_technique("confuserex.marker") {
                detected.push("markers");
            }
            if expected.has_suppress_ildasm && det.has_technique("generic.ildasm") {
                detected.push("suppress");
            }
            if expected.has_decryptors && det.has_technique("confuserex.constants") {
                detected.push("decryptors");
            }
            if expected.has_anti_debug && det.has_technique("confuserex.debug") {
                detected.push("antidebug");
            }
            if expected.has_anti_tamper && det.has_technique("confuserex.tamper") {
                detected.push("antitamper");
            }
            if expected.has_resources && det.has_technique("confuserex.resources") {
                detected.push("resources");
            }
            if expected.has_reference_proxy && det.has_technique("confuserex.proxy") {
                detected.push("proxy");
            }

            if !detected.is_empty() {
                eprintln!(
                    "       Detected: {} [decryptors={} antidebug={} antitamper={} resources={} proxies={}]",
                    detected.join(" "),
                    det.technique_evidence_count("confuserex.constants"),
                    det.technique_evidence_count("confuserex.debug"),
                    det.technique_evidence_count("confuserex.tamper"),
                    det.technique_evidence_count("confuserex.resources"),
                    det.technique_evidence_count("confuserex.proxy"),
                );
            }
        }

        // Stats line
        if let Some(ref stats) = result.stats {
            eprintln!(
                "       Stats: transformed={} constants={} strings={} branches={} artifacts={}",
                stats.methods_transformed,
                stats.constants_folded,
                stats.strings_decrypted,
                stats.branches_simplified,
                stats.artifacts_removed
            );
        }

        // Removal line (re-detection on deobfuscated output)
        if !result.sample.is_original {
            let post = &result.post_detection;
            eprintln!(
                "       Removal: valid={} entry={} markers={} suppress={} decryptors={} proxies={} roundtrip={}",
                result.assembly_valid,
                result.has_valid_entry_point,
                post.has_technique("confuserex.marker"),
                post.has_technique("generic.ildasm"),
                post.technique_evidence_count("confuserex.constants")
                    + post.technique_evidence_count("generic.constants"),
                post.technique_evidence_count("confuserex.proxy"),
                result.roundtrip_ok
            );
        }
    });

    // Print aggregate stats
    let mut total_artifacts = 0;
    let mut total_constants = 0;
    let mut total_methods = 0;
    let mut total_branches = 0;
    for result in results {
        if let Some(ref stats) = result.stats {
            total_artifacts += stats.artifacts_removed;
            total_constants += stats.constants_folded;
            total_methods += stats.methods_transformed;
            total_branches += stats.branches_simplified;
        }
    }
    eprintln!("  Methods transformed: {}", total_methods);
    eprintln!("  Constants folded: {}", total_constants);
    eprintln!("  Branches simplified: {}", total_branches);
    eprintln!("  Artifacts removed: {}", total_artifacts);
    eprintln!("--------------------------------------------------------------------------------\n");
}

/// The names of an assembly's manifest resource rows, in table order - the
/// order `Assembly.GetManifestResourceNames` returns them in.
fn manifest_resource_order(assembly: &CilObject) -> Vec<String> {
    let (Some(tables), Some(strings)) = (assembly.tables(), assembly.strings()) else {
        return Vec::new();
    };
    let Some(table) = tables.table::<ManifestResourceRaw>() else {
        return Vec::new();
    };
    table
        .iter()
        .filter_map(Result::ok)
        .filter_map(|row| strings.get(row.name as usize).ok().map(str::to_string))
        .collect()
}

/// ConfuserEx's resource protection moves the application's resources into a
/// hidden assembly, leaving rows in the application's order that name them.
/// Restored, they take those rows' places in that order, not the hidden
/// assembly's: the program lists its resources and sees the difference.
#[test]
fn restored_resources_keep_the_applications_order() {
    let (output, _) = deobfuscated("packers/confuserex/1.6.0/mkaring_normal.exe")
        .as_ref()
        .unwrap();
    let original = CilObject::from_path(fixture("packers/confuserex/1.6.0/original.exe")).unwrap();

    let restored = manifest_resource_order(output);
    assert!(!restored.is_empty(), "the resources are restored");
    assert_eq!(restored, manifest_resource_order(&original));
}

/// ConfuserEx's type scrambler makes `BuildMessage` generic and calls `BuildMessage<string>`
/// through a MethodSpec. Cleanup keeps the generic method its callers still call, and each of
/// their MethodSpecs still instantiates it.
#[test]
fn a_generic_method_called_through_a_method_spec_survives_cleanup() {
    let (output, _) = deobfuscated("packers/confuserex/1.6.0/mkaring_typescramble.exe")
        .as_ref()
        .expect("deobfuscates");

    let method_named = |name: &str| {
        output
            .methods()
            .iter()
            .find(|entry| entry.value().name == name)
            .map(|entry| entry.value().token)
    };
    let build_message = method_named("BuildMessage").expect("BuildMessage survives");
    let resolver = output.resolver();
    for caller in ["SayHello", "SayGoodbye"] {
        let caller = method_named(caller).expect("caller survives");
        let instantiations: Vec<_> = output
            .method(&caller)
            .expect("caller")
            .instructions()
            .filter_map(|instr| instr.get_token_operand())
            .filter(|token| token.is_table(TableId::MethodSpec))
            .collect();
        assert!(
            !instantiations.is_empty(),
            "{caller} calls through a MethodSpec"
        );
        for token in instantiations {
            assert_eq!(
                resolver.resolve_method(token),
                Some(build_message),
                "{token}"
            );
        }
    }
}

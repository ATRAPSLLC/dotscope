#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! .NET Reactor deobfuscation integration tests.
//!
//! This test suite verifies deobfuscation of .NET Reactor-protected assemblies.
//!
//! # Test Structure
//!
//! Each sample is tested through a unified harness that verifies:
//! 1. Detection: Engine identifies .NET Reactor
//! 2. Deobfuscation: Engine processes successfully
//! 3. Removal: Re-detection on output confirms artifacts removed
//!
//! # Protection Stages (from NETReactorSlayer analysis)
//!
//! .NET Reactor applies protections in strict order. NecroBit (Stage 1) must be
//! reversed first as it encrypts all method bodies, making other stages inoperable.
//!
//! | Stage | Protection | Sample Coverage |
//! |-------|-----------|-----------------|
//! | 1 | NecroBit (method body encryption) | reactor_necrobit, reactor_full |
//! | 2 | Control flow (opaque constants) | reactor_controlflow, reactor_full |
//! | 3 | Anti-tamper/debug | reactor_antitamp, reactor_full |
//! | 6 | String encryption (AES) | reactor_strings, reactor_full |
//! | 7 | Resource encryption | reactor_resources, reactor_full |

#![cfg(feature = "deobfuscation")]

use dotscope::{
    assembly::Operand,
    metadata::validation::ValidationConfig,
    testkit::{
        deobfuscated, fixture,
        framework::{
            assert_common_requirements, print_summary, run_deobfuscation_test, ProcessMode,
            SampleSpec,
        },
        verification::StructuralConfig,
    },
    CilObject, Error,
};

const SAMPLES_DIR: &str = "packers/netreactor/7.5.0";

/// Expected protections in a .NET Reactor sample.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ReactorExpectedProtections {
    /// NecroBit method body encryption (Stage 1).
    has_necrobit: bool,
    /// String encryption via AES (Stage 6).
    has_string_encryption: bool,
    /// Control flow obfuscation via opaque field constants (Stage 2).
    has_control_flow: bool,
    /// Anti-tamper protection (Stage 3).
    has_anti_tamper: bool,
    /// Resource encryption (Stage 7).
    has_resource_encryption: bool,
    /// Symbol renaming/obfuscation (Stage 15).
    has_obfuscation: bool,
    /// SuppressIldasm attribute.
    has_suppress_ildasm: bool,
    /// Native x86 EXE stub.
    has_native_exe: bool,
    /// Anti strong name removal (Stage 12).
    has_anti_strong: bool,
    /// Pre-JIT native code conversion.
    has_prejit: bool,
    /// Output compression.
    has_compression: bool,
    /// Code virtualization (VM-protected methods via [Obfuscation] attribute).
    has_virtualization: bool,
}

/// All .NET Reactor samples with their expected characteristics.
///
/// Samples are generated with .NET Reactor 7.5.0 via Chocolatey.
/// Each variant exercises specific protections in isolation or combination.
fn all_samples() -> Vec<SampleSpec<ReactorExpectedProtections>> {
    vec![
        SampleSpec {
            filename: "original.exe",
            description: "Unprotected original (baseline)",
            expected_protections: ReactorExpectedProtections::default(),
            is_original: true,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit.exe",
            description: "NecroBit only (method body encryption)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_strings.exe",
            description: "String encryption only (AES)",
            expected_protections: ReactorExpectedProtections {
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_controlflow.exe",
            description: "Control flow obfuscation (level 5)",
            expected_protections: ReactorExpectedProtections {
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_controlflow_max.exe",
            description: "Control flow obfuscation (level 9, maximum)",
            expected_protections: ReactorExpectedProtections {
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_resources.exe",
            description: "Resource encryption only",
            expected_protections: ReactorExpectedProtections {
                has_resource_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_antitamp.exe",
            description: "Anti-tamper only",
            expected_protections: ReactorExpectedProtections {
                has_anti_tamper: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_obfuscation.exe",
            description: "Symbol renaming (non-public)",
            expected_protections: ReactorExpectedProtections {
                has_obfuscation: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_suppressildasm.exe",
            description: "SuppressIldasm only",
            expected_protections: ReactorExpectedProtections {
                has_suppress_ildasm: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit_strings.exe",
            description: "NecroBit + string encryption",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_necrobit_strings_cff.exe",
            description: "NecroBit + strings + control flow (level 5)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_antistrong.exe",
            description: "Anti strong name removal only",
            expected_protections: ReactorExpectedProtections {
                has_anti_strong: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_prejit.exe",
            description: "Pre-JIT native code conversion",
            expected_protections: ReactorExpectedProtections {
                has_prejit: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_compression.exe",
            description: "Output compression only",
            expected_protections: ReactorExpectedProtections {
                has_compression: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_full.exe",
            description: "Full protection (all enabled, CFF level 9)",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_anti_tamper: true,
                has_resource_encryption: true,
                has_obfuscation: true,
                has_suppress_ildasm: true,
                has_anti_strong: true,
                has_compression: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: true,
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_nativeexe.exe",
            description: "Native x86 EXE stub + NecroBit",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_native_exe: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // Native stub may alter execution model
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_virtualization.exe",
            description: "Code virtualization only (VM on 8 attributed methods)",
            expected_protections: ReactorExpectedProtections {
                has_virtualization: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // VM replaces method bodies with stubs
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
        SampleSpec {
            filename: "reactor_virtualization_full.exe",
            description: "Code virtualization + all protections",
            expected_protections: ReactorExpectedProtections {
                has_necrobit: true,
                has_string_encryption: true,
                has_control_flow: true,
                has_anti_tamper: true,
                has_resource_encryption: true,
                has_obfuscation: true,
                has_suppress_ildasm: true,
                has_anti_strong: true,
                has_compression: true,
                has_virtualization: true,
                ..Default::default()
            },
            is_original: false,
            check_semantic_preservation: false, // VM + full protection
            check_structural_match: false,
            structural_config: StructuralConfig::default(),
        },
    ]
}

/// Verify that .NET Reactor samples can be loaded and parsed.
///
/// This is the first-pass test: before detection techniques are implemented,
/// we verify that the PE/metadata parser handles .NET Reactor binaries correctly.
#[test]
fn test_netreactor_samples_loadable() {
    let samples = all_samples();
    let mut loaded = 0;

    for sample in &samples {
        let path = fixture(&format!("{}/{}", SAMPLES_DIR, sample.filename));

        // Use analysis-level validation: .NET Reactor samples (especially NecroBit)
        // have encrypted method bodies that fail strict owned-type validation.
        let result = CilObject::from_path_with_validation(&path, ValidationConfig::analysis());
        if sample.expected_protections.has_native_exe {
            // A native EXE carries the assembly encrypted in its resources, behind an x86
            // loader. Unwrapping it is not supported yet: the file is refused for what it is,
            // never loaded as something else.
            assert!(
                matches!(result, Err(Error::NotSupported)),
                "{}: a native EXE wrapper is refused as not supported, got {:?}",
                sample.filename,
                result.map(|asm| asm.methods().len())
            );
            continue;
        }
        match result {
            Ok(asm) => {
                loaded += 1;
                eprintln!(
                    "  [OK] {} — {} methods",
                    sample.filename,
                    asm.methods().len(),
                );
            }
            Err(e) => {
                panic!(
                    "{}: Failed to load .NET Reactor sample: {}",
                    sample.filename, e
                );
            }
        }
    }

    eprintln!("\n.NET Reactor: {loaded} loaded");
}

/// Runs one .NET Reactor sample through the deobfuscation pipeline and checks it against its
/// description in [`all_samples`].
fn check_sample(filename: &str) {
    let sample = all_samples()
        .into_iter()
        .find(|sample| sample.filename == filename)
        .unwrap_or_else(|| panic!("{filename} is not a .NET Reactor sample"));

    if sample.expected_protections.has_native_exe {
        // Not supported yet (see `test_netreactor_samples_loadable`): deobfuscation refuses
        // it rather than writing anything.
        assert!(
            matches!(
                deobfuscated(&format!("{SAMPLES_DIR}/{filename}")),
                Err(Error::NotSupported)
            ),
            "{filename}: a native EXE wrapper is refused as not supported",
        );
        return;
    }
    let result = &run_deobfuscation_test(&sample, SAMPLES_DIR, ProcessMode::Assembly);

    print_summary(std::slice::from_ref(result), "NET REACTOR", |result| {
        if !result.sample.is_original {
            eprintln!(
                "       Detection: confidence={:.0}% techniques=[{}]",
                result.detection.confidence() * 100.0,
                result.detection.technique_ids.join(", "),
            );
        }
    });

    if result.sample.is_original {
        assert!(
            result.detection.confidence() < 0.5,
            "{}: Unprotected original should not be detected as .NET Reactor (confidence: {:.0}%)",
            result.sample.filename,
            result.detection.confidence() * 100.0
        );
        return;
    }

    // The contract cleanup must satisfy is structural validity, not a survival ratio: an
    // assembly that fails validation has had something deleted out from under a reference
    // that still names it, which is over-cleanup by definition. A ratio only correlates with
    // that loosely, and says nothing about *which* methods went.
    assert_common_requirements(result);

    // Coarse backstop, and only that. Validity catches deletions that leave a dangling
    // reference; it cannot catch deleting code nothing statically references (a VM
    // handler reached only through computed dispatch, say). Those samples are kept for
    // later analysis, so losing their real code silently is the failure this guards.
    if result.sample.expected_protections.has_virtualization {
        assert!(
            result.methods_after * 2 > result.methods_before,
            "{}: cleanup removed {} of {} methods; the VM runtime is still \
             referenced by the virtualized method stubs and must survive",
            result.sample.filename,
            result.methods_before.saturating_sub(result.methods_after),
            result.methods_before
        );
    }
}

sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    necrobit => "reactor_necrobit.exe",
    strings => "reactor_strings.exe",
    controlflow => "reactor_controlflow.exe",
    controlflow_max => "reactor_controlflow_max.exe",
    resources => "reactor_resources.exe",
    antitamp => "reactor_antitamp.exe",
    obfuscation => "reactor_obfuscation.exe",
    suppressildasm => "reactor_suppressildasm.exe",
    necrobit_strings => "reactor_necrobit_strings.exe",
    necrobit_strings_cff => "reactor_necrobit_strings_cff.exe",
    antistrong => "reactor_antistrong.exe",
    prejit => "reactor_prejit.exe",
    compression => "reactor_compression.exe",
    full => "reactor_full.exe",
    nativeexe => "reactor_nativeexe.exe",
    virtualization => "reactor_virtualization.exe",
    virtualization_full => "reactor_virtualization_full.exe",
}

/// The methods whose code loads a string containing `needle`.
fn methods_loading(assembly: &CilObject, needle: &str) -> Vec<String> {
    let Some(strings) = assembly.userstrings() else {
        return Vec::new();
    };
    assembly
        .methods()
        .iter()
        .filter(|entry| {
            entry.value().instructions().any(|instruction| {
                instruction.mnemonic == "ldstr"
                    && matches!(instruction.operand, Operand::Token(token)
                        if strings
                            .get(token.row() as usize)
                            .is_ok_and(|text| text.to_string_lossy().contains(needle)))
            })
        })
        .map(|entry| entry.value().name.clone())
        .collect()
}

/// .NET Reactor's trial build puts a license check at the start of the
/// program's constructors, and it throws two weeks after the protection date.
/// Removing the protection removes the check and every call to it: surviving
/// code calling it is the reason the check has to go, not a reason to keep it.
#[test]
fn the_trial_check_is_removed_with_its_call_sites() {
    let (output, _) = deobfuscated(&format!("{SAMPLES_DIR}/reactor_strings.exe"))
        .as_ref()
        .unwrap();

    assert_eq!(
        methods_loading(output, "unregistered version"),
        Vec::<String>::new()
    );
}

/// With every protection on, .NET Reactor encrypts the resources and hides
/// how its runtime names them: the resource names are encrypted strings, its
/// helpers take `object` for every argument, anti-tamper guards the runtime,
/// and NecroBit encrypts the helpers themselves. The resources come back under
/// their own names and the encrypted containers go.
#[test]
fn fully_protected_resources_are_restored() {
    let (output, _) = deobfuscated(&format!("{SAMPLES_DIR}/reactor_full.exe"))
        .as_ref()
        .unwrap();

    let names: Vec<String> = output
        .resources()
        .iter()
        .map(|entry| entry.value().name.clone())
        .collect();
    assert_eq!(
        names,
        [
            "ConfuserExTestApp.Resources.greeting.txt",
            "ConfuserExTestApp.Resources.data.bin",
        ]
    );
    let greeting = output
        .resources()
        .get("ConfuserExTestApp.Resources.greeting.txt")
        .and_then(|resource| output.resources().get_data(&resource).map(<[u8]>::to_vec))
        .expect("the greeting's bytes");
    assert!(String::from_utf8_lossy(&greeting).contains("Hello from embedded resource!"));
}

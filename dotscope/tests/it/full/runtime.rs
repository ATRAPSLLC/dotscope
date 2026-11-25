#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Deobfuscated packer samples print what the unprotected original prints.
//!
//! Every sample of a packer family is deobfuscated in-process and written out. The output must
//! load under production validation, and where Mono's metadata verifier accepts the protected
//! sample it must accept the output too. Then the output and the family's unprotected
//! original run under Mono, with a timeout, and the output must print exactly what the
//! original prints.
//!
//! A sample can be declared otherwise, each with its reason, in [`expectation`]: its lines in
//! any order, a protection dotscope does not reverse (still deobfuscated, validated and
//! verified, but not run against the original), or a file the engine refuses. A declaration
//! naming a sample that does not exist fails the family, so the list cannot go stale.

#![cfg(feature = "deobfuscation")]

use std::{fs, path::PathBuf};

use dotscope::{
    metadata::validation::ValidationConfig,
    testkit::{
        deobfuscated, fixture,
        mono::{
            capabilities::Runtime,
            execution::{execute_with_runtime, ExecutionResult},
        },
        tools::{peverify_metadata_findings, require_tool, ToolKind},
    },
    CilObject, Error,
};

/// What a sample's deobfuscated output must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Print exactly what the unprotected original prints.
    Exact,
    /// Print the original's lines, in some order: the protection changed an order the program
    /// observes, and the original order is not in the protected file.
    LinesInAnyOrder(&'static str),
    /// A protection dotscope does not reverse: deobfuscated, validated and verified, but not
    /// run against the original.
    NotSupported(&'static str),
    /// A file the engine refuses as not supported.
    Refused(&'static str),
}

/// What `sample` of the family in `dir` is declared to do; anything not declared prints
/// exactly what the original prints.
fn expectation(dir: &str, sample: &str) -> Expect {
    match (dir, sample) {
        ("packers/jiejie/source", _) => Expect::LinesInAnyOrder(
            "JIEJIE.NET serves the resources from a table it fills in its own order, so the \
             protected program lists them in that order and the original's is not in the file",
        ),
        ("packers/confuserex/1.6.0", "mkaring_typescramble.exe") => {
            Expect::NotSupported("ConfuserEx's type scrambler is not reversed")
        }
        (
            "packers/netreactor/7.5.0",
            "reactor_virtualization.exe" | "reactor_virtualization_full.exe",
        ) => Expect::NotSupported(".NET Reactor's code virtualization is not reversed"),
        ("packers/netreactor/7.5.0", "reactor_nativeexe.exe") => {
            Expect::Refused("a native executable wrapping the protected assembly")
        }
        _ => Expect::Exact,
    }
}

/// Every sample name [`expectation`] declares, by family: each must exist.
const DECLARED: &[(&str, &str)] = &[
    ("packers/confuserex/1.6.0", "mkaring_typescramble.exe"),
    ("packers/netreactor/7.5.0", "reactor_virtualization.exe"),
    (
        "packers/netreactor/7.5.0",
        "reactor_virtualization_full.exe",
    ),
    ("packers/netreactor/7.5.0", "reactor_nativeexe.exe"),
];

/// What one sample's output did that it should not have, if anything.
fn check_sample(
    dir: &str,
    sample: &str,
    original: &ExecutionResult,
    scratch: &std::path::Path,
) -> Option<String> {
    let expect = expectation(dir, sample);
    let output = match (deobfuscated(&format!("{dir}/{sample}")), expect) {
        (Err(Error::NotSupported), Expect::Refused(_)) => return None,
        (Err(error), _) => return Some(format!("deobfuscation failed: {error}")),
        (Ok(_), Expect::Refused(reason)) => {
            return Some(format!("deobfuscated, though declared refused ({reason})"));
        }
        (Ok((output, _)), _) => output,
    };

    let bytes = output.file().data().to_vec();
    let path = scratch.join(sample);
    fs::write(&path, &bytes).unwrap();
    if let Err(error) = CilObject::from_mem_with_validation(bytes, ValidationConfig::production()) {
        return Some(format!("fails production validation: {error}"));
    }
    let protected = fixture(&format!("{dir}/{sample}"));
    let references = protected.parent().unwrap();
    let findings = peverify_metadata_findings(&path, references).unwrap();
    if !findings.is_empty()
        && peverify_metadata_findings(&protected, references)
            .unwrap()
            .is_empty()
    {
        return Some(format!(
            "peverify accepts the protected sample and refuses the output:\n{findings}"
        ));
    }

    if let Expect::NotSupported(_) = expect {
        return None;
    }
    let run = execute_with_runtime(Runtime::Mono, &path).expect("Mono starts");
    if !run.is_success() {
        return Some(format!("does not run: {}", run.error_summary()));
    }
    let same = match expect {
        Expect::LinesInAnyOrder(_) => {
            let sorted = |text: &str| {
                let mut lines: Vec<&str> = text.lines().collect();
                lines.sort_unstable();
                lines.join("\n")
            };
            sorted(&run.stdout) == sorted(&original.stdout)
        }
        _ => run.stdout == original.stdout,
    };
    if same {
        return None;
    }
    let (expected, actual): (Vec<&str>, Vec<&str>) = (
        original.stdout.lines().collect(),
        run.stdout.lines().collect(),
    );
    let at = expected
        .iter()
        .zip(&actual)
        .position(|(a, b)| a != b)
        .unwrap_or(expected.len().min(actual.len()));
    Some(format!(
        "prints {} lines where the original prints {}; line {at} reads {:?}, the original's {:?}",
        actual.len(),
        expected.len(),
        actual.get(at),
        expected.get(at)
    ))
}

/// Runs every sample of the family in `dir` (a fixture directory) against its original.
fn check_family(dir: &str) {
    if require_tool(ToolKind::Mono).is_none() || require_tool(ToolKind::Verifier).is_none() {
        return;
    }
    let original = execute_with_runtime(Runtime::Mono, &fixture(&format!("{dir}/original.exe")))
        .expect("Mono starts");
    assert!(
        original.is_success(),
        "{dir}/original.exe does not run: {}",
        original.error_summary()
    );

    let mut samples: Vec<String> = fs::read_dir(fixture(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".exe") && name != "original.exe")
        .collect();
    samples.sort();
    assert!(!samples.is_empty(), "{dir} has no protected samples");
    for (family, declared) in DECLARED {
        assert!(
            *family != dir || samples.iter().any(|sample| sample == declared),
            "{dir}/{declared} is declared but does not exist"
        );
    }

    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("runtime")
        .join(dir.replace('/', "_"));
    fs::create_dir_all(&scratch).unwrap();
    let failures: Vec<String> = samples
        .iter()
        .filter_map(|sample| {
            check_sample(dir, sample, &original, &scratch)
                .map(|failure| format!("{sample}: {failure}"))
        })
        .collect();
    for sample in &samples {
        if let Expect::NotSupported(reason) | Expect::Refused(reason) = expectation(dir, sample) {
            eprintln!("{dir}/{sample}: not compared, {reason}");
        }
    }
    assert!(failures.is_empty(), "{dir}:\n{}", failures.join("\n"));
}

#[test]
fn confuserex_samples_print_what_the_original_prints() {
    check_family("packers/confuserex/1.6.0");
}

#[test]
fn bitmono_0_39_0_samples_print_what_the_original_prints() {
    check_family("packers/bitmono/0.39.0");
}

#[test]
fn bitmono_0_45_0_samples_print_what_the_original_prints() {
    check_family("packers/bitmono/0.45.0");
}

#[test]
fn obfuscar_samples_print_what_the_original_prints() {
    check_family("packers/obfuscar/2.2.50");
}

#[test]
fn jiejie_samples_print_what_the_original_prints() {
    check_family("packers/jiejie/source");
}

#[test]
fn netreactor_samples_print_what_the_original_prints() {
    check_family("packers/netreactor/7.5.0");
}

//! End-to-end deobfuscation benchmarks.
//!
//! Measures the full deobfuscation pipeline (detection -> emulation-driven
//! decryption -> SSA passes -> cleanup -> rewrite) on protected samples.
//!
//! The ConfuserEx samples are the primary workload: they exercise the CIL
//! emulation layer heavily via constant/string decryptor execution and
//! anti-tamper unpacking, which makes this the best proxy for emulation
//! throughput in a realistic pipeline.
//!
//! Run with:
//! ```sh
//! cargo bench --bench deobfuscation --features deobfuscation
//! ```

#![cfg(feature = "deobfuscation")]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dotscope::{
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    testkit::fixture,
};

const CONFUSEREX_DIR: &str = "packers/confuserex/1.6.0";
const NETREACTOR_DIR: &str = "packers/netreactor/7.5.0";

/// NetReactor samples, which lean much harder on the CIL emulation layer than
/// ConfuserEx does — NecroBit method-body decryption and string decryption both
/// run large amounts of emulated CIL.
const NETREACTOR_SAMPLES: &[(&str, &str)] = &[
    // String encryption only — emulation-dominated.
    ("reactor_strings.exe", "strings"),
    // NecroBit: encrypted method bodies recovered via emulation.
    ("reactor_necrobit.exe", "necrobit"),
    // NecroBit + strings + control flow: the heaviest emulation workload.
    ("reactor_necrobit_strings_cff.exe", "necrobit_strings_cff"),
    // Everything on.
    ("reactor_full.exe", "full"),
];

/// Samples chosen to isolate individual protection costs plus the combined worst case.
///
/// Each entry is `(filename, label)`. The protections named in the filename map
/// directly onto pipeline stages, so a regression in one stage shows up as a
/// regression in the samples that use it.
const CONFUSEREX_SAMPLES: &[(&str, &str)] = &[
    // Baseline: marker attributes only. Measures fixed pipeline overhead
    // (load, detect, rewrite) with essentially no real work.
    ("mkaring_minimal.exe", "minimal"),
    // Constant/string decryption — the heaviest pure-emulation workload.
    ("mkaring_constants.exe", "constants"),
    // Control-flow flattening — the heaviest pure-SSA workload.
    ("mkaring_controlflow.exe", "controlflow"),
    // Anti-tamper — emulation-driven method body decryption.
    ("mkaring_antitamper.exe", "antitamper"),
    // Combined constants + CFG + control flow.
    ("mkaring_constants_cfg_controlflow.exe", "constants_cfg_cf"),
    // Everything on. The realistic worst case and the headline number.
    ("mkaring_maximum.exe", "maximum"),
];

/// Benchmarks the full `process_file` pipeline across ConfuserEx samples.
fn bench_confuserex(c: &mut Criterion) {
    let mut group = c.benchmark_group("confuserex_deobfuscation");

    // Deobfuscation runs are measured in seconds, not microseconds. Keep the
    // sample count low enough that the suite finishes in reasonable time while
    // still giving criterion enough data for a stable estimate.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(3));

    for (filename, label) in CONFUSEREX_SAMPLES {
        let path = fixture(&format!("{CONFUSEREX_DIR}/{filename}"));

        group.bench_with_input(BenchmarkId::from_parameter(label), &path, |b, path| {
            b.iter(|| {
                let engine = DeobfuscationEngine::new(EngineConfig::default());
                // A sample that fails part-way would time as a speed-up: it must succeed
                let result = engine.process_file(black_box(path));
                black_box(result.expect("the sample deobfuscates"))
            });
        });
    }

    group.finish();
}

/// Benchmarks the full `process_file` pipeline across NetReactor samples.
fn bench_netreactor(c: &mut Criterion) {
    let mut group = c.benchmark_group("netreactor_deobfuscation");

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(3));

    for (filename, label) in NETREACTOR_SAMPLES {
        let path = fixture(&format!("{NETREACTOR_DIR}/{filename}"));

        group.bench_with_input(BenchmarkId::from_parameter(label), &path, |b, path| {
            b.iter(|| {
                let engine = DeobfuscationEngine::new(EngineConfig::default());
                let result = engine.process_file(black_box(path));
                black_box(result.expect("the sample deobfuscates"))
            });
        });
    }

    group.finish();
}

/// Benchmarks detection only, to separate detection cost from transformation cost.
///
/// Detection walks every method and runs the SSA-based pattern matchers, so it
/// is a useful control: if `process_file` regresses but this does not, the
/// regression is in the transformation/emulation stages.
fn bench_detection_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("confuserex_detection");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    for (filename, label) in CONFUSEREX_SAMPLES {
        let path = fixture(&format!("{CONFUSEREX_DIR}/{filename}"));

        // Load once outside the measured closure — we are timing detection,
        // not PE parsing.
        let assembly = match dotscope::CilObject::from_path(&path) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("skipping unloadable sample {}: {e}", path.display());
                continue;
            }
        };

        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &assembly,
            |b, assembly| {
                let engine = DeobfuscationEngine::default();
                b.iter(|| black_box(engine.detect(black_box(assembly))));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_confuserex,
    bench_netreactor,
    bench_detection_only
);
criterion_main!(benches);

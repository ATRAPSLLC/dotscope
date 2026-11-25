//! Benchmarks for owned vs. zero-copy parsing of standalone `.resources` files.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::{fs, hint::black_box};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::{
    metadata::resources::{parse_dotnet_resource, parse_dotnet_resource_ref},
    testkit::fixture,
};

/// Benchmark parsing from standalone .resources file (WindowsBase resources)
///
/// This benchmark compares the performance of owned vs zero-copy resource parsing
/// using a real .NET resources file extracted from WindowsBase.dll.
fn bench_parse_resources_file(c: &mut Criterion) {
    let path = fixture("WB_FxResources.WindowsBase.SR.resources.bin");

    let Ok(data) = fs::read(&path) else {
        eprintln!(
            "Skipping resources benchmark: failed to read {}",
            path.display()
        );
        return;
    };
    let file_size = data.len();

    println!(
        "Benchmarking resource file: {} bytes ({:.2} KB)",
        file_size,
        file_size as f64 / 1024.0
    );

    // Benchmark owned variant (allocates copies of strings and byte arrays)
    let mut group = c.benchmark_group("resources_owned");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse_dotnet_resource", |b| {
        b.iter(|| {
            let parsed = parse_dotnet_resource(black_box(&data));
            black_box(parsed.expect("the benchmarked work succeeds on its input"));
        });
    });
    group.finish();

    // Benchmark zero-copy variant (borrows strings and byte arrays from source)
    let mut group = c.benchmark_group("resources_zerocopy");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse_dotnet_resource_ref", |b| {
        b.iter(|| {
            let parsed = parse_dotnet_resource_ref(black_box(&data));
            black_box(parsed.expect("the benchmarked work succeeds on its input"));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_parse_resources_file);
criterion_main!(benches);

//! Benchmarks for COR20 (CLI) header parsing.
//!
//! The CLI header is a fixed 72-byte structure that contains essential
//! metadata about .NET assemblies including runtime version, metadata
//! location, and runtime flags.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::{fs, hint::black_box};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::{metadata::cor20header::Cor20Header, testkit::fixture};

/// Benchmark parsing the CLI header from a real assembly.
///
/// The CLI header is exactly 72 bytes and is parsed frequently during
/// assembly loading. This benchmark measures the parsing overhead.
fn bench_cor20_header_parse(c: &mut Criterion) {
    let path = fixture("WB_COR20_HEADER.bin");

    let Ok(data) = fs::read(&path) else {
        eprintln!(
            "Skipping cor20 benchmark: failed to read {}",
            path.display()
        );
        return;
    };
    let file_size = data.len();

    if file_size != 72 {
        eprintln!("COR20 header must be exactly 72 bytes, got {file_size}; skipping");
        return;
    }

    let mut group = c.benchmark_group("cor20_header");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(
                Cor20Header::read(black_box(&data))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
    group.finish();
}
criterion_group!(benches, bench_cor20_header_parse,);
criterion_main!(benches);

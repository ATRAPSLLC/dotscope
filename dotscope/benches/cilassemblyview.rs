//! Benchmarks for [`CilAssemblyView`] loading with and without metadata validation.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{testkit::fixture, CilAssemblyView, ValidationConfig};

/// Benchmark loading a `CilAssemblyView` with and without metadata validation.
pub fn criterion_benchmark(c: &mut Criterion) {
    let path = fixture("WindowsBase.dll");
    c.bench_function("bench_cilassemblyview", |b| {
        b.iter(|| {
            black_box(
                CilAssemblyView::from_path(&path)
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    c.bench_function("bench_cilassemblyview_validation", |b| {
        b.iter(|| {
            black_box(
                CilAssemblyView::from_path_with_validation(&path, ValidationConfig::strict())
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

//! Benchmarks for [`CilObject`] loading with and without metadata validation.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{metadata::cilobject::CilObject, testkit::fixture, ValidationConfig};

/// Benchmark loading a `CilObject` with and without metadata validation.
pub fn criterion_benchmark(c: &mut Criterion) {
    let path = fixture("mono_4.8/mscorlib.dll");
    c.bench_function("bench_cilobject", |b| {
        b.iter(|| {
            black_box(
                CilObject::from_path_with_validation(&path, ValidationConfig::disabled())
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    c.bench_function("bench_cilobject_validation", |b| {
        b.iter(|| {
            black_box(
                CilObject::from_path_with_validation(&path, ValidationConfig::strict())
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

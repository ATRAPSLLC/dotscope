//! Benchmarks for method body parsing, header and exception sections then the code decoded
//! into blocks, as a load reads a body.
//!
//! Tests parsing performance for various method body formats:
//! - Tiny headers (1 byte, up to 63 bytes code)
//! - Fat headers (12+ bytes, complex methods)
//! - Exception handlers (try/catch/finally blocks)

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::{
    assembly::decode_blocks_with_handlers, metadata::method::MethodBody, testkit::fixture_bytes,
};

/// Run a method-body parsing benchmark over fixture `sample`.
fn bench_method_file(c: &mut Criterion, group_name: &str, sample: &str) {
    let data = fixture_bytes(sample);
    let file_size = data.len();

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let body = MethodBody::from(black_box(data)).expect("the body parses");
            let end = body
                .size_header
                .checked_add(body.size_code)
                .expect("the body's size fits");
            let code = data
                .get(body.size_header..end)
                .expect("the body's code is in the file");
            black_box(
                decode_blocks_with_handlers(
                    code,
                    0,
                    0x2000,
                    Some(code.len()),
                    &body.exception_handlers,
                )
                .expect("the code decodes"),
            );
        });
    });
    group.finish();
}

/// Benchmark parsing a tiny method header.
///
/// Tiny headers are 1 byte and can represent methods up to 63 bytes of IL code.
/// This is the fastest path for simple methods.
fn bench_parse_method_tiny(c: &mut Criterion) {
    bench_method_file(c, "method_body_tiny", "WB_METHOD_TINY_0600032D.bin");
}

/// Benchmark parsing a fat method header.
///
/// Fat headers are 12+ bytes and support complex methods with local variables,
/// exception handlers, and large code sizes.
fn bench_parse_method_fat(c: &mut Criterion) {
    bench_method_file(c, "method_body_fat", "WB_METHOD_FAT_0600033E.bin");
}

/// Benchmark parsing a method with a single exception handler.
///
/// Tests the overhead of parsing exception handling sections.
fn bench_parse_method_with_exception(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_single",
        "WB_METHOD_FAT_EXCEPTION_06000341.bin",
    );
}

/// Benchmark parsing a method with local variables and exception handlers.
///
/// Tests a more realistic complex method scenario.
fn bench_parse_method_with_locals_and_exception(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_with_locals",
        "WB_METHOD_FAT_EXCEPTION_N1_2LOCALS_060001AA.bin",
    );
}

/// Benchmark parsing a method with multiple exception handlers.
///
/// Tests parsing of complex exception handling with multiple try/catch/finally blocks.
fn bench_parse_method_multiple_exceptions(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_multiple",
        "WB_METHOD_FAT_EXCEPTION_N2_06000421.bin",
    );
}

/// Benchmark parsing another complex method with nested exception handlers.
fn bench_parse_method_complex_exceptions(c: &mut Criterion) {
    bench_method_file(
        c,
        "method_body_exception_complex",
        "WB_METHOD_FAT_EXCEPTION_N2_06000D54.bin",
    );
}

criterion_group!(
    benches,
    bench_parse_method_tiny,
    bench_parse_method_fat,
    bench_parse_method_with_exception,
    bench_parse_method_with_locals_and_exception,
    bench_parse_method_multiple_exceptions,
    bench_parse_method_complex_exceptions,
);
criterion_main!(benches);

//! Benchmarks for metadata stream parsing.
//!
//! Tests parsing performance for .NET metadata heaps:
//! - #Strings heap (UTF-8 identifiers)
//! - #Blob heap (binary data, signatures)
//! - #US heap (UTF-16 user strings)
//! - #GUID heap (16-byte GUIDs)
//!
//! Includes both construction/parsing and access pattern benchmarks.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use dotscope::{
    metadata::streams::{Blob, Guid, Strings, UserStrings},
    testkit::fixture_bytes,
};

/// Benchmark parsing the complete #Strings heap.
fn bench_strings_heap_parse(c: &mut Criterion) {
    let data = fixture_bytes("WB_STRINGS.bin");
    let file_size = data.len();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(
                Strings::from(black_box(data)).expect("the benchmarked work succeeds on its input"),
            );
        });
    });
    group.finish();
}

/// Benchmark iterating over all strings in the heap.
fn bench_strings_heap_iterate(c: &mut Criterion) {
    let data = fixture_bytes("WB_STRINGS.bin");
    let Ok(strings) = Strings::from(data) else {
        eprintln!("Skipping iterate: failed to parse strings heap");
        return;
    };

    let string_count = strings.iter().count();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Elements(string_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&strings).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to strings by offset.
fn bench_strings_heap_random_access(c: &mut Criterion) {
    let data = fixture_bytes("WB_STRINGS.bin");
    let Ok(strings) = Strings::from(data) else {
        eprintln!("Skipping random_access: failed to parse strings heap");
        return;
    };

    let offsets: Vec<usize> = strings.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("strings_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                black_box(
                    strings
                        .get(offset)
                        .expect("the benchmarked work succeeds on its input"),
                );
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #Blob heap.
fn bench_blob_heap_parse(c: &mut Criterion) {
    let data = fixture_bytes("WB_BLOB.bin");
    let file_size = data.len();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(
                Blob::from(black_box(data)).expect("the benchmarked work succeeds on its input"),
            );
        });
    });
    group.finish();
}

/// Benchmark iterating over all blobs in the heap.
fn bench_blob_heap_iterate(c: &mut Criterion) {
    let data = fixture_bytes("WB_BLOB.bin");
    let Ok(blob) = Blob::from(data) else {
        eprintln!("Skipping iterate: failed to parse blob heap");
        return;
    };

    let blob_count = blob.iter().count();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Elements(blob_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&blob).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to blobs by offset.
fn bench_blob_heap_random_access(c: &mut Criterion) {
    let data = fixture_bytes("WB_BLOB.bin");
    let Ok(blob) = Blob::from(data) else {
        eprintln!("Skipping random_access: failed to parse blob heap");
        return;
    };

    let offsets: Vec<usize> = blob.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("blob_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                black_box(
                    blob.get(offset)
                        .expect("the benchmarked work succeeds on its input"),
                );
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #US (User Strings) heap.
fn bench_userstrings_heap_parse(c: &mut Criterion) {
    let data = fixture_bytes("WB_US.bin");
    let file_size = data.len();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(
                UserStrings::from(black_box(data))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
    group.finish();
}

/// Benchmark iterating over all user strings in the heap.
fn bench_userstrings_heap_iterate(c: &mut Criterion) {
    let data = fixture_bytes("WB_US.bin");
    let Ok(us) = UserStrings::from(data) else {
        eprintln!("Skipping iterate: failed to parse user strings heap");
        return;
    };

    let string_count = us.iter().count();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Elements(string_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&us).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to user strings by offset.
fn bench_userstrings_heap_random_access(c: &mut Criterion) {
    let data = fixture_bytes("WB_US.bin");
    let Ok(us) = UserStrings::from(data) else {
        eprintln!("Skipping random_access: failed to parse user strings heap");
        return;
    };

    let offsets: Vec<usize> = us.iter().map(|(offset, _)| offset).collect();

    let mut group = c.benchmark_group("userstrings_heap");
    group.throughput(Throughput::Elements(offsets.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &offset in black_box(&offsets) {
                black_box(
                    us.get(offset)
                        .expect("the benchmarked work succeeds on its input"),
                );
            }
        });
    });
    group.finish();
}

/// Benchmark parsing the complete #GUID heap.
fn bench_guid_heap_parse(c: &mut Criterion) {
    let data = fixture_bytes("WB_GUID.bin");
    let file_size = data.len();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            black_box(
                Guid::from(black_box(data)).expect("the benchmarked work succeeds on its input"),
            );
        });
    });
    group.finish();
}

/// Benchmark iterating over all GUIDs in the heap.
fn bench_guid_heap_iterate(c: &mut Criterion) {
    let data = fixture_bytes("WB_GUID.bin");
    let Ok(guid) = Guid::from(data) else {
        eprintln!("Skipping iterate: failed to parse GUID heap");
        return;
    };

    let guid_count = guid.iter().count();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Elements(guid_count as u64));
    group.bench_function("iterate_all", |b| {
        b.iter(|| {
            let count = black_box(&guid).iter().count();
            black_box(count)
        });
    });
    group.finish();
}

/// Benchmark random access to GUIDs by index (1-based as per ECMA-335).
fn bench_guid_heap_random_access(c: &mut Criterion) {
    let data = fixture_bytes("WB_GUID.bin");
    let Ok(guid) = Guid::from(data) else {
        eprintln!("Skipping random_access: failed to parse GUID heap");
        return;
    };

    let indices: Vec<usize> = guid.iter().map(|(idx, _)| idx).collect();

    let mut group = c.benchmark_group("guid_heap");
    group.throughput(Throughput::Elements(indices.len() as u64));
    group.bench_function("random_access", |b| {
        b.iter(|| {
            for &index in black_box(&indices) {
                black_box(
                    guid.get(index)
                        .expect("the benchmarked work succeeds on its input"),
                );
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    // Strings heap
    bench_strings_heap_parse,
    bench_strings_heap_iterate,
    bench_strings_heap_random_access,
    // Blob heap
    bench_blob_heap_parse,
    bench_blob_heap_iterate,
    bench_blob_heap_random_access,
    // User strings heap
    bench_userstrings_heap_parse,
    bench_userstrings_heap_iterate,
    bench_userstrings_heap_random_access,
    // GUID heap
    bench_guid_heap_parse,
    bench_guid_heap_iterate,
    bench_guid_heap_random_access,
);
criterion_main!(benches);

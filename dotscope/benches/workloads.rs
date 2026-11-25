//! Benchmarks of the crate's workloads, each with what it allocates.
//!
//! Every workload is timed by criterion and measured once by the counting allocator
//! (`common/alloc.rs`): its peak live bytes, its allocation count and the bytes it allocates,
//! written to `target/bench-mem/<workload>.json`. The allocator is installed for the whole
//! binary, so the times include its counting (a few atomic operations per allocation), the
//! same in every run they are compared across. Every workload asserts that it succeeds: one
//! that failed part-way would time as a speed-up.
//!
//! - `writer`: an unmodified assembly written back (WindowsBase, mono's mscorlib), one with a
//!   thousand methods added, and one with ten thousand user strings added.
//! - `ssa_lift`: every method of WindowsBase lifted to SSA.
//! - `passes`: the deobfuscation engine's whole pipeline over an unprotected program.
//! - `codegen`: every lifted method of `crafted_2.exe` generated back to CIL.
//! - `emulator`: an arithmetic loop (instructions per second), a decryptor-shaped loop over a
//!   string with BCL calls, and a process forked to run one small call.
//! - `project_loader`: mono's `System.dll` loaded as a project with mscorlib.
//! - `callgraph`: WindowsBase's call graph.
//! - `disasm`: WindowsBase written out as an IL listing.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used, clippy::panic)]

#[path = "common/alloc.rs"]
mod alloc;

use std::{fs, hint::black_box, path::PathBuf, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use dotscope::{
    analysis::CallGraph,
    compiler::SsaCodeGenerator,
    emulation::{EmValue, EmulationOutcome, EmulationProcess},
    formatting::{FormatterOptions, IlFormatter},
    metadata::{signatures::TypeSignature, token::Token},
    project::ProjectLoader,
    testkit::{emulation::process_builder, engine, fixture, fixture_bytes},
    CilAssembly, CilAssemblyView, CilObject, MethodBuilder,
};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

/// The unprotected program the packer samples are made from.
const TEST_APP: &str = "packers/confuserex/1.6.0/original.exe";

/// Measures `work` once with the counting allocator and writes what it allocated to
/// `target/bench-mem/<name>.json`.
fn report<R>(name: &str, work: impl FnOnce() -> R) {
    let (result, stats) = alloc::measure(work);
    drop(black_box(result));
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/bench-mem");
    fs::create_dir_all(&dir).expect("the bench-mem directory");
    fs::write(
        dir.join(format!("{name}.json")),
        format!(
            "{{\"peak_bytes\": {}, \"allocations\": {}, \"allocated_bytes\": {}}}\n",
            stats.peak_bytes, stats.allocations, stats.allocated_bytes
        ),
    )
    .expect("the bench-mem report");
}

fn load(name: &str) -> CilObject {
    CilObject::from_mem(fixture_bytes(name).to_vec()).expect("the fixture loads")
}

fn write_back(bytes: &[u8]) -> Vec<u8> {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).expect("the assembly reads");
    CilAssembly::new(view)
        .to_memory()
        .expect("the assembly writes")
}

fn with_methods(bytes: &[u8], count: usize) -> Vec<u8> {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).expect("the assembly reads");
    let mut assembly = CilAssembly::new(view);
    for index in 0..count {
        MethodBuilder::new(&format!("Added{index}"))
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .expect("the method builds");
    }
    assembly.to_memory().expect("the assembly writes")
}

fn with_user_strings(bytes: &[u8], count: usize) -> Vec<u8> {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).expect("the assembly reads");
    let mut assembly = CilAssembly::new(view);
    for index in 0..count {
        assembly
            .userstring_add(&format!(
                "user string number {index}, padded to a realistic length"
            ))
            .expect("the string is added");
    }
    assembly.to_memory().expect("the assembly writes")
}

fn bench_writer(c: &mut Criterion) {
    let mut group = c.benchmark_group("writer");
    group.sample_size(10);
    for (label, name) in [
        ("windowsbase", "WindowsBase.dll"),
        ("mscorlib", "mono_4.8/mscorlib.dll"),
    ] {
        let bytes = fixture_bytes(name);
        report(&format!("writer_{label}"), || write_back(bytes));
        group.bench_function(label, |b| {
            b.iter(|| black_box(write_back(black_box(bytes))))
        });
    }
    let bytes = fixture_bytes("crafted_2.exe");
    report("writer_1k_methods", || with_methods(bytes, 1000));
    group.bench_function("1k_methods", |b| {
        b.iter(|| black_box(with_methods(black_box(bytes), 1000)));
    });
    report("writer_10k_user_strings", || {
        with_user_strings(bytes, 10_000)
    });
    group.bench_function("10k_user_strings", |b| {
        b.iter(|| black_box(with_user_strings(black_box(bytes), 10_000)));
    });
    group.finish();
}

fn lift_all(assembly: &CilObject) -> usize {
    let lifted = assembly
        .methods()
        .iter()
        .filter(|entry| entry.value().body.get().is_some())
        .filter(|entry| entry.value().ssa(assembly).is_ok())
        .count();
    assert!(lifted > 0, "no method lifted");
    lifted
}

fn bench_ssa_lift(c: &mut Criterion) {
    let assembly = load("WindowsBase.dll");
    report("ssa_lift", || lift_all(&assembly));
    let mut group = c.benchmark_group("ssa_lift");
    group.sample_size(10);
    group.bench_function("windowsbase", |b| b.iter(|| black_box(lift_all(&assembly))));
    group.finish();
}

fn deobfuscate(bytes: &[u8]) -> CilObject {
    engine()
        .process_bytes(bytes.to_vec())
        .expect("the program deobfuscates")
        .0
}

fn bench_passes(c: &mut Criterion) {
    let bytes = fixture_bytes(TEST_APP);
    report("passes", || deobfuscate(bytes));
    let mut group = c.benchmark_group("passes");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.bench_function("test_app", |b| {
        b.iter(|| black_box(deobfuscate(black_box(bytes))))
    });
    group.finish();
}

fn generate_all(lifted: &[dotscope::analysis::SsaFunction], bytes: &[u8]) -> usize {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).expect("the assembly reads");
    let mut assembly = CilAssembly::new(view);
    let mut generator = SsaCodeGenerator::new();
    let generated = lifted
        .iter()
        .filter(|ssa| generator.compile(ssa, &mut assembly).is_ok())
        .count();
    assert!(generated > 0, "no method was generated");
    generated
}

fn bench_codegen(c: &mut Criterion) {
    let bytes = fixture_bytes("crafted_2.exe");
    let assembly = load("crafted_2.exe");
    let lifted: Vec<_> = assembly
        .methods()
        .iter()
        .filter(|entry| entry.value().body.get().is_some())
        .filter_map(|entry| entry.value().ssa(&assembly).ok())
        .collect();
    report("codegen", || generate_all(&lifted, bytes));
    let mut group = c.benchmark_group("codegen");
    group.sample_size(20);
    group.bench_function("crafted_2", |b| {
        b.iter(|| black_box(generate_all(&lifted, bytes)))
    });
    group.finish();
}

/// The token of TestApp's method `name`.
fn method(assembly: &CilObject, name: &str) -> Token {
    *assembly
        .methods()
        .iter()
        .find(|entry| entry.value().name == name)
        .unwrap_or_else(|| panic!("TestApp has no method {name}"))
        .key()
}

/// The instructions a completed emulation ran.
fn completed(outcome: EmulationOutcome) -> u64 {
    match outcome {
        EmulationOutcome::Completed { instructions, .. } => instructions,
        other => panic!("the emulation did not complete: {other:?}"),
    }
}

fn bench_emulator(c: &mut Criterion) {
    let assembly = load(TEST_APP);
    let (fibonacci, xor, add) = (
        method(&assembly, "Fibonacci"),
        method(&assembly, "XorEncrypt"),
        method(&assembly, "Add"),
    );
    let process: EmulationProcess = process_builder()
        .assembly(assembly)
        .with_max_instructions(100_000_000)
        .build()
        .expect("the process builds");
    let fibonacci_args = || vec![EmValue::Null, EmValue::I32(10_000)];
    let xor_args = |process: &EmulationProcess| {
        let text = process
            .address_space()
            .alloc_string(&"decryptor-shaped input ".repeat(64))
            .expect("the string is allocated");
        vec![EmValue::Null, EmValue::ObjectRef(text), EmValue::I32(0x5A)]
    };

    let run = |token: Token, args: Vec<EmValue>| {
        completed(
            process
                .execute_method(token, args)
                .expect("the method runs"),
        )
    };
    let instructions = run(fibonacci, fibonacci_args());
    report("emulator_arithmetic_loop", || {
        run(fibonacci, fibonacci_args())
    });
    report("emulator_decryptor_loop", || run(xor, xor_args(&process)));
    report("emulator_fork_and_call", || {
        let fork = process.fork().expect("the process forks");
        completed(
            fork.execute_method(add, vec![EmValue::Null, EmValue::I32(2), EmValue::I32(3)])
                .expect("the call runs"),
        )
    });

    let mut group = c.benchmark_group("emulator");
    group.sample_size(20);
    group.throughput(Throughput::Elements(instructions));
    group.bench_function("arithmetic_loop", |b| {
        b.iter(|| black_box(run(fibonacci, fibonacci_args())));
    });
    group.throughput(Throughput::Elements(1));
    group.bench_function("decryptor_loop", |b| {
        b.iter_batched(
            || xor_args(&process),
            |args| black_box(run(xor, args)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("fork_and_call", |b| {
        b.iter(|| {
            let fork = process.fork().expect("the process forks");
            black_box(completed(
                fork.execute_method(add, vec![EmValue::Null, EmValue::I32(2), EmValue::I32(3)])
                    .expect("the call runs"),
            ))
        });
    });
    group.finish();
}

fn load_project() -> usize {
    let project = ProjectLoader::new()
        .primary_file(fixture("mono_4.8/System.dll"))
        .expect("the primary file")
        .with_dependency(fixture("mono_4.8/mscorlib.dll"))
        .expect("the dependency")
        .auto_discover(false)
        .build()
        .expect("the project loads");
    assert!(
        project.success_count() > 1,
        "the project loaded {} assemblies",
        project.success_count()
    );
    project.success_count()
}

fn bench_project_loader(c: &mut Criterion) {
    report("project_loader", load_project);
    let mut group = c.benchmark_group("project_loader");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.bench_function("mono_system", |b| b.iter(|| black_box(load_project())));
    group.finish();
}

fn bench_callgraph(c: &mut Criterion) {
    let assembly = load("WindowsBase.dll");
    let build = || CallGraph::build(&assembly).expect("the call graph builds");
    report("callgraph", build);
    let mut group = c.benchmark_group("callgraph");
    group.sample_size(10);
    group.bench_function("windowsbase", |b| b.iter(|| black_box(build())));
    group.finish();
}

fn bench_disasm(c: &mut Criterion) {
    let assembly = load("WindowsBase.dll");
    let formatter = IlFormatter::new(FormatterOptions::default());
    let listing = || {
        let mut out = Vec::new();
        formatter
            .format_assembly(&mut out, &assembly)
            .expect("the listing is written");
        assert!(!out.is_empty(), "the listing is empty");
        out
    };
    report("disasm", listing);
    let mut group = c.benchmark_group("disasm");
    group.sample_size(10);
    group.bench_function("windowsbase", |b| b.iter(|| black_box(listing())));
    group.finish();
}

criterion_group!(
    benches,
    bench_writer,
    bench_ssa_lift,
    bench_passes,
    bench_codegen,
    bench_emulator,
    bench_project_loader,
    bench_callgraph,
    bench_disasm
);
criterion_main!(benches);

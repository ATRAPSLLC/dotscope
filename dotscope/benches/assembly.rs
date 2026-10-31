//! Benchmarks for CIL assembly and disassembly.
//!
//! Exercises both the fluent [`InstructionAssembler`] API and the lower-level
//! [`InstructionEncoder`] / [`decode_stream`] paths, plus assemble-disassemble
//! roundtrips.

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::{
    assembly::{decode_stream, InstructionAssembler, InstructionEncoder},
    metadata::token::Token,
    Result,
};

fn assemble_simple() -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_1()?.ldarg_2()?.add()?.ret()?;
    asm.finish()
}

fn assemble_complex() -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?
        .stloc_0()?
        .br("loop_condition")?
        .label("loop_start")?
        .ldarg_0()?
        .ldloc_0()?
        .ldarg_1()?
        .stelem_i4()?
        .ldloc_0()?
        .ldc_i4_1()?
        .add()?
        .stloc_0()?
        .label("loop_condition")?
        .ldloc_0()?
        .ldc_i4_const(10)?
        .clt()?
        .brtrue("loop_start")?
        .ret()?;
    asm.finish()
}

fn assemble_object(
    field_token: Token,
    method_token: Token,
) -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    asm.ldarg_0()?
        .ldfld(field_token)?
        .ldnull()?
        .ceq()?
        .brfalse("not_null")?
        .ldarg_0()?
        .newobj(method_token)?
        .stfld(field_token)?
        .label("not_null")?
        .ldarg_0()?
        .ldfld(field_token)?
        .callvirt(method_token)?
        .ret()?;
    asm.finish()
}

fn assemble_with_optimizations() -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_const(0)?
        .ldc_i4_const(1)?
        .ldc_i4_const(127)?
        .ldc_i4_const(1000)?
        .add()?
        .add()?
        .add()?
        .ret()?;
    asm.finish()
}

fn assemble_manual_selection() -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    asm.ldc_i4_0()?
        .ldc_i4_1()?
        .ldc_i4_s(127)?
        .ldc_i4(1000)?
        .add()?
        .add()?
        .add()?
        .ret()?;
    asm.finish()
}

fn assemble_large_method() -> Result<(
    Vec<u8>,
    u16,
    Vec<dotscope::metadata::method::ExceptionHandler>,
)> {
    let mut asm = InstructionAssembler::new();
    for i in 0i32..50 {
        asm.ldarg_0()?
            .ldc_i4_const(i)?
            .ceq()?
            .brtrue(&format!("case_{i}"))?;
    }
    asm.ldc_i4_m1()?.ret()?;
    for i in 0i32..50 {
        asm.label(&format!("case_{i}"))?
            .ldc_i4_const(i.saturating_mul(2))?
            .ret()?;
    }
    asm.finish()
}

fn encode_simple_direct() -> Result<(Vec<u8>, u16, std::collections::HashMap<String, u32>)> {
    let mut encoder = InstructionEncoder::new();
    encoder.emit_instruction("ldarg.1", None)?;
    encoder.emit_instruction("ldarg.2", None)?;
    encoder.emit_instruction("add", None)?;
    encoder.emit_instruction("ret", None)?;
    encoder.finalize()
}

/// Benchmark CIL assembly and disassembly across simple, complex, and large
/// method shapes plus assemble-disassemble roundtrips.
pub fn criterion_benchmark(c: &mut Criterion) {
    // Simple method: basic arithmetic
    c.bench_function("bench_assemble_simple_method", |b| {
        b.iter(|| {
            black_box(assemble_simple().expect("the benchmarked work succeeds on its input"));
        });
    });

    // Complex method: loops, branches, and object operations
    c.bench_function("bench_assemble_complex_method", |b| {
        b.iter(|| {
            black_box(assemble_complex().expect("the benchmarked work succeeds on its input"));
        });
    });

    // Object-heavy method: field access and method calls
    c.bench_function("bench_assemble_object_method", |b| {
        let field_token = Token::new(0x04000001);
        let method_token = Token::new(0x06000001);
        let _type_token = Token::new(0x02000001);

        b.iter(|| {
            black_box(
                assemble_object(field_token, method_token)
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    // Low-level encoder benchmark
    c.bench_function("bench_assemble_encoder_direct", |b| {
        b.iter(|| {
            black_box(encode_simple_direct().expect("the benchmarked work succeeds on its input"));
        });
    });

    // Roundtrip benchmark: assemble then disassemble
    let simple_bytecode = assemble_simple()
        .map(|(b, _, _)| b)
        .expect("the benchmark's input assembles");
    let complex_bytecode = assemble_complex()
        .map(|(b, _, _)| b)
        .expect("the benchmark's input assembles");

    c.bench_function("bench_roundtrip_simple", |b| {
        b.iter(|| {
            let _: Result<_> = (|| {
                let (bytecode, _max_stack, _) = assemble_simple()?;
                let mut parser = dotscope::Parser::new(&bytecode);
                decode_stream(&mut parser, 0x1000)
            })();
        });
    });

    c.bench_function("bench_roundtrip_complex", |b| {
        b.iter(|| {
            let _: Result<_> = (|| {
                let (bytecode, _max_stack, _) = assemble_complex()?;
                let mut parser = dotscope::Parser::new(&bytecode);
                decode_stream(&mut parser, 0x1000)
            })();
        });
    });

    // Disassemble-only benchmarks for comparison
    c.bench_function("bench_disassemble_simple", |b| {
        b.iter(|| {
            let mut parser = dotscope::Parser::new(&simple_bytecode);
            black_box(
                decode_stream(&mut parser, 0x1000)
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    c.bench_function("bench_disassemble_complex", |b| {
        b.iter(|| {
            let mut parser = dotscope::Parser::new(&complex_bytecode);
            black_box(
                decode_stream(&mut parser, 0x1000)
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    // Optimization benchmark: compare ldc_i4_const vs manual selection
    c.bench_function("bench_assemble_with_optimizations", |b| {
        b.iter(|| {
            black_box(
                assemble_with_optimizations().expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    c.bench_function("bench_assemble_manual_selection", |b| {
        b.iter(|| {
            black_box(
                assemble_manual_selection().expect("the benchmarked work succeeds on its input"),
            );
        });
    });

    // Memory-intensive benchmark: large method with many labels
    c.bench_function("bench_assemble_large_method", |b| {
        b.iter(|| {
            black_box(assemble_large_method().expect("the benchmarked work succeeds on its input"));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

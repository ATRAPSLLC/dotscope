//! Benchmarks for signature parsing.
//!
//! Tests parsing performance for various .NET metadata signature types:
//! - Method signatures (simple, generic, varargs)
//! - Field signatures (primitives, arrays, generics)
//! - Property signatures
//! - Local variable signatures
//! - Type specification signatures
//! - Method specification signatures

// A benchmark whose work fails must fail, not time the failure.
#![allow(clippy::expect_used)]

extern crate dotscope;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use dotscope::metadata::signatures::{
    parse_field_signature, parse_local_var_signature, parse_method_signature,
    parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
};

/// Benchmark parsing a simple void method with no parameters.
/// Signature: void Method()
fn bench_method_signature_void_no_params(c: &mut Criterion) {
    // DEFAULT calling convention, 0 params, VOID return
    let signature = [0x00, 0x00, 0x01];

    c.bench_function("sig_method_void_no_params", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method with primitive parameters.
/// Signature: int Method(int a, string b, bool c)
fn bench_method_signature_primitives(c: &mut Criterion) {
    // DEFAULT, 3 params, I4 return, I4, STRING, BOOLEAN params
    let signature = [0x00, 0x03, 0x08, 0x08, 0x0E, 0x02];

    c.bench_function("sig_method_primitives", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing an instance method (has 'this' parameter).
/// Signature: void Instance.Method(int a)
fn bench_method_signature_instance(c: &mut Criterion) {
    // HASTHIS, 1 param, VOID return, I4 param
    let signature = [0x20, 0x01, 0x01, 0x08];

    c.bench_function("sig_method_instance", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a generic method signature.
/// Signature: T Method<T>(T item)
fn bench_method_signature_generic(c: &mut Criterion) {
    // HASTHIS | GENERIC, 1 generic param, 1 method param, MVAR(0) return, MVAR(0) param
    let signature = [0x30, 0x01, 0x01, 0x1E, 0x00, 0x1E, 0x00];

    c.bench_function("sig_method_generic", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method with multiple generic parameters.
/// Signature: TResult Method<T, TResult>(T input)
fn bench_method_signature_multi_generic(c: &mut Criterion) {
    // HASTHIS | GENERIC, 2 generic params, 1 method param, MVAR(1) return, MVAR(0) param
    let signature = [0x30, 0x02, 0x01, 0x1E, 0x01, 0x1E, 0x00];

    c.bench_function("sig_method_multi_generic", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method with byref parameter.
/// Signature: void Method(ref int a, out string b)
fn bench_method_signature_byref(c: &mut Criterion) {
    // DEFAULT, 2 params, VOID return, BYREF I4, BYREF STRING
    let signature = [0x00, 0x02, 0x01, 0x10, 0x08, 0x10, 0x0E];

    c.bench_function("sig_method_byref", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method returning an array.
/// Signature: int[] Method()
fn bench_method_signature_array_return(c: &mut Criterion) {
    // DEFAULT, 0 params, SZARRAY I4 return
    let signature = [0x00, 0x00, 0x1D, 0x08];

    c.bench_function("sig_method_array_return", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method with many parameters.
/// Signature: void Method(int, int, int, int, int, int, int, int)
fn bench_method_signature_many_params(c: &mut Criterion) {
    // DEFAULT, 8 params, VOID return, 8x I4
    let signature = [
        0x00, 0x08, 0x01, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    ];

    c.bench_function("sig_method_many_params", |b| {
        b.iter(|| {
            black_box(
                parse_method_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a simple primitive field.
/// Signature: int field
fn bench_field_signature_primitive(c: &mut Criterion) {
    // FIELD, I4
    let signature = [0x06, 0x08];

    c.bench_function("sig_field_primitive", |b| {
        b.iter(|| {
            black_box(
                parse_field_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a string field.
/// Signature: string field
fn bench_field_signature_string(c: &mut Criterion) {
    // FIELD, STRING
    let signature = [0x06, 0x0E];

    c.bench_function("sig_field_string", |b| {
        b.iter(|| {
            black_box(
                parse_field_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing an array field.
/// Signature: int[] field
fn bench_field_signature_array(c: &mut Criterion) {
    // FIELD, SZARRAY, I4
    let signature = [0x06, 0x1D, 0x08];

    c.bench_function("sig_field_array", |b| {
        b.iter(|| {
            black_box(
                parse_field_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a generic parameter field.
/// Signature: T field (in generic type)
fn bench_field_signature_generic_param(c: &mut Criterion) {
    // FIELD, VAR(0)
    let signature = [0x06, 0x13, 0x00];

    c.bench_function("sig_field_generic_param", |b| {
        b.iter(|| {
            black_box(
                parse_field_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a field with a class type reference.
/// Signature: SomeClass field
fn bench_field_signature_class(c: &mut Criterion) {
    // FIELD, CLASS, TypeRef token (compressed: 0x49 = token 0x01000012)
    let signature = [0x06, 0x12, 0x49];

    c.bench_function("sig_field_class", |b| {
        b.iter(|| {
            black_box(
                parse_field_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a simple property getter.
/// Signature: int Property { get; }
fn bench_property_signature_simple(c: &mut Criterion) {
    // PROPERTY | HASTHIS, 0 params, I4 return
    let signature = [0x28, 0x00, 0x08];

    c.bench_function("sig_property_simple", |b| {
        b.iter(|| {
            black_box(
                parse_property_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing an indexer property.
/// Signature: string this[int index] { get; }
fn bench_property_signature_indexer(c: &mut Criterion) {
    // PROPERTY | HASTHIS, 1 param, STRING return, I4 index param
    let signature = [0x28, 0x01, 0x0E, 0x08];

    c.bench_function("sig_property_indexer", |b| {
        b.iter(|| {
            black_box(
                parse_property_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a static property.
/// Signature: static int Property { get; }
fn bench_property_signature_static(c: &mut Criterion) {
    // PROPERTY (no HASTHIS), 0 params, I4 return
    let signature = [0x08, 0x00, 0x08];

    c.bench_function("sig_property_static", |b| {
        b.iter(|| {
            black_box(
                parse_property_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a single local variable.
/// Locals: int a
fn bench_local_var_signature_single(c: &mut Criterion) {
    // LOCAL_SIG, 1 variable, I4
    let signature = [0x07, 0x01, 0x08];

    c.bench_function("sig_localvar_single", |b| {
        b.iter(|| {
            black_box(
                parse_local_var_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing multiple local variables.
/// Locals: int a; string b; bool c; object d
fn bench_local_var_signature_multiple(c: &mut Criterion) {
    // LOCAL_SIG, 4 variables, I4, STRING, BOOLEAN, OBJECT
    let signature = [0x07, 0x04, 0x08, 0x0E, 0x02, 0x1C];

    c.bench_function("sig_localvar_multiple", |b| {
        b.iter(|| {
            black_box(
                parse_local_var_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing local variables with byref.
/// Locals: ref int a; ref string b
fn bench_local_var_signature_byref(c: &mut Criterion) {
    // LOCAL_SIG, 2 variables, BYREF I4, BYREF STRING
    let signature = [0x07, 0x02, 0x10, 0x08, 0x10, 0x0E];

    c.bench_function("sig_localvar_byref", |b| {
        b.iter(|| {
            black_box(
                parse_local_var_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing local variables with pinned.
/// Locals: pinned int* ptr
fn bench_local_var_signature_pinned(c: &mut Criterion) {
    // LOCAL_SIG, 1 variable, PINNED PTR I4
    let signature = [0x07, 0x01, 0x45, 0x0F, 0x08];

    c.bench_function("sig_localvar_pinned", |b| {
        b.iter(|| {
            black_box(
                parse_local_var_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing many local variables (typical complex method).
/// Locals: 10 variables of various types
fn bench_local_var_signature_many(c: &mut Criterion) {
    // LOCAL_SIG, 10 variables
    let signature = [
        0x07, 0x0A, // LOCAL_SIG, 10 vars
        0x08, // I4
        0x0E, // STRING
        0x02, // BOOLEAN
        0x1C, // OBJECT
        0x08, // I4
        0x0E, // STRING
        0x08, // I4
        0x08, // I4
        0x1C, // OBJECT
        0x02, // BOOLEAN
    ];

    c.bench_function("sig_localvar_many", |b| {
        b.iter(|| {
            black_box(
                parse_local_var_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a generic type instantiation.
/// Type: List<int>
fn bench_type_spec_generic_simple(c: &mut Criterion) {
    // GENERICINST, CLASS, TypeRef token, 1 type arg, I4
    let signature = [0x15, 0x12, 0x49, 0x01, 0x08];

    c.bench_function("sig_typespec_generic_simple", |b| {
        b.iter(|| {
            black_box(
                parse_type_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a generic type with multiple type arguments.
/// Type: Dictionary<string, int>
fn bench_type_spec_generic_multi_arg(c: &mut Criterion) {
    // GENERICINST, CLASS, TypeRef token, 2 type args, STRING, I4
    let signature = [0x15, 0x12, 0x49, 0x02, 0x0E, 0x08];

    c.bench_function("sig_typespec_generic_multi_arg", |b| {
        b.iter(|| {
            black_box(
                parse_type_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing an array type specification.
/// Type: int[]
fn bench_type_spec_array(c: &mut Criterion) {
    // SZARRAY, I4
    let signature = [0x1D, 0x08];

    c.bench_function("sig_typespec_array", |b| {
        b.iter(|| {
            black_box(
                parse_type_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a pointer type specification.
/// Type: int*
fn bench_type_spec_pointer(c: &mut Criterion) {
    // PTR, I4
    let signature = [0x0F, 0x08];

    c.bench_function("sig_typespec_pointer", |b| {
        b.iter(|| {
            black_box(
                parse_type_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a generic parameter type specification.
/// Type: T (from enclosing generic type)
fn bench_type_spec_generic_param(c: &mut Criterion) {
    // VAR(0)
    let signature = [0x13, 0x00];

    c.bench_function("sig_typespec_generic_param", |b| {
        b.iter(|| {
            black_box(
                parse_type_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method specification with one type argument.
/// Method<int>
fn bench_method_spec_single(c: &mut Criterion) {
    // GENRICINST, 1 type arg, I4
    let signature = [0x0A, 0x01, 0x08];

    c.bench_function("sig_methodspec_single", |b| {
        b.iter(|| {
            black_box(
                parse_method_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method specification with multiple type arguments.
/// Method<int, string, bool>
fn bench_method_spec_multiple(c: &mut Criterion) {
    // GENRICINST, 3 type args, I4, STRING, BOOLEAN
    let signature = [0x0A, 0x03, 0x08, 0x0E, 0x02];

    c.bench_function("sig_methodspec_multiple", |b| {
        b.iter(|| {
            black_box(
                parse_method_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

/// Benchmark parsing a method specification with nested generic type argument.
/// Method<List<int>>
fn bench_method_spec_nested_generic(c: &mut Criterion) {
    // GENRICINST, 1 type arg, GENERICINST CLASS TypeRef 1 arg I4
    let signature = [0x0A, 0x01, 0x15, 0x12, 0x49, 0x01, 0x08];

    c.bench_function("sig_methodspec_nested_generic", |b| {
        b.iter(|| {
            black_box(
                parse_method_spec_signature(black_box(&signature))
                    .expect("the benchmarked work succeeds on its input"),
            );
        });
    });
}

criterion_group!(
    benches,
    // Method signatures
    bench_method_signature_void_no_params,
    bench_method_signature_primitives,
    bench_method_signature_instance,
    bench_method_signature_generic,
    bench_method_signature_multi_generic,
    bench_method_signature_byref,
    bench_method_signature_array_return,
    bench_method_signature_many_params,
    // Field signatures
    bench_field_signature_primitive,
    bench_field_signature_string,
    bench_field_signature_array,
    bench_field_signature_generic_param,
    bench_field_signature_class,
    // Property signatures
    bench_property_signature_simple,
    bench_property_signature_indexer,
    bench_property_signature_static,
    // Local variable signatures
    bench_local_var_signature_single,
    bench_local_var_signature_multiple,
    bench_local_var_signature_byref,
    bench_local_var_signature_pinned,
    bench_local_var_signature_many,
    // Type specification signatures
    bench_type_spec_generic_simple,
    bench_type_spec_generic_multi_arg,
    bench_type_spec_array,
    bench_type_spec_pointer,
    bench_type_spec_generic_param,
    // Method specification signatures
    bench_method_spec_single,
    bench_method_spec_multiple,
    bench_method_spec_nested_generic,
);
criterion_main!(benches);

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! What work allocates, counted by the binary's own allocator (`benches/common/alloc.rs`), so
//! a verdict does not depend on how busy the machine is.

#[path = "../benches/common/alloc.rs"]
mod alloc;

use dotscope::{
    emulation::{EmValue, EmulationOutcome},
    testkit::{emulation::process_builder, fixture_bytes},
    CilObject,
};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

/// An emulated loop over an array allocates in proportion to the array, not to its square:
/// `TestApp`'s `XorEncrypt` stores each character of its input into a `char[]`, and each
/// `stelem` copied the whole array to read its element type (each `ldelem`, `ldlen` and `ldfld`
/// copied what it read from as well), 228 MB for a 1,472-character string.
#[test]
fn an_array_loop_allocates_in_proportion_to_the_array() {
    let assembly =
        CilObject::from_mem(fixture_bytes("packers/confuserex/1.6.0/original.exe").to_vec())
            .expect("TestApp loads");
    let xor = *assembly
        .methods()
        .iter()
        .find(|entry| entry.value().name == "XorEncrypt")
        .expect("TestApp has XorEncrypt")
        .key();
    let process = process_builder()
        .assembly(assembly)
        .with_max_instructions(100_000_000)
        .build()
        .expect("the process builds");
    let mut allocated = Vec::new();
    for length in [1024, 2048] {
        let text = process
            .address_space()
            .alloc_string(&"x".repeat(length))
            .expect("the string is allocated");
        let args = vec![EmValue::Null, EmValue::ObjectRef(text), EmValue::I32(0x5A)];
        let (outcome, stats) = alloc::measure(|| process.execute_method(xor, args));
        assert!(
            matches!(outcome, Ok(EmulationOutcome::Completed { .. })),
            "XorEncrypt completes: {outcome:?}"
        );
        allocated.push(stats.allocated_bytes);
    }
    // Twice the input allocates about twice as much when each access costs the same; a copy
    // per access makes it four times
    assert!(
        allocated[1] < allocated[0] * 3,
        "1024 characters allocate {} bytes and 2048 allocate {}",
        allocated[0],
        allocated[1]
    );
}

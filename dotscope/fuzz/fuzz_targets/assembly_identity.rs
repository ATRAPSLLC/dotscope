//! The `assembly_identity` target: see `dotscope::testkit::fuzz::assembly_identity`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::assembly_identity(data));

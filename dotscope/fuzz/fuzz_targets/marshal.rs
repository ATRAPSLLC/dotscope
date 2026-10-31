//! The `marshal` target: see `dotscope::testkit::fuzz::marshal`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::marshal(data));

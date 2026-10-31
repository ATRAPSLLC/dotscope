//! The `signatures` target: see `dotscope::testkit::fuzz::signatures`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::signatures(data));

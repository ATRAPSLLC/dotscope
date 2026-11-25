//! The `pe_file` target: see `dotscope::testkit::fuzz::pe_file`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::pe_file(data));

//! The `assemblyview` target: see `dotscope::testkit::fuzz::assemblyview`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::assemblyview(data));

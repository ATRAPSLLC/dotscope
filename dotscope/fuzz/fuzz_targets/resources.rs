//! The `resources` target: see `dotscope::testkit::fuzz::resources`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::resources(data));

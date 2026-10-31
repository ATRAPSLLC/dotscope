//! The `customattributes` target: see `dotscope::testkit::fuzz::customattributes`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::customattributes(data));

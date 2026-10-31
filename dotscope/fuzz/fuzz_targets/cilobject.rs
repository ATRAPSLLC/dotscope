//! The `cilobject` target: see `dotscope::testkit::fuzz::cilobject`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::cilobject(data));

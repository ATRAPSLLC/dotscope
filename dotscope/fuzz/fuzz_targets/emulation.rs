//! The `emulation` target: see `dotscope::testkit::fuzz::emulation`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::emulation(data));

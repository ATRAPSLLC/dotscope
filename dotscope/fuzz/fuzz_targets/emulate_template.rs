//! The `emulate_template` target: see `dotscope::testkit::fuzz::emulate_template`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::emulate_template(data));

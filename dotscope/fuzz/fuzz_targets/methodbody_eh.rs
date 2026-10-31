//! The `methodbody_eh` target: see `dotscope::testkit::fuzz::methodbody_eh`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::methodbody_eh(data));

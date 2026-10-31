//! The `methodbody` target: see `dotscope::testkit::fuzz::methodbody`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::methodbody(data));

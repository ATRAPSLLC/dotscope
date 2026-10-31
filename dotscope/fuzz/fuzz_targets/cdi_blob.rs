//! The `cdi_blob` target: see `dotscope::testkit::fuzz::cdi_blob`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::cdi_blob(data));

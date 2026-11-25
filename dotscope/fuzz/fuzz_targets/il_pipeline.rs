//! The `il_pipeline` target: see `dotscope::testkit::fuzz::il_pipeline`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::il_pipeline(data));

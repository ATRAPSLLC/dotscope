//! The `codec_native_type` target: see `dotscope::testkit::fuzz::codec_native_type`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::codec_native_type(data));

//! The `codec_method_body` target: see `dotscope::testkit::fuzz::codec_method_body`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::codec_method_body(data));

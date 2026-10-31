//! The `codec_signatures` target: see `dotscope::testkit::fuzz::codec_signatures`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::codec_signatures(data));

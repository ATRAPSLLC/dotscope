//! The `codec_permissions` target: see `dotscope::testkit::fuzz::codec_permissions`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::codec_permissions(data));

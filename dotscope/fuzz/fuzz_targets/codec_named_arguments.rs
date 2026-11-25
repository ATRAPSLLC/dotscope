//! The `codec_named_arguments` target: see `dotscope::testkit::fuzz::codec_named_arguments`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::codec_named_arguments(data));

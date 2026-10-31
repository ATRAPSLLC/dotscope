//! The `writer_roundtrip` target: see `dotscope::testkit::fuzz::writer_roundtrip`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::writer_roundtrip(data));

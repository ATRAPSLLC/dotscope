//! The `deobfuscate_bounded` target: see `dotscope::testkit::fuzz::deobfuscate_bounded`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::deobfuscate_bounded(data));

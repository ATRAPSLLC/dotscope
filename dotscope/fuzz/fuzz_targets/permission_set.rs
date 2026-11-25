//! The `permission_set` target: see `dotscope::testkit::fuzz::permission_set`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::permission_set(data));

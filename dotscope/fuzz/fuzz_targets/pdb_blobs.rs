//! The `pdb_blobs` target: see `dotscope::testkit::fuzz::pdb_blobs`.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| dotscope::testkit::fuzz::pdb_blobs(data));

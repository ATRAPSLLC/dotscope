#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! The local fuzzing corpus, replayed when one is present.
//!
//! Every input under `fuzz/corpus/cilobject/` goes through `CilObject::from_path`; the property
//! is that the call returns rather than panicking, aborting, hanging or exhausting memory. The
//! corpus is what a local fuzzing run (`make fuzz`) grew: too large to commit, so absent on a
//! clean checkout, where this skips loudly. The committed inputs that once crashed a target are
//! replayed through their own targets by `tests/fuzz_regressions.rs`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use dotscope::metadata::cilobject::CilObject;

/// Loads every input in the local fuzzing corpus, when one is present.
///
/// The corpus is hundreds of megabytes and is not committed, so this skips on a clean
/// checkout. It prints when it skips so a vacuous pass is visible in the test output rather
/// than indistinguishable from a real one.
#[test]
fn fuzzer_corpus() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/cilobject");
    match load_every_file(&path) {
        Ok(loaded) => println!(
            "fuzzer_corpus: loaded {loaded} inputs from {}",
            path.display()
        ),
        Err(e) => println!(
            "fuzzer_corpus: SKIPPED — no local corpus at {} ({e}). \
             Run `make fuzz` to generate one.",
            path.display()
        ),
    }
}

/// Loads every regular file in `dir` through the parser, returning how many were loaded.
///
/// Parse errors are ignored by design; the assertion is that the call returns at all.
///
/// # Errors
///
/// Returns the underlying I/O error if `dir` cannot be read.
fn load_every_file(dir: &Path) -> std::io::Result<usize> {
    let mut loaded = 0usize;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            // Malformed input: an `Err` is the expected result and is discarded. What this
            // exercises is that the call returns instead of taking the process down.
            let _ = CilObject::from_path(&path);
            loaded += 1;
        }
    }
    Ok(loaded)
}

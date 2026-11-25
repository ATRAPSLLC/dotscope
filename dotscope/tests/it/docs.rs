#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Every documentation example is real code: it compiles when the doc tests run.

use std::{fs, path::Path};

/// The `ignore` fences in `dir`'s Rust sources, as `path:line`.
fn ignored_examples(dir: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            ignored_examples(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            for (number, line) in source.lines().enumerate() {
                let fence = line.trim_start().trim_start_matches(['/', '!']).trim();
                if fence.starts_with("```") && fence.contains("ignore") {
                    found.push(format!("{}:{}", path.display(), number.saturating_add(1)));
                }
            }
        }
    }
}

/// No example opts out of compiling with `ignore`: an example on a public item is `no_run`
/// at most, and one that needs crate-private API is a unit test beside the item.
#[test]
fn no_doc_example_is_ignored() {
    let mut found = Vec::new();
    ignored_examples(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert!(
        found.is_empty(),
        "ignored doc examples:\n{}",
        found.join("\n")
    );
}

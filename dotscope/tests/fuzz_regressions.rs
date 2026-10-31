#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Every input a fuzz target once crashed, hung, leaked or ran out of memory on replays
//! through that target's entry point (`testkit::fuzz`), and holds what it allocates to a
//! bound.
//!
//! `tests/samples/fuzz-regressions/<target>/` holds a target's inputs. Each runs twice
//! through the target's entry point under a counting allocator: the first run warms what a
//! process sets up once, and the second may allocate at most [`ALLOCATION_LIMIT`] bytes all
//! told, which bounds its peak however its threads interleave. The bound is a count, not a
//! time, so the verdict does not depend on how busy the machine is.
//!
//! What a run still holds when it returns is not checked: the crate frees some memory later,
//! on other threads (crossbeam-epoch), so the count swings by hundreds of kilobytes either way
//! from one run to the next with no trend (measured over 300 loads of `crafted_2.exe` and the
//! two `leak-*` inputs). A leak is the fuzzer's to find, under LeakSanitizer.
//!
//! The allocator is the binary's own, so this suite is a test binary of its own.

#[path = "../benches/common/alloc.rs"]
mod alloc;

use std::fs;

use dotscope::testkit::{fixture, fuzz::TARGETS};

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

/// The most bytes an input may allocate, all told: the largest committed input allocates 72
/// MiB (`cilobject/crash-22020b57...`), where an input once ran out of 2 GiB.
const ALLOCATION_LIMIT: u64 = 256 << 20;

#[test]
fn every_regression_replays_through_its_target() {
    let root = fixture("fuzz-regressions");
    let mut replayed = 0usize;
    let mut failures = Vec::new();
    for entry in fs::read_dir(&root).unwrap() {
        let dir = entry.unwrap().path();
        let target = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            dir.is_dir(),
            "{target}: fuzz-regressions holds one directory per target, not files"
        );
        let run = TARGETS
            .iter()
            .find(|(name, _)| *name == target)
            .unwrap_or_else(|| panic!("fuzz-regressions/{target} names no fuzz target"))
            .1;
        let mut inputs: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        inputs.sort();
        assert!(!inputs.is_empty(), "fuzz-regressions/{target} is empty");
        for input in inputs {
            let data = fs::read(&input).unwrap();
            let name = input.file_name().unwrap().to_string_lossy().into_owned();
            run(&data);
            let ((), stats) = alloc::measure(|| run(&data));
            if stats.allocated_bytes > ALLOCATION_LIMIT {
                failures.push(format!(
                    "{target}/{name}: allocates {} MiB, over {} MiB",
                    stats.allocated_bytes >> 20,
                    ALLOCATION_LIMIT >> 20
                ));
            }
            replayed += 1;
        }
    }
    assert!(replayed > 0, "no regression was replayed");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

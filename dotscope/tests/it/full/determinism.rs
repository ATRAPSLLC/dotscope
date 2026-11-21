#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Deobfuscating a sample twice gives the same bytes.
//!
//! Every packer sample is deobfuscated twice, side by side, once in a pool of one thread and
//! once in a pool of eight, and the two outputs must be byte-identical. Each run builds its
//! hash maps afresh, on its own threads with their own random seeds, so an output that follows
//! a map's iteration order, or the order parallel work finishes in, differs between the runs.
//! A sample the engine refuses must be refused both times.

#![cfg(feature = "deobfuscation")]

use std::fs;

use dotscope::testkit::{engine, fixture};

/// Deobfuscates `sample` in a pool of `threads` threads: the output's bytes, or the error.
fn deobfuscate_with(sample: &str, threads: usize) -> Result<Vec<u8>, String> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    pool.install(|| engine().process_file(fixture(sample)))
        .map(|(output, _)| output.file().data().to_vec())
        .map_err(|error| error.to_string())
}

/// Where two outputs first differ, or that one is a prefix of the other.
fn first_difference(a: &[u8], b: &[u8]) -> String {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(offset) => format!("first difference at offset {offset:#x}"),
        None => format!("lengths {} and {}", a.len(), b.len()),
    }
}

/// Deobfuscates every sample of the family in `dir` twice and requires identical output.
fn check_family(dir: &str) {
    let mut samples: Vec<String> = fs::read_dir(fixture(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".exe") && name != "original.exe")
        .collect();
    samples.sort();
    assert!(!samples.is_empty(), "{dir} has no protected samples");

    let differing: Vec<String> = samples
        .iter()
        .filter_map(|sample| {
            let path = format!("{dir}/{sample}");
            // The two runs go side by side: each in its own pool, on its own threads
            let (one, eight) = std::thread::scope(|scope| {
                let one = scope.spawn(|| deobfuscate_with(&path, 1));
                let eight = deobfuscate_with(&path, 8);
                (one.join().unwrap(), eight)
            });
            match (one, eight) {
                (Ok(one), Ok(eight)) if one == eight => None,
                (Ok(one), Ok(eight)) => Some(format!(
                    "{sample}: outputs differ, {}",
                    first_difference(&one, &eight)
                )),
                (Err(one), Err(eight)) if one == eight => None,
                (one, eight) => Some(format!(
                    "{sample}: one run gave {:?}, the other {:?}",
                    one.map(|bytes| bytes.len()),
                    eight.map(|bytes| bytes.len())
                )),
            }
        })
        .collect();
    assert!(differing.is_empty(), "{dir}:\n{}", differing.join("\n"));
}

#[test]
fn confuserex_output_is_deterministic() {
    check_family("packers/confuserex/1.6.0");
}

#[test]
fn bitmono_0_39_0_output_is_deterministic() {
    check_family("packers/bitmono/0.39.0");
}

#[test]
fn bitmono_0_45_0_output_is_deterministic() {
    check_family("packers/bitmono/0.45.0");
}

#[test]
fn obfuscar_output_is_deterministic() {
    check_family("packers/obfuscar/2.2.50");
}

#[test]
fn jiejie_output_is_deterministic() {
    check_family("packers/jiejie/source");
}

#[test]
fn netreactor_output_is_deterministic() {
    check_family("packers/netreactor/7.5.0");
}

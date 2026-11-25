#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

//! dotscope reads a metadata stream directory as the CLR does.
//!
//! `tests/samples/metadata/streams` holds StreamProbe rewritten with repeated, unknown and
//! malformed stream headers, and `factory/oracle.tsv` records what the .NET Framework printed
//! for each: one value from each heap. For every image the CLR runs, the heaps dotscope
//! reads must hold the values the CLR printed; every image the CLR refuses for its stream
//! directory, dotscope refuses. See `tests/samples/factory/README.md` for the rule.
//!
//! `tests/samples/metadata/layouts` holds TestApp rewritten with other tables-stream layouts
//! (the ExtraData word, HasDelete, `#-`, undefined HeapSizes bits, minimal-delta tables):
//! every one the CLR runs, dotscope reads with all of TestApp's methods.

use std::collections::{BTreeSet, HashMap};

use dotscope::{
    metadata::{tables::ModuleRaw, validation::ValidationConfig},
    testkit::fixture,
    CilAssemblyView, CilObject,
};

/// The oracle's rows for `metadata/<dir>`, by file name: (CLR runs it, the CLR's output).
fn oracle(dir: &str) -> HashMap<String, (bool, String)> {
    let text = std::fs::read_to_string(fixture("factory/oracle.tsv")).unwrap();
    let mut lines = text.lines().filter(|line| !line.starts_with('#'));
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    let column = |name: &str| header.iter().position(|c| *c == name).unwrap();
    let (path, runs, output) = (column("path"), column("netfx_runs"), column("netfx_output"));
    lines
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter_map(|row| {
            let name = row[path]
                .strip_prefix("metadata/")?
                .strip_prefix(dir)?
                .strip_prefix('/')?;
            Some((
                name.to_string(),
                (row[runs] == "yes", row[output].to_string()),
            ))
        })
        .collect()
}

/// The images the CLR refuses for their stream directory, and why.
const REFUSED: &[(&str, &str)] = &[
    (
        "unknown_bad_offset.exe",
        "a header reaches past the metadata",
    ),
    ("unknown_bad_size.exe", "a header reaches past the metadata"),
    (
        "us_shadowed_bad_offset.exe",
        "a header reaches past the metadata",
    ),
    (
        "us_used_bad_offset.exe",
        "a header reaches past the metadata",
    ),
    ("unknown_name_32.exe", "a name is longer than 32 bytes"),
    ("unknown_name_40.exe", "a name is longer than 32 bytes"),
    ("tables_junk_after.exe", "two tables streams"),
    ("tables_junk_before.exe", "two tables streams"),
    ("tables_enc_junk_after.exe", "two tables streams"),
    ("tables_changed_after.exe", "two tables streams"),
    ("tables_changed_before.exe", "two tables streams"),
    ("schema_before.exe", "#Schema before the tables stream"),
    (
        "schema_before_tables.exe",
        "#Schema before the tables stream",
    ),
];

/// The images the CLR reads but then fails to run, and the values dotscope must read from
/// them: the heaps the rule picks, as the same directory shape shows on the other heaps.
/// `strings_*` swap the case of the probe type's own name, which the program then cannot
/// find; `junk_*` read heaps of zeros.
const READ_BUT_NOT_RUN: &[(&str, &str)] = &[
    (
        "strings_after.exe",
        "strings=sTRINGSmARKER|us=UserStringMarker|blob=BlobMarker|guid=c229b41f-4366-4ab0-85eb-1813b9c651f7",
    ),
    (
        "strings_before_enc.exe",
        "strings=sTRINGSmARKER|us=UserStringMarker|blob=BlobMarker|guid=c229b41f-4366-4ab0-85eb-1813b9c651f7",
    ),
    (
        "junk_after.exe",
        "strings=-|us=-|blob=-|guid=00000000-0000-0000-0000-000000000000",
    ),
    (
        "junk_before_enc.exe",
        "strings=-|us=-|blob=-|guid=00000000-0000-0000-0000-000000000000",
    ),
];

/// The images the CLR refuses because `#JTD` beside `#-` tables makes their columns four
/// bytes wide, which these normal-width tables are not.
const MINIMAL_DELTA: &[&str] = &["jtd_after_enc.exe", "jtd_before_enc.exe"];

/// The case-insensitive match of `marker` in `text`, as it stands there.
fn find_marker(text: &str, marker: &str) -> Option<String> {
    let at = text
        .to_ascii_lowercase()
        .find(&marker.to_ascii_lowercase())?;
    Some(text.get(at..at.checked_add(marker.len())?)?.to_string())
}

/// The four values StreamProbe prints, read from the heaps dotscope reads: each marker as it
/// stands in its heap (`-` when the heap holds none), and the module's MVID.
fn probe_values(view: &CilAssemblyView) -> String {
    let strings = view
        .strings()
        .unwrap()
        .iter()
        .find_map(|(_, s)| find_marker(s, "StringsMarker"));
    let us = view
        .userstrings()
        .unwrap()
        .iter()
        .find_map(|(_, s)| find_marker(&s.to_string_lossy(), "UserStringMarker"));
    let blob = view
        .blobs()
        .unwrap()
        .iter()
        .find_map(|(_, bytes)| find_marker(&String::from_utf8_lossy(bytes), "BlobMarker"));
    let module = view
        .tables()
        .unwrap()
        .table::<ModuleRaw>()
        .unwrap()
        .get(1)
        .unwrap()
        .unwrap();
    let guid = view.guids().unwrap().get(module.mvid as usize).unwrap();
    format!(
        "strings={}|us={}|blob={}|guid={}",
        strings.as_deref().unwrap_or("-"),
        us.as_deref().unwrap_or("-"),
        blob.as_deref().unwrap_or("-"),
        guid
    )
}

fn load(name: &str) -> dotscope::Result<CilAssemblyView> {
    CilAssemblyView::from_path_with_validation(
        fixture("metadata/streams").join(name),
        ValidationConfig::disabled(),
    )
}

#[test]
fn every_stream_experiment_is_read_as_the_clr_reads_it() {
    let oracle = oracle("streams");
    assert!(oracle.len() > 50, "the oracle lists the stream experiments");
    let mut failures = Vec::new();
    for (name, (runs, output)) in &oracle {
        let refused = REFUSED.iter().find(|(n, _)| n == name);
        let derived = READ_BUT_NOT_RUN.iter().find(|(n, _)| n == name);
        let minimal_delta = MINIMAL_DELTA.contains(&name.as_str());
        let expected_refusal = refused
            .map(|(_, why)| *why)
            .or(minimal_delta.then_some("#JTD makes the tables' columns four bytes wide"));

        if let Some(why) = expected_refusal {
            assert!(
                !runs,
                "{name}: the oracle says the CLR runs it, yet it is listed as refused"
            );
            if load(name).is_ok() {
                failures.push(format!("{name}: loads, but the CLR refuses it ({why})"));
            }
            continue;
        }

        let expected = if *runs {
            output.as_str()
        } else if let Some((_, values)) = derived {
            values
        } else {
            panic!("{name}: the CLR does not run it, and it is in no list saying why");
        };
        match load(name) {
            Ok(view) => {
                let read = probe_values(&view);
                if read != expected {
                    failures.push(format!("{name}: read {read}, the CLR read {expected}"));
                }
            }
            Err(error) => failures.push(format!("{name}: refused ({error}), the CLR reads it")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The layouts the CLR does not run, and why: dotscope refuses the first, and reads the
/// second, whose failure is at run time (its code needs System.Private.CoreLib).
const LAYOUTS_NOT_RUN: &[(&str, bool)] = &[
    // Minimal-delta tables with heap index columns left two bytes wide: the CLR reads every
    // index column as four bytes.
    ("minimal_delta_tables_only.exe", false),
    ("two_corelibs_foreign_first.exe", true),
];

/// `Type::method` for every method of the assembly at `path`, read through dotscope.
fn method_names(path: &std::path::Path) -> dotscope::Result<BTreeSet<String>> {
    let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;
    Ok(assembly
        .methods()
        .iter()
        .map(|entry| {
            let method = entry.value();
            let owner = method
                .declaring_type_rc()
                .map(|t| t.fullname().to_string())
                .unwrap_or_default();
            format!("{owner}::{}", method.name)
        })
        .collect())
}

#[test]
fn every_layout_is_read_as_the_clr_reads_it() {
    let original = method_names(&fixture("packers/confuserex/1.6.0/original.exe")).unwrap();
    assert!(original.len() > 20, "TestApp has its methods");
    let oracle = oracle("layouts");
    assert!(oracle.len() >= 12, "the oracle lists the layouts");
    let mut failures = Vec::new();
    for (name, (runs, _)) in &oracle {
        let path = fixture("metadata/layouts").join(name);
        let read = match LAYOUTS_NOT_RUN.iter().find(|(n, _)| n == name) {
            Some((_, readable)) => {
                assert!(
                    !runs,
                    "{name}: the oracle says the CLR runs it, yet it is listed as not run"
                );
                if !readable {
                    if method_names(&path).is_ok() {
                        failures.push(format!("{name}: loads, but the CLR cannot read it"));
                    }
                    continue;
                }
                true
            }
            None => {
                assert!(
                    runs,
                    "{name}: the CLR does not run it, and it is in no list saying why"
                );
                true
            }
        };
        if read {
            match method_names(&path) {
                Ok(methods) => {
                    let missing: Vec<_> = original.difference(&methods).collect();
                    if !missing.is_empty() {
                        failures.push(format!("{name}: TestApp's {missing:?} are not read"));
                    }
                }
                Err(error) => failures.push(format!("{name}: refused ({error}), the CLR reads it")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

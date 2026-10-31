#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! dotscope reads each assembly as System.Reflection.Metadata reads it.
//!
//! `tests/oracle/srm-dump` writes an assembly's canonical dump from what Microsoft's reader
//! reads in the file; dotscope's [`CanonicalDump`] of the same file must hold the same, path by
//! path. The fixtures the manifest tags `srm` have that dump committed as a golden, so the
//! comparison runs wherever the tests do; with Mono's compiler installed (the oracle tier
//! requires it) the dumper is built and run again, and must write exactly the goldens.

use std::{collections::BTreeSet, fs, path::Path};

use dotscope::{
    metadata::validation::ValidationConfig,
    testkit::{
        corpus::sweep,
        dump::CanonicalDump,
        fixture_bytes,
        oracle::{
            goldens_dir, read_dump, srm_fixtures, Disagreement, ReadsAsSrm, SrmDumper, REFUSED,
        },
        tools::{require_tool, ToolKind},
    },
    CilAssemblyView,
};

/// Where System.Reflection.Metadata is not the authority on `fixture`, and why. Each reason
/// names the evidence: `factory/oracle.tsv` records whether the .NET Framework, CoreCLR and
/// Mono run each fixture, and `stream_directory.rs` holds dotscope to the values the CLR
/// printed for each stream directory experiment.
fn disagreement(fixture: &str) -> Option<Disagreement> {
    const DIRECTORY: &str = "SRM resolves a stream directory the runtime reads by another rule: \
         a repeated heap, an unknown stream, #JTD or a minimal-delta layout; \
         stream_directory.rs holds dotscope to what the CLR printed for it";
    const REFUSED_BY_THE_RUNTIME: &str = "the runtime refuses it (factory/oracle.tsv) and \
         dotscope's loader refuses it as its manifest entry names; read without validation, \
         SRM takes other heaps than dotscope";
    const BITMONO_HEADERS: &str = "BitMono corrupts the PE headers the Microsoft runtimes \
         check, and neither the .NET Framework nor CoreCLR runs it (factory/oracle.tsv); \
         dotscope reads it to repair it";
    let (dir, name) = fixture.rsplit_once('/').unwrap_or(("", fixture));
    match (dir, name) {
        (
            "metadata/streams",
            "blob_after_enc.exe"
            | "blob_before_enc.exe"
            | "guid_after_enc.exe"
            | "guid_before_enc.exe"
            | "junk_after_enc.exe"
            | "junk_after_schema_after.exe"
            | "schema_after_us_after.exe"
            | "strings_after_enc.exe"
            | "us_after_enc.exe"
            | "us_after_schema_after.exe"
            | "us_after_schema_after_tables.exe"
            | "us_before_enc.exe"
            | "us_before_schema_after.exe",
        )
        | ("metadata/layouts", "minimal_delta_all.exe" | "minimal_delta_all_heapsizes.exe") => {
            Some(Disagreement::ReadsOtherwise(DIRECTORY))
        }
        (
            "metadata/streams",
            "junk_after.exe"
            | "junk_before_enc.exe"
            | "strings_after.exe"
            | "strings_before_enc.exe",
        ) => Some(Disagreement::ReadsOtherwise(REFUSED_BY_THE_RUNTIME)),
        ("metadata/streams", "jtd_after.exe" | "jtd_before.exe") => Some(Disagreement::Refuses(
            "SRM refuses a #JTD stream beside a compressed tables stream, which the CLR reads \
             (factory/oracle.tsv, stream_directory.rs)",
        )),
        ("metadata/streams", "pdb_after.exe" | "pdb_before.exe") => Some(Disagreement::Refuses(
            "SRM reads a #Pdb stream in an assembly as a portable PDB's, and fails; the CLR \
             ignores it (factory/oracle.tsv, stream_directory.rs)",
        )),
        (
            "packers/bitmono/0.39.0" | "packers/bitmono/0.45.0",
            "bitmono_bitdecompiler.exe"
            | "bitmono_bitdotnet.exe"
            | "bitmono_maximum.exe"
            | "bitmono_packer.exe"
            | "bitmono_pe_combined.exe",
        ) => Some(Disagreement::Refuses(BITMONO_HEADERS)),
        ("metadata/sections", "raw_past_file.exe" | "virtual_size_zero.exe") => {
            Some(Disagreement::ReadsOtherwise(
                "neither the .NET Framework nor CoreCLR runs it (factory/oracle.tsv); dotscope \
                 reads it leniently, as sections.rs records, where SRM reads no data in a \
                 section of VirtualSize 0 or past the file",
            ))
        }
        (
            "packers/confuserex/1.6.0",
            "mkaring_invalidmetadata.exe" | "mkaring_invalidmetadata_antitamper.exe",
        ) => Some(Disagreement::Refuses(
            "SRM refuses the tables ConfuserEx adds to the compressed tables stream; the .NET \
             Framework runs it (factory/oracle.tsv)",
        )),
        _ => None,
    }
}

/// How many differences a failure lists before it counts the rest.
const LISTED: usize = 60;

/// The differences between dotscope's dump of `fixture` and SRM's, `dotscope != SRM`.
fn differences(fixture: &str, srm: &CanonicalDump) -> Vec<String> {
    if fixture.ends_with(".pdb") {
        let ours = CanonicalDump::of_pdb(fixture_bytes(fixture)).without_reasons();
        // A file both readers refuse is refused for their own reasons
        if ours.entries().contains_key(REFUSED) && srm.entries().contains_key(REFUSED) {
            return Vec::new();
        }
        return ours
            .diff(srm)
            .into_iter()
            .map(|line| format!("{fixture}: {line}"))
            .collect();
    }
    let view = CilAssemblyView::from_mem_with_validation(
        fixture_bytes(fixture).to_vec(),
        ValidationConfig::disabled(),
    );
    let ours = match view {
        Ok(view) => CanonicalDump::of(&view).without_reasons(),
        Err(error) => return vec![format!("{fixture}: dotscope cannot read it: {error}")],
    };
    ours.diff(srm)
        .into_iter()
        .map(|line| format!("{fixture}: {line}"))
        .collect()
}

fn assert_none(findings: &[String], what: &str) {
    assert!(
        findings.is_empty(),
        "{} {what} (dotscope's value first):\n{}{}",
        findings.len(),
        findings
            .iter()
            .take(LISTED)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        if findings.len() > LISTED {
            format!("\n... and {} more", findings.len().saturating_sub(LISTED))
        } else {
            String::new()
        }
    );
}

/// The goldens under `dir`, as the fixture paths they are named after.
fn goldens(dir: &Path, prefix: &str, found: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            goldens(&path, &format!("{prefix}{name}/"), found);
        } else {
            let fixture = name.strip_suffix(".json").unwrap_or_else(|| {
                panic!("{prefix}{name} in tests/oracle/goldens is not a golden")
            });
            found.insert(format!("{prefix}{fixture}"));
        }
    }
}

#[test]
fn every_srm_fixture_reads_as_its_golden() {
    let fixtures = srm_fixtures();
    assert!(!fixtures.is_empty(), "the manifest tags no fixture `srm`");
    let mut committed = BTreeSet::new();
    goldens(&goldens_dir(), "", &mut committed);
    let tagged: BTreeSet<String> = fixtures.iter().map(ToString::to_string).collect();
    assert_eq!(
        committed, tagged,
        "the goldens and the fixtures tagged `srm` differ: run `make oracle-goldens`"
    );
    let findings: Vec<String> = fixtures
        .iter()
        .flat_map(|fixture| differences(fixture, &read_dump(&goldens_dir(), fixture).unwrap()))
        .collect();
    assert_none(&findings, "differences from System.Reflection.Metadata");
}

#[test]
fn the_srm_dumper_writes_the_goldens() {
    if require_tool(ToolKind::MonoCompiler).is_none() {
        return;
    }
    let fixtures = srm_fixtures();
    let written = tempfile::tempdir().unwrap();
    SrmDumper::build()
        .unwrap()
        .dump(&fixtures, written.path())
        .unwrap();
    let stale: Vec<String> = fixtures
        .iter()
        .filter(|fixture| {
            let name = format!("{fixture}.json");
            fs::read(written.path().join(&name)).unwrap()
                != fs::read(goldens_dir().join(&name)).unwrap()
        })
        .map(|fixture| format!("{fixture}: the golden is not what the dumper writes"))
        .collect();
    assert_none(&stale, "stale goldens: run `make oracle-goldens`");
}

#[test]
fn every_corpus_assembly_reads_as_srm_reads_it() {
    if require_tool(ToolKind::MonoCompiler).is_none() {
        return;
    }
    sweep(&[&ReadsAsSrm::new(disagreement).unwrap()]).assert_clean();
}

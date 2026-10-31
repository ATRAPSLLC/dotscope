//! The committed test fixtures under `tests/samples`, named by their path relative to it.
//!
//! A fixture is resolved through the crate's manifest directory, never the working directory,
//! and a missing one fails the test that asked for it: a committed fixture is never skipped.
//! `tests/samples/MANIFEST.toml` lists every file with its hash, provenance and license, and the
//! unit test below holds the tree to it. An entry's `suites` are tags that select it for a tier
//! or a sweep (`quick-corpus`); they are curated by hand, like `source` and `license`.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

/// The directory the fixtures live in.
pub fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

/// The path of fixture `rel`, a file or directory under `tests/samples`.
///
/// # Panics
///
/// When the fixture is missing: it is listed in `tests/samples/MANIFEST.toml` and committed.
pub fn fixture(rel: &str) -> PathBuf {
    let path = samples_dir().join(rel);
    assert!(
        path.exists(),
        "fixture `{rel}` is missing from tests/samples (every fixture is committed and listed in \
         tests/samples/MANIFEST.toml)"
    );
    path
}

/// The bytes of fixture `rel`, read once per test binary.
///
/// # Panics
///
/// When the fixture is missing or cannot be read.
pub fn fixture_bytes(rel: &str) -> &'static [u8] {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.entry(rel.to_string()).or_insert_with(|| {
        let bytes = std::fs::read(fixture(rel))
            .unwrap_or_else(|e| panic!("fixture `{rel}` cannot be read: {e}"));
        Box::leak(bytes.into_boxed_slice())
    })
}

/// One fixture as `tests/samples/MANIFEST.toml` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    /// The SHA-256 of its bytes, in hex.
    pub sha256: String,
    /// Where it came from.
    pub source: String,
    /// The license it is under.
    pub license: String,
    /// The suites it is tagged for.
    pub suites: Vec<String>,
    /// For an input malformed by design, the error that loading it must fail with, without
    /// the source locations an error names (see [`without_locations`]): ECMA-335 or the CLR
    /// refuses the file, and so must dotscope. `None` for a fixture that must load. Written
    /// by hand, never by a refresh: it states what the file is.
    pub reject: Option<String>,
}

/// The fixtures `tests/samples/MANIFEST.toml` lists, by path, read once per test binary.
///
/// # Panics
///
/// When the manifest is missing or is not the TOML [`parse_manifest`] reads.
pub fn manifest() -> &'static BTreeMap<String, Fixture> {
    static MANIFEST: OnceLock<BTreeMap<String, Fixture>> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let path = samples_dir().join("MANIFEST.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} cannot be read: {e}", path.display()));
        parse_manifest(&text)
    })
}

/// `message` without the ` (path/to/file.rs:123)` locations dotscope's errors carry, which
/// move with every edit to the file that raised them.
pub fn without_locations(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(open) = rest.find(" (") {
        let (before, from) = rest.split_at(open);
        out.push_str(before);
        let location = from.find(')').and_then(|close| {
            let inner = from.get(2..close)?;
            let (file, line) = inner.rsplit_once(':')?;
            (file.ends_with(".rs") && !file.contains(' ') && line.parse::<u32>().is_ok())
                .then_some(close)
        });
        match location {
            Some(close) => rest = from.get(close.saturating_add(1)..).unwrap_or_default(),
            None => {
                out.push_str(from.get(..2).unwrap_or_default());
                rest = from.get(2..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    out
}

/// `s` as a TOML basic string: quoted, with backslashes, quotes and control characters escaped.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `manifest` as `tests/samples/MANIFEST.toml` holds it.
fn render_manifest(manifest: &BTreeMap<String, Fixture>) -> String {
    let mut text = String::from(
        "# Every committed test fixture under tests/samples: its hash, provenance, license and\n\
         # the suites it is tagged for. `source`, `license`, `suites` and `reject` are edited by\n\
         # hand; after adding, changing or removing fixtures, refresh paths and hashes with\n\
         #   DOTSCOPE_WRITE_MANIFEST=1 cargo test --lib -- testkit::fixtures\n\
         # `reject` names the error a fixture malformed by design must fail to load with.\n",
    );
    for (path, entry) in manifest {
        let suites: Vec<String> = entry.suites.iter().map(|s| quote(s)).collect();
        text.push_str(&format!(
            "\n[[fixture]]\npath = {}\nsha256 = {}\nsource = {}\nlicense = {}\nsuites = [{}]\n",
            quote(path),
            quote(&entry.sha256),
            quote(&entry.source),
            quote(&entry.license),
            suites.join(", ")
        ));
        if let Some(reject) = &entry.reject {
            text.push_str(&format!("reject = {}\n", quote(reject)));
        }
    }
    text
}

/// The fixtures a manifest's text lists, by path.
///
/// # Panics
///
/// When `text` is not TOML, or an entry lacks `path`, `sha256`, `source`, `license` or
/// `suites`.
fn parse_manifest(text: &str) -> BTreeMap<String, Fixture> {
    let table: toml::Table = text.parse().expect("MANIFEST.toml is TOML");
    let string = |value: &toml::Value, key: &str| {
        value
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("manifest entry without `{key}`: {value}"))
            .to_string()
    };
    table
        .get("fixture")
        .and_then(toml::Value::as_array)
        .expect("[[fixture]] entries")
        .iter()
        .map(|value| {
            let suites = value
                .get("suites")
                .and_then(toml::Value::as_array)
                .unwrap_or_else(|| panic!("manifest entry without `suites`: {value}"))
                .iter()
                .map(|s| s.as_str().expect("a suite is a string").to_string())
                .collect();
            let reject = value
                .get("reject")
                .map(|reject| reject.as_str().expect("`reject` is a string").to_string());
            (
                string(value, "path"),
                Fixture {
                    sha256: string(value, "sha256"),
                    source: string(value, "source"),
                    license: string(value, "license"),
                    suites,
                    reject,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path, process::Command, time::Duration};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::testkit::tools::run_with_timeout;

    /// The files under `root` that git would commit, by their path relative to it: tracked
    /// ones, and untracked ones the repository's ignore rules leave in (a `.DS_Store` is not a
    /// fixture). A committed file deleted from the working tree is not among them, so the
    /// manifest test reports it missing.
    fn committable(root: &Path) -> BTreeSet<String> {
        let output = run_with_timeout(
            Command::new("git")
                .args([
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                ])
                .args(["--", "."])
                .current_dir(root),
            Duration::from_secs(120),
        )
        .expect("git lists the fixtures");
        assert!(
            output.status.success(),
            "git ls-files: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
            .stdout
            .split(|&b| b == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .filter(|rel| rel != "MANIFEST.toml" && root.join(rel).is_file())
            .collect()
    }

    fn sha256(path: &Path) -> String {
        let bytes = fs::read(path).expect("readable");
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The provenance a new fixture is listed with, by where it lives. Entries already in the
    /// manifest keep theirs: it is edited by hand from then on.
    fn provenance(rel: &str) -> (&'static str, &'static str) {
        let first = rel.split('/').next().unwrap_or_default();
        let family = rel.split('/').nth(1).unwrap_or_default();
        match (first, family) {
            ("packers", "netreactor") => (
                ".NET Reactor 7.5 (licensed Windows install) over TestApp, packers/regenerate.sh",
                "TestApp Apache-2.0; the code the protector injects under the protector's license",
            ),
            ("packers", "source") => (
                "TestApp and ResourceTestApp, the sources every packer sample is built from",
                "Apache-2.0",
            ),
            ("packers", _) => (
                "sample factory (tests/samples/factory): the protector over TestApp",
                "TestApp Apache-2.0; the code the protector injects under the protector's license",
            ),
            ("factory", _) => ("the sample factory itself", "Apache-2.0"),
            ("metadata", _) | ("debug", _) => (
                "sample factory (tests/samples/factory): TestApp built or rewritten per variant",
                "test sample generated by the project from its TestApp (Apache-2.0)",
            ),
            ("pdb", _) => (
                "sample factory (tests/samples/factory): PdbProbe built per debug form",
                "test sample generated by the project from its PdbProbe (Apache-2.0)",
            ),
            ("winmd", _) => (
                "win32metadata project: Windows.Wdk.winmd",
                "MIT (microsoft/win32metadata)",
            ),
            ("fuzz-regressions", _) => (
                "cargo-fuzz inputs that once crashed or hung dotscope",
                "Apache-2.0",
            ),
            ("dotnet_10.0", _) => (
                ".NET 10 shared framework assemblies",
                "MIT (dotnet/runtime)",
            ),
            (mono, _) if mono.starts_with("mono_") => (
                "Mono framework assemblies of that profile",
                "mixed: Mono class libraries MIT; bundled Microsoft libraries under their own \
                 licenses",
            ),
            _ if rel.starts_with("WB_") || rel == "WindowsBase.dll" => (
                "WindowsBase.dll 8.0.6 of the .NET 8 Windows Desktop runtime (dotnet/wpf \
                 86a51738), and sections cut from it",
                "MIT (dotnet/wpf)",
            ),
            _ => ("built for dotscope's tests", "Apache-2.0"),
        }
    }

    /// The manifest after a refresh: the tree's files and hashes, each listed entry keeping its
    /// hand-written fields, each new one taking its provenance from where it lives.
    fn refreshed(
        listed: &BTreeMap<String, Fixture>,
        tree: &BTreeMap<String, String>,
    ) -> BTreeMap<String, Fixture> {
        tree.iter()
            .map(|(path, sha256)| {
                let entry = listed.get(path).cloned().unwrap_or_else(|| {
                    let (source, license) = provenance(path);
                    Fixture {
                        sha256: String::new(),
                        source: source.to_string(),
                        license: license.to_string(),
                        suites: Vec::new(),
                        reject: None,
                    }
                });
                let entry = Fixture {
                    sha256: sha256.clone(),
                    ..entry
                };
                (path.clone(), entry)
            })
            .collect()
    }

    #[test]
    fn the_manifest_lists_every_fixture_as_it_is() {
        let root = samples_dir();
        let path = root.join("MANIFEST.toml");
        let tree: BTreeMap<String, String> = committable(&root)
            .into_iter()
            .map(|rel| {
                let hash = sha256(&root.join(&rel));
                (rel, hash)
            })
            .collect();
        let text = fs::read_to_string(&path).unwrap_or_default();
        if std::env::var_os("DOTSCOPE_WRITE_MANIFEST").is_some() {
            let listed = if text.is_empty() {
                BTreeMap::new()
            } else {
                parse_manifest(&text)
            };
            fs::write(&path, render_manifest(&refreshed(&listed, &tree))).expect("writable");
        }
        let listed =
            parse_manifest(&fs::read_to_string(&path).expect("tests/samples/MANIFEST.toml"));

        let unlisted: Vec<&String> = tree.keys().filter(|p| !listed.contains_key(*p)).collect();
        let missing: Vec<&String> = listed.keys().filter(|p| !tree.contains_key(*p)).collect();
        let changed: Vec<&String> = tree
            .iter()
            .filter(|(p, hash)| listed.get(*p).is_some_and(|e| e.sha256 != **hash))
            .map(|(p, _)| p)
            .collect();
        assert!(
            unlisted.is_empty() && missing.is_empty() && changed.is_empty(),
            "tests/samples and MANIFEST.toml disagree: unlisted {unlisted:?}, missing {missing:?}, \
             changed {changed:?} (refresh with DOTSCOPE_WRITE_MANIFEST=1)"
        );
    }

    #[test]
    fn a_refresh_keeps_the_hand_written_fields() {
        let listed = BTreeMap::from([
            (
                "kept.exe".to_string(),
                Fixture {
                    sha256: "old".to_string(),
                    source: "by hand".to_string(),
                    license: "MIT".to_string(),
                    suites: vec!["quick-corpus".to_string()],
                    reject: Some("Assembly table contains 2 rows \"quoted\"".to_string()),
                },
            ),
            (
                "removed.exe".to_string(),
                Fixture {
                    sha256: "gone".to_string(),
                    source: String::new(),
                    license: String::new(),
                    suites: Vec::new(),
                    reject: None,
                },
            ),
        ]);
        let tree = BTreeMap::from([
            ("kept.exe".to_string(), "new".to_string()),
            ("mono_4.8/added.dll".to_string(), "fresh".to_string()),
        ]);
        let manifest = refreshed(&listed, &tree);
        assert_eq!(
            manifest.keys().collect::<Vec<_>>(),
            ["kept.exe", "mono_4.8/added.dll"]
        );
        assert_eq!(
            manifest["kept.exe"],
            Fixture {
                sha256: "new".to_string(),
                ..listed["kept.exe"].clone()
            }
        );
        assert_eq!(manifest["mono_4.8/added.dll"].sha256, "fresh");
        assert_eq!(
            manifest["mono_4.8/added.dll"].source,
            provenance("mono_4.8/added.dll").0
        );
        assert_eq!(parse_manifest(&render_manifest(&manifest)), manifest);
    }

    #[test]
    fn an_error_is_compared_without_its_source_locations() {
        assert_eq!(
            without_locations(
                "Failed to load (a) type: read past end (dotscope/src/a.rs:12) (src/b/c.rs:345)"
            ),
            "Failed to load (a) type: read past end"
        );
        assert_eq!(
            without_locations("stream (offset 4) reaches past the end (2 bytes)"),
            "stream (offset 4) reaches past the end (2 bytes)"
        );
    }

    #[test]
    fn a_fixture_resolves_through_the_manifest_directory() {
        let path = fixture("crafted_2.exe");
        assert!(path.is_absolute());
        assert_eq!(
            fixture_bytes("crafted_2.exe"),
            fs::read(&path).expect("readable")
        );
    }

    #[test]
    #[should_panic(expected = "fixture `no/such/fixture.exe` is missing")]
    fn a_missing_fixture_fails_the_test() {
        let _ = fixture("no/such/fixture.exe");
    }
}

//! The System.Reflection.Metadata oracle: `tests/oracle/srm-dump`, a C# program that writes an
//! assembly's [`CanonicalDump`] from what Microsoft's reader reads in the file, and its goldens.
//!
//! The dumper is built with Mono's C# compiler against the System.Reflection.Metadata the
//! fixtures hold (`mono_4.5`, pinned by its manifest hash) and runs under Mono. The fixtures
//! the manifest tags with the suite [`SRM_SUITE`] have their dumps committed under
//! `tests/oracle/goldens/<fixture path>.json`, so the comparison needs no .NET tool; `make
//! oracle-goldens` writes them again, and the oracle tier checks that the dumper still writes
//! exactly what is committed.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::{
    metadata::validation::ValidationConfig,
    testkit::{
        corpus::{CorpusCheck, CorpusItem},
        dump::CanonicalDump,
        fixtures::{fixture, manifest, samples_dir},
        tools::run_with_timeout,
    },
    CilAssemblyView, Error, Result,
};

/// How many differences an assembly reports before it counts the rest.
const LISTED_DIFFERENCES: usize = 10;

/// The one entry of the dump of a file System.Reflection.Metadata refuses: why.
pub const REFUSED: &str = "Image";

/// The manifest suite of the fixtures with a committed golden.
pub const SRM_SUITE: &str = "srm";

/// The System.Reflection.Metadata build the dumper runs against, and what it needs.
const SRM_ASSEMBLIES: [&str; 2] = [
    "mono_4.5/System.Reflection.Metadata.dll",
    "mono_4.5/System.Collections.Immutable.dll",
];

/// The directory the goldens live in.
pub fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/goldens")
}

/// The fixtures the manifest tags with [`SRM_SUITE`], in path order.
pub fn srm_fixtures() -> Vec<&'static str> {
    manifest()
        .iter()
        .filter(|(_, fixture)| fixture.suites.iter().any(|suite| suite == SRM_SUITE))
        .map(|(path, _)| path.as_str())
        .collect()
}

/// The dump the dumper wrote for `fixture` into `dir`.
///
/// # Errors
///
/// When the file cannot be read or does not hold a dump.
pub fn read_dump(dir: &Path, fixture: &str) -> Result<CanonicalDump> {
    let path = dir.join(format!("{fixture}.json"));
    let json = fs::read_to_string(&path)
        .map_err(|error| Error::Other(format!("{}: {error}", path.display())))?;
    CanonicalDump::from_json(&json).map_err(|error| Error::Other(format!("{fixture}: {error}")))
}

/// The dumper, built.
pub struct SrmDumper {
    dir: tempfile::TempDir,
}

impl SrmDumper {
    /// Builds the dumper with `mcs` into a directory of its own, next to the assemblies it
    /// references.
    ///
    /// # Errors
    ///
    /// When the compiler cannot be run or rejects the program.
    pub fn build() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let mut command = Command::new("mcs");
        command
            .current_dir(dir.path())
            .args(["-unsafe", "-out:SrmDump.exe"]);
        for assembly in SRM_ASSEMBLIES {
            let name = Path::new(assembly).file_name().unwrap();
            fs::copy(fixture(assembly), dir.path().join(name))?;
            command.arg(format!("-r:{}", name.to_string_lossy()));
        }
        command.arg("-r:Facades/System.Runtime.dll").arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/srm-dump/SrmDump.cs"),
        );
        let output = run_with_timeout(&mut command, Duration::from_secs(300))?;
        if !output.status.success() {
            return Err(Error::Other(format!(
                "mcs cannot build the SRM dumper: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(Self { dir })
    }

    /// Writes the dump of each fixture in `fixtures` to `<output>/<fixture>.json`.
    ///
    /// # Errors
    ///
    /// When Mono cannot run the dumper or it fails.
    pub fn dump(&self, fixtures: &[&str], output: &Path) -> Result<()> {
        // Mono writes its crash reports into the working directory: the dumper's own
        let mut command = Command::new("mono");
        command
            .current_dir(self.dir.path())
            .arg("SrmDump.exe")
            .arg(samples_dir())
            .arg(output)
            .args(fixtures);
        let output = run_with_timeout(&mut command, Duration::from_secs(3600))?;
        if !output.status.success() {
            return Err(Error::Other(format!(
                "the SRM dumper fails: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }
}

/// Where System.Reflection.Metadata is not the authority on a file, and why: a fixture whose
/// reading the runtime itself decides otherwise, as another test shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disagreement {
    /// SRM refuses the file, which dotscope reads.
    Refuses(&'static str),
    /// SRM reads the file otherwise than dotscope, which reads it as the runtime does.
    ReadsOtherwise(&'static str),
}

/// Every corpus assembly reads as System.Reflection.Metadata reads it: the dumper's dump of
/// the file and dotscope's [`CanonicalDump`] of it hold the same, path by path.
///
/// dotscope's side is the file as [`CilAssemblyView`] reads it without validation: the dump is
/// about what the bytes hold, and a validator's refusal is the [`Loads`](super::corpus::Loads)
/// check's to hold a fixture to. A fixture whose manifest entry `reject`s it and that dotscope
/// does not read at all is likewise left to that check. A fixture SRM is not the authority on
/// is declared, with its reason, and the declaration is held: SRM must refuse it, or read it
/// otherwise, as declared.
pub struct ReadsAsSrm {
    dumper: SrmDumper,
    declared: fn(&str) -> Option<Disagreement>,
}

impl ReadsAsSrm {
    /// The check, with the dumper built, and `declared` naming each fixture's
    /// [`Disagreement`].
    ///
    /// # Errors
    ///
    /// When the dumper cannot be built.
    pub fn new(declared: fn(&str) -> Option<Disagreement>) -> Result<Self> {
        Ok(Self {
            dumper: SrmDumper::build()?,
            declared,
        })
    }
}

impl CorpusCheck for ReadsAsSrm {
    fn id(&self) -> &'static str {
        "srm.oracle"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let srm = tempfile::tempdir().map_err(Error::from).and_then(|dir| {
            self.dumper.dump(&[item.path], dir.path())?;
            read_dump(dir.path(), item.path)
        });
        let srm = match srm {
            Ok(srm) => srm,
            Err(error) => return vec![error.to_string()],
        };
        // A standalone Portable PDB is dumped as one, by both readers
        if item.path.ends_with(".pdb") {
            let ours = match item.bytes() {
                Ok(bytes) => CanonicalDump::of_pdb(&bytes).without_reasons(),
                Err(error) => return vec![error],
            };
            // A file both readers refuse is refused for their own reasons
            if ours.entries().contains_key(REFUSED) && srm.entries().contains_key(REFUSED) {
                return Vec::new();
            }
            return ours
                .diff(&srm)
                .into_iter()
                .take(LISTED_DIFFERENCES)
                .collect();
        }
        let ours = match item.bytes() {
            Ok(bytes) => {
                CilAssemblyView::from_mem_with_validation(bytes, ValidationConfig::disabled())
            }
            Err(error) => return vec![error],
        };
        // A file the dumper's reader refuses is dumped as one entry saying why
        let refused = srm.entries().get(REFUSED);
        let declared = (self.declared)(item.path);
        let ours = match (ours, refused, declared) {
            (Ok(_), Some(_), Some(Disagreement::Refuses(_))) => return Vec::new(),
            (_, _, Some(Disagreement::Refuses(why))) => {
                return vec![format!("declared refused by SRM ({why}), yet it is not")]
            }
            (Ok(_), Some(why), _) => {
                return vec![format!("SRM refuses it ({why}), dotscope reads it")]
            }
            (Err(_), Some(_), _) => return Vec::new(),
            (Err(_), None, _) if item.fixture.reject.is_some() => return Vec::new(),
            (Err(error), None, _) => return vec![format!("dotscope cannot read it: {error}")],
            (Ok(view), None, _) => CanonicalDump::of(&view).without_reasons(),
        };
        let differences = ours.diff(&srm);
        if let Some(Disagreement::ReadsOtherwise(why)) = declared {
            return if differences.is_empty() {
                vec![format!(
                    "declared read otherwise by SRM ({why}), yet it reads the same"
                )]
            } else {
                Vec::new()
            };
        }
        let more = differences.len().saturating_sub(LISTED_DIFFERENCES);
        let mut findings: Vec<String> = differences.into_iter().take(LISTED_DIFFERENCES).collect();
        if more > 0 {
            findings.push(format!("{more} more differences"));
        }
        findings
    }
}

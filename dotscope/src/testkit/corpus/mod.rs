//! Sweeps over the corpus: every assembly `tests/samples/MANIFEST.toml` lists, loaded once and
//! handed to each check in turn, assemblies in parallel.
//!
//! A [`CorpusCheck`] states a property every assembly must have and reports, line by line,
//! what one assembly gets wrong. A sweep is clean when no check reports anything. There is no
//! list of failures to expect: a fixture malformed by design says so in its manifest entry's
//! `reject`, and [`Loads`] holds it to exactly that error.
//!
//! [`CORPUS_FILTER`] narrows a sweep to the fixtures whose path contains one of its
//! comma-separated parts, and [`CORPUS_REPORT`] names a file a failing sweep writes all its
//! findings to.

use std::{
    collections::BTreeMap,
    panic::{self, AssertUnwindSafe},
    sync::{Mutex, OnceLock},
};

use crate::{
    analysis::{SsaVerifier, VerifyLevel},
    metadata::streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
    testkit::fixtures::{manifest, samples_dir, without_locations, Fixture},
    CilAssemblyView, CilObject,
};

mod codecs;
#[cfg(feature = "compiler")]
mod codegen;
mod determinism;
mod identity;
mod writer;

pub use codecs::{
    BodyCode, CustomAttributes, ExceptionStructure, Marshalling, MethodBodies, PermissionSets,
    Signatures,
};
#[cfg(feature = "compiler")]
pub use codegen::CodegenEquivalence;
pub use determinism::Deterministic;
pub(crate) use identity::raw_tables;
pub use identity::{Heaps, TableRows};
pub use writer::WritesBackUnchanged;

/// The environment variable that narrows a sweep: comma-separated parts, one of which a
/// fixture's path must contain.
pub const CORPUS_FILTER: &str = "DOTSCOPE_CORPUS_FILTER";

/// The environment variable naming a file a failing sweep writes every finding to, where its
/// panic message lists a few per check.
pub const CORPUS_REPORT: &str = "DOTSCOPE_CORPUS_REPORT";

/// How many assemblies a sweep holds loaded at once: the largest lift to gigabytes of SSA.
const MAX_THREADS: usize = 8;

/// How many findings a check lists in a report before it counts the rest.
const LISTED_FINDINGS: usize = 40;

/// One corpus assembly: its manifest entry, and the assembly once a check asks for it.
pub struct CorpusItem {
    /// Its path under `tests/samples`.
    pub path: &'static str,
    /// Its manifest entry.
    pub fixture: &'static Fixture,
    object: OnceLock<Result<CilObject, String>>,
    view: OnceLock<Result<CilAssemblyView, String>>,
}

/// An assembly's tables and heaps, from whichever of its loads succeeded.
pub struct Metadata<'a> {
    /// The tables stream.
    pub tables: Option<&'a TablesHeader<'a>>,
    /// The `#Strings` heap.
    pub strings: Option<&'a Strings<'a>>,
    /// The `#US` heap.
    pub userstrings: Option<&'a UserStrings<'a>>,
    /// The `#Blob` heap.
    pub blobs: Option<&'a Blob<'a>>,
    /// The `#GUID` heap.
    pub guids: Option<&'a Guid<'a>>,
}

impl CorpusItem {
    /// The item for the manifest entry `fixture` at `path`.
    #[must_use]
    pub fn new(path: &'static str, fixture: &'static Fixture) -> Self {
        Self {
            path,
            fixture,
            object: OnceLock::new(),
            view: OnceLock::new(),
        }
    }

    /// The assembly's file bytes.
    ///
    /// # Errors
    ///
    /// When the file cannot be read.
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        std::fs::read(samples_dir().join(self.path))
            .map_err(|error| format!("cannot be read: {error}"))
    }

    /// The assembly's tables and heaps: the loaded [`CilObject`]'s, or for one that does not
    /// load (a fixture malformed by design among them), a [`CilAssemblyView`]'s. `None` when
    /// neither reads the file.
    pub fn metadata(&self) -> Option<Metadata<'_>> {
        if let Ok(object) = self.object() {
            return Some(Metadata {
                tables: object.tables(),
                strings: object.strings(),
                userstrings: object.userstrings(),
                blobs: object.blob(),
                guids: object.guids(),
            });
        }
        let view = self
            .view
            .get_or_init(|| {
                CilAssemblyView::from_mem(self.bytes()?)
                    .map_err(|error| without_locations(&error.to_string()))
            })
            .as_ref()
            .ok()?;
        Some(Metadata {
            tables: view.tables(),
            strings: view.strings(),
            userstrings: view.userstrings(),
            blobs: view.blobs(),
            guids: view.guids(),
        })
    }

    /// The assembly as [`CilObject::from_mem`] loads it, with the validation it applies by
    /// default, or the error loading it fails with, without its source locations.
    ///
    /// # Errors
    ///
    /// The load's error, as [`without_locations`] states it.
    pub fn object(&self) -> Result<&CilObject, &str> {
        self.object
            .get_or_init(|| {
                CilObject::from_mem(self.bytes()?)
                    .map_err(|error| without_locations(&error.to_string()))
            })
            .as_ref()
            .map_err(String::as_str)
    }
}

/// A property every corpus assembly must have.
pub trait CorpusCheck: Sync {
    /// The check's name in a report.
    fn id(&self) -> &'static str;

    /// What `item` gets wrong, a line per finding: empty when it has the property.
    fn run(&self, item: &CorpusItem) -> Vec<String>;

    /// What the check counted, by kind, over the items it ran on since it was last asked,
    /// without finding a defect in them: cases it could not decide, say. Asking drains the
    /// counts, so each sweep reports its own. The sweep reports them with its findings, so
    /// nothing a check passes over goes unseen.
    fn take_tallies(&self) -> BTreeMap<String, usize> {
        BTreeMap::new()
    }
}

/// What a sweep found.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// How many assemblies it swept.
    pub assemblies: usize,
    /// Each check's findings, as `path: finding`, in path order. A check that found nothing
    /// has no entry.
    pub findings: BTreeMap<&'static str, Vec<String>>,
    /// Each check's [tallies](CorpusCheck::take_tallies). A check that counted nothing has no
    /// entry.
    pub tallies: BTreeMap<&'static str, BTreeMap<String, usize>>,
}

impl SweepReport {
    /// Each check's tallies, a line per kind.
    #[must_use]
    pub fn tally_lines(&self) -> String {
        let mut lines = String::new();
        for (check, tallies) in &self.tallies {
            for (kind, count) in tallies {
                lines.push_str(&format!("{check}: {count:>9}  {kind}\n"));
            }
        }
        lines
    }

    /// Whether no check found anything.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Prints the tallies, then asserts nothing was found.
    ///
    /// # Panics
    ///
    /// When a check found anything: the message lists the findings, check by check, and the
    /// tallies.
    pub fn assert_clean(&self) {
        assert!(self.assemblies > 0, "the sweep found no assemblies");
        eprint!("{}", self.tally_lines());
        if self.is_clean() {
            return;
        }
        if let Some(path) = std::env::var_os(CORPUS_REPORT) {
            let all: Vec<String> = self
                .findings
                .iter()
                .flat_map(|(check, findings)| findings.iter().map(move |f| format!("{check}\t{f}")))
                .collect();
            if let Err(error) = std::fs::write(&path, all.join("\n")) {
                eprintln!("{CORPUS_REPORT}: {error}");
            }
        }
        let mut message = format!("{} assemblies swept:\n", self.assemblies);
        for (check, findings) in &self.findings {
            message.push_str(&format!("{check}: {} findings\n", findings.len()));
            for finding in findings.iter().take(LISTED_FINDINGS) {
                message.push_str(&format!("  {finding}\n"));
            }
            if let Some(more) = findings
                .len()
                .checked_sub(LISTED_FINDINGS)
                .filter(|n| *n > 0)
            {
                message.push_str(&format!("  ... and {more} more\n"));
            }
        }
        message.push_str(&self.tally_lines());
        panic!("{message}");
    }
}

/// The corpus: every `.dll`, `.exe` and `.winmd` the manifest lists, narrowed by
/// [`CORPUS_FILTER`].
#[must_use]
pub fn corpus() -> Vec<CorpusItem> {
    let filter = std::env::var(CORPUS_FILTER).ok();
    manifest()
        .iter()
        .filter(|(path, _)| {
            [".dll", ".exe", ".winmd"]
                .iter()
                .any(|kind| path.ends_with(kind))
        })
        .filter(|(path, _)| {
            filter
                .as_deref()
                .is_none_or(|filter| filter.split(',').any(|part| path.contains(part)))
        })
        .map(|(path, fixture)| CorpusItem::new(path, fixture))
        .collect()
}

/// Runs `checks` over the [`corpus`].
#[must_use]
pub fn sweep(checks: &[&dyn CorpusCheck]) -> SweepReport {
    sweep_items(corpus(), checks)
}

/// Runs `checks` over `items`: an item's checks in order on one thread, while the item alone
/// holds its assembly, and items on a few threads at once. A check that panics reports the
/// panic.
///
/// The threads are the sweep's own, not a rayon pool's: loading an assembly runs rayon work,
/// and a rayon worker that waits on it may take another item's checks onto the same stack.
#[must_use]
pub fn sweep_items(items: Vec<CorpusItem>, checks: &[&dyn CorpusCheck]) -> SweepReport {
    let report = Mutex::new(SweepReport {
        assemblies: items.len(),
        ..SweepReport::default()
    });
    let queue = Mutex::new(items.into_iter());
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_THREADS);
    let next = || {
        queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next()
    };
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while let Some(item) = next() {
                    for check in checks {
                        let findings = panic::catch_unwind(AssertUnwindSafe(|| check.run(&item)))
                            .unwrap_or_else(|payload| {
                                vec![format!("panicked: {}", panic_text(&*payload))]
                            });
                        if findings.is_empty() {
                            continue;
                        }
                        report
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .findings
                            .entry(check.id())
                            .or_default()
                            .extend(
                                findings
                                    .into_iter()
                                    .map(|finding| format!("{}: {finding}", item.path)),
                            );
                    }
                }
            });
        }
    });
    let mut report = report
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for findings in report.findings.values_mut() {
        findings.sort();
    }
    for check in checks {
        let tallies = check.take_tallies();
        if !tallies.is_empty() {
            report.tallies.insert(check.id(), tallies);
        }
    }
    report
}

/// A panic's message, when it carried one.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
        })
        .unwrap_or_else(|| "a panic without a message".to_string())
}

/// Every assembly loads, except one malformed by design, which fails with exactly the error
/// its manifest entry's `reject` names.
pub struct Loads;

impl CorpusCheck for Loads {
    fn id(&self) -> &'static str {
        "load"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        match (item.object(), item.fixture.reject.as_deref()) {
            (Ok(_), None) => Vec::new(),
            (Err(error), Some(expected)) if error == expected => Vec::new(),
            (Ok(_), Some(expected)) => {
                vec![format!(
                    "loads, but its manifest entry has it rejected with: {expected}"
                )]
            }
            (Err(error), None) => vec![format!("rejected: {error}")],
            (Err(error), Some(expected)) => vec![format!(
                "rejected with: {error}\n    its manifest entry has: {expected}"
            )],
        }
    }
}

/// Every method with a body lifts to SSA, and the verifier accepts what it lifts to. An
/// assembly that does not load is [`Loads`]' finding, not this one's.
pub struct Lifts;

impl CorpusCheck for Lifts {
    fn id(&self) -> &'static str {
        "ssa.lift"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Ok(assembly) = item.object() else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        for entry in assembly.methods().iter() {
            let method = entry.value();
            if method.body.get().is_none() {
                continue;
            }
            let name = || {
                let owner = method
                    .declaring_type_rc()
                    .map(|owner| owner.fullname())
                    .unwrap_or_default();
                format!("{owner}::{} ({:#010x})", method.name, method.token.value())
            };
            match method.ssa(assembly) {
                Err(error) => findings.push(format!("{}: {error}", name())),
                Ok(ssa) => {
                    let errors = SsaVerifier::new(&ssa).verify(VerifyLevel::Standard);
                    if let Some(first) = errors.first() {
                        findings.push(format!(
                            "{}: {} verifier findings, the first {first:?}",
                            name(),
                            errors.len()
                        ));
                    }
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A check that reports each item's path, and one that panics.
    struct Names;
    struct Panics;

    /// A check that finds nothing and counts the items it ran on.
    #[derive(Default)]
    struct Counts(Mutex<usize>);

    impl CorpusCheck for Counts {
        fn id(&self) -> &'static str {
            "counts"
        }

        fn run(&self, _item: &CorpusItem) -> Vec<String> {
            *self.0.lock().unwrap() += 1;
            Vec::new()
        }

        fn take_tallies(&self) -> BTreeMap<String, usize> {
            BTreeMap::from([(
                "items".to_string(),
                std::mem::take(&mut *self.0.lock().unwrap()),
            )])
        }
    }

    impl CorpusCheck for Names {
        fn id(&self) -> &'static str {
            "names"
        }

        fn run(&self, item: &CorpusItem) -> Vec<String> {
            vec![item.path.to_string()]
        }
    }

    impl CorpusCheck for Panics {
        fn id(&self) -> &'static str {
            "panics"
        }

        fn run(&self, _item: &CorpusItem) -> Vec<String> {
            panic!("the check broke");
        }
    }

    /// `crafted_2.exe` with the manifest entry `reject` gives it.
    fn crafted(reject: Option<&str>) -> CorpusItem {
        let fixture = Fixture {
            reject: reject.map(str::to_string),
            ..manifest()["crafted_2.exe"].clone()
        };
        CorpusItem::new("crafted_2.exe", Box::leak(Box::new(fixture)))
    }

    #[test]
    fn a_sweep_reports_every_finding_and_every_panic() {
        let report = sweep_items(vec![crafted(None), crafted(None)], &[&Names, &Panics]);
        assert_eq!(report.assemblies, 2);
        assert_eq!(report.findings["names"].len(), 2);
        assert_eq!(
            report.findings["panics"],
            ["crafted_2.exe: panicked: the check broke"; 2]
        );
        assert!(!report.is_clean());
    }

    /// What a check counts is reported with the sweep, each sweep its own.
    #[test]
    fn a_sweep_reports_each_checks_tallies() {
        let counts = Counts::default();
        for _ in 0..2 {
            let report = sweep_items(vec![crafted(None), crafted(None)], &[&counts]);
            assert!(report.is_clean());
            assert_eq!(report.tallies["counts"]["items"], 2);
            assert!(report.tally_lines().contains("counts:         2  items"));
        }
    }

    #[test]
    fn a_fixture_is_held_to_the_rejection_its_entry_names() {
        assert!(Loads.run(&crafted(None)).is_empty());
        let loads_but_rejected = Loads.run(&crafted(Some("anything")));
        assert!(
            loads_but_rejected[0].starts_with("loads, but"),
            "{loads_but_rejected:?}"
        );
    }

    #[test]
    fn a_corpus_lists_only_assemblies() {
        let corpus = corpus();
        assert!(corpus.iter().all(|item| [".dll", ".exe", ".winmd"]
            .iter()
            .any(|kind| item.path.ends_with(kind))));
        assert!(corpus.iter().any(|item| item.path.ends_with(".winmd")));
    }
}

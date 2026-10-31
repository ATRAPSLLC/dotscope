//! The validator test harness.
//!
//! A validator's test hands [`validator_test`] or [`owned_validator_test`] a factory of
//! [`TestAssembly`]s: a clean assembly the validator accepts, and crafted ones that each break
//! one rule. Every crafted case states the [`ExpectedError`] the validator must reject it with,
//! so a case never passes on an unrelated failure. The harness first sets each case up (load
//! the bytes, scan references, load the project for an owned validator); a case it cannot set
//! up fails the test whichever way it was expected to go, because the validator never ran.
//! Every case runs, and every mismatch is reported together.

use std::{fmt::Write as _, io::Write, panic::Location, path::PathBuf};

use tempfile::NamedTempFile;

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{
            OwnedValidationContext, RawValidationContext, ReferenceScanner, ValidationConfig,
        },
    },
    testkit::fixtures::fixture,
    Error, Result,
};

/// The error a crafted case must draw from the validator under test: text its message
/// contains, naming the rule the case breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedError(String);

impl ExpectedError {
    /// The validator's message must contain `text`.
    ///
    /// # Panics
    ///
    /// When `text` is blank: it would match any rejection.
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        assert!(
            !text.trim().is_empty(),
            "an expected error names the rule the case breaks"
        );
        Self(text)
    }

    /// Whether `message` is this rejection.
    pub fn matches(&self, message: &str) -> bool {
        message.contains(&self.0)
    }
}

/// What a test assembly must do under the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// The validator accepts it.
    Pass,
    /// The validator rejects it with this error.
    Fail(ExpectedError),
    /// The loader refuses it with this error before any validator runs: the rule is enforced
    /// at load. A case moves to [`Expect::Fail`] when a lenient load lets it through.
    Refused(ExpectedError),
}

impl Expect {
    /// A rejection whose message contains `text` (see [`ExpectedError::new`]).
    pub fn fail(text: impl Into<String>) -> Self {
        Self::Fail(ExpectedError::new(text))
    }

    /// A refusal at load whose message contains `text` (see [`ExpectedError::new`]).
    pub fn refused(text: impl Into<String>) -> Self {
        Self::Refused(ExpectedError::new(text))
    }
}

/// Where a test assembly's bytes come from.
#[derive(Debug)]
pub enum TestAssemblySource {
    /// File-backed assembly with path and optional temp file for cleanup
    File {
        path: PathBuf,
        _temp_file: Option<NamedTempFile>,
    },
    /// In-memory assembly data (zero-copy from generation)
    Memory(Vec<u8>),
}

/// One validation scenario: an assembly and what the validator must do with it.
#[derive(Debug)]
pub struct TestAssembly {
    /// Source of the assembly data
    pub source: TestAssemblySource,
    /// Whether the validator accepts it, or the error it rejects it with
    pub expect: Expect,
    /// Where the case was made, so a report names the factory that made it
    pub origin: &'static Location<'static>,
}

impl TestAssembly {
    /// A clean assembly file, which the validator accepts.
    #[track_caller]
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            source: TestAssemblySource::File {
                path: path.into(),
                _temp_file: None,
            },
            expect: Expect::Pass,
            origin: Location::caller(),
        }
    }

    /// An assembly in memory, with what the validator must do with it.
    #[track_caller]
    pub fn from_bytes(data: Vec<u8>, expect: Expect) -> Self {
        Self {
            source: TestAssemblySource::Memory(data),
            expect,
            origin: Location::caller(),
        }
    }

    /// Where the case was made, and what it holds, for reports.
    pub fn description(&self) -> String {
        match &self.source {
            TestAssemblySource::File { path, .. } => {
                format!("{} ({})", self.origin, path.display())
            }
            TestAssemblySource::Memory(data) => {
                format!("{} ({} bytes)", self.origin, data.len())
            }
        }
    }

    /// Loads this assembly as a `CilAssemblyView` with validation disabled.
    ///
    /// Used by the test harness to load assemblies for validator testing.
    pub fn load(&self) -> Result<CilAssemblyView> {
        match &self.source {
            TestAssemblySource::File { path, .. } => {
                CilAssemblyView::from_path_with_validation(path, ValidationConfig::disabled())
            }
            TestAssemblySource::Memory(data) => CilAssemblyView::from_mem_with_validation(
                data.clone(),
                ValidationConfig::disabled(),
            ),
        }
    }
}

/// File factory function type for creating test assemblies.
///
/// This function creates one or more test assemblies with specific validation issues.
/// Each assembly should target exactly one validation rule to ensure test isolation.
pub type FileFactory = fn() -> Result<Vec<TestAssembly>>;

/// What happened to one case.
enum Outcome {
    /// The harness could not set the case up: the validator never ran.
    SetupFailed(Error),
    /// The validator accepted the assembly.
    Accepted,
    /// The validator rejected the assembly.
    Rejected(Error),
}

/// Runs every case of `file_factory` through `run` and checks each outcome against its
/// expectation.
fn run_cases(
    file_factory: FileFactory,
    validator_name: &str,
    run: impl Fn(&TestAssembly) -> Outcome,
) -> Result<()> {
    let cases = file_factory()?;
    let mut failures = String::new();
    let mut clean = 0;
    for case in &cases {
        let outcome = run(case);
        let mismatch = match (&case.expect, outcome) {
            (Expect::Refused(expected), Outcome::SetupFailed(e)) => {
                let message = e.to_string();
                (!expected.matches(&message)).then(|| {
                    format!("refused at load for another reason, expected {expected:?}: {message}")
                })
            }
            (Expect::Refused(expected), _) => Some(format!(
                "loaded it, expected the loader to refuse it with {expected:?}"
            )),
            (_, Outcome::SetupFailed(e)) => Some(format!(
                "the harness could not set the case up, so {validator_name} never ran: {e}"
            )),
            (Expect::Pass, Outcome::Accepted) => None,
            (Expect::Pass, Outcome::Rejected(e)) => Some(format!("rejected a clean assembly: {e}")),
            (Expect::Fail(expected), Outcome::Accepted) => Some(format!(
                "accepted it, expected a rejection with {expected:?}"
            )),
            (Expect::Fail(expected), Outcome::Rejected(e)) => {
                let message = e.to_string();
                (!expected.matches(&message)).then(|| {
                    format!("rejected it for another reason, expected {expected:?}: {message}")
                })
            }
        };
        if case.expect == Expect::Pass {
            clean += 1;
        }
        if let Some(mismatch) = mismatch {
            let _ = writeln!(failures, "  {}: {mismatch}", case.description());
        }
    }
    if clean == 0 {
        let _ = writeln!(
            failures,
            "  no clean assembly: nothing shows the validator accepts valid metadata"
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "{validator_name}: {} of {} cases went wrong:\n{failures}",
            failures.lines().count(),
            cases.len()
        )))
    }
}

/// Runs a raw validator over every case of `file_factory` and checks each outcome.
///
/// # Errors
///
/// When the factory fails, or any case does not go the way it says: a clean assembly
/// rejected, a crafted one accepted or rejected for another reason, or a case the harness
/// could not set up.
pub fn validator_test<F>(
    file_factory: FileFactory,
    validator_name: &str,
    validation_config: ValidationConfig,
    run_validator: F,
) -> Result<()>
where
    F: Fn(&RawValidationContext) -> Result<()>,
{
    run_cases(file_factory, validator_name, |case| {
        let view = match case.load() {
            Ok(view) => view,
            Err(e) => return Outcome::SetupFailed(e),
        };
        let scanner = match ReferenceScanner::from_view(&view) {
            Ok(scanner) => scanner,
            Err(e) => return Outcome::SetupFailed(e),
        };
        let context = RawValidationContext::new_for_loading(&view, &scanner, &validation_config);
        match run_validator(&context) {
            Ok(()) => Outcome::Accepted,
            Err(e) => Outcome::Rejected(e),
        }
    })
}

/// Runs an owned validator over every case of `file_factory` and checks each outcome; the
/// same as [`validator_test`] over the resolved [`crate::CilObject`] of each case, loaded with
/// its mono_4.8 dependencies.
///
/// # Errors
///
/// As [`validator_test`].
pub fn owned_validator_test<F>(
    file_factory: FileFactory,
    validator_name: &str,
    validation_config: ValidationConfig,
    run_validator: F,
) -> Result<()>
where
    F: Fn(&OwnedValidationContext) -> Result<()>,
{
    run_cases(
        file_factory,
        validator_name,
        |case| match owned_context_outcome(case, &validation_config, &run_validator) {
            Ok(outcome) => outcome,
            Err(e) => Outcome::SetupFailed(e),
        },
    )
}

/// Sets a case up for an owned validator and runs it; `Err` is a setup failure.
fn owned_context_outcome<F>(
    assembly: &TestAssembly,
    config: &ValidationConfig,
    run_validator: &F,
) -> Result<Outcome>
where
    F: Fn(&OwnedValidationContext) -> Result<()>,
{
    let assembly_view = assembly.load()?;

    // ProjectLoader reads files: a case in memory goes through a temporary one.
    let _temp_file: Option<NamedTempFile>;
    let primary_path: PathBuf = match &assembly.source {
        TestAssemblySource::File { path, .. } => path.clone(),
        TestAssemblySource::Memory(data) => {
            let mut temp = NamedTempFile::new()?;
            temp.write_all(data)?;
            let path = temp.path().to_path_buf();
            _temp_file = Some(temp);
            path
        }
    };

    // Strict, so a case that does not load fails here instead of reaching the validator
    // half-loaded; unvalidated, so only the validator under test judges it.
    let project_result = crate::project::ProjectLoader::new()
        .primary_file(&primary_path)?
        .with_search_path(fixture("mono_4.8"))?
        .auto_discover(true)
        .strict_mode(true)
        .with_validation(ValidationConfig::disabled())
        .build()?;
    let object = project_result
        .project
        .get_primary()
        .ok_or_else(|| Error::Other("the project has no primary assembly".to_string()))?;

    let scanner = ReferenceScanner::from_view(&assembly_view)?;
    let context = OwnedValidationContext::new(object.as_ref(), &scanner, config);
    Ok(match run_validator(&context) {
        Ok(()) => Outcome::Accepted,
        Err(e) => Outcome::Rejected(e),
    })
}

/// The clean test file (WindowsBase.dll) for validator testing.
///
/// # Panics
///
/// When the fixture is missing (see [`fixture`]).
pub fn get_testfile_wb() -> PathBuf {
    fixture("WindowsBase.dll")
}

/// Returns path to crafted_2.exe for use as a clean test assembly with proper identity.
///
/// This is preferred over WindowsBase.dll for validation tests that create new types,
/// since crafted_2.exe has its own identity and created types will be recognized
/// as target assembly types.
///
/// # Panics
///
/// When the fixture is missing (see [`fixture`]).
pub fn get_testfile_crafted2() -> PathBuf {
    fixture("crafted_2.exe")
}

/// Returns path to mscorlib.dll for use as a completely self-contained test assembly.
///
/// This is the best choice for modification tests that don't need to test cross-assembly
/// dependencies, since mscorlib.dll has zero external dependencies and is completely
/// self-contained. This makes tests faster and more reliable than using assemblies
/// with many dependencies.
///
/// # Panics
///
/// When the fixture is missing (see [`fixture`]).
pub fn get_testfile_mscorlib() -> PathBuf {
    fixture("mono_4.8/mscorlib.dll")
}

/// `System.Object`'s TypeDef row in [`get_testfile_mscorlib`], the base a crafted type of it
/// extends (mscorlib has no TypeRefs to extend through).
pub const MSCORLIB_OBJECT_TYPEDEF: u32 = 167;

/// The RVA of `System.Object::.ctor`'s body in [`get_testfile_mscorlib`]: a real method body
/// for a crafted method that must have one.
pub const MSCORLIB_OBJECT_CTOR_RVA: u32 = 15404;

//! ProjectLoader builder API for flexible assembly loading.
//!
//! This module provides the `ProjectLoader` builder-style API for loading .NET assemblies
//! with automatic dependency resolution, confined to the search directories, and a load
//! that leaves out a dependency that fails rather than failing the whole project.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Component, Path, PathBuf},
    sync::Arc,
    thread,
};

use log::{debug, info, warn};

use crate::{
    file::File,
    metadata::{
        cilassemblyview::CilAssemblyView, cilobject::CilObject, identity::AssemblyIdentity,
        validation::ValidationConfig,
    },
    project::{context::ProjectContext, ProjectResult},
    Error, Result,
};

/// Builder for creating and loading CilProject instances with flexible dependency management.
///
/// `ProjectLoader` provides a builder-style API for loading .NET assemblies with automatic
/// dependency resolution. A dependency that is missing, or fails to read or load, is
/// reported in the [`ProjectResult`] and left out, and the rest of the project loads
/// without it (unless [`Self::strict_mode`] is set). This addresses the common scenario
/// where individual assemblies fail to load due to missing dependencies.
///
/// # Usage Examples
///
/// ## Basic Single Assembly Loading
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Multi-Assembly with Manual Dependencies
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_dependency("MyLib.dll")?
///     .with_dependency("System.Core.dll")?
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Automatic Discovery with Search Path
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_search_path("/path/to/dependencies")?
///     .auto_discover(true)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct ProjectLoader {
    /// Primary assembly file path - the main entry point
    primary_file: Option<PathBuf>,
    /// Additional dependency files to load
    dependency_files: Vec<PathBuf>,
    /// Search paths for automatic dependency discovery
    search_paths: Vec<PathBuf>,
    /// Whether to automatically discover and load dependencies
    auto_discover: bool,
    /// Whether a dependency that is missing, mismatched or fails to load fails the build
    strict_mode: bool,
    /// Validation configuration to apply during loading
    validation_config: Option<ValidationConfig>,
    /// The most assemblies one build loads, the primary included
    max_assemblies: usize,
    /// The simple name of an assembly whose load panics, to test that a panic in a loading
    /// thread is contained.
    #[cfg(test)]
    panic_on_load: Option<String>,
}

/// The longest simple assembly name the loader probes for, in bytes: the CLR's
/// `MAX_CLASSNAME_LENGTH`, the bound its binder puts on an assembly name.
const MAX_ASSEMBLY_NAME_LENGTH: usize = 1024;

/// The default bound on the number of assemblies one build loads
/// ([`ProjectLoader::max_assemblies`]).
const DEFAULT_MAX_ASSEMBLIES: usize = 4096;

impl ProjectLoader {
    /// Create a new ProjectLoader builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary_file: None,
            dependency_files: Vec::new(),
            search_paths: Vec::new(),
            auto_discover: false,
            strict_mode: false,
            validation_config: None,
            max_assemblies: DEFAULT_MAX_ASSEMBLIES,
            #[cfg(test)]
            panic_on_load: None,
        }
    }

    /// Set the primary assembly file.
    ///
    /// This is the main entry point of the project and will be loaded first.
    /// All dependency resolution will be performed relative to this assembly.
    ///
    /// # Arguments
    /// * `path` - Path to the primary assembly file (.exe or .dll)
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not readable.
    pub fn primary_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::Configuration(format!(
                "Primary file does not exist: {}",
                path.display()
            )));
        }
        self.primary_file = Some(path.to_path_buf());
        Ok(self)
    }

    /// Add a specific dependency file to load.
    ///
    /// Dependencies added through this method will be loaded regardless of
    /// whether they are discovered through automatic dependency analysis.
    ///
    /// # Arguments
    /// * `path` - Path to the dependency assembly file
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not readable.
    pub fn with_dependency<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::Configuration(format!(
                "Dependency file does not exist: {}",
                path.display()
            )));
        }
        self.dependency_files.push(path.to_path_buf());
        Ok(self)
    }

    /// Add a search path for automatic dependency discovery.
    ///
    /// When auto-discovery is enabled, these paths will be searched for
    /// assemblies that match dependencies referenced by the primary assembly.
    /// The search paths are probed in the order they were added, then the primary
    /// assembly's own directory.
    ///
    /// A dependency is only ever loaded from inside one of these directories: its
    /// AssemblyRef name must be a simple file name (no path separators, drive, `..` or
    /// NUL), and a candidate file that resolves, through a symbolic link, to a place
    /// outside its directory is refused and reported in
    /// [`ProjectResult::failed_loads`].
    ///
    /// # Arguments
    /// * `path` - Directory path to search for dependencies
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not a directory.
    pub fn with_search_path<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() || !path.is_dir() {
            return Err(Error::Configuration(format!(
                "Search path does not exist or is not a directory: {}",
                path.display()
            )));
        }
        self.search_paths.push(path.to_path_buf());
        Ok(self)
    }

    /// Enable or disable automatic dependency discovery.
    ///
    /// When enabled, the loader will analyze the primary assembly's references
    /// and attempt to locate and load matching assemblies from the search paths.
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable automatic discovery
    #[must_use]
    pub fn auto_discover(mut self, enabled: bool) -> Self {
        self.auto_discover = enabled;
        self
    }

    /// Enable or disable strict mode.
    ///
    /// In strict mode the build fails on the first dependency problem: a dependency
    /// that is not found, a reference whose name is not a valid simple assembly name, a
    /// candidate file outside its search directory, or a dependency that fails to read
    /// or load.
    ///
    /// A dependency found only in a version that does not satisfy the reference
    /// ([`AssemblyIdentity::satisfies`]) is loaded and recorded in `version_mismatches`
    /// in both modes: that check asks for the same major version, while the .NET Core
    /// binder accepts any higher one, so it would refuse projects the runtime loads.
    ///
    /// In non-strict mode (default) each such problem is recorded in the
    /// [`ProjectResult`] (`missing_dependencies`, `version_mismatches`, `failed_loads`)
    /// and the project is built from the assemblies that load. A dependency that fails
    /// to load is left out of the project, and the other assemblies are loaded without
    /// it. The primary assembly failing to load fails the build in both modes.
    ///
    /// # Arguments
    /// * `strict` - Whether to enable strict mode
    #[must_use]
    pub fn strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Set validation configuration for the loaded assemblies.
    ///
    /// The one configuration applies to every assembly of the project, when its file is
    /// read and when it is loaded. Without it, [`ValidationConfig::production`] applies.
    ///
    /// # Arguments
    /// * `config` - Validation configuration to apply
    #[must_use]
    pub fn with_validation(mut self, config: ValidationConfig) -> Self {
        self.validation_config = Some(config);
        self
    }

    /// Set the most assemblies one build loads, the primary included (default 4096).
    ///
    /// Every assembly of a project loads on its own thread at once, so the bound keeps a
    /// dependency closure that grows without end, such as a directory of generated
    /// assemblies referencing one another, from exhausting threads and memory. A build
    /// that would load more fails.
    ///
    /// # Arguments
    /// * `max` - The largest number of assemblies to load
    #[must_use]
    pub fn max_assemblies(mut self, max: usize) -> Self {
        self.max_assemblies = max;
        self
    }

    /// Make the load of the assembly named `name` panic, to test that the panic is
    /// contained.
    #[cfg(test)]
    fn panic_on_load(mut self, name: &str) -> Self {
        self.panic_on_load = Some(name.to_string());
        self
    }

    /// Build the CilProject with the configured settings.
    ///
    /// This method performs the actual loading and returns a unified ProjectResult
    /// containing both the loaded project and loading statistics. The loading process includes:
    ///
    /// 1. Read the primary assembly, then the explicitly specified dependencies
    /// 2. Perform automatic dependency discovery (if enabled): each referenced name is
    ///    probed for once, in the search paths and then the primary's directory, and each
    ///    file is read once
    /// 3. Load every discovered assembly, each on its own thread, with the type
    ///    registries linked for cross-assembly resolution
    /// 4. Apply validation (if configured)
    ///
    /// A dependency that fails to load, by an error or a panic, is left out and the
    /// others are loaded again without it, so no other assembly of the project fails
    /// because of it (see [`Self::strict_mode`]).
    ///
    /// # Returns
    /// A `ProjectResult` containing the loaded project and metadata about
    /// the loading process (success/failure counts, missing dependencies, etc.)
    ///
    /// # Errors
    /// Returns an error if:
    /// - No primary file was specified
    /// - The primary file cannot be read or loaded, or fails validation; the error is
    ///   the primary's own
    /// - Strict mode is enabled and a dependency is missing, misnamed, outside its
    ///   search directory or fails to load
    /// - More assemblies would load than [`Self::max_assemblies`] allows
    /// - A search path cannot be resolved to a canonical directory
    pub fn build(self) -> Result<ProjectResult> {
        let primary_file = self.primary_file.as_deref().ok_or_else(|| {
            Error::Configuration(
                "No primary file specified. Use primary_file() to set the main assembly."
                    .to_string(),
            )
        })?;
        info!("Loading project: primary={}", primary_file.display());

        let primary_path = canonical_path(primary_file)?;
        let primary_dir = primary_path.parent().ok_or_else(|| {
            Error::Configuration("Cannot determine parent directory of root file".to_string())
        })?;

        let mut roots = Vec::with_capacity(self.search_paths.len().saturating_add(1));
        for search_path in &self.search_paths {
            let root = canonical_path(search_path)?;
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        if !roots.iter().any(|root| root == primary_dir) {
            roots.push(primary_dir.to_path_buf());
        }

        let validation = self
            .validation_config
            .unwrap_or_else(ValidationConfig::production);
        let mut result = ProjectResult::new();
        let mut discovery = Discovery {
            loader: &self,
            validation,
            roots,
            assemblies: Vec::new(),
            by_path: HashMap::new(),
            probes: HashMap::new(),
            mismatches: HashSet::new(),
            result: &mut result,
        };
        discovery.discover(&primary_path)?;
        let assemblies = discovery.assemblies;
        debug!("Loading {} discovered assemblies", assemblies.len());

        self.load_assemblies(assemblies, validation, &mut result)?;

        info!(
            "Project loaded: {}/{} assemblies",
            result.success_count(),
            result
                .success_count()
                .saturating_add(result.failure_count())
        );
        Ok(result)
    }

    /// Load the discovered assemblies, each on its own thread, in rounds.
    ///
    /// The threads of a round meet at the barriers of a [`ProjectContext`], so the type
    /// registries can link to one another while each loads. A thread whose load fails,
    /// by an error or by a panic (caught here, so it never reaches the barriers' waiters
    /// as a hang), breaks the barriers, which aborts every other load of the round: the
    /// first assembly to fail is the only one known to have failed on its own. It is
    /// recorded and left out, and the next round loads the others again without it.
    /// Each round leaves out one assembly, so the rounds end. The primary failing ends
    /// the build with its error, and in strict mode so does any dependency failing.
    ///
    /// Every thread of a round is joined before the round's outcome is looked at, so no
    /// thread outlives the build.
    fn load_assemblies(
        &self,
        mut assemblies: Vec<Discovered>,
        validation: ValidationConfig,
        result: &mut ProjectResult,
    ) -> Result<()> {
        // A deterministic order, whatever order discovery found them in.
        assemblies.sort_by(|a, b| a.identity.cmp(&b.identity));

        loop {
            // The first round loads the views discovery read; a later one reads the files
            // again, since a load consumes its view.
            let mut views = Vec::with_capacity(assemblies.len());
            let mut unreadable = None;
            for (index, assembly) in assemblies.iter_mut().enumerate() {
                let view = match assembly.view.take() {
                    Some(view) => Ok(view),
                    None => read_assembly(&assembly.path, validation).map(|(view, _)| view),
                };
                match view {
                    Ok(view) => views.push(view),
                    Err(error) => {
                        unreadable = Some((index, error));
                        break;
                    }
                }
            }
            if let Some((index, error)) = unreadable {
                let assembly = assemblies.remove(index);
                self.leave_out(&assembly, error, result)?;
                continue;
            }

            let context = Arc::new(ProjectContext::new(views.len())?);
            let handles: Vec<_> = assemblies
                .iter()
                .zip(views)
                .map(|(assembly, view)| self.spawn_load(&context, assembly, view, validation))
                .collect();
            // Join every thread before looking at any outcome.
            let outcomes: Vec<Result<CilObject>> = assemblies
                .iter()
                .zip(handles)
                .map(|(assembly, handle)| {
                    let joined = handle.and_then(|handle| {
                        handle.join().unwrap_or_else(|payload| {
                            Err(Error::Other(format!(
                                "the thread loading {} panicked: {}",
                                assembly.identity.name,
                                panic_message(payload.as_ref())
                            )))
                        })
                    });
                    if let Err(error) = &joined {
                        // A thread that never ran its load, or died outside it, has not
                        // released the barriers itself.
                        context.abort(&assembly.identity, &error.to_string());
                    }
                    joined
                })
                .collect();

            let Some(first_failure) = context.first_failure().cloned() else {
                for (assembly, outcome) in assemblies.iter().zip(outcomes) {
                    result.project.add_assembly(outcome?, assembly.is_primary)?;
                    result.record_success(assembly.identity.clone());
                }
                return Ok(());
            };

            let index = assemblies
                .iter()
                .position(|assembly| assembly.identity == first_failure)
                .ok_or_else(|| {
                    Error::Other(format!(
                        "the failed assembly {} is not one of the round's",
                        first_failure.name
                    ))
                })?;
            let error = outcomes
                .into_iter()
                .nth(index)
                .and_then(Result::err)
                .unwrap_or_else(|| Error::Other(format!("{} failed to load", first_failure.name)));
            let assembly = assemblies.remove(index);
            self.leave_out(&assembly, error, result)?;
            info!(
                "Loading the project again without {}",
                assembly.identity.name
            );
        }
    }

    /// Start the thread loading one assembly of a round.
    ///
    /// The load runs under `catch_unwind`, so a panic, a loader's own or one rayon
    /// re-raises from its pool, becomes the assembly's error. A thread that ends without
    /// a loaded assembly, however it ends, breaks the round's barriers, so no other
    /// thread waits for it forever.
    ///
    /// # Errors
    /// Returns an error when the thread cannot be started; the caller then breaks the
    /// barriers for it.
    fn spawn_load(
        &self,
        context: &Arc<ProjectContext>,
        assembly: &Discovered,
        view: CilAssemblyView,
        validation: ValidationConfig,
    ) -> Result<thread::JoinHandle<Result<CilObject>>> {
        let guard = AbortGuard {
            context: Arc::clone(context),
            identity: assembly.identity.clone(),
            loaded: false,
        };
        #[cfg(test)]
        let inject_panic = self.panic_on_load.as_deref() == Some(assembly.identity.name.as_str());
        thread::Builder::new()
            .name(format!("dotscope-load-{}", assembly.identity.name))
            .spawn(move || {
                // Move the whole guard in (a closure would capture only the fields it
                // names, and the guard must drop here, with the thread).
                let mut guard = guard;
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if inject_panic {
                        panic!("injected panic loading {}", guard.identity.name);
                    }
                    CilObject::from_project(view, guard.context.as_ref(), validation)
                }))
                .unwrap_or_else(|payload| {
                    Err(Error::Other(format!(
                        "loading {} panicked: {}",
                        guard.identity.name,
                        panic_message(payload.as_ref())
                    )))
                });
                match &outcome {
                    Ok(_) => guard.loaded = true,
                    Err(error) => guard.context.abort(
                        &guard.identity,
                        &format!("Assembly {} failed to load: {error}", guard.identity.name),
                    ),
                }
                outcome
            })
            .map_err(|error| {
                Error::Other(format!(
                    "cannot start the thread loading {}: {error}",
                    assembly.identity.name
                ))
            })
    }

    /// Leave a dependency that failed to load out of the project, or fail the build when
    /// it is the primary or the build is strict.
    ///
    /// # Errors
    /// Returns the primary's own error when `assembly` is the primary, and the
    /// dependency's error in strict mode.
    fn leave_out(
        &self,
        assembly: &Discovered,
        error: Error,
        result: &mut ProjectResult,
    ) -> Result<()> {
        if assembly.is_primary {
            return Err(error);
        }
        if self.strict_mode {
            return Err(Error::Configuration(format!(
                "Failed to load {} in strict mode: {error}",
                assembly.identity.name
            )));
        }
        warn!(
            "Leaving {} out of the project: {error}",
            assembly.identity.name
        );
        result.record_failure(assembly.identity.name.to_string(), error.to_string());
        Ok(())
    }
}

impl Default for ProjectLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// One assembly discovery found for the project.
struct Discovered {
    /// The assembly's identity, from its Assembly row
    identity: AssemblyIdentity,
    /// The canonical path of its file
    path: PathBuf,
    /// The view read during discovery, until the first load round takes it
    view: Option<CilAssemblyView>,
    /// Whether this is the project's primary assembly
    is_primary: bool,
}

/// A file found for a referenced name, read and kept until a reference chooses it.
struct Candidate {
    /// The canonical path of the file
    path: PathBuf,
    /// The identity its Assembly row declares
    identity: AssemblyIdentity,
    /// The view read from it, until the candidate joins the project
    view: Option<CilAssemblyView>,
}

/// The discovery of a project's assemblies: the primary, the explicit dependencies and,
/// with auto-discovery, every assembly their references reach.
struct Discovery<'a> {
    /// The loader's settings
    loader: &'a ProjectLoader,
    /// The one validation configuration of the build
    validation: ValidationConfig,
    /// The canonical directories dependencies are found in, in probing order
    roots: Vec<PathBuf>,
    /// The assemblies found so far, in discovery order
    assemblies: Vec<Discovered>,
    /// The canonical path of every file read, to the identity it declares; a file is
    /// read once, whichever way it is reached
    by_path: HashMap<PathBuf, AssemblyIdentity>,
    /// The candidates found for each referenced name (lowercase, as the binder compares
    /// simple names case-insensitively); a name is probed for once
    probes: HashMap<String, Vec<Candidate>>,
    /// The version mismatches recorded, so each is recorded once
    mismatches: HashSet<(AssemblyIdentity, AssemblyIdentity)>,
    /// The report the problems are recorded in
    result: &'a mut ProjectResult,
}

impl Discovery<'_> {
    /// Discover the primary, the explicit dependencies and, with auto-discovery, the
    /// assemblies their references reach.
    ///
    /// # Errors
    /// Returns the primary's own error when it cannot be read; in strict mode, the first
    /// dependency problem; and an error when more assemblies are found than the loader
    /// allows.
    fn discover(&mut self, primary_path: &Path) -> Result<()> {
        let (view, identity) = read_assembly(primary_path, self.validation)?;
        self.add(primary_path.to_path_buf(), view, identity, true)?;

        let loader = self.loader;
        for file in &loader.dependency_files {
            let read = canonical_path(file).and_then(|path| {
                if self.by_path.contains_key(&path) {
                    return Ok(None);
                }
                read_assembly(&path, self.validation)
                    .map(|(view, identity)| Some((path, view, identity)))
            });
            match read {
                Ok(Some((path, view, identity))) => self.add(path, view, identity, false)?,
                Ok(None) => {}
                Err(error) => self.fail(file.display().to_string(), &error)?,
            }
        }

        if self.loader.auto_discover {
            let mut next = 0;
            while let Some(assembly) = self.assemblies.get(next) {
                let references = assembly
                    .view
                    .as_ref()
                    .map(CilAssemblyView::dependencies)
                    .unwrap_or_default();
                next = next.saturating_add(1);
                for required in references {
                    self.resolve(&required)?;
                }
            }
        }
        Ok(())
    }

    /// Add an assembly read from `path` to the project, unless one with its identity is
    /// already in it.
    ///
    /// # Errors
    /// Returns an error when the project would hold more assemblies than the loader
    /// allows.
    fn add(
        &mut self,
        path: PathBuf,
        view: CilAssemblyView,
        identity: AssemblyIdentity,
        is_primary: bool,
    ) -> Result<()> {
        self.by_path.insert(path.clone(), identity.clone());
        if self
            .assemblies
            .iter()
            .any(|known| known.identity == identity)
        {
            debug!("{} is already in the project", path.display());
            return Ok(());
        }
        if self.assemblies.len() >= self.loader.max_assemblies {
            return Err(Error::Configuration(format!(
                "The project would load more than {} assemblies (adding {})",
                self.loader.max_assemblies, identity.name
            )));
        }
        self.assemblies.push(Discovered {
            identity,
            path,
            view: Some(view),
            is_primary,
        });
        Ok(())
    }

    /// Find the assembly a reference names and add it to the project.
    ///
    /// The name is probed for once per build ([`Self::probe`]); each reference then
    /// takes the candidate that satisfies it, else the one whose version is closest.
    ///
    /// # Errors
    /// In strict mode, returns an error when the reference names no assembly or is not
    /// a valid simple name (a version mismatch is recorded in both modes, see
    /// [`ProjectLoader::strict_mode`]).
    fn resolve(&mut self, required: &AssemblyIdentity) -> Result<()> {
        if self
            .assemblies
            .iter()
            .any(|known| known.identity.satisfies(required))
        {
            return Ok(());
        }

        let key = required.name.to_ascii_lowercase();
        if !self.probes.contains_key(&key) {
            let candidates = self.probe(required)?;
            self.probes.insert(key.clone(), candidates);
        }
        let Some(candidates) = self.probes.get_mut(&key) else {
            return Ok(());
        };

        let mut best: Option<usize> = None;
        for (index, candidate) in candidates.iter().enumerate() {
            if candidate.identity.satisfies(required) {
                best = Some(index);
                break;
            }
            let dominated = best
                .and_then(|best| candidates.get(best))
                .is_some_and(|best| {
                    best.identity
                        .version
                        .is_closer_to(&candidate.identity.version, &required.version)
                });
            if !dominated {
                best = Some(index);
            }
        }
        let Some(candidate) = best.and_then(|best| candidates.get_mut(best)) else {
            // Not found: recorded once, when the name was probed for.
            return Ok(());
        };

        let actual = candidate.identity.clone();
        let path = candidate.path.clone();
        let view = candidate.view.take();
        if !actual.satisfies(required) && self.mismatches.insert((required.clone(), actual.clone()))
        {
            self.result
                .record_version_mismatch(required.clone(), actual.clone());
        }
        if let Some(view) = view {
            info!(
                "Resolved dependency: {} -> {}",
                required.name,
                path.display()
            );
            self.add(path, view, actual, false)?;
        }
        Ok(())
    }

    /// Probe the search directories for the files a referenced name may be in, and read
    /// each one found.
    ///
    /// The name comes from an AssemblyRef row of a file being analyzed, so it is checked
    /// to be a simple file name before it touches the file system, and each candidate is
    /// resolved to its canonical path and must lie inside the directory it was found in.
    /// A file already read is not read again. A candidate that is not a .NET assembly, or
    /// is a netmodule, is not the assembly the reference names and is passed over.
    ///
    /// # Errors
    /// In strict mode, returns an error for an invalid name, a candidate outside its
    /// directory, a candidate that fails to read, and a name with no candidate. A name
    /// whose only files were refused or unreadable is reported through those failures,
    /// not also as missing.
    fn probe(&mut self, required: &AssemblyIdentity) -> Result<Vec<Candidate>> {
        let name = required.name.as_str();
        if let Err(reason) = check_simple_name(name) {
            self.fail(
                format!("{name:?}"),
                &Error::Configuration(format!("not a valid assembly name: {reason}")),
            )?;
            return Ok(Vec::new());
        }

        let mut candidates: Vec<Candidate> = Vec::new();
        // Whether a file with the name was found but refused or unreadable, which is
        // reported as such instead of as a missing name.
        let mut reported = false;
        let roots = self.roots.clone();
        for root in &roots {
            for extension in ["dll", "exe"] {
                let probed = root.join(format!("{name}.{extension}"));
                let Ok(path) = std::fs::canonicalize(&probed) else {
                    continue;
                };
                if !path.starts_with(root) {
                    reported = true;
                    self.fail(
                        probed.display().to_string(),
                        &Error::Configuration(format!(
                            "resolves to {}, outside the search directory {}",
                            path.display(),
                            root.display()
                        )),
                    )?;
                    continue;
                }
                if candidates.iter().any(|candidate| candidate.path == path) {
                    continue;
                }
                if let Some(identity) = self.by_path.get(&path) {
                    candidates.push(Candidate {
                        path,
                        identity: identity.clone(),
                        view: None,
                    });
                    continue;
                }
                match read_candidate(&path, self.validation) {
                    Ok(Some((view, identity))) => {
                        self.by_path.insert(path.clone(), identity.clone());
                        candidates.push(Candidate {
                            path,
                            identity,
                            view: Some(view),
                        });
                    }
                    Ok(None) => debug!("{} is not a .NET assembly", path.display()),
                    Err(error) => {
                        reported = true;
                        self.fail(path.display().to_string(), &error)?;
                    }
                }
            }
        }

        if candidates.is_empty() && !reported {
            warn!(
                "Dependency not found: {} v{}",
                required.name, required.version
            );
            if self.loader.strict_mode {
                return Err(Error::Configuration(format!(
                    "Dependency {} v{} not found in strict mode",
                    required.name, required.version
                )));
            }
            self.result.record_missing(required.name.to_string());
        }
        Ok(candidates)
    }

    /// Record a dependency problem, or fail the build with it in strict mode.
    ///
    /// # Errors
    /// Returns the problem as an error in strict mode.
    fn fail(&mut self, subject: String, error: &Error) -> Result<()> {
        if self.loader.strict_mode {
            return Err(Error::Configuration(format!(
                "Failed to load {subject} in strict mode: {error}"
            )));
        }
        warn!("Failed to load {subject}: {error}");
        self.result.record_failure(subject, error.to_string());
        Ok(())
    }
}

/// Breaks a round's barriers when its loading thread ends without a loaded assembly,
/// however it ends.
///
/// The thread disarms it after a successful load. An error is reported to the barriers
/// with its message before the guard drops; the guard covers what escapes that, such as
/// a thread unwinding outside the caught load.
struct AbortGuard {
    /// The round's coordination context
    context: Arc<ProjectContext>,
    /// The assembly the thread loads
    identity: AssemblyIdentity,
    /// Whether the assembly loaded
    loaded: bool,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if !self.loaded {
            self.context.abort(
                &self.identity,
                &format!("Assembly {} did not finish loading", self.identity.name),
            );
        }
    }
}

/// Read a file as an assembly: a .NET image with an Assembly row.
///
/// # Errors
/// Returns the reading error, or an error naming the file when it is not a .NET image or
/// is a netmodule (a module without an Assembly row, which loads only as part of the
/// assembly whose File table names it).
fn read_assembly(
    path: &Path,
    validation: ValidationConfig,
) -> Result<(CilAssemblyView, AssemblyIdentity)> {
    let file = File::from_path(path)?;
    if !file.is_clr() {
        return Err(Error::Configuration(format!(
            "{} is not a .NET assembly: it has no CLR header",
            path.display()
        )));
    }
    let view = CilAssemblyView::from_dotscope_file_with_validation(file, validation)?;
    let identity = view.identity()?.ok_or_else(|| {
        Error::Configuration(format!(
            "{} is a netmodule (no Assembly row); load the assembly that owns it",
            path.display()
        ))
    })?;
    Ok((view, identity))
}

/// Read a probed file as an assembly, passing over a file that is not one.
///
/// # Returns
/// `None` for a file without a CLR header or without an Assembly row: a native image or
/// a netmodule that shares the referenced name, which is not the assembly referenced.
///
/// # Errors
/// Returns the error of a .NET image that fails to read.
fn read_candidate(
    path: &Path,
    validation: ValidationConfig,
) -> Result<Option<(CilAssemblyView, AssemblyIdentity)>> {
    let file = File::from_path(path)?;
    if !file.is_clr() {
        return Ok(None);
    }
    let view = CilAssemblyView::from_dotscope_file_with_validation(file, validation)?;
    Ok(view.identity()?.map(|identity| (view, identity)))
}

/// The canonical form of a path the caller named.
///
/// # Errors
/// Returns an error naming the path when it cannot be resolved.
fn canonical_path(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|error| {
        Error::Configuration(format!("Cannot resolve {}: {error}", path.display()))
    })
}

/// Check that a referenced assembly name is a simple name that is safe to probe for as a
/// file name inside a search directory.
///
/// The name comes from an AssemblyRef row of the file being analyzed. A name with a path
/// separator, a drive or alternate-stream colon, NUL, or that is `.` or `..`, would let
/// that file choose a path outside the search directories (an absolute path, a `..`
/// escape, or a UNC path that makes Windows connect to another host).
///
/// # Errors
/// Returns why the name is refused.
fn check_simple_name(name: &str) -> std::result::Result<(), &'static str> {
    if name.is_empty() {
        return Err("the name is empty");
    }
    if name.len() > MAX_ASSEMBLY_NAME_LENGTH {
        return Err("the name is longer than 1024 bytes");
    }
    if name.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0')) {
        return Err("the name contains a path separator, a colon or NUL");
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err("the name is not a single file name"),
    }
}

/// The message of a panic payload.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(ToString::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::{metadata::identity::AssemblyVersion, testkit::fixture};

    #[test]
    fn test_project_loader_basic_api() {
        // Test that the builder API compiles and has expected methods
        let _loader = ProjectLoader::new().auto_discover(true).strict_mode(false);

        // Test that Default works
        let _default_loader = ProjectLoader::default();
    }

    #[test]
    fn test_project_loader_validation_errors() {
        // Test that validation works for non-existent files
        let result = ProjectLoader::new().primary_file("/nonexistent/file.exe");

        assert!(result.is_err(), "Should fail for non-existent primary file");

        let result = ProjectLoader::new().with_dependency("/nonexistent/dep.dll");

        assert!(
            result.is_err(),
            "Should fail for non-existent dependency file"
        );

        let result = ProjectLoader::new().with_search_path("/nonexistent/directory");

        assert!(result.is_err(), "Should fail for non-existent search path");
    }

    #[test]
    fn test_project_loader_build_fails_without_primary() {
        // Test that build fails when no primary file is specified
        let result = ProjectLoader::new().build();

        assert!(
            result.is_err(),
            "Should fail when no primary file specified"
        );

        if let Err(e) = result {
            assert!(
                e.to_string().contains("No primary file specified"),
                "Error should mention missing primary file"
            );
        }
    }

    /// crafted_2.exe with two small mono assemblies as explicit dependencies: three
    /// loading threads meeting at the barriers.
    fn three_assemblies() -> ProjectLoader {
        ProjectLoader::new()
            .primary_file(fixture("crafted_2.exe"))
            .and_then(|loader| loader.with_dependency(fixture("mono_4.8/Mono.Tasklets.dll")))
            .and_then(|loader| loader.with_dependency(fixture("mono_4.8/SMDiagnostics.dll")))
            .expect("the fixtures exist")
    }

    fn loaded_names(result: &ProjectResult) -> Vec<&str> {
        result
            .loaded_assemblies
            .iter()
            .map(|identity| identity.name.as_str())
            .collect()
    }

    /// A panic while loading one dependency neither hangs the build nor fails the other
    /// assemblies: the panicking one is reported with the panic's message and the rest
    /// load without it. (Before the panic was caught, the other threads waited at a
    /// barrier forever and this test hung.)
    #[test]
    fn a_panicking_dependency_is_left_out_and_the_rest_load() {
        let result = three_assemblies()
            .panic_on_load("Mono.Tasklets")
            .build()
            .expect("a dependency's panic does not fail the build");

        assert_eq!(loaded_names(&result), ["SMDiagnostics", "crafted_2"]);
        assert!(result.project.get_primary().is_some());
        assert_eq!(result.failed_loads.len(), 1, "{:?}", result.failed_loads);
        let (subject, error) = &result.failed_loads[0];
        assert_eq!(subject, "Mono.Tasklets");
        assert!(error.contains("injected panic"), "{error}");
        assert!(result.missing_dependencies.is_empty());
    }

    /// A panic loading the primary fails the build with it, and in strict mode so does a
    /// panic loading a dependency.
    #[test]
    fn a_panic_fails_the_build_for_the_primary_or_in_strict_mode() {
        let error = three_assemblies()
            .panic_on_load("crafted_2")
            .build()
            .expect_err("the primary's panic fails the build");
        assert!(error.to_string().contains("injected panic"), "{error}");

        let error = three_assemblies()
            .strict_mode(true)
            .panic_on_load("SMDiagnostics")
            .build()
            .expect_err("a dependency's panic fails a strict build");
        let message = error.to_string();
        assert!(
            message.contains("SMDiagnostics") && message.contains("injected panic"),
            "{message}"
        );
    }

    /// A temporary directory holding a copy of crafted_2.exe, and nothing it references.
    fn lone_primary() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let primary = dir.path().join("crafted_2.exe");
        fs::copy(fixture("crafted_2.exe"), &primary).unwrap();
        (dir, primary)
    }

    /// Strict mode fails on a dependency that is not found; non-strict mode reports it as
    /// missing, and only as missing.
    #[test]
    fn strict_mode_fails_on_a_missing_dependency() {
        let (_dir, primary) = lone_primary();
        let loader = || {
            ProjectLoader::new()
                .primary_file(&primary)
                .unwrap()
                .auto_discover(true)
        };

        let error = loader()
            .strict_mode(true)
            .build()
            .expect_err("a strict build fails on a missing dependency");
        assert!(
            error
                .to_string()
                .contains("mscorlib v4.0.0.0 not found in strict mode"),
            "{error}"
        );

        let result = loader()
            .build()
            .expect("a non-strict build loads the primary");
        assert_eq!(loaded_names(&result), ["crafted_2"]);
        assert!(
            result
                .missing_dependencies
                .iter()
                .any(|name| name == "mscorlib"),
            "{:?}",
            result.missing_dependencies
        );
        assert!(result.failed_loads.is_empty(), "{:?}", result.failed_loads);
        assert_eq!(
            result.failure_count(),
            result.missing_dependencies.len(),
            "each missing name counts once"
        );
    }

    /// A dependency file that does not read is reported with its own error (not as a
    /// missing name, and not with a generic message), and the primary still loads; a
    /// primary that does not read fails the build even though its dependency reads.
    #[test]
    fn an_unreadable_file_reports_its_error_and_fails_only_as_primary() {
        let dir = TempDir::new().unwrap();
        let broken = dir.path().join("Broken.dll");
        fs::write(&broken, b"MZ not a PE image").unwrap();

        let result = ProjectLoader::new()
            .primary_file(fixture("crafted_2.exe"))
            .and_then(|loader| loader.with_dependency(&broken))
            .and_then(ProjectLoader::build)
            .expect("an unreadable dependency does not fail a non-strict build");
        assert_eq!(loaded_names(&result), ["crafted_2"]);
        assert!(result.missing_dependencies.is_empty());
        assert_eq!(result.failed_loads.len(), 1, "{:?}", result.failed_loads);
        let (subject, error) = &result.failed_loads[0];
        assert!(subject.ends_with("Broken.dll"), "{subject}");
        assert!(
            !error.is_empty() && error != "Failed to load assembly",
            "{error}"
        );

        let error = ProjectLoader::new()
            .primary_file(&broken)
            .and_then(|loader| loader.with_dependency(fixture("crafted_2.exe")))
            .and_then(ProjectLoader::build)
            .expect_err("an unreadable primary fails the build");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn a_referenced_name_must_be_a_simple_file_name() {
        let refused = [
            "",
            ".",
            "..",
            "/etc/passwd",
            "../x",
            "..\\x",
            "a/b",
            "a\\b",
            "C:\\x",
            "C:x",
            "\\\\host\\share\\x",
            "a\0b",
        ];
        for name in refused {
            assert!(check_simple_name(name).is_err(), "{name:?} is refused");
        }
        assert!(check_simple_name(&"a".repeat(MAX_ASSEMBLY_NAME_LENGTH + 1)).is_err());

        for name in [
            "mscorlib",
            "System.Core",
            "a..b",
            "..x",
            "x..",
            "Name With Spaces",
        ] {
            assert!(check_simple_name(name).is_ok(), "{name:?} is accepted");
        }
        assert!(check_simple_name(&"a".repeat(MAX_ASSEMBLY_NAME_LENGTH)).is_ok());
    }

    /// An identity with only a name, as an AssemblyRef naming `name` gives.
    fn reference(name: &str) -> AssemblyIdentity {
        AssemblyIdentity {
            name: name.into(),
            version: AssemblyVersion::UNKNOWN,
            culture: None,
            strong_name: None,
            processor_architecture: None,
        }
    }

    /// Resolve one reference against `root` alone and return the report.
    fn resolve_in(root: &Path, name: &str) -> ProjectResult {
        let loader = ProjectLoader::new();
        let mut result = ProjectResult::new();
        let mut discovery = Discovery {
            loader: &loader,
            validation: ValidationConfig::production(),
            roots: vec![std::fs::canonicalize(root).unwrap()],
            assemblies: Vec::new(),
            by_path: HashMap::new(),
            probes: HashMap::new(),
            mismatches: HashSet::new(),
            result: &mut result,
        };
        discovery.resolve(&reference(name)).unwrap();
        assert!(discovery.assemblies.is_empty(), "{name:?} loads nothing");
        result
    }

    /// A reference whose name climbs out of the search directory is refused for its name,
    /// before any path is built from it, although the file it names exists.
    #[test]
    fn a_traversing_reference_is_refused_by_name() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::copy(fixture("crafted_2.exe"), dir.path().join("x.dll")).unwrap();

        let result = resolve_in(&root, "../x");
        assert_eq!(result.failed_loads.len(), 1, "{:?}", result.failed_loads);
        assert!(
            result.failed_loads[0]
                .1
                .contains("not a valid assembly name"),
            "{:?}",
            result.failed_loads
        );
        assert!(result.missing_dependencies.is_empty());
    }

    /// A candidate inside the search directory that is a symbolic link to a file outside
    /// it is refused.
    #[cfg(unix)]
    #[test]
    fn a_candidate_linking_outside_its_directory_is_refused() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = dir.path().join("Evil.dll");
        fs::copy(fixture("crafted_2.exe"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("Evil.dll")).unwrap();

        let result = resolve_in(&root, "Evil");
        assert_eq!(result.failed_loads.len(), 1, "{:?}", result.failed_loads);
        assert!(
            result.failed_loads[0]
                .1
                .contains("outside the search directory"),
            "{:?}",
            result.failed_loads
        );
        assert!(result.missing_dependencies.is_empty());
    }
}

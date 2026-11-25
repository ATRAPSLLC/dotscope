//! Project loading result types and statistics.
//!
//! This module provides result types for project loading operations, tracking
//! successfully loaded assemblies, failures, and missing dependencies.

use crate::{metadata::identity::AssemblyIdentity, project::CilProject};

/// A version mismatch between a required and actual assembly version.
///
/// This occurs when an assembly is found but its version doesn't satisfy the
/// version requirement from the dependency reference.
#[derive(Debug, Clone)]
pub struct VersionMismatch {
    /// The assembly identity that was required by a dependency
    pub required: AssemblyIdentity,
    /// The assembly identity that was actually found
    pub actual: AssemblyIdentity,
}

/// Result of a project loading operation.
///
/// Contains the loaded project along with a report of the loading process: which
/// assemblies were loaded, which referenced names were not found, which files or
/// assemblies failed to load (with the error each gave), and which references were
/// satisfied only by another version.
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::project::{ProjectLoader, ProjectResult};
///
/// # fn main() -> dotscope::Result<()> {
/// // From ProjectLoader API
/// let result: ProjectResult = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
///
/// if result.is_complete_success() {
///     println!("Loaded {} assemblies successfully", result.success_count());
///     // Access the loaded project
///     for (identity, assembly) in result.project.iter() {
///         println!("Assembly: {} has {} types", identity.name, assembly.types().len());
///     }
/// } else {
///     println!("Loaded {} assemblies, {} failed",
///              result.success_count(), result.failure_count());
/// }
/// # Ok(())
/// # }
/// ```
pub struct ProjectResult {
    /// The loaded project containing all successfully loaded assemblies
    pub project: CilProject,
    /// Successfully loaded assembly identities
    pub loaded_assemblies: Vec<AssemblyIdentity>,
    /// Names referenced by an AssemblyRef that no search directory holds an assembly for
    pub missing_dependencies: Vec<String>,
    /// Files and assemblies that were found but failed to load, each with its error:
    /// a file that does not read, a dependency left out of the project because its load
    /// failed or panicked, a referenced name that is not a valid simple name, or a
    /// candidate file that resolves outside its search directory
    pub failed_loads: Vec<(String, String)>,
    /// Version mismatches detected during dependency resolution
    pub version_mismatches: Vec<VersionMismatch>,
    /// Total number of successfully loaded assemblies (`loaded_assemblies.len()`)
    pub loaded_count: usize,
    /// Total number of problems: `missing_dependencies.len() + failed_loads.len()`
    pub failed_count: usize,
}

impl std::fmt::Debug for ProjectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectResult")
            .field("project", &self.project)
            .field("loaded_assemblies", &self.loaded_assemblies)
            .field("missing_dependencies", &self.missing_dependencies)
            .field("failed_loads", &self.failed_loads)
            .field("version_mismatches", &self.version_mismatches)
            .field("loaded_count", &self.loaded_count)
            .field("failed_count", &self.failed_count)
            .finish()
    }
}

impl ProjectResult {
    /// Create a new empty project result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            project: CilProject::new(),
            loaded_assemblies: Vec::new(),
            missing_dependencies: Vec::new(),
            failed_loads: Vec::new(),
            version_mismatches: Vec::new(),
            loaded_count: 0,
            failed_count: 0,
        }
    }

    /// Check if the loading operation was completely successful (no failures).
    pub fn is_complete_success(&self) -> bool {
        self.failed_count == 0
    }

    /// Check if the loading operation had any failures.
    pub fn has_failures(&self) -> bool {
        self.failed_count > 0
    }

    /// Get the number of successfully loaded assemblies.
    pub fn success_count(&self) -> usize {
        self.loaded_count
    }

    /// Get the number of failed assembly loads.
    pub fn failure_count(&self) -> usize {
        self.failed_count
    }

    /// Record a successful assembly load.
    pub fn record_success(&mut self, identity: AssemblyIdentity) {
        self.loaded_assemblies.push(identity);
        self.loaded_count = self.loaded_count.saturating_add(1);
    }

    /// Record a file or assembly that was found but failed to load.
    ///
    /// # Arguments
    /// * `subject` - The file path or assembly name that failed
    /// * `error_message` - The error it failed with
    pub fn record_failure(&mut self, subject: String, error_message: String) {
        self.failed_loads.push((subject, error_message));
        self.failed_count = self.failed_count.saturating_add(1);
    }

    /// Record a referenced assembly name that no search directory holds.
    pub fn record_missing(&mut self, name: String) {
        self.missing_dependencies.push(name);
        self.failed_count = self.failed_count.saturating_add(1);
    }

    /// Record a version mismatch between required and actual assembly.
    pub fn record_version_mismatch(
        &mut self,
        required: AssemblyIdentity,
        actual: AssemblyIdentity,
    ) {
        self.version_mismatches
            .push(VersionMismatch { required, actual });
    }

    /// Check if there are any version mismatches.
    pub fn has_version_mismatches(&self) -> bool {
        !self.version_mismatches.is_empty()
    }

    /// Get the number of version mismatches.
    pub fn version_mismatch_count(&self) -> usize {
        self.version_mismatches.len()
    }

    /// Get all version mismatches.
    pub fn get_version_mismatches(&self) -> &[VersionMismatch] {
        &self.version_mismatches
    }
}

impl Default for ProjectResult {
    fn default() -> Self {
        Self::new()
    }
}

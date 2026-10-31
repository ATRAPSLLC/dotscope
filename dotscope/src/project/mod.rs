//! Multi-assembly project container and management system.
//!
//! This module provides the [`crate::project::CilProject`] container for managing collections of related
//! .NET assemblies with automatic dependency resolution, cross-assembly type resolution,
//! and unified analysis capabilities. It serves as the foundation for comprehensive
//! multi-assembly .NET project analysis.
//!
//! # Architecture
//!
//! The CilProject system provides several layers of functionality:
//!
//! - **Assembly Management**: Centralized loading and storage of multiple assemblies
//! - **Identity Management**: Assembly identification using comprehensive identity system
//! - **Cross-Assembly Access**: Direct iteration and querying across loaded assemblies
//! - **Primary Assembly Tracking**: Identification of the main entry point assembly
//!
//! # Key Components
//!
//! ## Core Container
//! - [`crate::project::CilProject`] - Main multi-assembly container and coordinator
//! - Assembly storage using [`crate::metadata::identity::AssemblyIdentity`] as primary key
//! - Primary assembly tracking for entry point identification
//!
//! ## Loading and Resolution
//! - Multiple assembly loading strategies via [`crate::project::ProjectLoader`]
//! - Automatic dependency discovery and resolution during loading
//! - Cross-assembly type registry linking for unified analysis
//!
//! # Usage Examples
//!
//! ## New ProjectLoader API (Recommended)
//!
//! ```rust,no_run
//! use dotscope::project::ProjectLoader;
//!
//! # fn main() -> dotscope::Result<()> {
//! // Basic single assembly loading
//! let result = ProjectLoader::new()
//!     .primary_file("MyApp.exe")?
//!     .build()?;
//!
//! // Multi-assembly with explicit dependencies
//! let result = ProjectLoader::new()
//!     .primary_file("MyApp.exe")?
//!     .with_dependency("MyLib.dll")?
//!     .with_dependency("System.Core.dll")?
//!     .build()?;
//!
//! // With automatic discovery
//! let result = ProjectLoader::new()
//!     .primary_file("MyApp.exe")?
//!     .with_search_path("./dependencies")?
//!     .auto_discover(true)
//!     .build()?;
//!
//! let project = &result.project;
//! println!("Loaded {} assemblies", result.success_count());
//! # Ok(())
//! # }
//! ```
//!
//! ## Manual Assembly Loading
//!
//! ```rust,no_run
//! use dotscope::project::CilProject;
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! # fn main() -> dotscope::Result<()> {
//! let project = CilProject::new();
//!
//! // Manually load assemblies and add to project
//! let main_assembly = CilObject::from_path(Path::new("MyApp.exe"))?;
//! let lib_assembly = CilObject::from_path(Path::new("MyLib.dll"))?;
//!
//! project.add_assembly(main_assembly, true)?;
//! project.add_assembly(lib_assembly, false)?;
//!
//! // Query the project
//! println!("Loaded {} assemblies", project.assembly_count());
//! for (identity, assembly) in project.iter() {
//!     println!("Assembly: {} has {} types", identity.name, assembly.types().len());
//! }
//! # Ok(())
//! # }
//! ```

pub mod context;
mod loader;
mod result;

use std::sync::{Arc, OnceLock};

pub(crate) use context::ProjectContext;
use dashmap::DashMap;
pub use loader::ProjectLoader;
pub use result::{ProjectResult, VersionMismatch};

use crate::{
    metadata::{
        cilobject::CilObject, identity::AssemblyIdentity, tables::TableId, token::Token,
        typesystem::CilTypeRc,
    },
    Error, Result,
};

/// Multi-assembly project container with dependency management and cross-assembly resolution.
///
/// Provides centralized management for collections of related .NET assemblies
/// with automatic dependency tracking, identity-based lookup, and cross-assembly
/// type resolution leveraging the existing Import/Export infrastructure.
///
/// # Core Features
///
/// - **Assembly Storage**: Efficient storage using AssemblyIdentity as key
/// - **Dependency Tracking**: Integrated dependency graph management
/// - **Import/Export Access**: Leverages existing Import/Export containers for resolution
/// - **Global Resolver**: Cross-assembly type resolution without duplication
/// - **Thread Safety**: All operations are thread-safe and concurrent
/// - **Clean Architecture**: Reuses existing infrastructure instead of duplicating it
///
/// # Design Principles
///
/// - **Leverage Existing**: Use Import/Export containers already built during parsing
/// - **Avoid Duplication**: Don't reinvent type tracking that already exists
/// - **External Resolution**: Resolver accesses CilObject imports/exports, not embedded
/// - **Symbol-Based Lookup**: Use AssemblyIdentity + SymbolName for unique identification
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::project::CilProject;
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let project = CilProject::new();
///
/// // Add assemblies to the project
/// let assembly = CilObject::from_path(Path::new("example.dll"))?;
/// project.add_assembly(assembly, true)?;
///
/// // Look up types across all loaded assemblies
/// if let Some(string_type) = project.get_type_by_name("System.String") {
///     println!("Found type: {}", string_type.name);
/// }
///
/// println!("Project contains {} assemblies", project.assembly_count());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct CilProject {
    /// Map of loaded assemblies indexed by their complete identity.
    ///
    /// Uses DashMap for lock-free concurrent access. AssemblyIdentity serves
    /// as the primary key, ensuring proper assembly identification across
    /// different versions, cultures, and strong names.
    assemblies: DashMap<AssemblyIdentity, Arc<CilObject>>,

    /// Direct reference to the primary/root assembly.
    ///
    /// This is typically the main executable or the primary library that
    /// serves as the entry point for the analysis. Set by ProjectLoader
    /// during the loading process using OnceLock for thread-safe single assignment.
    primary_assembly: OnceLock<Arc<CilObject>>,
}

impl CilProject {
    /// Create a new empty CilProject.
    ///
    /// Initializes an empty project container ready for assembly loading
    /// and dependency management.
    ///
    /// # Returns
    ///
    /// A new empty CilProject instance.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::CilProject;
    ///
    /// let project = CilProject::new();
    /// assert_eq!(project.assembly_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            assemblies: DashMap::new(),
            primary_assembly: OnceLock::new(),
        }
    }

    /// Get a type by its fully qualified name across all assemblies.
    ///
    /// This method searches through all assemblies in the project to find a type
    /// with the given name. It prioritizes TypeDef entries (actual definitions with
    /// table ID 0x02) over TypeRef entries (references with table ID 0x01).
    ///
    /// # Arguments
    /// * `full_name` - The fully qualified type name (e.g., "System.String")
    ///
    /// # Returns
    /// The actual type definition if found, None otherwise
    pub fn get_type_by_name(&self, full_name: &str) -> Option<CilTypeRc> {
        let mut typeref_match = None;

        // Search through all assemblies for matching types
        for assembly_identity in self.all_assemblies() {
            if let Some(assembly) = self.get_assembly(&assembly_identity) {
                // Check if this assembly defines the type locally
                for entry in assembly.types().iter() {
                    let type_instance = entry.value();
                    if &*type_instance.fullname() == full_name {
                        // Check if this is a TypeDef (0x02) or TypeRef (0x01)
                        if type_instance.token.is_table(TableId::TypeDef) {
                            // TypeDef - actual definition, return immediately
                            return Some(type_instance.clone());
                        } else if type_instance.token.is_table(TableId::TypeRef) {
                            // TypeRef - reference, keep as fallback
                            typeref_match = Some(type_instance.clone());
                        }
                    }
                }
            }
        }

        // Return TypeRef if no TypeDef was found
        typeref_match
    }

    /// Get all types defined in a specific assembly.
    ///
    /// # Arguments
    /// * `assembly_identity` - The assembly to get types from
    ///
    /// # Returns
    /// Vector of (token, type) pairs for all types in the assembly
    pub fn get_types_in_assembly(
        &self,
        assembly_identity: &AssemblyIdentity,
    ) -> Vec<(Token, CilTypeRc)> {
        if let Some(assembly) = self.get_assembly(assembly_identity) {
            assembly
                .types()
                .iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Add an assembly to the project.
    ///
    /// Adds the specified assembly to the project container and automatically
    /// analyzes its dependencies, updating the dependency graph. If an assembly
    /// with the same identity already exists, this operation will fail.
    ///
    /// This method also registers all types from the assembly in the global registry
    /// and builds TypeRef resolution mappings to previously loaded assemblies.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilObject to add to the project
    /// * `is_primary` - Whether this assembly should be marked as the primary/entry point
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the assembly was successfully added
    /// * `Err(Error)` if the assembly could not be added (e.g., duplicate identity)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::CilProject;
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let mut project = CilProject::new();
    /// let assembly = CilObject::from_path(Path::new("example.dll"))?;
    ///
    /// project.add_assembly(assembly, true)?; // Mark as primary
    /// assert_eq!(project.assembly_count(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the assembly lacks identity information or if an assembly
    /// with the same identity already exists in the project.
    pub fn add_assembly(&self, assembly: CilObject, is_primary: bool) -> Result<()> {
        let identity = assembly.identity().ok_or_else(|| {
            Error::Configuration("Assembly does not have identity information".to_string())
        })?;

        if self.assemblies.contains_key(&identity) {
            return Err(Error::Configuration(format!(
                "Assembly with identity '{}' already exists in project",
                identity.name
            )));
        }

        let assembly_arc = Arc::new(assembly);

        for existing_entry in &self.assemblies {
            let existing_identity = existing_entry.key();
            let existing_assembly = existing_entry.value();

            // Link new assembly -> existing assembly
            assembly_arc
                .types()
                .registry_link(existing_identity.clone(), &existing_assembly.types());

            // Link existing assembly -> new assembly
            existing_assembly
                .types()
                .registry_link(identity.clone(), &assembly_arc.types());
        }

        self.assemblies
            .insert(identity.clone(), assembly_arc.clone());

        if is_primary {
            self.primary_assembly
                .set(assembly_arc)
                .map_err(|existing| {
                    let existing_name = existing
                        .identity()
                        .map_or_else(|| "<unknown>".to_string(), |id| id.name.clone());
                    Error::Configuration(format!(
                        "Primary assembly already set to '{}', cannot set '{}' as primary",
                        existing_name, identity.name
                    ))
                })?;
        }

        Ok(())
    }

    /// Get an assembly by its identity.
    ///
    /// Looks up an assembly in the project using its complete identity.
    /// Returns a shared reference to the assembly if found.
    ///
    /// # Arguments
    ///
    /// * `identity` - The assembly identity to look up
    ///
    /// # Returns
    ///
    /// * `Some(Arc<CilObject>)` if the assembly is found
    /// * `None` if no assembly with the specified identity exists
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::CilProject;
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let project = CilProject::new();
    /// // ... add assemblies ...
    ///
    /// let identity = AssemblyIdentity::parse("MyLib, Version=1.0.0.0")?;
    /// if let Some(assembly) = project.get_assembly(&identity) {
    ///     println!("Found assembly with {} types", assembly.types().len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get_assembly(&self, identity: &AssemblyIdentity) -> Option<Arc<CilObject>> {
        self.assemblies.get(identity).map(|entry| entry.clone())
    }

    /// Get the number of assemblies in the project.
    ///
    /// Returns the total number of assemblies currently loaded in the project.
    ///
    /// # Returns
    ///
    /// The number of assemblies in the project.
    pub fn assembly_count(&self) -> usize {
        self.assemblies.len()
    }

    /// Get all assembly identities in the project.
    ///
    /// Returns a vector containing the identities of all assemblies currently
    /// loaded in the project.
    ///
    /// # Returns
    ///
    /// Vector of all assembly identities in the project.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::CilProject;
    ///
    /// let project = CilProject::new();
    /// // ... add assemblies ...
    ///
    /// for identity in project.all_assemblies() {
    ///     println!("Assembly: {}", identity.display_name());
    /// }
    /// ```
    pub fn all_assemblies(&self) -> Vec<AssemblyIdentity> {
        self.assemblies
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if the project contains an assembly with the specified identity.
    ///
    /// # Arguments
    ///
    /// * `identity` - The assembly identity to check for
    ///
    /// # Returns
    ///
    /// `true` if the assembly is present, `false` otherwise.
    pub fn contains_assembly(&self, identity: &AssemblyIdentity) -> bool {
        self.assemblies.contains_key(identity)
    }

    /// Check if the project is empty.
    ///
    /// # Returns
    ///
    /// `true` if the project contains no assemblies, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.assemblies.is_empty()
    }

    /// Iterate over all assemblies in the project.
    ///
    /// Provides direct iteration over all loaded assemblies without creating copies.
    /// Returns an iterator that yields (AssemblyIdentity, `Arc<CilObject>`) pairs.
    ///
    /// # Returns
    /// Iterator over all assemblies in the project
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::CilProject;
    ///
    /// let project = CilProject::new();
    /// // ... load assemblies via ProjectLoader ...
    ///
    /// for (identity, assembly) in project.iter() {
    ///     println!("Assembly: {} has {} types", identity.name, assembly.types().len());
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (AssemblyIdentity, Arc<CilObject>)> + '_ {
        self.assemblies
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
    }

    /// Find all assemblies that define a specific type.
    ///
    /// Searches through all assemblies to find those that contain a type definition
    /// matching the specified fully qualified name.
    ///
    /// # Arguments
    /// * `type_name` - The fully qualified type name to search for
    ///
    /// # Returns
    /// Vector of (AssemblyIdentity, CilTypeRc) pairs for all matches
    pub fn find_type_definitions(&self, type_name: &str) -> Vec<(AssemblyIdentity, CilTypeRc)> {
        let mut results = Vec::new();

        for (identity, assembly) in self.iter() {
            for entry in assembly.types().iter() {
                let type_instance = entry.value();
                if &*type_instance.fullname() == type_name
                    && type_instance.token.is_table(TableId::TypeDef)
                {
                    results.push((identity.clone(), type_instance.clone()));
                }
            }
        }

        results
    }

    /// Get the primary/root assembly of the project.
    ///
    /// Returns the assembly that was specified as the primary file when loading
    /// the project. This is typically the main executable or entry point library.
    ///
    /// # Returns
    /// * `Some(Arc<CilObject>)` if a primary assembly was set
    /// * `None` if no primary assembly was designated (manual loading)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::project::ProjectLoader;
    ///
    /// # fn main() -> dotscope::Result<()> {
    /// let result = ProjectLoader::new()
    ///     .primary_file("MyApp.exe")?
    ///     .build()?;
    ///
    /// if let Some(primary) = result.project.get_primary() {
    ///     println!("Primary assembly has {} types", primary.types().len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_primary(&self) -> Option<Arc<CilObject>> {
        self.primary_assembly.get().cloned()
    }

    /// Clear all assemblies from the project.
    ///
    /// Removes all assemblies from the project. This operation is useful for
    /// reusing a CilProject instance for different analysis tasks.
    /// Note: The primary assembly designation cannot be cleared due to OnceLock.
    pub fn clear(&self) {
        self.assemblies.clear();
        // Note: primary_assembly cannot be reset due to OnceLock semantics
    }
}

impl Default for CilProject {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CilProject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let primary_identity = self
            .primary_assembly
            .get()
            .and_then(|assembly| assembly.identity());

        f.debug_struct("CilProject")
            .field("assembly_count", &self.assembly_count())
            .field("primary_assembly", &primary_identity)
            .field("assemblies", &self.all_assemblies())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            typesystem::{CilTypeReference, TypeSource},
            validation::ValidationConfig,
        },
        testkit::{fixture, verify_crafted_2, verify_windowsbasedll},
    };

    /// In a project, a registry also holds the types its TypeRefs resolve to in other
    /// assemblies. The types it lists as its own assembly's are that assembly's alone: every
    /// assembly's row token is `0x20000001`, and keying sources by it once listed System's
    /// resolved mscorlib types (`ExtensionAttribute`, `CLSCompliantAttribute`, ...) as
    /// System's.
    #[test]
    fn a_registry_lists_only_its_own_assembly_s_types_as_its_own() {
        let result = ProjectLoader::new()
            .primary_file(fixture("mono_4.8/System.dll"))
            .and_then(|loader| loader.with_search_path(fixture("mono_4.8")))
            .map(|loader| {
                loader
                    .auto_discover(true)
                    .with_validation(ValidationConfig::disabled())
            })
            .and_then(ProjectLoader::build)
            .expect("System.dll loads with mscorlib");
        let system = result.project.get_primary().expect("the primary assembly");
        let identity = system.identity().expect("System's identity");
        let own = system
            .types()
            .types_from_source(&TypeSource::Assembly(identity.clone()));

        let foreign: Vec<String> = own
            .iter()
            .filter_map(|ty| match ty.external() {
                Some(CilTypeReference::Assembly(assembly)) if assembly.name != identity.name => {
                    Some(format!("{} from {}", ty.fullname(), assembly.name))
                }
                _ => None,
            })
            .collect();
        assert!(foreign.is_empty(), "{} foreign: {foreign:?}", foreign.len());
        assert!(own
            .iter()
            .any(|ty| &*ty.fullname() == "System.Text.RegularExpressions.GroupCollection"));
    }

    #[test]
    fn test_cilproject_creation() {
        let project = CilProject::new();
        assert_eq!(project.assembly_count(), 0);
        assert!(project.is_empty());
        assert!(project.all_assemblies().is_empty());
        assert!(project.get_primary().is_none());
    }

    #[test]
    fn test_cilproject_default() {
        let project = CilProject::default();
        assert_eq!(project.assembly_count(), 0);
        assert!(project.is_empty());
        assert!(project.get_primary().is_none());
    }

    #[test]
    fn test_get_primary_with_loader() {
        let result = ProjectLoader::new()
            .primary_file(fixture("crafted_2.exe"))
            .and_then(|loader| loader.with_search_path(fixture("mono_4.8")))
            .and_then(|loader| loader.auto_discover(true).build())
            .expect("crafted_2.exe loads with its dependencies");
        let primary = result
            .project
            .get_primary()
            .expect("the primary assembly is set after loading");
        assert!(
            !primary.types().is_empty(),
            "the primary assembly has types"
        );
    }

    #[test]
    fn test_load_crafted2_exe() {
        let crafted2_path = fixture("crafted_2.exe");
        let mono_deps_path = fixture("mono_4.8");

        println!("Loading crafted_2.exe from {:?}", crafted2_path);
        println!("Using Mono dependencies from {:?}", mono_deps_path);

        match ProjectLoader::new()
            .primary_file(&crafted2_path)
            .and_then(|loader| loader.with_search_path(&mono_deps_path))
            .map(|loader| loader.auto_discover(true))
            .and_then(|loader| loader.strict_mode(true).build())
        {
            Ok(result) => {
                println!(
                    "Loaded: {}, Failed: {}",
                    result.success_count(),
                    result.failure_count()
                );
                println!("Loaded assemblies:");
                for identity in &result.loaded_assemblies {
                    println!("  - {} v{}", identity.name, identity.version);
                }

                if !result.failed_loads.is_empty() {
                    println!("Failed to load {} assemblies:", result.failed_loads.len());
                    for (path, error) in &result.failed_loads {
                        println!("  - {}: {}", path, error);
                    }
                }

                if !result.missing_dependencies.is_empty() {
                    println!("Missing dependencies:");
                    for dep in &result.missing_dependencies {
                        println!("  - {}", dep);
                    }
                }

                // Assert that the root assembly (crafted_2.exe) was specifically loaded
                let crafted2_loaded = result
                    .loaded_assemblies
                    .iter()
                    .any(|identity| identity.name == "crafted_2");

                assert!(crafted2_loaded,
                    "crafted_2.exe (the root assembly) must be loaded successfully. Loaded assemblies: {:?}",
                    result.loaded_assemblies.iter().map(|id| &id.name).collect::<Vec<_>>());

                let loaded = result.project.get_primary().unwrap();
                verify_crafted_2(&loaded);
            }
            Err(e) => {
                panic!(
                    "❌ Test FAILED: Assembly loading must succeed without errors, but got: {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_load_windowsbase_dll() {
        let windowsbase_path = fixture("WindowsBase.dll");
        let mono_deps_path = fixture("mono_4.8");

        println!("Loading WindowsBase.dll from {:?}", windowsbase_path);
        println!("Using Mono dependencies from {:?}", mono_deps_path);

        match ProjectLoader::new()
            .primary_file(&windowsbase_path)
            .and_then(|loader| loader.with_search_path(&mono_deps_path))
            .map(|loader| loader.auto_discover(true))
            .and_then(|loader| loader.strict_mode(true).build())
        {
            Ok(result) => {
                println!(
                    "Loaded: {}, Failed: {}",
                    result.success_count(),
                    result.failure_count()
                );
                println!("Loaded assemblies:");
                for identity in &result.loaded_assemblies {
                    println!("  - {} v{}", identity.name, identity.version);
                }

                if !result.failed_loads.is_empty() {
                    println!("Failed to load {} assemblies:", result.failed_loads.len());
                    for (path, error) in &result.failed_loads {
                        println!("  - {}: {}", path, error);
                    }
                }

                if !result.missing_dependencies.is_empty() {
                    println!("Missing dependencies:");
                    for dep in &result.missing_dependencies {
                        println!("  - {}", dep);
                    }
                }

                // Assert that the root assembly (WindowsBase.dll) was specifically loaded
                let windowsbase_loaded = result
                    .loaded_assemblies
                    .iter()
                    .any(|identity| identity.name == "WindowsBase");

                assert!(windowsbase_loaded,
                    "WindowsBase.dll (the root assembly) must be loaded successfully. Loaded assemblies: {:?}", 
                    result.loaded_assemblies.iter().map(|id| &id.name).collect::<Vec<_>>());

                assert!(result.success_count() >= 1);
                assert!(!result.loaded_assemblies.is_empty());

                let loaded = result.project.get_primary().unwrap();
                verify_windowsbasedll(&loaded)
            }
            Err(e) => {
                panic!("❌ Failed to load WindowsBase.dll: {:?}", e);
            }
        }
    }
}

//! Unified import container combining both CIL and native PE imports.
//!
//! This module provides the [`crate::metadata::imports::UnifiedImportContainer`] which serves as a unified interface
//! for managing both managed (.NET) imports and native PE import tables. It builds
//! on the existing sophisticated CIL import functionality while adding native support
//! through composition rather than duplication.
//!
//! # Architecture
//!
//! The container uses a compositional approach:
//! - **CIL Imports**: Existing [`crate::metadata::imports::Imports`] container handles managed imports
//! - **Native Imports**: New [`crate::metadata::imports::NativeImports`] handles PE import tables
//! - **Unified Views**: Lightweight caching for cross-cutting queries
//!
//! # Design Goals
//!
//! - **Preserve Excellence**: Leverage existing concurrent CIL functionality unchanged
//! - **Unified Interface**: Single API for both import types
//! - **Performance**: Minimal overhead with cached unified views
//! - **Backward Compatibility**: Existing CIL imports accessible via `.cil()`
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::imports::{ImportEntry, UnifiedImportContainer};
//!
//! let container = UnifiedImportContainer::new();
//!
//! // Access existing CIL functionality
//! let cil_imports = container.cil();
//! let string_import = cil_imports.by_name("String");
//!
//! // Use unified search across both import types
//! let all_messagebox = container.find_by_name("MessageBox");
//! for import in all_messagebox {
//!     match import {
//!         ImportEntry::Cil(cil_import) => println!("CIL: {}", cil_import.fullname()),
//!         ImportEntry::Native(native_ref) => println!("Native: {}", native_ref.dll_name),
//!     }
//! }
//!
//! // Get all DLL dependencies
//! let dependencies = container.get_all_dll_dependencies();
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use crate::{
    metadata::{
        imports::{
            native::NativeImports, Import, ImportRc, ImportSourceId, ImportType,
            Imports as CilImports,
        },
        tables::ModuleRefRc,
        token::Token,
    },
    Result,
};

/// Unified container for both CIL and native PE imports.
///
/// This container provides a single interface for managing all types of imports
/// in a .NET assembly, including managed type/method references and native PE
/// import table entries. It preserves the existing sophisticated CIL import
/// functionality while adding native support through composition.
///
/// # Thread Safety
///
/// All operations are thread-safe using interior mutability:
/// - CIL imports use existing concurrent data structures
/// - Native imports are thread-safe by design
/// - The unified views are built once, by the first reader, and rebuilt after a change
///   to the native imports
///
/// # Performance
///
/// - CIL operations have identical performance to existing implementation
/// - Native operations use efficient hash-based lookups
/// - Unified views are cached and invalidated only when needed
/// - Lock-free access patterns throughout
pub struct UnifiedImportContainer {
    /// CIL managed imports (existing sophisticated implementation)
    cil: CilImports,

    /// Native PE imports (new implementation)
    native: NativeImports,

    /// The unified views, built on first use
    unified: OnceLock<Unified>,
}

/// The unified views of both import sources.
#[derive(Default)]
struct Unified {
    /// Imports by name
    by_name: HashMap<String, Vec<ImportEntry>>,
    /// DLL dependencies by DLL name
    by_dll: HashMap<String, DllSource>,
    /// The names of the CIL P/Invoke imports by lower-cased DLL name
    cil_functions: HashMap<String, HashSet<String>>,
}

/// Unified import entry that can represent either CIL or native imports.
#[derive(Clone)]
pub enum ImportEntry {
    /// Managed import from CIL metadata
    Cil(ImportRc),
    /// Native import from PE import table
    Native(NativeImportRef),
}

/// Reference to a native import function.
#[derive(Clone, Debug)]
pub struct NativeImportRef {
    /// DLL name containing the function, the string its descriptor's imports share
    pub dll_name: Arc<str>,
    /// Function name (if imported by name)
    pub function_name: Option<String>,
    /// Function ordinal (if imported by ordinal)
    pub ordinal: Option<u16>,
    /// Import Address Table RVA
    pub iat_rva: u32,
}

/// Source of DLL usage in the assembly.
#[derive(Clone, Debug)]
pub enum DllSource {
    /// Used only by CIL P/Invoke methods
    Cil(Vec<Token>),
    /// Used only by native import table
    Native,
    /// Used by both CIL P/Invoke and native imports
    Both(Vec<Token>),
}

/// DLL dependency information combining both import types.
#[derive(Clone, Debug)]
pub struct DllDependency {
    /// DLL name
    pub name: String,
    /// Source of the dependency
    pub source: DllSource,
    /// All functions imported from this DLL
    pub functions: Vec<String>,
}

impl Clone for UnifiedImportContainer {
    fn clone(&self) -> Self {
        Self {
            cil: self.cil.clone(),
            native: self.native.clone(),
            unified: OnceLock::new(),
        }
    }
}

impl UnifiedImportContainer {
    /// Create a new empty import container.
    ///
    /// Initializes both CIL and native import storage with empty state.
    /// Unified caches are created lazily on first access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cil: CilImports::new(),
            native: NativeImports::new(),
            unified: OnceLock::new(),
        }
    }

    /// Get the CIL imports container.
    ///
    /// Provides access to all existing CIL import functionality including
    /// sophisticated lookup methods, concurrent data structures, and
    /// cross-reference resolution.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// let cil_imports = container.cil();
    ///
    /// // Use existing CIL functionality
    /// let string_import = cil_imports.by_name("String");
    /// let system_imports = cil_imports.by_namespace("System");
    /// ```
    pub fn cil(&self) -> &CilImports {
        &self.cil
    }

    /// Get the native imports container.
    ///
    /// Provides access to PE import table functionality including
    /// DLL management, function imports, and IAT operations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// let native_imports = container.native();
    ///
    /// // Check native DLL dependencies
    /// let dll_names = native_imports.get_dll_names();
    /// println!("Native DLLs: {:?}", dll_names);
    /// ```
    pub fn native(&self) -> &NativeImports {
        &self.native
    }

    /// Get mutable access to the native imports container.
    ///
    /// Provides mutable access for populating or modifying native import data.
    /// Used internally during assembly loading to populate from PE files.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let mut container = UnifiedImportContainer::new();
    /// container.native_mut().add_dll("kernel32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_mut(&mut self) -> &mut NativeImports {
        self.invalidate_cache();
        &mut self.native
    }

    /// Find all imports by name across both CIL and native sources.
    ///
    /// Searches both managed type/method imports and native function imports
    /// for the specified name. Results include imports from all sources.
    ///
    /// # Arguments
    /// * `name` - Name to search for
    ///
    /// # Returns
    /// Vector of all matching imports, may be empty if none found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::{UnifiedImportContainer, ImportEntry};
    /// let container = UnifiedImportContainer::new();
    /// let imports = container.find_by_name("MessageBox");
    ///
    /// for import in imports {
    ///     match import {
    ///         ImportEntry::Cil(cil_import) => {
    ///             println!("CIL import: {}", cil_import.fullname());
    ///         }
    ///         ImportEntry::Native(native_ref) => {
    ///             println!("Native import: {} from {}",
    ///                 native_ref.function_name.as_ref().unwrap(),
    ///                 native_ref.dll_name);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn find_by_name(&self, name: &str) -> Vec<ImportEntry> {
        self.unified()
            .by_name
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all DLL dependencies from both CIL P/Invoke and native imports.
    ///
    /// Returns comprehensive dependency information including DLLs used by
    /// managed P/Invoke methods and native import table entries.
    ///
    /// # Returns
    /// Vector of all DLL dependencies with source and function information.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// let dependencies = container.get_all_dll_dependencies();
    ///
    /// for dep in dependencies {
    ///     println!("DLL: {} ({:?})", dep.name, dep.source);
    ///     for func in dep.functions {
    ///         println!("  Function: {}", func);
    ///     }
    /// }
    /// ```
    pub fn get_all_dll_dependencies(&self) -> Vec<DllDependency> {
        self.unified()
            .by_dll
            .iter()
            .map(|(dll_name, source)| DllDependency {
                name: dll_name.clone(),
                source: source.clone(),
                functions: self.get_functions_for_dll(dll_name),
            })
            .collect()
    }

    /// Get all DLL names from both import sources.
    ///
    /// Returns a deduplicated list of all DLL names referenced by
    /// either CIL P/Invoke methods or native import table entries.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// let dll_names = container.get_all_dll_names();
    /// println!("All DLL dependencies: {:?}", dll_names);
    /// ```
    pub fn get_all_dll_names(&self) -> Vec<String> {
        self.unified().by_dll.keys().cloned().collect()
    }

    /// Check if the container has any imports (CIL or native).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// if container.is_empty() {
    ///     println!("No imports found");
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cil.is_empty() && self.native.is_empty()
    }

    /// Get total count of all imports (CIL + native).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let container = UnifiedImportContainer::new();
    /// println!("Total imports: {}", container.total_count());
    /// ```
    pub fn total_count(&self) -> usize {
        self.cil
            .len()
            .saturating_add(self.native.total_function_count())
    }

    /// Add a native function import.
    ///
    /// Convenience method for adding native function imports. The DLL
    /// will be created if it doesn't exist.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to import from
    /// * `function_name` - Name of the function to import
    ///
    /// # Errors
    /// Returns error if the DLL name or function name is invalid,
    /// or if the function is already imported.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let mut container = UnifiedImportContainer::new();
    /// container.add_native_function("user32.dll", "MessageBoxW")?;
    /// container.add_native_function("kernel32.dll", "GetCurrentProcessId")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function(&mut self, dll_name: &str, function_name: &str) -> Result<()> {
        self.native.add_dll(dll_name)?;
        self.native.add_function(dll_name, function_name)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native function import by ordinal.
    ///
    /// Convenience method for adding ordinal-based native function imports.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to import from
    /// * `ordinal` - Ordinal number of the function to import
    ///
    /// # Errors
    /// Returns error if the DLL name is invalid, ordinal is 0,
    /// or if the ordinal is already imported.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let mut container = UnifiedImportContainer::new();
    /// container.add_native_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function_by_ordinal(&mut self, dll_name: &str, ordinal: u16) -> Result<()> {
        self.native.add_dll(dll_name)?;
        self.native.add_function_by_ordinal(dll_name, ordinal)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Update Import Address Table RVAs after section moves.
    ///
    /// Adjusts all IAT RVAs by the specified delta when sections are moved
    /// during PE layout changes.
    ///
    /// # Arguments
    /// * `rva_delta` - Signed delta to apply to all RVAs
    ///
    /// # Errors
    /// Returns error if the RVA delta would cause overflow.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::UnifiedImportContainer;
    /// let mut container = UnifiedImportContainer::new();
    /// // Move import table up by 0x1000 bytes
    /// container.update_iat_rvas(0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn update_iat_rvas(&mut self, rva_delta: i64) -> Result<()> {
        self.native.update_iat_rvas(rva_delta)?;

        // Note: CIL P/Invoke methods don't have IAT entries in the traditional PE sense.
        // P/Invoke resolution is handled at runtime through the ImplMap metadata table,
        // not through the Import Address Table. Therefore, no IAT update is needed
        // for CIL P/Invoke imports.

        Ok(())
    }

    /// The unified views, built by the first reader since the last change.
    fn unified(&self) -> &Unified {
        self.unified.get_or_init(|| self.build_unified())
    }

    /// Drops the unified views after a change to the native imports.
    fn invalidate_cache(&mut self) {
        self.unified = OnceLock::new();
    }

    /// Builds the unified views of both sources: every native import, and every CIL import
    /// but a P/Invoke import that a native import of the same DLL and function (ignoring
    /// case) duplicates. Each module's and each descriptor's DLL name is copied once, not
    /// once per import from it.
    fn build_unified(&self) -> Unified {
        let mut unified = Unified::default();

        // The native imports' function names by DLL, lower-cased, for the duplicates
        let mut native_names: HashMap<String, HashSet<String>> = HashMap::new();
        for descriptor in self.native.descriptors() {
            let names = native_names
                .entry(descriptor.dll_name.to_ascii_lowercase())
                .or_default();
            for function in &descriptor.functions {
                if let Some(name) = &function.name {
                    names.insert(name.to_ascii_lowercase());
                }
            }
        }

        let mut lowered: HashMap<Token, String> = HashMap::new();
        for import_entry in &self.cil {
            let import = import_entry.value();
            let token = *import_entry.key();
            let Some(module) = Self::pinvoke_module(import, &self.cil) else {
                unified
                    .by_name
                    .entry(import.name.clone())
                    .or_default()
                    .push(ImportEntry::Cil(import.clone()));
                continue;
            };
            let dll_lower = lowered
                .entry(module.token)
                .or_insert_with(|| module.name.to_ascii_lowercase());

            let is_duplicate = native_names
                .get(dll_lower.as_str())
                .is_some_and(|names| names.contains(&import.name.to_ascii_lowercase()));
            if !is_duplicate {
                unified
                    .by_name
                    .entry(import.name.clone())
                    .or_default()
                    .push(ImportEntry::Cil(import.clone()));
            }

            match unified.by_dll.get_mut(module.name.as_str()) {
                Some(DllSource::Cil(tokens) | DllSource::Both(tokens)) => tokens.push(token),
                Some(source) => *source = DllSource::Both(vec![token]),
                None => {
                    unified
                        .by_dll
                        .insert(module.name.clone(), DllSource::Cil(vec![token]));
                }
            }
            match unified.cil_functions.get_mut(dll_lower.as_str()) {
                Some(names) => {
                    names.insert(import.name.clone());
                }
                None => {
                    unified
                        .cil_functions
                        .insert(dll_lower.clone(), HashSet::from([import.name.clone()]));
                }
            }
        }

        for descriptor in self.native.descriptors() {
            if descriptor.functions.is_empty() {
                continue;
            }
            for function in &descriptor.functions {
                if let Some(name) = &function.name {
                    unified
                        .by_name
                        .entry(name.clone())
                        .or_default()
                        .push(ImportEntry::Native(NativeImportRef {
                            dll_name: Arc::clone(&descriptor.dll_name),
                            function_name: Some(name.clone()),
                            ordinal: function.ordinal,
                            iat_rva: function.rva,
                        }));
                }
            }
            match unified.by_dll.get_mut(&*descriptor.dll_name) {
                Some(source) => {
                    if let DllSource::Cil(tokens) = source {
                        *source = DllSource::Both(std::mem::take(tokens));
                    }
                }
                None => {
                    unified
                        .by_dll
                        .insert(descriptor.dll_name.to_string(), DllSource::Native);
                }
            }
        }

        unified
    }

    /// The module a CIL P/Invoke method import calls into, from the [`ModuleRef`] it names.
    ///
    /// [`ModuleRef`]: crate::metadata::tables::ModuleRef
    fn pinvoke_module(import: &Import, cil_imports: &CilImports) -> Option<ModuleRefRc> {
        if !matches!(import.import, ImportType::Method(_)) {
            return None;
        }
        match import.source_id {
            ImportSourceId::ModuleRef(token) => cil_imports.get_module_ref(token),
            _ => None,
        }
    }

    /// Get all function names imported from a specific DLL.
    ///
    /// Collects function names from both native PE imports and CIL P/Invoke
    /// method imports that target the specified DLL (its name compared ignoring case).
    fn get_functions_for_dll(&self, dll_name: &str) -> Vec<String> {
        let mut functions = HashSet::new();

        if let Some(descriptor) = self.native.get_descriptor(dll_name) {
            for function in &descriptor.functions {
                if let Some(ref name) = function.name {
                    functions.insert(name.clone());
                } else if let Some(ordinal) = function.ordinal {
                    functions.insert(format!("#{ordinal}"));
                }
            }
        }
        if let Some(names) = self
            .unified()
            .cil_functions
            .get(&dll_name.to_ascii_lowercase())
        {
            functions.extend(names.iter().cloned());
        }

        functions.into_iter().collect()
    }
}

impl Default for UnifiedImportContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Implement common traits for convenience
impl std::fmt::Debug for UnifiedImportContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedImportContainer")
            .field("cil_count", &self.cil.len())
            .field("native_dll_count", &self.native.dll_count())
            .field("native_function_count", &self.native.total_function_count())
            .field("is_cache_built", &self.unified.get().is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{create_method, create_module_ref};

    #[test]
    fn test_unified_import_container_new() {
        let container = UnifiedImportContainer::new();
        assert!(container.is_empty());
        assert_eq!(container.total_count(), 0);
    }

    #[test]
    fn test_unified_import_container_default() {
        let container = UnifiedImportContainer::default();
        assert!(container.is_empty());
    }

    #[test]
    fn test_add_native_function() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();

        assert!(!container.is_empty());
        assert!(container.total_count() >= 1);
    }

    #[test]
    fn test_add_multiple_native_functions_same_dll() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();
        container
            .add_native_function("kernel32.dll", "GetCurrentThreadId")
            .unwrap();
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .unwrap();

        assert!(!container.is_empty());
        assert!(container.total_count() >= 3);
    }

    #[test]
    fn test_add_native_functions_multiple_dlls() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();
        container
            .add_native_function("user32.dll", "MessageBoxW")
            .unwrap();

        assert!(!container.is_empty());
        assert!(container.total_count() >= 2);
    }

    #[test]
    fn test_add_native_function_by_ordinal() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function_by_ordinal("user32.dll", 100)
            .unwrap();

        assert!(!container.is_empty());
    }

    #[test]
    fn test_add_native_function_by_ordinal_invalid() {
        let mut container = UnifiedImportContainer::new();
        // Ordinal 0 should be invalid
        let result = container.add_native_function_by_ordinal("user32.dll", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_by_name_native() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "TestImport")
            .unwrap();

        let results = container.find_by_name("TestImport");
        assert_eq!(results.len(), 1);

        if let ImportEntry::Native(native_ref) = &results[0] {
            assert_eq!(&*native_ref.dll_name, "kernel32.dll");
            assert_eq!(native_ref.function_name, Some("TestImport".to_string()));
        } else {
            panic!("Expected Native import entry");
        }
    }

    #[test]
    fn test_find_by_name_not_found() {
        let container = UnifiedImportContainer::new();
        let results = container.find_by_name("NonExistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_all_dll_names() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "Func1")
            .unwrap();
        container
            .add_native_function("user32.dll", "Func2")
            .unwrap();
        container
            .add_native_function("advapi32.dll", "Func3")
            .unwrap();

        let dll_names = container.get_all_dll_names();
        assert_eq!(dll_names.len(), 3);
        assert!(dll_names.contains(&"kernel32.dll".to_string()));
        assert!(dll_names.contains(&"user32.dll".to_string()));
        assert!(dll_names.contains(&"advapi32.dll".to_string()));
    }

    #[test]
    fn test_get_all_dll_dependencies() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("kernel32.dll", "GetCurrentProcessId")
            .unwrap();
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .unwrap();

        let dependencies = container.get_all_dll_dependencies();
        assert!(!dependencies.is_empty());

        let kernel32_dep = dependencies.iter().find(|d| d.name == "kernel32.dll");
        assert!(kernel32_dep.is_some());

        let dep = kernel32_dep.unwrap();
        assert!(dep.functions.len() >= 2);
        assert!(dep.functions.contains(&"GetCurrentProcessId".to_string()));
        assert!(dep.functions.contains(&"GetLastError".to_string()));
    }

    #[test]
    fn test_cil_accessor() {
        let container = UnifiedImportContainer::new();
        let cil = container.cil();
        assert!(cil.is_empty());
    }

    #[test]
    fn test_native_accessor() {
        let container = UnifiedImportContainer::new();
        let native = container.native();
        assert!(native.is_empty());
    }

    #[test]
    fn test_native_mut_invalidates_cache() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("test.dll", "TestFunc")
            .unwrap();

        // Force cache to be built
        let _ = container.find_by_name("TestFunc");

        // Mutating native should invalidate cache
        let _ = container.native_mut();

        // The views are rebuilt on the next read
        assert!(container.unified.get().is_none());
    }

    #[test]
    fn test_clone_resets_cache() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("test.dll", "TestFunc")
            .unwrap();

        // Force cache to be built
        let _ = container.find_by_name("TestFunc");

        // A clone builds its own views
        let cloned = container.clone();
        assert!(cloned.unified.get().is_none());

        // But data should be preserved
        assert!(!cloned.is_empty());
    }

    #[test]
    fn test_debug_output() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("test.dll", "TestFunc")
            .unwrap();

        let debug_output = format!("{:?}", container);
        assert!(debug_output.contains("UnifiedImportContainer"));
        assert!(debug_output.contains("native_dll_count"));
        assert!(debug_output.contains("native_function_count"));
    }

    #[test]
    fn test_native_import_ref_structure() {
        let import_ref = NativeImportRef {
            dll_name: "kernel32.dll".into(),
            function_name: Some("GetCurrentProcessId".to_string()),
            ordinal: None,
            iat_rva: 0x1000,
        };

        assert_eq!(&*import_ref.dll_name, "kernel32.dll");
        assert_eq!(
            import_ref.function_name,
            Some("GetCurrentProcessId".to_string())
        );
        assert!(import_ref.ordinal.is_none());
        assert_eq!(import_ref.iat_rva, 0x1000);
    }

    #[test]
    fn test_native_import_ref_ordinal() {
        let import_ref = NativeImportRef {
            dll_name: "user32.dll".into(),
            function_name: None,
            ordinal: Some(120),
            iat_rva: 0x2000,
        };

        assert!(import_ref.function_name.is_none());
        assert_eq!(import_ref.ordinal, Some(120));
    }

    #[test]
    fn test_native_import_ref_clone() {
        let import_ref = NativeImportRef {
            dll_name: "test.dll".into(),
            function_name: Some("TestFunc".to_string()),
            ordinal: None,
            iat_rva: 0x3000,
        };

        let cloned = import_ref.clone();
        assert_eq!(&*cloned.dll_name, "test.dll");
        assert_eq!(cloned.function_name, Some("TestFunc".to_string()));
    }

    #[test]
    fn test_dll_source_cil() {
        let token = Token::new(0x06000001);
        let source = DllSource::Cil(vec![token]);

        if let DllSource::Cil(tokens) = source {
            assert_eq!(tokens.len(), 1);
            assert_eq!(tokens[0], token);
        } else {
            panic!("Expected Cil variant");
        }
    }

    #[test]
    fn test_dll_source_native() {
        let source = DllSource::Native;
        assert!(matches!(source, DllSource::Native));
    }

    #[test]
    fn test_dll_source_both() {
        let token = Token::new(0x06000001);
        let source = DllSource::Both(vec![token]);

        if let DllSource::Both(tokens) = source {
            assert_eq!(tokens.len(), 1);
        } else {
            panic!("Expected Both variant");
        }
    }

    #[test]
    fn test_dll_dependency_structure() {
        let dep = DllDependency {
            name: "kernel32.dll".to_string(),
            source: DllSource::Native,
            functions: vec![
                "GetCurrentProcessId".to_string(),
                "GetLastError".to_string(),
            ],
        };

        assert_eq!(dep.name, "kernel32.dll");
        assert!(matches!(dep.source, DllSource::Native));
        assert_eq!(dep.functions.len(), 2);
    }

    #[test]
    fn test_update_iat_rvas_positive() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("test.dll", "TestFunc")
            .unwrap();

        // Should succeed with positive delta
        let result = container.update_iat_rvas(0x1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_iat_rvas_negative() {
        let mut container = UnifiedImportContainer::new();
        container
            .add_native_function("test.dll", "TestFunc")
            .unwrap();

        // Should succeed with negative delta
        let result = container.update_iat_rvas(-0x100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cil_pinvoke_dll_extraction() {
        let container = UnifiedImportContainer::new();
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetProcessId");
        let token = Token::new(0x0A000001);

        // Add a P/Invoke method import to the CIL imports
        container
            .cil
            .add_method("GetProcessId".to_string(), &token, method, &module_ref)
            .expect("Failed to add method import");

        // Verify the DLL appears in the unified DLL list
        let dll_names = container.get_all_dll_names();
        assert!(
            dll_names.iter().any(|n| n == "kernel32.dll"),
            "kernel32.dll should appear in DLL dependencies. Found: {:?}",
            dll_names
        );
    }

    #[test]
    fn test_cil_pinvoke_functions_for_dll() {
        let container = UnifiedImportContainer::new();
        let module_ref = create_module_ref(1, "kernel32.dll");

        // Add multiple P/Invoke methods from kernel32.dll
        let method1 = create_method("GetProcessId");
        let method2 = create_method("GetCurrentProcess");
        let method3 = create_method("ExitProcess");

        container
            .cil
            .add_method(
                "GetProcessId".to_string(),
                &Token::new(0x0A000001),
                method1,
                &module_ref,
            )
            .expect("Failed to add method import");

        container
            .cil
            .add_method(
                "GetCurrentProcess".to_string(),
                &Token::new(0x0A000002),
                method2,
                &module_ref,
            )
            .expect("Failed to add method import");

        container
            .cil
            .add_method(
                "ExitProcess".to_string(),
                &Token::new(0x0A000003),
                method3,
                &module_ref,
            )
            .expect("Failed to add method import");

        // Get DLL dependencies and check the functions
        let dependencies = container.get_all_dll_dependencies();
        let kernel32_dep = dependencies
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .expect("kernel32.dll should be in dependencies");

        assert!(
            kernel32_dep.functions.contains(&"GetProcessId".to_string()),
            "GetProcessId should be in functions. Found: {:?}",
            kernel32_dep.functions
        );
        assert!(
            kernel32_dep
                .functions
                .contains(&"GetCurrentProcess".to_string()),
            "GetCurrentProcess should be in functions"
        );
        assert!(
            kernel32_dep.functions.contains(&"ExitProcess".to_string()),
            "ExitProcess should be in functions"
        );
    }

    #[test]
    fn test_cil_pinvoke_find_by_name() {
        let container = UnifiedImportContainer::new();
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("TestPInvokeMethod");
        let token = Token::new(0x0A000001);

        container
            .cil
            .add_method("TestPInvokeMethod".to_string(), &token, method, &module_ref)
            .expect("Failed to add method import");

        // Find the import by name in the unified container
        let results = container.find_by_name("TestPInvokeMethod");
        assert_eq!(results.len(), 1, "Should find exactly one import");

        if let ImportEntry::Cil(cil_import) = &results[0] {
            assert_eq!(cil_import.name, "TestPInvokeMethod");
            assert_eq!(cil_import.token, token);
        } else {
            panic!("Expected CIL import entry, got Native");
        }
    }

    #[test]
    fn test_mixed_cil_and_native_same_dll() {
        let mut container = UnifiedImportContainer::new();

        // Add native import from kernel32.dll
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .expect("Failed to add native function");

        // Add CIL P/Invoke import from kernel32.dll
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetProcessId");
        container
            .cil
            .add_method(
                "GetProcessId".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // Verify both functions appear in the DLL dependencies
        let dependencies = container.get_all_dll_dependencies();
        let kernel32_dep = dependencies
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .expect("kernel32.dll should be in dependencies");

        assert!(
            kernel32_dep.functions.contains(&"GetLastError".to_string()),
            "GetLastError should be in functions (native)"
        );
        assert!(
            kernel32_dep.functions.contains(&"GetProcessId".to_string()),
            "GetProcessId should be in functions (CIL P/Invoke)"
        );

        // Verify the DLL source is Both (since it's used by both CIL and native)
        assert!(
            matches!(kernel32_dep.source, DllSource::Both(_)),
            "Source should be Both since both CIL and native use kernel32.dll. Got: {:?}",
            kernel32_dep.source
        );
    }

    #[test]
    fn test_cil_pinvoke_case_insensitive_dll_lookup() {
        let container = UnifiedImportContainer::new();

        // Add with lowercase
        let module_ref = create_module_ref(1, "KERNEL32.DLL");
        let method = create_method("TestFunc");
        container
            .cil
            .add_method(
                "TestFunc".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // get_functions_for_dll uses case-insensitive comparison
        let functions = container.get_functions_for_dll("kernel32.dll");
        assert!(
            functions.contains(&"TestFunc".to_string()),
            "Should find function with case-insensitive DLL name lookup"
        );
    }

    #[test]
    fn test_deduplication_cil_and_native_same_function() {
        let mut container = UnifiedImportContainer::new();

        // Add native import for GetLastError from kernel32.dll
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .expect("Failed to add native function");

        // Add CIL P/Invoke import for the same function
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetLastError");
        container
            .cil
            .add_method(
                "GetLastError".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // Find by name should return only ONE entry (the native one, since it has IAT info)
        let results = container.find_by_name("GetLastError");
        assert_eq!(
            results.len(),
            1,
            "Should deduplicate and return only one entry. Found: {}",
            results.len()
        );

        // The entry should be the native one
        assert!(
            matches!(&results[0], ImportEntry::Native(_)),
            "The deduplicated entry should be the Native import (has IAT info)"
        );
    }

    #[test]
    fn test_deduplication_case_insensitive() {
        let mut container = UnifiedImportContainer::new();

        // Add native import with different casing
        container
            .add_native_function("KERNEL32.DLL", "GetLastError")
            .expect("Failed to add native function");

        // Add CIL P/Invoke import with lowercase DLL and different function case
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GETLASTERROR");
        container
            .cil
            .add_method(
                "GETLASTERROR".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // Find by the CIL name - should not find it because it was deduplicated
        let results_cil = container.find_by_name("GETLASTERROR");
        assert_eq!(
            results_cil.len(),
            0,
            "CIL import with same function (case-insensitive) should be deduplicated"
        );

        // Find by the native name - should find exactly one
        let results_native = container.find_by_name("GetLastError");
        assert_eq!(results_native.len(), 1, "Native import should be present");
    }

    #[test]
    fn test_deduplication_preserves_non_duplicate_cil() {
        let mut container = UnifiedImportContainer::new();

        // Add native import
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .expect("Failed to add native function");

        // Add CIL P/Invoke import for a DIFFERENT function
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetProcessId");
        container
            .cil
            .add_method(
                "GetProcessId".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // GetProcessId should still be found (not deduplicated)
        let results = container.find_by_name("GetProcessId");
        assert_eq!(
            results.len(),
            1,
            "Non-duplicate CIL import should still be present"
        );
        assert!(
            matches!(&results[0], ImportEntry::Cil(_)),
            "Should be a CIL import entry"
        );

        // GetLastError should also be found
        let results_native = container.find_by_name("GetLastError");
        assert_eq!(results_native.len(), 1);
    }

    #[test]
    fn test_deduplication_dll_source_still_both() {
        let mut container = UnifiedImportContainer::new();

        // Add native import
        container
            .add_native_function("kernel32.dll", "GetLastError")
            .expect("Failed to add native function");

        // Add CIL P/Invoke import for the same function (will be deduplicated in name cache)
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetLastError");
        container
            .cil
            .add_method(
                "GetLastError".to_string(),
                &Token::new(0x0A000001),
                method,
                &module_ref,
            )
            .expect("Failed to add method import");

        // The DLL source should still be Both, even though the name entry is deduplicated
        // This is important for accurate dependency tracking
        let dependencies = container.get_all_dll_dependencies();
        let kernel32_dep = dependencies
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .expect("kernel32.dll should be in dependencies");

        assert!(
            matches!(kernel32_dep.source, DllSource::Both(_)),
            "DLL source should be Both even when name cache is deduplicated. Got: {:?}",
            kernel32_dep.source
        );
    }
}

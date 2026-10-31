//! Unified export container combining both CIL and native PE exports.
//!
//! This module provides the [`UnifiedExportContainer`] which serves as a unified interface
//! for managing both managed (.NET) exports and native PE export tables. It builds
//! on the existing sophisticated CIL export functionality while adding native support
//! through composition rather than duplication.
//!
//! # Architecture
//!
//! The container uses a compositional approach:
//! - **CIL Exports**: Existing [`super::Exports`] container handles managed exports
//! - **Native Exports**: New [`super::NativeExports`] handles PE export tables
//! - **Unified Views**: Lightweight caching for cross-cutting queries
//!
//! # Design Goals
//!
//! - **Preserve Excellence**: Leverage existing concurrent CIL functionality unchanged
//! - **Unified Interface**: Single API for both export types
//! - **Performance**: Minimal overhead with cached unified views
//! - **Backward Compatibility**: Existing CIL exports accessible via `.cil()`
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::exports::{UnifiedExportContainer, ExportEntry};
//!
//! let container = UnifiedExportContainer::new();
//!
//! // Access existing CIL functionality
//! let cil_exports = container.cil();
//! let type_export = cil_exports.find_by_name("MyClass", Some("MyNamespace"));
//!
//! // Use unified search across both export types
//! let all_functions = container.find_by_name("MyFunction");
//! for export in all_functions {
//!     match export {
//!         ExportEntry::Cil(cil_export) => println!("CIL: {}", cil_export.name),
//!         ExportEntry::Native(native_ref) => println!("Native: ordinal {}", native_ref.ordinal),
//!     }
//! }
//!
//! // Get all exported function names
//! let functions = container.get_all_exported_functions();
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::{mapref::entry::Entry, DashMap};

use crate::{
    metadata::{
        exports::{native::NativeExports, Exports as CilExports},
        tables::ExportedTypeRc,
        token::Token,
    },
    Result,
};

/// Unified container for both CIL and native PE exports.
///
/// This container provides a single interface for managing all types of exports
/// in a .NET assembly, including managed type exports and native PE export
/// table entries. It preserves the existing sophisticated CIL export
/// functionality while adding native support through composition.
///
/// # Thread Safety
///
/// All operations are thread-safe using interior mutability:
/// - CIL exports use existing concurrent data structures
/// - Native exports are thread-safe by design
/// - Unified caches use atomic coordination with compare-and-swap
///
/// # Cache Invalidation
///
/// The container maintains unified caches for cross-type queries like [`find_by_name`](Self::find_by_name)
/// and [`get_all_exported_functions`](Self::get_all_exported_functions). These caches are:
///
/// - **Invalidated automatically** when:
///   - Adding native functions via [`add_native_function`](Self::add_native_function)
///   - Adding ordinal-only functions via [`add_native_function_by_ordinal`](Self::add_native_function_by_ordinal)
///   - Adding forwarders via [`add_native_forwarder`](Self::add_native_forwarder)
///   - Accessing mutable native exports via [`native_mut`](Self::native_mut)
///
/// - **Rebuilt lazily** on the next unified query (not on invalidation)
///
/// - **Thread-safe**: Uses atomic compare-and-swap to ensure only one thread
///   rebuilds the cache, avoiding redundant work when multiple threads detect
///   a dirty cache simultaneously
///
/// # Performance
///
/// - CIL operations have identical performance to existing implementation
/// - Native operations use efficient hash-based lookups
/// - Unified views are cached and invalidated only when needed
/// - Lock-free access patterns throughout
/// - Cache rebuilds are O(n) where n is total export count
pub struct UnifiedExportContainer {
    /// CIL managed exports (existing sophisticated implementation)
    cil: CilExports,

    /// Native PE exports (new implementation)
    native: NativeExports,

    /// Cached unified view by name (lazy-populated)
    unified_name_cache: DashMap<String, Vec<ExportEntry>>,

    /// Cached all exported function names (lazy-populated)
    unified_function_cache: DashMap<String, ExportSource>,

    /// Flag indicating unified caches need rebuilding
    cache_dirty: AtomicBool,
}

/// Unified export entry that can represent either CIL or native exports.
#[derive(Clone)]
pub enum ExportEntry {
    /// Managed export from CIL metadata
    Cil(ExportedTypeRc),
    /// Native export from PE export table
    Native(NativeExportRef),
}

impl std::fmt::Debug for ExportEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportEntry::Cil(cil_export) => f
                .debug_struct("Cil")
                .field("name", &cil_export.name)
                .field("namespace", &cil_export.namespace)
                .finish(),
            ExportEntry::Native(native_ref) => f
                .debug_struct("Native")
                .field("ordinal", &native_ref.ordinal)
                .field("name", &native_ref.name)
                .finish(),
        }
    }
}

/// Reference to a native export function.
#[derive(Clone, Debug)]
pub struct NativeExportRef {
    /// Function ordinal number
    pub ordinal: u16,
    /// Function name (if exported by name)
    pub name: Option<String>,
    /// Function address or forwarder information
    pub address_or_forwarder: ExportTarget,
}

/// Target of a native export (address or forwarder).
#[derive(Clone, Debug)]
pub enum ExportTarget {
    /// Direct function address
    Address(u32),
    /// Forwarded to another DLL function
    Forwarder(String),
}

/// Source of an exported function.
#[derive(Clone, Debug)]
pub enum ExportSource {
    /// Exported only by CIL metadata
    Cil(Token),
    /// Exported only by native export table
    Native(u16), // ordinal
    /// Exported by both (rare but possible)
    Both(Token, u16),
}

/// Information about an exported function combining both sources.
#[derive(Clone, Debug)]
pub struct ExportedFunction {
    /// Function name
    pub name: String,
    /// Source of the export
    pub source: ExportSource,
    /// Whether it's a forwarder (native only)
    pub is_forwarder: bool,
    /// Target DLL for forwarders
    pub forwarder_target: Option<String>,
}

impl Clone for UnifiedExportContainer {
    fn clone(&self) -> Self {
        Self {
            cil: self.cil.clone(),
            native: self.native.clone(),
            unified_name_cache: DashMap::new(), // Reset cache on clone
            unified_function_cache: DashMap::new(), // Reset cache on clone
            cache_dirty: AtomicBool::new(true), // Mark cache as dirty
        }
    }
}

impl UnifiedExportContainer {
    /// Create a new empty export container.
    ///
    /// Initializes both CIL and native export storage with empty state.
    /// Unified caches are created lazily on first access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cil: CilExports::new(),
            native: NativeExports::new(""), // Empty DLL name initially
            unified_name_cache: DashMap::new(),
            unified_function_cache: DashMap::new(),
            cache_dirty: AtomicBool::new(true),
        }
    }

    /// Create a new export container with a specific DLL name for native exports.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL for native exports
    #[must_use]
    pub fn with_dll_name(dll_name: &str) -> Self {
        Self {
            cil: CilExports::new(),
            native: NativeExports::new(dll_name),
            unified_name_cache: DashMap::new(),
            unified_function_cache: DashMap::new(),
            cache_dirty: AtomicBool::new(true),
        }
    }

    /// Get the CIL exports container.
    ///
    /// Provides access to all existing CIL export functionality including
    /// sophisticated lookup methods, concurrent data structures, and
    /// cross-reference resolution.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// let cil_exports = container.cil();
    ///
    /// // Use existing CIL functionality
    /// let type_export = cil_exports.find_by_name("MyClass", Some("MyNamespace"));
    /// ```
    pub fn cil(&self) -> &CilExports {
        &self.cil
    }

    /// Get the native exports container.
    ///
    /// Provides access to PE export table functionality including
    /// function exports, forwarders, and ordinal management.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// let native_exports = container.native();
    ///
    /// // Check native function exports
    /// let function_names = native_exports.get_exported_function_names();
    /// println!("Native functions: {:?}", function_names);
    /// ```
    pub fn native(&self) -> &NativeExports {
        &self.native
    }

    /// Get mutable access to the native exports container.
    ///
    /// Provides mutable access for populating or modifying native export data.
    /// Used internally during assembly loading to populate from PE files.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let mut container = UnifiedExportContainer::new();
    /// container.native_mut().add_function("MyFunction", 1, 0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_mut(&mut self) -> &mut NativeExports {
        self.invalidate_cache();
        &mut self.native
    }

    /// Find all exports by name across both CIL and native sources.
    ///
    /// Searches both managed type exports and native function exports
    /// for the specified name. Results include exports from all sources.
    ///
    /// # Arguments
    /// * `name` - Name to search for
    ///
    /// # Returns
    /// Vector of all matching exports, may be empty if none found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::{UnifiedExportContainer, ExportEntry};
    /// let container = UnifiedExportContainer::new();
    /// let exports = container.find_by_name("MyFunction");
    ///
    /// for export in exports {
    ///     match export {
    ///         ExportEntry::Cil(cil_export) => {
    ///             println!("CIL export: {}", cil_export.name);
    ///         }
    ///         ExportEntry::Native(native_ref) => {
    ///             println!("Native export: ordinal {}", native_ref.ordinal);
    ///         }
    ///     }
    /// }
    /// ```
    pub fn find_by_name(&self, name: &str) -> Vec<ExportEntry> {
        self.ensure_cache_fresh();

        if let Some(entries) = self.unified_name_cache.get(name) {
            entries.value().clone()
        } else {
            Vec::new()
        }
    }

    /// Get all exported function names from both CIL and native sources.
    ///
    /// Returns comprehensive list of all exported functions including
    /// managed type names and native function names.
    ///
    /// # Returns
    /// Vector of all exported function names.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::{UnifiedExportContainer, ExportSource};
    /// let container = UnifiedExportContainer::new();
    /// let functions = container.get_all_exported_functions();
    ///
    /// for func in functions {
    ///     println!("Exported function: {} ({})", func.name,
    ///         match func.source {
    ///             ExportSource::Cil(_) => "CIL",
    ///             ExportSource::Native(_) => "Native",
    ///             ExportSource::Both(_, _) => "Both",
    ///         });
    /// }
    /// ```
    pub fn get_all_exported_functions(&self) -> Vec<ExportedFunction> {
        self.ensure_cache_fresh();

        self.unified_function_cache
            .iter()
            .map(|entry| {
                let name = entry.key().clone();
                let source = entry.value().clone();

                let (is_forwarder, forwarder_target) = match &source {
                    ExportSource::Native(ordinal) => {
                        if let Some(forwarder) = self.native.get_forwarder_by_ordinal(*ordinal) {
                            (true, Some(forwarder.target.clone()))
                        } else {
                            (false, None)
                        }
                    }
                    _ => (false, None),
                };

                ExportedFunction {
                    name,
                    source,
                    is_forwarder,
                    forwarder_target,
                }
            })
            .collect()
    }

    /// Get all native function names only.
    ///
    /// Returns just the native PE export function names,
    /// excluding CIL type exports.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// let native_functions = container.get_native_function_names();
    /// println!("Native functions: {:?}", native_functions);
    /// ```
    pub fn get_native_function_names(&self) -> Vec<String> {
        self.native.get_exported_function_names()
    }

    /// Check if the container has any exports (CIL or native).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// if container.is_empty() {
    ///     println!("No exports found");
    /// }
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cil.is_empty() && self.native.is_empty()
    }

    /// Get total count of all exports (CIL + native).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// println!("Total exports: {}", container.total_count());
    /// ```
    pub fn total_count(&self) -> usize {
        // `function_count` counts the forwarders as well
        self.cil.len().saturating_add(self.native.function_count())
    }

    /// Add a native function export.
    ///
    /// Convenience method for adding native function exports.
    ///
    /// # Arguments
    /// * `function_name` - Name of the function to export
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address in the image
    ///
    /// # Errors
    /// Returns error if the function name is invalid, ordinal is 0,
    /// or if the ordinal is already used.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_function("MyFunction", 1, 0x1000)?;
    /// container.add_native_function("AnotherFunction", 2, 0x2000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function(
        &mut self,
        function_name: &str,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        self.native.add_function(function_name, ordinal, address)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native function export by ordinal only.
    ///
    /// Convenience method for adding ordinal-only native function exports.
    ///
    /// # Arguments
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address in the image
    ///
    /// # Errors
    /// Returns error if ordinal is 0 or already used.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_function_by_ordinal(100, 0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_function_by_ordinal(&mut self, ordinal: u16, address: u32) -> Result<()> {
        self.native.add_function_by_ordinal(ordinal, address)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Add a native export forwarder.
    ///
    /// Convenience method for adding export forwarders that redirect
    /// calls to functions in other DLLs.
    ///
    /// # Arguments
    /// * `function_name` - Name of the forwarded function
    /// * `ordinal` - Ordinal number for the export
    /// * `forwarder_target` - Target DLL and function (e.g., "kernel32.dll.GetCurrentProcessId")
    ///
    /// # Errors
    /// Returns error if parameters are invalid or ordinal is already used.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let mut container = UnifiedExportContainer::new();
    /// container.add_native_forwarder("GetProcessId", 1, "kernel32.dll.GetCurrentProcessId")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_forwarder(
        &mut self,
        function_name: &str,
        ordinal: u16,
        forwarder_target: &str,
    ) -> Result<()> {
        self.native
            .add_forwarder(function_name, ordinal, forwarder_target)?;
        self.invalidate_cache();
        Ok(())
    }

    /// Get native export table data for PE writing.
    ///
    /// Generates PE export table data that can be written to the
    /// export directory of a PE file. Returns None if no native
    /// exports exist.
    ///
    /// # Errors
    ///
    /// Returns an error if native export table generation fails due to
    /// invalid export data or encoding issues.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let container = UnifiedExportContainer::new();
    /// if let Some(export_data) = container.get_export_table_data()? {
    ///     // Write export_data to PE export directory
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn get_export_table_data(&self) -> Result<Option<Vec<u8>>> {
        if self.native.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.native.get_export_table_data()?))
        }
    }

    /// Set the DLL name for native exports.
    ///
    /// Updates the DLL name used in the native export directory.
    /// This is the name that will appear in the PE export table.
    ///
    /// # Arguments
    /// * `dll_name` - New DLL name to use
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::exports::UnifiedExportContainer;
    /// let mut container = UnifiedExportContainer::new();
    /// container.set_dll_name("MyLibrary.dll")?;
    /// assert_eq!(container.native().dll_name(), "MyLibrary.dll");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn set_dll_name(&mut self, dll_name: &str) -> Result<()> {
        self.native.set_dll_name(dll_name)
    }

    /// Ensure unified caches are up to date.
    ///
    /// Uses compare-and-swap to ensure only one thread rebuilds the cache,
    /// preventing wasteful duplicate work when multiple threads detect a dirty cache.
    fn ensure_cache_fresh(&self) {
        // Try to atomically claim the rebuild by changing dirty from true to false
        // If we succeed, we're responsible for rebuilding the cache
        // If we fail, either cache is already clean or another thread is rebuilding it
        if self
            .cache_dirty
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // We won the race, rebuild the cache
            self.rebuild_unified_caches();
        }
    }

    /// Mark unified caches as dirty (need rebuilding).
    fn invalidate_cache(&self) {
        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    /// Rebuild all unified cache structures.
    fn rebuild_unified_caches(&self) {
        self.unified_name_cache.clear();
        self.unified_function_cache.clear();

        // Populate from CIL exports
        for export_entry in &self.cil {
            let export_type = export_entry.value();
            let token = *export_entry.key();

            // Add to name cache
            self.unified_name_cache
                .entry(export_type.name.clone())
                .or_default()
                .push(ExportEntry::Cil(export_type.clone()));

            // Add to function cache
            match self.unified_function_cache.entry(export_type.name.clone()) {
                Entry::Occupied(mut entry) => {
                    match entry.get() {
                        ExportSource::Native(ordinal) => {
                            *entry.get_mut() = ExportSource::Both(token, *ordinal);
                        }
                        ExportSource::Cil(_) | ExportSource::Both(_, _) => {
                            // Keep the existing CIL entry or both entry
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(ExportSource::Cil(token));
                }
            }
        }

        // Populate from native exports
        for function in self.native.functions() {
            if let Some(ref name) = function.name {
                // Add to name cache
                self.unified_name_cache
                    .entry(name.clone())
                    .or_default()
                    .push(ExportEntry::Native(NativeExportRef {
                        ordinal: function.ordinal,
                        name: Some(name.clone()),
                        address_or_forwarder: ExportTarget::Address(function.address),
                    }));

                // Add to function cache
                match self.unified_function_cache.entry(name.clone()) {
                    Entry::Occupied(mut entry) => {
                        match entry.get() {
                            ExportSource::Cil(token) => {
                                *entry.get_mut() = ExportSource::Both(*token, function.ordinal);
                            }
                            ExportSource::Native(_) | ExportSource::Both(_, _) => {
                                // Keep the existing native entry or both entry
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(ExportSource::Native(function.ordinal));
                    }
                }
            }
        }

        // Populate from native forwarders
        for forwarder in self.native.forwarders() {
            if let Some(ref name) = forwarder.name {
                // Add to name cache
                self.unified_name_cache
                    .entry(name.clone())
                    .or_default()
                    .push(ExportEntry::Native(NativeExportRef {
                        ordinal: forwarder.ordinal,
                        name: Some(name.clone()),
                        address_or_forwarder: ExportTarget::Forwarder(forwarder.target.clone()),
                    }));

                // Add to function cache
                self.unified_function_cache
                    .entry(name.clone())
                    .or_insert_with(|| ExportSource::Native(forwarder.ordinal));
            }
        }
    }
}

impl Default for UnifiedExportContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Implement common traits for convenience
impl std::fmt::Debug for UnifiedExportContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedExportContainer")
            .field("cil_count", &self.cil.len())
            .field("native_function_count", &self.native.function_count())
            .field("native_forwarder_count", &self.native.forwarder_count())
            .field("is_cache_dirty", &self.cache_dirty.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_export_container_new() {
        let container = UnifiedExportContainer::new();
        assert!(container.is_empty());
        assert_eq!(container.total_count(), 0);
    }

    #[test]
    fn test_unified_export_container_with_dll_name() {
        let container = UnifiedExportContainer::with_dll_name("MyLibrary.dll");
        assert!(container.is_empty());
    }

    #[test]
    fn test_unified_export_container_default() {
        let container = UnifiedExportContainer::default();
        assert!(container.is_empty());
    }

    #[test]
    fn test_add_native_function() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("TestFunction", 1, 0x1000)
            .unwrap();

        assert!(!container.is_empty());
        assert_eq!(container.total_count(), 1);
    }

    #[test]
    fn test_add_multiple_native_functions() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("Function1", 1, 0x1000)
            .unwrap();
        container
            .add_native_function("Function2", 2, 0x2000)
            .unwrap();
        container
            .add_native_function("Function3", 3, 0x3000)
            .unwrap();

        assert_eq!(container.total_count(), 3);
    }

    #[test]
    fn test_add_native_function_by_ordinal() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function_by_ordinal(100, 0x5000)
            .unwrap();

        assert!(!container.is_empty());
        assert_eq!(container.total_count(), 1);
    }

    #[test]
    fn test_add_native_function_invalid_ordinal() {
        let mut container = UnifiedExportContainer::new();
        // Ordinal 0 should be invalid
        let result = container.add_native_function("Test", 0, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_native_function_duplicate_ordinal() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("Function1", 1, 0x1000)
            .unwrap();
        // Adding another function with the same ordinal should fail
        let result = container.add_native_function("Function2", 1, 0x2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_native_forwarder() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_forwarder("ForwardedFunction", 1, "kernel32.dll.GetCurrentProcessId")
            .unwrap();

        assert!(!container.is_empty());
        // total_count includes both function_count and forwarder_count
        // The implementation stores forwarders as both a function and forwarder entry
        assert!(container.total_count() >= 1);
        assert!(container.native().forwarder_count() >= 1);
    }

    #[test]
    fn test_find_by_name_native() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("MyExport", 1, 0x1000)
            .unwrap();

        let results = container.find_by_name("MyExport");
        assert_eq!(results.len(), 1);

        let ExportEntry::Native(native_ref) = &results[0] else {
            panic!("Expected Native export entry, got {:?}", results[0]);
        };
        assert_eq!(native_ref.ordinal, 1);
        assert_eq!(native_ref.name, Some("MyExport".to_string()));
    }

    #[test]
    fn test_find_by_name_not_found() {
        let container = UnifiedExportContainer::new();
        let results = container.find_by_name("NonExistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_native_function_names() {
        let mut container = UnifiedExportContainer::new();
        container.add_native_function("Alpha", 1, 0x1000).unwrap();
        container.add_native_function("Beta", 2, 0x2000).unwrap();
        container.add_native_function("Gamma", 3, 0x3000).unwrap();

        let names = container.get_native_function_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"Alpha".to_string()));
        assert!(names.contains(&"Beta".to_string()));
        assert!(names.contains(&"Gamma".to_string()));
    }

    #[test]
    fn test_get_all_exported_functions() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("NativeFunc", 1, 0x1000)
            .unwrap();

        let functions = container.get_all_exported_functions();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "NativeFunc");

        let ExportSource::Native(ordinal) = functions[0].source else {
            panic!(
                "Expected Native export source, got {:?}",
                functions[0].source
            );
        };
        assert_eq!(ordinal, 1);
    }

    #[test]
    fn test_get_all_exported_functions_with_forwarder() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_forwarder("ForwardedFunc", 1, "other.dll.RealFunc")
            .unwrap();

        let functions = container.get_all_exported_functions();
        assert_eq!(functions.len(), 1);
        assert!(functions[0].is_forwarder);
        assert_eq!(
            functions[0].forwarder_target,
            Some("other.dll.RealFunc".to_string())
        );
    }

    #[test]
    fn test_cil_accessor() {
        let container = UnifiedExportContainer::new();
        let cil = container.cil();
        assert!(cil.is_empty());
    }

    #[test]
    fn test_native_accessor() {
        let container = UnifiedExportContainer::new();
        let native = container.native();
        assert!(native.is_empty());
    }

    #[test]
    fn test_native_mut_invalidates_cache() {
        let mut container = UnifiedExportContainer::new();
        container.add_native_function("Test", 1, 0x1000).unwrap();

        // Force cache to be built
        let _ = container.find_by_name("Test");

        // Mutating native should invalidate cache
        let _ = container.native_mut();

        // Cache should be dirty now
        assert!(container.cache_dirty.load(Ordering::Relaxed));
    }

    #[test]
    fn test_clone_resets_cache() {
        let mut container = UnifiedExportContainer::new();
        container.add_native_function("Test", 1, 0x1000).unwrap();

        // Force cache to be built
        let _ = container.find_by_name("Test");

        // Clone should reset cache to dirty
        let cloned = container.clone();
        assert!(cloned.cache_dirty.load(Ordering::Relaxed));

        // But data should be preserved
        assert_eq!(cloned.total_count(), 1);
    }

    #[test]
    fn test_debug_output() {
        let mut container = UnifiedExportContainer::new();
        container.add_native_function("Test", 1, 0x1000).unwrap();

        let debug_output = format!("{:?}", container);
        assert!(debug_output.contains("UnifiedExportContainer"));
        assert!(debug_output.contains("native_function_count"));
    }

    #[test]
    fn test_export_target_address() {
        let target = ExportTarget::Address(0x1234);
        let ExportTarget::Address(addr) = target else {
            panic!("Expected Address variant, got {:?}", target);
        };
        assert_eq!(addr, 0x1234);
    }

    #[test]
    fn test_export_target_forwarder() {
        let target = ExportTarget::Forwarder("kernel32.dll.Func".to_string());
        let ExportTarget::Forwarder(ref fwd) = target else {
            panic!("Expected Forwarder variant, got {:?}", target);
        };
        assert_eq!(fwd, "kernel32.dll.Func");
    }

    #[test]
    fn test_export_source_variants() {
        let token = Token::new(0x02000001);

        let cil_source = ExportSource::Cil(token);
        if let ExportSource::Cil(t) = cil_source {
            assert_eq!(t, token);
        }

        let native_source = ExportSource::Native(42);
        if let ExportSource::Native(ord) = native_source {
            assert_eq!(ord, 42);
        }

        let both_source = ExportSource::Both(token, 42);
        if let ExportSource::Both(t, ord) = both_source {
            assert_eq!(t, token);
            assert_eq!(ord, 42);
        }
    }

    #[test]
    fn test_native_export_ref_clone() {
        let export_ref = NativeExportRef {
            ordinal: 1,
            name: Some("TestFunc".to_string()),
            address_or_forwarder: ExportTarget::Address(0x1000),
        };

        let cloned = export_ref.clone();
        assert_eq!(cloned.ordinal, 1);
        assert_eq!(cloned.name, Some("TestFunc".to_string()));
    }

    #[test]
    fn test_exported_function_structure() {
        let func = ExportedFunction {
            name: "TestFunction".to_string(),
            source: ExportSource::Native(1),
            is_forwarder: false,
            forwarder_target: None,
        };

        assert_eq!(func.name, "TestFunction");
        assert!(!func.is_forwarder);
        assert!(func.forwarder_target.is_none());
    }

    #[test]
    fn test_exported_function_forwarder() {
        let func = ExportedFunction {
            name: "ForwardedFunc".to_string(),
            source: ExportSource::Native(1),
            is_forwarder: true,
            forwarder_target: Some("target.dll.RealFunc".to_string()),
        };

        assert!(func.is_forwarder);
        assert_eq!(
            func.forwarder_target,
            Some("target.dll.RealFunc".to_string())
        );
    }

    #[test]
    fn test_set_dll_name() {
        let mut container = UnifiedExportContainer::new();
        assert_eq!(container.native().dll_name(), "");

        container.set_dll_name("MyLibrary.dll").unwrap();
        assert_eq!(container.native().dll_name(), "MyLibrary.dll");

        // Can be changed again
        container.set_dll_name("AnotherName.dll").unwrap();
        assert_eq!(container.native().dll_name(), "AnotherName.dll");
    }

    #[test]
    fn test_set_dll_name_validation() {
        let mut container = UnifiedExportContainer::new();

        // Empty name should fail
        let result = container.set_dll_name("");
        assert!(result.is_err());

        // Null bytes should fail
        let result = container.set_dll_name("test\0.dll");
        assert!(result.is_err());

        // Valid name should succeed
        let result = container.set_dll_name("Valid.dll");
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_freshness_compare_and_swap() {
        let mut container = UnifiedExportContainer::new();
        container
            .add_native_function("TestFunc", 1, 0x1000)
            .unwrap();

        // Cache should be dirty initially
        assert!(container.cache_dirty.load(Ordering::Relaxed));

        // First call to ensure_cache_fresh should rebuild
        container.ensure_cache_fresh();

        // Cache should now be clean
        assert!(!container.cache_dirty.load(Ordering::Relaxed));

        // Second call should not rebuild (cache is already fresh)
        container.ensure_cache_fresh();

        // Cache should still be clean
        assert!(!container.cache_dirty.load(Ordering::Relaxed));

        // After invalidation, cache should be dirty again
        container.invalidate_cache();
        assert!(container.cache_dirty.load(Ordering::Relaxed));

        // Ensure fresh should rebuild and mark clean
        container.ensure_cache_fresh();
        assert!(!container.cache_dirty.load(Ordering::Relaxed));
    }

    #[test]
    fn test_cache_invalidation_on_mutation() {
        let mut container = UnifiedExportContainer::new();

        // Add a function and build cache
        container.add_native_function("Func1", 1, 0x1000).unwrap();
        let _ = container.find_by_name("Func1");
        assert!(!container.cache_dirty.load(Ordering::Relaxed));

        // Mutating should invalidate cache
        container.add_native_function("Func2", 2, 0x2000).unwrap();
        assert!(container.cache_dirty.load(Ordering::Relaxed));

        // Cache should rebuild on next access
        let results = container.find_by_name("Func2");
        assert_eq!(results.len(), 1);
        assert!(!container.cache_dirty.load(Ordering::Relaxed));
    }

    #[test]
    fn test_mixed_native_function_types() {
        let mut container = UnifiedExportContainer::new();

        // Add named function
        container
            .add_native_function("NamedFunc", 1, 0x1000)
            .unwrap();

        // Add ordinal-only function
        container.add_native_function_by_ordinal(2, 0x2000).unwrap();

        // Add forwarder
        container
            .add_native_forwarder("ForwardedFunc", 3, "kernel32.dll.GetCurrentProcessId")
            .unwrap();

        // Verify counts
        assert_eq!(container.native().function_count(), 3);
        assert_eq!(container.native().forwarder_count(), 1);
        assert_eq!(container.total_count(), 3, "a forwarder counts once");

        // Verify named function is findable
        let named_results = container.find_by_name("NamedFunc");
        assert_eq!(named_results.len(), 1);

        // Verify forwarder is findable
        let forwarder_results = container.find_by_name("ForwardedFunc");
        assert_eq!(forwarder_results.len(), 1);

        // Verify all exported functions
        let all_functions = container.get_all_exported_functions();
        assert_eq!(all_functions.len(), 2); // Only named exports appear here

        // Check forwarder details
        let forwarder_func = all_functions
            .iter()
            .find(|f| f.name == "ForwardedFunc")
            .unwrap();
        assert!(forwarder_func.is_forwarder);
        assert_eq!(
            forwarder_func.forwarder_target,
            Some("kernel32.dll.GetCurrentProcessId".to_string())
        );
    }

    #[test]
    fn test_export_table_generation() {
        let mut container = UnifiedExportContainer::with_dll_name("TestLib.dll");

        container
            .add_native_function("Function1", 1, 0x1000)
            .unwrap();
        container
            .add_native_function("Function2", 2, 0x2000)
            .unwrap();

        // Set base RVA before generating table data
        container.native_mut().set_export_table_base_rva(0x3000);

        // Generate export table data
        let data = container.get_export_table_data().unwrap();
        assert!(data.is_some());

        let table_data = data.unwrap();
        // Export directory is 40 bytes minimum
        assert!(table_data.len() >= 40);
    }

    #[test]
    fn test_empty_container_export_table() {
        let container = UnifiedExportContainer::new();

        // Empty container should return None for export table data
        let data = container.get_export_table_data().unwrap();
        assert!(data.is_none());
    }

    #[test]
    fn test_unified_find_by_name_multiple_sources() {
        let mut container = UnifiedExportContainer::new();

        // Add multiple functions with same base name pattern
        container
            .add_native_function("ProcessData", 1, 0x1000)
            .unwrap();
        container
            .add_native_function("ProcessFile", 2, 0x2000)
            .unwrap();
        container
            .add_native_forwarder("ProcessMessage", 3, "other.dll.HandleMessage")
            .unwrap();

        // Each should be findable individually
        assert_eq!(container.find_by_name("ProcessData").len(), 1);
        assert_eq!(container.find_by_name("ProcessFile").len(), 1);
        assert_eq!(container.find_by_name("ProcessMessage").len(), 1);

        // Non-existent should return empty
        assert!(container.find_by_name("NonExistent").is_empty());
    }

    #[test]
    fn test_native_function_names_list() {
        let mut container = UnifiedExportContainer::new();

        container.add_native_function("Alpha", 1, 0x1000).unwrap();
        container.add_native_function("Beta", 2, 0x2000).unwrap();
        container.add_native_function_by_ordinal(3, 0x3000).unwrap(); // No name
        container
            .add_native_forwarder("Gamma", 4, "lib.dll.Func")
            .unwrap();

        let names = container.get_native_function_names();

        // Should include Alpha, Beta, and Gamma (named exports only)
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"Alpha".to_string()));
        assert!(names.contains(&"Beta".to_string()));
        assert!(names.contains(&"Gamma".to_string()));
    }
}

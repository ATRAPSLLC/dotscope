//! Analysis and representation of exported types in .NET assemblies.
//!
//! This module provides comprehensive functionality for tracking and analyzing all types
//! exported by a .NET assembly, including those made available to other assemblies,
//! COM clients, and external consumers. Essential for dependency analysis, interoperability
//! scenarios, and assembly metadata inspection workflows.
//!
//! # Architecture
//!
//! The module implements a thread-safe container for exported type metadata using
//! lock-free concurrent data structures. The architecture provides:
//!
//! - **Efficient Lookups**: O(log n) token-based access with concurrent safety
//! - **Name-based Searching**: Linear search capabilities by type name and namespace
//! - **Iterator Support**: Complete traversal of all exported types
//! - **Memory Management**: Reference counting for efficient memory usage
//!
//! # Key Components
//!
//! - [`crate::metadata::exports::Exports`] - Main container for exported type metadata
//! - [`crate::metadata::tables::ExportedTypeRc`] - Reference-counted exported type instances
//! - [`crate::metadata::tables::ExportedTypeMap`] - Thread-safe concurrent map implementation
//!
//! # Use Cases
//!
//! - **Dependency Analysis**: Identify types exposed by referenced assemblies
//! - **COM Interop**: Track types exported for COM visibility
//! - **Metadata Inspection**: Enumerate all publicly available types
//! - **Assembly Loading**: Resolve type references across assembly boundaries
//! - **Type Resolution**: Cross-assembly type lookup and validation
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::exports::Exports;
//! use dotscope::metadata::token::Token;
//!
//! let exports = Exports::new();
//!
//! // Find exported type by name and namespace
//! if let Some(exported_type) = exports.find_by_name("String", Some("System")) {
//!     println!("Found exported type: {} in namespace System", exported_type.name);
//! }
//!
//! // Iterate through all exported types
//! for entry in &exports {
//!     let token = entry.key();
//!     let exported_type = entry.value();
//!     println!("Token: {}, Type: {}", token, exported_type.name);
//! }
//! ```
//!
//! # Thread Safety
//!
//! All operations are thread-safe using lock-free data structures from the
//! [`crossbeam_skiplist`] crate. The [`crate::metadata::exports::Exports`] container
//! is [`std::marker::Send`] and [`std::marker::Sync`], enabling efficient concurrent
//! access patterns common in metadata processing scenarios. Multiple threads can
//! safely read, write, and iterate over exported types simultaneously.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Provides ExportedType table data structures
//! - [`crate::metadata::token`] - Token-based type identification system
//! - [`crate::metadata::typesystem`] - Type reference resolution and validation
//! - [`crate::CilObject`] - Assembly-level exported type management
use std::sync::Arc;

use crossbeam_skiplist::map::Entry;

use crate::{
    metadata::{
        tables::{ExportedTypeList, ExportedTypeMap, ExportedTypeRc},
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Container for exported types from a .NET assembly.
///
/// Provides efficient storage, lookup, and iteration over all types exported by an assembly.
/// Uses [`crossbeam_skiplist::SkipMap`] for thread-safe concurrent access with O(log n)
/// operations and lock-free performance characteristics.
///
/// # Storage Strategy
/// - **Token-based indexing**: Primary lookup by [`crate::metadata::token::Token`]
/// - **Concurrent access**: Lock-free operations for multi-threaded scenarios
/// - **Memory efficient**: Reference counting via [`crate::metadata::tables::ExportedTypeRc`]
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::exports::Exports;
/// use dotscope::metadata::token::Token;
///
/// let exports = Exports::new();
///
/// # fn get_exported_type() -> dotscope::metadata::tables::ExportedTypeRc { todo!() }
/// let exported_type = get_exported_type();
/// let token = Token::new(0x27000001); // ExportedType token
///
/// // Insert an exported type
/// exports.insert(token, exported_type.clone())?;
///
/// // Look up by token
/// if let Some(entry) = exports.get(&token) {
///     println!("Found exported type: {}", entry.value().name);
/// }
///
/// // Search by name and namespace
/// if let Some(found) = exports.find_by_name("MyClass", Some("MyNamespace")) {
///     println!("Type {} found in namespace MyNamespace", found.name);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`Exports`] is [`std::marker::Send`] and [`std::marker::Sync`], enabling safe concurrent access
/// from multiple threads. All operations use lock-free data structures for optimal performance
/// in multi-threaded scenarios.
pub struct Exports {
    /// Internal storage for exported type mappings
    data: ExportedTypeMap,
}

impl Exports {
    /// Create a new empty [`Exports`] container.
    ///
    /// Initializes an empty concurrent skip map for exported type storage.
    /// The container is immediately ready for concurrent insert and lookup operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    /// assert!(exports.is_empty());
    /// assert_eq!(exports.len(), 0);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new() -> Self {
        Exports {
            data: ExportedTypeMap::new(),
        }
    }

    /// Insert a new exported type with its token.
    ///
    /// Associates an [`crate::metadata::tables::ExportedType`] with its metadata token
    /// for efficient lookup. The operation is thread-safe and lock-free.
    ///
    /// # Arguments
    /// * `token` - The [`crate::metadata::token::Token`] identifying this exported type
    /// * `export` - The [`crate::metadata::tables::ExportedTypeRc`] to store
    ///
    /// # Returns
    /// Currently always returns `Ok(())`, but the [`crate::Result`] signature allows
    /// for future error conditions such as validation or capacity limits.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    /// use dotscope::metadata::token::Token;
    ///
    /// let exports = Exports::new();
    /// # fn get_exported_type() -> dotscope::metadata::tables::ExportedTypeRc { todo!() }
    /// let exported_type = get_exported_type();
    /// let token = Token::new(0x27000001);
    ///
    /// exports.insert(token, exported_type)?;
    /// assert_eq!(exports.len(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// This method currently does not return any errors but maintains a `Result` return type
    /// for future compatibility with potential validation or storage constraints.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn insert(&self, token: Token, export: ExportedTypeRc) -> Result<()> {
        self.data.insert(token, export);

        Ok(())
    }

    /// Get an exported type by its metadata token.
    ///
    /// Performs O(log n) lookup in the concurrent skip map to find the exported type
    /// associated with the given token. Returns an entry that provides access to both
    /// the key and value without additional lookups.
    ///
    /// # Arguments
    /// * `token` - The [`crate::metadata::token::Token`] to search for
    ///
    /// # Returns
    /// An optional [`crossbeam_skiplist::map::Entry`] containing the token and
    /// [`crate::metadata::tables::ExportedTypeRc`] if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::exports::Exports;
    /// use dotscope::metadata::token::Token;
    ///
    /// let exports = Exports::new();
    /// let token = Token::new(0x27000001);
    ///
    /// if let Some(entry) = exports.get(&token) {
    ///     println!("Found exported type: {}", entry.value().name);
    ///     assert_eq!(*entry.key(), token);
    /// } else {
    ///     println!("No exported type found for token {}", token);
    /// };
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn get(&self, token: &Token) -> Option<Entry<'_, Token, ExportedTypeRc>> {
        self.data.get(token)
    }

    /// Get direct access to the underlying exported types map.
    ///
    /// Returns a reference to the internal [`crate::metadata::tables::ExportedTypeMap`]
    /// for advanced operations that require direct map access. Use this when you need
    /// to perform multiple operations or custom iteration patterns.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    /// let map = exports.types();
    ///
    /// // Direct map operations
    /// println!("Map contains {} exported types", map.len());
    /// ```
    pub fn types(&self) -> &ExportedTypeMap {
        &self.data
    }

    /// Get an iterator over all exported types.
    ///
    /// Returns an iterator that yields [`crossbeam_skiplist::map::Entry`] instances,
    /// each containing a ([`crate::metadata::token::Token`], [`crate::metadata::tables::ExportedTypeRc`]) pair.
    /// The iteration order is sorted by token value due to the skip map's ordering properties.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    ///
    /// // Iterate through all exported types
    /// for entry in exports.iter() {
    ///     let token = entry.key();
    ///     let exported_type = entry.value();
    ///     println!("Token: {}, Name: {}", token, exported_type.name);
    /// }
    /// ```
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<'_, Token, ExportedTypeRc> {
        self.data.iter()
    }

    /// Find an exported type by its name and optional namespace.
    ///
    /// Performs a linear search through all exported types to find one matching
    /// the specified name and namespace criteria. This is less efficient than
    /// token-based lookup but essential for name-based type resolution.
    ///
    /// # Arguments
    /// * `name` - The type name to search for (case-sensitive)
    /// * `namespace` - Optional namespace to match, `None` for types in the global namespace
    ///
    /// # Returns
    /// The first [`crate::metadata::tables::ExportedTypeRc`] matching the criteria, or `None` if not found.
    ///
    /// # Matching Rules
    /// - **Name**: Exact case-sensitive match required
    /// - **Namespace**: `Some("")` matches empty namespace, `None` matches missing namespace
    /// - **Order**: Returns the first match encountered (iteration order by token)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    ///
    /// // Find type in specific namespace
    /// if let Some(string_type) = exports.find_by_name("String", Some("System")) {
    ///     println!("Found System.String: {}", string_type.name);
    /// }
    ///
    /// // Find type in global namespace
    /// if let Some(global_type) = exports.find_by_name("GlobalType", None) {
    ///     println!("Found global type: {}", global_type.name);
    /// }
    /// ```
    pub fn find_by_name(&self, name: &str, namespace: Option<&str>) -> Option<ExportedTypeRc> {
        for exported_type in &self.data {
            let exported = exported_type.value();

            if exported.name == name {
                if let Some(ns) = namespace {
                    if let Some(exported_ns) = &exported.namespace {
                        if exported_ns == ns {
                            return Some(exported.clone());
                        }
                    } else if ns.is_empty() {
                        return Some(exported.clone());
                    }
                } else if exported.namespace.is_none() {
                    return Some(exported.clone());
                }
            }
        }

        None
    }

    /// Find exported types by their implementation reference.
    ///
    /// Searches for all exported types that have the specified implementation reference.
    /// Implementation references indicate where the actual type definition resides,
    /// which can be a file, assembly reference, or another exported type.
    ///
    /// # Arguments
    /// * `reference` - The [`crate::metadata::typesystem::CilTypeReference`] to match against
    ///
    /// # Returns
    /// A [`crate::metadata::tables::ExportedTypeList`] containing all matching exported types.
    /// The list is empty if no matches are found.
    ///
    /// # Implementation Matching
    /// Compares tokens for each reference type:
    /// - **File**: Matches [`crate::metadata::typesystem::CilTypeReference::File`] tokens
    /// - **`AssemblyRef`**: Matches [`crate::metadata::typesystem::CilTypeReference::AssemblyRef`] tokens  
    /// - **`ExportedType`**: Matches [`crate::metadata::typesystem::CilTypeReference::ExportedType`] tokens
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    /// use dotscope::metadata::typesystem::CilTypeReference;
    ///
    /// let exports = Exports::new();
    /// # fn get_assembly_ref() -> CilTypeReference { todo!() }
    /// let assembly_ref = get_assembly_ref();
    ///
    /// let matching_types = exports.find_by_implementation(&assembly_ref);
    ///
    /// for (_, exported_type) in matching_types.iter() {
    ///     println!("Type: {}", exported_type.name);
    /// }
    /// ```
    pub fn find_by_implementation(&self, reference: &CilTypeReference) -> ExportedTypeList {
        let result = Arc::new(boxcar::Vec::new());

        for exported_type in &self.data {
            let borrowed = exported_type.value();

            // Compare implementation references
            if let Some(implementation) = borrowed.get_implementation() {
                match (implementation, reference) {
                    (CilTypeReference::File(a), CilTypeReference::File(b))
                        if a.token == b.token =>
                    {
                        result.push(borrowed.clone());
                    }
                    (CilTypeReference::AssemblyRef(a), CilTypeReference::AssemblyRef(b))
                        if a.token == b.token =>
                    {
                        result.push(borrowed.clone());
                    }
                    (CilTypeReference::ExportedType(a), CilTypeReference::ExportedType(b))
                        if a.token == b.token =>
                    {
                        result.push(borrowed.clone());
                    }
                    _ => {}
                }
            }
        }

        result
    }

    /// Return the number of exported types in the container.
    ///
    /// This operation is O(1) as the skip map maintains an internal count.
    /// Useful for statistics, capacity planning, and determining if the
    /// container has any content.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    /// assert_eq!(exports.len(), 0);
    ///
    /// # fn add_some_exports(exports: &Exports) {}
    /// add_some_exports(&exports);
    /// println!("Container now has {} exported types", exports.len());
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the container contains no exported types.
    ///
    /// Equivalent to `self.len() == 0` but may be more semantically clear
    /// in conditional expressions. This operation is O(1).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::Exports;
    ///
    /// let exports = Exports::new();
    /// assert!(exports.is_empty());
    ///
    /// # fn add_exported_type(exports: &Exports) -> dotscope::Result<()> { Ok(()) }
    /// add_exported_type(&exports)?;
    /// assert!(!exports.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a> IntoIterator for &'a Exports {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, ExportedTypeRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, ExportedTypeRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Default for Exports {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Exports {
    fn clone(&self) -> Self {
        // Create a new Exports container and copy all entries
        let new_exports = Self::new();
        for entry in &self.data {
            new_exports.data.insert(*entry.key(), entry.value().clone());
        }
        new_exports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{identity::AssemblyIdentity, token::Token, typesystem::TypeRegistry},
        testkit::{create_cil_type, create_exportedtype},
    };

    #[test]
    fn new_exports_is_empty() {
        let exports = Exports::new();
        assert_eq!(exports.len(), 0);
        assert!(exports.is_empty());
    }

    #[test]
    fn find_by_name_works() {
        let exports = Exports::new();

        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let type_registry = TypeRegistry::new(test_identity).unwrap();
        let dummy_type = create_cil_type(Token::new(0x02000001), "TestNamespace", "TestType", None);
        type_registry.insert(&dummy_type);

        let exported_type = create_exportedtype(dummy_type);

        // Add the exported type to the exports
        exports
            .data
            .insert(Token::new(0x27000001), exported_type.clone());

        // Test finding by name and namespace
        let found = exports.find_by_name("ExportedType", Some("Test.Namespace"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, Token::new(0x27000001));

        // Test not finding with wrong namespace
        let not_found = exports.find_by_name("ExportedType", Some("Wrong.Namespace"));
        assert!(not_found.is_none());

        // Test not finding with wrong name
        let not_found = exports.find_by_name("WrongName", Some("Test.Namespace"));
        assert!(not_found.is_none());
    }

    #[test]
    fn iter_works() {
        let exports = Exports::new();

        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let type_registry = TypeRegistry::new(test_identity).unwrap();
        let dummy_type1 =
            create_cil_type(Token::new(0x02000001), "TestNamespace", "TestType1", None);
        let dummy_type2 =
            create_cil_type(Token::new(0x02000002), "TestNamespace", "TestType2", None);
        type_registry.insert(&dummy_type1);
        type_registry.insert(&dummy_type2);

        let exported_type1 = create_exportedtype(dummy_type1);
        let exported_type2 = create_exportedtype(dummy_type2);

        // Add the exported types to the exports
        exports.data.insert(Token::new(0x27000001), exported_type1);
        exports.data.insert(Token::new(0x27000002), exported_type2);

        // Test that we can iterate over all exported types
        let mut count = 0;
        let mut tokens = Vec::new();

        for entry in exports.iter() {
            count += 1;
            tokens.push(*entry.key());
        }

        assert_eq!(count, 2);
        assert!(tokens.contains(&Token::new(0x27000001)));
        assert!(tokens.contains(&Token::new(0x27000002)));
    }
}

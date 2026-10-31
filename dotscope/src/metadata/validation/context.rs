//! Validation context types and implementations for the unified validation framework.
//!
//! This module provides context abstractions that allow validators to operate on different
//! types of metadata (raw vs owned) while maintaining a unified interface. The context
//! system supports both raw metadata validation (Stage 1) and owned metadata validation (Stage 2).
//!
//! # Architecture
//!
//! The validation system operates through two main context types:
//! - [`crate::metadata::validation::context::RawValidationContext`] - For raw metadata validation during assembly loading
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - For owned metadata validation with resolved data structures
//!
//! Both contexts implement the [`crate::metadata::validation::context::ValidationContext`] trait,
//! providing common functionality while allowing stage-specific operations.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::context::ValidationContext`] - Base trait for all validation contexts
//! - [`crate::metadata::validation::context::RawValidationContext`] - Context for Stage 1 raw validation
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Context for Stage 2 owned validation
//! - [`crate::metadata::validation::context::ValidationStage`] - Enumeration of validation stages
//! - [`crate::metadata::validation::context::factory`] - Factory functions for creating contexts
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawValidationContext, ValidationContext, ValidationConfig, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//! let config = ValidationConfig::production();
//!
//! // Create raw validation context for loading
//! let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
//! assert!(context.is_loading_validation());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`] when their contained references are.
//! Contexts are typically short-lived and used within a single validation run.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Uses contexts to execute validation
//! - [`crate::metadata::validation::traits`] - Validators receive contexts as parameters
//! - [`crate::metadata::validation::scanner`] - Provides shared reference scanning capabilities

use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashMap;

use crate::{
    cilassembly::AssemblyChanges,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        method::Method,
        token::Token,
        typesystem::{CilTypeRc, TypeSource},
        validation::{config::ValidationConfig, scanner::ReferenceScanner},
    },
};

/// Validation stage indicator for context discrimination.
///
/// Represents the two validation stages in the dotscope validation system:
/// raw metadata validation and owned metadata validation.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationStage;
///
/// let stage = ValidationStage::Raw;
/// assert_eq!(stage, ValidationStage::Raw);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStage {
    /// Stage 1: Raw metadata validation using [`crate::metadata::cilassemblyview::CilAssemblyView`]
    Raw,
    /// Stage 2: Owned metadata validation using [`crate::metadata::cilobject::CilObject`]
    Owned,
}

/// Base trait for all validation contexts.
///
/// This trait provides common functionality that all validation contexts must implement,
/// regardless of the validation stage or data type being validated. It ensures consistent
/// access to validation configuration and shared resources.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{ValidationContext, ValidationStage, ValidationConfig};
///
/// fn check_context<T: ValidationContext>(context: &T) {
///     match context.validation_stage() {
///         ValidationStage::Raw => println!("Raw validation context"),
///         ValidationStage::Owned => println!("Owned validation context"),
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// Implementations are thread-safe when their contained references are thread-safe.
pub trait ValidationContext {
    /// Returns the validation stage this context represents.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::context::ValidationStage`] indicating whether
    /// this is a raw or owned validation context.
    fn validation_stage(&self) -> ValidationStage;

    /// Returns a reference to the shared reference scanner.
    ///
    /// The reference scanner is used for efficient cross-table reference validation
    /// and is shared across all validators in a validation run.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::validation::scanner::ReferenceScanner`]
    /// for this validation context.
    fn reference_scanner(&self) -> &ReferenceScanner;

    /// Returns a reference to the validation configuration.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::validation::config::ValidationConfig`]
    /// that controls validation behavior.
    fn config(&self) -> &ValidationConfig;
}

/// Context for Stage 1 (raw) validation.
///
/// This context is used when validating raw metadata through [`crate::metadata::cilassemblyview::CilAssemblyView`],
/// either during initial loading or when validating assembly modifications.
/// It supports both scenarios through the optional changes parameter.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{RawValidationContext, ValidationConfig, ReferenceScanner};
/// use dotscope::metadata::cilassemblyview::CilAssemblyView;
/// use std::path::Path;
///
/// # let path = Path::new("assembly.dll");
/// let view = CilAssemblyView::from_path(&path)?;
/// let scanner = ReferenceScanner::from_view(&view)?;
/// let config = ValidationConfig::minimal();
///
/// // Create context for loading validation
/// let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
/// assert!(context.is_loading_validation());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This struct is [`Send`] and [`Sync`] when all contained references are thread-safe.
pub struct RawValidationContext<'a> {
    /// The assembly view containing raw metadata
    view: &'a CilAssemblyView,
    /// Optional assembly changes for modification validation
    changes: Option<&'a AssemblyChanges>,
    /// Shared reference scanner for efficient validation
    scanner: &'a ReferenceScanner,
    /// Validation configuration
    config: &'a ValidationConfig,
}

impl<'a> RawValidationContext<'a> {
    /// Creates a new raw validation context for loading validation.
    ///
    /// This constructor is used when validating a [`crate::metadata::cilassemblyview::CilAssemblyView`] during loading,
    /// without any modifications.
    ///
    /// # Arguments
    ///
    /// * `view` - The [`crate::metadata::cilassemblyview::CilAssemblyView`] to validate
    /// * `scanner` - Shared [`crate::metadata::validation::scanner::ReferenceScanner`] for cross-table validation
    /// * `config` - [`crate::metadata::validation::config::ValidationConfig`] controlling validation behavior
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::validation::context::RawValidationContext`] configured for loading validation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::{RawValidationContext, ValidationConfig, ReferenceScanner};
    /// use dotscope::metadata::cilassemblyview::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// # let path = Path::new("assembly.dll");
    /// let view = CilAssemblyView::from_path(&path)?;
    /// let scanner = ReferenceScanner::from_view(&view)?;
    /// let config = ValidationConfig::production();
    ///
    /// let context = RawValidationContext::new_for_loading(&view, &scanner, &config);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new_for_loading(
        view: &'a CilAssemblyView,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            view,
            changes: None,
            scanner,
            config,
        }
    }

    /// Creates a new raw validation context for modification validation.
    ///
    /// This constructor is used when validating assembly changes against
    /// an original [`crate::metadata::cilassemblyview::CilAssemblyView`].
    ///
    /// # Arguments
    ///
    /// * `view` - The original [`crate::metadata::cilassemblyview::CilAssemblyView`]
    /// * `changes` - The assembly changes to validate
    /// * `scanner` - Shared [`crate::metadata::validation::scanner::ReferenceScanner`]
    /// * `config` - [`crate::metadata::validation::config::ValidationConfig`] controlling validation
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::validation::context::RawValidationContext`] configured for modification validation.
    pub fn new_for_modification(
        view: &'a CilAssemblyView,
        changes: &'a AssemblyChanges,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            view,
            changes: Some(changes),
            scanner,
            config,
        }
    }

    /// Returns the assembly changes if this is a modification validation context.
    ///
    /// # Returns
    ///
    /// Returns `Some(&AssemblyChanges)` for modification validation,
    /// `None` for loading validation contexts.
    #[must_use]
    pub fn changes(&self) -> Option<&AssemblyChanges> {
        self.changes
    }

    /// Returns true if this context is for modification validation.
    ///
    /// # Returns
    ///
    /// Returns `true` if this context contains assembly changes, `false` otherwise.
    #[must_use]
    pub fn is_modification_validation(&self) -> bool {
        self.changes.is_some()
    }

    /// Returns true if this context is for loading validation.
    ///
    /// # Returns
    ///
    /// Returns `true` if this context is for loading validation, `false` otherwise.
    #[must_use]
    pub fn is_loading_validation(&self) -> bool {
        self.changes.is_none()
    }

    /// Returns a reference to the underlying [`crate::metadata::cilassemblyview::CilAssemblyView`].
    ///
    /// This provides access to raw metadata for raw validation.
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`crate::metadata::cilassemblyview::CilAssemblyView`] being validated.
    #[must_use]
    pub fn assembly_view(&self) -> &CilAssemblyView {
        self.view
    }
}

impl ValidationContext for RawValidationContext<'_> {
    fn validation_stage(&self) -> ValidationStage {
        ValidationStage::Raw
    }

    fn reference_scanner(&self) -> &ReferenceScanner {
        self.scanner
    }

    fn config(&self) -> &ValidationConfig {
        self.config
    }
}

/// Fast method-to-type mapping for efficient method ownership lookup.
///
/// This structure provides O(1) lookups for method-to-type relationships,
/// which are frequently needed during inheritance and method validation.
/// Building this mapping is expensive (iterates all types and methods),
/// so it's cached in the validation context and shared across validators.
///
/// # Thread Safety
///
/// This struct is [`Send`] and [`Sync`] as it contains only thread-safe types.
/// All contained data is immutable after construction.
pub struct MethodTypeMapping {
    /// Maps method address to the type address that owns it
    method_to_type: FxHashMap<usize, usize>,
    /// Maps type address to all method addresses it owns
    type_to_methods: FxHashMap<usize, Vec<usize>>,
    /// Maps method address to `Arc<Method>` for lookup
    address_to_method: FxHashMap<usize, Arc<Method>>,
}

impl MethodTypeMapping {
    /// Builds the method-to-type mapping for fast lookups using cross-assembly safe addresses.
    ///
    /// # Arguments
    ///
    /// * `all_types` - All types to build the mapping from (typically from `types().all_types()`)
    ///
    /// # Performance
    ///
    /// This is an O(n*m) operation where n is the number of types and m is the average
    /// number of methods per type. The result should be cached for reuse.
    #[must_use]
    pub fn new(all_types: Vec<CilTypeRc>) -> Self {
        let mut method_to_type = FxHashMap::default();
        let mut type_to_methods: FxHashMap<usize, Vec<usize>> = FxHashMap::default();
        let mut address_to_method = FxHashMap::default();

        for type_entry in all_types {
            let type_address = Arc::as_ptr(&type_entry) as usize;
            let mut type_methods = Vec::new();

            for (_, method_ref) in type_entry.methods.iter() {
                if let Some(method_rc) = method_ref.upgrade() {
                    let method_address = Arc::as_ptr(&method_rc) as usize;
                    method_to_type.insert(method_address, type_address);
                    address_to_method.insert(method_address, Arc::clone(&method_rc));
                    type_methods.push(method_address);
                }
            }

            if !type_methods.is_empty() {
                type_to_methods.insert(type_address, type_methods);
            }
        }

        Self {
            method_to_type,
            type_to_methods,
            address_to_method,
        }
    }

    /// Fast check if a method belongs to a specific type (O(1) lookup).
    ///
    /// # Arguments
    ///
    /// * `method_address` - The address of the method (obtained via `Arc::as_ptr`)
    /// * `type_address` - The address of the type (obtained via `Arc::as_ptr`)
    ///
    /// # Returns
    ///
    /// `true` if the method belongs to the type, `false` otherwise.
    #[must_use]
    pub fn method_belongs_to_type(&self, method_address: usize, type_address: usize) -> bool {
        self.method_to_type.get(&method_address) == Some(&type_address)
    }

    /// Get all methods for a specific type (O(1) lookup).
    ///
    /// # Arguments
    ///
    /// * `type_address` - The address of the type (obtained via `Arc::as_ptr`)
    ///
    /// # Returns
    ///
    /// Slice of method addresses belonging to the type, or empty slice if none.
    #[must_use]
    pub fn get_type_methods(&self, type_address: usize) -> &[usize] {
        self.type_to_methods
            .get(&type_address)
            .map_or(&[], Vec::as_slice)
    }

    /// Get method by address (O(1) lookup).
    ///
    /// # Arguments
    ///
    /// * `method_address` - The address of the method (obtained via `Arc::as_ptr`)
    ///
    /// # Returns
    ///
    /// Reference to the method if found, `None` otherwise.
    #[must_use]
    pub fn get_method(&self, method_address: usize) -> Option<&Arc<Method>> {
        self.address_to_method.get(&method_address)
    }

    /// Returns the total number of methods in the mapping.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.address_to_method.len()
    }

    /// Returns the total number of types in the mapping.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.type_to_methods.len()
    }
}

/// Lazy cache for expensive validation computations.
///
/// This structure holds cached data that is expensive to compute and may be
/// needed by multiple validators. Each field uses [`OnceLock`] to ensure:
/// - Data is computed at most once (on first access)
/// - Zero cost if a validator doesn't need that particular cache
/// - Thread-safe access without explicit locking after initialization
///
/// # Design Rationale
///
/// During validation, multiple validators need similar computed data:
/// - `inheritance.rs` calls `target_assembly_types()` 4 times
/// - `field.rs` calls `all_types()` 4 times
/// - `MethodTypeMapping` is rebuilt for each call to `validate_method_inheritance()`
/// - Interface relationship maps are built in both circularity validators
/// - Nested type relationship maps are built for nested type cycle detection
///
/// By caching these at the context level, we eliminate redundant computations
/// and can reduce validation time by 40-60% for complex assemblies.
///
/// # Thread Safety
///
/// All fields use [`OnceLock`] which provides thread-safe lazy initialization.
/// After initialization, all data is immutable and can be accessed concurrently.
#[derive(Default)]
pub struct ValidationCache {
    /// All types from target assembly (filtered by assembly identity).
    /// Used by: inheritance, circularity, dependency, method, ownership validators.
    target_types: OnceLock<Vec<CilTypeRc>>,

    /// All types including external references.
    /// Used by: field validator (4x), circularity validator.
    all_types: OnceLock<Vec<CilTypeRc>>,

    /// Method-to-type ownership mapping.
    /// Used by: inheritance validator (method override validation).
    /// Expensive to build: iterates all types and all methods.
    method_type_mapping: OnceLock<MethodTypeMapping>,

    /// Interface implementation relationships: type Arc pointer -> implemented interface Arc pointers.
    /// Used by: both circularity validators for cycle detection.
    /// Built from target assembly types, mapping each type to its directly implemented interfaces.
    /// Uses Arc pointers (as usize) instead of tokens to avoid token collisions in multi-assembly scenarios.
    interface_relationships: OnceLock<FxHashMap<usize, Vec<usize>>>,

    /// Nested type relationships: parent type token -> nested type tokens.
    /// Used by: types/circularity validator for nested type cycle detection.
    /// Built from all types, mapping each type to its direct nested types.
    nested_relationships: OnceLock<FxHashMap<Token, Vec<Token>>>,
}

impl ValidationCache {
    /// Creates a new empty validation cache.
    ///
    /// All cached values will be computed lazily on first access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            target_types: OnceLock::new(),
            all_types: OnceLock::new(),
            method_type_mapping: OnceLock::new(),
            interface_relationships: OnceLock::new(),
            nested_relationships: OnceLock::new(),
        }
    }
}

/// Context for Stage 2 (owned) validation.
///
/// This context is used when validating owned metadata through `CilObject`,
/// which contains fully resolved type information and cross-references.
/// CilObject provides access to both raw and resolved metadata through its public API.
///
/// # Caching
///
/// The context maintains a `ValidationCache` that lazily computes expensive
/// data structures on first access. This eliminates redundant computations
/// across validators while ensuring unused caches have zero overhead.
///
/// Available cached data:
/// - `target_assembly_types()` - Types from the target assembly
/// - `all_types()` - All types including external references
/// - `method_type_mapping()` - Method-to-type ownership mappings
pub struct OwnedValidationContext<'a> {
    /// The CilObject containing both raw and resolved metadata
    object: &'a CilObject,
    /// Shared reference scanner for efficient validation
    scanner: &'a ReferenceScanner,
    /// Validation configuration
    config: &'a ValidationConfig,
    /// Lazy cache for expensive computations shared across validators
    cache: ValidationCache,
}

impl<'a> OwnedValidationContext<'a> {
    /// Creates a new owned validation context.
    ///
    /// # Arguments
    ///
    /// * `object` - The CilObject containing both raw and resolved metadata
    /// * `scanner` - Shared reference scanner
    /// * `config` - Validation configuration
    ///
    /// # Caching
    ///
    /// The context initializes an empty `ValidationCache` that will lazily
    /// compute expensive data structures on first access by any validator.
    pub fn new(
        object: &'a CilObject,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> Self {
        Self {
            object,
            scanner,
            config,
            cache: ValidationCache::new(),
        }
    }

    /// Returns a reference to the CilObject.
    ///
    /// This provides access to both raw and fully resolved metadata including type registries,
    /// method maps, and other resolved structures through CilObject's public API.
    #[must_use]
    pub fn object(&self) -> &CilObject {
        self.object
    }
}

impl OwnedValidationContext<'_> {
    /// The first type a signature names that this assembly's type system does not hold: a
    /// TypeDef, TypeRef or TypeSpec token no loaded row answers. `names` adds the signature's
    /// tokens (a `type_tokens` method of the signature types).
    pub fn unresolved_type(&self, names: impl FnOnce(&mut Vec<Token>)) -> Option<Token> {
        let mut tokens = Vec::new();
        names(&mut tokens);
        let types = self.object.types();
        tokens.into_iter().find(|token| types.get(token).is_none())
    }

    /// Get types that belong to the assembly being validated (cached).
    ///
    /// This method returns only the types that should be validated for the current assembly,
    /// filtering out external assembly types that should not be subject to local validation rules.
    ///
    /// The result is cached on first access and shared across all validators.
    ///
    /// # Returns
    ///
    /// Cached reference to types from the target assembly that should be validated.
    ///
    /// # Performance
    ///
    /// First call: O(n) where n is the total number of types (filters by assembly)
    /// Subsequent calls: O(1) (returns cached reference)
    pub fn target_assembly_types(&self) -> &Vec<CilTypeRc> {
        self.cache.target_types.get_or_init(|| {
            if let Some(assembly_identity) = self.object.identity() {
                self.object
                    .types()
                    .types_from_source(&TypeSource::Assembly(assembly_identity))
            } else {
                // Fallback: if no assembly identity is available, return empty vec to avoid cross-assembly validation
                Vec::new()
            }
        })
    }

    /// Get all types including external references (cached).
    ///
    /// This method returns all types known to the type system, including types
    /// from external assemblies. This is needed by validators that must examine
    /// cross-assembly relationships (e.g., field type validation).
    ///
    /// The result is cached on first access and shared across all validators.
    ///
    /// # Returns
    ///
    /// Cached reference to all types in the type system.
    ///
    /// # Performance
    ///
    /// First call: O(n) where n is the total number of types
    /// Subsequent calls: O(1) (returns cached reference)
    pub fn all_types(&self) -> &Vec<CilTypeRc> {
        self.cache
            .all_types
            .get_or_init(|| self.object.types().all_types())
    }

    /// Get method-to-type ownership mapping (cached).
    ///
    /// This method returns a mapping structure that provides O(1) lookups for:
    /// - Which type owns a given method
    /// - All methods belonging to a given type
    /// - Method lookup by address
    ///
    /// The mapping is built from all types (not just target assembly types) to
    /// support cross-assembly method inheritance validation.
    ///
    /// The result is cached on first access and shared across all validators.
    ///
    /// # Returns
    ///
    /// Cached reference to the [`MethodTypeMapping`] structure.
    ///
    /// # Performance
    ///
    /// First call: O(n*m) where n is types and m is average methods per type
    /// Subsequent calls: O(1) (returns cached reference)
    ///
    /// # Usage
    ///
    /// ```no_run
    /// let mapping = context.method_type_mapping();
    /// let type_addr = Arc::as_ptr(&some_type) as usize;
    /// for &method_addr in mapping.get_type_methods(type_addr) {
    ///     if let Some(method) = mapping.get_method(method_addr) {
    ///         // Use method...
    ///     }
    /// }
    /// ```
    pub fn method_type_mapping(&self) -> &MethodTypeMapping {
        self.cache
            .method_type_mapping
            .get_or_init(|| MethodTypeMapping::new(self.all_types().clone()))
    }

    /// Get interface implementation relationships (cached).
    ///
    /// This method returns a mapping from type tokens to the tokens of interfaces
    /// they implement. This is used by circularity validators to detect cycles
    /// in interface implementation chains.
    ///
    /// The result is cached on first access and shared across all validators.
    ///
    /// # Returns
    ///
    /// Cached reference to a FxHashMap mapping type Arc pointers (as usize) to implemented
    /// interface Arc pointers (as usize). Using Arc pointers instead of tokens avoids
    /// token collisions in multi-assembly scenarios where different types from different
    /// assemblies may share the same token value.
    ///
    /// # Performance
    ///
    /// First call: O(n*m) where n is types and m is average interfaces per type
    /// Subsequent calls: O(1) (returns cached reference)
    pub fn interface_relationships(&self) -> &FxHashMap<usize, Vec<usize>> {
        self.cache.interface_relationships.get_or_init(|| {
            let mut relationships = FxHashMap::default();
            for type_entry in self.all_types() {
                let type_ptr = Arc::as_ptr(type_entry) as usize;
                let mut implemented_interfaces = Vec::new();

                for (_, entry) in type_entry.interfaces.iter() {
                    if let Some(interface_type) = entry.interface.upgrade() {
                        let interface_ptr = Arc::as_ptr(&interface_type) as usize;
                        implemented_interfaces.push(interface_ptr);
                    }
                }

                if !implemented_interfaces.is_empty() {
                    relationships.insert(type_ptr, implemented_interfaces);
                }
            }
            relationships
        })
    }

    /// Get nested type relationships (cached).
    ///
    /// This method returns a mapping from parent type tokens to the tokens of their
    /// nested types. This is used by circularity validators to detect cycles
    /// in nested type containment.
    ///
    /// The result is cached on first access and shared across all validators.
    ///
    /// # Returns
    ///
    /// Cached reference to a FxHashMap mapping type tokens to nested type tokens.
    ///
    /// # Performance
    ///
    /// First call: O(n*m) where n is types and m is average nested types per type
    /// Subsequent calls: O(1) (returns cached reference)
    pub fn nested_relationships(&self) -> &FxHashMap<Token, Vec<Token>> {
        self.cache.nested_relationships.get_or_init(|| {
            let mut relationships = FxHashMap::default();
            for type_entry in self.all_types() {
                let token = type_entry.token;
                let mut nested_tokens = Vec::new();
                for (_, nested_ref) in type_entry.nested_types.iter() {
                    if let Some(nested_type) = nested_ref.upgrade() {
                        nested_tokens.push(nested_type.token);
                    }
                }
                // Only insert if there are nested types to save memory
                if !nested_tokens.is_empty() {
                    relationships.insert(token, nested_tokens);
                }
            }
            relationships
        })
    }
}

impl ValidationContext for OwnedValidationContext<'_> {
    fn validation_stage(&self) -> ValidationStage {
        ValidationStage::Owned
    }

    fn reference_scanner(&self) -> &ReferenceScanner {
        self.scanner
    }

    fn config(&self) -> &ValidationConfig {
        self.config
    }
}

/// Factory functions for creating validation contexts.
pub mod factory {

    use super::{
        AssemblyChanges, CilAssemblyView, CilObject, OwnedValidationContext, RawValidationContext,
        ReferenceScanner, ValidationConfig,
    };

    /// Creates a raw validation context for loading validation.
    pub fn raw_loading_context<'a>(
        view: &'a CilAssemblyView,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> RawValidationContext<'a> {
        RawValidationContext::new_for_loading(view, scanner, config)
    }

    /// Creates a raw validation context for modification validation.
    pub fn raw_modification_context<'a>(
        view: &'a CilAssemblyView,
        changes: &'a AssemblyChanges,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> RawValidationContext<'a> {
        RawValidationContext::new_for_modification(view, changes, scanner, config)
    }

    /// Creates an owned validation context.
    pub fn owned_context<'a>(
        object: &'a CilObject,
        scanner: &'a ReferenceScanner,
        config: &'a ValidationConfig,
    ) -> OwnedValidationContext<'a> {
        OwnedValidationContext::new(object, scanner, config)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{metadata::validation::config::ValidationConfig, testkit::fixture};

    #[test]
    fn test_raw_loading_context() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).unwrap();
        let config = ValidationConfig::minimal();

        let context = RawValidationContext::new_for_loading(&view, &scanner, &config);

        assert_eq!(context.validation_stage(), ValidationStage::Raw);
        assert!(context.is_loading_validation());
        assert!(!context.is_modification_validation());
        assert!(context.changes().is_none());
    }

    #[test]
    fn test_raw_modification_context() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).unwrap();
        let config = ValidationConfig::minimal();
        let changes = AssemblyChanges::new();

        let context =
            RawValidationContext::new_for_modification(&view, &changes, &scanner, &config);

        assert_eq!(context.validation_stage(), ValidationStage::Raw);
        assert!(!context.is_loading_validation());
        assert!(context.is_modification_validation());
        assert!(context.changes().is_some());
    }

    #[test]
    fn test_factory_functions() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).unwrap();
        let config = ValidationConfig::minimal();
        let changes = AssemblyChanges::new();

        let loading_context = factory::raw_loading_context(&view, &scanner, &config);
        assert_eq!(loading_context.validation_stage(), ValidationStage::Raw);

        let modification_context =
            factory::raw_modification_context(&view, &changes, &scanner, &config);
        assert_eq!(
            modification_context.validation_stage(),
            ValidationStage::Raw
        );
    }
}

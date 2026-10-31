//! Central type registry for .NET assembly analysis.
//!
//! This module provides the `TypeRegistry`, a thread-safe, high-performance registry for managing
//! all types within a .NET assembly. It serves as the central hub for type lookup,
//! storage, and cross-reference resolution during metadata analysis.
//!
//! # Key Components
//!
//! - [`TypeRegistry`] - Central registry managing all types in an assembly
//! - [`TypeSource`] - Classification of type origins (current module, external assemblies, etc.)
//! - `SourceRegistry` - Internal management of external type references
//!
//! # Registry Architecture
//!
//! The type registry uses a multi-index approach for efficient type lookup:
//!
//! - **Token-based lookup**: Primary index using metadata tokens
//! - **Name-based lookup**: Secondary indices for full names, simple names, and namespaces
//! - **Source-based lookup**: Types grouped by their origin (assembly, module, etc.)
//! - **Signature cache**: Deduplication using type signature hashes
//!
//! # Thread Safety
//!
//! The registry is designed for high-concurrency scenarios:
//! - Lock-free data structures for primary storage (`SkipMap`)
//! - Concurrent hash maps for indices (`DashMap`)
//! - Atomic operations for token generation
//! - No blocking operations during normal lookup/insertion
//!
//! # Type Sources
//!
//! Types in the registry can originate from various sources:
//! - **Current Module**: Types defined in the assembly being analyzed
//! - **External Assemblies**: Types from referenced assemblies
//! - **Primitive Types**: Built-in CLR types (System.Int32, System.String, etc.)
//! - **External Modules**: Types from module references
//! - **Files**: Types from file references
//!
//! # Examples
//!
//! ## Creating and Using a Registry
//!
//! ```rust,no_run
//! use dotscope::metadata::typesystem::{TypeRegistry, CilType};
//! use dotscope::metadata::identity::AssemblyIdentity;
//! use dotscope::metadata::token::Token;
//!
//! // Create a new registry with primitive types
//! let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
//! let registry = TypeRegistry::new(test_identity)?;
//!
//! // Look up types by name
//! if let Some(string_type) = registry.get_by_fullname("System.String", true) {
//!     println!("Found String type: 0x{:08X}", string_type.token.value());
//! }
//!
//! // Look up by token
//! if let Some(type_def) = registry.get(&Token::new(0x02000001)) {
//!     println!("Type: {}.{}", type_def.namespace, type_def.name);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Registering New Types
//!
//! ```rust,no_run
//! use dotscope::metadata::typesystem::{TypeRegistry, CilType, TypeSource};
//! use dotscope::metadata::method::MethodRefList;
//! use dotscope::metadata::tables::TypeAttributes;
//! use dotscope::metadata::identity::AssemblyIdentity;
//! use dotscope::metadata::token::Token;
//! use std::sync::Arc;
//!
//! # fn example() -> dotscope::Result<()> {
//! let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
//! let registry = TypeRegistry::new(test_identity)?;
//!
//! // Create a new type
//! let new_type = CilType::new(
//!     Token::new(0x02000001),
//!     "MyNamespace".to_string(),
//!     "MyClass".to_string(),
//!     None, // No external reference
//!     None, // No base type yet
//!     TypeAttributes::new(0x00100001), // Public class
//!     Arc::new(boxcar::Vec::new()), // Empty fields
//!     MethodRefList::new(), // Empty methods, allocated on first push
//!     None, // Flavor will be computed
//! );
//!
//! // Register the type
//! registry.insert(&Arc::new(new_type));
//! # Ok(())
//! # }
//! ```
//!
//! ## Type Lookup Patterns
//!
//! The registry provides multiple lookup methods by name, namespace, and token.
//! Each method returns the appropriate collection type for the query.
//!
//! # ECMA-335 Compliance
//!
//! The registry handles all type reference mechanisms defined in ECMA-335:
//! - `TypeDef`, `TypeRef`, and `TypeSpec` tokens
//! - Assembly, Module, and File references
//! - Generic type instantiations
//! - Cross-assembly type resolution

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Weak,
    },
};

use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;

use crate::{
    metadata::{
        identity::AssemblyIdentity,
        signatures::{SignatureMethodSpec, TypeSignature},
        tables::{
            AssemblyRc, AssemblyRefRc, FileRc, MethodSpec, ModuleRc, ModuleRefRc, TableId,
            TypeAttributes,
        },
        token::Token,
        typesystem::{
            wellknown::names, CilFlavor, CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc,
            CilTypeRef, CilTypeReference, PointerSize, TypeSignatureHash,
        },
    },
    utils::LazyList,
    Error::TypeNotFound,
    Result,
};

/// Complete type specification for type construction
///
/// This structure contains all the information needed to create a type with full
/// structural identity, enabling proper construction of complex types like generic
/// instances, arrays, and other constructed types.
#[derive(Clone)]
pub struct CompleteTypeSpec {
    /// Optional specific token to assign (None for auto-generation)
    pub token_init: Option<Token>,
    /// The CIL flavor/kind of the type
    pub flavor: CilFlavor,
    /// Type namespace
    pub namespace: String,
    /// Type name
    pub name: String,
    /// Source context (assembly, module, etc.)
    pub source: TypeSource,
    /// Generic arguments for generic instances
    pub generic_args: Option<Vec<CilTypeRc>>,
    /// Base type for derived types
    pub base_type: Option<CilTypeRc>,
    /// TypeAttributes flags (optional, inherited from base type for generic instances)
    pub flags: Option<TypeAttributes>,
}

impl CompleteTypeSpec {
    /// Check if this specification matches an existing CilType for validation
    ///
    /// This method performs comprehensive structural comparison to determine if an
    /// existing type matches what this specification describes. This is used
    /// for validation and consistency checking during type construction.
    ///
    /// # Comparison Criteria
    /// Types are considered equivalent if they have identical:
    /// - **Basic identity**: Namespace, name, and flavor
    /// - **Source context**: Must originate from the same assembly/module/file  
    /// - **Generic arguments**: Type arguments must be identical (for generic instances)
    /// - **Base type**: Inheritance hierarchy must match (for derived types)
    ///
    /// # Arguments
    /// * `existing_type` - The existing CilType to compare against
    ///
    /// # Returns
    /// `true` if the existing type matches this specification exactly
    pub fn matches(&self, existing_type: &CilType) -> bool {
        // Basic identity check first for performance
        if existing_type.namespace != self.namespace
            || existing_type.name != self.name
            || *existing_type.flavor() != self.flavor
        {
            return false;
        }

        // Check source equivalence
        if !self.source_matches(existing_type) {
            return false;
        }

        // Check base type equivalence
        if !self.base_type_matches(existing_type) {
            return false;
        }

        // Check generic arguments equivalence
        self.generic_args_match(existing_type)
    }

    /// Check if type sources are equivalent
    fn source_matches(&self, existing_type: &CilType) -> bool {
        let ext_ref = existing_type.external();

        match (&self.source, ext_ref) {
            (TypeSource::Assembly(_), None) => true,
            (TypeSource::Assembly(_), Some(_)) => false, // Local vs external
            (src, Some(ext_ref)) => {
                match (ext_ref, src) {
                    (CilTypeReference::AssemblyRef(ar), TypeSource::AssemblyRef(tok)) => {
                        ar.token == *tok
                    }
                    (CilTypeReference::ModuleRef(mr), TypeSource::ModuleRef(tok)) => {
                        mr.token == *tok
                    }
                    (CilTypeReference::File(f), TypeSource::File(tok)) => f.token == *tok,
                    _ => true, // Allow different external source types for now
                }
            }
            _ => false, // External vs local
        }
    }

    /// Check if base types match
    fn base_type_matches(&self, existing_type: &CilType) -> bool {
        match (&self.base_type, existing_type.base.get()) {
            (Some(spec_base), Some(type_base)) => {
                match type_base.upgrade() {
                    Some(base_type) => {
                        spec_base.token == base_type.token
                            || spec_base.is_structurally_equivalent(&base_type)
                    }
                    None => false, // Base type reference is dropped
                }
            }
            (None, None) => true, // Both have no base type
            _ => false,           // One has base, one doesn't
        }
    }

    /// Check if generic arguments match
    fn generic_args_match(&self, existing_type: &CilType) -> bool {
        match &self.generic_args {
            Some(spec_args) => {
                // Must have same number of generic arguments
                if spec_args.len() != existing_type.generic_args.count() {
                    return false;
                }

                // Compare each generic argument by token
                for (i, spec_arg) in spec_args.iter().enumerate() {
                    if let Some(type_arg) = existing_type.generic_args.get(i) {
                        if spec_arg.token != type_arg.token {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            }
            None => existing_type.generic_args.count() == 0, // No generic args in spec
        }
    }
}

/// Classification of type origins within the .NET assembly ecosystem.
///
/// `TypeSource` identifies where a type is defined, enabling proper resolution
/// of cross-assembly and cross-module type references. This is crucial for
/// handling external dependencies and maintaining proper type identity.
///
/// # Type Resolution
///
/// Different sources require different resolution strategies:
/// - **`CurrentModule`**: Direct access to type definition
/// - **External sources**: Resolution through metadata references
/// - **Primitive**: Built-in CLR types with artificial tokens
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::typesystem::TypeSource;
/// use dotscope::metadata::token::Token;
///
/// // Local type
/// let local_source = TypeSource::Unknown;
///
/// // External assembly type
/// let external_source = TypeSource::AssemblyRef(Token::new(0x23000001));
///
/// // Primitive type
/// let primitive_source = TypeSource::Primitive;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeSource {
    /// Type is defined in a specific assembly (by identity)
    Assembly(AssemblyIdentity),
    /// Type is defined in an external module (cross-module reference)
    Module(Token),
    /// Type is defined in an external module reference
    ModuleRef(Token),
    /// Type is defined in an external assembly reference
    AssemblyRef(Token),
    /// Type is defined in an external file reference
    File(Token),
    /// Type is a primitive defined by the CLR runtime
    Primitive,
    /// Type source is not determined or not available
    Unknown,
}

impl TypeSource {
    /// Returns `true` if this type source refers to an external reference.
    ///
    /// External sources include module references, assembly references, and file references.
    /// Local sources (current assembly) and special sources (primitive, unknown) return `false`.
    #[must_use]
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            TypeSource::ModuleRef(_) | TypeSource::AssemblyRef(_) | TypeSource::File(_)
        )
    }

    /// Returns `true` if this is a primitive type source.
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        matches!(self, TypeSource::Primitive)
    }

    /// Returns `true` if this source is unknown/undetermined.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self, TypeSource::Unknown)
    }

    /// Returns the associated token if this source has one.
    ///
    /// Returns `Some(Token)` for Module, ModuleRef, AssemblyRef, and File variants.
    /// Returns `None` for Assembly, Primitive, and Unknown variants.
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        match self {
            TypeSource::Module(t)
            | TypeSource::ModuleRef(t)
            | TypeSource::AssemblyRef(t)
            | TypeSource::File(t) => Some(*t),
            TypeSource::Assembly(_) | TypeSource::Primitive | TypeSource::Unknown => None,
        }
    }
}

/// Internal registry for tracking external type reference sources.
///
/// `SourceRegistry` maintains weak references to external assemblies, modules,
/// and files to prevent circular reference cycles while enabling proper type
/// resolution. It serves as a lookup table for converting `TypeSource` values
/// back to their corresponding metadata references.
///
/// # Memory Management
///
/// The registry uses reference counting to track external sources without
/// creating strong circular references that could prevent garbage collection.
/// When sources are no longer needed, they can be automatically cleaned up.
///
/// # Thread Safety
///
/// All internal collections use `DashMap` for lock-free concurrent access,
/// making source registration and lookup safe from multiple threads.
struct SourceRegistry {
    /// External modules indexed by their metadata tokens
    modules: DashMap<Token, ModuleRc>,
    /// Module references indexed by their metadata tokens
    module_refs: DashMap<Token, ModuleRefRc>,
    /// Assembly references indexed by their metadata tokens
    assembly_refs: DashMap<Token, AssemblyRefRc>,
    /// File references indexed by their metadata tokens
    files: DashMap<Token, FileRc>,
    /// Memoised `TypeSource` per defining assembly, keyed by its `Assembly` row object.
    ///
    /// Deriving an `AssemblyIdentity` from an `Assembly` row rebuilds its name, culture and
    /// public-key blob. Every locally-defined type resolves to the same one, so it is
    /// derived once per assembly rather than once per type. The key is the row object, not
    /// its token: every assembly's row is `0x20000001`, and a registry also holds types
    /// resolved from other assemblies. The entry keeps the row alive, so its address is not
    /// reused.
    assembly_sources: DashMap<usize, (AssemblyRc, TypeSource)>,
}

impl SourceRegistry {
    /// Create a new empty source registry.
    ///
    /// Initializes all internal collections as empty, ready to receive
    /// source registrations during metadata loading.
    ///
    /// # Returns
    /// A new `SourceRegistry` with empty collections
    fn new() -> Self {
        SourceRegistry {
            modules: DashMap::new(),
            module_refs: DashMap::new(),
            assembly_refs: DashMap::new(),
            files: DashMap::new(),
            assembly_sources: DashMap::new(),
        }
    }

    /// Register an external type reference source.
    ///
    /// Stores the external reference and returns a corresponding `TypeSource`
    /// value that can be used for efficient lookups. This method handles all
    /// supported external reference types defined in ECMA-335.
    ///
    /// # Arguments
    /// * `source` - The external type reference to register
    ///
    /// # Returns
    /// A `TypeSource` value for efficient source identification
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from
    /// multiple threads during metadata loading.
    fn register_source(&self, source: &CilTypeReference) -> TypeSource {
        match source {
            CilTypeReference::Module(module) => {
                self.modules.insert(module.token, module.clone());
                TypeSource::Module(module.token)
            }
            CilTypeReference::ModuleRef(module_ref) => {
                self.module_refs
                    .insert(module_ref.token, module_ref.clone());
                TypeSource::ModuleRef(module_ref.token)
            }
            CilTypeReference::AssemblyRef(assembly_ref) => {
                self.assembly_refs
                    .insert(assembly_ref.token, assembly_ref.clone());
                TypeSource::AssemblyRef(assembly_ref.token)
            }
            CilTypeReference::Assembly(assembly) => {
                // Reached once per type that names the defining assembly as its source.
                // `from_assembly` is worse than a clone - it re-clones the name and culture
                // and rebuilds the public-key blob - and the result is identical for every
                // one of them, so it is derived once and reused.
                let key = Arc::as_ptr(assembly) as usize;
                if let Some(cached) = self.assembly_sources.get(&key) {
                    return cached.value().1.clone();
                }

                let source = TypeSource::Assembly(AssemblyIdentity::from_assembly(assembly));
                self.assembly_sources
                    .insert(key, (assembly.clone(), source.clone()));
                source
            }
            CilTypeReference::File(file) => {
                self.files.insert(file.token, file.clone());
                TypeSource::File(file.token)
            }
            _ => TypeSource::Unknown,
        }
    }

    /// Retrieve a type reference from a registered source.
    ///
    /// Converts a `TypeSource` back to its corresponding `CilTypeReference`,
    /// enabling resolution of external type references during analysis.
    ///
    /// # Arguments
    /// * `source` - The type source to look up
    ///
    /// # Returns
    /// * `Some(CilTypeReference)` - The corresponding external reference
    /// * `None` - If source is not external or not found
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free for concurrent access.
    fn get_source(&self, source: &TypeSource) -> Option<CilTypeReference> {
        match source {
            TypeSource::Module(token) => self
                .modules
                .get(token)
                .map(|module| CilTypeReference::Module(module.clone())),
            TypeSource::ModuleRef(token) => self
                .module_refs
                .get(token)
                .map(|moduleref| CilTypeReference::ModuleRef(moduleref.clone())),
            TypeSource::AssemblyRef(token) => self
                .assembly_refs
                .get(token)
                .map(|assemblyref| CilTypeReference::AssemblyRef(assemblyref.clone())),
            TypeSource::File(token) => self
                .files
                .get(token)
                .map(|file| CilTypeReference::File(file.clone())),
            TypeSource::Primitive | TypeSource::Unknown | TypeSource::Assembly(_) => None,
        }
    }
}

/// Central registry for managing all types within a .NET assembly.
///
/// `TypeRegistry` provides thread-safe, high-performance storage and lookup
/// capabilities for all types encountered during metadata analysis. It serves
/// as the authoritative source for type information and handles storage,
/// cross-references, and efficient query operations.
///
/// # Architecture
///
/// The registry uses a multi-layered indexing strategy:
/// - **Primary storage**: Token-based skip list for O(log n) lookups
/// - **Secondary indices**: Hash maps for name-based and source-based queries
/// - **Deduplication**: Signature cache to prevent duplicate type entries
/// - **External references**: Source registry for cross-assembly resolution
///
/// # Concurrency Design
///
/// All operations are designed for high-concurrency scenarios:
/// - Lock-free primary storage using `SkipMap`
/// - Concurrent secondary indices using `DashMap`
/// - Atomic token generation for thread-safe registration
/// - No blocking operations during normal operations
///
/// # Type Identity
///
/// Types are identified using multiple strategies:
/// - **Token identity**: Primary key using metadata tokens
/// - **Name identity**: Full namespace.name qualification
/// - **Source identity**: Origin-based grouping
///
/// # Memory Management
///
/// The registry uses reference counting (`Arc`) to manage type lifetime:
/// - Types can be shared across multiple consumers
/// - Automatic cleanup when no longer referenced
/// - Efficient memory usage through reference counting
///
/// # Examples
///
/// ## Basic Registry Operations
///
/// ```rust,no_run
/// use dotscope::metadata::typesystem::TypeRegistry;
/// use dotscope::metadata::identity::AssemblyIdentity;
///
/// // Create registry with primitive types
/// let identity = AssemblyIdentity::parse("Test, Version=1.0.0.0").unwrap();
/// let registry = TypeRegistry::new(identity)?;
///
/// // Query primitive types
/// if let Some(entry) = registry.get_by_fullname("System.Int32", true) {
///     println!("Found Int32: 0x{:08X}", entry.token.value());
/// }
///
/// // Check registry statistics
/// println!("Total types: {}", registry.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// The registry is fully thread-safe and optimized for concurrent access:
/// - Multiple threads can perform lookups simultaneously
/// - Registration operations are atomic and consistent
/// - No explicit locking required by consumers
///
/// # Performance Characteristics
///
/// - **Token lookup**: O(log n) using skip list
/// - **Name lookup**: O(1) average using hash indices  
/// - **Registration**: O(log n) + O(1) for indexing
/// - **Memory**: O(n) with reference counting efficiency
pub struct TypeRegistry {
    /// Primary type storage indexed by metadata tokens - uses skip list for O(log n) operations
    types: SkipMap<Token, CilTypeRc>,
    /// Atomic counter for generating unique artificial tokens for new types
    next_token: AtomicU32,
    /// Registry managing external assembly/module/file references
    sources: SourceRegistry,
    /// Identity of the assembly this registry represents
    current_assembly: AssemblyIdentity,
    /// Secondary index: types grouped by their origin source
    ///
    /// The four indices below hold `BTreeSet`s rather than `Vec`s because the TypeRef
    /// redirect sweep removes a token from each of them per resolved TypeRef, and a linear
    /// `retain` over lists that keep growing makes that sweep quadratic in TypeRef count.
    /// Ordered rather than hashed so that iteration - which decides *which* type a
    /// duplicated name resolves to - stays deterministic across runs.
    types_by_source: DashMap<TypeSource, BTreeSet<Token>>,
    /// Secondary index: types indexed by full name (namespace.name)
    types_by_fullname: DashMap<Arc<str>, BTreeSet<Token>>,
    /// Secondary index: types indexed by simple name (may have duplicates)
    types_by_name: DashMap<String, BTreeSet<Token>>,
    /// Secondary index: types grouped by namespace
    types_by_namespace: DashMap<String, BTreeSet<Token>>,
    /// Secondary index: nested types keyed by the last component of their fullname.
    ///
    /// A TypeRef may name a nested type by its inner name alone (`Enumerator`2`) while the
    /// TypeDef carries the full path (`NS.Partitioner/Enumerator`2`). Resolving that without
    /// an index means an `ends_with` scan of every registered fullname on *every* exact-name
    /// miss, and the custom-attribute parser drives two such misses per fixed argument.
    types_by_nested_suffix: DashMap<Arc<str>, BTreeSet<Token>>,
    /// Registered external TypeRegistries for cross-assembly type resolution, by assembly.
    /// The links are weak: registries of a project link to one another, and strong links
    /// made every project's registries keep each other alive forever.
    external_registries: DashMap<AssemblyIdentity, Weak<TypeRegistry>>,
    /// Secondary index: MethodDef token to the token of its declaring type.
    ///
    /// Without this, `TypeResolver::declaring_type` answers the MethodDef case by scanning
    /// every type and, inside that, every method - upgrading a `Weak` per candidate. That
    /// lookup sits on the emulator's hottest paths (`call`/`callvirt`/`newobj`), so an O(1)
    /// answer here is what keeps dispatch from degrading to O(total methods in assembly).
    method_to_type: DashMap<Token, Token>,
    /// Secondary index: FieldDef token to the token of its declaring type.
    ///
    /// Same rationale as [`method_to_type`](Self::method_to_type), for the `ldsfld`/`stsfld`
    /// paths.
    field_to_type: DashMap<Token, Token>,
}

impl TypeRegistry {
    /// Create a new type registry with initialized primitive types.
    ///
    /// Constructs a complete type registry with all .NET primitive types
    /// pre-registered and ready for use. The registry starts with artificial
    /// tokens in the `0xF000_0020`+ range for new type registration.
    ///
    /// # Primitive Types
    ///
    /// The following primitive types are automatically registered:
    /// - `System.Void`, `System.Boolean`, `System.Char`
    /// - Integer types: `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`
    /// - Floating point: `Single`, `Double`
    /// - Platform types: `IntPtr`, `UIntPtr`
    /// - Reference types: `Object`, `String`
    /// - Special types: `TypedReference`, `ValueType`
    ///
    /// # Returns
    /// * `Ok(TypeRegistry)` - Fully initialized registry with primitive types
    /// * `Err(Error)` - If primitive type initialization fails
    ///
    /// # Errors
    ///
    /// This function will return an error if the primitive type initialization fails,
    /// which could happen due to internal inconsistencies during registry setup.
    ///
    /// # Thread Safety
    ///
    /// The returned registry is fully thread-safe and ready for concurrent use.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let identity = AssemblyIdentity::parse("Test, Version=1.0.0.0").unwrap();
    /// let registry = TypeRegistry::new(identity)?;
    ///
    /// // Primitive types are immediately available
    /// let string_type = registry.get_by_fullname("System.String", true);
    /// assert!(string_type.is_some());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(assembly_identity: AssemblyIdentity) -> Result<Self> {
        let registry = TypeRegistry {
            types: SkipMap::new(),
            next_token: AtomicU32::new(0xF000_0020), // Start after reserved primitives
            sources: SourceRegistry::new(),
            current_assembly: assembly_identity,
            types_by_source: DashMap::new(),
            types_by_fullname: DashMap::new(),
            types_by_name: DashMap::new(),
            types_by_namespace: DashMap::new(),
            types_by_nested_suffix: DashMap::new(),
            external_registries: DashMap::new(),
            method_to_type: DashMap::new(),
            field_to_type: DashMap::new(),
        };

        registry.initialize_primitives()?;
        Ok(registry)
    }

    /// Get the current assembly identity.
    pub fn current_assembly(&self) -> AssemblyIdentity {
        self.current_assembly.clone()
    }

    /// Get the TypeSource for the current assembly.
    pub fn current_assembly_source(&self) -> TypeSource {
        TypeSource::Assembly(self.current_assembly.clone())
    }

    /// Get the next available token and increment the counter
    fn next_token(&self) -> Token {
        let next_token = self.next_token.fetch_add(1, Ordering::Relaxed);
        if next_token == 0xFFFF_FFFF {
            // We're out of tokens - this should never happen in practice
            debug_assert!(
                false,
                "We ran out of tokens and are going overwrite existing ones"
            );
            self.next_token.store(0xF100_0000, Ordering::Relaxed);
        }

        Token::new(next_token)
    }

    /// Initialize primitive types in the registry
    fn initialize_primitives(&self) -> Result<()> {
        for primitive in [
            CilPrimitive::new(CilPrimitiveKind::Void),
            CilPrimitive::new(CilPrimitiveKind::Boolean),
            CilPrimitive::new(CilPrimitiveKind::Char),
            CilPrimitive::new(CilPrimitiveKind::I1),
            CilPrimitive::new(CilPrimitiveKind::U1),
            CilPrimitive::new(CilPrimitiveKind::I2),
            CilPrimitive::new(CilPrimitiveKind::U2),
            CilPrimitive::new(CilPrimitiveKind::I4),
            CilPrimitive::new(CilPrimitiveKind::U4),
            CilPrimitive::new(CilPrimitiveKind::I8),
            CilPrimitive::new(CilPrimitiveKind::U8),
            CilPrimitive::new(CilPrimitiveKind::R4),
            CilPrimitive::new(CilPrimitiveKind::R8),
            CilPrimitive::new(CilPrimitiveKind::I),
            CilPrimitive::new(CilPrimitiveKind::U),
            CilPrimitive::new(CilPrimitiveKind::Object),
            CilPrimitive::new(CilPrimitiveKind::String),
            CilPrimitive::new(CilPrimitiveKind::TypedReference),
            CilPrimitive::new(CilPrimitiveKind::ValueType),
            CilPrimitive::new(CilPrimitiveKind::Var),
            CilPrimitive::new(CilPrimitiveKind::MVar),
            CilPrimitive::new(CilPrimitiveKind::Null),
        ] {
            let token = primitive.token();
            let flavor = primitive.to_flavor();

            let new_type = Arc::new(CilType::new(
                token,
                primitive.namespace().to_string(),
                primitive.name().to_string(),
                None,
                None,
                TypeAttributes::ZERO,
                Arc::new(boxcar::Vec::new()),
                LazyList::new(),
                Some(flavor),
            ));

            self.register_type_internal(&new_type, TypeSource::Primitive);
        }

        // Set up base type relationships
        let object_token = CilPrimitive::new(CilPrimitiveKind::Object).token();
        let value_type_token = CilPrimitive::new(CilPrimitiveKind::ValueType).token();

        // All value types extend System.ValueType
        for primitive in [
            CilPrimitive::new(CilPrimitiveKind::Void),
            CilPrimitive::new(CilPrimitiveKind::Boolean),
            CilPrimitive::new(CilPrimitiveKind::Char),
            CilPrimitive::new(CilPrimitiveKind::I1),
            CilPrimitive::new(CilPrimitiveKind::U1),
            CilPrimitive::new(CilPrimitiveKind::I2),
            CilPrimitive::new(CilPrimitiveKind::U2),
            CilPrimitive::new(CilPrimitiveKind::I4),
            CilPrimitive::new(CilPrimitiveKind::U4),
            CilPrimitive::new(CilPrimitiveKind::I8),
            CilPrimitive::new(CilPrimitiveKind::U8),
            CilPrimitive::new(CilPrimitiveKind::R4),
            CilPrimitive::new(CilPrimitiveKind::R8),
            CilPrimitive::new(CilPrimitiveKind::I),
            CilPrimitive::new(CilPrimitiveKind::U),
        ] {
            let type_token = primitive.token();
            if let (Some(type_rc), Some(value_type_rc)) = (
                self.types.get(&type_token),
                self.types.get(&value_type_token),
            ) {
                type_rc
                    .value()
                    .base
                    .set(value_type_rc.value().clone().into())
                    .map_err(|_| malformed_error!("Type base already set"))?;
            }
        }

        // System.ValueType itself extends System.Object
        if let (Some(value_type_rc), Some(object_rc)) = (
            self.types.get(&value_type_token),
            self.types.get(&object_token),
        ) {
            value_type_rc
                .value()
                .base
                .set(object_rc.value().clone().into())
                .map_err(|_| malformed_error!("ValueType base already set"))?;
        }

        // System.String extends System.Object
        if let (Some(string_rc), Some(object_rc)) = (
            self.types
                .get(&CilPrimitive::new(CilPrimitiveKind::String).token()),
            self.types.get(&object_token),
        ) {
            string_rc
                .value()
                .base
                .set(object_rc.value().clone().into())
                .map_err(|_| malformed_error!("String base already set"))?;
        }

        Ok(())
    }

    /// Register a new type in all the lookup tables
    ///
    /// ## Arguments
    /// * `type_rc`     - The type instance
    /// * `source`      - The the source of the type
    fn register_type_internal(&self, type_rc: &CilTypeRc, source: TypeSource) {
        let token = type_rc.token;
        if self.types.contains_key(&token) {
            return;
        }

        self.types.insert(token, type_rc.clone());

        self.types_by_source
            .entry(source)
            .or_default()
            .insert(type_rc.token);

        if !type_rc.namespace.is_empty() {
            self.types_by_namespace
                .entry(type_rc.namespace.clone())
                .or_default()
                .insert(type_rc.token);
        }

        self.types_by_name
            .entry(type_rc.name.clone())
            .or_default()
            .insert(type_rc.token);

        let fullname = type_rc.fullname();
        self.index_nested_suffix(&fullname, type_rc.token);
        self.types_by_fullname
            .entry(fullname)
            .or_default()
            .insert(type_rc.token);
    }

    /// Indexes a nested type under the last component of its fullname.
    ///
    /// Non-nested names are skipped: they are already answered exactly by
    /// `types_by_fullname`, and indexing them would make the suffix map a second copy of it.
    fn index_nested_suffix(&self, fullname: &str, token: Token) {
        if let Some(last) = fullname.rsplit('/').next() {
            if last.len() != fullname.len() {
                self.types_by_nested_suffix
                    .entry(Arc::from(last))
                    .or_default()
                    .insert(token);
            }
        }
    }

    /// Insert a `CilType` into the registry
    ///
    /// ## Arguments
    /// * '`new_type`' - The type to register
    pub fn insert(&self, new_type: &CilTypeRc) {
        let source = match new_type.external() {
            Some(external_source) => self.register_source(external_source),
            None => TypeSource::Assembly(self.current_assembly.clone()),
        };

        self.register_type_internal(new_type, source);
    }

    /// Create a new empty type with the next available token
    ///
    /// # Errors
    /// Returns an error if the type cannot be created or inserted into the registry.
    pub fn create_type_empty(&self) -> Result<CilTypeRc> {
        let token = self.next_token();

        let new_type = Arc::new(CilType::new(
            token,
            String::new(),
            String::new(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            None,
        ));

        self.types.insert(token, new_type.clone());
        Ok(new_type)
    }

    /// Create a new type with a specific flavor
    ///
    /// ## Arguments
    /// * 'flavor' - The flavor to set for the new type
    ///
    /// # Errors
    /// Returns an error if the type cannot be created or inserted into the registry.
    pub fn create_type_with_flavor(&self, flavor: CilFlavor) -> Result<CilTypeRc> {
        let token = self.next_token();

        let new_type = Arc::new(CilType::new(
            token,
            String::new(),
            String::new(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(flavor),
        ));

        self.types.insert(token, new_type.clone());
        Ok(new_type)
    }

    /// Get a primitive type by its `CilPrimitive` enum value
    ///
    /// ## Arguments
    /// * 'primitive' - The kind of primitive to look up
    ///
    /// # Errors
    /// Returns an error if the primitive type is not found in the registry.
    pub fn get_primitive(&self, primitive: CilPrimitiveKind) -> Result<CilTypeRc> {
        match self.types.get(&primitive.token()) {
            Some(res) => Ok(res.value().clone()),
            None => Err(TypeNotFound(primitive.token())),
        }
    }

    /// Look up a type by its metadata token.
    ///
    /// Performs the primary lookup operation using the token-based index.
    /// This is the most efficient lookup method with O(log n) complexity.
    ///
    /// # Arguments
    /// * `token` - The metadata token to look up
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The type if found
    /// * `None` - If no type exists with the given token
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free for concurrent access.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{typesystem::TypeRegistry, token::Token};
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// if let Some(type_def) = registry.get(&Token::new(0x02000001)) {
    ///     println!("Found type: {}.{}", type_def.namespace, type_def.name);
    /// }
    /// # }
    /// ```
    pub fn get(&self, token: &Token) -> Option<CilTypeRc> {
        self.types.get(token).map(|entry| entry.value().clone())
    }

    /// Returns the `<Module>` type which contains global fields and methods.
    ///
    /// The `<Module>` type is always TypeDef RID 1 in .NET assemblies. It contains
    /// global methods, the module static constructor (.cctor), and nested types
    /// injected by obfuscators.
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The module type
    /// * `None` - If the module type doesn't exist (malformed assembly)
    #[must_use]
    pub fn module_type(&self) -> Option<CilTypeRc> {
        self.get(&Token::new(0x0200_0001))
    }

    /// Returns the token of the module static constructor (.cctor) if it exists.
    ///
    /// The module `.cctor` is defined on the `<Module>` type (TypeDef RID 1).
    /// This method is commonly used to find initialization code that needs
    /// to be analyzed or neutralized during deobfuscation.
    ///
    /// # Returns
    ///
    /// * `Some(Token)` - The token of the module `.cctor` method
    /// * `None` - If the module type doesn't exist or has no `.cctor`
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// if let Some(cctor_token) = registry.module_cctor() {
    ///     println!("Module .cctor found: {:?}", cctor_token);
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn module_cctor(&self) -> Option<Token> {
        self.module_type().and_then(|module_type| {
            module_type.methods.iter().find_map(|(_, method_ref)| {
                method_ref
                    .upgrade()
                    .and_then(|m| if m.is_cctor() { Some(m.token) } else { None })
            })
        })
    }

    /// Look up a type by its source and qualified name.
    ///
    /// Performs a targeted lookup for types from a specific source with
    /// exact namespace and name matching. This is useful for resolving
    /// external type references where the source is known.
    ///
    /// # Arguments
    /// * `source` - The origin source of the type
    /// * `namespace` - The namespace of the type (can be empty)
    /// * `name` - The exact name of the type
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The first matching type from the specified source
    /// * `None` - If no matching type is found in the source
    ///
    /// # Performance
    ///
    /// This method combines source filtering with name lookup for efficient
    /// resolution of external type references.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{TypeRegistry, TypeSource};
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// let external_source = TypeSource::AssemblyRef(Token::new(0x23000001));
    /// if let Some(type_def) = registry.get_by_source_and_name(
    ///     &external_source,
    ///     "System",
    ///     "String"
    /// ) {
    ///     println!("Found external String type");
    /// }
    /// # }
    /// ```
    pub fn get_by_source_and_name(
        &self,
        source: &TypeSource,
        namespace: &str,
        name: &str,
    ) -> Option<CilTypeRc> {
        let fullname = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}.{name}")
        };

        if let Some(tokens) = self.types_by_source.get(source) {
            for &token in tokens.value() {
                if let Some(type_rc) = self.types.get(&token) {
                    if type_rc.value().namespace == namespace && type_rc.value().name == name {
                        return Some(type_rc.value().clone());
                    }
                }
            }
        }

        if let Some(tokens) = self.types_by_fullname.get(fullname.as_str()) {
            if let Some(&token) = tokens.first() {
                return self.types.get(&token).map(|res| res.value().clone());
            }
        }

        None
    }

    /// Get all types within a specific namespace.
    ///
    /// Returns all types that belong to the specified namespace, regardless
    /// of their source or other characteristics. This is useful for namespace
    /// exploration and type discovery operations.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to search for (case-sensitive)
    ///
    /// # Returns
    /// A vector of all types in the specified namespace. The vector may be
    /// empty if no types exist in the namespace.
    ///
    /// # Performance
    ///
    /// This operation is O(1) for namespace lookup plus O(n) for type
    /// resolution where n is the number of types in the namespace.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Get all System types
    /// let system_types = registry.get_by_namespace("System");
    /// for type_def in system_types {
    ///     println!("System type: {}", type_def.name);
    /// }
    ///
    /// // Get types in global namespace
    /// let global_types = registry.get_by_namespace("");
    /// # }
    /// ```
    pub fn get_by_namespace(&self, namespace: &str) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_namespace.get(namespace) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all types with a specific simple name across all namespaces.
    ///
    /// Returns all types that have the specified name, regardless of their
    /// namespace. This can return multiple types if the same name exists
    /// in different namespaces (e.g., multiple "List" types).
    ///
    /// # Arguments
    /// * `name` - The simple name to search for (case-sensitive)
    ///
    /// # Returns
    /// A vector of all types with the specified name. Types from different
    /// namespaces will be included. The vector may be empty if no types
    /// with the name exist.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Find all "List" types (may find System.Collections.List,
    /// // System.Collections.Generic.List, custom List types, etc.)
    /// let list_types = registry.get_by_name("List");
    /// for type_def in list_types {
    ///     println!("List type: {}.{}", type_def.namespace, type_def.name);
    /// }
    /// # }
    /// ```
    pub fn get_by_name(&self, name: &str) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_name.get(name) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get types by their fully qualified name (namespace.name).
    ///
    /// Returns all types that exactly match the specified fully qualified name.
    /// This is the most precise name-based lookup method and typically returns
    /// at most one type (unless there are duplicate definitions).
    ///
    /// # Arguments
    /// * `fullname` - The fully qualified name in "namespace.name" format
    /// * `external` - Whether to search external registries if not found locally
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The first TypeDef found
    /// * `None` - If no TypeDef with the name is found
    ///
    /// # Name Format
    ///
    /// The fullname should be in the format:
    /// - "Namespace.TypeName" for namespaced types
    /// - "`TypeName`" for types in the global namespace
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Find the specific System.String type (false = local only)
    /// if let Some(string_type) = registry.get_by_fullname("System.String", false) {
    ///     println!("Found System.String: 0x{:08X}", string_type.token.value());
    /// }
    ///
    /// // Find including external types
    /// let global_type = registry.get_by_fullname("GlobalType", true);
    /// # }
    /// ```
    pub fn get_by_fullname(&self, fullname: &str, external: bool) -> Option<CilTypeRc> {
        if let Some(tokens) = self.types_by_fullname.get(fullname) {
            for token in tokens.value() {
                if let Some(entry) = self.types.get(token) {
                    let type_rc = entry.value().clone();
                    // Accept TypeDef (0x02), TypeSpec (0x1B), and artificial types (0xF0)
                    if type_rc.token.is_table(TableId::TypeDef)
                        || type_rc.token.is_table(TableId::TypeSpec)
                        || type_rc.token.table() == 0xF0
                    {
                        return Some(type_rc);
                    }
                }
            }
        } else {
            // Fallback: suffix matching for nested types. A TypeRef may carry the inner name
            // alone (`DynamicPartitionEnumerator_Abstract`2`) where the TypeDef carries the
            // whole path (`Partitioner/DynamicPartitionEnumerator_Abstract`2`).
            //
            // `types_by_nested_suffix` narrows this to the types whose fullname ends in the
            // same *component*; the `ends_with` below then confirms the full requested
            // suffix, so a multi-component request still matches exactly as before. Only
            // matches that cut a component in half - `Bar` against `A/FooBar` - are no
            // longer accepted, and those were never nested-type resolutions.
            let requested_suffix = fullname.rsplit('/').next().unwrap_or(fullname);
            if let Some(tokens) = self.types_by_nested_suffix.get(requested_suffix) {
                for token in tokens.value() {
                    let Some(entry) = self.types.get(token) else {
                        continue;
                    };
                    let type_rc = entry.value().clone();
                    if !type_rc.token.is_table(TableId::TypeDef)
                        && !type_rc.token.is_table(TableId::TypeSpec)
                    {
                        continue;
                    }

                    let candidate = type_rc.fullname();
                    if candidate.ends_with(fullname) && &*candidate != fullname {
                        return Some(type_rc);
                    }
                }
            }
        }

        if external {
            for external_registry_entry in &self.external_registries {
                let Some(external_registry) = external_registry_entry.value().upgrade() else {
                    continue;
                };
                if let Some(external_type) = external_registry.get_by_fullname(fullname, false) {
                    return Some(external_type);
                }
            }
        }
        None
    }

    /// Resolves a type token to its most concrete [`CilType`] representation.
    ///
    /// For **TypeRef** tokens (table 0x01), performs a fullname-based lookup to find
    /// the corresponding **TypeDef** (or **TypeSpec**) within this assembly. This is
    /// essential because TypeRef entries are lightweight cross-module references that
    /// lack populated method and field lists - resolving to a TypeDef ensures callers
    /// can inspect the type's full structure.
    ///
    /// For all other token types (TypeDef, TypeSpec, primitives), behaves identically
    /// to [`get()`](Self::get).
    ///
    /// # Fallback Behavior
    ///
    /// If a TypeRef has no matching TypeDef in this assembly (i.e., it refers to an
    /// external type from another module), the original TypeRef entry is returned.
    /// This ensures the method never returns `None` for valid tokens that exist in
    /// the registry.
    ///
    /// # Arguments
    ///
    /// * `token` - A type metadata token (TypeDef, TypeRef, TypeSpec, or primitive).
    ///
    /// # Returns
    ///
    /// * `Some(CilTypeRc)` - The resolved type, preferring TypeDef over TypeRef
    /// * `None` - The token does not exist in the registry
    #[must_use]
    pub fn resolve(&self, token: &Token) -> Option<CilTypeRc> {
        let entry = self.get(token)?;
        if token.is_table(TableId::TypeRef) {
            self.get_by_fullname(&entry.fullname(), false)
                .or(Some(entry))
        } else {
            Some(entry)
        }
    }

    /// Get all TypeDefs by fully qualified name.
    ///
    /// # Arguments
    /// * `fullname` - The fully qualified name in "namespace.name" format
    /// * `include_external` - Whether to search external registries
    ///
    /// # Returns
    /// * `Vec<CilTypeRc>` - All TypeDefs found with the given name
    pub fn get_by_fullname_list(&self, fullname: &str, include_external: bool) -> Vec<CilTypeRc> {
        let mut typedef_matches = Vec::new();

        if let Some(tokens) = self.types_by_fullname.get(fullname) {
            for token in tokens.value() {
                if let Some(entry) = self.types.get(token) {
                    let type_rc = entry.value().clone();
                    if type_rc.token.table() == 0xF0
                        || (include_external && type_rc.token.is_table(TableId::TypeDef))
                    {
                        typedef_matches.push(type_rc);
                    }
                }
            }
        }

        if include_external {
            for external_registry_entry in &self.external_registries {
                let Some(external_registry) = external_registry_entry.value().upgrade() else {
                    continue;
                };
                let external_types = external_registry.get_by_fullname_list(fullname, false);
                typedef_matches.extend(external_types);
            }
        }

        typedef_matches
    }

    /// Returns the TypeRef through which this module imports `fullname` from its core
    /// library.
    ///
    /// The core library is the assembly defining `System.Object`, so the scope of the
    /// module's own `System.Object` reference names it (its `System.ValueType`
    /// reference in a module declaring only value types). A module can import one type
    /// from several scopes - an obfuscator built against another runtime adds references
    /// to that runtime's core library - and only the reference into the module's core
    /// library resolves wherever the module runs. Among several `System.Object`
    /// references the lowest row decides, as the compiler emits its rows before anything
    /// appended to the image later.
    ///
    /// Falls back to the lowest TypeRef of that name when the core library does not
    /// provide the type, and returns `None` when the module does not import it.
    #[must_use]
    pub fn get_corelib_typeref(&self, fullname: &str) -> Option<CilTypeRc> {
        let scope_of = |ty: &CilTypeRc| ty.external().and_then(CilTypeReference::token);

        let root = self
            .typerefs_named(names::OBJECT)
            .into_iter()
            .next()
            .or_else(|| self.typerefs_named(names::VALUE_TYPE).into_iter().next());
        let corelib = root.as_ref().and_then(scope_of);
        let candidates = self.typerefs_named(fullname);
        candidates
            .iter()
            .find(|ty| corelib.is_some() && scope_of(ty) == corelib)
            .or(candidates.first())
            .cloned()
    }

    /// Returns the TypeRefs named `fullname`, lowest row first.
    fn typerefs_named(&self, fullname: &str) -> Vec<CilTypeRc> {
        self.types_by_fullname
            .get(fullname)
            .map(|tokens| {
                tokens
                    .value()
                    .iter()
                    .filter(|token| token.is_table(TableId::TypeRef))
                    .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets the byte size of a field for FieldRVA initialization.
    ///
    /// This method looks up a field by its token and determines the size of its data
    /// based on the field's type signature. This is primarily used for pre-populating
    /// static fields from FieldRVA data in the PE file.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field (table 0x04)
    ///
    /// # Returns
    ///
    /// * `Some(size)` - For primitive types with known sizes (I1=1, I2=2, I4=4, I8=8, etc.)
    /// * `Some(class_size)` - For value types with explicit ClassLayout size
    /// * `None` - For arrays, reference types, or types without known sizes
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{TypeRegistry, PointerSize};
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// let field_token = Token::new(0x04000001);
    /// if let Some(size) = registry.get_field_byte_size(&field_token, PointerSize::Bit64) {
    ///     println!("Field size: {} bytes", size);
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn get_field_byte_size(&self, field_token: &Token, ptr_size: PointerSize) -> Option<usize> {
        // Search through all types to find the field
        for entry in self {
            let type_ref = entry.value();
            // Check if this type owns the field
            for (_, field) in type_ref.fields.iter() {
                if field.token == *field_token {
                    // Found the field, get its type signature
                    let sig = &field.signature;

                    // First try to get size from primitive type
                    if let Some(size) = sig.base.byte_size(ptr_size) {
                        return Some(size);
                    }

                    // For value types, try to look up class size
                    if let TypeSignature::ValueType(vt_token) = &sig.base {
                        if let Some(value_type) = self.get(vt_token) {
                            if let Some(class_size) = value_type.class_size.get() {
                                if *class_size > 0 {
                                    return Some(*class_size as usize);
                                }
                            }
                        }
                    }

                    return None;
                }
            }
        }

        None
    }

    /// Gets the type signature of a field by its metadata token.
    ///
    /// Searches through all types to find the field with the given token
    /// and returns its type signature.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the field to look up
    ///
    /// # Returns
    ///
    /// The field's type signature if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// let field_token = Token::new(0x04000001);
    /// if let Some(sig) = registry.get_field_signature(&field_token) {
    ///     println!("Field type: {:?}", sig);
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn get_field_signature(&self, field_token: &Token) -> Option<TypeSignature> {
        // Search through all types to find the field
        for entry in self {
            let type_ref = entry.value();
            // Check if this type owns the field
            for (_, field) in type_ref.fields.iter() {
                if field.token == *field_token {
                    return Some(field.signature.base.clone());
                }
            }
        }

        None
    }

    /// Returns the index of a field within a type's field list.
    ///
    /// This is used for accessing fields in value types (structs) stored inline.
    /// The index corresponds to the position in `EmValue::ValueType::fields`.
    ///
    /// # Arguments
    ///
    /// * `type_token` - Token of the type containing the field.
    /// * `field_token` - Token of the field to find.
    ///
    /// # Returns
    ///
    /// The zero-based index of the field within the type's field list,
    /// or `None` if the field is not found in the type.
    ///
    /// # Example
    ///
    /// ```text
    /// // For struct CFGCtx { uint A; uint B; uint C; uint D; }
    /// // get_field_index_in_type(CFGCtx, CFGCtx::A) returns Some(0)
    /// // get_field_index_in_type(CFGCtx, CFGCtx::D) returns Some(3)
    /// ```
    #[must_use]
    pub fn get_field_index_in_type(
        &self,
        type_token: &Token,
        field_token: &Token,
    ) -> Option<usize> {
        // Get the type
        let type_entry = self.get(type_token)?;

        // Find the field index within the type's field list
        for (index, (_, field)) in type_entry.fields.iter().enumerate() {
            if field.token == *field_token {
                return Some(index);
            }
        }

        None
    }

    /// Register a source entity to enable resolving references to it
    ///
    /// ## Arguments
    /// * 'source' - The source of the type to register
    pub fn register_source(&self, source: &CilTypeReference) -> TypeSource {
        self.sources.register_source(source)
    }

    /// Get a source reference by its id
    ///
    /// ## Arguments
    /// * 'source' - The source of the type to look for
    pub fn get_source_reference(&self, source: &TypeSource) -> Option<CilTypeReference> {
        self.sources.get_source(source)
    }

    /// This method creates types with complete structural information upfront, enabling
    /// proper type construction that considers the full type identity including generic arguments,
    /// base types, and other distinguishing characteristics.
    ///
    /// ## Arguments
    /// * `spec` - Complete type specification including all distinguishing information
    ///
    /// ## Errors
    /// Returns an error if type construction fails due to invalid specifications
    /// or if required dependencies cannot be resolved.
    pub fn get_or_create_type(&self, spec: &CompleteTypeSpec) -> Result<CilTypeRc> {
        let token = if let Some(init_token) = spec.token_init {
            init_token
        } else {
            self.next_token()
        };

        if let Some(existing) = self.types.get(&token) {
            return Ok(existing.value().clone());
        }

        let flags = spec.flags.unwrap_or(TypeAttributes::ZERO);
        let new_type = Arc::new(CilType::new(
            token,
            spec.namespace.clone(),
            spec.name.clone(),
            self.get_source_reference(&spec.source),
            None,
            flags,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(spec.flavor.clone()),
        ));

        Self::configure_type_from_spec(&new_type, spec)?;

        self.register_type_internal(&new_type, spec.source.clone());

        Ok(new_type)
    }

    /// Calculate hash for complete type specification with enhanced collision resistance
    fn calculate_complete_type_hash(spec: &CompleteTypeSpec) -> u64 {
        let mut hash_builder = TypeSignatureHash::new()
            .add_flavor(&spec.flavor)
            .add_fullname(&spec.namespace, &spec.name)
            .add_source(&spec.source);

        // Include generic arguments with enhanced entropy
        if let Some(generic_args) = &spec.generic_args {
            hash_builder = hash_builder
                .add_component(&generic_args.len())
                .add_component(&"generic_args_marker"); // Add distinguishing marker

            for (index, arg) in generic_args.iter().enumerate() {
                // Include position to prevent order-independent collisions
                hash_builder = hash_builder.add_component(&index).add_token(&arg.token);

                // Include additional type characteristics for better distinction
                hash_builder = hash_builder
                    .add_fullname(&arg.namespace, &arg.name)
                    .add_flavor(arg.flavor());
            }
        } else {
            // Add explicit marker for non-generic types to distinguish from empty generic args
            hash_builder = hash_builder.add_component(&"non_generic_marker");
        }

        // Include base type with enhanced information
        if let Some(base_type) = &spec.base_type {
            hash_builder = hash_builder
                .add_component(&"base_type_marker")
                .add_token(&base_type.token)
                .add_fullname(&base_type.namespace, &base_type.name)
                .add_flavor(base_type.flavor());
        } else {
            // Add explicit marker for types without base type
            hash_builder = hash_builder.add_component(&"no_base_type_marker");
        }

        hash_builder.finalize()
    }

    /// Configure type according to complete specification
    fn configure_type_from_spec(type_ref: &CilTypeRc, spec: &CompleteTypeSpec) -> Result<()> {
        // Set base type if specified
        if let Some(base_type) = &spec.base_type {
            if type_ref.base.get().is_none() {
                type_ref
                    .base
                    .set(CilTypeRef::from(base_type.clone()))
                    .map_err(|_| malformed_error!("Base type already set"))?;
            }
        }

        // Configure generic arguments if specified
        if let Some(generic_args) = &spec.generic_args {
            for (index, arg_type) in generic_args.iter().enumerate() {
                let rid = u32::try_from(index)
                    .map_err(|_| malformed_error!("Generic argument index too large"))?
                    .checked_add(1)
                    .ok_or_else(|| malformed_error!("Generic argument rid overflow"))?;
                let token_value = 0x2B00_0000_u32
                    .checked_add(
                        u32::try_from(index)
                            .map_err(|_| malformed_error!("Generic argument index too large"))?,
                    )
                    .and_then(|v| v.checked_add(1))
                    .ok_or_else(|| malformed_error!("Token value overflow"))?;

                let method_spec = Arc::new(MethodSpec {
                    rid,
                    token: Token::new(token_value),
                    offset: 0,
                    method: CilTypeReference::None,
                    instantiation: SignatureMethodSpec {
                        generic_args: vec![],
                    },
                    custom_attributes: Default::default(),
                    generic_args: {
                        let type_ref_list = Arc::new(boxcar::Vec::with_capacity(1));
                        type_ref_list.push(arg_type.clone().into());
                        type_ref_list
                    },
                });
                type_ref.generic_args.push(method_spec);
            }
        }

        Ok(())
    }

    /// Count of types in the registry
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Returns an iterator over all types in the registry
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<'_, Token, CilTypeRc> {
        self.types.iter()
    }

    /// Get all types in the registry
    ///
    /// Prefer [`iter`](Self::iter) where a borrow suffices: this clones an `Arc` per type, so
    /// each call is a heap allocation plus two atomic RMWs per type in the assembly.
    pub fn all_types(&self) -> Vec<CilTypeRc> {
        self.types
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns the token of the type declaring `method_token`, or `None` if no type claims it.
    ///
    /// The first lookup for a given token scans the registry; the answer is then memoised, so
    /// repeated dispatch to the same method - the emulator's actual access pattern, since a hot
    /// loop calls the same handful of methods - is O(1) thereafter.
    ///
    /// Memoisation is on demand rather than built once at load because a type's method list is
    /// populated *after* the type itself is registered; an eagerly built index could be
    /// permanently cached while incomplete.
    #[must_use]
    pub fn declaring_type_token_of_method(&self, method_token: Token) -> Option<Token> {
        if let Some(cached) = self.method_to_type.get(&method_token) {
            return Some(*cached);
        }

        for entry in self.types.iter() {
            let type_token = *entry.key();
            for (_, method_ref) in entry.value().methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    if method.token == method_token {
                        self.method_to_type.insert(method_token, type_token);
                        return Some(type_token);
                    }
                }
            }
        }

        None
    }

    /// Returns the token of the type declaring `field_token`, or `None` if no type claims it.
    ///
    /// Memoised on the same terms as
    /// [`declaring_type_token_of_method`](Self::declaring_type_token_of_method).
    #[must_use]
    pub fn declaring_type_token_of_field(&self, field_token: Token) -> Option<Token> {
        if let Some(cached) = self.field_to_type.get(&field_token) {
            return Some(*cached);
        }

        for entry in self.types.iter() {
            let type_token = *entry.key();
            for (_, field) in entry.value().fields.iter() {
                if field.token == field_token {
                    self.field_to_type.insert(field_token, type_token);
                    return Some(type_token);
                }
            }
        }

        None
    }

    /// Get types from a specific source
    ///
    /// ## Arguments
    /// * 'source' - The source of the types to look for
    pub fn types_from_source(&self, source: &TypeSource) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_source.get(source) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Link another TypeRegistry for cross-assembly type resolution.
    ///
    /// This enables the registry to search other assemblies' type registries when
    /// a type cannot be found locally. This is essential for resolving TypeRef
    /// tokens that reference external assemblies.
    ///
    /// The link is weak: it does not keep `registry` alive, whoever owns the external
    /// assembly does (a project holds each of its assemblies). Once that is dropped, lookups
    /// no longer search it.
    ///
    /// # Arguments
    /// * `assembly_identity` - The identity of the external assembly
    /// * `registry` - The TypeRegistry from the external assembly
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{
    ///     identity::AssemblyIdentity,
    ///     typesystem::TypeRegistry,
    /// };
    /// use std::sync::Arc;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let main_identity = AssemblyIdentity::parse("Main, Version=1.0.0.0")?;
    /// let main_registry = TypeRegistry::new(main_identity)?;
    /// let ext_identity = AssemblyIdentity::parse("mscorlib, Version=4.0.0.0")?;
    /// let external_registry = Arc::new(TypeRegistry::new(ext_identity.clone())?);
    /// let external_identity = ext_identity;
    ///
    /// main_registry.registry_link(external_identity, &external_registry);
    ///
    /// // Now main_registry can resolve types from the external assembly
    /// # Ok(())
    /// # }
    /// ```
    pub fn registry_link(&self, assembly_identity: AssemblyIdentity, registry: &Arc<TypeRegistry>) {
        self.external_registries
            .insert(assembly_identity, Arc::downgrade(registry));
    }

    /// Unlink a TypeRegistry from cross-assembly type resolution.
    ///
    /// # Arguments
    /// * `assembly_identity` - The identity of the assembly to unlink
    ///
    /// # Returns
    /// The removed TypeRegistry if it existed, None otherwise
    pub fn registry_unlink(
        &self,
        assembly_identity: &AssemblyIdentity,
    ) -> Option<Arc<TypeRegistry>> {
        self.external_registries
            .remove(assembly_identity)
            .and_then(|(_, registry)| registry.upgrade())
    }

    /// Get a type by fully qualified name across all registries.
    ///
    /// This is a convenience method that calls get_by_fullname_first with include_external=true.
    ///
    /// # Arguments  
    /// * `fullname` - The fully qualified name in "namespace.name" format
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The first TypeDef found
    /// * `None` - If no TypeDef with the name is found in any registry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// if let Some(string_type) = registry.resolve_type_global("System.String") {
    ///     println!("Resolved System.String: 0x{:08X}", string_type.token.value());
    ///     // This will be a TypeDef if available
    /// }
    /// # }
    /// ```
    pub fn resolve_type_global(&self, fullname: &str) -> Option<CilTypeRc> {
        self.get_by_fullname(fullname, true)
    }

    /// Get all registered external assembly identities.
    ///
    /// # Returns
    /// A vector of all assembly identities that have registered TypeRegistries
    pub fn external_assemblies(&self) -> Vec<AssemblyIdentity> {
        self.external_registries
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get an external TypeRegistry by assembly identity.
    ///
    /// # Arguments
    /// * `assembly_identity` - The identity of the external assembly
    ///
    /// # Returns  
    /// * `Some(Arc<TypeRegistry>)` - The external registry if registered
    /// * `None` - If no registry is registered for the assembly
    pub fn get_external_registry(
        &self,
        assembly_identity: &AssemblyIdentity,
    ) -> Option<Arc<TypeRegistry>> {
        self.external_registries
            .get(assembly_identity)
            .and_then(|entry| entry.value().upgrade())
    }

    /// Count of registered external registries.
    ///
    /// # Returns
    /// The number of external TypeRegistries currently registered
    pub fn external_registry_count(&self) -> usize {
        self.external_registries.len()
    }

    /// Replace TypeRef registry entries to point to resolved TypeDef.
    ///
    /// This method updates the registry's lookup tables so that the TypeRef token
    /// now points to the resolved TypeDef from another assembly, instead of the
    /// original TypeRef. The TypeRef token remains as the lookup key.
    ///
    /// # Arguments
    /// * `typeref_token` - The TypeRef token to redirect
    /// * `resolved_typedef` - The resolved TypeDef to point to
    ///
    /// # Returns
    /// * `true` if the replacement was successful
    /// * `false` if the TypeRef token was not found in this registry
    pub fn redirect_typeref_to_typedef(
        &self,
        typeref_token: Token,
        resolved_typedef: &CilTypeRc,
    ) -> bool {
        // Get the original TypeRef to clean up its secondary index entries
        let original_typeref = if let Some(entry) = self.types.get(&typeref_token) {
            entry.value().clone()
        } else {
            return false; // TypeRef not found
        };

        // Redirect the TypeRef token in all secondary indexes to use the TypeDef's metadata
        // Remove TypeRef from its original indexes (old metadata)
        if let Some(external) = original_typeref.external() {
            let source = self.register_source(external);
            if let Some(mut list) = self.types_by_source.get_mut(&source) {
                list.remove(&typeref_token);
            }
        } else {
            let current_source = self.current_assembly_source();
            if let Some(mut list) = self.types_by_source.get_mut(&current_source) {
                list.remove(&typeref_token);
            }
        }

        if !original_typeref.namespace.is_empty() {
            if let Some(mut list) = self.types_by_namespace.get_mut(&original_typeref.namespace) {
                list.remove(&typeref_token);
            }
        }

        if let Some(mut list) = self.types_by_name.get_mut(&original_typeref.name) {
            list.remove(&typeref_token);
        }

        let old_fullname = original_typeref.fullname();
        let old_suffix = old_fullname.rsplit('/').next().unwrap_or(&old_fullname);
        if let Some(mut list) = self.types_by_nested_suffix.get_mut(old_suffix) {
            list.remove(&typeref_token);
        }
        if let Some(mut list) = self.types_by_fullname.get_mut(&*old_fullname) {
            list.remove(&typeref_token);
        }

        // Add TypeRef token to the TypeDef's indexes (new metadata)
        if let Some(external) = resolved_typedef.external() {
            let source = self.register_source(external);
            self.types_by_source
                .entry(source)
                .or_default()
                .insert(typeref_token);
        }

        if !resolved_typedef.namespace.is_empty() {
            self.types_by_namespace
                .entry(resolved_typedef.namespace.clone())
                .or_default()
                .insert(typeref_token);
        }

        self.types_by_name
            .entry(resolved_typedef.name.clone())
            .or_default()
            .insert(typeref_token);

        let new_fullname = resolved_typedef.fullname();
        self.index_nested_suffix(&new_fullname, typeref_token);
        self.types_by_fullname
            .entry(new_fullname)
            .or_default()
            .insert(typeref_token);

        self.types.insert(typeref_token, resolved_typedef.clone());
        true
    }

    /// Build the fullname lookup table after structural relationships are established.
    ///
    /// This method should be called after all structural relationships (like nested classes)
    /// have been established, so that types can be looked up by their final hierarchical names.
    /// It populates the `types_by_fullname` index which is used by lookup methods.
    ///
    /// # Usage
    ///
    /// This should be called once per assembly after:
    /// - All TypeDef, TypeRef, TypeSpec entries are loaded
    /// - All NestedClass relationships are applied
    /// - Before InheritanceResolver runs (which needs to look up nested types)
    pub fn build_fullnames(&self) {
        self.types_by_fullname.clear();
        self.types_by_nested_suffix.clear();

        for entry in &self.types {
            let type_rc = entry.value();
            let current_fullname = type_rc.fullname();

            self.index_nested_suffix(&current_fullname, type_rc.token);
            self.types_by_fullname
                .entry(current_fullname)
                .or_default()
                .insert(type_rc.token);
        }
    }
}

impl<'a> IntoIterator for &'a TypeRegistry {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, CilTypeRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, CilTypeRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use uguid::guid;

    use super::*;
    use crate::{
        metadata::tables::{
            AssemblyFlags, AssemblyRef, AssemblyRefHash, File, FileAttributes, Module, ModuleRef,
        },
        testkit::{
            fixture,
            helpers::{runtime_type_handle_rows, TWO_CORELIB_FIXTURES},
        },
        CilObject,
    };

    /// Builds a type whose *name* already contains the nested path, which is the shape
    /// `compute_fullname` produces for a type with an enclosing type.
    fn nested_type(token: Token, namespace: &str, name: &str) -> CilTypeRc {
        Arc::new(CilType::new(
            token,
            namespace.to_string(),
            name.to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            None,
        ))
    }

    /// A TypeRef may name a nested type by its inner name alone while the TypeDef carries
    /// the whole path. Resolving that is what the suffix index replaced a full scan of every
    /// registered fullname with; the resolution itself must be unchanged.
    #[test]
    fn nested_types_resolve_by_their_inner_name() {
        let identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(identity).unwrap();

        let token = Token::new(0x0200_1234);
        registry.insert(&nested_type(
            token,
            "NS",
            "Partitioner/DynamicPartitionEnumerator`2",
        ));

        // The inner name alone resolves to the nested type...
        let found = registry
            .get_by_fullname("DynamicPartitionEnumerator`2", false)
            .expect("nested type must resolve by its inner name");
        assert_eq!(found.token, token);

        // ...as does a multi-component suffix.
        let found = registry
            .get_by_fullname("Partitioner/DynamicPartitionEnumerator`2", false)
            .expect("nested type must resolve by a multi-component suffix");
        assert_eq!(found.token, token);

        // The exact fullname still goes through the exact index, not the fallback.
        assert!(registry
            .get_by_fullname("NS.Partitioner/DynamicPartitionEnumerator`2", false)
            .is_some());

        // An unrelated name must not resolve.
        assert!(registry.get_by_fullname("SomethingElse", false).is_none());
    }

    /// The fullname index is set-valued so the TypeRef redirect sweep can remove in `O(log n)`
    /// instead of a linear `retain` over lists that keep growing. Registering the
    /// same token twice must therefore not duplicate it.
    #[test]
    fn fullname_index_holds_each_token_once() {
        let identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(identity).unwrap();

        let token = Token::new(0x0200_4321);
        let type_rc = nested_type(token, "NS", "Outer/Inner");
        registry.insert(&type_rc);
        registry.build_fullnames();
        registry.build_fullnames();

        let tokens = registry
            .types_by_fullname
            .get("NS.Outer/Inner")
            .expect("fullname must be indexed");
        assert_eq!(tokens.value().len(), 1);
    }

    #[test]
    fn test_registry_primitives() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let bool_type = registry.get_primitive(CilPrimitiveKind::Boolean).unwrap();
        assert_eq!(bool_type.name, "Boolean");
        assert_eq!(bool_type.namespace, "System");

        let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
        assert_eq!(int_type.name, "Int32");
        assert_eq!(int_type.namespace, "System");

        let object_type = registry.get_primitive(CilPrimitiveKind::Object).unwrap();
        let string_type = registry.get_primitive(CilPrimitiveKind::String).unwrap();

        assert_eq!(
            string_type.base.get().unwrap().token().unwrap(),
            object_type.token
        );

        let value_type = registry.get_primitive(CilPrimitiveKind::ValueType).unwrap();
        assert_eq!(
            value_type.base.get().unwrap().token().unwrap(),
            object_type.token
        );

        assert_eq!(
            int_type.base.get().unwrap().token().unwrap(),
            value_type.token
        );

        let all_primitives = [
            CilPrimitiveKind::Void,
            CilPrimitiveKind::Boolean,
            CilPrimitiveKind::Char,
            CilPrimitiveKind::I1,
            CilPrimitiveKind::U1,
            CilPrimitiveKind::I2,
            CilPrimitiveKind::U2,
            CilPrimitiveKind::I4,
            CilPrimitiveKind::U4,
            CilPrimitiveKind::I8,
            CilPrimitiveKind::U8,
            CilPrimitiveKind::R4,
            CilPrimitiveKind::R8,
            CilPrimitiveKind::I,
            CilPrimitiveKind::U,
            CilPrimitiveKind::Object,
            CilPrimitiveKind::String,
            CilPrimitiveKind::TypedReference,
            CilPrimitiveKind::ValueType,
            CilPrimitiveKind::Var,
            CilPrimitiveKind::MVar,
            CilPrimitiveKind::Null,
        ];

        for primitive in all_primitives.iter() {
            let prim_type = registry.get_primitive(*primitive);
            assert!(prim_type.is_ok(), "Failed to get primitive: {primitive:?}");
        }
    }

    #[test]
    fn test_create_and_lookup() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let list_type = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections.Generic".to_string(),
                name: "List`1".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");

        let found = registry.get_by_name("List`1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get_by_namespace("System.Collections.Generic");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get_by_fullname_list("System.Collections.Generic.List`1", false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get(&list_type.token);
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, list_type.token);

        let found = registry.get_by_source_and_name(
            &TypeSource::Unknown,
            "System.Collections.Generic",
            "List`1",
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, list_type.token);
    }

    #[test]
    fn test_multiple_types_with_same_name() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let point1 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::ValueType,
                namespace: "System.Drawing".to_string(),
                name: "Point".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let point2 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::ValueType,
                namespace: "System.Windows".to_string(),
                name: "Point".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_ne!(point1.token, point2.token);

        let found = registry.get_by_name("Point");
        assert_eq!(found.len(), 2);

        let found = registry.get_by_fullname_list("System.Drawing.Point", false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, point1.token);

        let found = registry.get_by_fullname_list("System.Windows.Point", false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, point2.token);
    }

    #[test]
    fn test_create_type_empty() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let empty_type = registry.create_type_empty().unwrap();

        assert_eq!(empty_type.namespace, "");
        assert_eq!(empty_type.name, "");
        assert!(matches!(*empty_type.flavor(), CilFlavor::Class)); // Empty types default to Class with lazy evaluation
    }

    #[test]
    fn test_create_type_with_flavor() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let class_type = registry.create_type_with_flavor(CilFlavor::Class).unwrap();

        assert_eq!(class_type.namespace, "");
        assert_eq!(class_type.name, "");
        assert!(matches!(*class_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_insert() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity.clone()).unwrap();

        let token = Token::new(0x01000123);
        let new_type = Arc::new(CilType::new(
            token,
            "MyNamespace".to_string(),
            "MyClass".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::Class),
        ));

        registry.insert(&new_type);

        let found = registry.get(&token);
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, token);

        registry.insert(&new_type);

        let user_types = registry.types_from_source(&TypeSource::Assembly(test_identity));
        assert_eq!(user_types.len(), 1);
    }

    #[test]
    fn test_source_registry() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let module = Arc::new(Module {
            token: Token::new(0x00000001),
            name: "MainModule".to_string(),
            mvid: guid!("01234567-89ab-cdef-0123-456789abcdef"),
            encid: None,
            rid: 1,
            offset: 1,
            generation: 0,
            encbaseid: None,
            imports: Vec::new(),
            custom_attributes: Default::default(),
        });

        let module_ref = Arc::new(ModuleRef {
            token: Token::new(0x1A000001),
            name: "ReferenceModule".to_string(),
            rid: 0,
            offset: 0,
            custom_attributes: Default::default(),
        });

        let assembly_ref = Arc::new(AssemblyRef {
            token: Token::new(0x23000001),
            flags: AssemblyFlags::ZERO,
            name: "ReferenceAssembly".to_string(),
            culture: Some("".to_string()),
            rid: 0,
            offset: 0,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 1,
            identifier: None,
            hash: None,
            os_platform_id: AtomicU32::new(0),
            os_major_version: AtomicU32::new(0),
            os_minor_version: AtomicU32::new(0),
            processor: AtomicU32::new(0),
            custom_attributes: Default::default(),
        });

        let file = Arc::new(File {
            token: Token::new(0x26000001),
            flags: FileAttributes::ZERO,
            name: "ExternalFile.dll".to_string(),
            rid: 0,
            offset: 0,
            hash_value: AssemblyRefHash::new(&[0xCC, 0xCC]).unwrap(),
            custom_attributes: Default::default(),
        });

        let module_source = registry.register_source(&CilTypeReference::Module(module.clone()));
        let module_ref_source =
            registry.register_source(&CilTypeReference::ModuleRef(module_ref.clone()));
        let assembly_ref_source =
            registry.register_source(&CilTypeReference::AssemblyRef(assembly_ref.clone()));
        let file_source = registry.register_source(&CilTypeReference::File(file.clone()));

        assert!(matches!(module_source, TypeSource::Module(_)));
        assert!(matches!(module_ref_source, TypeSource::ModuleRef(_)));
        assert!(matches!(assembly_ref_source, TypeSource::AssemblyRef(_)));
        assert!(matches!(file_source, TypeSource::File(_)));

        if let TypeSource::Module(token) = module_source {
            if let CilTypeReference::Module(ref m) =
                registry.get_source_reference(&module_source).unwrap()
            {
                assert_eq!(m.token, token);
            } else {
                panic!("Expected Module reference");
            }
        }

        if let TypeSource::ModuleRef(token) = module_ref_source {
            if let CilTypeReference::ModuleRef(ref m) =
                registry.get_source_reference(&module_ref_source).unwrap()
            {
                assert_eq!(m.token, token);
            } else {
                panic!("Expected ModuleRef reference");
            }
        }

        if let TypeSource::AssemblyRef(token) = assembly_ref_source {
            if let CilTypeReference::AssemblyRef(ref a) =
                registry.get_source_reference(&assembly_ref_source).unwrap()
            {
                assert_eq!(a.token, token);
            } else {
                panic!("Expected AssemblyRef reference");
            }
        }

        if let TypeSource::File(token) = file_source {
            if let CilTypeReference::File(ref f) =
                registry.get_source_reference(&file_source).unwrap()
            {
                assert_eq!(f.token, token);
            } else {
                panic!("Expected File reference");
            }
        }

        let type1 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections".to_string(),
                name: "ArrayList".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let type2 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections".to_string(),
                name: "ArrayList".to_string(),
                source: module_ref_source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let type3 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections".to_string(),
                name: "ArrayList".to_string(),
                source: assembly_ref_source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_ne!(type1.token, type2.token);
        assert_ne!(type1.token, type3.token);
        assert_ne!(type2.token, type3.token);

        let types_from_module_ref = registry.types_from_source(&module_ref_source);
        assert_eq!(types_from_module_ref.len(), 1);
        assert_eq!(types_from_module_ref[0].token, type2.token);

        let types_from_assembly_ref = registry.types_from_source(&assembly_ref_source);
        assert_eq!(types_from_assembly_ref.len(), 1);
        assert_eq!(types_from_assembly_ref[0].token, type3.token);
    }

    #[test]
    fn test_registry_count_and_all_types() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let initial_count = registry.len();

        let _ = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "MyNamespace".to_string(),
                name: "MyClass1".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let _ = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "MyNamespace".to_string(),
                name: "MyClass2".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_eq!(registry.len(), initial_count + 2);

        let all_types = registry.all_types();
        assert!(all_types.len() >= initial_count + 2);

        let class1_count = all_types
            .iter()
            .filter(|t| t.name == "MyClass1" && t.namespace == "MyNamespace")
            .count();

        let class2_count = all_types
            .iter()
            .filter(|t| t.name == "MyClass2" && t.namespace == "MyNamespace")
            .count();

        assert_eq!(class1_count, 1);
        assert_eq!(class2_count, 1);
    }

    #[test]
    fn test_type_signature_hash() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let source1 = TypeSource::Unknown;
        let source2 = TypeSource::AssemblyRef(Token::new(0x23000001));

        let type1 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections".to_string(),
                name: "ArrayList".to_string(),
                source: source1,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let type2 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System.Collections".to_string(),
                name: "ArrayList".to_string(),
                source: source2,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_ne!(type1.token, type2.token);
    }

    #[test]
    fn test_class_vs_generic_instance_hash_debug() {
        // Debug test to investigate hash collision between Class and GenericInstance
        let class_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System.Collections.Generic", "Dictionary`2")
            .add_source(&TypeSource::Unknown)
            .finalize();

        let generic_instance_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::GenericInstance)
            .add_fullname("System.Collections.Generic", "Dictionary`2")
            .add_source(&TypeSource::Unknown)
            .finalize();

        // They should be different
        assert_ne!(
            class_hash, generic_instance_hash,
            "Class and GenericInstance with same name should have different hashes"
        );
    }

    #[test]
    fn test_enhanced_generic_instance_creation() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        // Create primitive types for generic arguments
        let string_type = registry.get_primitive(CilPrimitiveKind::String).unwrap();
        let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
        let _object_type = registry.get_primitive(CilPrimitiveKind::Object).unwrap();

        // Test context-aware creation for generic instances
        let list_string_1 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::GenericInstance,
                namespace: "System.Collections.Generic".to_string(),
                name: "List`1".to_string(),
                source: TypeSource::Unknown,
                generic_args: Some(vec![string_type.clone()]),
                base_type: None,
                flags: None,
            })
            .unwrap();

        let list_string_2 = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::GenericInstance,
                namespace: "System.Collections.Generic".to_string(),
                name: "List`1".to_string(),
                source: TypeSource::Unknown,
                generic_args: Some(vec![string_type.clone()]),
                base_type: None,
                flags: None,
            })
            .unwrap();

        let list_int = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::GenericInstance,
                namespace: "System.Collections.Generic".to_string(),
                name: "List`1".to_string(),
                source: TypeSource::Unknown,
                generic_args: Some(vec![int_type.clone()]),
                base_type: None,
                flags: None,
            })
            .unwrap();

        // Since deduplication is disabled, these should be different instances
        assert_ne!(
            list_string_1.token, list_string_2.token,
            "Without deduplication, tokens should be different"
        );
        assert!(
            !Arc::ptr_eq(&list_string_1, &list_string_2),
            "Without deduplication, instances should be different"
        );

        assert!(
            !list_string_1.is_structurally_equivalent(&list_int),
            "List<string> and List<int> should NOT be structurally equivalent"
        );

        // Basic type identity checks
        assert_eq!(list_string_1.namespace, "System.Collections.Generic");
        assert_eq!(list_string_1.name, "List`1");
        assert!(matches!(
            *list_string_1.flavor(),
            CilFlavor::GenericInstance
        ));
    }

    #[test]
    fn test_token_generation() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let token1 = registry.create_type_empty().unwrap().token;
        let token2 = registry.create_type_empty().unwrap().token;
        let token3 = registry.create_type_empty().unwrap().token;

        assert_eq!(token2.value(), token1.value() + 1);
        assert_eq!(token3.value(), token2.value() + 1);
    }

    #[test]
    fn test_get_and_lookup_methods() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        let bad_token = Token::new(0x01999999);
        assert!(registry.get(&bad_token).is_none());

        let bad_name = registry.get_by_name("DoesNotExist");
        assert!(bad_name.is_empty());

        let bad_namespace = registry.get_by_namespace("NonExistent.Namespace");
        assert!(bad_namespace.is_empty());

        let bad_fullname = registry.get_by_fullname_list("NonExistent.Namespace.Type", false);
        assert!(bad_fullname.is_empty());

        let bad_source_name =
            registry.get_by_source_and_name(&TypeSource::Unknown, "NonExistent.Namespace", "Type");
        assert!(bad_source_name.is_none());
    }

    #[test]
    fn test_improved_hash_collision_resistance() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        // Test cases that would collide with old XOR-based approach
        let types = [
            ("System", "String", TypeSource::Unknown),
            ("System", "Object", TypeSource::Unknown),
            ("System.Collections", "ArrayList", TypeSource::Unknown),
            ("System.Collections.Generic", "List`1", TypeSource::Unknown),
            (
                "MyApp",
                "Helper",
                TypeSource::AssemblyRef(Token::new(0x23000001)),
            ),
            (
                "MyApp",
                "Helper",
                TypeSource::AssemblyRef(Token::new(0x23000002)),
            ),
        ];

        let mut created_types = Vec::new();
        for (namespace, name, source) in &types {
            let type_ref = registry
                .get_or_create_type(&CompleteTypeSpec {
                    token_init: None,
                    flavor: CilFlavor::Class,
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                    source: source.clone(),
                    generic_args: None,
                    base_type: None,
                    flags: None,
                })
                .unwrap();
            created_types.push(type_ref);
        }

        // All types should be unique (each request creates a new type instance)
        assert_eq!(created_types.len(), types.len());

        // Each type should have a unique token
        let mut tokens = std::collections::HashSet::new();
        for type_ref in &created_types {
            assert!(
                tokens.insert(type_ref.token),
                "Duplicate token found: {:?}",
                type_ref.token
            );
        }

        // Verify that identical requests create different instances (no deduplication)
        let duplicate_request = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "System".to_string(),
                name: "String".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        assert_ne!(
            duplicate_request.token, created_types[0].token,
            "Each request should create a unique type instance"
        );
    }

    #[test]
    fn test_hash_different_flavors() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        // Same name/namespace, different flavors should create different types
        let class_type = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Class,
                namespace: "MyNamespace".to_string(),
                name: "MyType".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let interface_type = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::Interface,
                namespace: "MyNamespace".to_string(),
                name: "MyType".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let value_type = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: None,
                flavor: CilFlavor::ValueType,
                namespace: "MyNamespace".to_string(),
                name: "MyType".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        // All should have different tokens
        assert_ne!(class_type.token, interface_type.token);
        assert_ne!(class_type.token, value_type.token);
        assert_ne!(interface_type.token, value_type.token);

        // Verify flavors are correct
        assert_eq!(*class_type.flavor(), CilFlavor::Class);
        assert_eq!(*interface_type.flavor(), CilFlavor::Interface);
        assert_eq!(*value_type.flavor(), CilFlavor::ValueType);
    }

    #[test]
    fn test_hash_collision_chain_functionality() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = TypeRegistry::new(test_identity).unwrap();

        // Force potential hash collision by creating many similar types
        let similar_types = [
            "Type1", "Type2", "Type3", "Type4", "Type5", "Type11", "Type12", "Type13", "Type14",
            "Type15", "TypeA", "TypeB", "TypeC", "TypeD", "TypeE",
        ];

        let mut created_tokens = std::collections::HashSet::new();

        for type_name in &similar_types {
            let type_ref = registry
                .get_or_create_type(&CompleteTypeSpec {
                    token_init: None,
                    flavor: CilFlavor::Class,
                    namespace: "TestNamespace".to_string(),
                    name: type_name.to_string(),
                    source: TypeSource::Unknown,
                    generic_args: None,
                    base_type: None,
                    flags: None,
                })
                .unwrap();

            // Each type should get a unique token
            assert!(
                created_tokens.insert(type_ref.token),
                "Token collision for type: {}",
                type_name
            );

            // Verify the type can be retrieved correctly
            assert_eq!(type_ref.name, *type_name);
            assert_eq!(type_ref.namespace, "TestNamespace");
        }

        // All types should be distinct
        assert_eq!(created_tokens.len(), similar_types.len());
    }

    #[test]
    fn test_signature_hash_ordering_independence() {
        // Test that hash function is sensitive to parameter order
        // This was a problem with the old XOR approach

        let hash1 = TypeSignatureHash::new()
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .add_flavor(&CilFlavor::Class)
            .finalize();

        let hash2 = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .finalize();

        let hash3 = TypeSignatureHash::new()
            .add_source(&TypeSource::Unknown)
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System", "String")
            .finalize();

        // Different orders should produce different hashes (order sensitivity)
        assert_ne!(hash1, hash2, "Hash should be order-sensitive");
        assert_ne!(hash1, hash3, "Hash should be order-sensitive");
        assert_ne!(hash2, hash3, "Hash should be order-sensitive");
    }

    #[test]
    fn test_signature_hash_component_uniqueness() {
        // Test that different components produce different hashes

        let base_hash = TypeSignatureHash::new()
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .finalize();

        let class_hash = TypeSignatureHash::new()
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .add_flavor(&CilFlavor::Class)
            .finalize();

        let interface_hash = TypeSignatureHash::new()
            .add_fullname("System", "String")
            .add_source(&TypeSource::Unknown)
            .add_flavor(&CilFlavor::Interface)
            .finalize();

        let different_source_hash = TypeSignatureHash::new()
            .add_fullname("System", "String")
            .add_source(&TypeSource::AssemblyRef(Token::new(0x23000001)))
            .add_flavor(&CilFlavor::Class)
            .finalize();

        // All should be different
        assert_ne!(base_hash, class_hash);
        assert_ne!(class_hash, interface_hash);
        assert_ne!(class_hash, different_source_hash);
        assert_ne!(interface_hash, different_source_hash);
    }

    #[test]
    fn test_class_vs_generic_instance_hash_collision() {
        // This is the specific collision that breaks the test
        let class_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::Class)
            .add_fullname("System.Collections.Generic", "Dictionary`2")
            .add_source(&TypeSource::Unknown)
            .finalize();

        let generic_instance_hash = TypeSignatureHash::new()
            .add_flavor(&CilFlavor::GenericInstance)
            .add_fullname("System.Collections.Generic", "Dictionary`2")
            .add_source(&TypeSource::Unknown)
            .finalize();

        // These should be different for proper type distinction
        assert_ne!(
            class_hash, generic_instance_hash,
            "CRITICAL: Class and GenericInstance are generating hash collisions! \
             This proves the original hash collision issue still exists."
        );
    }

    #[test]
    fn a_type_imported_from_two_core_libraries_resolves_to_the_modules_own() {
        // A module importing `System.RuntimeTypeHandle` from System.Private.CoreLib as
        // well as from its own core library resolves it to its own import, whichever of
        // the two TypeRefs the table lists first.
        for name in TWO_CORELIB_FIXTURES {
            let path = fixture(&format!("metadata/layouts/{name}"));
            let rows = runtime_type_handle_rows(&path);
            let (own, foreign) = (rows["mscorlib"], rows["System.Private.CoreLib"]);
            assert_eq!(
                foreign < own,
                name.contains("foreign_first"),
                "{name} lists the foreign TypeRef where its name says"
            );

            let assembly = CilObject::from_path(&path).unwrap();
            let types = assembly.types();
            let handle = types
                .get_corelib_typeref("System.RuntimeTypeHandle")
                .unwrap();
            assert_eq!(handle.token, Token::new(0x0100_0000 | own), "{name}");
            // A type the core library does not provide still resolves.
            assert!(
                types.get_corelib_typeref("System.Console").is_some(),
                "{name}"
            );
            assert!(
                types.get_corelib_typeref("No.Such.Type").is_none(),
                "{name}"
            );
        }
    }

    /// Registries linked both ways do not keep each other alive: dropping one frees it, and
    /// the other no longer finds it.
    #[test]
    fn linked_registries_do_not_keep_each_other_alive() {
        let identity_a = AssemblyIdentity::parse("A, Version=1.0.0.0").unwrap();
        let identity_b = AssemblyIdentity::parse("B, Version=1.0.0.0").unwrap();
        let a = Arc::new(TypeRegistry::new(identity_a.clone()).unwrap());
        let b = Arc::new(TypeRegistry::new(identity_b.clone()).unwrap());
        a.registry_link(identity_b.clone(), &b);
        b.registry_link(identity_a, &a);
        assert!(a.get_external_registry(&identity_b).is_some());

        let weak_b = Arc::downgrade(&b);
        drop(b);
        assert!(weak_b.upgrade().is_none());
        assert!(a.get_external_registry(&identity_b).is_none());
        assert!(a.resolve_type_global("Missing.Type").is_none());
    }
}

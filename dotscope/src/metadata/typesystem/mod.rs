//! .NET type system implementation for CIL analysis.
//!
//! This module provides a complete representation of the .NET type system, including
//! type definitions, references, generics, arrays, and primitive types. It bridges
//! the gap between raw metadata tables and a usable type system for analysis.
//!
//! # Key Components
//!
//! - [`crate::metadata::typesystem::CilType`]: Core type representation combining TypeDef, TypeRef, and TypeSpec
//! - [`crate::metadata::typesystem::TypeRegistry`]: Central registry for all types in an assembly  
//! - [`crate::metadata::typesystem::TypeResolver`]: Resolves type references and builds complete type information
//! - [`crate::metadata::typesystem::TypeBuilder`]: Builder pattern for constructing complex types
//! - [`crate::metadata::typesystem::CilPrimitive`]: Built-in primitive types (int32, string, object, etc.)
//!
//! # Type System Features
//!
//! - **Unified representation**: Combines metadata from multiple tables
//! - **Generic support**: Full generic type and method parameter handling
//! - **Array types**: Multi-dimensional and jagged array support
//! - **Inheritance**: Type hierarchy and interface implementation tracking
//! - **Primitive mapping**: Automatic mapping to runtime primitive types
//! - **Reference resolution**: Resolves cross-assembly type references
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::{CilObject, metadata::typesystem::TypeRegistry};
//!
//! let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
//! let type_registry = assembly.types();
//!
//! // Look up a specific type
//! if let Some(string_type) = type_registry.get_by_fullname("System.String", true) {
//!     println!("String type: {} (Token: 0x{:08X})",
//!         string_type.name, string_type.token.value());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

mod base;
mod builder;
mod encoder;
mod hash;
mod primitives;
mod registry;
mod resolver;
pub mod wellknown;

use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, OnceLock, RwLock},
};

pub use base::{
    ArrayDimensions, CilFlavor, CilModifier, CilTypeRef, CilTypeRefList, CilTypeRefListIter,
    CilTypeReference, PointerSize, ELEMENT_TYPE,
};
pub use builder::TypeBuilder;
pub use encoder::TypeSignatureEncoder;
pub use hash::TypeSignatureHash;
pub use primitives::{CilPrimitive, CilPrimitiveData, CilPrimitiveKind};
pub use registry::{CompleteTypeSpec, TypeRegistry, TypeSource};
pub use resolver::TypeResolver;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        method::{MethodRc, MethodRefList},
        query::{FieldQuery, MethodQuery},
        security::Security,
        tables::{
            EventList, FieldAttributes, FieldList, FieldRc, GenericParamList, InterfaceEntryList,
            MethodSpec, MethodSpecList, PropertyList, TableId, TypeAttributes,
        },
        token::Token,
    },
    utils::{LazyList, RowList},
    Error, Result,
};

/// A vector that holds a list of `CilType` references.
///
/// This is a thread-safe, efficient collection optimized for append-only operations
/// during metadata loading and concurrent read access during analysis.
pub type CilTypeList = Arc<boxcar::Vec<CilTypeRc>>;

/// Reference-counted pointer to a `CilType`.
///
/// Enables efficient sharing of type information across the metadata system
/// while maintaining thread safety for concurrent access scenarios.
pub type CilTypeRc = Arc<CilType>;

/// Maximum number of ancestors [`CilType::base_chain`] will yield before stopping.
///
/// Real inheritance chains are shallow - the deepest in the .NET base class library is well
/// under 20. This bound exists solely to terminate walks over malformed metadata, and is set
/// high enough that no legitimate assembly can reach it. It matches the limit already applied
/// to the virtual-dispatch walks in the emulation engine.
pub const MAX_BASE_WALK_DEPTH: usize = 256;

/// Iterator over a type's inheritance chain, hardened against attacker-supplied cycles.
///
/// Created by [`CilType::base_chain`]; see that method for why walking `base()` by hand is
/// unsafe on untrusted input.
pub struct BaseChain {
    /// Next ancestor to yield, or `None` once the chain is exhausted.
    current: Option<CilTypeRc>,
    /// Tokens already yielded, seeded with the starting type so self-extends terminates.
    visited: HashSet<Token>,
    /// Remaining depth budget.
    remaining: usize,
}

impl Iterator for BaseChain {
    type Item = CilTypeRc;

    fn next(&mut self) -> Option<CilTypeRc> {
        if self.remaining == 0 {
            return None;
        }
        let current = self.current.take()?;
        // A token we have already yielded means the chain closed into a cycle.
        if !self.visited.insert(current.token) {
            return None;
        }
        self.remaining = self.remaining.saturating_sub(1);
        self.current = current.base();
        Some(current)
    }
}

impl std::iter::FusedIterator for BaseChain {}

/// Represents a unified type definition combining information from `TypeDef`, `TypeRef`, and `TypeSpec` tables.
///
/// `CilType` provides a complete representation of a .NET type, merging metadata from multiple
/// tables into a single coherent structure. This eliminates the need to navigate between
/// different metadata tables during type analysis and provides a more convenient API.
///
/// The `token` field indicates the source table:
/// - `TypeDef` tokens for types defined in the current assembly
/// - `TypeRef` tokens for types referenced from other assemblies  
/// - `TypeSpec` tokens for generic instantiations and complex type signatures
/// - Artificial tokens for runtime primitive types
///
/// # Thread Safety
///
/// `CilType` is designed for concurrent access with interior mutability using `OnceLock`
/// for lazily computed fields. Most fields are immutable after construction, while
/// computed properties like `flavor` and `base` are thread-safely cached.
///
/// # Examples
///
/// Basic type information access is available through the type registry.
/// Complex iteration patterns may require understanding the current iterator implementation.
pub struct CilType {
    /// Metadata token identifying this type (`TypeDef`, `TypeRef`, `TypeSpec`, or artificial)
    pub token: Token,
    /// Computed type flavor - lazily determined from context and inheritance chain
    flavor: OnceLock<CilFlavor>,
    /// Type namespace (empty for global types and some special cases like `<Module>`)
    pub namespace: String,
    /// Type name (class name, interface name, etc.)
    pub name: String,
    /// The scope the type belongs to: for a type reference where it resolves (`AssemblyRef`,
    /// `File`, `ModuleRef`, an enclosing `TypeRef`); for a type definition its own assembly.
    /// Set for both, so it does not tell an imported type from a defined one: the token's
    /// table does.
    external: OnceLock<CilTypeReference>,
    /// Base type reference - the type this type inherits from (for classes) or extends (for interfaces)
    base: OnceLock<CilTypeRef>,
    /// Type attributes flags (ECMA-335 §II.23.1.15).
    pub flags: TypeAttributes,
    /// All fields defined in this type
    pub fields: FieldList,
    /// All methods defined in this type (constructors, instance methods, static methods)
    pub methods: MethodRefList,
    /// All properties defined in this type
    pub properties: PropertyList,
    /// All events defined in this type
    pub events: EventList,
    /// All interfaces this type implements (from `InterfaceImpl` table)
    pub interfaces: InterfaceEntryList,
    /// All method overwrites this type implements (explicit interface implementations)
    pub overwrites: RowList<CilTypeReference>,
    /// Nested types contained within this type (inner classes, delegates, etc.)
    pub nested_types: RowList<CilTypeRef>,
    /// Generic parameters for this type definition (e.g., T, U in Class<T, U>)
    pub generic_params: GenericParamList,
    /// Generic arguments for instantiated generic types (actual types substituted for parameters)
    pub generic_args: MethodSpecList,
    /// Custom attributes applied to this type (annotations, decorators)
    pub custom_attributes: CustomAttributeValueList,
    /// Field layout packing size - alignment of fields in memory (from `ClassLayout` table)
    pub packing_size: OnceLock<u16>,
    /// Total size of the class in bytes (from `ClassLayout` table)
    pub class_size: OnceLock<u32>,
    /// `TypeSpec` specifiers providing additional type information for complex types
    pub spec: OnceLock<CilFlavor>,
    /// Type modifiers from `TypeSpec` (required/optional modifiers, pinned types, etc.)
    pub modifiers: Arc<boxcar::Vec<CilModifier>>,
    /// The type's declarative security, a `DeclSecurity` row each, in table order: a type may
    /// demand permissions under several actions (a link demand and an inheritance demand,
    /// say).
    pub security: RowList<Security>,
    /// Enclosing type for nested types - used for reverse lookup to build hierarchical names
    pub enclosing_type: OnceLock<CilTypeRef>,
    /// Cached full name to avoid expensive recomputation.
    fullname: RwLock<Option<Arc<str>>>,
    // vtable
    // security
    // default_constructor: Option<MethodRef>
    // type_initializer: Option<MethodRef>
    // module: ModuleRef
    // assembly: AssemblyRef
    // flags holds a lot of information, split up for better access?
}

impl CilType {
    /// Create a new instance of a `CilType`.
    ///
    /// Creates a new type representation with the provided metadata. Some fields like
    /// `properties`, `events`, `interfaces`, etc. are initialized as empty collections
    /// and can be populated later during metadata loading.
    ///
    /// # Arguments
    /// * `token` - The metadata token for this type
    /// * `namespace` - The namespace of the type (can be empty for global types)
    /// * `name` - The name of the type  
    /// * `external` - External type reference if this is an imported type
    /// * `base` - Base type reference if this type inherits from another (optional)
    /// * `flags` - Type attributes flags from `TypeAttributes`
    /// * `fields` - Fields belonging to this type
    /// * `methods` - Methods belonging to this type
    /// * `flavor` - Optional explicit flavor. If None, flavor will be computed lazily
    ///
    /// # Thread Safety
    ///
    /// The returned `CilType` is safe for concurrent access. Lazily computed fields
    /// like `flavor` and `base` use `OnceLock` for thread-safe initialization.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::{
    ///     method::MethodRefList,
    ///     tables::TypeAttributes,
    ///     typesystem::{CilType, CilFlavor},
    ///     token::Token,
    /// };
    /// use std::sync::Arc;
    ///
    /// let cil_type = CilType::new(
    ///     Token::new(0x02000001), // TypeDef token
    ///     "MyNamespace".to_string(),
    ///     "MyClass".to_string(),
    ///     None, // Not an external type
    ///     None, // No base type specified yet
    ///     TypeAttributes::new(0x00100001), // TypeAttributes flags
    ///     Arc::new(boxcar::Vec::new()), // Empty fields list
    ///     MethodRefList::new(), // Empty methods list, allocated on first push
    ///     Some(CilFlavor::Class), // Explicit class flavor
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: Token,
        namespace: String,
        name: String,
        external: Option<CilTypeReference>,
        base: Option<CilTypeRef>,
        flags: TypeAttributes,
        fields: FieldList,
        methods: MethodRefList,
        flavor: Option<CilFlavor>,
    ) -> Self {
        let base_lock = OnceLock::new();
        if let Some(base_value) = base {
            base_lock.set(base_value).ok();
        }

        let external_lock = OnceLock::new();
        if let Some(external_value) = external {
            external_lock.set(external_value).ok();
        }

        let flavor_lock = OnceLock::new();
        if let Some(explicit_flavor) = flavor {
            flavor_lock.set(explicit_flavor).ok();
        }

        CilType {
            token,
            namespace,
            name,
            external: external_lock,
            base: base_lock,
            flags,
            flavor: flavor_lock,
            fields,
            methods,
            properties: Arc::new(boxcar::Vec::new()),
            events: Arc::new(boxcar::Vec::new()),
            interfaces: Default::default(),
            overwrites: Default::default(),
            nested_types: Default::default(),
            generic_params: Default::default(),
            generic_args: LazyList::new(),
            custom_attributes: Default::default(),
            packing_size: OnceLock::new(),
            class_size: OnceLock::new(),
            spec: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            security: RowList::new(),
            enclosing_type: OnceLock::new(),
            fullname: RwLock::new(None),
        }
    }

    /// Set the base type of this type for inheritance relationships.
    ///
    /// This method allows setting the base type after the `CilType` has been created,
    /// which is useful during metadata loading when type references may not be fully
    /// resolved at construction time.
    ///
    /// # Arguments
    /// * `base_type` - The base type this type inherits from
    ///
    /// # Returns
    /// * `Ok(())` if the base type was set successfully
    /// * `Err(base_type)` if a base type was already set for this type
    ///
    /// # Errors
    ///
    /// This function will return an error if a base type was already set for this type.
    /// The error contains the base type that was attempted to be set.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the base type.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::typesystem::{CilType, CilTypeRef};
    /// use std::sync::{Arc, Weak};
    ///
    /// # fn example(cil_type: &CilType, base_type: Arc<CilType>) {
    /// let base_ref = CilTypeRef::new(&base_type);
    /// match cil_type.set_base(base_ref) {
    ///     Ok(()) => println!("Base type set successfully"),
    ///     Err(_) => println!("Base type was already set"),
    /// }
    /// # }
    /// ```
    pub fn set_base(&self, base_type: &CilTypeRef) -> Result<()> {
        match self.base.set(base_type.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                if let Some(existing) = self.base.get() {
                    match (existing.upgrade(), base_type.upgrade()) {
                        (Some(existing_ref), Some(new_ref)) => {
                            if existing_ref.token == new_ref.token
                                || existing_ref.is_structurally_equivalent(&new_ref)
                            {
                                Ok(())
                            } else {
                                Err(Error::TypeError(
                                    format!("Base type was already set with different value: existing {} vs new {}",
                                           existing_ref.fullname(), new_ref.fullname())
                                ))
                            }
                        }
                        (None, None) => {
                            // Both weak references are dropped - we can't compare
                            // This might be acceptable for deduplication
                            Ok(())
                        }
                        (Some(_existing_ref), None) => {
                            // Existing is valid but new is dropped
                            Ok(())
                        }
                        (None, Some(_new_ref)) => {
                            // The existing weak reference was dropped but the new one is valid.
                            // This is an edge case that could indicate:
                            // 1. The original base type was garbage collected
                            // 2. There's a race condition in type construction
                            //
                            // We accept this case since:
                            // - We can't compare against the dropped reference
                            // - The type system allows base types to be GC'd
                            // - Rejecting would cause false negatives in valid scenarios
                            //
                            // Future: Consider logging this case for debugging if needed
                            Ok(())
                        }
                    }
                } else {
                    // This should be impossible with OnceLock - if set() failed, get() should return Some()
                    Err(Error::TypeError(
                        "Impossible OnceLock state detected".to_string(),
                    ))
                }
            }
        }
    }

    /// Access the base type of this type, if it exists.
    ///
    /// Returns the base type that this type inherits from, if one has been set.
    /// For classes, this is typically another class or `System.Object`. For value types,
    /// this is usually `System.ValueType` or `System.Enum`.
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The base type if one is set and the reference is still valid
    /// * `None` - If no base type is set or the reference has been dropped
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::typesystem::CilType;
    /// # fn example(cil_type: &CilType) {
    /// if let Some(base) = cil_type.base() {
    ///     println!("Base type: {}.{}", base.namespace, base.name);
    /// } else {
    ///     println!("No base type (likely System.Object or interface)");
    /// }
    /// # }
    /// ```
    pub fn base(&self) -> Option<CilTypeRc> {
        if let Some(base) = self.base.get() {
            base.upgrade()
        } else {
            None
        }
    }

    /// Iterates the type's inheritance chain, from the immediate base type towards the root.
    ///
    /// The starting type itself is **not** yielded - the first item is `self.base()`.
    ///
    /// # Why this exists
    ///
    /// [`CilType::base`] is populated directly from the TypeDef `extends` coded index, which is
    /// attacker-controlled. A malformed assembly can describe a type that extends itself, or an
    /// `A -> B -> A` cycle, and such an assembly still loads under
    /// [`ValidationConfig::analysis`](crate::metadata::validation::ValidationConfig::analysis)
    /// because that preset reports circular inheritance as a diagnostic rather than refusing the
    /// file. A hand-written `while let Some(t) = t.base()` loop over such a graph never
    /// terminates, and the recursive equivalent exhausts the native stack - an abort that no
    /// caller can catch and that no emulation budget can interrupt.
    ///
    /// This iterator is the only sanctioned way to walk a base chain. It is bounded twice over:
    /// by a visited set seeded with the starting type's token, so a cycle stops the walk the
    /// first time it closes, and by [`MAX_BASE_WALK_DEPTH`], so even an acyclic-but-absurd chain
    /// terminates. Both bounds end the iteration quietly rather than erroring, matching the
    /// permissive posture the rest of the analysis path takes towards malformed input.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::typesystem::CilType;
    /// # fn example(cil_type: &CilType) {
    /// // Safe against attacker-supplied inheritance cycles.
    /// let derives_from_exception = cil_type
    ///     .base_chain()
    ///     .any(|ancestor| &*ancestor.fullname() == "System.Exception");
    /// # }
    /// ```
    #[must_use]
    pub fn base_chain(&self) -> BaseChain {
        let mut visited = HashSet::new();
        visited.insert(self.token);
        BaseChain {
            current: self.base(),
            visited,
            remaining: MAX_BASE_WALK_DEPTH,
        }
    }

    /// Set the enclosing type for nested types.
    ///
    /// This method allows setting the enclosing type for nested types, establishing the
    /// bidirectional relationship between nested and enclosing types. This is used to
    /// build proper hierarchical names with "/" separators like the .NET runtime.
    ///
    /// # Arguments
    /// * `enclosing_type` - The enclosing type that contains this nested type
    ///
    /// # Returns
    /// * `Ok(())` if the enclosing type was set successfully or an equivalent type was already set
    /// * `Err(_)` if a different enclosing type was already set for this type
    ///
    /// # Errors
    /// Returns an error if an enclosing type was already set with a different value.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the enclosing type; subsequent calls with the
    /// same or equivalent enclosing type will succeed, while calls with a different
    /// enclosing type will return an error.
    pub fn set_enclosing_type(&self, enclosing_type: &CilTypeRef) -> Result<()> {
        match self.enclosing_type.set(enclosing_type.clone()) {
            Ok(()) => {
                // Invalidate the cached fullname so it will be recomputed
                // with the enclosing type prefix on next access.
                if let Ok(mut guard) = self.fullname.write() {
                    *guard = None;
                }
                Ok(())
            }
            Err(_) => {
                // Check if the existing enclosing type is equivalent
                if let Some(existing) = self.enclosing_type.get() {
                    match (existing.upgrade(), enclosing_type.upgrade()) {
                        (Some(existing_ref), Some(new_ref)) => {
                            if existing_ref.token == new_ref.token
                                || existing_ref.is_structurally_equivalent(&new_ref)
                            {
                                Ok(())
                            } else {
                                Err(Error::TypeError(format!(
                                    "Enclosing type was already set with different value: existing {} vs new {}",
                                    existing_ref.fullname(),
                                    new_ref.fullname()
                                )))
                            }
                        }
                        // Any combination where at least one is dropped - accept
                        // since we can't compare or keep existing
                        (None | Some(_), None) | (None, Some(_)) => Ok(()),
                    }
                } else {
                    // This should be impossible with OnceLock
                    Err(Error::TypeError(
                        "Impossible OnceLock state detected in set_enclosing_type".to_string(),
                    ))
                }
            }
        }
    }

    /// Access the enclosing type for nested types, if it exists.
    ///
    /// Returns the enclosing type that contains this nested type, if one has been set.
    /// This is used to traverse up the type hierarchy for building hierarchical names.
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The enclosing type if one is set and the reference is still valid
    /// * `None` - If this is not a nested type or the reference has been dropped
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently.
    pub fn enclosing_type(&self) -> Option<CilTypeRc> {
        if let Some(enclosing) = self.enclosing_type.get() {
            enclosing.upgrade()
        } else {
            None
        }
    }

    /// Sets the external type reference for this type.
    ///
    /// This method sets the external reference that indicates where this type is defined
    /// (e.g., which assembly, module, or file). This is primarily used for TypeRef entries
    /// that reference types defined outside the current assembly.
    ///
    /// ## Arguments
    /// * `external_ref` - The external type reference indicating where this type is defined
    ///
    /// ## Returns
    /// * `Ok(())` - External reference set successfully
    /// * `Err(_)` - External reference was already set or other error occurred
    ///
    /// # Errors
    ///
    /// Returns an error if the external reference was already set.
    ///
    /// ## Thread Safety
    /// This method is thread-safe and can be called concurrently. Only the first
    /// call will succeed in setting the external reference.
    pub fn set_external(&self, external_ref: &CilTypeReference) -> Result<()> {
        match self.external.set(external_ref.clone()) {
            Ok(()) => Ok(()),
            Err(_) => {
                if let Some(existing) = self.external.get() {
                    if Self::external_refs_compatible(existing, external_ref) {
                        Ok(())
                    } else {
                        Err(malformed_error!(
                            "External reference was already set with different value"
                        ))
                    }
                } else {
                    Err(malformed_error!("External reference was already set"))
                }
            }
        }
    }

    /// Check if two external references are compatible (for deduplication)
    fn external_refs_compatible(existing: &CilTypeReference, new: &CilTypeReference) -> bool {
        match (existing, new) {
            (CilTypeReference::AssemblyRef(ar1), CilTypeReference::AssemblyRef(ar2)) => {
                ar1.token == ar2.token
            }
            (CilTypeReference::ModuleRef(mr1), CilTypeReference::ModuleRef(mr2)) => {
                mr1.token == mr2.token
            }
            (CilTypeReference::File(f1), CilTypeReference::File(f2)) => f1.token == f2.token,
            // For deduplicated types, allow any external reference combination
            // since they should be structurally equivalent
            _ => true,
        }
    }

    /// The scope this type belongs to.
    ///
    /// For a type reference, where it resolves (`AssemblyRef`, `File`, `ModuleRef`, or the
    /// `TypeRef` enclosing a nested reference); for a type definition, the assembly that
    /// defines it, when the module has an Assembly row. It is therefore set for defined
    /// types too and does not tell an imported type from a defined one: the token's table
    /// does (`TypeDef` defines, `TypeRef` imports).
    ///
    /// ## Returns
    /// The scope, or `None` when none was recorded (a netmodule's type definitions, or a
    /// reference whose scope is still pending resolution).
    pub fn external(&self) -> Option<&CilTypeReference> {
        self.external.get()
    }

    /// Get the computed type flavor - determined lazily from context.
    ///
    /// The flavor represents the fundamental nature of the type (class, interface,
    /// value type, etc.) and is computed from type attributes, inheritance relationships,
    /// and naming patterns. The result is cached for performance.
    ///
    /// # Returns
    /// A reference to the computed `CilFlavor` for this type
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. The flavor is computed once and cached using
    /// `OnceLock` for subsequent calls.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{CilType, CilFlavor};
    ///
    /// # fn example(cil_type: &CilType) {
    /// match cil_type.flavor() {
    ///     CilFlavor::Class => println!("Reference type class"),
    ///     CilFlavor::ValueType => println!("Value type (struct/enum)"),
    ///     CilFlavor::Interface => println!("Interface definition"),
    ///     _ => println!("Other type flavor"),
    /// }
    /// # }
    /// ```
    pub fn flavor(&self) -> &CilFlavor {
        self.flavor.get_or_init(|| self.compute_flavor())
    }

    /// Records that this type is a value type, from a fact its own flavor
    /// computation cannot see yet.
    ///
    /// A type referenced from another assembly has no definition here to
    /// compute its kind from, and the heuristics then take it for a class:
    /// `System.DateTime`, `System.RuntimeTypeHandle` and every other imported
    /// struct would read as reference types. The signatures that use the type
    /// are required to say which it is. A type defined here derives from
    /// `System.ValueType` or `System.Enum` directly, as ECMA-335 requires, but
    /// its base is linked only after loaders that may already ask for its
    /// flavor have run, and a flavor computed then is a class forever. A
    /// primitive keeps its own flavor. Has no effect once the flavor has been
    /// computed.
    pub(crate) fn mark_value_type(&self) {
        let computed = self.compute_flavor();
        let flavor = if computed.is_value_type() {
            computed
        } else {
            CilFlavor::ValueType
        };
        let _ = self.flavor.set(flavor);
    }

    /// Compute the type flavor based on flags, inheritance chain, and intelligent heuristics.
    ///
    /// This method implements the core type classification logic, determining whether a type
    /// is a class, interface, value type, enum, delegate, etc. The classification follows
    /// these rules in priority order:
    ///
    /// 1. **ECMA-335 Interface flag** - Types with the Interface attribute are always interfaces
    /// 2. **System primitive types** - Well-known System namespace types get direct classification
    /// 3. **Inheritance chain analysis** - Types inheriting from ValueType, Enum, etc.
    /// 4. **Attribute-based heuristics** - Layout flags, sealed/abstract combinations, for a
    ///    type with no definition here (a defined type's base decides, ECMA-335 II.13)
    /// 5. **Default** - Unclassified types default to Class
    ///
    /// # Returns
    /// The computed `CilFlavor` representing this type's classification.
    fn compute_flavor(&self) -> CilFlavor {
        // 1. ECMA-335 definitive classification - Interface flag takes precedence
        if self.flags.is_interface() {
            return CilFlavor::Interface;
        }

        // 2. System primitive types (exact namespace/name matching)
        // Return specific CilFlavor for primitives to enable proper element sizing
        if self.namespace == "System" {
            match self.name.as_str() {
                // Primitive types with specific flavors
                "Boolean" => return CilFlavor::Boolean,
                "Char" => return CilFlavor::Char,
                "SByte" => return CilFlavor::I1,
                "Byte" => return CilFlavor::U1,
                "Int16" => return CilFlavor::I2,
                "UInt16" => return CilFlavor::U2,
                "Int32" => return CilFlavor::I4,
                "UInt32" => return CilFlavor::U4,
                "Int64" => return CilFlavor::I8,
                "UInt64" => return CilFlavor::U8,
                "Single" => return CilFlavor::R4,
                "Double" => return CilFlavor::R8,
                "IntPtr" => return CilFlavor::I,
                "UIntPtr" => return CilFlavor::U,
                // Decimal is a special value type (not a primitive flavor)
                "Decimal" => return CilFlavor::ValueType,
                // The bases of value types are classes themselves (ECMA-335 II.13): a
                // `System.Enum` or `System.ValueType` is a reference to a boxed value
                "ValueType" | "Enum" => return CilFlavor::Class,
                // Well-known reference types
                "Object" => return CilFlavor::Object,
                "String" => return CilFlavor::String,
                "Void" => return CilFlavor::Void,
                // Delegate types are classes with special semantics
                "Delegate" | "MulticastDelegate" => return CilFlavor::Class,
                _ => {}
            }
        }

        // 3. Enhanced inheritance chain analysis
        if let Some(inherited_flavor) = self.classify_by_inheritance() {
            return inherited_flavor;
        }

        // 4. Attribute-based guesses, for a type with no definition here to decide from. A
        // type defined here is a value type exactly when it extends System.ValueType or
        // System.Enum (ECMA-335 II.13), which its loader records before anything can ask
        // (`mark_value_type`); guessing from its flags would make a sealed class with
        // sequential layout, common in interop code, a value type whenever its base is not
        // linked yet.
        if !self.token.is_table(TableId::TypeDef) {
            if let Some(attribute_flavor) = self.classify_by_attributes() {
                return attribute_flavor;
            }
        }

        // 5. Default classification for reference types
        CilFlavor::Class
    }

    /// Classify type by analyzing its immediate inheritance chain.
    ///
    /// Examines the direct base type and performs limited traversal to identify
    /// well-known .NET framework types that determine classification. Uses cached
    /// flavor values when available to avoid infinite recursion.
    ///
    /// # Returns
    /// * `Some(CilFlavor::ValueType)` - If the type inherits from System.ValueType or System.Enum
    /// * `Some(CilFlavor::Class)` - If the type inherits from System.Delegate or has an interface base
    /// * `None` - If classification cannot be determined from inheritance
    fn classify_by_inheritance(&self) -> Option<CilFlavor> {
        if let Some(base_type) = self.base() {
            let base_fullname = base_type.fullname();

            // Direct well-known base types
            if &*base_fullname == wellknown::names::VALUE_TYPE
                || &*base_fullname == wellknown::names::ENUM
            {
                return Some(CilFlavor::ValueType);
            }

            if &*base_fullname == wellknown::names::DELEGATE
                || &*base_fullname == wellknown::names::MULTICAST_DELEGATE
            {
                return Some(CilFlavor::Class); // Delegates are reference types but special classes
            }

            // Traverse inheritance chain more intelligently
            if base_type.fullname() != self.fullname() {
                // Check if base type already has computed flavor
                if let Some(base_flavor) = base_type.flavor.get() {
                    match base_flavor {
                        CilFlavor::ValueType => return Some(CilFlavor::ValueType),
                        CilFlavor::Interface => {
                            // This shouldn't happen (can't inherit from interface)
                            // but if it does, this type is a class
                            return Some(CilFlavor::Class);
                        }
                        _ => {}
                    }
                } else {
                    // Base type flavor not computed yet - use transitive inheritance analysis
                    if let Some(transitive_flavor) =
                        Self::analyze_transitive_inheritance(&base_type)
                    {
                        return Some(transitive_flavor);
                    }
                }
            }
        }
        None
    }

    /// Analyze inheritance chain transitively without forcing computation.
    ///
    /// Traverses up the inheritance hierarchy looking for well-known system types
    /// like `System.ValueType`, `System.Enum`, `System.Delegate`, etc. to determine
    /// the correct type flavor without recursively computing flavors (which could
    /// cause infinite recursion).
    ///
    /// # Arguments
    /// * `base_type` - The base type to start analysis from
    ///
    /// # Returns
    /// * `Some(CilFlavor)` - If a definitive classification is found in the inheritance chain
    /// * `None` - If no classification can be determined from the chain
    fn analyze_transitive_inheritance(base_type: &CilType) -> Option<CilFlavor> {
        /// Maximum depth to traverse in the inheritance chain.
        ///
        /// This limit prevents infinite loops in case of circular inheritance
        /// (which shouldn't occur in valid assemblies but could in malformed ones).
        /// The value of 10 is chosen because:
        /// - Most .NET type hierarchies are shallow (< 5 levels)
        /// - Deep hierarchies beyond 10 levels are extremely rare
        /// - The limit ensures bounded performance even with malformed input
        const MAX_INHERITANCE_DEPTH: usize = 10;

        // Look up the inheritance chain without computing flavors (avoid infinite recursion)
        let mut current = base_type.base();
        let mut depth: usize = 0;

        while let Some(ancestor) = current {
            depth = depth.saturating_add(1);
            if depth > MAX_INHERITANCE_DEPTH {
                break;
            }

            let ancestor_name = ancestor.fullname();

            // Check for well-known ancestor types
            if &*ancestor_name == wellknown::names::VALUE_TYPE
                || &*ancestor_name == wellknown::names::ENUM
            {
                return Some(CilFlavor::ValueType);
            }

            if &*ancestor_name == wellknown::names::DELEGATE
                || &*ancestor_name == wellknown::names::MULTICAST_DELEGATE
            {
                return Some(CilFlavor::Class);
            }

            if &*ancestor_name == wellknown::names::OBJECT {
                // Reached the root - this is a reference type class
                return Some(CilFlavor::Class);
            }

            // Continue up the chain
            current = ancestor.base();
        }

        None
    }

    /// Classify type using TypeAttributes flags and pattern-based heuristics.
    ///
    /// When inheritance analysis doesn't provide a definitive classification, this method
    /// uses type attributes and structural characteristics to infer the type category.
    /// This is particularly useful for types where base type information is unavailable.
    ///
    /// # Classification Heuristics
    /// - Sealed types with no methods but with fields → likely ValueType
    /// - Sequential/Explicit layout + sealed + not abstract → likely ValueType
    /// - Abstract + not sealed → Class
    /// - Has enum characteristics (single `value__` field) → ValueType
    /// - Has delegate characteristics (Invoke/BeginInvoke/EndInvoke) → Class
    ///
    /// # Returns
    /// * `Some(CilFlavor)` - If a heuristic matches
    /// * `None` - If no heuristic applies
    fn classify_by_attributes(&self) -> Option<CilFlavor> {
        // ECMA-335 attribute-based classification

        // Sealed + Abstract is impossible, but if both are set, interface wins
        let is_sealed = self.flags.is_sealed();
        let is_abstract = self.flags.is_abstract();

        // Value type indicators:
        // 1. Sealed with no methods often indicates value type (struct/enum)
        if is_sealed && !is_abstract && self.methods.is_empty() && !self.fields.is_empty() {
            return Some(CilFlavor::ValueType);
        }

        // 2. Types with sequential or explicit layout are often value types
        let layout = self.flags.layout();
        if (layout == TypeAttributes::SEQUENTIAL_LAYOUT
            || layout == TypeAttributes::EXPLICIT_LAYOUT)
            && is_sealed
            && !is_abstract
        {
            return Some(CilFlavor::ValueType);
        }

        // 3. Abstract classes that aren't sealed
        if is_abstract && !is_sealed {
            return Some(CilFlavor::Class);
        }

        // 4. Check for enum-like characteristics
        if self.has_enum_characteristics() {
            return Some(CilFlavor::ValueType);
        }

        // 5. Check for delegate-like characteristics
        if self.has_delegate_characteristics() {
            return Some(CilFlavor::Class);
        }

        None
    }

    /// Check if this type exhibits characteristics typical of .NET enumerations.
    ///
    /// Enums in .NET have a specific structural pattern:
    /// - They are sealed (cannot be inherited)
    /// - They have exactly one instance field named `value__` (the underlying value)
    /// - They may have static fields representing the enum values
    ///
    /// This heuristic identifies enums even when base type information is unavailable.
    ///
    /// # Returns
    /// `true` if the type matches the enum pattern, `false` otherwise.
    fn has_enum_characteristics(&self) -> bool {
        // Enums typically:
        // 1. Are sealed
        // 2. Have a single instance field named "value__"
        // 3. May have static fields for enum values

        if !self.flags.is_sealed() {
            return false;
        }

        let instance_fields = self
            .fields
            .iter()
            .filter(|(_, field)| !field.flags.is_static())
            .count();

        let has_value_field = self
            .fields
            .iter()
            .any(|(_, field)| field.name == "value__" && !field.flags.is_static());

        // Classic enum pattern: single instance field named "value__"
        instance_fields == 1 && has_value_field
    }

    /// Check if this type exhibits characteristics typical of .NET delegates.
    ///
    /// Delegates in .NET are sealed classes with a specific method signature pattern:
    /// - They have an `Invoke` method (synchronous invocation)
    /// - They have `BeginInvoke` and `EndInvoke` methods (asynchronous invocation)
    ///
    /// This heuristic identifies delegates even when base type information is unavailable.
    ///
    /// # Returns
    /// `true` if the type matches the delegate pattern, `false` otherwise.
    fn has_delegate_characteristics(&self) -> bool {
        // Delegates typically:
        // 1. Are sealed classes
        // 2. Have Invoke, BeginInvoke, EndInvoke methods
        // 3. Have specific constructor signatures

        if !self.flags.is_sealed() {
            return false;
        }

        let has_invoke = self.find_method("Invoke").is_some();
        let has_async_methods =
            self.find_method("BeginInvoke").is_some() || self.find_method("EndInvoke").is_some();

        has_invoke && has_async_methods
    }

    /// Returns true if this type is publicly visible.
    ///
    /// A type is considered public if it has `Public` visibility (for top-level types)
    /// or `NestedPublic` visibility (for nested types).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// if cil_type.is_public() {
    ///     println!("Type {} is publicly accessible", cil_type.name);
    /// }
    /// ```
    pub fn is_public(&self) -> bool {
        self.flags.is_public()
    }

    /// Returns true if this type has internal/assembly-only visibility.
    ///
    /// Returns true for:
    /// - Top-level types with `NotPublic` visibility (internal to assembly)
    /// - Nested types with `NestedAssembly` visibility
    pub fn is_internal(&self) -> bool {
        let vis = self.flags.visibility();
        vis == TypeAttributes::NOT_PUBLIC || vis == TypeAttributes::NESTED_ASSEMBLY
    }

    /// Returns true if this type is an interface.
    ///
    /// Checks if the type's flavor is `CilFlavor::Interface`.
    #[must_use]
    pub fn is_interface(&self) -> bool {
        matches!(self.flavor(), CilFlavor::Interface)
    }

    /// Returns true if this type is a class.
    ///
    /// Checks if the type's flavor is `CilFlavor::Class`.
    #[must_use]
    pub fn is_class(&self) -> bool {
        matches!(self.flavor(), CilFlavor::Class)
    }

    /// Returns true if this type is a value type (struct, enum, or primitive value type).
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        self.flavor().is_value_type()
    }

    /// Returns true if this type is sealed (cannot be inherited from).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.flags.is_sealed()
    }

    /// Returns true if this type is abstract (cannot be instantiated directly).
    #[must_use]
    pub fn is_abstract(&self) -> bool {
        self.flags.is_abstract()
    }

    /// Returns true if this type is an enum (inherits from `System.Enum`).
    #[must_use]
    pub fn is_enum(&self) -> bool {
        self.base()
            .is_some_and(|b| &*b.fullname() == wellknown::names::ENUM)
    }

    /// Returns true if this type is a delegate (inherits from `System.Delegate` or `System.MulticastDelegate`).
    #[must_use]
    pub fn is_delegate(&self) -> bool {
        self.base().is_some_and(|b| {
            let name = b.fullname();
            &*name == wellknown::names::MULTICAST_DELEGATE || &*name == wellknown::names::DELEGATE
        })
    }

    /// Returns a composable query over methods defined in this type.
    ///
    /// This handles the weak-ref upgrade boilerplate automatically,
    /// replacing the common pattern:
    /// ```no_run
    /// for (_, method_ref) in type_info.methods.iter() {
    ///     if let Some(method) = method_ref.upgrade() { ... }
    /// }
    /// ```
    pub fn query_methods(&self) -> MethodQuery<'_> {
        MethodQuery::from_type(&self.methods)
    }

    /// Returns a composable query over fields defined in this type.
    ///
    /// This provides a fluent API mirroring [`query_methods()`](Self::query_methods):
    /// ```no_run
    /// let static_fields = type_info.query_fields().static_fields().find_all();
    /// let value_field = type_info.query_fields().instance_fields().name("value__").find_first();
    /// ```
    pub fn query_fields(&self) -> FieldQuery<'_> {
        FieldQuery::from_type(&self.fields)
    }

    /// Returns the `.cctor` (class constructor / type initializer) token, if present.
    #[must_use]
    pub fn cctor(&self) -> Option<Token> {
        self.query_methods()
            .static_constructors()
            .find_first()
            .map(|m| m.token)
    }

    /// Returns the first `.ctor` (instance constructor) token, if present.
    #[must_use]
    pub fn ctor(&self) -> Option<Token> {
        self.query_methods()
            .constructors()
            .find_first()
            .map(|m| m.token)
    }

    /// Returns true if this is the global `<Module>` type.
    #[must_use]
    pub fn is_module_type(&self) -> bool {
        self.name == wellknown::members::MODULE_TYPE
    }

    /// Returns an iterator over all methods defined in this type.
    ///
    /// Automatically upgrades weak references, skipping any that have been dropped.
    pub fn methods(&self) -> impl Iterator<Item = MethodRc> + '_ {
        self.methods
            .iter()
            .filter_map(|(_, method_ref)| method_ref.upgrade())
    }

    /// Returns an iterator over all fields defined in this type.
    ///
    /// Returns references to the field entries in the field list.
    pub fn fields(&self) -> impl Iterator<Item = &FieldRc> + '_ {
        self.fields.iter().map(|(_, field)| field)
    }

    /// Returns true if this is a nested type with private or internal visibility.
    ///
    /// This includes:
    /// - `NestedPrivate` - Only accessible within the declaring type
    /// - `NestedAssembly` - Only accessible within the same assembly
    /// - `NestedFamANDAssem` - Only accessible to derived types within the same assembly
    ///
    /// Useful for detecting obfuscation infrastructure types that are intentionally hidden.
    pub fn is_nested_internal(&self) -> bool {
        let vis = self.flags.visibility();
        vis == TypeAttributes::NESTED_PRIVATE
            || vis == TypeAttributes::NESTED_ASSEMBLY
            || vis == TypeAttributes::NESTED_FAM_AND_ASSEM
    }

    /// Returns true if any method in this type has public access.
    ///
    /// Iterates through all methods declared by this type and checks if any
    /// have `Public` accessibility.
    pub fn has_public_methods(&self) -> bool {
        self.methods
            .iter()
            .any(|(_, method_ref)| method_ref.upgrade().is_some_and(|m| m.is_public()))
    }

    /// Returns true if any field in this type has public access.
    ///
    /// Iterates through all fields declared by this type and checks if any
    /// have `Public` accessibility (flag value 0x06).
    pub fn has_public_fields(&self) -> bool {
        self.fields
            .iter()
            .any(|(_, field)| field.flags.access() == FieldAttributes::PUBLIC)
    }

    /// Finds the first method with the given name declared by this type.
    ///
    /// Searches through the type's method list, upgrading weak references
    /// and comparing names. Returns `None` if no method matches or if
    /// all matching weak references have been dropped.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<MethodRc> {
        self.methods
            .iter()
            .find_map(|(_, method_ref)| method_ref.upgrade().filter(|m| m.name == name))
    }

    /// Finds all methods with the given name declared by this type.
    ///
    /// Returns all matching methods, useful for finding overloaded methods.
    #[must_use]
    pub fn find_methods(&self, name: &str) -> Vec<MethodRc> {
        self.methods
            .iter()
            .filter_map(|(_, method_ref)| method_ref.upgrade().filter(|m| m.name == name))
            .collect()
    }

    /// Returns the full name (Namespace.Name) of the type.
    ///
    /// Combines the namespace and name to create a fully qualified type name,
    /// which is useful for type lookup and identification. For nested types,
    /// uses "/" separators as per .NET runtime convention.
    ///
    /// # Returns
    /// A string containing the full name in the format:
    /// - `"Namespace.Name"` for top-level types
    /// - `"Namespace.Outer/Inner"` for nested types
    ///
    /// # Caching
    /// The result is cached after first computation for performance.
    pub fn fullname(&self) -> Arc<str> {
        if let Ok(guard) = self.fullname.read() {
            if let Some(cached) = guard.as_ref() {
                return Arc::clone(cached);
            }
        }

        let fullname: Arc<str> = Arc::from(self.compute_fullname());
        if let Ok(mut guard) = self.fullname.write() {
            *guard = Some(Arc::clone(&fullname));
        }
        fullname
    }

    /// Computes the full name by traversing the enclosing type hierarchy.
    ///
    /// This is the core implementation separated from caching logic for clarity.
    fn compute_fullname(&self) -> String {
        let (path_components, outermost_namespace) = self.collect_type_path();

        if path_components.len() > 1 {
            // This is a nested type - use "/" separators like .NET runtime.
            // The namespace comes from the outermost enclosing type, not self,
            // because nested types in ECMA-335 typically have an empty namespace field.
            let nested_path = path_components.join("/");
            if outermost_namespace.is_empty() {
                nested_path
            } else {
                format!("{outermost_namespace}.{nested_path}")
            }
        } else {
            // This is a top-level type - use traditional "." separator
            self.format_toplevel_fullname()
        }
    }

    /// Collects the type path from innermost (self) to outermost enclosing type.
    ///
    /// Returns the path components in outermost-to-innermost order and the
    /// outermost enclosing type's namespace (which is the namespace that applies
    /// to the entire nested type chain in ECMA-335 metadata).
    fn collect_type_path(&self) -> (Vec<String>, String) {
        let mut path_components = Vec::new();

        path_components.push(self.safe_type_name());

        let mut outermost_namespace = self.namespace.clone();
        let mut visited_tokens = HashSet::new();
        visited_tokens.insert(self.token);

        let mut current_type = self.enclosing_type();
        while let Some(enclosing) = current_type {
            if visited_tokens.contains(&enclosing.token) {
                break; // Cycle detected
            }
            visited_tokens.insert(enclosing.token);

            outermost_namespace = enclosing.namespace.clone();
            path_components.push(Self::safe_name_for(&enclosing.name, enclosing.token));
            current_type = enclosing.enclosing_type();
        }

        // Reverse to get outermost-to-innermost order
        path_components.reverse();
        (path_components, outermost_namespace)
    }

    /// Returns a safe type name, using a placeholder for empty names.
    fn safe_type_name(&self) -> String {
        Self::safe_name_for(&self.name, self.token)
    }

    /// Returns a safe name string, using a token-based placeholder if empty.
    fn safe_name_for(name: &str, token: Token) -> String {
        if name.is_empty() {
            format!("<unnamed_{:08X}>", token.value())
        } else {
            name.to_string()
        }
    }

    /// Formats the full name for a top-level type using "." separator.
    fn format_toplevel_fullname(&self) -> String {
        let type_name = self.safe_type_name();
        if self.namespace.is_empty() {
            type_name
        } else {
            format!("{}.{}", self.namespace, type_name)
        }
    }

    /// Checks if this type was created from a TypeRef table entry.
    ///
    /// Returns `true` if this type's token indicates it originated from a TypeRef table,
    /// meaning it references a type defined in an external assembly. This is essential
    /// for TypeRef to TypeDef resolution during multi-assembly loading.
    ///
    /// # Returns
    /// * `true` - If the type's token has table ID 0x01 (TypeRef)
    /// * `false` - If the type came from TypeDef (0x02), TypeSpec (0x1B), or other sources
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::CilType;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(type_def: &CilType) {
    /// if type_def.is_typeref() {
    ///     println!("Type {} needs TypeRef resolution", type_def.fullname());
    /// }
    /// # }
    /// ```
    pub fn is_typeref(&self) -> bool {
        self.token.is_table(TableId::TypeRef)
    }

    /// Check if this type is compatible with (assignable to) another type
    ///
    /// This implements .NET type compatibility rules including:
    /// - Exact type matching
    /// - Inheritance compatibility  
    /// - Interface implementation
    /// - Primitive type widening
    /// - Reference type to System.Object
    ///
    /// # Arguments
    /// * `target` - The target type to check compatibility against
    ///
    /// # Returns
    /// `true` if this type can be assigned to the target type
    pub fn is_compatible_with(&self, target: &CilType) -> bool {
        if self.token == target.token {
            return true;
        }

        if self.namespace == target.namespace && self.name == target.name {
            return true;
        }

        self.is_assignable_to(target)
    }

    /// Check if this type is assignable to the target type according to .NET rules
    fn is_assignable_to(&self, target: &CilType) -> bool {
        if self.flavor().is_primitive() && target.flavor().is_primitive() {
            return self.flavor().is_compatible_with(target.flavor());
        }

        // Generic type parameters are compatible with any type since we don't have
        // runtime type substitution. This allows operations like unbox/castclass
        // to succeed when the target is a generic method parameter (TM0, TM1, etc.)
        if matches!(target.flavor(), CilFlavor::GenericParameter { .. })
            || matches!(self.flavor(), CilFlavor::GenericParameter { .. })
        {
            return true;
        }

        // Handle System.Object (can accept any reference type)
        if target.namespace == "System"
            && target.name == "Object"
            && self.flavor().is_reference_type()
        {
            return true;
        }

        // Handle inheritance compatibility
        if self.is_subtype_of(target) {
            return true;
        }

        // Handle interface implementation
        if target.is_interface() && self.implements_interface(target) {
            return true;
        }

        false
    }

    /// Check if this type is a subtype of (inherits from) the target type
    ///
    /// Walks via [`CilType::base_chain`], so a cyclic `extends` graph terminates the search
    /// instead of spinning forever.
    fn is_subtype_of(&self, target: &CilType) -> bool {
        self.base_chain().any(|base_type| {
            base_type.token == target.token
                || (base_type.namespace == target.namespace && base_type.name == target.name)
        })
    }

    /// Check if this type implements the specified interface
    ///
    /// Walks via [`CilType::base_chain`] rather than recursing, so a cyclic `extends` graph
    /// terminates the search instead of exhausting the native stack.
    fn implements_interface(&self, interface: &CilType) -> bool {
        fn declares(candidate: &CilType, interface: &CilType) -> bool {
            candidate.interfaces.iter().any(|(_, entry)| {
                entry.interface.upgrade().is_some_and(|impl_type| {
                    impl_type.token == interface.token
                        || (impl_type.namespace == interface.namespace
                            && impl_type.name == interface.name)
                })
            })
        }

        declares(self, interface)
            || self
                .base_chain()
                .any(|base_type| declares(&base_type, interface))
    }

    /// Check if a constant value is compatible with this type
    ///
    /// # Arguments  
    /// * `constant` - The constant primitive value to check
    ///
    /// # Returns
    /// `true` if the constant can be assigned to this type
    pub fn accepts_constant(&self, constant: &CilPrimitive) -> bool {
        let constant_flavor = constant.to_flavor();
        self.flavor().accepts_constant(&constant_flavor)
    }

    /// Performs deep structural comparison with another type for deduplication purposes
    ///
    /// This method compares all structural aspects of types to determine true equivalence,
    /// including generic arguments, base types, and source information. This is the
    /// authoritative method for determining if two types are semantically identical.
    ///
    /// ## Arguments
    /// * `other` - The other type to compare with
    ///
    /// ## Returns
    /// `true` if the types are structurally equivalent and can be deduplicated
    pub fn is_structurally_equivalent(&self, other: &CilType) -> bool {
        if self.namespace != other.namespace
            || self.name != other.name
            || *self.flavor() != *other.flavor()
        {
            return false;
        }

        if self.token != other.token {
            return false;
        }

        if !self.external_sources_equivalent(other) {
            return false;
        }

        if !self.generic_args_equivalent(other) {
            return false;
        }

        if !self.generic_params_equivalent(other) {
            return false;
        }

        self.base_types_equivalent(other)
    }

    /// Compare external source references for equivalence.
    ///
    /// Determines if two types originate from the same assembly by comparing their
    /// external source references (AssemblyRef, ModuleRef, File, etc.).
    ///
    /// # Returns
    ///
    /// - `true` if types are from the same assembly or indeterminate (conservative)
    /// - `false` if types are definitively from different assemblies
    ///
    /// # Examples
    ///
    /// Types from the same assembly will return `true`, while types from different
    /// assemblies (different AssemblyRef) will return `false`.
    pub fn external_sources_equivalent(&self, other: &CilType) -> bool {
        match (self.external.get(), other.external.get()) {
            // Both types have external references - compare them
            (Some(ext1), Some(ext2)) => Self::type_sources_equivalent(ext1, ext2),
            // Both are current module types (no external reference) - same assembly
            (None, None) => true,
            // One external, one local - different assemblies (TypeRef redirection case)
            _ => false,
        }
    }

    /// Compare type sources for equivalence
    fn type_sources_equivalent(source1: &CilTypeReference, source2: &CilTypeReference) -> bool {
        match (source1, source2) {
            (CilTypeReference::AssemblyRef(ar1), CilTypeReference::AssemblyRef(ar2)) => {
                if ar1.token == ar2.token {
                    return true;
                }

                // For cross-assembly type resolution, only consider assemblies equivalent
                // if they have identical name and strong name identity (be more conservative)
                // This prevents type conflicts while still allowing cross-assembly resolution
                ar1.name == ar2.name
                    && ar1.identifier == ar2.identifier
                    && ar1.major_version == ar2.major_version
                    && ar1.minor_version == ar2.minor_version
                    && ar1.build_number == ar2.build_number
                    && ar1.revision_number == ar2.revision_number
                    && ar1.culture == ar2.culture
            }
            (CilTypeReference::ModuleRef(mr1), CilTypeReference::ModuleRef(mr2)) => {
                mr1.token == mr2.token
            }
            (CilTypeReference::File(f1), CilTypeReference::File(f2)) => f1.token == f2.token,
            (CilTypeReference::None, CilTypeReference::None) => true,
            _ => false,
        }
    }

    /// Compare generic arguments for equivalence.
    ///
    /// Two types have equivalent generic arguments if they have the same number
    /// of arguments and each corresponding argument has the same token. This
    /// comparison is token-based for efficiency.
    fn generic_args_equivalent(&self, other: &CilType) -> bool {
        let count = self.generic_args.count();
        if count != other.generic_args.count() {
            return false;
        }

        (0..count).all(
            |i| match (self.generic_args.get(i), other.generic_args.get(i)) {
                (Some(a1), Some(a2)) => Self::method_specs_equivalent(a1, a2),
                (None, None) => true,
                _ => false,
            },
        )
    }

    /// Compare two MethodSpec entries for generic argument equivalence.
    ///
    /// MethodSpecs are equivalent if they have the same number of inner generic
    /// arguments and all corresponding inner arguments have matching tokens.
    fn method_specs_equivalent(spec1: &MethodSpec, spec2: &MethodSpec) -> bool {
        let inner_count = spec1.generic_args.count();
        if inner_count != spec2.generic_args.count() {
            return false;
        }

        (0..inner_count).all(
            |j| match (spec1.generic_args.get(j), spec2.generic_args.get(j)) {
                (Some(i1), Some(i2)) => i1.token() == i2.token(),
                (None, None) => true,
                _ => false,
            },
        )
    }

    /// Compare generic parameters for equivalence.
    ///
    /// Two types have equivalent generic parameters if they have the same number
    /// of parameters and each corresponding parameter has the same name and number.
    fn generic_params_equivalent(&self, other: &CilType) -> bool {
        if self.generic_params.count() != other.generic_params.count() {
            return false;
        }

        self.generic_params
            .iter()
            .zip(other.generic_params.iter())
            .all(|((_, p1), (_, p2))| p1.name == p2.name && p1.number == p2.number)
    }

    /// Compare base types for equivalence
    fn base_types_equivalent(&self, other: &CilType) -> bool {
        match (self.base.get(), other.base.get()) {
            (Some(base1), Some(base2)) => {
                // Compare base types structurally, not just tokens
                match (base1.upgrade(), base2.upgrade()) {
                    (Some(b1), Some(b2)) => {
                        if b1.token == b2.token {
                            true
                        } else {
                            b1.is_structurally_equivalent(&b2)
                        }
                    }
                    (None, None) => true, // Both have weak refs that are dropped
                    _ => false,           // One valid, one dropped
                }
            }
            (None, None) => true, // Both have no base type
            _ => false,           // One has base, one doesn't
        }
    }

    /// Check if this type has an array relationship with the given base type.
    ///
    /// Returns true if this type is an array type (ends with "[]") and the base type
    /// matches the array's element type. This handles nested types correctly by
    /// checking both direct name matches and nested type patterns.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential base type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If this type is an array of the specified base type
    /// * `false` - If this is not an array type, the base name is empty, or there's no match
    ///
    /// # Examples
    /// - `MyClass[]` is an array of `MyClass`
    /// - `AdjustmentRule[]` is an array of `TimeZoneInfo/AdjustmentRule`
    pub fn is_array_of(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        if let Some(element_name) = self.fullname().strip_suffix("[]") {
            base_fullname == element_name || base_fullname.ends_with(&format!("/{element_name}"))
        } else {
            false
        }
    }

    /// Check if this type has a pointer relationship with the given base type.
    ///
    /// Returns true if this type is a pointer type (ends with "*") and the base type
    /// matches the pointer's target type. This handles nested types correctly by
    /// checking both direct name matches and nested type patterns.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential target type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If this type is a pointer to the specified base type
    /// * `false` - If this is not a pointer type, the base name is empty, or there's no match
    ///
    /// # Examples
    /// - `EventData*` is a pointer to `EventData`
    /// - `MyStruct*` is a pointer to `OuterClass/MyStruct`
    pub fn is_pointer_to(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        if let Some(element_name) = self.fullname().strip_suffix('*') {
            base_fullname == element_name || base_fullname.ends_with(&format!("/{element_name}"))
        } else {
            false
        }
    }

    /// Check if this type represents a generic relationship with the base type.
    ///
    /// Returns true if either type has generic parameters (contains '`') and they
    /// share a common base name, indicating a generic instantiation relationship.
    ///
    /// # Arguments
    /// * `base_fullname` - The full name of the potential generic base type to check against.
    ///   Must be a non-empty, valid type name.
    ///
    /// # Returns
    /// * `true` - If the types share a generic relationship
    /// * `false` - If there's no generic relationship, or the base name is empty
    ///
    /// # Examples
    /// - `List<int>` has a generic relationship with `List<T>`
    /// - `Dictionary<string, int>` has a generic relationship with `Dictionary<K, V>`
    pub fn is_generic_of(&self, base_fullname: &str) -> bool {
        if base_fullname.is_empty() || base_fullname.trim().is_empty() {
            return false;
        }

        let derived_fullname = self.fullname();
        (derived_fullname.contains('`') || base_fullname.contains('`'))
            && (derived_fullname.starts_with(base_fullname.split('`').next().unwrap_or(""))
                || base_fullname.starts_with(derived_fullname.split('`').next().unwrap_or("")))
    }
}

impl fmt::Display for CilType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fullname())
    }
}

/// Tests that inheritance-chain walks terminate on attacker-controlled `extends` cycles.
///
/// Each case constructs an inheritance graph that no valid assembly contains but that a
/// malformed one can describe, then walks it. A regression shows up as a hung or killed test
/// process rather than an assertion failure, since the failure mode being guarded against is
/// an infinite loop or native stack exhaustion.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::builders::CilTypeBuilder;

    /// A type defined here is a value type only by its base (ECMA-335 II.13). A sealed class
    /// with sequential layout, as interop code declares one, stays a class while its base is
    /// not linked yet, instead of being guessed a value type from its flags.
    #[test]
    fn a_sealed_sequential_type_definition_is_not_guessed_a_value_type() {
        let defined = CilTypeBuilder::simple_class("Mono.Unix.Native", "SockaddrIn")
            .with_flags(TypeAttributes::SEALED | TypeAttributes::SEQUENTIAL_LAYOUT)
            .with_computed_flavor()
            .build();
        assert_eq!(*defined.flavor(), CilFlavor::Class);
    }

    /// Builds a type with a distinct token so the visited set can tell instances apart.
    fn typ(rid: u32, name: &str) -> CilTypeRc {
        CilTypeBuilder::simple_class("Test", name)
            .with_token(Token::new(0x0200_0000 | rid))
            .build()
    }

    #[test]
    fn base_chain_terminates_on_self_extends() {
        let a = typ(1, "SelfRef");
        a.set_base(&CilTypeRef::new(&a)).expect("set_base");

        // The starting token seeds the visited set, so the self-edge yields nothing at all.
        assert_eq!(a.base_chain().count(), 0);
    }

    #[test]
    fn base_chain_terminates_on_two_type_cycle() {
        let a = typ(1, "A");
        let b = typ(2, "B");
        a.set_base(&CilTypeRef::new(&b)).expect("set_base a -> b");
        b.set_base(&CilTypeRef::new(&a)).expect("set_base b -> a");

        // Walking from A yields B, then stops: A's token is already in the visited set.
        let chain: Vec<Token> = a.base_chain().map(|t| t.token).collect();
        assert_eq!(chain, vec![b.token]);
    }

    #[test]
    fn base_chain_terminates_on_three_type_cycle() {
        let a = typ(1, "A");
        let b = typ(2, "B");
        let c = typ(3, "C");
        a.set_base(&CilTypeRef::new(&b)).expect("set_base a -> b");
        b.set_base(&CilTypeRef::new(&c)).expect("set_base b -> c");
        c.set_base(&CilTypeRef::new(&a)).expect("set_base c -> a");

        let chain: Vec<Token> = a.base_chain().map(|t| t.token).collect();
        assert_eq!(chain, vec![b.token, c.token]);
    }

    #[test]
    fn base_chain_yields_acyclic_ancestors_in_order() {
        let object = typ(1, "Object");
        let mid = typ(2, "Mid");
        let leaf = typ(3, "Leaf");
        mid.set_base(&CilTypeRef::new(&object))
            .expect("set_base mid -> object");
        leaf.set_base(&CilTypeRef::new(&mid))
            .expect("set_base leaf -> mid");

        let chain: Vec<Token> = leaf.base_chain().map(|t| t.token).collect();
        assert_eq!(chain, vec![mid.token, object.token]);
    }

    #[test]
    fn base_chain_is_bounded_even_without_a_cycle() {
        // A chain longer than the depth budget, with every token distinct so only the depth
        // bound can stop it.
        let types: Vec<CilTypeRc> = (0..MAX_BASE_WALK_DEPTH + 50)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                typ(i as u32 + 1, "Deep")
            })
            .collect();
        for pair in types.windows(2) {
            if let [derived, base] = pair {
                derived.set_base(&CilTypeRef::new(base)).expect("set_base");
            }
        }

        let first = types.first().expect("non-empty");
        assert_eq!(first.base_chain().count(), MAX_BASE_WALK_DEPTH);
    }

    #[test]
    fn is_subtype_of_terminates_on_cycle() {
        let a = typ(1, "A");
        let b = typ(2, "B");
        let unrelated = typ(3, "Unrelated");
        a.set_base(&CilTypeRef::new(&b)).expect("set_base a -> b");
        b.set_base(&CilTypeRef::new(&a)).expect("set_base b -> a");

        // Searching for a type that is nowhere in the cycle is the non-terminating case.
        assert!(!a.is_subtype_of(&unrelated));
        assert!(a.is_subtype_of(&b));
    }

    #[test]
    fn implements_interface_terminates_on_cycle() {
        let a = typ(1, "A");
        let b = typ(2, "B");
        let iface = CilTypeBuilder::interface("Test", "IUnimplemented")
            .with_token(Token::new(0x0200_0003))
            .build();
        a.set_base(&CilTypeRef::new(&b)).expect("set_base a -> b");
        b.set_base(&CilTypeRef::new(&a)).expect("set_base b -> a");

        assert!(!a.implements_interface(&iface));
    }
}

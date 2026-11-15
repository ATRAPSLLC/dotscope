//! # Type System Base Types
//!
//! This module provides the foundational types and abstractions for the .NET CIL (Common
//! Intermediate Language) type system. It defines the core building blocks used throughout
//! the dotscope library for representing, manipulating, and reasoning about .NET types.
//!
//! ## Core Components
//!
//! ### Type References
//!
//! - [`CilTypeRef`] - Smart weak reference to prevent circular dependencies
//! - [`CilTypeRefList`] - Collection of type references
//! - [`CilTypeReference`] - Unified reference to any metadata table entry
//!
//! ### Type Flavors
//!
//! - [`CilFlavor`] - Categorizes types (primitives, arrays, classes, etc.)
//! - [`CilModifier`] - Required/optional type modifiers
//! - [`ArrayDimensions`] - Array dimension information
//!
//! ### Element Type Constants
//!
//! - [`ELEMENT_TYPE`] - Standard .NET metadata element type constants
//!
//! ## Type System Design
//!
//! The type system is designed to handle the complexity of .NET's type model:
//!
//! - **Primitive Types**: Built-in types like `int`, `string`, `bool`
//! - **Constructed Types**: Arrays, pointers, generic instantiations
//! - **Reference Types**: Classes, interfaces, delegates
//! - **Value Types**: Structs, enums, primitive values
//! - **Generic Types**: Generic parameters and instantiated generics
//!
//! ## Memory Management
//!
//! To handle circular references common in type systems (e.g., nested types, generic
//! constraints), this module uses weak references through [`CilTypeRef`]. This prevents
//! memory leaks while maintaining a clean API for type operations.
//!
//! ## Type Compatibility
//!
//! The type system implements .NET's type compatibility rules:
//!
//! - **Exact matching** for identity
//! - **Widening conversions** for primitive types
//! - **Reference type compatibility** through inheritance
//! - **Constant assignment rules** for compile-time values
//!
//! ## Usage Example
//!
//! ```rust
//! use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
//!
//! // Create a 2D array type
//! let array_type = CilFlavor::Array {
//!     element_type: Box::new(CilFlavor::I4),
//!     rank: 2,
//!     dimensions: vec![
//!         ArrayDimensions { size: Some(10), lower_bound: Some(0) },
//!         ArrayDimensions { size: Some(5), lower_bound: Some(0) },
//!     ],
//! };
//!
//! assert!(array_type.is_reference_type());
//! assert!(!array_type.is_primitive());
//!
//! // Check type compatibility
//! let int_type = CilFlavor::I4;
//! let long_type = CilFlavor::I8;
//! assert!(int_type.is_compatible_with(&long_type)); // int can widen to long
//! ```
//!
//! ## Thread Safety
//!
//! All types in this module are designed to be `Send + Sync` where appropriate.
//! [`CilTypeRef`] uses weak references which are thread-safe for concurrent access.
//!
//! ## References
//!
//! - [ECMA-335 §I.8 - Common Type System](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [`crate::metadata::typesystem`] - Higher-level type system operations

use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    sync::{Arc, Weak},
};

use crate::{
    metadata::{
        method::MethodRef,
        signatures::{SignatureMethod, TypeSignature},
        tables::{
            AssemblyRc, AssemblyRefRc, DeclSecurityRc, EventRc, ExportedTypeRc, FieldRc, FileRc,
            GenericParamConstraintRc, GenericParamRc, InterfaceImplRc, MemberRefRc, MethodSpecList,
            MethodSpecRc, ModuleRc, ModuleRefRc, ParamRc, PropertyRc, StandAloneSigRc,
        },
        typesystem::{CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc},
    },
    prelude::{GenericParamList, Token},
    utils::RowList,
};

/// A vector that holds [`CilTypeRef`] instances (weak references).
///
/// This type alias provides a convenient way to work with collections of type references
/// while maintaining the memory safety benefits of weak references. The use of `boxcar::Vec`
/// provides thread-safe, lock-free vector operations suitable for concurrent access patterns
/// common in metadata processing.
///
/// ## Usage
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilTypeRefList, CilTypeRef};
/// use std::sync::Arc;
///
/// # fn example() {
/// let type_list: CilTypeRefList = Arc::new(boxcar::Vec::new());
/// // Add type references to the collection
/// # }
/// ```
pub type CilTypeRefList = Arc<boxcar::Vec<CilTypeRef>>;

/// A smart reference to a [`CilType`] that uses weak references to prevent circular dependencies.
///
/// This type provides a safe way to reference [`CilType`] instances without creating
/// circular reference chains that could lead to memory leaks. It's particularly important
/// in type systems where types often reference each other (e.g., nested types, generic
/// constraints, inheritance hierarchies).
///
/// ## Design Rationale
///
/// The .NET type system has many scenarios where types reference each other:
/// - Nested types reference their enclosing types
/// - Generic types reference their type parameters
/// - Base types and derived types form hierarchies
/// - Interface implementations create bidirectional references
///
/// Using weak references breaks these cycles while still providing convenient access
/// to referenced types when they're needed.
///
/// ## Memory Safety
///
/// The weak reference will become invalid if the referenced [`CilType`] is dropped.
/// All methods that access the referenced type handle this gracefully by returning
/// [`Option`] types or providing panic-safe alternatives.
///
/// ## Usage Example
///
/// ```rust
/// use dotscope::metadata::typesystem::CilTypeRef;
/// use std::sync::Arc;
///
/// # fn example() {
/// # use dotscope::metadata::typesystem::CilType;
/// # let some_type: Arc<CilType> = unimplemented!();
/// // Create a weak reference to a type
/// let type_ref = CilTypeRef::new(&some_type);
///
/// // Access the type safely
/// if let Some(strong_ref) = type_ref.upgrade() {
///     println!("Type name: {}", strong_ref.name);
/// }
///
/// // Check if the reference is still valid
/// if type_ref.is_valid() {
///     // Safe to use expect() here
///     let strong_ref = type_ref.expect("Type should be valid");
/// }
/// # }
/// ```
///
/// ## Thread Safety
///
/// [`CilTypeRef`] is `Send + Sync` as it only contains a [`Weak`] pointer, which
/// is safe to share between threads.
#[derive(Clone, Debug)]
pub struct CilTypeRef {
    /// The weak reference to the actual type instance
    weak_ref: Weak<CilType>,
}

impl CilTypeRef {
    /// Creates a new weak reference from a strong reference to a [`CilType`].
    ///
    /// This method creates a [`CilTypeRef`] that holds a weak reference to the provided
    /// type. The weak reference will not prevent the type from being dropped when all
    /// strong references are released.
    ///
    /// ## Arguments
    ///
    /// * `strong_ref` - A strong reference to the type to create a weak reference to
    ///
    /// ## Returns
    ///
    /// A new [`CilTypeRef`] containing a weak reference to the provided type.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    /// assert!(type_ref.is_valid());
    /// # }
    /// ```
    pub fn new(strong_ref: &CilTypeRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Attempts to upgrade the weak reference to a strong reference.
    ///
    /// This method tries to convert the weak reference back to a strong reference.
    /// If the referenced type has been dropped, this will return [`None`].
    ///
    /// ## Returns
    ///
    /// - `Some(CilTypeRc)` if the referenced type is still alive
    /// - [`None`] if the referenced type has been dropped
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// match type_ref.upgrade() {
    ///     Some(strong_ref) => {
    ///         // Use the strong reference
    ///         println!("Type: {}", strong_ref.name);
    ///     }
    ///     None => {
    ///         println!("Type has been dropped");
    ///     }
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn upgrade(&self) -> Option<CilTypeRc> {
        self.weak_ref.upgrade()
    }

    /// Gets a strong reference to the type, panicking if the type has been dropped.
    ///
    /// This method is similar to [`upgrade`](Self::upgrade) but will panic if the
    /// referenced type is no longer available. Use this when you're certain the
    /// type should still exist and want to avoid handling the [`Option`].
    ///
    /// ## Arguments
    ///
    /// * `msg` - The panic message to use if the type has been dropped
    ///
    /// ## Returns
    ///
    /// A strong reference to the type.
    ///
    /// ## Returns
    ///
    /// Returns `Some` with a strong reference if the type is still alive, or
    /// `None` if the type has been dropped (i.e. the weak reference cannot
    /// be upgraded). The `msg` argument is kept for backwards compatibility
    /// but no longer used for panicking; the crate forbids panics in
    /// production code.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// if let Some(strong_ref) = type_ref.expect("Type should still be alive") {
    ///     println!("Type: {}", strong_ref.name);
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn expect(&self, _msg: &str) -> Option<CilTypeRc> {
        self.weak_ref.upgrade()
    }

    /// Checks if the referenced type is still alive.
    ///
    /// This method returns `true` if there are still strong references to the
    /// type, meaning [`upgrade()`](Self::upgrade) would succeed. Returns `false`
    /// if the type has been dropped.
    ///
    /// ## Returns
    ///
    /// `true` if the referenced type is still alive, `false` otherwise.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// if type_ref.is_valid() {
    ///     // Safe to call expect() or upgrade().unwrap()
    ///     let strong_ref = type_ref.upgrade().unwrap();
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weak_ref.strong_count() > 0
    }

    /// Gets the token of the referenced type, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        self.upgrade().map(|t| t.token)
    }

    /// Gets a clone of the name, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.upgrade().map(|t| t.name.clone())
    }

    /// Gets a clone of the namespace, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn namespace(&self) -> Option<String> {
        self.upgrade().map(|t| t.namespace.clone())
    }

    /// Gets the fully-qualified name (`Namespace.Name`), or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn fullname(&self) -> Option<String> {
        self.upgrade().map(|t| t.fullname().to_string())
    }

    /// Gets a clone of the nested types collection, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn nested_types(&self) -> Option<RowList<CilTypeRef>> {
        self.upgrade().map(|t| t.nested_types.clone())
    }

    /// Gets a clone of the generic parameters, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn generic_params(&self) -> Option<GenericParamList> {
        self.upgrade().map(|t| t.generic_params.clone())
    }

    /// Gets a clone of the generic arguments, or [`None`] if dropped.
    ///
    /// See the [Convenience Accessors](#convenience-accessors) section above for performance notes.
    #[must_use]
    pub fn generic_args(&self) -> Option<MethodSpecList> {
        self.upgrade().map(|t| t.generic_args.clone())
    }

    /// Checks if this type reference is compatible with another type.
    ///
    /// This method upgrades the weak reference and delegates to the type's
    /// compatibility checking logic. Returns `false` if the referenced type
    /// has been dropped.
    ///
    /// ## Arguments
    ///
    /// * `other` - The other type to check compatibility against
    ///
    /// ## Returns
    ///
    /// `true` if this type is compatible with the other type, `false` if
    /// incompatible or if the reference is invalid.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let type1: Arc<CilType> = unimplemented!();
    /// # let type2: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&type1);
    ///
    /// if type_ref.is_compatible_with(&type2) {
    ///     println!("Types are compatible");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_compatible_with(&self, other: &CilType) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.is_compatible_with(other)
        } else {
            false
        }
    }

    /// Checks if this type reference can accept a constant value.
    ///
    /// This method upgrades the weak reference and delegates to the type's
    /// constant acceptance logic. Returns `false` if the referenced type
    /// has been dropped.
    ///
    /// ## Arguments
    ///
    /// * `constant` - The constant value to check
    ///
    /// ## Returns
    ///
    /// `true` if this type can accept the constant, `false` if not or if
    /// the reference is invalid.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::{CilType, CilPrimitive};
    /// # use std::sync::Arc;
    /// # let type_ref: CilTypeRef = unimplemented!();
    /// # let constant: CilPrimitive = unimplemented!();
    /// if type_ref.accepts_constant(&constant) {
    ///     println!("Type can accept this constant");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn accepts_constant(&self, constant: &CilPrimitive) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.accepts_constant(constant)
        } else {
            false
        }
    }
}

impl From<CilTypeRc> for CilTypeRef {
    fn from(strong_ref: CilTypeRc) -> Self {
        Self::new(&strong_ref)
    }
}

/// Iterator over a [`CilTypeRefList`], yielding references to [`CilTypeRef`] items.
///
/// This iterator provides ergonomic access to type reference collections without
/// requiring manual index-based loops. It integrates with Rust's standard iterator
/// ecosystem, enabling use of methods like `filter()`, `map()`, `collect()`, etc.
///
/// ## Example
///
/// ```no_run
/// use dotscope::metadata::typesystem::{CilTypeRefList, CilTypeRefListIter};
///
/// # fn example(nested_types: &CilTypeRefList, types: &CilTypeRefList) {
/// // Iterate over nested types
/// for type_ref in CilTypeRefListIter::new(&nested_types) {
///     if let Some(resolved) = type_ref.upgrade() {
///         println!("Found nested type: {}", resolved.name);
///     }
/// }
///
/// // Use iterator adapters
/// let valid_types: Vec<_> = CilTypeRefListIter::new(&types)
///     .filter_map(|r| r.upgrade())
///     .collect();
/// # }
/// ```
pub struct CilTypeRefListIter<'a> {
    list: &'a CilTypeRefList,
    index: usize,
}

impl<'a> CilTypeRefListIter<'a> {
    /// Creates a new iterator over the given type reference list.
    #[must_use]
    pub fn new(list: &'a CilTypeRefList) -> Self {
        Self { list, index: 0 }
    }
}

impl<'a> Iterator for CilTypeRefListIter<'a> {
    type Item = &'a CilTypeRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.list.count() {
            // boxcar::Vec returns Option from get(), and we need to handle it
            let result = self.list.get(self.index);
            self.index = self.index.saturating_add(1);
            result
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.list.count().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for CilTypeRefListIter<'_> {
    fn len(&self) -> usize {
        self.list.count().saturating_sub(self.index)
    }
}

/// Represents a single dimension of a multi-dimensional array with optional size and bounds.
///
/// In .NET, arrays can have multiple dimensions with configurable lower bounds and sizes.
/// This structure captures the metadata for a single dimension of such an array.
///
/// ## Fields
///
/// - `size`: The number of elements in this dimension (if known at compile time)
/// - `lower_bound`: The lowest valid index for this dimension (typically 0)
///
/// ## Examples
///
/// ```rust
/// use dotscope::metadata::typesystem::ArrayDimensions;
///
/// // A dimension with 10 elements starting at index 0
/// let dim = ArrayDimensions {
///     size: Some(10),
///     lower_bound: Some(0),
/// };
///
/// // An unbounded dimension (size determined at runtime)
/// let unbounded = ArrayDimensions {
///     size: None,
///     lower_bound: Some(1), // 1-based indexing
/// };
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.2.13 - Array shapes](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
#[derive(Debug, Clone, PartialEq, Default, Hash)]
pub struct ArrayDimensions {
    /// The size of this dimension (number of elements).
    ///
    /// `None` indicates the size is not fixed at compile time and will be
    /// determined at runtime when the array is allocated.
    pub size: Option<u32>,

    /// The lower bound of this dimension (lowest index that can be used to access an element).
    ///
    /// Most .NET arrays use 0-based indexing, but the runtime supports arbitrary lower bounds.
    /// `None` typically means the lower bound is 0. Signed: a bound may be
    /// negative (ECMA-335 II.23.2.13).
    pub lower_bound: Option<i32>,
}

/// Represents a unified reference to various metadata table entries in the .NET runtime.
///
/// This enum provides a type-safe way to reference different kinds of metadata entries
/// that can appear in various contexts throughout the .NET type system. It's similar
/// to a `CodedIndex` but contains fully resolved references rather than raw indices.
///
/// ## Design
///
/// Unlike raw coded indices which are just numbers that need to be decoded, this enum
/// holds strong references to the actual metadata objects, making it easier and safer
/// to work with resolved metadata.
///
/// ## Variants
///
/// The enum covers all major metadata table types that can be referenced:
///
/// - **Type References**: [`crate::metadata::tables::TypeRefRaw`], [`crate::metadata::tables::TypeDefRaw`], [`crate::metadata::tables::TypeSpec`] - Different ways types can be referenced
/// - **Members**: [`crate::metadata::tables::Field`], [`crate::metadata::tables::Property`], [`crate::metadata::tables::MethodDefRaw`], [`crate::metadata::tables::MemberRef`] - Type members
/// - **Parameters**: [`crate::metadata::tables::Param`] - Method and property parameters
/// - **Modules**: [`crate::metadata::tables::Module`], [`crate::metadata::tables::ModuleRef`] - Assembly modules
/// - **Security**: [`crate::metadata::tables::DeclSecurity`] - Security declarations
/// - **Events**: [`crate::metadata::tables::Event`] - Event declarations
/// - **Signatures**: [`crate::metadata::tables::StandAloneSig`] - Standalone signatures
/// - **Assemblies**: [`crate::metadata::tables::Assembly`], [`crate::metadata::tables::AssemblyRef`] - Assembly references
/// - **Files**: [`crate::metadata::tables::File`], [`crate::metadata::tables::ExportedType`] - File and exported type references
/// - **Generics**: [`crate::metadata::tables::GenericParam`], [`crate::metadata::tables::GenericParamConstraint`], [`crate::metadata::tables::MethodSpec`] - Generic type system
/// - **Interfaces**: [`crate::metadata::tables::InterfaceImpl`] - Interface implementations
/// - **None**: Used when no reference is present
///
/// ## Usage Example
///
/// ```rust
/// use dotscope::metadata::typesystem::CilTypeReference;
///
/// # fn example(reference: CilTypeReference) {
/// match reference {
///     CilTypeReference::TypeDef(type_ref) => {
///         if let Some(type_obj) = type_ref.upgrade() {
///             println!("Found type: {}", type_obj.name);
///         }
///     }
///     CilTypeReference::Field(field) => {
///         println!("Found field: {}", field.name);
///     }
///     CilTypeReference::None => {
///         println!("No reference");
///     }
///     _ => {
///         println!("Other reference type");
///     }
/// }
/// # }
/// ```
///
/// ## Memory Management
///
/// Type references ([`crate::metadata::tables::TypeRefRaw`], [`crate::metadata::tables::TypeDefRaw`], [`crate::metadata::tables::TypeSpec`]) use [`CilTypeRef`] which
/// contains weak references to prevent circular dependencies. Other variants hold
/// strong references to their respective metadata objects.
///
/// ## Thread Safety
///
/// All contained references are designed to be thread-safe for concurrent access.
#[derive(Clone)]
pub enum CilTypeReference {
    /// Reference to a type defined in another module or assembly
    TypeRef(CilTypeRef),
    /// Reference to a type defined in the current module
    TypeDef(CilTypeRef),
    /// Reference to a type specification (constructed type)
    TypeSpec(CilTypeRef),
    /// Reference to a field
    Field(FieldRc),
    /// Reference to a parameter
    Param(ParamRc),
    /// Reference to a property
    Property(PropertyRc),
    /// Reference to a method definition
    MethodDef(MethodRef),
    /// Reference to an interface implementation
    InterfaceImpl(InterfaceImplRc),
    /// Reference to a member (field, method, etc.)
    MemberRef(MemberRefRc),
    /// Reference to a module
    Module(ModuleRc),
    /// Reference to a security declaration
    DeclSecurity(DeclSecurityRc),
    /// Reference to an event
    Event(EventRc),
    /// Reference to a standalone signature
    StandAloneSig(StandAloneSigRc),
    /// Reference to an external module
    ModuleRef(ModuleRefRc),
    /// Reference to an assembly
    Assembly(AssemblyRc),
    /// Reference to an external assembly
    AssemblyRef(AssemblyRefRc),
    /// Reference to a file
    File(FileRc),
    /// Reference to an exported type
    ExportedType(ExportedTypeRc),
    /// Reference to a generic parameter
    GenericParam(GenericParamRc),
    /// Reference to a generic parameter constraint
    GenericParamConstraint(GenericParamConstraintRc),
    /// Reference to a method specialization
    MethodSpec(MethodSpecRc),
    /// No reference (null/empty)
    None,
}

impl Debug for CilTypeReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CilTypeReference::TypeRef(_) => write!(f, "CilTypeReference::TypeRef(...)"),
            CilTypeReference::TypeDef(_) => write!(f, "CilTypeReference::TypeDef(...)"),
            CilTypeReference::TypeSpec(_) => write!(f, "CilTypeReference::TypeSpec(...)"),
            CilTypeReference::Field(_) => write!(f, "CilTypeReference::Field(...)"),
            CilTypeReference::Param(_) => write!(f, "CilTypeReference::Param(...)"),
            CilTypeReference::Property(_) => write!(f, "CilTypeReference::Property(...)"),
            CilTypeReference::MethodDef(_) => write!(f, "CilTypeReference::MethodDef(...)"),
            CilTypeReference::InterfaceImpl(_) => write!(f, "CilTypeReference::InterfaceImpl(...)"),
            CilTypeReference::MemberRef(_) => write!(f, "CilTypeReference::MemberRef(...)"),
            CilTypeReference::Module(_) => write!(f, "CilTypeReference::Module(...)"),
            CilTypeReference::DeclSecurity(_) => write!(f, "CilTypeReference::DeclSecurity(...)"),
            CilTypeReference::Event(_) => write!(f, "CilTypeReference::Event(...)"),
            CilTypeReference::StandAloneSig(_) => write!(f, "CilTypeReference::StandAloneSig(...)"),
            CilTypeReference::ModuleRef(_) => write!(f, "CilTypeReference::ModuleRef(...)"),
            CilTypeReference::Assembly(_) => write!(f, "CilTypeReference::Assembly(...)"),
            CilTypeReference::AssemblyRef(_) => write!(f, "CilTypeReference::AssemblyRef(...)"),
            CilTypeReference::File(_) => write!(f, "CilTypeReference::File(...)"),
            CilTypeReference::ExportedType(_) => write!(f, "CilTypeReference::ExportedType(...)"),
            CilTypeReference::GenericParam(_) => write!(f, "CilTypeReference::GenericParam(...)"),
            CilTypeReference::GenericParamConstraint(_) => {
                write!(f, "CilTypeReference::GenericParamConstraint(...)")
            }
            CilTypeReference::MethodSpec(_) => write!(f, "CilTypeReference::MethodSpec(...)"),
            CilTypeReference::None => write!(f, "CilTypeReference::None"),
        }
    }
}

impl CilTypeReference {
    /// Returns the metadata token for this reference, if available.
    ///
    /// Extracts the token from the underlying reference type. Returns `None`
    /// for the `None` variant or if the weak reference has been dropped.
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        match self {
            Self::TypeRef(r) | Self::TypeDef(r) | Self::TypeSpec(r) => r.token(),
            Self::Field(r) => Some(r.token),
            Self::Param(r) => Some(r.token),
            Self::Property(r) => Some(r.token),
            Self::MethodDef(r) => r.token(),
            Self::InterfaceImpl(r) => Some(r.token),
            Self::MemberRef(r) => Some(r.token),
            Self::Module(r) => Some(r.token),
            Self::DeclSecurity(r) => Some(r.token),
            Self::Event(r) => Some(r.token),
            Self::StandAloneSig(r) => Some(r.token),
            Self::ModuleRef(r) => Some(r.token),
            Self::Assembly(r) => Some(r.token),
            Self::AssemblyRef(r) => Some(r.token),
            Self::File(r) => Some(r.token),
            Self::ExportedType(r) => Some(r.token),
            Self::GenericParam(r) => Some(r.token),
            Self::GenericParamConstraint(r) => Some(r.token),
            Self::MethodSpec(r) => Some(r.token),
            Self::None => None,
        }
    }

    /// Returns the simple name for this reference, if available.
    ///
    /// For type variants (`TypeRef`, `TypeDef`, `TypeSpec`), delegates to
    /// [`CilTypeRef::name()`]. For other variants with a `name` field, returns
    /// that field directly. Returns `None` for variants without a meaningful
    /// name or if the weak reference has been dropped.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        match self {
            Self::TypeRef(r) | Self::TypeDef(r) | Self::TypeSpec(r) => r.name(),
            Self::Field(r) => Some(r.name.clone()),
            Self::Param(r) => r.name.clone(),
            Self::Property(r) => Some(r.name.clone()),
            Self::MethodDef(r) => r.name(),
            Self::MemberRef(r) => Some(r.name.clone()),
            Self::Module(r) => Some(r.name.clone()),
            Self::Event(r) => Some(r.name.clone()),
            Self::ModuleRef(r) => Some(r.name.clone()),
            Self::Assembly(r) => Some(r.name.clone()),
            Self::AssemblyRef(r) => Some(r.name.clone()),
            Self::File(r) => Some(r.name.clone()),
            Self::ExportedType(r) => Some(r.name.clone()),
            Self::GenericParam(r) => Some(r.name.clone()),
            _ => None,
        }
    }

    /// Returns the fully-qualified name (`Namespace.Name`) for this reference,
    /// if available.
    ///
    /// For type variants (`TypeRef`, `TypeDef`, `TypeSpec`), delegates to
    /// [`CilTypeRef::fullname()`]. For other variants, falls back to [`name()`](Self::name).
    #[must_use]
    pub fn fullname(&self) -> Option<String> {
        match self {
            Self::TypeRef(r) | Self::TypeDef(r) | Self::TypeSpec(r) => r.fullname(),
            _ => self.name(),
        }
    }
}

/// Constants representing .NET metadata element types as defined in ECMA-335.
///
/// These constants correspond to the element type values used in .NET metadata
/// signatures to identify different types. They are used throughout the runtime
/// for type identification, signature parsing, and type system operations.
///
/// ## Organization
///
/// The constants are organized into several categories:
///
/// ### Primitive Types (0x01-0x0e, 0x18-0x19, 0x1c)
/// Basic types built into the runtime like integers, floats, booleans, etc.
///
/// ### Constructed Types (0x0f-0x17, 0x1d-0x1e)
/// Types built from other types like arrays, pointers, generics.
///
/// ### Modifiers (0x1f-0x20, 0x40-0x45)
/// Type modifiers for optional/required constraints, variance, etc.
///
/// ## Usage
///
/// These constants are primarily used when parsing metadata signatures and
/// when generating type information for the runtime.
///
/// ```rust
/// use dotscope::metadata::typesystem::ELEMENT_TYPE;
///
/// # fn parse_signature_element(element: u8) {
/// match element {
///     ELEMENT_TYPE::I4 => println!("32-bit integer"),
///     ELEMENT_TYPE::STRING => println!("String type"),
///     ELEMENT_TYPE::SZARRAY => println!("Single-dimension array"),
///     _ => println!("Other element type"),
/// }
/// # }
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [CoreCLR Type System](https://github.com/dotnet/coreclr/blob/master/src/inc/corinfo.h)
#[allow(non_snake_case, dead_code)]
pub mod ELEMENT_TYPE {
    /// Marks the end of a list in signatures
    pub const END: u8 = 0x00;
    /// Void type (no return value)
    pub const VOID: u8 = 0x01;
    /// Boolean type (true/false)
    pub const BOOLEAN: u8 = 0x02;
    /// 16-bit Unicode character
    pub const CHAR: u8 = 0x03;
    /// Signed 8-bit integer
    pub const I1: u8 = 0x04;
    /// Unsigned 8-bit integer  
    pub const U1: u8 = 0x05;
    /// Signed 16-bit integer
    pub const I2: u8 = 0x06;
    /// Unsigned 16-bit integer
    pub const U2: u8 = 0x07;
    /// Signed 32-bit integer
    pub const I4: u8 = 0x08;
    /// Unsigned 32-bit integer
    pub const U4: u8 = 0x09;
    /// Signed 64-bit integer
    pub const I8: u8 = 0x0a;
    /// Unsigned 64-bit integer
    pub const U8: u8 = 0x0b;
    /// 32-bit floating point
    pub const R4: u8 = 0x0c;
    /// 64-bit floating point
    pub const R8: u8 = 0x0d;
    /// String type
    pub const STRING: u8 = 0x0e;
    /// Unmanaged pointer (followed by type)
    pub const PTR: u8 = 0x0f;
    /// Managed reference (followed by type)
    pub const BYREF: u8 = 0x10;
    /// Value type (followed by `TypeDef` or `TypeRef` token)
    pub const VALUETYPE: u8 = 0x11;
    /// Reference type/class (followed by `TypeDef` or `TypeRef` token)
    pub const CLASS: u8 = 0x12;
    /// Generic parameter in a generic type definition (represented as number)
    pub const VAR: u8 = 0x13;
    /// Multi-dimensional array (type rank boundsCount bound1 … loCount lo1 …)
    pub const ARRAY: u8 = 0x14;
    /// Generic type instantiation (followed by type type-arg-count type-1 ... type-n)
    pub const GENERICINST: u8 = 0x15;
    /// Typed reference type
    pub const TYPEDBYREF: u8 = 0x16;
    /// Native integer type (System.IntPtr)
    pub const I: u8 = 0x18;
    /// Native unsigned integer type (System.UIntPtr)
    pub const U: u8 = 0x19;
    /// Function pointer (followed by full method signature)
    pub const FNPTR: u8 = 0x1b;
    /// Object type (System.Object)
    pub const OBJECT: u8 = 0x1c;
    /// Single-dimension array with 0 lower bound
    pub const SZARRAY: u8 = 0x1d;
    /// Generic parameter in a generic method definition (represented as number)
    pub const MVAR: u8 = 0x1e;
    /// Required modifier (followed by a `TypeDef` or `TypeRef` token)
    pub const CMOD_REQD: u8 = 0x1f;
    /// Optional modifier (followed by a `TypeDef` or `TypeRef` token)
    pub const CMOD_OPT: u8 = 0x20;
    /// Implemented within the CLI
    pub const INTERNAL: u8 = 0x21;
    /// Modifier flag (OR'd with following element types)
    pub const MODIFIER: u8 = 0x40;
    /// Sentinel for vararg method signature
    pub const SENTINEL: u8 = 0x41;
    /// Denotes a local variable that points at a pinned object
    pub const PINNED: u8 = 0x45;
}

/// Represents a type modifier that can be applied to .NET types.
///
/// In the .NET type system, types can have modifiers that constrain or extend their behavior.
/// These modifiers can be either required (must be understood by the runtime) or optional
/// (can be ignored if not understood).
///
/// ## Modifier Types
///
/// - **Required modifiers** (`CMOD_REQD`): Must be processed by the runtime. If the runtime
///   doesn't understand a required modifier, it should reject the type.
/// - **Optional modifiers** (`CMOD_OPT`): Can be safely ignored by runtimes that don't
///   understand them.
///
/// ## Common Use Cases
///
/// - **const/volatile semantics**: Indicating memory access patterns
/// - **Platform-specific constraints**: Hardware or ABI-specific requirements  
/// - **Language-specific features**: Language extensions that map to runtime behavior
/// - **Interop constraints**: Requirements for native code interaction
///
/// ## Example
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilModifier, CilTypeRef};
///
/// # fn example(const_modifier_type: CilTypeRef) {
/// // A required const modifier
/// let const_modifier = CilModifier {
///     required: true,
///     modifier: const_modifier_type,
/// };
///
/// assert!(const_modifier.required);
/// # }
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.2.7 - Type](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [ECMA-335 §II.7.1.1 - modreq and modopt](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
pub struct CilModifier {
    /// Whether this modifier is required (`true`) or optional (`false`).
    ///
    /// Required modifiers must be understood and processed by the runtime.
    /// Optional modifiers can be safely ignored if not recognized.
    pub required: bool,

    /// The type reference that defines the modifier behavior.
    ///
    /// This typically points to a type that encodes the specific semantics
    /// of the modifier (e.g., a const modifier type, volatile modifier type, etc.).
    pub modifier: CilTypeRef,
}

/// Represents the different categories and flavors of types in the .NET type system.
///
/// This enum categorizes all possible types that can exist in .NET metadata, from simple
/// primitive types to complex constructed types like generics and arrays. It provides
/// a unified way to represent type information and perform type-related operations.
///
/// ## Type Categories
///
/// ### Primitive Types
/// Basic built-in types that have direct runtime support:
/// - **Integer types**: `I1`, `U1`, `I2`, `U2`, `I4`, `U4`, `I8`, `U8`
/// - **Floating point**: `R4` (float), `R8` (double)
/// - **Character types**: `Char` (16-bit Unicode)
/// - **Boolean**: `Boolean` (true/false)
/// - **Native integers**: `I` (`IntPtr`), `U` (`UIntPtr`)
/// - **Special types**: `Void`, `Object`, `String`
///
/// ### Constructed Types
/// Types built from other types:
/// - **Arrays**: Multi-dimensional (`Array`) and single-dimensional (`SZARRAY` via single-dimension arrays)
/// - **Pointers**: Unmanaged pointers (`Pointer`) and managed references (`ByRef`)
/// - **Function pointers**: `FnPtr` with method signatures
/// - **Generic instances**: `GenericInstance` with type arguments
/// - **Generic parameters**: `GenericParameter` from type or method definitions
///
/// ### Reference Categories
/// High-level categorizations:
/// - **Classes**: Reference types (`Class`)
/// - **Value types**: Stack-allocated types (`ValueType`)
/// - **Interfaces**: Contract definitions (`Interface`)
///
/// ## Usage Examples
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
///
/// // Primitive type
/// let int_type = CilFlavor::I4;
/// assert!(int_type.is_primitive());
/// assert!(int_type.is_value_type());
///
/// // Array type
/// let array_type = CilFlavor::Array {
///     element_type: Box::new(CilFlavor::I4),
///     rank: 2,
///     dimensions: vec![
///         ArrayDimensions { size: Some(10), lower_bound: Some(0) },
///         ArrayDimensions { size: Some(5), lower_bound: Some(0) },
///     ],
/// };
/// assert!(array_type.is_reference_type());
///
/// // Generic parameter
/// let generic_param = CilFlavor::GenericParameter {
///     index: 0,
///     method: false, // Type parameter, not method parameter
/// };
/// ```
///
/// ## Type Compatibility
///
/// The enum provides methods for checking type compatibility and primitive conversions:
///
/// ```rust
/// # use dotscope::metadata::typesystem::CilFlavor;
/// let byte_type = CilFlavor::U1;
/// let int_type = CilFlavor::I4;
/// let long_type = CilFlavor::I8;
///
/// // Byte can be widened to int
/// assert!(byte_type.is_compatible_with(&int_type));
///
/// // I4 is compatible with smaller types for stack normalization (stelem.i1/i2)
/// assert!(int_type.is_compatible_with(&byte_type));
///
/// // But I8 cannot be assigned to smaller non-64-bit types
/// assert!(!long_type.is_compatible_with(&int_type));
/// ```
///
/// ## Thread Safety
///
/// All variants are `Clone + Send + Sync` and safe for concurrent access.
///
/// ## References
///
/// - [ECMA-335 §I.8 - Common Type System](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
#[derive(Debug, Clone, PartialEq)]
pub enum CilFlavor {
    // Base primitive types
    /// Void type (no value, used for methods that don't return anything)
    Void,
    /// Boolean type (true or false)
    Boolean,
    /// 16-bit Unicode character
    Char,
    /// Signed 8-bit integer (-128 to 127)
    I1,
    /// Unsigned 8-bit integer (0 to 255)
    U1,
    /// Signed 16-bit integer (-32,768 to 32,767)
    I2,
    /// Unsigned 16-bit integer (0 to 65,535)
    U2,
    /// Signed 32-bit integer (-2,147,483,648 to 2,147,483,647)
    I4,
    /// Unsigned 32-bit integer (0 to 4,294,967,295)
    U4,
    /// Signed 64-bit integer
    I8,
    /// Unsigned 64-bit integer
    U8,
    /// 32-bit floating point number (IEEE 754 single precision)
    R4,
    /// 64-bit floating point number (IEEE 754 double precision)
    R8,
    /// Native signed integer (pointer-sized, `IntPtr`)
    I,
    /// Native unsigned integer (pointer-sized, `UIntPtr`)
    U,
    /// Base object type (System.Object)
    Object,
    /// String type (System.String)
    String,

    // Complex types
    /// Multi-dimensional array type with configurable dimensions and bounds
    Array {
        /// The element type of the array
        element_type: Box<CilFlavor>,
        /// The rank (number of dimensions) of the array
        rank: u32,
        /// Details about each dimension including size and lower bounds
        dimensions: Vec<ArrayDimensions>,
    },
    /// Unmanaged pointer type (unsafe, points to unmanaged memory)
    Pointer,
    /// Managed reference type (safe, tracked by garbage collector)
    ByRef,
    /// Generic type instantiation (e.g., `List<int>`, `Dictionary<string, object>`)
    GenericInstance,
    /// Pinned type (prevents garbage collector from moving the object)
    Pinned,
    /// Function pointer type with a specific method signature
    FnPtr {
        /// The method signature this function pointer must match.
        ///
        /// Boxed deliberately, matching [`TypeSignature::FnPtr`]. An inline `SignatureMethod`
        /// is ~144 bytes and, as the widest variant, sets the size of `CilFlavor` and
        /// everything built on it - `SymbolicValue`, and through it every `EmValue` moved on
        /// the interpreter's evaluation stack, local slot, argument slot and array element.
        /// Function pointers are rare in real assemblies, so the indirection is off the hot
        /// path while the size saving applies to every value. See the `EmValue` size
        /// assertion in `emulation::value::emvalue`.
        signature: Box<SignatureMethod>,
    },
    /// Generic parameter from a type or method definition
    GenericParameter {
        /// Index in the generic parameters list (0-based)
        index: u32,
        /// Whether this is a method parameter (`true`) or type parameter (`false`)
        method: bool,
    },

    // Type categories
    /// Reference type / class (allocated on managed heap)
    Class,
    /// Value type (allocated on stack or inline in objects)
    ValueType,
    /// Interface type (contract definition)
    Interface,
    /// Typed reference (System.TypedReference) - contains both a managed pointer and type info
    TypedRef {
        /// The type of the value being referenced (None if unknown at signature parse time)
        target_type: Option<Box<CilFlavor>>,
    },

    // Fallback
    /// Unknown or unsupported type
    Unknown,
}

impl Hash for CilFlavor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use discriminant to distinguish between variants
        std::mem::discriminant(self).hash(state);

        // Hash the data for variants that have data
        match self {
            CilFlavor::Array {
                element_type,
                rank,
                dimensions,
            } => {
                element_type.hash(state);
                rank.hash(state);
                dimensions.hash(state);
            }
            CilFlavor::FnPtr { signature } => {
                // Hash basic signature properties without requiring Hash on SignatureMethod
                signature.param_count.hash(state);
                signature.param_count_generic.hash(state);
                signature.has_this.hash(state);
                signature.explicit_this.hash(state);
                signature.vararg.hash(state);
            }
            CilFlavor::GenericParameter { index, method } => {
                index.hash(state);
                method.hash(state);
            }
            // All other variants have no data or are primitives
            _ => {}
        }
    }
}

impl CilFlavor {
    /// Checks if this type flavor is a primitive type with direct runtime support.
    ///
    /// Primitive types are built into the .NET runtime and have optimized handling.
    /// This includes all basic value types, the object and string reference types.
    ///
    /// ## Returns
    ///
    /// `true` if this is a primitive type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// assert!(CilFlavor::I4.is_primitive());
    /// assert!(CilFlavor::String.is_primitive());
    /// assert!(!CilFlavor::Class.is_primitive());
    /// ```
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            CilFlavor::Void
                | CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::Object
                | CilFlavor::String
        )
    }

    /// Checks if this type flavor represents a value type.
    ///
    /// Value types are typically allocated on the stack (for locals) or inline within
    /// objects and have value semantics (copying creates a new instance).
    ///
    /// ## Returns
    ///
    /// `true` if this is a value type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// assert!(CilFlavor::I4.is_value_type());
    /// assert!(CilFlavor::Boolean.is_value_type());
    /// assert!(!CilFlavor::String.is_value_type()); // String is a reference type
    /// assert!(!CilFlavor::Class.is_value_type());
    /// ```
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::ValueType
        )
    }

    /// Checks if this type flavor represents a reference type.
    ///
    /// Reference types are allocated on the managed heap and have reference semantics
    /// (copying creates a new reference to the same object). The garbage collector
    /// manages their memory.
    ///
    /// ## Returns
    ///
    /// `true` if this is a reference type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
    ///
    /// assert!(CilFlavor::String.is_reference_type());
    /// assert!(CilFlavor::Object.is_reference_type());
    /// assert!(CilFlavor::Class.is_reference_type());
    ///
    /// let array_type = CilFlavor::Array {
    ///     element_type: Box::new(CilFlavor::I4),
    ///     rank: 1,
    ///     dimensions: vec![ArrayDimensions::default()],
    /// };
    /// assert!(array_type.is_reference_type());
    ///
    /// assert!(!CilFlavor::I4.is_reference_type()); // int is a value type
    /// ```
    #[must_use]
    pub fn is_reference_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Object | CilFlavor::String | CilFlavor::Class | CilFlavor::Array { .. }
        )
    }

    /// Try to convert to a `CilPrimitive` if this is a primitive type
    #[must_use]
    pub fn to_primitive_kind(&self) -> Option<CilPrimitiveKind> {
        match self {
            CilFlavor::Void => Some(CilPrimitiveKind::Void),
            CilFlavor::Boolean => Some(CilPrimitiveKind::Boolean),
            CilFlavor::Char => Some(CilPrimitiveKind::Char),
            CilFlavor::I1 => Some(CilPrimitiveKind::I1),
            CilFlavor::U1 => Some(CilPrimitiveKind::U1),
            CilFlavor::I2 => Some(CilPrimitiveKind::I2),
            CilFlavor::U2 => Some(CilPrimitiveKind::U2),
            CilFlavor::I4 => Some(CilPrimitiveKind::I4),
            CilFlavor::U4 => Some(CilPrimitiveKind::U4),
            CilFlavor::I8 => Some(CilPrimitiveKind::I8),
            CilFlavor::U8 => Some(CilPrimitiveKind::U8),
            CilFlavor::R4 => Some(CilPrimitiveKind::R4),
            CilFlavor::R8 => Some(CilPrimitiveKind::R8),
            CilFlavor::I => Some(CilPrimitiveKind::I),
            CilFlavor::U => Some(CilPrimitiveKind::U),
            CilFlavor::Object => Some(CilPrimitiveKind::Object),
            CilFlavor::String => Some(CilPrimitiveKind::String),
            CilFlavor::ValueType => Some(CilPrimitiveKind::ValueType),
            CilFlavor::GenericParameter { method, .. } => {
                if *method {
                    Some(CilPrimitiveKind::MVar)
                } else {
                    Some(CilPrimitiveKind::Var)
                }
            }
            _ => None,
        }
    }

    /// Check if this flavor is compatible with (assignable to) the target flavor
    ///
    /// Implements .NET primitive type compatibility rules including:
    /// - Exact type matching
    /// - Primitive widening conversions (byte -> int -> long, etc.)
    /// - Reference type compatibility
    ///
    /// # Arguments
    /// * `target` - The target flavor to check compatibility against
    ///
    /// # Returns
    /// `true` if this flavor can be assigned to the target flavor
    #[must_use]
    pub fn is_compatible_with(&self, target: &CilFlavor) -> bool {
        // Exact match
        if self == target {
            return true;
        }

        // Primitive widening rules
        #[allow(clippy::match_same_arms)]
        match (self, target) {
            // Same-size signed/unsigned integers are storage-compatible
            // (important for array element storage)
            (CilFlavor::I1, CilFlavor::U1) | (CilFlavor::U1, CilFlavor::I1) => true,
            (CilFlavor::I2, CilFlavor::U2) | (CilFlavor::U2, CilFlavor::I2) => true,
            (CilFlavor::I4, CilFlavor::U4) | (CilFlavor::U4, CilFlavor::I4) => true,
            (CilFlavor::I8, CilFlavor::U8) | (CilFlavor::U8, CilFlavor::I8) => true,

            // Stack normalization: CIL stack uses I4/I8/F for all smaller types
            // stelem.i1/i2 expect I4 on stack and truncate during store
            // Char is a 2-byte unsigned value, equivalent to U2 for storage purposes
            (
                CilFlavor::I4,
                CilFlavor::I1 | CilFlavor::U1 | CilFlavor::I2 | CilFlavor::U2 | CilFlavor::Char,
            ) => true,

            // Bool is a 1-byte value, I4 on the stack
            (CilFlavor::I4, CilFlavor::Boolean) => true,

            // Integer widening: smaller -> larger
            (CilFlavor::I1 | CilFlavor::U1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float widening: float -> double
            (CilFlavor::R4, CilFlavor::R8) => true,

            // Integer to float (with potential precision loss)
            (
                CilFlavor::I1 | CilFlavor::U1 | CilFlavor::I2 | CilFlavor::U2 | CilFlavor::I4,
                CilFlavor::R4 | CilFlavor::R8,
            ) => true,
            (CilFlavor::I8 | CilFlavor::U4 | CilFlavor::U8, CilFlavor::R8) => true,

            // Any reference type to Object
            (source, CilFlavor::Object) if source.is_reference_type() => true,

            // All value types are compatible with ValueType
            (source, CilFlavor::ValueType) if source.is_value_type() => true,

            // Generic type parameters - be permissive since we don't have runtime type
            // substitution. This allows operations like unbox/castclass to succeed when
            // the target is a generic method parameter (TM0, TM1, etc.)
            (_, CilFlavor::GenericParameter { .. }) => true,
            (CilFlavor::GenericParameter { .. }, _) => true,

            _ => false,
        }
    }

    /// Check if this flavor can accept a constant of the given flavor
    ///
    /// This is more restrictive than general compatibility as constants
    /// require exact matches or safe widening conversions only.
    ///
    /// # Arguments
    /// * `constant_flavor` - The flavor of the constant value
    ///
    /// # Returns
    /// `true` if a constant of the given flavor can be assigned to this type
    #[must_use]
    pub fn accepts_constant(&self, constant_flavor: &CilFlavor) -> bool {
        // Exact match is always allowed
        if self == constant_flavor {
            return true;
        }

        // For constants, we're more restrictive - only safe widening
        #[allow(clippy::match_same_arms)]
        match (constant_flavor, self) {
            // Integer literal widening (safe)
            (CilFlavor::I1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer literal widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float literal widening
            (CilFlavor::R4, CilFlavor::R8) => true,

            // String constants to Object
            (CilFlavor::String, CilFlavor::Object) => true,

            // Null constant to any reference type
            // Note: This would need special handling for null literals
            _ => false,
        }
    }

    /// Check if a value of the given flavor is compatible for stack/local storage.
    ///
    /// This implements CIL stack normalization rules where smaller types widen
    /// to larger stack types during emulation. Used for type checking in local
    /// variables and arguments.
    ///
    /// # Arguments
    /// * `value_flavor` - The flavor of the value being stored
    ///
    /// # Returns
    /// `true` if a value of the given flavor can be stored in a slot of this type
    #[must_use]
    pub fn is_stack_assignable_from(&self, value_flavor: &CilFlavor) -> bool {
        // Exact match is always allowed
        if self == value_flavor {
            return true;
        }

        match (self, value_flavor) {
            // Small integers widen to I4 on the stack
            (
                CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::Boolean
                | CilFlavor::Char,
                CilFlavor::I4,
            )
            // Reference types, managed pointers, and arrays are all compatible with Object
            | (
                CilFlavor::Object
                | CilFlavor::String
                | CilFlavor::Class
                | CilFlavor::Interface
                | CilFlavor::ByRef
                | CilFlavor::Array { .. },
                CilFlavor::Object,
            )
            // Object is compatible with reference types, managed pointers, and arrays
            | (
                CilFlavor::Object,
                CilFlavor::String
                | CilFlavor::Class
                | CilFlavor::Interface
                | CilFlavor::ByRef
                | CilFlavor::Array { .. },
            )
            // Unmanaged pointer compatible with native integers (IntPtr/UIntPtr)
            // This is common in low-level code and P/Invoke scenarios
            | (CilFlavor::Pointer, CilFlavor::I | CilFlavor::U)
            | (CilFlavor::I | CilFlavor::U, CilFlavor::Pointer)
            // Native integers are compatible with each other (sign doesn't matter for storage)
            | (CilFlavor::I, CilFlavor::U)
            | (CilFlavor::U, CilFlavor::I)
            // Generic type parameters are compatible with any type since we don't have
            // runtime type substitution. This allows storing values in locals typed as
            // generic method parameters (TM0, TM1, etc.)
            | (CilFlavor::GenericParameter { .. }, _)
            | (_, CilFlavor::GenericParameter { .. }) => true,

            _ => false,
        }
    }

    /// Returns a static string representation of this CIL flavor.
    ///
    /// This is useful for error messages and diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            CilFlavor::Void => "void",
            CilFlavor::Boolean => "bool",
            CilFlavor::Char => "char",
            CilFlavor::I1 => "int8",
            CilFlavor::U1 => "uint8",
            CilFlavor::I2 => "int16",
            CilFlavor::U2 => "uint16",
            CilFlavor::I4 => "int32",
            CilFlavor::U4 => "uint32",
            CilFlavor::I8 => "int64",
            CilFlavor::U8 => "uint64",
            CilFlavor::R4 => "float32",
            CilFlavor::R8 => "float64",
            CilFlavor::I => "native int",
            CilFlavor::U => "native uint",
            CilFlavor::Object => "object",
            CilFlavor::String => "string",
            CilFlavor::Pointer => "ptr",
            CilFlavor::ByRef => "byref",
            CilFlavor::ValueType => "valuetype",
            CilFlavor::Class => "class",
            CilFlavor::Interface => "interface",
            CilFlavor::Array { .. } => "array",
            CilFlavor::GenericInstance => "generic",
            CilFlavor::GenericParameter { .. } => "typeparam",
            CilFlavor::TypedRef { .. } => "typedref",
            CilFlavor::FnPtr { .. } => "fnptr",
            CilFlavor::Pinned => "pinned",
            CilFlavor::Unknown => "unknown",
        }
    }

    /// Returns the size in bytes of a single element of this type flavor.
    ///
    /// This is used for array initialization to determine how many bytes to read
    /// from the PE file for each array element.
    ///
    /// # Arguments
    ///
    /// * `ptr_size` - The target pointer size, used for native int/uint types.
    ///
    /// # Returns
    ///
    /// The size in bytes, or `None` for types without a fixed size (objects, arrays, etc.)
    #[must_use]
    pub fn element_size(&self, ptr_size: PointerSize) -> Option<usize> {
        match self {
            CilFlavor::Boolean | CilFlavor::I1 | CilFlavor::U1 => Some(1),
            CilFlavor::Char | CilFlavor::I2 | CilFlavor::U2 => Some(2),
            CilFlavor::I4 | CilFlavor::U4 | CilFlavor::R4 => Some(4),
            CilFlavor::I8 | CilFlavor::U8 | CilFlavor::R8 => Some(8),
            CilFlavor::I | CilFlavor::U => Some(ptr_size.bytes()),
            // Reference types and complex types don't have a fixed byte size
            _ => None,
        }
    }

    /// Returns the size in bytes of this type flavor, if it has a fixed size.
    ///
    /// Returns `Some(n)` for primitive types and `Void`. Returns `None` for
    /// `ValueType` (needs `ClassLayout`), `FnPtr`, and all reference/complex types
    /// since their size depends on context.
    ///
    /// # Arguments
    ///
    /// * `ptr_size` - The target pointer size, used for native int/uint and reference types.
    #[must_use]
    pub fn byte_size(&self, ptr_size: PointerSize) -> Option<usize> {
        match self {
            CilFlavor::Void => Some(0),
            CilFlavor::Boolean | CilFlavor::I1 | CilFlavor::U1 => Some(1),
            CilFlavor::Char | CilFlavor::I2 | CilFlavor::U2 => Some(2),
            CilFlavor::I4 | CilFlavor::U4 | CilFlavor::R4 => Some(4),
            CilFlavor::I8 | CilFlavor::U8 | CilFlavor::R8 => Some(8),
            CilFlavor::I | CilFlavor::U => Some(ptr_size.bytes()),
            CilFlavor::TypedRef { .. } => Some(ptr_size.bytes().saturating_mul(2)),
            // Reference types are pointer-sized
            CilFlavor::Object
            | CilFlavor::String
            | CilFlavor::Class
            | CilFlavor::Interface
            | CilFlavor::Array { .. }
            | CilFlavor::Pointer
            | CilFlavor::ByRef
            | CilFlavor::GenericInstance => Some(ptr_size.bytes()),
            // ValueType, FnPtr, GenericParameter, Pinned, Unknown - context-dependent
            _ => None,
        }
    }
}

impl From<CilPrimitiveKind> for CilFlavor {
    fn from(kind: CilPrimitiveKind) -> Self {
        match kind {
            CilPrimitiveKind::Void => CilFlavor::Void,
            CilPrimitiveKind::Boolean => CilFlavor::Boolean,
            CilPrimitiveKind::Char => CilFlavor::Char,
            CilPrimitiveKind::I1 => CilFlavor::I1,
            CilPrimitiveKind::U1 => CilFlavor::U1,
            CilPrimitiveKind::I2 => CilFlavor::I2,
            CilPrimitiveKind::U2 => CilFlavor::U2,
            CilPrimitiveKind::I4 => CilFlavor::I4,
            CilPrimitiveKind::U4 => CilFlavor::U4,
            CilPrimitiveKind::I8 => CilFlavor::I8,
            CilPrimitiveKind::U8 => CilFlavor::U8,
            CilPrimitiveKind::R4 => CilFlavor::R4,
            CilPrimitiveKind::R8 => CilFlavor::R8,
            CilPrimitiveKind::I => CilFlavor::I,
            CilPrimitiveKind::U => CilFlavor::U,
            CilPrimitiveKind::Object => CilFlavor::Object,
            CilPrimitiveKind::String => CilFlavor::String,
            CilPrimitiveKind::ValueType => CilFlavor::ValueType,
            CilPrimitiveKind::Var => CilFlavor::GenericParameter {
                index: 0,
                method: false,
            },
            CilPrimitiveKind::MVar => CilFlavor::GenericParameter {
                index: 0,
                method: true,
            },
            CilPrimitiveKind::Null => CilFlavor::Object,
            CilPrimitiveKind::TypedReference => CilFlavor::TypedRef { target_type: None },
            CilPrimitiveKind::Class => CilFlavor::Class,
        }
    }
}

impl TryFrom<CilFlavor> for CilPrimitiveKind {
    type Error = ();

    fn try_from(flavor: CilFlavor) -> std::result::Result<Self, Self::Error> {
        flavor.to_primitive_kind().ok_or(())
    }
}

impl fmt::Display for CilFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Converts a type signature to the corresponding CIL flavor.
///
/// This implementation maps metadata type signatures to their runtime type flavors,
/// enabling type-aware emulation and analysis. The conversion follows ECMA-335 type
/// semantics.
impl From<&TypeSignature> for CilFlavor {
    fn from(sig: &TypeSignature) -> Self {
        match sig {
            // Void and sentinel (boundary between fixed and variable args in vararg calls)
            TypeSignature::Void | TypeSignature::Sentinel => CilFlavor::Void,

            // Primitive types
            TypeSignature::Boolean => CilFlavor::Boolean,
            TypeSignature::Char => CilFlavor::Char,
            TypeSignature::I1 => CilFlavor::I1,
            TypeSignature::U1 => CilFlavor::U1,
            TypeSignature::I2 => CilFlavor::I2,
            TypeSignature::U2 => CilFlavor::U2,
            TypeSignature::I4 => CilFlavor::I4,
            TypeSignature::U4 => CilFlavor::U4,
            TypeSignature::I8 => CilFlavor::I8,
            TypeSignature::U8 => CilFlavor::U8,
            TypeSignature::R4 => CilFlavor::R4,
            TypeSignature::R8 => CilFlavor::R8,
            TypeSignature::I => CilFlavor::I,
            TypeSignature::U => CilFlavor::U,

            // Reference types
            TypeSignature::String => CilFlavor::String,
            // Object and boxed value types are both treated as Object
            TypeSignature::Object | TypeSignature::Boxed => CilFlavor::Object,
            // Class references and System.Type in custom attributes
            TypeSignature::Class(_) | TypeSignature::Type => CilFlavor::Class,
            TypeSignature::ValueType(_) => CilFlavor::ValueType,

            // Pointer and reference types
            TypeSignature::Ptr(_) => CilFlavor::Pointer,
            TypeSignature::ByRef(_) => CilFlavor::ByRef,

            // Special types - TypedByRef doesn't carry target type info in signature
            TypeSignature::TypedByRef => CilFlavor::TypedRef { target_type: None },

            // Function pointer - carry the full signature
            TypeSignature::FnPtr(method_sig) => CilFlavor::FnPtr {
                signature: method_sig.clone(),
            },

            // Single-dimensional zero-based array
            TypeSignature::SzArray(sz_arr) => CilFlavor::Array {
                element_type: Box::new(CilFlavor::from(sz_arr.base.as_ref())),
                rank: 1,
                dimensions: vec![],
            },

            // Multi-dimensional array with dimensions
            TypeSignature::Array(arr) => CilFlavor::Array {
                element_type: Box::new(CilFlavor::from(arr.base.as_ref())),
                rank: arr.rank,
                dimensions: arr
                    .dimensions
                    .iter()
                    .map(|dim| ArrayDimensions {
                        size: dim.size,
                        lower_bound: dim.lower_bound,
                    })
                    .collect(),
            },

            // Generic instantiation
            TypeSignature::GenericInst(_, _) => CilFlavor::GenericInstance,

            // Generic type parameter (from enclosing type)
            TypeSignature::GenericParamType(index) => CilFlavor::GenericParameter {
                method: false,
                index: *index,
            },

            // Generic method parameter (from enclosing method)
            TypeSignature::GenericParamMethod(index) => CilFlavor::GenericParameter {
                method: true,
                index: *index,
            },

            // Pinned type - recurse to get the underlying flavor, then wrap
            TypeSignature::Pinned(inner) => {
                // For pinned types, we preserve the inner type's flavor but mark as pinned
                // The CilFlavor::Pinned variant exists for this purpose
                let inner_flavor = CilFlavor::from(inner.as_ref());
                // If the inner is already a simple type, we could just return Pinned
                // But since we want to preserve semantics, we return the inner flavor
                // The pinned nature is more about memory management than type identity
                match inner_flavor {
                    CilFlavor::Unknown => CilFlavor::Pinned,
                    _ => inner_flavor,
                }
            }

            // Custom modifiers - these don't carry the base type, just modifier metadata
            // They appear in signature parsing context where the actual type comes separately
            TypeSignature::ModifiedRequired(_) | TypeSignature::ModifiedOptional(_) => {
                CilFlavor::Unknown
            }

            // Fallback/unknown: Unknown, Internal CLI types, Modifier marker,
            // Reserved for future use, and Field signature marker
            TypeSignature::Unknown
            | TypeSignature::Internal
            | TypeSignature::Modifier
            | TypeSignature::Reserved
            | TypeSignature::Field => CilFlavor::Unknown,
        }
    }
}

/// Target pointer width for native int/uint types.
///
/// Re-exported from `analyssa::PointerSize`. The implementation moved to analyssa
/// so the IR core's generic arithmetic methods (which need pointer-width
/// masking) don't have to depend on `dotscope::metadata`.
///
/// Per ECMA-335, `native int` and `native uint` (`System.IntPtr` /
/// `System.UIntPtr`) are pointer-sized: 4 bytes on PE32, 8 bytes on PE32+.
/// Use [`PointerSize::from_is_64bit`] to derive from the PE header.
pub use analyssa::PointerSize;

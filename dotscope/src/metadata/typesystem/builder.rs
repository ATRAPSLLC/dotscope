//! # Type Builder
//!
//! This module provides the [`TypeBuilder`] struct, which offers a fluent API for constructing
//! complex .NET type specifications through a builder pattern. The builder enables the creation
//! of various types including primitives, classes, value types, interfaces, pointers, arrays,
//! and generic types while ensuring proper registration in the [`TypeRegistry`].
//!
//! ## Overview
//!
//! The [`TypeBuilder`] is designed to simplify the creation of type specifications commonly
//! found in .NET metadata. It provides a chainable interface that allows you to:
//!
//! - Create primitive types (integers, floats, etc.)
//! - Build complex reference types (classes, interfaces)
//! - Construct value types (structs, enums)
//! - Add type modifiers (pointers, references, arrays)
//! - Handle generic type instantiations
//! - Apply type constraints and modifiers
//!
//! ## Builder Pattern
//!
//! The builder uses a fluent interface where most methods return `Self`, allowing for method
//! chaining. The builder maintains state about the current type being constructed and can
//! apply various transformations.
//!
//! ## Usage Examples
//!
//! ### Basic Types
//!
//! ```rust
//! use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
//! let registry = Arc::new(TypeRegistry::new(identity)?);
//!
//! // Create a simple integer type
//! let int_type = TypeBuilder::new(registry.clone())
//!     .primitive(CilPrimitiveKind::I4)?
//!     .build()?;
//!
//! // Create a string class
//! let string_type = TypeBuilder::new(registry.clone())
//!     .class("System", "String")?
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Complex Types
//!
//! ```rust
//! # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
//! # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//! # use std::sync::Arc;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
//! # let registry = Arc::new(TypeRegistry::new(identity)?);
//! // Create an array of integers: int[]
//! let int_array = TypeBuilder::new(registry.clone())
//!     .primitive(CilPrimitiveKind::I4)?
//!     .array()?
//!     .build()?;
//!
//! // Create a pointer to an integer: int*
//! let int_pointer = TypeBuilder::new(registry.clone())
//!     .primitive(CilPrimitiveKind::I4)?
//!     .pointer()?
//!     .build()?;
//!
//! // Create a reference to a string: ref string
//! let string_ref = TypeBuilder::new(registry.clone())
//!     .class("System", "String")?
//!     .by_ref()?
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Generic Types
//!
//! Generic type construction requires specifying the type arguments through a builder closure.
//! The API has evolved to provide better type safety and memory management for complex generic
//! instantiations.
//!
//! ## Type Context
//!
//! The builder maintains context about where types are being created through the [`TypeSource`]
//! which helps with resolution and proper metadata references.
//!
//! ## Thread Safety
//!
//! The [`TypeBuilder`] is designed to work with the thread-safe [`TypeRegistry`] and can be
//! used safely across multiple threads when the underlying registry supports it.
//!
//! ## References
//!
//! - [`crate::metadata::typesystem::TypeRegistry`] - Type storage and retrieval
//! - [`crate::metadata::typesystem::CilFlavor`] - Type categorization
//! - [ECMA-335 §I.8 - Common Type System](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//!
//! [`TypeRegistry`]: crate::metadata::typesystem::TypeRegistry
//! [`TypeSource`]: crate::metadata::typesystem::TypeSource

use std::sync::Arc;

use crate::{
    metadata::{
        signatures::{SignatureMethod, SignatureMethodSpec},
        tables::MethodSpec,
        token::Token,
        typesystem::{
            CilFlavor, CilModifier, CilPrimitiveKind, CilTypeRc, CilTypeReference,
            CompleteTypeSpec, TypeRegistry, TypeResolver, TypeSource,
        },
    },
    Error::TypeError,
    Result,
};

/// A fluent builder for constructing .NET type specifications.
///
/// This struct provides a chainable interface for building complex type specifications
/// from simple primitives to complex constructed types like generics, arrays, and pointers.
/// The builder maintains state about the current type being constructed and provides
/// methods to apply various type transformations.
///
/// ## State Management
///
/// The builder maintains several pieces of state:
/// - **Registry**: Reference to the type registry for type storage/retrieval
/// - **Source Context**: Information about where the type is being created
/// - **Current Type**: The type currently being built (if any)
/// - **Initial Token**: Optional token for the root type being constructed
///
/// ## Usage Pattern
///
/// 1. Create a builder with [`TypeBuilder::new()`]
/// 2. Optionally set context with [`with_source()`](Self::with_source) or [`with_token_init()`](Self::with_token_init)
/// 3. Start with a base type (primitive, class, value type, interface)
/// 4. Apply transformations (pointer, array, generic instantiation, etc.)
/// 5. Build the final type with [`build()`](Self::build)
///
/// ## Example
///
/// ```rust
/// use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
/// use dotscope::metadata::identity::AssemblyIdentity;
/// use std::sync::Arc;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
/// let registry = Arc::new(TypeRegistry::new(test_identity)?);
///
/// // Build int**[] (array of pointers to pointers to int)
/// let complex_type = TypeBuilder::new(registry)
///     .primitive(CilPrimitiveKind::I4)?    // Start with int
///     .pointer()?                           // Make it int*
///     .pointer()?                           // Make it int**
///     .array()?                            // Make it int**[]
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Thread Safety
///
/// [`TypeBuilder`] itself is not `Send` or `Sync` as it maintains mutable state during
/// construction. However, it works with the thread-safe [`TypeRegistry`] for the actual
/// type storage.
///
/// [`TypeRegistry`]: crate::metadata::typesystem::TypeRegistry
pub struct TypeBuilder {
    /// Reference to the type registry for storing and retrieving type instances.
    ///
    /// The registry provides centralized storage for all types and ensures
    /// that equivalent types share the same instance (type identity).
    registry: Arc<TypeRegistry>,

    /// Source context indicating where this type is being created.
    ///
    /// This helps with type resolution and determines how relative references
    /// should be interpreted (e.g., current module vs. external assembly).
    source: TypeSource,

    /// The type currently being constructed by this builder.
    ///
    /// Starts as `None` and gets populated when a base type is created
    /// (primitive, class, etc.). Subsequent operations transform this type.
    current_type: Option<CilTypeRc>,

    /// Optional token for the initial/root type being constructed.
    ///
    /// Used to associate the constructed type with a specific metadata
    /// table entry, enabling proper cross-references in the metadata.
    token_init: Option<Token>,
}

impl TypeBuilder {
    /// Creates a new type builder with the specified type registry.
    ///
    /// The builder is initialized with default settings:
    /// - Source context set to the current assembly ([`TypeSource::Assembly`])
    /// - No current type (must be set with a base type method)
    /// - No initial token
    ///
    /// ## Arguments
    ///
    /// * `registry` - Shared reference to the type registry where types will be stored
    ///
    /// ## Returns
    ///
    /// A new [`TypeBuilder`] instance ready for use.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry};
    /// use dotscope::metadata::identity::AssemblyIdentity;
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
    /// let registry = Arc::new(TypeRegistry::new(test_identity)?);
    /// let builder = TypeBuilder::new(registry);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(registry: Arc<TypeRegistry>) -> Self {
        let source = registry.current_assembly_source();
        TypeBuilder {
            registry,
            source,
            current_type: None,
            token_init: None,
        }
    }

    /// Sets the source context for type resolution.
    ///
    /// The source context determines how the builder should interpret type references
    /// and where to look for type definitions. This affects how relative type names
    /// are resolved and which assemblies are searched.
    ///
    /// ## Arguments
    ///
    /// * `source` - The [`TypeSource`] context to use for type resolution
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, TypeSource};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use dotscope::metadata::token::Token;
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// let builder = TypeBuilder::new(registry)
    ///     .with_source(TypeSource::Module(Token::new(0x26000001)));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`TypeSource`]: crate::metadata::typesystem::TypeSource
    #[must_use]
    pub fn with_source(mut self, source: TypeSource) -> Self {
        self.source = source;
        self
    }

    /// Sets the initial token for the root type being constructed.
    ///
    /// This associates the type being built with a specific metadata table entry,
    /// which is important for maintaining proper cross-references in the metadata
    /// and ensuring that the type can be properly resolved later.
    ///
    /// ## Arguments
    ///
    /// * `token` - The [`crate::metadata::token::Token`] representing the metadata table entry for this type
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry};
    /// # use dotscope::metadata::token::Token;
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// # let token = Token::new(0x02000001); // TypeDef token
    /// let builder = TypeBuilder::new(registry)
    ///     .with_token_init(token);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    #[must_use]
    pub fn with_token_init(mut self, token: Token) -> Self {
        self.token_init = Some(token);
        self
    }

    /// Starts building with a primitive type as the base.
    ///
    /// Primitive types are the built-in types provided by the .NET runtime,
    /// such as integers, floating-point numbers, booleans, and characters.
    /// This method retrieves the appropriate primitive type from the registry.
    ///
    /// ## Arguments
    ///
    /// * `primitive` - The [`CilPrimitiveKind`] specifying which primitive type to use
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the primitive
    /// type cannot be retrieved from the registry.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if the primitive type is not available in the registry.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create a 32-bit signed integer type
    /// let int_type = TypeBuilder::new(registry.clone())
    ///     .primitive(CilPrimitiveKind::I4)?
    ///     .build()?;
    ///
    /// // Create a string type
    /// let string_type = TypeBuilder::new(registry)
    ///     .primitive(CilPrimitiveKind::String)?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`CilPrimitiveKind`]: crate::metadata::typesystem::CilPrimitiveKind
    /// [`TypeError`]: crate::Error::TypeError
    pub fn primitive(mut self, primitive: CilPrimitiveKind) -> Result<Self> {
        self.current_type = Some(self.registry.get_primitive(primitive)?);
        Ok(self)
    }

    /// Starts building with a reference type (class) as the base.
    ///
    /// Classes are reference types that are allocated on the managed heap and support
    /// inheritance. This method creates or retrieves a class type with the specified
    /// namespace and name from the registry.
    ///
    /// ## Arguments
    ///
    /// * `namespace` - The namespace containing the class (e.g., "System")
    /// * `name` - The name of the class (e.g., "String")
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the class
    /// type cannot be created or retrieved.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if the class type cannot be created or found in the registry.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create a System.String class type
    /// let string_type = TypeBuilder::new(registry.clone())
    ///     .class("System", "String")?
    ///     .build()?;
    ///
    /// // Create a custom class
    /// let custom_type = TypeBuilder::new(registry)
    ///     .class("MyNamespace", "MyClass")?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`TypeError`]: crate::Error::TypeError
    pub fn class(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(&CompleteTypeSpec {
            token_init: self.token_init.take(),
            flavor: CilFlavor::Class,
            namespace: namespace.to_string(),
            name: name.to_string(),
            source: self.source.clone(),
            generic_args: None,
            base_type: None,
            flags: None,
        })?);
        Ok(self)
    }

    /// Starts building with a value type (struct) as the base.
    ///
    /// Value types are typically allocated on the stack or inline within objects
    /// and have value semantics (copying creates a new instance). This method
    /// creates or retrieves a value type with the specified namespace and name.
    ///
    /// ## Arguments
    ///
    /// * `namespace` - The namespace containing the value type (e.g., "System")
    /// * `name` - The name of the value type (e.g., "Int32")
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the value type
    /// cannot be created or retrieved.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if the value type cannot be created or found in the registry.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create a System.DateTime value type
    /// let datetime_type = TypeBuilder::new(registry.clone())
    ///     .value_type("System", "DateTime")?
    ///     .build()?;
    ///
    /// // Create a custom struct
    /// let point_type = TypeBuilder::new(registry)
    ///     .value_type("MyNamespace", "Point")?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`TypeError`]: crate::Error::TypeError
    pub fn value_type(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(&CompleteTypeSpec {
            token_init: self.token_init.take(),
            flavor: CilFlavor::ValueType,
            namespace: namespace.to_string(),
            name: name.to_string(),
            source: self.source.clone(),
            generic_args: None,
            base_type: None,
            flags: None,
        })?);
        Ok(self)
    }

    /// Starts building with an interface type as the base.
    ///
    /// Interfaces define contracts that can be implemented by classes and structs.
    /// They specify method signatures, properties, and events that implementing
    /// types must provide. This method creates or retrieves an interface type
    /// with the specified namespace and name.
    ///
    /// ## Arguments
    ///
    /// * `namespace` - The namespace containing the interface (e.g., "System.Collections")
    /// * `name` - The name of the interface (e.g., `IEnumerable`)
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the interface
    /// type cannot be created or retrieved.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if the interface type cannot be created or found in the registry.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create IDisposable interface
    /// let disposable_interface = TypeBuilder::new(registry.clone())
    ///     .interface("System", "IDisposable")?
    ///     .build()?;
    ///
    /// // Create a custom interface
    /// let custom_interface = TypeBuilder::new(registry)
    ///     .interface("MyNamespace", "IMyInterface")?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`TypeError`]: crate::Error::TypeError
    pub fn interface(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(&CompleteTypeSpec {
            token_init: self.token_init.take(),
            flavor: CilFlavor::Interface,
            namespace: namespace.to_string(),
            name: name.to_string(),
            source: self.source.clone(),
            generic_args: None,
            base_type: None,
            flags: None,
        })?);
        Ok(self)
    }

    /// Creates a pointer type to the current type.
    ///
    /// This method transforms the current type into an unmanaged pointer type.
    /// Pointer types are used for unsafe operations and interop scenarios where
    /// direct memory access is required. The resulting type represents a pointer
    /// to the base type (e.g., `int*` for a pointer to `int`).
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the pointer
    /// type cannot be created.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if:
    /// - No current type is set (must call a base type method first)
    /// - The pointer type cannot be created in the registry
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create int* (pointer to int)
    /// let int_ptr = TypeBuilder::new(registry.clone())
    ///     .primitive(CilPrimitiveKind::I4)?
    ///     .pointer()?
    ///     .build()?;
    ///
    /// // Create char** (pointer to pointer to char)
    /// let char_ptr_ptr = TypeBuilder::new(registry)
    ///     .primitive(CilPrimitiveKind::Char)?
    ///     .pointer()?
    ///     .pointer()?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Safety
    ///
    /// Pointer types are inherently unsafe and should only be used when necessary
    /// for interop or performance-critical scenarios.
    ///
    /// [`TypeError`]: crate::Error::TypeError
    pub fn pointer(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let ptr_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::Pointer,
                namespace: base_type.namespace.clone(),
                name: format!("{}*", base_type.name),
                source: self.source.clone(),
                generic_args: None,
                base_type: Some(base_type),
                flags: None,
            })?;

            self.current_type = Some(ptr_type);
        }
        Ok(self)
    }

    /// Create a by-reference version of the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the by-reference type cannot be created.
    pub fn by_ref(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("{}&", base_type.name);
            let namespace = base_type.namespace.clone();

            let ref_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::ByRef,
                namespace: namespace.clone(),
                name,
                source: self.source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })?;

            ref_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("ByRef type base already set"))?;
            self.current_type = Some(ref_type);
        }
        Ok(self)
    }

    /// Create a pinned version of the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the pinned type cannot be created.
    pub fn pinned(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("pinned {}", base_type.name);
            let namespace = base_type.namespace.clone();

            let pinned_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::Pinned,
                namespace: namespace.clone(),
                name,
                source: self.source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })?;

            pinned_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Pinned type base already set"))?;
            self.current_type = Some(pinned_type);
        }
        Ok(self)
    }

    /// Creates a single-dimensional array type of the current type.
    ///
    /// This method transforms the current type into a single-dimensional array type
    /// with zero-based indexing (e.g., `int[]` for an array of integers). The array
    /// uses the standard .NET array semantics with automatic bounds checking.
    ///
    /// ## Returns
    ///
    /// The builder instance for method chaining, or an error if the array
    /// type cannot be created.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if:
    /// - No current type is set (must call a base type method first)
    /// - The array type cannot be created in the registry
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Create int[] (array of integers)
    /// let int_array = TypeBuilder::new(registry.clone())
    ///     .primitive(CilPrimitiveKind::I4)?
    ///     .array()?
    ///     .build()?;
    ///
    /// // Create string[] (array of strings)
    /// let string_array = TypeBuilder::new(registry.clone())
    ///     .class("System", "String")?
    ///     .array()?
    ///     .build()?;
    ///
    /// // Create int[][] (array of arrays of integers)
    /// let nested_array = TypeBuilder::new(registry)
    ///     .primitive(CilPrimitiveKind::I4)?
    ///     .array()?
    ///     .array()?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Notes
    ///
    /// - Single-dimensional arrays are the most common array type in .NET
    /// - They have zero-based indexing and automatic bounds checking
    /// - For multi-dimensional arrays, use [`multi_dimensional_array()`](Self::multi_dimensional_array)
    ///
    /// [`TypeError`]: crate::Error::TypeError
    pub fn array(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("{}[]", base_type.name);
            let namespace = base_type.namespace.clone();

            let array_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::Array {
                    element_type: Box::new(base_type.flavor().clone()),
                    rank: 1,
                    dimensions: vec![],
                },
                namespace: namespace.clone(),
                name,
                source: self.source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })?;

            array_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Array type base already set"))?;
            self.current_type = Some(array_type);
        }
        Ok(self)
    }

    /// Create a multi-dimensional array of the current type
    ///
    /// ## Arguments
    /// * 'rank' - The dimensions for the array
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the multi-dimensional array type cannot be created.
    pub fn multi_dimensional_array(mut self, rank: u32) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let dimension_part = if rank <= 1 {
                "[]".to_string()
            } else {
                format!("[{}]", ",".repeat((rank as usize).saturating_sub(1)))
            };

            let name = format!("{}{}", base_type.name, dimension_part);
            let namespace = base_type.namespace.clone();

            let array_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::Array {
                    element_type: Box::new(base_type.flavor().clone()),
                    rank,
                    dimensions: vec![],
                },
                namespace: namespace.clone(),
                name,
                source: self.source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })?;

            array_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Multi-dimensional array type base already set"))?;
            self.current_type = Some(array_type);
        }
        Ok(self)
    }

    /// Create or set a function pointer type
    ///
    /// ## Arguments
    /// * 'signature' - Set the signature for the function pointer
    ///
    /// # Errors
    /// Returns an error if the function pointer type cannot be created.
    pub fn function_pointer(mut self, signature: SignatureMethod) -> Result<Self> {
        let name = TypeResolver::format_fnptr_name(&signature);

        let fn_ptr_type = self.registry.get_or_create_type(&CompleteTypeSpec {
            token_init: self.token_init.take(),
            flavor: CilFlavor::FnPtr {
                signature: Box::new(signature),
            },
            namespace: String::new(),
            name,
            source: self.source.clone(),
            generic_args: None,
            base_type: None,
            flags: None,
        })?;

        self.current_type = Some(fn_ptr_type);
        Ok(self)
    }

    /// Add required modifier to the current type
    ///
    /// ## Arguments
    /// * `modifer_token` - Set the modifier token
    ///
    /// # Errors
    /// Returns an error if the modifier cannot be applied (currently always succeeds).
    pub fn required_modifier(self, modifier_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            if let Some(modifier_type) = self.registry.get(&modifier_token) {
                current.modifiers.push(CilModifier {
                    required: true,
                    modifier: modifier_type.into(),
                });
            }
        }
        Ok(self)
    }

    /// Add optional modifier to the current type
    ///
    /// ## Arguments
    /// * `modifer_token` - Set the modifier token
    ///
    /// # Errors
    /// Returns an error if the modifier cannot be applied (currently always succeeds).
    pub fn optional_modifier(self, modifier_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            if let Some(modifier_type) = self.registry.get(&modifier_token) {
                current.modifiers.push(CilModifier {
                    required: false,
                    modifier: modifier_type.into(),
                });
            }
        }
        Ok(self)
    }

    /// Specify a base type for the current type
    ///
    /// ## Arguments
    /// * `base_token` - Set the base of the type
    ///
    /// # Errors
    /// Returns an error if the base type is already set or if the base token cannot be resolved.
    pub fn extends(self, base_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            // Get the base type
            if let Some(base_type) = self.registry.get(&base_token) {
                current
                    .base
                    .set(base_type.into())
                    .map_err(|_| malformed_error!("Base type already set"))?;
            }
        }
        Ok(self)
    }

    /// Create a generic instance of the current type, named as the type is and nested where it
    /// is.
    ///
    /// ## Arguments
    /// * `arg_count`   - Argument count for the generic instance
    /// * `arg_builder` - Builder function for the arguments
    ///
    /// # Errors
    /// Returns an error if the argument builder fails or builds other than `arg_count`
    /// arguments, or if the generic instance type cannot be created.
    pub fn generic_instance<F>(mut self, arg_count: usize, arg_builder: F) -> Result<Self>
    where
        F: FnOnce(Arc<TypeRegistry>) -> Result<Vec<CilTypeRc>>,
    {
        if let Some(base_type) = self.current_type.take() {
            let name = base_type.name.clone();
            let namespace = base_type.namespace.clone();
            let generic_type = self.registry.get_or_create_type(&CompleteTypeSpec {
                token_init: self.token_init.take(),
                flavor: CilFlavor::GenericInstance,
                namespace: namespace.clone(),
                name,
                source: self.source.clone(),
                generic_args: None,
                base_type: None,
                flags: None,
            })?;

            let args = arg_builder(self.registry.clone())?;
            if args.len() != arg_count {
                return Err(malformed_error!(
                    "Generic instance of {} takes {arg_count} arguments, {} were built",
                    base_type.name,
                    args.len()
                ));
            }
            if !args.is_empty() {
                // For type-level generic instances, create MethodSpec instances that wrap the resolved types
                for (index, arg) in args.iter().enumerate() {
                    // Create a dummy method specification for the type argument
                    let rid = u32::try_from(index)
                        .map_err(|_| malformed_error!("Generic argument index too large"))?
                        .checked_add(1)
                        .ok_or_else(|| malformed_error!("Generic argument rid overflow"))?;
                    let token_value =
                        0x2B00_0000_u32
                            .checked_add(u32::try_from(index).map_err(|_| {
                                malformed_error!("Generic argument index too large")
                            })?)
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
                            type_ref_list.push(arg.clone().into());
                            type_ref_list
                        },
                    });
                    generic_type.generic_args.push(method_spec);
                }
            }
            if let Some(enclosing) = base_type.enclosing_type.get() {
                let _ = generic_type.set_enclosing_type(enclosing);
            }
            self.current_type = Some(generic_type);
        }
        Ok(self)
    }

    /// Finalizes the type construction and returns the built type.
    ///
    /// This method completes the type building process and returns the constructed
    /// type specification. It consumes the builder and returns the final type that
    /// was created through the chain of builder method calls.
    ///
    /// ## Returns
    ///
    /// The constructed [`CilTypeRc`] representing the complete type specification,
    /// or an error if the type construction failed.
    ///
    /// ## Errors
    ///
    /// Returns [`TypeError`] if:
    /// - No type has been constructed (no base type method was called)
    /// - The type construction process failed at any step
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
    /// # use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// # use std::sync::Arc;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let identity = AssemblyIdentity::new("TestAssembly", AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// # let registry = Arc::new(TypeRegistry::new(identity)?);
    /// // Build a complete type specification
    /// let array_type = TypeBuilder::new(registry)
    ///     .primitive(CilPrimitiveKind::I4)?  // Start with int
    ///     .pointer()?                        // Make it int*
    ///     .array()?                         // Make it (int*)[]
    ///     .build()?;                        // Finalize
    ///
    /// // The type is now ready for use
    /// println!("Built type: {}.{}", array_type.namespace, array_type.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Notes
    ///
    /// - This method must be called to complete the type construction process
    /// - The builder is consumed by this method and cannot be reused
    /// - The returned type is registered in the type registry and can be retrieved later
    ///
    /// [`CilTypeRc`]: crate::metadata::typesystem::CilTypeRc
    /// [`TypeError`]: crate::Error::TypeError
    pub fn build(self) -> Result<CilTypeRc> {
        match self.current_type {
            Some(t) => Ok(t),
            None => Err(TypeError("Failed to build requested Type".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::{
        metadata::{
            identity::AssemblyIdentity,
            signatures::{SignatureMethod, SignatureParameter, TypeSignature},
            tables::{GenericParam, GenericParamAttributes},
            token::Token,
            typesystem::{CilFlavor, CilPrimitiveKind, TypeRegistry, TypeSource},
        },
        Error,
    };

    #[test]
    fn test_build_primitive() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let int_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.name, "Int32");
        assert_eq!(int_type.namespace, "System");
        assert!(matches!(*int_type.flavor(), CilFlavor::I4));
    }

    #[test]
    fn test_build_pointer() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let int_ptr = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .pointer()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_ptr.name, "Int32*");
        assert!(matches!(*int_ptr.flavor(), CilFlavor::Pointer));

        let base_type = int_ptr.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Int32");
    }

    #[test]
    fn test_build_array() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let string_array = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .array()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(string_array.name, "String[]");
        assert!(matches!(*string_array.flavor(), CilFlavor::Array { .. }));

        let base_type = string_array.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "String");
    }

    #[test]
    fn test_build_multidimensional_array() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let int_2d_array = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .multi_dimensional_array(2)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_2d_array.name, "Int32[,]");

        if let CilFlavor::Array { rank, .. } = *int_2d_array.flavor() {
            assert_eq!(rank, 2);
        } else {
            panic!("Expected Array flavor");
        };
    }

    #[test]
    fn test_build_class() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let list_type = TypeBuilder::new(registry.clone())
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");
        assert!(matches!(*list_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_build_value_type() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let struct_type = TypeBuilder::new(registry.clone())
            .value_type("System", "DateTime")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(struct_type.name, "DateTime");
        assert_eq!(struct_type.namespace, "System");
        assert!(matches!(*struct_type.flavor(), CilFlavor::ValueType));
    }

    #[test]
    fn test_build_interface() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let interface_type = TypeBuilder::new(registry.clone())
            .interface("System.Collections.Generic", "IList`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(interface_type.name, "IList`1");
        assert_eq!(interface_type.namespace, "System.Collections.Generic");
        assert!(matches!(*interface_type.flavor(), CilFlavor::Interface));
    }

    #[test]
    fn test_build_generic_instance() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let list_type = TypeBuilder::new(registry.clone())
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        let generic_param = Arc::new(GenericParam {
            token: Token::new(0x2A000001),
            number: 0,
            flags: GenericParamAttributes::ZERO,
            owner: OnceLock::new(),
            name: "T".to_string(),
            constraints: Default::default(),
            rid: 0,
            offset: 0,
            custom_attributes: Default::default(),
        });

        list_type.generic_params.push(generic_param);

        let list_int_instance = TypeBuilder::new(registry.clone())
            .with_source(TypeSource::Unknown)
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .generic_instance(1, |registry| {
                // Get int type
                let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
                Ok(vec![int_type])
            })
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_int_instance.name, "List`1");
        assert!(matches!(
            *list_int_instance.flavor(),
            CilFlavor::GenericInstance
        ));

        assert_eq!(list_int_instance.generic_args.count(), 1);
        assert_eq!(
            list_int_instance
                .generic_args
                .get(0)
                .unwrap()
                .generic_args
                .get(0)
                .unwrap()
                .name()
                .unwrap(),
            "Int32"
        );
    }

    #[test]
    fn test_build_byref() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let byref_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .by_ref()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(byref_type.name, "Int32&");
        assert!(matches!(*byref_type.flavor(), CilFlavor::ByRef));

        let base_type = byref_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Int32");
    }

    #[test]
    fn test_build_pinned() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let pinned_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::Object)
            .unwrap()
            .pinned()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(pinned_type.name, "pinned Object");
        assert!(matches!(*pinned_type.flavor(), CilFlavor::Pinned));

        let base_type = pinned_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Object");
    }

    #[test]
    fn test_build_function_pointer() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let signature = SignatureMethod {
            has_this: false,
            explicit_this: false,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                base: TypeSignature::Void,
                by_ref: false,
            },
            params: Vec::new(),
            default: false,
            vararg: false,
            cdecl: false,
            stdcall: true,
            thiscall: false,
            fastcall: false,
            unmanaged: false,
            param_count_generic: 0,
            param_count: 0,
            varargs: Vec::new(),
        };

        let fn_ptr = TypeBuilder::new(registry.clone())
            .function_pointer(signature)
            .unwrap()
            .build()
            .unwrap();

        // Name format changed from pointer-based to deterministic signature-based
        assert!(fn_ptr.name.starts_with("FnPtr_"));
        if let CilFlavor::FnPtr { signature: sig } = fn_ptr.flavor() {
            assert!(!sig.has_this);
            assert_eq!(sig.params.len(), 0);
        } else {
            panic!("Expected FnPtr flavor");
        };
    }

    #[test]
    fn test_with_source() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let source = TypeSource::AssemblyRef(Token::new(0x23000001));
        let int_type = TypeBuilder::new(registry.clone())
            .with_source(source)
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.name, "Int32");
    }

    #[test]
    fn test_with_token_init() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let token: Token = Token::new(0x01000999);
        let list_type = TypeBuilder::new(registry.clone())
            .with_token_init(token)
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");
        assert_eq!(list_type.token, token);
        assert!(matches!(*list_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_modifiers() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let in_attr_token = Token::new(0x01000888);
        let _ = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: Some(in_attr_token),
                flavor: CilFlavor::Class,
                namespace: "System.Runtime.InteropServices".to_string(),
                name: "InAttribute".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let int_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .required_modifier(in_attr_token)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.modifiers.count(), 1);
        assert!(int_type.modifiers[0].required);
        assert_eq!(
            int_type.modifiers[0].modifier.name().unwrap(),
            "InAttribute"
        );

        let string_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .optional_modifier(in_attr_token)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(string_type.modifiers.count(), 1);
        assert!(!string_type.modifiers[0].required);
    }

    #[test]
    fn test_extends() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let base_token = Token::new(0x01000777);
        let _ = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: Some(base_token),
                flavor: CilFlavor::Class,
                namespace: "System".to_string(),
                name: "Exception".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let derived_type = TypeBuilder::new(registry.clone())
            .class("System.IO", "IOException")
            .unwrap()
            .extends(base_token)
            .unwrap()
            .build()
            .unwrap();

        let base_type = derived_type.base.get().unwrap().upgrade();
        assert!(base_type.is_some());
        let base_type = base_type.unwrap();
        assert_eq!(base_type.token, base_token);
        assert_eq!(base_type.name, "Exception");
    }

    #[test]
    fn test_build_failure() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        let result = TypeBuilder::new(registry.clone()).build();
        assert!(result.is_err());
        match result {
            Err(Error::TypeError(_)) => (), // Expected error
            _ => panic!("Expected TypeError"),
        }
    }

    #[test]
    fn test_build_complex_chain() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        // Build a complex type chain: string[][]*&
        let complex_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .array()
            .unwrap() // string[]
            .array()
            .unwrap() // string[][]
            .pointer()
            .unwrap() // string[][]*
            .by_ref()
            .unwrap() // string[][]*&
            .build()
            .unwrap();

        assert_eq!(complex_type.name, "String[][]*&");
        assert!(matches!(*complex_type.flavor(), CilFlavor::ByRef));

        let pointer_type = complex_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(pointer_type.name, "String[][]*");
        assert!(matches!(*pointer_type.flavor(), CilFlavor::Pointer));

        let array2d_type = pointer_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(array2d_type.name, "String[][]");

        let array_type = array2d_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(array_type.name, "String[]");

        let string_type = array_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(string_type.name, "String");
    }

    #[test]
    fn test_generic_instance_with_multiple_args() {
        let test_identity = AssemblyIdentity::parse("TestAssembly, Version=1.0.0.0").unwrap();
        let registry = Arc::new(TypeRegistry::new(test_identity).unwrap());

        // Create Dictionary<TKey, TValue> type
        let dict_token = Token::new(0x01000555);
        let dict_type = registry
            .get_or_create_type(&CompleteTypeSpec {
                token_init: Some(dict_token),
                flavor: CilFlavor::Class,
                namespace: "System.Collections.Generic".to_string(),
                name: "Dictionary`2".to_string(),
                source: TypeSource::Unknown,
                generic_args: None,
                base_type: None,
                flags: None,
            })
            .unwrap();

        let key_param = Arc::new(GenericParam {
            token: Token::new(0x2A000002),
            number: 0,
            flags: GenericParamAttributes::ZERO,
            owner: OnceLock::new(),
            name: "TKey".to_string(),
            constraints: Default::default(),
            rid: 0,
            offset: 0,
            custom_attributes: Default::default(),
        });

        let value_param = Arc::new(GenericParam {
            token: Token::new(0x2A000003),
            number: 1,
            flags: GenericParamAttributes::ZERO,
            owner: OnceLock::new(),
            name: "TValue".to_string(),
            constraints: Default::default(),
            rid: 1,
            offset: 1,
            custom_attributes: Default::default(),
        });

        dict_type.generic_params.push(key_param);
        dict_type.generic_params.push(value_param);

        // Create a Dictionary<string, int> instance
        let dict_instance = TypeBuilder::new(registry.clone())
            .with_source(TypeSource::Unknown)
            .class("System.Collections.Generic", "Dictionary`2")
            .unwrap()
            .generic_instance(2, |registry| {
                let string_type = registry.get_primitive(CilPrimitiveKind::String).unwrap();
                let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
                Ok(vec![string_type, int_type])
            })
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(dict_instance.name, "Dictionary`2");
        assert!(matches!(
            *dict_instance.flavor(),
            CilFlavor::GenericInstance
        ));

        assert_eq!(dict_instance.generic_args.count(), 2);
        assert_eq!(
            dict_instance
                .generic_args
                .get(0)
                .unwrap()
                .generic_args
                .get(0)
                .unwrap()
                .name()
                .unwrap(),
            "String"
        );
        assert_eq!(
            dict_instance
                .generic_args
                .get(1)
                .unwrap()
                .generic_args
                .get(0)
                .unwrap()
                .name()
                .unwrap(),
            "Int32"
        );

        // With the simplified approach, we only store the resolved types
        // The order corresponds to the generic parameter order (0=TKey, 1=TValue)
        assert_eq!(
            dict_instance
                .generic_args
                .get(0)
                .unwrap()
                .generic_args
                .get(0)
                .unwrap()
                .name()
                .unwrap(),
            "String"
        ); // TKey -> String
        assert_eq!(
            dict_instance
                .generic_args
                .get(1)
                .unwrap()
                .generic_args
                .get(0)
                .unwrap()
                .name()
                .unwrap(),
            "Int32"
        ); // TValue -> Int32
    }
}

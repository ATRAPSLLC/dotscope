//! High-level method builder for creating complete method definitions.
//!
//! This module provides [`MethodBuilder`] for creating complete method definitions
//! including metadata, signatures, parameters, and implementations. It orchestrates
//! the existing low-level builders to provide a fluent, high-level API.

use crate::{
    cilassembly::{builders::method_body::MethodBodyBuilder, ChangeRefRc, CilAssembly},
    metadata::{
        method::{MethodAccessFlags, MethodImplCodeType, MethodImplOptions, MethodModifiers},
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{MethodDefBuilder, ParamAttributes, ParamBuilder, TableId},
        token::Token,
    },
    Result,
};

/// High-level builder for creating complete method definitions.
///
/// `MethodBuilder` provides a fluent API for creating methods with metadata,
/// signatures, parameters, and implementations. It composes the existing
/// low-level builders ([`crate::metadata::tables::MethodDefBuilder`],
/// [`crate::cilassembly::builders::MethodBodyBuilder`], etc.) to provide
/// a convenient high-level interface.
///
/// # Design
///
/// The builder follows a composition approach:
/// - Uses existing `MethodDefBuilder` for metadata table creation
/// - Uses `MethodBodyBuilder` for CIL implementation
/// - Uses existing signature builders for method signatures
/// - Orchestrates all components through `CilAssembly`
///
/// # Examples
///
/// ## Simple Static Method
///
/// ```rust,no_run
/// use dotscope::prelude::*;
/// use dotscope::MethodBuilder;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = CilAssembly::new(view);
/// let method_token = MethodBuilder::new("Add")
///     .public()
///     .static_method()
///     .parameter("a", TypeSignature::I4)
///     .parameter("b", TypeSignature::I4)
///     .returns(TypeSignature::I4)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             asm.ldarg_0()?
///                .ldarg_1()?
///                .add()?
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Instance Constructor
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let ctor_token = MethodBuilder::constructor()
///     .parameter("name", TypeSignature::String)
///     .parameter("age", TypeSignature::I4)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             // Call base constructor
///             asm.ldarg_0()?  // this
///                .call(Token::new(0x0A000001))? // base ctor token
///                // Initialize fields...
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Property Getter
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let getter_token = MethodBuilder::property_getter("Name", TypeSignature::String)
///     .implementation(|body| {
///         body.implementation(|asm| {
///             asm.ldarg_0()?  // this
///                .ldfld(Token::new(0x04000001))? // field token
///                .ret()?;
///             Ok(())
///         })
///     })
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## P/Invoke Method with Custom Calling Convention
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let pinvoke_token = MethodBuilder::new("GetLastError")
///     .public()
///     .static_method()
///     .calling_convention_stdcall() // Windows API calling convention
///     .returns(TypeSignature::I4)
///     .pinvoke_impl() // No IL implementation - native code
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Variable Argument Method
///
/// ```rust,no_run
/// use dotscope::MethodBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let printf_token = MethodBuilder::new("printf")
///     .public()
///     .static_method()
///     .calling_convention_vararg() // Supports variable arguments
///     .parameter("format", TypeSignature::String)
///     .returns(TypeSignature::I4)
///     .pinvoke_impl()
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodBuilder {
    /// Method name
    name: String,

    /// Access flags (public, private, etc.)
    access_flags: MethodAccessFlags,

    /// Method modifiers (static, virtual, etc.)
    modifiers: MethodModifiers,

    /// Implementation flags (IL, native, etc.)
    impl_flags: MethodImplCodeType,

    /// Implementation options (internal call and the like), combined with the code type into
    /// the ImplFlags column
    impl_options: MethodImplOptions,

    /// Return type
    return_type: TypeSignature,

    /// Parameters
    parameters: Vec<(String, TypeSignature)>,

    /// Method body builder
    body_builder: Option<MethodBodyBuilder>,

    /// Whether this method has a 'this' parameter
    has_this: bool,

    /// Calling convention: explicit 'this'
    explicit_this: bool,

    /// Calling convention: default managed
    default_calling_convention: bool,

    /// Calling convention: variable arguments
    vararg: bool,

    /// Calling convention: C declaration (cdecl)
    cdecl: bool,

    /// Calling convention: standard call (stdcall)
    stdcall: bool,

    /// Calling convention: this call (thiscall)
    thiscall: bool,

    /// Calling convention: fast call (fastcall)
    fastcall: bool,
}

impl MethodBuilder {
    /// Create a new method builder with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - Method name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("MyMethod");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            access_flags: MethodAccessFlags::PRIVATE, // Default to private
            modifiers: MethodModifiers::ZERO,
            impl_flags: MethodImplCodeType::IL,
            impl_options: MethodImplOptions::ZERO,
            return_type: TypeSignature::Void,
            parameters: Vec::new(),
            body_builder: None,
            has_this: true, // Default to instance method
            explicit_this: false,
            default_calling_convention: true, // Default to managed calling convention
            vararg: false,
            cdecl: false,
            stdcall: false,
            thiscall: false,
            fastcall: false,
        }
    }

    /// Create a constructor method builder.
    ///
    /// This sets up the method with the appropriate name (".ctor"), flags,
    /// and return type for an instance constructor.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let ctor = MethodBuilder::constructor();
    /// ```
    #[must_use]
    pub fn constructor() -> Self {
        Self::new(".ctor").public().special_name().rtspecial_name()
    }

    /// Create a static constructor method builder.
    ///
    /// This sets up the method with the appropriate name (".cctor"), flags,
    /// and return type for a static constructor (type initializer).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let static_ctor = MethodBuilder::static_constructor();
    /// ```
    #[must_use]
    pub fn static_constructor() -> Self {
        Self::new(".cctor")
            .private()
            .static_method()
            .special_name()
            .rtspecial_name()
    }

    /// Create a property getter method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("get_PropertyName"),
    /// flags, and return type for a property getter.
    ///
    /// # Arguments
    ///
    /// * `property_name` - Name of the property
    /// * `return_type` - Type that the property returns
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let getter = MethodBuilder::property_getter("Name", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn property_getter(property_name: &str, return_type: TypeSignature) -> Self {
        Self::new(&format!("get_{property_name}"))
            .public()
            .special_name()
            .returns(return_type)
    }

    /// Create a property setter method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("set_PropertyName"),
    /// flags, and a value parameter for a property setter.
    ///
    /// # Arguments
    ///
    /// * `property_name` - Name of the property
    /// * `value_type` - Type of the property value
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let setter = MethodBuilder::property_setter("Name", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn property_setter(property_name: &str, value_type: TypeSignature) -> Self {
        Self::new(&format!("set_{property_name}"))
            .public()
            .special_name()
            .parameter("value", value_type)
    }

    /// Create an event add method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("add_EventName"),
    /// flags, and a delegate parameter for an event add accessor.
    ///
    /// # Arguments
    ///
    /// * `event_name` - The name of the event
    /// * `delegate_type` - The type of the event delegate
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let add_method = MethodBuilder::event_add("OnClick", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn event_add(event_name: &str, delegate_type: TypeSignature) -> Self {
        Self::new(&format!("add_{event_name}"))
            .public()
            .special_name()
            .parameter("value", delegate_type)
    }

    /// Create an event remove method builder.
    ///
    /// This sets up the method with the appropriate name pattern ("remove_EventName"),
    /// flags, and a delegate parameter for an event remove accessor.
    ///
    /// # Arguments
    ///
    /// * `event_name` - The name of the event
    /// * `delegate_type` - The type of the event delegate
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let remove_method = MethodBuilder::event_remove("OnClick", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn event_remove(event_name: &str, delegate_type: TypeSignature) -> Self {
        Self::new(&format!("remove_{event_name}"))
            .public()
            .special_name()
            .parameter("value", delegate_type)
    }

    /// Set the method as public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access_flags = MethodAccessFlags::PUBLIC;
        self
    }

    /// Set the method as private.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").private();
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.access_flags = MethodAccessFlags::PRIVATE;
        self
    }

    /// Set the method as protected.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").protected();
    /// ```
    #[must_use]
    pub fn protected(mut self) -> Self {
        self.access_flags = MethodAccessFlags::FAMILY;
        self
    }

    /// Set the method as internal (assembly-level access).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").internal();
    /// ```
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.access_flags = MethodAccessFlags::ASSEMBLY;
        self
    }

    /// Set the method as static.
    ///
    /// Static methods do not have a 'this' parameter and belong to the type
    /// rather than an instance.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").static_method();
    /// ```
    #[must_use]
    pub fn static_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::STATIC;
        self.has_this = false;
        self
    }

    /// Set the method as virtual.
    ///
    /// Virtual methods can be overridden in derived classes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").virtual_method();
    /// ```
    #[must_use]
    pub fn virtual_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::VIRTUAL;
        self
    }

    /// Set the method as abstract.
    ///
    /// Abstract methods have no implementation and must be overridden.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").abstract_method();
    /// ```
    #[must_use]
    pub fn abstract_method(mut self) -> Self {
        self.modifiers |= MethodModifiers::ABSTRACT;
        self
    }

    /// Set the method as sealed (final).
    ///
    /// Sealed methods cannot be overridden further.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").sealed();
    /// ```
    #[must_use]
    pub fn sealed(mut self) -> Self {
        self.modifiers |= MethodModifiers::FINAL;
        self
    }

    /// Mark the method as having a special name.
    ///
    /// This is typically used for constructors, property accessors, etc.
    #[must_use]
    pub fn special_name(mut self) -> Self {
        self.modifiers |= MethodModifiers::SPECIAL_NAME;
        self
    }

    /// Mark the method as having a runtime special name.  
    ///
    /// This is typically used for constructors and other runtime-special methods.
    #[must_use]
    pub fn rtspecial_name(mut self) -> Self {
        self.modifiers |= MethodModifiers::RTSPECIAL_NAME;
        self
    }

    /// Set the method to use the default managed calling convention.
    ///
    /// This is the standard calling convention for .NET methods and is enabled by default.
    /// Most managed methods should use this calling convention.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Test").calling_convention_default();
    /// ```
    #[must_use]
    pub fn calling_convention_default(mut self) -> Self {
        self.clear_calling_conventions();
        self.default_calling_convention = true;
        self
    }

    /// Set the method to use the variable argument calling convention.
    ///
    /// Methods using this calling convention can accept additional arguments
    /// beyond those declared in the signature (similar to C's variadic functions).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Printf").calling_convention_vararg();
    /// ```
    #[must_use]
    pub fn calling_convention_vararg(mut self) -> Self {
        self.clear_calling_conventions();
        self.vararg = true;
        self
    }

    /// Set the method to use the C declaration calling convention (cdecl).
    ///
    /// This calling convention is used for interoperability with native C functions.
    /// Arguments are pushed right-to-left and the caller cleans up the stack.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("CFunction").calling_convention_cdecl();
    /// ```
    #[must_use]
    pub fn calling_convention_cdecl(mut self) -> Self {
        self.clear_calling_conventions();
        self.cdecl = true;
        self
    }

    /// Set the method to use the standard call calling convention (stdcall).
    ///
    /// This calling convention is commonly used for Windows API functions.
    /// Arguments are pushed right-to-left and the callee cleans up the stack.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("WinAPI").calling_convention_stdcall();
    /// ```
    #[must_use]
    pub fn calling_convention_stdcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.stdcall = true;
        self
    }

    /// Set the method to use the this call calling convention (thiscall).
    ///
    /// This calling convention is used for C++ member functions.
    /// The 'this' pointer is passed in a register (typically ECX on x86).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("CppMethod").calling_convention_thiscall();
    /// ```
    #[must_use]
    pub fn calling_convention_thiscall(mut self) -> Self {
        self.clear_calling_conventions();
        self.thiscall = true;
        self
    }

    /// Set the method to use the fast call calling convention (fastcall).
    ///
    /// This calling convention uses registers for parameter passing where possible,
    /// providing better performance for frequently called methods.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("FastMethod").calling_convention_fastcall();
    /// ```
    #[must_use]
    pub fn calling_convention_fastcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.fastcall = true;
        self
    }

    /// Set the method to use explicit 'this' parameter.
    ///
    /// When enabled, the 'this' parameter is explicitly declared in the method signature
    /// rather than being implicit. This is rarely used in managed code.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("ExplicitThis").explicit_this();
    /// ```
    #[must_use]
    pub fn explicit_this(mut self) -> Self {
        self.explicit_this = true;
        self
    }

    /// Set the return type of the method.
    ///
    /// # Arguments
    ///
    /// * `return_type` - Type signature for the return value
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBuilder::new("GetValue").returns(TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn returns(mut self, return_type: TypeSignature) -> Self {
        self.return_type = return_type;
        self
    }

    /// Add a parameter to the method.
    ///
    /// Parameters are added in order and will be accessible via ldarg instructions
    /// starting from index 0 (or 1 for instance methods, where 0 is 'this').
    ///
    /// # Arguments
    ///
    /// * `name` - Parameter name
    /// * `param_type` - Parameter type signature
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBuilder::new("Add")
    ///     .parameter("a", TypeSignature::I4)
    ///     .parameter("b", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn parameter(mut self, name: &str, param_type: TypeSignature) -> Self {
        self.parameters.push((name.to_string(), param_type));
        self
    }

    /// Set the method implementation using a method body builder.
    ///
    /// This defines what the method actually does. The closure receives a
    /// `MethodBodyBuilder` that can be configured with locals and implementation.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that configures the method body
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = dotscope::metadata::cilassemblyview::CilAssemblyView::from_path("test.dll")?;
    /// # let mut assembly = dotscope::CilAssembly::new(view);
    /// let method = MethodBuilder::new("Test")
    ///     .implementation(|body| {
    ///         body.local("temp", dotscope::metadata::signatures::TypeSignature::I4)
    ///             .implementation(|asm| {
    ///                 asm.ldc_i4_const(42)?
    ///                    .stloc_0()?
    ///                    .ldloc_0()?
    ///                    .ret()?;
    ///                 Ok(())
    ///             })
    ///     })
    ///     .build(&mut assembly)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn implementation<F>(mut self, f: F) -> Self
    where
        F: FnOnce(MethodBodyBuilder) -> MethodBodyBuilder,
    {
        let body_builder = f(MethodBodyBuilder::new());
        self.body_builder = Some(body_builder);
        self
    }

    /// Mark this method as extern (no implementation).
    ///
    /// Extern methods are implemented outside of IL (e.g., native code,
    /// runtime-provided, etc.). This drops the IL body only: ECMA-335 §II.22.26 lets a
    /// method have no body (RVA 0) only when it is abstract, a P/Invoke
    /// ([`pinvoke_impl`](Self::pinvoke_impl)), an internal call
    /// ([`internal_call`](Self::internal_call)) or implemented by the runtime
    /// ([`runtime_implemented`](Self::runtime_implemented)), and
    /// [`build`](Self::build) refuses a bodyless method that is none of these.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("ExternalMethod").extern_method();
    /// ```
    #[must_use]
    pub fn extern_method(mut self) -> Self {
        self.body_builder = None; // No IL implementation
        self
    }

    /// Mark this method as a P/Invoke: implemented by a native function, without an IL body.
    ///
    /// Sets `PinvokeImpl` (0x2000) and drops any body. The native function it calls is named
    /// by an ImplMap row ([`crate::metadata::tables::ImplMapBuilder`]) forwarding to this
    /// method, which ECMA-335 §II.22.22 requires of every P/Invoke.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("MessageBoxW").public().static_method().pinvoke_impl();
    /// ```
    #[must_use]
    pub fn pinvoke_impl(mut self) -> Self {
        self.modifiers |= MethodModifiers::PINVOKE_IMPL;
        self.body_builder = None;
        self
    }

    /// Mark this method as an internal call: implemented inside the runtime itself, without an
    /// IL body.
    ///
    /// Sets the `InternalCall` implementation flag (0x1000) and drops any body.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("GetHashCode").public().internal_call();
    /// ```
    #[must_use]
    pub fn internal_call(mut self) -> Self {
        self.impl_options |= MethodImplOptions::INTERNAL_CALL;
        self.body_builder = None;
        self
    }

    /// Mark this method as implemented by the runtime, without an IL body: the code type is
    /// `Runtime` (0x0003), as for a delegate's `Invoke`, `BeginInvoke` and `EndInvoke`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBuilder;
    ///
    /// let builder = MethodBuilder::new("Invoke").public().virtual_method().runtime_implemented();
    /// ```
    #[must_use]
    pub fn runtime_implemented(mut self) -> Self {
        self.impl_flags = MethodImplCodeType::RUNTIME;
        self.body_builder = None;
        self
    }

    /// Build the complete method and add it to the assembly.
    ///
    /// This method orchestrates the creation of:
    /// 1. Method signature from return type and parameters
    /// 2. Method body from the body builder (if present)
    /// 3. Parameter table entries
    /// 4. Method definition table entry
    ///
    /// # Arguments
    ///
    /// * `assembly` - CIL assembly for managing the metadata
    ///
    /// # Returns
    ///
    /// A token representing the newly created method definition.
    ///
    /// # Errors
    ///
    /// Returns an error if method creation fails at any step.
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // ECMA-335 §II.22.26: a method has a body (RVA non-zero) exactly when it is neither
        // abstract, nor a P/Invoke, nor an internal call, nor implemented by the runtime.
        let bodyless = self.modifiers.contains(MethodModifiers::ABSTRACT)
            || self.modifiers.contains(MethodModifiers::PINVOKE_IMPL)
            || self.impl_options.contains(MethodImplOptions::INTERNAL_CALL)
            || self.impl_flags == MethodImplCodeType::RUNTIME;
        match (&self.body_builder, bodyless) {
            (None, false) => {
                return Err(malformed_error!(
                    "Method '{}' has no body but is not abstract, a P/Invoke, an internal call \
                     or runtime-implemented (ECMA-335 II.22.26)",
                    self.name
                ));
            }
            (Some(_), true) => {
                return Err(malformed_error!(
                    "Method '{}' has a body but is abstract, a P/Invoke, an internal call or \
                     runtime-implemented, which have none (ECMA-335 II.22.26)",
                    self.name
                ));
            }
            _ => {}
        }

        // Extract values needed for both signature and parameter creation
        let return_type = self.return_type.clone();
        let parameters = self.parameters.clone();
        let has_this = self.has_this;

        // Create method signature
        let signature = SignatureMethod {
            has_this,
            explicit_this: self.explicit_this,
            default: self.default_calling_convention,
            vararg: self.vararg,
            cdecl: self.cdecl,
            stdcall: self.stdcall,
            thiscall: self.thiscall,
            fastcall: self.fastcall,
            unmanaged: false,
            param_count_generic: 0,
            param_count: u32::try_from(parameters.len())
                .map_err(|_| malformed_error!("Method parameter count exceeds u32 range"))?,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: return_type.clone(),
            },
            params: parameters
                .iter()
                .map(|(_, param_type)| SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: param_type.clone(),
                })
                .collect(),
            varargs: Vec::new(),
        };

        let signature_bytes = encode_method_signature(&signature)?;

        // Create method body if we have an implementation
        let (rva, _local_sig_token) = if let Some(body_builder) = self.body_builder {
            let (body_bytes, local_sig_token) = body_builder.build(assembly)?;

            // Store method body through CilAssembly and get a placeholder RVA.
            // This placeholder will be resolved to the actual RVA during PE writing
            // when the real code section layout is determined.
            let placeholder_rva = assembly.store_method_body(body_bytes);

            (placeholder_rva, local_sig_token)
        } else {
            // Abstract or extern method - no implementation
            (0u32, Token::new(0))
        };

        // Combine all flags for the method definition
        let combined_flags = self.access_flags.bits() | self.modifiers.bits();

        // Get the next parameter table index (where our parameters will start)
        let param_start_index = assembly.next_rid(TableId::Param)?;

        for (sequence, (name, _param_type)) in parameters.iter().enumerate() {
            let one_based = sequence
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Parameter sequence overflow"))?;
            let param_sequence = u32::try_from(one_based)
                .map_err(|_| malformed_error!("Parameter sequence exceeds u32 range"))?; // Parameters start at sequence 1

            ParamBuilder::new()
                .name(name)
                .flags(ParamAttributes::IN) // Default to IN parameter
                .sequence(param_sequence)
                .build(assembly)?;
        }

        // Create the method definition with the correct parameter list index
        let method_token = MethodDefBuilder::new()
            .name(&self.name)
            .flags(combined_flags)
            .impl_flags(self.impl_flags.bits() | self.impl_options.bits())
            .signature(&signature_bytes)
            .rva(rva)
            .param_list(param_start_index) // Point to our parameter table entries
            .build(assembly)?;

        Ok(method_token)
    }

    /// Helper method to clear all calling convention flags.
    ///
    /// This ensures only one calling convention is active at a time.
    fn clear_calling_conventions(&mut self) {
        self.default_calling_convention = false;
        self.vararg = false;
        self.cdecl = false;
        self.stdcall = false;
        self.thiscall = false;
        self.fastcall = false;
    }
}

impl Default for MethodBuilder {
    fn default() -> Self {
        Self::new("DefaultMethod")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, signatures::TypeSignature, tables::TableId},
        testkit::fixture,
    };

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_method_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let method_ref = MethodBuilder::new("TestMethod")
            .public()
            .static_method()
            .returns(TypeSignature::Void)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.nop()?;
                    asm.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        // Should create a valid method reference
        assert_eq!(
            method_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_builder_with_parameters() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let method_ref = MethodBuilder::new("Add")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            method_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_constructor_builder() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ctor_ref = MethodBuilder::constructor()
            .parameter("name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // this
                        .call(Token::new(0x0A000001))? // base ctor
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(ctor_ref.kind(), ChangeRefKind::TableRow(TableId::MethodDef));

        Ok(())
    }

    #[test]
    fn test_property_getter() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let getter_ref = MethodBuilder::property_getter("Name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ldfld(Token::new(0x04000001))?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            getter_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_property_setter() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let setter_ref = MethodBuilder::property_setter("Name", TypeSignature::String)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // this
                        .ldarg_1()? // value
                        .stfld(Token::new(0x04000001))?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            setter_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_abstract_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let method_ref = MethodBuilder::new("AbstractMethod")
            .public()
            .abstract_method()
            .virtual_method()
            .returns(TypeSignature::I4)
            .build(&mut assembly)?;

        assert_eq!(
            method_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_static_constructor() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let static_ctor_ref = MethodBuilder::static_constructor()
            .implementation(|body| {
                body.implementation(|asm| {
                    // Initialize static fields
                    asm.ldc_i4_const(42)?
                        .stsfld(Token::new(0x04000001))?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            static_ctor_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_with_locals() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let method_ref = MethodBuilder::new("ComplexMethod")
            .public()
            .static_method()
            .parameter("input", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.local("temp", TypeSignature::I4)
                    .local("result", TypeSignature::I4)
                    .implementation(|asm| {
                        asm.ldarg_0()? // Load input
                            .stloc_0()? // Store to temp
                            .ldloc_0()? // Load temp
                            .ldc_i4_1()? // Load 1
                            .add()? // Add 1
                            .stloc_1()? // Store to result
                            .ldloc_1()? // Load result
                            .ret()?; // Return result
                        Ok(())
                    })
            })
            .build(&mut assembly)?;

        assert_eq!(
            method_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_builder_calling_conventions() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test cdecl calling convention
        let cdecl_method = MethodBuilder::new("CdeclMethod")
            .public()
            .static_method()
            .calling_convention_cdecl()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .pinvoke_impl()
            .build(&mut assembly)?;

        assert_eq!(
            cdecl_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        // Test stdcall calling convention
        let stdcall_method = MethodBuilder::new("StdcallMethod")
            .public()
            .static_method()
            .calling_convention_stdcall()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .pinvoke_impl()
            .build(&mut assembly)?;

        assert_eq!(
            stdcall_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        // Test default calling convention (should work for managed methods)
        let default_method = MethodBuilder::new("DefaultMethod")
            .public()
            .static_method()
            .calling_convention_default()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()?.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            default_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_builder_vararg_calling_convention() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let vararg_method = MethodBuilder::new("VarargMethod")
            .public()
            .static_method()
            .calling_convention_vararg()
            .parameter("format", TypeSignature::String)
            .returns(TypeSignature::Void)
            .pinvoke_impl() // Vararg methods are typically P/Invokes
            .build(&mut assembly)?;

        assert_eq!(
            vararg_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_builder_explicit_this() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let explicit_this_method = MethodBuilder::new("ExplicitThisMethod")
            .public()
            .explicit_this()
            .parameter("value", TypeSignature::I4)
            .returns(TypeSignature::Void)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load explicit 'this'
                        .ldarg_1()? // Load value parameter
                        .stfld(Token::new(0x04000001))? // Store to field
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            explicit_this_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        );

        Ok(())
    }

    #[test]
    fn test_method_builder_calling_convention_switching() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test that setting a new calling convention clears the previous one
        let method = MethodBuilder::new("SwitchingMethod")
            .public()
            .static_method()
            .calling_convention_cdecl() // Set cdecl first
            .calling_convention_stdcall() // Switch to stdcall (should clear cdecl)
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .pinvoke_impl()
            .build(&mut assembly)?;

        assert_eq!(method.kind(), ChangeRefKind::TableRow(TableId::MethodDef));

        Ok(())
    }

    #[test]
    fn test_event_add_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let add_method = MethodBuilder::event_add("OnClick", TypeSignature::Object)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load 'this'
                        .ldfld(Token::new(0x04000001))? // Load current delegate
                        .ldarg_1()? // Load new delegate
                        .call(Token::new(0x0A000001))? // Call Delegate.Combine
                        .stfld(Token::new(0x04000001))? // Store combined delegate
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            add_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        ); // MethodDef table

        Ok(())
    }

    #[test]
    fn test_event_remove_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let remove_method = MethodBuilder::event_remove("OnClick", TypeSignature::Object)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldarg_0()? // Load 'this'
                        .ldfld(Token::new(0x04000001))? // Load current delegate
                        .ldarg_1()? // Load delegate to remove
                        .call(Token::new(0x0A000002))? // Call Delegate.Remove
                        .stfld(Token::new(0x04000001))? // Store updated delegate
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)?;

        assert_eq!(
            remove_method.kind(),
            ChangeRefKind::TableRow(TableId::MethodDef)
        ); // MethodDef table

        Ok(())
    }

    /// ECMA-335 §II.22.26: a method without a body must be abstract, a P/Invoke, an internal
    /// call or runtime-implemented, and one of those must not have a body. The builder made a
    /// bodyless method of any other kind, which the loader's validation refuses.
    #[test]
    fn a_method_has_a_body_exactly_when_its_kind_needs_one() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        assert!(MethodBuilder::new("NoBody")
            .public()
            .static_method()
            .build(&mut assembly)
            .is_err());
        assert!(MethodBuilder::new("NoBodyExtern")
            .public()
            .static_method()
            .extern_method()
            .build(&mut assembly)
            .is_err());
        assert!(MethodBuilder::new("AbstractWithBody")
            .public()
            .virtual_method()
            .abstract_method()
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ret()?;
                    Ok(())
                })
            })
            .build(&mut assembly)
            .is_err());

        MethodBuilder::new("Native")
            .public()
            .static_method()
            .pinvoke_impl()
            .build(&mut assembly)?;
        MethodBuilder::new("Intrinsic")
            .public()
            .static_method()
            .internal_call()
            .build(&mut assembly)?;
        MethodBuilder::new("Invoke")
            .public()
            .virtual_method()
            .runtime_implemented()
            .build(&mut assembly)?;
        Ok(())
    }
}

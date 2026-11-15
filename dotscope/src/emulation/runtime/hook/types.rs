//! Core types for the hook system.
//!
//! This module defines the fundamental types used throughout the hook system:
//!
//! - [`HookPriority`]: Controls the order in which hooks are evaluated
//! - [`HookContext`]: Information about the method call being intercepted
//! - [`PreHookResult`]: Result of pre-hook execution (continue or bypass)
//! - [`PostHookResult`]: Result of post-hook execution (keep or replace)
//! - [`PreHookFn`]: Type alias for pre-hook closures
//! - [`PostHookFn`]: Type alias for post-hook closures

use std::sync::Arc;

use crate::{
    emulation::{synthetic_exception, thread::ReflectionInvokeRequest, EmValue, EmulationThread},
    metadata::{
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
};

/// Priority level for hooks, controlling evaluation order.
///
/// Higher priority hooks are evaluated first. When multiple hooks could match
/// a method call, only the highest priority matching hook is executed.
///
/// # Predefined Priorities
///
/// | Constant | Value | Use Case |
/// |----------|-------|----------|
/// | [`HIGHEST`](Self::HIGHEST) | 1000 | Override everything |
/// | [`HIGH`](Self::HIGH) | 500 | Specific patterns |
/// | [`NORMAL`](Self::NORMAL) | 0 | Default handlers |
/// | [`LOW`](Self::LOW) | -500 | Fallback handlers |
/// | [`LOWEST`](Self::LOWEST) | -1000 | Catch-all defaults |
///
/// # Custom Priorities
///
/// Create custom priority levels for fine-grained control:
///
/// ```rust,no_run
/// use dotscope::emulation::HookPriority;
///
/// // Priority between HIGH and HIGHEST
/// let my_priority = HookPriority(750);
/// ```
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::emulation::HookPriority;
///
/// // Comparison works as expected
/// assert!(HookPriority::HIGHEST > HookPriority::HIGH);
/// assert!(HookPriority::HIGH > HookPriority::NORMAL);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookPriority(pub i32);

impl HookPriority {
    /// Highest priority - checked first (value: 1000).
    ///
    /// Use for hooks that must override all others, such as security bypasses
    /// or critical deobfuscation hooks.
    pub const HIGHEST: Self = Self(1000);

    /// High priority (value: 500).
    ///
    /// Use for specific, targeted hooks that should take precedence over
    /// general handlers.
    pub const HIGH: Self = Self(500);

    /// Normal priority - default (value: 0).
    ///
    /// Use for general-purpose hooks. This is the default when no priority
    /// is explicitly specified.
    pub const NORMAL: Self = Self(0);

    /// Low priority (value: -500).
    ///
    /// Use for fallback hooks that should yield to more specific ones.
    pub const LOW: Self = Self(-500);

    /// Lowest priority - checked last (value: -1000).
    ///
    /// Use for catch-all hooks that only apply when no other hook matches.
    pub const LOWEST: Self = Self(-1000);
}

impl Default for HookPriority {
    fn default() -> Self {
        Self::NORMAL
    }
}

/// Context passed to hooks during execution.
///
/// Contains all information about the method call being intercepted, including
/// method metadata, arguments, and type information. Hooks use this context to
/// make matching decisions and access call data.
///
/// # Lifetime
///
/// The context borrows data from the emulation state and is only valid for the
/// duration of the hook execution. Hooks should extract any needed data before
/// returning.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{HookContext, PreHookResult, EmulationThread};
///
/// fn my_pre_hook(ctx: &HookContext, thread: &mut EmulationThread) -> PreHookResult {
///     println!("Method: {}.{}::{}", ctx.namespace, ctx.type_name, ctx.method_name);
///     println!("Args: {:?}", ctx.args);
///     PreHookResult::Continue
/// }
/// ```
pub struct HookContext<'a> {
    /// The method token being called.
    ///
    /// This is either a MethodDef token (for internal methods) or a MemberRef
    /// token (for external methods).
    pub method_token: Token,

    /// Namespace of the method (may be empty for global methods).
    pub namespace: &'a str,

    /// Type name containing the method.
    pub type_name: &'a str,

    /// Method name.
    pub method_name: &'a str,

    /// The `this` reference for instance methods.
    ///
    /// `None` for static methods or when the `this` reference is not available.
    pub this: Option<&'a EmValue>,

    /// Method arguments (excluding `this`).
    ///
    /// Arguments are in the order they were passed to the method.
    pub args: &'a [EmValue],

    /// Whether this is an internal method (MethodDef) vs external (MemberRef).
    ///
    /// Internal methods are defined in the assembly being analyzed. External
    /// methods are from referenced assemblies (typically BCL).
    pub is_internal: bool,

    /// Whether this is a P/Invoke (native) call.
    ///
    /// When `true`, `dll_name` contains the DLL name and `method_name` contains
    /// the native function name.
    pub is_native: bool,

    /// DLL name for P/Invoke calls.
    ///
    /// Only set when `is_native` is `true`.
    pub dll_name: Option<&'a str>,

    /// Parameter types if available.
    ///
    /// `None` if type information could not be resolved.
    pub param_types: Option<&'a [CilFlavor]>,

    /// Return type if available.
    ///
    /// `None` if type information could not be resolved or the method returns void.
    pub return_type: Option<CilFlavor>,

    /// Target pointer size for native int/uint types.
    pub pointer_size: PointerSize,
}

impl<'a> HookContext<'a> {
    /// Creates a new hook context with basic fields.
    ///
    /// Use the `with_*` builder methods to add additional fields like
    /// arguments, `this` reference, and type information.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method being called
    /// * `namespace` - The method's namespace
    /// * `type_name` - The containing type's name
    /// * `method_name` - The method's name
    /// * `ptr_size` - Target pointer size for native int/uint types
    #[must_use]
    pub fn new(
        method_token: Token,
        namespace: &'a str,
        type_name: &'a str,
        method_name: &'a str,
        ptr_size: PointerSize,
    ) -> Self {
        Self {
            method_token,
            namespace,
            type_name,
            method_name,
            this: None,
            args: &[],
            is_internal: false,
            is_native: false,
            dll_name: None,
            param_types: None,
            return_type: None,
            pointer_size: ptr_size,
        }
    }

    /// Creates a hook context for a P/Invoke (native) call.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method being called
    /// * `dll_name` - The name of the native DLL
    /// * `function_name` - The native function name
    /// * `ptr_size` - Target pointer size for native int/uint types
    #[must_use]
    pub fn native(
        method_token: Token,
        dll_name: &'a str,
        function_name: &'a str,
        ptr_size: PointerSize,
    ) -> Self {
        Self {
            method_token,
            namespace: "",
            type_name: "",
            method_name: function_name,
            this: None,
            args: &[],
            is_internal: false,
            is_native: true,
            dll_name: Some(dll_name),
            param_types: None,
            return_type: None,
            pointer_size: ptr_size,
        }
    }

    /// Sets the `this` reference for instance methods.
    #[must_use]
    pub fn with_this(mut self, this: Option<&'a EmValue>) -> Self {
        self.this = this;
        self
    }

    /// Sets the method arguments.
    #[must_use]
    pub fn with_args(mut self, args: &'a [EmValue]) -> Self {
        self.args = args;
        self
    }

    /// Sets whether this is an internal method.
    #[must_use]
    pub fn with_internal(mut self, is_internal: bool) -> Self {
        self.is_internal = is_internal;
        self
    }

    /// Sets the parameter types.
    #[must_use]
    pub fn with_param_types(mut self, types: Option<&'a [CilFlavor]>) -> Self {
        self.param_types = types;
        self
    }

    /// Sets the return type.
    #[must_use]
    pub fn with_return_type(mut self, return_type: Option<CilFlavor>) -> Self {
        self.return_type = return_type;
        self
    }
}

/// Result of executing a pre-hook.
///
/// Pre-hooks run before the original method and can either continue with normal
/// execution or bypass the original method entirely.
///
/// # Variants
///
/// | Variant | Original Method | Post-Hook |
/// |---------|-----------------|-----------|
/// | [`Continue`](Self::Continue) | Runs | Runs |
/// | [`Bypass`](Self::Bypass) | Skipped | Skipped |
/// | [`Error`](Self::Error) | Skipped | Skipped |
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{PreHookResult, EmValue};
///
/// // Continue to let the original method run
/// PreHookResult::Continue;
///
/// // Bypass the original and return a custom value
/// PreHookResult::Bypass(Some(EmValue::I32(42)));
///
/// // Bypass with void return
/// PreHookResult::Bypass(None);
///
/// // Report an error
/// PreHookResult::Error("Invalid argument".to_string());
/// ```
#[derive(Debug)]
pub enum PreHookResult {
    /// Continue with the original method execution.
    ///
    /// The original method will run, followed by any post-hooks.
    Continue,

    /// Bypass the original method and return this value directly.
    ///
    /// The original method and post-hooks will NOT be called. Use `Some(value)`
    /// for methods that return a value, `None` for void methods.
    Bypass(Option<EmValue>),

    /// Bypass the original method and signal a reflection invoke redirect.
    ///
    /// The hook has resolved a reflection call (e.g., `MethodBase.Invoke`) and
    /// wants the controller to redirect execution to the target method. The
    /// `bypass_value` serves as the placeholder return value (e.g., the newly
    /// allocated object for constructor invokes).
    ReflectionInvoke {
        /// The reflection invoke request describing which method to call.
        request: Box<ReflectionInvokeRequest>,
        /// Placeholder return value for the hook's caller.
        bypass_value: Option<EmValue>,
    },

    /// An error occurred in the hook.
    ///
    /// The emulator will propagate this error to the caller as a hard Rust error
    /// that bypasses CIL exception handling. Use [`Throw`](Self::Throw) instead
    /// when simulating a CLR exception that should be routable to `catch` handlers.
    Error(String),

    /// The hook throws a CLR exception that should be routable to CIL catch handlers.
    ///
    /// Unlike [`Error`](Self::Error), this variant creates an exception that flows
    /// through the normal CIL exception handling path (`try`/`catch`/`finally`).
    Throw {
        /// Synthetic exception type token (from `synthetic_exception` constants).
        exception_type: Token,
        /// Message for diagnostics/tracing.
        message: String,
    },
}

impl PreHookResult {
    /// Creates a `Throw` for `System.NullReferenceException`.
    #[must_use]
    pub fn throw_null_reference() -> Self {
        Self::Throw {
            exception_type: synthetic_exception::NULL_REFERENCE,
            message: "NullReferenceException".into(),
        }
    }

    /// Creates a `Throw` for `System.IO.EndOfStreamException`.
    #[must_use]
    pub fn throw_end_of_stream() -> Self {
        Self::Throw {
            exception_type: synthetic_exception::END_OF_STREAM,
            message: "EndOfStreamException".into(),
        }
    }

    /// Creates a `Throw` for `System.ObjectDisposedException`.
    #[must_use]
    pub fn throw_object_disposed() -> Self {
        Self::Throw {
            exception_type: synthetic_exception::OBJECT_DISPOSED,
            message: "ObjectDisposedException".into(),
        }
    }

    /// Creates a `Throw` for `System.AccessViolationException`.
    #[must_use]
    pub fn throw_access_violation(msg: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::ACCESS_VIOLATION,
            message: format!("AccessViolationException: {msg}"),
        }
    }

    /// Creates a `Throw` for `System.InvalidOperationException`.
    #[must_use]
    pub fn throw_invalid_operation(msg: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::INVALID_OPERATION,
            message: format!("InvalidOperationException: {msg}"),
        }
    }

    /// Creates a `Throw` for `System.FormatException`.
    #[must_use]
    pub fn throw_format_exception() -> Self {
        Self::Throw {
            exception_type: synthetic_exception::FORMAT_EXCEPTION,
            message: "FormatException".into(),
        }
    }

    /// Creates a `Throw` for `System.Collections.Generic.KeyNotFoundException`.
    #[must_use]
    pub fn throw_key_not_found() -> Self {
        Self::Throw {
            exception_type: synthetic_exception::KEY_NOT_FOUND,
            message: "KeyNotFoundException".into(),
        }
    }

    /// Creates a `Throw` for `System.ArgumentNullException`.
    #[must_use]
    pub fn throw_argument_null(param: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::ARGUMENT_NULL,
            message: format!("ArgumentNullException: {param}"),
        }
    }

    /// Creates a `Throw` for `System.IO.FileNotFoundException`.
    #[must_use]
    pub fn throw_file_not_found(path: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::FILE_NOT_FOUND,
            message: format!("FileNotFoundException: {path}"),
        }
    }

    /// Creates a `Throw` for `System.ArgumentException`.
    #[must_use]
    pub fn throw_argument_exception(msg: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
            message: format!("ArgumentException: {msg}"),
        }
    }

    /// Creates a `Throw` for `System.TypeLoadException`.
    #[must_use]
    pub fn throw_type_load(msg: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::TYPE_LOAD,
            message: format!("TypeLoadException: {msg}"),
        }
    }

    /// Creates a `Throw` for `System.NotImplementedException`.
    #[must_use]
    pub fn throw_not_implemented(msg: &str) -> Self {
        Self::Throw {
            exception_type: synthetic_exception::NOT_IMPLEMENTED,
            message: format!("NotImplementedException: {msg}"),
        }
    }
}

/// Result of executing a post-hook.
///
/// Post-hooks run after the original method and can either keep the original
/// return value or replace it with a new value.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{PostHookResult, EmValue};
///
/// // Keep the original return value unchanged
/// PostHookResult::Keep;
///
/// // Replace the return value
/// PostHookResult::Replace(Some(EmValue::I32(100)));
///
/// // Report an error
/// PostHookResult::Error("Post-processing failed".to_string());
/// ```
#[derive(Debug)]
pub enum PostHookResult {
    /// Keep the original return value unchanged.
    Keep,

    /// Replace the return value with a new value.
    Replace(Option<EmValue>),

    /// An error occurred in the hook.
    ///
    /// The emulator will propagate this error to the caller.
    Error(String),
}

/// Type alias for pre-hook functions.
///
/// Pre-hooks receive the hook context and mutable thread access. They return
/// a [`PreHookResult`] indicating whether to continue with the original method
/// or bypass it.
///
/// # Thread Safety
///
/// Pre-hook functions must be `Send + Sync` to allow registration from any thread.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{PreHookFn, PreHookResult};
/// use std::sync::Arc;
///
/// let my_hook: PreHookFn = Arc::new(|ctx, thread| {
///     println!("Called: {}", ctx.method_name);
///     PreHookResult::Continue
/// });
/// ```
pub type PreHookFn =
    Arc<dyn Fn(&HookContext<'_>, &mut EmulationThread) -> PreHookResult + Send + Sync>;

/// Type alias for post-hook functions.
///
/// Post-hooks receive the hook context, thread access, and the original return
/// value. They can modify or replace the result.
///
/// # Thread Safety
///
/// Post-hook functions must be `Send + Sync` to allow registration from any thread.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::{PostHookFn, PostHookResult};
/// use std::sync::Arc;
///
/// let my_hook: PostHookFn = Arc::new(|ctx, thread, result| {
///     println!("Returned: {:?}", result);
///     PostHookResult::Keep
/// });
/// ```
pub type PostHookFn = Arc<
    dyn Fn(&HookContext<'_>, &mut EmulationThread, Option<&EmValue>) -> PostHookResult
        + Send
        + Sync,
>;

/// Outcome of hook execution via [`HookManager::execute`].
///
/// This enum represents the result of attempting to execute a method call
/// through the hook system. Errors are returned via `Result`, not as an
/// outcome variant, enabling clean `?` propagation.
///
/// # Examples
///
/// ```
/// use dotscope::emulation::{HookContext, HookManager, HookOutcome};
/// use dotscope::metadata::{token::Token, typesystem::PointerSize};
/// # use std::sync::{Arc, RwLock};
/// # use dotscope::emulation::{
/// #     AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
/// #     SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
/// # };
/// # let address_space = Arc::new(AddressSpace::new());
/// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
/// # let context = Arc::new(ThreadContext::new(
/// #     address_space,
/// #     Arc::new(RwLock::new(RuntimeState::new())),
/// #     Arc::new(CaptureContext::new()),
/// #     Arc::new(EmulationConfig::default()),
/// #     None,
/// #     fake_objects,
/// #     Arc::new(VirtualFs::new()),
/// # ));
/// # let mut thread = EmulationThread::new(ThreadId::MAIN, context);
/// # let manager = HookManager::new();
/// # let context =
/// #     HookContext::new(Token::new(0x0A00_0001), "System", "String", "Concat", PointerSize::Bit64);
///
/// let outcome = manager.execute(&context, &mut thread, |_thread| None)?;
/// match outcome {
///     HookOutcome::NoMatch => {
///         // No hook matched - execute method normally
///     }
///     HookOutcome::Handled(value) => {
///         // Hook handled the call, use this return value
///     }
///     HookOutcome::ReflectionInvoke { .. } => {
///         // Hook resolved a reflection call: redirect to the invoked method
///     }
///     HookOutcome::ThrewException { .. } => {
///         // Hook threw a CLR exception: route it to the handlers
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// [`HookManager::execute`]: crate::emulation::runtime::HookManager::execute
#[derive(Debug)]
pub enum HookOutcome {
    /// No hook matched this method call.
    ///
    /// The caller should execute the method through normal means (stubs,
    /// internal execution, etc.).
    NoMatch,

    /// A hook handled the method call.
    ///
    /// The contained value is the final return value after pre-hook and/or
    /// post-hook processing. `None` indicates a void return.
    Handled(Option<EmValue>),

    /// A hook resolved a reflection invoke redirect.
    ///
    /// The controller should redirect execution to the method specified in
    /// the request, using `bypass_value` as the placeholder return value.
    ReflectionInvoke {
        /// The reflection invoke request describing which method to call.
        request: Box<ReflectionInvokeRequest>,
        /// Placeholder return value for the hook's caller.
        bypass_value: Option<EmValue>,
    },

    /// A hook threw a CLR exception.
    ///
    /// The controller should create a synthetic exception object and route it
    /// through the CIL exception handling path (`try`/`catch`/`finally`).
    ThrewException {
        /// Synthetic exception type token.
        exception_type: Token,
        /// Diagnostic message.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_priority_ordering() {
        assert!(HookPriority::HIGHEST > HookPriority::HIGH);
        assert!(HookPriority::HIGH > HookPriority::NORMAL);
        assert!(HookPriority::NORMAL > HookPriority::LOW);
        assert!(HookPriority::LOW > HookPriority::LOWEST);
    }

    #[test]
    fn test_hook_priority_default() {
        assert_eq!(HookPriority::default(), HookPriority::NORMAL);
    }

    #[test]
    fn test_hook_context_builder() {
        let ctx = HookContext::new(
            Token::new(0x06000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        )
        .with_internal(false)
        .with_return_type(Some(CilFlavor::String));

        assert_eq!(ctx.namespace, "System");
        assert_eq!(ctx.type_name, "String");
        assert_eq!(ctx.method_name, "Concat");
        assert!(!ctx.is_internal);
        assert_eq!(ctx.return_type, Some(CilFlavor::String));
    }
}

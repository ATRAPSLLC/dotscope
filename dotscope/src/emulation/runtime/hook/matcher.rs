//! Matcher trait and implementations for hook matching.
//!
//! This module defines the [`HookMatcher`] trait and several implementations for
//! determining whether a hook should be applied to a given method call.
//!
//! # Available Matchers
//!
//! | Matcher | Description |
//! |---------|-------------|
//! | [`NameMatcher`] | Match by namespace, type, and/or method name |
//! | [`InternalMethodMatcher`] | Match only internal methods (MethodDef) |
//! | [`SignatureMatcher`] | Match by parameter and return types |
//! | [`RuntimeMatcher`] | Match by inspecting runtime argument values |
//!
//! # Combining Matchers
//!
//! Multiple matchers can be added to a single hook. All matchers must match for
//! the hook to be applied (AND semantics).
//!
//! ```
//! use dotscope::emulation::{EmValue, EmulationThread, Hook, HookContext};
//! use dotscope::metadata::typesystem::{CilFlavor, PointerSize};
//!
//!/// Whether the first argument is a byte array that opens as LZMA does.
//!fn is_lzma_header(ctx: &HookContext<'_>, thread: &EmulationThread) -> bool {
//!    let Some(EmValue::ObjectRef(array)) = ctx.args.first() else {
//!        return false;
//!    };
//!    matches!(
//!        thread.heap().get_array_as_bytes(*array, PointerSize::Bit64),
//!        Ok(Some(bytes)) if bytes.len() >= 5 && bytes[0] == 0x5D
//!    )
//!}
//!
//!// `byte[]`, the parameter and the result the hook matches
//!let byte_array = || CilFlavor::Array {
//!    element_type: Box::new(CilFlavor::U1),
//!    rank: 1,
//!    dimensions: Vec::new(),
//!};
//!
//! // This hook requires ALL conditions to be true:
//! // 1. Internal method
//! // 2. Parameter is byte[]
//! // 3. Returns byte[]
//! // 4. First argument looks like LZMA header
//! let hook = Hook::new("lzma-decompressor")
//!     .match_internal_method()
//!     .match_signature(vec![byte_array()], Some(byte_array()))
//!     .match_runtime("lzma-header", |ctx, thread| {
//!         // Custom runtime check
//!         is_lzma_header(ctx, thread)
//!     });
//! ```

use std::sync::Arc;

use crate::{
    emulation::{runtime::hook::types::HookContext, EmulationThread},
    metadata::typesystem::CilFlavor,
};

/// Type alias for runtime matcher predicates.
pub type RuntimePredicate = dyn Fn(&HookContext<'_>, &EmulationThread) -> bool + Send + Sync;

/// Trait for implementing hook matchers.
///
/// Matchers determine whether a hook should be applied to a given method call.
/// Each matcher implements a single matching criterion. Multiple matchers can
/// be combined on a hook (all must match).
///
/// # Implementing Custom Matchers
///
/// ```rust,no_run
/// use dotscope::emulation::{HookMatcher, HookContext, EmulationThread};
///
/// struct ModuleNameMatcher {
///     module_name: String,
/// }
///
/// impl HookMatcher for ModuleNameMatcher {
///     fn matches(&self, context: &HookContext<'_>, _thread: &EmulationThread) -> bool {
///         // Custom matching logic based on module name
///         context.method_token.table() == 0x06 // Check if MethodDef
///     }
///
///     fn description(&self) -> String {
///         format!("module={}", self.module_name)
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// Matchers must be `Send + Sync` to allow hook registration from any thread.
pub trait HookMatcher: Send + Sync {
    /// Checks if this matcher matches the given context.
    ///
    /// # Arguments
    ///
    /// * `context` - The hook context containing method call information
    /// * `thread` - The emulation thread (for runtime data inspection)
    ///
    /// # Returns
    ///
    /// `true` if the matcher matches, `false` otherwise.
    fn matches(&self, context: &HookContext<'_>, thread: &EmulationThread) -> bool;

    /// Returns a description of this matcher for debugging.
    ///
    /// This should be a concise description of what the matcher checks for,
    /// such as "namespace=System, type=String" or "internal method only".
    fn description(&self) -> String;

    /// Returns the name components if this is a name-based matcher.
    ///
    /// Used by [`HookManager`](super::HookManager) to build the hook dispatch
    /// index. Returns `(namespace, type_name, method_name)` where each component
    /// is `Some` if specified or `None` if it matches anything.
    ///
    /// The default implementation returns `None`, indicating this matcher does
    /// not provide name-based indexing hints.
    fn name_components(&self) -> Option<(Option<&str>, Option<&str>, Option<&str>)> {
        None
    }

    /// Returns `true` if this matcher requires runtime argument inspection.
    ///
    /// Runtime matchers evaluate closures over the actual call arguments. The
    /// hook manager uses this to determine whether a hook can be resolved purely
    /// from name-based indexing or needs full context evaluation.
    fn is_runtime_matcher(&self) -> bool {
        false
    }

    /// Returns `true` if this matcher requires method signature information.
    ///
    /// Signature matchers check parameter types and return types. The hook
    /// manager uses this to determine whether parameter/return type metadata
    /// must be fetched before matching.
    fn is_signature_matcher(&self) -> bool {
        false
    }
}

/// Matches methods by namespace, type name, and/or method name.
///
/// Each component is optional. Unset components match anything. When multiple
/// components are set, all must match.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::emulation::NameMatcher;
///
/// // Match all methods named "Decrypt" in any namespace/type
/// let matcher = NameMatcher::new().method_name("Decrypt");
///
/// // Match String.Concat specifically
/// let matcher = NameMatcher::full("System", "String", "Concat");
///
/// // Match all methods in the System namespace
/// let matcher = NameMatcher::new().namespace("System");
/// ```
#[derive(Clone, Debug, Default)]
pub struct NameMatcher {
    namespace: Option<String>,
    type_name: Option<String>,
    method_name: Option<String>,
}

impl NameMatcher {
    /// Creates a new name matcher with all components optional.
    ///
    /// Use the builder methods to specify which components to match.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the namespace to match.
    ///
    /// # Arguments
    ///
    /// * `ns` - The namespace to match exactly
    #[must_use]
    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Sets the type name to match.
    ///
    /// # Arguments
    ///
    /// * `name` - The type name to match exactly
    #[must_use]
    pub fn type_name(mut self, name: impl Into<String>) -> Self {
        self.type_name = Some(name.into());
        self
    }

    /// Sets the method name to match.
    ///
    /// # Arguments
    ///
    /// * `name` - The method name to match exactly
    #[must_use]
    pub fn method_name(mut self, name: impl Into<String>) -> Self {
        self.method_name = Some(name.into());
        self
    }

    /// Creates a matcher from all three components.
    ///
    /// This is a convenience method for matching a specific method.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace to match
    /// * `type_name` - The type name to match
    /// * `method_name` - The method name to match
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::NameMatcher;
    ///
    /// let matcher = NameMatcher::full("System", "String", "Concat");
    /// ```
    #[must_use]
    pub fn full(
        namespace: impl Into<String>,
        type_name: impl Into<String>,
        method_name: impl Into<String>,
    ) -> Self {
        Self {
            namespace: Some(namespace.into()),
            type_name: Some(type_name.into()),
            method_name: Some(method_name.into()),
        }
    }
}

impl HookMatcher for NameMatcher {
    fn matches(&self, context: &HookContext<'_>, _thread: &EmulationThread) -> bool {
        let ns_matches = self
            .namespace
            .as_ref()
            .is_none_or(|ns| ns == context.namespace);

        let type_matches = self
            .type_name
            .as_ref()
            .is_none_or(|t| t == context.type_name);

        let method_matches = self
            .method_name
            .as_ref()
            .is_none_or(|m| m == context.method_name);

        ns_matches && type_matches && method_matches
    }

    fn description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ns) = &self.namespace {
            parts.push(format!("namespace={ns}"));
        }
        if let Some(t) = &self.type_name {
            parts.push(format!("type={t}"));
        }
        if let Some(m) = &self.method_name {
            parts.push(format!("method={m}"));
        }
        if parts.is_empty() {
            "any".to_string()
        } else {
            parts.join(", ")
        }
    }

    fn name_components(&self) -> Option<(Option<&str>, Option<&str>, Option<&str>)> {
        Some((
            self.namespace.as_deref(),
            self.type_name.as_deref(),
            self.method_name.as_deref(),
        ))
    }
}

/// Matches only internal methods (MethodDef, not MemberRef).
///
/// Internal methods are defined in the assembly being analyzed. External methods
/// are from referenced assemblies (typically BCL or third-party libraries).
///
/// This is useful for matching obfuscator-generated methods that wouldn't be
/// in the BCL.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::emulation::{Hook, InternalMethodMatcher};
///
/// let hook = Hook::new("internal-only")
///     .add_matcher(InternalMethodMatcher);
/// ```
#[derive(Clone, Debug, Default)]
pub struct InternalMethodMatcher;

impl HookMatcher for InternalMethodMatcher {
    fn matches(&self, context: &HookContext<'_>, _thread: &EmulationThread) -> bool {
        context.is_internal
    }

    fn description(&self) -> String {
        "internal method only".to_string()
    }
}

/// Matches methods by their parameter and return types.
///
/// Uses CIL type flavors to match the method signature. Both parameter types
/// and return type can be specified independently.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::emulation::SignatureMatcher;
/// use dotscope::metadata::typesystem::CilFlavor;
///
/// // Match methods that take (int32, int32) and return int32
/// let matcher = SignatureMatcher::new()
///     .params(vec![CilFlavor::I4, CilFlavor::I4])
///     .returns(CilFlavor::I4);
///
/// // Match methods that return int32
/// let matcher = SignatureMatcher::new()
///     .returns(CilFlavor::I4);
/// ```
#[derive(Clone, Debug, Default)]
pub struct SignatureMatcher {
    param_types: Option<Vec<CilFlavor>>,
    return_type: Option<CilFlavor>,
}

impl SignatureMatcher {
    /// Creates a new signature matcher.
    ///
    /// By default, no type constraints are applied.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the expected parameter types.
    ///
    /// All parameter types must match exactly in order.
    ///
    /// # Arguments
    ///
    /// * `types` - The expected parameter types
    #[must_use]
    pub fn params(mut self, types: Vec<CilFlavor>) -> Self {
        self.param_types = Some(types);
        self
    }

    /// Sets the expected return type.
    ///
    /// # Arguments
    ///
    /// * `return_type` - The expected return type
    #[must_use]
    pub fn returns(mut self, return_type: CilFlavor) -> Self {
        self.return_type = Some(return_type);
        self
    }
}

impl HookMatcher for SignatureMatcher {
    fn matches(&self, context: &HookContext<'_>, _thread: &EmulationThread) -> bool {
        // Check parameter types if specified
        if let Some(expected_params) = &self.param_types {
            match context.param_types {
                Some(actual_params) => {
                    if expected_params.len() != actual_params.len() {
                        return false;
                    }
                    for (expected, actual) in expected_params.iter().zip(actual_params.iter()) {
                        if expected != actual {
                            return false;
                        }
                    }
                }
                None => return false, // Can't verify, fail conservatively
            }
        }

        // Check return type if specified
        if let Some(expected_ret) = &self.return_type {
            match &context.return_type {
                Some(actual_ret) => {
                    if expected_ret != actual_ret {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    fn description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(params) = &self.param_types {
            parts.push(format!("params={params:?}"));
        }
        if let Some(ret) = &self.return_type {
            parts.push(format!("returns={ret:?}"));
        }
        if parts.is_empty() {
            "any signature".to_string()
        } else {
            parts.join(", ")
        }
    }

    fn is_signature_matcher(&self) -> bool {
        true
    }
}

/// Matches methods based on runtime argument inspection.
///
/// This matcher uses a closure to inspect actual argument values at runtime.
/// This enables pattern matching like "input looks like LZMA data" that cannot
/// be determined from metadata alone.
///
/// # Performance
///
/// Runtime matchers are evaluated for every method call that passes other
/// matchers. Keep the predicate efficient to avoid performance impact.
///
/// # Examples
///
/// ```
/// use dotscope::emulation::{EmValue, RuntimeMatcher};
/// use dotscope::metadata::typesystem::PointerSize;
///
/// // Match methods where first argument is a byte[] starting with LZMA header
/// let matcher = RuntimeMatcher::new("lzma-header", |ctx, thread| {
///     if let Some(EmValue::ObjectRef(r)) = ctx.args.first() {
///         if let Ok(Some(bytes)) = thread.heap().get_array_as_bytes(*r, PointerSize::Bit64) {
///             return bytes.len() >= 5 && bytes[0] == 0x5D;
///         }
///     }
///     false
/// });
/// ```
pub struct RuntimeMatcher {
    predicate: Arc<RuntimePredicate>,
    description: String,
}

impl RuntimeMatcher {
    /// Creates a new runtime matcher with the given predicate.
    ///
    /// # Arguments
    ///
    /// * `description` - Human-readable description of what this matches
    /// * `predicate` - Function that inspects context and returns `true` if matched
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::emulation::RuntimeMatcher;
    ///
    /// let matcher = RuntimeMatcher::new("has-three-args", |ctx, _thread| {
    ///     ctx.args.len() == 3
    /// });
    /// ```
    pub fn new<F>(description: impl Into<String>, predicate: F) -> Self
    where
        F: Fn(&HookContext<'_>, &EmulationThread) -> bool + Send + Sync + 'static,
    {
        Self {
            predicate: Arc::new(predicate),
            description: description.into(),
        }
    }
}

impl HookMatcher for RuntimeMatcher {
    fn matches(&self, context: &HookContext<'_>, thread: &EmulationThread) -> bool {
        (self.predicate)(context, thread)
    }

    fn description(&self) -> String {
        self.description.clone()
    }

    fn is_runtime_matcher(&self) -> bool {
        true
    }
}

/// Matches P/Invoke (native) method calls by DLL name and/or function name.
///
/// This matcher identifies calls to unmanaged code through the P/Invoke
/// mechanism. It can match by DLL name, function name, or both.
///
/// # Normalization
///
/// DLL names are normalized to lowercase and the `.dll` extension is removed
/// for consistent matching. Function names are compared case-sensitively.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::emulation::NativeMethodMatcher;
///
/// // Match all calls to kernel32.dll
/// let matcher = NativeMethodMatcher::new().dll("kernel32");
///
/// // Match VirtualProtect specifically
/// let matcher = NativeMethodMatcher::full("kernel32", "VirtualProtect");
///
/// // Match any function named GetModuleHandle (any DLL)
/// let matcher = NativeMethodMatcher::new().function("GetModuleHandle");
/// ```
#[derive(Clone, Debug, Default)]
pub struct NativeMethodMatcher {
    dll_name: Option<String>,
    function_name: Option<String>,
}

impl NativeMethodMatcher {
    /// Creates a new native method matcher with no constraints.
    ///
    /// Use the builder methods to specify which components to match.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the DLL name to match.
    ///
    /// The DLL name is normalized: converted to lowercase with `.dll` extension removed.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL name to match (e.g., "kernel32" or "kernel32.dll")
    #[must_use]
    pub fn dll(mut self, dll: impl Into<String>) -> Self {
        let dll = dll.into().to_lowercase();
        let normalized = dll
            .trim_end_matches(".dll")
            .trim_end_matches(".DLL")
            .to_string();
        self.dll_name = Some(normalized);
        self
    }

    /// Sets the function name to match.
    ///
    /// Function names are matched case-sensitively.
    ///
    /// # Arguments
    ///
    /// * `function` - The function name to match (e.g., "VirtualProtect")
    #[must_use]
    pub fn function(mut self, function: impl Into<String>) -> Self {
        self.function_name = Some(function.into());
        self
    }

    /// Creates a matcher for a specific DLL and function combination.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL name (normalized automatically)
    /// * `function` - The function name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::NativeMethodMatcher;
    ///
    /// let matcher = NativeMethodMatcher::full("kernel32", "VirtualProtect");
    /// ```
    #[must_use]
    pub fn full(dll: impl Into<String>, function: impl Into<String>) -> Self {
        Self::new().dll(dll).function(function)
    }
}

impl HookMatcher for NativeMethodMatcher {
    fn matches(&self, context: &HookContext<'_>, _thread: &EmulationThread) -> bool {
        // Must be a native call
        if !context.is_native {
            return false;
        }

        // Check DLL name if specified
        if let Some(expected_dll) = &self.dll_name {
            let actual_dll = context
                .dll_name
                .map(|d| {
                    d.to_lowercase()
                        .trim_end_matches(".dll")
                        .trim_end_matches(".DLL")
                        .to_string()
                })
                .unwrap_or_default();
            if expected_dll != &actual_dll {
                return false;
            }
        }

        // Check function name if specified
        if let Some(expected_fn) = &self.function_name {
            if expected_fn != context.method_name {
                return false;
            }
        }

        true
    }

    fn description(&self) -> String {
        let mut parts = Vec::new();
        parts.push("native".to_string());
        if let Some(dll) = &self.dll_name {
            parts.push(format!("dll={dll}"));
        }
        if let Some(func) = &self.function_name {
            parts.push(format!("function={func}"));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_matcher_full() {
        let matcher = NameMatcher::full("System", "String", "Concat");
        assert_eq!(
            matcher.description(),
            "namespace=System, type=String, method=Concat"
        );
    }

    #[test]
    fn test_name_matcher_partial() {
        let matcher = NameMatcher::new().method_name("Decrypt");
        assert_eq!(matcher.description(), "method=Decrypt");
    }

    #[test]
    fn test_name_matcher_empty() {
        let matcher = NameMatcher::new();
        assert_eq!(matcher.description(), "any");
    }

    #[test]
    fn test_internal_method_matcher_description() {
        let matcher = InternalMethodMatcher;
        assert_eq!(matcher.description(), "internal method only");
    }

    #[test]
    fn test_signature_matcher_description() {
        let matcher = SignatureMatcher::new()
            .params(vec![CilFlavor::I4, CilFlavor::I4])
            .returns(CilFlavor::I4);

        let desc = matcher.description();
        assert!(desc.contains("params="));
        assert!(desc.contains("returns="));
    }
}

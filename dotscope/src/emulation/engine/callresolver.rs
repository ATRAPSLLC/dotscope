//! Call resolution and method dispatch for the emulation engine.
//!
//! This module provides the [`CallResolver`], which encapsulates the multi-tier
//! method resolution pipeline used by the
//! [`EmulationController`](super::controller::EmulationController). It handles:
//!
//! - **Hook dispatch**: Token-cached, lock-free hook matching against the
//!   [`HookManager`] registry with O(1) fast-path for non-matching tokens
//! - **P/Invoke resolution**: Native method stub lookup for platform invoke methods
//! - **Virtual dispatch**: Runtime type-based method resolution with DashMap caching
//!   for both class inheritance and interface dispatch
//! - **Delegate dispatch**: Redirecting `Invoke` calls to the delegate's target method
//! - **MemberRef/MethodSpec resolution**: Resolving external references and generic
//!   instantiations to concrete method tokens
//! - **Frame management**: Creating and pushing call frames for entering methods
//! - **Type initialization**: Triggering `.cctor` execution before static field access
//!
//! # Token Cache
//!
//! The resolver maintains a per-token cache ([`DashMap`]) that eliminates metadata
//! lookups on repeated calls to the same method. On first encounter:
//!
//! 1. Full metadata resolution: Arc lookups, `CilTypeReference` upgrades, signature parsing
//! 2. Name-based hook matching against the `HookManager` index
//! 3. Result cached as [`TokenCacheEntry::NoMatch`] (fast reject) or
//!    [`TokenCacheEntry::Cached`] (pre-resolved identity)
//!
//! Subsequent calls skip directly to hook execution (~95% of tokens are `NoMatch`).
//!
//! # Usage
//!
//! The `CallResolver` is constructed once by the `EmulationController` and shared
//! for the lifetime of the emulation. The main execution loop calls
//! [`resolve_call`](CallResolver::resolve_call) in a redirect loop, acting on the
//! returned [`CallResolution`] variant.
//!
//! Free functions [`push_method_frame`] and [`maybe_run_type_cctor`] handle
//! frame creation and type initialization, called directly from the execution loop.

use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use log::debug;

use crate::{
    emulation::{
        engine::{
            cctors::CctorTracker, context::EmulationContext, dispatch::DispatchResolver,
            error::synthetic_exception, generics::GenericRegistry, interpreter::Interpreter,
            resolution::CallResolution, typeops, EmulationError,
        },
        memory::{AddressSpace, HeapObject, TypeInitState},
        process::{EmulationConfig, UnknownMethodBehavior},
        runtime::{HookContext, HookManager, HookOutcome, RuntimeState},
        thread::{EmulationThread, MulticastState, ThreadCallFrame},
        tokens,
        tracer::{TraceEvent, TraceWriter},
        EmValue, SymbolicValue, TaintSource,
    },
    metadata::{
        signatures::TypeSignature,
        streams::SharedStr,
        tables::{MemberRef, MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilFlavor, CilTypeReference, FullName},
    },
    Result,
};

/// Cached result of token-to-hook resolution.
///
/// Populated lazily on the first call with each method token. Subsequent calls
/// with the same token skip all metadata resolution and name-based matching.
///
/// # Variants
///
/// - [`NoMatch`](Self::NoMatch) — No hook can match this token. The resolver
///   returns immediately without any metadata lookups or stack inspection. This
///   is the fast path for the ~95% of method calls that don't hit any hook.
///
/// - [`Cached`](Self::Cached) — A hook might (or does) match. Stores pre-resolved
///   name components and method metadata so that subsequent calls skip Phase 1
///   (metadata resolution) entirely and jump straight to context building and
///   hook execution.
enum TokenCacheEntry {
    /// No hook can match this token. Skip all name resolution and hook dispatch.
    NoMatch,

    /// Pre-resolved method identity and metadata for fast hook dispatch.
    ///
    /// On cache hit, the resolver skips the full metadata resolution (Arc lookups,
    /// `CilTypeReference` upgrades, signature parsing) and builds the `HookContext`
    /// directly from these cached values.
    Cached(ResolvedMethodInfo),
}

/// Pre-resolved method identity and metadata used for hook dispatch.
///
/// Groups the namespace, type name, method name, and calling convention
/// metadata needed to build a [`HookContext`] without re-resolving
/// metadata on every call.
#[derive(Clone)]
struct ResolvedMethodInfo {
    /// Namespace of the declaring type (e.g., `"System"`).
    namespace: Arc<str>,
    /// Name of the declaring type (e.g., `"String"`).
    type_name: Arc<str>,
    /// Name of the method (e.g., `"Concat"`).
    method_name: Arc<str>,
    /// Whether this is an internal (MethodDef) method.
    is_internal: bool,
    /// Number of declared parameters (excluding `this`).
    param_count: usize,
    /// Whether the method has a `this` parameter.
    has_this: bool,
}

/// Encapsulates method call resolution for the emulation engine.
///
/// The `CallResolver` owns the hook dispatch pipeline, virtual dispatch cache,
/// and token resolution cache. It is constructed once by the
/// [`EmulationController`](super::controller::EmulationController) and provides
/// the [`resolve_call`](Self::resolve_call) entry point for the main execution loop.
///
/// # Thread Safety
///
/// All methods take `&self` — concurrent access is safe because:
/// - [`DashMap`] provides lock-free concurrent reads/writes for the token cache
/// - [`DispatchResolver`] uses `DashMap` internally for virtual dispatch caching
/// - [`HookManager`] is immutable after construction (hooks registered during setup)
/// - [`RwLock<RuntimeState>`] provides synchronized access to runtime configuration
pub struct CallResolver {
    /// Direct reference to the hook manager for lock-free hook dispatch.
    /// Extracted from `RuntimeState` during construction. Since hooks are only
    /// registered during setup, this reference is effectively immutable.
    hooks: Arc<HookManager>,

    /// Token-to-hook resolution cache.
    ///
    /// Maps method tokens to pre-resolved metadata + match status, eliminating
    /// repeated metadata lookups and name matching for hot call sites.
    token_cache: DashMap<Token, TokenCacheEntry>,

    /// Cached virtual and interface method dispatch resolution.
    dispatch: DispatchResolver,

    /// Emulation configuration (provides pointer size, tracing settings).
    config: Arc<EmulationConfig>,

    /// Shared runtime state (for unknown method behavior configuration).
    runtime: Arc<RwLock<RuntimeState>>,

    /// Optional trace writer for hook invocation tracing.
    trace_writer: Option<Arc<TraceWriter>>,

    /// Generic type/method instantiation registry for MethodSpec resolution.
    generics: Arc<GenericRegistry>,
}

impl CallResolver {
    /// Creates a new call resolver with the given shared infrastructure.
    ///
    /// Extracts a direct `Arc<HookManager>` reference from the runtime state
    /// for lock-free hook dispatch during emulation.
    ///
    /// # Arguments
    ///
    /// * `runtime` — Shared runtime state containing the hook manager and
    ///   unknown-method behavior configuration.
    /// * `config` — Emulation configuration (pointer size, tracing settings).
    /// * `trace_writer` — Optional trace writer for hook invocation tracing.
    /// * `generics` — Generic instantiation registry for MethodSpec resolution.
    pub fn new(
        runtime: Arc<RwLock<RuntimeState>>,
        config: Arc<EmulationConfig>,
        trace_writer: Option<Arc<TraceWriter>>,
        generics: Arc<GenericRegistry>,
    ) -> Result<Self> {
        let hooks = runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime state",
            })?
            .hooks();
        Ok(Self {
            hooks,
            token_cache: DashMap::new(),
            dispatch: DispatchResolver::new(),
            config,
            runtime,
            trace_writer,
            generics,
        })
    }

    /// Returns a reference to the hook manager.
    ///
    /// Used by the execution loop for operations that need direct hook access
    /// (e.g., `newobj` resolution via [`typeops`]).
    #[must_use]
    pub fn hooks(&self) -> &HookManager {
        &self.hooks
    }

    /// Writes a trace event if tracing is enabled.
    #[inline]
    fn trace(&self, event: TraceEvent) {
        if let Some(ref writer) = self.trace_writer {
            writer.write(event);
        }
    }

    /// Checks if stub/hook tracing is enabled.
    #[inline]
    fn trace_stubs_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_stubs
    }

    /// Formats a method name from the token cache for trace output.
    ///
    /// # Arguments
    ///
    /// * `method_token` — Token of the method to format.
    ///
    /// # Returns
    ///
    /// `"Namespace.Type::Method"` if the token was previously resolved by the
    /// hook dispatch pipeline, or `"0xXXXXXXXX"` as fallback.
    #[must_use]
    pub fn format_method_name(&self, method_token: Token) -> String {
        if let Some(cached) = self.token_cache.get(&method_token) {
            if let TokenCacheEntry::Cached(info) = cached.value() {
                return if info.namespace.is_empty() {
                    format!("{}::{}", info.type_name, info.method_name)
                } else {
                    format!(
                        "{}.{}::{}",
                        info.namespace, info.type_name, info.method_name
                    )
                };
            }
        }
        format!("0x{:08X}", method_token.value())
    }

    /// Attempts to resolve a MemberRef by searching dynamically loaded assemblies.
    ///
    /// When the primary assembly references a method from an assembly loaded at
    /// runtime via `Assembly.Load(byte[])`, the MemberRef can't be resolved locally.
    /// This method searches all loaded assemblies for a type+method match and
    /// returns a [`CallResolution::EnterMethod`]-compatible redirect if found.
    ///
    /// # Returns
    ///
    /// `Some(CallResolution::Redirect)` if a matching MethodDef was found in a
    /// loaded assembly (with the appropriate `assembly_index` for frame tracking),
    /// `None` if the method couldn't be found in any loaded assembly.
    fn try_cross_assembly_resolve(
        &self,
        member_ref: &MemberRef,
        is_virtual: bool,
    ) -> Result<Option<CallResolution>> {
        let Some((namespace, type_name)) = EmulationContext::get_member_ref_type_info(member_ref)
        else {
            return Ok(None);
        };
        let method_name = &member_ref.name;
        let fullname = FullName::top_level(namespace, type_name);

        let state = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime state",
            })?;
        for i in 0..state.app_domain().parsed_assembly_count() {
            let Some(asm) = state.app_domain().get_parsed_assembly(i) else {
                continue;
            };
            let Some(cil_type) = asm.types().get_by_full_name(&fullname, true) else {
                continue;
            };
            if let Some(method) = cil_type.find_method(method_name) {
                debug!(
                    "Cross-assembly resolve: {}.{} → asm[{}] 0x{:08X}",
                    fullname,
                    method_name,
                    i,
                    method.token.value()
                );
                return Ok(Some(CallResolution::Redirect {
                    target_token: method.token,
                    arguments: vec![],
                    is_virtual,
                    pre_push_value: None,
                    is_reflection_invoke: false,
                    // The index must survive intact: it is what binds the new frame to the
                    // metadata the token was resolved against. A narrowing conversion here
                    // wraps a large index onto a different assembly's `EmulationContext`,
                    // which executes a valid token against the wrong method table.
                    // Unreachable in practice: `max_loaded_assemblies` bounds the list far
                    // below `u32::MAX`, so this is an invariant check, not a runtime path.
                    assembly_index: Some(u32::try_from(i).map_err(|_| {
                        EmulationError::InternalError {
                            description: format!("assembly index {i} exceeds u32"),
                        }
                    })?),
                    method_type_args: None,
                }));
            }
        }
        Ok(None)
    }

    /// Resolves a method call to a [`CallResolution`] without touching the
    /// instruction pointer or call stack.
    ///
    /// This is the main entry point for call resolution. The execution loop
    /// calls this in a redirect loop and acts on the returned variant:
    ///
    /// - [`HookedBypass`](CallResolution::HookedBypass) — Hook handled the call
    /// - [`ReturnSynthetic`](CallResolution::ReturnSynthetic) — Synthetic return value
    /// - [`EnterMethod`](CallResolution::EnterMethod) — Enter the method body
    /// - [`ThrowException`](CallResolution::ThrowException) — Throw a CLR exception
    /// - [`Redirect`](CallResolution::Redirect) — Redirect to another method token
    ///
    /// # Resolution Order
    ///
    /// 0. **Runtime-type hook**: for `callvirt` through a MemberRef, the hook of the
    ///    receiver's runtime type, where it differs from the declared type (a CryptoStream
    ///    written through `Stream::Write`)
    /// 1. **Hook dispatch** — Check registered hooks via the token cache
    /// 2. **P/Invoke** — Check native stubs for unmanaged methods
    /// 3. **MethodSpec** — Resolve generic method instantiations
    /// 4. **MemberRef** — Resolve external method references
    /// 5. **Virtual dispatch** — Resolve callvirt to the runtime override
    /// 6. **Delegate dispatch** — Redirect `Invoke` to the delegate target
    /// 7. **Method body** — Enter the IL method body for emulation
    ///
    /// # Arguments
    ///
    /// * `context` — Assembly metadata context for method lookup.
    /// * `method_token` — Token of the method to resolve (MethodDef, MemberRef,
    ///   or MethodSpec).
    /// * `thread` — The emulation thread (for stack inspection, args, and heap).
    /// * `is_virtual` — `true` for `callvirt` instructions (enables virtual dispatch).
    /// * `constrained_type` — When set, the `constrained.` prefix type token.
    ///
    /// # Returns
    ///
    /// A [`CallResolution`] variant instructing the execution loop what to do next.
    ///
    /// # Errors
    ///
    /// Returns an error if method metadata lookup fails or the hook throws
    /// an unrecoverable error.
    pub fn resolve_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
        is_virtual: bool,
        constrained_type: Option<Token>,
        address_space: &AddressSpace,
    ) -> Result<CallResolution> {
        // `callvirt` reaches the override of the receiver's runtime type: a user method
        // overriding the named one runs before any hook, and the runtime type's hook before
        // the declared method's
        if is_virtual && method_token.is_table(TableId::MemberRef) {
            if let Some(resolution) = self.try_member_ref_override(context, method_token, thread)? {
                return Ok(resolution);
            }
            if let Some(resolution) = self.try_runtime_type_hook(context, method_token, thread)? {
                return Ok(resolution);
            }
        }

        // Then the hooks of the method as named (highest priority after dispatch)
        match self.try_hook_call(context, method_token, thread)? {
            HookOutcome::ReflectionInvoke {
                request,
                bypass_value,
            } => {
                if self.trace_stubs_enabled() {
                    let name = self.format_method_name(method_token);
                    self.trace(TraceEvent::HookInvoke {
                        method: method_token,
                        hook_name: format!("{name} [reflection-invoke]"),
                        bypassed: false,
                        return_value: None,
                    });
                }

                let request = *request;
                let target_token = request.method_token;

                if target_token.is_table(TableId::MethodDef) {
                    // For ConstructorInfo.Invoke: the hook's return value IS the result
                    // (the newly allocated object). Push it before entering the constructor
                    // so it's preserved in the caller's saved stack.
                    //
                    // For MethodBase.Invoke (non-constructor): the method's return value
                    // is pushed by the callee naturally — no pre-push needed, UNLESS the
                    // target is void. MethodBase.Invoke always returns Object, so void
                    // targets need a Null pre-push to satisfy the caller's stack.
                    let is_ctor_invoke = context
                        .get_method(target_token)
                        .map(|m| m.name == ".ctor")
                        .unwrap_or(false);
                    let target_returns_value =
                        context.method_returns_value(target_token).unwrap_or(false);
                    let pre_push = if is_ctor_invoke {
                        bypass_value.clone()
                    } else if !target_returns_value {
                        // Void method: Invoke returns null
                        Some(EmValue::Null)
                    } else {
                        None
                    };

                    // Build arguments for the reflected method.
                    // For instance methods, always include this_ref (even null) as arg[0]
                    // — real .NET passes null `this` and the NullRef happens when the
                    // method body dereferences it, not at call setup. For static methods,
                    // skip the this_ref entirely (it's always null for statics).
                    let is_static = context.is_static_method(target_token).unwrap_or(true);
                    let mut args = Vec::new();
                    if let Some(this_val) = request.this_ref {
                        if !is_static {
                            args.push(this_val);
                        }
                    }
                    args.extend(request.args);

                    return Ok(CallResolution::Redirect {
                        target_token,
                        arguments: args,
                        is_virtual: false,
                        pre_push_value: pre_push,
                        is_reflection_invoke: true,
                        assembly_index: None,
                        method_type_args: request.method_type_args,
                    });
                }

                // Target is not a MethodDef — can't invoke via reflection.
                // Push the placeholder return value so the caller's stack is correct.
                return Ok(CallResolution::HookedBypass {
                    return_value: bypass_value,
                });
            }
            HookOutcome::Handled(value) => {
                if self.trace_stubs_enabled() {
                    let name = self.format_method_name(method_token);
                    self.trace(TraceEvent::HookInvoke {
                        method: method_token,
                        hook_name: name,
                        bypassed: true,
                        return_value: value.as_ref().map(|v| format!("{v}")),
                    });
                }
                if let Some(EmValue::Symbolic(ref sym)) = value {
                    debug!(
                        "Hook for 0x{:08X} returned Symbolic({:?}, source={:?})",
                        method_token.value(),
                        sym.cil_flavor,
                        sym.source,
                    );
                }
                return Ok(CallResolution::HookedBypass {
                    return_value: self.checked_hook_return(context, method_token, value)?,
                });
            }
            HookOutcome::ThrewException {
                exception_type,
                message,
            } => {
                return Ok(CallResolution::ThrowException {
                    exception_type,
                    message,
                });
            }
            HookOutcome::NoMatch => { /* continue to next resolution step */ }
        }

        // Then try native stubs for P/Invoke methods
        if let Some(result) = self.try_native_call(context, method_token, thread)? {
            if self.trace_stubs_enabled() {
                self.trace(TraceEvent::HookInvoke {
                    method: method_token,
                    hook_name: format!("{} [native]", self.format_method_name(method_token)),
                    bypassed: true,
                    return_value: result.as_ref().map(|v| format!("{v}")),
                });
            }
            return Ok(CallResolution::HookedBypass {
                return_value: result,
            });
        }

        // Handle synthetic methods (from DynamicMethod/ILGenerator)
        if context.is_synthetic_method(method_token) {
            let is_static = context.is_static_method(method_token)?;
            let param_types = context.get_parameter_types(method_token)?;
            let total_args = if is_static {
                param_types.len()
            } else {
                param_types.len().saturating_add(1)
            };
            let arg_values = thread.pop_args(total_args)?;
            let expects_return = context.method_returns_value(method_token)?;
            return Ok(CallResolution::EnterMethod {
                token: method_token,
                arguments: arg_values,
                expects_return,
                assembly_index: None,
                method_type_args: None,
            });
        }

        // Handle MethodSpec tokens (generic method instantiations)
        if method_token.is_table(TableId::MethodSpec) {
            if let Some(method_spec) = context.get_method_spec(method_token) {
                if let Some(underlying_token) =
                    EmulationContext::resolve_method_spec_to_token(&method_spec)
                {
                    // Extract generic type arguments from the MethodSpec signature.
                    // These are the concrete types for !!0, !!1, etc.
                    let type_args: Vec<Token> = method_spec
                        .instantiation
                        .generic_args
                        .iter()
                        .filter_map(|sig| {
                            // Resolve from current frame's generic context
                            let frame_type_args = thread
                                .current_frame()
                                .and_then(|f| f.type_type_args().map(|a| a.to_vec()));
                            let frame_method_args = thread
                                .current_frame()
                                .and_then(|f| f.method_type_args().map(|a| a.to_vec()));
                            context.type_signature_to_token(
                                sig,
                                frame_type_args.as_deref(),
                                frame_method_args.as_deref(),
                                &self.generics,
                            )
                        })
                        .collect();

                    let method_type_args = if type_args.is_empty() {
                        None
                    } else {
                        Some(type_args)
                    };

                    return Ok(CallResolution::Redirect {
                        target_token: underlying_token,
                        arguments: vec![],
                        is_virtual,
                        is_reflection_invoke: false,
                        pre_push_value: None,
                        assembly_index: None,
                        method_type_args,
                    });
                }
            }

            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // A delegate's `Invoke` through a MemberRef (`Action`, `Func` and every other delegate
        // type of another assembly) dispatches as one through a MethodDef does. It fell
        // through to an unhooked MemberRef, answered with a symbolic value, and the delegate's
        // method never ran.
        if method_token.is_table(TableId::MemberRef) {
            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let MemberRefSignature::Method(signature) = &member_ref.signature {
                    if member_ref.name == "Invoke" && signature.has_this {
                        let total_args = (signature.param_count as usize).saturating_add(1);
                        let receiver = thread.peek_args(total_args)?.into_iter().next();
                        let is_delegate = matches!(
                            receiver,
                            Some(EmValue::ObjectRef(href))
                                if matches!(
                                    thread.heap().get_shared(href).as_deref(),
                                    Ok(HeapObject::Delegate { .. })
                                )
                        );
                        if is_delegate {
                            let arg_values = thread.pop_args(total_args)?;
                            if let Some(resolution) = self.dispatch_delegate_invoke(
                                context,
                                thread,
                                method_token,
                                &arg_values,
                            )? {
                                return Ok(resolution);
                            }
                            for arg in arg_values {
                                thread.push(arg)?;
                            }
                        }
                    }
                }
            }
        }

        // Handle MemberRef tokens (external methods) without stubs
        if method_token.is_table(TableId::MemberRef) {
            // Try resolving MemberRef → local MethodDef before returning Symbolic
            if let Some(resolved) = context.assembly().resolver().resolve_method(method_token) {
                if resolved.is_table(TableId::MethodDef) {
                    return Ok(CallResolution::Redirect {
                        target_token: resolved,
                        arguments: vec![],
                        is_virtual,
                        pre_push_value: None,
                        is_reflection_invoke: false,
                        assembly_index: None,
                        method_type_args: None,
                    });
                }
            }

            // Try cross-assembly resolution: the MemberRef may reference a method
            // in a dynamically loaded assembly (via Assembly.Load). Search loaded
            // assemblies by declaring type + method name.
            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let Some(resolution) =
                    self.try_cross_assembly_resolve(&member_ref, is_virtual)?
                {
                    return Ok(resolution);
                }
            }

            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
                    let total_args = if method_sig.has_this {
                        (method_sig.param_count as usize).saturating_add(1)
                    } else {
                        method_sig.param_count as usize
                    };

                    // Pop arguments from stack
                    for _ in 0..total_args {
                        thread.pop()?;
                    }

                    // Get declaring type info for better diagnostics
                    let type_info = EmulationContext::get_member_ref_type_info(&member_ref);
                    let type_desc = type_info
                        .as_ref()
                        .map(|(ns, tn)| format!("{ns}.{tn}"))
                        .unwrap_or_else(|| "Unknown".to_string());

                    // Return symbolic value if the method has a return type
                    let value = if !matches!(method_sig.return_type.base, TypeSignature::Void) {
                        let return_type = CilFlavor::from(&method_sig.return_type.base);
                        debug!(
                            "Unhooked MemberRef 0x{:08X} '{}.{}' → returning Symbolic({:?})",
                            method_token.value(),
                            type_desc,
                            member_ref.name,
                            return_type
                        );
                        Some(EmValue::Symbolic(SymbolicValue::new(
                            return_type,
                            TaintSource::MethodReturn(method_token.value()),
                        )))
                    } else {
                        debug!(
                            "Unhooked MemberRef 0x{:08X} '{}.{}' → void (no return)",
                            method_token.value(),
                            type_desc,
                            member_ref.name,
                        );
                        None
                    };

                    if self.trace_stubs_enabled() {
                        self.trace(TraceEvent::HookInvoke {
                            method: method_token,
                            hook_name: format!("{}.{} [synthetic]", type_desc, member_ref.name),
                            bypassed: true,
                            return_value: value.as_ref().map(|v| format!("{v}")),
                        });
                    }
                    return Ok(CallResolution::ReturnSynthetic { value });
                }
            }

            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // Get method signature for internal method
        let method = context.get_method(method_token)?;

        let param_count = method.signature.params.len();
        let is_instance = !context.is_static_method(method_token)?;
        let total_args = if is_instance {
            param_count.saturating_add(1)
        } else {
            param_count
        };

        // Pop arguments from stack (in correct order)
        let mut arg_values = thread.pop_args(total_args)?;

        // Resolve virtual dispatch if this is a callvirt instruction
        let resolved_method_token = if is_virtual && is_instance && !arg_values.is_empty() {
            if let Some(constraint_token) = constrained_type {
                // constrained. callvirt: resolve against the constraint type, not runtime type.
                // For value types that override (e.g., Int32.ToString()), this finds the override.
                // For reference types or value types without an override, falls back to the
                // declared method (normal virtual dispatch will apply).
                let resolved = context.resolve_virtual_call(method_token, constraint_token);

                // ECMA-335 III.2.1: If the constraint type is a value type and it does NOT
                // override the method, box the value type and use the boxed ref as 'this'.
                if resolved == method_token && context.is_value_type(constraint_token) {
                    let ptr_opt = match arg_values.first() {
                        Some(EmValue::ManagedPtr(ptr)) => Some(ptr.clone()),
                        _ => None,
                    };
                    if let Some(ptr) = ptr_opt {
                        if let Ok(value) = typeops::deref_managed_ptr(address_space, thread, &ptr) {
                            let boxed = thread.heap_mut().alloc_boxed(constraint_token, value)?;
                            if let Some(slot) = arg_values.first_mut() {
                                *slot = EmValue::ObjectRef(boxed);
                            }
                        }
                    }
                }
                resolved
            } else {
                let Some(this_arg) = arg_values.first() else {
                    return Err(out_of_bounds_error!());
                };
                self.resolve_virtual_dispatch(context, thread, method_token, this_arg)
            }
        } else {
            method_token
        };

        // Re-fetch method if we resolved to a different one
        let method = if resolved_method_token == method_token {
            method
        } else {
            context.get_method(resolved_method_token)?
        };

        // Check if this is a native method (x86 code, not IL)
        if method.is_code_native() && method.is_code_unmanaged() {
            return Err(EmulationError::InternalError {
                description: format!(
                    "Cannot emulate native x86 method 0x{:08x} '{}'. \
                     Native methods must be converted to CIL during deobfuscation.",
                    resolved_method_token.value(),
                    method.name
                ),
            }
            .into());
        }

        // Delegate dispatch: a `runtime managed` method named "Invoke" on a delegate object
        // runs the delegate's entries
        if method.is_code_runtime() && method.name == "Invoke" && is_instance {
            if let Some(resolution) =
                self.dispatch_delegate_invoke(context, thread, resolved_method_token, &arg_values)?
            {
                return Ok(resolution);
            }
        }

        // Check if we should emulate or return symbolic
        let has_instructions = method.instructions().next().is_some();
        let default_behavior = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?
            .unknown_method_behavior();
        match default_behavior {
            UnknownMethodBehavior::Emulate => {
                if method.has_body() && has_instructions {
                    let expects_return = context.method_returns_value(resolved_method_token)?;
                    return Ok(CallResolution::EnterMethod {
                        token: resolved_method_token,
                        arguments: arg_values,
                        expects_return,
                        assembly_index: None,
                        method_type_args: None,
                    });
                }
                // No body, likely a P/Invoke: its result is symbolic. A void method has
                // none, and pushing one left a value on the caller's stack that no
                // instruction pops.
                let value = context
                    .get_return_type(resolved_method_token)?
                    .map(|return_flavor| {
                        EmValue::Symbolic(SymbolicValue::new(
                            return_flavor,
                            TaintSource::MethodReturn(resolved_method_token.value()),
                        ))
                    });
                Ok(CallResolution::ReturnSynthetic { value })
            }

            UnknownMethodBehavior::Symbolic => {
                // A symbolic result for a method returning one; a void method has none
                let value = context
                    .get_return_type(resolved_method_token)?
                    .map(|return_flavor| {
                        EmValue::Symbolic(SymbolicValue::new(
                            return_flavor,
                            TaintSource::MethodReturn(resolved_method_token.value()),
                        ))
                    });
                Ok(CallResolution::ReturnSynthetic { value })
            }

            UnknownMethodBehavior::Fail => Err(EmulationError::UnsupportedMethod {
                token: resolved_method_token,
                reason: "No hook registered and Fail behavior configured",
            }
            .into()),

            UnknownMethodBehavior::Default => {
                let return_flavor = context.get_return_type(resolved_method_token)?;
                let value = return_flavor.and_then(|flavor| match flavor {
                    CilFlavor::Void => None,
                    CilFlavor::Boolean
                    | CilFlavor::I1
                    | CilFlavor::U1
                    | CilFlavor::I2
                    | CilFlavor::U2
                    | CilFlavor::I4
                    | CilFlavor::U4
                    | CilFlavor::Char => Some(EmValue::I32(0)),
                    CilFlavor::I8 | CilFlavor::U8 => Some(EmValue::I64(0)),
                    CilFlavor::R4 => Some(EmValue::F32(0.0)),
                    CilFlavor::R8 => Some(EmValue::F64(0.0)),
                    CilFlavor::I | CilFlavor::U => Some(EmValue::NativeInt(0)),
                    _ => Some(EmValue::Null),
                });
                Ok(CallResolution::ReturnSynthetic { value })
            }

            UnknownMethodBehavior::Skip => Ok(CallResolution::ReturnSynthetic { value: None }),
        }
    }
    /// Dispatches a delegate's `Invoke` (`invoke_token`) to the method its invocation list
    /// names, with `arg_values` the arguments `Invoke` was called with, the delegate first.
    ///
    /// A closed delegate passes its target as the first argument; a multicast delegate runs
    /// one entry per `Invoke`, the controller reissuing it for each next entry (see
    /// [`MulticastState`]). A native function pointer runs through its hook.
    ///
    /// # Returns
    ///
    /// The resolution that runs the entry, or `None` when the receiver is no delegate (or its
    /// list is empty) and the call resolves as any other.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap or a native hook fails.
    fn dispatch_delegate_invoke(
        &self,
        context: &EmulationContext,
        thread: &mut EmulationThread,
        invoke_token: Token,
        arg_values: &[EmValue],
    ) -> Result<Option<CallResolution>> {
        if let Some(EmValue::ObjectRef(href)) = arg_values.first() {
            match thread.heap().get_shared(*href).as_deref() {
                Ok(HeapObject::Delegate {
                    invocation_list, ..
                }) => {
                    // A multicast delegate runs its entries in order, one per `Invoke`:
                    // the controller reissues the `Invoke` for each next entry (see
                    // `MulticastState`), which starts here at the entry it recorded.
                    let start = thread.take_delegate_resume(*href);
                    if let Some(entry) = invocation_list.get(start) {
                        let target_token = entry.method_token;
                        let delegate_target = entry.target;
                        // The entries after this one, for the controller to run next
                        let multicast =
                            (invocation_list.len() > start.saturating_add(1)).then(|| {
                                MulticastState {
                                    delegate: *href,
                                    invoke_args: arg_values.to_vec(),
                                    next_entry: start.saturating_add(1),
                                    call_offset: 0,
                                }
                            });
                        // A closed delegate (one bound to a target) passes its target as
                        // the first argument, as the CLR does: `this` of an instance
                        // method, or the first parameter of a static one closed over it.
                        // An open delegate passes the arguments alone.
                        let delegate_args: Vec<EmValue> = delegate_target
                            .map(EmValue::ObjectRef)
                            .into_iter()
                            .chain(arg_values.iter().skip(1).cloned())
                            .collect();

                        // Native function pointer delegates use synthetic
                        // tokens allocated per-function by the registry.
                        // Look up the function name and return an
                        // appropriate value for each native API.
                        if tokens::is_native_function_pointer(target_token) {
                            // Element 0 is the delegate itself; the rest are
                            // the arguments the native function was called
                            // with, and a hook needs them to do its work.
                            let native_args: Vec<EmValue> =
                                arg_values.iter().skip(1).cloned().collect();
                            let return_value =
                                self.dispatch_native_delegate(target_token, &native_args, thread)?;
                            if let Some(state) = multicast {
                                thread.set_multicast_state(state);
                            }
                            return Ok(Some(CallResolution::HookedBypass { return_value }));
                        }

                        // Resolve MemberRef → MethodDef if the target is local
                        let mut dispatch_token = if target_token.is_table(TableId::MemberRef) {
                            context
                                .assembly()
                                .resolver()
                                .resolve_method(target_token)
                                .filter(|t| t.is_table(TableId::MethodDef))
                                .unwrap_or(target_token)
                        } else {
                            target_token
                        };

                        let should_dispatch = if context.is_synthetic_method(dispatch_token) {
                            // Synthetic methods from DynamicMethod/ILGenerator
                            // are always dispatchable.
                            true
                        } else if dispatch_token.is_table(TableId::MethodDef) {
                            let has_il = context
                                .get_method(dispatch_token)
                                .map(|m| m.has_body() && m.instructions().next().is_some())
                                .unwrap_or(false);
                            if has_il {
                                true
                            } else {
                                let is_virtual = context
                                    .get_method(dispatch_token)
                                    .map(|m| m.is_virtual())
                                    .unwrap_or(false);

                                if is_virtual {
                                    let instance_ref = delegate_target.or_else(|| {
                                        arg_values.get(1).and_then(|v| match v {
                                            EmValue::ObjectRef(r) => Some(*r),
                                            _ => None,
                                        })
                                    });

                                    if let Some(inst_ref) = instance_ref {
                                        let resolved = self.resolve_virtual_dispatch(
                                            context,
                                            thread,
                                            dispatch_token,
                                            &EmValue::ObjectRef(inst_ref),
                                        );
                                        if resolved != dispatch_token {
                                            let resolved_has_il = context
                                                .get_method(resolved)
                                                .map(|m| {
                                                    m.has_body()
                                                        && m.instructions().next().is_some()
                                                })
                                                .unwrap_or(false);
                                            if resolved_has_il {
                                                dispatch_token = resolved;
                                                true
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }
                        } else {
                            false
                        };

                        if should_dispatch {
                            if let Some(state) = multicast {
                                thread.set_multicast_state(state);
                            }

                            return Ok(Some(CallResolution::Redirect {
                                target_token: dispatch_token,
                                arguments: delegate_args,
                                is_virtual: false,
                                pre_push_value: None,
                                is_reflection_invoke: false,
                                assembly_index: None,
                                method_type_args: None,
                            }));
                        }

                        if target_token.is_table(TableId::MemberRef) {
                            if let Some(state) = multicast {
                                thread.set_multicast_state(state);
                            }

                            return Ok(Some(CallResolution::Redirect {
                                target_token,
                                arguments: delegate_args,
                                is_virtual: false,
                                pre_push_value: None,
                                is_reflection_invoke: false,
                                assembly_index: None,
                                method_type_args: None,
                            }));
                        }

                        debug!(
                            "delegate dispatch failed: target 0x{:08X} has no concrete implementation",
                            target_token.value()
                        );
                        return Ok(Some(CallResolution::ThrowException {
                            exception_type: synthetic_exception::INVALID_OPERATION,
                            message: format!(
                                "delegate target 0x{:08X} has no concrete implementation",
                                target_token.value()
                            ),
                        }));
                    }
                }
                Ok(other) => {
                    debug!(
                        "Delegate Invoke on {:?}: this is {}, not a Delegate: dispatch skipped",
                        invoke_token,
                        other.kind(),
                    );
                }
                Err(_) => {
                    debug!(
                        "Delegate Invoke on {:?}: heap lookup failed for {:?}",
                        invoke_token, href,
                    );
                }
            }
        } else {
            debug!(
                "Delegate Invoke on {:?}: this is {:?}, not an ObjectRef",
                invoke_token,
                arg_values.first(),
            );
        }
        Ok(None)
    }

    /// Enters the method of the receiver's runtime type that overrides the one a `callvirt`
    /// names by a MemberRef, as the CLR dispatches it: a user type overriding `ToString`,
    /// `Dispose` or `Stream.Read` runs its own method, not the BCL method's hook.
    ///
    /// # Returns
    /// `None` when the receiver is not an object, its type does not override the method,
    /// the override has no body to emulate, or methods without hooks are not emulated:
    /// the hooks and the declared method then answer the call.
    ///
    /// # Errors
    /// Returns an error when the arguments cannot be read off the stack.
    fn try_member_ref_override(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<CallResolution>> {
        let Some(member_ref) = context.get_member_ref(method_token) else {
            return Ok(None);
        };
        let MemberRefSignature::Method(method_sig) = &member_ref.signature else {
            return Ok(None);
        };
        if !method_sig.has_this {
            return Ok(None);
        }
        let total_args = (method_sig.param_count as usize).saturating_add(1);
        let resolved = {
            let args = thread.peek_args(total_args)?;
            let Some(this_arg) = args.first() else {
                return Err(out_of_bounds_error!());
            };
            self.resolve_virtual_dispatch(context, thread, method_token, this_arg)
        };
        if resolved == method_token || !resolved.is_table(TableId::MethodDef) {
            return Ok(None);
        }
        let method = context.get_method(resolved)?;
        if !method.has_body() || method.instructions().next().is_none() {
            return Ok(None);
        }
        let emulates = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?
            .unknown_method_behavior()
            == UnknownMethodBehavior::Emulate;
        if !emulates {
            return Ok(None);
        }
        let arguments = thread.pop_args(total_args)?;
        let expects_return = context.method_returns_value(resolved)?;
        Ok(Some(CallResolution::EnterMethod {
            token: resolved,
            arguments,
            expects_return,
            assembly_index: None,
            method_type_args: None,
        }))
    }

    /// Runs the hook of the receiver's runtime type for a `callvirt` through a MemberRef,
    /// before the hook of the declared method.
    ///
    /// `callvirt` reaches the override the runtime type of `this` declares (ECMA-335
    /// §III.3.19), and compilers name the method where it was first declared: C# compiles
    /// `cryptoStream.Write(...)` to `callvirt Stream::Write`. A hook registered for the
    /// declared type (`Stream.Write`) would otherwise handle a `CryptoStream`, a
    /// `DeflateStream` or a `StreamReader` as the base type it knows, reading nothing or
    /// dropping what is written. So when the runtime type differs from the declared type
    /// and has a hook for the method, that hook runs; otherwise the declared method's hook
    /// and the rest of resolution follow as before.
    ///
    /// # Returns
    ///
    /// The resolution when the runtime type's hook handled the call, with the arguments
    /// popped; `None` when no such hook matched, with the stack untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if the arguments cannot be read or the hook fails.
    fn try_runtime_type_hook(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<CallResolution>> {
        let Some(member_ref) = context.get_member_ref(method_token) else {
            return Ok(None);
        };
        let MemberRefSignature::Method(method_sig) = &member_ref.signature else {
            return Ok(None);
        };
        if !method_sig.has_this {
            return Ok(None);
        }
        let total_args = (method_sig.param_count as usize).saturating_add(1);
        let args = thread.peek_args(total_args)?;
        let Some((this_arg, rest_args)) = args.split_first() else {
            return Err(out_of_bounds_error!());
        };
        let EmValue::ObjectRef(heap_ref) = this_arg else {
            return Ok(None);
        };
        let Ok(runtime_type_token) = thread.heap().get_type_token(*heap_ref) else {
            return Ok(None);
        };
        let Some(runtime_type) = context.get_type(runtime_type_token) else {
            return Ok(None);
        };
        let rt_namespace = if runtime_type.namespace.is_empty() {
            runtime_type
                .enclosing_type()
                .map(|enc| enc.namespace.clone())
                .filter(|ns| !ns.is_empty())
                .unwrap_or_default()
        } else {
            runtime_type.namespace.clone()
        };
        let rt_type_name = &runtime_type.name;

        // The declared type's own hook is the declared method's: nothing to dispatch
        let declared_type_info = EmulationContext::get_member_ref_type_info(&member_ref);
        if declared_type_info
            .as_ref()
            .is_some_and(|(dns, dtn)| dns == &rt_namespace && dtn == rt_type_name.as_str())
        {
            return Ok(None);
        }

        let param_types = context.get_parameter_types(method_token).ok();
        // `Void` for a void method; `None` only when the signature cannot be read
        let return_type = context
            .get_return_type(method_token)
            .ok()
            .map(|flavor| flavor.unwrap_or(CilFlavor::Void));
        let hook_context = HookContext::new(
            method_token,
            &rt_namespace,
            rt_type_name,
            &member_ref.name,
            self.config.pointer_size,
        )
        .with_this(Some(this_arg))
        .with_args(rest_args)
        .with_param_types(param_types.as_deref())
        .with_return_type(return_type);

        let resolution = match self.hooks.execute(&hook_context, thread, |_| None)? {
            HookOutcome::Handled(value) => {
                if self.trace_stubs_enabled() {
                    self.trace(TraceEvent::HookInvoke {
                        method: method_token,
                        hook_name: format!(
                            "{}.{}.{} [virtual dispatch]",
                            rt_namespace, rt_type_name, member_ref.name
                        ),
                        bypassed: true,
                        return_value: value.as_ref().map(|v| format!("{v}")),
                    });
                }
                CallResolution::HookedBypass {
                    return_value: self.checked_hook_return(context, method_token, value)?,
                }
            }
            HookOutcome::ThrewException {
                exception_type,
                message,
            } => CallResolution::ThrowException {
                exception_type,
                message,
            },
            // A reflection redirect does not arise from a stream or reader hook
            HookOutcome::ReflectionInvoke { .. } => {
                CallResolution::HookedBypass { return_value: None }
            }
            HookOutcome::NoMatch => return Ok(None),
        };
        thread.pop_args(total_args)?;
        Ok(Some(resolution))
    }

    /// Resolves virtual dispatch to find the actual method to call.
    ///
    /// For virtual method calls (`callvirt`), this resolves the declared method
    /// to the actual implementation based on the runtime type of the `this`
    /// object. Uses the [`DispatchResolver`] cache for O(1) repeated lookups.
    ///
    /// # Arguments
    ///
    /// * `context` — Assembly metadata context for type/method lookup.
    /// * `thread` — The emulation thread (for heap access to get runtime type).
    /// * `declared_method` — Token of the method as declared in the instruction.
    /// * `this_arg` — The `this` object value (must be `ObjectRef` for virtual
    ///   dispatch to take effect).
    ///
    /// # Returns
    ///
    /// The resolved method token. If virtual dispatch cannot be performed
    /// (e.g., `this` is null, type unknown, method not overridden), returns
    /// `declared_method` unchanged.
    pub fn resolve_virtual_dispatch(
        &self,
        context: &EmulationContext,
        thread: &EmulationThread,
        declared_method: Token,
        this_arg: &EmValue,
    ) -> Token {
        // Get the runtime type of the 'this' object
        let runtime_type = match this_arg {
            EmValue::ObjectRef(heap_ref) => {
                match thread.heap().get_type_token(*heap_ref) {
                    Ok(token) => token,
                    Err(_) => return declared_method, // Can't get type, use declared
                }
            }
            _ => return declared_method, // Null or other non-object type
        };

        // Use the cached dispatch resolver (handles both class virtual and interface dispatch)
        self.dispatch
            .resolve(declared_method, runtime_type, context)
    }

    /// Tries to execute a method call via a hook.
    ///
    /// Hooks provide flexible method interception with matching criteria and
    /// bypass capabilities. This method creates a [`HookContext`] and checks
    /// registered hooks in priority order.
    ///
    /// Uses a multi-phase resolution strategy:
    /// 1. **Cache hit** — Token already resolved, skip metadata lookups
    /// 2. **Metadata resolution** — Extract method identity from `MethodDef`/`MemberRef`
    /// 3. **Fast reject** — O(1) hash lookup against the hook registry index
    /// 4. **Context build + execute** — Build `HookContext` and run matching hooks
    ///
    /// # Returns
    ///
    /// - [`HookOutcome::Handled`] — Hook matched and returned a value
    /// - [`HookOutcome::ReflectionInvoke`] — Hook resolved a reflection redirect
    /// - [`HookOutcome::ThrewException`] — Hook threw a CLR exception
    /// - [`HookOutcome::NoMatch`] — No matching hook found
    fn try_hook_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<HookOutcome> {
        // Fast path: check token cache for previously resolved tokens.
        // This eliminates all metadata lookups and name matching for tokens
        // we've already seen.
        if let Some(cached) = self.token_cache.get(&method_token) {
            return match cached.value() {
                TokenCacheEntry::NoMatch => Ok(HookOutcome::NoMatch),
                TokenCacheEntry::Cached(info) => {
                    // Drop the DashMap guard before doing any mutable thread work
                    let info = info.clone();
                    drop(cached);

                    self.execute_hook_with_resolved(context, method_token, thread, &info)
                }
            };
        }

        // Cache miss: full metadata resolution path.
        // Phase 1: Extract lightweight method identity.
        // Keep Arc handles alive at function scope so we can borrow &str from them
        // without any String cloning.
        let member_ref_arc;
        let method_arc;
        let declaring_type_arc;
        let is_internal: bool;
        let param_count: usize;
        let has_this: bool;

        if method_token.is_table(TableId::MemberRef) {
            // MemberRef (external method)
            let Some(mr) = context.get_member_ref(method_token) else {
                self.token_cache
                    .insert(method_token, TokenCacheEntry::NoMatch);
                return Ok(HookOutcome::NoMatch);
            };

            // Upgrade the declaring type weak reference to get namespace/type (O(1))
            declaring_type_arc = match &mr.declaredby {
                CilTypeReference::TypeRef(r)
                | CilTypeReference::TypeDef(r)
                | CilTypeReference::TypeSpec(r) => r.upgrade(),
                _ => None,
            };

            let (count, ht) = match &mr.signature {
                MemberRefSignature::Method(sig) => (sig.param_count as usize, sig.has_this),
                MemberRefSignature::Field(_) => {
                    self.token_cache
                        .insert(method_token, TokenCacheEntry::NoMatch);
                    return Ok(HookOutcome::NoMatch);
                }
            };

            member_ref_arc = Some(mr);
            method_arc = None;
            is_internal = false;
            param_count = count;
            has_this = ht;
        } else {
            // MethodDef (internal method)
            let Ok(method) = context.get_method(method_token) else {
                self.token_cache
                    .insert(method_token, TokenCacheEntry::NoMatch);
                return Ok(HookOutcome::NoMatch);
            };

            declaring_type_arc = method.declaring_type_rc();
            let ht = !method.is_static();
            let pc = method.signature.params.len();

            method_arc = Some(method);
            member_ref_arc = None;
            is_internal = true;
            param_count = pc;
            has_this = ht;
        }

        // Borrow &str from the Arc handles — zero allocation
        let raw_namespace = declaring_type_arc
            .as_ref()
            .map_or("", |dt| dt.namespace.as_str());
        let type_name = declaring_type_arc
            .as_ref()
            .map_or("", |dt| dt.name.as_str());

        // Resolve namespace from enclosing type for nested types.
        // In .NET, nested types have empty namespace in metadata but inherit their
        // enclosing type's namespace (e.g., List`1/Enumerator → "System.Collections.Generic").
        let enclosing_ns: Option<SharedStr>;
        let namespace = if raw_namespace.is_empty() {
            enclosing_ns = declaring_type_arc
                .as_ref()
                .and_then(|dt| {
                    // First try: direct enclosing_type on the CilType.
                    let enc = dt.enclosing_type()?;
                    if enc.namespace.is_empty() {
                        None
                    } else {
                        Some(enc.namespace.clone())
                    }
                })
                .or_else(|| {
                    // Fallback for TypeSpec generic instantiations of nested types:
                    // Parse the TypeSpec blob to find the underlying TypeRef/TypeDef
                    // and check its enclosing type.
                    let dt = declaring_type_arc.as_ref()?;
                    if !dt.token.is_table(TableId::TypeSpec) {
                        return None;
                    }
                    let sig = context.get_typespec_signature(dt.token)?;
                    let base_token = match &sig.base {
                        TypeSignature::GenericInst(base_sig, _) => match base_sig.as_ref() {
                            TypeSignature::Class(t) | TypeSignature::ValueType(t) => Some(*t),
                            _ => None,
                        },
                        _ => None,
                    }?;
                    let base_type = context.get_type(base_token)?;
                    let enc = base_type.enclosing_type()?;
                    if enc.namespace.is_empty() {
                        None
                    } else {
                        Some(enc.namespace.clone())
                    }
                });
            enclosing_ns.as_deref().unwrap_or("")
        } else {
            raw_namespace
        };

        let method_name = if let Some(mr) = &member_ref_arc {
            mr.name.as_str()
        } else if let Some(m) = &method_arc {
            m.name.as_str()
        } else {
            self.token_cache
                .insert(method_token, TokenCacheEntry::NoMatch);
            return Ok(HookOutcome::NoMatch);
        };

        // Phase 2: Fast reject — O(1) hash lookup, zero allocation.
        // Also populates the token cache so future calls with the same token
        // skip all metadata resolution entirely.
        if !self
            .hooks
            .has_potential_match(namespace, type_name, method_name)?
        {
            self.token_cache
                .insert(method_token, TokenCacheEntry::NoMatch);
            return Ok(HookOutcome::NoMatch);
        }

        // Cache this token as a potential match for future calls.
        let info = ResolvedMethodInfo {
            namespace: Arc::from(namespace),
            type_name: Arc::from(type_name),
            method_name: Arc::from(method_name),
            is_internal,
            param_count,
            has_this,
        };
        self.token_cache
            .insert(method_token, TokenCacheEntry::Cached(info.clone()));

        // Phase 3+4: Build context and execute hook.
        self.execute_hook_with_resolved(context, method_token, thread, &info)
    }

    /// Dispatches a native function reached through a function pointer.
    ///
    /// A protection that wants its native calls to go unnoticed does not declare
    /// them: it resolves the address with `GetProcAddress` and calls it through a
    /// delegate. Nothing about the call site says "P/Invoke", so
    /// [`Self::try_native_call`] — which starts from a `MethodDef` with an
    /// ImplMap — never sees it, and the hooks registered for that function never
    /// run. .NET Reactor resolves `VirtualProtect` exactly this way.
    ///
    /// The identity survives the round trip: `GetProcAddress` records the
    /// function against a fake address, `GetDelegateForFunctionPointer` turns
    /// that address back into a token, and the token names the function here. So
    /// the call is given the same shape a declared P/Invoke would have and run
    /// through the ordinary hook path, which is what makes the *effect* happen
    /// rather than merely the return value.
    ///
    /// Falls back to a plausible return value when no hook matches, so a
    /// protection calling something unimplemented still makes progress.
    fn dispatch_native_delegate(
        &self,
        target_token: Token,
        args: &[EmValue],
        thread: &mut EmulationThread,
    ) -> Result<Option<EmValue>> {
        let function = thread
            .runtime_state()
            .read()
            .ok()
            .and_then(|rt| rt.native_functions().lookup_by_token(target_token));

        let Some(function) = function else {
            log::debug!(
                "Native delegate invoke: token 0x{:08X} names no known function",
                target_token.value()
            );
            return Ok(Some(EmValue::I32(0)));
        };

        // A function whose module was never observed can still match a hook that
        // does not constrain the DLL, so dispatch is attempted either way.
        let dll = function.dll.as_deref().unwrap_or_default();
        let hook_context =
            HookContext::native(target_token, dll, &function.name, self.config.pointer_size)
                .with_args(args);

        match self.hooks.execute(&hook_context, thread, |_| None)? {
            HookOutcome::NoMatch => Ok(native_delegate_fallback(
                &function.name,
                thread,
                target_token,
            )),
            HookOutcome::Handled(result)
            | HookOutcome::ReflectionInvoke {
                bypass_value: result,
                ..
            } => {
                log::debug!("Native delegate invoke: {dll}!{} handled", function.name);
                Ok(result)
            }
            HookOutcome::ThrewException { message, .. } => Err(EmulationError::HookError(format!(
                "native delegate hook threw CLR exception: {message}"
            ))
            .into()),
        }
    }

    /// Tries to execute a method call via a native (P/Invoke) stub.
    ///
    /// For `MethodDef` tokens that have no IL body (P/Invoke methods), looks up
    /// the real import name from the assembly's import table and tries matching
    /// native hooks.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Some(value)))` — Stub matched and returned a value
    /// - `Ok(Some(None))` — Stub matched and returned void
    /// - `Ok(None)` — No matching stub found
    #[allow(clippy::option_option)] // None = no hook, Some(None) = void return, Some(Some) = value
    fn try_native_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<Option<EmValue>>> {
        // Only MethodDef tokens can be P/Invoke - MemberRefs are handled via hooks
        if method_token.table() != 0x06 {
            return Ok(None);
        }

        // Get method info
        let Ok(method) = context.get_method(method_token) else {
            return Ok(None);
        };

        // Check if this is a P/Invoke (no method body)
        if method.has_body() {
            return Ok(None);
        }

        // For P/Invoke methods, look up the real import name from CilImports
        // This handles obfuscated method names where the actual import name differs
        let (function_name, dll_name): (SharedStr, Option<SharedStr>) =
            if let Some(import) = context.find_import_by_method(method_token) {
                let dll = context.get_import_dll_name(&import);
                (import.name.clone(), dll)
            } else {
                (method.name.clone(), None)
            };

        // Try native hooks for P/Invoke
        if let Some(dll) = &dll_name {
            // Get argument count - P/Invoke methods are always static
            let param_count = method.signature.params.len();

            // Pop arguments from stack
            let args = thread.pop_args(param_count)?;

            // Create native hook context
            let hook_context =
                HookContext::native(method_token, dll, &function_name, self.config.pointer_size)
                    .with_args(&args);

            // P/Invoke calls are always bypassed - no "original" to execute (lock-free)
            match self.hooks.execute(&hook_context, thread, |_| None)? {
                HookOutcome::NoMatch => {
                    // No hook found: the arguments go back as they were, the first deepest,
                    // and the caller decides how to handle the unhandled P/Invoke.
                    // (`pop_args` returns them in declaration order; pushing them back in
                    // reverse swapped them for whatever ran the call next.)
                    for arg in args {
                        thread.push(arg)?;
                    }
                    return Ok(None);
                }
                HookOutcome::Handled(result)
                | HookOutcome::ReflectionInvoke {
                    bypass_value: result,
                    ..
                } => {
                    return Ok(Some(self.checked_hook_return(
                        context,
                        method_token,
                        result,
                    )?));
                }
                HookOutcome::ThrewException { message, .. } => {
                    return Err(EmulationError::HookError(format!(
                        "P/Invoke hook threw CLR exception: {message}"
                    ))
                    .into());
                }
            }
        }

        Ok(None)
    }

    /// Checks the result a hook gave for `method_token` against the method's signature: a
    /// value for a method that returns one, nothing for a void method. The caller pushes the
    /// result as the call's, so a value a void method's hook returned stayed on the stack, and
    /// a missing one let the caller pop whatever lay below.
    ///
    /// A signature that cannot be read leaves the result as the hook gave it.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HookError`] naming the method when the result does not fit
    /// its signature.
    fn checked_hook_return(
        &self,
        context: &EmulationContext,
        method_token: Token,
        value: Option<EmValue>,
    ) -> Result<Option<EmValue>> {
        let Ok(return_type) = context.get_return_type(method_token) else {
            return Ok(value);
        };
        match (return_type, &value) {
            (Some(_), Some(_)) | (None, None) => Ok(value),
            (Some(return_type), None) => Err(EmulationError::HookError(format!(
                "the hook for {} returned nothing for a method returning {return_type:?}",
                self.format_method_name(method_token)
            ))
            .into()),
            (None, Some(returned)) => Err(EmulationError::HookError(format!(
                "the hook for {} returned {returned} for a void method",
                self.format_method_name(method_token)
            ))
            .into()),
        }
    }

    /// Builds a [`HookContext`] from pre-resolved method identity and executes
    /// the hook pipeline.
    ///
    /// This is the shared execution path used by both the cache-hit and cache-miss
    /// branches of [`try_hook_call`](Self::try_hook_call). All metadata resolution
    /// has already been done; this method only handles argument peeking, context
    /// building, and hook dispatch.
    fn execute_hook_with_resolved(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
        info: &ResolvedMethodInfo,
    ) -> Result<HookOutcome> {
        let total_args = if info.has_this {
            info.param_count.saturating_add(1)
        } else {
            info.param_count
        };

        // Peek at arguments without popping (we may not match a hook)
        let args = thread.peek_args(total_args)?;

        // Get parameter types if available
        let param_types = context.get_parameter_types(method_token).ok();
        let param_types_ref: Option<&[CilFlavor]> = param_types.as_deref();

        // `Void` for a void method; `None` only when the signature cannot be read
        let return_type = context
            .get_return_type(method_token)
            .ok()
            .map(|flavor| flavor.unwrap_or(CilFlavor::Void));

        // Split into this and method args
        let (this_ref, method_args): (Option<&EmValue>, &[EmValue]) = if info.has_this {
            match args.split_first() {
                Some((first, rest)) => (Some(first), rest),
                None => (None, args.as_slice()),
            }
        } else {
            (None, args.as_slice())
        };

        let hook_context = HookContext::new(
            method_token,
            &info.namespace,
            &info.type_name,
            &info.method_name,
            self.config.pointer_size,
        )
        .with_this(this_ref)
        .with_args(method_args)
        .with_internal(info.is_internal)
        .with_param_types(param_types_ref)
        .with_return_type(return_type);

        // Execute matching hook (lock-free via direct Arc<HookManager>)
        let outcome = self.hooks.execute(&hook_context, thread, |_| {
            // Original method execution callback - for now, we don't execute
            // the original here since the controller handles stubs/internal
            // methods separately. Post-hooks that depend on the original
            // result won't work in this mode.
            None
        })?;

        match &outcome {
            HookOutcome::NoMatch => {}
            _ => {
                // Hook matched — pop the arguments from the stack
                thread.pop_args(total_args)?;
            }
        }

        Ok(outcome)
    }
}

/// Pushes a new call frame for a resolved method.
///
/// Saves the caller's evaluation stack, creates the callee's frame with local
/// variable slots and typed arguments, and updates the interpreter to point at
/// the callee's entry point (offset 0).
///
/// This is a shared helper used by the `Call`, `CallIndirect`, and `NewObj`
/// paths in the main execution loop.
///
/// # Arguments
///
/// * `interpreter` - The CIL interpreter (updated to the callee's method/offset)
/// * `thread` - The emulation thread (stack saved, new frame pushed)
/// * `context` - The emulation context for method metadata
/// * `token` - Method token of the callee
/// * `arguments` - Arguments to pass to the callee
/// * `expects_return` - Whether the caller expects a return value
///
/// # Errors
///
/// Returns an error if the method's local variable types or parameter types
/// cannot be resolved from metadata.
pub fn push_method_frame(
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    token: Token,
    arguments: Vec<EmValue>,
    expects_return: bool,
) -> Result<()> {
    // Get return info from current frame
    let return_method = thread.current_frame().map(ThreadCallFrame::method);
    let return_offset = interpreter.ip().next_offset();

    // Save caller's evaluation stack before entering new method
    let caller_stack = thread.take_stack();

    // Get local types for the callee
    let local_cil_flavors = context.get_local_types(token)?;

    // Get argument types
    let callee_is_instance = !context.is_static_method(token)?;
    let param_types = context.get_parameter_types(token)?;
    let arg_types: Vec<CilFlavor> = if callee_is_instance {
        let mut types = vec![CilFlavor::Object];
        types.extend(param_types);
        types
    } else {
        param_types
    };

    // Combine args with types
    let args_with_types: Vec<(EmValue, CilFlavor)> = arguments.into_iter().zip(arg_types).collect();

    // Create new call frame
    let mut frame = ThreadCallFrame::new(
        token,
        return_method,
        return_offset,
        local_cil_flavors,
        args_with_types,
        expects_return,
    );
    frame.save_caller_stack(caller_stack);

    // Save and clear the leave target from exception state.
    // This prevents the callee's `leave` instructions from clobbering
    // the caller's leave target (which is needed when the caller is
    // executing a finally handler entered via `leave`).
    let saved_leave_target = thread.exception_state_mut().take_leave_target();
    frame.save_leave_target(saved_leave_target);

    // Push the frame to the thread's call stack
    thread.push_frame(frame);

    // Update interpreter to new method
    interpreter.set_method(token);
    interpreter.set_offset(0);

    Ok(())
}

/// Checks if a type needs initialization and runs its `.cctor` if needed.
///
/// Implements lazy type initialization as per ECMA-335 §II.10.5.3: before
/// accessing a type's static members, its static constructor (`.cctor`) must
/// be run exactly once. If the `.cctor` previously failed, the type is
/// permanently unusable (though this implementation uses lenient mode).
///
/// # Arguments
///
/// * `address_space` - Shared address space for static field state
/// * `cctor_tracker` - Tracks `.cctor` failures for permanent type poisoning
/// * `interpreter` - Updated to point at the `.cctor` entry point if one is pushed
/// * `thread` - The emulation thread (new `.cctor` frame pushed if needed)
/// * `context` - The emulation context for type/method metadata
/// * `field` - The static field token being accessed
///
/// # Returns
///
/// * `true` — A `.cctor` was pushed and needs to run first (don't advance IP)
/// * `false` — Type is already initialized or has no `.cctor`
///
/// # Errors
///
/// Returns an error if the `.cctor` method cannot be resolved from metadata,
/// or if frame creation fails (e.g., local types cannot be determined).
pub fn maybe_run_type_cctor(
    address_space: &AddressSpace,
    cctor_tracker: &CctorTracker,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    field: Token,
) -> Result<bool> {
    // Only process Field table tokens (0x04)
    if field.table() != 0x04 {
        return Ok(false);
    }

    // Find the type that owns this field
    let Some(type_token) = context
        .assembly()
        .resolver()
        .declaring_type_of_field(field)
        .map(|t| t.token)
    else {
        return Ok(false);
    };

    enter_type_cctor(
        address_space,
        cctor_tracker,
        interpreter,
        thread,
        context,
        type_token,
        field,
    )
}

/// Checks if a method's declaring type needs `.cctor` initialization and runs it if needed.
///
/// Implements ECMA-335 §II.10.5.3: before invoking a type's static method,
/// its static constructor (`.cctor`) must be run exactly once. This complements
/// [`maybe_run_type_cctor`] which handles static field access.
///
/// # Returns
///
/// * `true` — A `.cctor` was pushed and needs to run first (don't advance IP)
/// * `false` — Type is already initialized, has no `.cctor`, or the method's
///   declaring type couldn't be resolved
pub fn maybe_run_type_cctor_for_method(
    address_space: &AddressSpace,
    cctor_tracker: &CctorTracker,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    method: Token,
) -> Result<bool> {
    // Only process MethodDef (0x06), MemberRef (0x0A), MethodSpec (0x2B)
    let table = method.table();
    if table != 0x06 && table != 0x0A && table != 0x2B {
        return Ok(false);
    }

    // Find the type that declares this method.
    //
    // This runs for every call instruction, including after the type is initialised and this
    // function has nothing left to do. The initialisation check cannot be hoisted above it —
    // it is keyed by *type* token, which is precisely what this lookup produces. The lookup
    // itself is therefore what has to be cheap: `declaring_type` resolves through the method's
    // own back-pointer, falling back to a memoised registry index. A scan over every type and
    // method would make dispatch O(total methods in assembly).
    let Some(type_info) = context.assembly().resolver().declaring_type(method) else {
        return Ok(false);
    };
    let type_token = type_info.token;

    // Skip <Module> (global type) — its .cctor is run explicitly during warmup
    if type_token.table() == 0x02 && type_token.row() == 1 {
        return Ok(false);
    }

    enter_type_cctor(
        address_space,
        cctor_tracker,
        interpreter,
        thread,
        context,
        type_token,
        method,
    )
}

/// Runs the type initializer (`.cctor`) of `type_token` if it has not run, for the access
/// `trigger` (a static field or a method of the type) that needs it.
///
/// The type is marked in progress and its static fields are zeroed (ECMA-335 §II.10.5.3.2)
/// before the `.cctor` frame is pushed, so an access from inside the `.cctor` itself, or from
/// a type it initializes in turn, sees the type as initialized rather than starting it again
/// (§II.10.5.3.3). A type without a `.cctor`, or whose `.cctor` has no body, is initialized at
/// once.
///
/// Only this type's initializer runs. ECMA-335 §II.10.5.3.1 triggers a type's initializer by
/// accesses to that type alone, and the CLR runs a base type's when the base itself is first
/// accessed (its static members, or its constructor the derived one calls), which these same
/// triggers handle. Marking the base type in progress here without running its `.cctor` would
/// leave it looking initialized, its initializer never run and its statics zero.
///
/// # Returns
///
/// * `true`: a `.cctor` frame was pushed and runs first (the caller does not advance its IP)
/// * `false`: the type is initialized, or its `.cctor` failed before (lenient mode)
///
/// # Errors
///
/// Returns an error if the static state cannot be read or written.
fn enter_type_cctor(
    address_space: &AddressSpace,
    cctor_tracker: &CctorTracker,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    context: &EmulationContext,
    type_token: Token,
    trigger: Token,
) -> Result<bool> {
    // If this type's .cctor previously failed, re-throw the stored exception.
    // Per ECMA-335, a type whose .cctor threw is permanently unusable.
    if cctor_tracker.get_type_failure(type_token)?.is_some() {
        // Signal failure — the caller's error handling will treat this as a
        // CLR exception (TypeInitializationException). For now we log and
        // skip, matching the existing lenient behavior.
        debug!(
            "type 0x{:08X} .cctor previously failed — skipping re-throw (lenient mode)",
            type_token.value()
        );
        return Ok(false);
    }

    // Check if already initialized
    if address_space.statics().is_type_initialized(type_token)? {
        return Ok(false);
    }

    // Find the .cctor for this type
    let Some(cctor_token) = context.find_type_cctor(type_token) else {
        // No .cctor - mark as initialized and proceed
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    // Get method info for .cctor and check if it has a body
    let Ok(method) = context.get_method(cctor_token) else {
        // Can't get method - mark as initialized and skip
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    };

    // Check if .cctor has a body (it might be extern/P/Invoke)
    if !method.has_body() {
        // No body - mark as initialized and skip
        address_space.statics().mark_type_initialized(type_token)?;
        return Ok(false);
    }

    // Mark type as InProgress BEFORE running .cctor to prevent infinite recursion.
    // Per ECMA-335 §II.10.5.3.3: re-entrant access during .cctor is allowed (skip .cctor).
    address_space
        .statics()
        .set_type_init_state(type_token, TypeInitState::InProgress)?;

    // Zero-initialize all static fields for this type before running .cctor
    zero_initialize_static_fields(address_space, context, type_token)?;

    debug!(
        "triggering .cctor 0x{:08X} for type 0x{:08X} (access 0x{:08X})",
        cctor_token.value(),
        type_token.value(),
        trigger.value()
    );

    // .cctor takes no arguments and returns void
    let local_types = context.get_local_types(cctor_token).unwrap_or_default();

    // Save current stack state
    let caller_stack = thread.take_stack();

    // Current method and offset for return
    let return_method = interpreter.ip().method();
    let return_offset = interpreter.ip().offset();

    // .cctor has no arguments (it's always static and parameterless)
    let args_with_types: Vec<(EmValue, CilFlavor)> = vec![];

    // Create new call frame - .cctor never returns a value
    let mut frame = ThreadCallFrame::new(
        cctor_token,
        Some(return_method),
        return_offset,
        local_types,
        args_with_types,
        false, // .cctor returns void
    );
    frame.save_caller_stack(caller_stack);
    frame.set_is_cctor();

    // Push the frame and set up interpreter
    thread.push_frame(frame);
    interpreter.set_method(cctor_token);
    interpreter.set_offset(0);

    Ok(true)
}

/// Zero-initializes all static fields for a type before running its .cctor.
///
/// Per ECMA-335 §II.10.5.3.2, all static fields are zero-initialized before
/// the type initializer runs. This ensures fields have predictable default
/// values even if the .cctor doesn't explicitly set them.
fn zero_initialize_static_fields(
    address_space: &AddressSpace,
    context: &EmulationContext,
    type_token: Token,
) -> Result<()> {
    let Some(type_info) = context.get_type(type_token) else {
        return Ok(());
    };

    for (_, field) in type_info.fields.iter() {
        if !field.flags.is_static() {
            continue;
        }

        // Only set if not already present (don't overwrite values set by parent .cctors)
        if address_space.statics().contains(field.token)? {
            continue;
        }

        let default_value = match CilFlavor::from(&field.signature.base) {
            CilFlavor::Boolean
            | CilFlavor::I1
            | CilFlavor::U1
            | CilFlavor::I2
            | CilFlavor::U2
            | CilFlavor::I4
            | CilFlavor::U4
            | CilFlavor::Char => EmValue::I32(0),
            CilFlavor::I8 | CilFlavor::U8 => EmValue::I64(0),
            CilFlavor::R4 => EmValue::F32(0.0),
            CilFlavor::R8 => EmValue::F64(0.0),
            CilFlavor::I | CilFlavor::U => EmValue::NativeInt(0),
            _ => EmValue::Null,
        };

        address_space.statics().set(field.token, default_value)?;
    }
    Ok(())
}

/// Returns a plausible value for a native API that no hook implements.
///
/// A last resort. It reports success without performing the call's effect, so
/// anything whose effect matters — a memory protection change, a write through a
/// pointer — belongs in a hook, not here.
fn native_delegate_fallback(
    name: &str,
    thread: &EmulationThread,
    target_token: Token,
) -> Option<EmValue> {
    log::debug!(
        "Native delegate invoke: {name} (token 0x{:08X}) has no hook, returning a default",
        target_token.value()
    );

    match name {
        // BOOL-returning APIs — return TRUE (1)
        "VirtualProtect" | "VirtualFree" | "CloseHandle" | "FreeLibrary" => Some(EmValue::I32(1)),
        // Pointer-returning APIs — allocate real memory
        "VirtualAlloc" => {
            let size = 0x1_0000usize; // 64KB default
            match thread.address_space().alloc_unmanaged(size) {
                Ok(addr) => Some(EmValue::NativeInt(addr as i64)),
                Err(_) => Some(EmValue::NativeInt(0)),
            }
        }
        // Handle-returning APIs
        "GetCurrentProcess" => Some(EmValue::NativeInt(-1)),
        "GetCurrentThread" => Some(EmValue::NativeInt(-2)),
        // Integer-returning APIs
        "GetLastError" => Some(EmValue::I32(0)),
        "GetTickCount" | "GetTickCount64" => Some(EmValue::I32(0)),
        _ => {
            log::debug!("Native delegate invoke: unknown function {name}, returning 0");
            Some(EmValue::I32(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assembly::{InstructionAssembler, Operand},
        cilassembly::{ChangeRefRc, CilAssembly, MethodBuilder},
        emulation::{
            engine::generics::GenericRegistry, runtime::RuntimeState, tracer::TraceWriter,
            EmulationOutcome, Hook, PreHookResult, ProcessBuilder,
        },
        metadata::tables::{
            AssemblyRefBuilder, CodedIndex, CodedIndexType, FieldAttributes, FieldBuilder,
            ImplMapBuilder, MemberRefBuilder, ModuleRefBuilder, PInvokeAttributes, TypeAttributes,
            TypeDefBuilder, TypeRefBuilder,
        },
        testkit::{
            emulation::{create_test_thread, emulation_config},
            fixture,
        },
        utils::compute_hmac_sha256,
        CilObject, ValidationConfig,
    };

    fn create_test_resolver() -> CallResolver {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let config = Arc::new(emulation_config());
        let generics = Arc::new(GenericRegistry::new());
        CallResolver::new(runtime, config, None, generics).unwrap()
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = create_test_resolver();
        // RuntimeState::new() initializes with default hooks
        assert!(!resolver.hooks().is_empty());
    }

    #[test]
    fn test_format_method_name_no_cache() {
        let resolver = create_test_resolver();
        // Unknown token should return hex format
        let name = resolver.format_method_name(Token::new(0x0600_1234));
        assert_eq!(name, "0x06001234");
    }

    #[test]
    fn test_format_method_name_with_cache() {
        let resolver = create_test_resolver();

        // Manually insert a cached entry
        let info = ResolvedMethodInfo {
            namespace: Arc::from("System"),
            type_name: Arc::from("String"),
            method_name: Arc::from("Concat"),
            is_internal: false,
            param_count: 2,
            has_this: false,
        };
        resolver
            .token_cache
            .insert(Token::new(0x0A00_0042), TokenCacheEntry::Cached(info));

        let name = resolver.format_method_name(Token::new(0x0A00_0042));
        assert_eq!(name, "System.String::Concat");
    }

    #[test]
    fn test_format_method_name_empty_namespace() {
        let resolver = create_test_resolver();

        let info = ResolvedMethodInfo {
            namespace: Arc::from(""),
            type_name: Arc::from("Program"),
            method_name: Arc::from("Main"),
            is_internal: true,
            param_count: 0,
            has_this: false,
        };
        resolver
            .token_cache
            .insert(Token::new(0x0600_0001), TokenCacheEntry::Cached(info));

        let name = resolver.format_method_name(Token::new(0x0600_0001));
        assert_eq!(name, "Program::Main");
    }

    #[test]
    fn test_format_method_name_no_match_cached() {
        let resolver = create_test_resolver();

        // Insert a NoMatch entry
        resolver
            .token_cache
            .insert(Token::new(0x0600_0099), TokenCacheEntry::NoMatch);

        // Should fall through to hex format
        let name = resolver.format_method_name(Token::new(0x0600_0099));
        assert_eq!(name, "0x06000099");
    }

    #[test]
    fn test_resolver_with_trace_writer() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let config = Arc::new(emulation_config());
        let writer = Arc::new(TraceWriter::new_memory(1000, None));
        let generics = Arc::new(GenericRegistry::new());
        let resolver = CallResolver::new(runtime, config, Some(writer), generics).unwrap();

        // trace_stubs_enabled depends on config.tracing.trace_stubs
        // Default config has trace_stubs = false
        assert!(!resolver.trace_stubs_enabled());
    }

    /// `callvirt Stream::Write` on a CryptoStream, as C# compiles `cs.Write(...)`, reaches
    /// the CryptoStream's hook and is buffered for its final block, instead of the hook of
    /// `Stream.Write`, which knows only plain streams and drops the bytes. The method is
    /// .NET Reactor's own wrapper around that call (`0x060000A5`).
    #[test]
    fn callvirt_reaches_the_hook_of_the_receivers_runtime_type() {
        let assembly = Arc::new(
            // Two Assembly rows, as .NET Reactor writes them: loaded as analysis loads it
            CilObject::from_path_with_validation(
                fixture("packers/netreactor/7.5.0/reactor_full.exe"),
                ValidationConfig::analysis(),
            )
            .unwrap(),
        );
        // The TypeRef the program names CryptoStream with, as `newobj` records it
        let crypto_stream_type = assembly
            .types()
            .get_by_name("CryptoStream")
            .into_iter()
            .find(|t| t.namespace == "System.Security.Cryptography")
            .unwrap()
            .token;
        let process = ProcessBuilder::new()
            .assembly_arc(Arc::clone(&assembly))
            .build()
            .unwrap();
        let heap = process.address_space().managed_heap();
        let underlying = heap.alloc_stream(Vec::new(), None).unwrap();
        let transform = heap
            .alloc_crypto_transform("AES", vec![1; 16], vec![2; 16], true, 1, 2, None)
            .unwrap();
        let stream = heap
            .alloc_crypto_stream(underlying, transform, 1, Some(crypto_stream_type))
            .unwrap();
        let buffer = heap.alloc_byte_array(b"through Stream::Write").unwrap();

        let wrapper = Token::new(0x0600_00A5);
        let outcome = process
            .execute_method(
                wrapper,
                vec![
                    EmValue::ObjectRef(stream),
                    EmValue::ObjectRef(buffer),
                    EmValue::I32(0),
                    EmValue::I32(21),
                ],
            )
            .unwrap();
        assert!(
            matches!(outcome, EmulationOutcome::Completed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            heap.get_crypto_stream_write_buffer(stream).unwrap(),
            Some(b"through Stream::Write".to_vec())
        );
    }

    /// A `callvirt` of a BCL method named by a MemberRef runs the receiver's own override:
    /// `App.Show(object o)` calls `[mscorlib]System.Object::GetHashCode()` on an `App.Named`
    /// whose `GetHashCode` returns 4242, and gets 4242, not the `Object.GetHashCode` hook's
    /// answer or a symbolic value.
    #[test]
    fn callvirt_through_a_member_ref_runs_the_receivers_override() {
        let crafted = CilObject::from_path(fixture("crafted_2.exe")).unwrap();
        let object = crafted
            .types()
            .iter()
            .map(|entry| entry.value().clone())
            .find(|ty| {
                ty.token.is_table(TableId::TypeRef)
                    && ty.namespace == "System"
                    && ty.name == "Object"
            })
            .expect("crafted_2 imports System.Object")
            .token;

        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        // HASTHIS, no parameters, returning int32
        let get_hash_code = MemberRefBuilder::new()
            .class(CodedIndex::new(
                TableId::TypeRef,
                object.row(),
                CodedIndexType::MemberRefParent,
            ))
            .name("GetHashCode")
            .signature(&[0x20, 0x00, 0x08])
            .build(&mut app)
            .unwrap();
        let get_hash_code = Token::from_parts(TableId::MemberRef, added_row(&get_hash_code));
        let named = TypeDefBuilder::new()
            .name("Named")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .extends(CodedIndex::new(
                TableId::TypeRef,
                object.row(),
                CodedIndexType::TypeDefOrRef,
            ))
            .build(&mut app)
            .unwrap();
        let named = Token::from_parts(TableId::TypeDef, added_row(&named));
        MethodBuilder::new("GetHashCode")
            .public()
            .virtual_method()
            .returns(TypeSignature::I4)
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ldc_i4(4242)?.ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        let show = MethodBuilder::new("Show")
            .public()
            .static_method()
            .parameter("o", TypeSignature::Object)
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldarg_0()?.callvirt(get_hash_code)?.ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        let show = Token::from_parts(TableId::MethodDef, added_row(&show));
        let app = CilObject::from_mem(app.to_memory().unwrap()).unwrap();

        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .build()
            .unwrap();
        let receiver = process
            .address_space()
            .managed_heap()
            .alloc_object(named)
            .unwrap();
        let outcome = process
            .execute_method(show, vec![EmValue::ObjectRef(receiver)])
            .unwrap();
        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(4242)),
                    ..
                }
            ),
            "the override runs: {outcome:?}"
        );
    }

    /// The row of a table row a builder added.
    fn added_row(change: &ChangeRefRc) -> u32 {
        change.token().expect("the row has a token").row()
    }

    /// Assembly `Lib`, `crafted_2` with `Lib.Calc` added: `Bar(a, b) = a + b`, and
    /// `Foo(a, b) = Bar(a, b) + 100`, which calls `Bar` by its own MethodDef token.
    fn calc_library() -> CilObject {
        let mut lib = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        TypeDefBuilder::new()
            .name("Calc")
            .namespace("Lib")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut lib)
            .unwrap();
        let bar = MethodBuilder::new("Bar")
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
            .build(&mut lib)
            .unwrap();
        let bar = Token::from_parts(TableId::MethodDef, added_row(&bar));
        MethodBuilder::new("Foo")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldarg_0()?
                        .ldarg_1()?
                        .call(bar)?
                        .ldc_i4(100)?
                        .add()?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut lib)
            .unwrap();
        CilObject::from_mem(lib.to_memory().unwrap()).unwrap()
    }

    /// A method of an assembly loaded at run time runs in that assembly, and so do the
    /// methods it calls by its own tokens. The application calls `Lib.Calc::Foo(3, 4)` through
    /// a MemberRef; `Foo` calls `Bar`. Both applications are `crafted_2` with methods added, so
    /// `Bar`'s token in the application is the application's `Main`: the redirect into `Lib`
    /// was resolved again in the application, and the frame `Foo`'s call to `Bar` pushed named
    /// no assembly and ran in the application.
    #[test]
    fn a_loaded_assembly_runs_its_own_methods() {
        let lib = calc_library();
        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        let lib_ref = AssemblyRefBuilder::new()
            .name("Lib")
            .version(1, 0, 0, 0)
            .build(&mut app)
            .unwrap();
        let calc = TypeRefBuilder::new()
            .name("Calc")
            .namespace("Lib")
            .resolution_scope(CodedIndex::new(
                TableId::AssemblyRef,
                added_row(&lib_ref),
                CodedIndexType::ResolutionScope,
            ))
            .build(&mut app)
            .unwrap();
        // DEFAULT (static), two parameters, returning int32, taking int32 and int32
        let foo = MemberRefBuilder::new()
            .class(CodedIndex::new(
                TableId::TypeRef,
                added_row(&calc),
                CodedIndexType::MemberRefParent,
            ))
            .name("Foo")
            .signature(&[0x00, 0x02, 0x08, 0x08, 0x08])
            .build(&mut app)
            .unwrap();
        let foo = Token::from_parts(TableId::MemberRef, added_row(&foo));
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        let main = MethodBuilder::new("Main")
            .public()
            .static_method()
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldc_i4(3)?.ldc_i4(4)?.call(foo)?.ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        let main = Token::from_parts(TableId::MethodDef, added_row(&main));
        let app = CilObject::from_mem(app.to_memory().unwrap()).unwrap();

        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .build()
            .unwrap();
        process
            .runtime()
            .write()
            .unwrap()
            .app_domain_mut()
            .register_parsed_assembly(Arc::new(lib), 8)
            .expect("the library registers");

        let outcome = process.execute_method(main, Vec::new()).unwrap();
        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(107)),
                    ..
                }
            ),
            "Main returns Foo(3, 4) = 107: {outcome:?}"
        );
    }

    /// crafted_2 with `App.Program`: `Native(int a, int b)`, a void P/Invoke of `native.dll`
    /// no hook answers, and `Main`, which returns 7 after calling `Native(1, 2)`. Returns the
    /// assembly and the tokens of `Native` and `Main`.
    fn pinvoke_app() -> (CilObject, Token, Token) {
        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        let module = ModuleRefBuilder::new()
            .name("native.dll")
            .build(&mut app)
            .unwrap();
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        let native = MethodBuilder::new("Native")
            .public()
            .static_method()
            .parameter("a", TypeSignature::I4)
            .parameter("b", TypeSignature::I4)
            .pinvoke_impl()
            .build(&mut app)
            .unwrap();
        let native = added_row(&native);
        ImplMapBuilder::new()
            .mapping_flags(PInvokeAttributes::CALL_CONV_WINAPI)
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                native,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("Native")
            .import_scope(added_row(&module))
            .build(&mut app)
            .unwrap();
        let native = Token::from_parts(TableId::MethodDef, native);
        let main = MethodBuilder::new("Main")
            .public()
            .static_method()
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldc_i4(7)?.ldc_i4_1()?.ldc_i4_2()?.call(native)?.ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        let main = Token::from_parts(TableId::MethodDef, added_row(&main));
        let app = CilObject::from_mem(app.to_memory().unwrap()).unwrap();
        (app, native, main)
    }

    /// A P/Invoke no native hook answers leaves its arguments as they were, the first deepest,
    /// for the resolution steps after it. They were pushed back reversed.
    #[test]
    fn an_unhooked_pinvoke_leaves_its_arguments_in_order() {
        let (app, native, _) = pinvoke_app();
        let context = EmulationContext::new(Arc::new(app), Arc::new(DashMap::new()));
        let resolver = create_test_resolver();
        let mut thread = create_test_thread();
        thread.start_method(Token::new(0x0600_0001), vec![], vec![], false);
        thread.push(EmValue::I32(1)).unwrap();
        thread.push(EmValue::I32(2)).unwrap();

        let native_result = resolver
            .try_native_call(&context, native, &mut thread)
            .unwrap();

        assert!(native_result.is_none(), "no native hook answers native.dll");
        assert_eq!(thread.pop().unwrap(), EmValue::I32(2));
        assert_eq!(thread.pop().unwrap(), EmValue::I32(1));
    }

    /// A bodyless void method no hook answers returns nothing, under every behaviour that
    /// makes up a result: a phantom symbolic return stayed on the caller's stack, and `Main`
    /// returned it instead of its 7.
    #[test]
    fn an_unhooked_void_pinvoke_returns_nothing() {
        for behavior in [
            UnknownMethodBehavior::Emulate,
            UnknownMethodBehavior::Symbolic,
            UnknownMethodBehavior::Default,
        ] {
            let (app, _, main) = pinvoke_app();
            let process = ProcessBuilder::new()
                .assembly_arc(Arc::new(app))
                .build()
                .unwrap();
            process
                .runtime()
                .write()
                .unwrap()
                .set_unknown_method_behavior(behavior);

            let outcome = process.execute_method(main, Vec::new()).unwrap();

            assert!(
                matches!(
                    outcome,
                    EmulationOutcome::Completed {
                        return_value: Some(EmValue::I32(7)),
                        ..
                    }
                ),
                "{behavior:?}: Main returns 7: {outcome:?}"
            );
        }
    }

    /// Adds class `App.<name>` to `app`, extending `extends` when given, with the static
    /// `int <field>` its `.cctor` sets to `value`. Returns the type's and the field's tokens.
    fn class_with_cctor(
        app: &mut CilAssembly,
        name: &str,
        extends: Option<Token>,
        field: &str,
        value: i32,
    ) -> (Token, Token) {
        let mut class = TypeDefBuilder::new()
            .name(name)
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC);
        if let Some(base) = extends {
            class = class.extends(CodedIndex::new(
                TableId::TypeDef,
                base.row(),
                CodedIndexType::TypeDefOrRef,
            ));
        }
        let class = class.build(app).unwrap();
        let class = Token::from_parts(TableId::TypeDef, added_row(&class));
        // FIELD, int32
        let field = FieldBuilder::new()
            .name(field)
            .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC)
            .signature(&[0x06, 0x08])
            .build(app)
            .unwrap();
        let field = Token::from_parts(TableId::Field, added_row(&field));
        MethodBuilder::static_constructor()
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldc_i4(value)?.stsfld(field)?.ret()?;
                    Ok(())
                })
            })
            .build(app)
            .unwrap();
        (class, field)
    }

    /// A derived type's initializer does not touch its base's: the base's `.cctor` runs when
    /// the base is first accessed. Running the derived `.cctor` marked the base in progress
    /// without running it, so the base looked initialized and its static stayed zero.
    #[test]
    fn a_base_type_runs_its_own_cctor() {
        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        let (base, base_value) = class_with_cctor(&mut app, "Base", None, "BaseValue", 5);
        let (_, derived_value) =
            class_with_cctor(&mut app, "Derived", Some(base), "DerivedValue", 1);
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        // Main() => Derived.DerivedValue * 10 + Base.BaseValue
        let main = MethodBuilder::new("Main")
            .public()
            .static_method()
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldsfld(derived_value)?
                        .ldc_i4(10)?
                        .mul()?
                        .ldsfld(base_value)?
                        .add()?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        let main = Token::from_parts(TableId::MethodDef, added_row(&main));
        let app = CilObject::from_mem(app.to_memory().unwrap()).unwrap();
        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .build()
            .unwrap();

        let outcome = process.execute_method(main, Vec::new()).unwrap();

        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(15)),
                    ..
                }
            ),
            "both initializers ran, 1 * 10 + 5: {outcome:?}"
        );
    }

    /// Adds `Main` to crafted_2, with `TypeRef`s and `MemberRef`s to `ns.name` built by
    /// `members`, the body by `body`, and returns the assembly and `Main`'s token.
    fn app_with_main(
        members: impl FnOnce(&mut CilAssembly) -> Vec<Token>,
        body: impl Fn(&mut InstructionAssembler, &[Token]) -> Result<()> + 'static,
    ) -> (CilObject, Token) {
        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        let tokens = members(&mut app);
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        let main = MethodBuilder::new("Main")
            .public()
            .static_method()
            .returns(TypeSignature::I4)
            .implementation(move |method| method.implementation(move |asm| body(asm, &tokens)))
            .build(&mut app)
            .unwrap();
        let main = Token::from_parts(TableId::MethodDef, added_row(&main));
        (CilObject::from_mem(app.to_memory().unwrap()).unwrap(), main)
    }

    /// A `TypeRef` to framework type `namespace.name` (crafted_2's first AssemblyRef).
    fn framework_type(app: &mut CilAssembly, namespace: &str, name: &str) -> Token {
        let type_ref = TypeRefBuilder::new()
            .name(name)
            .namespace(namespace)
            .resolution_scope(CodedIndex::new(
                TableId::AssemblyRef,
                1,
                CodedIndexType::ResolutionScope,
            ))
            .build(app)
            .unwrap();
        Token::from_parts(TableId::TypeRef, added_row(&type_ref))
    }

    /// A `MemberRef` to method `name` of type `class` with signature blob `signature`.
    fn framework_method(
        app: &mut CilAssembly,
        class: Token,
        name: &str,
        signature: &[u8],
    ) -> Token {
        let member = MemberRefBuilder::new()
            .class(CodedIndex::new(
                TableId::TypeRef,
                class.row(),
                CodedIndexType::MemberRefParent,
            ))
            .name(name)
            .signature(signature)
            .build(app)
            .unwrap();
        Token::from_parts(TableId::MemberRef, added_row(&member))
    }

    /// `new HMACSHA256(key).ComputeHash(data)` hashes with the key: the constructor hook
    /// initializes the object `newobj` pushes. It returned another object, which `newobj`
    /// dropped, so `ComputeHash` ran on an uninitialized object.
    #[test]
    fn a_constructor_hook_initializes_the_new_object() {
        let (app, main) = app_with_main(
            |app| {
                let byte = framework_type(app, "System", "Byte");
                let hmac = framework_type(app, "System.Security.Cryptography", "HMACSHA256");
                // HASTHIS, one parameter, void, uint8[]
                let ctor = framework_method(app, hmac, ".ctor", &[0x20, 0x01, 0x01, 0x1D, 0x05]);
                // HASTHIS, one parameter, uint8[], uint8[]
                let compute = framework_method(
                    app,
                    hmac,
                    "ComputeHash",
                    &[0x20, 0x01, 0x1D, 0x05, 0x1D, 0x05],
                );
                vec![byte, ctor, compute]
            },
            |asm, tokens| {
                // Main() => new HMACSHA256(new byte[] { 7, 0, 0, 0 }).ComputeHash(new byte[3])[0].
                // A key of zeros hashes as an empty key does, so the key has a non-zero byte.
                asm.ldc_i4(4)?
                    .newarr(tokens[0])?
                    .dup()?
                    .ldc_i4(0)?
                    .ldc_i4(7)?
                    // stelem.i1
                    .emit_opcode(0x9C, None)?
                    .newobj(tokens[1])?
                    .ldc_i4(3)?
                    .newarr(tokens[0])?
                    .callvirt(tokens[2])?
                    .ldc_i4(0)?
                    // ldelem.u1
                    .emit_opcode(0x91, None)?
                    .ret()?;
                Ok(())
            },
        );
        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .build()
            .unwrap();

        let outcome = process.execute_method(main, Vec::new()).unwrap();

        let expected = i32::from(compute_hmac_sha256(&[7, 0, 0, 0], &[0, 0, 0])[0]);
        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(first)),
                    ..
                } if first == expected
            ),
            "the hash is the HMAC-SHA256 of the data under the key: {outcome:?}"
        );
    }

    /// Runs `Main` calling `Environment.<name>`, a framework method with signature
    /// `signature`, under a hook for it that returns `returned`. The names are made up, so
    /// no built-in hook answers them before the test's.
    fn run_hooked(
        name: &'static str,
        signature: &'static [u8],
        returned: Option<EmValue>,
    ) -> Result<EmulationOutcome> {
        let (app, main) = app_with_main(
            move |app| {
                let environment = framework_type(app, "System", "Environment");
                vec![framework_method(app, environment, name, signature)]
            },
            |asm, tokens| {
                asm.ldc_i4(7)?.call(tokens[0])?.ret()?;
                Ok(())
            },
        );
        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .hook(
                Hook::new("test")
                    .match_name("System", "Environment", name)
                    .pre(move |_, _| PreHookResult::Bypass(returned.clone())),
            )
            .build()
            .unwrap();
        process.execute_method(main, Vec::new())
    }

    /// A hook's result is checked against the signature of the method it stands for: the
    /// caller pushes it as the call's. A value from a void method's hook stayed on the
    /// caller's stack (here, `Main` returned it instead of its 7); a missing value from a
    /// hook of a method returning one let the caller take whatever lay below.
    #[test]
    fn a_hook_returns_what_its_method_returns() {
        // DEFAULT, no parameters, void / int32
        let void_signature: &'static [u8] = &[0x00, 0x00, 0x01];
        let int_signature: &'static [u8] = &[0x00, 0x00, 0x08];

        assert!(
            run_hooked("Notify", void_signature, Some(EmValue::I32(9))).is_err(),
            "a value for a void method is refused"
        );
        assert!(
            run_hooked("get_Answer", int_signature, None).is_err(),
            "no value for a method returning one is refused"
        );

        let fitting = run_hooked("Notify", void_signature, None).unwrap();
        assert!(
            matches!(
                fitting,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(7)),
                    ..
                }
            ),
            "{fitting:?}"
        );
    }

    /// crafted_2 with class `App.Counter { int total; int Add(int x) => total += x; }`, the
    /// delegate type `App.Callback : MulticastDelegate` (`int Invoke(int)`), and `Main`, whose
    /// body `body` gets the tokens `[Counter..ctor, Counter.Add, Callback..ctor,
    /// Callback.Invoke, Delegate.Combine, Callback, Lib.IntFunc.Invoke]`, the last a MemberRef
    /// to `int Invoke(int)` of a delegate type of another assembly. Main has one object local.
    fn delegate_app(
        body: impl Fn(&mut InstructionAssembler, &[Token]) -> Result<()> + 'static,
    ) -> (CilObject, Token) {
        let mut app = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
        let multicast = framework_type(&mut app, "System", "MulticastDelegate");
        let delegate = framework_type(&mut app, "System", "Delegate");

        TypeDefBuilder::new()
            .name("Counter")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        // FIELD, int32
        let total = FieldBuilder::new()
            .name("total")
            .flags(FieldAttributes::PUBLIC)
            .signature(&[0x06, 0x08])
            .build(&mut app)
            .unwrap();
        let total = Token::from_parts(TableId::Field, added_row(&total));
        let counter_ctor = MethodBuilder::constructor()
            .implementation(|body| {
                body.implementation(|asm| {
                    asm.ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();
        let add = MethodBuilder::new("Add")
            .public()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .implementation(move |body| {
                body.implementation(move |asm| {
                    asm.ldarg_0()?
                        .ldarg_0()?
                        .ldfld(total)?
                        .ldarg_1()?
                        .add()?
                        .stfld(total)?
                        .ldarg_0()?
                        .ldfld(total)?
                        .ret()?;
                    Ok(())
                })
            })
            .build(&mut app)
            .unwrap();

        let callback = TypeDefBuilder::new()
            .name("Callback")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC | TypeAttributes::SEALED)
            .extends(CodedIndex::new(
                TableId::TypeRef,
                multicast.row(),
                CodedIndexType::TypeDefOrRef,
            ))
            .build(&mut app)
            .unwrap();
        let callback_ctor = MethodBuilder::constructor()
            .parameter("object", TypeSignature::Object)
            .parameter("method", TypeSignature::I)
            .runtime_implemented()
            .build(&mut app)
            .unwrap();
        let invoke = MethodBuilder::new("Invoke")
            .public()
            .virtual_method()
            .parameter("x", TypeSignature::I4)
            .returns(TypeSignature::I4)
            .runtime_implemented()
            .build(&mut app)
            .unwrap();

        // DEFAULT, two parameters, returning Delegate, taking Delegate and Delegate: CLASS
        // and the TypeDefOrRef coded index of the TypeRef, compressed
        let coded = (delegate.row() << 2) | 1;
        let mut class = vec![0x12];
        if coded < 0x80 {
            class.push(u8::try_from(coded).unwrap());
        } else {
            class.push(0x80 | u8::try_from(coded >> 8).unwrap());
            class.push(u8::try_from(coded & 0xFF).unwrap());
        }
        let mut combine_signature = vec![0x00, 0x02];
        for _ in 0..3 {
            combine_signature.extend_from_slice(&class);
        }
        let combine = framework_method(&mut app, delegate, "Combine", &combine_signature);
        let int_func = framework_type(&mut app, "Lib", "IntFunc");
        // HASTHIS, one parameter, int32, int32
        let foreign_invoke =
            framework_method(&mut app, int_func, "Invoke", &[0x20, 0x01, 0x08, 0x08]);

        let tokens = vec![
            Token::from_parts(TableId::MethodDef, added_row(&counter_ctor)),
            Token::from_parts(TableId::MethodDef, added_row(&add)),
            Token::from_parts(TableId::MethodDef, added_row(&callback_ctor)),
            Token::from_parts(TableId::MethodDef, added_row(&invoke)),
            combine,
            Token::from_parts(TableId::TypeDef, added_row(&callback)),
            foreign_invoke,
        ];
        TypeDefBuilder::new()
            .name("Program")
            .namespace("App")
            .flags(TypeAttributes::CLASS | TypeAttributes::PUBLIC)
            .build(&mut app)
            .unwrap();
        let main = MethodBuilder::new("Main")
            .public()
            .static_method()
            .returns(TypeSignature::I4)
            .implementation(move |method| {
                method
                    .local("counter", TypeSignature::Object)
                    .implementation(move |asm| body(asm, &tokens))
            })
            .build(&mut app)
            .unwrap();
        let main = Token::from_parts(TableId::MethodDef, added_row(&main));
        (CilObject::from_mem(app.to_memory().unwrap()).unwrap(), main)
    }

    /// Runs `Main` of [`delegate_app`] and returns its result.
    fn run_delegate_app(
        body: impl Fn(&mut InstructionAssembler, &[Token]) -> Result<()> + 'static,
    ) -> EmulationOutcome {
        let (app, main) = delegate_app(body);
        let process = ProcessBuilder::new()
            .assembly_arc(Arc::new(app))
            .build()
            .unwrap();
        process.execute_method(main, Vec::new()).unwrap()
    }

    /// Emits `new Callback(counter, Counter.Add)` with `counter` in local 0.
    fn emit_callback(asm: &mut InstructionAssembler, tokens: &[Token]) -> Result<()> {
        asm.ldloc_0()?
            // ldftn Counter.Add
            .emit_opcode(0xFE06, Some(Operand::Token(tokens[1])))?
            .newobj(tokens[2])?;
        Ok(())
    }

    /// A delegate bound to an instance method passes its target as `this`. The target was
    /// dropped, so the method took its `this` from the caller's stack.
    #[test]
    fn a_closed_delegate_passes_its_target() {
        // Main() => 1000 + new Callback(new Counter(), Counter.Add).Invoke(5)
        let outcome = run_delegate_app(|asm, tokens| {
            asm.ldc_i4(1000)?.newobj(tokens[0])?.stloc_0()?;
            emit_callback(asm, tokens)?;
            asm.ldc_i4(5)?.callvirt(tokens[3])?.add()?.ret()?;
            Ok(())
        });

        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(1005)),
                    ..
                }
            ),
            "Add(5) on the counter: {outcome:?}"
        );
    }

    /// A multicast delegate runs every entry in order and returns the last one's result to
    /// its caller, whose stack stays as it was. The next entry returned into the entry before
    /// it, at the offset after its `ret`.
    #[test]
    fn a_multicast_delegate_runs_every_entry() {
        // Main() => 1000 + ((Callback)Delegate.Combine(add, add)).Invoke(5)
        let outcome = run_delegate_app(|asm, tokens| {
            asm.ldc_i4(1000)?.newobj(tokens[0])?.stloc_0()?;
            emit_callback(asm, tokens)?;
            emit_callback(asm, tokens)?;
            asm.call(tokens[4])?
                .castclass(tokens[5])?
                .ldc_i4(5)?
                .callvirt(tokens[3])?
                .add()?
                .ret()?;
            Ok(())
        });

        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(1010)),
                    ..
                }
            ),
            "both entries add 5, and the second's total is the result: {outcome:?}"
        );
    }

    /// A delegate's `Invoke` through a MemberRef to a delegate type of another assembly
    /// (`Action`, `Func` and every framework delegate are called this way) runs the
    /// delegate's method. It fell through to an unhooked MemberRef: a symbolic result, and the
    /// method never ran.
    #[test]
    fn a_delegate_of_another_assembly_runs_its_method() {
        // Main() => 1000 + ((IntFunc)new Callback(new Counter(), Counter.Add)).Invoke(5)
        let outcome = run_delegate_app(|asm, tokens| {
            asm.ldc_i4(1000)?.newobj(tokens[0])?.stloc_0()?;
            emit_callback(asm, tokens)?;
            asm.ldc_i4(5)?.callvirt(tokens[6])?.add()?.ret()?;
            Ok(())
        });

        assert!(
            matches!(
                outcome,
                EmulationOutcome::Completed {
                    return_value: Some(EmValue::I32(1005)),
                    ..
                }
            ),
            "Add(5) on the counter: {outcome:?}"
        );
    }
}

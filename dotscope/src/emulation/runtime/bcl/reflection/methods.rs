//! Method invocation and method metadata hooks for the CIL emulator.
//!
//! This module provides hook implementations for `System.Reflection.MethodBase`,
//! `System.Reflection.MethodInfo`, `System.Reflection.ConstructorInfo`, and
//! `System.Reflection.Emit` (DynamicMethod / ILGenerator) operations.
//!
//! These hooks are critical for deobfuscation because obfuscators frequently use
//! reflection-based method invocation to:
//!
//! - Call decryption methods indirectly via `MethodBase.Invoke()`
//! - Build dynamic methods with `DynamicMethod` + `ILGenerator.Emit()` to create
//!   delegate trampolines that proxy calls to the real target methods
//! - Query method metadata (`IsStatic`, `IsVirtual`, `ReturnType`, `GetParameters`)
//!   in control-flow flattening state machines to decide dispatch behavior
//! - Obtain method bodies via `GetMethodBody()` for self-inspection anti-tamper checks
//!
//! The `method_invoke_pre` and `constructor_invoke_pre` hooks return
//! `PreHookResult::ReflectionInvoke` requests, which the emulation controller
//! redirects into actual method execution within the emulator.

use log::{debug, warn};

use crate::{
    assembly::{
        decode_stream, Immediate, InstructionAssembler, Operand, OperandType, INSTRUCTIONS,
        INSTRUCTIONS_FE, INSTRUCTIONS_FE_MAX, INSTRUCTIONS_MAX,
    },
    emulation::{
        engine::{EmulationError, SyntheticMethodBody},
        runtime::{
            bcl::reflection::{
                extract_type_token, object_ref_equality_pre, object_ref_inequality_pre,
                resolve_method_from_token, unbox_value,
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::{EmulationThread, ReflectionInvokeRequest},
        tokens, EmValue, HeapObject, HeapRef, ManagedPointer,
    },
    file::parser::Parser,
    metadata::{
        tables::MemberRefSignature,
        token::Token,
        typesystem::{CilFlavor, TypeResolver},
    },
    Result,
};

/// Registers all method invocation and metadata hooks.
///
/// Called by the parent `reflection::register()` to wire up `MethodBase`, `MethodInfo`,
/// `ConstructorInfo`, and `DynamicMethod`/`ILGenerator` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // MethodBase / MethodInfo comparison operators
    manager.register(
        Hook::new("System.Reflection.MethodBase.op_Equality")
            .match_name("System.Reflection", "MethodBase", "op_Equality")
            .pre(object_ref_equality_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.op_Inequality")
            .match_name("System.Reflection", "MethodBase", "op_Inequality")
            .pre(object_ref_inequality_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodInfo.op_Equality")
            .match_name("System.Reflection", "MethodInfo", "op_Equality")
            .pre(object_ref_equality_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodInfo.op_Inequality")
            .match_name("System.Reflection", "MethodInfo", "op_Inequality")
            .pre(object_ref_inequality_pre),
    )?;

    // Method invocation
    manager.register(
        Hook::new("System.Reflection.MethodBase.Invoke")
            .match_name("System.Reflection", "MethodBase", "Invoke")
            .pre(method_invoke_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodInfo.Invoke")
            .match_name("System.Reflection", "MethodInfo", "Invoke")
            .pre(method_invoke_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.ConstructorInfo.Invoke")
            .match_name("System.Reflection", "ConstructorInfo", "Invoke")
            .pre(constructor_invoke_pre),
    )?;

    // Method metadata
    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsStatic")
            .match_name("System.Reflection", "MethodBase", "get_IsStatic")
            .pre(method_get_is_static_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodInfo.get_ReturnType")
            .match_name("System.Reflection", "MethodInfo", "get_ReturnType")
            .pre(method_get_return_type_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.GetParameters")
            .match_name("System.Reflection", "MethodBase", "GetParameters")
            .pre(method_get_parameters_pre),
    )?;

    // DynamicMethod / ILGenerator
    manager.register(
        Hook::new("System.Reflection.Emit.DynamicMethod..ctor")
            .match_name("System.Reflection.Emit", "DynamicMethod", ".ctor")
            .pre(dynamic_method_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.DynamicMethod.GetILGenerator")
            .match_name("System.Reflection.Emit", "DynamicMethod", "GetILGenerator")
            .pre(dynamic_method_get_il_generator_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.Emit")
            .match_name("System.Reflection.Emit", "ILGenerator", "Emit")
            .pre(il_generator_emit_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.DeclareLocal")
            .match_name("System.Reflection.Emit", "ILGenerator", "DeclareLocal")
            .pre(il_generator_declare_local_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.DynamicMethod.CreateDelegate")
            .match_name("System.Reflection.Emit", "DynamicMethod", "CreateDelegate")
            .pre(dynamic_method_create_delegate_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.DefineLabel")
            .match_name("System.Reflection.Emit", "ILGenerator", "DefineLabel")
            .pre(il_generator_define_label_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.MarkLabel")
            .match_name("System.Reflection.Emit", "ILGenerator", "MarkLabel")
            .pre(il_generator_mark_label_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.BeginExceptionBlock")
            .match_name(
                "System.Reflection.Emit",
                "ILGenerator",
                "BeginExceptionBlock",
            )
            .pre(il_generator_define_label_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.BeginCatchBlock")
            .match_name("System.Reflection.Emit", "ILGenerator", "BeginCatchBlock")
            .pre(il_generator_noop_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Emit.ILGenerator.EndExceptionBlock")
            .match_name("System.Reflection.Emit", "ILGenerator", "EndExceptionBlock")
            .pre(il_generator_noop_pre),
    )?;

    // Method name and flags
    manager.register(
        Hook::new("System.Reflection.MethodBase.get_Name")
            .match_name("System.Reflection", "MethodBase", "get_Name")
            .pre(method_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsVirtual")
            .match_name("System.Reflection", "MethodBase", "get_IsVirtual")
            .pre(method_get_is_virtual_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsAbstract")
            .match_name("System.Reflection", "MethodBase", "get_IsAbstract")
            .pre(method_get_is_abstract_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_IsPublic")
            .match_name("System.Reflection", "MethodBase", "get_IsPublic")
            .pre(method_get_is_public_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.GetMethodBody")
            .match_name("System.Reflection", "MethodBase", "GetMethodBody")
            .pre(method_get_method_body_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_MethodHandle")
            .match_name("System.Reflection", "MethodBase", "get_MethodHandle")
            .pre(method_get_method_handle_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.get_ContainsGenericParameters")
            .match_name(
                "System.Reflection",
                "MethodBase",
                "get_ContainsGenericParameters",
            )
            .pre(method_get_contains_generic_parameters_pre),
    )?;

    // MakeGenericMethod
    manager.register(
        Hook::new("System.Reflection.MethodInfo.MakeGenericMethod")
            .match_name("System.Reflection", "MethodInfo", "MakeGenericMethod")
            .pre(method_make_generic_method_pre),
    )?;

    Ok(())
}

/// Hook for `System.Reflection.MethodBase.Invoke` and `System.Reflection.MethodInfo.Invoke` methods.
///
/// Invokes the method or constructor represented by the current instance.
/// Extracts the method token from the `ReflectionMethod` heap object, unboxes
/// arguments from the `object[]` array, and returns a `ReflectionInvoke` request
/// for the emulation controller to dispatch.
fn method_invoke_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to get the method token from the 'this' parameter (the MethodBase object)
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod {
            method_token,
            method_type_args,
        }) = thread.heap().get_shared(*method_ref).as_deref()
        {
            // Extract the target object (first argument to Invoke)
            let this_ref = ctx.args.first().cloned();

            // Look up method signature to detect ByRef parameters
            let sig_params: Option<Vec<bool>> = thread
                .assembly()
                .and_then(|asm| asm.method(method_token).ok())
                .map(|m| m.signature.params.iter().map(|p| p.by_ref).collect());

            // Extract the method arguments from the object[] array (second argument).
            // For ByRef parameters, pass a ManagedPtr to the array element so writes
            // propagate back. For normal parameters, unbox boxed primitives.
            let method_args = if let Some(EmValue::ObjectRef(arr_ref)) = ctx.args.get(1) {
                if let Ok(HeapObject::Array { elements, .. }) =
                    thread.heap().get_shared(*arr_ref).as_deref()
                {
                    elements
                        .iter()
                        .enumerate()
                        .map(|(i, v)| {
                            let is_byref = sig_params
                                .as_ref()
                                .and_then(|params: &Vec<bool>| params.get(i).copied())
                                .unwrap_or(false);
                            if is_byref {
                                EmValue::ManagedPtr(ManagedPointer::to_array_element(*arr_ref, i))
                            } else {
                                unbox_value(thread, v)
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Return a reflection invoke request — the controller will
            // redirect execution to the target method
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token: *method_token,
                    this_ref,
                    args: method_args,
                    method_type_args: method_type_args.clone(),
                }),
                bypass_value: Some(EmValue::Null),
            };
        }
    }

    // Fallback: no valid method token found
    debug!("MethodBase.Invoke: no valid method token found, returning Null");
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Reflection.ConstructorInfo.Invoke` method.
///
/// Invokes the constructor represented by the current instance. Allocates a new
/// object of the declaring type, extracts constructor arguments from the `object[]`
/// array, and returns a `ReflectionInvoke` request for the emulation controller.
fn constructor_invoke_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the constructor's method token from 'this' (ReflectionMethod)
    if let Some(EmValue::ObjectRef(ctor_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*ctor_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                // Find the declaring type to allocate the right object
                let declaring_type_token = match asm.resolver().declaring_type(*method_token) {
                    Some(t) => t.token,
                    None => {
                        return PreHookResult::throw_invalid_operation(
                            "ConstructorInfo.Invoke: cannot resolve declaring type",
                        );
                    }
                };

                // Allocate the new object
                match thread.heap_mut().alloc_object(declaring_type_token) {
                    Ok(obj_ref) => {
                        // Extract constructor arguments from the first Object[] argument.
                        // Unbox any boxed primitives since constructors expect raw values.
                        let ctor_args: Vec<EmValue> = ctx
                            .args
                            .iter()
                            .find_map(|arg| {
                                if let EmValue::ObjectRef(arr_ref) = arg {
                                    if let Ok(HeapObject::Array { elements, .. }) =
                                        thread.heap().get_shared(*arr_ref).as_deref()
                                    {
                                        return Some(elements.clone());
                                    }
                                }
                                None
                            })
                            .unwrap_or_default()
                            .into_iter()
                            .map(|v| unbox_value(thread, &v))
                            .collect();

                        // Resolve MemberRef -> MethodDef so the controller can
                        // redirect to the actual constructor body.
                        let resolved_token = asm
                            .resolver()
                            .resolve_method(*method_token)
                            .unwrap_or(*method_token);

                        // Return a reflection invoke request for the constructor
                        return PreHookResult::ReflectionInvoke {
                            request: Box::new(ReflectionInvokeRequest {
                                method_token: resolved_token,
                                this_ref: Some(EmValue::ObjectRef(obj_ref)),
                                args: ctor_args,
                                method_type_args: None,
                            }),
                            bypass_value: Some(EmValue::ObjectRef(obj_ref)),
                        };
                    }
                    Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            }
        }
    }

    // Fallback: invalid constructor reference
    PreHookResult::throw_invalid_operation("ConstructorInfo.Invoke: invalid constructor reference")
}

/// Hook for `MethodBase.get_Name`.
///
/// Returns the name of the method by resolving the method token against assembly metadata.
/// Falls back to `MemberRef.name` for external methods.
fn method_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                // Try resolved MethodDef first
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    match thread.heap_mut().alloc_string(&method.name) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
                // Fallback: MemberRef name
                if let Some(member_ref) = asm.member_ref(method_token) {
                    match thread.heap_mut().alloc_string(&member_ref.name) {
                        Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `MethodBase.get_IsStatic` property.
///
/// Checks whether the method is static by looking up its flags in the assembly metadata.
/// Falls back to the `MemberRef` calling convention for external methods.
fn method_get_is_static_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_static(),
                    ))));
                }
                // Fallback: use MemberRef signature calling convention
                if let Some(member_ref) = asm.member_ref(method_token) {
                    if let MemberRefSignature::Method(sig) = &member_ref.signature {
                        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(!sig.has_this))));
                    }
                }
            }
        }
    }
    // Fallback: assume static
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `MethodBase.get_IsVirtual`.
///
/// Checks whether the method is virtual. For external methods referenced via
/// `MemberRef`, assumes instance methods are virtual (matches C# compiler behavior).
fn method_get_is_virtual_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_virtual(),
                    ))));
                }
                // Fallback: external instance methods are typically virtual in the BCL.
                // The C# compiler emits callvirt for all instance calls, and most BCL
                // instance methods are virtual. This is critical for CFF state machines
                // that use IsVirtual to decide dispatch behavior.
                if let Some(member_ref) = asm.member_ref(method_token) {
                    if let MemberRefSignature::Method(sig) = &member_ref.signature {
                        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(sig.has_this))));
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_IsAbstract`.
///
/// Checks whether the method is abstract. External methods referenced via
/// `MemberRef` are assumed concrete.
fn method_get_is_abstract_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_abstract(),
                    ))));
                }
            }
        }
    }
    // External methods referenced via MemberRef are concrete (abstract methods
    // can't be called cross-assembly without an intermediate override).
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MethodBase.get_IsPublic`.
///
/// Checks whether the method is public. External methods referenced via
/// `MemberRef` are assumed public.
fn method_get_is_public_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        method.is_public(),
                    ))));
                }
            }
        }
    }
    // External methods referenced via MemberRef are typically public
    // (private members can't be referenced cross-assembly).
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `MethodInfo.get_ReturnType` property.
///
/// Returns the return type of the method by resolving the method signature
/// from assembly metadata. Uses `TypeResolver` to preserve wrapper type info
/// (ByRef, Ptr, SzArray) in the returned `CilType`.
fn method_get_return_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                let ret_sig = resolve_method_from_token(*method_token, &asm)
                    .map(|m| m.signature.return_type.base.clone())
                    .or_else(|| {
                        asm.member_ref(method_token).and_then(|mr| {
                            if let MemberRefSignature::Method(sig) = &mr.signature {
                                Some(sig.return_type.base.clone())
                            } else {
                                None
                            }
                        })
                    });
                if let Some(ret_type) = ret_sig {
                    // Use the TypeResolver to resolve the full signature, preserving
                    // wrapper type info (ByRef, Ptr, SzArray) in the CilType's flavor.
                    // This ensures Type.get_IsByRef / get_IsPointer / get_IsArray work.
                    if let Ok(cil_type) = TypeResolver::new(asm.types()).resolve(&ret_type) {
                        match thread
                            .heap_mut()
                            .alloc_reflection_type(cil_type.token, None)
                        {
                            Ok(type_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                            }
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                    return PreHookResult::throw_type_load("Cannot resolve method return type");
                }
            }
        }
    }
    PreHookResult::throw_type_load("Cannot resolve method return type")
}

/// Hook for `MethodBase.GetParameters()`.
///
/// Returns an array of `ParameterInfo` objects with real parameter type information
/// when the method token resolves to real assembly metadata. Falls back to `MemberRef`
/// signature for external methods.
fn method_get_parameters_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    let mut param_elements = Vec::new();
                    #[allow(clippy::cast_possible_truncation)]
                    for (i, param) in method.signature.params.iter().enumerate() {
                        match thread.heap_mut().alloc_reflection_parameter(
                            *method_token,
                            i as u32,
                            param.base.clone(),
                        ) {
                            Ok(p_ref) => param_elements.push(EmValue::ObjectRef(p_ref)),
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, param_elements)
                    {
                        Ok(arr_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                        }
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
                // Fallback: use MemberRef signature for parameter info
                if let Some(member_ref) = asm.member_ref(method_token) {
                    if let MemberRefSignature::Method(sig) = &member_ref.signature {
                        let mut param_elements = Vec::new();
                        #[allow(clippy::cast_possible_truncation)]
                        for (i, param) in sig.params.iter().enumerate() {
                            match thread.heap_mut().alloc_reflection_parameter(
                                *method_token,
                                i as u32,
                                param.base.clone(),
                            ) {
                                Ok(p_ref) => param_elements.push(EmValue::ObjectRef(p_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                        match thread
                            .heap_mut()
                            .alloc_array_with_values(CilFlavor::Object, param_elements)
                        {
                            Ok(arr_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
                            }
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: return an empty array
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `MethodBase.get_MethodHandle`.
///
/// Returns a `RuntimeMethodHandle` value type. In the real CLR this wraps a
/// pointer to the internal method descriptor. For emulation we return the
/// method's metadata token as an `I64` — a unique, deterministic value that
/// `PrepareMethod` can accept (which is a no-op in our emulator anyway).
fn method_get_method_handle_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let method_token = ctx
        .this
        .and_then(|this| match this {
            EmValue::ObjectRef(href) => thread
                .heap()
                .get_reflection_method_token(*href)
                .ok()
                .flatten(),
            _ => None,
        })
        .unwrap_or(ctx.method_token);

    // RuntimeMethodHandle is a value type with a single IntPtr field.
    // Return the token value as a stable handle.
    PreHookResult::Bypass(Some(EmValue::I64(i64::from(method_token.value()))))
}

/// Hook for `MethodBase.GetMethodBody()`.
///
/// Returns a stub `MethodBody` object if the method has a body, or null if the
/// method is abstract/extern.
fn method_get_method_body_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Ok(method) = asm.method(method_token) {
                    if method.body.get().is_some() {
                        match thread
                            .heap_mut()
                            .alloc_object(tokens::reflection::METHOD_BODY)
                        {
                            Ok(body_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(body_ref)))
                            }
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                }
            }
        }
    }
    // Method has no body (abstract, extern) or can't resolve — null is correct
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `MethodBase.get_ContainsGenericParameters`.
///
/// Checks whether the method contains unresolved generic parameters.
/// External methods referenced via `MemberRef` are assumed to be concrete instantiations.
fn method_get_contains_generic_parameters_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(method_ref)) = ctx.this {
        if let Ok(HeapObject::ReflectionMethod { method_token, .. }) =
            thread.heap().get_shared(*method_ref).as_deref()
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = resolve_method_from_token(*method_token, &asm) {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                        !method.generic_params.is_empty(),
                    ))));
                }
                // MemberRef fallback: external methods referenced via MemberRef
                // are typically concrete instantiations, not open generic methods.
                // MethodSpec wrapping indicates generic instantiation, but the
                // inner method itself has no open generic parameters.
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `DynamicMethod..ctor(string, Type, Type[], ...)`.
///
/// Captures the parameter types from the constructor arguments and stores them
/// on the `HeapObject::DynamicMethod`. This is called after the object is allocated
/// by `newobj` in `typeops.rs`.
fn dynamic_method_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dm_ref)) = ctx.this {
        // .ctor args: this, name, returnType, Type[] paramTypes, ...
        // But since `this` is separate, args[0]=name, args[1]=returnType, args[2]=paramTypes

        // Extract return type from arg[1]
        let return_type = ctx.args.get(1).and_then(|arg| {
            if let EmValue::ObjectRef(t_ref) = arg {
                thread
                    .heap()
                    .get_reflection_type_token(*t_ref)
                    .unwrap_or_default()
            } else {
                None
            }
        });

        // Extract parameter types from the Type[] argument at arg[2]
        let param_types: Vec<Token> = ctx
            .args
            .get(2)
            .and_then(|arg| {
                if let EmValue::ObjectRef(arr_ref) = arg {
                    if let Ok(HeapObject::Array { elements, .. }) =
                        thread.heap().get_shared(*arr_ref).as_deref()
                    {
                        return Some(
                            elements
                                .iter()
                                .filter_map(|e| {
                                    if let EmValue::ObjectRef(t_ref) = e {
                                        thread
                                            .heap()
                                            .get_reflection_type_token(*t_ref)
                                            .unwrap_or_default()
                                    } else {
                                        None
                                    }
                                })
                                .collect(),
                        );
                    }
                }
                None
            })
            .unwrap_or_default();

        // Store param types and return type on the DynamicMethod heap object
        try_hook!(thread
            .heap()
            .set_dynamic_method_params(*dm_ref, param_types));
        try_hook!(thread
            .heap()
            .set_dynamic_method_return_type(*dm_ref, return_type));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `DynamicMethod.GetILGenerator()`.
///
/// Creates a proper `HeapObject::ILGenerator` with an embedded
/// `InstructionAssembler` linked to the DynamicMethod.
fn dynamic_method_get_il_generator_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dm_ref)) = ctx.this {
        match thread.heap_mut().alloc_il_generator(*dm_ref) {
            Ok(il_ref) => {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(il_ref)));
            }
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }
    // Fallback: stub ILGenerator for non-DynamicMethod `this`
    match thread
        .heap_mut()
        .alloc_object(tokens::codegen::DYNAMIC_METHOD)
    {
        Ok(il_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(il_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for all `ILGenerator.Emit(...)` overloads.
///
/// Delegates each Emit call to the embedded `InstructionAssembler`:
/// - `Emit(OpCode)` — emits a no-operand instruction
/// - `Emit(OpCode, int32)` — emits instruction with i32 operand
/// - `Emit(OpCode, MethodInfo)` — emits call/callvirt with real method token
/// - `Emit(OpCode, FieldInfo)` — emits ldfld/stfld with real field token
/// - `Emit(OpCode, Type)` — emits token-based instruction
/// - `Emit(OpCode, Label)` — emits branch to label
///
/// Also maintains the legacy shortcut: the last MethodInfo token emitted
/// is stored on the DynamicMethod for simple single-call proxy patterns.
fn il_generator_emit_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(il_ref)) = ctx.this else {
        return PreHookResult::Bypass(None);
    };
    let il_ref = *il_ref;

    // Get the assembler from the ILGenerator
    let Some(assembler_arc) = try_hook!(thread.heap().get_il_generator_assembler(il_ref)) else {
        return PreHookResult::Bypass(None);
    };

    // The first argument is always the OpCode. Extract the opcode value.
    let opcode_value = extract_opcode_value(ctx, thread);

    // Parse the remaining arguments to determine the operand
    let mut method_token: Option<Token> = None;
    let mut field_token: Option<Token> = None;
    let mut type_token: Option<Token> = None;
    let mut label_id: Option<i32> = None;
    let mut i32_operand: Option<i32> = None;
    let mut i64_operand: Option<i64> = None;

    for (i, arg) in ctx.args.iter().enumerate() {
        if i == 0 {
            continue; // Skip OpCode arg
        }
        match arg {
            EmValue::ObjectRef(href) => {
                if let Ok(obj) = thread.heap().get_shared(*href).as_deref() {
                    match obj {
                        HeapObject::ReflectionMethod {
                            method_token: mt, ..
                        } => method_token = Some(*mt),
                        HeapObject::ReflectionField {
                            field_token: ft, ..
                        } => field_token = Some(*ft),
                        HeapObject::ReflectionType { type_token: tt, .. } => type_token = Some(*tt),
                        _ => {}
                    }
                }
            }
            EmValue::I32(v) => {
                if i == 1 {
                    label_id = Some(*v);
                }
                i32_operand = Some(*v);
            }
            EmValue::I64(v) => i64_operand = Some(*v),
            _ => {}
        }
    }

    // Emit to the assembler using the clean opcode-based API
    let mut asm = match assembler_arc.lock() {
        Ok(guard) => guard,
        Err(_) => return PreHookResult::Error("assembler lock poisoned".into()),
    };

    let emit_result = if InstructionAssembler::is_branch_opcode(opcode_value) {
        // Branch instruction — resolve label name and emit branch
        let label = resolve_label_name(label_id, il_ref, thread);
        asm.emit_branch_to_label(opcode_value, &label).map(|_| ())
    } else if InstructionAssembler::is_token_opcode(opcode_value) {
        // Token operand — use the resolved method/field/type token
        let token = method_token
            .or(field_token)
            .or(type_token)
            .unwrap_or(Token::new(0));
        asm.emit_opcode(opcode_value, Some(Operand::Token(token)))
            .map(|_| ())
    } else if let Some(v) = i64_operand {
        // i64 operand (ldc.i8)
        asm.emit_opcode(opcode_value, Some(Operand::Immediate(Immediate::Int64(v))))
            .map(|_| ())
    } else if let Some(v) = i32_operand {
        // i32 operand — determine the correct immediate size from the opcode metadata
        let operand = build_immediate_operand(opcode_value, v);
        asm.emit_opcode(opcode_value, operand).map(|_| ())
    } else {
        // No operand
        asm.emit_opcode(opcode_value, None).map(|_| ())
    };

    if let Err(e) = emit_result {
        debug!(
            "ILGenerator.Emit: assembler error for opcode 0x{:04X}: {e}",
            opcode_value
        );
    }

    PreHookResult::Bypass(None)
}

/// Builds the correctly-typed `Operand` for an i32 value based on the opcode's expected
/// operand type from the instruction tables.
fn build_immediate_operand(opcode: u16, value: i32) -> Option<Operand> {
    let op_type = if opcode < u16::from(INSTRUCTIONS_MAX) {
        INSTRUCTIONS.get(opcode as usize)?.op_type
    } else if opcode >= 0xFE00 {
        let sub = (opcode & 0xFF) as usize;
        if sub >= usize::from(INSTRUCTIONS_FE_MAX) {
            return None;
        }
        INSTRUCTIONS_FE.get(sub)?.op_type
    } else {
        return None;
    };

    match op_type {
        OperandType::None => None,
        OperandType::Int8 => Some(Operand::Immediate(Immediate::Int8(value as i8))),
        OperandType::UInt8 => Some(Operand::Immediate(Immediate::UInt8(value as u8))),
        OperandType::Int16 => Some(Operand::Immediate(Immediate::Int16(value as i16))),
        OperandType::UInt16 => Some(Operand::Immediate(Immediate::UInt16(value as u16))),
        OperandType::Int32 => Some(Operand::Immediate(Immediate::Int32(value))),
        OperandType::UInt32 => Some(Operand::Immediate(Immediate::UInt32(value as u32))),
        OperandType::Int64 => Some(Operand::Immediate(Immediate::Int64(i64::from(value)))),
        OperandType::UInt64 => Some(Operand::Immediate(Immediate::UInt64(value as u64))),
        OperandType::Float32 => Some(Operand::Immediate(Immediate::Float32(value as f32))),
        OperandType::Float64 => Some(Operand::Immediate(Immediate::Float64(f64::from(value)))),
        OperandType::Token => Some(Operand::Immediate(Immediate::UInt32(value as u32))),
        OperandType::Switch => None,
    }
}

/// Extracts the opcode integer value from the first argument.
///
/// In the emulator, OpCode is typically passed as an I32 containing the opcode value
/// (0x00-0xFF for single-byte, or 0xFE00-0xFEFF for two-byte opcodes).
fn extract_opcode_value(ctx: &HookContext<'_>, thread: &EmulationThread) -> u16 {
    match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as u16,
        Some(EmValue::ObjectRef(href)) => {
            // Boxed OpCode — try to read the Value field
            if let Ok(HeapObject::BoxedValue { value, .. }) =
                thread.heap().get_shared(*href).as_deref()
            {
                if let EmValue::I32(v) = value.as_ref() {
                    return *v as u16;
                }
            }
            // Try to read a "Value" field from an OpCode struct object
            if let Ok(EmValue::I32(v)) = thread
                .heap()
                .get_field(*href, tokens::misc_fields::OPCODE_VALUE)
            {
                return v as u16;
            }
            0
        }
        Some(EmValue::ValueType { fields, .. }) => {
            // OpCode is a value type struct. The first field is an I32 containing
            // the opcode value (as stored by our BCL OpCodes static field resolution).
            if let Some(EmValue::I32(packed)) = fields.first() {
                (*packed & 0xFFFF) as u16
            } else {
                debug!("OpCode ValueType has no i32 field, fields: {:?}", fields);
                0
            }
        }
        _ => 0,
    }
}

/// Resolves a label ID to the corresponding label name string.
///
/// If the label ID matches a known label, returns its name. Otherwise
/// creates a fallback name like `"_L42"`.
fn resolve_label_name(label_id: Option<i32>, il_ref: HeapRef, thread: &EmulationThread) -> String {
    let id = label_id.unwrap_or(0) as usize;
    match thread.heap().il_generator_get_label(il_ref, id) {
        Ok(Some(name)) => name,
        _ => format!("_L{id}"),
    }
}

/// Hook for `ILGenerator.DeclareLocal(Type)`.
///
/// Tracks the declared local variable type and returns a stub `LocalBuilder`.
fn il_generator_declare_local_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Track local type on the ILGenerator
    if let Some(EmValue::ObjectRef(il_ref)) = ctx.this {
        let type_token = ctx.args.first().and_then(|a| extract_type_token(thread, a));
        if let Some(tt) = type_token {
            try_hook!(thread.heap().il_generator_push_local(*il_ref, tt));
        }
    }

    match thread
        .heap_mut()
        .alloc_object(tokens::codegen::IL_GENERATOR)
    {
        Ok(lb_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(lb_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `DynamicMethod.CreateDelegate(Type)`.
///
/// If the DynamicMethod has a simple single-call target (legacy shortcut),
/// creates a delegate directly. Otherwise, finalizes the ILGenerator's
/// `InstructionAssembler` to produce raw bytecode, decodes it into
/// `Instruction` objects, registers a synthetic method body, and creates
/// a delegate pointing to the synthetic method token.
fn dynamic_method_create_delegate_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // CreateDelegate(Type) — first arg is always the delegate type
    let type_token = ctx.args.first().and_then(|arg| {
        if let EmValue::ObjectRef(href) = arg {
            thread
                .heap()
                .get_reflection_type_token(*href)
                .unwrap_or_default()
        } else {
            None
        }
    });

    let Some(type_token) = type_token else {
        warn!("DynamicMethod.CreateDelegate: missing delegate type argument");
        return PreHookResult::throw_argument_null("delegateType");
    };

    let Some(EmValue::ObjectRef(dm_ref)) = ctx.this else {
        return PreHookResult::throw_invalid_operation("CreateDelegate: invalid this");
    };
    let dm_ref = *dm_ref;

    // Finalize the ILGenerator's assembled IL into a synthetic method body,
    // register it, and create a delegate pointing to it.
    match finalize_dynamic_method_delegate(thread, dm_ref, type_token) {
        Ok(del_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
        Err(e) => {
            warn!("DynamicMethod.CreateDelegate: finalization failed: {e}");
            PreHookResult::throw_invalid_operation("DynamicMethod IL finalization failed")
        }
    }
}

/// Finalizes a `DynamicMethod`'s IL and creates a delegate from it.
///
/// This performs the full IL finalization pipeline:
/// 1. Get the ILGenerator from the DynamicMethod
/// 2. Take ownership of the `InstructionAssembler` (replacing with a fresh empty one)
/// 3. Finalize the assembler into bytecode + exception handlers
/// 4. Decode the bytecode into `Vec<Instruction>`
/// 5. Resolve local variable and parameter types to `CilFlavor`
/// 6. Register as a synthetic method and create a delegate
fn finalize_dynamic_method_delegate(
    thread: &mut EmulationThread,
    dm_ref: HeapRef,
    type_token: Token,
) -> Result<HeapRef> {
    // 1. Get ILGenerator from DynamicMethod
    let il_ref = thread
        .heap()
        .get_dynamic_method_il_generator(dm_ref)?
        .ok_or_else(|| EmulationError::InternalError {
            description: "DynamicMethod has no ILGenerator".into(),
        })?;

    // 2. Get the InstructionAssembler Arc from the ILGenerator
    let assembler_arc = thread
        .heap()
        .get_il_generator_assembler(il_ref)?
        .ok_or_else(|| EmulationError::InternalError {
            description: "ILGenerator has no assembler".into(),
        })?;

    // 3. Take ownership: replace the assembler with a fresh empty one.
    //    Second CreateDelegate calls on the same DynamicMethod will get an empty method.
    let assembler = {
        let mut guard = assembler_arc
            .lock()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "IL generator assembler",
            })?;
        std::mem::take(&mut *guard)
    };

    // 4. Finalize: assembler → (bytecode, max_stack, exception_handlers)
    let (bytecode, _max_stack, exception_handlers) = assembler.finish()?;

    // 5. Decode bytecode into instructions
    let instructions = if bytecode.is_empty() {
        Vec::new()
    } else {
        let mut parser = Parser::new(&bytecode);
        decode_stream(&mut parser, 0)?
    };

    // 6. Get local types from ILGenerator, convert to CilFlavor
    let local_tokens = thread
        .heap()
        .il_generator_get_locals(il_ref)?
        .unwrap_or_default();
    let local_types: Vec<CilFlavor> = local_tokens
        .iter()
        .map(|tok| {
            thread
                .type_token_to_cil_flavor(*tok)
                .unwrap_or(CilFlavor::Object)
        })
        .collect();

    // 7. Get parameter types and static flag from DynamicMethod
    let (is_static, param_tokens) = thread
        .heap()
        .get_dynamic_method_info(dm_ref)?
        .unwrap_or((true, Vec::new()));
    let param_types: Vec<CilFlavor> = param_tokens
        .iter()
        .map(|tok| {
            thread
                .type_token_to_cil_flavor(*tok)
                .unwrap_or(CilFlavor::Object)
        })
        .collect();

    // 7b. Determine if the method returns a value (non-void)
    let return_type_token = thread.heap().get_dynamic_method_return_type(dm_ref)?;
    let returns_value = match return_type_token {
        None => false,
        Some(tok) => match thread.type_token_to_cil_flavor(tok) {
            Some(CilFlavor::Void) => false,
            Some(_) => true,
            None => true, // Unknown type — conservatively assume returns value
        },
    };

    debug!(
        "DynamicMethod.CreateDelegate: finalized {} instructions, {} locals, {} params, {} handlers, returns={}",
        instructions.len(),
        local_types.len(),
        param_types.len(),
        exception_handlers.len(),
        returns_value,
    );

    // 8. Build and register the synthetic method body
    let body = SyntheticMethodBody {
        instructions,
        local_types,
        param_types,
        is_static,
        returns_value,
        exception_handlers,
    };
    let synthetic_token = thread.register_synthetic_method(body);

    // 9. Create delegate pointing to the synthetic method
    thread
        .heap_mut()
        .alloc_delegate(type_token, None, synthetic_token)
}

/// Hook for `MethodInfo.MakeGenericMethod(params Type[])`.
///
/// Creates a closed generic method by binding type arguments to the open method.
/// Returns a new `ReflectionMethod` object with the same method token but with
/// generic type arguments stored for later dispatch.
fn method_make_generic_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract the open method token from 'this'
    let method_token = match ctx.this {
        Some(EmValue::ObjectRef(method_ref)) => {
            try_hook!(thread.heap().get_reflection_method_token(*method_ref))
        }
        _ => None,
    };

    let Some(method_token) = method_token else {
        debug!("MakeGenericMethod: no valid method token on 'this'");
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Extract type arguments from the Type[] parameter
    let type_args = match ctx.args.first() {
        Some(EmValue::ObjectRef(arr_ref)) => match thread.heap().get_shared(*arr_ref).as_deref() {
            Ok(HeapObject::Array { elements, .. }) => {
                let mut args = Vec::with_capacity(elements.len());
                for elem in elements {
                    if let EmValue::ObjectRef(type_ref) = elem {
                        if let Some(tt) =
                            try_hook!(thread.heap().get_reflection_type_token(*type_ref))
                        {
                            args.push(tt);
                        }
                    }
                }
                args
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };

    if type_args.is_empty() {
        debug!("MakeGenericMethod: no type arguments provided, returning open method");
        // Return a copy of the same method — no generic args to bind
        match thread.heap_mut().alloc_reflection_method(method_token) {
            Ok(href) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }

    debug!(
        "MakeGenericMethod: 0x{:08X} with {} type arg(s)",
        method_token.value(),
        type_args.len()
    );

    // Allocate a new ReflectionMethod with the type arguments attached
    match thread
        .heap_mut()
        .alloc_reflection_method_generic(method_token, type_args)
    {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `ILGenerator.DefineLabel()` and `ILGenerator.BeginExceptionBlock()`.
///
/// Creates a new label in the embedded `InstructionAssembler` and returns its
/// integer ID. The label name is auto-generated and stored in the label_names
/// map for later resolution by branch instructions.
fn il_generator_define_label_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(il_ref)) = ctx.this {
        if let Some((id, _name)) = try_hook!(thread.heap().il_generator_define_label(*il_ref)) {
            return PreHookResult::Bypass(Some(EmValue::I32(id as i32)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `ILGenerator.MarkLabel(Label)`.
///
/// Defines the label position in the `InstructionAssembler` at the current
/// bytecode offset, so that branch instructions targeting this label will
/// be resolved correctly during finalization.
fn il_generator_mark_label_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(il_ref)) = ctx.this {
        let label_id = match ctx.args.first() {
            Some(EmValue::I32(v)) => *v as usize,
            _ => 0,
        };

        if let Some(label_name) = try_hook!(thread.heap().il_generator_get_label(*il_ref, label_id))
        {
            if let Some(assembler_arc) =
                try_hook!(thread.heap().get_il_generator_assembler(*il_ref))
            {
                let mut asm = match assembler_arc.lock() {
                    Ok(guard) => guard,
                    Err(_) => return PreHookResult::Error("assembler lock poisoned".into()),
                };
                if let Err(e) = asm.label(&label_name) {
                    debug!("ILGenerator.MarkLabel: assembler error: {e}");
                }
            }
        }
    }

    PreHookResult::Bypass(None)
}

/// No-op hook for ILGenerator methods that don't produce a return value.
///
/// Used for `BeginCatchBlock(Type)` and `EndExceptionBlock()` which perform
/// bookkeeping in real .NET but aren't fully wired into the assembler yet.
fn il_generator_noop_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use super::method_invoke_pre;
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_method_invoke_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Reflection",
            "MethodBase",
            "Invoke",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = method_invoke_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::Null)) => {}
            _ => panic!("Expected Bypass with Null"),
        }
    }
}

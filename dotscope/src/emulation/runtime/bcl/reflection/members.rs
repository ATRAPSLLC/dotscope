//! Field, property, and parameter metadata hooks for the CIL emulator.
//!
//! This module provides hook implementations for `System.Reflection.FieldInfo`,
//! `System.Reflection.PropertyInfo`, `System.Reflection.ParameterInfo`, and
//! `System.Reflection.MemberInfo` operations.
//!
//! These hooks are essential for deobfuscation because obfuscators use reflection
//! to manipulate field and property values at runtime:
//!
//! - **Field access**: `FieldInfo.GetValue()` and `FieldInfo.SetValue()` are used
//!   by obfuscators to initialize static fields (e.g., decryption keys, lookup tables)
//!   through reflection rather than direct `stsfld` instructions, making static analysis
//!   more difficult
//! - **Property invocation**: `PropertyInfo.GetValue()` and `SetValue()` dispatch to
//!   the underlying getter/setter methods, which may themselves be obfuscated
//! - **Member metadata**: `MemberInfo.MetadataToken`, `DeclaringType`, and field flags
//!   (`IsStatic`, `IsPublic`, `IsLiteral`, etc.) are queried by CFF state machines
//!   and delegate builders to make control-flow decisions
//! - **Parameter types**: `ParameterInfo.ParameterType` is used during delegate
//!   construction to verify method signatures match delegate types

use log::debug;

use crate::{
    emulation::{
        runtime::{
            bcl::reflection::{
                box_value_if_needed, extract_type_token, resolve_attribute_type_token, unbox_value,
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::{EmulationThread, ReflectionInvokeRequest},
        EmValue, HeapObject,
    },
    metadata::{
        customattributes::CustomAttributeValueList,
        tables::FieldAttributes,
        typesystem::{CilFlavor, TypeResolver},
    },
    CilObject, Result,
};

/// Registers all field, property, parameter, and member metadata hooks.
///
/// Called by the parent `reflection::register()` to wire up `FieldInfo`, `PropertyInfo`,
/// `ParameterInfo`, and `MemberInfo` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // FieldInfo methods
    manager.register(
        Hook::new("System.Reflection.FieldInfo.GetValue")
            .match_name("System.Reflection", "FieldInfo", "GetValue")
            .pre(field_get_value_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.SetValue")
            .match_name("System.Reflection", "FieldInfo", "SetValue")
            .pre(field_set_value_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_FieldType")
            .match_name("System.Reflection", "FieldInfo", "get_FieldType")
            .pre(field_get_field_type_pre),
    )?;

    // MemberInfo.get_MetadataToken
    manager.register(
        Hook::new("System.Reflection.MemberInfo.get_MetadataToken")
            .match_name("System.Reflection", "MemberInfo", "get_MetadataToken")
            .pre(member_get_metadata_token_pre),
    )?;

    // MemberInfo.get_DeclaringType
    manager.register(
        Hook::new("System.Reflection.MemberInfo.get_DeclaringType")
            .match_name("System.Reflection", "MemberInfo", "get_DeclaringType")
            .pre(member_get_declaring_type_pre),
    )?;

    // ParameterInfo.get_ParameterType
    manager.register(
        Hook::new("System.Reflection.ParameterInfo.get_ParameterType")
            .match_name("System.Reflection", "ParameterInfo", "get_ParameterType")
            .pre(parameter_get_parameter_type_pre),
    )?;

    // PropertyInfo methods
    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetValue")
            .match_name("System.Reflection", "PropertyInfo", "GetValue")
            .pre(property_get_value_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.SetValue")
            .match_name("System.Reflection", "PropertyInfo", "SetValue")
            .pre(property_set_value_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_PropertyType")
            .match_name("System.Reflection", "PropertyInfo", "get_PropertyType")
            .pre(property_get_property_type_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_CanRead")
            .match_name("System.Reflection", "PropertyInfo", "get_CanRead")
            .pre(property_get_can_read_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_CanWrite")
            .match_name("System.Reflection", "PropertyInfo", "get_CanWrite")
            .pre(property_get_can_write_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.get_Name")
            .match_name("System.Reflection", "PropertyInfo", "get_Name")
            .pre(property_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetGetMethod")
            .match_name("System.Reflection", "PropertyInfo", "GetGetMethod")
            .pre(property_get_get_method_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetSetMethod")
            .match_name("System.Reflection", "PropertyInfo", "GetSetMethod")
            .pre(property_get_set_method_pre),
    )?;

    // FieldInfo name and flags
    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_Name")
            .match_name("System.Reflection", "FieldInfo", "get_Name")
            .pre(field_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsStatic")
            .match_name("System.Reflection", "FieldInfo", "get_IsStatic")
            .pre(field_get_is_static_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsPublic")
            .match_name("System.Reflection", "FieldInfo", "get_IsPublic")
            .pre(field_get_is_public_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsPrivate")
            .match_name("System.Reflection", "FieldInfo", "get_IsPrivate")
            .pre(field_get_is_private_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsLiteral")
            .match_name("System.Reflection", "FieldInfo", "get_IsLiteral")
            .pre(field_get_is_literal_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.get_IsInitOnly")
            .match_name("System.Reflection", "FieldInfo", "get_IsInitOnly")
            .pre(field_get_is_init_only_pre),
    )?;

    // ConstructorInfo.get_DeclaringType (shares member_get_declaring_type_pre)
    manager.register(
        Hook::new("System.Reflection.ConstructorInfo.get_DeclaringType")
            .match_name("System.Reflection", "ConstructorInfo", "get_DeclaringType")
            .pre(member_get_declaring_type_pre),
    )?;

    // Custom attributes on members
    manager.register(
        Hook::new("System.Reflection.MemberInfo.GetCustomAttributes")
            .match_name("System.Reflection", "MemberInfo", "GetCustomAttributes")
            .pre(member_get_custom_attributes_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MethodBase.GetCustomAttributes")
            .match_name("System.Reflection", "MethodBase", "GetCustomAttributes")
            .pre(member_get_custom_attributes_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.FieldInfo.GetCustomAttributes")
            .match_name("System.Reflection", "FieldInfo", "GetCustomAttributes")
            .pre(member_get_custom_attributes_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.PropertyInfo.GetCustomAttributes")
            .match_name("System.Reflection", "PropertyInfo", "GetCustomAttributes")
            .pre(member_get_custom_attributes_pre),
    )?;

    Ok(())
}

/// Hook for `System.Reflection.FieldInfo.GetValue` method.
///
/// Returns the value of a field. When the `this` object is a `ReflectionField`
/// carrying a real field token, reads the value from the emulator's heap (for
/// instance fields) or static field storage (for static fields).
fn field_get_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, is_static)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if is_static {
                // Read from static field storage
                if let Some(value) = try_hook!(thread.address_space().get_static(field_token)) {
                    return PreHookResult::Bypass(Some(box_value_if_needed(thread, value)));
                }
            } else {
                // Read from instance field on the target object
                let target = ctx.args.first();
                if let Some(EmValue::ObjectRef(obj_ref)) = target {
                    if let Ok(value) = thread.heap().get_field(*obj_ref, field_token) {
                        return PreHookResult::Bypass(Some(box_value_if_needed(thread, value)));
                    }
                }
                debug!(
                    "FieldInfo.GetValue: instance field 0x{:08X} → target not found or field missing",
                    field_token.value(),
                );
            }
        } else {
            debug!(
                "FieldInfo.GetValue: no reflection field info for {:?}",
                fi_ref
            );
        }
    } else {
        debug!(
            "FieldInfo.GetValue: this is not an ObjectRef: {:?}",
            ctx.this
        );
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Reflection.FieldInfo.SetValue` method.
///
/// Sets the value of a field. When the `this` object is a `ReflectionField`
/// carrying a real field token, writes the value to the emulator's heap (for
/// instance fields) or static field storage (for static fields). The value
/// argument is unboxed if it's a `BoxedValue` to extract the inner primitive.
fn field_set_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, is_static)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            // Get the value to set (args[1] for SetValue(obj, value))
            let value = ctx.args.get(1).cloned().unwrap_or(EmValue::Null);

            // Unbox the value if it's a BoxedValue on the heap
            let unboxed = unbox_value(thread, &value);

            if is_static {
                // Write to static field storage — works for both null and non-null target
                try_hook!(thread.address_space().set_static(field_token, unboxed));
            } else {
                // Write to instance field on the target object
                let target = ctx.args.first();
                if let Some(EmValue::ObjectRef(obj_ref)) = target {
                    try_hook!(thread.heap().set_field(*obj_ref, field_token, unboxed));
                }
            }

            return PreHookResult::Bypass(None);
        }
        log::warn!(
            "FieldInfo.SetValue: no reflection field info for {:?} — field not written",
            fi_ref
        );
    } else {
        log::warn!(
            "FieldInfo.SetValue: this is not an ObjectRef: {:?} — field not written",
            ctx.this
        );
    }

    // Fallback: no-op if we can't identify the field
    PreHookResult::Bypass(None)
}

/// Hook for `System.Reflection.FieldInfo.get_FieldType` property.
///
/// Returns the type of the field by resolving the field's type signature from
/// assembly metadata.
fn field_get_field_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, _declaring_type, _is_static)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(sig) = asm
                    .fields()
                    .get(&field_token)
                    .map(|entry| entry.value().signature.base.clone())
                {
                    if let Ok(cil_type) = TypeResolver::new(asm.types()).resolve(&sig) {
                        if let Ok(type_ref) = thread
                            .heap_mut()
                            .alloc_reflection_type(cil_type.token, None)
                        {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::throw_type_load("Cannot resolve field type")
}

/// Hook for `MemberInfo.get_MetadataToken` property.
///
/// Returns the metadata token of the member. For `ReflectionField`, returns the
/// field token. For `ReflectionMethod`, returns the method token. For
/// `ReflectionType`, returns the type token.
fn member_get_metadata_token_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(member_ref)) = ctx.this {
        if let Ok(obj) = thread.heap().get_shared(*member_ref).as_deref() {
            #[allow(clippy::cast_possible_wrap)]
            let token = match obj {
                HeapObject::ReflectionField { field_token, .. } => Some(field_token.value() as i32),
                HeapObject::ReflectionMethod { method_token, .. } => {
                    Some(method_token.value() as i32)
                }
                HeapObject::ReflectionType { type_token, .. } => Some(type_token.value() as i32),
                _ => None,
            };
            if let Some(token_val) = token {
                return PreHookResult::Bypass(Some(EmValue::I32(token_val)));
            }
        }
    }
    // Fallback: return 0 (invalid token)
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MemberInfo.get_DeclaringType` property.
///
/// Handles `ReflectionField`, `ReflectionMethod`, and `ReflectionProperty`.
/// Returns the declaring type as a `ReflectionType` heap object.
fn member_get_declaring_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(member_ref)) = ctx.this {
        if let Ok(obj) = thread.heap().get_shared(*member_ref).as_deref() {
            let declaring_token = match obj {
                HeapObject::ReflectionField {
                    declaring_type_token,
                    ..
                } => Some(*declaring_type_token),
                HeapObject::ReflectionProperty {
                    declaring_type_token,
                    ..
                } => Some(*declaring_type_token),
                HeapObject::ReflectionMethod { method_token, .. } => {
                    thread.assembly().and_then(|asm| {
                        asm.resolver()
                            .declaring_type(*method_token)
                            .map(|t| t.token)
                    })
                }
                _ => None,
            };
            if let Some(dt) = declaring_token {
                match thread.heap_mut().alloc_reflection_type(dt, None) {
                    Ok(type_ref) => {
                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                    }
                    Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            }
        }
    }
    // .NET returns null for members without a declaring type (e.g., global functions)
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.GetValue(object)` -- invoke the getter via reflection.
///
/// Dispatches to the property's getter method via a `ReflectionInvoke` request.
fn property_get_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            let this_ref = ctx.args.first().cloned();
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token: getter,
                    this_ref,
                    args: Vec::new(),
                    method_type_args: None,
                }),
                bypass_value: Some(EmValue::Null),
            };
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.SetValue(object, object)` -- invoke the setter via reflection.
///
/// Dispatches to the property's setter method via a `ReflectionInvoke` request.
fn property_set_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, Some(setter))) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            let this_ref = ctx.args.first().cloned();
            let set_args = ctx.args.get(1).cloned().into_iter().collect();
            return PreHookResult::ReflectionInvoke {
                request: Box::new(ReflectionInvokeRequest {
                    method_token: setter,
                    this_ref,
                    args: set_args,
                    method_type_args: None,
                }),
                bypass_value: None,
            };
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `PropertyInfo.get_PropertyType`.
///
/// Returns the property's type by resolving the getter method's return type.
fn property_get_property_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(method) = asm.methods().get(&getter).map(|e| e.value().clone()) {
                    if let Ok(cil_type) =
                        TypeResolver::new(asm.types()).resolve(&method.signature.return_type.base)
                    {
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
                    return PreHookResult::throw_type_load("Cannot resolve property type");
                }
            }
        }
    }
    PreHookResult::throw_type_load("Cannot resolve property type")
}

/// Hook for `PropertyInfo.get_CanRead`.
///
/// Returns whether the property has a getter method.
fn property_get_can_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, getter_token, _)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(getter_token.is_some()))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `PropertyInfo.get_CanWrite`.
///
/// Returns whether the property has a setter method.
fn property_get_can_write_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, setter_token)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(setter_token.is_some()))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `PropertyInfo.get_Name`.
///
/// Returns the name of the property.
fn property_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((name, _, _, _)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            match thread.heap_mut().alloc_string(&name) {
                Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.GetGetMethod`.
///
/// Returns a `ReflectionMethod` for the property's getter, or null if none.
fn property_get_get_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, Some(getter), _)) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            match thread.heap_mut().alloc_reflection_method(getter) {
                Ok(m_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `PropertyInfo.GetSetMethod`.
///
/// Returns a `ReflectionMethod` for the property's setter, or null if none.
fn property_get_set_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(prop_ref)) = ctx.this {
        if let Some((_, _, _, Some(setter))) =
            try_hook!(thread.heap().get_reflection_property_info(*prop_ref))
        {
            match thread.heap_mut().alloc_reflection_method(setter) {
                Ok(m_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `ParameterInfo.get_ParameterType` -- return real type from ReflectionParameter.
///
/// Resolves the parameter's type signature from the stored `CilTypeReference` and
/// returns a `ReflectionType` heap object.
fn parameter_get_parameter_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(param_ref)) = ctx.this {
        if let Some((_, _, param_type)) =
            try_hook!(thread.heap().get_reflection_parameter_info(*param_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Ok(cil_type) = TypeResolver::new(asm.types()).resolve(&param_type) {
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
                return PreHookResult::throw_type_load("Cannot resolve parameter type");
            }
        }
    }
    PreHookResult::throw_type_load("Cannot resolve parameter type")
}

/// Hook for `FieldInfo.get_Name`.
///
/// Returns the name of the field by looking up the field token in the declaring type's metadata.
fn field_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            match thread.heap_mut().alloc_string(&field.name) {
                                Ok(s_ref) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref)))
                                }
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `FieldInfo.get_IsStatic`.
///
/// Returns whether the field is static from the stored `ReflectionField` metadata.
fn field_get_is_static_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((_, _, is_static)) = try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_static))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsPublic`.
///
/// Returns whether the field has public accessibility by checking its `FieldAttributes`.
fn field_get_is_public_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            let is_public = field.flags.access() == FieldAttributes::PUBLIC;
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_public))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsPrivate`.
///
/// Returns whether the field has private accessibility by checking its `FieldAttributes`.
fn field_get_is_private_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            let is_private = field.flags.access() == FieldAttributes::PRIVATE;
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                is_private,
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsLiteral`.
///
/// Returns whether the field is a compile-time constant (`const` in C#).
fn field_get_is_literal_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                field.flags.is_literal(),
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `FieldInfo.get_IsInitOnly`.
///
/// Returns whether the field is `readonly` in C# (can only be assigned in constructors).
fn field_get_is_init_only_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(fi_ref)) = ctx.this {
        if let Some((field_token, declaring_type_token, _)) =
            try_hook!(thread.heap().get_reflection_field_info(*fi_ref))
        {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&declaring_type_token) {
                    for (_, field) in cil_type.fields.iter() {
                        if field.token == field_token {
                            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(
                                field.flags.is_init_only(),
                            ))));
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `GetCustomAttributes` on `MemberInfo`, `MethodBase`, `FieldInfo`, `PropertyInfo`.
///
/// Reads the custom attributes list directly from the member's metadata struct
/// and returns an `Attribute[]` array. Supports optional type filtering when a
/// `Type` argument is provided.
fn member_get_custom_attributes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let filter_token = ctx
        .args
        .iter()
        .find_map(|arg| extract_type_token(thread, arg));

    if let Some(asm) = thread.assembly().cloned() {
        if let Some(attrs) = extract_member_custom_attrs(ctx, thread, &asm) {
            let mut elements = Vec::new();

            for (_, attr_rc) in attrs.iter() {
                let attr_type = match resolve_attribute_type_token(&asm, &attr_rc.constructor) {
                    Some(t) => t,
                    None => continue,
                };

                if let Some(filter) = filter_token {
                    if attr_type != filter {
                        continue;
                    }
                }

                match thread.heap_mut().alloc_object(attr_type) {
                    Ok(obj_ref) => elements.push(EmValue::ObjectRef(obj_ref)),
                    Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            }

            match thread
                .heap_mut()
                .alloc_array_with_values(CilFlavor::Object, elements)
            {
                Ok(arr_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }

    // Fallback: empty array
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Extracts the custom attributes list from the member referenced by `this`.
fn extract_member_custom_attrs(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
    asm: &CilObject,
) -> Option<CustomAttributeValueList> {
    let href = match ctx.this {
        Some(EmValue::ObjectRef(href)) => *href,
        _ => return None,
    };
    match thread.heap().get_shared(href).as_deref() {
        Ok(HeapObject::ReflectionMethod { method_token, .. }) => asm
            .method(method_token)
            .ok()
            .map(|m| m.custom_attributes.clone()),
        Ok(HeapObject::ReflectionField {
            field_token,
            declaring_type_token,
            ..
        }) => {
            let cil_type = asm.types().resolve(declaring_type_token)?;
            for (_, field_rc) in cil_type.fields.iter() {
                if field_rc.token == *field_token {
                    return Some(field_rc.custom_attributes.clone());
                }
            }
            None
        }
        Ok(HeapObject::ReflectionProperty {
            declaring_type_token,
            property_name,
            ..
        }) => {
            let cil_type = asm.types().resolve(declaring_type_token)?;
            for (_, prop_rc) in cil_type.properties.iter() {
                if prop_rc.name == property_name.as_ref() {
                    return Some(prop_rc.custom_attributes.clone());
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::field_get_value_pre;
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_field_get_value_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Reflection",
            "FieldInfo",
            "GetValue",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = field_get_value_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::Null)) => {}
            _ => panic!("Expected Bypass with Null"),
        }
    }
}

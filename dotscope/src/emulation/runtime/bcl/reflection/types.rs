//! `System.Type`-related reflection hooks for the CIL emulator.
//!
//! This module provides hook implementations for `System.Type` properties and methods,
//! `Object.GetType()`, `Activator.CreateInstance()`, delegate creation/invocation, and
//! custom attribute inspection. These hooks form the backbone of reflection emulation
//! for deobfuscation, where obfuscators use runtime type inspection to:
//!
//! - Resolve types via `Type.GetTypeFromHandle` after `ldtoken`
//! - Check type properties (`IsValueType`, `IsArray`, `IsEnum`, etc.) in control-flow
//!   flattening state machines
//! - Enumerate type members (`GetMethods`, `GetFields`, `GetProperties`) to locate
//!   decryption routines or build delegate dispatch tables
//! - Create instances via `Activator.CreateInstance` for runtime object construction
//! - Build delegates through `Delegate.CreateDelegate` and combine them with
//!   `Delegate.Combine`; a delegate's `Invoke`, whatever type declares it, is dispatched
//!   by the call resolver to the methods of its invocation list
//! - Check custom attributes via `GetCustomAttributes` and `IsDefined` for licensing
//!   or anti-tamper verification
//!
//! All returned objects are symbolic heap allocations carrying real metadata tokens,
//! enabling downstream hooks (e.g., `MethodBase.Invoke`, `FieldInfo.SetValue`) to
//! operate on the correct assembly metadata.

use std::sync::Arc;

use log::{debug, warn};

use crate::{
    emulation::{
        memory::TypeWrapper,
        runtime::{
            bcl::reflection::{
                alloc_type_array_from_tokens, extract_type_token, find_method_by_name,
                normalize_type_token, resolve_attribute_type_token, unbox_value,
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::{EmulationThread, ReflectionInvokeRequest},
        tokens, EmValue, HeapObject,
    },
    metadata::{
        method::Method,
        token::Token,
        typesystem::{
            wellknown, CilFlavor, CilPrimitiveData, CilPrimitiveKind, CilType, CilTypeReference,
            TypeResolver,
        },
    },
    Result,
};

/// Registers all `System.Type`, `Object.GetType`, `Activator`, delegate, and
/// custom attribute hooks.
///
/// Called by the parent `reflection::register()` to wire up type-related hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Type.op_Equality")
            .match_name("System", "Type", "op_Equality")
            .pre(type_op_equality_pre),
    )?;

    manager.register(
        Hook::new("System.Type.op_Inequality")
            .match_name("System", "Type", "op_Inequality")
            .pre(type_op_inequality_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_Module")
            .match_name("System", "Type", "get_Module")
            .pre(type_get_module_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetTypeFromHandle")
            .match_name("System", "Type", "GetTypeFromHandle")
            .pre(type_get_type_from_handle_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_TypeHandle")
            .match_name("System", "Type", "get_TypeHandle")
            .pre(type_get_type_handle_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetMethod")
            .match_name("System", "Type", "GetMethod")
            .pre(type_get_method_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetField")
            .match_name("System", "Type", "GetField")
            .pre(type_get_field_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetFields")
            .match_name("System", "Type", "GetFields")
            .pre(type_get_fields_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetProperty")
            .match_name("System", "Type", "GetProperty")
            .pre(type_get_property_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetConstructor")
            .match_name("System", "Type", "GetConstructor")
            .pre(type_get_constructor_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_Assembly")
            .match_name("System", "Type", "get_Assembly")
            .pre(type_get_assembly_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.CreateDelegate")
            .match_name("System", "Delegate", "CreateDelegate")
            .pre(delegate_create_delegate_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetGenericArguments")
            .match_name("System", "Type", "GetGenericArguments")
            .pre(type_get_generic_arguments_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsValueType")
            .match_name("System", "Type", "get_IsValueType")
            .pre(type_get_is_value_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.MakeByRefType")
            .match_name("System", "Type", "MakeByRefType")
            .pre(type_make_by_ref_type_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.Combine")
            .match_name("System", "Delegate", "Combine")
            .pre(delegate_combine_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.Remove")
            .match_name("System", "Delegate", "Remove")
            .pre(delegate_remove_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.get_Method")
            .match_name("System", "Delegate", "get_Method")
            .pre(delegate_get_method_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.get_Target")
            .match_name("System", "Delegate", "get_Target")
            .pre(delegate_get_target_pre),
    )?;

    manager.register(
        Hook::new("System.Delegate.DynamicInvoke")
            .match_name("System", "Delegate", "DynamicInvoke")
            .pre(delegate_dynamic_invoke_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_FullName")
            .match_name("System", "Type", "get_FullName")
            .pre(type_get_full_name_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_Name")
            .match_name("System", "Type", "get_Name")
            .pre(type_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_Namespace")
            .match_name("System", "Type", "get_Namespace")
            .pre(type_get_namespace_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_BaseType")
            .match_name("System", "Type", "get_BaseType")
            .pre(type_get_base_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetElementType")
            .match_name("System", "Type", "GetElementType")
            .pre(type_get_element_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.MakeArrayType")
            .match_name("System", "Type", "MakeArrayType")
            .pre(type_make_array_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.MakeGenericType")
            .match_name("System", "Type", "MakeGenericType")
            .pre(type_make_generic_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsArray")
            .match_name("System", "Type", "get_IsArray")
            .pre(type_get_is_array_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsEnum")
            .match_name("System", "Type", "get_IsEnum")
            .pre(type_get_is_enum_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsInterface")
            .match_name("System", "Type", "get_IsInterface")
            .pre(type_get_bool_flag_pre(
                |cil_type| cil_type.flags.is_interface(),
                None,
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsAbstract")
            .match_name("System", "Type", "get_IsAbstract")
            .pre(type_get_bool_flag_pre(
                |cil_type| cil_type.flags.is_abstract(),
                None,
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsSealed")
            .match_name("System", "Type", "get_IsSealed")
            .pre(type_get_bool_flag_pre(
                |cil_type| cil_type.flags.is_sealed(),
                None,
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsPublic")
            .match_name("System", "Type", "get_IsPublic")
            .pre(type_get_bool_flag_pre(
                |cil_type| cil_type.flags.is_public(),
                None,
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsGenericType")
            .match_name("System", "Type", "get_IsGenericType")
            .pre(type_get_bool_flag_pre(
                |cil_type| !cil_type.generic_params.is_empty(),
                Some(|w| matches!(w, TypeWrapper::GenericInst(_))),
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsByRef")
            .match_name("System", "Type", "get_IsByRef")
            .pre(type_get_bool_flag_pre(
                |cil_type| *cil_type.flavor() == CilFlavor::ByRef,
                Some(|w| matches!(w, TypeWrapper::ByRef)),
            )),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsPointer")
            .match_name("System", "Type", "get_IsPointer")
            .pre(type_get_bool_flag_pre(
                |cil_type| *cil_type.flavor() == CilFlavor::Pointer,
                Some(|w| matches!(w, TypeWrapper::Pointer)),
            )),
    )?;

    manager.register(
        Hook::new("System.Type.GetMethods")
            .match_name("System", "Type", "GetMethods")
            .pre(type_get_methods_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetProperties")
            .match_name("System", "Type", "GetProperties")
            .pre(type_get_properties_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetConstructors")
            .match_name("System", "Type", "GetConstructors")
            .pre(type_get_constructors_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetInterfaces")
            .match_name("System", "Type", "GetInterfaces")
            .pre(type_get_interfaces_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetNestedTypes")
            .match_name("System", "Type", "GetNestedTypes")
            .pre(type_get_nested_types_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetMembers")
            .match_name("System", "Type", "GetMembers")
            .pre(type_get_members_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetCustomAttributes")
            .match_name("System", "Type", "GetCustomAttributes")
            .pre(type_get_custom_attributes_pre),
    )?;

    manager.register(
        Hook::new("System.Attribute.IsDefined")
            .match_name("System", "Attribute", "IsDefined")
            .pre(attribute_is_defined_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.MemberInfo.IsDefined")
            .match_name("System.Reflection", "MemberInfo", "IsDefined")
            .pre(member_is_defined_pre),
    )?;

    manager.register(
        Hook::new("System.Type.IsDefined")
            .match_name("System", "Type", "IsDefined")
            .pre(member_is_defined_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetEnumValues")
            .match_name("System", "Type", "GetEnumValues")
            .pre(type_get_enum_values_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetEnumNames")
            .match_name("System", "Type", "GetEnumNames")
            .pre(type_get_enum_names_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetEnumUnderlyingType")
            .match_name("System", "Type", "GetEnumUnderlyingType")
            .pre(type_get_enum_underlying_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.IsAssignableFrom")
            .match_name("System", "Type", "IsAssignableFrom")
            .pre(type_is_assignable_from_pre),
    )?;

    manager.register(
        Hook::new("System.Type.IsSubclassOf")
            .match_name("System", "Type", "IsSubclassOf")
            .pre(type_is_subclass_of_pre),
    )?;

    manager.register(
        Hook::new("System.Activator.CreateInstance")
            .match_name("System", "Activator", "CreateInstance")
            .pre(activator_create_instance_pre),
    )?;

    manager.register(
        Hook::new("System.Object.GetType")
            .match_name("System", "Object", "GetType")
            .pre(object_get_type_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetInterfaceMap")
            .match_name("System", "Type", "GetInterfaceMap")
            .pre(type_get_interface_map_pre),
    )?;

    manager.register(
        Hook::new("System.Type.get_IsGenericParameter")
            .match_name("System", "Type", "get_IsGenericParameter")
            .pre(type_get_bool_flag_pre(|_| false, None)),
    )?;

    manager.register(
        Hook::new("System.Type.GetTypeCode")
            .match_name("System", "Type", "GetTypeCode")
            .pre(type_get_type_code_pre),
    )?;

    manager.register(
        Hook::new("System.Type.GetType")
            .match_name("System", "Type", "GetType")
            .pre(type_get_type_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.AssemblyName.GetPublicKeyToken")
            .match_name("System.Reflection", "AssemblyName", "GetPublicKeyToken")
            .pre(assembly_name_get_public_key_token_pre),
    )?;

    Ok(())
}

/// Hook for `System.Object.GetType()`.
///
/// Returns a `ReflectionType` representing the runtime type of the object.
/// Inspects the heap object to determine its type token:
/// - For `Object`, `BoxedValue`, `Delegate`: uses the stored `type_token`
/// - For `ReflectionType`: returns itself (Type.GetType() returns System.Type)
/// - For strings/arrays: returns a placeholder type
/// - Fallback: returns `Null`
fn object_get_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        // Try to get the type token from the heap object
        if let Ok(type_token) = thread.heap().get_type_token(*obj_ref) {
            match thread.heap_mut().alloc_reflection_type(type_token, None) {
                Ok(type_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)));
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
        // Check if it's a ReflectionType — Type.GetType() returns typeof(System.Type)
        if try_hook!(thread.heap().get_reflection_type_token(*obj_ref)).is_some() {
            // Look up System.Type in the assembly's type registry
            let system_type_token = thread
                .assembly()
                .and_then(|asm| {
                    asm.types()
                        .get_by_fullname("System.Type", true)
                        .map(|t| t.token)
                })
                .unwrap_or_else(|| {
                    warn!("Object.GetType: System.Type not found in type registry, using System.Object");
                    CilPrimitiveKind::Object.token()
                });
            match thread
                .heap_mut()
                .alloc_reflection_type(system_type_token, None)
            {
                Ok(type_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)));
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    // Every .NET object is at least System.Object
    let object_token = CilPrimitiveKind::Object.token();
    match thread.heap_mut().alloc_reflection_type(object_token, None) {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(e) => PreHookResult::Error(format!("Object.GetType: heap allocation failed: {e}")),
    }
}

/// Hook for `System.Type.op_Equality(Type, Type)`.
///
/// Compares two Type references for equality by their underlying metadata tokens.
/// Tokens are normalized so that TypeRef tokens for BCL primitives (e.g.,
/// `System.Int32`) compare equal to their artificial `0xF000_XXXX` counterparts.
/// Two null types are considered equal; a null and non-null are not.
fn type_op_equality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let lhs_null = matches!(ctx.args.first(), Some(EmValue::Null) | None);
    let rhs_null = matches!(ctx.args.get(1), Some(EmValue::Null) | None);

    let equal = match (lhs_null, rhs_null) {
        (true, true) => true,
        (true, false) | (false, true) => false,
        (false, false) => {
            let lhs = ctx
                .args
                .first()
                .and_then(|v| extract_type_token(thread, v))
                .map(|t| normalize_type_token(thread, t));
            let rhs = ctx
                .args
                .get(1)
                .and_then(|v| extract_type_token(thread, v))
                .map(|t| normalize_type_token(thread, t));
            lhs == rhs
        }
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for `System.Type.op_Inequality(Type, Type)`.
///
/// Compares two Type references for inequality by their underlying metadata tokens.
/// Tokens are normalized via [`normalize_type_token`] before comparison.
fn type_op_inequality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let lhs_null = matches!(ctx.args.first(), Some(EmValue::Null) | None);
    let rhs_null = matches!(ctx.args.get(1), Some(EmValue::Null) | None);

    let not_equal = match (lhs_null, rhs_null) {
        (true, true) => false,
        (true, false) | (false, true) => true,
        (false, false) => {
            let lhs = ctx
                .args
                .first()
                .and_then(|v| extract_type_token(thread, v))
                .map(|t| normalize_type_token(thread, t));
            let rhs = ctx
                .args
                .get(1)
                .and_then(|v| extract_type_token(thread, v))
                .map(|t| normalize_type_token(thread, t));
            lhs != rhs
        }
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(not_equal))))
}

/// Hook for `System.Type.get_Module` property.
///
/// Gets the module (the DLL) in which the current Type is defined.
/// Returns a fake Module heap object.
fn type_get_module_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_object(tokens::reflection::MODULE) {
        Ok(module_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(module_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Type.get_Assembly` property.
///
/// Gets the assembly in which the type is defined.
///
/// Returns the pre-allocated fake Assembly object from [`FakeObjects`](crate::emulation::FakeObjects), ensuring
/// consistency with `Module.get_Assembly`.
fn type_get_assembly_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(asm_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref)));
    }

    match thread.heap_mut().alloc_object(tokens::singletons::ASSEMBLY) {
        Ok(asm_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Type.GetTypeFromHandle` method.
///
/// Gets the type referenced by the specified type handle. The `ldtoken` instruction
/// pushes a `NativeInt` containing the raw metadata token, which is then passed as
/// a `RuntimeTypeHandle` argument. We extract this token and allocate a `ReflectionType`
/// heap object that carries it, enabling subsequent calls like `Type.GetFields()` to
/// look up the type's actual fields from assembly metadata.
fn type_get_type_from_handle_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract the type token from the RuntimeTypeHandle argument.
    // The emulator represents ldtoken as NativeInt(token_value).
    #[allow(clippy::cast_sign_loss)]
    let type_token = ctx.args.first().and_then(|arg| match arg {
        EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
        EmValue::I32(v) => Some(Token::new(*v as u32)),
        EmValue::NativeUInt(v) => Some(Token::new(*v as u32)),
        // ValueType wrapping the handle — try the first field
        EmValue::ValueType { fields, .. } => fields.first().and_then(|f| match f {
            EmValue::NativeInt(v) => Some(Token::new(*v as u32)),
            EmValue::I32(v) => Some(Token::new(*v as u32)),
            _ => None,
        }),
        _ => None,
    });

    let type_token = match type_token {
        Some(t) => t,
        None => {
            return PreHookResult::throw_argument_exception("Invalid RuntimeTypeHandle");
        }
    };

    // Detect SzArray primitive tokens (e.g., byte[] = 0xF000_0105) and create
    // a ReflectionType with SzArray wrapper so GetElementType works correctly.
    let (effective_token, wrapper) = if tokens::is_szarray_primitive(type_token) {
        let elem_token = tokens::szarray_element_token(type_token).unwrap_or(type_token);
        (elem_token, Some(TypeWrapper::SzArray))
    } else {
        (type_token, None)
    };

    match thread
        .heap_mut()
        .alloc_reflection_type(effective_token, wrapper)
    {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.get_TypeHandle` property.
///
/// Returns the `RuntimeTypeHandle` for the given `Type` object. Extracts the
/// type token stored in the `ReflectionType` heap object and wraps it as a
/// `NativeInt`, matching the convention used by `GetRuntimeTypeHandleFromMetadataToken`
/// and expected by `GetTypeFromHandle`.
fn type_get_type_handle_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            return PreHookResult::Bypass(Some(EmValue::NativeInt(i64::from(type_token.value()))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::NativeInt(0)))
}

/// Hook for `System.Type.GetMethod` method.
///
/// Searches for the specified method, using the specified binding constraints.
/// Supports multiple overloads including those with `BindingFlags`, `Type[]` parameters,
/// and `ParameterModifier[]`.
fn type_get_method_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to resolve the method by name if we have a ReflectionType with real metadata
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Try to get the method name from the first argument
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(method_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(resolved) = find_method_by_name(&asm, type_token, &method_name)
                        {
                            match thread.heap_mut().alloc_reflection_method(resolved) {
                                Ok(m_ref) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref)))
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

    warn!("Type.GetMethod: no matching method found, returning null");
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Type.GetField` method.
///
/// Searches for the specified field, using the specified binding constraints.
/// Resolves the field from the type's metadata and returns a `ReflectionField`
/// heap object carrying the real field token.
fn type_get_field_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to resolve the field by name if we have a ReflectionType with real metadata
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Try to get the field name from the first argument
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(field_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().resolve(&type_token) {
                            for (_, field) in cil_type.fields.iter() {
                                if field.name == field_name.as_ref() {
                                    if let Ok(fi_ref) = thread.heap_mut().alloc_reflection_field(
                                        field.token,
                                        type_token,
                                        field.flags.is_static(),
                                    ) {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            fi_ref,
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    debug!("Type.GetField: no matching field found, returning null");
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Type.GetFields` method.
///
/// Returns all fields of the type. When the `this` object is a `ReflectionType`
/// carrying a real metadata token, this hook looks up the type in the assembly's
/// type registry and returns an array of `ReflectionField` heap objects, each
/// carrying the actual field metadata token.
fn type_get_fields_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to get the type token from the 'this' ReflectionType object
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Look up the type in the assembly's type registry
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    // Collect all fields into ReflectionField heap objects
                    let mut field_elements = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        match thread.heap_mut().alloc_reflection_field(
                            field.token,
                            type_token,
                            field.flags.is_static(),
                        ) {
                            Ok(fi_ref) => field_elements.push(EmValue::ObjectRef(fi_ref)),
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }

                    // Allocate an array containing the FieldInfo objects
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, field_elements)
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

    // Fallback: return an empty array
    debug!("Type.GetFields: returning empty fallback array");
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Type.GetProperty` method.
///
/// Searches for the specified property, using the specified binding constraints.
/// Supports multiple overloads. Falls back to searching for `get_Name` / `set_Name`
/// method patterns when no property metadata entry matches.
fn type_get_property_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
                if let Ok(property_name) = thread.heap().get_string(*name_ref) {
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().resolve(&type_token) {
                            // Search properties by name
                            for (_, prop) in cil_type.properties.iter() {
                                if prop.name == property_name.as_ref() {
                                    let getter_token = prop
                                        .fn_getter
                                        .get()
                                        .and_then(|mr| mr.upgrade().map(|m| m.token));
                                    let setter_token = prop
                                        .fn_setter
                                        .get()
                                        .and_then(|mr| mr.upgrade().map(|m| m.token));
                                    match thread.heap_mut().alloc_reflection_property(
                                        Arc::from(property_name.as_ref()),
                                        type_token,
                                        getter_token,
                                        setter_token,
                                    ) {
                                        Ok(p_ref) => {
                                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                                p_ref,
                                            )))
                                        }
                                        Err(_) => {
                                            return PreHookResult::Bypass(Some(EmValue::Null))
                                        }
                                    }
                                }
                            }

                            // Fallback: look for get_Name / set_Name method patterns
                            let get_name = format!("get_{property_name}");
                            let set_name = format!("set_{property_name}");
                            let getter_token = find_method_by_name(&asm, type_token, &get_name);
                            let setter_token = find_method_by_name(&asm, type_token, &set_name);
                            if getter_token.is_some() || setter_token.is_some() {
                                match thread.heap_mut().alloc_reflection_property(
                                    Arc::from(property_name.as_ref()),
                                    type_token,
                                    getter_token,
                                    setter_token,
                                ) {
                                    Ok(p_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            p_ref,
                                        )))
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
    }

    warn!("Type.GetProperty: no matching property found, returning null");
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Type.GetConstructor` method.
///
/// Searches for a constructor whose parameters match the specified argument types.
/// Supports multiple overloads with `BindingFlags`, `Binder`, and `CallingConventions`.
fn type_get_constructor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                // Determine expected parameter count from the Type[] argument
                let expected_params = ctx
                    .args
                    .iter()
                    .find_map(|arg| {
                        if let EmValue::ObjectRef(arr_ref) = arg {
                            if let Ok(HeapObject::Array { elements, .. }) =
                                thread.heap().get_shared(*arr_ref).as_deref()
                            {
                                return Some(elements.len());
                            }
                        }
                        None
                    })
                    .unwrap_or(0);

                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    // Search for .ctor with matching parameter count
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor"
                                && method.signature.params.len() == expected_params
                            {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            m_ref,
                                        )))
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
                    // If no exact match, try first .ctor
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor" {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            m_ref,
                                        )))
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
    }

    warn!("Type.GetConstructor: no matching constructor found, returning null");
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.GetGenericArguments()`.
///
/// Returns generic type arguments from three sources (checked in order):
/// 1. `TypeWrapper::GenericInst(args)` -- types created by `MakeGenericType()` at runtime
/// 2. `CilType.generic_args` -- constructed generic types from metadata (e.g., `List<int>`)
/// 3. `CilType.generic_params` -- open generic type definitions (e.g., `List<T>`)
fn type_get_generic_arguments_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        // Source 1: TypeWrapper::GenericInst from MakeGenericType()
        if let Some(TypeWrapper::GenericInst(ref args)) =
            try_hook!(thread.heap().get_reflection_type_wrapper(*type_ref))
        {
            if !args.is_empty() {
                return alloc_type_array_from_tokens(thread, args);
            }
        }

        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    // Source 2: Constructed generic types from metadata
                    let mut arg_tokens = Vec::new();
                    for i in 0..cil_type.generic_args.count() {
                        if let Some(method_spec) = cil_type.generic_args.get(i) {
                            for j in 0..method_spec.generic_args.count() {
                                if let Some(type_arg_ref) = method_spec.generic_args.get(j) {
                                    if let Some(t) = type_arg_ref.token() {
                                        arg_tokens.push(t);
                                    }
                                }
                            }
                        }
                    }
                    if !arg_tokens.is_empty() {
                        return alloc_type_array_from_tokens(thread, &arg_tokens);
                    }

                    // Source 3: Open generic type definitions
                    for (_, gp) in cil_type.generic_params.iter() {
                        arg_tokens.push(gp.token);
                    }
                    if !arg_tokens.is_empty() {
                        return alloc_type_array_from_tokens(thread, &arg_tokens);
                    }
                }
            }
        }
    }
    // No generic arguments — return empty Type[]
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.get_IsValueType` property.
///
/// Checks whether the type is a value type by walking the base type chain
/// looking for `System.ValueType`. Matches Mono semantics where `System.ValueType`
/// and `System.Enum` themselves are NOT value types.
fn type_get_is_value_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    // Matches Mono: System.ValueType and System.Enum are NOT value types
                    if cil_type.namespace == "System"
                        && (cil_type.name == "ValueType" || cil_type.name == "Enum")
                    {
                        return PreHookResult::Bypass(Some(EmValue::I32(0)));
                    }

                    // Matches Mono: IsSubclassOf(typeof(ValueType))
                    // Walk the base type chain looking for System.ValueType.
                    // `base_chain` bounds the walk against cyclic `extends` graphs.
                    for ancestor in cil_type.base_chain() {
                        let name = ancestor.fullname();
                        if &*name == "System.ValueType" {
                            return PreHookResult::Bypass(Some(EmValue::I32(1)));
                        }
                        if &*name == "System.Object" {
                            break;
                        }
                    }

                    // Fallback: check CilFlavor for value types whose base chain
                    // may not be available (e.g., TypeRef entries for external types)
                    if cil_type.flavor().is_value_type() {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }

                    // Final fallback: well-known value type fullnames for cases where
                    // neither the base chain nor flavor correctly identify the type
                    // (e.g., TypeRef entries with no base and default flags)
                    if wellknown::is_known_value_type(&cil_type.fullname()) {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }

                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }
            }
            // Token not found in the registry — check if it's a well-known primitive
            // token (0xF000xxxx) that might not have been registered
            if type_token.value() & 0xFFFF_FF00 == 0xF000_0000 {
                if let Ok(kind) = CilPrimitiveKind::from_byte((type_token.value() & 0xFF) as u8) {
                    if kind.is_value_type() {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }
                }
            }
            warn!(
                "IsValueType: type token 0x{:08X} not found in registry",
                type_token.value()
            );
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.MakeByRefType()`.
///
/// Returns a `Type` object with `ByRef` wrapper tracking. Rejects double ByRef
/// (matches Mono behavior: `if (IsByRef) throw new TypeLoadException`).
fn type_make_by_ref_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        // Reject double ByRef (matches Mono behavior)
        if let Some(TypeWrapper::ByRef) =
            try_hook!(thread.heap().get_reflection_type_wrapper(*type_ref))
        {
            return PreHookResult::throw_type_load("Cannot create a ByRef type of a ByRef type");
        }

        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Also check registry flavor for types not created via MakeByRefType
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    if *cil_type.flavor() == CilFlavor::ByRef {
                        return PreHookResult::throw_type_load(
                            "Cannot create a ByRef type of a ByRef type",
                        );
                    }
                }
            }
            match thread
                .heap_mut()
                .alloc_reflection_type(type_token, Some(TypeWrapper::ByRef))
            {
                Ok(new_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::throw_type_load("MakeByRefType: failed to resolve base type")
}

/// Hook for `Type.MakeArrayType()`.
///
/// Returns a `Type` object with `SzArray` wrapper tracking.
fn type_make_array_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            match thread
                .heap_mut()
                .alloc_reflection_type(type_token, Some(TypeWrapper::SzArray))
            {
                Ok(new_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::throw_type_load("MakeArrayType: failed to resolve base type")
}

/// Hook for `Type.MakeGenericType(Type[])`.
///
/// Returns a `Type` object with `GenericInst` wrapper tracking, storing the
/// generic argument tokens extracted from the `Type[]` parameter.
fn type_make_generic_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Extract type argument tokens from the Type[] arg
            let mut arg_tokens = Vec::new();
            if let Some(EmValue::ObjectRef(arr_ref)) = ctx.args.first() {
                if let Ok(len) = thread.heap().get_array_length(*arr_ref) {
                    for i in 0..len {
                        if let Ok(EmValue::ObjectRef(elem_ref)) =
                            thread.heap().get_array_element(*arr_ref, i)
                        {
                            if let Some(t) =
                                try_hook!(thread.heap().get_reflection_type_token(elem_ref))
                            {
                                arg_tokens.push(t);
                            }
                        }
                    }
                }
            }
            match thread
                .heap_mut()
                .alloc_reflection_type(type_token, Some(TypeWrapper::GenericInst(arg_tokens)))
            {
                Ok(new_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::throw_type_load("MakeGenericType: failed to resolve base type")
}

/// Hook for `Type.GetElementType()`.
///
/// Returns the element type for wrapper types (`ByRef`, `SzArray`, `Pointer`) and
/// array types. Returns null for non-wrapper/non-array types.
fn type_get_element_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        // If this type has a wrapper, GetElementType returns the unwrapped base type
        if let Some(wrapper) = try_hook!(thread.heap().get_reflection_type_wrapper(*type_ref)) {
            if matches!(
                wrapper,
                TypeWrapper::ByRef | TypeWrapper::SzArray | TypeWrapper::Pointer
            ) {
                if let Some(type_token) =
                    try_hook!(thread.heap().get_reflection_type_token(*type_ref))
                {
                    match thread.heap_mut().alloc_reflection_type(type_token, None) {
                        Ok(base_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(base_ref)))
                        }
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
            }
        }
        // For non-wrapper types, try to unwrap from the type registry
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    if let CilFlavor::Array { .. } = cil_type.flavor() {
                        if let Some(base) = cil_type.base() {
                            match thread.heap_mut().alloc_reflection_type(base.token, None) {
                                Ok(elem_ref) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                        elem_ref,
                                    )))
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
    // Non-array/non-wrapper types return null (matches .NET behavior)
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_BaseType`.
///
/// Returns the base type of the type, or null if the type has no base
/// (e.g., `System.Object`).
fn type_get_base_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    if let Some(base_type) = cil_type.base() {
                        match thread
                            .heap_mut()
                            .alloc_reflection_type(base_type.token, None)
                        {
                            Ok(t_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(t_ref)))
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
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Type.get_IsArray`.
///
/// Returns whether the type represents an array type, checking both wrapper
/// overrides (`TypeWrapper::SzArray`) and the type registry's `CilFlavor`.
fn type_get_is_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        // Check wrapper override first
        if let Some(wrapper) = try_hook!(thread.heap().get_reflection_type_wrapper(*type_ref)) {
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(matches!(
                wrapper,
                TypeWrapper::SzArray
            )))));
        }
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let is_array = matches!(cil_type.flavor(), CilFlavor::Array { .. });
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_array))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.get_IsEnum`.
///
/// Returns whether the type is an enum by checking if its base type is `System.Enum`.
fn type_get_is_enum_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let is_enum = cil_type
                        .base()
                        .is_some_and(|base| base.name == "Enum" && base.namespace == "System");
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_enum))));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Factory for Type boolean flag hooks that check CilType metadata.
///
/// When `wrapper_check` is provided, it is checked first against any
/// [`TypeWrapper`] override on the heap object. This handles types
/// created by `MakeByRefType()`, `MakeArrayType()`, etc.
fn type_get_bool_flag_pre(
    check: fn(&CilType) -> bool,
    wrapper_check: Option<fn(&TypeWrapper) -> bool>,
) -> impl Fn(&HookContext<'_>, &mut EmulationThread) -> PreHookResult {
    move |ctx, thread| {
        if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
            // Check wrapper override first
            if let Some(wcheck) = wrapper_check {
                if let Some(wrapper) =
                    try_hook!(thread.heap().get_reflection_type_wrapper(*type_ref))
                {
                    return PreHookResult::Bypass(Some(EmValue::I32(i32::from(wcheck(&wrapper)))));
                }
            }
            // Fall back to registry lookup
            if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref))
            {
                if let Some(asm) = thread.assembly().cloned() {
                    if let Some(cil_type) = asm.types().resolve(&type_token) {
                        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(check(
                            &cil_type,
                        )))));
                    }
                }
            }
        }
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `Type.GetTypeCode(Type) -> TypeCode`.
///
/// Static method — the Type argument is `ctx.args[0]`, not `ctx.this`.
/// Maps the type's token or fullname to a .NET `TypeCode` enum value.
fn type_get_type_code_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_arg = ctx.args.first().unwrap_or(&EmValue::Null);

    if let EmValue::ObjectRef(type_ref) = type_arg {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            // Fast path: primitive synthetic tokens
            if let Some(code) = wellknown::primitive_token_to_typecode(type_token) {
                return PreHookResult::Bypass(Some(EmValue::I32(code)));
            }
            // Slow path: resolve via assembly type registry
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let fullname = cil_type.fullname();
                    return PreHookResult::Bypass(Some(EmValue::I32(
                        wellknown::fullname_to_typecode(&fullname),
                    )));
                }
            }
        }
    }

    // Null type or unresolvable → TypeCode.Empty (0)
    if matches!(type_arg, EmValue::Null) {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Fallback: TypeCode.Object
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Type.GetMethods()` / `Type.GetMethods(BindingFlags)`.
///
/// Returns all non-constructor methods of the type as a `MethodInfo[]` array.
fn type_get_methods_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut method_elements = Vec::new();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            // Skip constructors — GetMethods() doesn't include them
                            if method.name == wellknown::members::CTOR
                                || method.name == wellknown::members::CCTOR
                            {
                                continue;
                            }
                            match thread.heap_mut().alloc_reflection_method(method.token) {
                                Ok(m_ref) => method_elements.push(EmValue::ObjectRef(m_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, method_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetProperties()` / `Type.GetProperties(BindingFlags)`.
///
/// Returns all properties of the type as a `PropertyInfo[]` array.
fn type_get_properties_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut prop_elements = Vec::new();
                    for (_, prop) in cil_type.properties.iter() {
                        let getter_token = prop
                            .fn_getter
                            .get()
                            .and_then(|mr| mr.upgrade().map(|m| m.token));
                        let setter_token = prop
                            .fn_setter
                            .get()
                            .and_then(|mr| mr.upgrade().map(|m| m.token));
                        match thread.heap_mut().alloc_reflection_property(
                            Arc::from(prop.name.as_str()),
                            type_token,
                            getter_token,
                            setter_token,
                        ) {
                            Ok(p_ref) => prop_elements.push(EmValue::ObjectRef(p_ref)),
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, prop_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetConstructors()` / `Type.GetConstructors(BindingFlags)`.
///
/// Returns all constructors of the type as a `ConstructorInfo[]` array.
fn type_get_constructors_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut ctor_elements = Vec::new();
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            if method.name == ".ctor" {
                                match thread.heap_mut().alloc_reflection_method(method.token) {
                                    Ok(m_ref) => ctor_elements.push(EmValue::ObjectRef(m_ref)),
                                    Err(e) => {
                                        return PreHookResult::Error(format!(
                                            "heap allocation failed: {e}"
                                        ))
                                    }
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, ctor_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetInterfaces()`.
///
/// Returns all interfaces implemented by the type as a `Type[]` array.
fn type_get_interfaces_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut iface_elements = Vec::new();
                    for (_, iface_entry) in cil_type.interfaces.iter() {
                        if let Some(iface_type) = iface_entry.interface.upgrade() {
                            match thread
                                .heap_mut()
                                .alloc_reflection_type(iface_type.token, None)
                            {
                                Ok(t_ref) => iface_elements.push(EmValue::ObjectRef(t_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, iface_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetNestedTypes()`.
///
/// Returns all nested types of the type as a `Type[]` array.
fn type_get_nested_types_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut nested_elements = Vec::new();
                    for (_, nested_ref) in cil_type.nested_types.iter() {
                        if let Some(nested_type) = nested_ref.upgrade() {
                            match thread
                                .heap_mut()
                                .alloc_reflection_type(nested_type.token, None)
                            {
                                Ok(t_ref) => nested_elements.push(EmValue::ObjectRef(t_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, nested_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetMembers()` -- returns combined fields + methods + properties.
///
/// Returns all members (fields and methods) of the type as a `MemberInfo[]` array.
fn type_get_members_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut member_elements = Vec::new();

                    // Add fields
                    for (_, field) in cil_type.fields.iter() {
                        match thread.heap_mut().alloc_reflection_field(
                            field.token,
                            type_token,
                            field.flags.is_static(),
                        ) {
                            Ok(fi_ref) => member_elements.push(EmValue::ObjectRef(fi_ref)),
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }

                    // Add methods
                    for (_, method_weak) in cil_type.methods.iter() {
                        if let Some(method) = method_weak.upgrade() {
                            match thread.heap_mut().alloc_reflection_method(method.token) {
                                Ok(m_ref) => member_elements.push(EmValue::ObjectRef(m_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }

                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, member_elements)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.get_FullName`.
///
/// Returns the fully qualified name of the type (namespace + name).
fn type_get_full_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let full_name = if cil_type.namespace.is_empty() {
                        cil_type.name.to_string()
                    } else {
                        format!("{}.{}", cil_type.namespace, cil_type.name)
                    };
                    match thread.heap_mut().alloc_string(&full_name) {
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

/// Hook for `Type.get_Name`.
///
/// Returns the simple name of the type (without namespace).
fn type_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    match thread.heap_mut().alloc_string(&cil_type.name) {
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

/// Hook for `Type.get_Namespace`.
///
/// Returns the namespace of the type.
fn type_get_namespace_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    match thread.heap_mut().alloc_string(&cil_type.namespace) {
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

/// Hook for `Type.GetEnumValues()`.
///
/// Returns an array of the enum's constant field values.
fn type_get_enum_values_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut values = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        if field.flags.is_literal() && field.flags.is_static() {
                            // Get the constant value if available
                            if let Some(val) = field.default.get() {
                                #[allow(clippy::cast_possible_wrap)]
                                let em_val = match &val.data {
                                    CilPrimitiveData::I4(v) => EmValue::I32(*v),
                                    CilPrimitiveData::I8(v) => EmValue::I64(*v),
                                    CilPrimitiveData::U4(v) => EmValue::I32(*v as i32),
                                    CilPrimitiveData::I2(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::U2(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::I1(v) => EmValue::I32(i32::from(*v)),
                                    CilPrimitiveData::U1(v) => EmValue::I32(i32::from(*v)),
                                    _ => EmValue::I32(0),
                                };
                                values.push(em_val);
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::I4, values)
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
    match thread.heap_mut().alloc_array(CilFlavor::I4, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetEnumNames()`.
///
/// Returns an array of the names of the enum's constant fields.
fn type_get_enum_names_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    let mut names = Vec::new();
                    for (_, field) in cil_type.fields.iter() {
                        if field.flags.is_literal() && field.flags.is_static() {
                            match thread.heap_mut().alloc_string(&field.name) {
                                Ok(s_ref) => names.push(EmValue::ObjectRef(s_ref)),
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                    match thread
                        .heap_mut()
                        .alloc_array_with_values(CilFlavor::Object, names)
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
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Type.GetEnumUnderlyingType()`.
///
/// Returns the underlying integral type of an enum. Throws `ArgumentException`
/// if the type is not an enum (matching .NET behavior).
fn type_get_enum_underlying_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.this {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    if !cil_type.is_enum() {
                        return PreHookResult::throw_argument_exception(
                            "Type provided must be an Enum",
                        );
                    }
                    // The underlying type is the single non-static, non-literal instance field
                    for (_, field) in cil_type.fields.iter() {
                        if !field.flags.is_static() && !field.flags.is_literal() {
                            let underlying_token = TypeResolver::new(asm.types())
                                .resolve(&field.signature.base)
                                .map(|t| t.token)
                                .unwrap_or_else(|_| CilPrimitiveKind::I4.token());
                            match thread
                                .heap_mut()
                                .alloc_reflection_type(underlying_token, None)
                            {
                                Ok(tr) => {
                                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(tr)))
                                }
                                Err(e) => {
                                    return PreHookResult::Error(format!(
                                        "heap allocation failed: {e}"
                                    ))
                                }
                            }
                        }
                    }
                    // Fallback: Int32 is the most common underlying type
                    match thread
                        .heap_mut()
                        .alloc_reflection_type(CilPrimitiveKind::I4.token(), None)
                    {
                        Ok(tr) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(tr))),
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
            }
        }
    }
    PreHookResult::throw_argument_exception("Type provided must be an Enum")
}

/// Hook for `Type.IsAssignableFrom(Type)`.
///
/// Checks whether an instance of the specified type can be assigned to the current type.
/// Walks the inheritance chain and checks interface implementations.
fn type_is_assignable_from_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(this_token) = try_hook!(thread.heap().get_reflection_type_token(*this_ref)) {
            if let Some(EmValue::ObjectRef(other_ref)) = ctx.args.first() {
                if let Some(other_token) =
                    try_hook!(thread.heap().get_reflection_type_token(*other_ref))
                {
                    // Same type
                    if this_token == other_token {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }
                    // Walk inheritance chain of 'other' looking for 'this'.
                    // `base_chain` bounds the walk: a hostile assembly can describe a cyclic
                    // `extends` graph, on which a hand-rolled token loop never terminates.
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(other_type) = asm.types().resolve(&other_token) {
                            if other_type
                                .base_chain()
                                .any(|ancestor| ancestor.token == this_token)
                            {
                                return PreHookResult::Bypass(Some(EmValue::I32(1)));
                            }
                        }
                        // Check interfaces
                        if let Some(other_type) = asm.types().resolve(&other_token) {
                            for (_, iface_entry) in other_type.interfaces.iter() {
                                if let Some(iface) = iface_entry.interface.upgrade() {
                                    if iface.token == this_token {
                                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.IsSubclassOf(Type)`.
///
/// Checks whether the current type derives from the specified type by walking
/// the inheritance chain.
fn type_is_subclass_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Some(this_token) = try_hook!(thread.heap().get_reflection_type_token(*this_ref)) {
            if let Some(EmValue::ObjectRef(other_ref)) = ctx.args.first() {
                if let Some(other_token) =
                    try_hook!(thread.heap().get_reflection_type_token(*other_ref))
                {
                    if let Some(asm) = thread.assembly().cloned() {
                        // Walk inheritance chain of 'this' looking for 'other'.
                        // `base_chain` bounds the walk against cyclic `extends` graphs.
                        if let Some(this_type) = asm.types().resolve(&this_token) {
                            if this_type
                                .base_chain()
                                .any(|ancestor| ancestor.token == other_token)
                            {
                                return PreHookResult::Bypass(Some(EmValue::I32(1)));
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Type.GetCustomAttributes`.
///
/// Reads custom attributes from the type's metadata and returns an array of
/// stub objects, one per attribute. When a filter type argument is provided
/// (`GetCustomAttributes(Type, bool)`), only matching attributes are returned.
fn type_get_custom_attributes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let type_token = ctx.this.and_then(|t| extract_type_token(thread, t));

    let filter_token = ctx
        .args
        .iter()
        .find_map(|arg| extract_type_token(thread, arg));

    if let (Some(type_token), Some(asm)) = (type_token, thread.assembly().cloned()) {
        if let Some(cil_type) = asm.types().resolve(&type_token) {
            let attrs = &cil_type.custom_attributes;
            let mut elements = Vec::new();

            for (_, attr_rc) in attrs.iter() {
                // If a filter type was specified, check if this attribute matches
                if let Some(filter) = filter_token {
                    if let Some(ctor_declaring) =
                        resolve_attribute_type_token(&asm, &attr_rc.constructor)
                    {
                        if ctor_declaring != filter {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Allocate a stub object representing the attribute instance
                let attr_type = match resolve_attribute_type_token(&asm, &attr_rc.constructor) {
                    Some(t) => t,
                    None => continue, // Skip attributes whose type can't be resolved
                };
                match thread.heap_mut().alloc_object(attr_type) {
                    Ok(obj_ref) => elements.push(EmValue::ObjectRef(obj_ref)),
                    Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            }

            match thread
                .heap_mut()
                .alloc_array_with_values(CilFlavor::Object, elements)
            {
                Ok(arr_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)));
                }
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

/// Hook for `Attribute.IsDefined(MemberInfo, Type)`.
///
/// Checks whether a custom attribute of the specified type is applied to a
/// member (type, method, field, etc.). This is a static method.
fn attribute_is_defined_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // First arg: element (MemberInfo/Type), second arg: attributeType (Type)
    let element_token = ctx
        .args
        .first()
        .and_then(|arg| extract_type_token(thread, arg));
    let attr_type_token = ctx
        .args
        .get(1)
        .and_then(|arg| extract_type_token(thread, arg));

    if let (Some(element), Some(attr_type), Some(asm)) =
        (element_token, attr_type_token, thread.assembly().cloned())
    {
        if let Some(cil_type) = asm.types().resolve(&element) {
            for (_, attr_rc) in cil_type.custom_attributes.iter() {
                if let Some(ctor_type) = resolve_attribute_type_token(&asm, &attr_rc.constructor) {
                    if ctor_type == attr_type {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }
                }
            }
        }
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `MemberInfo.IsDefined(Type, bool)` and `Type.IsDefined(Type, bool)`.
///
/// Instance method version that checks the `this` object for custom attributes
/// matching the specified type.
fn member_is_defined_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let this_token = ctx.this.and_then(|t| extract_type_token(thread, t));
    let attr_type_token = ctx
        .args
        .first()
        .and_then(|arg| extract_type_token(thread, arg));

    if let (Some(this_type), Some(attr_type), Some(asm)) =
        (this_token, attr_type_token, thread.assembly().cloned())
    {
        if let Some(cil_type) = asm.types().resolve(&this_type) {
            for (_, attr_rc) in cil_type.custom_attributes.iter() {
                if let Some(ctor_type) = resolve_attribute_type_token(&asm, &attr_rc.constructor) {
                    if ctor_type == attr_type {
                        return PreHookResult::Bypass(Some(EmValue::I32(1)));
                    }
                }
            }
        }
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Activator.CreateInstance(Type)` and `Activator.CreateInstance(Type, object[])`.
///
/// Creates an instance of the specified type. When an `object[]` argument is present,
/// finds a constructor with matching parameter count and dispatches via `ReflectionInvoke`.
fn activator_create_instance_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Find the Type argument (first arg that's a ReflectionType)
    let type_token = ctx.args.iter().find_map(|arg| {
        if let EmValue::ObjectRef(href) = arg {
            thread
                .heap()
                .get_reflection_type_token(*href)
                .unwrap_or_default()
        } else {
            None
        }
    });

    if let Some(type_token) = type_token {
        // Allocate the object
        match thread.heap_mut().alloc_object(type_token) {
            Ok(obj_ref) => {
                // Find a matching constructor
                if let Some(asm) = thread.assembly().cloned() {
                    // Extract args from object[] parameter if present.
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

                    let expected_params = ctor_args.len();
                    if let Some(cil_type) = asm.types().resolve(&type_token) {
                        // Find matching .ctor
                        for (_, method_weak) in cil_type.methods.iter() {
                            if let Some(method) = method_weak.upgrade() {
                                if method.name == ".ctor"
                                    && method.signature.params.len() == expected_params
                                {
                                    return PreHookResult::ReflectionInvoke {
                                        request: Box::new(ReflectionInvokeRequest {
                                            method_token: method.token,
                                            this_ref: Some(EmValue::ObjectRef(obj_ref)),
                                            args: ctor_args,
                                            method_type_args: None,
                                        }),
                                        bypass_value: Some(EmValue::ObjectRef(obj_ref)),
                                    };
                                }
                            }
                        }
                    }
                }
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref)));
            }
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }

    // Fallback: type argument could not be resolved
    PreHookResult::throw_invalid_operation(
        "Activator.CreateInstance: unable to resolve target type",
    )
}

/// Hook for `Delegate.CreateDelegate(Type, MethodInfo)` static method.
///
/// Creates a functional `HeapObject::Delegate` using the method token from the
/// `ReflectionMethod` argument. This enables delegate dispatch to actually invoke
/// the target method.
fn delegate_create_delegate_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Overloads: (Type, MethodInfo) or (Type, Object, MethodInfo)
    let mut method_token = None;
    let mut target = None;
    let mut type_token = None;

    for arg in ctx.args.iter() {
        if let EmValue::ObjectRef(href) = arg {
            if let Ok(obj) = thread.heap().get_shared(*href).as_deref() {
                match obj {
                    HeapObject::ReflectionMethod {
                        method_token: mt, ..
                    } => {
                        method_token = Some(*mt);
                    }
                    HeapObject::ReflectionType { type_token: tt, .. } => {
                        type_token = Some(*tt);
                    }
                    _ => {
                        // Could be the target object for instance delegates
                        target = Some(*href);
                    }
                }
            }
        }
    }

    let Some(type_token) = type_token else {
        warn!("Delegate.CreateDelegate: missing delegate type argument");
        return PreHookResult::throw_argument_null("type");
    };

    if let Some(mt) = method_token {
        match thread.heap_mut().alloc_delegate(type_token, target, mt) {
            Ok(del_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(del_ref))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }

    warn!("Delegate.CreateDelegate: no method argument found");
    PreHookResult::throw_argument_null("method")
}

/// Hook for `Delegate.Combine(Delegate, Delegate)` static method.
///
/// Concatenates the invocation lists of two delegates into a new multicast delegate.
/// Null-safe: `Combine(null, x) = x`, `Combine(x, null) = x`.
fn delegate_combine_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let args = ctx.args;

    // Extract the two delegate arguments
    let (Some(arg0), Some(arg1)) = (args.first(), args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };
    let (a_ref_opt, b_ref_opt) = (arg0.as_object_ref(), arg1.as_object_ref());

    // Null-safe: Combine(null, x) = x, Combine(x, null) = x
    let Some(a_ref) = a_ref_opt else {
        return PreHookResult::Bypass(Some(arg1.clone()));
    };
    let Some(b_ref) = b_ref_opt else {
        return PreHookResult::Bypass(Some(arg0.clone()));
    };

    // Get invocation lists from both delegates
    let (type_token, mut entries) = match thread.heap().get_shared(a_ref).as_deref() {
        Ok(HeapObject::Delegate {
            type_token,
            invocation_list,
        }) => (*type_token, invocation_list.clone()),
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    };

    // Concatenate: a's entries followed by b's entries
    match thread.heap().get_shared(b_ref).as_deref() {
        Ok(HeapObject::Delegate {
            invocation_list, ..
        }) => entries.extend(invocation_list.iter().cloned()),
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    }

    match thread
        .heap_mut()
        .alloc_multicast_delegate(type_token, entries)
    {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("delegate combine allocation failed: {e}")),
    }
}

/// Hook for `Delegate.Remove(Delegate, Delegate)` static method.
///
/// Removes the last occurrence of `value`'s invocation list from `source`.
/// For single-entry removal (most common), removes the last entry matching by method_token.
fn delegate_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let args = ctx.args;

    let (Some(arg0), Some(arg1)) = (args.first(), args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };
    if args.len() != 2 {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let source_ref_opt = arg0.as_object_ref();
    let value_ref_opt = arg1.as_object_ref();

    let Some(source_ref) = source_ref_opt else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };
    let Some(value_ref) = value_ref_opt else {
        return PreHookResult::Bypass(Some(arg0.clone()));
    };

    let (type_token, mut entries) = match thread.heap().get_shared(source_ref).as_deref() {
        Ok(HeapObject::Delegate {
            type_token,
            invocation_list,
        }) => (*type_token, invocation_list.clone()),
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    };

    let remove_token = match thread.heap().get_shared(value_ref).as_deref() {
        Ok(HeapObject::Delegate {
            invocation_list, ..
        }) => {
            if let Some(entry) = invocation_list.last() {
                entry.method_token
            } else {
                return PreHookResult::Bypass(Some(arg0.clone()));
            }
        }
        _ => return PreHookResult::Bypass(Some(arg0.clone())),
    };

    // Remove last matching entry
    if let Some(pos) = entries.iter().rposition(|e| e.method_token == remove_token) {
        entries.remove(pos);
    }

    if entries.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    match thread
        .heap_mut()
        .alloc_multicast_delegate(type_token, entries)
    {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("delegate remove allocation failed: {e}")),
    }
}

/// Hook for `Delegate.get_Method` property.
///
/// Returns a ReflectionMethod for the last entry's method token.
fn delegate_get_method_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(HeapObject::Delegate {
            invocation_list, ..
        }) = thread.heap().get_shared(*href).as_deref()
        {
            if let Some(entry) = invocation_list.last() {
                match thread
                    .heap_mut()
                    .alloc_reflection_method(entry.method_token)
                {
                    Ok(method_ref) => {
                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(method_ref)));
                    }
                    Err(e) => {
                        return PreHookResult::Error(format!(
                            "delegate get_Method allocation failed: {e}"
                        ));
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Delegate.get_Target` property.
///
/// Returns the target object from the last invocation list entry.
fn delegate_get_target_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(HeapObject::Delegate {
            invocation_list, ..
        }) = thread.heap().get_shared(*href).as_deref()
        {
            if let Some(entry) = invocation_list.last() {
                return PreHookResult::Bypass(Some(
                    entry.target.map_or(EmValue::Null, EmValue::ObjectRef),
                ));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Delegate.DynamicInvoke(object[])`.
///
/// Unboxes arguments from the `object[]` array and dispatches to the delegate's
/// target method via `ReflectionInvoke`. For multicast delegates, only the last
/// entry is invoked (matching .NET behavior for DynamicInvoke on the outermost delegate).
fn delegate_dynamic_invoke_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(EmValue::ObjectRef(delegate_ref)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let Ok(delegate) = thread.heap().get_shared(*delegate_ref) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };
    let HeapObject::Delegate {
        invocation_list, ..
    } = &*delegate
    else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let Some(entry) = invocation_list.last() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let method_token = entry.method_token;
    let this_ref = entry.target.map(EmValue::ObjectRef);

    // Extract arguments from the object[] array (first argument to DynamicInvoke)
    let method_args = if let Some(EmValue::ObjectRef(arr_ref)) = ctx.args.first() {
        if let Ok(HeapObject::Array { elements, .. }) =
            thread.heap().get_shared(*arr_ref).as_deref()
        {
            elements.iter().map(|v| unbox_value(thread, v)).collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    PreHookResult::ReflectionInvoke {
        request: Box::new(ReflectionInvokeRequest {
            method_token,
            this_ref,
            args: method_args,
            method_type_args: None,
        }),
        bypass_value: Some(EmValue::Null),
    }
}

/// Hook for `Type.GetInterfaceMap(Type)`.
///
/// Returns a struct-like object representing the interface method mapping.
/// Since the emulator doesn't have a proper `InterfaceMapping` value type, this
/// returns a stub object that satisfies the caller's basic needs. The mapping
/// maps interface methods to their concrete implementations on the runtime type.
fn type_get_interface_map_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let type_token = ctx.this.and_then(|t| extract_type_token(thread, t));
    let interface_token = ctx.args.first().and_then(|a| extract_type_token(thread, a));

    if let (Some(type_token), Some(iface_token), Some(asm)) =
        (type_token, interface_token, thread.assembly().cloned())
    {
        if let (Some(cil_type), Some(iface_type)) = (
            asm.types().resolve(&type_token),
            asm.types().resolve(&iface_token),
        ) {
            // Build arrays of interface methods and their implementations
            let mut iface_methods = Vec::new();
            let mut target_methods = Vec::new();

            for (_, iface_method_ref) in iface_type.methods.iter() {
                let Some(iface_method) = iface_method_ref.upgrade() else {
                    continue;
                };

                // Find the implementation on the concrete type
                let impl_token =
                    find_interface_impl_for_map(&cil_type, iface_method.token, &iface_method)
                        .unwrap_or(iface_method.token);

                // Allocate ReflectionMethod objects for both
                match (
                    thread
                        .heap_mut()
                        .alloc_reflection_method(iface_method.token),
                    thread.heap_mut().alloc_reflection_method(impl_token),
                ) {
                    (Ok(iface_ref), Ok(impl_ref)) => {
                        iface_methods.push(EmValue::ObjectRef(iface_ref));
                        target_methods.push(EmValue::ObjectRef(impl_ref));
                    }
                    _ => continue,
                }
            }

            // Return a stub object with the interface type + method arrays as fields
            // Real .NET returns an InterfaceMapping struct, but hooks consuming this
            // typically just read InterfaceMethods/TargetMethods arrays.
            let iface_type_ref = match thread.heap_mut().alloc_reflection_type(iface_token, None) {
                Ok(r) => r,
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            };
            let iface_arr = match thread
                .heap_mut()
                .alloc_array_with_values(CilFlavor::Object, iface_methods)
            {
                Ok(r) => r,
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            };
            let target_arr = match thread
                .heap_mut()
                .alloc_array_with_values(CilFlavor::Object, target_methods)
            {
                Ok(r) => r,
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            };

            // Pack into a generic object with fields:
            // field 0 = InterfaceType, field 1 = InterfaceMethods, field 2 = TargetMethods
            match thread
                .heap_mut()
                .alloc_object(tokens::reflection::CUSTOM_ATTRIBUTE_DATA)
            {
                Ok(obj_ref) => {
                    try_hook!(thread.heap().set_field(
                        obj_ref,
                        tokens::attribute_fields::INTERFACE_TYPE,
                        EmValue::ObjectRef(iface_type_ref),
                    ));
                    try_hook!(thread.heap().set_field(
                        obj_ref,
                        tokens::attribute_fields::INTERFACE_METHODS,
                        EmValue::ObjectRef(iface_arr),
                    ));
                    try_hook!(thread.heap().set_field(
                        obj_ref,
                        tokens::attribute_fields::TARGET_METHODS,
                        EmValue::ObjectRef(target_arr),
                    ));
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref)));
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }

    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Finds the implementation of an interface method on a concrete type.
/// Used by GetInterfaceMap to map interface methods → concrete implementations.
///
/// Ancestors are visited via [`CilType::base_chain`], which bounds the walk against the cyclic
/// `extends` graphs a hostile assembly can describe.
fn find_interface_impl_for_map(
    type_info: &CilType,
    interface_method: Token,
    base_method: &Method,
) -> Option<Token> {
    if let Some(token) = find_interface_impl_on_type(type_info, interface_method, base_method) {
        return Some(token);
    }
    type_info
        .base_chain()
        .find_map(|ancestor| find_interface_impl_on_type(&ancestor, interface_method, base_method))
}

/// Finds an interface-method implementation declared directly on `type_info`.
fn find_interface_impl_on_type(
    type_info: &CilType,
    interface_method: Token,
    base_method: &Method,
) -> Option<Token> {
    // Step 1: Explicit MethodImpl overrides
    for (_, method_ref) in type_info.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };
        for (_, override_ref) in method.overrides.iter() {
            let override_token = match override_ref {
                CilTypeReference::MethodDef(weak) => weak.upgrade().map(|m| m.token),
                CilTypeReference::MemberRef(rc) => Some(rc.token),
                _ => None,
            };
            if override_token == Some(interface_method) {
                return Some(method.token);
            }
        }
    }

    // Step 2: Implicit name+signature match
    for (_, method_ref) in type_info.methods.iter() {
        let Some(method) = method_ref.upgrade() else {
            continue;
        };
        if method.name == base_method.name
            && !method.is_static()
            && method.signature.param_count == base_method.signature.param_count
        {
            return Some(method.token);
        }
    }

    // Step 3: base types are handled by the caller's `base_chain` walk.
    None
}

/// Hook for `System.Type.GetType(string)` static method.
///
/// Returns a `Type` object for the given type name. For emulation, we try
/// to resolve the name against the assembly's type definitions. If no match
/// is found, returns null (the type is not available in the emulated context).
///
/// # Handled Overloads
///
/// - `Type.GetType(String) -> Type`
/// - `Type.GetType(String, Boolean) -> Type`
/// - `Type.GetType(String, Boolean, Boolean) -> Type`
fn type_get_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_name = ctx
        .args
        .first()
        .and_then(|v| v.as_object_ref())
        .and_then(|r| thread.heap().get_string(r).ok());

    if let Some(name) = type_name {
        // Try to find the type in the assembly's type registry
        if let Some(assembly) = thread.assembly() {
            let types = assembly.types();
            for type_entry in types.iter() {
                let ty = type_entry.value();
                let full_name = if ty.namespace.is_empty() {
                    ty.name.to_string()
                } else {
                    format!("{}.{}", ty.namespace, ty.name)
                };
                if full_name == *name || *ty.name == *name {
                    match thread.heap_mut().alloc_reflection_type(ty.token, None) {
                        Ok(type_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref)))
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    // Type not found — return null (matches .NET behavior when throwOnError=false)
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `AssemblyName.GetPublicKeyToken()`.
///
/// Returns the public key token as a byte array. For emulation, we return
/// an empty byte array since the assembly's strong name is not relevant
/// to deobfuscation.
fn assembly_name_get_public_key_token_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_array(CilFlavor::U1, 0) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

#[cfg(test)]
mod tests {
    use super::{type_get_module_pre, type_get_type_from_handle_pre};
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_get_module_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Type",
            "get_Module",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = type_get_module_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_get_type_from_handle_hook_with_arg() {
        let args = [EmValue::NativeInt(0x0200_0001)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Type",
            "GetTypeFromHandle",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = create_test_thread();
        let result = type_get_type_from_handle_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_get_type_from_handle_hook_no_arg_throws() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Type",
            "GetTypeFromHandle",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = type_get_type_from_handle_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Throw { .. } => {}
            _ => panic!("Expected Throw for missing argument"),
        }
    }
}

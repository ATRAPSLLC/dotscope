//! Shared helper functions for reflection hooks.
//!
//! These helpers are used across multiple reflection submodules (types, methods,
//! members, modules) for common operations like token extraction, type
//! normalization, method resolution, and value boxing/unboxing.

use crate::{
    emulation::{runtime::hook::PreHookResult, thread::EmulationThread, EmValue, HeapObject},
    metadata::{
        method::MethodRc,
        token::Token,
        typesystem::{CilFlavor, CilPrimitiveKind, CilType, CilTypeReference},
    },
    CilObject,
};

/// Extracts a reflection type token from an `EmValue` that may be an `ObjectRef`
/// pointing to a `ReflectionType` on the heap, or `Null`.
pub fn extract_type_token(thread: &EmulationThread, val: &EmValue) -> Option<Token> {
    match val {
        EmValue::ObjectRef(href) => thread
            .heap()
            .get_reflection_type_token(*href)
            .unwrap_or_default(),
        EmValue::Null => None,
        _ => None,
    }
}

/// Normalizes a type token to a canonical form for comparison.
///
/// TypeRef tokens pointing to well-known BCL primitive types (e.g., `System.Int32`)
/// are mapped to their artificial `0xF000_XXXX` primitive tokens. This ensures that
/// `typeof(int)` (which uses a TypeRef from `ldtoken`) compares equal to the token
/// produced by `FieldInfo.get_FieldType` for an `int32` field.
pub fn normalize_type_token(thread: &EmulationThread, token: Token) -> Token {
    // Artificial tokens are already canonical
    if token.value() & 0xFF00_0000 == 0xF000_0000 {
        return token;
    }

    // For TypeRef (0x01) and TypeDef (0x02) tokens, check if they resolve to a
    // well-known BCL primitive type by looking up in the assembly's type registry.
    if matches!(token.table(), 0x01 | 0x02) {
        if let Some(asm) = thread.assembly().cloned() {
            if let Some(cil_type) = asm.types().resolve(&token) {
                if cil_type.namespace == "System" {
                    if let Some(primitive_token) = bcl_name_to_primitive_token(&cil_type.name) {
                        return primitive_token;
                    }
                }
            }
        }
    }

    token
}

/// Maps a BCL type name in the `System` namespace to its artificial primitive token.
pub fn bcl_name_to_primitive_token(name: &str) -> Option<Token> {
    let kind = match name {
        "Boolean" => CilPrimitiveKind::Boolean,
        "Char" => CilPrimitiveKind::Char,
        "SByte" => CilPrimitiveKind::I1,
        "Byte" => CilPrimitiveKind::U1,
        "Int16" => CilPrimitiveKind::I2,
        "UInt16" => CilPrimitiveKind::U2,
        "Int32" => CilPrimitiveKind::I4,
        "UInt32" => CilPrimitiveKind::U4,
        "Int64" => CilPrimitiveKind::I8,
        "UInt64" => CilPrimitiveKind::U8,
        "Single" => CilPrimitiveKind::R4,
        "Double" => CilPrimitiveKind::R8,
        "IntPtr" => CilPrimitiveKind::I,
        "UIntPtr" => CilPrimitiveKind::U,
        "String" => CilPrimitiveKind::String,
        "Object" => CilPrimitiveKind::Object,
        "Void" => CilPrimitiveKind::Void,
        _ => return None,
    };
    Some(kind.token())
}

/// Finds the best-matching method declared directly on `cil_type`.
///
/// If multiple overloads match, prefers the one with fewer parameters
/// (common obfuscator pattern).
fn find_method_on_type(cil_type: &CilType, name: &str) -> Option<Token> {
    let mut best: Option<(Token, usize)> = None;
    for (_, method_weak) in cil_type.methods.iter() {
        if let Some(method) = method_weak.upgrade() {
            if method.name == name {
                let param_count = method.signature.params.len();
                if best.is_none_or(|(_, n)| param_count < n) {
                    best = Some((method.token, param_count));
                }
            }
        }
    }
    best.map(|(token, _)| token)
}

/// Finds a method by name on a type, searching the inheritance chain.
///
/// If multiple overloads match, prefers the one with fewer parameters
/// (common obfuscator pattern). Ancestors are visited via
/// [`CilType::base_chain`](crate::metadata::typesystem::CilType::base_chain), which bounds the
/// walk — a hostile assembly can describe an inheritance cycle, and searching for a name that
/// appears nowhere in it would otherwise recurse until the native stack is exhausted.
pub fn find_method_by_name(asm: &CilObject, type_token: Token, name: &str) -> Option<Token> {
    let cil_type = asm.types().resolve(&type_token)?;
    if let Some(token) = find_method_on_type(&cil_type, name) {
        return Some(token);
    }
    cil_type
        .base_chain()
        .find_map(|ancestor| find_method_on_type(&ancestor, name))
}

/// Resolves a method token (MethodDef, MemberRef, or MethodSpec) to a [`MethodRc`].
///
/// Tries direct MethodDef lookup first, then falls back to the assembly's
/// [`TokenResolver`](crate::metadata::resolver::TokenResolver) for MemberRef -> MethodDef resolution. Returns `None`
/// for external methods that have no local MethodDef (e.g., BCL methods
/// referenced via TypeRef).
pub fn resolve_method_from_token(method_token: Token, asm: &CilObject) -> Option<MethodRc> {
    // Direct MethodDef lookup
    if let Some(method) = asm.methods().get(&method_token).map(|e| e.value().clone()) {
        return Some(method);
    }
    // Resolver: MemberRef/MethodSpec -> MethodDef
    if let Some(resolved) = asm.resolver().resolve_method(method_token) {
        if resolved != method_token {
            return asm.methods().get(&resolved).map(|e| e.value().clone());
        }
    }
    None
}

/// Allocates a `Type[]` and populates it with `ReflectionType` objects for each token.
pub fn alloc_type_array_from_tokens(
    thread: &mut EmulationThread,
    tokens: &[Token],
) -> PreHookResult {
    match thread
        .heap_mut()
        .alloc_array(CilFlavor::Object, tokens.len())
    {
        Ok(arr_ref) => {
            for (i, token) in tokens.iter().enumerate() {
                if let Ok(elem_ref) = thread.heap_mut().alloc_reflection_type(*token, None) {
                    try_hook!(thread.heap().set_array_element(
                        arr_ref,
                        i,
                        EmValue::ObjectRef(elem_ref)
                    ));
                }
            }
            PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref)))
        }
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Unboxes a value if it is a `BoxedValue` on the heap, otherwise returns it as-is.
///
/// In .NET, `FieldInfo.SetValue(obj, value)` passes the value as `object`,
/// so primitives are boxed. This helper extracts the inner value.
pub fn unbox_value(thread: &EmulationThread, value: &EmValue) -> EmValue {
    if let EmValue::ObjectRef(href) = value {
        if let Ok(HeapObject::BoxedValue { value: inner, .. }) =
            thread.heap().get_shared(*href).as_deref()
        {
            return <EmValue as Clone>::clone(&**inner);
        }
    }
    value.clone()
}

/// Boxes a primitive value for return from `FieldInfo.GetValue`.
///
/// If the value is already an `ObjectRef` or `Null`, returns as-is.
/// Otherwise, boxes it so it can be used as an `object` return value.
pub fn box_value_if_needed(thread: &EmulationThread, value: EmValue) -> EmValue {
    match &value {
        EmValue::ObjectRef(_) | EmValue::Null => value,
        EmValue::I32(_) => {
            match thread
                .heap()
                .alloc_boxed(CilPrimitiveKind::I4.token(), value)
            {
                Ok(href) => EmValue::ObjectRef(href),
                Err(_) => EmValue::Null,
            }
        }
        EmValue::I64(_) => {
            match thread
                .heap()
                .alloc_boxed(CilPrimitiveKind::I8.token(), value)
            {
                Ok(href) => EmValue::ObjectRef(href),
                Err(_) => EmValue::Null,
            }
        }
        // For other types, return as-is (the caller may need to handle boxing)
        _ => value,
    }
}

/// Resolves the declaring type token of a custom attribute constructor.
///
/// Given the `CilTypeReference` from a `CustomAttributeValue.constructor`,
/// finds the declaring type by looking up the method's declaring type.
pub fn resolve_attribute_type_token(
    asm: &CilObject,
    constructor: &CilTypeReference,
) -> Option<Token> {
    match constructor {
        CilTypeReference::MethodDef(method_weak) => {
            let method = method_weak.upgrade()?;
            asm.resolver().declaring_type(method.token).map(|t| t.token)
        }
        CilTypeReference::MemberRef(member_rc) => match &member_rc.declaredby {
            CilTypeReference::TypeDef(r) | CilTypeReference::TypeRef(r) => r.token(),
            _ => None,
        },
        _ => None,
    }
}

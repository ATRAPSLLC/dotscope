//! `System.Enum` method hooks.
//!
//! This module provides hook implementations for `Enum` operations commonly
//! used in obfuscated code for flag checking and string conversion.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Enum.HasFlag(Enum)` | Bitwise flag check |
//! | `Enum.ToString()` | Convert to integer string (name lookup not supported) |
//! | `Enum.IsDefined(Type, object)` | Always returns true (conservative) |
//! | `Enum.GetUnderlyingType(Type)` | Returns typeof(int) placeholder |
//!
//! # Limitations
//!
//! Full enum metadata lookup (name↔value mapping) requires walking the type's
//! static literal fields, which is not always available during emulation. The
//! implementation provides best-effort support focused on the numeric operations
//! that obfuscators rely on (HasFlag, bitwise ops).

use log::warn;

use crate::{
    emulation::{
        memory::HeapObject,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::typesystem::{CilPrimitiveData, CilPrimitiveKind, TypeResolver},
    Result,
};

/// Registers all Enum method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Enum.HasFlag")
            .match_name("System", "Enum", "HasFlag")
            .pre(enum_has_flag_pre),
    )?;

    manager.register(
        Hook::new("System.Enum.ToString")
            .match_name("System", "Enum", "ToString")
            .pre(enum_to_string_pre),
    )?;

    manager.register(
        Hook::new("System.Enum.IsDefined")
            .match_name("System", "Enum", "IsDefined")
            .pre(enum_is_defined_pre),
    )?;

    manager.register(
        Hook::new("System.Enum.GetUnderlyingType")
            .match_name("System", "Enum", "GetUnderlyingType")
            .pre(enum_get_underlying_type_pre),
    )?;

    Ok(())
}

/// Extracts the integer value from an enum-like value (boxed or direct).
fn enum_to_i64(value: &EmValue, thread: &EmulationThread) -> Option<i64> {
    match value {
        EmValue::I32(v) => Some(i64::from(*v)),
        EmValue::I64(v) => Some(*v),
        EmValue::NativeInt(v) => Some(*v),
        EmValue::NativeUInt(v) => Some(*v as i64),
        EmValue::ObjectRef(href) => {
            if let Ok(HeapObject::BoxedValue { value, .. }) = thread.heap().get(*href) {
                match *value {
                    EmValue::I32(v) => Some(i64::from(v)),
                    EmValue::I64(v) => Some(v),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Hook for `Enum.HasFlag(Enum flag)`.
///
/// Performs `(this & flag) == flag` on the underlying integer values.
fn enum_has_flag_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if let Some(flag_val) = ctx.args.first() {
            if let (Some(this_i), Some(flag_i)) =
                (enum_to_i64(this_val, thread), enum_to_i64(flag_val, thread))
            {
                let result = (this_i & flag_i) == flag_i;
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(result))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Enum.ToString()`.
///
/// Converts the enum's underlying integer value to a string representation.
/// Full name lookup from metadata is not supported; returns the numeric string.
fn enum_to_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if let Some(int_val) = enum_to_i64(this_val, thread) {
            if let Ok(str_ref) = thread.heap().alloc_string(&int_val.to_string()) {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref)));
            }
        }
    }
    PreHookResult::Continue
}

/// Hook for `Enum.IsDefined(Type, object)`.
///
/// Checks whether the given value matches any of the enum's static literal
/// field constants. Falls back to `true` if the type cannot be resolved.
fn enum_is_defined_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.args.first() {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().resolve(&type_token) {
                    if let Some(check_value) = ctx.args.get(1) {
                        if let Some(check_i64) = enum_to_i64(check_value, thread) {
                            // Check against all static literal fields (enum constants)
                            for (_, field) in cil_type.fields.iter() {
                                if field.flags.is_static() && field.flags.is_literal() {
                                    if let Some(constant) = field.default.get() {
                                        #[allow(clippy::cast_possible_wrap)]
                                        let field_val = match &constant.data {
                                            CilPrimitiveData::I4(v) => Some(i64::from(*v)),
                                            CilPrimitiveData::I8(v) => Some(*v),
                                            CilPrimitiveData::U4(v) => Some(i64::from(*v)),
                                            CilPrimitiveData::U8(v) => Some(*v as i64),
                                            CilPrimitiveData::I2(v) => Some(i64::from(*v)),
                                            CilPrimitiveData::U2(v) => Some(i64::from(*v)),
                                            CilPrimitiveData::I1(v) => Some(i64::from(*v)),
                                            CilPrimitiveData::U1(v) => Some(i64::from(*v)),
                                            _ => None,
                                        };
                                        if field_val == Some(check_i64) {
                                            return PreHookResult::Bypass(Some(EmValue::I32(1)));
                                        }
                                    }
                                }
                            }
                            // No matching constant found
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                }
            }
        }
    }
    // Can't resolve — conservatively return true
    warn!("Enum.IsDefined: cannot resolve enum type, returning true as fallback");
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `Enum.GetUnderlyingType(Type)`.
///
/// Reads the enum's underlying type from its one instance field
/// ([`CilType::enum_underlying`](crate::metadata::typesystem::CilType::enum_underlying)).
/// Falls back to `System.Int32` if metadata is unavailable.
fn enum_get_underlying_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.args.first() {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(underlying) = asm
                    .types()
                    .resolve(&type_token)
                    .and_then(|cil_type| cil_type.enum_underlying().cloned())
                {
                    let underlying_token = TypeResolver::new(asm.types())
                        .resolve(&underlying)
                        .map(|t| t.token)
                        .unwrap_or_else(|_| CilPrimitiveKind::I4.token());
                    return match thread
                        .heap_mut()
                        .alloc_reflection_type(underlying_token, None)
                    {
                        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
                    };
                }
            }
        }
    }
    // Fallback: Int32 (most common underlying type)
    let token = CilPrimitiveKind::I4.token();
    match thread.heap_mut().alloc_reflection_type(token, None) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    fn ctx<'a>(method: &'a str, this: Option<&'a EmValue>, args: &'a [EmValue]) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Enum",
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::system::enums::register(&manager).unwrap();
        assert_eq!(manager.len(), 4);
    }

    #[test]
    fn test_has_flag_true() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(7); // 0b111
        let args = [EmValue::I32(2)]; // 0b010
        let result = enum_has_flag_pre(&ctx("HasFlag", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_has_flag_false() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(4); // 0b100
        let args = [EmValue::I32(2)]; // 0b010
        let result = enum_has_flag_pre(&ctx("HasFlag", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_has_flag_boxed() {
        let mut thread = create_test_thread();
        let boxed_this = thread
            .heap_mut()
            .alloc_boxed(Token::new(0x02000001), EmValue::I32(7))
            .unwrap();
        let boxed_flag = thread
            .heap_mut()
            .alloc_boxed(Token::new(0x02000001), EmValue::I32(4))
            .unwrap();

        let this = EmValue::ObjectRef(boxed_this);
        let args = [EmValue::ObjectRef(boxed_flag)];
        let result = enum_has_flag_pre(&ctx("HasFlag", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_to_string() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(42);
        let result = enum_to_string_pre(&ctx("ToString", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "42");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_to_string_boxed() {
        let mut thread = create_test_thread();
        let boxed = thread
            .heap_mut()
            .alloc_boxed(Token::new(0x02000001), EmValue::I32(99))
            .unwrap();
        let this = EmValue::ObjectRef(boxed);
        let result = enum_to_string_pre(&ctx("ToString", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "99");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_is_defined_fallback() {
        let mut thread = create_test_thread();
        // No assembly context — conservatively returns true
        let result = enum_is_defined_pre(&ctx("IsDefined", None, &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_get_underlying_type_fallback() {
        let mut thread = create_test_thread();
        // No assembly context — returns reflection type for Int32
        let result =
            enum_get_underlying_type_pre(&ctx("GetUnderlyingType", None, &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }
}

//! `System.Nullable<T>` method hooks.
//!
//! This module provides hook implementations for `Nullable<T>` operations.
//! In .NET, `Nullable<T>` is a value type wrapper that allows value types to
//! represent null. Obfuscators use nullable types for control flow state.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `get_HasValue` | Check if nullable has a value |
//! | `get_Value` | Get the value (error if null) |
//! | `GetValueOrDefault()` | Get value or default |
//! | `Nullable.GetUnderlyingType(Type)` | Get underlying type if Nullable, else null |

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all Nullable method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Nullable.get_HasValue")
            .match_name("System", "Nullable`1", "get_HasValue")
            .pre(nullable_has_value_pre),
    )?;

    manager.register(
        Hook::new("System.Nullable.get_Value")
            .match_name("System", "Nullable`1", "get_Value")
            .pre(nullable_get_value_pre),
    )?;

    manager.register(
        Hook::new("System.Nullable.GetValueOrDefault")
            .match_name("System", "Nullable`1", "GetValueOrDefault")
            .pre(nullable_get_value_or_default_pre),
    )?;

    manager.register(
        Hook::new("System.Nullable.GetUnderlyingType")
            .match_name("System", "Nullable", "GetUnderlyingType")
            .pre(nullable_get_underlying_type_pre),
    )?;

    Ok(())
}

/// Hook for `Nullable<T>.get_HasValue`.
///
/// Returns `true` if the nullable value is non-null.
fn nullable_has_value_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        let has_value = !matches!(this_val, EmValue::Null);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(has_value))));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Nullable<T>.get_Value`.
///
/// Returns the value if non-null, otherwise returns an error.
fn nullable_get_value_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if !matches!(this_val, EmValue::Null) {
            return PreHookResult::Bypass(Some(this_val.clone()));
        }
    }
    PreHookResult::throw_invalid_operation("Nullable object must have a value")
}

/// Hook for `Nullable<T>.GetValueOrDefault()`.
///
/// Returns the value if non-null, or the default value for the type.
fn nullable_get_value_or_default_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(this_val) = ctx.this {
        if !matches!(this_val, EmValue::Null) {
            return PreHookResult::Bypass(Some(this_val.clone()));
        }
    }
    // Default value: I32(0) covers most value type defaults
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Nullable.GetUnderlyingType(Type)` (static method).
///
/// Returns `null` if the type is NOT `Nullable<T>`, or the underlying `T` type
/// if it IS. Extracts `T` from the generic instantiation arguments in the type's
/// `generic_args` MethodSpec list.
fn nullable_get_underlying_type_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Extract the type token from the ReflectionType argument
    if let Some(EmValue::ObjectRef(type_ref)) = ctx.args.first() {
        if let Some(type_token) = try_hook!(thread.heap().get_reflection_type_token(*type_ref)) {
            if let Some(asm) = thread.assembly().cloned() {
                if let Some(cil_type) = asm.types().get(&type_token) {
                    // Check if this is Nullable`1 in namespace System
                    if cil_type.name == "Nullable`1" && cil_type.namespace == "System" {
                        // Extract T from generic args
                        for (_, method_spec) in cil_type.generic_args.iter() {
                            for (_, type_arg_ref) in method_spec.generic_args.iter() {
                                let Some(arg_token) = type_arg_ref.token() else {
                                    continue;
                                };
                                match thread.heap_mut().alloc_reflection_type(arg_token, None) {
                                    Ok(href) => {
                                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(
                                            href,
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
                        // Nullable`1 detected but can't extract T — return Null as safe fallback
                        return PreHookResult::Bypass(Some(EmValue::Null));
                    }
                }
            }
        }
    }

    // Not Nullable<T> (or couldn't resolve) — return null
    PreHookResult::Bypass(Some(EmValue::Null))
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
            "Nullable`1",
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::system::nullable::register(&manager).unwrap();
        assert_eq!(manager.len(), 4);
    }

    #[test]
    fn test_has_value_true() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(42);
        let result = nullable_has_value_pre(&ctx("get_HasValue", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_has_value_false() {
        let mut thread = create_test_thread();
        let this = EmValue::Null;
        let result = nullable_has_value_pre(&ctx("get_HasValue", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_get_value_present() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(42);
        let result = nullable_get_value_pre(&ctx("get_Value", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_get_value_null_throws() {
        let mut thread = create_test_thread();
        let this = EmValue::Null;
        let result = nullable_get_value_pre(&ctx("get_Value", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_get_value_or_default_present() {
        let mut thread = create_test_thread();
        let this = EmValue::I32(42);
        let result = nullable_get_value_or_default_pre(
            &ctx("GetValueOrDefault", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_get_value_or_default_null() {
        let mut thread = create_test_thread();
        let this = EmValue::Null;
        let result = nullable_get_value_or_default_pre(
            &ctx("GetValueOrDefault", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_get_underlying_type_fallback() {
        let mut thread = create_test_thread();
        // No assembly context — should return Null
        let result = nullable_get_underlying_type_pre(
            &HookContext::new(
                Token::new(0x0A000001),
                "System",
                "Nullable",
                "GetUnderlyingType",
                PointerSize::Bit64,
            ),
            &mut thread,
        );
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }
}

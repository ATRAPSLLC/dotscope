//! `System.Exception` method hooks for .NET emulation.
//!
//! This module provides hook implementations for `System.Exception` constructors,
//! property getters, and methods commonly encountered during deobfuscation. Exception
//! objects store their state (message, inner exception, HResult, source) in synthetic
//! heap fields that don't collide with real metadata tokens.
//!
//! # Emulated Methods
//!
//! ## Constructors
//!
//! | Constructor | Behavior |
//! |------------|---------|
//! | `Exception..ctor()` | No-op (no message) |
//! | `Exception..ctor(string)` | Store message in synthetic field |
//! | `Exception..ctor(string, Exception)` | Store message + inner exception |
//!
//! ## Property Getters
//!
//! | Property | Behavior |
//! |----------|---------|
//! | `get_Message` | Read message field, fallback to empty string |
//! | `get_InnerException` | Read inner exception field, fallback to Null |
//! | `get_StackTrace` | Return empty string |
//! | `get_Source` | Read source field, fallback to empty string |
//! | `get_HResult` | Read HResult field, fallback to `COR_E_EXCEPTION` |
//! | `get_Data` | Return Null |
//! | `get_HelpLink` | Return Null |
//! | `get_TargetSite` | Return Null |
//!
//! ## Methods
//!
//! | Method | Behavior |
//! |--------|---------|
//! | `ToString` | Format as `"ExceptionType: message"` |
//! | `GetBaseException` | Walk inner exception chain, return deepest |

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens, EmValue,
    },
    Result,
};

/// Default HResult for `System.Exception` (`COR_E_EXCEPTION` = 0x80131500).
const COR_E_EXCEPTION: i32 = -2_146_233_088;

/// Registers all `System.Exception` method hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    register_exception_type(manager, "System", "Exception")?;
    register_exception_type(manager, "System", "SystemException")?;
    register_exception_type(manager, "System", "ApplicationException")?;
    register_exception_type(manager, "System", "InvalidOperationException")?;
    register_exception_type(manager, "System", "ArgumentException")?;
    register_exception_type(manager, "System", "ArgumentNullException")?;
    register_exception_type(manager, "System", "ArgumentOutOfRangeException")?;
    register_exception_type(manager, "System", "FormatException")?;
    register_exception_type(manager, "System", "NotSupportedException")?;
    register_exception_type(manager, "System", "NotImplementedException")?;
    register_exception_type(manager, "System", "AccessViolationException")?;
    register_exception_type(
        manager,
        "System.Security.Cryptography",
        "CryptographicException",
    )?;
    register_exception_type(manager, "System.IO", "InvalidDataException")?;
    register_exception_type(manager, "System", "NullReferenceException")?;
    register_exception_type(manager, "System", "IndexOutOfRangeException")?;
    register_exception_type(manager, "System", "InvalidCastException")?;
    register_exception_type(manager, "System", "OverflowException")?;
    register_exception_type(manager, "System", "OutOfMemoryException")?;
    register_exception_type(manager, "System", "ArithmeticException")?;
    register_exception_type(manager, "System", "TypeInitializationException")?;
    register_exception_type(manager, "System", "ObjectDisposedException")?;
    register_exception_type(manager, "System.IO", "IOException")?;
    register_exception_type(manager, "System.IO", "FileNotFoundException")?;
    register_exception_type(manager, "System.Security", "SecurityException")?;
    register_exception_type(
        manager,
        "System.Security.Cryptography",
        "CryptographicException",
    )?;

    Ok(())
}

/// Registers constructor, property, and method hooks for an exception type.
fn register_exception_type(manager: &HookManager, namespace: &str, type_name: &str) -> Result<()> {
    let prefix = if namespace.is_empty() {
        type_name.to_string()
    } else {
        format!("{namespace}.{type_name}")
    };

    // .ctor (all overloads handled by arg count)
    manager.register(
        Hook::new(format!("{prefix}..ctor"))
            .match_name(namespace, type_name, ".ctor")
            .pre(exception_ctor_pre),
    )?;

    // Property getters — only register for base Exception since MemberRef declaring
    // type for derived types still resolves to "Exception" in metadata.
    if type_name == "Exception" {
        manager.register(
            Hook::new(format!("{prefix}.get_Message"))
                .match_name(namespace, type_name, "get_Message")
                .pre(exception_get_message_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_InnerException"))
                .match_name(namespace, type_name, "get_InnerException")
                .pre(exception_get_inner_exception_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_StackTrace"))
                .match_name(namespace, type_name, "get_StackTrace")
                .pre(exception_get_stack_trace_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_Source"))
                .match_name(namespace, type_name, "get_Source")
                .pre(exception_get_source_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_HResult"))
                .match_name(namespace, type_name, "get_HResult")
                .pre(exception_get_hresult_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_Data"))
                .match_name(namespace, type_name, "get_Data")
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::Null))),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_HelpLink"))
                .match_name(namespace, type_name, "get_HelpLink")
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::Null))),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.get_TargetSite"))
                .match_name(namespace, type_name, "get_TargetSite")
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::Null))),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.ToString"))
                .match_name(namespace, type_name, "ToString")
                .pre(exception_to_string_pre),
        )?;

        manager.register(
            Hook::new(format!("{prefix}.GetBaseException"))
                .match_name(namespace, type_name, "GetBaseException")
                .pre(exception_get_base_exception_pre),
        )?;
    }

    Ok(())
}

/// Hook for `Exception..ctor()`, `Exception..ctor(string)`, `Exception..ctor(string, Exception)`.
///
/// Distinguishes overloads by argument count:
/// - 0 args: no-op
/// - 1 arg: store message
/// - 2 args: store message + inner exception
fn exception_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(obj_ref)) = ctx.this else {
        return PreHookResult::Bypass(None);
    };

    let msg_field = tokens::exception_fields::MESSAGE;
    let inner_field = tokens::exception_fields::INNER_EXCEPTION;

    if let Some(message) = ctx.args.first() {
        try_hook!(thread
            .heap()
            .set_field(*obj_ref, msg_field, message.clone()));
    }

    if let Some(inner) = ctx.args.get(1) {
        try_hook!(thread
            .heap()
            .set_field(*obj_ref, inner_field, inner.clone()));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `Exception.get_Message`.
fn exception_get_message_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        let field = tokens::exception_fields::MESSAGE;
        if let Ok(value) = thread.heap().get_field(*obj_ref, field) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    // Fallback: allocate empty string
    if let Ok(href) = thread.heap().alloc_string("") {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(href)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Exception.get_InnerException`.
fn exception_get_inner_exception_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        let field = tokens::exception_fields::INNER_EXCEPTION;
        if let Ok(value) = thread.heap().get_field(*obj_ref, field) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Exception.get_StackTrace` — returns empty string.
fn exception_get_stack_trace_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Ok(href) = thread.heap().alloc_string("") {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(href)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Exception.get_Source`.
fn exception_get_source_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        let field = tokens::exception_fields::SOURCE;
        if let Ok(value) = thread.heap().get_field(*obj_ref, field) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    if let Ok(href) = thread.heap().alloc_string("") {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(href)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Exception.get_HResult`.
fn exception_get_hresult_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.this {
        let field = tokens::exception_fields::HRESULT;
        if let Ok(value) = thread.heap().get_field(*obj_ref, field) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(COR_E_EXCEPTION)))
}

/// Hook for `Exception.ToString()`.
///
/// Formats as `"ExceptionType: message"` or just the type name if no message.
fn exception_to_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_name = ctx.type_name;
    let message = ctx.this.and_then(|this| {
        if let EmValue::ObjectRef(obj_ref) = this {
            let field = tokens::exception_fields::MESSAGE;
            thread.heap().get_field(*obj_ref, field).ok()
        } else {
            None
        }
    });

    let text = match message {
        Some(EmValue::ObjectRef(href)) => {
            if let Ok(msg) = thread.heap().get_string(href) {
                if msg.is_empty() {
                    type_name.to_string()
                } else {
                    format!("{type_name}: {msg}")
                }
            } else {
                type_name.to_string()
            }
        }
        _ => type_name.to_string(),
    };

    if let Ok(href) = thread.heap().alloc_string(&text) {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(href)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Exception.GetBaseException()`.
///
/// Walks the inner exception chain and returns the deepest non-null exception,
/// or `this` if there is no inner exception.
fn exception_get_base_exception_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(EmValue::ObjectRef(obj_ref)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let inner_field = tokens::exception_fields::INNER_EXCEPTION;
    let mut current = *obj_ref;

    // Walk up to 100 levels to prevent infinite loops
    for _ in 0..100 {
        match thread.heap().get_field(current, inner_field) {
            Ok(EmValue::ObjectRef(inner_ref)) => {
                current = inner_ref;
            }
            _ => break,
        }
    }

    PreHookResult::Bypass(Some(EmValue::ObjectRef(current)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    fn ctx<'a>(
        type_name: &'a str,
        method: &'a str,
        this: Option<&'a EmValue>,
        args: &'a [EmValue],
    ) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System",
            type_name,
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    fn make_exception(
        thread: &mut crate::emulation::thread::EmulationThread,
    ) -> crate::emulation::HeapRef {
        thread
            .heap_mut()
            .alloc_object(Token::new(0x7F01_0001))
            .unwrap()
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        super::register(&manager).unwrap();
        assert!(
            manager.len() >= 31,
            "Expected at least 31 hooks, got {}",
            manager.len()
        );
    }

    #[test]
    fn test_exception_ctor_no_args() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        let result = exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_exception_ctor_with_message() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        let msg = thread.heap_mut().alloc_string("test error").unwrap();

        let args = [EmValue::ObjectRef(msg)];
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &args), &mut thread);

        let result = exception_get_message_pre(
            &ctx("Exception", "get_Message", Some(&this), &[]),
            &mut thread,
        );
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "test error");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_ctor_with_message_and_inner() {
        let mut thread = create_test_thread();
        let outer = make_exception(&mut thread);
        let inner = make_exception(&mut thread);
        let outer_this = EmValue::ObjectRef(outer);
        let inner_this = EmValue::ObjectRef(inner);

        let msg = thread.heap_mut().alloc_string("outer").unwrap();
        let args = [EmValue::ObjectRef(msg), inner_this.clone()];
        exception_ctor_pre(
            &ctx("Exception", ".ctor", Some(&outer_this), &args),
            &mut thread,
        );

        let result = exception_get_inner_exception_pre(
            &ctx("Exception", "get_InnerException", Some(&outer_this), &[]),
            &mut thread,
        );
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) if r == inner));
    }

    #[test]
    fn test_exception_get_message_default() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result = exception_get_message_pre(
            &ctx("Exception", "get_Message", Some(&this), &[]),
            &mut thread,
        );
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_get_inner_exception_null() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result = exception_get_inner_exception_pre(
            &ctx("Exception", "get_InnerException", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }

    #[test]
    fn test_exception_get_stack_trace() {
        let mut thread = create_test_thread();
        let result = exception_get_stack_trace_pre(
            &ctx("Exception", "get_StackTrace", None, &[]),
            &mut thread,
        );
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_get_hresult_default() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result = exception_get_hresult_pre(
            &ctx("Exception", "get_HResult", Some(&this), &[]),
            &mut thread,
        );
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::I32(v))) if v == COR_E_EXCEPTION)
        );
    }

    #[test]
    fn test_exception_get_source_default() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result = exception_get_source_pre(
            &ctx("Exception", "get_Source", Some(&this), &[]),
            &mut thread,
        );
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_to_string_with_message() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        let msg = thread.heap_mut().alloc_string("bad thing").unwrap();

        let args = [EmValue::ObjectRef(msg)];
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &args), &mut thread);

        let result =
            exception_to_string_pre(&ctx("Exception", "ToString", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(
                &*thread.heap().get_string(r).unwrap(),
                "Exception: bad thing"
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_to_string_no_message() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result =
            exception_to_string_pre(&ctx("Exception", "ToString", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Exception");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_exception_get_base_exception_no_inner() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        exception_ctor_pre(&ctx("Exception", ".ctor", Some(&this), &[]), &mut thread);

        let result = exception_get_base_exception_pre(
            &ctx("Exception", "GetBaseException", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) if r == obj));
    }

    #[test]
    fn test_exception_get_base_exception_chain() {
        let mut thread = create_test_thread();
        let deepest = make_exception(&mut thread);
        let middle = make_exception(&mut thread);
        let outer = make_exception(&mut thread);

        // Build chain: outer -> middle -> deepest
        let deepest_val = EmValue::ObjectRef(deepest);
        let middle_val = EmValue::ObjectRef(middle);
        let outer_val = EmValue::ObjectRef(outer);

        let msg = thread.heap_mut().alloc_string("d").unwrap();
        let args = [EmValue::ObjectRef(msg)];
        exception_ctor_pre(
            &ctx("Exception", ".ctor", Some(&deepest_val), &args),
            &mut thread,
        );

        let msg = thread.heap_mut().alloc_string("m").unwrap();
        let args = [EmValue::ObjectRef(msg), deepest_val.clone()];
        exception_ctor_pre(
            &ctx("Exception", ".ctor", Some(&middle_val), &args),
            &mut thread,
        );

        let msg = thread.heap_mut().alloc_string("o").unwrap();
        let args = [EmValue::ObjectRef(msg), middle_val.clone()];
        exception_ctor_pre(
            &ctx("Exception", ".ctor", Some(&outer_val), &args),
            &mut thread,
        );

        let result = exception_get_base_exception_pre(
            &ctx("Exception", "GetBaseException", Some(&outer_val), &[]),
            &mut thread,
        );
        assert!(
            matches!(result, PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) if r == deepest)
        );
    }

    #[test]
    fn test_derived_exception_ctor() {
        let mut thread = create_test_thread();
        let obj = make_exception(&mut thread);
        let this = EmValue::ObjectRef(obj);
        let msg = thread.heap_mut().alloc_string("param is null").unwrap();

        let args = [EmValue::ObjectRef(msg)];
        exception_ctor_pre(
            &ctx("ArgumentNullException", ".ctor", Some(&this), &args),
            &mut thread,
        );

        // Can still read message via base Exception getter
        let result = exception_get_message_pre(
            &ctx("Exception", "get_Message", Some(&this), &[]),
            &mut thread,
        );
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "param is null");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }
}

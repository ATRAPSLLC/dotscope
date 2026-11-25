//! `System.Span<T>` and `System.Memory<T>` method hooks.
//!
//! Provides minimal stub implementations for modern .NET span/memory types
//! that obfuscated code or their targets may reference. Since the emulator
//! does not support `ref struct` semantics natively, Span is represented as
//! a thin wrapper around the underlying array reference.
//!
//! # Emulated Methods
//!
//! ## `Span<T>`
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Span<T>..ctor(T[])` | Store the array reference |
//! | `Span<T>.get_Length` | Return array length |
//! | `Span<T>.get_Item(int)` | Return array element |
//! | `Span<T>.ToArray()` | Return a copy of the underlying array |
//! | `Span<T>.get_Empty` | Return an empty span stub |
//!
//! ## `ReadOnlySpan<T>`
//!
//! | Method | Description |
//! |--------|-------------|
//! | `ReadOnlySpan<T>..ctor(T[])` | Store the array reference |
//! | `ReadOnlySpan<T>.get_Length` | Return array length |
//! | `ReadOnlySpan<T>.get_Item(int)` | Return array element |
//! | `ReadOnlySpan<T>.ToArray()` | Return a copy of the underlying array |
//! | `ReadOnlySpan<T>.get_Empty` | Return an empty span stub |
//!
//! ## `Memory<T>`
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Memory<T>..ctor(T[])` | Store the array reference |
//! | `Memory<T>.get_Span` | Return the stored array as a span stub |
//! | `Memory<T>.get_Length` | Return array length |

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::{token::Token, typesystem::CilFlavor},
    Result,
};

/// Registers all Span/Memory hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    // Span<T>
    manager.register(
        Hook::new("System.Span`1..ctor")
            .match_name("System", "Span`1", ".ctor")
            .pre(span_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Span`1.get_Length")
            .match_name("System", "Span`1", "get_Length")
            .pre(span_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.Span`1.get_Item")
            .match_name("System", "Span`1", "get_Item")
            .pre(span_get_item_pre),
    )?;

    manager.register(
        Hook::new("System.Span`1.ToArray")
            .match_name("System", "Span`1", "ToArray")
            .pre(span_to_array_pre),
    )?;

    manager.register(
        Hook::new("System.Span`1.get_Empty")
            .match_name("System", "Span`1", "get_Empty")
            .pre(span_get_empty_pre),
    )?;

    // ReadOnlySpan<T>
    manager.register(
        Hook::new("System.ReadOnlySpan`1..ctor")
            .match_name("System", "ReadOnlySpan`1", ".ctor")
            .pre(span_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlySpan`1.get_Length")
            .match_name("System", "ReadOnlySpan`1", "get_Length")
            .pre(span_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlySpan`1.get_Item")
            .match_name("System", "ReadOnlySpan`1", "get_Item")
            .pre(span_get_item_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlySpan`1.ToArray")
            .match_name("System", "ReadOnlySpan`1", "ToArray")
            .pre(span_to_array_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlySpan`1.get_Empty")
            .match_name("System", "ReadOnlySpan`1", "get_Empty")
            .pre(span_get_empty_pre),
    )?;

    // Memory<T>
    manager.register(
        Hook::new("System.Memory`1..ctor")
            .match_name("System", "Memory`1", ".ctor")
            .pre(memory_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Memory`1.get_Span")
            .match_name("System", "Memory`1", "get_Span")
            .pre(memory_get_span_pre),
    )?;

    manager.register(
        Hook::new("System.Memory`1.get_Length")
            .match_name("System", "Memory`1", "get_Length")
            .pre(memory_get_length_pre),
    )?;

    // Implicit conversion operators: Span<T>(T[]) and ReadOnlySpan<T>(T[])
    manager.register(
        Hook::new("System.Span`1.op_Implicit")
            .match_name("System", "Span`1", "op_Implicit")
            .pre(span_op_implicit_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlySpan`1.op_Implicit")
            .match_name("System", "ReadOnlySpan`1", "op_Implicit")
            .pre(span_op_implicit_pre),
    )?;

    // ReadOnlyMemory<T>
    manager.register(
        Hook::new("System.ReadOnlyMemory`1..ctor")
            .match_name("System", "ReadOnlyMemory`1", ".ctor")
            .pre(memory_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlyMemory`1.get_Span")
            .match_name("System", "ReadOnlyMemory`1", "get_Span")
            .pre(memory_get_span_pre),
    )?;

    manager.register(
        Hook::new("System.ReadOnlyMemory`1.get_Length")
            .match_name("System", "ReadOnlyMemory`1", "get_Length")
            .pre(memory_get_length_pre),
    )?;

    Ok(())
}

/// Extracts the underlying array HeapRef from a span/memory stub object.
fn extract_array_from_wrapper(
    this: Option<&EmValue>,
    field_token: Token,
    thread: &EmulationThread,
) -> Option<EmValue> {
    match this? {
        EmValue::ObjectRef(href) => thread.heap().get_field(*href, field_token).ok(),
        EmValue::Null => None,
        other => Some(other.clone()),
    }
}

/// Hook for `Span<T>..ctor(T[])`.
///
/// Allocates a span wrapper object and stores the array reference in it.
/// For the emulator, a Span is just an indirection to the underlying array.
fn span_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // .ctor is instance: this = the span being constructed, args[0] = array
    // But since Span is a value type (ref struct), `this` may be a ManagedPtr.
    // The simplest approach: if we have an array arg, store it in a wrapper object
    // and write it back through the pointer.

    let array_val = ctx.args.first().cloned().unwrap_or(EmValue::Null);

    // If `this` is a ManagedPtr, write the array directly as the span value.
    // Many callers just use the span's fields — we represent span as the array itself.
    if let Some(EmValue::ManagedPtr(ptr)) = ctx.this {
        // Store the array ref as the span value (the span IS the array in our model)
        try_hook!(thread.store_through_pointer(ptr, array_val));
        return PreHookResult::Bypass(None);
    }

    // If `this` is an ObjectRef (boxed span or object-based construction),
    // store the array in a field.
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        try_hook!(thread
            .heap()
            .set_field(*href, tokens::span_fields::SPAN_ARRAY, array_val));
        return PreHookResult::Bypass(None);
    }

    // Fallback: allocate a wrapper
    if let Ok(span_ref) = thread.heap_mut().alloc_object(tokens::system::SPAN) {
        try_hook!(thread
            .heap()
            .set_field(span_ref, tokens::span_fields::SPAN_ARRAY, array_val));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(span_ref)));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `Span<T>.get_Length`.
///
/// Returns the length of the underlying array.
fn span_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Try to get the array from the wrapper object
    if let Some(EmValue::ObjectRef(array_ref)) =
        extract_array_from_wrapper(ctx.this, tokens::span_fields::SPAN_ARRAY, thread)
    {
        if let Ok(len) = thread.heap().get_array_length(array_ref) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(len as i32)));
        }
    }

    // If `this` is itself an array reference (simplified span model)
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(len) = thread.heap().get_array_length(*href) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(len as i32)));
        }
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Span<T>.get_Item(int)`.
///
/// Returns the element at the given index from the underlying array.
fn span_get_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    #[allow(clippy::cast_sign_loss)]
    let index = match ctx.args.first() {
        Some(EmValue::I32(i)) => *i as usize,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    // Try wrapper object
    if let Some(EmValue::ObjectRef(array_ref)) =
        extract_array_from_wrapper(ctx.this, tokens::span_fields::SPAN_ARRAY, thread)
    {
        if let Ok(val) = thread.heap().get_array_element(array_ref, index) {
            return PreHookResult::Bypass(Some(val));
        }
    }

    // Try direct array
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(val) = thread.heap().get_array_element(*href, index) {
            return PreHookResult::Bypass(Some(val));
        }
    }

    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Span<T>.ToArray()`.
///
/// Returns a copy of the underlying array.
fn span_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Find the source array
    let source_ref = if let Some(EmValue::ObjectRef(array_ref)) =
        extract_array_from_wrapper(ctx.this, tokens::span_fields::SPAN_ARRAY, thread)
    {
        array_ref
    } else if let Some(EmValue::ObjectRef(href)) = ctx.this {
        *href
    } else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Read array length and element type
    let len = match thread.heap().get_array_length(source_ref) {
        Ok(l) => l,
        Err(_) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(source_ref))),
    };

    let elem_type = thread
        .heap()
        .get_array_element_type(source_ref)
        .unwrap_or(CilFlavor::Object);

    // Copy elements
    let mut elements = Vec::with_capacity(len);
    for i in 0..len {
        let val = thread
            .heap()
            .get_array_element(source_ref, i)
            .unwrap_or(EmValue::Null);
        elements.push(val);
    }

    match thread
        .heap_mut()
        .alloc_array_with_values(elem_type, elements)
    {
        Ok(new_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::ObjectRef(source_ref))),
    }
}

/// Hook for `Span<T>.get_Empty` / `ReadOnlySpan<T>.get_Empty`.
///
/// Returns an empty array as the empty span.
fn span_get_empty_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `Span<T>.op_Implicit(T[])` / `ReadOnlySpan<T>.op_Implicit(T[])`.
///
/// Implicit conversion from array to span — allocate a wrapper storing the array.
fn span_op_implicit_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let array_val = ctx.args.first().cloned().unwrap_or(EmValue::Null);

    if let Ok(span_ref) = thread.heap_mut().alloc_object(tokens::system::SPAN) {
        try_hook!(thread
            .heap()
            .set_field(span_ref, tokens::span_fields::SPAN_ARRAY, array_val));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(span_ref)));
    }

    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Memory<T>..ctor(T[])`.
///
/// Stores the array reference in a Memory wrapper object.
fn memory_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let array_val = ctx.args.first().cloned().unwrap_or(EmValue::Null);

    // If `this` is a ManagedPtr (value type construction)
    if let Some(EmValue::ManagedPtr(ptr)) = ctx.this {
        try_hook!(thread.store_through_pointer(ptr, array_val));
        return PreHookResult::Bypass(None);
    }

    // If `this` is an ObjectRef
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        try_hook!(thread
            .heap()
            .set_field(*href, tokens::span_fields::MEMORY_ARRAY, array_val));
        return PreHookResult::Bypass(None);
    }

    // Fallback: allocate wrapper
    if let Ok(mem_ref) = thread.heap_mut().alloc_object(tokens::system::MEMORY) {
        try_hook!(thread
            .heap()
            .set_field(mem_ref, tokens::span_fields::MEMORY_ARRAY, array_val));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(mem_ref)));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `Memory<T>.get_Span`.
///
/// Returns the stored array as a span (which in our model is the array itself,
/// wrapped in a span stub object).
fn memory_get_span_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the array from the Memory wrapper
    if let Some(array_val) =
        extract_array_from_wrapper(ctx.this, tokens::span_fields::MEMORY_ARRAY, thread)
    {
        // Wrap it in a span object
        if let Ok(span_ref) = thread.heap_mut().alloc_object(tokens::system::SPAN) {
            try_hook!(thread.heap().set_field(
                span_ref,
                tokens::span_fields::SPAN_ARRAY,
                array_val
            ));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(span_ref)));
        }
    }

    // Fallback: if this is an ObjectRef that's actually an array, wrap it
    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(span_ref) = thread.heap_mut().alloc_object(tokens::system::SPAN) {
            try_hook!(thread.heap().set_field(
                span_ref,
                tokens::span_fields::SPAN_ARRAY,
                EmValue::ObjectRef(*href),
            ));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(span_ref)));
        }
    }

    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Memory<T>.get_Length`.
///
/// Returns the length of the underlying array.
fn memory_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(array_ref)) =
        extract_array_from_wrapper(ctx.this, tokens::span_fields::MEMORY_ARRAY, thread)
    {
        if let Ok(len) = thread.heap().get_array_length(array_ref) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(len as i32)));
        }
    }

    if let Some(EmValue::ObjectRef(href)) = ctx.this {
        if let Ok(len) = thread.heap().get_array_length(*href) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(len as i32)));
        }
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::{runtime::hook::HookManager, EmValue},
        metadata::{
            token::Token,
            typesystem::{CilFlavor, PointerSize},
        },
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

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 18);
    }

    #[test]
    fn test_span_op_implicit_and_length() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();
        let args = [EmValue::ObjectRef(arr)];

        // op_Implicit creates a span wrapper
        let result = span_op_implicit_pre(&ctx("Span`1", "op_Implicit", None, &args), &mut thread);
        let span_val = match result {
            PreHookResult::Bypass(Some(v)) => v,
            _ => panic!("Expected Bypass with value"),
        };

        // get_Length returns the array length
        let result = span_get_length_pre(
            &ctx("Span`1", "get_Length", Some(&span_val), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_span_get_item() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 1, EmValue::I32(42))
            .unwrap();

        // Wrap in span
        let args = [EmValue::ObjectRef(arr)];
        let result = span_op_implicit_pre(&ctx("Span`1", "op_Implicit", None, &args), &mut thread);
        let span_val = match result {
            PreHookResult::Bypass(Some(v)) => v,
            _ => panic!("Expected Bypass with value"),
        };

        // get_Item(1) should return 42
        let idx_args = [EmValue::I32(1)];
        let result = span_get_item_pre(
            &ctx("Span`1", "get_Item", Some(&span_val), &idx_args),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_span_get_empty() {
        let mut thread = create_test_thread();
        let result = span_get_empty_pre(&ctx("Span`1", "get_Empty", None, &[]), &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(href))) => {
                assert_eq!(thread.heap().get_array_length(href).unwrap(), 0);
            }
            _ => panic!("Expected Bypass with ObjectRef"),
        }
    }

    #[test]
    fn test_memory_roundtrip() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::U1, 10).unwrap();

        // Allocate a Memory wrapper object
        let mem_ref = thread
            .heap_mut()
            .alloc_object(tokens::system::MEMORY)
            .unwrap();
        thread
            .heap()
            .set_field(
                mem_ref,
                tokens::span_fields::MEMORY_ARRAY,
                EmValue::ObjectRef(arr),
            )
            .unwrap();

        let mem_val = EmValue::ObjectRef(mem_ref);

        // get_Length
        let result = memory_get_length_pre(
            &ctx("Memory`1", "get_Length", Some(&mem_val), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(10)))
        ));

        // get_Span should return a span wrapper
        let result = memory_get_span_pre(
            &ctx("Memory`1", "get_Span", Some(&mem_val), &[]),
            &mut thread,
        );
        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_))) => {}
            _ => panic!("Expected Bypass with ObjectRef for span"),
        }
    }
}

//! `System.Collections.Generic` Stack, Queue, and HashSet method hooks.
//!
//! This module provides hook implementations for `Stack<T>`, `Queue<T>`, and
//! `HashSet<T>` operations used by obfuscator initialization routines.
//!
//! # Emulated Types
//!
//! ## Stack&lt;T&gt; (LIFO)
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty stack |
//! | `Push(T)` | Push element |
//! | `Pop()` | Pop element |
//! | `Peek()` | Peek at top |
//! | `get_Count` | Get element count |
//! | `Contains(T)` | Check if element exists |
//! | `Clear()` | Remove all elements |
//! | `ToArray()` | Convert to array (LIFO order) |
//!
//! ## Queue&lt;T&gt; (FIFO)
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty queue |
//! | `Enqueue(T)` | Add to back |
//! | `Dequeue()` | Remove from front |
//! | `Peek()` | Peek at front |
//! | `get_Count` | Get element count |
//! | `Contains(T)` | Check if element exists |
//! | `Clear()` | Remove all elements |
//! | `ToArray()` | Convert to array (FIFO order) |
//!
//! ## HashSet&lt;T&gt;
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty set |
//! | `Add(T)` | Add element (returns bool) |
//! | `Remove(T)` | Remove element (returns bool) |
//! | `Contains(T)` | Check membership |
//! | `get_Count` | Get element count |
//! | `Clear()` | Remove all elements |
//! | `UnionWith(IEnumerable)` | Add all from collection |

use log::warn;

use crate::{
    emulation::{
        memory::{DictionaryKey, HeapObject},
        runtime::{
            bcl::io::stream::stream_dispose_pre,
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all Stack, Queue, HashSet, and common interface hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    register_stack(manager)?;
    register_queue(manager)?;
    register_hashset(manager)?;
    register_interfaces(manager)?;
    Ok(())
}

fn register_interfaces(manager: &HookManager) -> Result<()> {
    // IDisposable.Dispose(), which the compiler emits for `foreach` enumerators and `using`
    // blocks (callvirt System.IDisposable::Dispose()). Emulated objects hold nothing to
    // release, but a CryptoStream disposed this way flushes its final block, as the runtime's
    // does, which the stream hook does.
    manager.register(
        Hook::new("System.IDisposable.Dispose")
            .match_name("System", "IDisposable", "Dispose")
            .pre(stream_dispose_pre),
    )?;
    Ok(())
}

fn register_stack(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Collections.Generic.Stack..ctor")
            .match_name("System.Collections.Generic", "Stack`1", ".ctor")
            .pre(stack_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Push")
            .match_name("System.Collections.Generic", "Stack`1", "Push")
            .pre(stack_push_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Pop")
            .match_name("System.Collections.Generic", "Stack`1", "Pop")
            .pre(stack_pop_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Peek")
            .match_name("System.Collections.Generic", "Stack`1", "Peek")
            .pre(stack_peek_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.get_Count")
            .match_name("System.Collections.Generic", "Stack`1", "get_Count")
            .pre(stack_get_count_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Contains")
            .match_name("System.Collections.Generic", "Stack`1", "Contains")
            .pre(stack_contains_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.Clear")
            .match_name("System.Collections.Generic", "Stack`1", "Clear")
            .pre(stack_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Stack.ToArray")
            .match_name("System.Collections.Generic", "Stack`1", "ToArray")
            .pre(stack_to_array_pre),
    )?;

    Ok(())
}

fn stack_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        try_hook!(thread.heap().replace_with_stack(*stack_ref));
    }
    PreHookResult::Bypass(None)
}

fn stack_push_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let value = match ctx.args.first() {
            Some(v) => v.clone(),
            None => {
                warn!("Stack.Push: missing value argument — possible stack misalignment");
                EmValue::Null
            }
        };
        try_hook!(thread.heap().stack_push(*stack_ref, value));
    }
    PreHookResult::Bypass(None)
}

fn stack_pop_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(value) = try_hook!(thread.heap().stack_pop(*stack_ref)) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::throw_invalid_operation("Stack empty")
}

fn stack_peek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(value) = try_hook!(thread.heap().stack_peek(*stack_ref)) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::throw_invalid_operation("Stack empty")
}

fn stack_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let count = try_hook!(thread.heap().stack_count(*stack_ref));
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn stack_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let obj = try_hook!(thread.heap().get_shared(*stack_ref));
            if let HeapObject::Stack { elements } = &*obj {
                let found = elements.iter().any(|e| e.clr_equals(needle));
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn stack_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        try_hook!(thread.heap().stack_clear(*stack_ref));
    }
    PreHookResult::Bypass(None)
}

fn stack_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(stack_ref)) = ctx.this {
        let elements = try_hook!(thread.heap().stack_to_vec(*stack_ref));
        let array_ref = try_hook!(thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, elements));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

fn register_queue(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Collections.Generic.Queue..ctor")
            .match_name("System.Collections.Generic", "Queue`1", ".ctor")
            .pre(queue_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Enqueue")
            .match_name("System.Collections.Generic", "Queue`1", "Enqueue")
            .pre(queue_enqueue_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Dequeue")
            .match_name("System.Collections.Generic", "Queue`1", "Dequeue")
            .pre(queue_dequeue_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Peek")
            .match_name("System.Collections.Generic", "Queue`1", "Peek")
            .pre(queue_peek_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.get_Count")
            .match_name("System.Collections.Generic", "Queue`1", "get_Count")
            .pre(queue_get_count_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Contains")
            .match_name("System.Collections.Generic", "Queue`1", "Contains")
            .pre(queue_contains_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.Clear")
            .match_name("System.Collections.Generic", "Queue`1", "Clear")
            .pre(queue_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Queue.ToArray")
            .match_name("System.Collections.Generic", "Queue`1", "ToArray")
            .pre(queue_to_array_pre),
    )?;

    Ok(())
}

fn queue_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        try_hook!(thread.heap().replace_with_queue(*queue_ref));
    }
    PreHookResult::Bypass(None)
}

fn queue_enqueue_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let value = match ctx.args.first() {
            Some(v) => v.clone(),
            None => {
                warn!("Queue.Enqueue: missing value argument — possible stack misalignment");
                EmValue::Null
            }
        };
        try_hook!(thread.heap().queue_enqueue(*queue_ref, value));
    }
    PreHookResult::Bypass(None)
}

fn queue_dequeue_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(value) = try_hook!(thread.heap().queue_dequeue(*queue_ref)) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::throw_invalid_operation("Queue empty")
}

fn queue_peek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(value) = try_hook!(thread.heap().queue_peek(*queue_ref)) {
            return PreHookResult::Bypass(Some(value));
        }
    }
    PreHookResult::throw_invalid_operation("Queue empty")
}

fn queue_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let count = try_hook!(thread.heap().queue_count(*queue_ref));
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn queue_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let obj = try_hook!(thread.heap().get_shared(*queue_ref));
            if let HeapObject::Queue { elements } = &*obj {
                let found = elements.iter().any(|e| e.clr_equals(needle));
                return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn queue_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        try_hook!(thread.heap().queue_clear(*queue_ref));
    }
    PreHookResult::Bypass(None)
}

fn queue_to_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(queue_ref)) = ctx.this {
        let elements = try_hook!(thread.heap().queue_to_vec(*queue_ref));
        let array_ref = try_hook!(thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, elements));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

fn register_hashset(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Collections.Generic.HashSet..ctor")
            .match_name("System.Collections.Generic", "HashSet`1", ".ctor")
            .pre(hashset_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Add")
            .match_name("System.Collections.Generic", "HashSet`1", "Add")
            .pre(hashset_add_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Remove")
            .match_name("System.Collections.Generic", "HashSet`1", "Remove")
            .pre(hashset_remove_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Contains")
            .match_name("System.Collections.Generic", "HashSet`1", "Contains")
            .pre(hashset_contains_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.get_Count")
            .match_name("System.Collections.Generic", "HashSet`1", "get_Count")
            .pre(hashset_get_count_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.Clear")
            .match_name("System.Collections.Generic", "HashSet`1", "Clear")
            .pre(hashset_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.HashSet.UnionWith")
            .match_name("System.Collections.Generic", "HashSet`1", "UnionWith")
            .pre(hashset_union_with_pre),
    )?;

    Ok(())
}

fn hashset_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        try_hook!(thread.heap().replace_with_hashset(*set_ref));
    }
    PreHookResult::Bypass(None)
}

fn hashset_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let added = try_hook!(thread.heap().hashset_add(*set_ref, key));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(added))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let removed = try_hook!(thread.heap().hashset_remove(*set_ref, &key));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(removed))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let found = try_hook!(thread.heap().hashset_contains(*set_ref, &key));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        let count = try_hook!(thread.heap().hashset_count(*set_ref));
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

fn hashset_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        try_hook!(thread.heap().hashset_clear(*set_ref));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `HashSet.UnionWith(IEnumerable<T>)`.
///
/// Supports array and list sources. Other IEnumerable implementations are ignored.
fn hashset_union_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(set_ref)) = ctx.this {
        if let Some(EmValue::ObjectRef(source_ref)) = ctx.args.first() {
            let source = try_hook!(thread.heap().get_shared(*source_ref));
            let elements: Vec<EmValue> = match &*source {
                HeapObject::Array { elements, .. } => elements.to_vec(),
                HeapObject::List { elements } => elements.to_vec(),
                _ => Vec::new(),
            };
            for elem in &elements {
                if let Some(key) = DictionaryKey::from_emvalue(elem, thread.heap()) {
                    try_hook!(thread.heap().hashset_add(*set_ref, key));
                }
            }
        }
    }
    PreHookResult::Bypass(None)
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
            "System.Collections.Generic",
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
        crate::emulation::runtime::bcl::collections::generic::register(&manager).unwrap();
        assert_eq!(manager.len(), 24);
    }

    #[test]
    fn test_stack_ctor() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let result = stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
        // Verify it's now a Stack by pushing
        thread.heap().stack_push(obj, EmValue::I32(1)).unwrap();
        assert_eq!(thread.heap().stack_count(obj).unwrap(), 1);
    }

    #[test]
    fn test_stack_push_pop_lifo() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        // Push 1, 2, 3
        for v in [1, 2, 3] {
            let args = [EmValue::I32(v)];
            stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);
        }

        // Pop should return 3, 2, 1 (LIFO)
        for expected in [3, 2, 1] {
            let result = stack_pop_pre(&ctx("Stack`1", "Pop", Some(&this), &[]), &mut thread);
            assert!(
                matches!(result, PreHookResult::Bypass(Some(EmValue::I32(v))) if v == expected)
            );
        }
    }

    #[test]
    fn test_stack_pop_empty_throws() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let result = stack_pop_pre(&ctx("Stack`1", "Pop", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_stack_peek() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);

        let result = stack_peek_pre(&ctx("Stack`1", "Peek", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
        // Peek should not remove
        assert_eq!(thread.heap().stack_count(obj).unwrap(), 1);
    }

    #[test]
    fn test_stack_peek_empty_throws() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let result = stack_peek_pre(&ctx("Stack`1", "Peek", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_stack_get_count() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let result =
            stack_get_count_pre(&ctx("Stack`1", "get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));

        let args = [EmValue::I32(1)];
        stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);
        let result =
            stack_get_count_pre(&ctx("Stack`1", "get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_stack_contains_found() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);

        let search = [EmValue::I32(42)];
        let result = stack_contains_pre(
            &ctx("Stack`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_stack_contains_not_found() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);

        let search = [EmValue::I32(99)];
        let result = stack_contains_pre(
            &ctx("Stack`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_stack_clear() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(1)];
        stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);
        stack_clear_pre(&ctx("Stack`1", "Clear", Some(&this), &[]), &mut thread);

        assert_eq!(thread.heap().stack_count(obj).unwrap(), 0);
    }

    #[test]
    fn test_stack_to_array_lifo() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stack_ctor_pre(&ctx("Stack`1", ".ctor", Some(&this), &[]), &mut thread);

        for v in [1, 2, 3] {
            let args = [EmValue::I32(v)];
            stack_push_pre(&ctx("Stack`1", "Push", Some(&this), &args), &mut thread);
        }

        let result = stack_to_array_pre(&ctx("Stack`1", "ToArray", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            // Stack.ToArray returns LIFO order (top of stack first)
            let e0 = thread.heap().get_array_element(arr, 0).unwrap();
            let e1 = thread.heap().get_array_element(arr, 1).unwrap();
            let e2 = thread.heap().get_array_element(arr, 2).unwrap();
            assert!(matches!(e0, EmValue::I32(3)));
            assert!(matches!(e1, EmValue::I32(2)));
            assert!(matches!(e2, EmValue::I32(1)));
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_queue_ctor() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let result = queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_queue_enqueue_dequeue_fifo() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        for v in [1, 2, 3] {
            let args = [EmValue::I32(v)];
            queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);
        }

        // Dequeue should return 1, 2, 3 (FIFO)
        for expected in [1, 2, 3] {
            let result =
                queue_dequeue_pre(&ctx("Queue`1", "Dequeue", Some(&this), &[]), &mut thread);
            assert!(
                matches!(result, PreHookResult::Bypass(Some(EmValue::I32(v))) if v == expected)
            );
        }
    }

    #[test]
    fn test_queue_dequeue_empty_throws() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let result = queue_dequeue_pre(&ctx("Queue`1", "Dequeue", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_queue_peek() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(10)];
        queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);

        let result = queue_peek_pre(&ctx("Queue`1", "Peek", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(10)))
        ));
        assert_eq!(thread.heap().queue_count(obj).unwrap(), 1);
    }

    #[test]
    fn test_queue_peek_empty_throws() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let result = queue_peek_pre(&ctx("Queue`1", "Peek", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_queue_get_count() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let result =
            queue_get_count_pre(&ctx("Queue`1", "get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));

        let args = [EmValue::I32(1)];
        queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);
        let result =
            queue_get_count_pre(&ctx("Queue`1", "get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_queue_contains() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);

        let search = [EmValue::I32(42)];
        let result = queue_contains_pre(
            &ctx("Queue`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let search = [EmValue::I32(99)];
        let result = queue_contains_pre(
            &ctx("Queue`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_queue_clear() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(1)];
        queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);
        queue_clear_pre(&ctx("Queue`1", "Clear", Some(&this), &[]), &mut thread);
        assert_eq!(thread.heap().queue_count(obj).unwrap(), 0);
    }

    #[test]
    fn test_queue_to_array_fifo() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        queue_ctor_pre(&ctx("Queue`1", ".ctor", Some(&this), &[]), &mut thread);

        for v in [10, 20, 30] {
            let args = [EmValue::I32(v)];
            queue_enqueue_pre(&ctx("Queue`1", "Enqueue", Some(&this), &args), &mut thread);
        }

        let result = queue_to_array_pre(&ctx("Queue`1", "ToArray", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            assert_eq!(
                thread.heap().get_array_element(arr, 0).unwrap(),
                EmValue::I32(10)
            );
            assert_eq!(
                thread.heap().get_array_element(arr, 1).unwrap(),
                EmValue::I32(20)
            );
            assert_eq!(
                thread.heap().get_array_element(arr, 2).unwrap(),
                EmValue::I32(30)
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_hashset_ctor() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let result = hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_hashset_add_unique_returns_true() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        let result = hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_hashset_add_duplicate_returns_false() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        let result = hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_hashset_remove() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);

        let result =
            hashset_remove_pre(&ctx("HashSet`1", "Remove", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let result =
            hashset_remove_pre(&ctx("HashSet`1", "Remove", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_hashset_contains() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);

        let search = [EmValue::I32(42)];
        let result = hashset_contains_pre(
            &ctx("HashSet`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let search = [EmValue::I32(99)];
        let result = hashset_contains_pre(
            &ctx("HashSet`1", "Contains", Some(&this), &search),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_hashset_get_count() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let result = hashset_get_count_pre(
            &ctx("HashSet`1", "get_Count", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));

        let args = [EmValue::I32(1)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        let result = hashset_get_count_pre(
            &ctx("HashSet`1", "get_Count", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_hashset_count_stays_1_on_duplicate() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(42)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);

        let result = hashset_get_count_pre(
            &ctx("HashSet`1", "get_Count", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_hashset_clear() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let args = [EmValue::I32(1)];
        hashset_add_pre(&ctx("HashSet`1", "Add", Some(&this), &args), &mut thread);
        hashset_clear_pre(&ctx("HashSet`1", "Clear", Some(&this), &[]), &mut thread);

        let result = hashset_get_count_pre(
            &ctx("HashSet`1", "get_Count", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_hashset_union_with_array() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        hashset_ctor_pre(&ctx("HashSet`1", ".ctor", Some(&this), &[]), &mut thread);

        let arr = thread
            .heap_mut()
            .alloc_array_with_values(
                crate::metadata::typesystem::CilFlavor::I4,
                vec![EmValue::I32(1), EmValue::I32(2), EmValue::I32(3)],
            )
            .unwrap();

        let args = [EmValue::ObjectRef(arr)];
        hashset_union_with_pre(
            &ctx("HashSet`1", "UnionWith", Some(&this), &args),
            &mut thread,
        );

        let result = hashset_get_count_pre(
            &ctx("HashSet`1", "get_Count", Some(&this), &[]),
            &mut thread,
        );
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(3)))
        ));
    }
}

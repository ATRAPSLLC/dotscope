//! `System.Collections.Generic.Dictionary` method hooks.
//!
//! This module provides hook implementations for `Dictionary<TKey, TValue>` operations
//! commonly used by obfuscator initialization routines that build lookup tables from
//! encrypted resource data.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Dictionary..ctor()` | Create empty dictionary |
//! | `Dictionary..ctor(int)` | Create dictionary with initial capacity |
//! | `Dictionary.Add(TKey, TValue)` | Add key-value pair |
//! | `Dictionary.ContainsKey(TKey)` | Check if key exists |
//! | `Dictionary.get_Item(TKey)` | Get value by key (indexer) |
//! | `Dictionary.set_Item(TKey, TValue)` | Set value by key (indexer) |
//! | `Dictionary.get_Count` | Get entry count |
//! | `Dictionary.TryGetValue(TKey, out TValue)` | Try to get value, store via out param |
//! | `Dictionary.Remove(TKey)` | Remove entry by key |
//! | `Dictionary.Clear()` | Remove all entries |
//! | `Dictionary.get_Keys` | Get collection of keys |
//! | `Dictionary.get_Values` | Get collection of values |
//! | `Dictionary.ContainsValue(TValue)` | Check if value exists |
//!
//! # Key Types
//!
//! Dictionary keys are stored as [`DictionaryKey`] which supports integers, strings,
//! booleans, chars, and object references. This covers the primary use cases:
//! `Dictionary<int, int>`, `Dictionary<string, object>`, etc.

use log::warn;

use crate::{
    emulation::{
        memory::DictionaryKey,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all Dictionary method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Collections.Generic.Dictionary..ctor")
            .match_name("System.Collections.Generic", "Dictionary`2", ".ctor")
            .pre(dictionary_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Add")
            .match_name("System.Collections.Generic", "Dictionary`2", "Add")
            .pre(dictionary_add_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.ContainsKey")
            .match_name("System.Collections.Generic", "Dictionary`2", "ContainsKey")
            .pre(dictionary_contains_key_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Item")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Item")
            .pre(dictionary_get_item_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.set_Item")
            .match_name("System.Collections.Generic", "Dictionary`2", "set_Item")
            .pre(dictionary_set_item_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Count")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Count")
            .pre(dictionary_get_count_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.TryGetValue")
            .match_name("System.Collections.Generic", "Dictionary`2", "TryGetValue")
            .pre(dictionary_try_get_value_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Remove")
            .match_name("System.Collections.Generic", "Dictionary`2", "Remove")
            .pre(dictionary_remove_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.Clear")
            .match_name("System.Collections.Generic", "Dictionary`2", "Clear")
            .pre(dictionary_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Keys")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Keys")
            .pre(dictionary_get_keys_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.get_Values")
            .match_name("System.Collections.Generic", "Dictionary`2", "get_Values")
            .pre(dictionary_get_values_pre),
    )?;

    manager.register(
        Hook::new("System.Collections.Generic.Dictionary.ContainsValue")
            .match_name(
                "System.Collections.Generic",
                "Dictionary`2",
                "ContainsValue",
            )
            .pre(dictionary_contains_value_pre),
    )?;

    Ok(())
}

/// Hook for `Dictionary..ctor()` and `Dictionary..ctor(int capacity)`.
fn dictionary_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        try_hook!(thread.heap().replace_with_dictionary(*dict_ref));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.Add(TKey, TValue)`.
fn dictionary_add_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let value = match ctx.args.get(1) {
                Some(v) => v.clone(),
                None => {
                    warn!("Dictionary.Add: missing value argument — possible stack misalignment");
                    EmValue::Null
                }
            };
            try_hook!(thread.heap().dictionary_add(*dict_ref, key, value));
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.ContainsKey(TKey)`.
fn dictionary_contains_key_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let found = try_hook!(thread.heap().dictionary_contains_key(*dict_ref, &key));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.get_Item(TKey)` — indexer getter.
fn dictionary_get_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Some(value) = try_hook!(thread.heap().dictionary_get(*dict_ref, &key)) {
                return PreHookResult::Bypass(Some(value));
            }
        }
    }
    PreHookResult::throw_key_not_found()
}

/// Hook for `Dictionary.set_Item(TKey, TValue)` — indexer setter.
fn dictionary_set_item_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let value = match ctx.args.get(1) {
                Some(v) => v.clone(),
                None => {
                    warn!(
                        "Dictionary.set_Item: missing value argument — possible stack misalignment"
                    );
                    EmValue::Null
                }
            };
            try_hook!(thread.heap().dictionary_set(*dict_ref, key, value));
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.get_Count`.
fn dictionary_get_count_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let count = try_hook!(thread.heap().dictionary_count(*dict_ref));
        #[allow(clippy::cast_possible_truncation)]
        return PreHookResult::Bypass(Some(EmValue::I32(count as i32)));
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.TryGetValue(TKey, out TValue)`.
///
/// Stores the found value through the out parameter pointer and returns
/// a boolean indicating whether the key was found.
fn dictionary_try_get_value_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            if let Some(value) = try_hook!(thread.heap().dictionary_get(*dict_ref, &key)) {
                // Store value through the out parameter
                if let Some(ptr) = ctx.args.get(1).and_then(EmValue::as_managed_ptr) {
                    try_hook!(thread.store_through_pointer(ptr, value));
                }
                return PreHookResult::Bypass(Some(EmValue::I32(1)));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.Remove(TKey)`.
fn dictionary_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(key) = ctx
            .args
            .first()
            .and_then(|v| DictionaryKey::from_emvalue(v, thread.heap()))
        {
            let removed = try_hook!(thread.heap().dictionary_remove(*dict_ref, &key));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(removed))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Dictionary.Clear()`.
fn dictionary_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        try_hook!(thread.heap().dictionary_clear(*dict_ref));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `Dictionary.get_Keys`.
///
/// Returns the keys as an array allocated on the heap.
fn dictionary_get_keys_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let keys = try_hook!(thread.heap().dictionary_keys(*dict_ref));
        let values: Vec<EmValue> = keys.iter().map(|k| k.to_emvalue(thread.heap())).collect();
        let array_ref = try_hook!(thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, values));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Dictionary.get_Values`.
///
/// Returns the values as an array allocated on the heap.
fn dictionary_get_values_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        let values = try_hook!(thread.heap().dictionary_values(*dict_ref));
        let array_ref = try_hook!(thread
            .heap()
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, values));
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Dictionary.ContainsValue(TValue)`.
///
/// Linear scan over all values using [`EmValue::clr_equals`].
fn dictionary_contains_value_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(dict_ref)) = ctx.this {
        if let Some(needle) = ctx.args.first() {
            let values = try_hook!(thread.heap().dictionary_values(*dict_ref));
            let found = values.iter().any(|v| v.clr_equals(needle));
            return PreHookResult::Bypass(Some(EmValue::I32(i32::from(found))));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
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
            "System.Collections.Generic",
            "Dictionary`2",
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    fn make_dict(
        thread: &mut crate::emulation::thread::EmulationThread,
    ) -> crate::emulation::HeapRef {
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        dictionary_ctor_pre(&ctx(".ctor", Some(&this), &[]), thread);
        obj
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::collections::dictionary::register(&manager).unwrap();
        assert_eq!(manager.len(), 12);
    }

    #[test]
    fn test_dictionary_ctor() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);
        let result = dictionary_get_count_pre(&ctx("get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_add_and_get_item() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1)];
        let result = dictionary_get_item_pre(&ctx("get_Item", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(100)))
        ));
    }

    #[test]
    fn test_dictionary_contains_key() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1)];
        let result =
            dictionary_contains_key_pre(&ctx("ContainsKey", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let args = [EmValue::I32(99)];
        let result =
            dictionary_contains_key_pre(&ctx("ContainsKey", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_get_item_missing_throws() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1)];
        let result = dictionary_get_item_pre(&ctx("get_Item", Some(&this), &args), &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_dictionary_set_item_new_key() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(5), EmValue::I32(50)];
        dictionary_set_item_pre(&ctx("set_Item", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(5)];
        let result = dictionary_get_item_pre(&ctx("get_Item", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(50)))
        ));
    }

    #[test]
    fn test_dictionary_set_item_overwrite() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1), EmValue::I32(200)];
        dictionary_set_item_pre(&ctx("set_Item", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1)];
        let result = dictionary_get_item_pre(&ctx("get_Item", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(200)))
        ));
    }

    #[test]
    fn test_dictionary_get_count() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(10)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);
        let args = [EmValue::I32(2), EmValue::I32(20)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let result = dictionary_get_count_pre(&ctx("get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(2)))
        ));
    }

    #[test]
    fn test_dictionary_remove() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1)];
        let result = dictionary_remove_pre(&ctx("Remove", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let result = dictionary_remove_pre(&ctx("Remove", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_clear() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(10)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        dictionary_clear_pre(&ctx("Clear", Some(&this), &[]), &mut thread);

        let result = dictionary_get_count_pre(&ctx("get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_get_keys() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(10)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);
        let args = [EmValue::I32(2), EmValue::I32(20)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let result = dictionary_get_keys_pre(&ctx("get_Keys", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            let len = thread.heap().get_array_length(arr).unwrap();
            assert_eq!(len, 2);
        } else {
            panic!("Expected Bypass with ObjectRef array");
        }
    }

    #[test]
    fn test_dictionary_get_values() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(10)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let result = dictionary_get_values_pre(&ctx("get_Values", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            let len = thread.heap().get_array_length(arr).unwrap();
            assert_eq!(len, 1);
        } else {
            panic!("Expected Bypass with ObjectRef array");
        }
    }

    #[test]
    fn test_dictionary_contains_value() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(100)];
        let result =
            dictionary_contains_value_pre(&ctx("ContainsValue", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        let args = [EmValue::I32(999)];
        let result =
            dictionary_contains_value_pre(&ctx("ContainsValue", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_add_string_key_and_retrieve() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let key = thread.heap_mut().alloc_string("hello").unwrap();
        let args = [EmValue::ObjectRef(key), EmValue::I32(42)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        let key2 = thread.heap_mut().alloc_string("hello").unwrap();
        let args = [EmValue::ObjectRef(key2)];
        let result = dictionary_get_item_pre(&ctx("get_Item", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_dictionary_try_get_value_found() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(1), EmValue::I32(100)];
        dictionary_add_pre(&ctx("Add", Some(&this), &args), &mut thread);

        // Without managed pointer, just test the bool return
        let args = [EmValue::I32(1)];
        let result =
            dictionary_try_get_value_pre(&ctx("TryGetValue", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_dictionary_try_get_value_not_found() {
        let mut thread = create_test_thread();
        let obj = make_dict(&mut thread);
        let this = EmValue::ObjectRef(obj);

        let args = [EmValue::I32(99)];
        let result =
            dictionary_try_get_value_pre(&ctx("TryGetValue", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_dictionary_ctor_with_capacity() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let args = [EmValue::I32(100)];
        dictionary_ctor_pre(&ctx(".ctor", Some(&this), &args), &mut thread);

        let result = dictionary_get_count_pre(&ctx("get_Count", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }
}

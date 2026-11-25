//! Base Class Library (BCL) method hooks for .NET emulation.
//!
//! This module provides hook implementations for common .NET Framework Base Class Library
//! methods that cannot be emulated by executing their actual bytecode. These hooks are
//! essential for deobfuscation analysis as many obfuscators rely on string manipulation,
//! encoding, cryptographic operations, and array handling.
//!
//! # Overview
//!
//! When analyzing obfuscated .NET assemblies, the emulator encounters calls to BCL methods
//! that would normally be provided by the .NET runtime. Since we are analyzing statically
//! (without actually running on the CLR), these hooks provide compatible behavior that
//! allows the emulation to continue while capturing relevant information for analysis.
//!
//! # Organization
//!
//! Hooks are organized by their .NET namespace hierarchy:
//!
//! | Module | .NET Namespace | Description |
//! |--------|----------------|-------------|
//! | [`system`] | `System` | Core types: `Array`, `Buffer`, `Convert`, `Enum`, `Environment`, `Exception`, `Math`, `Nullable`, `String`, `Char` |
//! | [`collections`] | `System.Collections.Generic` | `Dictionary`, `List`, `Stack`, `Queue`, `HashSet` |
//! | [`io`] | `System.IO` | `MemoryStream`, `BinaryReader`, `FileStream`, `File`, `Path` |
//! | [`reflection`] | `System.Reflection` | `Type`, `MethodBase`, `FieldInfo`, `PropertyInfo`, `Module`, `Assembly` |
//! | [`crypto`] | `System.Security.Cryptography` | Hash algorithms, symmetric encryption, key derivation |
//! | [`text`] | `System.Text` | `Encoding`, `StringBuilder` |
//! | [`interop`] | `System.Runtime.InteropServices` | `Marshal`, `IntPtr`, `GCHandle` |
//! | [`appdomain`] | `System` | `AppDomain` and `Assembly` loading operations |
//! | [`runtime`] | `System.Runtime.CompilerServices` | `RuntimeHelpers` support methods |
//! | [`threading`] | `System.Threading` | Thread synchronization primitives |
//!
//! # Limitations
//!
//! These hooks provide simplified implementations that may differ from actual .NET behavior:
//!
//! - **Stream operations**: Maintain actual data buffers but simplified position tracking
//! - **Reflection**: Return symbolic objects rather than actual runtime type information
//! - **Cryptographic operations**: Hash functions work correctly, but symmetric encryption
//!   hooks capture keys/IVs for analysis rather than performing actual encryption
//! - **Assembly loading**: Captures assembly bytes but returns fake `Assembly` objects
//! - **File I/O**: Sandboxed to an in-memory virtual filesystem
//!
//! # Usage
//!
//! Register all BCL hooks with a [`HookManager`] to enable method interception during
//! emulation:
//!
//! The `examples::register_example` test in this module runs this example.
//!
//! # Deobfuscation Support
//!
//! These hooks are specifically designed to support deobfuscation of protected .NET
//! assemblies. Common obfuscation techniques that these hooks help defeat include:
//!
//! - **String encryption**: `Encoding.GetString`, `Convert.FromBase64String`
//! - **Resource encryption**: `Assembly.GetManifestResourceStream`, cryptographic transforms
//! - **Dynamic loading**: `Assembly.Load(byte[])` captures unpacked assemblies
//! - **Control flow flattening**: Math operations for state variable manipulation
//! - **Anti-tamper**: `Marshal.GetHINSTANCE`, `RuntimeHelpers.InitializeArray`
//!
//! [`HookManager`]: crate::emulation::runtime::HookManager

mod appdomain;
mod collections;
mod crypto;
mod interop;
mod io;
mod limits;
mod reflection;
mod runtime;
mod statics;
mod system;
mod text;
mod threading;

pub use statics::get_bcl_static_field;

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all BCL method hooks with the given hook manager.
///
/// This is the primary entry point for registering BCL method implementations.
/// All method interception is handled through hooks, which can bypass original
/// methods or modify their results. Delegates to each namespace submodule's
/// `register()` function to install the complete set of BCL hooks required
/// for .NET emulation.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Example
///
/// The `examples::register_example` test in this module runs this example.
///
/// [`HookManager`]: crate::emulation::runtime::HookManager
pub fn register(manager: &HookManager) -> Result<()> {
    system::register(manager)?;
    collections::register(manager)?;
    io::register(manager)?;
    reflection::register(manager)?;
    crypto::register(manager)?;
    text::register(manager)?;
    interop::register(manager)?;
    appdomain::register(manager)?;
    runtime::register(manager)?;
    threading::register(manager)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{memory::DictionaryKey, EmValue},
        metadata::{token::Token, typesystem::CilFlavor},
        testkit::emulation::create_test_thread,
    };

    /// List → add elements → verify via get, then verify count.
    #[test]
    fn test_list_to_array_pattern() {
        let thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread.heap().replace_with_list(obj).unwrap();

        thread.heap().list_add(obj, EmValue::I32(10)).unwrap();
        thread.heap().list_add(obj, EmValue::I32(20)).unwrap();
        thread.heap().list_add(obj, EmValue::I32(30)).unwrap();

        assert_eq!(thread.heap().list_count(obj).unwrap(), 3);
        assert_eq!(
            thread.heap().list_get(obj, 0).unwrap(),
            Some(EmValue::I32(10))
        );
        assert_eq!(
            thread.heap().list_get(obj, 1).unwrap(),
            Some(EmValue::I32(20))
        );
        assert_eq!(
            thread.heap().list_get(obj, 2).unwrap(),
            Some(EmValue::I32(30))
        );
    }

    /// Dictionary → add entries → get keys → verify contents.
    #[test]
    fn test_dictionary_keys_values() {
        let thread = create_test_thread();
        let dict = thread.heap_mut().alloc_dictionary().unwrap();

        thread
            .heap()
            .dictionary_add(dict, DictionaryKey::Integer(1), EmValue::I32(100))
            .unwrap();
        thread
            .heap()
            .dictionary_add(dict, DictionaryKey::Integer(2), EmValue::I32(200))
            .unwrap();
        thread
            .heap()
            .dictionary_add(dict, DictionaryKey::Integer(3), EmValue::I32(300))
            .unwrap();

        assert_eq!(thread.heap().dictionary_count(dict).unwrap(), 3);

        let keys = thread.heap().dictionary_keys(dict).unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&DictionaryKey::Integer(1)));
        assert!(keys.contains(&DictionaryKey::Integer(2)));
        assert!(keys.contains(&DictionaryKey::Integer(3)));

        let values = thread.heap().dictionary_values(dict).unwrap();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&EmValue::I32(100)));
        assert!(values.contains(&EmValue::I32(200)));
        assert!(values.contains(&EmValue::I32(300)));
    }

    /// Stack push/pop interleaved — deobfuscator state machine pattern.
    #[test]
    fn test_stack_push_pop_interleaved() {
        let thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread.heap().replace_with_stack(obj).unwrap();

        // Push 3 items
        thread.heap().stack_push(obj, EmValue::I32(1)).unwrap();
        thread.heap().stack_push(obj, EmValue::I32(2)).unwrap();
        thread.heap().stack_push(obj, EmValue::I32(3)).unwrap();
        assert_eq!(thread.heap().stack_count(obj).unwrap(), 3);

        // Pop 2 (LIFO: 3, 2)
        assert_eq!(thread.heap().stack_pop(obj).unwrap(), Some(EmValue::I32(3)));
        assert_eq!(thread.heap().stack_pop(obj).unwrap(), Some(EmValue::I32(2)));

        // Push 2 more
        thread.heap().stack_push(obj, EmValue::I32(4)).unwrap();
        thread.heap().stack_push(obj, EmValue::I32(5)).unwrap();
        assert_eq!(thread.heap().stack_count(obj).unwrap(), 3);

        // Pop all (LIFO: 5, 4, 1)
        assert_eq!(thread.heap().stack_pop(obj).unwrap(), Some(EmValue::I32(5)));
        assert_eq!(thread.heap().stack_pop(obj).unwrap(), Some(EmValue::I32(4)));
        assert_eq!(thread.heap().stack_pop(obj).unwrap(), Some(EmValue::I32(1)));
        assert_eq!(thread.heap().stack_count(obj).unwrap(), 0);
    }

    /// Queue enqueue/dequeue — FIFO order verification.
    #[test]
    fn test_queue_fifo_order() {
        let thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread.heap().replace_with_queue(obj).unwrap();

        thread.heap().queue_enqueue(obj, EmValue::I32(10)).unwrap();
        thread.heap().queue_enqueue(obj, EmValue::I32(20)).unwrap();
        thread.heap().queue_enqueue(obj, EmValue::I32(30)).unwrap();

        assert_eq!(
            thread.heap().queue_dequeue(obj).unwrap(),
            Some(EmValue::I32(10))
        );
        assert_eq!(
            thread.heap().queue_dequeue(obj).unwrap(),
            Some(EmValue::I32(20))
        );
        assert_eq!(
            thread.heap().queue_dequeue(obj).unwrap(),
            Some(EmValue::I32(30))
        );
        assert_eq!(thread.heap().queue_count(obj).unwrap(), 0);
    }

    /// HashSet add/contains/remove cycle.
    #[test]
    fn test_hashset_add_contains_remove() {
        let thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread.heap().replace_with_hashset(obj).unwrap();

        assert!(thread
            .heap()
            .hashset_add(obj, DictionaryKey::Integer(42))
            .unwrap());
        assert!(!thread
            .heap()
            .hashset_add(obj, DictionaryKey::Integer(42))
            .unwrap()); // duplicate
        assert_eq!(thread.heap().hashset_count(obj).unwrap(), 1);

        assert!(thread
            .heap()
            .hashset_contains(obj, &DictionaryKey::Integer(42))
            .unwrap());
        assert!(!thread
            .heap()
            .hashset_contains(obj, &DictionaryKey::Integer(99))
            .unwrap());

        assert!(thread
            .heap()
            .hashset_remove(obj, &DictionaryKey::Integer(42))
            .unwrap());
        assert_eq!(thread.heap().hashset_count(obj).unwrap(), 0);
    }

    /// Array copy between arrays — cross-module array operation.
    #[test]
    fn test_array_copy_and_reverse() {
        let thread = create_test_thread();
        let src = thread.heap_mut().alloc_array(CilFlavor::I4, 4).unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 0, EmValue::I32(1))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 1, EmValue::I32(2))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 2, EmValue::I32(3))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 3, EmValue::I32(4))
            .unwrap();

        // Clone and verify independence
        let dst = thread.heap_mut().alloc_array(CilFlavor::I4, 4).unwrap();
        for i in 0..4 {
            let val = thread.heap().get_array_element(src, i).unwrap();
            thread.heap_mut().set_array_element(dst, i, val).unwrap();
        }

        // Modify source, verify destination unaffected
        thread
            .heap_mut()
            .set_array_element(src, 0, EmValue::I32(99))
            .unwrap();
        assert_eq!(
            thread.heap().get_array_element(dst, 0).unwrap(),
            EmValue::I32(1)
        );
    }

    /// String alloc + byte array alloc — encoding roundtrip simulation.
    #[test]
    fn test_string_to_bytes_roundtrip() {
        let thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let text = thread.heap().get_string(s).unwrap();

        // Simulate Encoding.GetBytes
        let bytes = text.as_bytes();
        let arr = thread.heap_mut().alloc_byte_array(bytes).unwrap();
        let retrieved = thread.heap().get_byte_array(arr).unwrap().unwrap();
        assert_eq!(retrieved, b"Hello World");

        // Simulate Encoding.GetString
        let decoded = String::from_utf8_lossy(&retrieved).into_owned();
        let s2 = thread.heap_mut().alloc_string(&decoded).unwrap();
        assert_eq!(&*thread.heap().get_string(s2).unwrap(), "Hello World");
    }

    /// Dictionary with string keys — common obfuscator pattern.
    #[test]
    fn test_dictionary_string_key_pattern() {
        let thread = create_test_thread();
        let dict = thread.heap_mut().alloc_dictionary().unwrap();

        let key1 = thread.heap_mut().alloc_string("method_a").unwrap();
        let key2 = thread.heap_mut().alloc_string("method_b").unwrap();

        thread
            .heap()
            .dictionary_add(dict, DictionaryKey::ObjectRef(key1), EmValue::I32(1))
            .unwrap();
        thread
            .heap()
            .dictionary_add(dict, DictionaryKey::ObjectRef(key2), EmValue::I32(2))
            .unwrap();

        assert_eq!(
            thread
                .heap()
                .dictionary_get(dict, &DictionaryKey::ObjectRef(key1))
                .unwrap(),
            Some(EmValue::I32(1))
        );
        assert_eq!(
            thread
                .heap()
                .dictionary_get(dict, &DictionaryKey::ObjectRef(key2))
                .unwrap(),
            Some(EmValue::I32(2))
        );
        assert_eq!(thread.heap().dictionary_count(dict).unwrap(), 2);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{emulation::HookManager, Result};

    #[test]
    fn register_example() -> Result<()> {
        let manager = HookManager::new();
        register(&manager)?;
        assert!(!manager.is_empty());

        // Manager now contains hooks for:
        // - System.Array, System.Buffer, System.String, System.Math
        // - System.Convert, System.Enum, System.Nullable<T>
        // - System.Collections.Generic.Dictionary, List, Stack, Queue, HashSet
        // - System.IO.MemoryStream, BinaryReader, FileStream
        // - System.Reflection.Type, MethodBase, FieldInfo, Module, Assembly
        // - System.Security.Cryptography.MD5, SHA*, AES, DES, RSA
        // - System.Text.Encoding, StringBuilder
        // - System.Runtime.InteropServices.Marshal, GCHandle
        // - And more...
        Ok(())
    }
}

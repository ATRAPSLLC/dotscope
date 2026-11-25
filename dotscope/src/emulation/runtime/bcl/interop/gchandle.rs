//! `System.Runtime.InteropServices.GCHandle` method hooks.
//!
//! This module provides hook implementations for `GCHandle` methods used for pinning
//! managed objects in memory for interoperation with native code. In the context of
//! deobfuscation, `GCHandle` is commonly used to get raw pointers to byte arrays
//! for unsafe memory operations.
//!
//! # Overview
//!
//! `GCHandle` provides a way to pin managed objects in memory, preventing the garbage
//! collector from moving them. This is essential for interop scenarios where native
//! code needs a stable pointer to managed data.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `GCHandle.Alloc(object)` | Allocates a handle for an object |
//! | `GCHandle.Alloc(object, GCHandleType)` | Allocates with specific handle type |
//! | `GCHandle.AddrOfPinnedObject()` | Gets the address of the pinned object |
//! | `GCHandle.Free()` | Releases the handle |
//! | `GCHandle.Target` | Gets/sets the target object |
//! | `GCHandle.IsAllocated` | Returns whether the handle is allocated |
//! | `GCHandle.ToIntPtr(GCHandle)` | Converts handle to `IntPtr` |
//! | `GCHandle.FromIntPtr(IntPtr)` | Converts `IntPtr` back to handle |
//!
//! # Deobfuscation Use Cases
//!
//! ## Unsafe Memory Access
//!
//! Obfuscators use `GCHandle` to perform unsafe operations on byte arrays:
//!
//! ```csharp
//! byte[] data = GetEncryptedData();
//! GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
//! IntPtr ptr = handle.AddrOfPinnedObject();
//! // Perform unsafe memory operations...
//! handle.Free();
//! ```
//!
//! ## Anti-Tamper Checks
//!
//! Some anti-tamper routines pin memory to read raw bytes from the assembly image.
//!
//! # Limitations
//!
//! - Handles are symbolic; they wrap the object reference ID as an `i64`
//! - No actual memory pinning occurs
//! - `AddrOfPinnedObject` returns the handle value, not a real memory address

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    Result,
};

/// Registers all `GCHandle` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `GCHandle.Alloc` - Allocate handles
/// - `GCHandle.AddrOfPinnedObject` - Get pinned address
/// - `GCHandle.Free` - Release handle
/// - `GCHandle.Target` - Get/set target object
/// - `GCHandle.IsAllocated` - Check allocation status
/// - `GCHandle.ToIntPtr` / `FromIntPtr` - Handle conversion
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.Alloc")
            .match_name("System.Runtime.InteropServices", "GCHandle", "Alloc")
            .pre(gchandle_alloc_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.AddrOfPinnedObject")
            .match_name(
                "System.Runtime.InteropServices",
                "GCHandle",
                "AddrOfPinnedObject",
            )
            .pre(gchandle_addr_of_pinned_object_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.Free")
            .match_name("System.Runtime.InteropServices", "GCHandle", "Free")
            .pre(gchandle_free_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.get_Target")
            .match_name("System.Runtime.InteropServices", "GCHandle", "get_Target")
            .pre(gchandle_get_target_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.set_Target")
            .match_name("System.Runtime.InteropServices", "GCHandle", "set_Target")
            .pre(gchandle_set_target_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.get_IsAllocated")
            .match_name(
                "System.Runtime.InteropServices",
                "GCHandle",
                "get_IsAllocated",
            )
            .pre(gchandle_is_allocated_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.ToIntPtr")
            .match_name("System.Runtime.InteropServices", "GCHandle", "ToIntPtr")
            .pre(gchandle_to_intptr_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.GCHandle.FromIntPtr")
            .match_name("System.Runtime.InteropServices", "GCHandle", "FromIntPtr")
            .pre(gchandle_from_intptr_pre),
    )?;

    Ok(())
}

/// Hook for `System.Runtime.InteropServices.GCHandle.Alloc` method.
///
/// Allocates a GC handle for the specified object.
///
/// # Handled Overloads
///
/// - `GCHandle.Alloc(Object) -> GCHandle`
/// - `GCHandle.Alloc(Object, GCHandleType) -> GCHandle`
///
/// # Parameters
///
/// - `value`: The object to allocate a handle for
/// - `type`: The type of handle to allocate (optional, ignored)
fn gchandle_alloc_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Return a fake GCHandle (wrap the object reference ID)
    let result = if let Some(obj) = ctx.args.first() {
        match obj {
            #[allow(clippy::cast_possible_wrap)]
            EmValue::ObjectRef(r) => EmValue::NativeInt(r.id() as i64),
            _ => EmValue::NativeInt(0x1000),
        }
    } else {
        EmValue::NativeInt(0x1000)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.InteropServices.GCHandle.AddrOfPinnedObject` method.
///
/// Returns the address of the pinned object.
///
/// # Handled Overloads
///
/// - `GCHandle.AddrOfPinnedObject() -> IntPtr`
fn gchandle_addr_of_pinned_object_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // Return the handle value as a pointer
    let result = if let Some(EmValue::NativeInt(handle)) = ctx.this {
        EmValue::NativeInt(*handle)
    } else {
        EmValue::NativeInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.InteropServices.GCHandle.Free` method.
///
/// Releases the GC handle (no-op in emulation).
///
/// # Handled Overloads
///
/// - `GCHandle.Free() -> void`
fn gchandle_free_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.GCHandle.get_Target` property getter.
///
/// Returns the object referenced by the handle.
///
/// # Handled Overloads
///
/// - `GCHandle.get_Target() -> Object`
fn gchandle_get_target_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // The GCHandle stores the HeapRef ID as a NativeInt
    let result = if let Some(EmValue::NativeInt(heap_id)) = ctx.this {
        if *heap_id > 0 {
            // Reconstruct HeapRef from the stored ID
            #[allow(clippy::cast_sign_loss)]
            let heap_ref = HeapRef::new(*heap_id as u64);
            EmValue::ObjectRef(heap_ref)
        } else {
            EmValue::Null
        }
    } else {
        EmValue::Null
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.InteropServices.GCHandle.set_Target` property setter.
///
/// Sets the object referenced by the handle (no-op in emulation).
///
/// # Handled Overloads
///
/// - `GCHandle.set_Target(Object) -> void`
///
/// # Parameters
///
/// - `value`: The new target object
fn gchandle_set_target_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.GCHandle.get_IsAllocated` property getter.
///
/// Returns whether the handle is allocated (always true in emulation).
///
/// # Handled Overloads
///
/// - `GCHandle.get_IsAllocated() -> Boolean`
fn gchandle_is_allocated_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1))) // true
}

/// Hook for `System.Runtime.InteropServices.GCHandle.ToIntPtr` method.
///
/// Converts a GCHandle to an IntPtr representation.
///
/// # Handled Overloads
///
/// - `GCHandle.ToIntPtr(GCHandle) -> IntPtr`
///
/// # Parameters
///
/// - `value`: The GCHandle to convert
fn gchandle_to_intptr_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(EmValue::NativeInt(handle)) = ctx.args.first() {
        EmValue::NativeInt(*handle)
    } else {
        EmValue::NativeInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.InteropServices.GCHandle.FromIntPtr` method.
///
/// Converts an IntPtr back to a GCHandle.
///
/// # Handled Overloads
///
/// - `GCHandle.FromIntPtr(IntPtr) -> GCHandle`
///
/// # Parameters
///
/// - `value`: The IntPtr to convert
fn gchandle_from_intptr_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(EmValue::NativeInt(ptr)) = ctx.args.first() {
        EmValue::NativeInt(*ptr)
    } else {
        EmValue::NativeInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 8);
    }

    #[test]
    fn test_alloc_hook() {
        let obj_ref = HeapRef::new(42);
        let args = [EmValue::ObjectRef(obj_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "Alloc",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_alloc_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with NativeInt(42)"),
        }
    }

    #[test]
    fn test_addr_of_pinned_object_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "AddrOfPinnedObject",
            PointerSize::Bit64,
        )
        .with_this(Some(&EmValue::NativeInt(0x1000)));

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_addr_of_pinned_object_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 0x1000),
            _ => panic!("Expected Bypass with NativeInt(0x1000)"),
        }
    }

    #[test]
    fn test_get_target_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "get_Target",
            PointerSize::Bit64,
        )
        .with_this(Some(&EmValue::NativeInt(42)));

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_get_target_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => assert_eq!(r.id(), 42),
            _ => panic!("Expected Bypass with ObjectRef(42)"),
        }
    }

    #[test]
    fn test_get_target_null_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "get_Target",
            PointerSize::Bit64,
        )
        .with_this(Some(&EmValue::NativeInt(0)));

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_get_target_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::Null)) => {}
            _ => panic!("Expected Bypass with Null"),
        }
    }

    #[test]
    fn test_free_returns_bypass_none() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "Free",
            PointerSize::Bit64,
        );
        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_free_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_is_allocated_returns_true() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "get_IsAllocated",
            PointerSize::Bit64,
        );
        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = gchandle_is_allocated_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_roundtrip() {
        // Allocate a handle for an object
        let obj_ref = HeapRef::new(123);
        let args = [EmValue::ObjectRef(obj_ref)];
        let alloc_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "Alloc",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let handle = match gchandle_alloc_pre(&alloc_ctx, &mut thread) {
            PreHookResult::Bypass(Some(v)) => v,
            _ => panic!("Expected Bypass"),
        };

        // Get the target back
        let get_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "GCHandle",
            "get_Target",
            PointerSize::Bit64,
        )
        .with_this(Some(&handle));

        let result = gchandle_get_target_pre(&get_ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => assert_eq!(r.id(), 123),
            _ => panic!("Expected Bypass with ObjectRef(123)"),
        }
    }
}

//! `System.Runtime.InteropServices.Marshal` and pointer method hooks.
//!
//! This module provides hook implementations for interop-related methods used in
//! obfuscated .NET assemblies for accessing unmanaged memory, P/Invoke operations,
//! and pointer arithmetic. These are critical for anti-tamper and native code interaction.
//!
//! # Overview
//!
//! The `Marshal` class and pointer types (`IntPtr`, `UIntPtr`) are heavily used by
//! obfuscators to access raw memory, read PE headers, and implement anti-tamper checks.
//!
//! # Emulated .NET Methods
//!
//! ## Marshal Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Marshal.GetHINSTANCE(Module)` | Returns PE image base address |
//! | `Marshal.Copy(IntPtr, byte[], int, int)` | Copies from unmanaged to managed |
//! | `Marshal.ReadByte(IntPtr)` | Reads a byte from unmanaged memory |
//! | `Marshal.ReadInt32(IntPtr)` | Reads a 32-bit integer |
//! | `Marshal.WriteByte(IntPtr, byte)` | Writes a byte to unmanaged memory |
//! | `Marshal.WriteInt32(IntPtr, int)` | Writes a 32-bit integer |
//!
//! ## IntPtr Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `IntPtr.op_Explicit` | Type conversion operators |
//! | `IntPtr.Add(IntPtr, int)` | Pointer arithmetic |
//! | `IntPtr.ToInt32()` | Convert to 32-bit integer |
//! | `IntPtr.ToInt64()` | Convert to 64-bit integer |
//!
//! ## UIntPtr Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `UIntPtr.op_Explicit` | Type conversion operators |
//!
//! # Deobfuscation Use Cases
//!
//! ## Anti-Tamper Checks
//!
//! Many obfuscators read the PE image to verify checksums or locate encrypted code:
//!
//! ```csharp
//! Module mod = typeof(MyClass).Module;
//! IntPtr imageBase = Marshal.GetHINSTANCE(mod);  // <-- Returns PE image base
//! byte[] header = new byte[4096];
//! Marshal.Copy(imageBase, header, 0, 4096);  // <-- Reads PE header
//! ```
//!
//! ## ConfuserEx Anti-Tamper
//!
//! ConfuserEx uses `GetHINSTANCE` to locate the PE sections containing encrypted
//! method bodies. The hook returns the actual image base from the PE file.
//!
//! # Address Space
//!
//! These hooks interact with the [`AddressSpace`] to simulate unmanaged memory.
//! The PE image is mapped into the address space, allowing reads of actual PE data.
//!
//! [`AddressSpace`]: crate::emulation::memory::AddressSpace

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::{
            bcl::limits::{checked_len, MAX_HOOK_BUFFER},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        tokens,
        value::{ManagedPointer, PointerTarget},
        EmValue, EmulationError, HeapObject,
    },
    metadata::token::Token,
    Error, Result,
};

/// Extracts a memory address from a hook argument.
///
/// Handles both direct pointer values (`NativeInt`, `UnmanagedPtr`) and boxed
/// IntPtr values (`ObjectRef` wrapping a `BoxedValue` containing a `NativeInt`).
/// .NET Reactor's body patcher passes IntPtr through generic wrappers that box
/// the value — this helper ensures the address is recovered regardless.
fn resolve_address(arg: &EmValue, thread: &EmulationThread) -> Option<u64> {
    match arg {
        EmValue::UnmanagedPtr(a) => Some(*a),
        EmValue::NativeInt(a) => Some(a.cast_unsigned()),
        EmValue::NativeUInt(a) => Some(*a),
        EmValue::I32(a) => Some(a.cast_unsigned() as u64),
        EmValue::ObjectRef(href) => {
            // Unbox: ObjectRef → BoxedValue or Object with IntPtr field
            match thread.heap().get_shared(*href).as_deref() {
                Ok(HeapObject::BoxedValue { value, .. }) => match value.as_ref() {
                    EmValue::NativeInt(a) => Some(a.cast_unsigned()),
                    EmValue::NativeUInt(a) => Some(*a),
                    EmValue::I32(a) => Some(a.cast_unsigned() as u64),
                    EmValue::I64(a) => Some(a.cast_unsigned()),
                    _ => None,
                },
                Ok(HeapObject::Object { fields, .. }) => {
                    // IntPtr stored via intptr_ctor_pre with synthetic field
                    let intptr_field = Token::new(0x04FF_FF01);
                    fields.get(&intptr_field).and_then(|v| match v {
                        EmValue::NativeInt(a) => Some(a.cast_unsigned()),
                        EmValue::NativeUInt(a) => Some(*a),
                        EmValue::I32(a) => Some(a.cast_unsigned() as u64),
                        EmValue::I64(a) => Some(a.cast_unsigned()),
                        _ => None,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolves a `ManagedPointer` to an i64 value.
///
/// Reads the value that the pointer points to (local variable, argument, or field)
/// and converts it to i64. Used by IntPtr hooks when the `this` argument is a
/// `ldloca`-produced managed pointer instead of a direct value.
fn resolve_managed_ptr_as_i64(ptr: &ManagedPointer, thread: &EmulationThread) -> Option<i64> {
    let value = match &ptr.target {
        PointerTarget::Local(idx) => thread.get_local(*idx as usize).ok().cloned(),
        PointerTarget::StaticField(token) => {
            thread.address_space().statics().get(*token).ok().flatten()
        }
        _ => None,
    }?;
    match value {
        EmValue::NativeInt(n) => Some(n),
        EmValue::NativeUInt(n) => Some(n.cast_signed()),
        EmValue::I32(n) => Some(i64::from(n)),
        EmValue::I64(n) => Some(n),
        _ => None,
    }
}

/// Registers all interop method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `Marshal.GetHINSTANCE`, `Marshal.Copy`, `Marshal.ReadByte/Int32`, `Marshal.WriteByte/Int32`
/// - `IntPtr.op_Explicit`, `IntPtr.Add`, `IntPtr.ToInt32/64`
/// - `UIntPtr.op_Explicit`
pub fn register(manager: &HookManager) -> Result<()> {
    // Marshal methods
    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.GetHINSTANCE")
            .match_name("System.Runtime.InteropServices", "Marshal", "GetHINSTANCE")
            .pre(marshal_get_hinstance_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.Copy")
            .match_name("System.Runtime.InteropServices", "Marshal", "Copy")
            .pre(marshal_copy_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadByte")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadByte")
            .pre(marshal_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadInt32")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadInt32")
            .pre(marshal_read_int32_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteByte")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteByte")
            .pre(marshal_write_byte_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteInt32")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteInt32")
            .pre(marshal_write_int32_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadInt64")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadInt64")
            .pre(marshal_read_int64_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadInt16")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadInt16")
            .pre(marshal_read_int16_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadIntPtr")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadIntPtr")
            .pre(marshal_read_intptr_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteInt64")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteInt64")
            .pre(marshal_write_int64_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteInt16")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteInt16")
            .pre(marshal_write_int16_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteIntPtr")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteIntPtr")
            .pre(marshal_write_intptr_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.AllocCoTaskMem")
            .match_name(
                "System.Runtime.InteropServices",
                "Marshal",
                "AllocCoTaskMem",
            )
            .pre(marshal_alloc_cotaskmem_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.FreeCoTaskMem")
            .match_name("System.Runtime.InteropServices", "Marshal", "FreeCoTaskMem")
            .pre(marshal_free_cotaskmem_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.AllocHGlobal")
            .match_name("System.Runtime.InteropServices", "Marshal", "AllocHGlobal")
            .pre(marshal_alloc_hglobal_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.FreeHGlobal")
            .match_name("System.Runtime.InteropServices", "Marshal", "FreeHGlobal")
            .pre(marshal_free_hglobal_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.SizeOf")
            .match_name("System.Runtime.InteropServices", "Marshal", "SizeOf")
            .pre(marshal_sizeof_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer")
            .match_name(
                "System.Runtime.InteropServices",
                "Marshal",
                "GetDelegateForFunctionPointer",
            )
            .pre(marshal_get_delegate_for_function_pointer_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate")
            .match_name(
                "System.Runtime.InteropServices",
                "Marshal",
                "GetFunctionPointerForDelegate",
            )
            .pre(marshal_get_function_pointer_for_delegate_pre),
    )?;

    // IntPtr methods
    manager.register(
        Hook::new("System.IntPtr..ctor")
            .match_name("System", "IntPtr", ".ctor")
            .pre(intptr_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.get_Size")
            .match_name("System", "IntPtr", "get_Size")
            .pre(intptr_get_size_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.op_Explicit")
            .match_name("System", "IntPtr", "op_Explicit")
            .pre(intptr_op_explicit_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.Add")
            .match_name("System", "IntPtr", "Add")
            .pre(intptr_add_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.ToInt32")
            .match_name("System", "IntPtr", "ToInt32")
            .pre(intptr_to_int32_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.ToInt64")
            .match_name("System", "IntPtr", "ToInt64")
            .pre(intptr_to_int64_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.op_Equality")
            .match_name("System", "IntPtr", "op_Equality")
            .pre(intptr_op_equality_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.op_Inequality")
            .match_name("System", "IntPtr", "op_Inequality")
            .pre(intptr_op_inequality_pre),
    )?;

    manager.register(
        Hook::new("System.IntPtr.get_Zero")
            .match_name("System", "IntPtr", "get_Zero")
            .pre(intptr_get_zero_pre),
    )?;

    // UIntPtr methods
    manager.register(
        Hook::new("System.UIntPtr.op_Explicit")
            .match_name("System", "UIntPtr", "op_Explicit")
            .pre(uintptr_op_explicit_pre),
    )?;

    Ok(())
}

/// Size of the window materialised for a write to an unmapped address.
const AUTO_ALLOC_SIZE: usize = 0x1_0000; // 64KB

/// Writes bytes to a possibly-unmapped address, auto-allocating if needed.
///
/// Some obfuscated code writes to addresses that don't exist in emulation (e.g. CLR method
/// table addresses). Rather than aborting emulation, a window is materialised at the target
/// and the write proceeds.
///
/// The address is attacker-chosen and this is reached from ordinary CIL, so the allocation is
/// charged against the unmanaged memory budget. Past it the write is refused: a wild pointer
/// then faults, as it would on a real process, instead of quietly becoming valid memory —
/// which is both the containment property and what stops the analyst's picture of the
/// program's memory from including regions the program never legitimately had.
///
/// # Errors
///
/// Returns the address space's own error when the window cannot be mapped — the unmanaged
/// budget is exhausted, or the range collides with an existing mapping — or when the write
/// itself fails.
fn write_with_auto_alloc(thread: &EmulationThread, addr: u64, data: &[u8]) -> Result<()> {
    let failure = match thread.address_space().write(addr, data) {
        Ok(()) => return Ok(()),
        Err(failure) => failure,
    };

    // A refusal is not an absence. `AccessViolation` means the page is mapped
    // and rejected the write — a PE section carrying no `IMAGE_SCN_MEM_WRITE`
    // is the common case, and a protection writing decrypted method bodies back
    // into `.text` lands there. Materialising a window would try to map over the
    // image the address already belongs to, fail on the overlap, and report that
    // instead of the permission that actually stopped the write.
    if matches!(
        &failure,
        Error::Emulation(inner) if matches!(**inner, EmulationError::AccessViolation { .. })
    ) {
        return Err(failure);
    }

    let page_base = addr & !0xFFFF;
    log::debug!(
        "Auto-allocating 0x{AUTO_ALLOC_SIZE:X} bytes at 0x{page_base:X} for write to 0x{addr:X}"
    );

    thread
        .address_space()
        .alloc_unmanaged_at(page_base, AUTO_ALLOC_SIZE, "auto-alloc")?;

    thread.address_space().write(addr, data)
}

/// Hook for `System.Runtime.InteropServices.Marshal.GetHINSTANCE` method.
///
/// Returns the PE base address for the module's assembly image.
///
/// # Handled Overloads
///
/// - `Marshal.GetHINSTANCE(Module) -> IntPtr`
///
/// # Parameters
///
/// - `m`: The module whose HINSTANCE is requested
fn marshal_get_hinstance_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Try to get actual image base from the assembly
    let image_base = thread
        .assembly()
        .map_or(tokens::native_addresses::CURRENT_MODULE as u64, |asm| {
            asm.file().imagebase()
        });

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::NativeInt(image_base as i64)))
}

/// Hook for `System.Runtime.InteropServices.Marshal.Copy` method.
///
/// Copies data between managed byte arrays and unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.Copy(IntPtr, Byte[], Int32, Int32) -> void` (unmanaged to managed)
/// - `Marshal.Copy(Byte[], Int32, IntPtr, Int32) -> void` (managed to unmanaged)
/// - `Marshal.Copy(IntPtr, Char[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int16[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int32[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int64[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Single[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Double[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, IntPtr[], Int32, Int32) -> void`
///
/// # Parameters
///
/// - `source`: Source pointer or array
/// - `destination`: Destination array or pointer
/// - `startIndex`: Starting index in the array
/// - `length`: Number of elements to copy
fn marshal_copy_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1), Some(arg2), Some(arg3)) = (
        ctx.args.first(),
        ctx.args.get(1),
        ctx.args.get(2),
        ctx.args.get(3),
    ) else {
        return PreHookResult::Bypass(None);
    };

    // Check first arg type to determine which overload
    let src_addr = match arg0 {
        EmValue::UnmanagedPtr(a) => Some(*a),
        EmValue::NativeInt(a) => Some((*a).cast_unsigned()),
        _ => None,
    };

    if let Some(src_addr) = src_addr {
        // Overload: Copy(IntPtr source, byte[] dest, int startIndex, int length)
        let dst_ref = match arg1 {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        // `cast_unsigned() as usize` turned a negative Int32 into a value near 4 GiB, which
        // then drove both an address-space read and a per-byte loop taking the heap lock.
        // .NET throws ArgumentOutOfRangeException for either argument being negative.
        let start_idx = match arg2 {
            EmValue::I32(v) => match checked_len(*v, MAX_HOOK_BUFFER, "Marshal.Copy", "startIndex")
            {
                Ok(n) => n,
                Err(result) => return result,
            },
            _ => return PreHookResult::Bypass(None),
        };
        let length = match arg3 {
            EmValue::I32(v) => match checked_len(*v, MAX_HOOK_BUFFER, "Marshal.Copy", "length") {
                Ok(n) => n,
                Err(result) => return result,
            },
            _ => return PreHookResult::Bypass(None),
        };

        // Validate the destination window before reading anything, so an overrun is reported
        // as the managed exception rather than discovered part-way through the copy.
        match thread.heap().get_array_length(dst_ref) {
            Ok(dst_len) => {
                if start_idx
                    .checked_add(length)
                    .is_none_or(|end| end > dst_len)
                {
                    return PreHookResult::Throw {
                        exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
                        message: format!(
                            "Marshal.Copy: destination range {start_idx}..+{length} exceeds \
                             array length {dst_len}"
                        ),
                    };
                }
            }
            Err(e) => return PreHookResult::Error(format!("Marshal.Copy: {e}")),
        }

        if let Ok(bytes) = thread.address_space().read(src_addr, length) {
            for (i, &byte) in bytes.iter().enumerate() {
                let Some(idx) = start_idx.checked_add(i) else {
                    return PreHookResult::Bypass(None);
                };
                try_hook!(thread.heap_mut().set_array_element(
                    dst_ref,
                    idx,
                    EmValue::I32(i32::from(byte)),
                ));
            }
        }
        return PreHookResult::Bypass(None);
    }

    // Overload: Copy(byte[] source, int startIndex, IntPtr dest, int length)
    let EmValue::ObjectRef(src_ref) = arg0 else {
        return PreHookResult::Bypass(None);
    };
    let start_idx = match arg1 {
        EmValue::I32(v) => match checked_len(*v, MAX_HOOK_BUFFER, "Marshal.Copy", "startIndex") {
            Ok(n) => n,
            Err(result) => return result,
        },
        _ => return PreHookResult::Bypass(None),
    };
    let dest_addr = match arg2 {
        EmValue::UnmanagedPtr(a) => *a,
        EmValue::NativeInt(a) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(None),
    };
    let length = match arg3 {
        EmValue::I32(v) => match checked_len(*v, MAX_HOOK_BUFFER, "Marshal.Copy", "length") {
            Ok(n) => n,
            Err(result) => return result,
        },
        _ => return PreHookResult::Bypass(None),
    };

    // Validate the source window up front rather than letting per-element read failures
    // degrade into a silent run of zero bytes.
    match thread.heap().get_array_length(*src_ref) {
        Ok(src_len) => {
            if start_idx
                .checked_add(length)
                .is_none_or(|end| end > src_len)
            {
                return PreHookResult::Throw {
                    exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
                    message: format!(
                        "Marshal.Copy: source range {start_idx}..+{length} exceeds array \
                         length {src_len}"
                    ),
                };
            }
        }
        Err(e) => return PreHookResult::Error(format!("Marshal.Copy: {e}")),
    }

    let mut bytes = Vec::with_capacity(length);
    for i in 0..length {
        let Some(idx) = start_idx.checked_add(i) else {
            return PreHookResult::Bypass(None);
        };
        #[allow(clippy::cast_possible_truncation)]
        let byte_val = thread
            .heap()
            .get_array_element(*src_ref, idx)
            .map(|elem| match elem {
                EmValue::I32(v) => v.cast_unsigned() as u8,
                _ => 0,
            })
            .unwrap_or(0);
        bytes.push(byte_val);
    }

    if let Err(e) = write_with_auto_alloc(thread, dest_addr, &bytes) {
        return PreHookResult::throw_access_violation(&e.to_string());
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadByte` method.
///
/// Reads a single byte from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadByte(IntPtr) -> Byte`
/// - `Marshal.ReadByte(IntPtr, Int32) -> Byte`
/// - `Marshal.ReadByte(Object, Int32) -> Byte`
///
/// # Parameters
///
/// - `ptr`: Pointer to read from
/// - `ofs`: Byte offset to add to ptr (optional)
/// - `o`: Object in unmanaged memory to read from (overload 3)
fn marshal_read_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(addr) = ctx.args.first().and_then(|a| resolve_address(a, thread)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if let Ok(bytes) = thread.address_space().read(addr, 1) {
        let byte = bytes.first().copied().unwrap_or(0);
        PreHookResult::Bypass(Some(EmValue::I32(i32::from(byte))))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadInt32` method.
///
/// Reads a 32-bit signed integer from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadInt32(IntPtr) -> Int32`
/// - `Marshal.ReadInt32(IntPtr, Int32) -> Int32`
/// - `Marshal.ReadInt32(Object, Int32) -> Int32`
///
/// # Parameters
///
/// - `ptr`: Pointer to read from
/// - `ofs`: Byte offset to add to ptr (optional)
/// - `o`: Object in unmanaged memory to read from (overload 3)
fn marshal_read_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let addr = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    if let Ok(bytes) = thread.address_space().read(addr, 4) {
        let Some(slice) = bytes.get(0..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };
        let value = i32::from_le_bytes(slice);
        PreHookResult::Bypass(Some(EmValue::I32(value)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteByte` method.
///
/// Writes a single byte to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteByte(IntPtr, Byte) -> void`
/// - `Marshal.WriteByte(IntPtr, Int32, Byte) -> void`
/// - `Marshal.WriteByte(Object, Int32, Byte) -> void`
///
/// # Parameters
///
/// - `ptr`: Pointer to write to
/// - `ofs`: Byte offset to add to ptr (overloads 2-3)
/// - `val`: Byte value to write
/// - `o`: Object in unmanaged memory to write to (overload 3)
fn marshal_write_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let addr = match arg0 {
        EmValue::UnmanagedPtr(a) => *a,
        EmValue::NativeInt(a) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(None),
    };

    #[allow(clippy::cast_possible_truncation)]
    let value = match arg1 {
        EmValue::I32(v) => (*v).cast_unsigned() as u8,
        _ => return PreHookResult::Bypass(None),
    };

    if let Err(e) = write_with_auto_alloc(thread, addr, &[value]) {
        return PreHookResult::throw_access_violation(&e.to_string());
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteInt32` method.
///
/// Writes a 32-bit signed integer to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteInt32(IntPtr, Int32) -> void`
/// - `Marshal.WriteInt32(IntPtr, Int32, Int32) -> void`
/// - `Marshal.WriteInt32(Object, Int32, Int32) -> void`
///
/// # Parameters
///
/// - `ptr`: Pointer to write to
/// - `ofs`: Byte offset to add to ptr (overloads 2-3)
/// - `val`: 32-bit value to write
/// - `o`: Object in unmanaged memory to write to (overload 3)
fn marshal_write_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let Some(addr) = resolve_address(arg0, thread) else {
        return PreHookResult::Bypass(None);
    };

    let value = match arg1 {
        EmValue::I32(v) => *v,
        _ => return PreHookResult::Bypass(None),
    };

    if let Err(e) = write_with_auto_alloc(thread, addr, &value.to_le_bytes()) {
        return PreHookResult::throw_access_violation(&e.to_string());
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadInt64` method.
///
/// Reads a 64-bit signed integer from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadInt64(IntPtr) -> Int64`
/// - `Marshal.ReadInt64(IntPtr, Int32) -> Int64`
fn marshal_read_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(base_addr) = ctx.args.first().and_then(|a| resolve_address(a, thread)) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let offset = ctx
        .args
        .get(1)
        .and_then(EmValue::as_i32)
        .map(i64::from)
        .unwrap_or(0);
    let addr = (base_addr as i64).wrapping_add(offset).cast_unsigned();

    if let Ok(bytes) = thread.address_space().read(addr, 8) {
        let Some(slice) = bytes.get(0..8).and_then(|s| <[u8; 8]>::try_from(s).ok()) else {
            return PreHookResult::Bypass(Some(EmValue::I64(0)));
        };
        let value = i64::from_le_bytes(slice);
        PreHookResult::Bypass(Some(EmValue::I64(value)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I64(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadInt16` method.
///
/// Reads a 16-bit signed integer from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadInt16(IntPtr) -> Int16`
/// - `Marshal.ReadInt16(IntPtr, Int32) -> Int16`
fn marshal_read_int16_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let base_addr = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let offset = ctx
        .args
        .get(1)
        .and_then(EmValue::as_i32)
        .map(i64::from)
        .unwrap_or(0);
    let addr = (base_addr as i64).wrapping_add(offset).cast_unsigned();

    if let Ok(bytes) = thread.address_space().read(addr, 2) {
        let Some(slice) = bytes.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };
        let value = i16::from_le_bytes(slice);
        PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadIntPtr` method.
///
/// Reads a pointer-sized value from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadIntPtr(IntPtr) -> IntPtr`
/// - `Marshal.ReadIntPtr(IntPtr, Int32) -> IntPtr`
fn marshal_read_intptr_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let base_addr = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
    };

    let offset = ctx
        .args
        .get(1)
        .and_then(EmValue::as_i32)
        .map(i64::from)
        .unwrap_or(0);
    let addr = (base_addr as i64).wrapping_add(offset).cast_unsigned();

    let ptr_size = ctx.pointer_size.bytes();
    if let Ok(bytes) = thread.address_space().read(addr, ptr_size) {
        let value = if ptr_size == 8 {
            let Some(slice) = bytes.get(0..8).and_then(|s| <[u8; 8]>::try_from(s).ok()) else {
                return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
            };
            i64::from_le_bytes(slice)
        } else {
            let Some(slice) = bytes.get(0..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
                return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
            };
            i64::from(i32::from_le_bytes(slice))
        };
        PreHookResult::Bypass(Some(EmValue::NativeInt(value)))
    } else {
        PreHookResult::Bypass(Some(EmValue::NativeInt(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteInt64` method.
///
/// Writes a 64-bit signed integer to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteInt64(IntPtr, Int64) -> void`
/// - `Marshal.WriteInt64(IntPtr, Int32, Int64) -> void`
fn marshal_write_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let Some(addr) = resolve_address(arg0, thread) else {
        return PreHookResult::Bypass(None);
    };

    // Two-arg form: WriteInt64(IntPtr, Int64)
    // Three-arg form: WriteInt64(IntPtr, Int32 offset, Int64)
    let (offset, value) = if let Some(arg2) = ctx.args.get(2) {
        let ofs = arg1.as_i32().map(i64::from).unwrap_or(0);
        let val = match arg2 {
            EmValue::I64(v) | EmValue::NativeInt(v) => *v,
            _ => return PreHookResult::Bypass(None),
        };
        (ofs, val)
    } else {
        let val = match arg1 {
            EmValue::I64(v) | EmValue::NativeInt(v) => *v,
            _ => return PreHookResult::Bypass(None),
        };
        (0, val)
    };

    let final_addr = (addr as i64).wrapping_add(offset).cast_unsigned();
    if let Err(e) = write_with_auto_alloc(thread, final_addr, &value.to_le_bytes()) {
        return PreHookResult::throw_access_violation(&e.to_string());
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteInt16` method.
///
/// Writes a 16-bit signed integer to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteInt16(IntPtr, Int16) -> void`
/// - `Marshal.WriteInt16(IntPtr, Int32, Int16) -> void`
fn marshal_write_int16_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let Some(addr) = resolve_address(arg0, thread) else {
        return PreHookResult::Bypass(None);
    };

    // 3-arg overload: WriteInt16(IntPtr ptr, Int32 offset, Int16 value)
    // 2-arg overload: WriteInt16(IntPtr ptr, Int16 value)
    let (offset, value_arg) = if let Some(arg2) = ctx.args.get(2) {
        let off = match arg1 {
            EmValue::I32(v) => i64::from(*v),
            _ => 0,
        };
        (off, arg2)
    } else {
        (0i64, arg1)
    };

    #[allow(clippy::cast_possible_truncation)]
    let value = match value_arg {
        EmValue::I32(v) => *v as i16,
        _ => return PreHookResult::Bypass(None),
    };

    let final_addr = (addr as i64).wrapping_add(offset).cast_unsigned();
    if let Err(e) = write_with_auto_alloc(thread, final_addr, &value.to_le_bytes()) {
        return PreHookResult::throw_access_violation(&e.to_string());
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteIntPtr` method.
///
/// Writes a pointer-sized value to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteIntPtr(IntPtr, IntPtr) -> void`
/// - `Marshal.WriteIntPtr(IntPtr, Int32, IntPtr) -> void`
fn marshal_write_intptr_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let Some(addr) = resolve_address(arg0, thread) else {
        return PreHookResult::Bypass(None);
    };

    // Two-arg form: WriteIntPtr(IntPtr, IntPtr)
    // Three-arg form: WriteIntPtr(IntPtr, Int32 offset, IntPtr)
    let (offset, value) = if let Some(arg2) = ctx.args.get(2) {
        let ofs = arg1.as_i32().map(i64::from).unwrap_or(0);
        let val = match arg2 {
            EmValue::NativeInt(v) | EmValue::I64(v) => *v,
            EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => (*v).cast_signed(),
            EmValue::I32(v) => i64::from(*v),
            _ => return PreHookResult::Bypass(None),
        };
        (ofs, val)
    } else {
        let val = match arg1 {
            EmValue::NativeInt(v) | EmValue::I64(v) => *v,
            EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => (*v).cast_signed(),
            EmValue::I32(v) => i64::from(*v),
            _ => return PreHookResult::Bypass(None),
        };
        (0, val)
    };

    let final_addr = (addr as i64).wrapping_add(offset).cast_unsigned();
    let ptr_size = ctx.pointer_size.bytes();
    if ptr_size == 8 {
        if let Err(e) = write_with_auto_alloc(thread, final_addr, &value.to_le_bytes()) {
            return PreHookResult::throw_access_violation(&e.to_string());
        }
    } else {
        #[allow(clippy::cast_possible_truncation)]
        let val32 = value as i32;
        if let Err(e) = write_with_auto_alloc(thread, final_addr, &val32.to_le_bytes()) {
            return PreHookResult::throw_access_violation(&e.to_string());
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.AllocCoTaskMem` method.
///
/// Allocates unmanaged memory from the emulator's address space.
///
/// # Handled Overloads
///
/// - `Marshal.AllocCoTaskMem(Int32) -> IntPtr`
fn marshal_alloc_cotaskmem_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let size = match checked_len(
        ctx.args.first().and_then(EmValue::as_i32).unwrap_or(0),
        MAX_HOOK_BUFFER,
        "Marshal.AllocCoTaskMem",
        "cb",
    ) {
        Ok(n) => n.max(1), // Minimum 1 byte allocation
        Err(result) => return result,
    };

    match thread.address_space().alloc_unmanaged(size) {
        Ok(addr) => PreHookResult::Bypass(Some(EmValue::NativeInt(addr as i64))),
        // .NET signals allocation failure by throwing, and returning a null IntPtr instead
        // lets emulated code carry on writing through a pointer that was never allocated.
        Err(e) => PreHookResult::Throw {
            exception_type: synthetic_exception::OUT_OF_MEMORY,
            message: format!("Marshal.AllocCoTaskMem: {e}"),
        },
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.FreeCoTaskMem` method.
///
/// Releases the region and returns its bytes to the unmanaged allocation budget. Emulated
/// code that allocates and frees in a loop would otherwise exhaust that budget, since the
/// allocations are real but the frees were not.
///
/// # Handled Overloads
///
/// - `Marshal.FreeCoTaskMem(IntPtr) -> void`
fn marshal_free_cotaskmem_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    free_unmanaged_arg(ctx, thread)
}

/// Shared body for `FreeHGlobal` and `FreeCoTaskMem`.
///
/// A free of a null or unrecognised pointer is ignored rather than reported: .NET treats
/// `Free*(IntPtr.Zero)` as a no-op, and emulated code frequently frees pointers this emulator
/// never handed out (for instance when a paired allocation was bypassed by another hook).
fn free_unmanaged_arg(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let address = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => (*a).cast_unsigned(),
        _ => return PreHookResult::Bypass(None),
    };
    if address != 0 {
        let _ = thread.address_space().free_unmanaged(address);
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.AllocHGlobal` method.
///
/// Allocates unmanaged memory (same as `AllocCoTaskMem` for emulation purposes).
///
/// # Handled Overloads
///
/// - `Marshal.AllocHGlobal(Int32) -> IntPtr`
/// - `Marshal.AllocHGlobal(IntPtr) -> IntPtr`
fn marshal_alloc_hglobal_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let size = match ctx.args.first() {
        Some(EmValue::I32(v)) => checked_len(*v, MAX_HOOK_BUFFER, "Marshal.AllocHGlobal", "cb"),
        Some(EmValue::NativeInt(v)) => {
            checked_len(*v, MAX_HOOK_BUFFER, "Marshal.AllocHGlobal", "cb")
        }
        _ => Ok(0),
    };
    let size = match size {
        Ok(n) => n.max(1),
        Err(result) => return result,
    };

    match thread.address_space().alloc_unmanaged(size) {
        Ok(addr) => PreHookResult::Bypass(Some(EmValue::NativeInt(addr as i64))),
        Err(e) => PreHookResult::Throw {
            exception_type: synthetic_exception::OUT_OF_MEMORY,
            message: format!("Marshal.AllocHGlobal: {e}"),
        },
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.FreeHGlobal` method.
///
/// Releases the region and returns its bytes to the unmanaged allocation budget.
///
/// # Handled Overloads
///
/// - `Marshal.FreeHGlobal(IntPtr) -> void`
fn marshal_free_hglobal_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    free_unmanaged_arg(ctx, thread)
}

/// Hook for `System.Runtime.InteropServices.Marshal.SizeOf` method.
///
/// Returns the unmanaged size of a type. For primitive types, returns the
/// exact size. For unknown types, falls back to pointer size.
///
/// # Handled Overloads
///
/// - `Marshal.SizeOf(Object) -> Int32`
/// - `Marshal.SizeOf(Type) -> Int32`
/// - `Marshal.SizeOf<T>() -> Int32`
fn marshal_sizeof_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let ptr_size = ctx.pointer_size;

    // Try to resolve the type from the first argument (a Type reflection object)
    let type_token = ctx.args.first().and_then(|arg| {
        if let EmValue::ObjectRef(href) = arg {
            thread
                .heap()
                .get_reflection_type_token(*href)
                .ok()
                .flatten()
        } else {
            None
        }
    });

    let size = if let Some(token) = type_token {
        // Look up the type and compute its marshal size
        thread
            .assembly()
            .and_then(|asm| asm.types().get(&token))
            .and_then(|ty| ty.flavor().byte_size(ptr_size))
            .unwrap_or(ptr_size.bytes())
    } else {
        ptr_size.bytes()
    };

    PreHookResult::Bypass(Some(EmValue::I32(size as i32)))
}

/// Hook for `Marshal.GetDelegateForFunctionPointer` method.
///
/// Creates a delegate from a native function pointer. The delegate is
/// allocated as a `HeapObject::Delegate` so that `Invoke` dispatches
/// correctly through the emulator's delegate resolution system.
///
/// The delegate's target method token is set to
/// [`tokens::native::NATIVE_FUNCTION_POINTER`] — a synthetic marker that
/// the delegate dispatcher recognizes as a native function pointer delegate.
/// When invoked, the dispatcher returns a default success value appropriate
/// for the return type.
///
/// # Handled Overloads
///
/// - `Marshal.GetDelegateForFunctionPointer(IntPtr, Type) -> Delegate`
/// - `Marshal.GetDelegateForFunctionPointer<TDelegate>(IntPtr) -> TDelegate`
fn marshal_get_delegate_for_function_pointer_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let type_token = if let Some(EmValue::ObjectRef(type_ref)) = ctx.args.get(1) {
        thread
            .heap()
            .get_reflection_type_token(*type_ref)
            .unwrap_or(None)
    } else {
        None
    };

    let delegate_type = type_token.unwrap_or(Token::new(0x0200_0001));

    // Extract the function pointer address and look up its name in the
    // native function registry to allocate a per-function token.
    let func_addr = ctx.args.first().and_then(|v| match v {
        EmValue::NativeInt(a) => Some(*a as u64),
        EmValue::NativeUInt(a) => Some(*a),
        EmValue::I32(a) => Some(*a as u64),
        EmValue::I64(a) => Some(*a as u64),
        _ => None,
    });

    let native_target = if let Some(addr) = func_addr {
        let runtime = thread.runtime_state().read().ok();
        runtime
            .as_ref()
            .and_then(|rt| {
                let function = rt.native_functions().lookup_by_address(addr)?;
                let token = rt.native_functions().allocate_token(&function);
                log::debug!(
                    "GetDelegateForFunctionPointer(0x{addr:X}) → {}!{} → token 0x{:08X}",
                    function.dll.as_deref().unwrap_or("?"),
                    function.name,
                    token.value()
                );
                Some(token)
            })
            .unwrap_or(tokens::native::NATIVE_FUNCTION_POINTER)
    } else {
        tokens::native::NATIVE_FUNCTION_POINTER
    };

    match thread
        .heap_mut()
        .alloc_delegate(delegate_type, None, native_target)
    {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Marshal.GetFunctionPointerForDelegate` method.
///
/// Converts a managed delegate back to a native function pointer. If the
/// delegate wraps a native function (created via `GetDelegateForFunctionPointer`),
/// looks up the original address from the native function registry. For managed
/// delegates, allocates a synthetic native address so the caller has a valid
/// pointer value.
///
/// # Handled Overloads
///
/// - `Marshal.GetFunctionPointerForDelegate(Delegate) -> IntPtr`
/// - `Marshal.GetFunctionPointerForDelegate<TDelegate>(TDelegate) -> IntPtr`
fn marshal_get_function_pointer_for_delegate_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let delegate_ref = ctx.args.first().and_then(|v| match v {
        EmValue::ObjectRef(href) => Some(*href),
        _ => None,
    });

    if let Some(href) = delegate_ref {
        if let Ok(crate::emulation::HeapObject::Delegate {
            invocation_list, ..
        }) = thread.heap().get_shared(href).as_deref()
        {
            if let Some(entry) = invocation_list.first() {
                let method_token = entry.method_token;
                if tokens::is_native_function_pointer(method_token) {
                    if let Ok(rt) = thread.runtime_state().read() {
                        if let Some(function) = rt.native_functions().lookup_by_token(method_token)
                        {
                            if let Some(addr) =
                                rt.native_functions().lookup_address_by_name(&function.name)
                            {
                                let name = &function.name;
                                log::debug!("GetFunctionPointerForDelegate → {name} at 0x{addr:X}");
                                return PreHookResult::Bypass(Some(EmValue::NativeInt(
                                    addr as i64,
                                )));
                            }
                        }
                    }
                }
                // For managed delegates, return the method token value as a fake address
                return PreHookResult::Bypass(Some(EmValue::NativeInt(i64::from(
                    method_token.value(),
                ))));
            }
        }
    }

    // Fallback: return a non-null pointer so callers don't crash
    PreHookResult::Bypass(Some(EmValue::NativeInt(
        tokens::native_addresses::DELEGATE_FUNCTION_POINTER_FALLBACK,
    )))
}

/// Hook for `System.IntPtr..ctor` constructor.
///
/// Initializes an IntPtr from an integer value. Since IntPtr is a value type
/// on the CIL stack, the constructor replaces the `this` pointer's target
/// with the integer value.
///
/// # Handled Overloads
///
/// - `IntPtr..ctor(Int32) -> void`
/// - `IntPtr..ctor(Int64) -> void`
/// - `IntPtr..ctor(void*) -> void`
fn intptr_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let value = match ctx.args.first() {
        Some(EmValue::I32(v)) => EmValue::NativeInt(i64::from(*v)),
        Some(EmValue::I64(v)) | Some(EmValue::NativeInt(v)) => EmValue::NativeInt(*v),
        Some(EmValue::NativeUInt(v)) | Some(EmValue::UnmanagedPtr(v)) => {
            EmValue::NativeInt((*v).cast_signed())
        }
        _ => EmValue::NativeInt(0),
    };

    // Store the value through the `this` pointer.
    // For value type locals (ldloca path): this is a ManagedPtr.
    // For heap-allocated objects (newobj path): this is an ObjectRef — store as a
    // synthetic field so resolve_address can recover it later.
    match ctx.this {
        Some(EmValue::ManagedPtr(ptr)) => {
            let _ = thread.store_through_pointer(ptr, value);
        }
        Some(EmValue::ObjectRef(href)) => {
            // Store the IntPtr value as a field on the heap object.
            // Use the well-known IntPtr.m_value field token (0x04_FFFF_01).
            let field_token = Token::new(0x04FF_FF01);
            let _ = thread.heap_mut().set_field(*href, field_token, value);
        }
        _ => {}
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.IntPtr.get_Size` property.
///
/// Returns the size of a pointer in bytes (4 for 32-bit, 8 for 64-bit).
fn intptr_get_size_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let size = ctx.pointer_size.bytes() as i32;
    PreHookResult::Bypass(Some(EmValue::I32(size)))
}

/// Hook for `System.IntPtr.op_Explicit` operator method.
///
/// Converts between IntPtr and various integer/pointer types.
///
/// # Handled Overloads
///
/// - `IntPtr.op_Explicit(IntPtr) -> Int32`
/// - `IntPtr.op_Explicit(IntPtr) -> Int64`
/// - `IntPtr.op_Explicit(IntPtr) -> void*`
/// - `IntPtr.op_Explicit(Int32) -> IntPtr`
/// - `IntPtr.op_Explicit(Int64) -> IntPtr`
/// - `IntPtr.op_Explicit(void*) -> IntPtr`
///
/// # Parameters
///
/// - `value`: The value to convert
fn intptr_op_explicit_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(arg) = ctx.args.first() {
        match arg {
            EmValue::NativeInt(v) | EmValue::I64(v) => EmValue::NativeInt(*v),
            EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => {
                EmValue::NativeInt((*v).cast_signed())
            }
            EmValue::I32(v) => EmValue::NativeInt(i64::from(*v)),
            _ => arg.clone(),
        }
    } else {
        EmValue::NativeInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.IntPtr.Add` method.
///
/// Adds an offset to a pointer value.
///
/// # Handled Overloads
///
/// - `IntPtr.Add(IntPtr, Int32) -> IntPtr`
///
/// # Parameters
///
/// - `pointer`: The pointer to add to
/// - `offset`: The offset to add
fn intptr_add_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
    };

    let ptr = match arg0 {
        EmValue::NativeInt(v) => *v,
        EmValue::UnmanagedPtr(v) => (*v).cast_signed(),
        _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
    };

    let offset = match arg1 {
        EmValue::I32(v) => i64::from(*v),
        EmValue::I64(v) => *v,
        _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(ptr))),
    };

    PreHookResult::Bypass(Some(EmValue::NativeInt(ptr.wrapping_add(offset))))
}

/// Hook for `System.IntPtr.ToInt32` method.
///
/// Converts the pointer value to a 32-bit signed integer.
///
/// # Handled Overloads
///
/// - `IntPtr.ToInt32() -> Int32`
fn intptr_to_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    #[allow(clippy::cast_possible_truncation)]
    let value = match ctx.this {
        Some(EmValue::NativeInt(v)) => *v as i32,
        Some(EmValue::UnmanagedPtr(v)) => *v as i32,
        Some(EmValue::ManagedPtr(ptr)) => {
            resolve_managed_ptr_as_i64(ptr, thread).unwrap_or(0) as i32
        }
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IntPtr.ToInt64` method.
///
/// Converts the pointer value to a 64-bit signed integer.
/// Handles direct values, unmanaged pointers, and ManagedPointer references
/// (from `ldloca + call` on value type locals).
///
/// # Handled Overloads
///
/// - `IntPtr.ToInt64() -> Int64`
fn intptr_to_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let value = match ctx.this {
        Some(EmValue::NativeInt(v)) => *v,
        Some(EmValue::UnmanagedPtr(v)) => (*v).cast_signed(),
        Some(EmValue::ManagedPtr(ptr)) => {
            // Dereference: read the IntPtr value from the pointed-to local/field
            resolve_managed_ptr_as_i64(ptr, thread).unwrap_or(0)
        }
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.UIntPtr.op_Explicit` operator method.
///
/// Converts between UIntPtr and various integer/pointer types.
///
/// # Handled Overloads
///
/// - `UIntPtr.op_Explicit(UIntPtr) -> UInt32`
/// - `UIntPtr.op_Explicit(UIntPtr) -> UInt64`
/// - `UIntPtr.op_Explicit(UIntPtr) -> void*`
/// - `UIntPtr.op_Explicit(UInt32) -> UIntPtr`
/// - `UIntPtr.op_Explicit(UInt64) -> UIntPtr`
/// - `UIntPtr.op_Explicit(void*) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to convert
fn uintptr_op_explicit_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(arg) = ctx.args.first() {
        match arg {
            EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => EmValue::NativeUInt(*v),
            EmValue::NativeInt(v) | EmValue::I64(v) => EmValue::NativeUInt((*v).cast_unsigned()),
            EmValue::I32(v) => EmValue::NativeUInt((*v).cast_unsigned().into()),
            _ => arg.clone(),
        }
    } else {
        EmValue::NativeUInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Coerces an `EmValue` to an `i64` for pointer comparison operations.
fn coerce_to_native(val: &EmValue) -> i64 {
    match val {
        EmValue::NativeInt(v) | EmValue::I64(v) => *v,
        EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => *v as i64,
        EmValue::I32(v) => i64::from(*v),
        EmValue::Null => 0,
        _ => 0,
    }
}

/// Hook for `IntPtr.op_Equality(IntPtr, IntPtr)`.
///
/// Compares two `IntPtr` values for equality.
fn intptr_op_equality_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let lhs = ctx.args.first().map(coerce_to_native).unwrap_or(0);
    let rhs = ctx.args.get(1).map(coerce_to_native).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(lhs == rhs))))
}

/// Hook for `IntPtr.op_Inequality(IntPtr, IntPtr)`.
///
/// Compares two `IntPtr` values for inequality.
fn intptr_op_inequality_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let lhs = ctx.args.first().map(coerce_to_native).unwrap_or(0);
    let rhs = ctx.args.get(1).map(coerce_to_native).unwrap_or(0);
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(lhs != rhs))))
}

/// Hook for `IntPtr.get_Zero`.
///
/// Returns `IntPtr.Zero` (a null pointer).
fn intptr_get_zero_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::NativeInt(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 29);
    }

    #[test]
    fn test_gethinstance_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "Marshal",
            "GetHINSTANCE",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();

        // Without an assembly, returns default Windows image base
        let result = marshal_get_hinstance_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => {
                assert_eq!(v, tokens::native_addresses::CURRENT_MODULE);
            }
            _ => panic!("Expected Bypass with NativeInt"),
        }
    }

    #[test]
    fn test_intptr_op_explicit_hook() {
        let args = [EmValue::I32(42)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "op_Explicit",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = create_test_thread();

        let result = intptr_op_explicit_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with NativeInt(42)"),
        }
    }

    #[test]
    fn test_intptr_add_hook() {
        let args = [EmValue::NativeInt(0x1000), EmValue::I32(0x100)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "Add",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = create_test_thread();

        let result = intptr_add_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 0x1100),
            _ => panic!("Expected Bypass with NativeInt(0x1100)"),
        }
    }

    #[test]
    fn test_intptr_to_int64_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "ToInt64",
            PointerSize::Bit64,
        )
        .with_this(Some(&EmValue::NativeInt(0x1_0000_0000)));

        let mut thread = create_test_thread();
        let result = intptr_to_int64_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I64(v))) => assert_eq!(v, 0x1_0000_0000),
            _ => panic!("Expected Bypass with I64"),
        }
    }

    #[test]
    fn test_intptr_get_zero_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "get_Zero",
            PointerSize::Bit64,
        );
        let mut thread = create_test_thread();
        let result = intptr_get_zero_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::NativeInt(0)))
        ));
    }

    #[test]
    fn test_intptr_op_equality_same() {
        let args = [EmValue::NativeInt(42), EmValue::NativeInt(42)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "op_Equality",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let mut thread = create_test_thread();
        let result = intptr_op_equality_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_intptr_op_equality_different() {
        let args = [EmValue::NativeInt(1), EmValue::NativeInt(2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "op_Equality",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let mut thread = create_test_thread();
        let result = intptr_op_equality_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_intptr_op_inequality() {
        let args = [EmValue::NativeInt(1), EmValue::NativeInt(2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "op_Inequality",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let mut thread = create_test_thread();
        let result = intptr_op_inequality_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_intptr_to_int32_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "IntPtr",
            "ToInt32",
            PointerSize::Bit64,
        )
        .with_this(Some(&EmValue::NativeInt(42)));

        let mut thread = create_test_thread();

        let result = intptr_to_int32_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }
}

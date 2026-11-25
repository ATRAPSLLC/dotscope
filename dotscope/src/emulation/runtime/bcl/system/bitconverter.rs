//! `System.BitConverter` method hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for `System.BitConverter`, which converts
//! between primitive types and byte arrays. These methods are commonly used in XOR
//! decryption routines and other byte-level manipulation in obfuscated assemblies.
//!
//! # Covered APIs
//!
//! - `GetBytes(int/long/...)` — converts primitives to little-endian byte arrays
//! - `ToInt32(byte[], int)` — converts bytes to 32-bit signed integer
//! - `ToInt64(byte[], int)` — converts bytes to 64-bit signed integer
//! - `ToUInt32(byte[], int)` — converts bytes to 32-bit unsigned integer

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    utils::LeBytes,
    Result,
};

/// Registers all `System.BitConverter` hooks.
///
/// Called by the parent `system::register()` to wire up BitConverter hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.BitConverter.GetBytes")
            .match_name("System", "BitConverter", "GetBytes")
            .pre(bitconverter_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.BitConverter.ToInt32")
            .match_name("System", "BitConverter", "ToInt32")
            .pre(bitconverter_to_int32_pre),
    )?;

    manager.register(
        Hook::new("System.BitConverter.ToInt64")
            .match_name("System", "BitConverter", "ToInt64")
            .pre(bitconverter_to_int64_pre),
    )?;

    manager.register(
        Hook::new("System.BitConverter.ToUInt32")
            .match_name("System", "BitConverter", "ToUInt32")
            .pre(bitconverter_to_uint32_pre),
    )?;

    Ok(())
}

/// Hook for `System.BitConverter.GetBytes` method.
///
/// Converts a primitive value to its byte array representation (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.GetBytes(Boolean) -> Byte[]`
/// - `BitConverter.GetBytes(Char) -> Byte[]`
/// - `BitConverter.GetBytes(Double) -> Byte[]`
/// - `BitConverter.GetBytes(Int16) -> Byte[]`
/// - `BitConverter.GetBytes(Int32) -> Byte[]`
/// - `BitConverter.GetBytes(Int64) -> Byte[]`
/// - `BitConverter.GetBytes(Single) -> Byte[]`
/// - `BitConverter.GetBytes(UInt16) -> Byte[]`
/// - `BitConverter.GetBytes(UInt32) -> Byte[]`
/// - `BitConverter.GetBytes(UInt64) -> Byte[]`
///
/// # Parameters
///
/// - `value`: The value to convert to bytes
fn bitconverter_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(arg) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let bytes = match arg {
        EmValue::I32(v) => LeBytes::from_4(v.to_le_bytes()),
        EmValue::I64(v) | EmValue::NativeInt(v) => LeBytes::from_8(v.to_le_bytes()),
        EmValue::F32(v) => LeBytes::from_4(v.to_le_bytes()),
        EmValue::F64(v) => LeBytes::from_8(v.to_le_bytes()),
        EmValue::NativeUInt(v) => LeBytes::from_8(v.to_le_bytes()),
        EmValue::Bool(v) => LeBytes::from_byte(u8::from(*v)),
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread.heap().alloc_byte_array(&bytes) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.BitConverter.ToInt32` method.
///
/// Converts 4 bytes from a byte array to a 32-bit signed integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToInt32(Byte[], Int32) -> Int32`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some(bytes) = (match arg0 {
        EmValue::ObjectRef(handle) => try_hook!(thread.heap().get_byte_array(*handle)),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    }) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let start_index = usize::try_from(arg1).unwrap_or(usize::MAX);
    let Some(end_index) = start_index.checked_add(4) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };
    let Some(slice) = bytes
        .get(start_index..end_index)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
    else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let value = i32::from_le_bytes(slice);
    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.BitConverter.ToInt64` method.
///
/// Converts 8 bytes from a byte array to a 64-bit signed integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToInt64(Byte[], Int32) -> Int64`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let Some(bytes) = (match arg0 {
        EmValue::ObjectRef(handle) => try_hook!(thread.heap().get_byte_array(*handle)),
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    }) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let start_index = usize::try_from(arg1).unwrap_or(usize::MAX);
    let Some(end_index) = start_index.checked_add(8) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };
    let Some(slice) = bytes
        .get(start_index..end_index)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
    else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let value = i64::from_le_bytes(slice);
    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.BitConverter.ToUInt32` method.
///
/// Converts 4 bytes from a byte array to a 32-bit unsigned integer (little-endian).
///
/// # Handled Overloads
///
/// - `BitConverter.ToUInt32(Byte[], Int32) -> UInt32`
///
/// # Parameters
///
/// - `value`: Byte array containing the bytes to convert
/// - `startIndex`: Starting position within the array
fn bitconverter_to_uint32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some(bytes) = (match arg0 {
        EmValue::ObjectRef(handle) => try_hook!(thread.heap().get_byte_array(*handle)),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    }) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let start_index = usize::try_from(arg1).unwrap_or(usize::MAX);
    let Some(end_index) = start_index.checked_add(4) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };
    let Some(slice) = bytes
        .get(start_index..end_index)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
    else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let value = u32::from_le_bytes(slice);

    #[allow(clippy::cast_possible_wrap)]
    let signed_value = value as i32;
    PreHookResult::Bypass(Some(EmValue::I32(signed_value)))
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_bitconverter_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(0x12345678)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "BitConverter",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::bitconverter_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_bitconverter_to_int32_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0x78, 0x56, 0x34, 0x12])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "BitConverter",
            "ToInt32",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::bitconverter_to_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));
    }

    #[test]
    fn test_bitconverter_to_int64_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "BitConverter",
            "ToInt64",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::bitconverter_to_int64_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0x123456789ABCDEF0)))
        ));
    }

    #[test]
    fn test_bitconverter_to_uint32_hook() {
        let mut thread = create_test_thread();
        let bytes = thread
            .heap()
            .alloc_byte_array(&[0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();

        let args = [EmValue::ObjectRef(bytes), EmValue::I32(0)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "BitConverter",
            "ToUInt32",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::bitconverter_to_uint32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }
}

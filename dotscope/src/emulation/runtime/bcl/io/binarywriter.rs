//! `System.IO.BinaryWriter` method hooks.
//!
//! This module provides hook implementations for BinaryWriter, which wraps an
//! underlying stream and provides typed write methods. BinaryWriter is used by
//! some obfuscators to construct encrypted payloads or write structured data.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `BinaryWriter..ctor(Stream)` | Create writer | Stores stream reference in synthetic field |
//! | `BinaryWriter.get_BaseStream` | Get underlying stream | Returns stored stream reference |
//! | `BinaryWriter.Write(bool)` | Write boolean | 1 byte (0 or 1) |
//! | `BinaryWriter.Write(byte)` | Write byte | 1 byte unsigned |
//! | `BinaryWriter.Write(sbyte)` | Write signed byte | 1 byte signed |
//! | `BinaryWriter.Write(char)` | Write character | UTF-8 encoded |
//! | `BinaryWriter.Write(short)` | Write 16-bit int | 2 bytes little-endian |
//! | `BinaryWriter.Write(ushort)` | Write unsigned 16-bit | 2 bytes little-endian |
//! | `BinaryWriter.Write(int)` | Write 32-bit int | 4 bytes little-endian |
//! | `BinaryWriter.Write(uint)` | Write unsigned 32-bit | 4 bytes little-endian |
//! | `BinaryWriter.Write(long)` | Write 64-bit int | 8 bytes little-endian |
//! | `BinaryWriter.Write(ulong)` | Write unsigned 64-bit | 8 bytes little-endian |
//! | `BinaryWriter.Write(float)` | Write single | 4 bytes IEEE 754 |
//! | `BinaryWriter.Write(double)` | Write double | 8 bytes IEEE 754 |
//! | `BinaryWriter.Write(byte[])` | Write byte array | Writes raw bytes to stream |
//! | `BinaryWriter.Write(byte[], int, int)` | Write byte slice | Writes slice to stream |
//! | `BinaryWriter.Write(string)` | Write string | Writes 7-bit length prefix + UTF-8 bytes |
//! | `BinaryWriter.Seek(int, SeekOrigin)` | Seek in stream | Sets position based on origin |
//! | `BinaryWriter.Flush()` | Flush writer | No-op |
//! | `BinaryWriter.Close()` | Close writer | No-op |
//! | `BinaryWriter.Dispose()` | Dispose writer | No-op |

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::{
            bcl::{io::stream::stream_dispose_pre, limits::buffer_range},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        tokens::io_fields,
        EmValue, HeapRef,
    },
    metadata::typesystem::CilFlavor,
    utils::write_7bit_encoded_int,
    Result,
};

/// Helper function to get the underlying stream reference from a BinaryWriter.
fn get_binary_writer_stream(writer_ref: HeapRef, thread: &EmulationThread) -> Option<HeapRef> {
    let field_value = thread
        .heap()
        .get_field(writer_ref, io_fields::BINARY_WRITER_STREAM)
        .ok()?;
    match field_value {
        EmValue::ObjectRef(stream_ref) => Some(stream_ref),
        _ => None,
    }
}

/// Registers all BinaryWriter method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.IO.BinaryWriter..ctor")
            .match_name("System.IO", "BinaryWriter", ".ctor")
            .pre(binary_writer_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.get_BaseStream")
            .match_name("System.IO", "BinaryWriter", "get_BaseStream")
            .pre(binary_writer_get_base_stream_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.Write")
            .match_name("System.IO", "BinaryWriter", "Write")
            .pre(binary_writer_write_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.Seek")
            .match_name("System.IO", "BinaryWriter", "Seek")
            .pre(binary_writer_seek_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.Flush")
            .match_name("System.IO", "BinaryWriter", "Flush")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.Close")
            .match_name("System.IO", "BinaryWriter", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryWriter.Dispose")
            .match_name("System.IO", "BinaryWriter", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.BinaryWriter..ctor` constructor.
///
/// # Handled Overloads
///
/// - `BinaryWriter..ctor(Stream)`
/// - `BinaryWriter..ctor(Stream, Encoding)` (encoding argument is ignored)
///
/// # Parameters
///
/// - `output`: The underlying stream to write to
fn binary_writer_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the BinaryWriter object reference
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the stream argument
    let stream_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Store the stream reference in the BinaryWriter's field
    try_hook!(thread.heap_mut().set_field(
        writer_ref,
        io_fields::BINARY_WRITER_STREAM,
        EmValue::ObjectRef(stream_ref),
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryWriter.get_BaseStream` property.
///
/// # Handled Overloads
///
/// - `BinaryWriter.BaseStream { get; } -> Stream`
///
/// # Returns
///
/// The underlying stream reference stored during construction
fn binary_writer_get_base_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match get_binary_writer_stream(writer_ref, thread) {
        Some(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        None => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.IO.BinaryWriter.Write` method.
///
/// # Handled Overloads
///
/// - `BinaryWriter.Write(Boolean)` - Writes 1 byte (0 or 1)
/// - `BinaryWriter.Write(Byte)` - Writes 1 byte
/// - `BinaryWriter.Write(SByte)` - Writes 1 byte (signed)
/// - `BinaryWriter.Write(Int16)` - Writes 2 bytes little-endian
/// - `BinaryWriter.Write(UInt16)` - Writes 2 bytes little-endian
/// - `BinaryWriter.Write(Char)` - Writes UTF-8 encoded character
/// - `BinaryWriter.Write(Int32)` - Writes 4 bytes little-endian
/// - `BinaryWriter.Write(UInt32)` - Writes 4 bytes little-endian
/// - `BinaryWriter.Write(Int64)` - Writes 8 bytes little-endian
/// - `BinaryWriter.Write(UInt64)` - Writes 8 bytes little-endian
/// - `BinaryWriter.Write(Single)` - Writes 4 bytes IEEE 754
/// - `BinaryWriter.Write(Double)` - Writes 8 bytes IEEE 754
/// - `BinaryWriter.Write(Byte[])` - Writes raw bytes
/// - `BinaryWriter.Write(Byte[], Int32, Int32)` - Writes a slice of bytes
/// - `BinaryWriter.Write(String)` - Writes a 7-bit length prefix followed by UTF-8 bytes
///
/// # Implementation Note
///
/// Uses `param_types` from the hook context to correctly distinguish between overloads
/// that share the same `EmValue` representation (e.g. `Write(byte)` vs `Write(int)` both
/// arrive as `I32`). Falls back to type/count-based heuristics when `param_types` is unavailable.
fn binary_writer_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some(stream_ref) = get_binary_writer_stream(writer_ref, thread) else {
        return PreHookResult::Bypass(None);
    };

    // Try to use param_types for precise overload dispatch
    if let Some(param_types) = ctx.param_types {
        if let Some(first_type) = param_types.first().filter(|_| param_types.len() == 1) {
            match first_type {
                // Write(Boolean) — 1 byte: 0 or 1
                CilFlavor::Boolean => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) if *v != 0 => 1u8,
                        _ => 0u8,
                    };
                    try_hook!(thread.heap_mut().write_to_stream(stream_ref, &[v]));
                    return PreHookResult::Bypass(None);
                }
                // Write(Byte) — 1 byte unsigned
                CilFlavor::U1 => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u8,
                        _ => 0u8,
                    };
                    try_hook!(thread.heap_mut().write_to_stream(stream_ref, &[v]));
                    return PreHookResult::Bypass(None);
                }
                // Write(SByte) — 1 byte signed
                CilFlavor::I1 => {
                    #[allow(clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as i8 as u8,
                        _ => 0u8,
                    };
                    try_hook!(thread.heap_mut().write_to_stream(stream_ref, &[v]));
                    return PreHookResult::Bypass(None);
                }
                // Write(Char) — UTF-8 encoded character
                CilFlavor::Char => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    if let Some(EmValue::I32(v)) = ctx.args.first() {
                        if let Some(ch) = char::from_u32(*v as u32) {
                            let mut buf = [0u8; 4];
                            let encoded = ch.encode_utf8(&mut buf);
                            try_hook!(thread
                                .heap_mut()
                                .write_to_stream(stream_ref, encoded.as_bytes()));
                        }
                    }
                    return PreHookResult::Bypass(None);
                }
                // Write(Int16) — 2 bytes little-endian
                CilFlavor::I2 => {
                    #[allow(clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as i16,
                        _ => 0i16,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt16) — 2 bytes little-endian
                CilFlavor::U2 => {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u16,
                        _ => 0u16,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(Int32) — 4 bytes little-endian
                CilFlavor::I4 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v,
                        _ => 0i32,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt32) — 4 bytes little-endian
                CilFlavor::U4 => {
                    #[allow(clippy::cast_sign_loss)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I32(v)) => *v as u32,
                        _ => 0u32,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(Int64) — 8 bytes little-endian
                CilFlavor::I8 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::I64(v)) => *v,
                        Some(EmValue::I32(v)) => i64::from(*v),
                        _ => 0i64,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(UInt64) — 8 bytes little-endian
                CilFlavor::U8 => {
                    #[allow(clippy::cast_sign_loss)]
                    let v = match ctx.args.first() {
                        Some(EmValue::I64(v)) => *v as u64,
                        Some(EmValue::I32(v)) => *v as u64,
                        _ => 0u64,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(Single) — 4 bytes IEEE 754
                CilFlavor::R4 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::F32(v)) => *v,
                        Some(EmValue::F64(v)) => *v as f32,
                        _ => 0.0f32,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(Double) — 8 bytes IEEE 754
                CilFlavor::R8 => {
                    let v = match ctx.args.first() {
                        Some(EmValue::F64(v)) => *v,
                        Some(EmValue::F32(v)) => f64::from(*v),
                        _ => 0.0f64,
                    };
                    try_hook!(thread
                        .heap_mut()
                        .write_to_stream(stream_ref, &v.to_le_bytes()));
                    return PreHookResult::Bypass(None);
                }
                // Write(String) — 7-bit length prefix + UTF-8
                CilFlavor::String => {
                    if let Some(EmValue::ObjectRef(obj_ref)) = ctx.args.first() {
                        if let Ok(s) = thread.heap().get_string(*obj_ref) {
                            let s_bytes = s.as_bytes().to_vec();
                            let mut len_prefix = Vec::new();
                            #[allow(clippy::cast_possible_truncation)]
                            write_7bit_encoded_int(s_bytes.len() as u32, &mut len_prefix);
                            try_hook!(thread.heap_mut().write_to_stream(stream_ref, &len_prefix));
                            try_hook!(thread.heap_mut().write_to_stream(stream_ref, &s_bytes));
                        }
                    }
                    return PreHookResult::Bypass(None);
                }
                _ => {} // Fall through to heuristic dispatch
            }
        }
    }

    // Fallback: heuristic dispatch based on argument types and count
    match (ctx.args.first(), ctx.args.len()) {
        // Write(byte[]) or Write(string) — single ObjectRef argument
        (Some(EmValue::ObjectRef(obj_ref)), 1) => {
            if let Ok(s) = thread.heap().get_string(*obj_ref) {
                // Write(string): 7-bit length prefix + UTF-8 bytes
                let s_bytes = s.as_bytes().to_vec();
                let mut len_prefix = Vec::new();
                #[allow(clippy::cast_possible_truncation)]
                write_7bit_encoded_int(s_bytes.len() as u32, &mut len_prefix);
                try_hook!(thread.heap_mut().write_to_stream(stream_ref, &len_prefix));
                try_hook!(thread.heap_mut().write_to_stream(stream_ref, &s_bytes));
            } else if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*obj_ref)) {
                // Write(byte[]): write raw bytes
                try_hook!(thread.heap_mut().write_to_stream(stream_ref, &bytes));
            }
        }
        // Write(byte[], int, int): the slice, its arguments checked as the stream beneath
        // checks them; a null buffer is the `ArgumentNullException` the runtime throws
        (Some(EmValue::ObjectRef(_) | EmValue::Null), 3) => {
            let (buffer_ref, offset, count) =
                match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
                    Ok(range) => range,
                    Err(result) => return result,
                };
            // `Write(char[], int, int)` takes the same shape: not a byte slice, and not
            // emulated, rather than written as nothing
            let Some(bytes) = try_hook!(thread.heap().get_byte_array(buffer_ref)) else {
                return PreHookResult::Error(
                    "BinaryWriter.Write of an array slice that is no byte[] is not emulated"
                        .to_string(),
                );
            };
            // In range: `buffer_range` checked it against the buffer's length
            let slice = bytes
                .get(offset..offset.saturating_add(count))
                .unwrap_or_default();
            try_hook!(thread.heap_mut().write_to_stream(stream_ref, slice));
        }
        // Write(int) — 4 bytes little-endian (fallback: assumes Int32 when no type info)
        (Some(EmValue::I32(v)), 1) => {
            try_hook!(thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes()));
        }
        // Write(long) — 8 bytes little-endian
        (Some(EmValue::I64(v)), 1) => {
            try_hook!(thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes()));
        }
        // Write(float) — 4 bytes IEEE 754
        (Some(EmValue::F32(v)), 1) => {
            try_hook!(thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes()));
        }
        // Write(double) — 8 bytes IEEE 754
        (Some(EmValue::F64(v)), 1) => {
            try_hook!(thread
                .heap_mut()
                .write_to_stream(stream_ref, &v.to_le_bytes()));
        }
        _ => {}
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryWriter.Seek` method.
///
/// # Handled Overloads
///
/// - `BinaryWriter.Seek(Int32, SeekOrigin) -> Int64`
///
/// # Parameters
///
/// - `offset`: Byte offset relative to origin
/// - `origin`: Reference point (Begin=0, Current=1, End=2)
fn binary_writer_seek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let writer_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    let Some(stream_ref) = get_binary_writer_stream(writer_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    // Reuse the stream seek logic by building a temporary context for the stream
    let offset = match ctx.args.first() {
        Some(EmValue::I32(v)) => i64::from(*v),
        Some(EmValue::I64(v)) => *v,
        _ => 0,
    };

    let origin = match ctx.args.get(1) {
        Some(EmValue::I32(v)) => *v,
        _ => 0,
    };

    let length = match try_hook!(thread.heap().stream_len(stream_ref)) {
        Some(len) => len,
        None => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };
    let current_pos = match try_hook!(thread.heap().stream_position(stream_ref)) {
        Some(pos) => pos,
        None => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let new_pos = match origin {
        1 => {
            #[allow(clippy::cast_possible_wrap)]
            let pos = (current_pos as i64).saturating_add(offset);
            pos.max(0) as usize
        }
        2 => {
            #[allow(clippy::cast_possible_wrap)]
            let pos = (length as i64).saturating_add(offset);
            pos.max(0) as usize
        }
        _ => offset.max(0) as usize,
    };

    let clamped_pos = new_pos.min(length);
    try_hook!(thread
        .heap_mut()
        .set_stream_position(stream_ref, clamped_pos));

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(clamped_pos as i64)))
}

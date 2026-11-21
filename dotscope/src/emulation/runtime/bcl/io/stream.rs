//! `System.IO.Stream` and `System.IO.MemoryStream` method hooks.
//!
//! This module provides hook implementations for stream base class and MemoryStream,
//! which are fundamental to .NET I/O operations. Obfuscators commonly use `MemoryStream`
//! to wrap byte arrays for further processing with `BinaryReader` or compression streams.
//! Streams are backed by [`HeapObject::Stream`] for full data tracking and position management.
//!
//! # Emulated .NET Methods
//!
//! ## MemoryStream Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `MemoryStream..ctor(byte[])` | Create stream from bytes | Stores data in heap Stream object |
//! | `MemoryStream.Read(byte[], int, int)` | Read bytes | Reads from Stream data, advances position |
//! | `MemoryStream.ReadByte()` | Read single byte | Reads byte, advances position |
//! | `MemoryStream.Write(byte[], int, int)` | Write bytes | Appends data to stream |
//! | `MemoryStream.WriteByte(byte)` | Write single byte | Appends byte to stream |
//! | `MemoryStream.ToArray()` | Get stream contents | Returns full Stream data as byte array |
//! | `MemoryStream.GetBuffer()` | Get internal buffer | Returns full Stream data as byte array |
//! | `MemoryStream.get_Length` | Stream length | Returns actual data length |
//! | `MemoryStream.get_Capacity` | Stream capacity | Returns data length (simplified) |
//! | `MemoryStream.get_Position` | Current position | Returns current read position |
//! | `MemoryStream.set_Position` | Set position | Updates stream position |
//! | `MemoryStream.Seek(long, SeekOrigin)` | Seek to position | Updates position based on origin |
//! | `MemoryStream.SetLength(long)` | Set stream length | Truncates or extends stream |
//! | `MemoryStream.CopyTo(Stream)` | Copy to another stream | Copies remaining data |
//! | `MemoryStream.Flush()` | Flush stream | No-op |
//! | `MemoryStream.Close()` | Close stream | No-op |
//! | `MemoryStream.Dispose()` | Dispose stream | No-op |
//! | `MemoryStream.get_CanRead` | Can read | Always true |
//! | `MemoryStream.get_CanSeek` | Can seek | Always true |
//! | `MemoryStream.get_CanWrite` | Can write | Always true |
//!
//! ## Stream Base Class Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `Stream.Read(byte[], int, int)` | Read bytes | Reads from Stream data |
//! | `Stream.ReadByte()` | Read single byte | Reads byte from Stream |
//! | `Stream.Write(byte[], int, int)` | Write bytes | Appends data to stream |
//! | `Stream.WriteByte(byte)` | Write single byte | Appends byte to stream |
//! | `Stream.get_Length` | Stream length | Returns actual length |
//! | `Stream.get_Position` | Current position | Returns current position |
//! | `Stream.set_Position` | Set position | Updates stream position |
//! | `Stream.Seek(long, SeekOrigin)` | Seek to position | Updates position based on origin |
//! | `Stream.SetLength(long)` | Set stream length | Truncates or extends stream |
//! | `Stream.CopyTo(Stream)` | Copy to another stream | Copies remaining data |
//! | `Stream.Flush()` | Flush stream | No-op |
//! | `Stream.Close()` | Close stream | No-op |
//! | `Stream.Dispose()` | Dispose stream | No-op |
//! | `Stream.get_CanRead` | Can read | Always true |
//! | `Stream.get_CanSeek` | Can seek | Always true |
//! | `Stream.get_CanWrite` | Can write | Always true |
//!
//! # Implementation Notes
//!
//! Stream data is stored in [`HeapObject::Stream`] which provides:
//!
//! - **Full data tracking**: Stream contents are stored and retrieved correctly
//! - **Position tracking**: Read position advances as data is consumed
//! - **Length tracking**: Actual data length is available
//! - **Write support**: `MemoryStream.Write` and `WriteByte` operations append data to streams
//!
//! [`HeapObject::Stream`]: crate::emulation::memory::HeapObject::Stream

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::{
            bcl::{
                crypto::{finish_crypto_stream, transform_stream_data},
                limits::buffer_range,
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    utils::{decompress_deflate, decompress_gzip},
    Result,
};

/// Registers all Stream and MemoryStream method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    // MemoryStream methods
    manager.register(
        Hook::new("System.IO.MemoryStream..ctor")
            .match_name("System.IO", "MemoryStream", ".ctor")
            .pre(memory_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Read")
            .match_name("System.IO", "MemoryStream", "Read")
            .pre(stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.ReadByte")
            .match_name("System.IO", "MemoryStream", "ReadByte")
            .pre(stream_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Write")
            .match_name("System.IO", "MemoryStream", "Write")
            .pre(stream_write_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.ToArray")
            .match_name("System.IO", "MemoryStream", "ToArray")
            .pre(memory_stream_to_array_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Length")
            .match_name("System.IO", "MemoryStream", "get_Length")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Position")
            .match_name("System.IO", "MemoryStream", "get_Position")
            .pre(stream_get_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.set_Position")
            .match_name("System.IO", "MemoryStream", "set_Position")
            .pre(stream_set_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.WriteByte")
            .match_name("System.IO", "MemoryStream", "WriteByte")
            .pre(stream_write_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Seek")
            .match_name("System.IO", "MemoryStream", "Seek")
            .pre(stream_seek_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.GetBuffer")
            .match_name("System.IO", "MemoryStream", "GetBuffer")
            .pre(memory_stream_get_buffer_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.SetLength")
            .match_name("System.IO", "MemoryStream", "SetLength")
            .pre(stream_set_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_Capacity")
            .match_name("System.IO", "MemoryStream", "get_Capacity")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.CopyTo")
            .match_name("System.IO", "MemoryStream", "CopyTo")
            .pre(stream_copy_to_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Flush")
            .match_name("System.IO", "MemoryStream", "Flush")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Close")
            .match_name("System.IO", "MemoryStream", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.Dispose")
            .match_name("System.IO", "MemoryStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanRead")
            .match_name("System.IO", "MemoryStream", "get_CanRead")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanSeek")
            .match_name("System.IO", "MemoryStream", "get_CanSeek")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.MemoryStream.get_CanWrite")
            .match_name("System.IO", "MemoryStream", "get_CanWrite")
            .pre(stream_can_true_pre),
    )?;

    // Stream base class methods
    manager.register(
        Hook::new("System.IO.Stream.Read")
            .match_name("System.IO", "Stream", "Read")
            .pre(stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.ReadByte")
            .match_name("System.IO", "Stream", "ReadByte")
            .pre(stream_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_Length")
            .match_name("System.IO", "Stream", "get_Length")
            .pre(stream_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_Position")
            .match_name("System.IO", "Stream", "get_Position")
            .pre(stream_get_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.set_Position")
            .match_name("System.IO", "Stream", "set_Position")
            .pre(stream_set_position_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Write")
            .match_name("System.IO", "Stream", "Write")
            .pre(stream_write_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.WriteByte")
            .match_name("System.IO", "Stream", "WriteByte")
            .pre(stream_write_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Seek")
            .match_name("System.IO", "Stream", "Seek")
            .pre(stream_seek_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.SetLength")
            .match_name("System.IO", "Stream", "SetLength")
            .pre(stream_set_length_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.CopyTo")
            .match_name("System.IO", "Stream", "CopyTo")
            .pre(stream_copy_to_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Flush")
            .match_name("System.IO", "Stream", "Flush")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Close")
            .match_name("System.IO", "Stream", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.Dispose")
            .match_name("System.IO", "Stream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanRead")
            .match_name("System.IO", "Stream", "get_CanRead")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanSeek")
            .match_name("System.IO", "Stream", "get_CanSeek")
            .pre(stream_can_true_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Stream.get_CanWrite")
            .match_name("System.IO", "Stream", "get_CanWrite")
            .pre(stream_can_true_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.MemoryStream..ctor` constructor.
///
/// # Handled Overloads
///
/// - `MemoryStream..ctor()` - Creates an empty stream
/// - `MemoryStream..ctor(Byte[])` - Creates a stream from byte array
///
/// # Parameters
///
/// - `buffer`: Optional byte array containing initial stream data
fn memory_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the byte array argument (may be None for empty stream)
    let data = if let Some(EmValue::ObjectRef(array_ref)) = ctx.args.first() {
        // Try get_byte_array first (for byte[] arrays with I32 elements)
        // Fall back to get_array_as_bytes which handles multi-byte element types
        // (e.g., uint[] arrays serialized to bytes in little-endian order)
        let primary = try_hook!(thread.heap().get_byte_array(*array_ref));
        if let Some(bytes) = primary {
            bytes
        } else {
            try_hook!(thread
                .heap()
                .get_array_as_bytes(*array_ref, ctx.pointer_size))
            .unwrap_or_default()
        }
    } else {
        Vec::new()
    };

    match ctx.this {
        Some(EmValue::ObjectRef(stream_ref)) => {
            // Instance call: replace the allocated object with a Stream
            try_hook!(thread.heap_mut().replace_with_stream(*stream_ref, data));
            PreHookResult::Bypass(None) // Constructor returns void
        }
        _ => {
            // Factory pattern: allocate a new Stream directly
            let type_token = thread.resolve_type_token("System.IO", "MemoryStream");
            match thread.heap_mut().alloc_stream(data, type_token) {
                Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
}

/// Hook for `System.IO.Stream.Read` and `System.IO.MemoryStream.Read` methods.
///
/// # Handled Overloads
///
/// - `Stream.Read(Byte[], Int32, Int32) -> Int32`
/// - `MemoryStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array to read into
/// - `offset`: Zero-based byte offset in buffer to begin storing data
/// - `count`: Maximum number of bytes to read
///
/// # Returns
///
/// Number of bytes actually read into the buffer
fn stream_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };
    let (buffer_ref, offset, count) =
        match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
            Ok(range) => range,
            Err(result) => return result,
        };

    // Read up to `count` bytes from the stream (advances position internally)
    let Some(bytes) = try_hook!(thread.heap().stream_read(stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let to_read = bytes.len();

    // Copy read bytes into the destination buffer array
    for (i, &byte) in bytes.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            offset.saturating_add(i),
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(to_read as i32)))
}

/// Hook for `System.IO.Stream.ReadByte` and `System.IO.MemoryStream.ReadByte` methods.
///
/// # Handled Overloads
///
/// - `Stream.ReadByte() -> Int32`
/// - `MemoryStream.ReadByte() -> Int32`
///
/// # Returns
///
/// The byte cast to `Int32`, or -1 if at end of stream
fn stream_read_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    // Read a single byte from the stream (advances position internally)
    let Some(byte) = try_hook!(thread.heap().stream_read_byte(stream_ref)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1))); // EOF or not a stream
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(byte))))
}

/// Hook for `System.IO.MemoryStream.Write` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.Write(Byte[], Int32, Int32) -> Void`
///
/// # Parameters
///
/// - `buffer`: Source byte array containing data to write
/// - `offset`: Zero-based byte offset in buffer from which to copy bytes
/// - `count`: Number of bytes to write
fn stream_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };
    let (buffer_ref, offset, count) =
        match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
            Ok(range) => range,
            Err(result) => return result,
        };
    let Some(buffer_data) = try_hook!(thread.heap().get_byte_array(buffer_ref)) else {
        return PreHookResult::Error("Stream.Write from an array that is no byte[]".to_string());
    };
    // In range: `buffer_range` checked it against the buffer's length
    let bytes_to_write = buffer_data
        .get(offset..offset.saturating_add(count))
        .unwrap_or_default();

    // Write to the stream
    try_hook!(thread
        .heap_mut()
        .write_to_stream(stream_ref, bytes_to_write));

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.ToArray` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.ToArray() -> Byte[]`
///
/// # Returns
///
/// A new byte array containing the stream contents
fn memory_stream_to_array_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            // Return empty byte array if no stream
            match thread.heap_mut().alloc_byte_array(&[]) {
                Ok(array_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    };

    // ToArray needs the full buffer — clone is unavoidable here
    let data = match try_hook!(thread.heap().get_stream_data(stream_ref)) {
        Some((data, _)) => data,
        None => Vec::new(),
    };

    // Allocate and return byte array
    match thread.heap_mut().alloc_byte_array(&data) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.Stream.get_Length` and `System.IO.MemoryStream.get_Length` properties.
///
/// # Handled Overloads
///
/// - `Stream.Length { get; } -> Int64`
/// - `MemoryStream.Length { get; } -> Int64`
///
/// # Returns
///
/// The length of the stream in bytes
fn stream_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get stream length without cloning data
    let length = try_hook!(thread.heap().stream_len(stream_ref)).unwrap_or(0);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(length as i64)))
}

/// Hook for `System.IO.MemoryStream.get_Position` property.
///
/// # Handled Overloads
///
/// - `MemoryStream.Position { get; } -> Int64`
///
/// # Returns
///
/// The current position within the stream
fn stream_get_position_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the stream reference
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get stream position without cloning data
    let position = try_hook!(thread.heap().stream_position(stream_ref)).unwrap_or(0);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(position as i64)))
}

/// The largest position and length a `MemoryStream` takes: `int.MaxValue`, its
/// `MemStreamMaxLength`.
const MEMORY_STREAM_MAX_LENGTH: i64 = i32::MAX as i64;

/// The `Int64` (or `Int32`) first argument of a stream method, or the emulation error for an
/// argument of another shape, which is no call the runtime makes.
fn int64_argument(ctx: &HookContext<'_>) -> std::result::Result<i64, PreHookResult> {
    match ctx.args.first() {
        Some(EmValue::I64(v)) => Ok(*v),
        Some(EmValue::I32(v)) => Ok(i64::from(*v)),
        other => Err(PreHookResult::Error(format!(
            "{}.{} with {other:?}, no int64",
            ctx.type_name, ctx.method_name
        ))),
    }
}

/// The stream a stream method is called on: a null `this` is the `NullReferenceException`
/// the runtime throws, a `this` of another shape an emulation error.
fn this_stream(ctx: &HookContext<'_>) -> std::result::Result<HeapRef, PreHookResult> {
    match ctx.this {
        Some(EmValue::ObjectRef(r)) => Ok(*r),
        Some(EmValue::Null) => Err(PreHookResult::throw_null_reference()),
        other => Err(PreHookResult::Error(format!(
            "{}.{} on {other:?}, no stream",
            ctx.type_name, ctx.method_name
        ))),
    }
}

/// Hook for `System.IO.MemoryStream.set_Position` property.
///
/// A position past the end is allowed, as the runtime allows it: the next write grows the
/// stream to it (within the heap's budget) and a read there reads nothing. A negative
/// position, or one past `int.MaxValue`, is the `ArgumentOutOfRangeException` the runtime
/// throws, rather than a cast to a position gigabytes long.
///
/// # Handled Overloads
///
/// - `MemoryStream.Position { set; }`
///
/// # Parameters
///
/// - `value`: The new position within the stream
fn stream_set_position_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (stream_ref, value) = match (this_stream(ctx), int64_argument(ctx)) {
        (Ok(stream_ref), Ok(value)) => (stream_ref, value),
        (Err(result), _) | (_, Err(result)) => return result,
    };
    let Some(new_pos) = usize::try_from(value)
        .ok()
        .filter(|_| value <= MEMORY_STREAM_MAX_LENGTH)
    else {
        return PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            message: format!("Position {value} is outside 0..={MEMORY_STREAM_MAX_LENGTH}"),
        };
    };
    try_hook!(thread.heap_mut().set_stream_position(stream_ref, new_pos));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.Seek` method.
///
/// Follows the runtime's `MemoryStream.Seek`: an offset past `int.MaxValue` is
/// `ArgumentOutOfRangeException`, a position before the beginning `IOException`, and an
/// origin other than Begin, Current or End `ArgumentException`. A position past the end is
/// allowed, not clamped to the length: the next write grows the stream to it.
///
/// # Handled Overloads
///
/// - `MemoryStream.Seek(Int64, SeekOrigin) -> Int64`
///
/// # Parameters
///
/// - `offset`: Byte offset relative to origin
/// - `origin`: Reference point (Begin=0, Current=1, End=2)
///
/// # Returns
///
/// The new position within the stream
fn stream_seek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (stream_ref, offset) = match (this_stream(ctx), int64_argument(ctx)) {
        (Ok(stream_ref), Ok(offset)) => (stream_ref, offset),
        (Err(result), _) | (_, Err(result)) => return result,
    };
    let Some(EmValue::I32(origin)) = ctx.args.get(1) else {
        return PreHookResult::Error(format!("{}.Seek without a SeekOrigin", ctx.type_name));
    };
    if offset > MEMORY_STREAM_MAX_LENGTH {
        return PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            message: format!("offset {offset} passes {MEMORY_STREAM_MAX_LENGTH}"),
        };
    }
    let Some(length) = try_hook!(thread.heap().stream_len(stream_ref)) else {
        return PreHookResult::Error(format!("{}.Seek on no emulated stream", ctx.type_name));
    };
    let current = try_hook!(thread.heap().stream_position(stream_ref)).unwrap_or(0);
    let base = match origin {
        0 => 0,
        1 => current,
        2 => length,
        _ => {
            return PreHookResult::Throw {
                exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
                message: format!("Invalid seek origin {origin}."),
            }
        }
    };
    // Positions and lengths stay within `int.MaxValue`, so they fit an i64
    let new_pos = i64::try_from(base)
        .unwrap_or(i64::MAX)
        .saturating_add(offset);
    let Ok(new_pos) = usize::try_from(new_pos) else {
        return PreHookResult::Throw {
            exception_type: synthetic_exception::IO_EXCEPTION,
            message: "An attempt was made to move the position before the beginning of the \
                      stream."
                .to_string(),
        };
    };
    try_hook!(thread.heap_mut().set_stream_position(stream_ref, new_pos));
    PreHookResult::Bypass(Some(EmValue::I64(
        i64::try_from(new_pos).unwrap_or(i64::MAX),
    )))
}

/// Hook for `System.IO.Stream.WriteByte` and `System.IO.MemoryStream.WriteByte` methods.
///
/// # Handled Overloads
///
/// - `Stream.WriteByte(Byte) -> Void`
/// - `MemoryStream.WriteByte(Byte) -> Void`
///
/// # Parameters
///
/// - `value`: The byte to write
fn stream_write_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let byte = match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as u8,
        _ => return PreHookResult::Bypass(None),
    };

    try_hook!(thread.heap_mut().write_to_stream(stream_ref, &[byte]));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.MemoryStream.GetBuffer` method.
///
/// # Handled Overloads
///
/// - `MemoryStream.GetBuffer() -> Byte[]`
///
/// # Returns
///
/// The internal byte array buffer of the stream
fn memory_stream_get_buffer_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Identical to ToArray — return all stream data as a byte array
    memory_stream_to_array_pre(ctx, thread)
}

/// Hook for `System.IO.Stream.SetLength` and `System.IO.MemoryStream.SetLength` methods.
///
/// # Handled Overloads
///
/// - `Stream.SetLength(Int64) -> Void`
/// - `MemoryStream.SetLength(Int64) -> Void`
///
/// # Parameters
///
/// - `value`: The new length of the stream
fn stream_set_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (stream_ref, value) = match (this_stream(ctx), int64_argument(ctx)) {
        (Ok(stream_ref), Ok(value)) => (stream_ref, value),
        (Err(result), _) | (_, Err(result)) => return result,
    };
    // As the runtime's `MemoryStream.SetLength`: a length outside `0..=int.MaxValue` is
    // `ArgumentOutOfRangeException`; growth within it is charged to the heap's budget
    let Some(new_length) = usize::try_from(value)
        .ok()
        .filter(|_| value <= MEMORY_STREAM_MAX_LENGTH)
    else {
        return PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            message: format!("length {value} is outside 0..={MEMORY_STREAM_MAX_LENGTH}"),
        };
    };

    try_hook!(thread.heap_mut().truncate_stream(stream_ref, new_length));
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.Stream.CopyTo` and `System.IO.MemoryStream.CopyTo` methods.
///
/// # Handled Overloads
///
/// - `Stream.CopyTo(Stream) -> Void`
/// - `Stream.CopyTo(Stream, Int32) -> Void`
/// - `MemoryStream.CopyTo(Stream) -> Void`
/// - `MemoryStream.CopyTo(Stream, Int32) -> Void`
///
/// # Parameters
///
/// - `destination`: The target stream to copy data to
/// - `bufferSize`: (optional) ignored
fn stream_copy_to_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let src_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let dst_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Plain `MemoryStream` / `Stream` source. Fast path that mirrors the
    // original CopyTo behavior — read remaining bytes, advance position.
    if let Some((data, position)) = try_hook!(thread.heap().get_stream_data(src_ref)) {
        if position < data.len() {
            let remaining: &[u8] = data.get(position..).unwrap_or(&[]);
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, remaining));
        }
        let len = data.len();
        try_hook!(thread.heap_mut().set_stream_position(src_ref, len));
        return PreHookResult::Bypass(None);
    }

    // `DeflateStream` / `GZipStream` source. Decompress the underlying
    // stream the same way `compressed_stream_read_pre` does, then drain
    // the cached buffer into the destination. Without this branch a CFF
    // dispatcher pattern like `MemoryStream(enc) -> DeflateStream ->
    // CopyTo(MemoryStream)` ends up writing nothing because the original
    // `get_stream_data` only matched `HeapObject::Stream`.
    if let Some((underlying, compression_type, _mode)) =
        try_hook!(thread.heap().get_compressed_stream_info(src_ref))
    {
        if !try_hook!(thread.heap().has_compressed_stream_data(src_ref)) {
            let Some((compressed_data, underlying_pos)) =
                try_hook!(thread.heap().get_stream_data(underlying))
            else {
                return PreHookResult::Bypass(None);
            };
            let effective: &[u8] = if underlying_pos < compressed_data.len() {
                compressed_data.get(underlying_pos..).unwrap_or(&[])
            } else {
                &[]
            };
            let decompressed = match compression_type {
                0 => decompress_deflate(effective).ok(),
                1 => decompress_gzip(effective).ok(),
                _ => None,
            };
            try_hook!(thread
                .heap()
                .set_compressed_stream_data(src_ref, decompressed.unwrap_or_default()));
        }
        let Some(bytes) = try_hook!(thread.heap().read_compressed_stream(src_ref, usize::MAX))
        else {
            return PreHookResult::Bypass(None);
        };
        if !bytes.is_empty() {
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, &bytes));
        }
        return PreHookResult::Bypass(None);
    }

    // `CryptoStream` source. Lazily transform the underlying buffer once,
    // then drain. Mirrors `crypto_stream_read_pre` so behaviour matches
    // whether the caller does `CopyTo` or repeated `Read`s.
    if let Some((underlying, transform, _mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(src_ref))
    {
        if try_hook!(thread.heap().get_crypto_stream_transformed(src_ref)).is_none() {
            let Some((stream_data, underlying_pos)) =
                try_hook!(thread.heap().get_stream_data(underlying))
            else {
                return PreHookResult::Bypass(None);
            };
            let effective: &[u8] = if underlying_pos < stream_data.len() {
                stream_data.get(underlying_pos..).unwrap_or(&[])
            } else {
                &[]
            };
            let effective = effective.to_vec();
            let transformed = match transform_stream_data(thread, transform, &effective) {
                Ok(transformed) => transformed,
                Err(result) => return result,
            };
            try_hook!(thread
                .heap()
                .set_crypto_stream_transformed(src_ref, transformed));
        }
        let Some(bytes) = try_hook!(thread.heap().read_crypto_stream(src_ref, usize::MAX)) else {
            return PreHookResult::Bypass(None);
        };
        if !bytes.is_empty() {
            try_hook!(thread.heap_mut().write_to_stream(dst_ref, &bytes));
        }
        return PreHookResult::Bypass(None);
    }

    // Unknown stream subclass — leave the destination untouched rather
    // than guess at a backing store.
    PreHookResult::Bypass(None)
}

/// Hook for `Stream.get_CanRead`, `Stream.get_CanSeek`, `Stream.get_CanWrite` properties.
///
/// Emulated streams always support all operations.
pub fn stream_can_true_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `System.IO.Stream.Close`, `Stream.Dispose`, `IDisposable.Dispose` and the
/// `Close` and `Dispose` methods of the other streams, readers and writers.
///
/// # Handled Overloads
///
/// - `Stream.Close() -> Void`
/// - `Stream.Dispose() -> Void`
/// - `IDisposable.Dispose() -> Void`
///
/// # Implementation Note
///
/// Emulated objects hold nothing to release, but closing or disposing a CryptoStream
/// completes it, as the runtime's `Close` (which disposes) and `CryptoStream.Dispose` do: the
/// final block is flushed unless `FlushFinalBlock` did, so a CryptoStream written in a
/// `using` block, or closed, without `FlushFinalBlock` still writes its last (padded) block,
/// as [`finish_crypto_stream`] does. Disposing it again does nothing.
pub fn stream_dispose_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(object)) = ctx.this {
        if let Err(result) = finish_crypto_stream(thread, *object, false) {
            return result;
        }
    }
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            engine::synthetic_exception,
            runtime::{
                bcl::io::stream::{
                    memory_stream_ctor_pre, memory_stream_to_array_pre, stream_dispose_pre,
                    stream_get_length_pre, stream_get_position_pre, stream_read_byte_pre,
                    stream_seek_pre, stream_set_length_pre, stream_set_position_pre,
                    stream_write_pre,
                },
                hook::{HookContext, HookManager, PreHookResult},
            },
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        super::register(&manager).unwrap();
        assert_eq!(manager.len(), 36);
    }

    #[test]
    fn test_stream_close_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "Close",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = stream_dispose_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(None) => {}
            _ => panic!("Expected Bypass(None)"),
        }
    }

    #[test]
    fn test_stream_read_byte_eof_without_stream() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        );

        let mut thread = create_test_thread();
        let result = stream_read_byte_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(-1))) => {}
            _ => panic!("Expected Bypass with I32(-1) for EOF"),
        }
    }

    #[test]
    fn test_stream_read_byte_with_data() {
        let mut thread = create_test_thread();

        // Create a stream with test data
        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        // Read first byte
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        // Read second byte
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(2)))
        ));

        // Read remaining bytes
        for expected in [3, 4, 5] {
            let result = stream_read_byte_pre(&ctx, &mut thread);
            assert!(
                matches!(result, PreHookResult::Bypass(Some(EmValue::I32(v))) if v == expected)
            );
        }

        // After all bytes, should return EOF
        let result = stream_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_stream_get_length_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = stream_get_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(5)))
        ));
    }

    #[test]
    fn test_stream_get_position_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let get_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "get_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let read_byte_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        // Initial position is 0
        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0)))
        ));

        // Read a byte, position should advance
        stream_read_byte_pre(&read_byte_ctx, &mut thread);

        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(1)))
        ));
    }

    #[test]
    fn test_stream_set_position_hook() {
        let mut thread = create_test_thread();

        let data = vec![1, 2, 3, 4, 5];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let args = [EmValue::I64(3)];
        let set_pos_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "set_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        // Set position to 3
        stream_set_position_pre(&set_pos_ctx, &mut thread);

        // Verify position
        let get_pos_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "Stream",
            "get_Position",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_get_position_pre(&get_pos_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(3)))
        ));

        // Read byte at position 3 (value should be 4)
        let read_byte_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "Stream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_byte_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));
    }

    #[test]
    fn test_memory_stream_to_array_hook() {
        let mut thread = create_test_thread();

        let data = vec![10, 20, 30];
        let stream_ref = thread.heap_mut().alloc_stream(data.clone(), None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            "ToArray",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = memory_stream_to_array_pre(&ctx, &mut thread);

        // Verify we get an array back
        let array_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        // Verify array contents
        let retrieved = thread.heap().get_byte_array(array_ref).unwrap().unwrap();
        assert_eq!(retrieved.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn test_memory_stream_ctor_hook() {
        let mut thread = create_test_thread();

        // Create source byte array
        let data = vec![1, 2, 3, 4, 5];
        let array_ref = thread.heap_mut().alloc_byte_array(&data).unwrap();

        // Call constructor (factory pattern)
        let args = [EmValue::ObjectRef(array_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = memory_stream_ctor_pre(&ctx, &mut thread);

        let stream_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        // Verify stream has correct length
        let this = EmValue::ObjectRef(stream_ref);
        let length_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "MemoryStream",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = stream_get_length_pre(&length_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(5)))
        ));

        // Verify we can read data
        let read_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "MemoryStream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_stream_seek_hook() {
        let mut thread = create_test_thread();

        let data = vec![10, 20, 30, 40, 50];
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        let this = EmValue::ObjectRef(stream_ref);

        // Seek to position 2 from beginning (origin = 0)
        let args = [EmValue::I64(2), EmValue::I32(0)];
        let seek_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            "Seek",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = stream_seek_pre(&seek_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(2)))
        ));

        // Read byte at position 2 (value should be 30)
        let read_ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "MemoryStream",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(30)))
        ));

        // Seek to end (origin = 2) with offset -1
        let args = [EmValue::I64(-1), EmValue::I32(2)];
        let seek_ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "MemoryStream",
            "Seek",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = stream_seek_pre(&seek_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(4)))
        ));

        // Read last byte (value should be 50)
        let result = stream_read_byte_pre(&read_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(50)))
        ));
    }

    /// A call of `MemoryStream.method` on `this` with `args`.
    fn stream_call<'a>(method: &'a str, this: &'a EmValue, args: &'a [EmValue]) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "MemoryStream",
            method,
            PointerSize::Bit64,
        )
        .with_this(Some(this))
        .with_args(args)
    }

    fn throws(result: &PreHookResult, expected: Token) -> bool {
        matches!(result, PreHookResult::Throw { exception_type, .. } if *exception_type == expected)
    }

    /// Positions follow the runtime's `MemoryStream`: negative or past `int.MaxValue` is
    /// `ArgumentOutOfRangeException`, a seek before the beginning `IOException`, an unknown
    /// origin `ArgumentException`, and a seek past the end is kept, not clamped.
    #[test]
    fn stream_positions_follow_the_runtime() {
        let mut thread = create_test_thread();
        let stream_ref = thread
            .heap()
            .alloc_stream(vec![1, 2, 3, 4, 5], None)
            .unwrap();
        let this = EmValue::ObjectRef(stream_ref);
        let range = synthetic_exception::ARGUMENT_OUT_OF_RANGE;
        for value in [-1, 0x7FFF_FFFF_FFFF] {
            let args = [EmValue::I64(value)];
            let ctx = stream_call("set_Position", &this, &args);
            assert!(throws(&stream_set_position_pre(&ctx, &mut thread), range));
            let ctx = stream_call("SetLength", &this, &args);
            assert!(throws(&stream_set_length_pre(&ctx, &mut thread), range));
        }
        let seek = |thread: &mut _, offset: i64, origin: i32| {
            let args = [EmValue::I64(offset), EmValue::I32(origin)];
            stream_seek_pre(&stream_call("Seek", &this, &args), thread)
        };
        assert!(matches!(
            seek(&mut thread, 10, 2),
            PreHookResult::Bypass(Some(EmValue::I64(15)))
        ));
        assert!(throws(
            &seek(&mut thread, -1, 0),
            synthetic_exception::IO_EXCEPTION
        ));
        assert!(throws(
            &seek(&mut thread, -16, 1),
            synthetic_exception::IO_EXCEPTION
        ));
        assert!(throws(
            &seek(&mut thread, 0, 3),
            synthetic_exception::ARGUMENT_EXCEPTION
        ));
        assert!(throws(&seek(&mut thread, 0x8000_0000, 0), range));
        assert_eq!(
            thread.heap().stream_position(stream_ref).unwrap(),
            Some(15),
            "a refused seek leaves the position where it was"
        );
    }

    /// A position set far past the end makes the next write grow the stream to it: within
    /// the heap's budget, so a write at `int.MaxValue` fails as an emulation error instead of
    /// resizing the stream to gigabytes, and the stream is left as it was.
    #[test]
    fn a_write_far_past_the_end_fails_within_the_budget() {
        let mut thread = create_test_thread();
        let stream_ref = thread.heap().alloc_stream(vec![1, 2, 3], None).unwrap();
        let this = EmValue::ObjectRef(stream_ref);
        let args = [EmValue::I64(i64::from(i32::MAX))];
        assert!(matches!(
            stream_set_position_pre(&stream_call("set_Position", &this, &args), &mut thread),
            PreHookResult::Bypass(None)
        ));
        let buffer = thread.heap().alloc_byte_array(&[9]).unwrap();
        let args = [EmValue::ObjectRef(buffer), EmValue::I32(0), EmValue::I32(1)];
        assert!(matches!(
            stream_write_pre(&stream_call("Write", &this, &args), &mut thread),
            PreHookResult::Error(_)
        ));
        assert_eq!(thread.heap().stream_len(stream_ref).unwrap(), Some(3));

        // Within the budget, the gap a position past the end leaves is zero-filled
        let args = [EmValue::I64(5)];
        stream_set_position_pre(&stream_call("set_Position", &this, &args), &mut thread);
        let args = [EmValue::ObjectRef(buffer), EmValue::I32(0), EmValue::I32(1)];
        stream_write_pre(&stream_call("Write", &this, &args), &mut thread);
        assert_eq!(
            thread
                .heap()
                .get_stream_data(stream_ref)
                .unwrap()
                .unwrap()
                .0,
            vec![1, 2, 3, 0, 0, 9]
        );
    }
}

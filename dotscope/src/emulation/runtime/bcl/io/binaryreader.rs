//! `System.IO.BinaryReader` method hooks.
//!
//! This module provides hook implementations for BinaryReader, which is used by
//! obfuscators for reading structured data from encrypted blobs (tokens, lengths,
//! offsets). BinaryReader wraps an underlying stream and provides typed read methods.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `BinaryReader..ctor(Stream)` | Create reader | Stores stream reference in synthetic field |
//! | `BinaryReader.get_BaseStream` | Get underlying stream | Returns stored stream reference |
//! | `BinaryReader.Read()` | Read single char | UTF-8 decoded char as int, -1 on EOF |
//! | `BinaryReader.Read(byte[], int, int)` | Read into buffer | Copies bytes into array |
//! | `BinaryReader.ReadBoolean()` | Read boolean | 1 byte, nonzero = true |
//! | `BinaryReader.ReadByte()` | Read byte | 1 byte unsigned |
//! | `BinaryReader.ReadSByte()` | Read signed byte | 1 byte signed |
//! | `BinaryReader.ReadBytes(int)` | Read byte array | Reads from stream, advances position |
//! | `BinaryReader.ReadChar()` | Read character | UTF-8 decoded char |
//! | `BinaryReader.ReadChars(int)` | Read character array | UTF-8 decoded characters |
//! | `BinaryReader.ReadInt16()` | Read 16-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt16()` | Read unsigned 16-bit | Reads little-endian from stream |
//! | `BinaryReader.ReadInt32()` | Read 32-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt32()` | Read unsigned 32-bit | Reads little-endian, bit pattern preserved |
//! | `BinaryReader.ReadInt64()` | Read 64-bit int | Reads little-endian from stream |
//! | `BinaryReader.ReadUInt64()` | Read unsigned 64-bit | Reads little-endian, bit pattern preserved |
//! | `BinaryReader.ReadSingle()` | Read float | 4 bytes IEEE 754 |
//! | `BinaryReader.ReadDouble()` | Read double | 8 bytes IEEE 754 |
//! | `BinaryReader.ReadDecimal()` | Read decimal | 16 bytes, approximated as f64 |
//! | `BinaryReader.ReadString()` | Read length-prefixed string | Reads 7-bit length + UTF-8 bytes |
//! | `BinaryReader.Read7BitEncodedInt()` | Read LEB128 int | Variable-length 32-bit integer |
//! | `BinaryReader.PeekChar()` | Peek next char | Returns char without advancing |
//! | `BinaryReader.Close()` | Close reader | No-op |
//! | `BinaryReader.Dispose()` | Dispose reader | No-op |

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::{
            bcl::{
                io::stream::stream_dispose_pre,
                limits::{buffer_range, checked_len, MAX_HOOK_BUFFER},
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        tokens::io_fields,
        EmValue, HeapRef,
    },
    metadata::typesystem::CilFlavor,
    Result,
};

/// Helper function to get the underlying stream reference from a BinaryReader.
fn get_binary_reader_stream(reader_ref: HeapRef, thread: &EmulationThread) -> Option<HeapRef> {
    let field_value = thread
        .heap()
        .get_field(reader_ref, io_fields::BINARY_READER_STREAM)
        .ok()?;
    match field_value {
        EmValue::ObjectRef(stream_ref) => Some(stream_ref),
        _ => None,
    }
}

/// Registers all BinaryReader method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.IO.BinaryReader..ctor")
            .match_name("System.IO", "BinaryReader", ".ctor")
            .pre(binary_reader_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.get_BaseStream")
            .match_name("System.IO", "BinaryReader", "get_BaseStream")
            .pre(binary_reader_get_base_stream_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.Read")
            .match_name("System.IO", "BinaryReader", "Read")
            .pre(binary_reader_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadBoolean")
            .match_name("System.IO", "BinaryReader", "ReadBoolean")
            .pre(binary_reader_read_boolean_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadByte")
            .match_name("System.IO", "BinaryReader", "ReadByte")
            .pre(binary_reader_read_byte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadSByte")
            .match_name("System.IO", "BinaryReader", "ReadSByte")
            .pre(binary_reader_read_sbyte_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadBytes")
            .match_name("System.IO", "BinaryReader", "ReadBytes")
            .pre(binary_reader_read_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadChar")
            .match_name("System.IO", "BinaryReader", "ReadChar")
            .pre(binary_reader_read_char_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadChars")
            .match_name("System.IO", "BinaryReader", "ReadChars")
            .pre(binary_reader_read_chars_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt16")
            .match_name("System.IO", "BinaryReader", "ReadInt16")
            .pre(binary_reader_read_int16_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt16")
            .match_name("System.IO", "BinaryReader", "ReadUInt16")
            .pre(binary_reader_read_uint16_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt32")
            .match_name("System.IO", "BinaryReader", "ReadInt32")
            .pre(binary_reader_read_int32_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt32")
            .match_name("System.IO", "BinaryReader", "ReadUInt32")
            .pre(binary_reader_read_uint32_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadInt64")
            .match_name("System.IO", "BinaryReader", "ReadInt64")
            .pre(binary_reader_read_int64_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadUInt64")
            .match_name("System.IO", "BinaryReader", "ReadUInt64")
            .pre(binary_reader_read_uint64_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadSingle")
            .match_name("System.IO", "BinaryReader", "ReadSingle")
            .pre(binary_reader_read_single_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadDouble")
            .match_name("System.IO", "BinaryReader", "ReadDouble")
            .pre(binary_reader_read_double_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadDecimal")
            .match_name("System.IO", "BinaryReader", "ReadDecimal")
            .pre(binary_reader_read_decimal_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.ReadString")
            .match_name("System.IO", "BinaryReader", "ReadString")
            .pre(binary_reader_read_string_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.Read7BitEncodedInt")
            .match_name("System.IO", "BinaryReader", "Read7BitEncodedInt")
            .pre(binary_reader_read_7bit_encoded_int_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.PeekChar")
            .match_name("System.IO", "BinaryReader", "PeekChar")
            .pre(binary_reader_peek_char_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.Close")
            .match_name("System.IO", "BinaryReader", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.BinaryReader.Dispose")
            .match_name("System.IO", "BinaryReader", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.BinaryReader..ctor` constructor.
///
/// # Handled Overloads
///
/// - `BinaryReader..ctor(Stream)`
///
/// # Parameters
///
/// - `input`: The underlying stream to read from
fn binary_reader_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the stream argument
    let stream_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::Bypass(None);
        }
    };

    // Store the stream reference in the BinaryReader's field
    try_hook!(thread.heap_mut().set_field(
        reader_ref,
        io_fields::BINARY_READER_STREAM,
        EmValue::ObjectRef(stream_ref),
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.BinaryReader.get_BaseStream` property.
///
/// # Handled Overloads
///
/// - `BinaryReader.BaseStream { get; } -> Stream`
///
/// # Returns
///
/// The underlying stream reference stored during construction
fn binary_reader_get_base_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::Bypass(Some(EmValue::Null));
        }
    };

    match get_binary_reader_stream(reader_ref, thread) {
        Some(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        None => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.IO.BinaryReader.ReadByte` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadByte() -> Byte`
///
/// # Returns
///
/// The next byte read from the underlying stream
fn binary_reader_read_byte_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read one byte and advance position
    let Some(byte) = try_hook!(thread.heap().stream_read_byte(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(byte))))
}

/// Hook for `System.IO.BinaryReader.ReadBytes` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `count`: Number of bytes to read
///
/// # Returns
///
/// A byte array containing the requested bytes
fn binary_reader_read_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let count = match ctx.args.first() {
        Some(EmValue::I32(v)) => {
            match checked_len(*v, MAX_HOOK_BUFFER, "BinaryReader.ReadBytes", "count") {
                Ok(n) => n,
                Err(result) => return result,
            }
        }
        _ => 0,
    };

    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_object_disposed(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_object_disposed();
    };

    // Read up to `count` bytes and advance position
    let Some(bytes) = try_hook!(thread.heap().stream_read(stream_ref, count)) else {
        return PreHookResult::throw_object_disposed();
    };

    match thread.heap_mut().alloc_byte_array(&bytes) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.BinaryReader.ReadInt16` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt16() -> Int16`
///
/// # Returns
///
/// A 2-byte signed integer read in little-endian format
fn binary_reader_read_int16_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read 2 bytes and advance position
    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<2>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = i16::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadInt32` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt32() -> Int32`
///
/// # Returns
///
/// A 4-byte signed integer read in little-endian format
fn binary_reader_read_int32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read 4 bytes and advance position
    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<4>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = i32::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadInt64` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadInt64() -> Int64`
///
/// # Returns
///
/// An 8-byte signed integer read in little-endian format
fn binary_reader_read_int64_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read 8 bytes and advance position
    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<8>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = i64::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.IO.BinaryReader.ReadString` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadString() -> String`
///
/// # Returns
///
/// A string read using 7-bit encoded length prefix followed by UTF-8 bytes
fn binary_reader_read_string_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Get the BinaryReader object reference
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    // Get the underlying stream
    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read 7-bit encoded length then string bytes, all under a single lock
    let Some(result) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        // Read 7-bit encoded length (LEB128-style)
        let mut length: usize = 0;
        let mut shift: u32 = 0;
        loop {
            let &byte = data.get(*position)?;
            *position = position.saturating_add(1);
            length |= ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift = shift.saturating_add(7);
            // Prevent infinite loop on malformed data
            if shift > 35 {
                break;
            }
        }

        // Read the string bytes — return None if not enough data
        let end = position.checked_add(length)?;
        let slice = data.get(*position..end)?;
        let s = String::from_utf8_lossy(slice).into_owned();
        *position = end;
        Some(s)
    })) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(s) = result else {
        return PreHookResult::throw_end_of_stream();
    };

    match thread.heap_mut().alloc_string(&s) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.BinaryReader.Read` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.Read() -> Int32` — reads a single character, returns its code point or -1 on EOF
/// - `BinaryReader.Read(Byte[], Int32, Int32) -> Int32` — reads bytes into a buffer
///
/// # Returns
///
/// For the no-arg overload: the character code point, or -1 on EOF.
/// For the buffer overload: the number of bytes actually read.
fn binary_reader_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_object_disposed(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_object_disposed();
    };

    // Dispatch based on argument count
    match ctx.args.len() {
        // Read() — single character as int, or -1 on EOF
        0 => {
            let Some(result) =
                try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
                    let Some(remaining) = data.get(*position..) else {
                        return -1_i32;
                    };
                    if remaining.is_empty() {
                        return -1_i32;
                    }

                    // Read a single UTF-8 character
                    let s = String::from_utf8_lossy(remaining);
                    if let Some(ch) = s.chars().next() {
                        *position = position.saturating_add(ch.len_utf8());
                        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                        {
                            ch as i32
                        }
                    } else {
                        -1_i32
                    }
                }))
            else {
                return PreHookResult::Bypass(Some(EmValue::I32(-1)));
            };

            PreHookResult::Bypass(Some(EmValue::I32(result)))
        }
        // Read(byte[], int, int) — buffer read
        3 => {
            // `BinaryReader` throws `ArgumentException` for a range past the buffer's end
            let (buffer_ref, offset, count) =
                match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_EXCEPTION) {
                    Ok(range) => range,
                    Err(result) => return result,
                };

            let Some(bytes) = try_hook!(thread.heap().stream_read(stream_ref, count)) else {
                return PreHookResult::Bypass(Some(EmValue::I32(0)));
            };

            for (i, &byte) in bytes.iter().enumerate() {
                let Some(idx) = offset.checked_add(i) else {
                    break;
                };
                try_hook!(thread.heap_mut().set_array_element(
                    buffer_ref,
                    idx,
                    EmValue::I32(i32::from(byte)),
                ));
            }

            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
        }
        _ => PreHookResult::Bypass(Some(EmValue::I32(0))),
    }
}

/// Hook for `System.IO.BinaryReader.ReadBoolean` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadBoolean() -> Boolean`
///
/// # Returns
///
/// `true` (1) if the byte is nonzero, `false` (0) otherwise
fn binary_reader_read_boolean_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(byte) = try_hook!(thread.heap().stream_read_byte(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = if byte != 0 { 1 } else { 0 };

    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadSByte` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadSByte() -> SByte`
///
/// # Returns
///
/// A signed byte (-128 to 127) widened to I32
fn binary_reader_read_sbyte_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(byte) = try_hook!(thread.heap().stream_read_byte(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = byte as i8;

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadChar` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadChar() -> Char`
///
/// # Returns
///
/// A single UTF-8 decoded character widened to I32
fn binary_reader_read_char_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(result) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        let remaining = data.get(*position..)?;
        if remaining.is_empty() {
            return None;
        }

        // Decode one UTF-8 character from the stream
        let s = String::from_utf8_lossy(remaining);
        if let Some(ch) = s.chars().next() {
            *position = position.saturating_add(ch.len_utf8());
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            Some(ch as i32)
        } else {
            None
        }
    })) else {
        return PreHookResult::throw_end_of_stream();
    };

    match result {
        Some(ch) => PreHookResult::Bypass(Some(EmValue::I32(ch))),
        None => PreHookResult::Bypass(Some(EmValue::I32(0))),
    }
}

/// Hook for `System.IO.BinaryReader.ReadChars` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadChars(Int32) -> Char[]`
///
/// # Parameters
///
/// - `count`: Number of characters to read
///
/// # Returns
///
/// An array of characters
fn binary_reader_read_chars_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let count = match ctx.args.first() {
        Some(EmValue::I32(v)) => {
            match checked_len(*v, MAX_HOOK_BUFFER, "BinaryReader.ReadChars", "count") {
                Ok(n) => n,
                Err(result) => return result,
            }
        }
        _ => 0,
    };

    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_object_disposed(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_object_disposed();
    };

    let Some(chars) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        // Reserve for what the stream can actually supply, not for what was asked. One char
        // needs at least one byte, so the remaining byte count is a hard upper bound on the
        // number of chars this call can return.
        let available = data.len().saturating_sub(*position);
        let mut chars = Vec::with_capacity(count.min(available));

        for _ in 0..count {
            let Some(remaining) = data.get(*position..) else {
                break;
            };
            if remaining.is_empty() {
                break;
            }

            // Decode a single scalar from the front of the slice. Running
            // `String::from_utf8_lossy` over the whole remainder on each iteration would
            // re-scan and re-allocate the entire stream tail per character, making this loop
            // quadratic in stream length.
            let mut decoded = None;
            let window = remaining.len().min(4);
            for take in 1..=window {
                let Some(prefix) = remaining.get(..take) else {
                    break;
                };
                if let Ok(valid) = std::str::from_utf8(prefix) {
                    if let Some(ch) = valid.chars().next() {
                        decoded = Some((ch, take));
                        break;
                    }
                }
            }

            match decoded {
                Some((ch, len)) => {
                    chars.push(ch);
                    *position = position.saturating_add(len);
                }
                // Not a valid scalar in any 1..=4 byte prefix: substitute and advance one
                // byte, matching `from_utf8_lossy`'s behaviour without its cost.
                None => {
                    chars.push(char::REPLACEMENT_CHARACTER);
                    *position = position.saturating_add(1);
                }
            }
        }
        chars
    })) else {
        return PreHookResult::throw_object_disposed();
    };

    alloc_char_array_result(thread, &chars)
}

/// Allocates a Char[] array on the heap and returns it as a `PreHookResult`.
fn alloc_char_array_result(thread: &mut EmulationThread, chars: &[char]) -> PreHookResult {
    let elements: Vec<EmValue> = chars
        .iter()
        .map(|&c| {
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            EmValue::I32(c as i32)
        })
        .collect();
    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Char, elements)
    {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.BinaryReader.ReadUInt16` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt16() -> UInt16`
///
/// # Returns
///
/// A 2-byte unsigned integer read in little-endian format, widened to I32
fn binary_reader_read_uint16_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<2>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = u16::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(value))))
}

/// Hook for `System.IO.BinaryReader.ReadUInt32` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt32() -> UInt32`
///
/// # Returns
///
/// A 4-byte unsigned integer read in little-endian format, stored as I32
/// (bit pattern preserved, as per CLI spec where uint32 maps to I32 on the stack)
fn binary_reader_read_uint32_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<4>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Read as u32 and reinterpret as i32 (bit pattern preserved per CLI spec)
    let value = u32::from_le_bytes(bytes);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I32(value as i32)))
}

/// Hook for `System.IO.BinaryReader.ReadUInt64` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadUInt64() -> UInt64`
///
/// # Returns
///
/// An 8-byte unsigned integer read in little-endian format, stored as I64
/// (bit pattern preserved, as per CLI spec where uint64 maps to I64 on the stack)
fn binary_reader_read_uint64_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<8>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = u64::from_le_bytes(bytes);

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::I64(value as i64)))
}

/// Hook for `System.IO.BinaryReader.ReadSingle` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadSingle() -> Single`
///
/// # Returns
///
/// A 4-byte IEEE 754 single-precision floating point value
fn binary_reader_read_single_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<4>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = f32::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::F32(value)))
}

/// Hook for `System.IO.BinaryReader.ReadDouble` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadDouble() -> Double`
///
/// # Returns
///
/// An 8-byte IEEE 754 double-precision floating point value
fn binary_reader_read_double_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<8>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    let value = f64::from_le_bytes(bytes);

    PreHookResult::Bypass(Some(EmValue::F64(value)))
}

/// Hook for `System.IO.BinaryReader.ReadDecimal` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.ReadDecimal() -> Decimal`
///
/// # Returns
///
/// A 16-byte Decimal value. Since the emulator does not have a native Decimal type,
/// we read the 16 bytes and reconstruct it as an f64 approximation using the .NET
/// Decimal binary format: bytes 0-3 = lo, 4-7 = mid, 8-11 = hi, 12-15 = flags.
fn binary_reader_read_decimal_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    let Some(bytes) = try_hook!(thread.heap().stream_read_exact::<16>(stream_ref)) else {
        return PreHookResult::throw_end_of_stream();
    };

    // .NET Decimal binary layout (BinaryReader order):
    // bytes 0-3:   lo (Int32)
    // bytes 4-7:   mid (Int32)
    // bytes 8-11:  hi (Int32)
    // bytes 12-15: flags (sign in bit 31, scale in bits 16-23)
    let lo = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mid = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let hi = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let flags = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

    let negative = (flags & 0x8000_0000) != 0;
    let scale = (flags >> 16) & 0xFF;

    // Reconstruct the 96-bit integer mantissa as f64
    let mantissa = f64::from(lo)
        + f64::from(mid) * 4_294_967_296.0
        + f64::from(hi) * 18_446_744_073_709_551_616.0;
    let divisor = 10_f64.powi(scale as i32);
    let value = if negative {
        -mantissa / divisor
    } else {
        mantissa / divisor
    };

    PreHookResult::Bypass(Some(EmValue::F64(value)))
}

/// Hook for `System.IO.BinaryReader.Read7BitEncodedInt` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.Read7BitEncodedInt() -> Int32`
///
/// # Returns
///
/// A 32-bit integer decoded from 7-bit encoded (LEB128-style) format
fn binary_reader_read_7bit_encoded_int_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::throw_end_of_stream(),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::throw_end_of_stream();
    };

    // Represents the three possible outcomes of reading a 7-bit encoded int
    enum Read7BitResult {
        Ok(u32),
        EndOfStream,
        FormatError,
    }

    let Some(result) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        if *position >= data.len() {
            return Read7BitResult::EndOfStream;
        }

        let mut value: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            if shift > 35 {
                // .NET throws FormatException for too many bytes
                return Read7BitResult::FormatError;
            }
            let Some(&byte) = data.get(*position) else {
                return Read7BitResult::EndOfStream;
            };
            *position = position.saturating_add(1);
            value |= u32::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift = shift.saturating_add(7);
        }
        Read7BitResult::Ok(value)
    })) else {
        return PreHookResult::throw_end_of_stream();
    };

    match result {
        Read7BitResult::Ok(value) =>
        {
            #[allow(clippy::cast_possible_wrap)]
            PreHookResult::Bypass(Some(EmValue::I32(value as i32)))
        }
        Read7BitResult::EndOfStream => PreHookResult::throw_end_of_stream(),
        Read7BitResult::FormatError => PreHookResult::throw_format_exception(),
    }
}

/// Hook for `System.IO.BinaryReader.PeekChar` method.
///
/// # Handled Overloads
///
/// - `BinaryReader.PeekChar() -> Int32`
///
/// # Returns
///
/// The next character without advancing the stream, or -1 on EOF
fn binary_reader_peek_char_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let reader_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let Some(stream_ref) = get_binary_reader_stream(reader_ref, thread) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    // Peek without advancing position
    let Some(result) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        let Some(remaining) = data.get(*position..) else {
            return -1_i32;
        };
        if remaining.is_empty() {
            return -1_i32;
        }

        // Decode one UTF-8 character without advancing position
        let s = String::from_utf8_lossy(remaining);
        if let Some(ch) = s.chars().next() {
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            {
                ch as i32
            }
        } else {
            -1_i32
        }
    })) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    PreHookResult::Bypass(Some(EmValue::I32(result)))
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::{
                bcl::io::binaryreader::{
                    binary_reader_ctor_pre, binary_reader_read_byte_pre,
                    binary_reader_read_bytes_pre, binary_reader_read_int16_pre,
                    binary_reader_read_int32_pre, binary_reader_read_int64_pre,
                    binary_reader_read_string_pre,
                },
                hook::{HookContext, HookManager, PreHookResult},
            },
            thread::EmulationThread,
            EmValue, HeapRef,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    /// Helper to create a BinaryReader backed by a stream with the given data.
    fn create_binary_reader(thread: &mut EmulationThread, data: Vec<u8>) -> HeapRef {
        // Create the stream
        let stream_ref = thread.heap_mut().alloc_stream(data, None).unwrap();

        // Create an empty object for the BinaryReader
        let reader_token = Token::new(0x0200_0001); // Dummy type token
        let reader_ref = thread.heap_mut().alloc_object(reader_token).unwrap();

        // Call constructor to store the stream reference
        let this = EmValue::ObjectRef(reader_ref);
        let args = [EmValue::ObjectRef(stream_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        binary_reader_ctor_pre(&ctx, thread);

        reader_ref
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        super::register(&manager).unwrap();
        assert_eq!(manager.len(), 23);
    }

    #[test]
    fn test_binary_reader_read_byte_from_stream() {
        let mut thread = create_test_thread();
        let reader_ref = create_binary_reader(&mut thread, vec![0x42, 0x55, 0x88]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        // Read first byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x42)))
        ));

        // Read second byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x55)))
        ));

        // Read third byte
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x88)))
        ));
    }

    #[test]
    fn test_binary_reader_read_bytes_from_stream() {
        let mut thread = create_test_thread();
        let reader_ref = create_binary_reader(&mut thread, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let this = EmValue::ObjectRef(reader_ref);
        let args = [EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadBytes",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = binary_reader_read_bytes_pre(&ctx, &mut thread);

        let array_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        let bytes = thread.heap().get_byte_array(array_ref).unwrap().unwrap();
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_binary_reader_read_int16() {
        let mut thread = create_test_thread();
        // Little-endian: 0x1234 = [0x34, 0x12]
        let reader_ref = create_binary_reader(&mut thread, vec![0x34, 0x12]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt16",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int16_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x1234)))
        ));
    }

    #[test]
    fn test_binary_reader_read_int32() {
        let mut thread = create_test_thread();
        // Little-endian: 0x12345678 = [0x78, 0x56, 0x34, 0x12]
        let reader_ref = create_binary_reader(&mut thread, vec![0x78, 0x56, 0x34, 0x12]);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt32",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));
    }

    #[test]
    fn test_binary_reader_read_int64() {
        let mut thread = create_test_thread();
        // Little-endian: 0x0102030405060708
        let reader_ref = create_binary_reader(
            &mut thread,
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        );

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadInt64",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = binary_reader_read_int64_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(0x0102030405060708)))
        ));
    }

    #[test]
    fn test_binary_reader_read_string() {
        let mut thread = create_test_thread();
        // Length-prefixed string: length=5, "Hello"
        let reader_ref = create_binary_reader(&mut thread, vec![5, b'H', b'e', b'l', b'l', b'o']);

        let this = EmValue::ObjectRef(reader_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadString",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = binary_reader_read_string_pre(&ctx, &mut thread);

        let str_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };

        let s = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(s.as_ref(), "Hello");
    }

    #[test]
    fn test_binary_reader_mixed_reads() {
        let mut thread = create_test_thread();
        // Create data with: byte, int32, string
        // byte: 0xFF
        // int32: 0x12345678 (little-endian: [0x78, 0x56, 0x34, 0x12])
        // string: length=4, "Test"
        let reader_ref = create_binary_reader(
            &mut thread,
            vec![
                0xFF, // byte
                0x78, 0x56, 0x34, 0x12, // int32
                4, b'T', b'e', b's', b't', // string
            ],
        );

        let this = EmValue::ObjectRef(reader_ref);

        // Read byte
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "BinaryReader",
            "ReadByte",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = binary_reader_read_byte_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0xFF)))
        ));

        // Read int32
        let ctx = HookContext::new(
            Token::new(0x0A000002),
            "System.IO",
            "BinaryReader",
            "ReadInt32",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = binary_reader_read_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(0x12345678)))
        ));

        // Read string
        let ctx = HookContext::new(
            Token::new(0x0A000003),
            "System.IO",
            "BinaryReader",
            "ReadString",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = binary_reader_read_string_pre(&ctx, &mut thread);

        let str_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            _ => panic!("Expected Bypass with ObjectRef"),
        };
        let s = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(s.as_ref(), "Test");
    }
}

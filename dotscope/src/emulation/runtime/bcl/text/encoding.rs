//! `System.Text.Encoding` method hooks.
//!
//! This module provides hook implementations for text encoding and decoding
//! methods commonly used in obfuscation for string concealment and data
//! transformation.
//!
//! # Overview
//!
//! Text encoding is fundamental to .NET string handling and is heavily used by
//! obfuscators to encrypt and decrypt strings at runtime. These hooks support
//! multiple encodings and automatically capture decoded strings for analysis.
//!
//! # Emulated .NET Methods
//!
//! ## Encoding Properties
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Encoding.get_UTF8` | Returns UTF-8 encoding instance |
//! | `Encoding.get_ASCII` | Returns ASCII encoding instance |
//! | `Encoding.get_Unicode` | Returns UTF-16 LE encoding instance |
//! | `Encoding.get_BigEndianUnicode` | Returns UTF-16 BE encoding instance |
//! | `Encoding.get_UTF32` | Returns UTF-32 encoding instance |
//! | `Encoding.GetEncoding(int)` | Returns encoding by code page |
//!
//! ## Encoding Base Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Encoding.GetBytes(string)` | Encodes string to byte array |
//! | `Encoding.GetString(byte[])` | Decodes byte array to string |
//! | `Encoding.GetByteCount(string)` | Returns encoded byte count |
//! | `Encoding.GetCharCount(byte[])` | Returns decoded character count |
//!
//! ## Specific Encoding Classes
//!
//! | Class | GetBytes | GetString |
//! |-------|----------|-----------|
//! | `UTF8Encoding` | UTF-8 encode | UTF-8 decode |
//! | `ASCIIEncoding` | ASCII encode | ASCII decode |
//! | `UnicodeEncoding` | UTF-16 LE encode | UTF-16 LE decode |
//!
//! # Deobfuscation Use Cases
//!
//! ## String Decryption
//!
//! Obfuscators encrypt strings and decode them at runtime:
//!
//! ```csharp
//! byte[] encrypted = GetResource("strings");
//! byte[] decrypted = DecryptAes(encrypted, key);
//! string secret = Encoding.UTF8.GetString(decrypted);
//! ```
//!
//! ## Base64 + Encoding
//!
//! Common pattern combining Base64 with encoding:
//!
//! ```csharp
//! byte[] bytes = Convert.FromBase64String(obfuscated);
//! string plaintext = Encoding.UTF8.GetString(bytes);
//! ```
//!
//! ## Unicode Obfuscation
//!
//! Some obfuscators use UTF-16 or other encodings:
//!
//! ```csharp
//! byte[] data = ...; // Embedded resource
//! string decoded = Encoding.Unicode.GetString(data);
//! ```
//!
//! # String Capture
//!
//! All `GetString` methods automatically capture decoded strings through
//! the [`CaptureContext`] for analysis:
//!
//! ```text
//! // When Encoding.UTF8.GetString(bytes) is called:
//! // 1. Decode bytes to string
//! // 2. Capture string with source location info
//! // 3. Return string reference
//! thread.capture().capture_string(decoded_string, source);
//! ```
//!
//! This enables extraction of decrypted strings from obfuscated code.
//!
//! # Supported Code Pages
//!
//! The `GetEncoding(int)` method supports these code pages:
//!
//! | Code Page | Encoding |
//! |-----------|----------|
//! | 65001 | UTF-8 (default) |
//! | 20127 | US-ASCII |
//! | 1200 | UTF-16 LE |
//! | 1201 | UTF-16 BE |
//! | 12000 | UTF-32 LE |
//!
//! [`CaptureContext`]: crate::emulation::capture::CaptureContext

use crate::{
    emulation::{
        capture::CaptureSource,
        memory::EncodingType,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::token::Token,
    Result,
};

/// Registers all `System.Text.Encoding` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - **Encoding base**: `GetBytes`, `GetString`, `GetByteCount`, `GetCharCount`
/// - **Encoding properties**: `get_UTF8`, `get_ASCII`, `get_Unicode`, `get_BigEndianUnicode`, `get_UTF32`
/// - **Factory**: `GetEncoding(int)`
/// - **UTF8Encoding**: `GetBytes`, `GetString`
/// - **ASCIIEncoding**: `GetBytes`, `GetString`
/// - **UnicodeEncoding**: `GetBytes`, `GetString`
///
/// # String Capture
///
/// All `GetString` methods automatically capture decoded strings through
/// the emulation thread's capture context.
pub fn register(manager: &HookManager) -> Result<()> {
    // Encoding base methods
    manager.register(
        Hook::new("System.Text.Encoding.GetBytes")
            .match_name("System.Text", "Encoding", "GetBytes")
            .pre(encoding_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.GetString")
            .match_name("System.Text", "Encoding", "GetString")
            .pre(encoding_get_string_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.GetByteCount")
            .match_name("System.Text", "Encoding", "GetByteCount")
            .pre(encoding_get_byte_count_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.GetCharCount")
            .match_name("System.Text", "Encoding", "GetCharCount")
            .pre(encoding_get_char_count_pre),
    )?;

    // Encoding properties
    manager.register(
        Hook::new("System.Text.Encoding.get_UTF8")
            .match_name("System.Text", "Encoding", "get_UTF8")
            .pre(encoding_get_utf8_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.get_ASCII")
            .match_name("System.Text", "Encoding", "get_ASCII")
            .pre(encoding_get_ascii_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.get_Unicode")
            .match_name("System.Text", "Encoding", "get_Unicode")
            .pre(encoding_get_unicode_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.get_BigEndianUnicode")
            .match_name("System.Text", "Encoding", "get_BigEndianUnicode")
            .pre(encoding_get_big_endian_unicode_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.get_UTF32")
            .match_name("System.Text", "Encoding", "get_UTF32")
            .pre(encoding_get_utf32_pre),
    )?;

    manager.register(
        Hook::new("System.Text.Encoding.GetEncoding")
            .match_name("System.Text", "Encoding", "GetEncoding")
            .pre(encoding_get_encoding_pre),
    )?;

    // UTF8Encoding methods
    manager.register(
        Hook::new("System.Text.UTF8Encoding.GetBytes")
            .match_name("System.Text", "UTF8Encoding", "GetBytes")
            .pre(utf8_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Text.UTF8Encoding.GetString")
            .match_name("System.Text", "UTF8Encoding", "GetString")
            .pre(utf8_get_string_pre),
    )?;

    // ASCIIEncoding methods
    manager.register(
        Hook::new("System.Text.ASCIIEncoding.GetBytes")
            .match_name("System.Text", "ASCIIEncoding", "GetBytes")
            .pre(ascii_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Text.ASCIIEncoding.GetString")
            .match_name("System.Text", "ASCIIEncoding", "GetString")
            .pre(ascii_get_string_pre),
    )?;

    // UnicodeEncoding methods
    manager.register(
        Hook::new("System.Text.UnicodeEncoding.GetBytes")
            .match_name("System.Text", "UnicodeEncoding", "GetBytes")
            .pre(unicode_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Text.UnicodeEncoding.GetString")
            .match_name("System.Text", "UnicodeEncoding", "GetString")
            .pre(unicode_get_string_pre),
    )?;

    Ok(())
}

/// Hook for `System.Text.Encoding.GetBytes` method.
///
/// Inspects the `this` encoding instance to determine the actual encoding
/// (UTF-8, ASCII, UTF-16LE, etc.) and produces the correct byte output.
/// Falls back to UTF-8 when the encoding type cannot be determined.
///
/// # Handled Overloads
///
/// - `Encoding.GetBytes(String) -> Byte[]`
/// - `Encoding.GetBytes(Char[]) -> Byte[]`
/// - `Encoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode, or
/// - `chars`: Character array to encode
/// - `index`: Starting position in character array
/// - `count`: Number of characters to encode
///
/// # Returns
///
/// A byte array containing the encoded characters
fn encoding_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let encoding_type = ctx
        .this
        .and_then(|this_val| {
            if let EmValue::ObjectRef(href) = this_val {
                thread.heap().get_encoding_type(*href).ok().flatten()
            } else {
                None
            }
        })
        .unwrap_or(EncodingType::Utf8);

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Ok(s) = thread.heap().get_string(*handle) {
            let bytes = encode_string(&s, encoding_type);
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.Encoding.GetString` method.
///
/// Inspects the `this` encoding instance to determine the actual encoding
/// (UTF-8, ASCII, UTF-16LE, etc.) and decodes the bytes accordingly.
/// Falls back to UTF-8 when the encoding type cannot be determined.
///
/// This is critical for obfuscators like .NET Reactor that call
/// `Encoding.Unicode.GetString(bytes)` through the base class virtual
/// dispatch — without encoding-aware handling, UTF-16LE bytes would be
/// misinterpreted as UTF-8, producing strings with embedded null bytes.
///
/// # Handled Overloads
///
/// - `Encoding.GetString(Byte[]) -> String`
/// - `Encoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
/// - `index`: Starting position in byte array
/// - `count`: Number of bytes to decode
///
/// # Returns
///
/// A string containing the decoded bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn encoding_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Determine encoding type from the `this` instance. The base class
    // Encoding.GetString dispatches virtually, so the actual encoding depends
    // on which Encoding subclass is on the stack (UTF8, ASCII, Unicode, etc.).
    let encoding_type = ctx
        .this
        .and_then(|this_val| {
            if let EmValue::ObjectRef(href) = this_val {
                thread.heap().get_encoding_type(*href).ok().flatten()
            } else {
                None
            }
        })
        .unwrap_or(EncodingType::Utf8);

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(all_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let bytes = slice_bytes_with_offset_count(&all_bytes, ctx.args.get(1), ctx.args.get(2))
                .unwrap_or(all_bytes);

            let s = decode_bytes(&bytes, encoding_type);

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Applies a `(byte[], int offset, int count)` slice spec to `all_bytes`.
///
/// Returns `Some(slice)` when both `offset_arg` and `count_arg` are present
/// and `offset.checked_add(count) <= all_bytes.len()`. Returns `None` when
/// the offset/count overload was not used (either argument missing) or when
/// the requested range is invalid — callers fall back to the full buffer in
/// both cases, matching the legacy behaviour.
fn slice_bytes_with_offset_count(
    all_bytes: &[u8],
    offset_arg: Option<&EmValue>,
    count_arg: Option<&EmValue>,
) -> Option<Vec<u8>> {
    let (offset_arg, count_arg) = (offset_arg?, count_arg?);
    // Negative or non-`I32` offset/count is treated as "no slice", matching
    // the legacy behaviour of falling back to the full buffer.
    let offset = match offset_arg {
        EmValue::I32(o) => usize::try_from(*o).ok()?,
        _ => 0,
    };
    let count = match count_arg {
        EmValue::I32(c) => usize::try_from(*c).ok()?,
        _ => all_bytes.len(),
    };
    let end = offset.checked_add(count)?;
    all_bytes.get(offset..end).map(<[u8]>::to_vec)
}

/// Hook for `System.Text.Encoding.GetByteCount` method.
///
/// Inspects the `this` encoding instance to determine the actual encoding
/// (UTF-8, ASCII, UTF-16LE, etc.) and computes the encoded byte length.
/// Falls back to UTF-8 when the encoding type cannot be determined.
///
/// # Handled Overloads
///
/// - `Encoding.GetByteCount(String) -> Int32`
/// - `Encoding.GetByteCount(Char[]) -> Int32`
/// - `Encoding.GetByteCount(Char[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `s`: String to measure, or
/// - `chars`: Character array to measure
/// - `index`: Starting position in character array
/// - `count`: Number of characters to measure
///
/// # Returns
///
/// The number of bytes that would result from encoding
fn encoding_get_byte_count_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let encoding_type = ctx
        .this
        .and_then(|this_val| {
            if let EmValue::ObjectRef(href) = this_val {
                thread.heap().get_encoding_type(*href).ok().flatten()
            } else {
                None
            }
        })
        .unwrap_or(EncodingType::Utf8);

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Ok(s) = thread.heap().get_string(*handle) {
            let byte_len = encode_string(&s, encoding_type).len();
            let len = i32::try_from(byte_len).unwrap_or(i32::MAX);
            return PreHookResult::Bypass(Some(EmValue::I32(len)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Text.Encoding.GetCharCount` method.
///
/// Inspects the `this` encoding instance to determine the actual encoding
/// (UTF-8, ASCII, UTF-16LE, etc.) and computes the decoded character count.
/// Falls back to UTF-8 when the encoding type cannot be determined.
///
/// # Handled Overloads
///
/// - `Encoding.GetCharCount(Byte[]) -> Int32`
/// - `Encoding.GetCharCount(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `bytes`: Byte array to measure
/// - `index`: Starting position in byte array
/// - `count`: Number of bytes to measure
///
/// # Returns
///
/// The number of characters that would result from decoding
fn encoding_get_char_count_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let encoding_type = ctx
        .this
        .and_then(|this_val| {
            if let EmValue::ObjectRef(href) = this_val {
                thread.heap().get_encoding_type(*href).ok().flatten()
            } else {
                None
            }
        })
        .unwrap_or(EncodingType::Utf8);

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let s = decode_bytes(&bytes, encoding_type);
            let count = i32::try_from(s.chars().count()).unwrap_or(i32::MAX);
            return PreHookResult::Bypass(Some(EmValue::I32(count)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Text.Encoding.get_UTF8` static property.
///
/// # Handled Overloads
///
/// - `Encoding.UTF8 { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-8 encoding object
fn encoding_get_utf8_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread
        .heap_mut()
        .alloc_encoding(EncodingType::Utf8, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.Encoding.get_ASCII` static property.
///
/// # Handled Overloads
///
/// - `Encoding.ASCII { get; } -> Encoding`
///
/// # Returns
///
/// An ASCII encoding object
fn encoding_get_ascii_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread
        .heap_mut()
        .alloc_encoding(EncodingType::Ascii, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.Encoding.get_Unicode` static property.
///
/// # Handled Overloads
///
/// - `Encoding.Unicode { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-16 Little Endian encoding object
fn encoding_get_unicode_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread
        .heap_mut()
        .alloc_encoding(EncodingType::Utf16Le, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.Encoding.get_BigEndianUnicode` static property.
///
/// # Handled Overloads
///
/// - `Encoding.BigEndianUnicode { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-16 Big Endian encoding object
fn encoding_get_big_endian_unicode_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread
        .heap_mut()
        .alloc_encoding(EncodingType::Utf16Be, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.Encoding.get_UTF32` static property.
///
/// # Handled Overloads
///
/// - `Encoding.UTF32 { get; } -> Encoding`
///
/// # Returns
///
/// A UTF-32 encoding object
fn encoding_get_utf32_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread
        .heap_mut()
        .alloc_encoding(EncodingType::Utf32, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.Encoding.GetEncoding` static method.
///
/// # Handled Overloads
///
/// - `Encoding.GetEncoding(Int32) -> Encoding`
/// - `Encoding.GetEncoding(String) -> Encoding`
///
/// # Parameters
///
/// - `codepage`: Code page identifier, or
/// - `name`: Encoding name
///
/// # Supported Code Pages
///
/// - `65001` - UTF-8 (default for unknown code pages)
/// - `20127` - US-ASCII
/// - `1200` - UTF-16 LE
/// - `1201` - UTF-16 BE
/// - `12000` - UTF-32 LE
///
/// # Returns
///
/// An encoding object for the specified code page
fn encoding_get_encoding_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let encoding_type = if let Some(EmValue::I32(code_page)) = ctx.args.first() {
        match *code_page {
            20127 => EncodingType::Ascii,  // US-ASCII
            1200 => EncodingType::Utf16Le, // UTF-16 LE
            1201 => EncodingType::Utf16Be, // UTF-16 BE
            12000 => EncodingType::Utf32,  // UTF-32 LE
            // 65001 is UTF-8, and unknown code pages default to UTF-8
            _ => EncodingType::Utf8,
        }
    } else {
        EncodingType::Utf8
    };

    let type_token = thread.resolve_type_token("System.Text", "Encoding");
    match thread.heap_mut().alloc_encoding(encoding_type, type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Text.UTF8Encoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `UTF8Encoding.GetBytes(String) -> Byte[]`
/// - `UTF8Encoding.GetBytes(Char[]) -> Byte[]`
/// - `UTF8Encoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the UTF-8 encoded string
fn utf8_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Ok(s) = thread.heap().get_string(*handle) {
            let bytes: Vec<u8> = s.as_bytes().to_vec();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UTF8Encoding.GetString` method.
///
/// # Handled Overloads
///
/// - `UTF8Encoding.GetString(Byte[]) -> String`
/// - `UTF8Encoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
///
/// # Returns
///
/// A string containing the decoded UTF-8 bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn utf8_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(all_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let bytes = slice_bytes_with_offset_count(&all_bytes, ctx.args.get(1), ctx.args.get(2))
                .unwrap_or(all_bytes);

            let s = String::from_utf8_lossy(&bytes).into_owned();

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.ASCIIEncoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `ASCIIEncoding.GetBytes(String) -> Byte[]`
/// - `ASCIIEncoding.GetBytes(Char[]) -> Byte[]`
/// - `ASCIIEncoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the ASCII encoded string.
/// Non-ASCII characters are replaced with `?` (0x3F).
fn ascii_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Ok(s) = thread.heap().get_string(*handle) {
            // ASCII encoding - replace non-ASCII with '?'
            let bytes: Vec<u8> = s
                .chars()
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
                .collect();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.ASCIIEncoding.GetString` method.
///
/// # Handled Overloads
///
/// - `ASCIIEncoding.GetString(Byte[]) -> String`
/// - `ASCIIEncoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode
///
/// # Returns
///
/// A string containing the decoded ASCII bytes.
/// Bytes >= 128 are replaced with `?`.
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn ascii_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(all_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let bytes = slice_bytes_with_offset_count(&all_bytes, ctx.args.get(1), ctx.args.get(2))
                .unwrap_or(all_bytes);

            // ASCII decoding - only keep valid ASCII
            let s: String = bytes
                .iter()
                .map(|&b| if b < 128 { char::from(b) } else { '?' })
                .collect();

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UnicodeEncoding.GetBytes` method.
///
/// # Handled Overloads
///
/// - `UnicodeEncoding.GetBytes(String) -> Byte[]`
/// - `UnicodeEncoding.GetBytes(Char[]) -> Byte[]`
/// - `UnicodeEncoding.GetBytes(Char[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `s`: String to encode
///
/// # Returns
///
/// A byte array containing the UTF-16 Little Endian encoded string
fn unicode_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Ok(s) = thread.heap().get_string(*handle) {
            // UTF-16 LE encoding
            let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            match thread.heap_mut().alloc_byte_array(&bytes) {
                Ok(arr_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Text.UnicodeEncoding.GetString` method.
///
/// # Handled Overloads
///
/// - `UnicodeEncoding.GetString(Byte[]) -> String`
/// - `UnicodeEncoding.GetString(Byte[], Int32, Int32) -> String`
///
/// # Parameters
///
/// - `bytes`: Byte array to decode (must have even length)
///
/// # Returns
///
/// A string containing the decoded UTF-16 Little Endian bytes
///
/// # Note
///
/// Automatically captures the decoded string for deobfuscation analysis.
fn unicode_get_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    // Handle both GetString(byte[]) and GetString(byte[], int, int) overloads
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(all_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let bytes = slice_bytes_with_offset_count(&all_bytes, ctx.args.get(1), ctx.args.get(2))
                .unwrap_or(all_bytes);

            // UTF-16 LE decoding
            if !bytes.len().is_multiple_of(2) {
                return PreHookResult::Bypass(Some(EmValue::Null));
            }

            let u16s: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_le_bytes)
                .collect();

            let s = String::from_utf16_lossy(&u16s);

            // Capture decoded string for analysis
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_string(s.clone(), source);

            match thread.heap_mut().alloc_string(&s) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Encodes a Rust string into a byte vector using the specified .NET encoding.
///
/// Mirrors the behavior of `System.Text.Encoding.GetBytes(String)` for each
/// encoding subclass. Non-ASCII bytes in ASCII mode are replaced with `?`,
/// matching the .NET `ASCIIEncoding` fallback behavior.
///
/// # Arguments
///
/// * `s` - The UTF-8 string to encode.
/// * `encoding_type` - The .NET encoding to use (UTF-8, ASCII, UTF-16LE, UTF-16BE, UTF-32).
///
/// # Returns
///
/// The encoded byte representation of the string.
fn encode_string(s: &str, encoding_type: EncodingType) -> Vec<u8> {
    match encoding_type {
        EncodingType::Utf8 => s.as_bytes().to_vec(),
        EncodingType::Ascii => s.bytes().map(|b| if b > 127 { b'?' } else { b }).collect(),
        EncodingType::Utf16Le => s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        EncodingType::Utf16Be => s.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        EncodingType::Utf32 => s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect(),
    }
}

/// Decodes a byte slice into a Rust string using the specified .NET encoding.
///
/// Mirrors the behavior of `System.Text.Encoding.GetString(Byte[])` for each
/// encoding subclass. Invalid sequences are handled lossily (replacement
/// characters for UTF-8/UTF-16, truncation for odd-length UTF-16/UTF-32 input).
///
/// # Arguments
///
/// * `bytes` - The raw bytes to decode.
/// * `encoding_type` - The .NET encoding to use (UTF-8, ASCII, UTF-16LE, UTF-16BE, UTF-32).
///
/// # Returns
///
/// The decoded string. Returns an empty string if the byte slice has an invalid
/// length for the chosen multi-byte encoding (e.g. odd length for UTF-16).
fn decode_bytes(bytes: &[u8], encoding_type: EncodingType) -> String {
    match encoding_type {
        EncodingType::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        EncodingType::Ascii => bytes.iter().map(|&b| b as char).collect(),
        EncodingType::Utf16Le => {
            if !bytes.len().is_multiple_of(2) {
                return String::new();
            }
            let u16s: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_le_bytes)
                .collect();
            String::from_utf16_lossy(&u16s)
        }
        EncodingType::Utf16Be => {
            if !bytes.len().is_multiple_of(2) {
                return String::new();
            }
            let u16s: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_be_bytes)
                .collect();
            String::from_utf16_lossy(&u16s)
        }
        EncodingType::Utf32 => {
            if !bytes.len().is_multiple_of(4) {
                return String::new();
            }
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .copied()
                .map(u32::from_le_bytes)
                .filter_map(char::from_u32)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::{
                bcl::text::encoding::{
                    ascii_get_bytes_pre, encoding_get_big_endian_unicode_pre,
                    encoding_get_byte_count_pre, encoding_get_char_count_pre,
                    encoding_get_encoding_pre, encoding_get_string_pre, encoding_get_unicode_pre,
                    register, unicode_get_bytes_pre, unicode_get_string_pre, utf8_get_bytes_pre,
                    utf8_get_string_pre,
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
        register(&manager).unwrap();
        assert_eq!(manager.len(), 16);
    }

    #[test]
    fn test_utf8_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UTF8Encoding",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = utf8_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(
                thread.heap().get_byte_array(handle).unwrap(),
                Some(b"Hello".to_vec())
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_utf8_get_string_hook() {
        let mut thread = create_test_thread();
        let data = thread.heap_mut().alloc_byte_array(b"World").unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UTF8Encoding",
            "GetString",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = utf8_get_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_ascii_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "ASCIIEncoding",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = ascii_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(
                thread.heap().get_byte_array(handle).unwrap(),
                Some(b"Hello".to_vec())
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_unicode_get_bytes_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("AB").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UnicodeEncoding",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = unicode_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            // "AB" in UTF-16 LE: 0x41 0x00 0x42 0x00
            assert_eq!(
                thread.heap().get_byte_array(handle).unwrap(),
                Some(vec![0x41, 0x00, 0x42, 0x00])
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_unicode_get_string_hook() {
        let mut thread = create_test_thread();
        // "AB" in UTF-16 LE
        let data = thread
            .heap_mut()
            .alloc_byte_array(&[0x41, 0x00, 0x42, 0x00])
            .unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "UnicodeEncoding",
            "GetString",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = unicode_get_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "AB");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_encoding_get_byte_count() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetByteCount",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_byte_count_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_encoding_get_char_count() {
        let mut thread = create_test_thread();
        let data = thread.heap_mut().alloc_byte_array(b"Hello").unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetCharCount",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_char_count_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_encoding_get_string_with_offset() {
        let mut thread = create_test_thread();
        let data = thread.heap_mut().alloc_byte_array(b"Hello World").unwrap();

        // GetString(byte[], 6, 5) -> "World"
        let args = [EmValue::ObjectRef(data), EmValue::I32(6), EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetString",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_string_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_encoding_get_unicode_property() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "get_Unicode",
            PointerSize::Bit64,
        );
        let result = encoding_get_unicode_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_encoding_get_big_endian_unicode_property() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "get_BigEndianUnicode",
            PointerSize::Bit64,
        );
        let result = encoding_get_big_endian_unicode_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_get_encoding_ascii_codepage() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(20127)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetEncoding",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_encoding_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_get_encoding_hook() {
        let mut thread = create_test_thread();

        // Test UTF-8 (default)
        let args = [EmValue::I32(65001)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetEncoding",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_encoding_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));

        // Test ASCII
        let args = [EmValue::I32(20127)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "Encoding",
            "GetEncoding",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = encoding_get_encoding_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }
}

//! `System.IO.Compression.DeflateStream` and `System.IO.Compression.GZipStream` method hooks.
//!
//! This module provides hook implementations for compressed stream types used by
//! obfuscators for decompressing embedded payloads. On the first read, the entire
//! underlying stream is decompressed and cached for subsequent reads.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `DeflateStream..ctor(Stream, CompressionMode)` | Create deflate stream | Wraps underlying stream for decompression |
//! | `DeflateStream.Read(byte[], int, int)` | Read decompressed data | Decompresses on first read, serves from cache |
//! | `DeflateStream.Close()` | Close stream | No-op |
//! | `DeflateStream.Dispose()` | Dispose stream | No-op |
//! | `GZipStream..ctor(Stream, CompressionMode)` | Create gzip stream | Wraps underlying stream for decompression |
//! | `GZipStream.Read(byte[], int, int)` | Read decompressed data | Decompresses on first read, serves from cache |
//! | `GZipStream.Close()` | Close stream | No-op |
//! | `GZipStream.Dispose()` | Dispose stream | No-op |

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::{
            bcl::{io::stream::stream_dispose_pre, limits::buffer_range},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    utils::{decompress_deflate, decompress_gzip},
    Result,
};

/// Registers all compression stream hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    // DeflateStream methods
    manager.register(
        Hook::new("System.IO.Compression.DeflateStream..ctor")
            .match_name("System.IO.Compression", "DeflateStream", ".ctor")
            .pre(deflate_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Read")
            .match_name("System.IO.Compression", "DeflateStream", "Read")
            .pre(compressed_stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Close")
            .match_name("System.IO.Compression", "DeflateStream", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.DeflateStream.Dispose")
            .match_name("System.IO.Compression", "DeflateStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    // GZipStream methods
    manager.register(
        Hook::new("System.IO.Compression.GZipStream..ctor")
            .match_name("System.IO.Compression", "GZipStream", ".ctor")
            .pre(gzip_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Read")
            .match_name("System.IO.Compression", "GZipStream", "Read")
            .pre(compressed_stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Close")
            .match_name("System.IO.Compression", "GZipStream", "Close")
            .pre(stream_dispose_pre),
    )?;

    manager.register(
        Hook::new("System.IO.Compression.GZipStream.Dispose")
            .match_name("System.IO.Compression", "GZipStream", "Dispose")
            .pre(stream_dispose_pre),
    )?;

    Ok(())
}

/// Hook for `System.IO.Compression.DeflateStream..ctor` constructor.
///
/// Creates a DeflateStream wrapping an underlying stream for decompression.
///
/// # Handled Overloads
///
/// - `DeflateStream..ctor(Stream, CompressionMode)`
///
/// # Parameters
///
/// - `stream`: The underlying stream containing compressed data
/// - `mode`: CompressionMode (0=Decompress, 1=Compress)
fn deflate_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    compressed_stream_ctor(ctx, thread, 0) // 0 = Deflate
}

/// Hook for `System.IO.Compression.GZipStream..ctor` constructor.
///
/// Creates a GZipStream wrapping an underlying stream for decompression.
///
/// # Handled Overloads
///
/// - `GZipStream..ctor(Stream, CompressionMode)`
///
/// # Parameters
///
/// - `stream`: The underlying stream containing compressed data
/// - `mode`: CompressionMode (0=Decompress, 1=Compress)
fn gzip_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    compressed_stream_ctor(ctx, thread, 1) // 1 = GZip
}

/// Shared constructor logic for DeflateStream and GZipStream.
fn compressed_stream_ctor(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
    compression_type: u8,
) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get underlying stream argument
    let underlying_stream = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get CompressionMode: 0=Decompress, 1=Compress
    #[allow(clippy::cast_sign_loss)]
    let mode = match ctx.args.get(1) {
        Some(EmValue::I32(v)) => *v as u8,
        _ => 0, // Default to Decompress
    };

    try_hook!(thread.heap().replace_with_compressed_stream(
        stream_ref,
        underlying_stream,
        compression_type,
        mode,
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `DeflateStream.Read` and `GZipStream.Read` methods.
///
/// On the first read, decompresses the entire underlying stream's data and caches
/// the result. Subsequent reads serve data from the cache.
///
/// # Handled Overloads
///
/// - `DeflateStream.Read(Byte[], Int32, Int32) -> Int32`
/// - `GZipStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array
/// - `offset`: Byte offset in buffer
/// - `count`: Maximum bytes to read
fn compressed_stream_read_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::Error(format!("{}.Read without a stream", ctx.type_name)),
    };

    let (buffer_ref, offset, count) =
        match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
            Ok(range) => range,
            Err(result) => return result,
        };

    // On first read, decompress the underlying stream data
    if !try_hook!(thread.heap().has_compressed_stream_data(stream_ref)) {
        let Some((underlying, compression_type, _mode)) =
            try_hook!(thread.heap().get_compressed_stream_info(stream_ref))
        else {
            return PreHookResult::Error(format!(
                "{}.Read on no emulated compressed stream",
                ctx.type_name
            ));
        };

        let Some((compressed_data, underlying_pos)) =
            try_hook!(thread.heap().get_stream_data(underlying))
        else {
            return PreHookResult::Error(format!("{}.Read over no emulated stream", ctx.type_name));
        };

        // Use data from the underlying stream's current position, not from offset 0
        let effective_data = compressed_data.get(underlying_pos..).unwrap_or(&[]);

        // Data that does not inflate is the InvalidDataException the runtime throws, not an
        // empty stream
        let decompressed = match compression_type {
            0 => decompress_deflate(effective_data),
            1 => decompress_gzip(effective_data),
            other => {
                return PreHookResult::Error(format!("compression type {other} is not emulated"))
            }
        };
        let data = match decompressed {
            Ok(data) => data,
            Err(e) => {
                return PreHookResult::Throw {
                    exception_type: synthetic_exception::INVALID_DATA,
                    message: format!("the compressed data is not valid: {e}"),
                }
            }
        };
        try_hook!(thread.heap().set_compressed_stream_data(stream_ref, data));
    }

    // Read from the decompressed cache
    let Some(bytes) = try_hook!(thread.heap().read_compressed_stream(stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Copy bytes into the output buffer
    for (i, &byte) in bytes.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            offset.saturating_add(i),
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    /// `DeflateStream.Read` of `buffer` with `offset` and `count` over a stream of `data`.
    fn read_deflate(data: &[u8], offset: i32, count: i32) -> PreHookResult {
        let mut thread = create_test_thread();
        let underlying = thread.heap().alloc_stream(data.to_vec(), None).unwrap();
        let stream = thread.heap().alloc_stream(Vec::new(), None).unwrap();
        assert!(thread
            .heap()
            .replace_with_compressed_stream(stream, underlying, 0, 0)
            .unwrap());
        let buffer = thread.heap().alloc_byte_array(&[0u8; 16]).unwrap();
        let this = EmValue::ObjectRef(stream);
        let args = [
            EmValue::ObjectRef(buffer),
            EmValue::I32(offset),
            EmValue::I32(count),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO.Compression",
            "DeflateStream",
            "Read",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        compressed_stream_read_pre(&ctx, &mut thread)
    }

    /// Data that does not inflate is the `InvalidDataException` the runtime throws, not an
    /// empty stream; a negative offset or count, or a range past the buffer, the argument
    /// exceptions it throws before reading.
    #[test]
    fn a_read_the_runtime_refuses_throws() {
        let thrown = |result: PreHookResult, expected: Token| matches!(result, PreHookResult::Throw { exception_type, .. } if exception_type == expected);
        // Block type 3 is reserved: no deflate stream starts with it
        assert!(thrown(
            read_deflate(&[0xFF, 0xFF, 0xFF], 0, 16),
            synthetic_exception::INVALID_DATA
        ));
        assert!(thrown(
            read_deflate(&[0x03, 0x00], -1, 4),
            synthetic_exception::ARGUMENT_OUT_OF_RANGE
        ));
        assert!(thrown(
            read_deflate(&[0x03, 0x00], 8, 16),
            synthetic_exception::ARGUMENT_OUT_OF_RANGE
        ));
        assert!(thrown(
            read_deflate(&[0x03, 0x00], 17, 0),
            synthetic_exception::ARGUMENT_OUT_OF_RANGE
        ));
        // An empty final stored block inflates to nothing: a read of zero bytes
        assert!(matches!(
            read_deflate(&[0x03, 0x00], 0, 16),
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }
}

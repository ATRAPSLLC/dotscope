//! `System.IO` namespace BCL method hooks.
//!
//! This module provides hook implementations for .NET I/O types that are frequently
//! encountered during emulation, particularly in resource decryption and assembly
//! unpacking routines.
//!
//! # Organization
//!
//! | Module | .NET Type(s) | Description |
//! |--------|-------------|-------------|
//! | [`stream`] | `System.IO.Stream`, `System.IO.MemoryStream` | Stream base class and in-memory stream operations |
//! | [`binaryreader`] | `System.IO.BinaryReader` | Typed binary reading from streams |
//! | [`binarywriter`] | `System.IO.BinaryWriter` | Typed binary writing to streams |
//! | [`compression`] | `System.IO.Compression.DeflateStream`, `System.IO.Compression.GZipStream` | Compressed stream decompression |
//! | [`filestream`] | `System.IO.FileStream`, `System.IO.File`, `System.IO.Path`, `System.IO.Directory` | File system operations (sandboxed for emulation) |
//!
//! # Deobfuscation Relevance
//!
//! I/O operations are critical in deobfuscation because:
//! - **MemoryStream**: Wraps decrypted resource data for further processing
//! - **BinaryReader**: Reads structured data from encrypted blobs (tokens, lengths, offsets)
//! - **BinaryWriter**: Constructs encrypted payloads or writes structured data
//! - **DeflateStream/GZipStream**: Decompresses embedded payloads
//! - **FileStream/File**: Used by some obfuscators to read the assembly's own PE file
//! - **Path/Directory**: Anti-analysis checks that inspect the execution environment
//!
//! # Limitations
//!
//! - Stream operations maintain actual data buffers but simplified position tracking
//! - File system operations are sandboxed — writes go to an in-memory virtual filesystem
//! - `BinaryReader.Read*()` methods correctly throw `EndOfStreamException` at EOF to
//!   prevent infinite loops in CFF dispatcher emulation

mod binaryreader;
mod binarywriter;
mod compression;
mod filestream;
pub mod stream;

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all `System.IO` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Stream`, `MemoryStream`, `BinaryReader`, `BinaryWriter`, `DeflateStream`,
/// `GZipStream`, `FileStream`, `File`, `Path`, and `Directory`.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    stream::register(manager)?;
    binaryreader::register(manager)?;
    binarywriter::register(manager)?;
    compression::register(manager)?;
    filestream::register(manager)?;
    Ok(())
}

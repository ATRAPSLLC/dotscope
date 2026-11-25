//! `System` namespace BCL method hooks.
//!
//! This module provides hook implementations for core .NET `System` namespace types
//! that are frequently encountered during emulation of obfuscated assemblies.
//!
//! # Organization
//!
//! | Module | .NET Type(s) | Description |
//! |--------|-------------|-------------|
//! | [`array`](mod@array) | `System.Array`, `System.Buffer` | Array manipulation and block copy operations |
//! | [`bitconverter`] | `System.BitConverter` | Primitive-to-byte and byte-to-primitive conversions |
//! | [`convert`] | `System.Convert` | Type conversions and Base64 encoding/decoding |
//! | [`enums`] | `System.Enum` | Enum parsing, formatting, and value inspection |
//! | [`environment`] | `System.Environment` | Environment variable and runtime info queries |
//! | [`exception`] | `System.Exception` | Exception construction and property access |
//! | [`math`] | `System.Math`, `System.Numerics.BitOperations` | Mathematical operations and bit manipulation |
//! | [`nullable`] | `System.Nullable<T>` | Nullable value type handling |
//! | [`spans`] | `System.Span<T>`, `System.ReadOnlySpan<T>`, `System.Memory<T>` | Span and memory stubs |
//! | [`string`] | `System.String`, `System.Char` | String manipulation and character operations |
//!
//! # Deobfuscation Relevance
//!
//! Types in the `System` namespace form the backbone of most obfuscated code. String
//! manipulation is central to string encryption schemes, `Convert` handles Base64
//! encoding used in encrypted payloads, `Array` and `Buffer` are used extensively in
//! decryption routines, and `Math` operations drive control flow flattening state machines.

mod array;
mod bitconverter;
mod convert;
mod datetime;
mod diagnostics;
mod enums;
mod environment;
mod exception;
mod math;
mod nullable;
mod spans;
mod string;

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all `System` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Array`, `BitConverter`, `Buffer`, `Convert`, `Enum`, `Environment`, `Exception`,
/// `Math`, `Nullable<T>`, `String`, and `Char`.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    array::register(manager)?;
    bitconverter::register(manager)?;
    convert::register(manager)?;
    datetime::register(manager)?;
    diagnostics::register(manager)?;
    enums::register(manager)?;
    environment::register(manager)?;
    exception::register(manager)?;
    math::register(manager)?;
    nullable::register(manager)?;
    spans::register(manager)?;
    string::register(manager)?;
    Ok(())
}

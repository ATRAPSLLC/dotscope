//! Low-level byte order and safe reading/writing utilities for CIL and PE parsing.
//!
//! This module provides comprehensive, endian-aware binary data reading and writing functionality for parsing
//! .NET PE files and CIL metadata structures. It implements safe, bounds-checked operations for
//! reading and writing primitive types from/to byte buffers with both little-endian and big-endian support,
//! ensuring data integrity and preventing buffer overruns during binary analysis and generation.
//!
//! # Architecture
//!
//! The module is built around the [`crate::utils::CilIO`] trait which provides a unified
//! interface for reading and writing binary data in a type-safe manner. The architecture includes:
//!
//! - Generic trait-based reading and writing for all primitive types
//! - Automatic bounds checking to prevent buffer overruns
//! - Support for both fixed-size and dynamic-size field reading/writing
//! - Consistent error handling through the [`crate::Result`] type
//!
//! # Key Components
//!
//! ## Core Trait
//! - [`crate::utils::CilIO`] - Trait defining endian-aware reading and writing capabilities for primitive types
//!
//! ## Little-Endian Reading Functions
//! - [`crate::utils::read_le`] - Read values from buffer start in little-endian format
//! - [`crate::utils::read_le_at`] - Read values at specific offset with auto-advance in little-endian
//! - [`crate::utils::read_le_at_dyn`] - Dynamic size reading (2 or 4 bytes) in little-endian
//!
//! ## Little-Endian Writing Functions
//! - [`crate::utils::write_le`] - Write values to buffer start in little-endian format
//! - [`crate::utils::write_le_at`] - Write values at specific offset with auto-advance in little-endian
//! - [`crate::utils::write_le_at_dyn`] - Dynamic size writing (2 or 4 bytes) in little-endian
//!
//! ## Big-Endian Reading Functions
//! - [`crate::utils::read_be`] - Read values from buffer start in big-endian format
//! - [`crate::utils::read_be_at`] - Read values at specific offset with auto-advance in big-endian
//! - [`crate::utils::read_be_at_dyn`] - Dynamic size reading (2 or 4 bytes) in big-endian
//!
//! ## Big-Endian Writing Functions
//! - [`crate::utils::write_be`] - Write values to buffer start in big-endian format
//! - [`crate::utils::write_be_at`] - Write values at specific offset with auto-advance in big-endian
//! - [`crate::utils::write_be_at_dyn`] - Dynamic size writing (2 or 4 bytes) in big-endian
//!
//! ## Supported Types
//! The [`crate::utils::CilIO`] trait is implemented for:
//! - **Unsigned integers**: `u8`, `u16`, `u32`, `u64`
//! - **Signed integers**: `i8`, `i16`, `i32`, `i64`
//! - **Floating point**: `f32`, `f64`
//!
//! # Usage Examples
//!
//! ## Basic Value Reading
//!
//! ```no_run
//! use dotscope::io::read_le;
//! use dotscope::io::read_be;
//!
//! // Little-endian reading (most common for PE files)
//! let data = [0x01, 0x00, 0x00, 0x00]; // u32 value: 1
//! let value: u32 = read_le(&data)?;
//! assert_eq!(value, 1);
//!
//! // Big-endian reading (less common)
//! let data = [0x00, 0x00, 0x00, 0x01]; // u32 value: 1
//! let value: u32 = read_be(&data)?;
//! assert_eq!(value, 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Basic Value Writing
//!
//! ```no_run
//! use dotscope::io::write_le;
//! use dotscope::io::write_be;
//!
//! // Little-endian writing (most common for PE files)
//! let mut data = [0u8; 4];
//! write_le(&mut data, 1u32)?;
//! assert_eq!(data, [0x01, 0x00, 0x00, 0x00]);
//!
//! // Big-endian writing (less common)
//! let mut data = [0u8; 4];
//! write_be(&mut data, 1u32)?;
//! assert_eq!(data, [0x00, 0x00, 0x00, 0x01]);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Sequential Reading with Offset Tracking
//!
//! ```no_run
//! use dotscope::io::read_le_at;
//!
//! let data = [0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00];
//! let mut offset = 0;
//!
//! // Read multiple values sequentially
//! let first: u16 = read_le_at(&data, &mut offset)?;  // offset: 0 -> 2
//! let second: u16 = read_le_at(&data, &mut offset)?; // offset: 2 -> 4  
//! let third: u32 = read_le_at(&data, &mut offset)?;  // offset: 4 -> 8
//!
//! assert_eq!(first, 1);
//! assert_eq!(second, 2);
//! assert_eq!(third, 3);
//! assert_eq!(offset, 8);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Sequential Writing with Offset Tracking
//!
//! ```no_run
//! use dotscope::io::write_le_at;
//!
//! let mut data = [0u8; 8];
//! let mut offset = 0;
//!
//! // Write multiple values sequentially
//! write_le_at(&mut data, &mut offset, 1u16)?;  // offset: 0 -> 2
//! write_le_at(&mut data, &mut offset, 2u16)?;  // offset: 2 -> 4  
//! write_le_at(&mut data, &mut offset, 3u32)?;  // offset: 4 -> 8
//!
//! assert_eq!(data, [0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00]);
//! assert_eq!(offset, 8);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Dynamic Size Reading/Writing
//!
//! ```no_run
//! use dotscope::io::read_le_at_dyn;
//! use dotscope::io::write_le_at_dyn;
//!
//! let mut data = [0u8; 6];
//! let mut offset = 0;
//!
//! // Write values with dynamic sizing
//! write_le_at_dyn(&mut data, &mut offset, 1, false)?; // 2 bytes
//! write_le_at_dyn(&mut data, &mut offset, 2, true)?;  // 4 bytes
//! assert_eq!(offset, 6);
//!
//! // Read them back
//! offset = 0;
//! let small = read_le_at_dyn(&data, &mut offset, false)?;
//! let large = read_le_at_dyn(&data, &mut offset, true)?;
//! assert_eq!(small, 1);
//! assert_eq!(large, 2);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! All reading and writing functions return [`crate::Result<T>`] and will return [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]
//! if there are insufficient bytes in the buffer to complete the operation. This ensures
//! memory safety and prevents buffer overruns during parsing and generation.
//!
//! # Thread Safety
//!
//! All functions and types in this module are thread-safe. The [`crate::utils::CilIO`] trait
//! implementations are based on primitive types and standard library functions that are inherently
//! thread-safe. All reading and writing functions are pure operations that don't modify shared state,
//! making them safe to call concurrently from multiple threads.
//!

use crate::{Error, ParseFailure, ParseStage, Result};

#[inline]
fn io_oob() -> Error {
    ParseFailure::OutOfBounds {
        stage: ParseStage::Generic,
    }
    .into()
}

/// Trait for implementing type-specific safe binary data reading operations.
///
/// This trait provides a unified interface for reading primitive types from byte slices
/// in a safe and endian-aware manner. It abstracts over the conversion from byte arrays
/// to typed values, supporting both little-endian and big-endian formats commonly
/// encountered in binary file parsing.
///
/// The trait is implemented for all primitive integer and floating-point types used
/// in PE file and .NET metadata parsing, ensuring type safety and consistent behavior
/// across all binary reading operations.
///
/// # Implementation Details
///
/// Each implementation defines a `Bytes` associated type that represents the fixed-size
/// byte array required for that particular type (e.g., `[u8; 4]` for `u32`). The trait
/// methods then convert these byte arrays to the target type using the appropriate
/// endianness conversion.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::CilIO;
///
/// // The trait is used internally by the reading functions
/// let bytes = [0x01, 0x00, 0x00, 0x00];
/// let value = u32::from_le_bytes(bytes);
/// assert_eq!(value, 1);
///
/// // Big-endian conversion
/// let bytes = [0x00, 0x00, 0x00, 0x01];
/// let value = u32::from_be_bytes(bytes);
/// assert_eq!(value, 1);
/// ```
///
/// # Thread Safety
///
/// All implementations of [`CilIO`] are thread-safe as they only work with primitive types
/// and perform pure conversion operations without any shared state modification.
pub trait CilIO: Sized {
    /// Associated type representing the byte array type for this numeric type.
    ///
    /// This type must be convertible from a byte slice and is used for reading
    /// binary data in both little-endian and big-endian formats.
    type Bytes: Sized + AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Read T from a byte buffer in little-endian
    fn from_le_bytes(bytes: Self::Bytes) -> Self;
    /// Read T from a byte buffer in big-endian
    fn from_be_bytes(bytes: Self::Bytes) -> Self;

    /// Write T to a byte buffer in little-endian
    fn to_le_bytes(self) -> Self::Bytes;
    /// Write T to a byte buffer in big-endian
    fn to_be_bytes(self) -> Self::Bytes;
}

// Implement CilIO support for u64
impl CilIO for u64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u64::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        u64::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        u64::to_be_bytes(self)
    }
}

// Implement CilIO support for i64
impl CilIO for i64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i64::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        i64::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        i64::to_be_bytes(self)
    }
}

// Implement CilIO support for u32
impl CilIO for u32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u32::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        u32::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        u32::to_be_bytes(self)
    }
}

// Implement CilIO support for i32
impl CilIO for i32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i32::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        i32::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        i32::to_be_bytes(self)
    }
}

// Implement CilIO support from u16
impl CilIO for u16 {
    type Bytes = [u8; 2];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u16::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u16::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        u16::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        u16::to_be_bytes(self)
    }
}

// Implement CilIO support from i16
impl CilIO for i16 {
    type Bytes = [u8; 2];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i16::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i16::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        i16::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        i16::to_be_bytes(self)
    }
}

// Implement CilIO support from u8
impl CilIO for u8 {
    type Bytes = [u8; 1];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u8::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u8::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        u8::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        u8::to_be_bytes(self)
    }
}

// Implement CilIO support from i8
impl CilIO for i8 {
    type Bytes = [u8; 1];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i8::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i8::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        i8::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        i8::to_be_bytes(self)
    }
}

// Implement CilIO support from f32
impl CilIO for f32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        f32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        f32::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        f32::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        f32::to_be_bytes(self)
    }
}

// Implement CilIO support from f64
impl CilIO for f64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        f64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        f64::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        f64::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        f64::to_be_bytes(self)
    }
}

// Implement CilIO support from usize
impl CilIO for usize {
    type Bytes = [u8; std::mem::size_of::<usize>()];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        usize::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        usize::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        usize::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        usize::to_be_bytes(self)
    }
}

// Implement CilIO support from isize
impl CilIO for isize {
    type Bytes = [u8; std::mem::size_of::<isize>()];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        isize::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        isize::from_be_bytes(bytes)
    }

    fn to_le_bytes(self) -> Self::Bytes {
        isize::to_le_bytes(self)
    }

    fn to_be_bytes(self) -> Self::Bytes {
        isize::to_be_bytes(self)
    }
}

/// Safely reads a value of type `T` in little-endian byte order from a data buffer.
///
/// This function reads from the beginning of the buffer and supports all types that implement
/// the [`crate::utils::CilIO`] trait (u8, i8, u16, i16, u32, i32, u64, i64, f32, f64).
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_le;
///
/// let data = [0x01, 0x00, 0x00, 0x00]; // Little-endian u32: 1
/// let value: u32 = read_le(&data)?;
/// assert_eq!(value, 1);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn read_le<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_le_at(data, &mut offset)
}

/// Safely reads a value of type `T` in little-endian byte order from a data buffer at a specific offset.
///
/// This function reads from the specified offset and automatically advances the offset by the
/// number of bytes read. Supports all types that implement the [`crate::utils::CilIO`] trait.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_le_at;
///
/// let data = [0x01, 0x00, 0x02, 0x00]; // Two u16 values: 1, 2
/// let mut offset = 0;
///
/// let first: u16 = read_le_at(&data, &mut offset)?;
/// assert_eq!(first, 1);
/// assert_eq!(offset, 2);
///
/// let second: u16 = read_le_at(&data, &mut offset)?;
/// assert_eq!(second, 2);
/// assert_eq!(offset, 4);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn read_le_at<T: CilIO>(data: &[u8], offset: &mut usize) -> Result<T> {
    let type_len = std::mem::size_of::<T>();
    let end = offset.checked_add(type_len).ok_or(io_oob())?;
    let slice = data.get(*offset..end).ok_or(io_oob())?;
    let Ok(read) = slice.try_into() else {
        return Err(io_oob());
    };

    *offset = end;

    Ok(T::from_le_bytes(read))
}

/// Dynamically reads either a 2-byte or 4-byte value in little-endian byte order.
///
/// This function reads either a u16 or u32 value based on the `is_large` parameter,
/// automatically promoting u16 values to u32 for consistent return type handling.
/// This is commonly used in PE metadata parsing where field sizes vary based on context.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
/// * `is_large` - If `true`, reads 4 bytes as u32; if `false`, reads 2 bytes as u16 and promotes to u32
///
/// # Returns
///
/// Returns the decoded value as u32, or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_le_at_dyn;
///
/// let data = [0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
/// let mut offset = 0;
///
/// // Read 2 bytes (promoted to u32)
/// let small_val = read_le_at_dyn(&data, &mut offset, false)?;
/// assert_eq!(small_val, 1);
/// assert_eq!(offset, 2);
///
/// // Read 4 bytes
/// let large_val = read_le_at_dyn(&data, &mut offset, true)?;
/// assert_eq!(large_val, 2);
/// assert_eq!(offset, 6);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn read_le_at_dyn(data: &[u8], offset: &mut usize, is_large: bool) -> Result<u32> {
    let res = if is_large {
        read_le_at::<u32>(data, offset)?
    } else {
        u32::from(read_le_at::<u16>(data, offset)?)
    };

    Ok(res)
}

/// Safely reads a value of type `T` in big-endian byte order from a data buffer.
///
/// This function reads from the beginning of the buffer and supports all types that implement
/// the [`crate::utils::CilIO`] trait. Note that PE/CIL files typically use little-endian,
/// so this function is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_be;
///
/// let data = [0x00, 0x00, 0x00, 0x01]; // Big-endian u32: 1
/// let value: u32 = read_be(&data)?;
/// assert_eq!(value, 1);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn read_be<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_be_at(data, &mut offset)
}

/// Safely reads a value of type `T` in big-endian byte order from a data buffer at a specific offset.
///
/// This function reads from the specified offset and automatically advances the offset by the
/// number of bytes read. Note that PE/CIL files typically use little-endian, so this function
/// is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_be_at;
///
/// let data = [0x00, 0x01, 0x00, 0x02]; // Two big-endian u16 values: 1, 2
/// let mut offset = 0;
///
/// let first: u16 = read_be_at(&data, &mut offset)?;
/// assert_eq!(first, 1);
/// assert_eq!(offset, 2);
///
/// let second: u16 = read_be_at(&data, &mut offset)?;
/// assert_eq!(second, 2);
/// assert_eq!(offset, 4);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn read_be_at<T: CilIO>(data: &[u8], offset: &mut usize) -> Result<T> {
    let type_len = std::mem::size_of::<T>();
    let end = offset.checked_add(type_len).ok_or(io_oob())?;
    let slice = data.get(*offset..end).ok_or(io_oob())?;
    let Ok(read) = slice.try_into() else {
        return Err(io_oob());
    };

    *offset = end;

    Ok(T::from_be_bytes(read))
}

/// Dynamically reads either a 2-byte or 4-byte value in big-endian byte order.
///
/// This function reads either a u16 or u32 value based on the `is_large` parameter,
/// automatically promoting u16 values to u32 for consistent return type handling.
/// Note that PE/CIL files typically use little-endian, so this function is mainly
/// for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
/// * `is_large` - If `true`, reads 4 bytes as u32; if `false`, reads 2 bytes as u16 and promotes to u32
///
/// # Returns
///
/// Returns the decoded value as u32, or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_be_at_dyn;
///
/// let data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
/// let mut offset = 0;
///
/// // Read 2 bytes (promoted to u32)
/// let small_val = read_be_at_dyn(&data, &mut offset, false)?;
/// assert_eq!(small_val, 1);
/// assert_eq!(offset, 2);
///
/// // Read 4 bytes
/// let large_val = read_be_at_dyn(&data, &mut offset, true)?;
/// assert_eq!(large_val, 2);
/// assert_eq!(offset, 6);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn read_be_at_dyn(data: &[u8], offset: &mut usize, is_large: bool) -> Result<u32> {
    let res = if is_large {
        read_be_at::<u32>(data, offset)?
    } else {
        u32::from(read_be_at::<u16>(data, offset)?)
    };

    Ok(res)
}

/// Safely writes a value of type `T` in little-endian byte order to a data buffer.
///
/// This function writes to the beginning of the buffer and supports all types that implement
/// the [`crate::utils::CilIO`] trait (u8, i8, u16, i16, u32, i32, u64, i64, f32, f64).
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `value` - The value to write
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_le;
///
/// let mut data = [0u8; 4];
/// let value: u32 = 1;
/// write_le(&mut data, value)?;
/// assert_eq!(data, [0x01, 0x00, 0x00, 0x00]); // Little-endian u32: 1
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn write_le<T: CilIO>(data: &mut [u8], value: T) -> Result<()> {
    let mut offset = 0_usize;
    write_le_at(data, &mut offset, value)
}

/// Safely writes a value of type `T` in little-endian byte order to a data buffer at a specific offset.
///
/// This function writes at the specified offset and automatically advances the offset by the
/// number of bytes written. Supports all types that implement the [`crate::utils::CilIO`] trait.
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `offset` - Mutable reference to the offset position (will be advanced after writing)
/// * `value` - The value to write
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_le_at;
///
/// let mut data = [0u8; 4];
/// let mut offset = 0;
///
/// let first: u16 = 1;
/// write_le_at(&mut data, &mut offset, first)?;
/// assert_eq!(offset, 2);
///
/// let second: u16 = 2;
/// write_le_at(&mut data, &mut offset, second)?;
/// assert_eq!(offset, 4);
/// assert_eq!(data, [0x01, 0x00, 0x02, 0x00]); // Two u16 values: 1, 2
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn write_le_at<T: CilIO>(data: &mut [u8], offset: &mut usize, value: T) -> Result<()> {
    let type_len = std::mem::size_of::<T>();
    let end = offset.checked_add(type_len).ok_or(io_oob())?;
    let bytes = value.to_le_bytes();
    let dst = data.get_mut(*offset..end).ok_or(io_oob())?;
    dst.copy_from_slice(bytes.as_ref());
    *offset = end;

    Ok(())
}

/// Dynamically writes either a 2-byte or 4-byte value in little-endian byte order.
///
/// This function writes either a u16 or u32 value based on the `is_large` parameter.
/// If `is_large` is false, the u32 value is truncated to u16 before writing.
/// This is commonly used in PE metadata generation where field sizes vary based on context.
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `offset` - Mutable reference to the offset position (will be advanced after writing)
/// * `value` - The u32 value to write
/// * `is_large` - If `true`, writes 4 bytes as u32; if `false`, writes 2 bytes as u16
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Errors
///
/// When there are too few bytes, and when `is_large` is `false` and `value` does not fit two
/// bytes: an index too wide for its column is refused rather than cut to its low bytes, which
/// would point at another row or heap entry.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_le_at_dyn;
///
/// let mut data = [0u8; 6];
/// let mut offset = 0;
///
/// // Write 2 bytes
/// write_le_at_dyn(&mut data, &mut offset, 1, false)?;
/// assert_eq!(offset, 2);
///
/// // Write 4 bytes
/// write_le_at_dyn(&mut data, &mut offset, 2, true)?;
/// assert_eq!(offset, 6);
/// assert_eq!(data, [0x01, 0x00, 0x02, 0x00, 0x00, 0x00]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn write_le_at_dyn(
    data: &mut [u8],
    offset: &mut usize,
    value: u32,
    is_large: bool,
) -> Result<()> {
    if is_large {
        write_le_at::<u32>(data, offset, value)?;
    } else {
        let narrow = u16::try_from(value)
            .map_err(|_| malformed_error!("{value:#x} does not fit a two-byte index column"))?;
        write_le_at::<u16>(data, offset, narrow)?;
    }

    Ok(())
}

/// Safely writes a value of type `T` in big-endian byte order to a data buffer.
///
/// This function writes to the beginning of the buffer and supports all types that implement
/// the [`crate::utils::CilIO`] trait. Note that PE/CIL files typically use little-endian,
/// so this function is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `value` - The value to write
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_be;
///
/// let mut data = [0u8; 4];
/// let value: u32 = 1;
/// write_be(&mut data, value)?;
/// assert_eq!(data, [0x00, 0x00, 0x00, 0x01]); // Big-endian u32: 1
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn write_be<T: CilIO>(data: &mut [u8], value: T) -> Result<()> {
    let mut offset = 0_usize;
    write_be_at(data, &mut offset, value)
}

/// Safely writes a value of type `T` in big-endian byte order to a data buffer at a specific offset.
///
/// This function writes at the specified offset and automatically advances the offset by the
/// number of bytes written. Note that PE/CIL files typically use little-endian, so this function
/// is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `offset` - Mutable reference to the offset position (will be advanced after writing)
/// * `value` - The value to write
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_be_at;
///
/// let mut data = [0u8; 4];
/// let mut offset = 0;
///
/// let first: u16 = 1;
/// write_be_at(&mut data, &mut offset, first)?;
/// assert_eq!(offset, 2);
///
/// let second: u16 = 2;
/// write_be_at(&mut data, &mut offset, second)?;
/// assert_eq!(offset, 4);
/// assert_eq!(data, [0x00, 0x01, 0x00, 0x02]); // Two big-endian u16 values: 1, 2
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn write_be_at<T: CilIO>(data: &mut [u8], offset: &mut usize, value: T) -> Result<()> {
    let type_len = std::mem::size_of::<T>();
    let end = offset.checked_add(type_len).ok_or(io_oob())?;
    let bytes = value.to_be_bytes();
    let dst = data.get_mut(*offset..end).ok_or(io_oob())?;
    dst.copy_from_slice(bytes.as_ref());
    *offset = end;

    Ok(())
}

/// Dynamically writes either a 2-byte or 4-byte value in big-endian byte order.
///
/// This function writes either a u16 or u32 value based on the `is_large` parameter.
/// If `is_large` is false, the u32 value is truncated to u16 before writing.
/// Note that PE/CIL files typically use little-endian, so this function is mainly
/// for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The mutable byte buffer to write to
/// * `offset` - Mutable reference to the offset position (will be advanced after writing)
/// * `value` - The u32 value to write
/// * `is_large` - If `true`, writes 4 bytes as u32; if `false`, writes 2 bytes as u16
///
/// # Returns
///
/// Returns `Ok(())` on success or [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if there are insufficient bytes.
///
/// # Errors
///
/// When there are too few bytes, and when `is_large` is `false` and `value` does not fit two
/// bytes: an index too wide for its column is refused rather than cut to its low bytes, which
/// would point at another row or heap entry.
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_be_at_dyn;
///
/// let mut data = [0u8; 6];
/// let mut offset = 0;
///
/// // Write 2 bytes
/// write_be_at_dyn(&mut data, &mut offset, 1, false)?;
/// assert_eq!(offset, 2);
///
/// // Write 4 bytes
/// write_be_at_dyn(&mut data, &mut offset, 2, true)?;
/// assert_eq!(offset, 6);
/// assert_eq!(data, [0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn write_be_at_dyn(
    data: &mut [u8],
    offset: &mut usize,
    value: u32,
    is_large: bool,
) -> Result<()> {
    if is_large {
        write_be_at::<u32>(data, offset, value)?;
    } else {
        let narrow = u16::try_from(value)
            .map_err(|_| malformed_error!("{value:#x} does not fit a two-byte index column"))?;
        write_be_at::<u16>(data, offset, narrow)?;
    }

    Ok(())
}

/// Write methods for binary serialization
///
/// These methods provide the counterpart to the read methods, enabling binary
/// data serialization using the same formats and encodings.
/// Write a compressed unsigned integer using ECMA-335 format (II.23.2).
///
/// # Encoding Format
///
/// - **0x00-0x7F**: Single byte (value & 0x7F)
/// - **0x80-0x3FFF**: Two bytes (0x80 | (value >> 8), value & 0xFF)
/// - **0x4000-0x1FFFFFFF**: Four bytes (0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
///
/// # Arguments
///
/// * `value` - The unsigned integer to encode, at most `0x1FFF_FFFF`
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Errors
///
/// When `value` exceeds `0x1FFF_FFFF`, which the format cannot state; nothing is written.
///
/// # Examples
///
/// ```rust
/// # use dotscope::io::write_compressed_uint;
/// let mut buffer = Vec::new();
/// write_compressed_uint(127, &mut buffer)?;
/// assert_eq!(buffer, vec![127]);
///
/// let mut buffer = Vec::new();
/// write_compressed_uint(128, &mut buffer)?;
/// assert_eq!(buffer, vec![0x80, 0x80]);
///
/// assert!(write_compressed_uint(0x2000_0000, &mut buffer).is_err());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn write_compressed_uint(value: u32, buffer: &mut Vec<u8>) -> Result<()> {
    if value < 0x80 {
        buffer.push(value as u8);
    } else if value < 0x4000 {
        buffer.push(0x80 | ((value >> 8) as u8));
        buffer.push(value as u8);
    } else if value <= 0x1FFF_FFFF {
        buffer.push(0xC0 | ((value >> 24) as u8));
        buffer.push((value >> 16) as u8);
        buffer.push((value >> 8) as u8);
        buffer.push(value as u8);
    } else {
        return Err(malformed_error!(
            "{value:#x} is outside the range of a compressed unsigned integer"
        ));
    }
    Ok(())
}

/// Write a compressed signed integer using ECMA-335 format (II.23.2).
///
/// The value is taken as a two's complement number of the narrowest width
/// that holds it (7, 14 or 29 bits), rotated left by one bit so the sign lands
/// in the lowest bit, and written in the 1, 2 or 4 byte unsigned form.
///
/// # Arguments
///
/// * `value` - The signed integer to encode, in `-2^28..2^28`
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Errors
///
/// Returns an error for a value outside `-2^28..2^28`, which the format
/// cannot represent.
///
/// # Examples
///
/// ```no_run
/// # use dotscope::io::write_compressed_int;
/// let mut buffer = Vec::new();
/// write_compressed_int(3, &mut buffer)?;
/// assert_eq!(buffer, vec![0x06]);
///
/// let mut buffer = Vec::new();
/// write_compressed_int(-3, &mut buffer)?;
/// assert_eq!(buffer, vec![0x7B]);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[allow(clippy::cast_sign_loss)]
pub fn write_compressed_int(value: i32, buffer: &mut Vec<u8>) -> Result<()> {
    let bits: u32 = if (-(1 << 6)..(1 << 6)).contains(&value) {
        7
    } else if (-(1 << 13)..(1 << 13)).contains(&value) {
        14
    } else if (-(1 << 28)..(1 << 28)).contains(&value) {
        29
    } else {
        return Err(malformed_error!(
            "{value} is outside the range of a compressed signed integer"
        ));
    };
    // The encoding's mask and the shift that brings its top bit to bit 0.
    let (mask, top_shift): (u32, u32) = match bits {
        7 => (0x7F, 6),
        14 => (0x3FFF, 13),
        _ => (0x1FFF_FFFF, 28),
    };
    let twos = (value as u32) & mask;
    let rotated = ((twos << 1) & mask) | (twos >> top_shift);
    // The width is the value's, not the rotated bits': -8192 rotates to 1
    // and is still written in two bytes.
    #[allow(clippy::cast_possible_truncation)]
    match bits {
        7 => buffer.push(rotated as u8),
        14 => buffer.extend_from_slice(&((0x8000 | rotated) as u16).to_be_bytes()),
        _ => buffer.extend_from_slice(&(0xC000_0000 | rotated).to_be_bytes()),
    }
    Ok(())
}

/// Write a 7-bit encoded integer.
///
/// Encodes an unsigned integer using 7-bit encoding with continuation bits.
/// This encoding uses the most significant bit of each byte as a continuation flag.
///
/// # Arguments
///
/// * `value` - The unsigned integer to encode
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Examples
///
/// ```no_run
/// # use dotscope::io::write_7bit_encoded_int;
/// let mut buffer = Vec::new();
/// write_7bit_encoded_int(127, &mut buffer);
/// assert_eq!(buffer, vec![0x7F]);
///
/// let mut buffer = Vec::new();
/// write_7bit_encoded_int(128, &mut buffer);
/// assert_eq!(buffer, vec![0x80, 0x01]);
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn write_7bit_encoded_int(mut value: u32, buffer: &mut Vec<u8>) {
    while value >= 0x80 {
        buffer.push((value as u8) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

/// Write a UTF-8 string with null terminator.
///
/// Encodes the string as UTF-8 bytes followed by a null terminator (0x00).
///
/// # Arguments
///
/// * `value` - The string to encode
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Examples
///
/// ```no_run
/// # use dotscope::io::write_string_utf8;
/// let mut buffer = Vec::new();
/// write_string_utf8("Hello", &mut buffer);
/// assert_eq!(buffer, b"Hello\0");
/// ```
pub fn write_string_utf8(value: &str, buffer: &mut Vec<u8>) {
    buffer.extend_from_slice(value.as_bytes());
    buffer.push(0);
}

/// Write a length-prefixed UTF-8 string.
///
/// Encodes the string length as a 7-bit encoded integer, followed by the
/// UTF-8 bytes. This format is commonly used in .NET metadata streams.
///
/// # Arguments
///
/// * `value` - The string to encode
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Examples
///
/// ```no_run
/// # use dotscope::io::write_prefixed_string_utf8;
/// let mut buffer = Vec::new();
/// write_prefixed_string_utf8("Hello", &mut buffer);
/// assert_eq!(buffer, vec![5, b'H', b'e', b'l', b'l', b'o']);
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn write_prefixed_string_utf8(value: &str, buffer: &mut Vec<u8>) {
    let bytes = value.as_bytes();
    write_7bit_encoded_int(bytes.len() as u32, buffer);
    buffer.extend_from_slice(bytes);
}

/// Write a length-prefixed UTF-16 string.
///
/// Encodes the string length in bytes as a 7-bit encoded integer, followed by
/// the UTF-16 bytes in little-endian format.
///
/// # Arguments
///
/// * `value` - The string to encode
/// * `buffer` - The output buffer to write encoded bytes to
///
/// # Examples
///
/// ```no_run
/// # use dotscope::io::write_prefixed_string_utf16;
/// let mut buffer = Vec::new();
/// write_prefixed_string_utf16("Hello", &mut buffer);
/// // Length 10 bytes (5 UTF-16 chars), followed by "Hello" in UTF-16 LE
/// assert_eq!(buffer, vec![10, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]);
/// ```
#[allow(clippy::cast_possible_truncation)]
pub fn write_prefixed_string_utf16(value: &str, buffer: &mut Vec<u8>) {
    let utf16_chars: Vec<u16> = value.encode_utf16().collect();
    // saturating_mul: the byte length is then bounded; the 7-bit prefix is u32
    // and overflow only matters for >2GiB strings, which we cannot encode anyway.
    let byte_length = utf16_chars.len().saturating_mul(2);

    write_7bit_encoded_int(byte_length as u32, buffer);

    for char in utf16_chars {
        buffer.push(char as u8); // Low byte (little-endian)
        buffer.push((char >> 8) as u8); // High byte
    }
}

/// Decodes a null-terminated UTF-16LE byte slice to a [`String`].
///
/// Reads 16-bit little-endian code units until a null terminator (`0x0000`)
/// is reached or the data is exhausted. Requires at least 2 bytes and at
/// least one non-null code unit.
///
/// # Returns
///
/// `Some(String)` on success, `None` if the input is too short or contains
/// only a null terminator.
#[cfg(feature = "deobfuscation")]
#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    let mut utf16_chars = Vec::new();
    // `as_chunks` hands back the two-byte arrays themselves, so there is no
    // fallible conversion to answer for; a trailing odd byte lands in the
    // remainder, which a UTF-16 unit cannot be built from anyway.
    for &pair in bytes.as_chunks::<2>().0 {
        let ch = u16::from_le_bytes(pair);
        if ch == 0 {
            break;
        }
        utf16_chars.push(ch);
    }
    if utf16_chars.is_empty() {
        return None;
    }
    String::from_utf16(&utf16_chars).ok()
}

/// Write a null-terminated UTF-8 string at a specific offset.
///
/// Writes the string bytes followed by a null terminator to the buffer at the
/// specified offset, advancing the offset by the number of bytes written.
/// This is commonly used for PE format string tables and null-terminated string data.
///
/// # Arguments
///
/// * `data` - The buffer to write to
/// * `offset` - Mutable reference to the current position (will be advanced)
/// * `value` - The string to write
///
/// # Returns
/// * `Ok(())` - If the string was written successfully
/// * `Err(OutOfBounds)` - If there is insufficient space in the buffer
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::write_string_at;
///
/// let mut buffer = [0u8; 10];
/// let mut offset = 0;
///
/// write_string_at(&mut buffer, &mut offset, "Hello")?;
/// assert_eq!(offset, 6); // 5 chars + null terminator
/// assert_eq!(&buffer[0..6], b"Hello\0");
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
/// Note that the offset parameter is modified, so each thread should use its own offset variable.
pub fn write_string_at(data: &mut [u8], offset: &mut usize, value: &str) -> Result<()> {
    let string_bytes = value.as_bytes();
    let after_str = offset.checked_add(string_bytes.len()).ok_or(io_oob())?;
    let after_null = after_str.checked_add(1).ok_or(io_oob())?;

    let dst = data.get_mut(*offset..after_str).ok_or(io_oob())?;
    dst.copy_from_slice(string_bytes);

    *data.get_mut(after_str).ok_or(io_oob())? = 0;

    *offset = after_null;

    Ok(())
}

/// Reads a compressed integer from a byte buffer according to ECMA-335 II.24.2.4.
///
/// Compressed integers are used throughout .NET metadata to encode length prefixes
/// and other size information efficiently. The encoding uses 1, 2, or 4 bytes
/// depending on the value being encoded.
///
/// # Format
/// - Single byte (0xxxxxxx): Values 0-127
/// - Two bytes (10xxxxxx xxxxxxxx): Values 128-16383  
/// - Four bytes (110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx): Values 16384-536870911
///
/// # Arguments
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the current position (will be advanced)
///
/// # Returns
/// * `Ok((value, bytes_consumed))` - The decoded value and number of bytes read
/// * `Err(OutOfBounds)` - If there are insufficient bytes in the buffer
///
/// # Examples
/// ```no_run
/// use dotscope::io::read_compressed_int;
///
/// let data = [0x7F, 0x80, 0x80, 0xC0, 0x00, 0x00, 0x40];
/// let mut offset = 0;
///
/// // Read single byte value (127)
/// let (value, consumed) = read_compressed_int(&data, &mut offset)?;
/// assert_eq!(value, 127);
/// assert_eq!(consumed, 1);
/// assert_eq!(offset, 1);
///
/// // Read two byte value (128)
/// let (value, consumed) = read_compressed_int(&data, &mut offset)?;
/// assert_eq!(value, 128);
/// assert_eq!(consumed, 2);
/// assert_eq!(offset, 3);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_compressed_int(data: &[u8], offset: &mut usize) -> Result<(usize, usize)> {
    let first_byte = *data.get(*offset).ok_or(io_oob())?;

    if first_byte & 0x80 == 0 {
        // Single byte: 0xxxxxxx
        *offset = offset.checked_add(1).ok_or(io_oob())?;
        Ok((first_byte as usize, 1))
    } else if first_byte & 0xC0 == 0x80 {
        // Two bytes: 10xxxxxx xxxxxxxx
        let next = offset.checked_add(1).ok_or(io_oob())?;
        let second_byte = *data.get(next).ok_or(io_oob())?;
        let value = (((first_byte & 0x3F) as usize) << 8) | (second_byte as usize);
        *offset = offset.checked_add(2).ok_or(io_oob())?;
        Ok((value, 2))
    } else {
        // Four bytes: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        let o1 = offset.checked_add(1).ok_or(io_oob())?;
        let o2 = offset.checked_add(2).ok_or(io_oob())?;
        let o3 = offset.checked_add(3).ok_or(io_oob())?;
        let b1 = *data.get(o1).ok_or(io_oob())?;
        let b2 = *data.get(o2).ok_or(io_oob())?;
        let b3 = *data.get(o3).ok_or(io_oob())?;
        let mut value = ((first_byte & 0x1F) as usize) << 24;
        value |= (b1 as usize) << 16;
        value |= (b2 as usize) << 8;
        value |= b3 as usize;
        *offset = offset.checked_add(4).ok_or(io_oob())?;
        Ok((value, 4))
    }
}

/// Reads a compressed integer from a specific offset without advancing a mutable offset.
///
/// This is a convenience function for reading compressed integers when you need
/// to specify an absolute offset rather than using a mutable offset reference.
///
/// # Arguments
/// * `data` - The byte buffer to read from  
/// * `offset` - The absolute offset to read from
///
/// # Returns
/// * `Ok((value, bytes_consumed))` - The decoded value and number of bytes read
/// * `Err(OutOfBounds)` - If there are insufficient bytes in the buffer
///
/// # Examples
/// ```no_run
/// use dotscope::io::read_compressed_int_at;
///
/// let data = [0x7F, 0x80, 0x80];
///
/// // Read from offset 0
/// let (value, consumed) = read_compressed_int_at(&data, 0)?;
/// assert_eq!(value, 127);
/// assert_eq!(consumed, 1);
///
/// // Read from offset 1  
/// let (value, consumed) = read_compressed_int_at(&data, 1)?;
/// assert_eq!(value, 128);
/// assert_eq!(consumed, 2);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_compressed_int_at(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    let mut mutable_offset = offset;
    read_compressed_int(data, &mut mutable_offset)
}

/// Reads a .NET SerString packed length (ECMA-335, Partition II, Section 23.2).
///
/// Thin wrapper around [`read_compressed_int_at`] that additionally handles
/// the `0xFF` null-string sentinel and empty input. The encoding uses 1, 2,
/// or 4 bytes for the length; `0xFF` signals a null string.
///
/// # Returns
///
/// `Some((length, bytes_consumed))` on success, `None` for null strings
/// (`0xFF`), empty input, or truncated data.
#[cfg(feature = "deobfuscation")]
#[must_use]
pub fn read_packed_len(data: &[u8]) -> Option<(usize, usize)> {
    if *data.first()? == 0xFF {
        return None;
    }
    read_compressed_int_at(data, 0).ok()
}

/// Reads a compressed unsigned integer from a byte buffer according to ECMA-335 specification.
///
/// This function reads a compressed unsigned integer value from the buffer at the current
/// offset and advances the offset by the number of bytes consumed. The encoding follows
/// the ECMA-335 standard for compressed unsigned integers used in .NET metadata.
///
/// # Arguments
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
///
/// # Returns
/// * `Ok(value)` - The decoded u32 value
/// * `Err(OutOfBounds)` - If there are insufficient bytes in the buffer
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_compressed_uint;
///
/// let data = [0x2A]; // Single byte: 42
/// let mut offset = 0;
/// let value = read_compressed_uint(&data, &mut offset)?;
/// assert_eq!(value, 42);
/// assert_eq!(offset, 1);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_compressed_uint(data: &[u8], offset: &mut usize) -> Result<u32> {
    let (value, _consumed) = read_compressed_int(data, offset)?;
    u32::try_from(value).map_err(|_| io_oob())
}

/// Reads a compressed unsigned integer from a specific offset without advancing a mutable offset.
///
/// This is a convenience function for reading compressed unsigned integers when you need
/// to specify an absolute offset rather than using a mutable offset reference.
///
/// # Arguments
/// * `data` - The byte buffer to read from  
/// * `offset` - The absolute offset to read from
///
/// # Returns
/// * `Ok(value)` - The decoded u32 value
/// * `Err(OutOfBounds)` - If there are insufficient bytes in the buffer
///
/// # Examples
///
/// ```no_run
/// use dotscope::io::read_compressed_uint_at;
///
/// let data = [0x81, 0x2C]; // Two bytes: 300
/// let value = read_compressed_uint_at(&data, 0)?;
/// assert_eq!(value, 300);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_compressed_uint_at(data: &[u8], offset: usize) -> Result<u32> {
    let mut mutable_offset = offset;
    read_compressed_uint(data, &mut mutable_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, ParseFailure};

    const TEST_BUFFER: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    #[test]
    fn read_le_u8() {
        let result = read_le::<u8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x01);
    }

    #[test]
    fn read_le_i8() {
        let result = read_le::<i8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x01);
    }

    #[test]
    fn read_le_u16() {
        let result = read_le::<u16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0201);
    }

    #[test]
    fn read_le_i16() {
        let result = read_le::<i16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0201);
    }

    #[test]
    fn read_le_u32() {
        let result = read_le::<u32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0403_0201);
    }

    #[test]
    fn read_le_i32() {
        let result = read_le::<i32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0403_0201);
    }

    #[test]
    fn read_le_u64() {
        let result = read_le::<u64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0807_0605_0403_0201);
    }

    #[test]
    fn read_le_i64() {
        let result = read_le::<i64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0807_0605_0403_0201);
    }

    #[test]
    fn read_be_u8() {
        let result = read_be::<u8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1);
    }

    #[test]
    fn read_be_i8() {
        let result = read_be::<i8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1);
    }

    #[test]
    fn read_be_u16() {
        let result = read_be::<u16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102);
    }

    #[test]
    fn read_be_i16() {
        let result = read_be::<i16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102);
    }

    #[test]
    fn read_be_u32() {
        let result = read_be::<u32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0102_0304);
    }

    #[test]
    fn read_be_i32() {
        let result = read_be::<i32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0102_0304);
    }

    #[test]
    fn read_be_u64() {
        let result = read_be::<u64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_be_i64() {
        let result = read_be::<i64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_be_f32() {
        let result = read_be::<f32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 2.3879393e-38);
    }

    #[test]
    fn read_be_f64() {
        let result = read_be::<f64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 8.20788039913184e-304);
    }

    #[test]
    fn read_le_f32() {
        let result = read_le::<f32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 1.5399896e-36);
    }

    #[test]
    fn read_le_f64() {
        let result = read_le::<f64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 5.447603722011605e-270);
    }

    #[test]
    fn read_be_from() {
        let mut offset = 2_usize;
        let result = read_be_at::<u16>(&TEST_BUFFER, &mut offset).unwrap();
        assert_eq!(result, 0x304);
    }

    #[test]
    fn read_le_from() {
        let mut offset = 2_usize;
        let result = read_le_at::<u16>(&TEST_BUFFER, &mut offset).unwrap();
        assert_eq!(result, 0x403);
    }

    #[test]
    fn read_le_dyn() {
        let mut offset = 0;

        let res_1 = read_le_at_dyn(&TEST_BUFFER, &mut offset, true).unwrap();
        assert_eq!(res_1, 0x4030201);

        offset = 0;
        let res_2 = read_le_at_dyn(&TEST_BUFFER, &mut offset, false).unwrap();
        assert_eq!(res_2, 0x201);
    }

    #[test]
    fn read_be_dyn() {
        let mut offset = 0;

        let res_1 = read_be_at_dyn(&TEST_BUFFER, &mut offset, true).unwrap();
        assert_eq!(res_1, 0x1020304);

        offset = 0;
        let res_2 = read_be_at_dyn(&TEST_BUFFER, &mut offset, false).unwrap();
        assert_eq!(res_2, 0x102);
    }

    #[test]
    fn errors() {
        let buffer = [0xFF, 0xFF, 0xFF, 0xFF];

        let result = read_le::<u64>(&buffer);
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        let result = read_le::<f64>(&buffer);
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn read_le_usize() {
        let size_bytes = std::mem::size_of::<usize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - little endian representation of 0x12345678 (or truncated for smaller usize)
        buffer[0] = 0x78;
        buffer[1] = 0x56;
        if size_bytes >= 4 {
            buffer[2] = 0x34;
            buffer[3] = 0x12;
        }

        let result = read_le::<usize>(&buffer).unwrap();
        if size_bytes == 8 {
            assert_eq!(result, 0x12345678);
        } else {
            assert_eq!(result, 0x5678);
        }
    }

    #[test]
    fn read_be_usize() {
        let size_bytes = std::mem::size_of::<usize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - big endian representation
        if size_bytes >= 4 {
            buffer[size_bytes - 4] = 0x12;
            buffer[size_bytes - 3] = 0x34;
        }
        buffer[size_bytes - 2] = 0x56;
        buffer[size_bytes - 1] = 0x78;

        let result = read_be::<usize>(&buffer).unwrap();
        if size_bytes == 8 {
            assert_eq!(result, 0x12345678);
        } else {
            assert_eq!(result, 0x5678);
        }
    }

    #[test]
    fn read_le_isize() {
        let size_bytes = std::mem::size_of::<isize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - little endian representation of -1
        for item in buffer.iter_mut().take(size_bytes) {
            *item = 0xFF;
        }

        let result = read_le::<isize>(&buffer).unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn read_be_isize() {
        let size_bytes = std::mem::size_of::<isize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - big endian representation of -1
        for item in buffer.iter_mut().take(size_bytes) {
            *item = 0xFF;
        }

        let result = read_be::<isize>(&buffer).unwrap();
        assert_eq!(result, -1);
    }

    // Writing function tests
    #[test]
    fn write_le_u8() {
        let mut buffer = [0u8; 1];
        write_le(&mut buffer, 0x42u8).unwrap();
        assert_eq!(buffer, [0x42]);
    }

    #[test]
    fn write_le_i8() {
        let mut buffer = [0u8; 1];
        write_le(&mut buffer, -1i8).unwrap();
        assert_eq!(buffer, [0xFF]);
    }

    #[test]
    fn write_le_u16() {
        let mut buffer = [0u8; 2];
        write_le(&mut buffer, 0x1234u16).unwrap();
        assert_eq!(buffer, [0x34, 0x12]); // Little-endian
    }

    #[test]
    fn write_le_i16() {
        let mut buffer = [0u8; 2];
        write_le(&mut buffer, -1i16).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF]);
    }

    #[test]
    fn write_le_u32() {
        let mut buffer = [0u8; 4];
        write_le(&mut buffer, 0x12345678u32).unwrap();
        assert_eq!(buffer, [0x78, 0x56, 0x34, 0x12]); // Little-endian
    }

    #[test]
    fn write_le_i32() {
        let mut buffer = [0u8; 4];
        write_le(&mut buffer, -1i32).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn write_le_u64() {
        let mut buffer = [0u8; 8];
        write_le(&mut buffer, 0x123456789ABCDEFu64).unwrap();
        assert_eq!(buffer, [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]); // Little-endian
    }

    #[test]
    fn write_le_i64() {
        let mut buffer = [0u8; 8];
        write_le(&mut buffer, -1i64).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn write_be_u8() {
        let mut buffer = [0u8; 1];
        write_be(&mut buffer, 0x42u8).unwrap();
        assert_eq!(buffer, [0x42]);
    }

    #[test]
    fn write_be_i8() {
        let mut buffer = [0u8; 1];
        write_be(&mut buffer, -1i8).unwrap();
        assert_eq!(buffer, [0xFF]);
    }

    #[test]
    fn write_be_u16() {
        let mut buffer = [0u8; 2];
        write_be(&mut buffer, 0x1234u16).unwrap();
        assert_eq!(buffer, [0x12, 0x34]); // Big-endian
    }

    #[test]
    fn write_be_i16() {
        let mut buffer = [0u8; 2];
        write_be(&mut buffer, -1i16).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF]);
    }

    #[test]
    fn write_be_u32() {
        let mut buffer = [0u8; 4];
        write_be(&mut buffer, 0x12345678u32).unwrap();
        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78]); // Big-endian
    }

    #[test]
    fn write_be_i32() {
        let mut buffer = [0u8; 4];
        write_be(&mut buffer, -1i32).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn write_be_u64() {
        let mut buffer = [0u8; 8];
        write_be(&mut buffer, 0x123456789ABCDEFu64).unwrap();
        assert_eq!(buffer, [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]); // Big-endian
    }

    #[test]
    fn write_be_i64() {
        let mut buffer = [0u8; 8];
        write_be(&mut buffer, -1i64).unwrap();
        assert_eq!(buffer, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn write_le_f32() {
        let mut buffer = [0u8; 4];
        write_le(&mut buffer, 1.0f32).unwrap();
        // IEEE 754 little-endian representation of 1.0f32
        assert_eq!(buffer, [0x00, 0x00, 0x80, 0x3F]);
    }

    #[test]
    fn write_le_f64() {
        let mut buffer = [0u8; 8];
        write_le(&mut buffer, 1.0f64).unwrap();
        // IEEE 754 little-endian representation of 1.0f64
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F]);
    }

    #[test]
    fn write_be_f32() {
        let mut buffer = [0u8; 4];
        write_be(&mut buffer, 1.0f32).unwrap();
        // IEEE 754 big-endian representation of 1.0f32
        assert_eq!(buffer, [0x3F, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn write_be_f64() {
        let mut buffer = [0u8; 8];
        write_be(&mut buffer, 1.0f64).unwrap();
        // IEEE 754 big-endian representation of 1.0f64
        assert_eq!(buffer, [0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn write_le_at_sequential() {
        let mut buffer = [0u8; 8];
        let mut offset = 0;

        write_le_at(&mut buffer, &mut offset, 0x1234u16).unwrap();
        assert_eq!(offset, 2);

        write_le_at(&mut buffer, &mut offset, 0x5678u16).unwrap();
        assert_eq!(offset, 4);

        write_le_at(&mut buffer, &mut offset, 0xABCDu32).unwrap();
        assert_eq!(offset, 8);

        assert_eq!(buffer, [0x34, 0x12, 0x78, 0x56, 0xCD, 0xAB, 0x00, 0x00]);
    }

    #[test]
    fn write_be_at_sequential() {
        let mut buffer = [0u8; 8];
        let mut offset = 0;

        write_be_at(&mut buffer, &mut offset, 0x1234u16).unwrap();
        assert_eq!(offset, 2);

        write_be_at(&mut buffer, &mut offset, 0x5678u16).unwrap();
        assert_eq!(offset, 4);

        write_be_at(&mut buffer, &mut offset, 0xABCDu32).unwrap();
        assert_eq!(offset, 8);

        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0xAB, 0xCD]);
    }

    #[test]
    fn write_le_dyn() {
        let mut buffer = [0u8; 6];
        let mut offset = 0;

        // Write 2 bytes (small)
        write_le_at_dyn(&mut buffer, &mut offset, 0x1234, false).unwrap();
        assert_eq!(offset, 2);

        // Write 4 bytes (large)
        write_le_at_dyn(&mut buffer, &mut offset, 0x56789ABC, true).unwrap();
        assert_eq!(offset, 6);

        assert_eq!(buffer, [0x34, 0x12, 0xBC, 0x9A, 0x78, 0x56]);
    }

    #[test]
    fn write_be_dyn() {
        let mut buffer = [0u8; 6];
        let mut offset = 0;

        // Write 2 bytes (small)
        write_be_at_dyn(&mut buffer, &mut offset, 0x1234, false).unwrap();
        assert_eq!(offset, 2);

        // Write 4 bytes (large)
        write_be_at_dyn(&mut buffer, &mut offset, 0x56789ABC, true).unwrap();
        assert_eq!(offset, 6);

        assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    /// A value past two bytes is refused for a two-byte write, in either byte order, and
    /// nothing is written: it was cut to its low two bytes, which name another row.
    #[test]
    fn a_value_too_wide_for_two_bytes_is_refused() {
        for write in [write_le_at_dyn, write_be_at_dyn] {
            let mut buffer = [0xAAu8; 4];
            let mut offset = 0;
            assert!(write(&mut buffer, &mut offset, 0x1_0000, false).is_err());
            assert_eq!((buffer, offset), ([0xAA; 4], 0));
            write(&mut buffer, &mut offset, 0xFFFF, false).unwrap();
            assert_eq!(offset, 2);
        }
    }

    #[test]
    fn write_errors() {
        let mut buffer = [0u8; 2];

        // Try to write u32 (4 bytes) into 2-byte buffer
        let result = write_le(&mut buffer, 0x12345678u32);
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        let result = write_be(&mut buffer, 0x12345678u32);
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn round_trip_consistency() {
        // Test that read(write(x)) == x for various types and endianness
        const VALUE_U32: u32 = 0x12345678;
        const VALUE_I32: i32 = -12345;
        const VALUE_F32: f32 = 3.0419;

        // Little-endian round trip
        let mut buffer = [0u8; 4];
        write_le(&mut buffer, VALUE_U32).unwrap();
        let read_value: u32 = read_le(&buffer).unwrap();
        assert_eq!(read_value, VALUE_U32);

        write_le(&mut buffer, VALUE_I32).unwrap();
        let read_value: i32 = read_le(&buffer).unwrap();
        assert_eq!(read_value, VALUE_I32);

        write_le(&mut buffer, VALUE_F32).unwrap();
        let read_value: f32 = read_le(&buffer).unwrap();
        assert_eq!(read_value, VALUE_F32);

        // Big-endian round trip
        write_be(&mut buffer, VALUE_U32).unwrap();
        let read_value: u32 = read_be(&buffer).unwrap();
        assert_eq!(read_value, VALUE_U32);

        write_be(&mut buffer, VALUE_I32).unwrap();
        let read_value: i32 = read_be(&buffer).unwrap();
        assert_eq!(read_value, VALUE_I32);

        write_be(&mut buffer, VALUE_F32).unwrap();
        let read_value: f32 = read_be(&buffer).unwrap();
        assert_eq!(read_value, VALUE_F32);
    }

    #[test]
    fn test_write_compressed_uint_single_byte() {
        let test_cases = vec![
            (0, vec![0]),
            (1, vec![1]),
            (127, vec![127]), // Max single byte value
        ];

        for (value, expected) in test_cases {
            let mut buffer = Vec::new();
            write_compressed_uint(value, &mut buffer).unwrap();
            assert_eq!(buffer, expected, "Failed for value {value}");
        }
    }

    #[test]
    fn test_write_compressed_uint_two_bytes() {
        let test_cases = vec![
            (128, vec![0x80, 0x80]),   // Min two-byte value
            (255, vec![0x80, 0xFF]),   //
            (16383, vec![0xBF, 0xFF]), // Max two-byte value
        ];

        for (value, expected) in test_cases {
            let mut buffer = Vec::new();
            write_compressed_uint(value, &mut buffer).unwrap();
            assert_eq!(buffer, expected, "Failed for value {value}");
        }
    }

    #[test]
    fn test_write_compressed_uint_four_bytes() {
        let test_cases = vec![
            (16384, vec![0xC0, 0x00, 0x40, 0x00]), // Min four-byte value
            (0x1FFFFFFF, vec![0xDF, 0xFF, 0xFF, 0xFF]), // Max four-byte value
        ];

        for (value, expected) in test_cases {
            let mut buffer = Vec::new();
            write_compressed_uint(value, &mut buffer).unwrap();
            assert_eq!(buffer, expected, "Failed for value {value}");
        }
    }

    /// A value past 29 bits has no compressed form: it is refused, where it was written as
    /// four bytes whose top bits named another length.
    #[test]
    fn a_value_past_29_bits_is_refused() {
        for value in [0x2000_0000, 0x8000_0000, u32::MAX] {
            let mut buffer = vec![0xAA];
            assert!(
                write_compressed_uint(value, &mut buffer).is_err(),
                "{value:#x}"
            );
            assert_eq!(buffer, vec![0xAA], "nothing is written for {value:#x}");
        }
    }

    /// The signed examples of ECMA-335 II.23.2, with the ends of each width.
    const ECMA_SIGNED: &[(i32, &[u8])] = &[
        (0, &[0x00]),
        (3, &[0x06]),
        (-3, &[0x7B]),
        (63, &[0x7E]),
        (-1, &[0x7F]),
        (64, &[0x80, 0x80]),
        (-64, &[0x01]),
        (-65, &[0xBF, 0x7F]),
        (8192, &[0xC0, 0x00, 0x40, 0x00]),
        (-8192, &[0x80, 0x01]),
        (268_435_455, &[0xDF, 0xFF, 0xFF, 0xFE]),
        (-268_435_456, &[0xC0, 0x00, 0x00, 0x01]),
    ];

    #[test]
    fn test_write_compressed_int_matches_ecma() {
        for (value, expected) in ECMA_SIGNED {
            let mut buffer = Vec::new();
            write_compressed_int(*value, &mut buffer).unwrap();
            assert_eq!(buffer, *expected, "Failed for value {value}");
        }
    }

    #[test]
    fn test_write_compressed_int_out_of_range() {
        for value in [268_435_456, -268_435_457, i32::MAX, i32::MIN] {
            assert!(
                write_compressed_int(value, &mut Vec::new()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn test_write_7bit_encoded_int() {
        let test_cases = vec![
            (0, vec![0]),
            (127, vec![0x7F]),                       // Max single byte
            (128, vec![0x80, 0x01]),                 // Min two bytes
            (16383, vec![0xFF, 0x7F]),               // Max two bytes
            (16384, vec![0x80, 0x80, 0x01]),         // Min three bytes
            (2097151, vec![0xFF, 0xFF, 0x7F]),       // Max three bytes
            (2097152, vec![0x80, 0x80, 0x80, 0x01]), // Min four bytes
        ];

        for (value, expected) in test_cases {
            let mut buffer = Vec::new();
            write_7bit_encoded_int(value, &mut buffer);
            assert_eq!(buffer, expected, "Failed for value {value}");
        }
    }

    #[test]
    fn test_write_string_utf8() {
        let test_cases = vec![
            ("", vec![0]),                                            // Empty string
            ("Hello", b"Hello\0".to_vec()),                           // Simple ASCII
            ("中文", vec![0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0x00]), // UTF-8
        ];

        for (input, expected) in test_cases {
            let mut buffer = Vec::new();
            write_string_utf8(input, &mut buffer);
            assert_eq!(buffer, expected, "Failed for input '{input}'");
        }
    }

    #[test]
    fn test_write_prefixed_string_utf8() {
        let test_cases = vec![
            ("", vec![0]),                                    // Empty string
            ("Hello", vec![5, b'H', b'e', b'l', b'l', b'o']), // Simple ASCII
            ("Hi", vec![2, b'H', b'i']),                      // Short string
        ];

        for (input, expected) in test_cases {
            let mut buffer = Vec::new();
            write_prefixed_string_utf8(input, &mut buffer);
            assert_eq!(buffer, expected, "Failed for input '{input}'");
        }
    }

    #[test]
    fn test_write_prefixed_string_utf16() {
        let test_cases = vec![
            ("", vec![0]),              // Empty string
            ("A", vec![2, 0x41, 0x00]), // Single character
            (
                "Hello",
                vec![
                    10, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00,
                ],
            ), // "Hello"
        ];

        for (input, expected) in test_cases {
            let mut buffer = Vec::new();
            write_prefixed_string_utf16(input, &mut buffer);
            assert_eq!(buffer, expected, "Failed for input '{input}'");
        }
    }

    #[test]
    fn test_string_encoding_edge_cases() {
        // Test very long string for prefixed UTF-8
        let long_string = "a".repeat(200);
        let mut buffer = Vec::new();
        write_prefixed_string_utf8(&long_string, &mut buffer);

        // Should start with length encoded as 7-bit encoded int (200 = 0xC8, 0x01)
        assert_eq!(buffer[0], 0xC8);
        assert_eq!(buffer[1], 0x01);
        assert_eq!(buffer.len(), 202); // 2 bytes length + 200 bytes content

        // Test UTF-16 with non-ASCII characters
        let mut buffer = Vec::new();
        write_prefixed_string_utf16("中", &mut buffer);
        // "中" is U+4E2D, should be encoded as 0x2D 0x4E in little-endian
        assert_eq!(buffer, vec![2, 0x2D, 0x4E]);
    }

    #[test]
    fn test_write_string_at() {
        let mut buffer = [0u8; 20];
        let mut offset = 0;

        // Test writing a simple string
        write_string_at(&mut buffer, &mut offset, "Hello").unwrap();
        assert_eq!(offset, 6); // 5 chars + null terminator
        assert_eq!(&buffer[0..6], b"Hello\0");

        // Test writing another string after the first
        write_string_at(&mut buffer, &mut offset, "World").unwrap();
        assert_eq!(offset, 12); // Previous 6 + 5 chars + null terminator
        assert_eq!(&buffer[6..12], b"World\0");

        // Test that the complete buffer contains expected data
        assert_eq!(&buffer[0..12], b"Hello\0World\0");
    }

    #[test]
    fn test_write_string_at_empty_string() {
        let mut buffer = [0u8; 5];
        let mut offset = 0;

        write_string_at(&mut buffer, &mut offset, "").unwrap();
        assert_eq!(offset, 1); // Just null terminator
        assert_eq!(&buffer[0..1], b"\0");
    }

    #[test]
    fn test_write_string_at_exact_fit() {
        let mut buffer = [0u8; 6];
        let mut offset = 0;

        write_string_at(&mut buffer, &mut offset, "Hello").unwrap();
        assert_eq!(offset, 6);
        assert_eq!(&buffer, b"Hello\0");
    }

    #[test]
    fn test_write_string_at_bounds_error() {
        let mut buffer = [0u8; 5];
        let mut offset = 0;

        // Try to write a string that won't fit (6 bytes needed, 5 available)
        let result = write_string_at(&mut buffer, &mut offset, "Hello");
        assert!(result.is_err());
        assert_eq!(offset, 0); // Offset should not be modified on error
    }

    #[test]
    fn test_write_string_at_with_offset() {
        let mut buffer = [0u8; 10];
        let mut offset = 3; // Start writing at offset 3

        write_string_at(&mut buffer, &mut offset, "Hi").unwrap();
        assert_eq!(offset, 6); // 3 + 2 chars + null terminator
        assert_eq!(&buffer[3..6], b"Hi\0");
        assert_eq!(&buffer[0..3], &[0, 0, 0]); // First 3 bytes should remain zero
    }

    #[test]
    fn test_write_string_at_utf8() {
        let mut buffer = [0u8; 20];
        let mut offset = 0;

        // Test with UTF-8 characters
        write_string_at(&mut buffer, &mut offset, "café").unwrap();
        assert_eq!(offset, 6); // 4 UTF-8 bytes + 1 null terminator
        assert_eq!(&buffer[0..6], "café\0".as_bytes());
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_empty() {
        assert_eq!(read_packed_len(&[]), None);
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_null_sentinel() {
        assert_eq!(read_packed_len(&[0xFF]), None);
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_one_byte() {
        assert_eq!(read_packed_len(&[0x00]), Some((0, 1)));
        assert_eq!(read_packed_len(&[0x03]), Some((3, 1)));
        assert_eq!(read_packed_len(&[0x7F]), Some((127, 1)));
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_two_bytes() {
        assert_eq!(read_packed_len(&[0x80, 0x80]), Some((0x0080, 2)));
        assert_eq!(read_packed_len(&[0xBF, 0xFF]), Some((0x3FFF, 2)));
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_two_bytes_truncated() {
        assert_eq!(read_packed_len(&[0x80]), None);
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_four_bytes() {
        assert_eq!(
            read_packed_len(&[0xC0, 0x00, 0x40, 0x00]),
            Some((0x4000, 4))
        );
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_read_packed_len_four_bytes_truncated() {
        assert_eq!(read_packed_len(&[0xC0, 0x00, 0x40]), None);
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_decode_utf16le_basic() {
        // "Hi" in UTF-16LE with null terminator
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16le(&data), Some("Hi".to_string()));
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_decode_utf16le_no_terminator() {
        // "Hi" in UTF-16LE without null terminator
        let data = [0x48, 0x00, 0x69, 0x00];
        assert_eq!(decode_utf16le(&data), Some("Hi".to_string()));
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_decode_utf16le_empty() {
        assert_eq!(decode_utf16le(&[]), None);
        assert_eq!(decode_utf16le(&[0x00]), None);
    }

    #[cfg(feature = "deobfuscation")]
    #[test]
    fn test_decode_utf16le_null_only() {
        assert_eq!(decode_utf16le(&[0x00, 0x00]), None);
    }
}

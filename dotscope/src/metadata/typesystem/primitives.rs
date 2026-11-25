//! .NET primitive types and constant value handling.
//!
//! This module provides comprehensive support for .NET's built-in primitive types and their
//! constant values. It handles the mapping between ECMA-335 element types and Rust representations,
//! providing type-safe conversions and value operations.
//!
//! # Key Components
//!
//! - [`CilPrimitive`] - Complete primitive type with optional constant data
//! - [`CilPrimitiveKind`] - Enumeration of all .NET primitive types
//! - [`CilPrimitiveData`] - Type-safe storage for constant primitive values
//!
//! # Primitive Type System
//!
//! The .NET runtime supports a rich set of primitive types that map directly to hardware
//! and language constructs. This module provides a unified representation for:
//!
//! - **Numeric types**: Signed/unsigned integers (8, 16, 32, 64-bit), floating point (32, 64-bit)
//! - **Character types**: Unicode characters and strings
//! - **Platform types**: Native integers (pointer-sized)
//! - **Special types**: Boolean, void, object references
//! - **Generic types**: Type and method parameters (var, mvar)
//!
//! # ECMA-335 Compliance
//!
//! All primitive types conform to the ECMA-335 standard specification:
//! - Element type constants (§II.23.1.16)
//! - Value encoding and decoding (§II.24.2.6)
//! - Type compatibility rules (§III.1.1.1)
//!
//! # Examples
//!
//! ## Creating Primitive Constants
//!
//! ```rust,no_run
//! use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveKind, CilPrimitiveData};
//!
//! // Create a boolean constant
//! let bool_const = CilPrimitive::boolean(true);
//!
//! // Create an integer constant (i32 uses i4 method)
//! let int_const = CilPrimitive::i4(42);
//!
//! // Create a string constant  
//! let str_const = CilPrimitive::string("Hello, World!");
//! ```
//!
//! ## Type Conversions
//!
//! ```rust,no_run
//! use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveData};
//!
//! let primitive = CilPrimitive::i4(42);
//!
//! // Convert to different representations
//! if let Some(as_bool) = primitive.data.as_boolean() {
//!     println!("As boolean: {}", as_bool); // true (non-zero)
//! }
//!
//! if let Some(as_float) = primitive.data.as_f64() {
//!     println!("As float: {}", as_float); // 42.0
//! }
//! ```
//!
//! ## Parsing from Metadata
//!
//! ```rust,no_run
//! use dotscope::metadata::typesystem::{CilPrimitiveData, ELEMENT_TYPE};
//!
//! // Parse a 32-bit integer from metadata bytes
//! let bytes = [42, 0, 0, 0]; // Little-endian 42
//! let data = CilPrimitiveData::from_bytes(ELEMENT_TYPE::I4, &bytes)?;
//!
//! match data {
//!     CilPrimitiveData::I4(value) => println!("Parsed: {}", value),
//!     _ => unreachable!(),
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are `Send` and `Sync`, making them safe for concurrent access.
//! Primitive values are immutable after creation, eliminating race conditions.
//!
//! # Performance
//!
//! - Primitive operations are zero-cost abstractions where possible
//! - Memory layout is optimized for cache efficiency
//! - Conversion methods avoid unnecessary allocations
//! - Token generation uses compile-time constants

use std::{convert::TryFrom, fmt};

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilFlavor, ELEMENT_TYPE},
    },
    utils::read_le,
    Error::{self, TypeConversionInvalid, TypeNotPrimitive},
    ParseFailure, ParseStage, Result,
};

#[inline]
fn primitives_oob() -> Error {
    ParseFailure::OutOfBounds {
        stage: ParseStage::Generic,
    }
    .into()
}

/// Type-safe storage for constant primitive values.
///
/// `CilPrimitiveData` provides a unified storage mechanism for all .NET primitive constant
/// values. It handles the full range of primitive types from the ECMA-335 specification
/// and provides safe conversion methods between different representations.
///
/// # Memory Layout
///
/// The enum is designed to minimize memory usage while maintaining type safety.
/// Each variant stores only the necessary data for its specific type.
///
/// # Thread Safety
///
/// All variants are `Send` and `Sync`, making them safe for concurrent access.
/// Values are immutable after creation.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::typesystem::CilPrimitiveData;
///
/// // Create different primitive values
/// let bool_val = CilPrimitiveData::Boolean(true);
/// let int_val = CilPrimitiveData::I4(42);
/// let str_val = CilPrimitiveData::String("test".to_string());
///
/// // Convert between types safely
/// assert_eq!(bool_val.as_i32(), Some(1));
/// assert_eq!(int_val.as_f64(), Some(42.0));
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub enum CilPrimitiveData {
    /// No data - used for void types, null references, and uninitialized values
    #[default]
    None,
    /// Boolean value - System.Boolean (true/false)
    Boolean(bool),
    /// Unicode character - System.Char (UTF-16 code unit)
    /// .NET's System.Char is a 16-bit value that can represent any UTF-16 code unit,
    /// including surrogate pairs (0xD800-0xDFFF) which are valid in .NET but not in Rust char
    Char(u16),
    /// Signed 8-bit integer - System.SByte (-128 to 127)
    I1(i8),
    /// Unsigned 8-bit integer - System.Byte (0 to 255)
    U1(u8),
    /// Signed 16-bit integer - System.Int16 (-32,768 to 32,767)
    I2(i16),
    /// Unsigned 16-bit integer - System.UInt16 (0 to 65,535)
    U2(u16),
    /// Signed 32-bit integer - System.Int32 (-2^31 to 2^31-1)
    I4(i32),
    /// Unsigned 32-bit integer - System.UInt32 (0 to 2^32-1)
    U4(u32),
    /// Signed 64-bit integer - System.Int64 (-2^63 to 2^63-1)
    I8(i64),
    /// Unsigned 64-bit integer - System.UInt64 (0 to 2^64-1)
    U8(u64),
    /// Platform-specific unsigned integer - System.UIntPtr (pointer-sized)
    U(usize),
    /// Platform-specific signed integer - System.IntPtr (pointer-sized)
    I(isize),
    /// 32-bit IEEE 754 floating point - System.Single
    R4(f32),
    /// 64-bit IEEE 754 floating point - System.Double
    R8(f64),
    /// Unicode string - System.String (UTF-16 encoded)
    String(String),
    /// Raw byte array - used for complex constants and blob data
    Bytes(Vec<u8>),
}

impl CilPrimitiveData {
    /// Convert to a boolean value following .NET conversion rules.
    ///
    /// Implements the standard .NET conversion semantics where:
    /// - Boolean values return their direct value
    /// - Numeric values return `true` if non-zero, `false` if zero
    /// - Other types return `None`
    ///
    /// # Returns
    /// * `Some(bool)` - The converted boolean value
    /// * `None` - If the value cannot be converted to boolean
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::CilPrimitiveData;
    ///
    /// assert_eq!(CilPrimitiveData::Boolean(true).as_boolean(), Some(true));
    /// assert_eq!(CilPrimitiveData::I4(42).as_boolean(), Some(true));
    /// assert_eq!(CilPrimitiveData::I4(0).as_boolean(), Some(false));
    /// assert_eq!(CilPrimitiveData::String("test".to_string()).as_boolean(), None);
    /// ```
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(*value),
            CilPrimitiveData::I4(value) => Some(*value != 0),
            CilPrimitiveData::U4(value) => Some(*value != 0),
            CilPrimitiveData::I8(value) => Some(*value != 0),
            CilPrimitiveData::U8(value) => Some(*value != 0),
            _ => None,
        }
    }

    /// Convert to a 32-bit signed integer with overflow handling.
    ///
    /// Performs safe conversion from various numeric types to `i32`, handling
    /// potential overflow conditions gracefully. Floating point values are
    /// truncated toward zero if they fit within the i32 range.
    ///
    /// # Returns
    /// * `Some(i32)` - The converted integer value
    /// * `None` - If the value cannot be converted or would overflow
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::CilPrimitiveData;
    ///
    /// assert_eq!(CilPrimitiveData::Boolean(true).as_i32(), Some(1));
    /// assert_eq!(CilPrimitiveData::U1(255).as_i32(), Some(255));
    /// assert_eq!(CilPrimitiveData::R4(42.7).as_i32(), Some(42));
    /// assert_eq!(CilPrimitiveData::U8(u64::MAX).as_i32(), None); // Overflow
    /// ```
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(i32::from(*value)),
            CilPrimitiveData::I1(value) => Some(i32::from(*value)),
            CilPrimitiveData::U1(value) => Some(i32::from(*value)),
            CilPrimitiveData::I2(value) => Some(i32::from(*value)),
            CilPrimitiveData::U2(value) => Some(i32::from(*value)),
            CilPrimitiveData::I4(value) => Some(*value),
            CilPrimitiveData::U4(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::I8(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::U8(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::I(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::U(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::R4(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i32::MIN as f32 && *value <= i32::MAX as f32 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i32)
                } else {
                    None
                }
            }
            CilPrimitiveData::R8(value) => {
                #[allow(clippy::cast_possible_truncation)]
                if value.is_finite()
                    && *value >= f64::from(i32::MIN)
                    && *value <= f64::from(i32::MAX)
                {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i32)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Try to convert to a 64-bit integer value
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(i64::from(*value)),
            CilPrimitiveData::I1(value) => Some(i64::from(*value)),
            CilPrimitiveData::U1(value) => Some(i64::from(*value)),
            CilPrimitiveData::I2(value) => Some(i64::from(*value)),
            CilPrimitiveData::U2(value) => Some(i64::from(*value)),
            CilPrimitiveData::I4(value) => Some(i64::from(*value)),
            CilPrimitiveData::U4(value) => Some(i64::from(*value)),
            CilPrimitiveData::I8(value) => Some(*value),
            CilPrimitiveData::U8(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::I(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::U(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::R4(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i64::MIN as f32 && *value <= i64::MAX as f32 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i64)
                } else {
                    None
                }
            }
            CilPrimitiveData::R8(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i64::MIN as f64 && *value <= i64::MAX as f64 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Try to convert to a floating point value
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(f64::from(*value)),
            CilPrimitiveData::I1(value) => Some(f64::from(*value)),
            CilPrimitiveData::U1(value) => Some(f64::from(*value)),
            CilPrimitiveData::I2(value) => Some(f64::from(*value)),
            CilPrimitiveData::U2(value) => Some(f64::from(*value)),
            CilPrimitiveData::I4(value) => Some(f64::from(*value)),
            CilPrimitiveData::U4(value) => Some(f64::from(*value)),
            #[allow(clippy::cast_precision_loss)]
            CilPrimitiveData::I8(value) => Some(*value as f64),
            #[allow(clippy::cast_precision_loss)]
            CilPrimitiveData::U8(value) => Some(*value as f64),
            CilPrimitiveData::R4(value) => Some(f64::from(*value)),
            CilPrimitiveData::R8(value) => Some(*value),
            _ => None,
        }
    }

    /// Try to convert to a string value
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self {
            CilPrimitiveData::String(value) => Some(value.clone()),
            CilPrimitiveData::Boolean(value) => Some(value.to_string()),
            CilPrimitiveData::Char(value) => {
                // Try to convert to a valid Unicode char first
                if let Some(ch) = char::from_u32(u32::from(*value)) {
                    Some(ch.to_string())
                } else {
                    // For surrogates or invalid values, show as Unicode escape
                    Some(format!("\\u{{{value:04X}}}"))
                }
            }
            CilPrimitiveData::I1(value) => Some(value.to_string()),
            CilPrimitiveData::U1(value) => Some(value.to_string()),
            CilPrimitiveData::I2(value) => Some(value.to_string()),
            CilPrimitiveData::U2(value) => Some(value.to_string()),
            CilPrimitiveData::I4(value) => Some(value.to_string()),
            CilPrimitiveData::U4(value) => Some(value.to_string()),
            CilPrimitiveData::I8(value) => Some(value.to_string()),
            CilPrimitiveData::U8(value) => Some(value.to_string()),
            CilPrimitiveData::R4(value) => Some(value.to_string()),
            CilPrimitiveData::R8(value) => Some(value.to_string()),
            _ => None,
        }
    }

    /// Parse primitive constant data from raw metadata bytes.
    ///
    /// Converts raw byte data from .NET metadata into the appropriate primitive type
    /// according to ECMA-335 encoding rules. This method handles endianness conversion
    /// and validates data length for each primitive type.
    ///
    /// # Arguments
    /// * `type_byte` - `ELEMENT_TYPE` constant identifying the primitive type
    /// * `data` - Raw byte data containing the encoded value
    ///
    /// # Returns
    /// * `Ok(CilPrimitiveData)` - Successfully parsed primitive value
    /// * `Err(OutOfBounds)` - Data buffer too short for the specified type
    /// * `Err(Error)` - Invalid data encoding or unsupported type
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The data buffer is too short for the specified primitive type
    /// - The `type_byte` represents an unsupported or invalid primitive type
    /// - The data encoding is malformed for the specified type
    ///
    /// # Encoding Format
    ///
    /// All multi-byte values are stored in little-endian format as per ECMA-335:
    /// - Integers: Little-endian byte order
    /// - Floating point: IEEE 754 format
    /// - Strings: Length-prefixed UTF-8 or UTF-16
    /// - Booleans: Single byte (0 = false, non-zero = true)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{CilPrimitiveData, ELEMENT_TYPE};
    ///
    /// // Parse a 32-bit integer (little-endian)
    /// let bytes = [42, 0, 0, 0];
    /// let value = CilPrimitiveData::from_bytes(ELEMENT_TYPE::I4, &bytes)?;
    /// assert_eq!(value, CilPrimitiveData::I4(42));
    ///
    /// // Parse a boolean
    /// let bool_bytes = [1];
    /// let bool_val = CilPrimitiveData::from_bytes(ELEMENT_TYPE::BOOLEAN, &bool_bytes)?;
    /// assert_eq!(bool_val, CilPrimitiveData::Boolean(true));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_bytes(type_byte: u8, data: &[u8]) -> Result<Self> {
        match type_byte {
            ELEMENT_TYPE::BOOLEAN => {
                let b = data.first().ok_or(primitives_oob())?;
                Ok(CilPrimitiveData::Boolean(*b != 0))
            }
            ELEMENT_TYPE::CHAR => {
                let bytes = data.get(0..2).ok_or(primitives_oob())?;
                let code = u16::from_le_bytes([
                    *bytes.first().ok_or(primitives_oob())?,
                    *bytes.get(1).ok_or(primitives_oob())?,
                ]);
                // .NET System.Char is a UTF-16 code unit, so any u16 value is valid
                Ok(CilPrimitiveData::Char(code))
            }
            ELEMENT_TYPE::I1 => Ok(CilPrimitiveData::I1(read_le::<i8>(data)?)),
            ELEMENT_TYPE::U1 => Ok(CilPrimitiveData::U1(read_le::<u8>(data)?)),
            ELEMENT_TYPE::I2 => Ok(CilPrimitiveData::I2(read_le::<i16>(data)?)),
            ELEMENT_TYPE::U2 => Ok(CilPrimitiveData::U2(read_le::<u16>(data)?)),
            ELEMENT_TYPE::I4 => Ok(CilPrimitiveData::I4(read_le::<i32>(data)?)),
            ELEMENT_TYPE::U4 => Ok(CilPrimitiveData::U4(read_le::<u32>(data)?)),
            ELEMENT_TYPE::I8 => Ok(CilPrimitiveData::I8(read_le::<i64>(data)?)),
            ELEMENT_TYPE::U8 => Ok(CilPrimitiveData::U8(read_le::<u64>(data)?)),
            ELEMENT_TYPE::R4 => Ok(CilPrimitiveData::R4(read_le::<f32>(data)?)),
            ELEMENT_TYPE::R8 => Ok(CilPrimitiveData::R8(read_le::<f64>(data)?)),
            ELEMENT_TYPE::U => Ok(CilPrimitiveData::U(read_le::<usize>(data)?)),
            ELEMENT_TYPE::I => Ok(CilPrimitiveData::I(read_le::<isize>(data)?)),
            ELEMENT_TYPE::STRING => {
                if data.is_empty() {
                    return Ok(CilPrimitiveData::String(String::new()));
                }

                if !data.len().is_multiple_of(2) {
                    return Err(ParseFailure::InvalidField {
                        stage: ParseStage::Generic,
                        field: "utf16_length",
                        reason: format!(
                            "invalid UTF-16 string length: {} (must be even)",
                            data.len()
                        ),
                    }
                    .into());
                }

                // `data.len()` is even (rejected above otherwise), so `as_chunks::<2>`
                // consumes it fully. It yields the two-byte arrays themselves, so the
                // per-byte bounds checks the pair used to need are gone with them.
                let utf16_chars: Vec<u16> = data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .copied()
                    .map(u16::from_le_bytes)
                    .collect();

                match String::from_utf16(&utf16_chars) {
                    Ok(utf_string) => Ok(CilPrimitiveData::String(utf_string)),
                    Err(_) => Err(ParseFailure::InvalidField {
                        stage: ParseStage::Generic,
                        field: "utf16_string",
                        reason: "invalid UTF-16 sequence in primitive string".into(),
                    }
                    .into()),
                }
            }
            ELEMENT_TYPE::CLASS => {
                // Null reference constant: CLASS type with 4-byte zero value
                if data.len() == 4 && data == [0, 0, 0, 0] {
                    Ok(CilPrimitiveData::None)
                } else {
                    Ok(CilPrimitiveData::Bytes(data.to_vec()))
                }
            }
            _ => Ok(CilPrimitiveData::Bytes(data.to_vec())),
        }
    }
}

/// Complete primitive type representation with optional constant data.
///
/// `CilPrimitive` combines a primitive type classification with optional constant data,
/// providing a complete representation for both type information and literal values.
/// This is commonly used for default values, constant fields, and literal expressions.
///
/// # Use Cases
///
/// - Constant field values in metadata
/// - Default parameter values  
/// - Literal values in custom attributes
/// - Type system analysis and validation
///
/// # Thread Safety
///
/// `CilPrimitive` is `Send` and `Sync`, making it safe for concurrent access.
/// All data is immutable after construction.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveKind, CilPrimitiveData};
///
/// // Create a primitive with data
/// let int_const = CilPrimitive::i4(42);
/// assert_eq!(int_const.kind, CilPrimitiveKind::I4);
/// assert_eq!(int_const.data, CilPrimitiveData::I4(42));
///
/// // Create a type-only primitive
/// let void_type = CilPrimitive::new(CilPrimitiveKind::Void);
/// assert_eq!(void_type.data, CilPrimitiveData::None);
/// ```
#[derive(Debug, Clone, PartialEq)]
// ToDo: This can be simplified to directly be an enum that contains the data and type
pub struct CilPrimitive {
    /// The primitive type classification
    pub kind: CilPrimitiveKind,
    /// Optional constant data for this primitive
    pub data: CilPrimitiveData,
}

/// Classification of all .NET primitive types from ECMA-335.
///
/// `CilPrimitiveKind` provides a complete enumeration of built-in .NET primitive types
/// as defined in the ECMA-335 specification. Each variant corresponds to a specific
/// System type and `ELEMENT_TYPE` constant.
///
/// # ECMA-335 Mapping
///
/// This enum directly maps to `ELEMENT_TYPE` constants (§II.23.1.16):
/// - Numeric types (I1, U1, I2, U2, I4, U4, I8, U8, R4, R8)
/// - Platform types (I, U for native integers)
/// - Character and string types (CHAR, STRING)
/// - Special types (VOID, BOOLEAN, OBJECT)
/// - Generic parameters (VAR, MVAR)
///
/// # Artificial Tokens
///
/// Each primitive kind has an associated artificial token (`0xF000_XXXX` range)
/// for use in type resolution and metadata table operations.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::typesystem::CilPrimitiveKind;
///
/// // Common primitive types
/// let int_type = CilPrimitiveKind::I4;    // System.Int32
/// let bool_type = CilPrimitiveKind::Boolean; // System.Boolean
/// let str_type = CilPrimitiveKind::String;   // System.String
///
/// // Get artificial token
/// let token = int_type.token();
/// println!("I4 token: 0x{:08X}", token.value());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilPrimitiveKind {
    /// System.Void - represents no value or return type (`ELEMENT_TYPE_VOID`)
    Void,
    /// System.Boolean - true/false value, single byte storage (`ELEMENT_TYPE_BOOLEAN`)
    Boolean,
    /// System.Char - Unicode UTF-16 code unit, 16-bit value (`ELEMENT_TYPE_CHAR`)
    Char,
    /// System.SByte - signed 8-bit integer (-128 to 127) (`ELEMENT_TYPE_I1`)
    I1,
    /// System.Byte - unsigned 8-bit integer (0 to 255) (`ELEMENT_TYPE_U1`)
    U1,
    /// System.Int16 - signed 16-bit integer (-32,768 to 32,767) (`ELEMENT_TYPE_I2`)
    I2,
    /// System.UInt16 - unsigned 16-bit integer (0 to 65,535) (`ELEMENT_TYPE_U2`)
    U2,
    /// System.Int32 - signed 32-bit integer (-2^31 to 2^31-1) (`ELEMENT_TYPE_I4`)
    I4,
    /// System.UInt32 - unsigned 32-bit integer (0 to 2^32-1) (`ELEMENT_TYPE_U4`)
    U4,
    /// System.Int64 - signed 64-bit integer (-2^63 to 2^63-1) (`ELEMENT_TYPE_I8`)
    I8,
    /// System.UInt64 - unsigned 64-bit integer (0 to 2^64-1) (`ELEMENT_TYPE_U8`)
    U8,
    /// System.Single - 32-bit IEEE 754 floating point (`ELEMENT_TYPE_R4`)
    R4,
    /// System.Double - 64-bit IEEE 754 floating point (`ELEMENT_TYPE_R8`)
    R8,
    /// System.IntPtr - platform-specific signed integer (pointer-sized) (`ELEMENT_TYPE_I`)
    I,
    /// System.UIntPtr - platform-specific unsigned integer (pointer-sized) (`ELEMENT_TYPE_U`)
    U,
    /// System.Object - root of the .NET type hierarchy, all types derive from this (`ELEMENT_TYPE_OBJECT`)
    Object,
    /// System.String - immutable sequence of UTF-16 characters (`ELEMENT_TYPE_STRING`)
    String,
    /// Null reference constant - used for null literal values in metadata
    Null,
    /// System.TypedReference - compiler-generated type for type-safe variable arguments
    TypedReference,
    /// System.ValueType - base class for all value types (structs, enums)
    ValueType,
    /// Generic type parameter (T, U, etc.) from type definitions (`ELEMENT_TYPE_VAR`)
    Var,
    /// Generic method parameter (T, U, etc.) from method definitions (`ELEMENT_TYPE_MVAR`)
    MVar,
    /// General class reference - used for non-primitive reference types (`ELEMENT_TYPE_CLASS`)
    Class,
}

impl CilPrimitiveKind {
    /// Get the artificial token for this primitive type.
    ///
    /// Returns a unique artificial token in the `0xF000_XXXX` range that can be used
    /// to represent this primitive type in metadata operations and type resolution.
    /// These tokens do not correspond to actual metadata table entries but provide
    /// a consistent identifier for primitive types.
    ///
    /// # Token Range
    ///
    /// All primitive tokens use the artificial range `0xF000_0001` to `0xF000_0017`,
    /// which avoids conflicts with actual metadata table tokens.
    ///
    /// # Returns
    /// A unique `Token` for this primitive type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::CilPrimitiveKind;
    ///
    /// let int_token = CilPrimitiveKind::I4.token();
    /// let bool_token = CilPrimitiveKind::Boolean.token();
    ///
    /// assert_eq!(int_token.value(), 0xF000_0008);
    /// assert_eq!(bool_token.value(), 0xF000_0002);
    /// ```
    #[must_use]
    pub fn token(&self) -> Token {
        Token::new(match self {
            CilPrimitiveKind::Void => 0xF000_0001,
            CilPrimitiveKind::Boolean => 0xF000_0002,
            CilPrimitiveKind::Char => 0xF000_0003,
            CilPrimitiveKind::I1 => 0xF000_0004,
            CilPrimitiveKind::U1 => 0xF000_0005,
            CilPrimitiveKind::I2 => 0xF000_0006,
            CilPrimitiveKind::U2 => 0xF000_0007,
            CilPrimitiveKind::I4 => 0xF000_0008,
            CilPrimitiveKind::U4 => 0xF000_0009,
            CilPrimitiveKind::I8 => 0xF000_000A,
            CilPrimitiveKind::U8 => 0xF000_000B,
            CilPrimitiveKind::R4 => 0xF000_000C,
            CilPrimitiveKind::R8 => 0xF000_000D,
            CilPrimitiveKind::I => 0xF000_000E,
            CilPrimitiveKind::U => 0xF000_000F,
            CilPrimitiveKind::Object => 0xF000_0010,
            CilPrimitiveKind::String => 0xF000_0011,
            CilPrimitiveKind::TypedReference => 0xF000_0012,
            CilPrimitiveKind::ValueType => 0xF000_0013,
            CilPrimitiveKind::Var => 0xF000_0014,
            CilPrimitiveKind::MVar => 0xF000_0015,
            CilPrimitiveKind::Null => 0xF000_0016,
            CilPrimitiveKind::Class => 0xF000_0017,
        })
    }

    /// Maps this primitive kind to a .NET `System.TypeCode` integer.
    ///
    /// Returns the `TypeCode` enum value for primitive types that have one.
    /// Non-primitive kinds (Object, Void, IntPtr, UIntPtr, etc.) return `None`.
    #[must_use]
    pub fn typecode(&self) -> Option<i32> {
        match self {
            CilPrimitiveKind::Boolean => Some(3),
            CilPrimitiveKind::Char => Some(4),
            CilPrimitiveKind::I1 => Some(5),  // SByte
            CilPrimitiveKind::U1 => Some(6),  // Byte
            CilPrimitiveKind::I2 => Some(7),  // Int16
            CilPrimitiveKind::U2 => Some(8),  // UInt16
            CilPrimitiveKind::I4 => Some(9),  // Int32
            CilPrimitiveKind::U4 => Some(10), // UInt32
            CilPrimitiveKind::I8 => Some(11), // Int64
            CilPrimitiveKind::U8 => Some(12), // UInt64
            CilPrimitiveKind::R4 => Some(13), // Single
            CilPrimitiveKind::R8 => Some(14), // Double
            CilPrimitiveKind::String => Some(18),
            _ => None,
        }
    }

    /// Returns whether this primitive kind represents a .NET value type.
    ///
    /// All numeric types, `Boolean`, `Char`, `IntPtr`, `UIntPtr`, and
    /// `TypedReference` are value types. `Void`, `Object`, `String`, and
    /// structural kinds (`Class`, `ValueType`, `Var`, `MVar`, `Null`) are not.
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self,
            CilPrimitiveKind::Boolean
                | CilPrimitiveKind::Char
                | CilPrimitiveKind::I1
                | CilPrimitiveKind::U1
                | CilPrimitiveKind::I2
                | CilPrimitiveKind::U2
                | CilPrimitiveKind::I4
                | CilPrimitiveKind::U4
                | CilPrimitiveKind::I8
                | CilPrimitiveKind::U8
                | CilPrimitiveKind::R4
                | CilPrimitiveKind::R8
                | CilPrimitiveKind::I
                | CilPrimitiveKind::U
                | CilPrimitiveKind::TypedReference
        )
    }

    /// Parse primitive type from `ELEMENT_TYPE` byte constant.
    ///
    /// Converts an `ELEMENT_TYPE` constant from ECMA-335 metadata into the corresponding
    /// primitive type. This is used when parsing type signatures and metadata tables
    /// that contain element type specifications.
    ///
    /// # Arguments
    /// * `type_byte` - `ELEMENT_TYPE` constant from metadata (see ECMA-335 §II.23.1.16)
    ///
    /// # Returns
    /// * `Ok(CilPrimitiveKind)` - Successfully parsed primitive type
    /// * `Err(TypeNotPrimitive)` - Byte does not represent a valid primitive type
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided byte does not correspond
    /// to a valid primitive type constant as defined in ECMA-335.
    ///
    /// # `ELEMENT_TYPE` Mapping
    ///
    /// Maps standard `ELEMENT_TYPE` constants to primitive kinds:
    /// - `ELEMENT_TYPE_BOOLEAN` (0x02) → `Boolean`
    /// - `ELEMENT_TYPE_I4` (0x08) → `I4`
    /// - `ELEMENT_TYPE_STRING` (0x0E) → `String`
    /// - And so on for all supported primitive types
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{CilPrimitiveKind, ELEMENT_TYPE};
    ///
    /// let bool_kind = CilPrimitiveKind::from_byte(ELEMENT_TYPE::BOOLEAN)?;
    /// assert_eq!(bool_kind, CilPrimitiveKind::Boolean);
    ///
    /// let int_kind = CilPrimitiveKind::from_byte(ELEMENT_TYPE::I4)?;
    /// assert_eq!(int_kind, CilPrimitiveKind::I4);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_byte(type_byte: u8) -> Result<Self> {
        match type_byte {
            ELEMENT_TYPE::BOOLEAN => Ok(CilPrimitiveKind::Boolean),
            ELEMENT_TYPE::CHAR => Ok(CilPrimitiveKind::Char),
            ELEMENT_TYPE::I1 => Ok(CilPrimitiveKind::I1),
            ELEMENT_TYPE::U1 => Ok(CilPrimitiveKind::U1),
            ELEMENT_TYPE::I2 => Ok(CilPrimitiveKind::I2),
            ELEMENT_TYPE::U2 => Ok(CilPrimitiveKind::U2),
            ELEMENT_TYPE::I4 => Ok(CilPrimitiveKind::I4),
            ELEMENT_TYPE::U4 => Ok(CilPrimitiveKind::U4),
            ELEMENT_TYPE::I8 => Ok(CilPrimitiveKind::I8),
            ELEMENT_TYPE::U8 => Ok(CilPrimitiveKind::U8),
            ELEMENT_TYPE::R4 => Ok(CilPrimitiveKind::R4),
            ELEMENT_TYPE::R8 => Ok(CilPrimitiveKind::R8),
            ELEMENT_TYPE::U => Ok(CilPrimitiveKind::U),
            ELEMENT_TYPE::I => Ok(CilPrimitiveKind::I),
            ELEMENT_TYPE::STRING => Ok(CilPrimitiveKind::String),
            ELEMENT_TYPE::CLASS => Ok(CilPrimitiveKind::Class),
            _ => Err(TypeNotPrimitive),
        }
    }

    /// Returns a stable `&'static str` identifier for this primitive kind.
    ///
    /// The strings follow ILAsm / ECMA-335 §I.8.2.2 conventions and are part
    /// of the stable public API - safe to persist (file, database, log line)
    /// and to parse. Pointer-sized integers and the structural kinds use the
    /// short ILAsm names rather than the C# / `System.*` aliases:
    ///
    /// `"void"`, `"bool"`, `"char"`, `"int8"`, `"uint8"`, `"int16"`,
    /// `"uint16"`, `"int32"`, `"uint32"`, `"int64"`, `"uint64"`,
    /// `"float32"`, `"float64"`, `"native int"`, `"native uint"`,
    /// `"object"`, `"string"`, `"null"`, `"typedref"`, `"valuetype"`,
    /// `"var"`, `"mvar"`, `"class"`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            CilPrimitiveKind::Void => "void",
            CilPrimitiveKind::Boolean => "bool",
            CilPrimitiveKind::Char => "char",
            CilPrimitiveKind::I1 => "int8",
            CilPrimitiveKind::U1 => "uint8",
            CilPrimitiveKind::I2 => "int16",
            CilPrimitiveKind::U2 => "uint16",
            CilPrimitiveKind::I4 => "int32",
            CilPrimitiveKind::U4 => "uint32",
            CilPrimitiveKind::I8 => "int64",
            CilPrimitiveKind::U8 => "uint64",
            CilPrimitiveKind::R4 => "float32",
            CilPrimitiveKind::R8 => "float64",
            CilPrimitiveKind::I => "native int",
            CilPrimitiveKind::U => "native uint",
            CilPrimitiveKind::Object => "object",
            CilPrimitiveKind::String => "string",
            CilPrimitiveKind::Null => "null",
            CilPrimitiveKind::TypedReference => "typedref",
            CilPrimitiveKind::ValueType => "valuetype",
            CilPrimitiveKind::Var => "var",
            CilPrimitiveKind::MVar => "mvar",
            CilPrimitiveKind::Class => "class",
        }
    }
}

impl fmt::Display for CilPrimitiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CilPrimitive {
    /// Create a new primitive type without constant data.
    ///
    /// Creates a primitive type representation with the specified kind but no
    /// associated constant value. The data field is set to `CilPrimitiveData::None`.
    /// This is useful for type analysis where only the type classification matters.
    ///
    /// # Arguments
    /// * `kind` - The primitive type classification to create
    ///
    /// # Returns
    /// A new `CilPrimitive` with the specified kind and no data
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveKind, CilPrimitiveData};
    ///
    /// let void_type = CilPrimitive::new(CilPrimitiveKind::Void);
    /// assert_eq!(void_type.kind, CilPrimitiveKind::Void);
    /// assert_eq!(void_type.data, CilPrimitiveData::None);
    /// ```
    #[must_use]
    pub fn new(kind: CilPrimitiveKind) -> Self {
        CilPrimitive {
            kind,
            data: CilPrimitiveData::None,
        }
    }

    /// Create a primitive with both type and constant data.
    ///
    /// Creates a complete primitive representation with both type classification
    /// and an associated constant value. This is the most general constructor
    /// and allows for any combination of kind and data.
    ///
    /// # Arguments
    /// * `kind` - The primitive type classification
    /// * `data` - The constant data value (must be compatible with the kind)
    ///
    /// # Returns
    /// A new `CilPrimitive` with the specified kind and data
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveKind, CilPrimitiveData};
    ///
    /// let int_const = CilPrimitive::with_data(
    ///     CilPrimitiveKind::I4,
    ///     CilPrimitiveData::I4(42)
    /// );
    /// assert_eq!(int_const.kind, CilPrimitiveKind::I4);
    /// assert_eq!(int_const.data, CilPrimitiveData::I4(42));
    /// ```
    #[must_use]
    pub fn with_data(kind: CilPrimitiveKind, data: CilPrimitiveData) -> Self {
        CilPrimitive { kind, data }
    }

    /// Create a boolean primitive constant.
    ///
    /// Convenience constructor for creating a boolean primitive with a specific value.
    /// Equivalent to `with_data(CilPrimitiveKind::Boolean, CilPrimitiveData::Boolean(value))`.
    ///
    /// # Arguments
    /// * `value` - The boolean value (true or false)
    ///
    /// # Returns
    /// A new `CilPrimitive` representing a boolean constant
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::typesystem::CilPrimitive;
    ///
    /// let true_const = CilPrimitive::boolean(true);
    /// let false_const = CilPrimitive::boolean(false);
    ///
    /// assert_eq!(true_const.data.as_boolean(), Some(true));
    /// assert_eq!(false_const.data.as_boolean(), Some(false));
    /// ```
    #[must_use]
    pub fn boolean(value: bool) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Boolean,
            data: CilPrimitiveData::Boolean(value),
        }
    }

    /// Create a character primitive from a Rust char
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn char(value: char) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Char,
            data: CilPrimitiveData::Char(value as u16),
        }
    }

    /// Create a character primitive from a UTF-16 code unit
    ///
    /// ## Arguments  
    /// * `value` - The UTF-16 code unit value (including surrogates)
    #[must_use]
    pub fn char_from_u16(value: u16) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Char,
            data: CilPrimitiveData::Char(value),
        }
    }

    /// Create an i8 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i1(value: i8) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I1,
            data: CilPrimitiveData::I1(value),
        }
    }

    /// Create a u8 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u1(value: u8) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U1,
            data: CilPrimitiveData::U1(value),
        }
    }

    /// Create an i16 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i2(value: i16) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I2,
            data: CilPrimitiveData::I2(value),
        }
    }

    /// Create a u16 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u2(value: u16) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U2,
            data: CilPrimitiveData::U2(value),
        }
    }

    /// Create an i32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i4(value: i32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::I4(value),
        }
    }

    /// Create a u32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u4(value: u32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U4,
            data: CilPrimitiveData::U4(value),
        }
    }

    /// Create an i64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i8(value: i64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I8,
            data: CilPrimitiveData::I8(value),
        }
    }

    /// Create a u64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u8(value: u64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U8,
            data: CilPrimitiveData::U8(value),
        }
    }

    /// Create an f32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn r4(value: f32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::R4,
            data: CilPrimitiveData::R4(value),
        }
    }

    /// Create an f64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn r8(value: f64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::R8,
            data: CilPrimitiveData::R8(value),
        }
    }

    /// Create an usize primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u(value: usize) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U,
            data: CilPrimitiveData::U(value),
        }
    }

    /// Create an isize primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i(value: isize) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I,
            data: CilPrimitiveData::I(value),
        }
    }

    /// Create a string primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn string(value: &str) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::String,
            data: CilPrimitiveData::String(value.to_string()),
        }
    }

    /// Create a null primitive
    #[must_use]
    pub fn null() -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Null,
            data: CilPrimitiveData::None,
        }
    }

    /// Get the token for this primitive type
    #[must_use]
    pub fn token(&self) -> Token {
        self.kind.token()
    }

    /// Get the byte representation in type signatures (per ECMA-335 spec)
    #[must_use]
    pub fn as_byte(&self) -> u8 {
        match self.kind {
            CilPrimitiveKind::Void => ELEMENT_TYPE::VOID,
            CilPrimitiveKind::Boolean => ELEMENT_TYPE::BOOLEAN,
            CilPrimitiveKind::Char => ELEMENT_TYPE::CHAR,
            CilPrimitiveKind::I1 => ELEMENT_TYPE::I1,
            CilPrimitiveKind::U1 => ELEMENT_TYPE::U1,
            CilPrimitiveKind::I2 => ELEMENT_TYPE::I2,
            CilPrimitiveKind::U2 => ELEMENT_TYPE::U2,
            CilPrimitiveKind::I4 => ELEMENT_TYPE::I4,
            CilPrimitiveKind::U4 => ELEMENT_TYPE::U4,
            CilPrimitiveKind::I8 => ELEMENT_TYPE::I8,
            CilPrimitiveKind::U8 => ELEMENT_TYPE::U8,
            CilPrimitiveKind::R4 => ELEMENT_TYPE::R4,
            CilPrimitiveKind::R8 => ELEMENT_TYPE::R8,
            CilPrimitiveKind::I => ELEMENT_TYPE::I,
            CilPrimitiveKind::U => ELEMENT_TYPE::U,
            CilPrimitiveKind::Object => ELEMENT_TYPE::OBJECT,
            CilPrimitiveKind::String => ELEMENT_TYPE::STRING,
            CilPrimitiveKind::TypedReference => ELEMENT_TYPE::TYPEDBYREF,
            CilPrimitiveKind::ValueType => ELEMENT_TYPE::VALUETYPE, // Used for VALUETYPE signature
            CilPrimitiveKind::Var => ELEMENT_TYPE::VAR,             // Used for VAR signature
            CilPrimitiveKind::MVar => ELEMENT_TYPE::MVAR,           // Used for MVAR signature
            CilPrimitiveKind::Null => 0xFF,                         // Not used in signatures
            CilPrimitiveKind::Class => ELEMENT_TYPE::CLASS,
        }
    }

    /// Try to parse a primitive type from a signature byte
    ///
    /// ## Arguments
    /// * `byte` - The kind byte to convert
    ///
    /// # Errors
    /// Returns [`TypeNotPrimitive`] if the byte does not represent a valid primitive type.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            ELEMENT_TYPE::VOID => Ok(Self::new(CilPrimitiveKind::Void)),
            ELEMENT_TYPE::BOOLEAN => Ok(Self::new(CilPrimitiveKind::Boolean)),
            ELEMENT_TYPE::CHAR => Ok(Self::new(CilPrimitiveKind::Char)),
            ELEMENT_TYPE::I1 => Ok(Self::new(CilPrimitiveKind::I1)),
            ELEMENT_TYPE::U1 => Ok(Self::new(CilPrimitiveKind::U1)),
            ELEMENT_TYPE::I2 => Ok(Self::new(CilPrimitiveKind::I2)),
            ELEMENT_TYPE::U2 => Ok(Self::new(CilPrimitiveKind::U2)),
            ELEMENT_TYPE::I4 => Ok(Self::new(CilPrimitiveKind::I4)),
            ELEMENT_TYPE::U4 => Ok(Self::new(CilPrimitiveKind::U4)),
            ELEMENT_TYPE::I8 => Ok(Self::new(CilPrimitiveKind::I8)),
            ELEMENT_TYPE::U8 => Ok(Self::new(CilPrimitiveKind::U8)),
            ELEMENT_TYPE::R4 => Ok(Self::new(CilPrimitiveKind::R4)),
            ELEMENT_TYPE::R8 => Ok(Self::new(CilPrimitiveKind::R8)),
            ELEMENT_TYPE::STRING => Ok(Self::new(CilPrimitiveKind::String)),
            ELEMENT_TYPE::TYPEDBYREF => Ok(Self::new(CilPrimitiveKind::TypedReference)),
            ELEMENT_TYPE::I => Ok(Self::new(CilPrimitiveKind::I)),
            ELEMENT_TYPE::U => Ok(Self::new(CilPrimitiveKind::U)),
            ELEMENT_TYPE::OBJECT => Ok(Self::new(CilPrimitiveKind::Object)),
            ELEMENT_TYPE::CLASS => Ok(Self::new(CilPrimitiveKind::Class)),
            // Note: 0x11 (VALUETYPE), 0x13 (VAR), and 0x1E (MVAR) are handled separately
            // in signature parsing as they require additional parameters
            _ => Err(TypeNotPrimitive),
        }
    }

    /// Get the CLR full type name (with namespace)
    #[must_use]
    pub fn clr_full_name(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Void => "System.Void",
            CilPrimitiveKind::Boolean => "System.Boolean",
            CilPrimitiveKind::Char => "System.Char",
            CilPrimitiveKind::I1 => "System.SByte",
            CilPrimitiveKind::U1 => "System.Byte",
            CilPrimitiveKind::I2 => "System.Int16",
            CilPrimitiveKind::U2 => "System.UInt16",
            CilPrimitiveKind::I4 => "System.Int32",
            CilPrimitiveKind::U4 => "System.UInt32",
            CilPrimitiveKind::I8 => "System.Int64",
            CilPrimitiveKind::U8 => "System.UInt64",
            CilPrimitiveKind::R4 => "System.Single",
            CilPrimitiveKind::R8 => "System.Double",
            CilPrimitiveKind::I => "System.IntPtr",
            CilPrimitiveKind::U => "System.UIntPtr",
            CilPrimitiveKind::Object => "System.Object",
            CilPrimitiveKind::String => "System.String",
            CilPrimitiveKind::TypedReference => "System.TypedReference",
            CilPrimitiveKind::ValueType => "System.ValueType",
            CilPrimitiveKind::Var => "<Generic Parameter>",
            CilPrimitiveKind::MVar => "<Generic Method Parameter>",
            CilPrimitiveKind::Null => "<null>",
            CilPrimitiveKind::Class => "",
        }
    }

    /// Get the namespace of this type
    #[must_use]
    pub fn namespace(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Var | CilPrimitiveKind::MVar | CilPrimitiveKind::Null => "",
            _ => "System",
        }
    }

    /// Get the short name (without namespace)
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Void => "Void",
            CilPrimitiveKind::Boolean => "Boolean",
            CilPrimitiveKind::Char => "Char",
            CilPrimitiveKind::I1 => "SByte",
            CilPrimitiveKind::U1 => "Byte",
            CilPrimitiveKind::I2 => "Int16",
            CilPrimitiveKind::U2 => "UInt16",
            CilPrimitiveKind::I4 => "Int32",
            CilPrimitiveKind::U4 => "UInt32",
            CilPrimitiveKind::I8 => "Int64",
            CilPrimitiveKind::U8 => "UInt64",
            CilPrimitiveKind::R4 => "Single",
            CilPrimitiveKind::R8 => "Double",
            CilPrimitiveKind::I => "IntPtr",
            CilPrimitiveKind::U => "UIntPtr",
            CilPrimitiveKind::Object => "Object",
            CilPrimitiveKind::String => "String",
            CilPrimitiveKind::TypedReference => "TypedReference",
            CilPrimitiveKind::ValueType => "ValueType",
            CilPrimitiveKind::Var => "<Generic Parameter>",
            CilPrimitiveKind::MVar => "<Generic Method Parameter>",
            CilPrimitiveKind::Null => "<null>",
            CilPrimitiveKind::Class => "Class",
        }
    }

    /// Convert to `CilFlavor`
    #[must_use]
    pub fn to_flavor(&self) -> CilFlavor {
        match self.kind {
            CilPrimitiveKind::Void => CilFlavor::Void,
            CilPrimitiveKind::Boolean => CilFlavor::Boolean,
            CilPrimitiveKind::Char => CilFlavor::Char,
            CilPrimitiveKind::I1 => CilFlavor::I1,
            CilPrimitiveKind::U1 => CilFlavor::U1,
            CilPrimitiveKind::I2 => CilFlavor::I2,
            CilPrimitiveKind::U2 => CilFlavor::U2,
            CilPrimitiveKind::I4 => CilFlavor::I4,
            CilPrimitiveKind::U4 => CilFlavor::U4,
            CilPrimitiveKind::I8 => CilFlavor::I8,
            CilPrimitiveKind::U8 => CilFlavor::U8,
            CilPrimitiveKind::R4 => CilFlavor::R4,
            CilPrimitiveKind::R8 => CilFlavor::R8,
            CilPrimitiveKind::I => CilFlavor::I,
            CilPrimitiveKind::U => CilFlavor::U,
            CilPrimitiveKind::Object => CilFlavor::Object,
            CilPrimitiveKind::String => CilFlavor::String,
            CilPrimitiveKind::TypedReference | CilPrimitiveKind::Null => CilFlavor::Unknown,
            CilPrimitiveKind::ValueType => CilFlavor::ValueType,
            CilPrimitiveKind::Var => CilFlavor::GenericParameter {
                index: 0,
                method: false,
            },
            CilPrimitiveKind::MVar => CilFlavor::GenericParameter {
                index: 0,
                method: true,
            },
            CilPrimitiveKind::Class => CilFlavor::Class,
        }
    }

    /// Check if this primitive is compatible with a target flavor
    ///
    /// This is a convenience method that converts the primitive to a flavor
    /// and checks compatibility with the target flavor.
    ///
    /// # Arguments
    /// * `target_flavor` - The target flavor to check compatibility against
    ///
    /// # Returns
    /// `true` if this primitive value can be assigned to the target flavor
    #[must_use]
    pub fn is_compatible_with(&self, target_flavor: &CilFlavor) -> bool {
        let this_flavor = self.to_flavor();
        this_flavor.is_compatible_with(target_flavor)
    }

    /// Is this a value type
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self.kind,
            CilPrimitiveKind::Boolean
                | CilPrimitiveKind::Char
                | CilPrimitiveKind::I1
                | CilPrimitiveKind::U1
                | CilPrimitiveKind::I2
                | CilPrimitiveKind::U2
                | CilPrimitiveKind::I4
                | CilPrimitiveKind::U4
                | CilPrimitiveKind::I8
                | CilPrimitiveKind::U8
                | CilPrimitiveKind::R4
                | CilPrimitiveKind::R8
                | CilPrimitiveKind::I
                | CilPrimitiveKind::U
                | CilPrimitiveKind::ValueType
        )
    }

    /// Is this a reference type
    #[must_use]
    pub fn is_reference_type(&self) -> bool {
        matches!(
            self.kind,
            CilPrimitiveKind::Object | CilPrimitiveKind::String
        )
    }

    /// Parse a primitive value from a blob of data
    ///
    /// ## Arguments
    /// * `p_type`  - The primitive byte to determine the kind of
    /// * `blob`    - The data blob to parse for the value
    ///
    /// # Errors
    /// Returns [`crate::Error::TypeNotPrimitive`] if the primitive type is invalid.
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] or other errors if the blob data is insufficient or invalid.
    pub fn from_blob(p_type: u8, blob: &[u8]) -> Result<Self> {
        Ok(CilPrimitive {
            kind: CilPrimitiveKind::from_byte(p_type)?,
            data: CilPrimitiveData::from_bytes(p_type, blob)?,
        })
    }

    /// Try to get as boolean value
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        self.data.as_boolean()
    }

    /// Try to get as i32 value
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        self.data.as_i32()
    }

    /// Try to get as i64 value
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.data.as_i64()
    }

    /// Try to get as f64 value
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.data.as_f64()
    }

    /// Try to get as string value
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        self.data.as_string()
    }

    /// Serialize this primitive to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.data {
            CilPrimitiveData::None => Vec::new(),
            CilPrimitiveData::Boolean(value) => vec![u8::from(*value)],
            CilPrimitiveData::Char(value) => {
                let code = *value;
                vec![(code & 0xFF) as u8, ((code >> 8) & 0xFF) as u8]
            }
            CilPrimitiveData::I1(value) => vec![{
                #[allow(clippy::cast_sign_loss)]
                {
                    *value as u8
                }
            }],
            CilPrimitiveData::U1(value) => vec![*value],
            CilPrimitiveData::I2(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U2(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::R4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::R8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::String(value) => {
                let utf16_chars: Vec<u16> = value.encode_utf16().collect();
                let mut bytes = Vec::with_capacity(utf16_chars.len().saturating_mul(2));
                for ch in utf16_chars {
                    bytes.extend_from_slice(&ch.to_le_bytes());
                }
                bytes
            }
            CilPrimitiveData::Bytes(value) => value.clone(),
        }
    }
}

impl fmt::Display for CilPrimitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            CilPrimitiveData::None => write!(f, "{}", self.clr_full_name()),
            CilPrimitiveData::Boolean(value) => write!(f, "{value}"),
            CilPrimitiveData::Char(value) => {
                // Try to display as a proper Unicode character if possible
                if let Some(ch) = char::from_u32(u32::from(*value)) {
                    write!(f, "'{ch}'")
                } else {
                    // For surrogates or invalid values, show as Unicode escape
                    write!(f, "'\\u{{{value:04X}}}'")
                }
            }
            CilPrimitiveData::I1(value) => write!(f, "{value}"),
            CilPrimitiveData::U1(value) => write!(f, "{value}"),
            CilPrimitiveData::I2(value) => write!(f, "{value}"),
            CilPrimitiveData::U2(value) => write!(f, "{value}"),
            CilPrimitiveData::I4(value) => write!(f, "{value}"),
            CilPrimitiveData::U4(value) => write!(f, "{value}"),
            CilPrimitiveData::I8(value) => write!(f, "{value}"),
            CilPrimitiveData::U8(value) => write!(f, "{value}"),
            CilPrimitiveData::R4(value) => write!(f, "{value}"),
            CilPrimitiveData::R8(value) => write!(f, "{value}"),
            CilPrimitiveData::U(value) => write!(f, "{value}"),
            CilPrimitiveData::I(value) => write!(f, "{value}"),
            CilPrimitiveData::String(value) => write!(f, "\"{value}\""),
            CilPrimitiveData::Bytes(value) => {
                write!(f, "Bytes[")?;
                for (i, byte) in value.iter().enumerate().take(8) {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{byte:02X}")?;
                }
                if value.len() > 8 {
                    write!(f, "...")?;
                }
                write!(f, "]")
            }
        }
    }
}

impl From<bool> for CilPrimitive {
    fn from(value: bool) -> Self {
        CilPrimitive::boolean(value)
    }
}

impl From<char> for CilPrimitive {
    fn from(value: char) -> Self {
        CilPrimitive::char(value)
    }
}

impl From<i8> for CilPrimitive {
    fn from(value: i8) -> Self {
        CilPrimitive::i1(value)
    }
}

impl From<u8> for CilPrimitive {
    fn from(value: u8) -> Self {
        CilPrimitive::u1(value)
    }
}

impl From<i16> for CilPrimitive {
    fn from(value: i16) -> Self {
        CilPrimitive::i2(value)
    }
}

impl From<u16> for CilPrimitive {
    fn from(value: u16) -> Self {
        CilPrimitive::u2(value)
    }
}

impl From<i32> for CilPrimitive {
    fn from(value: i32) -> Self {
        CilPrimitive::i4(value)
    }
}

impl From<u32> for CilPrimitive {
    fn from(value: u32) -> Self {
        CilPrimitive::u4(value)
    }
}

impl From<i64> for CilPrimitive {
    fn from(value: i64) -> Self {
        CilPrimitive::i8(value)
    }
}

impl From<u64> for CilPrimitive {
    fn from(value: u64) -> Self {
        CilPrimitive::u8(value)
    }
}

impl From<f32> for CilPrimitive {
    fn from(value: f32) -> Self {
        CilPrimitive::r4(value)
    }
}

impl From<f64> for CilPrimitive {
    fn from(value: f64) -> Self {
        CilPrimitive::r8(value)
    }
}

impl From<&str> for CilPrimitive {
    fn from(value: &str) -> Self {
        CilPrimitive::string(value)
    }
}

impl From<String> for CilPrimitive {
    fn from(value: String) -> Self {
        CilPrimitive::string(&value)
    }
}

impl TryFrom<CilPrimitive> for bool {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_boolean().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for i32 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_i32().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for i64 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_i64().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for f64 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_f64().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for String {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_string().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilFlavor> for CilPrimitive {
    type Error = Error;

    fn try_from(flavor: CilFlavor) -> Result<Self> {
        match flavor.to_primitive_kind() {
            Some(kind) => Ok(CilPrimitive::new(kind)),
            None => Err(TypeNotPrimitive),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use crate::ParseFailure;

    #[test]
    fn test_primitive_creation() {
        let bool_primitive = CilPrimitive::boolean(true);
        assert_eq!(bool_primitive.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_primitive.data, CilPrimitiveData::Boolean(true));

        let int_primitive = CilPrimitive::i4(42);
        assert_eq!(int_primitive.kind, CilPrimitiveKind::I4);
        assert_eq!(int_primitive.data, CilPrimitiveData::I4(42));

        let string_primitive = CilPrimitive::string("Hello");
        assert_eq!(string_primitive.kind, CilPrimitiveKind::String);
        assert_eq!(
            string_primitive.data,
            CilPrimitiveData::String("Hello".to_string())
        );

        let void_primitive = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_primitive.kind, CilPrimitiveKind::Void);
        assert_eq!(void_primitive.data, CilPrimitiveData::None);

        let char_primitive =
            CilPrimitive::with_data(CilPrimitiveKind::Char, CilPrimitiveData::Char('A' as u16));
        assert_eq!(char_primitive.kind, CilPrimitiveKind::Char);
        assert_eq!(char_primitive.data, CilPrimitiveData::Char('A' as u16));
    }

    #[test]
    fn test_data_conversion() {
        let int_primitive = CilPrimitive::i4(42);
        assert_eq!(int_primitive.as_i32(), Some(42));
        assert_eq!(int_primitive.as_i64(), Some(42i64));
        assert_eq!(int_primitive.as_f64(), Some(42.0));
        assert_eq!(int_primitive.as_boolean(), Some(true));
        assert_eq!(int_primitive.as_string(), Some("42".to_string()));

        let bool_primitive = CilPrimitive::boolean(true);
        assert_eq!(bool_primitive.as_i32(), Some(1));
        assert_eq!(bool_primitive.as_boolean(), Some(true));

        let string_primitive = CilPrimitive::string("123");
        assert_eq!(string_primitive.as_string(), Some("123".to_string()));
        assert_eq!(string_primitive.as_i32(), None); // Can't convert string to int

        // Test data conversion for more types
        let i1_primitive = CilPrimitive::i1(-42);
        assert_eq!(i1_primitive.as_i32(), Some(-42));

        let u1_primitive = CilPrimitive::u1(42);
        assert_eq!(u1_primitive.as_i32(), Some(42));

        let i2_primitive = CilPrimitive::i2(-1000);
        assert_eq!(i2_primitive.as_i32(), Some(-1000));

        let u2_primitive = CilPrimitive::u2(1000);
        assert_eq!(u2_primitive.as_i32(), Some(1000));

        let i8_primitive = CilPrimitive::i8(-1_000_000_000_000);
        assert_eq!(i8_primitive.as_i64(), Some(-1_000_000_000_000));

        let u8_primitive = CilPrimitive::u8(1_000_000_000_000);
        assert_eq!(u8_primitive.as_i64(), Some(1_000_000_000_000));

        let r4_primitive = CilPrimitive::r4(3.01);
        assert!((r4_primitive.as_f64().unwrap() - 3.01).abs() < 0.001);

        let r8_primitive = CilPrimitive::r8(3.00009);
        assert!((r8_primitive.as_f64().unwrap() - 3.00009).abs() < 0.000001);

        let i_primitive = CilPrimitive::i(42);
        assert_eq!(i_primitive.as_i32(), Some(42));

        let u_primitive = CilPrimitive::u(42);
        assert_eq!(u_primitive.as_i32(), Some(42));
    }

    #[test]
    fn test_primitive_from_blob() {
        let bool_blob = vec![1]; // true
        let bool_prim = CilPrimitive::from_blob(ELEMENT_TYPE::BOOLEAN, &bool_blob).unwrap();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_prim.as_boolean(), Some(true));

        let int_blob = vec![42, 0, 0, 0]; // 42 as i32
        let int_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I4, &int_blob).unwrap();
        assert_eq!(int_prim.kind, CilPrimitiveKind::I4);
        assert_eq!(int_prim.as_i32(), Some(42));

        let float_blob = vec![0, 0, 0x20, 0x41]; // 10.0 as f32
        let float_prim = CilPrimitive::from_blob(ELEMENT_TYPE::R4, &float_blob).unwrap();
        assert_eq!(float_prim.kind, CilPrimitiveKind::R4);
        assert!((float_prim.as_f64().unwrap() - 10.0).abs() < 0.001);

        let i1_blob = vec![0xFF]; // -1 as i8
        let i1_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I1, &i1_blob).unwrap();
        assert_eq!(i1_prim.kind, CilPrimitiveKind::I1);
        assert_eq!(i1_prim.as_i32(), Some(-1));

        let u1_blob = vec![0xFF]; // 255 as u8
        let u1_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U1, &u1_blob).unwrap();
        assert_eq!(u1_prim.kind, CilPrimitiveKind::U1);
        assert_eq!(u1_prim.as_i32(), Some(255));

        let i2_blob = vec![0xFF, 0xFF]; // -1 as i16
        let i2_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I2, &i2_blob).unwrap();
        assert_eq!(i2_prim.kind, CilPrimitiveKind::I2);
        assert_eq!(i2_prim.as_i32(), Some(-1));

        let u2_blob = vec![0xFF, 0xFF]; // 65535 as u16
        let u2_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U2, &u2_blob).unwrap();
        assert_eq!(u2_prim.kind, CilPrimitiveKind::U2);
        assert_eq!(u2_prim.as_i32(), Some(65535));

        let i8_blob = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // -1 as i64
        let i8_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I8, &i8_blob).unwrap();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I8);
        assert_eq!(i8_prim.as_i64(), Some(-1));

        let u8_blob = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // max u64
        let u8_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U8, &u8_blob).unwrap();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U8);
        assert_eq!(u8_prim.as_i64(), None);

        let char_blob = vec![65, 0]; // 'A' as UTF-16 little-endian
        let char_prim = CilPrimitive::from_blob(ELEMENT_TYPE::CHAR, &char_blob).unwrap();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);
        assert_eq!(char_prim.data, CilPrimitiveData::Char('A' as u16));
    }

    #[test]
    fn test_to_flavor() {
        let bool_prim = CilPrimitive::boolean(true);
        let flavor = bool_prim.to_flavor();
        assert!(matches!(flavor, CilFlavor::Boolean));

        let int_prim = CilPrimitive::i4(42);
        let flavor = int_prim.to_flavor();
        assert!(matches!(flavor, CilFlavor::I4));

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert!(matches!(void_prim.to_flavor(), CilFlavor::Void));

        let char_prim = CilPrimitive::char('A');
        assert!(matches!(char_prim.to_flavor(), CilFlavor::Char));

        let i1_prim = CilPrimitive::i1(42);
        assert!(matches!(i1_prim.to_flavor(), CilFlavor::I1));

        let u1_prim = CilPrimitive::u1(42);
        assert!(matches!(u1_prim.to_flavor(), CilFlavor::U1));

        let i2_prim = CilPrimitive::i2(42);
        assert!(matches!(i2_prim.to_flavor(), CilFlavor::I2));

        let u2_prim = CilPrimitive::u2(42);
        assert!(matches!(u2_prim.to_flavor(), CilFlavor::U2));

        let u4_prim = CilPrimitive::u4(42);
        assert!(matches!(u4_prim.to_flavor(), CilFlavor::U4));

        let i8_prim = CilPrimitive::i8(42);
        assert!(matches!(i8_prim.to_flavor(), CilFlavor::I8));

        let u8_prim = CilPrimitive::u8(42);
        assert!(matches!(u8_prim.to_flavor(), CilFlavor::U8));

        let r4_prim = CilPrimitive::r4(3.04);
        assert!(matches!(r4_prim.to_flavor(), CilFlavor::R4));

        let r8_prim = CilPrimitive::r8(3.04);
        assert!(matches!(r8_prim.to_flavor(), CilFlavor::R8));

        let i_prim = CilPrimitive::i(42);
        assert!(matches!(i_prim.to_flavor(), CilFlavor::I));

        let u_prim = CilPrimitive::u(42);
        assert!(matches!(u_prim.to_flavor(), CilFlavor::U));

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert!(matches!(obj_prim.to_flavor(), CilFlavor::Object));

        let str_prim = CilPrimitive::string("Hello");
        assert!(matches!(str_prim.to_flavor(), CilFlavor::String));

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        if let CilFlavor::GenericParameter { index, method } = var_prim.to_flavor() {
            assert_eq!(index, 0);
            assert!(!method);
        } else {
            panic!("Expected GenericParameter flavor");
        }

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        if let CilFlavor::GenericParameter { index, method } = mvar_prim.to_flavor() {
            assert_eq!(index, 0);
            assert!(method);
        } else {
            panic!("Expected GenericParameter flavor");
        }
    }

    #[test]
    fn test_from_conversions() {
        let bool_prim: CilPrimitive = true.into();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_prim.as_boolean(), Some(true));

        let int_prim: CilPrimitive = 42i32.into();
        assert_eq!(int_prim.kind, CilPrimitiveKind::I4);
        assert_eq!(int_prim.as_i32(), Some(42));

        let string_prim: CilPrimitive = "Hello".into();
        assert_eq!(string_prim.kind, CilPrimitiveKind::String);
        assert_eq!(string_prim.as_string(), Some("Hello".to_string()));

        let i8_prim: CilPrimitive = 42i8.into();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I1);
        assert_eq!(i8_prim.as_i32(), Some(42));

        let u8_prim: CilPrimitive = 42u8.into();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U1);
        assert_eq!(u8_prim.as_i32(), Some(42));

        let i16_prim: CilPrimitive = 42i16.into();
        assert_eq!(i16_prim.kind, CilPrimitiveKind::I2);
        assert_eq!(i16_prim.as_i32(), Some(42));

        let u16_prim: CilPrimitive = 42u16.into();
        assert_eq!(u16_prim.kind, CilPrimitiveKind::U2);
        assert_eq!(u16_prim.as_i32(), Some(42));

        let u32_prim: CilPrimitive = 42u32.into();
        assert_eq!(u32_prim.kind, CilPrimitiveKind::U4);
        assert_eq!(u32_prim.as_i32(), Some(42));

        let i64_prim: CilPrimitive = 42i64.into();
        assert_eq!(i64_prim.kind, CilPrimitiveKind::I8);
        assert_eq!(i64_prim.as_i64(), Some(42));

        let u64_prim: CilPrimitive = 42u64.into();
        assert_eq!(u64_prim.kind, CilPrimitiveKind::U8);
        assert_eq!(u64_prim.as_i64(), Some(42));

        let f32_prim: CilPrimitive = 3.01f32.into();
        assert_eq!(f32_prim.kind, CilPrimitiveKind::R4);
        assert!((f32_prim.as_f64().unwrap() - 3.01).abs() < 0.001);

        let f64_prim: CilPrimitive = 3.00002f64.into();
        assert_eq!(f64_prim.kind, CilPrimitiveKind::R8);
        assert!((f64_prim.as_f64().unwrap() - 3.00002).abs() < 0.00001);

        let char_prim: CilPrimitive = 'A'.into();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);

        let string_owned_prim: CilPrimitive = "Hello".to_string().into();
        assert_eq!(string_owned_prim.kind, CilPrimitiveKind::String);
        assert_eq!(string_owned_prim.as_string(), Some("Hello".to_string()));
    }

    #[test]
    fn test_try_into_conversions() {
        let bool_prim = CilPrimitive::boolean(true);
        let bool_val: bool = bool_prim.try_into().unwrap();
        assert!(bool_val);

        let int_prim = CilPrimitive::i4(42);
        let int_val: i32 = int_prim.try_into().unwrap();
        assert_eq!(int_val, 42);

        let string_prim = CilPrimitive::string("Hello");
        let string_val: String = string_prim.try_into().unwrap();
        assert_eq!(string_val, "Hello");

        let string_prim = CilPrimitive::string("Hello");
        let int_result: Result<i32> = string_prim.try_into();
        assert!(int_result.is_err());
        assert!(matches!(int_result, Err(Error::TypeConversionInvalid)));

        let i64_prim = CilPrimitive::i8(42);
        let i64_val: i64 = i64_prim.try_into().unwrap();
        assert_eq!(i64_val, 42);

        let f64_prim = CilPrimitive::r8(3.0);
        let f64_val: f64 = f64_prim.try_into().unwrap();
        assert!((f64_val - 3.0).abs() < 0.00001);

        let large_i64 = CilPrimitive::i8(i64::MAX);
        let i32_result: Result<i32> = large_i64.try_into();
        assert!(i32_result.is_err());

        let large_u64 = CilPrimitive::u8(u64::MAX);
        let i64_result: Result<i64> = large_u64.try_into();
        assert!(i64_result.is_err());
    }

    #[test]
    fn test_display() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.to_string(), "true");

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.to_string(), "42");

        let string_prim = CilPrimitive::string("Hello");
        assert_eq!(string_prim.to_string(), "\"Hello\"");

        let bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        };
        assert_eq!(bytes_prim.to_string(), "Bytes[01 02 03 04 05 06 07 08...]");

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.to_string(), "System.Void");

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.to_string(), "'A'");

        let i1_prim = CilPrimitive::i1(-42);
        assert_eq!(i1_prim.to_string(), "-42");

        let u1_prim = CilPrimitive::u1(255);
        assert_eq!(u1_prim.to_string(), "255");

        let i2_prim = CilPrimitive::i2(-1000);
        assert_eq!(i2_prim.to_string(), "-1000");

        let u2_prim = CilPrimitive::u2(65535);
        assert_eq!(u2_prim.to_string(), "65535");

        let u4_prim = CilPrimitive::u4(4294967295);
        assert_eq!(u4_prim.to_string(), "4294967295");

        let i8_prim = CilPrimitive::i8(-1000000000000);
        assert_eq!(i8_prim.to_string(), "-1000000000000");

        let u8_prim = CilPrimitive::u8(18446744073709551615);
        assert_eq!(u8_prim.to_string(), "18446744073709551615");

        let r4_prim = CilPrimitive::r4(3.01);
        assert!(r4_prim.to_string().starts_with("3.0"));

        let r8_prim = CilPrimitive::r8(3.01);
        assert!(r8_prim.to_string().starts_with("3.0"));

        let i_prim = CilPrimitive::i(42);
        assert_eq!(i_prim.to_string(), "42");

        let u_prim = CilPrimitive::u(42);
        assert_eq!(u_prim.to_string(), "42");

        let small_bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3]),
        };
        assert_eq!(small_bytes_prim.to_string(), "Bytes[01 02 03]");
    }

    #[test]
    fn test_serialization() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.to_bytes(), vec![1]);

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.to_bytes(), vec![42, 0, 0, 0]);

        let string_prim = CilPrimitive::string("Hello");
        assert_eq!(
            string_prim.to_bytes(),
            vec![72, 0, 101, 0, 108, 0, 108, 0, 111, 0]
        );

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert!(void_prim.to_bytes().is_empty());

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.to_bytes(), vec![65, 0]);

        let i1_prim = CilPrimitive::i1(-1);
        assert_eq!(i1_prim.to_bytes(), vec![255]);

        let u1_prim = CilPrimitive::u1(255);
        assert_eq!(u1_prim.to_bytes(), vec![255]);

        let i2_prim = CilPrimitive::i2(-1);
        assert_eq!(i2_prim.to_bytes(), vec![255, 255]);

        let u2_prim = CilPrimitive::u2(65535);
        assert_eq!(u2_prim.to_bytes(), vec![255, 255]);

        let i8_prim = CilPrimitive::i8(-1);
        assert_eq!(
            i8_prim.to_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );

        let u8_prim = CilPrimitive::u8(0xFFFFFFFFFFFFFFFF);
        assert_eq!(
            u8_prim.to_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );

        let bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::U1,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3, 4]),
        };
        assert_eq!(bytes_prim.to_bytes(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_primitive_token() {
        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.token().value(), 0xF0000001);

        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.token().value(), 0xF0000002);

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.token().value(), 0xF0000003);

        let i1_prim = CilPrimitive::i1(0);
        assert_eq!(i1_prim.token().value(), 0xF0000004);

        let u1_prim = CilPrimitive::u1(0);
        assert_eq!(u1_prim.token().value(), 0xF0000005);

        let i2_prim = CilPrimitive::i2(0);
        assert_eq!(i2_prim.token().value(), 0xF0000006);

        let u2_prim = CilPrimitive::u2(0);
        assert_eq!(u2_prim.token().value(), 0xF0000007);

        let i4_prim = CilPrimitive::i4(0);
        assert_eq!(i4_prim.token().value(), 0xF0000008);

        let u4_prim = CilPrimitive::u4(0);
        assert_eq!(u4_prim.token().value(), 0xF0000009);

        let i8_prim = CilPrimitive::i8(0);
        assert_eq!(i8_prim.token().value(), 0xF000000A);

        let u8_prim = CilPrimitive::u8(0);
        assert_eq!(u8_prim.token().value(), 0xF000000B);

        let r4_prim = CilPrimitive::r4(0.0);
        assert_eq!(r4_prim.token().value(), 0xF000000C);

        let r8_prim = CilPrimitive::r8(0.0);
        assert_eq!(r8_prim.token().value(), 0xF000000D);

        let i_prim = CilPrimitive::i(0);
        assert_eq!(i_prim.token().value(), 0xF000000E);

        let u_prim = CilPrimitive::u(0);
        assert_eq!(u_prim.token().value(), 0xF000000F);

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert_eq!(obj_prim.token().value(), 0xF0000010);

        let str_prim = CilPrimitive::string("");
        assert_eq!(str_prim.token().value(), 0xF0000011);

        let typed_ref_prim = CilPrimitive::new(CilPrimitiveKind::TypedReference);
        assert_eq!(typed_ref_prim.token().value(), 0xF0000012);

        let value_type_prim = CilPrimitive::new(CilPrimitiveKind::ValueType);
        assert_eq!(value_type_prim.token().value(), 0xF0000013);

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.token().value(), 0xF0000014);

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.token().value(), 0xF0000015);

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.token().value(), 0xF0000016);

        let class_prim = CilPrimitive::new(CilPrimitiveKind::Class);
        assert_eq!(class_prim.token().value(), 0xF0000017);
    }

    #[test]
    fn test_as_byte() {
        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.as_byte(), ELEMENT_TYPE::VOID);

        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.as_byte(), ELEMENT_TYPE::BOOLEAN);

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.as_byte(), ELEMENT_TYPE::CHAR);

        let i1_prim = CilPrimitive::i1(0);
        assert_eq!(i1_prim.as_byte(), ELEMENT_TYPE::I1);

        let u1_prim = CilPrimitive::u1(0);
        assert_eq!(u1_prim.as_byte(), ELEMENT_TYPE::U1);

        let i2_prim = CilPrimitive::i2(0);
        assert_eq!(i2_prim.as_byte(), ELEMENT_TYPE::I2);

        let u2_prim = CilPrimitive::u2(0);
        assert_eq!(u2_prim.as_byte(), ELEMENT_TYPE::U2);

        let i4_prim = CilPrimitive::i4(0);
        assert_eq!(i4_prim.as_byte(), ELEMENT_TYPE::I4);

        let u4_prim = CilPrimitive::u4(0);
        assert_eq!(u4_prim.as_byte(), ELEMENT_TYPE::U4);

        let i8_prim = CilPrimitive::i8(0);
        assert_eq!(i8_prim.as_byte(), ELEMENT_TYPE::I8);

        let u8_prim = CilPrimitive::u8(0);
        assert_eq!(u8_prim.as_byte(), ELEMENT_TYPE::U8);

        let r4_prim = CilPrimitive::r4(0.0);
        assert_eq!(r4_prim.as_byte(), ELEMENT_TYPE::R4);

        let r8_prim = CilPrimitive::r8(0.0);
        assert_eq!(r8_prim.as_byte(), ELEMENT_TYPE::R8);

        let i_prim = CilPrimitive::i(0);
        assert_eq!(i_prim.as_byte(), ELEMENT_TYPE::I);

        let u_prim = CilPrimitive::u(0);
        assert_eq!(u_prim.as_byte(), ELEMENT_TYPE::U);

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert_eq!(obj_prim.as_byte(), ELEMENT_TYPE::OBJECT);

        let str_prim = CilPrimitive::string("");
        assert_eq!(str_prim.as_byte(), ELEMENT_TYPE::STRING);

        let typed_ref_prim = CilPrimitive::new(CilPrimitiveKind::TypedReference);
        assert_eq!(typed_ref_prim.as_byte(), ELEMENT_TYPE::TYPEDBYREF);

        let value_type_prim = CilPrimitive::new(CilPrimitiveKind::ValueType);
        assert_eq!(value_type_prim.as_byte(), ELEMENT_TYPE::VALUETYPE);

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.as_byte(), ELEMENT_TYPE::VAR);

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.as_byte(), ELEMENT_TYPE::MVAR);

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.as_byte(), 0xFF); // Not used in signatures

        let class_prim = CilPrimitive::new(CilPrimitiveKind::Class);
        assert_eq!(class_prim.as_byte(), ELEMENT_TYPE::CLASS);
    }

    #[test]
    fn test_from_byte() {
        let void_prim = CilPrimitive::from_byte(ELEMENT_TYPE::VOID).unwrap();
        assert_eq!(void_prim.kind, CilPrimitiveKind::Void);

        let bool_prim = CilPrimitive::from_byte(ELEMENT_TYPE::BOOLEAN).unwrap();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);

        let char_prim = CilPrimitive::from_byte(ELEMENT_TYPE::CHAR).unwrap();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);

        let i1_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I1).unwrap();
        assert_eq!(i1_prim.kind, CilPrimitiveKind::I1);

        let u1_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U1).unwrap();
        assert_eq!(u1_prim.kind, CilPrimitiveKind::U1);

        let i2_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I2).unwrap();
        assert_eq!(i2_prim.kind, CilPrimitiveKind::I2);

        let u2_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U2).unwrap();
        assert_eq!(u2_prim.kind, CilPrimitiveKind::U2);

        let i4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I4).unwrap();
        assert_eq!(i4_prim.kind, CilPrimitiveKind::I4);

        let u4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U4).unwrap();
        assert_eq!(u4_prim.kind, CilPrimitiveKind::U4);

        let i8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I8).unwrap();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I8);

        let u8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U8).unwrap();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U8);

        let r4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::R4).unwrap();
        assert_eq!(r4_prim.kind, CilPrimitiveKind::R4);

        let r8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::R8).unwrap();
        assert_eq!(r8_prim.kind, CilPrimitiveKind::R8);

        let i_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I).unwrap();
        assert_eq!(i_prim.kind, CilPrimitiveKind::I);

        let u_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U).unwrap();
        assert_eq!(u_prim.kind, CilPrimitiveKind::U);

        let obj_prim = CilPrimitive::from_byte(ELEMENT_TYPE::OBJECT).unwrap();
        assert_eq!(obj_prim.kind, CilPrimitiveKind::Object);

        let str_prim = CilPrimitive::from_byte(ELEMENT_TYPE::STRING).unwrap();
        assert_eq!(str_prim.kind, CilPrimitiveKind::String);

        let typed_ref_prim = CilPrimitive::from_byte(ELEMENT_TYPE::TYPEDBYREF).unwrap();
        assert_eq!(typed_ref_prim.kind, CilPrimitiveKind::TypedReference);

        let result = CilPrimitive::from_byte(0xFF);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::VALUETYPE);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::VAR);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::MVAR);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_type_info() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.namespace(), "System");
        assert_eq!(bool_prim.name(), "Boolean");
        assert_eq!(bool_prim.clr_full_name(), "System.Boolean");

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.namespace(), "System");
        assert_eq!(int_prim.name(), "Int32");
        assert_eq!(int_prim.clr_full_name(), "System.Int32");

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.namespace(), "");
        assert_eq!(var_prim.name(), "<Generic Parameter>");
        assert_eq!(var_prim.clr_full_name(), "<Generic Parameter>");

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.namespace(), "");
        assert_eq!(mvar_prim.name(), "<Generic Method Parameter>");
        assert_eq!(mvar_prim.clr_full_name(), "<Generic Method Parameter>");

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.namespace(), "");
        assert_eq!(null_prim.name(), "<null>");
        assert_eq!(null_prim.clr_full_name(), "<null>");
    }

    #[test]
    fn test_is_value_type_and_reference_type() {
        assert!(CilPrimitive::boolean(true).is_value_type());
        assert!(CilPrimitive::char('A').is_value_type());
        assert!(CilPrimitive::i1(0).is_value_type());
        assert!(CilPrimitive::u1(0).is_value_type());
        assert!(CilPrimitive::i2(0).is_value_type());
        assert!(CilPrimitive::u2(0).is_value_type());
        assert!(CilPrimitive::i4(0).is_value_type());
        assert!(CilPrimitive::u4(0).is_value_type());
        assert!(CilPrimitive::i8(0).is_value_type());
        assert!(CilPrimitive::u8(0).is_value_type());
        assert!(CilPrimitive::r4(0.0).is_value_type());
        assert!(CilPrimitive::r8(0.0).is_value_type());
        assert!(CilPrimitive::i(0).is_value_type());
        assert!(CilPrimitive::u(0).is_value_type());
        assert!(CilPrimitive::new(CilPrimitiveKind::ValueType).is_value_type());

        assert!(!CilPrimitive::new(CilPrimitiveKind::Void).is_value_type());
        assert!(!CilPrimitive::new(CilPrimitiveKind::Object).is_value_type());
        assert!(!CilPrimitive::string("").is_value_type());

        assert!(CilPrimitive::new(CilPrimitiveKind::Object).is_reference_type());
        assert!(CilPrimitive::string("").is_reference_type());

        assert!(!CilPrimitive::boolean(true).is_reference_type());
        assert!(!CilPrimitive::i4(0).is_reference_type());
        assert!(!CilPrimitive::new(CilPrimitiveKind::Void).is_reference_type());
    }

    #[test]
    fn test_cil_primitive_kind_from_byte() {
        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::BOOLEAN).unwrap(),
            CilPrimitiveKind::Boolean
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::CHAR).unwrap(),
            CilPrimitiveKind::Char
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I1).unwrap(),
            CilPrimitiveKind::I1
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U1).unwrap(),
            CilPrimitiveKind::U1
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I2).unwrap(),
            CilPrimitiveKind::I2
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U2).unwrap(),
            CilPrimitiveKind::U2
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I4).unwrap(),
            CilPrimitiveKind::I4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U4).unwrap(),
            CilPrimitiveKind::U4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I8).unwrap(),
            CilPrimitiveKind::I8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U8).unwrap(),
            CilPrimitiveKind::U8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::R4).unwrap(),
            CilPrimitiveKind::R4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::R8).unwrap(),
            CilPrimitiveKind::R8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I).unwrap(),
            CilPrimitiveKind::I
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U).unwrap(),
            CilPrimitiveKind::U
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::STRING).unwrap(),
            CilPrimitiveKind::String
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::CLASS).unwrap(),
            CilPrimitiveKind::Class
        );

        let result = CilPrimitiveKind::from_byte(0xFF);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_primitive_data_conversions() {
        let default_data = CilPrimitiveData::default();
        assert!(matches!(default_data, CilPrimitiveData::None));

        let bool_data = CilPrimitiveData::Boolean(true);
        assert_eq!(bool_data.as_boolean(), Some(true));
        assert_eq!(bool_data.as_i32(), Some(1));
        assert_eq!(bool_data.as_i64(), Some(1));
        assert_eq!(bool_data.as_f64(), Some(1.0));
        assert_eq!(bool_data.as_string(), Some("true".to_string()));

        let i4_data = CilPrimitiveData::I4(42);
        assert!((i4_data.as_f64().unwrap() - 42.0).abs() < 0.00001);

        let r4_data = CilPrimitiveData::R4(42.0);
        assert_eq!(r4_data.as_i32(), Some(42));
        assert_eq!(r4_data.as_i64(), Some(42));

        let max_i32_as_i64 = CilPrimitiveData::I8(i32::MAX as i64);
        assert_eq!(max_i32_as_i64.as_i32(), Some(i32::MAX));

        let over_i32_as_i64 = CilPrimitiveData::I8((i32::MAX as i64) + 1);
        assert_eq!(over_i32_as_i64.as_i32(), None);

        let min_i32_as_i64 = CilPrimitiveData::I8(i32::MIN as i64);
        assert_eq!(min_i32_as_i64.as_i32(), Some(i32::MIN));

        let under_i32_as_i64 = CilPrimitiveData::I8(i64::from(i32::MIN) - 1);
        assert_eq!(under_i32_as_i64.as_i32(), None);

        let max_i32_as_u32 = CilPrimitiveData::U4(u32::try_from(i32::MAX).unwrap());
        assert_eq!(max_i32_as_u32.as_i32(), Some(i32::MAX));

        let over_i32_as_u32 = CilPrimitiveData::U4(u32::try_from(i32::MAX).unwrap() + 1);
        assert_eq!(over_i32_as_u32.as_i32(), None);

        let max_i64_as_u64 = CilPrimitiveData::U8(u64::try_from(i64::MAX).unwrap());
        assert_eq!(max_i64_as_u64.as_i64(), Some(i64::MAX));

        let over_i64_as_u64 = CilPrimitiveData::U8(u64::try_from(i64::MAX).unwrap() + 1);
        assert_eq!(over_i64_as_u64.as_i64(), None);

        let max_i32_as_f32 = CilPrimitiveData::R4(i32::MAX as f32);
        assert_eq!(max_i32_as_f32.as_i32(), Some(i32::MAX));

        let over_i32_as_f32 = CilPrimitiveData::R4((i32::MAX as f32) * 2.0);
        assert_eq!(over_i32_as_f32.as_i32(), None);

        let max_i64_as_f64 = CilPrimitiveData::R8(i64::MAX as f64);
        assert_eq!(max_i64_as_f64.as_i64(), Some(i64::MAX));

        let over_i64_as_f64 = CilPrimitiveData::R8((i64::MAX as f64) * 2.0);
        assert_eq!(over_i64_as_f64.as_i64(), None);
    }

    #[test]
    fn test_from_blob_error_cases() {
        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::BOOLEAN, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::CHAR, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::I4, &[1, 2]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::STRING, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CilPrimitiveData::String("".to_string()));
    }

    #[test]
    fn test_try_from_cil_flavor() {
        let flavor = CilFlavor::I4;
        let prim = CilPrimitive::try_from(flavor).unwrap();
        assert_eq!(prim.kind, CilPrimitiveKind::I4);

        let flavor = CilFlavor::Boolean;
        let prim = CilPrimitive::try_from(flavor).unwrap();
        assert_eq!(prim.kind, CilPrimitiveKind::Boolean);

        let flavor = CilFlavor::Pointer;
        let result = CilPrimitive::try_from(flavor);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let flavor = CilFlavor::Array {
            element_type: Box::new(CilFlavor::I4),
            rank: 1,
            dimensions: vec![],
        };
        let result = CilPrimitive::try_from(flavor);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_null_primitive() {
        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.kind, CilPrimitiveKind::Null);
        assert_eq!(null_prim.data, CilPrimitiveData::None);

        assert_eq!(null_prim.as_boolean(), None);
        assert_eq!(null_prim.as_i32(), None);
        assert_eq!(null_prim.as_i64(), None);
        assert_eq!(null_prim.as_f64(), None);
        assert_eq!(null_prim.as_string(), None);

        assert_eq!(null_prim.token().value(), 0xF0000016);

        assert!(!null_prim.is_value_type());
        assert!(!null_prim.is_reference_type());
    }

    #[test]
    fn test_constant_encoding_round_trip() {
        // Test boolean constants
        let bool_true = CilPrimitive::boolean(true);
        let bool_true_bytes = bool_true.to_bytes();
        let bool_true_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::BOOLEAN, &bool_true_bytes).unwrap();
        assert_eq!(bool_true_decoded, CilPrimitiveData::Boolean(true));

        let bool_false = CilPrimitive::boolean(false);
        let bool_false_bytes = bool_false.to_bytes();
        let bool_false_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::BOOLEAN, &bool_false_bytes).unwrap();
        assert_eq!(bool_false_decoded, CilPrimitiveData::Boolean(false));

        // Test char constants
        let char_a = CilPrimitive::char('A');
        let char_a_bytes = char_a.to_bytes();
        let char_a_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::CHAR, &char_a_bytes).unwrap();
        assert_eq!(char_a_decoded, CilPrimitiveData::Char('A' as u16));

        let char_unicode = CilPrimitive::char('ñ'); // Unicode character within BMP
        let char_unicode_bytes = char_unicode.to_bytes();
        let char_unicode_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::CHAR, &char_unicode_bytes).unwrap();
        assert_eq!(char_unicode_decoded, CilPrimitiveData::Char('ñ' as u16));

        // Test integer constants
        let i1_test = CilPrimitive::i1(-128);
        let i1_test_bytes = i1_test.to_bytes();
        let i1_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::I1, &i1_test_bytes).unwrap();
        assert_eq!(i1_test_decoded, CilPrimitiveData::I1(-128));

        let u1_test = CilPrimitive::u1(255);
        let u1_test_bytes = u1_test.to_bytes();
        let u1_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::U1, &u1_test_bytes).unwrap();
        assert_eq!(u1_test_decoded, CilPrimitiveData::U1(255));

        let i2_test = CilPrimitive::i2(-32768);
        let i2_test_bytes = i2_test.to_bytes();
        let i2_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::I2, &i2_test_bytes).unwrap();
        assert_eq!(i2_test_decoded, CilPrimitiveData::I2(-32768));

        let u2_test = CilPrimitive::u2(65535);
        let u2_test_bytes = u2_test.to_bytes();
        let u2_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::U2, &u2_test_bytes).unwrap();
        assert_eq!(u2_test_decoded, CilPrimitiveData::U2(65535));

        let i4_test = CilPrimitive::i4(-2147483648);
        let i4_test_bytes = i4_test.to_bytes();
        let i4_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::I4, &i4_test_bytes).unwrap();
        assert_eq!(i4_test_decoded, CilPrimitiveData::I4(-2147483648));

        let u4_test = CilPrimitive::u4(4294967295);
        let u4_test_bytes = u4_test.to_bytes();
        let u4_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::U4, &u4_test_bytes).unwrap();
        assert_eq!(u4_test_decoded, CilPrimitiveData::U4(4294967295));

        let i8_test = CilPrimitive::i8(-9223372036854775808);
        let i8_test_bytes = i8_test.to_bytes();
        let i8_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::I8, &i8_test_bytes).unwrap();
        assert_eq!(i8_test_decoded, CilPrimitiveData::I8(-9223372036854775808));

        let u8_test = CilPrimitive::u8(18446744073709551615);
        let u8_test_bytes = u8_test.to_bytes();
        let u8_test_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::U8, &u8_test_bytes).unwrap();
        assert_eq!(u8_test_decoded, CilPrimitiveData::U8(18446744073709551615));

        // Test string constants
        let string_empty = CilPrimitive::string("");
        let string_empty_bytes = string_empty.to_bytes();
        let string_empty_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::STRING, &string_empty_bytes).unwrap();
        assert_eq!(
            string_empty_decoded,
            CilPrimitiveData::String("".to_string())
        );

        let string_hello = CilPrimitive::string("Hello, World!");
        let string_hello_bytes = string_hello.to_bytes();
        let string_hello_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::STRING, &string_hello_bytes).unwrap();
        assert_eq!(
            string_hello_decoded,
            CilPrimitiveData::String("Hello, World!".to_string())
        );

        let string_unicode = CilPrimitive::string("Çå UTF-16 Tëst ñ");
        let string_unicode_bytes = string_unicode.to_bytes();
        let string_unicode_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::STRING, &string_unicode_bytes).unwrap();
        assert_eq!(
            string_unicode_decoded,
            CilPrimitiveData::String("Çå UTF-16 Tëst ñ".to_string())
        );

        // Test null reference constants
        let null_ref_bytes = vec![0, 0, 0, 0]; // 4-byte zero value for null references
        let null_ref_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::CLASS, &null_ref_bytes).unwrap();
        assert_eq!(null_ref_decoded, CilPrimitiveData::None);
    }

    #[test]
    fn test_floating_point_precision_round_trip() {
        // Test R4 (32-bit float) precision
        let r4_pi = CilPrimitive::r4(std::f32::consts::PI);
        let r4_pi_bytes = r4_pi.to_bytes();
        let r4_pi_decoded = CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_pi_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_pi_decoded {
            assert_eq!(decoded_value, std::f32::consts::PI);
        } else {
            panic!("Expected R4 data");
        }

        let r4_small = CilPrimitive::r4(1.23456e-30_f32);
        let r4_small_bytes = r4_small.to_bytes();
        let r4_small_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_small_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_small_decoded {
            assert_eq!(decoded_value, 1.23456e-30_f32);
        } else {
            panic!("Expected R4 data");
        }

        // Test R8 (64-bit double) precision
        let r8_e = CilPrimitive::r8(std::f64::consts::E);
        let r8_e_bytes = r8_e.to_bytes();
        let r8_e_decoded = CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_e_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_e_decoded {
            assert_eq!(decoded_value, std::f64::consts::E);
        } else {
            panic!("Expected R8 data");
        }

        let r8_precise = CilPrimitive::r8(1.23456789012345e-100_f64);
        let r8_precise_bytes = r8_precise.to_bytes();
        let r8_precise_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_precise_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_precise_decoded {
            assert_eq!(decoded_value, 1.23456789012345e-100_f64);
        } else {
            panic!("Expected R8 data");
        }
    }

    #[test]
    fn test_floating_point_edge_cases() {
        // Test NaN (Not a Number)
        let r4_nan = CilPrimitive::r4(f32::NAN);
        let r4_nan_bytes = r4_nan.to_bytes();
        let r4_nan_decoded = CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_nan_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_nan_decoded {
            assert!(decoded_value.is_nan());
        } else {
            panic!("Expected R4 data");
        }

        let r8_nan = CilPrimitive::r8(f64::NAN);
        let r8_nan_bytes = r8_nan.to_bytes();
        let r8_nan_decoded = CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_nan_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_nan_decoded {
            assert!(decoded_value.is_nan());
        } else {
            panic!("Expected R8 data");
        }

        // Test Positive and Negative Infinity
        let r4_inf_pos = CilPrimitive::r4(f32::INFINITY);
        let r4_inf_pos_bytes = r4_inf_pos.to_bytes();
        let r4_inf_pos_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_inf_pos_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_inf_pos_decoded {
            assert_eq!(decoded_value, f32::INFINITY);
        } else {
            panic!("Expected R4 data");
        }

        let r4_inf_neg = CilPrimitive::r4(f32::NEG_INFINITY);
        let r4_inf_neg_bytes = r4_inf_neg.to_bytes();
        let r4_inf_neg_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_inf_neg_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_inf_neg_decoded {
            assert_eq!(decoded_value, f32::NEG_INFINITY);
        } else {
            panic!("Expected R4 data");
        }

        let r8_inf_pos = CilPrimitive::r8(f64::INFINITY);
        let r8_inf_pos_bytes = r8_inf_pos.to_bytes();
        let r8_inf_pos_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_inf_pos_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_inf_pos_decoded {
            assert_eq!(decoded_value, f64::INFINITY);
        } else {
            panic!("Expected R8 data");
        }

        let r8_inf_neg = CilPrimitive::r8(f64::NEG_INFINITY);
        let r8_inf_neg_bytes = r8_inf_neg.to_bytes();
        let r8_inf_neg_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_inf_neg_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_inf_neg_decoded {
            assert_eq!(decoded_value, f64::NEG_INFINITY);
        } else {
            panic!("Expected R8 data");
        }

        // Test very small denormalized numbers
        let r4_denorm = CilPrimitive::r4(f32::MIN_POSITIVE);
        let r4_denorm_bytes = r4_denorm.to_bytes();
        let r4_denorm_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_denorm_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_denorm_decoded {
            assert_eq!(decoded_value, f32::MIN_POSITIVE);
        } else {
            panic!("Expected R4 data");
        }

        let r8_denorm = CilPrimitive::r8(f64::MIN_POSITIVE);
        let r8_denorm_bytes = r8_denorm.to_bytes();
        let r8_denorm_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R8, &r8_denorm_bytes).unwrap();
        if let CilPrimitiveData::R8(decoded_value) = r8_denorm_decoded {
            assert_eq!(decoded_value, f64::MIN_POSITIVE);
        } else {
            panic!("Expected R8 data");
        }

        // Test positive and negative zero
        let r4_zero = CilPrimitive::r4(0.0f32);
        let r4_zero_bytes = r4_zero.to_bytes();
        let r4_zero_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_zero_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_zero_decoded {
            assert_eq!(decoded_value, 0.0f32);
        } else {
            panic!("Expected R4 data");
        }

        let r4_neg_zero = CilPrimitive::r4(-0.0f32);
        let r4_neg_zero_bytes = r4_neg_zero.to_bytes();
        let r4_neg_zero_decoded =
            CilPrimitiveData::from_bytes(ELEMENT_TYPE::R4, &r4_neg_zero_bytes).unwrap();
        if let CilPrimitiveData::R4(decoded_value) = r4_neg_zero_decoded {
            assert_eq!(decoded_value, -0.0f32);
        } else {
            panic!("Expected R4 data");
        }
    }

    #[test]
    fn test_cil_primitive_kind_stable_strings() {
        // The strings here are part of the stable public API. They follow
        // ILAsm / ECMA-335 §I.8.2.2 conventions. Changing them is a breaking
        // change for downstream consumers that persist these values.
        let cases = [
            (CilPrimitiveKind::Void, "void"),
            (CilPrimitiveKind::Boolean, "bool"),
            (CilPrimitiveKind::Char, "char"),
            (CilPrimitiveKind::I1, "int8"),
            (CilPrimitiveKind::U1, "uint8"),
            (CilPrimitiveKind::I2, "int16"),
            (CilPrimitiveKind::U2, "uint16"),
            (CilPrimitiveKind::I4, "int32"),
            (CilPrimitiveKind::U4, "uint32"),
            (CilPrimitiveKind::I8, "int64"),
            (CilPrimitiveKind::U8, "uint64"),
            (CilPrimitiveKind::R4, "float32"),
            (CilPrimitiveKind::R8, "float64"),
            (CilPrimitiveKind::I, "native int"),
            (CilPrimitiveKind::U, "native uint"),
            (CilPrimitiveKind::Object, "object"),
            (CilPrimitiveKind::String, "string"),
            (CilPrimitiveKind::Null, "null"),
            (CilPrimitiveKind::TypedReference, "typedref"),
            (CilPrimitiveKind::ValueType, "valuetype"),
            (CilPrimitiveKind::Var, "var"),
            (CilPrimitiveKind::MVar, "mvar"),
            (CilPrimitiveKind::Class, "class"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_str(), expected);
            assert_eq!(format!("{variant}"), expected);
        }
    }
}

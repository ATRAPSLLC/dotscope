//! Resource type definitions and parsing for .NET resource files.
//!
//! This module provides comprehensive support for parsing and representing the various data types
//! that can be stored in .NET resource files (.resources). It implements the complete type system
//! defined by the .NET resource format specification, including primitive types, special types,
//! and user-defined types.
//!
//! # .NET Resource Type System
//!
//! The .NET resource format supports a hierarchical type system:
//! - **Primitive Types (0x00-0x1F)**: Built-in .NET value types like integers, strings, booleans
//! - **Special Types (0x20-0x3F)**: Complex types with special serialization like byte arrays
//! - **User Types (0x40+)**: Custom types serialized using the binary formatter
//!
//! # Magic Number
//!
//! All .NET resource files begin with the magic number `0xBEEFCACE` to identify the format.
//!
//! # Examples
//!
//! ## Basic Type Parsing
//!
//! ```no_run
//! use dotscope::metadata::resources::ResourceType;
//! use dotscope::metadata::resources::RESOURCE_MAGIC;
//! use dotscope::Parser;
//!
//! // Parse a resource file header
//! let mut parser = Parser::new(&data);
//! let magic = parser.read_le::<u32>()?;
//! assert_eq!(magic, RESOURCE_MAGIC);
//!
//! // Parse a type from type byte
//! let type_byte = parser.read_le::<u8>()?;
//! let resource_type = ResourceType::from_type_byte(type_byte, &mut parser)?;
//!
//! match resource_type {
//!     ResourceType::String(s) => println!("Found string: {}", s),
//!     ResourceType::Int32(i) => println!("Found integer: {}", i),
//!     ResourceType::ByteArray(bytes) => println!("Found byte array: {} bytes", bytes.len()),
//!     _ => println!("Found other type"),
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Type Name Resolution
//!
//! ```no_run
//! use dotscope::metadata::resources::ResourceType;
//! use dotscope::Parser;
//!
//! let mut parser = Parser::new(&data);
//!
//! // Parse using type name instead of type byte
//! let resource_type = ResourceType::from_type_name("System.String", &mut parser)?;
//! if let ResourceType::String(s) = resource_type {
//!     println!("Parsed string from type name: {}", s);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe:
//! - [`ResourceType`] implements `Send + Sync` for safe sharing across threads
//! - Parsing operations are stateless and can be performed concurrently
//! - No global state is maintained during parsing operations

/// The magic number that identifies a .NET resource file (0xBEEFCACE)
pub const RESOURCE_MAGIC: u32 = 0xBEEF_CACE;

use crate::{file::parser::Parser, Error::TypeError, Result};

/// Represents all data types that can be stored in .NET resource files.
///
/// This enum provides a complete representation of the type system used in .NET resource files,
/// including all primitive types, special collection types, and extensibility for user-defined types.
/// Each variant corresponds to specific type codes defined in the .NET resource format specification.
///
/// # Type Code Ranges
///
/// - **0x00-0x1F**: Primitive and built-in types (null, strings, numbers, dates)
/// - **0x20-0x3F**: Special types with custom serialization (byte arrays, streams)
/// - **0x40+**: User-defined types serialized with the binary formatter
///
/// # Examples
///
/// ```no_run
/// use dotscope::metadata::resources::ResourceType;
/// use dotscope::Parser;
///
/// // Parse different resource types
/// let mut parser = Parser::new(&data);
///
/// // Parse a string resource (type code 0x01)
/// let string_resource = ResourceType::from_type_byte(0x01, &mut parser)?;
/// if let ResourceType::String(s) = string_resource {
///     println!("String resource: {}", s);
/// }
///
/// // Parse an integer resource (type code 0x08)
/// let int_resource = ResourceType::from_type_byte(0x08, &mut parser)?;
/// if let ResourceType::Int32(i) = int_resource {
///     println!("Integer resource: {}", i);
/// }
///
/// // Parse a byte array resource (type code 0x20)
/// let bytes_resource = ResourceType::from_type_byte(0x20, &mut parser)?;
/// if let ResourceType::ByteArray(bytes) = bytes_resource {
///     println!("Byte array: {} bytes", bytes.len());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// All variants are thread-safe and can be safely shared across threads without synchronization.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceType {
    /// Null resource value (type code 0x00)
    Null,
    /// UTF-8 string resource with length prefix (type code 0x01)
    String(String),
    /// Boolean resource value, false=0, true=non-zero (type code 0x02)
    Boolean(bool),
    /// Single character resource stored as UTF-16 code unit (type code 0x03)
    Char(char),
    /// Unsigned 8-bit integer resource (type code 0x04)
    Byte(u8),
    /// Signed 8-bit integer resource (type code 0x05)
    SByte(i8),
    /// Signed 16-bit integer resource, little-endian (type code 0x06)
    Int16(i16),
    /// Unsigned 16-bit integer resource, little-endian (type code 0x07)
    UInt16(u16),
    /// Signed 32-bit integer resource, little-endian (type code 0x08)
    Int32(i32),
    /// Unsigned 32-bit integer resource, little-endian (type code 0x09)
    UInt32(u32),
    /// Signed 64-bit integer resource, little-endian (type code 0x0A)
    Int64(i64),
    /// Unsigned 64-bit integer resource, little-endian (type code 0x0B)
    UInt64(u64),
    /// 32-bit floating point resource, little-endian (type code 0x0C)
    Single(f32),
    /// 64-bit floating point resource, little-endian (type code 0x0D)
    Double(f64),
    /// .NET Decimal resource value stored as raw bits (type code 0x0E)
    ///
    /// Represents a 128-bit decimal number using the same binary format as .NET's
    /// `System.Decimal`. The four 32-bit integers represent:
    /// - `lo`: Low 32 bits of the 96-bit mantissa
    /// - `mid`: Middle 32 bits of the 96-bit mantissa
    /// - `hi`: High 32 bits of the 96-bit mantissa
    /// - `flags`: Sign (bit 31) and scale (bits 16-23, valid range 0-28)
    ///
    /// # Binary Format
    ///
    /// The decimal is stored as 16 bytes (4 consecutive little-endian i32 values):
    /// ```text
    /// Bytes 0-3:   lo    (low 32 bits of mantissa)
    /// Bytes 4-7:   mid   (middle 32 bits of mantissa)
    /// Bytes 8-11:  hi    (high 32 bits of mantissa)
    /// Bytes 12-15: flags (sign in bit 31, scale in bits 16-23)
    /// ```
    ///
    /// # Example
    ///
    /// The value `3.261` would be represented as mantissa `3261` with scale `3`.
    Decimal {
        /// Low 32 bits of the 96-bit mantissa
        lo: i32,
        /// Middle 32 bits of the 96-bit mantissa
        mid: i32,
        /// High 32 bits of the 96-bit mantissa
        hi: i32,
        /// Flags containing sign (bit 31) and scale (bits 16-23)
        flags: i32,
    },
    /// .NET DateTime resource value stored as binary ticks (type code 0x0F)
    ///
    /// Represents a point in time using the same binary format as .NET's
    /// `System.DateTime.ToBinary()`. The 64-bit value encodes both the ticks
    /// (100-nanosecond intervals since 12:00 midnight, January 1, 0001 CE)
    /// and the `DateTimeKind` (UTC, Local, or Unspecified).
    ///
    /// # Binary Format
    ///
    /// The value is stored as a single little-endian i64:
    /// - Bits 0-61: Ticks (number of 100-nanosecond intervals)
    /// - Bits 62-63: DateTimeKind (0=Unspecified, 1=UTC, 2=Local)
    ///
    /// # Conversion
    ///
    /// To extract the components:
    /// ```text
    /// ticks = binary_value & 0x3FFFFFFFFFFFFFFF
    /// kind  = (binary_value >> 62) & 0x3
    /// ```
    ///
    /// To reconstruct a .NET DateTime, use `DateTime.FromBinary(binary_value)`.
    DateTime(i64),
    /// .NET TimeSpan resource value stored as ticks (type code 0x10)
    ///
    /// Represents a time interval using the same format as .NET's
    /// `System.TimeSpan.Ticks`. The 64-bit signed value represents the number
    /// of 100-nanosecond intervals in the time span.
    ///
    /// # Binary Format
    ///
    /// The value is stored as a single little-endian i64 representing ticks.
    /// Negative values represent negative time spans.
    ///
    /// # Conversion Examples
    ///
    /// Common conversions:
    /// ```text
    /// 1 tick         = 100 nanoseconds
    /// 10,000 ticks   = 1 millisecond
    /// 10,000,000 ticks = 1 second
    /// 600,000,000 ticks = 1 minute
    /// 36,000,000,000 ticks = 1 hour
    /// ```
    ///
    /// To convert to seconds: `seconds = ticks / 10_000_000`
    TimeSpan(i64),
    /// Byte array resource with length prefix (type code 0x20)
    ByteArray(Vec<u8>),
    /// Stream resource with length prefix (type code 0x21)
    Stream(Vec<u8>),
    /// Marker for the beginning of user-defined types (type code 0x40+)
    StartOfUserTypes,
}

impl ResourceType {
    /// Returns the .NET type name for this resource type.
    ///
    /// Provides the canonical .NET Framework type name that corresponds to this
    /// resource type. This is used for .NET resource file format encoding and
    /// type resolution during resource serialization.
    ///
    /// # Returns
    ///
    /// Returns the .NET type name as a string slice, or `None` for types that
    /// don't have a corresponding .NET type name (like `Null` or unimplemented types).
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::ResourceType;
    ///
    /// let string_type = ResourceType::String("hello".to_string());
    /// assert_eq!(string_type.as_str(), Some("System.String"));
    ///
    /// let int_type = ResourceType::Int32(42);
    /// assert_eq!(int_type.as_str(), Some("System.Int32"));
    ///
    /// let null_type = ResourceType::Null;
    /// assert_eq!(null_type.as_str(), None);
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            ResourceType::String(_) => Some("System.String"),
            ResourceType::Boolean(_) => Some("System.Boolean"),
            ResourceType::Char(_) => Some("System.Char"),
            ResourceType::Byte(_) => Some("System.Byte"),
            ResourceType::SByte(_) => Some("System.SByte"),
            ResourceType::Int16(_) => Some("System.Int16"),
            ResourceType::UInt16(_) => Some("System.UInt16"),
            ResourceType::Int32(_) => Some("System.Int32"),
            ResourceType::UInt32(_) => Some("System.UInt32"),
            ResourceType::Int64(_) => Some("System.Int64"),
            ResourceType::UInt64(_) => Some("System.UInt64"),
            ResourceType::Single(_) => Some("System.Single"),
            ResourceType::Double(_) => Some("System.Double"),
            ResourceType::Decimal { .. } => Some("System.Decimal"),
            ResourceType::DateTime(_) => Some("System.DateTime"),
            ResourceType::TimeSpan(_) => Some("System.TimeSpan"),
            ResourceType::ByteArray(_) => Some("System.Byte[]"),
            ResourceType::Stream(_) => Some("System.IO.Stream"),
            // Types without .NET equivalents
            ResourceType::Null | ResourceType::StartOfUserTypes => None,
        }
    }

    /// Returns the hard-coded type index for this resource type.
    ///
    /// Provides the index that this resource type should have in .NET resource file
    /// type tables. This method returns constant indices that match the standard
    /// .NET resource file type ordering, providing O(1) constant-time access without
    /// needing HashMap lookups.
    ///
    /// The indices correspond to the standard ordering used in .NET resource files:
    /// - Boolean: 0
    /// - Byte: 1  
    /// - SByte: 2
    /// - Char: 3
    /// - Int16: 4
    /// - UInt16: 5
    /// - Int32: 6
    /// - UInt32: 7
    /// - Int64: 8
    /// - UInt64: 9
    /// - Single: 10
    /// - Double: 11
    /// - String: 12
    /// - ByteArray: 13
    ///
    /// # Returns
    ///
    /// Returns the type index as a `u32`, or `None` for types that don't have
    /// a corresponding index in the standard .NET resource type table.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::ResourceType;
    ///
    /// let string_type = ResourceType::String("hello".to_string());
    /// assert_eq!(string_type.index(), Some(12));
    ///
    /// let int_type = ResourceType::Int32(42);
    /// assert_eq!(int_type.index(), Some(6));
    ///
    /// let null_type = ResourceType::Null;
    /// assert_eq!(null_type.index(), None);
    /// ```
    #[must_use]
    pub fn index(&self) -> Option<u32> {
        match self {
            ResourceType::Boolean(_) => Some(0),
            ResourceType::Byte(_) => Some(1),
            ResourceType::SByte(_) => Some(2),
            ResourceType::Char(_) => Some(3),
            ResourceType::Int16(_) => Some(4),
            ResourceType::UInt16(_) => Some(5),
            ResourceType::Int32(_) => Some(6),
            ResourceType::UInt32(_) => Some(7),
            ResourceType::Int64(_) => Some(8),
            ResourceType::UInt64(_) => Some(9),
            ResourceType::Single(_) => Some(10),
            ResourceType::Double(_) => Some(11),
            ResourceType::String(_) => Some(12),
            ResourceType::Decimal { .. } => Some(13),
            ResourceType::DateTime(_) => Some(14),
            ResourceType::TimeSpan(_) => Some(15),
            ResourceType::ByteArray(_) => Some(16),
            ResourceType::Stream(_) => Some(17),
            // Types without .NET equivalents
            ResourceType::Null | ResourceType::StartOfUserTypes => None,
        }
    }

    /// Returns the official .NET type code for this resource type for encoding.
    ///
    /// This method returns the official .NET type code that should be used when encoding
    /// this resource type in .NET resource format files. These codes match the official
    /// ResourceTypeCode enumeration from the .NET runtime.
    ///
    /// # Returns
    ///
    /// - `Some(type_code)` for supported .NET resource types
    /// - `None` for types that don't have direct .NET equivalents or are not yet implemented
    ///
    /// # Official .NET Type Code Mapping
    ///
    /// The returned codes map to the official .NET ResourceTypeCode enumeration:
    /// - 0x01: String
    /// - 0x02: Boolean
    /// - 0x03: Char
    /// - 0x04: Byte  
    /// - 0x05: SByte
    /// - 0x06: Int16
    /// - 0x07: UInt16
    /// - 0x08: Int32
    /// - 0x09: UInt32
    /// - 0x0A: Int64
    /// - 0x0B: UInt64
    /// - 0x0C: Single
    /// - 0x0D: Double
    /// - 0x0E: Decimal
    /// - 0x0F: DateTime
    /// - 0x10: TimeSpan
    /// - 0x20: ByteArray
    /// - 0x21: Stream
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::ResourceType;
    ///
    /// let string_type = ResourceType::String("Hello".to_string());
    /// assert_eq!(string_type.type_code(), Some(0x01));
    ///
    /// let int_type = ResourceType::Int32(42);
    /// assert_eq!(int_type.type_code(), Some(0x08));
    ///
    /// let null_type = ResourceType::Null;
    /// assert_eq!(null_type.type_code(), None); // No .NET equivalent
    /// ```
    #[must_use]
    pub fn type_code(&self) -> Option<u32> {
        match self {
            ResourceType::String(_) => Some(0x01),
            ResourceType::Boolean(_) => Some(0x02),
            ResourceType::Char(_) => Some(0x03),
            ResourceType::Byte(_) => Some(0x04),
            ResourceType::SByte(_) => Some(0x05),
            ResourceType::Int16(_) => Some(0x06),
            ResourceType::UInt16(_) => Some(0x07),
            ResourceType::Int32(_) => Some(0x08),
            ResourceType::UInt32(_) => Some(0x09),
            ResourceType::Int64(_) => Some(0x0A),
            ResourceType::UInt64(_) => Some(0x0B),
            ResourceType::Single(_) => Some(0x0C),
            ResourceType::Double(_) => Some(0x0D),
            ResourceType::Decimal { .. } => Some(0x0E),
            ResourceType::DateTime(_) => Some(0x0F),
            ResourceType::TimeSpan(_) => Some(0x10),
            ResourceType::ByteArray(_) => Some(0x20),
            ResourceType::Stream(_) => Some(0x21),
            // Types without .NET equivalents
            ResourceType::Null | ResourceType::StartOfUserTypes => None,
        }
    }

    /// Returns the size in bytes that this resource's data will occupy when encoded.
    ///
    /// Calculates the exact number of bytes this resource will take when written
    /// in .NET resource file format, including length prefixes for variable-length
    /// data but excluding the type index.
    ///
    /// # Returns
    ///
    /// Returns the data size in bytes, or `None` for types that are not yet
    /// implemented or cannot be encoded.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::ResourceType;
    ///
    /// let string_type = ResourceType::String("hello".to_string());
    /// assert_eq!(string_type.data_size(), Some(6)); // 1 byte length + 5 bytes UTF-8
    ///
    /// let int_type = ResourceType::Int32(42);
    /// assert_eq!(int_type.data_size(), Some(4)); // 4 bytes for i32
    ///
    /// let bool_type = ResourceType::Boolean(true);
    /// assert_eq!(bool_type.data_size(), Some(1)); // 1 byte for boolean
    ///
    /// let bytes_type = ResourceType::ByteArray(vec![1, 2, 3]);
    /// assert_eq!(bytes_type.data_size(), Some(7)); // 4 bytes LE length + 3 bytes data
    /// ```
    #[must_use]
    pub fn data_size(&self) -> Option<u32> {
        match self {
            ResourceType::String(s) => {
                // UTF-8 byte length (7-bit encoded: 7 bits a byte) + UTF-8 bytes
                let utf8_size = u32::try_from(s.len()).ok()?;
                let bits = u32::BITS.saturating_sub(utf8_size.leading_zeros());
                let prefix_size = bits.div_ceil(7).max(1);
                prefix_size.checked_add(utf8_size)
            }
            ResourceType::Boolean(_) | ResourceType::Byte(_) | ResourceType::SByte(_) => Some(1), // Single byte
            ResourceType::Char(_) | ResourceType::Int16(_) | ResourceType::UInt16(_) => Some(2), // 2 bytes
            ResourceType::Int32(_) | ResourceType::UInt32(_) | ResourceType::Single(_) => Some(4), // 4 bytes
            ResourceType::Int64(_)
            | ResourceType::UInt64(_)
            | ResourceType::Double(_)
            | ResourceType::DateTime(_)  // i64 binary ticks
            | ResourceType::TimeSpan(_)  // i64 ticks
            => Some(8), // 8 bytes
            ResourceType::Decimal { .. } => Some(16), // 4 × i32 = 16 bytes
            ResourceType::ByteArray(data) | ResourceType::Stream(data) => {
                // Length (4-byte LE integer) + data bytes
                // Per .NET specification: ByteArray and Stream use fixed 4-byte LE length
                // Note: Type code is NOT included here - encoder adds type_code_size separately
                let data_size = u32::try_from(data.len()).ok()?;
                4_u32.checked_add(data_size)
            }
            // Types without .NET equivalents
            ResourceType::Null | ResourceType::StartOfUserTypes => None,
        }
    }

    /// Parses a resource type from its binary type code.
    ///
    /// This method reads a resource value from the parser based on the provided type byte,
    /// which corresponds to the type codes defined in the .NET resource format specification.
    /// Each type code indicates both the data type and how to parse the following bytes.
    ///
    /// # Arguments
    ///
    /// * `byte` - The type code byte (0x00-0xFF) that identifies the data type
    /// * `parser` - A mutable reference to the parser positioned after the type byte
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceType>`] containing the parsed resource value,
    /// or an error if the type code is unsupported or parsing fails.
    ///
    /// # Supported Type Codes
    ///
    /// - `0x01`: UTF-8 string with length prefix
    /// - `0x02`: Boolean value (0 = false, non-zero = true)
    /// - `0x03`: Single character as byte
    /// - `0x04`: Unsigned 8-bit integer
    /// - `0x05`: Signed 8-bit integer
    /// - `0x06`: Signed 16-bit integer (little-endian)
    /// - `0x07`: Unsigned 16-bit integer (little-endian)
    /// - `0x08`: Signed 32-bit integer (little-endian)
    /// - `0x09`: Unsigned 32-bit integer (little-endian)
    /// - `0x0A`: Signed 64-bit integer (little-endian)
    /// - `0x0B`: Unsigned 64-bit integer (little-endian)
    /// - `0x0C`: 32-bit floating point (little-endian)
    /// - `0x0D`: 64-bit floating point (little-endian)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::ResourceType;
    /// use dotscope::Parser;
    ///
    /// let mut parser = Parser::new(&data);
    ///
    /// // Parse a string resource (type code 0x01)
    /// let string_type = ResourceType::from_type_byte(0x01, &mut parser)?;
    /// if let ResourceType::String(s) = string_type {
    ///     println!("Found string: {}", s);
    /// }
    ///
    /// // Parse an integer resource (type code 0x08)
    /// let int_type = ResourceType::from_type_byte(0x08, &mut parser)?;
    /// if let ResourceType::Int32(value) = int_type {
    ///     println!("Found integer: {}", value);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type byte is not supported
    /// - Parser errors: If reading the underlying data fails (e.g., truncated data)
    pub fn from_type_byte(byte: u8, parser: &mut Parser) -> Result<Self> {
        match byte {
            0x0 => {
                // ResourceTypeCode.Null - no data to read
                Ok(ResourceType::Null)
            }
            0x1 => {
                // .NET string resources use UTF-8 encoding with 7-bit encoded byte length prefix
                // (Resource names use UTF-16, but string DATA values use UTF-8)
                Ok(ResourceType::String(parser.read_prefixed_string_utf8()?))
            }
            0x2 => Ok(ResourceType::Boolean(parser.read_le::<u8>()? > 0)),
            0x3 => {
                // ResourceTypeCode.Char - 2 bytes (UInt16)
                // .NET writes chars as UInt16 (UTF-16 code unit), not as single byte
                // See: ResourceWriter.WriteValue writes `(UInt16)(char)value`
                //      ResourceReader._LoadObjectV2 reads `(char)_store.ReadUInt16()`
                let code_unit = parser.read_le::<u16>()?;
                Ok(ResourceType::Char(
                    char::from_u32(u32::from(code_unit)).ok_or_else(|| {
                        TypeError("Invalid UTF-16 code unit for Char".to_string())
                    })?,
                ))
            }
            0x4 => Ok(ResourceType::Byte(parser.read_le::<u8>()?)),
            0x5 => Ok(ResourceType::SByte(parser.read_le::<i8>()?)),
            0x6 => Ok(ResourceType::Int16(parser.read_le::<i16>()?)),
            0x7 => Ok(ResourceType::UInt16(parser.read_le::<u16>()?)),
            0x8 => Ok(ResourceType::Int32(parser.read_le::<i32>()?)),
            0x9 => Ok(ResourceType::UInt32(parser.read_le::<u32>()?)),
            0xA => Ok(ResourceType::Int64(parser.read_le::<i64>()?)),
            0xB => Ok(ResourceType::UInt64(parser.read_le::<u64>()?)),
            0xC => Ok(ResourceType::Single(parser.read_le::<f32>()?)),
            0xD => Ok(ResourceType::Double(parser.read_le::<f64>()?)),
            0xE => {
                // ResourceTypeCode.Decimal - 16 bytes (4 × i32)
                // Format: lo, mid, hi, flags (all little-endian i32)
                let lo = parser.read_le::<i32>()?;
                let mid = parser.read_le::<i32>()?;
                let hi = parser.read_le::<i32>()?;
                let flags = parser.read_le::<i32>()?;
                Ok(ResourceType::Decimal { lo, mid, hi, flags })
            }
            0xF => {
                // ResourceTypeCode.DateTime - 8 bytes (i64 binary format)
                // Contains ticks (bits 0-61) and DateTimeKind (bits 62-63)
                let binary_value = parser.read_le::<i64>()?;
                Ok(ResourceType::DateTime(binary_value))
            }
            0x10 => {
                // ResourceTypeCode.TimeSpan - 8 bytes (i64 ticks)
                // Ticks represent 100-nanosecond intervals
                let ticks = parser.read_le::<i64>()?;
                Ok(ResourceType::TimeSpan(ticks))
            }
            0x20 => {
                let length = parser.read_le::<u32>()?;
                let start_pos = parser.pos();
                let end_pos = start_pos.checked_add(length as usize).ok_or_else(|| {
                    malformed_error!(
                        "ByteArray resource end offset overflow: start={} length={}",
                        start_pos,
                        length
                    )
                })?;

                let data = parser
                    .data()
                    .get(start_pos..end_pos)
                    .ok_or(out_of_bounds_error!())?
                    .to_vec();
                if end_pos < parser.data().len() {
                    parser.seek(end_pos)?;
                }
                Ok(ResourceType::ByteArray(data))
            }
            0x21 => {
                let length = parser.read_le::<u32>()?;
                let start_pos = parser.pos();
                let end_pos = start_pos.checked_add(length as usize).ok_or_else(|| {
                    malformed_error!(
                        "Stream resource end offset overflow: start={} length={}",
                        start_pos,
                        length
                    )
                })?;

                let data = parser
                    .data()
                    .get(start_pos..end_pos)
                    .ok_or(out_of_bounds_error!())?
                    .to_vec();
                if end_pos < parser.data().len() {
                    parser.seek(end_pos)?;
                }
                // Stream uses same format as ByteArray, just different type code
                Ok(ResourceType::Stream(data))
            }
            0x40..=0xFF => {
                // User types - these require a type table for resolution
                // According to .NET ResourceReader, if we have user types but no type table,
                // this is a BadImageFormat error
                Err(TypeError(format!(
                    "TypeByte - {byte:X} is a user type (>=0x40) but requires type table resolution which is not yet implemented"
                )))
            }
            _ => Err(TypeError(format!(
                "TypeByte - {byte:X} is currently not supported"
            ))),
        }
    }

    /// Parses a resource type from its .NET type name.
    ///
    /// This method provides an alternative parsing mechanism that uses .NET type names instead
    /// of type bytes. It maps common .NET Framework type names to their corresponding binary
    /// representations and delegates to [`Self::from_type_byte`] for the actual parsing.
    ///
    /// This approach is commonly used in resource files that store type information as strings
    /// rather than numeric type codes, particularly in older .NET resource formats.
    ///
    /// # Arguments
    ///
    /// * `type_name` - The fully qualified .NET type name (e.g., "System.String")
    /// * `parser` - A mutable reference to the parser positioned at the resource value
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceType>`] containing the parsed resource value,
    /// or an error if the type name is unsupported or parsing fails.
    ///
    /// # Supported Type Names
    ///
    /// - `"System.Null"`: Null value
    /// - `"System.String"`: UTF-8 string with length prefix
    /// - `"System.Boolean"`: Boolean value
    /// - `"System.Char"`: Single character
    /// - `"System.Byte"`: Unsigned 8-bit integer
    /// - `"System.SByte"`: Signed 8-bit integer
    /// - `"System.Int16"`: Signed 16-bit integer
    /// - `"System.UInt16"`: Unsigned 16-bit integer
    /// - `"System.Int32"`: Signed 32-bit integer
    /// - `"System.UInt32"`: Unsigned 32-bit integer
    /// - `"System.Int64"`: Signed 64-bit integer
    /// - `"System.UInt64"`: Unsigned 64-bit integer
    /// - `"System.Single"`: 32-bit floating point
    /// - `"System.Double"`: 64-bit floating point
    /// - `"System.Byte[]"`: Byte array
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::ResourceType;
    /// use dotscope::Parser;
    ///
    /// let mut parser = Parser::new(&data);
    ///
    /// // Parse using .NET type names
    /// let string_resource = ResourceType::from_type_name("System.String", &mut parser)?;
    /// if let ResourceType::String(s) = string_resource {
    ///     println!("String resource: {}", s);
    /// }
    ///
    /// let int_resource = ResourceType::from_type_name("System.Int32", &mut parser)?;
    /// if let ResourceType::Int32(value) = int_resource {
    ///     println!("Integer resource: {}", value);
    /// }
    ///
    /// let bytes_resource = ResourceType::from_type_name("System.Byte[]", &mut parser)?;
    /// if let ResourceType::ByteArray(bytes) = bytes_resource {
    ///     println!("Byte array: {} bytes", bytes.len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type name is not supported
    /// - Parser errors: If reading the underlying data fails
    pub fn from_type_name(type_name: &str, parser: &mut Parser) -> Result<Self> {
        match type_name {
            "System.Null" => ResourceType::from_type_byte(0x0, parser),
            "System.String" => ResourceType::from_type_byte(0x1, parser),
            "System.Boolean" => ResourceType::from_type_byte(0x2, parser),
            "System.Char" => ResourceType::from_type_byte(0x3, parser),
            "System.Byte" => ResourceType::from_type_byte(0x4, parser),
            "System.SByte" => ResourceType::from_type_byte(0x5, parser),
            "System.Int16" => ResourceType::from_type_byte(0x6, parser),
            "System.UInt16" => ResourceType::from_type_byte(0x7, parser),
            "System.Int32" => ResourceType::from_type_byte(0x8, parser),
            "System.UInt32" => ResourceType::from_type_byte(0x9, parser),
            "System.Int64" => ResourceType::from_type_byte(0xA, parser),
            "System.UInt64" => ResourceType::from_type_byte(0xB, parser),
            "System.Single" => ResourceType::from_type_byte(0xC, parser),
            "System.Double" => ResourceType::from_type_byte(0xD, parser),
            "System.Decimal" => ResourceType::from_type_byte(0xE, parser),
            "System.DateTime" => ResourceType::from_type_byte(0xF, parser),
            "System.TimeSpan" => ResourceType::from_type_byte(0x10, parser),
            "System.Byte[]" => ResourceType::from_type_byte(0x20, parser),
            "System.IO.Stream" => ResourceType::from_type_byte(0x21, parser),
            _ => Err(TypeError(format!(
                "TypeName - {type_name} is currently not supported"
            ))),
        }
    }
}

/// A parsed .NET resource entry with owned data.
///
/// This structure contains owned copies of resource data. For zero-copy access to large
/// resources (like embedded ZIP archives), see [`ResourceEntryRef`].
pub struct ResourceEntry {
    /// The name of the resource
    pub name: String,
    /// The hash of the name
    pub name_hash: u32,
    /// The parsed resource
    pub data: ResourceType,
}

/// Zero-copy variant of [`ResourceType`] that borrows data instead of copying.
///
/// This enum is identical to [`ResourceType`] except that `String` and `ByteArray` variants
/// hold borrowed references instead of owned data. This enables efficient access to large
/// embedded resources (like ZIP archives) without allocating copies that could be hundreds
/// of megabytes or gigabytes.
///
/// # Lifetime
///
/// The lifetime parameter `'a` represents the lifetime of the source data buffer. All borrowed
/// data (strings and byte arrays) will remain valid for this lifetime.
///
/// # Usage
///
/// Use this type when:
/// - Working with large embedded resources (e.g., ZIP archives, large binary data)
/// - Memory-mapping resource files for efficient access
/// - Avoiding unnecessary allocations for performance-critical code
///
/// Use [`ResourceType`] (the owned variant) when:
/// - You need to store resources beyond the lifetime of the source buffer
/// - Working with small resources where copying overhead is negligible
/// - You prefer simpler APIs without lifetime parameters
///
/// # Examples
///
/// ```no_run
/// use dotscope::metadata::resources::parse_dotnet_resource_ref;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resources = parse_dotnet_resource_ref(&resource_data)?;
///
/// for (name, entry) in &resources {
///     match &entry.data {
///         ResourceTypeRef::ByteArray(bytes) => {
///             // Zero-copy access to potentially large byte array
///             println!("Resource '{}': {} bytes (no copy!)", name, bytes.len());
///
///             // Can pass directly to functions expecting &[u8]
///             process_zip_archive(bytes)?;
///         }
///         ResourceTypeRef::String(s) => {
///             // Zero-copy access to string data
///             println!("String resource: {}", s);
///         }
///         _ => {}
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// All variants are thread-safe and can be safely shared across threads without synchronization,
/// as long as the underlying data buffer remains valid.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceTypeRef<'a> {
    /// Null resource value (type code 0x00)
    Null,
    /// UTF-8 string resource with borrowed data (type code 0x01)
    String(&'a str),
    /// Boolean resource value, false=0, true=non-zero (type code 0x02)
    Boolean(bool),
    /// Single character resource stored as UTF-16 code unit (type code 0x03)
    Char(char),
    /// Unsigned 8-bit integer resource (type code 0x04)
    Byte(u8),
    /// Signed 8-bit integer resource (type code 0x05)
    SByte(i8),
    /// Signed 16-bit integer resource, little-endian (type code 0x06)
    Int16(i16),
    /// Unsigned 16-bit integer resource, little-endian (type code 0x07)
    UInt16(u16),
    /// Signed 32-bit integer resource, little-endian (type code 0x08)
    Int32(i32),
    /// Unsigned 32-bit integer resource, little-endian (type code 0x09)
    UInt32(u32),
    /// Signed 64-bit integer resource, little-endian (type code 0x0A)
    Int64(i64),
    /// Unsigned 64-bit integer resource, little-endian (type code 0x0B)
    UInt64(u64),
    /// 32-bit floating point resource, little-endian (type code 0x0C)
    Single(f32),
    /// 64-bit floating point resource, little-endian (type code 0x0D)
    Double(f64),
    /// .NET Decimal resource value stored as raw bits (type code 0x0E)
    ///
    /// See [`ResourceType::Decimal`] for detailed documentation on the binary format.
    Decimal {
        /// Low 32 bits of the 96-bit mantissa
        lo: i32,
        /// Middle 32 bits of the 96-bit mantissa
        mid: i32,
        /// High 32 bits of the 96-bit mantissa
        hi: i32,
        /// Flags containing sign (bit 31) and scale (bits 16-23)
        flags: i32,
    },
    /// .NET DateTime resource value stored as binary ticks (type code 0x0F)
    ///
    /// See [`ResourceType::DateTime`] for detailed documentation on the binary format.
    DateTime(i64),
    /// .NET TimeSpan resource value stored as ticks (type code 0x10)
    ///
    /// See [`ResourceType::TimeSpan`] for detailed documentation on the binary format.
    TimeSpan(i64),
    /// Byte array resource with borrowed data (type code 0x20)
    ByteArray(&'a [u8]),
    /// Stream resource with borrowed data (type code 0x21)
    Stream(&'a [u8]),
    /// Marker for the beginning of user-defined types (type code 0x40+)
    StartOfUserTypes,
}

/// A parsed .NET resource entry with borrowed data for zero-copy access.
///
/// This is the zero-copy variant of [`ResourceEntry`] that borrows resource data instead of
/// copying it. Use this when working with large embedded resources to avoid allocating
/// potentially hundreds of megabytes or gigabytes of memory.
///
/// # Lifetime
///
/// The lifetime parameter `'a` represents the lifetime of the source resource data buffer.
/// The resource data will remain valid for this lifetime.
///
/// # Examples
///
/// ```no_run
/// use dotscope::metadata::resources::Resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let mut resource = Resource::parse(&resource_data)?;
/// let resources = resource.read_resources_ref(&resource_data)?;
///
/// for (name, entry) in &resources {
///     println!("Resource: {} (Hash: 0x{:08X})", name, entry.name_hash);
///
///     match &entry.data {
///         ResourceTypeRef::ByteArray(bytes) => {
///             // Extract embedded ZIP without copying
///             if bytes.starts_with(b"PK\x03\x04") {
///                 println!("  Found ZIP archive: {} bytes", bytes.len());
///                 extract_zip(bytes)?;
///             }
///         }
///         ResourceTypeRef::String(s) => {
///             println!("  String: '{}'", s);
///         }
///         _ => {}
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ResourceEntryRef<'a> {
    /// The name of the resource (owned for efficient map key usage)
    pub name: String,
    /// The hash of the name
    pub name_hash: u32,
    /// The parsed resource with borrowed data
    pub data: ResourceTypeRef<'a>,
}

impl<'a> ResourceTypeRef<'a> {
    /// Parses a resource type from its binary type code with zero-copy semantics.
    ///
    /// This is the zero-copy variant of [`ResourceType::from_type_byte`]. Instead of allocating
    /// owned copies for string and byte array data, it returns borrowed slices directly into
    /// the parser's underlying data buffer.
    ///
    /// This method reads a resource value from the parser based on the provided type byte,
    /// which corresponds to the type codes defined in the .NET resource format specification.
    /// Each type code indicates both the data type and how to parse the following bytes.
    ///
    /// # Arguments
    ///
    /// * `byte` - The type code byte (0x00-0xFF) that identifies the data type
    /// * `parser` - A mutable reference to the parser positioned after the type byte
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceTypeRef<'a>>`] containing the parsed resource value
    /// with borrowed data where applicable (strings and byte arrays).
    ///
    /// # Supported Type Codes
    ///
    /// All type codes from [`ResourceType::from_type_byte`] are supported with the same
    /// semantics, except:
    /// - `0x01`: UTF-8 string returns `&'a str` instead of `String`
    /// - `0x20`: Byte array returns `&'a [u8]` instead of `Vec<u8>`
    /// - `0x21`: Stream returns `&'a [u8]` instead of `Vec<u8>`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::ResourceTypeRef;
    /// use dotscope::Parser;
    ///
    /// let data = b"\x05hello"; // Type byte 0x01, length 5, "hello"
    /// let mut parser = Parser::new(data);
    ///
    /// // Parse a string resource (type code 0x01) - zero-copy
    /// let string_type = ResourceTypeRef::from_type_byte_ref(0x01, &mut parser)?;
    /// if let ResourceTypeRef::String(s) = string_type {
    ///     println!("Found string: {}", s); // No allocation occurred
    /// }
    ///
    /// // Parse a byte array (type code 0x20) - zero-copy
    /// let data = b"\x04\x01\x02\x03\x04"; // Length 4, followed by 4 bytes
    /// let mut parser = Parser::new(data);
    /// let bytes_type = ResourceTypeRef::from_type_byte_ref(0x20, &mut parser)?;
    /// if let ResourceTypeRef::ByteArray(bytes) = bytes_type {
    ///     println!("Found {} bytes (no copy!)", bytes.len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type byte is not supported
    /// - Parser errors: If reading the underlying data fails (e.g., truncated data)
    ///
    /// # Implementation Note
    ///
    /// Both `parser` and `data` parameters are required even though `parser.data()` returns `&'a [u8]`.
    /// This is because the parser is typically a local variable with a shorter lifetime than `'a`,
    /// and we need to return slices with lifetime `'a`. The `data` parameter provides the stable
    /// reference with lifetime `'a` that our returned slices borrow from, while `parser` is used
    /// for position tracking and reading operations.
    pub fn from_type_byte_ref(byte: u8, parser: &mut Parser<'a>, data: &'a [u8]) -> Result<Self> {
        match byte {
            0x0 => {
                // ResourceTypeCode.Null - no data to read
                Ok(ResourceTypeRef::Null)
            }
            0x1 => {
                // .NET string resources use UTF-8 encoding with 7-bit encoded byte length prefix
                // Zero-copy variant - returns borrowed slice
                Ok(ResourceTypeRef::String(
                    parser.read_prefixed_string_utf8_ref()?,
                ))
            }
            0x2 => Ok(ResourceTypeRef::Boolean(parser.read_le::<u8>()? > 0)),
            0x3 => {
                // ResourceTypeCode.Char - 2 bytes (UInt16)
                // .NET writes chars as UInt16 (UTF-16 code unit), not as single byte
                // See: ResourceWriter.WriteValue writes `(UInt16)(char)value`
                //      ResourceReader._LoadObjectV2 reads `(char)_store.ReadUInt16()`
                let code_unit = parser.read_le::<u16>()?;
                Ok(ResourceTypeRef::Char(
                    char::from_u32(u32::from(code_unit)).ok_or_else(|| {
                        TypeError("Invalid UTF-16 code unit for Char".to_string())
                    })?,
                ))
            }
            0x4 => Ok(ResourceTypeRef::Byte(parser.read_le::<u8>()?)),
            0x5 => Ok(ResourceTypeRef::SByte(parser.read_le::<i8>()?)),
            0x6 => Ok(ResourceTypeRef::Int16(parser.read_le::<i16>()?)),
            0x7 => Ok(ResourceTypeRef::UInt16(parser.read_le::<u16>()?)),
            0x8 => Ok(ResourceTypeRef::Int32(parser.read_le::<i32>()?)),
            0x9 => Ok(ResourceTypeRef::UInt32(parser.read_le::<u32>()?)),
            0xA => Ok(ResourceTypeRef::Int64(parser.read_le::<i64>()?)),
            0xB => Ok(ResourceTypeRef::UInt64(parser.read_le::<u64>()?)),
            0xC => Ok(ResourceTypeRef::Single(parser.read_le::<f32>()?)),
            0xD => Ok(ResourceTypeRef::Double(parser.read_le::<f64>()?)),
            0xE => {
                // ResourceTypeCode.Decimal - 16 bytes (4 × i32)
                // Format: lo, mid, hi, flags (all little-endian i32)
                let lo = parser.read_le::<i32>()?;
                let mid = parser.read_le::<i32>()?;
                let hi = parser.read_le::<i32>()?;
                let flags = parser.read_le::<i32>()?;
                Ok(ResourceTypeRef::Decimal { lo, mid, hi, flags })
            }
            0xF => {
                // ResourceTypeCode.DateTime - 8 bytes (i64 binary format)
                // Contains ticks (bits 0-61) and DateTimeKind (bits 62-63)
                let binary_value = parser.read_le::<i64>()?;
                Ok(ResourceTypeRef::DateTime(binary_value))
            }
            0x10 => {
                // ResourceTypeCode.TimeSpan - 8 bytes (i64 ticks)
                // Ticks represent 100-nanosecond intervals
                let ticks = parser.read_le::<i64>()?;
                Ok(ResourceTypeRef::TimeSpan(ticks))
            }
            0x20 => {
                let length = parser.read_le::<u32>()?;
                let start_pos = parser.pos();
                let end_pos = start_pos.checked_add(length as usize).ok_or_else(|| {
                    malformed_error!(
                        "ByteArray resource end offset overflow: start={} length={}",
                        start_pos,
                        length
                    )
                })?;

                let slice = data.get(start_pos..end_pos).ok_or(out_of_bounds_error!())?;

                if end_pos < data.len() {
                    parser.seek(end_pos)?;
                }

                Ok(ResourceTypeRef::ByteArray(slice))
            }
            0x21 => {
                let length = parser.read_le::<u32>()?;
                let start_pos = parser.pos();
                let end_pos = start_pos.checked_add(length as usize).ok_or_else(|| {
                    malformed_error!(
                        "Stream resource end offset overflow: start={} length={}",
                        start_pos,
                        length
                    )
                })?;

                let slice = data.get(start_pos..end_pos).ok_or(out_of_bounds_error!())?;

                if end_pos < data.len() {
                    parser.seek(end_pos)?;
                }

                // Stream uses same format as ByteArray, just different type code
                Ok(ResourceTypeRef::Stream(slice))
            }
            0x40..=0xFF => {
                // User types - these require a type table for resolution
                Err(TypeError(format!(
                    "TypeByte - {byte:X} is a user type (>=0x40) but requires type table resolution which is not yet implemented"
                )))
            }
            _ => Err(TypeError(format!(
                "TypeByte - {byte:X} is currently not supported"
            ))),
        }
    }

    /// Parses a resource type from its .NET type name with zero-copy semantics.
    ///
    /// This is the zero-copy variant of [`ResourceType::from_type_name`]. It maps common
    /// .NET Framework type names to their corresponding binary representations and delegates
    /// to [`Self::from_type_byte_ref`] for the actual parsing with zero-copy semantics.
    ///
    /// # Arguments
    ///
    /// * `type_name` - The fully qualified .NET type name (e.g., "System.String")
    /// * `parser` - A mutable reference to the parser positioned at the resource value
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceTypeRef<'a>>`] containing the parsed resource value
    /// with borrowed data for strings and byte arrays.
    ///
    /// # Supported Type Names
    ///
    /// All type names from [`ResourceType::from_type_name`] are supported. String and
    /// ByteArray types return borrowed slices instead of owned data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::ResourceTypeRef;
    /// use dotscope::Parser;
    ///
    /// let data = b"\x05hello";
    /// let mut parser = Parser::new(data);
    ///
    /// // Parse using .NET type name - zero-copy
    /// let string_resource = ResourceTypeRef::from_type_name_ref("System.String", &mut parser)?;
    /// if let ResourceTypeRef::String(s) = string_resource {
    ///     println!("String resource: {}", s); // No allocation
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type name is not supported
    /// - Parser errors: If reading the underlying data fails
    pub fn from_type_name_ref(
        type_name: &str,
        parser: &mut Parser<'a>,
        data: &'a [u8],
    ) -> Result<Self> {
        match type_name {
            "System.Null" => ResourceTypeRef::from_type_byte_ref(0x0, parser, data),
            "System.String" => ResourceTypeRef::from_type_byte_ref(0x1, parser, data),
            "System.Boolean" => ResourceTypeRef::from_type_byte_ref(0x2, parser, data),
            "System.Char" => ResourceTypeRef::from_type_byte_ref(0x3, parser, data),
            "System.Byte" => ResourceTypeRef::from_type_byte_ref(0x4, parser, data),
            "System.SByte" => ResourceTypeRef::from_type_byte_ref(0x5, parser, data),
            "System.Int16" => ResourceTypeRef::from_type_byte_ref(0x6, parser, data),
            "System.UInt16" => ResourceTypeRef::from_type_byte_ref(0x7, parser, data),
            "System.Int32" => ResourceTypeRef::from_type_byte_ref(0x8, parser, data),
            "System.UInt32" => ResourceTypeRef::from_type_byte_ref(0x9, parser, data),
            "System.Int64" => ResourceTypeRef::from_type_byte_ref(0xA, parser, data),
            "System.UInt64" => ResourceTypeRef::from_type_byte_ref(0xB, parser, data),
            "System.Single" => ResourceTypeRef::from_type_byte_ref(0xC, parser, data),
            "System.Double" => ResourceTypeRef::from_type_byte_ref(0xD, parser, data),
            "System.Decimal" => ResourceTypeRef::from_type_byte_ref(0xE, parser, data),
            "System.DateTime" => ResourceTypeRef::from_type_byte_ref(0xF, parser, data),
            "System.TimeSpan" => ResourceTypeRef::from_type_byte_ref(0x10, parser, data),
            "System.Byte[]" => ResourceTypeRef::from_type_byte_ref(0x20, parser, data),
            "System.IO.Stream" => ResourceTypeRef::from_type_byte_ref(0x21, parser, data),
            _ => Err(TypeError(format!(
                "TypeName - {type_name} is currently not supported"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::parser::Parser;

    #[test]
    fn test_resource_magic_constant() {
        assert_eq!(RESOURCE_MAGIC, 0xBEEFCACE);
    }

    #[test]
    fn test_from_type_byte_string() {
        // UTF-8 encoding: length (5 bytes) + "hello" as UTF-8
        let data = b"\x05hello";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x1, &mut parser).unwrap();

        if let ResourceType::String(s) = result {
            assert_eq!(s, "hello");
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn test_from_type_byte_boolean_true() {
        let data = b"\x01";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x2, &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_byte_boolean_false() {
        let data = b"\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x2, &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(!b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_byte_char() {
        // Char is stored as UInt16 (2 bytes) in .NET resource format
        // 'A' = 0x0041 in UTF-16 LE
        let data = &[0x41, 0x00];
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x3, &mut parser).unwrap();

        if let ResourceType::Char(c) = result {
            assert_eq!(c, 'A');
        } else {
            panic!("Expected Char variant");
        }

        // Test non-ASCII char (e.g., '€' = U+20AC = 0x20AC in UTF-16 LE)
        let data_euro = &[0xAC, 0x20];
        let mut parser_euro = Parser::new(data_euro);
        let result_euro = ResourceType::from_type_byte(0x3, &mut parser_euro).unwrap();

        if let ResourceType::Char(c) = result_euro {
            assert_eq!(c, '€');
        } else {
            panic!("Expected Char variant for euro sign");
        }
    }

    #[test]
    fn test_from_type_byte_byte() {
        let data = b"\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x4, &mut parser).unwrap();

        if let ResourceType::Byte(b) = result {
            assert_eq!(b, 255);
        } else {
            panic!("Expected Byte variant");
        }
    }

    #[test]
    fn test_from_type_byte_sbyte() {
        let data = b"\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x5, &mut parser).unwrap();

        if let ResourceType::SByte(sb) = result {
            assert_eq!(sb, -1);
        } else {
            panic!("Expected SByte variant");
        }
    }

    #[test]
    fn test_from_type_byte_int16() {
        let data = b"\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x6, &mut parser).unwrap();

        if let ResourceType::Int16(i) = result {
            assert_eq!(i, -1);
        } else {
            panic!("Expected Int16 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint16() {
        let data = b"\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x7, &mut parser).unwrap();

        if let ResourceType::UInt16(u) = result {
            assert_eq!(u, 65535);
        } else {
            panic!("Expected UInt16 variant");
        }
    }

    #[test]
    fn test_from_type_byte_int32() {
        let data = b"\x2A\x00\x00\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x8, &mut parser).unwrap();

        if let ResourceType::Int32(i) = result {
            assert_eq!(i, 42);
        } else {
            panic!("Expected Int32 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint32() {
        let data = b"\xFF\xFF\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x9, &mut parser).unwrap();

        if let ResourceType::UInt32(u) = result {
            assert_eq!(u, 4294967295);
        } else {
            panic!("Expected UInt32 variant");
        }
    }

    #[test]
    fn test_from_type_byte_int64() {
        let data = b"\x2A\x00\x00\x00\x00\x00\x00\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xA, &mut parser).unwrap();

        if let ResourceType::Int64(i) = result {
            assert_eq!(i, 42);
        } else {
            panic!("Expected Int64 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint64() {
        let data = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xB, &mut parser).unwrap();

        if let ResourceType::UInt64(u) = result {
            assert_eq!(u, 18446744073709551615);
        } else {
            panic!("Expected UInt64 variant");
        }
    }

    #[test]
    fn test_from_type_byte_single() {
        let data = b"\x00\x00\x28\x42"; // 42.0 as f32 in little endian
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xC, &mut parser).unwrap();

        if let ResourceType::Single(f) = result {
            assert_eq!(f, 42.0);
        } else {
            panic!("Expected Single variant");
        }
    }

    #[test]
    fn test_from_type_byte_double() {
        let data = b"\x00\x00\x00\x00\x00\x00\x45\x40"; // 42.0 as f64 in little endian
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xD, &mut parser).unwrap();

        if let ResourceType::Double(d) = result {
            assert_eq!(d, 42.0);
        } else {
            panic!("Expected Double variant");
        }
    }

    #[test]
    fn test_from_type_byte_unsupported() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xFF, &mut parser);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("FF is a user type (>=0x40) but requires type table resolution which is not yet implemented"));
    }

    #[test]
    fn test_from_type_name_null() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.Null", &mut parser);

        // This should successfully parse as ResourceType::Null (type code 0)
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ResourceType::Null);
    }

    #[test]
    fn test_from_type_name_string() {
        // UTF-8 encoding: length (5 bytes) + "hello" as UTF-8
        let data = b"\x05hello";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.String", &mut parser).unwrap();

        if let ResourceType::String(s) = result {
            assert_eq!(s, "hello");
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn test_from_type_name_boolean() {
        let data = b"\x01";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.Boolean", &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_name_all_supported_types() {
        // Test each type individually since they have different data sizes

        // String
        let mut parser = Parser::new(b"\x05hello");
        assert!(ResourceType::from_type_name("System.String", &mut parser).is_ok());

        // Boolean
        let mut parser = Parser::new(b"\x01");
        assert!(ResourceType::from_type_name("System.Boolean", &mut parser).is_ok());

        // Char (2 bytes - UInt16 in .NET)
        let mut parser = Parser::new(&[0x41, 0x00]); // 'A' in UTF-16 LE
        assert!(ResourceType::from_type_name("System.Char", &mut parser).is_ok());

        // Byte
        let mut parser = Parser::new(b"\xFF");
        assert!(ResourceType::from_type_name("System.Byte", &mut parser).is_ok());

        // SByte
        let mut parser = Parser::new(b"\xFF");
        assert!(ResourceType::from_type_name("System.SByte", &mut parser).is_ok());

        // Int16
        let mut parser = Parser::new(b"\xFF\xFF");
        assert!(ResourceType::from_type_name("System.Int16", &mut parser).is_ok());

        // UInt16
        let mut parser = Parser::new(b"\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt16", &mut parser).is_ok());

        // Int32
        let mut parser = Parser::new(b"\x2A\x00\x00\x00");
        assert!(ResourceType::from_type_name("System.Int32", &mut parser).is_ok());

        // UInt32
        let mut parser = Parser::new(b"\xFF\xFF\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt32", &mut parser).is_ok());

        // Int64
        let mut parser = Parser::new(b"\x2A\x00\x00\x00\x00\x00\x00\x00");
        assert!(ResourceType::from_type_name("System.Int64", &mut parser).is_ok());

        // UInt64
        let mut parser = Parser::new(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt64", &mut parser).is_ok());

        // Single
        let mut parser = Parser::new(b"\x00\x00\x28\x42");
        assert!(ResourceType::from_type_name("System.Single", &mut parser).is_ok());

        // Double
        let mut parser = Parser::new(b"\x00\x00\x00\x00\x00\x00\x45\x40");
        assert!(ResourceType::from_type_name("System.Double", &mut parser).is_ok());
    }

    #[test]
    fn test_from_type_name_unsupported() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.NotSupported", &mut parser);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("System.NotSupported is currently not supported"));
    }

    #[test]
    fn test_resource_entry_creation() {
        let entry = ResourceEntry {
            name: "TestResource".to_string(),
            name_hash: 12345,
            data: ResourceType::String("test_data".to_string()),
        };

        assert_eq!(entry.name, "TestResource");
        assert_eq!(entry.name_hash, 12345);

        if let ResourceType::String(s) = &entry.data {
            assert_eq!(s, "test_data");
        } else {
            panic!("Expected String data");
        }
    }

    #[test]
    fn test_resource_type_debug() {
        let resource = ResourceType::String("test".to_string());
        let debug_str = format!("{resource:?}");
        assert!(debug_str.contains("String"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_resource_type_clone() {
        let original = ResourceType::Int32(42);
        let cloned = original.clone();

        assert_eq!(original, cloned);

        if let (ResourceType::Int32(orig), ResourceType::Int32(clone)) = (&original, &cloned) {
            assert_eq!(orig, clone);
        } else {
            panic!("Clone should preserve type and value");
        }
    }

    #[test]
    fn test_resource_type_partial_eq() {
        let res1 = ResourceType::String("test".to_string());
        let res2 = ResourceType::String("test".to_string());
        let res3 = ResourceType::String("different".to_string());
        let res4 = ResourceType::Int32(42);

        assert_eq!(res1, res2);
        assert_ne!(res1, res3);
        assert_ne!(res1, res4);
    }

    #[test]
    fn test_resource_type_as_str() {
        // Test implemented types
        assert_eq!(
            ResourceType::String("test".to_string()).as_str(),
            Some("System.String")
        );
        assert_eq!(ResourceType::Boolean(true).as_str(), Some("System.Boolean"));
        assert_eq!(ResourceType::Int32(42).as_str(), Some("System.Int32"));
        assert_eq!(
            ResourceType::ByteArray(vec![1, 2, 3]).as_str(),
            Some("System.Byte[]")
        );
        assert_eq!(
            ResourceType::Double(std::f64::consts::PI).as_str(),
            Some("System.Double")
        );

        // Test special types (without data)
        assert_eq!(ResourceType::Null.as_str(), None);
        assert_eq!(ResourceType::StartOfUserTypes.as_str(), None);

        // Test implemented types (with data)
        assert_eq!(
            ResourceType::Decimal {
                lo: 0,
                mid: 0,
                hi: 0,
                flags: 0
            }
            .as_str(),
            Some("System.Decimal")
        );
        assert_eq!(ResourceType::DateTime(0).as_str(), Some("System.DateTime"));
        assert_eq!(ResourceType::TimeSpan(0).as_str(), Some("System.TimeSpan"));
    }

    #[test]
    fn test_resource_type_index() {
        // Test that all implemented types have correct indices
        assert_eq!(ResourceType::Boolean(true).index(), Some(0));
        assert_eq!(ResourceType::Byte(255).index(), Some(1));
        assert_eq!(ResourceType::SByte(-1).index(), Some(2));
        assert_eq!(ResourceType::Char('A').index(), Some(3));
        assert_eq!(ResourceType::Int16(42).index(), Some(4));
        assert_eq!(ResourceType::UInt16(65535).index(), Some(5));
        assert_eq!(ResourceType::Int32(42).index(), Some(6));
        assert_eq!(ResourceType::UInt32(42).index(), Some(7));
        assert_eq!(ResourceType::Int64(42).index(), Some(8));
        assert_eq!(ResourceType::UInt64(42).index(), Some(9));
        assert_eq!(ResourceType::Single(std::f32::consts::PI).index(), Some(10));
        assert_eq!(ResourceType::Double(std::f64::consts::PI).index(), Some(11));
        assert_eq!(ResourceType::String("test".to_string()).index(), Some(12));
        assert_eq!(
            ResourceType::Decimal {
                lo: 0,
                mid: 0,
                hi: 0,
                flags: 0
            }
            .index(),
            Some(13)
        );
        assert_eq!(ResourceType::DateTime(0).index(), Some(14));
        assert_eq!(ResourceType::TimeSpan(0).index(), Some(15));
        assert_eq!(ResourceType::ByteArray(vec![1, 2, 3]).index(), Some(16));
        assert_eq!(ResourceType::Stream(vec![]).index(), Some(17));

        // Test special types (without data)
        assert_eq!(ResourceType::Null.index(), None);
        assert_eq!(ResourceType::StartOfUserTypes.index(), None);
    }

    #[test]
    fn test_resource_type_index_consistency() {
        // Test that types with as_str() also have index() and vice versa
        let test_types = [
            ResourceType::Boolean(false),
            ResourceType::Byte(0),
            ResourceType::SByte(0),
            ResourceType::Char('A'),
            ResourceType::Int16(0),
            ResourceType::UInt16(0),
            ResourceType::Int32(0),
            ResourceType::UInt32(0),
            ResourceType::Int64(0),
            ResourceType::UInt64(0),
            ResourceType::Single(0.0),
            ResourceType::Double(0.0),
            ResourceType::String("".to_string()),
            ResourceType::ByteArray(vec![]),
        ];

        for resource_type in &test_types {
            // Types with as_str() should also have index()
            if resource_type.as_str().is_some() {
                assert!(
                    resource_type.index().is_some(),
                    "Type {resource_type:?} has as_str() but no index()"
                );
            }

            // Types with index() should also have as_str()
            if resource_type.index().is_some() {
                assert!(
                    resource_type.as_str().is_some(),
                    "Type {resource_type:?} has index() but no as_str()"
                );
            }
        }
    }

    #[test]
    fn test_resource_type_data_size() {
        // Test data size calculations for all implemented types
        assert_eq!(ResourceType::Boolean(true).data_size(), Some(1));
        assert_eq!(ResourceType::Byte(255).data_size(), Some(1));
        assert_eq!(ResourceType::SByte(-1).data_size(), Some(1));
        assert_eq!(ResourceType::Char('A').data_size(), Some(2)); // UTF-16
        assert_eq!(ResourceType::Int16(42).data_size(), Some(2));
        assert_eq!(ResourceType::UInt16(42).data_size(), Some(2));
        assert_eq!(ResourceType::Int32(42).data_size(), Some(4));
        assert_eq!(ResourceType::UInt32(42).data_size(), Some(4));
        assert_eq!(ResourceType::Int64(42).data_size(), Some(8));
        assert_eq!(ResourceType::UInt64(42).data_size(), Some(8));
        assert_eq!(
            ResourceType::Single(std::f32::consts::PI).data_size(),
            Some(4)
        );
        assert_eq!(
            ResourceType::Double(std::f64::consts::PI).data_size(),
            Some(8)
        );

        // Test variable-length types
        assert_eq!(
            ResourceType::String("hello".to_string()).data_size(),
            Some(6)
        ); // 1 byte length prefix + 5 bytes UTF-8
        assert_eq!(ResourceType::String("".to_string()).data_size(), Some(1)); // 1 byte length + 0 bytes
        assert_eq!(ResourceType::ByteArray(vec![1, 2, 3]).data_size(), Some(7)); // 4 byte LE length + 3 bytes data
        assert_eq!(ResourceType::ByteArray(vec![]).data_size(), Some(4)); // 4 byte LE length + 0 bytes

        // Test implemented types (Decimal, DateTime, TimeSpan)
        assert_eq!(
            ResourceType::Decimal {
                lo: 0,
                mid: 0,
                hi: 0,
                flags: 0
            }
            .data_size(),
            Some(16) // 4 × i32 = 16 bytes
        );
        assert_eq!(ResourceType::DateTime(0).data_size(), Some(8)); // i64
        assert_eq!(ResourceType::TimeSpan(0).data_size(), Some(8)); // i64
        assert_eq!(ResourceType::Stream(vec![1, 2, 3]).data_size(), Some(7)); // Same as ByteArray

        // Test special types (without data)
        assert_eq!(ResourceType::Null.data_size(), None);
        assert_eq!(ResourceType::StartOfUserTypes.data_size(), None);
    }

    #[test]
    fn test_resource_type_full_consistency() {
        // Test that types with data_size() also have as_str() and index()
        let test_types = [
            ResourceType::Boolean(false),
            ResourceType::Byte(0),
            ResourceType::SByte(0),
            ResourceType::Char('A'),
            ResourceType::Int16(0),
            ResourceType::UInt16(0),
            ResourceType::Int32(0),
            ResourceType::UInt32(0),
            ResourceType::Int64(0),
            ResourceType::UInt64(0),
            ResourceType::Single(0.0),
            ResourceType::Double(0.0),
            ResourceType::String("test".to_string()),
            ResourceType::ByteArray(vec![1, 2, 3]),
        ];

        for resource_type in &test_types {
            // All implemented types should have all three methods
            assert!(
                resource_type.as_str().is_some(),
                "Type {resource_type:?} should have as_str()"
            );
            assert!(
                resource_type.index().is_some(),
                "Type {resource_type:?} should have index()"
            );
            assert!(
                resource_type.data_size().is_some(),
                "Type {resource_type:?} should have data_size()"
            );
        }
    }
}

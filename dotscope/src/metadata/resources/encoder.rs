//! Resource data encoding for .NET resource files and embedded resources.
//!
//! This module provides comprehensive encoding functionality for creating .NET resource files
//! and managing embedded resource data within assemblies. It supports the complete .NET resource
//! type system and handles proper alignment and format compliance according to
//! the .NET resource file specification.
//!
//! # Architecture
//!
//! The encoding system implements a layered approach to resource data creation:
//!
//! ## Format Support
//! - **.NET Resource File Format**: Complete support for .resources file generation
//! - **Embedded Resource Data**: Direct binary data embedding in assemblies
//! - **Resource Alignment**: Configurable alignment for optimal performance
//!
//! ## Encoding Pipeline
//! The encoding process follows these stages:
//! 1. **Resource Registration**: Add individual resources with names and data
//! 2. **Type Analysis**: Determine optimal encoding for each resource type
//! 3. **Format Selection**: Choose between .NET resource format or raw binary
//! 4. **Alignment Processing**: Apply proper alignment constraints
//! 5. **Serialization**: Write final binary data with proper structure
//!
//! ## Optimization Strategies
//! For resource optimization:
//! - **Duplicate Detection**: Identify and deduplicate identical resource data
//! - **Alignment Optimization**: Balance size and performance requirements
//! - **Efficient Encoding**: Optimal encoding of resource metadata
//!
//! # Key Components
//!
//! - [`crate::metadata::resources::DotNetResourceEncoder`] - Main encoder for resource data creation
//! - [`crate::metadata::resources::DotNetResourceEncoder`] - Specialized encoder for .NET resource file format
//!
//! # Usage Examples
//!
//! ## Basic Resource Data Encoding
//!
//! ```
//! use dotscope::metadata::resources::DotNetResourceEncoder;
//!
//! let mut encoder = DotNetResourceEncoder::new();
//!
//! // Add various resource types
//! encoder.add_string("AppName", "My Application")?;
//! encoder.add_int32("Version", 1)?;
//! encoder.add_byte_array("IconData", &[0x89, 0x50, 0x4E, 0x47])?;
//!
//! // Generate encoded resource data
//! let resource_data = encoder.encode_dotnet_format()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## .NET Resource File Creation
//!
//! ```
//! use dotscope::metadata::resources::DotNetResourceEncoder;
//!
//! let mut encoder = DotNetResourceEncoder::new();
//!
//! // Add strongly-typed resources
//! encoder.add_string("WelcomeMessage", "Welcome to the application!")?;
//! encoder.add_int32("MaxConnections", 100)?;
//! encoder.add_byte_array("DefaultConfig", &[1, 2, 3, 4])?;
//!
//! // Generate .NET resource file format
//! let resource_file = encoder.encode_dotnet_format()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//!
//! # Error Handling
//!
//! This module defines resource encoding-specific error handling:
//! - **Invalid Resource Types**: When resource data cannot be encoded in the target format
//! - **Alignment Violations**: When resource data cannot meet alignment requirements
//! - **Format Compliance**: When generated data violates .NET resource format specifications
//!
//! All encoding operations return [`crate::Result<Vec<u8>>`] and follow consistent error patterns.
//!
//! # Thread Safety
//!
//! The [`crate::metadata::resources::encoder::DotNetResourceEncoder`] is not [`Send`] or [`Sync`] due to internal
//! mutable state. For concurrent encoding, create separate encoder instances per thread
//! or use the stateless encoding functions for simple scenarios.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::resources::types`] - For resource type definitions and parsing compatibility
//! - [`crate::metadata::resources::parser`] - For validation and round-trip testing
//! - [`crate::cilassembly::CilAssembly`] - For embedding resources in assembly modification pipeline
//! - [`crate::file::io`] - For 7-bit encoded integer encoding and binary I/O utilities
//!
//! # References
//!
//! - [.NET Resource File Format Specification](https://docs.microsoft.com/en-us/dotnet/framework/resources/)
//! - [.NET Binary Format Data Structure](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/)
//! - Microsoft .NET Framework Resource Management Documentation

use std::collections::BTreeMap;

use crate::{
    metadata::resources::{ResourceType, RESOURCE_MAGIC},
    utils::{to_u32, write_7bit_encoded_int},
    Error, Result,
};

/// The `ResourceManager` header version `ResourceWriter` writes.
const RESOURCE_MANAGER_HEADER_VERSION: u32 = 1;

/// The reader `ResourceWriter` names in the header.
const READER_TYPE: &str = "System.Resources.ResourceReader, mscorlib, Version=4.0.0.0, \
                           Culture=neutral, PublicKeyToken=b77a5c561934e089";

/// The resource set `ResourceWriter` names in the header.
const RESOURCE_SET_TYPE: &str = "System.Resources.RuntimeResourceSet";

/// Writes `value` as `BinaryWriter.Write(string)` does: its UTF-8 length as a 7-bit encoded
/// int, then its UTF-8 bytes.
fn write_string(value: &str, buffer: &mut Vec<u8>) -> Result<()> {
    write_7bit_encoded_int(to_u32(value.len())?, buffer);
    buffer.extend_from_slice(value.as_bytes());
    Ok(())
}

/// The hash the runtime looks a resource name up by (`FastResourceComparer.HashFunction`):
/// djb2 over the name's UTF-16 code units, `hash = (hash << 5) + hash ^ unit`, read as a
/// signed 32-bit value.
fn compute_resource_hash(key: &str) -> i32 {
    let mut hash = 5381u32;
    for unit in key.encode_utf16() {
        hash = (hash << 5).wrapping_add(hash) ^ u32::from(unit);
    }
    hash.cast_signed()
}

/// Specialized encoder for .NET resource file format.
///
/// The [`crate::metadata::resources::encoder::DotNetResourceEncoder`] creates resource files compatible with
/// the .NET resource system, including proper magic numbers, type headers, and
/// data serialization according to the .NET binary format specification.
///
/// # .NET Resource Format
///
/// The .NET resource format includes:
/// 1. **Magic Number**: `0xBEEFCACE` to identify the format
/// 2. **Version Information**: Resource format version numbers
/// 3. **Type Table**: Names and indices of resource types used
/// 4. **Resource Table**: Names and data offsets for each resource
/// 5. **Data Section**: Actual resource data with type information
///
/// # Usage Examples
///
/// ```
/// use dotscope::metadata::resources::DotNetResourceEncoder;
///
/// let mut encoder = DotNetResourceEncoder::new();
///
/// // Add various .NET resource types
/// encoder.add_string("WelcomeMessage", "Welcome to the application!")?;
/// encoder.add_int32("MaxRetries", 3)?;
/// encoder.add_boolean("DebugMode", true)?;
/// encoder.add_byte_array("ConfigData", &[1, 2, 3, 4])?;
///
/// // Generate .NET resource file
/// let resource_file = encoder.encode_dotnet_format()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] because it maintains mutable state
/// during resource building. Create separate instances for concurrent encoding.
#[derive(Debug, Clone)]
pub struct DotNetResourceEncoder {
    /// Collection of typed resources
    resources: Vec<(String, ResourceType)>,
    /// Resource format version
    version: u32,
}

impl DotNetResourceEncoder {
    /// Creates a new .NET resource encoder.
    ///
    /// Initializes an empty encoder configured for .NET resource file format
    /// generation with the current format version.
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::resources::encoder::DotNetResourceEncoder`] instance ready for resource addition.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// assert_eq!(encoder.resource_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        DotNetResourceEncoder {
            resources: Vec::new(),
            version: 2, // Microsoft ResourceWriter uses version 2
        }
    }

    /// Adds a string resource.
    ///
    /// Registers a string value with the specified name. String resources are
    /// encoded using the .NET string serialization format.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - String value to store
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_string("ApplicationName", "My Application")?;
    /// encoder.add_string("Version", "1.0.0")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_string(&mut self, name: &str, value: &str) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::String(value.to_string())));
        Ok(())
    }

    /// Adds a 32-bit integer resource.
    ///
    /// Registers an integer value with the specified name. Integer resources
    /// use the .NET Int32 serialization format.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - Integer value to store
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_int32("MaxConnections", 100)?;
    /// encoder.add_int32("TimeoutSeconds", 30)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_int32(&mut self, name: &str, value: i32) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Int32(value)));
        Ok(())
    }

    /// Adds a boolean resource.
    ///
    /// Registers a boolean value with the specified name. Boolean resources
    /// use the .NET Boolean serialization format.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - Boolean value to store
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_boolean("DebugMode", true)?;
    /// encoder.add_boolean("EnableLogging", false)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_boolean(&mut self, name: &str, value: bool) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Boolean(value)));
        Ok(())
    }

    /// Adds a byte array resource.
    ///
    /// Registers binary data as a byte array resource. Byte array resources
    /// use the .NET byte array serialization format with length prefix.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `data` - Binary data to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    ///
    /// let config_data = vec![0x01, 0x02, 0x03, 0x04];
    /// encoder.add_byte_array("ConfigurationData", &config_data)?;
    ///
    /// // For file data, read the file first
    /// // let icon_data = std::fs::read("icon.png")?;
    /// // encoder.add_byte_array("ApplicationIcon", &icon_data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_byte_array(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::ByteArray(data.to_vec())));
        Ok(())
    }

    /// Adds a stream resource.
    ///
    /// Registers binary data as a stream resource. Stream resources use the same
    /// storage format as byte arrays (4-byte LE length prefix + data), but are
    /// returned as a `Stream` by .NET's `ResourceReader` instead of a `byte[]`.
    /// This allows for memory-mapped access and streaming reads for large resources.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `data` - Binary data to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    ///
    /// let image_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG header
    /// encoder.add_stream("BackgroundImage", &image_data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_stream(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Stream(data.to_vec())));
        Ok(())
    }

    /// Adds an unsigned 8-bit integer resource.
    ///
    /// Registers a byte value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - Byte value to store (0-255)
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_byte("MaxRetries", 5)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_byte(&mut self, name: &str, value: u8) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Byte(value)));
        Ok(())
    }

    /// Adds a signed 8-bit integer resource.
    ///
    /// Registers a signed byte value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - Signed byte value to store (-128 to 127)
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_sbyte("TemperatureOffset", -10)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_sbyte(&mut self, name: &str, value: i8) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::SByte(value)));
        Ok(())
    }

    /// Adds a character resource.
    ///
    /// Registers a Unicode character with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - Character value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_char("Separator", ',')?;
    /// encoder.add_char("Delimiter", '|')?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_char(&mut self, name: &str, value: char) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Char(value)));
        Ok(())
    }

    /// Adds a signed 16-bit integer resource.
    ///
    /// Registers a 16-bit signed integer value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 16-bit signed integer value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_int16("PortNumber", 8080)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_int16(&mut self, name: &str, value: i16) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Int16(value)));
        Ok(())
    }

    /// Adds an unsigned 16-bit integer resource.
    ///
    /// Registers a 16-bit unsigned integer value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 16-bit unsigned integer value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_uint16("MaxConnections", 65535)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_uint16(&mut self, name: &str, value: u16) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::UInt16(value)));
        Ok(())
    }

    /// Adds an unsigned 32-bit integer resource.
    ///
    /// Registers a 32-bit unsigned integer value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 32-bit unsigned integer value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_uint32("FileSize", 1024000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_uint32(&mut self, name: &str, value: u32) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::UInt32(value)));
        Ok(())
    }

    /// Adds a signed 64-bit integer resource.
    ///
    /// Registers a 64-bit signed integer value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 64-bit signed integer value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_int64("TimestampTicks", 637500000000000000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_int64(&mut self, name: &str, value: i64) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Int64(value)));
        Ok(())
    }

    /// Adds an unsigned 64-bit integer resource.
    ///
    /// Registers a 64-bit unsigned integer value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 64-bit unsigned integer value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_uint64("MaxFileSize", 18446744073709551615)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_uint64(&mut self, name: &str, value: u64) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::UInt64(value)));
        Ok(())
    }

    /// Adds a 32-bit floating point resource.
    ///
    /// Registers a single-precision floating point value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 32-bit floating point value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_single("ScaleFactor", 1.5)?;
    /// encoder.add_single("Pi", 3.14159)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_single(&mut self, name: &str, value: f32) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Single(value)));
        Ok(())
    }

    /// Adds a 64-bit floating point resource.
    ///
    /// Registers a double-precision floating point value with the specified name.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `value` - 64-bit floating point value to store
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_double("PreciseValue", 3.14159265358979323846)?;
    /// encoder.add_double("EulerNumber", 2.71828182845904523536)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_double(&mut self, name: &str, value: f64) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::Double(value)));
        Ok(())
    }

    /// Adds a .NET Decimal resource using raw bit representation.
    ///
    /// Registers a 128-bit decimal value with the specified name using the same
    /// binary format as .NET's `System.Decimal`. The four 32-bit integers represent
    /// the internal structure of a .NET decimal number.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `lo` - Low 32 bits of the 96-bit mantissa
    /// * `mid` - Middle 32 bits of the 96-bit mantissa
    /// * `hi` - High 32 bits of the 96-bit mantissa
    /// * `flags` - Sign (bit 31) and scale (bits 16-23, valid range 0-28)
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    ///
    /// // Represents 3.261 (mantissa=3261, scale=3, positive)
    /// // flags = 0x00030000 (scale 3 in bits 16-23)
    /// encoder.add_decimal("Price", 3261, 0, 0, 0x00030000)?;
    ///
    /// // Represents -123.45 (mantissa=12345, scale=2, negative)
    /// // flags = 0x80020000 (sign bit + scale 2)
    /// encoder.add_decimal("Discount", 12345, 0, 0, 0x80020000_u32 as i32)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_decimal(
        &mut self,
        name: &str,
        lo: i32,
        mid: i32,
        hi: i32,
        flags: i32,
    ) -> Result<()> {
        self.resources.push((
            name.to_string(),
            ResourceType::Decimal { lo, mid, hi, flags },
        ));
        Ok(())
    }

    /// Adds a .NET DateTime resource using binary representation.
    ///
    /// Registers a date/time value with the specified name using the same binary
    /// format as .NET's `DateTime.ToBinary()`. The 64-bit value encodes both the
    /// ticks and the `DateTimeKind`.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `binary_value` - The binary representation from `DateTime.ToBinary()`
    ///   - Bits 0-61: Ticks (100-nanosecond intervals since 01/01/0001 00:00:00)
    ///   - Bits 62-63: DateTimeKind (0=Unspecified, 1=UTC, 2=Local)
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    ///
    /// // Ticks for 2024-01-01 00:00:00 UTC (kind=1, so bits 62-63 = 0b01)
    /// let ticks: i64 = 638_396_736_000_000_000; // Ticks component
    /// let kind: i64 = 1 << 62; // UTC kind
    /// encoder.add_datetime("ReleaseDate", ticks | kind)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_datetime(&mut self, name: &str, binary_value: i64) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::DateTime(binary_value)));
        Ok(())
    }

    /// Adds a .NET TimeSpan resource using ticks.
    ///
    /// Registers a time interval with the specified name. The 64-bit signed value
    /// represents the number of 100-nanosecond intervals in the time span.
    ///
    /// # Arguments
    ///
    /// * `name` - Unique name for the resource
    /// * `ticks` - Number of 100-nanosecond intervals (negative for negative spans)
    ///
    /// # Conversion Reference
    ///
    /// Common tick conversions:
    /// - 1 millisecond = 10,000 ticks
    /// - 1 second = 10,000,000 ticks
    /// - 1 minute = 600,000,000 ticks
    /// - 1 hour = 36,000,000,000 ticks
    /// - 1 day = 864,000,000,000 ticks
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    ///
    /// // 1 hour timeout
    /// encoder.add_timespan("Timeout", 36_000_000_000)?;
    ///
    /// // 30 seconds
    /// encoder.add_timespan("RetryDelay", 300_000_000)?;
    ///
    /// // Negative 5 minutes
    /// encoder.add_timespan("TimeOffset", -3_000_000_000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Future versions may return errors
    /// for invalid resource names or encoding issues.
    pub fn add_timespan(&mut self, name: &str, ticks: i64) -> Result<()> {
        self.resources
            .push((name.to_string(), ResourceType::TimeSpan(ticks)));
        Ok(())
    }

    /// Returns the number of resources in the encoder.
    ///
    /// # Returns
    ///
    /// The total number of resources that have been added.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// assert_eq!(encoder.resource_count(), 0);
    ///
    /// encoder.add_string("test", "value")?;
    /// assert_eq!(encoder.resource_count(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Encodes all resources into .NET resource file format.
    ///
    /// Generates a complete .NET resource file including magic number, headers,
    /// type information, and resource data according to the .NET specification.
    ///
    /// # Returns
    ///
    /// Returns the encoded .NET resource file as a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if encoding fails due to invalid resource data
    /// or serialization errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::DotNetResourceEncoder;
    ///
    /// let mut encoder = DotNetResourceEncoder::new();
    /// encoder.add_string("AppName", "My Application")?;
    /// encoder.add_int32("Version", 1)?;
    ///
    /// let resource_file = encoder.encode_dotnet_format()?;
    ///
    /// // The encoded data can be saved to a file or embedded in an assembly
    /// assert!(!resource_file.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode_dotnet_format(&self) -> Result<Vec<u8>> {
        // The data section first, each resource's offset into it recorded as it is written
        let mut data = Vec::new();
        let mut data_offsets = Vec::with_capacity(self.resources.len());
        for (_, resource_type) in &self.resources {
            data_offsets.push(to_u32(data.len())?);
            Self::write_resource_data(resource_type, &mut data)?;
        }

        // The runtime finds a name by a binary search over the hashes, signed
        let mut order: Vec<(i32, usize)> = self
            .resources
            .iter()
            .enumerate()
            .map(|(index, (name, _))| (compute_resource_hash(name), index))
            .collect();
        order.sort_by_key(|&(hash, _)| hash);

        // Each name as `BinaryWriter(Encoding.Unicode).Write(string)` writes it, then its
        // resource's offset into the data section
        let mut names = Vec::new();
        let mut name_positions = Vec::with_capacity(order.len());
        for &(_, index) in &order {
            let (name, _) = self.resources.get(index).ok_or(out_of_bounds_error!())?;
            let data_offset = data_offsets.get(index).ok_or(out_of_bounds_error!())?;
            name_positions.push(to_u32(names.len())?);
            let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            write_7bit_encoded_int(to_u32(utf16.len())?, &mut names);
            names.extend_from_slice(&utf16);
            names.extend_from_slice(&data_offset.to_le_bytes());
        }

        // ResourceManager header: the reader and set types, after the count of their bytes
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&RESOURCE_MAGIC.to_le_bytes());
        buffer.extend_from_slice(&RESOURCE_MANAGER_HEADER_VERSION.to_le_bytes());
        let mut types = Vec::new();
        write_string(READER_TYPE, &mut types)?;
        write_string(RESOURCE_SET_TYPE, &mut types)?;
        buffer.extend_from_slice(&to_u32(types.len())?.to_le_bytes());
        buffer.extend_from_slice(&types);

        // RuntimeResourceReader header: no type table, every resource has a primitive type code
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&to_u32(self.resources.len())?.to_le_bytes());
        buffer.extend_from_slice(&0u32.to_le_bytes());

        // The hashes are 8-byte aligned from the magic, padded as ResourceWriter pads
        let misalignment = buffer.len() % 8;
        if misalignment != 0 {
            buffer.extend_from_slice(b"PADPADPA".get(misalignment..).unwrap_or_default());
        }
        for &(hash, _) in &order {
            buffer.extend_from_slice(&hash.to_le_bytes());
        }
        for position in &name_positions {
            buffer.extend_from_slice(&position.to_le_bytes());
        }

        // The data section's offset from the magic, then the names and the data
        let data_section = buffer
            .len()
            .checked_add(4)
            .and_then(|offset| offset.checked_add(names.len()))
            .ok_or_else(|| malformed_error!("Resource data section offset overflow"))?;
        buffer.extend_from_slice(&to_u32(data_section)?.to_le_bytes());
        buffer.extend_from_slice(&names);
        buffer.extend_from_slice(&data);

        Ok(buffer)
    }

    /// Collects all unique resource types used in the current resource set.
    ///
    /// This method identifies which .NET resource types are actually used, allowing
    /// the type table to include only necessary types for optimal file size.
    ///
    /// # Returns
    ///
    /// Returns a vector of tuples containing (type_name, type_index) pairs sorted by index.
    fn get_used_types(&self) -> Vec<(&'static str, u32)> {
        let mut used_types = BTreeMap::new();

        for (_, resource_type) in &self.resources {
            if let (Some(type_name), Some(type_index)) =
                (resource_type.as_str(), resource_type.index())
            {
                used_types.insert(type_index, type_name);
            }
        }

        used_types
            .into_iter()
            .map(|(index, name)| (name, index))
            .collect()
    }

    /// Writes one resource's type code and value as `ResourceWriter` writes them.
    fn write_resource_data(resource_type: &ResourceType, buffer: &mut Vec<u8>) -> Result<()> {
        // Use Microsoft's ResourceTypeCode enum values exactly
        let type_code = match resource_type {
            ResourceType::Null => 0u32,            // ResourceTypeCode.Null
            ResourceType::String(_) => 1u32,       // ResourceTypeCode.String
            ResourceType::Boolean(_) => 2u32,      // ResourceTypeCode.Boolean
            ResourceType::Char(_) => 3u32,         // ResourceTypeCode.Char
            ResourceType::Byte(_) => 4u32,         // ResourceTypeCode.Byte
            ResourceType::SByte(_) => 5u32,        // ResourceTypeCode.SByte
            ResourceType::Int16(_) => 6u32,        // ResourceTypeCode.Int16
            ResourceType::UInt16(_) => 7u32,       // ResourceTypeCode.UInt16
            ResourceType::Int32(_) => 8u32,        // ResourceTypeCode.Int32
            ResourceType::UInt32(_) => 9u32,       // ResourceTypeCode.UInt32
            ResourceType::Int64(_) => 10u32,       // ResourceTypeCode.Int64
            ResourceType::UInt64(_) => 11u32,      // ResourceTypeCode.UInt64
            ResourceType::Single(_) => 12u32,      // ResourceTypeCode.Single
            ResourceType::Double(_) => 13u32,      // ResourceTypeCode.Double
            ResourceType::Decimal { .. } => 14u32, // ResourceTypeCode.Decimal (0x0E)
            ResourceType::DateTime(_) => 15u32,    // ResourceTypeCode.DateTime (0x0F)
            ResourceType::TimeSpan(_) => 16u32,    // ResourceTypeCode.TimeSpan (0x10)
            ResourceType::ByteArray(_) => 32u32,   // ResourceTypeCode.ByteArray (0x20)
            ResourceType::Stream(_) => 33u32,      // ResourceTypeCode.Stream (0x21)
            ResourceType::StartOfUserTypes => return Err(Error::NotSupported),
        };

        // The type code is a 7-bit encoded int (`data.Write7BitEncodedInt`)
        write_7bit_encoded_int(type_code, buffer);

        // Write value data following Microsoft's WriteValue method exactly
        match resource_type {
            ResourceType::Null => {
                // No data for null
            }
            ResourceType::String(s) => write_string(s, buffer)?,
            ResourceType::Boolean(b) => {
                buffer.push(u8::from(*b));
            }
            ResourceType::Char(c) => {
                // Microsoft writes char as ushort (UTF-16)
                let utf16_char = *c as u16;
                buffer.extend_from_slice(&utf16_char.to_le_bytes());
            }
            ResourceType::Byte(b) => {
                buffer.push(*b);
            }
            ResourceType::SByte(sb) => {
                #[allow(clippy::cast_sign_loss)]
                {
                    buffer.push(*sb as u8);
                }
            }
            ResourceType::Int16(i) => {
                buffer.extend_from_slice(&i.to_le_bytes());
            }
            ResourceType::UInt16(u) => {
                buffer.extend_from_slice(&u.to_le_bytes());
            }
            ResourceType::Int32(i) => {
                buffer.extend_from_slice(&i.to_le_bytes());
            }
            ResourceType::UInt32(u) => {
                buffer.extend_from_slice(&u.to_le_bytes());
            }
            ResourceType::Int64(i) => {
                buffer.extend_from_slice(&i.to_le_bytes());
            }
            ResourceType::UInt64(u) => {
                buffer.extend_from_slice(&u.to_le_bytes());
            }
            ResourceType::Single(f) => {
                buffer.extend_from_slice(&f.to_le_bytes());
            }
            ResourceType::Double(d) => {
                buffer.extend_from_slice(&d.to_le_bytes());
            }
            ResourceType::Decimal { lo, mid, hi, flags } => {
                // Write 4 × i32 in little-endian order: lo, mid, hi, flags
                buffer.extend_from_slice(&lo.to_le_bytes());
                buffer.extend_from_slice(&mid.to_le_bytes());
                buffer.extend_from_slice(&hi.to_le_bytes());
                buffer.extend_from_slice(&flags.to_le_bytes());
            }
            ResourceType::DateTime(binary_value) => {
                // Write i64 binary representation (ticks + kind)
                buffer.extend_from_slice(&binary_value.to_le_bytes());
            }
            ResourceType::TimeSpan(ticks) => {
                // Write i64 ticks
                buffer.extend_from_slice(&ticks.to_le_bytes());
            }
            ResourceType::ByteArray(data) | ResourceType::Stream(data) => {
                buffer.extend_from_slice(&to_u32(data.len())?.to_le_bytes());
                buffer.extend_from_slice(data);
            }
            ResourceType::StartOfUserTypes => {
                return Err(Error::NotSupported);
            }
        }

        Ok(())
    }
}

impl Default for DotNetResourceEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::resources::parser::{parse_dotnet_resource, Resource};

    /// Every name in WindowsBase's resources, which the .NET tooling wrote, is stored under
    /// the hash this computes, and the hashes are in signed order.
    #[test]
    fn the_hash_is_the_runtimes() {
        let data =
            include_bytes!("../../../tests/samples/WB_FxResources.WindowsBase.SR.resources.bin");
        let entries = parse_dotnet_resource(data).unwrap();
        assert!(entries.len() > 500);
        for entry in entries.values() {
            assert_eq!(
                entry.name_hash,
                compute_resource_hash(&entry.name).cast_unsigned(),
                "{}",
                entry.name
            );
        }
        let stored = Resource::parse(data).unwrap().name_hashes;
        assert!(stored
            .windows(2)
            .all(|pair| pair[0].cast_signed() <= pair[1].cast_signed()));
    }

    /// The names written cover both signs of the hash: they are in signed order, as the
    /// runtime's binary search reads them, and each one reads back.
    #[test]
    fn names_are_in_signed_hash_order() {
        let mut encoder = DotNetResourceEncoder::new();
        for index in 0..300 {
            encoder
                .add_string(&format!("Name{index}"), &format!("value {index}"))
                .unwrap();
        }
        let encoded = encoder.encode_dotnet_format().unwrap();

        let hashes: Vec<i32> = Resource::parse(&encoded)
            .unwrap()
            .name_hashes
            .iter()
            .map(|hash| hash.cast_signed())
            .collect();
        assert!(hashes.iter().any(|hash| *hash < 0) && hashes.iter().any(|hash| *hash > 0));
        assert!(hashes.windows(2).all(|pair| pair[0] <= pair[1]));
        let entries = parse_dotnet_resource(&encoded).unwrap();
        assert_eq!(entries.len(), 300);
        assert!(matches!(
            &entries["Name123"].data,
            ResourceType::String(value) if value == "value 123"
        ));
    }

    /// Embedded in an assembly, a stream sits after its 4-byte length, and reads back the
    /// same: its padding and data offsets count from its magic. A name past 63 characters
    /// and a string past 16 KiB take longer 7-bit lengths.
    #[test]
    fn an_embedded_stream_reads_back() {
        let long_name = "N".repeat(100);
        let long_value = "x\u{e9}\u{1F600}\t".repeat(5000);
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string(&long_name, &long_value).unwrap();
        encoder.add_int32("Emoji\u{1F600}", 42).unwrap();
        encoder.add_byte_array("Bytes", &[1, 2, 255]).unwrap();
        let stream = encoder.encode_dotnet_format().unwrap();

        for data in [stream.clone(), {
            let mut embedded = u32::try_from(stream.len()).unwrap().to_le_bytes().to_vec();
            embedded.extend_from_slice(&stream);
            embedded
        }] {
            let entries = parse_dotnet_resource(&data).unwrap();
            assert!(
                matches!(&entries[&long_name].data, ResourceType::String(value) if *value == long_value)
            );
            assert!(matches!(
                entries["Emoji\u{1F600}"].data,
                ResourceType::Int32(42)
            ));
            assert!(
                matches!(&entries["Bytes"].data, ResourceType::ByteArray(bytes) if bytes == &[1, 2, 255])
            );
        }
    }

    #[test]
    fn test_dotnet_resource_encoder_basic() {
        let mut encoder = DotNetResourceEncoder::new();
        assert_eq!(encoder.resource_count(), 0);

        encoder
            .add_string("AppName", "Test App")
            .expect("Should add string");
        encoder.add_int32("Version", 1).expect("Should add integer");
        encoder
            .add_boolean("Debug", true)
            .expect("Should add boolean");

        assert_eq!(encoder.resource_count(), 3);
    }

    #[test]
    fn test_dotnet_resource_encoder_encoding() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder
            .add_string("test", "value")
            .expect("Should add string resource");

        let encoded = encoder
            .encode_dotnet_format()
            .expect("Should encode .NET format");
        assert!(!encoded.is_empty());

        // A .resources stream starts with its magic: embedding adds the length before it
        let magic = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(magic, RESOURCE_MAGIC);

        // Verify encoding works and produces reasonable output
        assert!(encoded.len() > 20); // Should have headers and data
    }

    /// Test that demonstrates the complete DotNetResourceEncoder API
    #[test]
    fn test_comprehensive_resource_encoder_api() {
        let mut encoder = DotNetResourceEncoder::new();

        // Test all supported add methods
        encoder.add_string("AppName", "My Application").unwrap();
        encoder.add_boolean("DebugMode", true).unwrap();
        encoder.add_char("Separator", ',').unwrap();
        encoder.add_byte("MaxRetries", 5).unwrap();
        encoder.add_sbyte("Offset", -10).unwrap();
        encoder.add_int16("Port", 8080).unwrap();
        encoder.add_uint16("MaxConnections", 65535).unwrap();
        encoder.add_int32("Version", 42).unwrap();
        encoder.add_uint32("FileSize", 1024000).unwrap();
        encoder
            .add_int64("TimestampTicks", 637500000000000000)
            .unwrap();
        encoder
            .add_uint64("MaxFileSize", 18446744073709551615)
            .unwrap();
        encoder.add_single("ScaleFactor", 1.5).unwrap();
        encoder.add_double("Pi", std::f64::consts::PI).unwrap();
        encoder
            .add_byte_array("ConfigData", &[1, 2, 3, 4, 5])
            .unwrap();

        // Verify all resources were added
        assert_eq!(encoder.resource_count(), 14);

        // Test that encoding produces valid output
        let encoded_data = encoder.encode_dotnet_format().unwrap();
        assert!(!encoded_data.is_empty());
        assert!(encoded_data.len() > 100); // Should be substantial

        // Verify magic number is correct
        let magic = u32::from_le_bytes([
            encoded_data[0],
            encoded_data[1],
            encoded_data[2],
            encoded_data[3],
        ]);
        assert_eq!(magic, RESOURCE_MAGIC);

        // Verify encoding completed successfully
        assert_eq!(encoder.resource_count(), 14);
        assert!(encoded_data.len() > 100);
    }

    #[test]
    fn test_debug_encoder_format() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("TestResource", "Hello World").unwrap();

        let buffer = encoder.encode_dotnet_format().unwrap();

        // Use our own parser to verify the generated data is valid
        let mut resource = crate::metadata::resources::Resource::parse(&buffer).unwrap();

        // Verify basic characteristics
        assert_eq!(resource.rr_version, 2);
        assert_eq!(resource.resource_count, 1);

        // Try to parse the resources to verify validity
        resource
            .read_resources(&buffer)
            .expect("Should be able to parse generated resources");
    }

    #[test]
    fn test_roundtrip_edge_values() {
        let mut encoder = DotNetResourceEncoder::new();

        // Test edge values
        encoder.add_string("EmptyString", "").unwrap();
        encoder
            .add_string("UnicodeString", "🦀 Rust rocks! 你好世界")
            .unwrap();
        encoder.add_byte_array("EmptyByteArray", &[]).unwrap();
        encoder.add_single("NaN", f32::NAN).unwrap();
        encoder.add_single("Infinity", f32::INFINITY).unwrap();
        encoder
            .add_single("NegInfinity", f32::NEG_INFINITY)
            .unwrap();
        encoder.add_double("DoubleNaN", f64::NAN).unwrap();
        encoder.add_double("DoubleInfinity", f64::INFINITY).unwrap();
        encoder
            .add_double("DoubleNegInfinity", f64::NEG_INFINITY)
            .unwrap();

        // Encode and parse back
        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        // Verify edge cases
        assert_eq!(parsed_resources.len(), 9);

        // Empty string
        let empty_string = parsed_resources.get("EmptyString").unwrap();
        if let crate::metadata::resources::ResourceType::String(ref s) = empty_string.data {
            assert_eq!(s, "");
        } else {
            panic!("Expected String resource type");
        }

        // Unicode string
        let unicode_string = parsed_resources.get("UnicodeString").unwrap();
        if let crate::metadata::resources::ResourceType::String(ref s) = unicode_string.data {
            assert_eq!(s, "🦀 Rust rocks! 你好世界");
        } else {
            panic!("Expected String resource type");
        }

        // Empty byte array
        let empty_bytes = parsed_resources.get("EmptyByteArray").unwrap();
        if let crate::metadata::resources::ResourceType::ByteArray(ref ba) = empty_bytes.data {
            assert_eq!(ba, &Vec::<u8>::new());
        } else {
            panic!("Expected ByteArray resource type");
        }

        // NaN and infinity values
        let nan_val = parsed_resources.get("NaN").unwrap();
        if let crate::metadata::resources::ResourceType::Single(f) = nan_val.data {
            assert!(f.is_nan());
        } else {
            panic!("Expected Single resource type");
        }

        let inf_val = parsed_resources.get("Infinity").unwrap();
        if let crate::metadata::resources::ResourceType::Single(f) = inf_val.data {
            assert_eq!(f, f32::INFINITY);
        } else {
            panic!("Expected Single resource type");
        }

        let neg_inf_val = parsed_resources.get("NegInfinity").unwrap();
        if let crate::metadata::resources::ResourceType::Single(f) = neg_inf_val.data {
            assert_eq!(f, f32::NEG_INFINITY);
        } else {
            panic!("Expected Single resource type");
        }
    }

    #[test]
    fn test_large_resource_data() {
        let mut encoder = DotNetResourceEncoder::new();

        // Test large string resource
        let large_string = "x".repeat(10000);
        encoder.add_string("LargeString", &large_string).unwrap();

        // Test large byte array
        let large_bytes: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        encoder
            .add_byte_array("LargeByteArray", &large_bytes)
            .unwrap();

        // Encode and parse back
        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 2);

        // Verify large string
        let parsed_string = parsed_resources.get("LargeString").unwrap();
        if let crate::metadata::resources::ResourceType::String(ref s) = parsed_string.data {
            assert_eq!(s.len(), 10000);
            assert_eq!(s, &large_string);
        } else {
            panic!("Expected String resource type");
        }

        // Verify large byte array
        let parsed_bytes = parsed_resources.get("LargeByteArray").unwrap();
        if let crate::metadata::resources::ResourceType::ByteArray(ref ba) = parsed_bytes.data {
            assert_eq!(ba.len(), 5000);
            assert_eq!(ba, &large_bytes);
        } else {
            panic!("Expected ByteArray resource type");
        }
    }
}

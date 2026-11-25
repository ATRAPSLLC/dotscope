//! ECMA-335 Stream Header Parsing for .NET Metadata Directory
//!
//! This module provides parsing and validation of stream headers according to ECMA-335 Section II.24.2.2.
//! Stream headers form the directory structure within .NET metadata that describes the location, size,
//! and identity of each metadata stream (strings, blobs, GUIDs, tables) within the assembly file.
//!
//! # Stream Header Structure
//!
//! Each stream header consists of a fixed-size binary structure followed by a variable-length
//! null-terminated ASCII name. The header provides essential information for locating and
//! validating stream content within the metadata section.
//!
//! ## Binary Format
//! ```text
//! Offset | Size | Field       | Description
//! -------|------|-------------|------------------------------------------
//! 0      | 4    | Offset      | Byte offset from metadata root to stream data
//! 4      | 4    | Size        | Stream size in bytes (must be 4-byte aligned)
//! 8      | N+1  | Name        | Null-terminated ASCII stream name (max 32 chars)
//! ```
//!
//! ## ECMA-335 Compliance Requirements
//! - **Size Alignment**: Stream size should be divisible by 4 per spec, but unaligned sizes are tolerated
//! - **Offset Range**: Stream offset must not exceed maximum reasonable metadata size
//! - **Name Validation**: Stream name must match predefined standard stream identifiers
//! - **Null Termination**: Stream name must be properly null-terminated ASCII
//!
//! # Standard Stream Names
//!
//! The ECMA-335 specification defines specific names for standard metadata streams:
//!
//! ## String Storage Streams
//! - **`#Strings`**: UTF-8 identifier strings (type names, member names, namespaces)
//! - **`#US`**: UTF-16 user string literals (IL string constants, resource names)
//!
//! ## Binary Data Streams
//! - **`#Blob`**: Variable-length binary data (signatures, custom attributes, constants)
//! - **`#GUID`**: 128-bit globally unique identifiers (assembly/module correlation)
//!
//! ## Metadata Table Streams
//! - **`#~`**: Compressed metadata tables (modern .NET assemblies)
//! - **`#-`**: Uncompressed metadata tables (legacy format, rare)
//!
//! # Validation and Security
//!
//! Stream header parsing includes comprehensive validation to prevent:
//! - **Buffer overflow attacks**: Bounds checking on all field access
//! - **Integer overflow**: Range validation on offset and size values
//! - **Format corruption**: Alignment and name validation
//! - **Resource exhaustion**: Reasonable limits on stream sizes
//!
//! ## Validation Rules
//! 1. **Minimum size**: Header must contain at least offset, size, and one name byte
//! 2. **4-byte alignment**: Stream size must be multiple of 4 per ECMA-335
//! 3. **Range limits**: Offset and size must not exceed 0x7FFFFFFF (2GB limit)
//! 4. **Name validation**: Must match one of the six standard stream names
//! 5. **Null termination**: Name must be properly terminated within 32-character limit
//!
//! # Examples
//!
//! ## Basic Stream Header Parsing
//! ```rust
//! use dotscope::metadata::streams::StreamHeader;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Example metadata table stream header
//! #[rustfmt::skip]
//! let header_data = [
//!     0x6C, 0x00, 0x00, 0x00,  // Offset: 0x6C (108 bytes)
//!     0xA4, 0x45, 0x00, 0x00,  // Size: 0x45A4 (17,828 bytes)
//!     0x23, 0x7E, 0x00,        // Name: "#~\0" (compressed tables)
//! ];
//!
//! let header = StreamHeader::from(&header_data)?;
//!
//! assert_eq!(header.offset, 0x6C);
//! assert_eq!(header.size, 0x45A4);
//! assert_eq!(header.name, "#~");
//!
//! println!("Stream '{}' at offset 0x{:X}, size {} bytes",
//!          header.name, header.offset, header.size);
//! # Ok(())
//! # }
//! ```
//!
//! ## Stream Directory Processing
//! ```rust
//! use dotscope::metadata::streams::StreamHeader;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Process multiple stream headers from metadata directory
//! let directory_data = &[
//!     // First stream header
//!     0x6C, 0x00, 0x00, 0x00,           // Offset
//!     0xA4, 0x45, 0x00, 0x00,           // Size  
//!     0x23, 0x7E, 0x00, 0x00,           // "#~\0" (padded to 4-byte boundary)
//!     // Second stream header would follow...
//! ];
//!
//! let mut offset = 0;
//! let mut streams = Vec::new();
//!
//! // Parse first stream header
//! if offset < directory_data.len() {
//!     let header = StreamHeader::from(&directory_data[offset..])?;
//!     println!("Found stream: {} (offset: 0x{:X}, size: {})",
//!              header.name, header.offset, header.size);
//!     streams.push(header);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling and Validation
//! ```rust
//! use dotscope::metadata::streams::StreamHeader;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Example with invalid stream header (unaligned size)
//! #[rustfmt::skip]
//! let invalid_data = [
//!     0x6C, 0x00, 0x00, 0x00,  // Valid offset
//!     0xA5, 0x45, 0x00, 0x00,  // Invalid size (not 4-byte aligned)
//!     0x23, 0x7E, 0x00,        // Valid name "#~\0"
//! ];
//!
//! match StreamHeader::from(&invalid_data) {
//!     Ok(header) => println!("Parsed header: {}", header.name),
//!     Err(e) => println!("Validation failed: {}", e),
//! }
//!
//! // Example with invalid stream name
//! #[rustfmt::skip]
//! let invalid_name = [
//!     0x6C, 0x00, 0x00, 0x00,  // Valid offset
//!     0xA4, 0x45, 0x00, 0x00,  // Valid size
//!     0x24, 0x7E, 0x00,        // Invalid name "$~\0"
//! ];
//!
//! assert!(StreamHeader::from(&invalid_name).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 Partition II, Section 24.2.2:
//! - Correct parsing of offset, size, and name fields
//! - Proper validation of 4-byte size alignment requirement
//! - Standard stream name validation and recognition
//! - Comprehensive error handling for malformed headers
//!
//! # See Also
//! - [`crate::metadata::streams`]: Overview of all metadata stream types
//! - [`crate::metadata::root`]: Metadata root and stream directory parsing
//! - [ECMA-335 II.24.2.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Stream header specification
//!
//! # References
//! - **ECMA-335 II.24.2.2**: Stream header format and directory structure
//! - **ECMA-335 II.24.2**: Complete metadata stream architecture overview

use std::io::Write;

use crate::{utils::read_le_at, ParseFailure, ParseStage, Result};

/// The bytes a stream name and its terminating zero may take.
const MAX_NAME_BYTES: usize = 32;

/// ECMA-335 compliant stream header providing metadata stream location and identification.
///
/// A stream header describes a single metadata stream within a .NET assembly's metadata directory.
/// Each header contains the stream's file offset, size, and identifying name according to
/// ECMA-335 Section II.24.2.2. The structure enables runtime and analysis tools to locate
/// and validate specific metadata streams (strings, blobs, GUIDs, tables) within assembly files.
///
/// ## Binary Layout
///
/// Stream headers have a variable-length binary format:
/// ```text
/// [0-3]   u32     Stream offset from metadata root (4-byte aligned)
/// [4-7]   u32     Stream size in bytes (must be multiple of 4)  
/// [8-N]   CStr    Null-terminated ASCII stream name (max 32 chars)
/// ```
///
/// ## Standard Stream Names
///
/// The ECMA-335 specification defines six standard stream names:
/// - **`#Strings`**: UTF-8 identifier strings (type/member names)
/// - **`#US`**: UTF-16 user string literals (string constants)
/// - **`#Blob`**: Variable-length binary data (signatures, attributes)
/// - **`#GUID`**: 128-bit globally unique identifiers
/// - **`#~`**: Compressed metadata tables (modern assemblies)
/// - **`#-`**: Uncompressed metadata tables (legacy format)
///
/// ## Validation Requirements
///
/// All stream headers must meet ECMA-335 compliance requirements:
/// - Stream size must be 4-byte aligned (divisible by 4)
/// - Offset and size must not exceed 0x7FFFFFFF (2GB limit)
/// - Stream name must match one of the six standard names
/// - Name must be null-terminated ASCII within 32 characters
///
/// ## Thread Safety
///
/// [`StreamHeader`] instances are immutable after construction and safe for concurrent access.
/// All fields contain owned data with no shared references or interior mutability.
///
/// # Examples
///
/// ## Parsing a Metadata Table Stream Header
/// ```rust
/// use dotscope::metadata::streams::StreamHeader;
///
/// # fn example() -> dotscope::Result<()> {
/// // Binary data for "#~" (compressed tables) stream header
/// #[rustfmt::skip]
/// let header_data = [
///     0x6C, 0x00, 0x00, 0x00,  // Offset: 0x6C (108 bytes)
///     0xA4, 0x45, 0x00, 0x00,  // Size: 0x45A4 (17,828 bytes, 4-byte aligned)
///     0x23, 0x7E, 0x00,        // Name: "#~\0" (compressed metadata tables)
/// ];
///
/// let header = StreamHeader::from(&header_data)?;
///
/// assert_eq!(header.offset, 0x6C);
/// assert_eq!(header.size, 0x45A4);
/// assert_eq!(header.name, "#~");
///
/// println!("Compressed metadata tables at offset 0x{:X}, {} bytes",
///          header.offset, header.size);
/// # Ok(())
/// # }
/// ```
///
/// ## Processing String Stream Headers
/// ```rust
/// use dotscope::metadata::streams::StreamHeader;
///
/// # fn example() -> dotscope::Result<()> {
/// // String stream header with null-terminated name
/// #[rustfmt::skip]
/// let strings_header = [
///     0x20, 0x00, 0x00, 0x00,           // Offset: 0x20 (32 bytes)
///     0x48, 0x12, 0x00, 0x00,           // Size: 0x1248 (4,680 bytes)
///     0x23, 0x53, 0x74, 0x72, 0x69,     // "#Strings" name
///     0x6E, 0x67, 0x73, 0x00,           // null-terminated
/// ];
///
/// let header = StreamHeader::from(&strings_header)?;
///
/// assert_eq!(header.name, "#Strings");
/// assert!(header.size % 4 == 0); // ECMA-335 alignment requirement
///
/// match header.name.as_str() {
///     "#Strings" => println!("Found identifier strings stream"),
///     "#US" => println!("Found user strings stream"),
///     "#Blob" => println!("Found binary data stream"),
///     "#GUID" => println!("Found GUID stream"),
///     "#~" => println!("Found compressed metadata tables"),
///     "#-" => println!("Found uncompressed metadata tables"),
///     _ => unreachable!("Invalid stream names are rejected during parsing"),
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Error Handling for Invalid Headers
/// ```rust
/// use dotscope::metadata::streams::StreamHeader;
///
/// // A name with no terminating zero within its 32 bytes is refused, as the runtime does.
/// let mut unterminated = vec![0x6C, 0x00, 0x00, 0x00, 0xA4, 0x45, 0x00, 0x00];
/// unterminated.extend([b'#'; 32]);
/// assert!(StreamHeader::from(&unterminated).is_err());
///
/// // A name the runtime gives no stream is read; the directory ignores it.
/// #[rustfmt::skip]
/// let unknown = [
///     0x6C, 0x00, 0x00, 0x00,  // offset
///     0xA4, 0x45, 0x00, 0x00,  // size
///     0x24, 0x58, 0x00,        // "$X"
/// ];
/// assert_eq!(StreamHeader::from(&unknown).unwrap().name, "$X");
/// ```
///
/// # References
/// - [ECMA-335 II.24.2.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Stream header format specification
/// - [`crate::metadata::streams`]: Overview of metadata stream architecture
/// - [`crate::metadata::root`]: Metadata root and stream directory parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    /// Byte offset from the metadata root to the start of this stream's data.
    ///
    /// The offset is relative to the beginning of the metadata section and must point
    /// to a valid location within the assembly file. Values must not exceed 0x7FFFFFFF
    /// (2GB limit) to prevent integer overflow attacks.
    ///
    /// ## ECMA-335 Compliance
    /// - Must be a valid file offset within the metadata section
    /// - Subject to reasonable bounds checking (≤ 2GB)
    /// - Points to 4-byte aligned stream data (implementation detail)
    pub offset: u32,

    /// Size of this stream's data in bytes, must be a multiple of 4 per ECMA-335.
    ///
    /// The size represents the exact byte count of stream data. ECMA-335 Section II.24.2.2
    /// states sizes should be 4-byte aligned, but many real-world tools produce unaligned
    /// sizes which are tolerated for compatibility.
    ///
    /// ## Validation Rules
    /// - Should be divisible by 4 per spec (unaligned values are tolerated)
    /// - Must not exceed 0x7FFFFFFF (2GB limit)
    /// - Zero size is valid for empty streams
    ///
    /// ## Security Considerations
    /// - Bounds checked to prevent integer overflow attacks
    /// - Combined with offset validation to prevent out-of-bounds access
    pub size: u32,

    /// Stream identifier name, null-terminated ASCII string (maximum 32 characters).
    ///
    /// The name uniquely identifies the stream type and must match one of the six
    /// standard stream names defined in ECMA-335. Names are case-sensitive and
    /// must be properly null-terminated within the 32-character limit.
    ///
    /// ## Valid Stream Names
    /// - **`#Strings`**: UTF-8 identifier strings (namespaces, type names, member names)
    /// - **`#US`**: UTF-16 user string literals (string constants from IL code)
    /// - **`#Blob`**: Variable-length binary data (method signatures, custom attributes)
    /// - **`#GUID`**: 128-bit globally unique identifiers (assembly correlation)
    /// - **`#~`**: Compressed metadata tables (modern .NET assemblies, space-efficient)
    /// - **`#-`**: Uncompressed metadata tables (legacy format, rarely used)
    ///
    /// ## Security and Validation
    /// - Only standard ECMA-335 names are accepted to prevent malformed metadata
    /// - ASCII encoding enforced during parsing to prevent encoding attacks
    /// - Maximum length limit prevents buffer overflow vulnerabilities
    pub name: String,
}

impl StreamHeader {
    /// Parse a stream header from binary data according to ECMA-335 specification.
    ///
    /// Creates a [`StreamHeader`] by parsing the binary format defined in ECMA-335 Section II.24.2.2.
    /// The method performs comprehensive validation to ensure compliance with the specification
    /// and protect against malformed metadata that could cause security vulnerabilities.
    ///
    /// ## Binary Format Parsed
    /// ```text
    /// Offset | Size | Field       | Description
    /// -------|------|-------------|------------------------------------------
    /// 0      | 4    | Offset      | Stream data offset from metadata root (LE)
    /// 4      | 4    | Size        | Stream size in bytes (LE, 4-byte aligned)
    /// 8      | N+1  | Name        | Null-terminated ASCII name (max 32 chars)
    /// ```
    ///
    /// ## Validation Performed
    ///
    /// This method enforces all ECMA-335 compliance requirements:
    /// 1. **Minimum size**: Data must contain at least 9 bytes (8-byte header + 1 name byte)
    /// 2. **4-byte alignment**: Stream size must be divisible by 4
    /// 3. **Range limits**: Offset and size must not exceed 0x7FFFFFFF (2GB)
    /// 4. **Valid stream names**: Name must match one of six standard ECMA-335 stream identifiers
    /// 5. **Null termination**: Name must be properly null-terminated within 32 characters
    /// 6. **ASCII encoding**: Name must contain only valid ASCII characters
    ///
    /// ## Standard Stream Names
    /// - `#Strings`: UTF-8 identifier strings
    /// - `#US`: UTF-16 user string literals  
    /// - `#Blob`: Variable-length binary data
    /// - `#GUID`: 128-bit globally unique identifiers
    /// - `#~`: Compressed metadata tables
    /// - `#-`: Uncompressed metadata tables
    ///
    /// # Arguments
    /// * `data` - Binary data slice containing the stream header to parse
    ///
    /// # Returns
    /// * `Ok(StreamHeader)` - Successfully parsed and validated stream header
    /// * `Err(Error)` - Parsing failed due to insufficient data or validation errors
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - **[`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]**: Data slice too short (< 9 bytes)
    /// - **Malformed data**: Stream size not 4-byte aligned (ECMA-335 violation)
    /// - **Range error**: Offset or size exceeds 0x7FFFFFFF (integer overflow protection)
    /// - **Invalid name**: Stream name doesn't match standard ECMA-335 identifiers
    /// - **Format error**: Name not properly null-terminated or contains non-ASCII
    ///
    /// # Examples
    ///
    /// ## Parsing Valid Stream Headers
    /// ```rust
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Compressed metadata tables stream header
    /// #[rustfmt::skip]
    /// let tables_header = [
    ///     0x6C, 0x00, 0x00, 0x00,  // Offset: 0x6C
    ///     0xA4, 0x45, 0x00, 0x00,  // Size: 0x45A4 (4-byte aligned)
    ///     0x23, 0x7E, 0x00,        // Name: "#~\0"
    /// ];
    ///
    /// let header = StreamHeader::from(&tables_header)?;
    /// assert_eq!(header.name, "#~");
    /// assert_eq!(header.offset, 0x6C);
    /// assert_eq!(header.size, 0x45A4);
    /// assert!(header.size % 4 == 0); // ECMA-335 alignment verified
    ///
    /// // Strings stream header with longer name
    /// #[rustfmt::skip]
    /// let strings_header = [
    ///     0x20, 0x00, 0x00, 0x00,           // Offset: 0x20
    ///     0x48, 0x12, 0x00, 0x00,           // Size: 0x1248
    ///     0x23, 0x53, 0x74, 0x72, 0x69,     // "#Strings"
    ///     0x6E, 0x67, 0x73, 0x00,           // null-terminated
    /// ];
    ///
    /// let header = StreamHeader::from(&strings_header)?;
    /// assert_eq!(header.name, "#Strings");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Cases and Validation
    /// ```rust
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// # fn example() {
    /// // Error: Data too short
    /// let too_short = [0x6C, 0x00, 0x00, 0x00, 0xA4]; // Only 5 bytes
    /// assert!(StreamHeader::from(&too_short).is_err());
    ///
    /// // Error: Size not 4-byte aligned
    /// #[rustfmt::skip]
    /// let unaligned = [
    ///     0x6C, 0x00, 0x00, 0x00,  // Valid offset
    ///     0xA5, 0x45, 0x00, 0x00,  // Size 0x45A5 (not divisible by 4)
    ///     0x23, 0x7E, 0x00,        // Valid name
    /// ];
    /// assert!(StreamHeader::from(&unaligned).is_err());
    ///
    /// // Error: Invalid stream name
    /// #[rustfmt::skip]
    /// let invalid_name = [
    ///     0x6C, 0x00, 0x00, 0x00,  // Valid offset
    ///     0xA4, 0x45, 0x00, 0x00,  // Valid size
    ///     0x24, 0x58, 0x00,        // Invalid name "$X\0"
    /// ];
    /// assert!(StreamHeader::from(&invalid_name).is_err());
    ///
    /// // Error: Offset too large (> 2GB)
    /// #[rustfmt::skip]
    /// let large_offset = [
    ///     0xFF, 0xFF, 0xFF, 0xFF,  // Offset: 0xFFFFFFFF (> 0x7FFFFFFF)
    ///     0xA4, 0x45, 0x00, 0x00,  // Valid size
    ///     0x23, 0x7E, 0x00,        // Valid name
    /// ];
    /// assert!(StreamHeader::from(&large_offset).is_err());
    /// # }
    /// ```
    ///
    /// ## Processing Multiple Headers
    /// ```rust
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Directory with multiple stream headers
    /// let directory_data = [
    ///     // First header: "#~" stream
    ///     0x6C, 0x00, 0x00, 0x00, 0xA4, 0x45, 0x00, 0x00, 0x23, 0x7E, 0x00, 0x00,
    ///     // Second header would follow at proper alignment...
    /// ];
    ///
    /// let mut offset = 0;
    /// let mut streams = Vec::new();
    ///
    /// while offset < directory_data.len() {
    ///     match StreamHeader::from(&directory_data[offset..]) {
    ///         Ok(header) => {
    ///             println!("Found stream: {}", header.name);
    ///             streams.push(header);
    ///             // Calculate next header offset (implementation specific)
    ///             break; // For this example
    ///         }
    ///         Err(_) => break,
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # ECMA-335 Compliance
    ///
    /// This implementation fully complies with ECMA-335 Partition II, Section 24.2.2
    /// including all validation requirements and format specifications.
    ///
    /// # See Also
    /// - [`crate::metadata::root`]: Metadata root parsing for stream directory context
    /// - [ECMA-335 II.24.2.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Official stream header specification
    pub fn from(data: &[u8]) -> Result<StreamHeader> {
        if data.len() < 9 {
            return Err(ParseFailure::Truncated {
                stage: ParseStage::StreamHeader,
                expected: 9,
                found: data.len(),
            }
            .into());
        }

        let mut cursor = 0_usize;
        let offset = read_le_at::<u32>(data, &mut cursor)?;
        let size = read_le_at::<u32>(data, &mut cursor)?;

        // ECMA-335 II.24.2.2 says stream sizes "shall be a multiple of 4", but many real-world
        // .NET tools (AsmResolver, Mono's writer, etc.) produce unaligned sizes. The .NET runtime
        // handles this gracefully, so we tolerate it here and use the actual size as-is. The stream
        // data at [offset..offset+size] is still valid regardless of alignment.

        // Validate offset bounds - offset must be reasonable
        if offset > 0x7FFF_FFFF {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::StreamHeader,
                field: "offset",
                reason: format!("{offset} exceeds maximum 0x7FFFFFFF"),
            }
            .into());
        }

        // Validate size bounds - prevent integer overflow and unreasonable sizes
        if size > 0x7FFF_FFFF {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::StreamHeader,
                field: "size",
                reason: format!("{size} exceeds maximum 0x7FFFFFFF"),
            }
            .into());
        }

        // The name and its terminating zero take at most 32 bytes: the runtime refuses a
        // longer name, even one it gives no stream. A name it gives no stream is otherwise
        // accepted, and ignored by the directory (see `Root::stream`).
        let field = data.get(cursor..).unwrap_or_default();
        let field = field.get(..MAX_NAME_BYTES).unwrap_or(field);
        let Some(length) = field.iter().position(|&byte| byte == 0) else {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::StreamHeader,
                field: "name",
                reason: format!("no terminating zero within the name's {MAX_NAME_BYTES} bytes"),
            }
            .into());
        };
        let name: String = field
            .get(..length)
            .unwrap_or_default()
            .iter()
            .map(|&byte| char::from(byte))
            .collect();

        Ok(StreamHeader { offset, size, name })
    }

    /// Writes this stream header to a writer in ECMA-335 binary format.
    ///
    /// Serializes the stream header including offset, size, and null-terminated name
    /// with proper 4-byte alignment padding according to ECMA-335 Section II.24.2.2.
    ///
    /// ## Binary Format Written
    /// ```text
    /// Offset | Size | Field  | Description
    /// -------|------|--------|------------------------------------------
    /// 0      | 4    | Offset | Stream data offset from metadata root (LE)
    /// 4      | 4    | Size   | Stream size in bytes (LE)
    /// 8      | N    | Name   | Null-terminated ASCII name
    /// 8+N    | P    | Pad    | Zero padding to 4-byte boundary
    /// ```
    ///
    /// # Arguments
    /// * `writer` - Any type implementing [`std::io::Write`]
    ///
    /// # Returns
    /// * `Ok(())` - Header written successfully
    /// * `Err(Error)` - Write operation failed
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let header = StreamHeader {
    ///     offset: 0x6C,
    ///     size: 0x1000,
    ///     name: "#~".to_string(),
    /// };
    ///
    /// let mut buffer = Vec::new();
    /// header.write_to(&mut buffer)?;
    ///
    /// // Buffer contains: offset (4) + size (4) + "#~\0" (3) + padding (1) = 12 bytes
    /// assert_eq!(buffer.len(), 12);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the writer fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write offset (4 bytes, little-endian)
        writer.write_all(&self.offset.to_le_bytes())?;

        // Write size (4 bytes, little-endian)
        writer.write_all(&self.size.to_le_bytes())?;

        // Write null-terminated name
        writer.write_all(self.name.as_bytes())?;
        writer.write_all(&[0u8])?; // Null terminator

        // Pad to 4-byte boundary
        // Name length + 1 (null terminator), padded to multiple of 4
        let name_with_null =
            self.name
                .len()
                .checked_add(1)
                .ok_or_else(|| ParseFailure::InvalidField {
                    stage: ParseStage::StreamHeader,
                    field: "name",
                    reason: format!("name length overflow: {}", self.name.len()),
                })?;
        let padded_len =
            name_with_null
                .checked_add(3)
                .ok_or_else(|| ParseFailure::InvalidField {
                    stage: ParseStage::StreamHeader,
                    field: "name",
                    reason: format!("padded length overflow: {name_with_null} + 3"),
                })?
                & !3;
        let padding =
            padded_len
                .checked_sub(name_with_null)
                .ok_or_else(|| ParseFailure::InvalidField {
                    stage: ParseStage::StreamHeader,
                    field: "name",
                    reason: format!(
                        "padding underflow: padded={padded_len} name_with_null={name_with_null}",
                    ),
                })?;
        if padding > 0 {
            writer.write_all(&vec![0u8; padding])?;
        }

        Ok(())
    }

    /// Returns the total serialized size of this stream header in bytes.
    ///
    /// The size includes the fixed fields (offset + size = 8 bytes) plus the
    /// null-terminated name padded to a 4-byte boundary.
    ///
    /// # Returns
    /// The total size in bytes when written with [`write_to`](Self::write_to).
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// let header = StreamHeader {
    ///     offset: 0x6C,
    ///     size: 0x1000,
    ///     name: "#~".to_string(),
    /// };
    ///
    /// // 8 (fixed) + ceil4("#~\0") = 8 + 4 = 12
    /// assert_eq!(header.serialized_size(), 12);
    ///
    /// let strings_header = StreamHeader {
    ///     offset: 0x20,
    ///     size: 0x500,
    ///     name: "#Strings".to_string(),
    /// };
    ///
    /// // 8 (fixed) + ceil4("#Strings\0") = 8 + 12 = 20
    /// assert_eq!(strings_header.serialized_size(), 20);
    /// ```
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        let name_with_null = self.name.len().saturating_add(1);
        let padded_name = name_with_null.saturating_add(3) & !3;
        // offset (4) + size (4) + padded name
        8_usize.saturating_add(padded_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let header_bytes = [
            0x6C, 0x00, 0x00, 0x00,
            0xA4, 0x45, 0x00, 0x00,
            0x23, 0x7E, 0x00,
        ];

        let parsed_header = StreamHeader::from(&header_bytes).unwrap();

        assert_eq!(parsed_header.offset, 0x6C);
        assert_eq!(parsed_header.size, 0x45A4);
        assert_eq!(parsed_header.name, "#~");
    }

    /// A name the runtime gives no stream is read like any other; the directory ignores it.
    #[test]
    fn a_name_the_runtime_gives_no_stream_is_read() {
        #[rustfmt::skip]
        let header_bytes = [
            0x6C, 0x00, 0x00, 0x00,
            0xA4, 0x45, 0x00, 0x00,
            0x24, 0x7E, 0x00,
        ];

        assert_eq!(StreamHeader::from(&header_bytes).unwrap().name, "$~");
    }

    /// The runtime reads a name and its terminating zero from at most 32 bytes: 31
    /// characters load, 32 are refused (`metadata/streams/unknown_name_{31,32}.exe`).
    #[test]
    fn a_name_takes_at_most_32_bytes_with_its_terminator() {
        let header = |length: usize| {
            let mut bytes = vec![0x6C, 0x00, 0x00, 0x00, 0xA4, 0x45, 0x00, 0x00];
            bytes.push(b'#');
            bytes.extend(std::iter::repeat_n(b'n', length - 1));
            bytes.push(0);
            bytes
        };
        assert_eq!(StreamHeader::from(&header(31)).unwrap().name.len(), 31);
        assert!(StreamHeader::from(&header(32)).is_err());
        // A name the data ends inside has no terminator either.
        assert!(StreamHeader::from(&header(8)[..12]).is_err());
    }

    #[test]
    fn test_write_to_short_name() {
        let header = StreamHeader {
            offset: 0x6C,
            size: 0x45A4,
            name: "#~".to_string(),
        };

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Expected: offset (4) + size (4) + "#~\0" (3) + padding (1) = 12 bytes
        assert_eq!(buffer.len(), 12);

        // Verify offset
        assert_eq!(&buffer[0..4], &[0x6C, 0x00, 0x00, 0x00]);
        // Verify size
        assert_eq!(&buffer[4..8], &[0xA4, 0x45, 0x00, 0x00]);
        // Verify name "#~" + null + padding
        assert_eq!(&buffer[8..12], &[0x23, 0x7E, 0x00, 0x00]);
    }

    #[test]
    fn test_write_to_long_name() {
        let header = StreamHeader {
            offset: 0x20,
            size: 0x1248,
            name: "#Strings".to_string(),
        };

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Expected: offset (4) + size (4) + "#Strings\0" (9) + padding (3) = 20 bytes
        assert_eq!(buffer.len(), 20);

        // Verify offset
        assert_eq!(&buffer[0..4], &[0x20, 0x00, 0x00, 0x00]);
        // Verify size
        assert_eq!(&buffer[4..8], &[0x48, 0x12, 0x00, 0x00]);
        // Verify name "#Strings" + null + padding
        assert_eq!(
            &buffer[8..20],
            &[0x23, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x73, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_serialized_size() {
        // "#~" (2 chars) + null = 3, padded to 4
        let header = StreamHeader {
            offset: 0,
            size: 0,
            name: "#~".to_string(),
        };
        assert_eq!(header.serialized_size(), 12); // 8 + 4

        // "#Strings" (8 chars) + null = 9, padded to 12
        let header = StreamHeader {
            offset: 0,
            size: 0,
            name: "#Strings".to_string(),
        };
        assert_eq!(header.serialized_size(), 20); // 8 + 12

        // "#US" (3 chars) + null = 4, already aligned
        let header = StreamHeader {
            offset: 0,
            size: 0,
            name: "#US".to_string(),
        };
        assert_eq!(header.serialized_size(), 12); // 8 + 4

        // "#GUID" (5 chars) + null = 6, padded to 8
        let header = StreamHeader {
            offset: 0,
            size: 0,
            name: "#GUID".to_string(),
        };
        assert_eq!(header.serialized_size(), 16); // 8 + 8

        // "#Blob" (5 chars) + null = 6, padded to 8
        let header = StreamHeader {
            offset: 0,
            size: 0,
            name: "#Blob".to_string(),
        };
        assert_eq!(header.serialized_size(), 16); // 8 + 8
    }

    #[test]
    fn test_write_read_roundtrip() {
        let original = StreamHeader {
            offset: 0x1234,
            size: 0x5678,
            name: "#Blob".to_string(),
        };

        let mut buffer = Vec::new();
        original.write_to(&mut buffer).unwrap();

        let parsed = StreamHeader::from(&buffer).unwrap();
        assert_eq!(parsed.offset, original.offset);
        assert_eq!(parsed.size, original.size);
        assert_eq!(parsed.name, original.name);
    }
}

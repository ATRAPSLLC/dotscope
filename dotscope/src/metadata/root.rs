//! Metadata root header and stream directory for .NET assemblies.
//!
//! This module defines the [`crate::metadata::root::Root`] struct, which represents the root metadata header and stream
//! directory as specified by ECMA-335. It provides access to all metadata streams, version info,
//! and structural metadata required for parsing .NET assemblies.
//!
//! # Overview
//!
//! The metadata root is the entry point for reading .NET assembly metadata. It contains the version
//! string, stream directory, and other header fields required to locate and interpret all metadata
//! streams (such as `#~`, `#Strings`, `#Blob`, etc.).
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::metadata::root::Root;
//! let root = Root::read(&[
//!            0x42, 0x53, 0x4A, 0x42,
//!            0x00, 0x20,
//!            0x00, 0x30,
//!            0x00, 0x00, 0x00, 0x40,
//!            0x05, 0x00, 0x00, 0x00,
//!            b'H', b'E', b'L', b'L', b'O',
//!            0x00, 0x60,
//!            0x01, 0x00,
//!            0x1, 0x00, 0x00, 0x00, // StreamHeader
//!            0x5, 0x00, 0x00, 0x00,
//!            0x23, 0x7E, 0x00,
//!        ])?;
//! println!("Metadata version: {}", root.version);
//! for stream in &root.stream_headers {
//!     println!("Stream: {} (offset: {}, size: {})", stream.name, stream.offset, stream.size);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//!
//! - [ECMA-335 II.24.2.1: Metadata root](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use std::io::Write;

use crate::{
    metadata::streams::StreamHeader,
    utils::{read_le, read_le_at},
    Error, ParseFailure, ParseStage, Result,
};

/// The MAGIC value indicating the CIL header ("BSJB" in ASCII).
pub const CIL_HEADER_MAGIC: u32 = 0x424A_5342;

/// Minimum size in bytes required for a valid metadata root header.
/// This includes: signature(4) + major_version(2) + minor_version(2) + reserved(4) +
/// length(4) + version_string(min 4) + flags(2) + stream_number(2) + stream_header(min 12).
const MIN_ROOT_HEADER_SIZE: usize = 36;

/// Offset in the root header where the version string length field is located.
const VERSION_LENGTH_OFFSET: usize = 12;

/// Offset in the root header where the version string begins.
const VERSION_STRING_OFFSET: u16 = 16;

/// Size of the flags field following the version string.
const FLAGS_FIELD_SIZE: usize = 2;

/// Size of the stream count field.
const STREAM_COUNT_FIELD_SIZE: usize = 2;

/// The most bytes the version string takes with its terminator (ECMA-335 II.24.2.1).
const MAX_VERSION_STRING_LENGTH: usize = 255;

/// The stream whose presence makes the runtime read the first of repeated heap headers.
const SCHEMA_STREAM_NAME: &str = "#Schema";

/// Minimum size in bytes for a valid stream header.
/// This includes: offset(4) + size(4) + name(min 1 char + null terminator = 2, aligned to 4).
const MIN_STREAM_HEADER_SIZE: usize = 12;

/// Size of the fixed fields in a stream header (offset + size).
const STREAM_HEADER_FIXED_SIZE: usize = 8;

/// Field offsets within the root header for fixed-position fields.
const FIELD_OFFSET_MAJOR_VERSION: usize = 4;
const FIELD_OFFSET_MINOR_VERSION: usize = 6;
const FIELD_OFFSET_RESERVED: usize = 8;

/// Represents the metadata root header and stream directory of a .NET assembly.
///
/// The Root structure is the entry point for all .NET assembly metadata parsing, containing
/// the metadata header information and directory of all available metadata streams. It follows
/// the ECMA-335 specification for physical metadata layout and provides access to version
/// information, stream locations, and structural metadata.
///
/// This structure is typically the first metadata component parsed when analyzing a .NET assembly,
/// as it provides the roadmap for locating all other metadata streams such as the tables stream (`#~`),
/// strings heap (`#Strings`), GUID heap (`#GUID`), blob heap (`#Blob`), and user strings heap (`#US`).
///
/// # Physical Layout
///
/// The metadata root follows this binary structure:
/// ```text
/// Offset | Size | Field           | Description
/// -------|------|-----------------|---------------------------
/// 0x00   | 4    | Signature       | Magic: 0x424A5342 ("BSJB")
/// 0x04   | 2    | MajorVersion    | Metadata format major version
/// 0x06   | 2    | MinorVersion    | Metadata format minor version  
/// 0x08   | 4    | Reserved        | Always 0
/// 0x0C   | 4    | Length          | Length of version string
/// 0x10   | N    | Version         | Version string (null-terminated)
/// ...    | 2    | Flags           | Reserved, always 0
/// ...    | 2    | StreamNumber    | Number of stream headers
/// ...    | ...  | StreamHeaders   | Array of stream headers
/// ```
///
/// # Stream Directory
///
/// The Root contains a directory of all metadata streams, each described by a [`crate::metadata::streams::StreamHeader`]
/// that specifies the stream's name, offset, and size. Common streams include:
/// - `#~` or `#-`: Compressed metadata tables stream
/// - `#Strings`: String heap for identifiers and names
/// - `#GUID`: GUID heap for type and assembly identifiers
/// - `#Blob`: Binary blob heap for signatures and complex data
/// - `#US`: User strings heap for string literals
///
/// # Examples
///
/// ## Basic Root Parsing
///
/// ```rust,no_run
/// use dotscope::metadata::root::Root;
///
/// let root = Root::read(&[
///     0x42, 0x53, 0x4A, 0x42,  // Magic signature "BSJB"
///     0x01, 0x00,              // Major version 1
///     0x00, 0x00,              // Minor version 0
///     0x00, 0x00, 0x00, 0x00,  // Reserved
///     0x0C, 0x00, 0x00, 0x00,  // Version string length
///     b'v', b'4', b'.', b'0',  // Version string "v4.0.30319"
///     b'.', b'3', b'0', b'3',
///     b'1', b'9', 0x00, 0x00,  // Null terminated + padding
///     0x00, 0x00,              // Flags
///     0x01, 0x00,              // Stream count: 1
///     0x5C, 0x00, 0x00, 0x00,  // Stream offset
///     0x08, 0x00, 0x00, 0x00,  // Stream size
///     b'#', b'~', 0x00, 0x00,  // Stream name "#~" + padding
/// ])?;
///
/// println!("Metadata version: {}", root.version);
/// println!("Found {} streams", root.stream_headers.len());
/// for stream in &root.stream_headers {
///     println!("Stream '{}' at offset 0x{:X}, size {} bytes",
///              stream.name, stream.offset, stream.size);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Stream Directory Analysis
///
/// ```rust,no_run
/// use dotscope::metadata::root::Root;
///
/// # let metadata_bytes = &[0u8; 100]; // placeholder
/// let root = Root::read(metadata_bytes)?;
///
/// // The streams the runtime reads (a directory may repeat a name; see `Root::stream`)
/// if let Some(tables_stream) = root.tables_stream() {
///     println!("Tables stream at offset 0x{:X}", tables_stream.offset);
/// }
///
/// if let Some(strings_stream) = root.stream("#Strings") {
///     println!("Strings heap at offset 0x{:X}", strings_stream.offset);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The Root structure performs automatic validation during parsing:
/// - Verifies the magic signature matches `0x424A5342`
/// - Reads the version string as UTF-8 up to its null terminator, and refuses one that takes
///   more than 255 bytes with it
/// - Refuses the stream directories the runtime refuses: a header reaching past the
///   metadata, a name longer than 32 bytes with its terminator, more than one tables
///   stream, and `#Schema` before the tables stream
///
/// # Thread Safety
///
/// Root instances are immutable after creation and safe to share across threads.
/// All fields use thread-safe types and no internal mutability is required.
///
/// # References
///
/// - [ECMA-335 II.24.2.1: Metadata root](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
/// - [ECMA-335 II.24.2.2: Stream header](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// Magic signature identifying valid metadata: `0x424A5342` ("BSJB" in ASCII).
    ///
    /// This field must always contain the value [`CIL_HEADER_MAGIC`] for the metadata
    /// to be considered valid by the .NET runtime and analysis tools.
    pub signature: u32,

    /// Major version number of the metadata format.
    ///
    /// Typically 1 for most .NET Framework and .NET Core assemblies. This indicates
    /// the overall structure and capabilities of the metadata format.
    pub major_version: u16,

    /// Minor version number of the metadata format.
    ///
    /// Usually 1 for .NET Framework 2.0+ assemblies. Combined with `major_version`,
    /// this determines the exact metadata format specification being used.
    pub minor_version: u16,

    /// Reserved field, always 0.
    ///
    /// This field is reserved for future use and should always contain zero
    /// in valid .NET assemblies.
    pub reserved: u32,

    /// Length in bytes of the version string that follows.
    ///
    /// This includes the null terminator and any padding bytes required to
    /// align the following fields to 4-byte boundaries.
    pub length: u32,

    /// Version string identifying the .NET runtime version: the field's text up to its null
    /// terminator, without the padding that follows.
    ///
    /// Common values include:
    /// - `"v2.0.50727"` for .NET Framework 2.0/3.0/3.5
    /// - `"v4.0.30319"` for .NET Framework 4.0+
    /// - Various strings for .NET Core/.NET 5+ assemblies
    pub version: String,

    /// Reserved flags field, always 0.
    ///
    /// This field is reserved for future use and should always contain zero
    /// in current .NET assemblies.
    pub flags: u16,

    /// Number of metadata streams in the stream directory.
    ///
    /// Typical assemblies have 3-5 streams (tables, strings, GUID, blob, and optionally user strings).
    /// This count determines how many [`crate::metadata::streams::StreamHeader`] entries follow.
    pub stream_number: u16,

    /// Every stream header of the directory, in directory order.
    ///
    /// A directory may repeat a name and hold names the runtime gives no stream; the header
    /// the runtime reads for a name is [`Root::stream`]'s answer, and the rest are
    /// [`Root::unread_streams`]. Common streams include:
    /// - `#~` or `#-`: Compressed metadata tables
    /// - `#Strings`: String heap for identifiers  
    /// - `#GUID`: GUID heap for type references
    /// - `#Blob`: Binary blob heap for signatures
    /// - `#US`: User strings heap for literals
    pub stream_headers: Vec<StreamHeader>,
}

/// The stream names the runtime gives a stream; any other is ignored.
const KNOWN_STREAM_NAMES: [&str; 6] = ["#~", "#-", "#Strings", "#US", "#Blob", "#GUID"];

/// Whether `name` names a tables stream.
fn is_tables_stream(name: &str) -> bool {
    name == "#~" || name == "#-"
}

impl Root {
    /// Parses a metadata root header from binary data.
    ///
    /// This method reads and validates the complete metadata root structure including the
    /// magic signature, version information, and stream directory. It performs comprehensive
    /// validation to ensure the metadata conforms to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the metadata root header and stream directory.
    ///   Must start at the beginning of the metadata root structure.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<Root>`] containing the parsed root structure, or an error
    /// if parsing fails due to invalid data, malformed headers, or insufficient bytes.
    ///
    /// # Validation Performed
    ///
    /// This method performs extensive validation during parsing:
    /// - Verifies minimum required data length (36 bytes)
    /// - Validates magic signature matches [`CIL_HEADER_MAGIC`] (`0x424A5342`)
    /// - Reads the version string as UTF-8 up to its null terminator, and refuses one that
    ///   takes more than 255 bytes with it
    /// - Refuses the stream directories the runtime refuses: a header reaching past the
    ///   metadata, a name longer than 32 bytes with its terminator, more than one tables
    ///   stream, and `#Schema` before the tables stream
    ///
    /// # Binary Format
    ///
    /// The expected binary layout is:
    /// ```text
    /// Offset | Size | Field         | Description
    /// -------|------|---------------|---------------------------
    /// 0x00   | 4    | Signature     | Magic: 0x424A5342 ("BSJB")
    /// 0x04   | 2    | MajorVersion  | Format major version
    /// 0x06   | 2    | MinorVersion  | Format minor version
    /// 0x08   | 4    | Reserved      | Always 0
    /// 0x0C   | 4    | Length        | Version string length
    /// 0x10   | N    | Version       | Null-terminated version string
    /// ...    | 2    | Flags         | Reserved, always 0
    /// ...    | 2    | StreamNumber  | Number of streams
    /// ...    | ...  | StreamHeaders | Stream directory entries
    /// ```
    ///
    /// # Examples
    ///
    /// ## Basic Parsing
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::root::Root;
    ///
    /// // Parse metadata root from assembly bytes
    /// # let metadata_bytes = &[0u8; 100]; // placeholder
    /// let root = Root::read(metadata_bytes)?;
    ///
    /// println!("Metadata version: {}", root.version);
    /// println!("Stream count: {}", root.stream_headers.len());
    ///
    /// // Validate magic signature
    /// assert_eq!(root.signature, 0x424A5342);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## Stream Directory Access
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::root::Root;
    ///
    /// # let metadata_bytes = &[0u8; 100]; // placeholder
    /// let root = Root::read(metadata_bytes)?;
    ///
    /// // Find the tables stream
    /// let tables_stream = root.tables_stream().expect("Tables stream not found");
    ///
    /// println!("Tables stream at offset 0x{:X}, size {} bytes",
    ///          tables_stream.offset, tables_stream.size);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: If the data slice is too short for the required fields
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: If the magic signature is invalid, version string is malformed,
    ///   or stream directory is inconsistent
    /// - [`crate::Error::TypeError`]: If integer overflow occurs during parsing
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads
    /// as it performs no mutations and uses only stack-allocated temporary variables.
    pub fn read(data: &[u8]) -> Result<Root> {
        let invalid = |field: &'static str, reason: String| ParseFailure::InvalidField {
            stage: ParseStage::MetadataRoot,
            field,
            reason,
        };
        let oob = || ParseFailure::OutOfBounds {
            stage: ParseStage::MetadataRoot,
        };

        if data.len() < MIN_ROOT_HEADER_SIZE {
            return Err(ParseFailure::Truncated {
                stage: ParseStage::MetadataRoot,
                expected: MIN_ROOT_HEADER_SIZE,
                found: data.len(),
            }
            .into());
        }

        let signature = read_le::<u32>(data)?;
        if signature != CIL_HEADER_MAGIC {
            return Err(ParseFailure::BadMagic {
                stage: ParseStage::MetadataRoot,
                expected: CIL_HEADER_MAGIC,
                found: signature,
            }
            .into());
        }

        let version_string_length = read_le_at::<u32>(data, &mut { VERSION_LENGTH_OFFSET })?;
        match version_string_length.checked_add(u32::from(VERSION_STRING_OFFSET)) {
            Some(str_end) => {
                let data_len = u32::try_from(data.len()).map_err(|_| {
                    invalid("data_length", "metadata root data length too large".into())
                })?;
                if str_end > data_len {
                    return Err(oob().into());
                }
            }
            None => {
                return Err(invalid(
                    "version_string_length",
                    format!(
                        "{version_string_length} causes integer overflow [ECMA-335 §II.24.2.1]",
                    ),
                )
                .into())
            }
        }

        // The field holds UTF-8 text up to its null terminator, then padding to four bytes
        let field_end = usize::from(VERSION_STRING_OFFSET)
            .checked_add(version_string_length as usize)
            .ok_or_else(|| invalid("version_string_offset", "offset overflow".into()))?;
        let field = data
            .get(usize::from(VERSION_STRING_OFFSET)..field_end)
            .ok_or_else(oob)?;
        let text = field.split(|&b| b == 0).next().unwrap_or_default();
        // Any text is a version: the .NET Framework 4.8, CoreCLR and Mono run an image whose
        // version is empty, does not start with `v`, or is not ASCII
        let version_string = String::from_utf8_lossy(text).into_owned();

        if text.len() >= MAX_VERSION_STRING_LENGTH {
            return Err(invalid(
                "version_string",
                format!(
                    "{} bytes with its terminator, where at most {MAX_VERSION_STRING_LENGTH} \
                     are allowed [ECMA-335 §II.24.2.1]",
                    text.len().saturating_add(1),
                ),
            )
            .into());
        }

        // Stream count is located after: the version field + FLAGS_FIELD_SIZE
        let mut stream_count_offset = field_end
            .checked_add(FLAGS_FIELD_SIZE)
            .ok_or_else(|| invalid("stream_count_offset", "offset overflow".into()))?;
        let stream_count = read_le_at::<u16>(data, &mut stream_count_offset)?;

        // Every header takes at least twelve bytes, so the root's own bytes bound the count;
        // the runtime sets no other limit (a 45-header directory loads).
        let stream_count_size = (stream_count as usize)
            .checked_mul(MIN_STREAM_HEADER_SIZE)
            .ok_or_else(|| invalid("stream_count", "size overflow".into()))?;
        if stream_count == 0 || stream_count_size > data.len() {
            return Err(invalid(
                "stream_count",
                format!(
                    "{stream_count} stream headers do not fit the metadata root's {} bytes",
                    data.len()
                ),
            )
            .into());
        }

        let mut streams = Vec::with_capacity(stream_count as usize);
        // Stream directory starts after: the version field + FLAGS_FIELD_SIZE + STREAM_COUNT_FIELD_SIZE
        let mut stream_offset = field_end
            .checked_add(FLAGS_FIELD_SIZE)
            .and_then(|v| v.checked_add(STREAM_COUNT_FIELD_SIZE))
            .ok_or_else(|| invalid("stream_directory_offset", "offset overflow".into()))?;

        for _i in 0..stream_count {
            if stream_offset > data.len() {
                return Err(oob().into());
            }

            let stream_data = data
                .get(stream_offset..)
                .ok_or_else(|| Error::from(oob()))?;
            let new_stream = StreamHeader::from(stream_data)?;

            // The runtime refuses a header whose stream reaches past the metadata, whatever
            // its name and whether or not it then reads that stream.
            let in_bounds = u32::checked_add(new_stream.offset, new_stream.size)
                .is_some_and(|end| end as usize <= data.len());
            if !in_bounds {
                return Err(invalid(
                    "stream_extent",
                    format!(
                        "stream '{}' at offset {} with size {} reaches past the metadata's {} bytes [ECMA-335 §II.24.2.2]",
                        new_stream.name,
                        new_stream.offset,
                        new_stream.size,
                        data.len()
                    ),
                )
                .into());
            }

            let name_aligned = new_stream
                .name
                .len()
                .checked_add(1)
                .and_then(|v| v.checked_add(3))
                .ok_or_else(|| invalid("stream_name", "alignment overflow".into()))?
                & !3usize;
            stream_offset = stream_offset
                .checked_add(STREAM_HEADER_FIXED_SIZE)
                .and_then(|v| v.checked_add(name_aligned))
                .ok_or_else(|| invalid("stream_offset", "offset overflow".into()))?;

            streams.push(new_stream);
        }

        // The two directory shapes the runtime refuses outright.
        let tables: Vec<usize> = streams
            .iter()
            .enumerate()
            .filter(|(_, s)| is_tables_stream(&s.name))
            .map(|(index, _)| index)
            .collect();
        if tables.len() > 1 {
            return Err(invalid(
                "stream_name",
                format!(
                    "{} tables streams; the runtime reads only a directory with one",
                    tables.len()
                ),
            )
            .into());
        }
        if let Some(&table) = tables.first() {
            if streams
                .iter()
                .take(table)
                .any(|s| s.name == SCHEMA_STREAM_NAME)
            {
                return Err(invalid(
                    "stream_name",
                    "'#Schema' stands before the tables stream, a directory the runtime refuses"
                        .into(),
                )
                .into());
            }
        }

        if streams.is_empty() {
            return Err(invalid(
                "streams",
                "no valid streams found [ECMA-335 §II.24.2.1]".into(),
            )
            .into());
        }

        let flags_offset = field_end;

        Ok(Root {
            signature,
            major_version: read_le::<u16>(
                data.get(FIELD_OFFSET_MAJOR_VERSION..)
                    .ok_or_else(|| Error::from(oob()))?,
            )?,
            minor_version: read_le::<u16>(
                data.get(FIELD_OFFSET_MINOR_VERSION..)
                    .ok_or_else(|| Error::from(oob()))?,
            )?,
            reserved: read_le::<u32>(
                data.get(FIELD_OFFSET_RESERVED..)
                    .ok_or_else(|| Error::from(oob()))?,
            )?,
            length: version_string_length,
            flags: read_le::<u16>(data.get(flags_offset..).ok_or_else(|| Error::from(oob()))?)?,
            stream_number: u16::try_from(streams.len()).map_err(|_| {
                invalid(
                    "stream_count",
                    "too many streams [ECMA-335 §II.24.2.1]".into(),
                )
            })?,
            stream_headers: streams,
            version: version_string,
        })
    }

    /// The tables stream (`#~` or `#-`), if the directory has one. [`Root::read`] refuses a
    /// directory with more than one.
    #[must_use]
    pub fn tables_stream(&self) -> Option<&StreamHeader> {
        self.stream_headers
            .iter()
            .find(|s| is_tables_stream(&s.name))
    }

    /// The header the runtime reads for the stream named `name`, or `None` if the directory
    /// has none of that name.
    ///
    /// A directory may repeat a heap's name, and the runtime reads one header of it by a
    /// rule measured on the .NET Framework 4.8 and CoreCLR (they agree; see
    /// `tests/samples/factory/README.md`): the first such header when the tables stream is
    /// uncompressed (`#-`) or the directory has a `#Schema` stream, and the last otherwise.
    /// The others are never read.
    #[must_use]
    pub fn stream(&self, name: &str) -> Option<&StreamHeader> {
        if is_tables_stream(name) {
            return self.tables_stream().filter(|s| s.name == name);
        }
        let mut named = self.stream_headers.iter().filter(|s| s.name == name);
        if self.reads_first_of_repeated_heaps() {
            named.next()
        } else {
            named.next_back()
        }
    }

    /// The headers the runtime does not read: names it gives no stream, and the repeats of a
    /// heap's name that [`Root::stream`] does not answer.
    pub fn unread_streams(&self) -> impl Iterator<Item = &StreamHeader> {
        self.stream_headers.iter().filter(move |header| {
            !KNOWN_STREAM_NAMES.contains(&header.name.as_str())
                || !self
                    .stream(&header.name)
                    .is_some_and(|read| std::ptr::eq(read, *header))
        })
    }

    /// Whether the runtime reads the first of repeated heap headers rather than the last.
    fn reads_first_of_repeated_heaps(&self) -> bool {
        self.stream_headers
            .iter()
            .any(|s| s.name == "#-" || s.name == SCHEMA_STREAM_NAME)
    }

    /// Validates that loaded streams do not overlap in memory
    ///
    /// This method should be called after all streams have been loaded and their actual
    /// positions and sizes are known. It performs comprehensive overlap detection that
    /// was deferred during initial parsing.
    ///
    /// # Arguments
    /// * `meta_root_offset` - The offset where the metadata root starts
    /// * `total_metadata_size` - The total size of the metadata section
    ///
    /// # Errors
    /// Returns an error if any streams overlap or extend beyond the metadata bounds
    pub fn validate_stream_layout(
        &self,
        meta_root_offset: usize,
        total_metadata_size: u32,
    ) -> Result<()> {
        let invalid = |field: &'static str, reason: String| ParseFailure::InvalidField {
            stage: ParseStage::MetadataRoot,
            field,
            reason,
        };
        let mut stream_ranges: Vec<(u32, u32, &str)> = Vec::new();

        // Validate stream doesn't exceed metadata bounds
        let metadata_end = meta_root_offset
            .checked_add(total_metadata_size as usize)
            .ok_or_else(|| {
                invalid(
                    "metadata_size",
                    format!("size causes overflow: {meta_root_offset} + {total_metadata_size}",),
                )
            })?;

        // Calculate actual stream positions
        for stream in &self.stream_headers {
            let absolute_start = meta_root_offset
                .checked_add(stream.offset as usize)
                .ok_or_else(|| {
                    invalid(
                        "stream_offset",
                        format!(
                            "stream '{}' offset causes overflow: {} + {}",
                            stream.name, meta_root_offset, stream.offset
                        ),
                    )
                })?;

            let absolute_end = absolute_start
                .checked_add(stream.size as usize)
                .ok_or_else(|| {
                    invalid(
                        "stream_size",
                        format!(
                            "stream '{}' size causes overflow: {} + {}",
                            stream.name, absolute_start, stream.size
                        ),
                    )
                })?;

            if absolute_end > metadata_end {
                return Err(invalid(
                    "stream_extent",
                    format!(
                        "stream '{}' extends beyond metadata bounds (end {} > metadata end {})",
                        stream.name, absolute_end, metadata_end
                    ),
                )
                .into());
            }

            stream_ranges.push((
                u32::try_from(absolute_start).map_err(|_| {
                    invalid(
                        "stream_start",
                        format!(
                            "stream '{}' start position {} exceeds u32 range",
                            stream.name, absolute_start
                        ),
                    )
                })?,
                u32::try_from(absolute_end).map_err(|_| {
                    invalid(
                        "stream_end",
                        format!(
                            "stream '{}' end position {} exceeds u32 range",
                            stream.name, absolute_end
                        ),
                    )
                })?,
                &stream.name,
            ));
        }

        for (i, &(start1, end1, name1)) in stream_ranges.iter().enumerate() {
            let skip = i.saturating_add(1);
            for &(start2, end2, name2) in stream_ranges.iter().skip(skip) {
                if start1 < end2 && start2 < end1 {
                    return Err(invalid(
                        "stream_overlap",
                        format!(
                            "stream '{name1}' ({start1}..{end1}) overlaps with stream '{name2}' ({start2}..{end2})",
                        ),
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    /// Writes the metadata root header to a writer in ECMA-335 binary format.
    ///
    /// Serializes the complete metadata root header including signature, version info,
    /// and stream directory according to ECMA-335 Section II.24.2.1.
    ///
    /// ## Binary Format Written
    /// ```text
    /// Offset | Size | Field        | Description
    /// -------|------|--------------|----------------------------------
    /// 0x00   | 4    | Signature    | Magic: 0x424A5342 ("BSJB")
    /// 0x04   | 2    | MajorVersion | Metadata format major version
    /// 0x06   | 2    | MinorVersion | Metadata format minor version
    /// 0x08   | 4    | Reserved     | Always 0
    /// 0x0C   | 4    | Length       | Version string length (padded)
    /// 0x10   | N    | Version      | Version string + null padding
    /// ...    | 2    | Flags        | Reserved, always 0
    /// ...    | 2    | StreamNumber | Number of stream headers
    /// ...    | ...  | Streams      | Stream header directory
    /// ```
    ///
    /// # Arguments
    /// * `writer` - Any type implementing [`std::io::Write`]
    ///
    /// # Returns
    /// * `Ok(())` - Root header written successfully
    /// * `Err(Error)` - Write operation failed
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::metadata::root::Root;
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let root = Root {
    ///     signature: 0x424A5342,
    ///     major_version: 1,
    ///     minor_version: 1,
    ///     reserved: 0,
    ///     length: 12,
    ///     version: "v4.0.30319".to_string(),
    ///     flags: 0,
    ///     stream_number: 1,
    ///     stream_headers: vec![
    ///         StreamHeader { offset: 0x6C, size: 0x1000, name: "#~".to_string() },
    ///     ],
    /// };
    ///
    /// let mut buffer = Vec::new();
    /// root.write_to(&mut buffer)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the writer fails or if the version string
    /// length exceeds u32 range.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Signature (4 bytes) - "BSJB" magic
        writer.write_all(&self.signature.to_le_bytes())?;

        // Major version (2 bytes)
        writer.write_all(&self.major_version.to_le_bytes())?;

        // Minor version (2 bytes)
        writer.write_all(&self.minor_version.to_le_bytes())?;

        // Reserved (4 bytes)
        writer.write_all(&self.reserved.to_le_bytes())?;

        // Version string length: the string, its terminator and padding to 4 bytes
        let version_bytes = self.version.as_bytes();
        let padded_len = self.version_field_size();
        let padded_len_u32 = u32::try_from(padded_len).map_err(|_| ParseFailure::InvalidField {
            stage: ParseStage::MetadataRoot,
            field: "version_string_length",
            reason: format!("padded length {padded_len} exceeds u32 range"),
        })?;
        writer.write_all(&padded_len_u32.to_le_bytes())?;

        // Version string, then its terminator and the padding
        writer.write_all(version_bytes)?;
        let padding = padded_len.saturating_sub(version_bytes.len());
        if padding > 0 {
            writer.write_all(&vec![0u8; padding])?;
        }

        // Flags (2 bytes)
        writer.write_all(&self.flags.to_le_bytes())?;

        // Stream count (2 bytes)
        writer.write_all(&self.stream_number.to_le_bytes())?;

        // Stream headers
        for stream in &self.stream_headers {
            stream.write_to(writer)?;
        }

        Ok(())
    }

    /// The bytes the version field takes when written: the version string, its null
    /// terminator and padding to a multiple of four (ECMA-335 II.24.2.1).
    #[must_use]
    pub fn version_field_size(&self) -> usize {
        self.version.len().saturating_add(4) & !3usize
    }

    /// Returns the total serialized size of this metadata root header in bytes.
    ///
    /// The size includes the fixed header fields plus the padded version string
    /// and all stream headers with their alignment padding.
    ///
    /// # Returns
    /// The total size in bytes when written with [`write_to`](Self::write_to).
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::root::Root;
    /// use dotscope::metadata::streams::StreamHeader;
    ///
    /// let root = Root {
    ///     signature: 0x424A5342,
    ///     major_version: 1,
    ///     minor_version: 1,
    ///     reserved: 0,
    ///     length: 12,
    ///     version: "v4.0.30319".to_string(),
    ///     flags: 0,
    ///     stream_number: 1,
    ///     stream_headers: vec![
    ///         StreamHeader { offset: 0x6C, size: 0x1000, name: "#~".to_string() },
    ///     ],
    /// };
    ///
    /// // Fixed: 4+2+2+4+4+2+2 = 20
    /// // Version: "v4.0.30319" (10 chars) padded to 12
    /// // Stream header: 12 bytes (for "#~")
    /// // Total: 20 + 12 + 12 = 44
    /// assert_eq!(root.serialized_size(), 44);
    /// ```
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        // Fixed fields: signature(4) + major(2) + minor(2) + reserved(4) + length(4) + flags(2) + stream_number(2)
        let fixed_size = 20usize;

        let version_padded = self.version_field_size();

        // Stream headers
        let streams_size: usize = self
            .stream_headers
            .iter()
            .map(crate::StreamHeader::serialized_size)
            .fold(0usize, usize::saturating_add);

        fixed_size
            .saturating_add(version_padded)
            .saturating_add(streams_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
            let header_bytes = [
            0x42, 0x53, 0x4A, 0x42,
            0x00, 0x20,
            0x00, 0x30,
            0x00, 0x00, 0x00, 0x40,
            0x06, 0x00, 0x00, 0x00, // length = 6 for "v4.0.0"
            b'v', b'4', b'.', b'0', b'.', b'0',
            0x00, 0x60,
            0x01, 0x00,

            0x1, 0x00, 0x00, 0x00, // StreamHeader
            0x8, 0x00, 0x00, 0x00,
            0x23, 0x7E, 0x00,
        ];

        let parsed_header = Root::read(&header_bytes).unwrap();

        assert_eq!(parsed_header.signature, CIL_HEADER_MAGIC);
        assert_eq!(parsed_header.major_version, 0x2000);
        assert_eq!(parsed_header.minor_version, 0x3000);
        assert_eq!(parsed_header.reserved, 0x40000000);
        assert_eq!(parsed_header.length, 6);
        assert_eq!(parsed_header.version, "v4.0.0");
        assert_eq!(parsed_header.flags, 0x6000);
        assert_eq!(parsed_header.stream_number, 1);
        assert_eq!(parsed_header.stream_headers.len(), 1);
        assert_eq!(parsed_header.stream_headers[0].offset, 0x1);
        assert_eq!(parsed_header.stream_headers[0].size, 0x8);
        assert_eq!(parsed_header.stream_headers[0].name, "#~");
    }

    /// The version is the field's UTF-8 text up to its terminator, and the stream directory
    /// follows the whole field: "v4.0é" is six bytes, then two of padding.
    #[test]
    fn the_version_is_utf8_text_up_to_its_terminator() {
        #[rustfmt::skip]
        let header_bytes = [
            0x42, 0x53, 0x4A, 0x42,
            0x01, 0x00,
            0x01, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            b'v', b'4', b'.', b'0', 0xC3, 0xA9, 0x00, 0x00,
            0x00, 0x00,
            0x01, 0x00,
            0x28, 0x00, 0x00, 0x00, // StreamHeader
            0x04, 0x00, 0x00, 0x00,
            0x23, 0x7E, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let root = Root::read(&header_bytes).unwrap();

        assert_eq!(root.version, "v4.0\u{e9}");
        assert_eq!(root.length, 8);
        assert_eq!(root.stream_headers[0].name, "#~");
        assert_eq!(root.stream_headers[0].offset, 0x28);
    }

    /// The runtimes run an image whose version is empty or does not start with `v` (measured
    /// on the .NET Framework 4.8, CoreCLR and Mono with TestApp's version field rewritten), so
    /// it reads.
    #[test]
    fn any_version_text_reads() {
        for version in [
            &b"\0\0\0\0"[..],
            b"x4.0\0\0\0\0",
            b"Standard CLI 2005\0\0\0",
        ] {
            let mut header_bytes = vec![0x42, 0x53, 0x4A, 0x42, 0x01, 0x00, 0x01, 0x00];
            header_bytes.extend_from_slice(&[0; 4]);
            header_bytes.extend_from_slice(&u32::try_from(version.len()).unwrap().to_le_bytes());
            header_bytes.extend_from_slice(version);
            let directory = header_bytes.len() + 4 + 12;
            header_bytes.extend_from_slice(&[0, 0, 1, 0]);
            header_bytes.extend_from_slice(&u32::try_from(directory).unwrap().to_le_bytes());
            header_bytes.extend_from_slice(&[4, 0, 0, 0, 0x23, 0x7E, 0, 0, 0, 0, 0, 0]);

            let root = Root::read(&header_bytes).unwrap();

            let text = version.split(|&b| b == 0).next().unwrap();
            assert_eq!(root.version.as_bytes(), text);
            assert_eq!(root.stream_headers[0].name, "#~");
        }
    }

    /// A version whose length is a multiple of four is written with its terminator, in a
    /// field four bytes longer, and reads back as itself.
    #[test]
    fn a_written_version_keeps_its_terminator() {
        let root = Root {
            signature: CIL_HEADER_MAGIC,
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            length: 8,
            version: "v1.2".to_string(),
            flags: 0,
            stream_number: 1,
            stream_headers: vec![StreamHeader {
                offset: 0x28,
                size: 4,
                name: "#~".to_string(),
            }],
        };
        let mut buffer = Vec::new();
        root.write_to(&mut buffer).unwrap();
        assert_eq!(&buffer[12..24], b"\x08\0\0\0v1.2\0\0\0\0");
        assert_eq!(root.serialized_size(), buffer.len());
        buffer.resize(0x2C, 0);
        assert_eq!(Root::read(&buffer).unwrap(), root);
    }

    /// The runtime refuses a directory with two tables streams (`metadata/streams/tables_*`).
    #[test]
    fn two_tables_streams_are_refused() {
        #[rustfmt::skip]
        let mut header_bytes = vec![
            0x42, 0x53, 0x4A, 0x42,  // CIL_HEADER_MAGIC
            0x00, 0x20,              // major_version
            0x00, 0x30,              // minor_version
            0x00, 0x00, 0x00, 0x40,  // reserved
            0x06, 0x00, 0x00, 0x00,  // length (version string length)
            b'v', b'4', b'.', b'0', b'.', b'0',  // version string
            0x00, 0x60,              // flags
            0x02, 0x00,              // stream_number (2 streams)

            // First StreamHeader - #~
            0x52, 0x00, 0x00, 0x00,  // offset (82 - past all headers)
            0x08, 0x00, 0x00, 0x00,  // size (8 bytes - aligned)
            0x23, 0x7E, 0x00, 0x00,  // "#~\0" + padding

            // Second StreamHeader - duplicate #~
            0x5A, 0x00, 0x00, 0x00,  // offset (90 - after first stream)
            0x08, 0x00, 0x00, 0x00,  // size (8 bytes - aligned)
            0x23, 0x7E, 0x00, 0x00,  // "#~\0" + padding (duplicate)
        ];

        // Add enough padding to reach offset 82 and then the stream data
        header_bytes.resize(98, 0x00);

        let result = Root::read(&header_bytes);
        let err = result.expect_err("a directory with two tables streams is refused");
        assert!(
            err.to_string().contains("2 tables streams"),
            "unexpected error: {err}"
        );
    }

    /// A metadata root whose directory holds `names` in order, each stream four bytes of
    /// data after the directory.
    fn directory(names: &[&str]) -> Vec<u8> {
        let mut headers = Vec::new();
        for name in names {
            let mut entry = vec![0u8; 8];
            entry.extend(name.as_bytes());
            entry.push(0);
            while !entry.len().is_multiple_of(4) {
                entry.push(0);
            }
            headers.push(entry);
        }
        let start = 16 + 4 + 4 + headers.iter().map(Vec::len).sum::<usize>();
        let mut bytes = vec![0x42, 0x53, 0x4A, 0x42, 1, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0];
        bytes.extend(b"v4\0\0");
        bytes.extend([0, 0]);
        bytes.extend(u16::try_from(names.len()).unwrap().to_le_bytes());
        for (index, mut entry) in headers.into_iter().enumerate() {
            let offset = u32::try_from(start + index * 4).unwrap();
            entry[..4].copy_from_slice(&offset.to_le_bytes());
            entry[4..8].copy_from_slice(&4u32.to_le_bytes());
            bytes.extend(entry);
        }
        bytes.resize(start + names.len() * 4, 0);
        bytes
    }

    /// The position in `names` of the header `Root::stream` answers for `name`.
    fn read_index(names: &[&str], name: &str) -> Option<usize> {
        let root = Root::read(&directory(names)).unwrap();
        let read = root.stream(name)?;
        root.stream_headers
            .iter()
            .position(|h| std::ptr::eq(h, read))
    }

    /// Repeated heap headers: the last in `#~` metadata, the first in `#-` metadata or when
    /// the directory has `#Schema` (`metadata/streams/{us,blob,guid,strings}_*`).
    #[test]
    fn repeated_heaps_read_the_header_the_runtime_reads() {
        let tilde = ["#~", "#US", "#Strings", "#US"];
        assert_eq!(read_index(&tilde, "#US"), Some(3));
        assert_eq!(read_index(&tilde, "#Strings"), Some(2));
        let uncompressed = ["#-", "#US", "#Strings", "#US"];
        assert_eq!(read_index(&uncompressed, "#US"), Some(1));
        let schema = ["#~", "#US", "#Schema", "#US"];
        assert_eq!(read_index(&schema, "#US"), Some(1));
        assert_eq!(read_index(&schema, "#~"), Some(0));
        assert_eq!(read_index(&schema, "#Blob"), None);
    }

    /// Names the runtime gives no stream are read and left unread; a directory may hold any
    /// number of headers (45 load: `metadata/streams/unknown_after_40.exe`).
    #[test]
    fn unknown_names_and_long_directories_load() {
        let mut names = vec!["#Foo", "#~", "#Strings"];
        names.extend(std::iter::repeat_n("#Unknown", 42));
        let root = Root::read(&directory(&names)).unwrap();
        assert_eq!(root.stream_headers.len(), 45);
        assert_eq!(root.unread_streams().count(), 43);
        assert!(root
            .unread_streams()
            .all(|s| s.name == "#Foo" || s.name == "#Unknown"));
    }

    /// The runtime refuses `#Schema` before the tables stream
    /// (`metadata/streams/schema_before*.exe`), and accepts it after.
    #[test]
    fn schema_before_the_tables_stream_is_refused() {
        assert!(Root::read(&directory(&["#Foo", "#Schema", "#~"])).is_err());
        assert!(Root::read(&directory(&["#~", "#Schema", "#Strings"])).is_ok());
    }

    /// The runtime refuses a header whose stream reaches past the metadata, whatever its
    /// name (`metadata/streams/*_bad_*.exe`).
    #[test]
    fn a_stream_past_the_metadata_is_refused_whatever_its_name() {
        for name in ["#Foo", "#US"] {
            let mut bytes = directory(&["#~", name]);
            let size_field = 16 + 4 + 4 + 12 + 4;
            bytes[size_field..size_field + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            assert!(Root::read(&bytes).is_err(), "{name}");
        }
    }

    #[test]
    fn test_write_to_basic() {
        let root = Root {
            signature: CIL_HEADER_MAGIC,
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            length: 12, // Will be recalculated during write
            version: "v4.0.30319".to_string(),
            flags: 0,
            stream_number: 1,
            stream_headers: vec![StreamHeader {
                offset: 0x6C,
                size: 0x1000,
                name: "#~".to_string(),
            }],
        };

        let mut buffer = Vec::new();
        root.write_to(&mut buffer).unwrap();

        // Verify signature "BSJB"
        assert_eq!(&buffer[0..4], &[0x42, 0x53, 0x4A, 0x42]);
        // Verify major version
        assert_eq!(&buffer[4..6], &[0x01, 0x00]);
        // Verify minor version
        assert_eq!(&buffer[6..8], &[0x01, 0x00]);
        // Verify reserved
        assert_eq!(&buffer[8..12], &[0x00, 0x00, 0x00, 0x00]);
        // Verify version string length (padded to 12)
        assert_eq!(&buffer[12..16], &[0x0C, 0x00, 0x00, 0x00]);
        // Verify version string starts with "v4.0"
        assert_eq!(&buffer[16..20], b"v4.0");
    }

    #[test]
    fn test_serialized_size() {
        let root = Root {
            signature: CIL_HEADER_MAGIC,
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            length: 12,
            version: "v4.0.30319".to_string(), // 10 chars, padded to 12
            flags: 0,
            stream_number: 1,
            stream_headers: vec![StreamHeader {
                offset: 0x6C,
                size: 0x1000,
                name: "#~".to_string(), // "#~" + null (3) padded to 4, + 8 fixed = 12
            }],
        };

        // Fixed: 20 bytes
        // Version: 12 bytes (10 chars padded to 12)
        // Stream header: 12 bytes
        // Total: 44 bytes
        assert_eq!(root.serialized_size(), 44);
    }

    #[test]
    fn test_serialized_size_multiple_streams() {
        let root = Root {
            signature: CIL_HEADER_MAGIC,
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            length: 12,
            version: "v4.0.30319".to_string(),
            flags: 0,
            stream_number: 3,
            stream_headers: vec![
                StreamHeader {
                    offset: 0x6C,
                    size: 0x1000,
                    name: "#~".to_string(),
                }, // 12 bytes
                StreamHeader {
                    offset: 0x106C,
                    size: 0x500,
                    name: "#Strings".to_string(),
                }, // 20 bytes
                StreamHeader {
                    offset: 0x156C,
                    size: 0x100,
                    name: "#Blob".to_string(),
                }, // 16 bytes
            ],
        };

        // Fixed: 20 bytes
        // Version: 12 bytes
        // Stream headers: 12 + 20 + 16 = 48 bytes
        // Total: 80 bytes
        assert_eq!(root.serialized_size(), 80);
    }
}

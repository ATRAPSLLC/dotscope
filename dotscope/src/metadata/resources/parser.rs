//! .NET resource file parsing infrastructure.
//!
//! This module provides comprehensive parsing capabilities for .NET resource files,
//! implementing the full .NET `ResourceManager` and `RuntimeResourceReader` format
//! specifications. It handles both V1 and V2 resource formats with support for
//! debug builds and all standard resource types.
//!
//! # Resource Format Overview
//!
//! .NET resources use a complex binary format optimized for efficient lookup and
//! type-safe deserialization. The format consists of multiple sections:
//!
//! ## Header Structure
//! 1. **Resource Manager Header**: Contains magic number, version, and type information
//! 2. **Runtime Resource Reader Header**: Contains resource count, type table, and section offsets
//! 3. **Name Section**: Contains resource names and their data offsets
//! 4. **Data Section**: Contains the actual resource data with type information
//!
//! ## Format Versions
//! - **Version 1**: Standard release format
//! - **Version 2**: Enhanced format with optional debug information
//!
//! # Key Components
//!
//! - [`parse_dotnet_resource()`] - High-level parsing function for complete resource extraction
//! - [`Resource`] - Low-level parser that exposes all format details
//! - [`crate::metadata::resources::ResourceEntry`] - Individual resource representation
//! - [`crate::metadata::resources::ResourceType`] - Typed resource data representation
//!
//! # Usage Patterns
//!
//! ## High-Level Resource Parsing
//!
//! ```no_run
//! use dotscope::metadata::resources::parse_dotnet_resource;
//!
//! // Parse complete resource file
//! let resource_data = /* ... resource file bytes ... */;
//! let resources = parse_dotnet_resource(resource_data)?;
//!
//! for (name, entry) in resources {
//!     println!("Resource: {} (Hash: 0x{:X})", name, entry.name_hash);
//!     match entry.data {
//!         ResourceType::String(ref s) => println!("  String: {}", s),
//!         ResourceType::ByteArray(ref bytes) => println!("  Binary: {} bytes", bytes.len()),
//!         _ => println!("  Other type"),
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Low-Level Resource Analysis
//!
//! ```no_run
//! use dotscope::metadata::resources::Resource;
//!
//! // Parse resource header and examine structure
//! let resource_data = /* ... resource file bytes ... */;
//! let mut resource = Resource::parse(resource_data)?;
//!
//! println!("Resource Manager Version: {}", resource.res_mgr_header_version);
//! println!("Resource Reader Version: {}", resource.rr_version);
//! println!("Resource Count: {}", resource.resource_count);
//! println!("Type Count: {}", resource.type_names.len());
//! println!("Debug Build: {}", resource.is_debug);
//!
//! // Parse individual resources
//! let resources = resource.read_resources(resource_data)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The parser implements comprehensive validation:
//! - **Magic Number Verification**: Ensures correct file format
//! - **Bounds Checking**: All data access is bounds-checked
//! - **Format Validation**: Header consistency and section alignment checks
//! - **Type Safety**: Resource type validation during deserialization

use std::collections::BTreeMap;

use crate::{
    file::parser::Parser,
    metadata::resources::{
        ResourceEntry, ResourceEntryRef, ResourceType, ResourceTypeRef, RESOURCE_MAGIC,
    },
    ParseFailure, ParseStage, Result,
};

/// Maximum number of resource types allowed in a resource file.
/// Real-world .NET resource files typically have < 50 types.
const MAX_RESOURCE_TYPES: u32 = 4096;

/// Maximum number of resources allowed in a resource file.
/// Real-world .NET resource files typically have < 10,000 resources.
const MAX_RESOURCES: u32 = 1_000_000;

/// Parse a complete .NET resource buffer into a collection of named resources.
///
/// This is the primary entry point for resource parsing, providing a high-level
/// interface that handles all the complexity of the .NET resource format. It
/// performs complete parsing and returns a map of resource names to their
/// corresponding data and metadata.
///
/// # Format Support
///
/// - **V1 Resources**: Standard release format
/// - **V2 Resources**: Enhanced format with optional debug information
/// - **All Resource Types**: Strings, primitives, byte arrays, and complex objects
///
/// # Arguments
///
/// * `data` - Complete resource file data starting with the resource header
///
/// # Returns
///
/// A `BTreeMap<String, ResourceEntry>` containing all parsed resources, sorted
/// by name for consistent iteration order.
///
/// # Errors
///
/// Returns an error if:
/// - The data is too small to contain a valid resource header
/// - The magic number doesn't match the expected value (0xBEEFCACE)
/// - Header versions are unsupported or malformed
/// - Resource data sections are truncated or corrupted
/// - Individual resource entries cannot be parsed
///
/// # Examples
///
/// ```no_run
/// use dotscope::metadata::resources::parse_dotnet_resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resources = parse_dotnet_resource(&resource_data)?;
///
/// println!("Found {} resources:", resources.len());
/// for (name, entry) in &resources {
///     println!("  {}: {:?}", name, entry.data);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn parse_dotnet_resource(data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
    let mut resource = Resource::parse(data)?;
    resource.read_resources(data)
}

/// Parse a complete .NET resource buffer with zero-copy semantics.
///
/// This is the zero-copy variant of [`parse_dotnet_resource`]. Instead of allocating
/// owned copies of resource data, it returns borrowed slices directly into the source
/// data buffer. This is the recommended entry point when working with large embedded
/// resources (like ZIP archives) that could be hundreds of megabytes or gigabytes.
///
/// # Format Support
///
/// - **V1 Resources**: Standard release format
/// - **V2 Resources**: Enhanced format with optional debug information
/// - **All Resource Types**: Strings, primitives, byte arrays, and complex objects
/// - **Zero-Copy Data**: String and byte array resources borrow from source buffer
///
/// # Arguments
///
/// * `data` - Complete resource file data starting with the resource header
///
/// # Lifetime
///
/// The returned resources borrow from the `data` parameter. All borrowed resource data
/// (strings and byte arrays) will remain valid as long as `data` is valid.
///
/// # Returns
///
/// A `BTreeMap<String, ResourceEntryRef>` containing all parsed resources with borrowed
/// data, sorted by name for consistent iteration order.
///
/// # Errors
///
/// Returns an error if:
/// - The data is too small to contain a valid resource header
/// - The magic number doesn't match the expected value (0xBEEFCACE)
/// - Header versions are unsupported or malformed
/// - Resource data sections are truncated or corrupted
/// - Individual resource entries cannot be parsed
///
/// # Examples
///
/// ## Basic Usage
///
/// ```no_run
/// use dotscope::metadata::resources::parse_dotnet_resource_ref;
/// use dotscope::metadata::resources::ResourceTypeRef;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resources = parse_dotnet_resource_ref(&resource_data)?;
///
/// println!("Found {} resources:", resources.len());
/// for (name, entry) in &resources {
///     match &entry.data {
///         ResourceTypeRef::ByteArray(bytes) => {
///             println!("  {}: {} bytes (no copy!)", name, bytes.len());
///         }
///         ResourceTypeRef::String(s) => {
///             println!("  {}: \"{}\"", name, s);
///         }
///         _ => {
///             println!("  {}: {:?}", name, entry.data);
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Extracting Embedded ZIP Archives
///
/// ```no_run
/// use dotscope::metadata::resources::parse_dotnet_resource_ref;
/// use dotscope::metadata::resources::ResourceTypeRef;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resources = parse_dotnet_resource_ref(&resource_data)?;
///
/// // Find and extract ZIP files without copying data
/// for (name, entry) in &resources {
///     if let ResourceTypeRef::ByteArray(bytes) = &entry.data {
///         if bytes.starts_with(b"PK\x03\x04") {
///             println!("Found ZIP: {} ({} bytes)", name, bytes.len());
///
///             // Process ZIP directly from borrowed slice - no allocation!
///             let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
///             for i in 0..archive.len() {
///                 let file = archive.by_index(i)?;
///                 println!("  - {}", file.name());
///             }
///         }
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// For small resources or when data needs to outlive the source buffer, consider
/// using [`parse_dotnet_resource`] instead.
pub fn parse_dotnet_resource_ref(data: &[u8]) -> Result<BTreeMap<String, ResourceEntryRef<'_>>> {
    let mut resource = Resource::parse(data)?;
    resource.read_resources_ref(data)
}

/// Low-level parser for .NET `ResourceManager` format with complete format exposure.
///
/// This struct provides direct access to all aspects of the .NET resource format,
/// enabling detailed analysis and custom parsing scenarios. It implements the full
/// specification from `CoreCLR` for both V1 and V2 resource formats.
///
/// # Format Structure
///
/// The `Resource` parser exposes all sections of the .NET resource format:
///
/// ## Resource Manager Header
/// - Magic number validation (0xBEEFCACE)
/// - Version information and header sizing
/// - Type information for resource reader and resource set classes
///
/// ## Runtime Resource Reader Header  
/// - Resource reader version (1 or 2)
/// - Optional debug information for V2 debug builds
/// - Resource and type counts
/// - Type name table for all resource types used
///
/// ## Hash and Position Tables
/// - Pre-computed hash values for fast resource lookup
/// - Virtual offsets into the name section for each resource
/// - Data section absolute offset
///
/// ## Use Cases
///
/// - **Format Analysis**: Examining resource file structure and metadata
/// - **Custom Parsing**: Implementing specialized resource extraction logic
/// - **Debugging**: Investigating resource file corruption or format issues
/// - **Research**: Understanding .NET resource format implementation details
///
/// # Examples
///
/// ## Format Analysis
///
/// ```no_run
/// use dotscope::metadata::resources::Resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resource = Resource::parse(&resource_data)?;
///
/// println!("=== Resource Format Analysis ===");
/// println!("Manager Version: {}", resource.res_mgr_header_version);
/// println!("Reader Version: {}", resource.rr_version);
/// println!("Header Size: {} bytes", resource.header_size);
/// println!("Debug Build: {}", resource.is_debug);
/// println!("Resources: {}", resource.resource_count);
/// println!("Types: {}", resource.type_names.len());
/// println!("Padding: {} bytes", resource.padding);
///
/// println!("\nType Table:");
/// for (i, type_name) in resource.type_names.iter().enumerate() {
///     println!("  [{}] {}", i, type_name);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Custom Resource Processing
///
/// ```no_run
/// use dotscope::metadata::resources::Resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let mut resource = Resource::parse(&resource_data)?;
///
/// // Access hash table for fast lookups
/// for (i, hash) in resource.name_hashes.iter().enumerate() {
///     println!("Resource {}: Hash=0x{:08X}, Offset={}",
///              i, hash, resource.name_positions[i]);
/// }
///
/// // Parse all resources with full control
/// let resources = resource.read_resources(&resource_data)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Format Details from `CoreCLR`
///
/// From `CoreCLR` documentation, the system default file format (V1) is:
///
/// ```text
/// What                                               Type of Data
/// ====================================================   ===========
///
///                        Resource Manager header
/// Magic Number (0xBEEFCACE)                               Int32
/// Resource Manager header version                         Int32
/// Num bytes to skip from here to get past this header     Int32
/// Class name of IResourceReader to parse this file        String
/// Class name of ResourceSet to parse this file            String
///
///                       RuntimeResourceReader header
/// ResourceReader version number                           Int32
/// [Only in debug V2 builds - "***DEBUG***"]               String
/// Number of resources in the file                         Int32
/// Number of types in the type table                       Int32
/// Name of each type                                       Set of Strings
/// Padding bytes for 8-byte alignment (use PAD)            Bytes (0-7)
/// Hash values for each resource name                      Int32 array, sorted
/// Virtual offset of each resource name                    Int32 array, coupled with hash values
/// Absolute location of Data section                       Int32
///
///                     RuntimeResourceReader Name Section
/// Name & virtual offset of each resource                  Set of (UTF-16 String, Int32) pairs
///
///                     RuntimeResourceReader Data Section
/// Type and Value of each resource                         Set of (Int32, blob of bytes) pairs
/// ```
///
/// # Thread Safety
///
/// `Resource` is not thread-safe due to mutable parsing state. Create separate
/// instances for concurrent parsing operations.
///
/// # Memory Efficiency
///
/// The parser uses streaming techniques to minimize memory allocation:
/// - String data is parsed directly from source buffer when possible
/// - Binary data maintains references to original data
/// - Type information is stored efficiently in vectors
#[derive(Default)]
pub struct Resource {
    /// Resource Manager header version
    pub res_mgr_header_version: u32,
    /// Size of the header
    pub header_size: u32,
    /// Class name of `IResourceReader` to parse this file
    pub reader_type: String,
    /// Class name of `ResourceSet` to parse this file
    pub resource_set_type: String,
    /// Offset of the `ResourceReader` Header
    pub rr_header_offset: usize,
    /// `ResourceReader` version number
    pub rr_version: u32,
    /// Number of resources in the file
    pub resource_count: u32,
    /// The type table - names of the types used in resources
    pub type_names: Vec<String>,
    /// The amount of padding used
    pub padding: usize,
    /// The name hash table - for faster lookups of resources by name
    pub name_hashes: Vec<u32>,
    /// Virtual offset of each resource name (in `RuntimeResourceReader` Name Section)
    pub name_positions: Vec<u32>,
    /// Absolute location of Data section
    pub data_section_offset: usize,
    /// Beginning of the name section
    pub name_section_offset: usize,
    /// Is a debug build
    pub is_debug: bool,
    /// Is this an embedded resource (with size prefix) vs standalone .resources file
    pub is_embedded_resource: bool,
}

impl Resource {
    /// Parse resource header and structure from raw data with comprehensive validation.
    ///
    /// This method performs complete parsing of the resource file header structure,
    /// including all sections up to but not including the actual resource data.
    /// It validates the format, extracts metadata, and prepares for resource enumeration.
    ///
    /// # Parsing Process
    ///
    /// 1. **Size Validation**: Verifies the data buffer is large enough
    /// 2. **Magic Number Check**: Confirms the file is a valid .NET resource
    /// 3. **Header Parsing**: Extracts version and type information
    /// 4. **Structure Analysis**: Parses type tables, hash arrays, and section offsets
    /// 5. **Offset Calculation**: Determines positions for name and data sections
    ///
    /// # Arguments
    ///
    /// * `data` - Complete resource file data buffer starting with the size header
    ///
    /// # Returns
    ///
    /// A fully initialized `Resource` parser ready for resource enumeration via
    /// [`read_resources()`](Resource::read_resources).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Data buffer is smaller than 12 bytes (minimum header size)
    /// - Size field indicates invalid or truncated data
    /// - Magic number is not 0xBEEFCACE
    /// - Header structure is malformed or truncated
    /// - Type table or hash array data is corrupted
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::Resource;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let resource = Resource::parse(&resource_data)?;
    ///
    /// println!("Parsed resource file:");
    /// println!("  Manager Version: {}", resource.res_mgr_header_version);
    /// println!("  Reader Version: {}", resource.rr_version);
    /// println!("  Resource Count: {}", resource.resource_count);
    /// println!("  Type Count: {}", resource.type_names.len());
    /// println!("  Debug Build: {}", resource.is_debug);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Format Validation
    ///
    /// The parser performs extensive validation:
    /// - **Size Consistency**: Header size fields must be consistent with data length
    /// - **Magic Number**: Must be exactly 0xBEEFCACE for valid .NET resources
    /// - **Version Support**: Supports V1 and V2 resource reader formats
    /// - **Alignment Checks**: Validates padding and alignment requirements
    /// - **Array Bounds**: Ensures hash and position arrays match resource count
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(ParseFailure::Truncated {
                stage: ParseStage::Resources,
                expected: 12,
                found: data.len(),
            }
            .into());
        }

        let mut parser = Parser::new(data);

        // Step 1: Detect format and validate magic number
        let is_embedded_resource = Self::parse_and_validate_magic(&mut parser, data)?;

        // Step 2: Parse resource manager header
        let (res_mgr_header_version, header_size, reader_type, resource_set_type) =
            Self::parse_resource_manager_header(&mut parser)?;

        // Step 3: Initialize result struct with header data
        let mut res = Resource {
            res_mgr_header_version,
            header_size,
            reader_type,
            resource_set_type,
            is_embedded_resource,
            rr_header_offset: parser.pos(),
            ..Default::default()
        };

        // Step 4: Parse RuntimeResourceReader header
        Self::parse_runtime_reader_header(&mut parser, data, &mut res)?;

        // Step 5: Parse type table
        Self::parse_type_table(&mut parser, &mut res)?;

        // Step 6: Handle padding/alignment, counted from the magic as the runtime counts it
        let magic = if is_embedded_resource { 4 } else { 0 };
        res.padding = Self::skip_padding(&mut parser, magic)?;

        // Step 7: Parse hash and position tables
        Self::parse_lookup_tables(&mut parser, &mut res)?;

        // Step 8: Read data section offset and record name section start
        res.data_section_offset = parser.read_le::<u32>()? as usize;
        res.name_section_offset = parser.pos();

        Ok(res)
    }

    /// Detect resource format (embedded vs standalone) and validate magic number.
    ///
    /// .NET resources can appear in two formats:
    /// - **Embedded**: `[size: u32][magic: u32][header...]` - Used when resources are embedded in assemblies
    /// - **Standalone**: `[magic: u32][header...]` - Used for standalone `.resources` files
    ///
    /// This method reads the first 8 bytes to detect which format is being used and
    /// validates that the magic number (0xBEEFCACE) is present.
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned at the start of the resource data
    /// * `data` - Complete resource data buffer (used for size validation)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Embedded resource format detected (parser positioned after magic)
    /// * `Ok(false)` - Standalone format detected (parser positioned after magic)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Neither format's magic number is found at the expected position
    /// - Embedded format has invalid size (too large or too small)
    fn parse_and_validate_magic(parser: &mut Parser, data: &[u8]) -> Result<bool> {
        let first_u32 = parser.read_le::<u32>()?;
        let second_u32 = parser.read_le::<u32>()?;

        if second_u32 == RESOURCE_MAGIC {
            // Embedded resource format: [size][magic][header...]
            let size = first_u32 as usize;
            let max_size = data.len().saturating_sub(4);
            if size > max_size || size < 8 {
                return Err(malformed_error!("Invalid embedded resource size: {}", size));
            }
            Ok(true)
        } else if first_u32 == RESOURCE_MAGIC {
            // Standalone .resources file format: [magic][header...]
            parser.seek(4)?; // Reset to after magic number
            Ok(false)
        } else {
            Err(malformed_error!(
                "Invalid resource format - expected magic 0x{:08X}, found 0x{:08X}/0x{:08X}",
                RESOURCE_MAGIC,
                first_u32,
                second_u32
            ))
        }
    }

    /// Parse the Resource Manager header section.
    ///
    /// The Resource Manager header contains version information and type strings that
    /// identify the reader and resource set classes used to parse the file.
    ///
    /// # Header Format
    ///
    /// ```text
    /// [version: u32]           - Header version (1 = V1 format with type strings)
    /// [num_bytes_to_skip: u32] - For V1: ignored; For V2+: bytes to skip
    /// [reader_type: string]    - V1 only: IResourceReader implementation class name
    /// [resource_set_type: string] - V1 only: ResourceSet implementation class name
    /// ```
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned after the magic number
    ///
    /// # Returns
    ///
    /// A tuple of `(version, header_size, reader_type, resource_set_type)`.
    /// For V2+ formats, `reader_type` and `resource_set_type` will be empty strings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The skip bytes value exceeds 1GB (sanity check)
    /// - The reader type is not a supported implementation
    /// - String reading fails due to malformed data
    fn parse_resource_manager_header(parser: &mut Parser) -> Result<(u32, u32, String, String)> {
        let version = parser.read_le::<u32>()?;
        let num_bytes_to_skip = parser.read_le::<u32>()?;

        if version > 1 {
            // Future version: skip the specified number of bytes
            if num_bytes_to_skip > (1 << 30) {
                return Err(malformed_error!(
                    "Invalid skip bytes: {}",
                    num_bytes_to_skip
                ));
            }
            parser.advance_by(num_bytes_to_skip as usize)?;
            Ok((version, num_bytes_to_skip, String::new(), String::new()))
        } else {
            // V1 header: read reader type and resource set type
            let reader_type = parser.read_prefixed_string_utf8()?;
            let resource_set_type = parser.read_prefixed_string_utf8()?;

            if !Self::validate_reader_type(&reader_type) {
                return Err(malformed_error!("Unsupported reader type: {}", reader_type));
            }

            Ok((version, num_bytes_to_skip, reader_type, resource_set_type))
        }
    }

    /// Parse the `RuntimeResourceReader` header section.
    ///
    /// This section contains the resource reader version, optional debug information,
    /// and the total count of resources in the file.
    ///
    /// # Header Format
    ///
    /// ```text
    /// [rr_version: u32]        - RuntimeResourceReader version (1 or 2)
    /// ["***DEBUG***": string]  - V2 only, optional: Present in debug builds
    /// [resource_count: u32]    - Number of resources in this file
    /// ```
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned at the start of the RR header
    /// * `data` - Complete resource data buffer (used for bounds checking)
    /// * `res` - Resource struct to populate with parsed values
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The RR version is not 1 or 2
    /// - The resource count exceeds `MAX_RESOURCES` (1,000,000)
    fn parse_runtime_reader_header(
        parser: &mut Parser,
        data: &[u8],
        res: &mut Resource,
    ) -> Result<()> {
        res.rr_version = parser.read_le::<u32>()?;

        if res.rr_version != 1 && res.rr_version != 2 {
            return Err(malformed_error!(
                "Unsupported resource reader version: {}",
                res.rr_version
            ));
        }

        // Check for debug string in V2 debug builds ("***DEBUG***")
        if res.rr_version == 2 && data.len().saturating_sub(parser.pos()) >= 11 {
            res.is_debug = Self::try_parse_debug_marker(parser);
        }

        res.resource_count = parser.read_le::<u32>()?;
        if res.resource_count > MAX_RESOURCES {
            return Err(malformed_error!(
                "Resource file has too many resources: {} (max: {})",
                res.resource_count,
                MAX_RESOURCES
            ));
        }

        Ok(())
    }

    /// Try to parse the optional `"***DEBUG***"` marker in V2 resources.
    ///
    /// In V2 debug builds, .NET includes a debug marker string immediately after the
    /// RR version number. This method attempts to read and identify this marker using
    /// a peek-and-restore pattern to avoid consuming data if the marker isn't present.
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned where the debug marker might be
    ///
    /// # Returns
    ///
    /// * `true` - Debug marker was found and consumed
    /// * `false` - No debug marker present (parser position restored)
    fn try_parse_debug_marker(parser: &mut Parser) -> bool {
        let result = parser.transactional(|p| {
            let s = p.read_prefixed_string_utf8()?;
            if s == "***DEBUG***" {
                Ok(true)
            } else {
                Err(malformed_error!("not a debug marker"))
            }
        });

        result.unwrap_or(false)
    }

    /// Parse the type name table.
    ///
    /// The type table contains fully-qualified .NET type names for all resource types
    /// used in this file. Resources reference these types by index when their type
    /// code indicates a user-defined type.
    ///
    /// # Table Format
    ///
    /// ```text
    /// [type_count: u32]        - Number of type names in the table
    /// [type_name: string]...   - Length-prefixed UTF-8 type names (repeated type_count times)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned at the start of the type table
    /// * `res` - Resource struct to populate with parsed type names
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The type count exceeds `MAX_RESOURCE_TYPES` (4,096)
    /// - Any type name string is malformed
    fn parse_type_table(parser: &mut Parser, res: &mut Resource) -> Result<()> {
        let type_count = parser.read_le::<u32>()?;

        if type_count > MAX_RESOURCE_TYPES {
            return Err(malformed_error!(
                "Resource file has too many types: {} (max: {})",
                type_count,
                MAX_RESOURCE_TYPES
            ));
        }

        res.type_names.reserve(type_count as usize);
        for _ in 0..type_count {
            res.type_names.push(parser.read_prefixed_string_utf8()?);
        }

        Ok(())
    }

    /// Skip the padding that aligns the hash table to 8 bytes from the magic at `magic`.
    ///
    /// `ResourceReader` skips the bytes to the boundary without looking at them, and the
    /// alignment is counted from the stream's start, the magic: in an embedded resource, 4
    /// bytes past its length prefix. Counted from the prefix, a stream whose type table ends
    /// 2 bytes past a boundary had 6 bytes skipped, 4 of them the first hash.
    ///
    /// # Returns
    ///
    /// The number of padding bytes skipped.
    fn skip_padding(parser: &mut Parser, magic: usize) -> Result<usize> {
        let misalignment = parser.pos().saturating_sub(magic) & 7;
        if misalignment == 0 {
            return Ok(0);
        }
        let padding = 8usize.saturating_sub(misalignment);
        parser.advance_by(padding)?;
        Ok(padding)
    }

    /// Parse the name hash and position lookup tables.
    ///
    /// These tables enable efficient resource lookup by name. The hash table contains
    /// pre-computed hash values for each resource name, and the position table contains
    /// offsets into the name section where each resource's name and data pointer are stored.
    ///
    /// # Table Format
    ///
    /// ```text
    /// [name_hash: u32]...      - Hash values (repeated resource_count times)
    /// [name_position: u32]...  - Name section offsets (repeated resource_count times)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `parser` - Parser positioned after padding, at the start of the hash table
    /// * `res` - Resource struct to populate with hash and position arrays
    ///
    /// # Notes
    ///
    /// The arrays are pre-allocated using `reserve()` to avoid reallocation during parsing.
    fn parse_lookup_tables(parser: &mut Parser, res: &mut Resource) -> Result<()> {
        let count = res.resource_count as usize;

        res.name_hashes.reserve(count);
        for _ in 0..count {
            res.name_hashes.push(parser.read_le::<u32>()?);
        }

        res.name_positions.reserve(count);
        for _ in 0..count {
            res.name_positions.push(parser.read_le::<u32>()?);
        }

        Ok(())
    }

    /// Parse all resources into a name-indexed collection with full type resolution.
    ///
    /// This method performs the actual resource data parsing, extracting resource names,
    /// types, and values from the name and data sections. It uses the hash table and
    /// position information parsed by [`parse()`](Resource::parse) to efficiently
    /// locate and decode each resource.
    ///
    /// # Parsing Process
    ///
    /// For each resource:
    /// 1. **Name Resolution**: Uses position table to locate UTF-16 resource name
    /// 2. **Offset Calculation**: Extracts data section offset for the resource
    /// 3. **Type Identification**: Reads type code and resolves to concrete type
    /// 4. **Data Extraction**: Parses typed resource data based on type information
    /// 5. **Entry Creation**: Creates complete `ResourceEntry` with metadata
    ///
    /// # Arguments
    ///
    /// * `data` - The same complete resource file data buffer used for parsing
    ///
    /// # Returns
    ///
    /// A `BTreeMap<String, ResourceEntry>` containing all resources indexed by name.
    /// The map maintains sorted order for consistent iteration and enables efficient
    /// lookups by resource name.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Name section offsets point beyond the data buffer
    /// - UTF-16 resource names are malformed or truncated
    /// - Data section offsets are invalid or out of bounds
    /// - Resource type codes are unsupported or corrupted
    /// - Individual resource data cannot be parsed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::Resource;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let mut resource = Resource::parse(&resource_data)?;
    /// let resources = resource.read_resources(&resource_data)?;
    ///
    /// println!("Found {} resources:", resources.len());
    /// for (name, entry) in &resources {
    ///     println!("Resource: {} (Hash: 0x{:08X})", name, entry.name_hash);
    ///
    ///     match &entry.data {
    ///         ResourceType::String(s) => {
    ///             println!("  String: '{}'", s);
    ///         }
    ///         ResourceType::ByteArray(bytes) => {
    ///             println!("  Binary data: {} bytes", bytes.len());
    ///         }
    ///         ResourceType::Int32(value) => {
    ///             println!("  Integer: {}", value);
    ///         }
    ///         _ => {
    ///             println!("  Other type: {:?}", entry.data);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Resource Types
    ///
    /// Supports all standard .NET resource types:
    /// - **Primitive Types**: `bool`, `byte`, `sbyte`, `char`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `single`, `double`, `decimal`
    /// - **String Types**: UTF-16 strings with length prefixes
    /// - **`DateTime`**: .NET `DateTime` binary format
    /// - **`TimeSpan`**: .NET `TimeSpan` binary format
    /// - **Byte Arrays**: Raw binary data with length prefixes
    /// - **Custom Objects**: Serialized .NET objects (parsing depends on type)
    pub fn read_resources(&mut self, data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
        let count = self.resource_count as usize;
        if self.name_hashes.len() != count || self.name_positions.len() != count {
            return Err(malformed_error!(
                "Resource count {} doesn't match hash/position array lengths ({}/{})",
                self.resource_count,
                self.name_hashes.len(),
                self.name_positions.len()
            ));
        }

        let mut resources = BTreeMap::new();
        let mut parser = Parser::new(data);

        for i in 0..count {
            let name_pos_offset = *self
                .name_positions
                .get(i)
                .ok_or_else(|| malformed_error!("name_positions index {} out of bounds", i))?
                as usize;
            let name_pos = self
                .name_section_offset
                .checked_add(name_pos_offset)
                .ok_or_else(|| malformed_error!("name position overflow"))?;
            parser.seek(name_pos)?;

            let name = parser.read_prefixed_string_utf16()?;
            let type_offset = parser.read_le::<u32>()?;

            let data_pos = if self.is_embedded_resource {
                // Embedded resources: offset calculated from magic number position, need +4 for size field
                self.data_section_offset
                    .checked_add(type_offset as usize)
                    .and_then(|v| v.checked_add(4))
                    .ok_or_else(|| malformed_error!("embedded resource data position overflow"))?
            } else {
                // Standalone .resources files: use direct offset
                self.data_section_offset
                    .checked_add(type_offset as usize)
                    .ok_or_else(|| malformed_error!("standalone resource data position overflow"))?
            };

            // Validate data position bounds
            if data_pos >= data.len() {
                return Err(malformed_error!(
                    "Resource data offset {} is beyond file bounds",
                    data_pos
                ));
            }

            parser.seek(data_pos)?;

            let resource_data = if self.rr_version == 1 {
                // V1 format: type index (7-bit encoded) followed by data
                let type_index = parser.read_7bit_encoded_int()?;
                if type_index == u32::MAX {
                    // -1 encoded as 7-bit represents null
                    ResourceType::Null
                } else if let Some(type_name) = self.type_names.get(type_index as usize) {
                    ResourceType::from_type_name(type_name, &mut parser)?
                } else {
                    return Err(malformed_error!("Invalid type index: {}", type_index));
                }
            } else {
                // V2 format: type code (7-bit encoded) followed by data
                #[allow(clippy::cast_possible_truncation)]
                let type_code = parser.read_7bit_encoded_int()? as u8;

                if self.type_names.is_empty() {
                    // No type table - this file uses only primitive types (direct type codes)
                    // Common in resource files that contain only strings/primitives
                    ResourceType::from_type_byte(type_code, &mut parser)?
                } else if let Some(type_name) = self.type_names.get(type_code as usize) {
                    ResourceType::from_type_name(type_name, &mut parser)?
                } else {
                    return Err(malformed_error!("Invalid type index: {}", type_code));
                }
            };

            let name_hash = *self
                .name_hashes
                .get(i)
                .ok_or_else(|| malformed_error!("name_hashes index {} out of bounds", i))?;
            let result = ResourceEntry {
                name: name.clone(),
                name_hash,
                data: resource_data,
            };

            resources.insert(name, result);
        }

        Ok(resources)
    }

    /// Parse all resources into a name-indexed collection with zero-copy semantics.
    ///
    /// This is the zero-copy variant of [`read_resources`](Resource::read_resources). Instead
    /// of allocating owned copies of resource data, it returns borrowed slices directly into
    /// the source data buffer. This is essential for efficient handling of large embedded
    /// resources like ZIP archives that could be hundreds of megabytes or gigabytes.
    ///
    /// # Parsing Process
    ///
    /// Identical to [`read_resources`](Resource::read_resources), but for each resource:
    /// - **String data**: Returns `&'a str` instead of allocating `String`
    /// - **Byte arrays**: Returns `&'a [u8]` instead of allocating `Vec<u8>`
    /// - **Primitive types**: Returned by value (no difference from owned variant)
    ///
    /// # Arguments
    ///
    /// * `data` - The complete resource file data buffer used for parsing. This is the same
    ///   buffer that was passed to [`parse`](Resource::parse).
    ///
    /// # Lifetime
    ///
    /// The returned resources borrow from the `data` parameter. All borrowed resource data
    /// (strings and byte arrays) will remain valid as long as `data` is valid.
    ///
    /// # Returns
    ///
    /// A `BTreeMap<String, ResourceEntryRef<'a>>` containing all resources indexed by name.
    /// The map maintains sorted order for consistent iteration and enables efficient lookups.
    /// Resource names are owned (String) for efficient map key usage, but resource data is borrowed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Name section offsets point beyond the data buffer
    /// - UTF-16 resource names are malformed or truncated
    /// - Data section offsets are invalid or out of bounds
    /// - Resource type codes are unsupported or corrupted
    /// - Individual resource data cannot be parsed
    ///
    /// # Examples
    ///
    /// ## Basic Zero-Copy Usage
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::Resource;
    /// use dotscope::metadata::resources::ResourceTypeRef;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let mut resource = Resource::parse(&resource_data)?;
    /// let resources = resource.read_resources_ref(&resource_data)?;
    ///
    /// println!("Found {} resources:", resources.len());
    /// for (name, entry) in &resources {
    ///     println!("Resource: {} (Hash: 0x{:08X})", name, entry.name_hash);
    ///
    ///     match &entry.data {
    ///         ResourceTypeRef::ByteArray(bytes) => {
    ///             // Zero-copy access - no allocation!
    ///             println!("  Binary data: {} bytes (no copy!)", bytes.len());
    ///         }
    ///         ResourceTypeRef::String(s) => {
    ///             // Zero-copy string access
    ///             println!("  String: '{}'", s);
    ///         }
    ///         ResourceTypeRef::Int32(value) => {
    ///             println!("  Integer: {}", value);
    ///         }
    ///         _ => {
    ///             println!("  Other type: {:?}", entry.data);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// ## Extracting Embedded ZIP Archives
    ///
    /// ```no_run
    /// use dotscope::metadata::resources::Resource;
    /// use dotscope::metadata::resources::ResourceTypeRef;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let mut resource = Resource::parse(&resource_data)?;
    /// let resources = resource.read_resources_ref(&resource_data)?;
    ///
    /// for (name, entry) in &resources {
    ///     if let ResourceTypeRef::ByteArray(bytes) = &entry.data {
    ///         // Check if this is a ZIP file (PK magic number)
    ///         if bytes.len() > 4 && &bytes[0..4] == b"PK\x03\x04" {
    ///             println!("Found embedded ZIP: {} ({} bytes)", name, bytes.len());
    ///
    ///             // Extract ZIP without copying the data
    ///             // Pass borrowed slice directly to ZIP library
    ///             let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ///             println!("  Contains {} files", archive.len());
    ///         }
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Use [`read_resources`](Resource::read_resources) when:
    /// - Resource data needs to outlive the source buffer
    /// - Working with small resources where copy overhead is negligible
    /// - You prefer simpler APIs without lifetime parameters
    pub fn read_resources_ref<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<BTreeMap<String, ResourceEntryRef<'a>>> {
        let count = self.resource_count as usize;
        if self.name_hashes.len() != count || self.name_positions.len() != count {
            return Err(malformed_error!(
                "Resource count {} doesn't match hash/position array lengths ({}/{})",
                self.resource_count,
                self.name_hashes.len(),
                self.name_positions.len()
            ));
        }

        let mut resources = BTreeMap::new();
        let mut parser = Parser::new(data);

        for i in 0..count {
            let name_pos_offset = *self
                .name_positions
                .get(i)
                .ok_or_else(|| malformed_error!("name_positions index {} out of bounds", i))?
                as usize;
            let name_pos = self
                .name_section_offset
                .checked_add(name_pos_offset)
                .ok_or_else(|| malformed_error!("name position overflow"))?;
            parser.seek(name_pos)?;

            let name = parser.read_prefixed_string_utf16()?;
            let type_offset = parser.read_le::<u32>()?;

            let data_pos = if self.is_embedded_resource {
                self.data_section_offset
                    .checked_add(type_offset as usize)
                    .and_then(|v| v.checked_add(4))
                    .ok_or_else(|| malformed_error!("embedded resource data position overflow"))?
            } else {
                self.data_section_offset
                    .checked_add(type_offset as usize)
                    .ok_or_else(|| malformed_error!("standalone resource data position overflow"))?
            };

            // Validate data position bounds
            if data_pos >= data.len() {
                return Err(malformed_error!(
                    "Resource data offset {} is beyond file bounds",
                    data_pos
                ));
            }

            parser.seek(data_pos)?;

            let resource_data = if self.rr_version == 1 {
                // V1 format: type index (7-bit encoded) followed by data
                let type_index = parser.read_7bit_encoded_int()?;
                if type_index == u32::MAX {
                    // -1 encoded as 7-bit represents null
                    ResourceTypeRef::Null
                } else if let Some(type_name) = self.type_names.get(type_index as usize) {
                    ResourceTypeRef::from_type_name_ref(type_name, &mut parser, data)?
                } else {
                    return Err(malformed_error!("Invalid type index: {}", type_index));
                }
            } else {
                // V2 format: type code (7-bit encoded) followed by data
                #[allow(clippy::cast_possible_truncation)]
                let type_code = parser.read_7bit_encoded_int()? as u8;

                if self.type_names.is_empty() {
                    // No type table - this file uses only primitive types (direct type codes)
                    ResourceTypeRef::from_type_byte_ref(type_code, &mut parser, data)?
                } else if let Some(type_name) = self.type_names.get(type_code as usize) {
                    ResourceTypeRef::from_type_name_ref(type_name, &mut parser, data)?
                } else {
                    return Err(malformed_error!("Invalid type index: {}", type_code));
                }
            };

            let name_hash = *self
                .name_hashes
                .get(i)
                .ok_or_else(|| malformed_error!("name_hashes index {} out of bounds", i))?;
            let result = ResourceEntryRef {
                name: name.clone(),
                name_hash,
                data: resource_data,
            };

            resources.insert(name, result);
        }

        Ok(resources)
    }

    /// Validate that the reader type is supported by this parser.
    ///
    /// Based on .NET Framework validation, accepts:
    /// - System.Resources.ResourceReader (with or without assembly qualification)
    /// - System.Resources.Extensions.DeserializingResourceReader
    fn validate_reader_type(reader_type: &str) -> bool {
        match reader_type {
            "System.Resources.ResourceReader"
            | "System.Resources.Extensions.DeserializingResourceReader" => true,
            // Accept fully qualified names with mscorlib assembly info
            s if s.starts_with("System.Resources.ResourceReader,") => true,
            s if s.starts_with("System.Resources.Extensions.DeserializingResourceReader,") => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testkit::verify_wbdll_resource_buffer;

    #[test]
    fn wb_example() {
        let data =
            include_bytes!("../../../tests/samples/WB_FxResources.WindowsBase.SR.resources.bin");
        verify_wbdll_resource_buffer(data);
    }
}

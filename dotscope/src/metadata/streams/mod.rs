//! ECMA-335 Metadata Streams for .NET Assembly Processing
//!
//! This module implements comprehensive parsing, representation, and access to metadata streams
//! according to the ECMA-335 standard. Metadata streams are the fundamental data structures
//! within .NET assemblies that store type definitions, method signatures, string literals,
//! binary data, and global identifiers in optimized, compressed formats.
//!
//! # Metadata Stream Architecture
//!
//! The .NET metadata format organizes data into distinct streams, each optimized for specific
//! data types and access patterns. This separation enables efficient compression, fast lookup
//! operations, and minimal memory overhead during assembly processing.
//!
//! ## Physical Layout
//! ```text
//! Metadata Root
//! ├── Stream Header Directory
//! │   ├── #Strings - String identifier heap
//! │   ├── #US - User string literals heap  
//! │   ├── #Blob - Binary data heap
//! │   ├── #GUID - Global identifier array
//! │   └── #~ - Compressed metadata tables
//! └── Stream Data Sections
//! ```
//!
//! ## Stream Identification
//! Each stream is identified by a specific name and serves a distinct purpose:
//! - Fixed names like `#Strings`, `#US`, `#Blob`, `#GUID`
//! - Table streams use `#~` (compressed) or `#-` (uncompressed)
//! - Custom streams may exist but are non-standard
//!
//! # Standard Stream Types
//!
//! The ECMA-335 specification defines five standard stream types with specific formats
//! and access patterns optimized for their data characteristics.
//!
//! ## String Storage Streams
//!
//! ### `#Strings` - Identifier Heap
//! **Purpose**: Stores UTF-8 encoded identifier strings referenced by metadata tables
//! - **Content**: Type names, member names, namespace identifiers, attribute names
//! - **Format**: Null-terminated UTF-8 strings with mandatory null entry at offset 0
//! - **Access**: 0-based offset indexing with O(1) random access
//! - **Compression**: Shared string storage eliminates duplication
//! - **Performance**: Optimized for frequent lookup during type resolution
//!
//! ### `#US` - User String Heap  
//! **Purpose**: Stores UTF-16 encoded string literals from IL code
//! - **Content**: String constants, resource names, exception messages
//! - **Format**: Length-prefixed UTF-16 with terminal flag byte
//! - **Access**: 0-based offset indexing with variable-length entries
//! - **Encoding**: Little-endian UTF-16 with embedded null support
//! - **Performance**: Optimized for runtime string literal access
//!
//! ## Binary Data Streams
//!
//! ### `#Blob` - Binary Data Heap
//! **Purpose**: Stores variable-length binary data referenced by metadata tables
//! - **Content**: Method signatures, field types, custom attribute values, constants
//! - **Format**: Size-prefixed binary chunks with compressed length encoding
//! - **Access**: 0-based offset indexing with O(1) blob retrieval
//! - **Compression**: ECMA-335 compressed integer size prefixes
//! - **Performance**: Lazy parsing for on-demand signature decoding
//!
//! ### `#GUID` - Global Identifier Array
//! **Purpose**: Stores 128-bit globally unique identifiers for assembly correlation
//! - **Content**: Assembly GUIDs, module identifiers, type library references
//! - **Format**: Sequential 16-byte GUID entries in little-endian format
//! - **Access**: 1-based indexing (unique among metadata streams)
//! - **Alignment**: Fixed 16-byte boundaries for optimal memory access
//! - **Performance**: Direct array access with minimal validation overhead
//!
//! ## Metadata Table Streams
//!
//! ### `#~` - Compressed Metadata Tables
//! **Purpose**: Stores structural metadata in compressed tabular format
//! - **Content**: Type definitions, method signatures, field layouts, references
//! - **Format**: Variable-width compressed tables with optimized storage
//! - **Access**: Token-based indexing with cross-table references
//! - **Compression**: Row-based compression with minimal table overhead
//! - **Performance**: Bulk operations optimized for metadata scanning
//!
//! # Access Patterns and Performance
//!
//! ## Unified Interface Design
//! All heap types provide consistent access patterns:
//! - **Indexed Access**: `get(index)` for direct element retrieval
//! - **Sequential Access**: `iter()` for complete traversal
//! - **Zero-Copy**: Direct references to heap data without allocation
//! - **Error Handling**: Comprehensive bounds checking and format validation
//!
//! # Advanced Features
//!
//! ## Cross-Stream References
//! Metadata tables use indices to reference data across different streams:
//! ```text
//! Method Table Entry
//! ├── Name → #Strings offset
//! ├── Signature → #Blob offset  
//! ├── RVA → Code location
//! └── Flags → Method attributes
//! ```
//!
//! ## Compression Techniques
//! - **String deduplication**: Shared storage for identical strings
//! - **Compressed integers**: Variable-length encoding for sizes and counts
//! - **Table optimization**: Minimal overhead for sparse tables
//! - **Reference packing**: Optimized token formats for cross-references
//!
//! ## Format Evolution
//! The module supports multiple metadata format versions:
//! - Legacy uncompressed format (`#-` tables)
//! - Modern compressed format (`#~` tables)
//! - Extended table schemas for newer .NET versions
//! - Backward compatibility with older assemblies
//!
//! # Examples
//!
//! ## Basic Stream Access
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! # fn example() -> dotscope::Result<()> {
//! let assembly = CilObject::from_path("example.dll")?;
//!
//! // Access string heap for type and member names
//! if let Some(strings) = assembly.strings() {
//!     let type_name = strings.get(0x123)?; // Get string at offset 0x123
//!     println!("Type name: {}", type_name);
//!     
//!     // Enumerate all strings in the heap
//!     for (offset, string) in strings.iter() {
//!         if !string.is_empty() {
//!             println!("String at 0x{:X}: '{}'", offset, string);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Signature Analysis
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! # fn example() -> dotscope::Result<()> {
//! let assembly = CilObject::from_path("example.dll")?;
//!
//! // Access blob heap for method signatures and field types
//! if let Some(blob) = assembly.blob() {
//!     let signature_data = blob.get(1)?; // Get blob at offset 1
//!     println!("Signature bytes: {} bytes", signature_data.len());
//!     
//!     // Analyze all binary data for debugging
//!     for (offset, blob_data) in blob.iter() {
//!         if blob_data.len() > 0 {
//!             println!("Blob at 0x{:X}: {} bytes", offset, blob_data.len());
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Assembly Identity and Versioning
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! # fn example() -> dotscope::Result<()> {
//! let assembly = CilObject::from_path("example.dll")?;
//!
//! // Access GUID heap for assembly and module identifiers
//! if let Some(guid) = assembly.guids() {
//!     let assembly_guid = guid.get(1)?; // Get GUID at index 1
//!     println!("Assembly GUID: {}", assembly_guid);
//!     
//!     // Enumerate all GUIDs for correlation analysis
//!     for (index, guid_value) in guid.iter() {
//!         let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
//!         if guid_value != null_guid {
//!             println!("Active GUID at index {}: {}", index, guid_value);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## String Literal Processing
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! # fn example() -> dotscope::Result<()> {
//! let assembly = CilObject::from_path("example.dll")?;
//!
//! // Access user strings heap for IL string literals
//! if let Some(user_strings) = assembly.userstrings() {
//!     let literal = user_strings.get(0x100)?; // Get user string at offset 0x100
//!     println!("String literal: '{}'", literal.to_string_lossy());
//!     
//!     // Process all string literals for analysis
//!     for (offset, string_data) in user_strings.iter() {
//!         if !string_data.is_empty() {
//!             println!("User string at 0x{:X}: '{}'", offset, string_data.to_string_lossy());
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Comprehensive Metadata Analysis
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! # fn example() -> dotscope::Result<()> {
//! let assembly = CilObject::from_path("example.dll")?;
//!
//! // Analyze all available streams for comprehensive metadata overview
//! println!("=== Metadata Stream Analysis ===");
//!
//! if let Some(strings) = assembly.strings() {
//!     let string_count = strings.iter().count();
//!     println!("String heap: {} entries", string_count);
//! }
//!
//! if let Some(user_strings) = assembly.userstrings() {
//!     let literal_count = user_strings.iter().count();
//!     println!("User string heap: {} entries", literal_count);
//! }
//!
//! if let Some(blob) = assembly.blob() {
//!     let blob_count = blob.iter().count();
//!     println!("Blob heap: {} entries", blob_count);
//! }
//!
//! if let Some(guid) = assembly.guids() {
//!     let guid_count = guid.iter().count();
//!     println!("GUID heap: {} entries", guid_count);
//! }
//!
//! if let Some(tables) = assembly.tables() {
//!     let table_count = tables.table_count();
//!     println!("Metadata tables: {} tables present", table_count);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling and Validation
//!
//! All stream operations provide comprehensive error handling:
//! - **Format Validation**: Ensures stream headers and data integrity
//! - **Bounds Checking**: Prevents access beyond stream boundaries
//! - **Encoding Validation**: Verifies string encoding and compressed integers
//! - **Cross-Reference Validation**: Validates indices between streams and tables
//!
//! ## Iterator Error Behavior
//!
//! An iterator stops only where the heap's own structure ends, never at an entry it cannot
//! decode, so nothing after a malformed entry goes unseen:
//!
//! | Iterator | Entries | Ends |
//! |----------|---------|------|
//! | `StringEntries` | every entry, as bytes | at the end of the heap |
//! | `StringsIterator` | the entries that are valid UTF-8 | at the end of the heap |
//! | `UserStringsIterator` | the entries that hold a string | where a length is unreadable or overruns the heap |
//! | `BlobIterator` | every entry | where a length is unreadable or overruns the heap |
//! | `GuidIterator` | every 16-byte entry | at the last whole entry |
//!
//! ## Common Error Scenarios
//! - Corrupted or truncated stream data
//! - Invalid offset or index values
//! - Malformed compressed integer encoding
//! - Inconsistent cross-stream references
//! - Unsupported metadata format versions
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 requirements:
//! - Correct parsing of all standard stream formats
//! - Proper handling of compressed and uncompressed metadata
//! - Support for all defined string encodings (UTF-8, UTF-16)
//! - Accurate implementation of compressed integer formats
//! - Complete validation of stream headers and data integrity
//!
//! # Implementation Notes
//!
//! ## Memory Management
//! - **Zero-copy design**: All stream data accessed via direct references
//! - **Lazy evaluation**: Stream parsing deferred until first access
//! - **Minimal allocation**: Iterator state requires minimal heap allocation
//! - **Reference counting**: Safe lifetime management across thread boundaries
//!
//! ## Optimization Strategies
//! - **Compressed integer caching**: Frequently accessed sizes cached
//! - **String interning**: Identical strings share storage automatically
//! - **Sequential access optimization**: Iterator patterns optimized for cache locality
//! - **Bulk operations**: Table scanning operations optimized for performance
//!
//! ## Cross-Platform Considerations
//! - **Endianness handling**: Proper little-endian conversion on all platforms
//! - **Alignment requirements**: Respect platform-specific alignment constraints
//! - **Unicode normalization**: Consistent string handling across operating systems
//! - **Path separators**: Platform-agnostic resource name processing
//!
//! # See Also
//! - [`crate::metadata::cilobject::CilObject`]: Main assembly access interface
//! - [`crate::metadata::tables`]: Metadata table processing and analysis
//! - [`crate::File`]: PE file format handling and data access
//! - [`crate::metadata::signatures`]: Binary signature parsing and analysis
//!
//! # References
//! - **ECMA-335 II.24.2.2**: Stream header specification and directory format
//! - **ECMA-335 II.24.2.3**: `#Strings` heap format and encoding rules
//! - **ECMA-335 II.24.2.4**: `#Blob` heap format and compression details
//! - **ECMA-335 II.24.2.5**: `#GUID` heap format and indexing convention
//! - **ECMA-335 II.24.2.6**: `#US` heap format and UTF-16 encoding
//! - **ECMA-335 II.22**: Metadata table definitions and relationships

/// Stream header parsing and validation for ECMA-335 metadata directory.
///
/// Provides [`crate::metadata::streams::streamheader::StreamHeader`] for parsing stream directory entries, validating
/// stream names, and calculating data offsets within the metadata section.
mod streamheader;
pub use streamheader::StreamHeader;

/// UTF-8 identifier string heap (`#Strings`) implementation.
///
/// Provides [`crate::metadata::streams::strings::Strings`] and [`crate::metadata::streams::strings::StringsIterator`] for accessing null-terminated
/// UTF-8 strings used for type names, member names, and other identifiers.
mod strings;
pub use strings::{StringEntries, Strings, StringsIterator};

/// UTF-16 user string heap (`#US`) implementation.
///
/// Provides [`crate::metadata::streams::userstrings::UserStrings`] and [`crate::metadata::streams::userstrings::UserStringsIterator`] for accessing
/// length-prefixed UTF-16 string literals from IL code and resources.
mod userstrings;
pub use userstrings::{UserStrings, UserStringsIterator};

/// Metadata tables header (`#~` / `#-`) parsing and validation.
///
/// Provides [`crate::metadata::streams::tablesheader::TablesHeader`] for parsing compressed and uncompressed
/// metadata table headers, schemas, and row count information.
mod tablesheader;
pub use tablesheader::TablesHeader;

/// 128-bit GUID array (`#GUID`) implementation.
///
/// Provides [`crate::metadata::streams::guid::Guid`] and [`crate::metadata::streams::guid::GuidIterator`] for accessing globally unique
/// identifiers used for assembly identity and cross-reference correlation.
mod guid;
pub use guid::{Guid, GuidIterator};

/// Variable-length binary data heap (`#Blob`) implementation.
///
/// Provides [`crate::metadata::streams::blob::Blob`] and [`crate::metadata::streams::blob::BlobIterator`] for accessing size-prefixed
/// binary data including signatures, custom attributes, and constants.
mod blob;
pub use blob::{Blob, BlobIterator};

/// The Portable PDB `#Pdb` stream: the PDB's identity, entry point, and the row counts of the
/// assembly tables its tables reference.
mod pdb;
pub use pdb::PdbStream;

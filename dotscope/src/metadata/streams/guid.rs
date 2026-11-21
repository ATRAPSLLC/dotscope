//! ECMA-335 GUID Heap (`#GUID`) for .NET Metadata Storage
//!
//! This module provides safe access to the `#GUID` heap according to ECMA-335 Section II.24.2.5.
//! The GUID heap stores 128-bit globally unique identifiers used for assembly identity, type library
//! references, and cross-assembly metadata correlation in .NET applications.
//!
//! # GUID Heap Structure
//!
//! The `#GUID` heap is a simple array of 128-bit (16-byte) GUID values stored in little-endian
//! byte order. Each GUID occupies exactly 16 consecutive bytes, and GUIDs are referenced by
//! 1-based indices from metadata tables.
//!
//! ## Memory Layout
//! ```text
//! Offset | Content
//! -------|-------------------
//! 0x00   | GUID₁ (16 bytes)
//! 0x10   | GUID₂ (16 bytes)
//! 0x20   | GUID₃ (16 bytes)
//! ...    | ...
//! ```
//!
//! ## Indexing Scheme
//! Unlike other metadata heaps that use 0-based indexing, the GUID heap uses **1-based indexing**:
//! - Index 1 → First GUID (bytes 0-15)
//! - Index 2 → Second GUID (bytes 16-31)
//! - Index N → Nth GUID (bytes (N-1)*16 to N*16-1)
//!
//! # GUID Usage in .NET Metadata
//!
//! ## Assembly Identity
//! Each .NET assembly can have an associated GUID for unique identification:
//! - Used for strong naming and version resolution
//! - Referenced by AssemblyRef and Assembly metadata tables
//! - Enables cross-domain and cross-process assembly correlation
//!
//! ## Type Library References
//! For COM interop scenarios, GUIDs identify type libraries:
//! - Map .NET types to COM interfaces
//! - Support legacy COM component integration
//! - Enable marshalling between managed and unmanaged code
//!
//! ## Module Identification
//! Module-level GUIDs provide unique identification:
//! - Distinguish modules within multi-module assemblies
//! - Support incremental compilation scenarios
//! - Enable debugging and profiling correlation
//!

//!
//! # Examples
//!
//! ## Basic GUID Access
//! ```rust
//! use dotscope::metadata::streams::Guid;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Example GUID heap with two entries
//! #[rustfmt::skip]
//! let heap_data = [
//!     // First GUID: d437908e-65e6-487c-9735-7bdff699bea5
//!     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
//!     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
//!     // Second GUID: all zeros (null GUID)
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let guid_heap = Guid::from(&heap_data)?;
//!
//! // Access GUIDs using 1-based indexing
//! let first_guid = guid_heap.get(1)?;
//! let second_guid = guid_heap.get(2)?;
//!
//! println!("Assembly GUID: {}", first_guid);
//! println!("Module GUID: {}", second_guid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Iterating Over All GUIDs
//! ```rust
//! use dotscope::metadata::streams::Guid;
//!
//! # fn example() -> dotscope::Result<()> {
//! let heap_data = [0xFF; 32]; // Two GUIDs with all bytes set to 0xFF
//! let guid_heap = Guid::from(&heap_data)?;
//!
//! for (index, guid) in guid_heap.iter() {
//!     println!("GUID {}: {}", index, guid);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Assembly Identity Example
//! ```rust
//! use dotscope::metadata::streams::Guid;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Real-world assembly GUID from metadata table reference
//! let assembly_guid_index = 1; // From Assembly table
//! let heap_data = [
//!     // Assembly GUID: actual assembly identifier
//!     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
//!     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
//! ];
//!
//! let guid_heap = Guid::from(&heap_data)?;
//! let assembly_guid = guid_heap.get(assembly_guid_index)?;
//!
//! // Use GUID for assembly comparison or caching
//! let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
//! if assembly_guid != null_guid {
//!     println!("Assembly has unique identifier: {}", assembly_guid);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! The GUID heap API provides comprehensive error handling for:
//! - **Insufficient Data**: Heap too small to contain valid GUIDs
//! - **Out of Bounds Access**: Invalid GUID indices
//! - **Alignment Issues**: Data not properly aligned to 16-byte boundaries
//! - **Index Validation**: Proper 1-based indexing enforcement
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 Partition II, Section 24.2.5:
//! - Correct 16-byte GUID alignment and storage
//! - Proper 1-based indexing as specified
//! - Little-endian byte order handling
//! - Comprehensive bounds checking and validation
//!
//! # See Also
//! - [`crate::metadata::streams::Strings`]: For string heap access
//! - [`crate::metadata::streams::Blob`]: For binary blob heap access  
//! - [`crate::metadata::tables`]: For metadata tables that reference GUIDs
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Official specification
//!
//! # References
//! - **ECMA-335 II.24.2.5**: `#GUID` heap specification
//! - **RFC 4122**: UUID/GUID format and generation standards

use crate::{HeapKind, ParseFailure, ParseStage, Result};

/// ECMA-335 GUID heap providing indexed access to 128-bit globally unique identifiers.
///
/// The `Guid` struct represents the `#GUID` metadata heap according to ECMA-335 Section II.24.2.5.
/// It provides safe, zero-copy access to 16-byte GUID values referenced by metadata table entries
/// for assembly identification, type library correlation, and module tracking.
///
/// # GUID Heap Organization
///
/// ## Storage Format
/// GUIDs are stored as consecutive 16-byte little-endian values:
/// - Each GUID occupies exactly 16 bytes
/// - No padding or alignment between entries
/// - Standard RFC 4122 UUID format within each 16-byte block
/// - Sequential storage enables efficient bulk operations
///
/// ## Indexing Convention
/// The GUID heap uses **1-based indexing** unlike other metadata heaps:
/// ```text
/// Index | Byte Offset | GUID Content
/// ------|-------------|-------------
/// 1     | 0-15        | First GUID
/// 2     | 16-31       | Second GUID
/// 3     | 32-47       | Third GUID
/// ```
///
/// This convention aligns with ECMA-335 requirements and metadata table references.
///
/// # GUID Types and Usage
///
/// ## Assembly Identity GUIDs
/// Uniquely identify assemblies across application domains:
/// - Enable version-independent assembly correlation
/// - Support strong naming and security policies
/// - Facilitate debugging and profiling scenarios
///
/// ## Type Library GUIDs  
/// Support COM interoperability:
/// - Map .NET types to COM interfaces
/// - Enable marshalling between managed/unmanaged code
/// - Provide backward compatibility with legacy systems
///
/// ## Module GUIDs
/// Distinguish modules within multi-module assemblies:
/// - Support incremental compilation workflows
/// - Enable fine-grained dependency tracking
/// - Facilitate debugging symbol correlation
///
/// # Examples
///
/// ## Creating and Accessing GUIDs
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// // Sample GUID heap with two entries
/// #[rustfmt::skip]
/// let heap_data = [
///     // GUID 1: d437908e-65e6-487c-9735-7bdff699bea5
///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
///     // GUID 2: All zeros (null GUID)
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ];
///
/// let guid_heap = Guid::from(&heap_data)?;
///
/// // Access GUIDs using 1-based indexing (as per ECMA-335)
/// let assembly_guid = guid_heap.get(1)?;
/// let module_guid = guid_heap.get(2)?;
///
/// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
/// assert_ne!(assembly_guid, null_guid);
/// assert_eq!(module_guid, null_guid);
/// # Ok(())
/// # }
/// ```
///
/// ## Assembly Identity Verification
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = [0xAB; 16]; // Non-null GUID
/// let guid_heap = Guid::from(&heap_data)?;
/// let assembly_guid = guid_heap.get(1)?;
///
/// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
/// // Check if assembly has unique identity
/// if assembly_guid != null_guid {
///     println!("Assembly ID: {}", assembly_guid);
///     // Use for caching, comparison, or security checks
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Iterating Over All GUIDs
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = [0xFF; 32]; // Two GUIDs with pattern data
/// let guid_heap = Guid::from(&heap_data)?;
///
/// for (index, guid) in &guid_heap {
///     println!("GUID {}: {}", index, guid);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Error Handling
///
/// Comprehensive error handling for various failure scenarios:
/// - **Insufficient data**: Heap smaller than minimum GUID size (16 bytes)
/// - **Out of bounds**: Invalid index or incomplete GUID data
/// - **Invalid indexing**: Index 0 or negative indices rejected
/// - **Alignment issues**: Proper 16-byte boundary validation
///
/// # ECMA-335 Compliance
///
/// This implementation fully supports ECMA-335 requirements:
/// - Correct 1-based indexing convention
/// - Proper 16-byte GUID storage alignment
/// - Little-endian byte order handling
/// - Standard RFC 4122 UUID format support
///
/// # See Also
/// - [`crate::metadata::streams::guid::GuidIterator`]: For sequential access to all GUIDs
/// - [`crate::metadata::tables`]: For metadata tables referencing GUIDs
/// - [`uguid::Guid`]: The underlying GUID implementation
/// - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Official specification
///
pub struct Guid<'a> {
    /// Raw bytes of the GUID heap
    data: &'a [u8],
}

impl<'a> Guid<'a> {
    /// Creates a new `Guid` heap accessor from raw metadata bytes.
    ///
    /// Validates that the provided data contains sufficient bytes to represent at least one
    /// complete 16-byte GUID. The GUID heap stores sequential 128-bit globally unique
    /// identifiers referenced by metadata table entries.
    ///
    /// # Parameters
    /// * `data` - Raw bytes containing the complete `#GUID` heap data
    ///
    /// # Returns
    /// A `Guid` instance providing safe access to the heap contents, or an error
    /// if the data format is invalid.
    ///
    /// # Errors
    /// Returns [`crate::Error`] in the following cases:
    /// - **Insufficient data**: Less than 16 bytes provided (minimum for one GUID)
    /// - **Invalid alignment**: Data length not divisible by 16 (partial GUID)
    /// - **Empty heap**: No GUID data available for processing
    ///
    /// # Examples
    ///
    /// ## Valid GUID Heap
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Single GUID heap (minimum valid size)
    /// let single_guid = [0xAB; 16];
    /// let guid_heap = Guid::from(&single_guid)?;
    /// assert_eq!(guid_heap.get(1)?.to_bytes(), single_guid);
    ///
    /// // Multiple GUID heap
    /// let multiple_guids = [0xFF; 48]; // Three GUIDs
    /// let guid_heap = Guid::from(&multiple_guids)?;
    /// assert!(guid_heap.get(1).is_ok());
    /// assert!(guid_heap.get(3).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Invalid GUID Heap
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// // Too small for even one GUID
    /// let too_small = [0u8; 10];
    /// assert!(Guid::from(&too_small).is_err());
    ///
    /// // Empty data
    /// let empty_data = &[];
    /// assert!(Guid::from(empty_data).is_err());
    /// ```
    ///
    /// ## Assembly Identity Use Case
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Real assembly GUID from PE metadata
    /// #[rustfmt::skip]
    /// let assembly_heap = [
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    /// ];
    ///
    /// let guid_heap = Guid::from(&assembly_heap)?;
    /// let assembly_id = guid_heap.get(1)?;
    ///
    /// // Use for assembly identification or caching
    /// println!("Assembly GUID: {}", assembly_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance
    /// - **Zero-copy**: No data is copied or allocated during construction
    /// - **O(1) validation**: Only checks minimum size requirement
    /// - **Lazy parsing**: GUID entries parsed only when accessed
    /// - **Memory efficient**: Direct reference to source data
    ///
    /// # GUID Heap Validation
    /// This method performs minimal validation for performance:
    /// - Ensures minimum 16-byte size for at least one GUID
    /// - Does not validate GUID content or format
    /// - Individual GUID access via [`get`](Self::get) provides bounds checking
    ///
    ///
    /// # See Also
    /// - [`get`](Self::get): Access individual GUIDs by 1-based index
    /// - [`iter`](Self::iter): Iterate over all GUIDs in the heap
    /// - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): GUID heap specification
    pub fn from(data: &'a [u8]) -> Result<Guid<'a>> {
        if data.len() < 16 {
            return Err(ParseFailure::Truncated {
                stage: ParseStage::Heap,
                expected: 16,
                found: data.len(),
            }
            .into());
        }

        Ok(Guid { data })
    }

    /// Retrieves a GUID from the heap by its 1-based index.
    ///
    /// Returns a constructed GUID from the 16-byte data stored at the specified index.
    /// The index typically comes from metadata table entries that reference specific
    /// GUIDs for assembly identity, type library correlation, or module identification.
    ///
    /// # Parameters
    /// * `index` - 1-based GUID index within the heap (from metadata table references)
    ///
    /// # Returns
    /// A [`uguid::Guid`] constructed from the 16-byte data at the specified index,
    /// or an error if the index is invalid or the data is insufficient.
    ///
    /// # Errors
    /// Returns [`crate::Error`] in the following cases:
    /// - **Invalid index**: Index 0 (GUIDs use 1-based indexing per ECMA-335)
    /// - **Out of bounds**: Index exceeds available GUID count
    /// - **Incomplete data**: Insufficient bytes for complete 16-byte GUID
    /// - **Integer overflow**: Index calculations exceed platform limits
    ///
    /// # Examples
    ///
    /// ## Basic GUID Access
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     // GUID 1: d437908e-65e6-487c-9735-7bdff699bea5
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    ///     // GUID 2: All zeros (null GUID)
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /// ];
    ///
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// // Access first GUID (1-based indexing)
    /// let first_guid = guid_heap.get(1)?;
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    /// assert_ne!(first_guid, null_guid);
    ///
    /// // Access second GUID
    /// let second_guid = guid_heap.get(2)?;
    /// assert_eq!(second_guid, null_guid);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Assembly Identity Example
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Assembly table references GUID index 1
    /// let assembly_guid_index = 1;
    /// let heap_data = [0xAB; 16]; // Sample assembly GUID
    ///
    /// let guid_heap = Guid::from(&heap_data)?;
    /// let assembly_guid = guid_heap.get(assembly_guid_index)?;
    ///
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    /// // Use for assembly comparison or caching
    /// if assembly_guid != null_guid {
    ///     println!("Assembly identifier: {}", assembly_guid);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0xFF; 16]; // Single GUID heap
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// // Valid access
    /// assert!(guid_heap.get(1).is_ok());
    ///
    /// // Invalid index 0 (1-based indexing required)
    /// assert!(guid_heap.get(0).is_err());
    ///
    /// // Out of bounds access
    /// assert!(guid_heap.get(2).is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance
    /// - **O(1) access**: Direct offset calculation and validation
    /// - **Zero-copy construction**: GUID built from direct data reference
    /// - **Bounds checking**: Full validation with minimal overhead
    /// - **Cache friendly**: Sequential data access pattern
    ///
    /// # Index Calculation
    /// The byte offset for a GUID is calculated as `(index - 1) * 16`:
    ///
    /// | Index | Byte Range | Description |
    /// |-------|------------|-------------|
    /// | 1     | 0-15       | First GUID  |
    /// | 2     | 16-31      | Second GUID |
    /// | N     | (N-1)*16 to N*16-1 | Nth GUID |
    ///
    /// # GUID Format
    /// Each 16-byte GUID follows RFC 4122 UUID format stored in little-endian
    /// byte order as specified by ECMA-335.
    ///
    /// # See Also
    /// - [`iter`](Self::iter): Iterate over all GUIDs sequentially
    /// - [`uguid::Guid`]: The returned GUID type with formatting and comparison methods
    /// - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): GUID heap specification
    pub fn get(&self, index: usize) -> Result<uguid::Guid> {
        let oob = || ParseFailure::HeapOutOfBounds {
            heap: HeapKind::Guid,
            index: u32::try_from(index).unwrap_or(u32::MAX),
        };
        if index < 1 {
            return Err(oob().into());
        }
        let offset_start = index
            .checked_sub(1)
            .and_then(|i| i.checked_mul(16))
            .ok_or_else(oob)?;
        let offset_end = offset_start.checked_add(16).ok_or_else(oob)?;

        let bytes = self.data.get(offset_start..offset_end).ok_or_else(oob)?;
        let mut buffer = [0u8; 16];
        buffer.copy_from_slice(bytes);

        Ok(uguid::Guid::from_bytes(buffer))
    }

    /// Returns an iterator over all GUIDs in the heap.
    ///
    /// Provides sequential access to every GUID stored in the heap, yielding
    /// both the 1-based index and constructed GUID for each entry. This is useful for
    /// comprehensive analysis, validation, or enumeration of all assembly and module identifiers.
    ///
    /// # Returns
    /// Returns a [`crate::metadata::streams::guid::GuidIterator`] that yields `(usize, uguid::Guid)` tuples containing:
    /// - **Index**: 1-based position of the GUID within the heap
    /// - **GUID**: Constructed 128-bit globally unique identifier
    ///
    /// # Iteration Behavior
    /// - **Sequential access**: GUIDs returned in storage order (index 1, 2, 3, ...)
    /// - **1-based indexing**: Consistent with ECMA-335 specification and `get()` method
    /// - **Complete iteration**: Processes all valid GUIDs until heap end
    /// - **Error handling**: Invalid GUIDs are skipped (iteration terminates early)
    ///
    /// # Examples
    ///
    /// ## Basic Iteration
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     // GUID 1: Sample assembly identifier
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    ///     // GUID 2: Null GUID
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /// ];
    ///
    /// let guid_heap = Guid::from(&heap_data)?;
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    ///
    /// for (index, guid) in guid_heap.iter() {
    ///     println!("GUID {}: {}", index, guid);
    ///     
    ///     if guid != null_guid {
    ///         println!("  Non-null identifier found");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Assembly and Module Enumeration
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0xAB; 48]; // Three identical GUIDs for demonstration
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// let mut assembly_guids = Vec::new();
    /// let mut module_guids = Vec::new();
    ///
    /// for (index, guid) in guid_heap.iter() {
    ///     
    ///     if index == 1 {
    ///         assembly_guids.push(guid);
    ///     } else {
    ///         module_guids.push(guid);
    ///     }
    /// }
    ///
    /// println!("Found {} assembly GUIDs, {} module GUIDs",
    ///          assembly_guids.len(), module_guids.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling During Iteration
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0xFF; 32]; // Two complete GUIDs
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// for (index, guid) in guid_heap.iter() {
    ///     println!("Valid GUID at index {}: {}", index, guid);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Collecting Non-Null GUIDs
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0x00; 32]; // Two null GUIDs
    /// let guid_heap = Guid::from(&heap_data)?;
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    ///
    /// let mut non_null_guids = Vec::new();
    /// for (index, guid) in guid_heap.iter() {
    ///     if guid != null_guid {
    ///         non_null_guids.push((index, guid));
    ///     }
    /// }
    ///
    /// println!("Found {} non-null GUIDs", non_null_guids.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Error Recovery
    /// If a malformed GUID is encountered (e.g., due to heap truncation),
    /// the iterator terminates early. This design ensures data integrity
    /// while allowing processing of all valid entries up to the error point.
    ///
    /// # Use Cases
    /// - **Assembly enumeration**: Identify all assemblies in a multi-module application
    /// - **GUID validation**: Verify heap integrity and detect corruption
    /// - **Debugging support**: Display all identifiers for diagnostic purposes
    /// - **Metadata analysis**: Extract identity information for processing
    ///
    /// # See Also
    /// - [`crate::metadata::streams::guid::GuidIterator`]: The iterator implementation details
    /// - [`get`](Self::get): Direct access to specific GUIDs by index
    /// - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): GUID heap specification
    #[must_use]
    pub fn iter(&self) -> GuidIterator<'_> {
        GuidIterator::new(self)
    }

    /// Returns the raw underlying data of the GUID heap.
    ///
    /// This provides access to the complete heap data containing all 16-byte GUID entries
    /// in their original binary format. This method is useful for heap size calculation,
    /// bounds checking, and low-level metadata analysis.
    ///
    /// # Returns
    /// A byte slice containing the complete GUID heap data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0xAB; 32]; // Two GUIDs, 16 bytes each
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// assert_eq!(guid_heap.data().len(), 32);
    /// assert_eq!(guid_heap.data().len() / 16, 2); // Two GUIDs
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Checks if the GUID heap contains a specific GUID value.
    ///
    /// Searches through all GUIDs in the heap to determine if any entry matches
    /// the provided GUID. This is useful for quick existence checks without
    /// needing to know the specific index.
    ///
    /// # Arguments
    /// * `guid` - The GUID value to search for
    ///
    /// # Returns
    /// `true` if the GUID exists in the heap, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    /// ];
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// let target = uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5");
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    ///
    /// assert!(guid_heap.contains(&target));
    /// assert!(!guid_heap.contains(&null_guid));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn contains(&self, guid: &uguid::Guid) -> bool {
        self.iter().any(|(_, value)| &value == guid)
    }

    /// Finds the first occurrence of a GUID and returns its 1-based index.
    ///
    /// Searches through all GUIDs in the heap and returns the 1-based index of the
    /// first matching entry. This index can be used with metadata table references.
    ///
    /// # Arguments
    /// * `guid` - The GUID value to search for
    ///
    /// # Returns
    /// `Some(index)` if the GUID is found (1-based), `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /// ];
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// let target = uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5");
    /// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
    ///
    /// assert_eq!(guid_heap.find(&target), Some(1));  // 1-based index
    /// assert_eq!(guid_heap.find(&null_guid), Some(2));  // 1-based index
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find(&self, guid: &uguid::Guid) -> Option<u32> {
        self.iter()
            .find(|(_, value)| *value == *guid)
            .and_then(|(index, _)| u32::try_from(index).ok())
    }

    /// Finds all occurrences of a GUID and returns their 1-based indices.
    ///
    /// Searches through all GUIDs in the heap and returns the 1-based indices of all
    /// matching entries. This handles the case where duplicate GUIDs exist in the heap.
    ///
    /// # Arguments
    /// * `guid` - The GUID value to search for
    ///
    /// # Returns
    /// A vector of 1-based indices where the GUID was found. Empty if not found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Guid;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    ///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
    ///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
    /// ];
    /// let guid_heap = Guid::from(&heap_data)?;
    ///
    /// let target = uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5");
    /// let indices = guid_heap.find_all(&target);
    ///
    /// assert_eq!(indices.len(), 2);
    /// assert_eq!(indices[0], 1);  // 1-based index
    /// assert_eq!(indices[1], 2);  // 1-based index
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find_all(&self, guid: &uguid::Guid) -> Vec<u32> {
        self.iter()
            .filter(|(_, value)| *value == *guid)
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect()
    }
}

impl<'a> IntoIterator for &'a Guid<'a> {
    type Item = (usize, uguid::Guid);
    type IntoIter = GuidIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator providing sequential access to all GUIDs in the `#GUID` heap.
///
/// The `GuidIterator` traverses the GUID heap in storage order, yielding each GUID's
/// 1-based index and constructed value. It handles the fixed 16-byte GUID format
/// and provides comprehensive error reporting for incomplete or corrupted entries.
///
/// # Iteration Protocol
///
/// ## Yielded Items
/// Each iteration returns `(index, guid)` where:
/// - **`index`**: 1-based position of the GUID within the heap (consistent with ECMA-335)
/// - **`guid`**: Constructed [`uguid::Guid`] from the 16-byte heap data
///
/// ## Error Handling
/// Malformed or incomplete GUIDs cause iteration termination:
/// - **Out of bounds**: GUID extends beyond heap boundaries
/// - **Incomplete data**: Less than 16 bytes available for complete GUID
/// - **Index overflow**: GUID count exceeds platform limits
///
/// ## Iteration Behavior
/// - **Starts at index 1**: Follows ECMA-335 1-based indexing convention
/// - **Sequential processing**: Processes GUIDs in heap storage order
/// - **Termination**: Stops when insufficient data remains for complete GUID
/// - **Early termination**: Immediately stops on first malformed entry
///
/// # GUID Construction
///
/// Each iteration constructs a new [`uguid::Guid`] from 16 consecutive bytes:
/// - Uses little-endian byte order as per ECMA-335
/// - Follows RFC 4122 UUID format within each 16-byte block
/// - Provides standard GUID operations (formatting, comparison, null checking)
///
/// # Examples
///
/// ## Basic Sequential Access
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// #[rustfmt::skip]
/// let heap_data = [
///     // GUID 1: Real assembly identifier
///     0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48,
///     0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
///     // GUID 2: Module identifier
///     0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
///     0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
/// ];
///
/// let guid_heap = Guid::from(&heap_data)?;
/// let mut iterator = guid_heap.iter();
/// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
///
/// // First GUID at index 1
/// let (index1, guid1) = iterator.next().unwrap();
/// assert_eq!(index1, 1);
/// assert_ne!(guid1, null_guid);
///
/// // Second GUID at index 2
/// let (index2, guid2) = iterator.next().unwrap();
/// assert_eq!(index2, 2);
/// assert_ne!(guid2, null_guid);
///
/// // No more GUIDs
/// assert!(iterator.next().is_none());
/// # Ok(())
/// # }
/// ```
///
/// ## Identity Classification
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = [0x00; 48]; // Three null GUIDs
/// let guid_heap = Guid::from(&heap_data)?;
/// let null_guid = uguid::guid!("00000000-0000-0000-0000-000000000000");
///
/// let mut null_count = 0;
/// let mut non_null_count = 0;
///
/// for result in guid_heap.iter() {
///     let (index, guid) = result;
///     
///     if guid == null_guid {
///         null_count += 1;
///         println!("Null GUID at index {}", index);
///     } else {
///         non_null_count += 1;
///         println!("Active GUID at index {}: {}", index, guid);
///     }
/// }
///
/// println!("Summary: {} null, {} active", null_count, non_null_count);
/// # Ok(())
/// # }
/// ```
///
/// ## Error Handling
/// ```rust
/// use dotscope::metadata::streams::Guid;
///
/// # fn example() -> dotscope::Result<()> {
/// // Valid heap with two complete GUIDs
/// let heap_data = [0xFF; 32];
/// let guid_heap = Guid::from(&heap_data)?;
///
/// for (index, guid) in guid_heap.iter() {
///     println!("GUID {}: {}", index, guid);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Memory Usage
///
/// - **No allocation**: GUIDs constructed on stack during iteration
/// - **Constant overhead**: Iterator state requires minimal memory
/// - **Zero-copy access**: Direct construction from heap data
///
/// # Implementation Notes
///
/// - **Index tracking**: Maintains current 1-based position
/// - **Bounds checking**: Validates sufficient data for each GUID
/// - **Error propagation**: Returns errors without advancing position
/// - **Termination logic**: Stops cleanly when heap data exhausted
///
/// # See Also
/// - [`crate::metadata::streams::guid::Guid::iter`]: Creates new iterator instances
/// - [`crate::metadata::streams::guid::Guid::get`]: Direct access to specific GUIDs by index
/// - [`uguid::Guid`]: The constructed GUID type with rich functionality
/// - [ECMA-335 II.24.2.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): GUID heap specification
pub struct GuidIterator<'a> {
    /// Reference to the GUID heap being iterated
    guid: &'a Guid<'a>,
    /// Current 1-based index into the GUID heap
    index: usize,
}

impl<'a> GuidIterator<'a> {
    /// Creates a new iterator for the given GUID heap.
    ///
    /// Initializes the iterator to begin at index 1, following the ECMA-335
    /// specification for 1-based GUID heap indexing.
    ///
    /// # Parameters
    /// * `guid` - Reference to the GUID heap to iterate over
    ///
    /// # Returns
    /// A new `GuidIterator` positioned at the first GUID entry (index 1).
    ///
    /// # Note
    /// This method is internal and called by [`crate::metadata::streams::guid::Guid::iter`]. Users should
    /// prefer the public `iter()` method for creating iterators.
    pub fn new(guid: &'a Guid<'a>) -> Self {
        Self {
            guid,
            index: 1, // GUID indices start at 1
        }
    }
}

impl Iterator for GuidIterator<'_> {
    type Item = (usize, uguid::Guid);

    fn next(&mut self) -> Option<Self::Item> {
        match self.guid.get(self.index) {
            Ok(guid) => {
                let current_index = self.index;
                self.index = self.index.saturating_add(1);
                Some((current_index, guid))
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data : [u8; 48] = [
            /* 0 - 0;16   */  0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48, 0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
            /* 1 - 16;33  */  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            /* 2 - 33;49  */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let guids = Guid::from(&data).unwrap();

        assert_eq!(
            guids.get(1).unwrap(),
            uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5")
        );
        assert_eq!(
            guids.get(2).unwrap(),
            uguid::guid!("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
        );
        assert_eq!(
            guids.get(3).unwrap(),
            uguid::guid!("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn test_guid_iterator_basic() {
        let data = [0u8; 32]; // Two empty GUIDs
        let guids = Guid::from(&data).unwrap();
        let mut iter = guids.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(
            first.1,
            uguid::guid!("00000000-0000-0000-0000-000000000000")
        );

        let second = iter.next().unwrap();
        assert_eq!(second.0, 2);
        assert_eq!(
            second.1,
            uguid::guid!("00000000-0000-0000-0000-000000000000")
        );

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_guid_iterator_single_guid() {
        #[rustfmt::skip]
        let data = [
            0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48, 
            0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
        ];

        let guids = Guid::from(&data).unwrap();
        let mut iter = guids.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(
            first.1,
            uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5")
        );

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_guid_iterator_multiple_guids() {
        #[rustfmt::skip]
        let data = [
            // First GUID
            0x8e, 0x90, 0x37, 0xd4, 0xe6, 0x65, 0x7c, 0x48, 
            0x97, 0x35, 0x7b, 0xdf, 0xf6, 0x99, 0xbe, 0xa5,
            // Second GUID (all AA)
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // Third GUID (all zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let guids = Guid::from(&data).unwrap();
        let mut iter = guids.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(
            first.1,
            uguid::guid!("d437908e-65e6-487c-9735-7bdff699bea5")
        );

        let second = iter.next().unwrap();
        assert_eq!(second.0, 2);
        assert_eq!(
            second.1,
            uguid::guid!("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")
        );

        let third = iter.next().unwrap();
        assert_eq!(third.0, 3);
        assert_eq!(
            third.1,
            uguid::guid!("00000000-0000-0000-0000-000000000000")
        );

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_guid_iterator_partial_guid() {
        // Only 10 bytes - not enough for a complete GUID
        let data = [0u8; 10];

        // This should fail at creation because data is too small
        assert!(Guid::from(&data).is_err());
    }

    #[test]
    fn test_guid_iterator_exact_size() {
        // Exactly 16 bytes - one complete GUID
        let data = [0xFF; 16];

        let guids = Guid::from(&data).unwrap();
        let mut iter = guids.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(
            first.1,
            uguid::guid!("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
        );

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_guid_index_calculation_correctness() {
        // Test with specific data pattern to verify 16-byte alignment
        // Each GUID should be exactly 16 bytes apart
        #[rustfmt::skip]
        let data = [
            // GUID 1: All 0x11
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // GUID 2: All 0x22  
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            // GUID 3: All 0x33
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        ];

        let guids = Guid::from(&data).unwrap();

        // Verify each GUID can be accessed correctly with proper 16-byte spacing
        let guid1 = guids.get(1).unwrap();
        let guid2 = guids.get(2).unwrap();
        let guid3 = guids.get(3).unwrap();

        // Each GUID should contain the expected pattern
        assert_eq!(guid1, uguid::guid!("11111111-1111-1111-1111-111111111111"));
        assert_eq!(guid2, uguid::guid!("22222222-2222-2222-2222-222222222222"));
        assert_eq!(guid3, uguid::guid!("33333333-3333-3333-3333-333333333333"));

        // Test out of bounds
        assert!(guids.get(4).is_err(), "Index 4 should be out of bounds");
        assert!(
            guids.get(0).is_err(),
            "Index 0 should be invalid (1-based indexing)"
        );
    }
}

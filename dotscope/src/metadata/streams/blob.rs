//! ECMA-335 Blob Heap (`#Blob`) for .NET Metadata Storage
//!
//! This module provides access to the binary blob heap in .NET assemblies according to ECMA-335
//! Section II.24.2.4. The blob heap stores variable-length binary data including method signatures,
//! custom attribute values, field signatures, and other metadata that cannot be represented
//! as simple strings or primitive values.
//!
//! # Blob Heap Structure
//!
//! The `#Blob` heap is a sequence of variable-length binary chunks where each blob is prefixed
//! with its size encoded in a compressed format. The heap always starts with a null byte at
//! offset 0, and subsequent blobs are stored consecutively with no padding.
//!
//! ## Size Encoding Format
//!
//! Blob sizes are encoded using ECMA-335's compressed unsigned integer format:
//!
//! - **1-byte encoding**: `0bbbbbbb` → size = `bbbbbbb` (0-127 bytes)
//! - **2-byte encoding**: `10bbbbbb xxxxxxxx` → size = `(bbbbbb << 8) | xxxxxxxx` (128-16,383 bytes)
//! - **4-byte encoding**: `110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz` → size = `(bbbbb << 24) | (x << 16) | (y << 8) | z` (16,384+ bytes)
//!
//! ## Memory Layout
//!
//! ```text
//! Offset | Content
//! -------|--------
//! 0x00   | 0x00 (null blob)
//! 0x01   | Size₁ | Data₁...
//! ...    | Size₂ | Data₂...
//! ...    | Size₃ | Data₃...
//! ```
//!
//! # Blob Content Types
//!
//! The blob heap stores various types of binary metadata:
//!
//! ## Method Signatures
//! Binary-encoded method signatures containing:
//! - Calling conventions and parameter counts
//! - Return type and parameter type information
//! - Generic parameter specifications
//!
//! ## Field Signatures
//! Type information for fields including:
//! - Base type specifications
//! - Custom modifiers and constraints
//! - Array and pointer type definitions
//!
//! ## Custom Attribute Values
//! Serialized constructor arguments and named parameters:
//! - Primitive value arrays
//! - String and enum values
//! - Complex nested structures
//!
//! ## Constant Values
//! Default values for fields and parameters:
//! - Primitive type values
//! - String constants
//! - Null references
//!
//! # Examples
//!
//! ## Basic Blob Access
//! ```rust
//! use dotscope::metadata::streams::Blob;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Example blob heap with two entries
//! let data = &[
//!     0x00,                    // Null blob at offset 0
//!     0x03, 0x41, 0x42, 0x43, // 3-byte blob "ABC" at offset 1
//!     0x02, 0x44, 0x45        // 2-byte blob "DE" at offset 5
//! ];
//!
//! let blob_heap = Blob::from(data)?;
//!
//! // Access blob at offset 1 (referenced by metadata tables)
//! let first_blob = blob_heap.get(1)?;
//! assert_eq!(first_blob, b"ABC");
//!
//! // Access blob at offset 5
//! let second_blob = blob_heap.get(5)?;
//! assert_eq!(second_blob, b"DE");
//! # Ok(())
//! # }
//! ```
//!
//! ## Iterating Over All Blobs
//! ```rust
//! use dotscope::metadata::streams::Blob;
//!
//! # fn example() -> dotscope::Result<()> {
//! let data = &[0x00, 0x03, 0x41, 0x42, 0x43, 0x02, 0x44, 0x45];
//! let blob_heap = Blob::from(data)?;
//!
//! for (offset, blob_data) in blob_heap.iter() {
//!     println!("Blob at offset {}: {} bytes", offset, blob_data.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with Large Blobs
//! ```rust
//! use dotscope::metadata::streams::Blob;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Create blob heap with a large blob (2-byte size encoding)
//! let mut data = vec![0x00];
//! data.push(0x81);  // First byte: 10000001 (2-byte encoding)
//! data.push(0x00);  // Second byte: 00000000 (total size = 128)
//! data.extend(vec![0xFF; 128]); // 128 bytes of data
//!
//! let blob_heap = Blob::from(&data)?;
//! let large_blob = blob_heap.get(1)?;
//! assert_eq!(large_blob.len(), 128);
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! The blob heap API provides comprehensive error handling for:
//! - **Invalid Heap Format**: Missing null byte at offset 0
//! - **Out of Bounds Access**: Invalid blob offsets or corrupted size data
//! - **Truncated Data**: Incomplete blob entries
//! - **Malformed Size Encoding**: Invalid compressed integer format
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 Partition II, Section 24.2.4:
//! - Supports all three size encoding formats
//! - Handles edge cases like empty blobs and maximum size limits
//! - Provides safe access with proper bounds checking
//! - Maintains the required null blob at offset 0
//!
//! # See Also
//!
//! - [`crate::metadata::streams::Strings`]: For string heap access
//! - [`crate::metadata::streams::UserStrings`]: For user string heap access
//! - [`crate::metadata::signatures`]: For parsing blob content as signatures
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Official specification
//!
//! # References
//!
//! - **ECMA-335 II.24.2.4**: `#Blob` heap specification
//! - **ECMA-335 II.23.2**: Signature encoding formats stored in blobs

use std::sync::{Arc, OnceLock};

use dashmap::DashMap;

use crate::{
    file::parser::Parser,
    metadata::{
        pdb::DocumentName,
        streams::{sentinel_heap, SharedBytes},
    },
    Error, HeapKind, ParseFailure, Result,
};

/// ECMA-335 binary blob heap providing indexed access to variable-length data.
///
/// The `Blob` struct represents the `#Blob` metadata heap according to ECMA-335 Section II.24.2.4.
/// It provides safe, zero-copy access to binary data referenced by metadata table entries
/// such as method signatures, field types, custom attributes, and constant values.
///
/// # Blob Heap Properties
///
/// ## Indexed Access Model
/// Blobs are accessed by offset rather than sequential iteration:
/// - Metadata tables store blob heap offsets as indices
/// - Each offset points to a size-prefixed binary chunk
/// - Size encoding uses compressed unsigned integers
/// - Random access enables efficient metadata parsing
///
/// ## Size Encoding Details
/// The blob size prefix uses ECMA-335 compressed format:
///
/// ```text
/// Format           | Size Range        | Encoding
/// -----------------|-------------------|------------------
/// 1-byte           | 0-127 bytes      | 0bbbbbbb
/// 2-byte           | 128-16,383 bytes | 10bbbbbb xxxxxxxx
/// 4-byte           | 16,384+ bytes    | 110bbbbb xxxxxxxx yyyyyyyy zzzzzzzz
/// ```
///
/// ## Memory Layout
/// ```text
/// Offset | Content
/// -------|------------------
/// 0      | 0x00 (null blob)
/// 1      | Size₁ | Data₁
/// N      | Size₂ | Data₂
/// M      | Size₃ | Data₃
/// ```
///
/// # Blob Content Categories
///
/// ## Signature Blobs
/// Method, field, and property signatures:
/// - Calling conventions and parameter information
/// - Type specifications and generic parameters
/// - Custom modifiers and constraints
///
/// ## Custom Attribute Blobs
/// Constructor arguments and named parameters:
/// - Primitive arrays and enum values
/// - Complex nested data structures
/// - String and object references
///
/// ## Constant Value Blobs
/// Default values for fields and parameters:
/// - Primitive type constants
/// - String literals and null values
/// - Binary data for complex constants
///
/// # Safety and Error Handling
///
/// The `Blob` struct provides comprehensive safety guarantees:
/// - Bounds checking for all offset and size calculations
/// - Validation of compressed size encoding format
/// - Protection against integer overflow in size calculations
/// - Graceful handling of truncated or malformed data
///
/// # Examples
///
/// ## Creating and Accessing Blobs
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// // Create blob heap with sample data
/// let heap_data = &[
///     0x00,                           // Required null blob at offset 0
///     0x04, 0x01, 0x02, 0x03, 0x04,  // 4-byte blob at offset 1
///     0x02, 0xFF, 0xFE,              // 2-byte blob at offset 6
/// ];
///
/// let blob_heap = Blob::from(heap_data)?;
///
/// // Access specific blobs by offset (as referenced by metadata tables)
/// let first_blob = blob_heap.get(1)?;
/// assert_eq!(first_blob, &[0x01, 0x02, 0x03, 0x04]);
///
/// let second_blob = blob_heap.get(6)?;
/// assert_eq!(second_blob, &[0xFF, 0xFE]);
/// # Ok(())
/// # }
/// ```
///
/// ## Handling Large Blobs
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// // Large blob with 2-byte size encoding
/// let mut heap_data = vec![0x00];                    // Null blob
/// heap_data.push(0x81);                             // Size: 10000001 (2-byte format)
/// heap_data.push(0x00);                             // Size: 00000000 (total = 128)
/// heap_data.extend(std::iter::repeat(0xAA).take(128)); // 128 bytes of data
///
/// let blob_heap = Blob::from(&heap_data)?;
/// let large_blob = blob_heap.get(1)?;
/// assert_eq!(large_blob.len(), 128);
/// assert!(large_blob.iter().all(|&b| b == 0xAA));
/// # Ok(())
/// # }
/// ```
///
/// ## Iterating Through All Blobs
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = &[0x00, 0x03, 0x41, 0x42, 0x43, 0x01, 0x44];
/// let blob_heap = Blob::from(heap_data)?;
///
/// for (offset, data) in &blob_heap {
///     println!("Blob at offset {}: {:02X?}", offset, data);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # ECMA-335 Compliance
///
/// This implementation fully supports ECMA-335 requirements:
/// - Correct handling of all three size encoding formats
/// - Mandatory null blob at offset 0
/// - Proper bounds checking and error handling
/// - Support for maximum blob sizes (up to 2^29 bytes)
///
/// # See Also
/// - [`BlobIterator`]: For sequential access to all blobs
/// - [`crate::metadata::signatures`]: For parsing blob content as type signatures
/// - [`crate::file::parser::Parser`]: For reading compressed integers
/// - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Official specification
///
pub struct Blob<'a> {
    /// Raw bytes of the blob heap
    data: &'a [u8],
    /// A copy of the heap shared by every [`SharedBytes`] taken from it, made on the first
    /// [`Self::get_shared`]
    shared: OnceLock<Arc<[u8]>>,
    /// Each Portable PDB document name read through [`Self::document_name`], by its blob's
    /// index: a name blob is checked once, however many Document rows name it
    document_names: DashMap<u32, Result<DocumentName>>,
}

impl<'a> Blob<'a> {
    /// Creates a new `Blob` heap accessor from raw metadata bytes.
    ///
    /// Validates that the provided data represents a well-formed ECMA-335 `#Blob` heap
    /// with the required null blob at offset 0. The blob heap stores variable-length
    /// binary data referenced by metadata table entries.
    ///
    /// # Parameters
    /// * `data` - Raw bytes containing the complete `#Blob` heap data
    ///
    /// # Returns
    /// A `Blob` instance providing safe access to the heap contents, or an error
    /// if the data format is invalid.
    ///
    /// # Errors
    /// Returns [`crate::Error`] in the following cases:
    /// - **Empty data**: The heap must contain at least one byte
    /// - **Missing null blob**: First byte must be 0x00 per ECMA-335 requirements
    /// - **Invalid format**: Data doesn't conform to blob heap structure
    ///
    /// # Examples
    ///
    /// ## Valid Blob Heap
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let valid_data = &[
    ///     0x00,                    // Required null blob at offset 0
    ///     0x04, 0x01, 0x02, 0x03, 0x04,  // 4-byte blob
    ///     0x02, 0xFF, 0xFE,        // 2-byte blob
    /// ];
    ///
    /// let blob_heap = Blob::from(valid_data)?;
    /// assert_eq!(blob_heap.get(1)?, &[0x01, 0x02, 0x03, 0x04]);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Invalid Blob Heap
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// // Missing required null byte at offset 0
    /// let invalid_data = &[0x01, 0x02, 0x03];
    /// assert!(Blob::from(invalid_data).is_err());
    ///
    /// // A stream of no bytes is a heap with no entries
    /// let empty_heap = Blob::from(&[]).unwrap();
    /// assert!(empty_heap.get(0).unwrap().is_empty());
    /// ```
    ///
    /// # Safety
    /// This method performs minimal validation for performance. Individual blob
    /// access via [`get`](Self::get) provides comprehensive bounds checking.
    ///
    /// # See Also
    /// - [`get`](Self::get): Access individual blobs by offset
    /// - [`iter`](Self::iter): Iterate over all blobs in the heap
    /// - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Blob heap specification
    pub fn from(data: &'a [u8]) -> Result<Blob<'a>> {
        Ok(Blob {
            data: sentinel_heap(data, HeapKind::Blob)?,
            shared: OnceLock::new(),
            document_names: DashMap::new(),
        })
    }

    /// Retrieves a blob from the heap by its offset.
    ///
    /// Returns a zero-copy view of the binary data stored at the specified offset.
    /// The offset typically comes from metadata table entries that reference blob
    /// heap data such as method signatures, custom attributes, or constant values.
    ///
    /// # Parameters
    /// * `index` - Byte offset within the blob heap (from metadata table references)
    ///
    /// # Returns
    /// A slice containing the blob data at the specified offset, or an error
    /// if the offset is invalid or the blob is malformed.
    ///
    /// # Errors
    /// Returns [`crate::Error`] in the following cases:
    /// - **Out of bounds**: `index` exceeds the heap size
    /// - **Invalid size encoding**: Blob size header is malformed
    /// - **Truncated data**: Blob extends beyond heap boundaries
    /// - **Integer overflow**: Size calculations exceed platform limits
    ///
    /// # Examples
    ///
    /// ## Basic Blob Access
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = &[
    ///     0x00,                           // Null blob at offset 0
    ///     0x03, 0x41, 0x42, 0x43,        // "ABC" at offset 1
    ///     0x81, 0x02,                     // 2-byte size encoding for 258 bytes
    ///     // ... 258 bytes of data would follow
    /// ];
    ///
    /// let blob_heap = Blob::from(&data[..6])?; // Truncated for example
    ///
    /// // Access null blob (always empty)
    /// let null_blob = blob_heap.get(0)?;
    /// assert_eq!(null_blob, &[] as &[u8]);
    ///
    /// // Access first real blob
    /// let first_blob = blob_heap.get(1)?;
    /// assert_eq!(first_blob, b"ABC");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = &[0x00, 0x02, 0x41]; // Blob claims 2 bytes but only 1 available
    /// let blob_heap = Blob::from(data)?;
    ///
    /// // This will fail due to truncated data
    /// assert!(blob_heap.get(1).is_err());
    ///
    /// // Out of bounds access
    /// assert!(blob_heap.get(100).is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Size Encoding Details
    /// The blob size is encoded using ECMA-335 compressed unsigned integers:
    ///
    /// | Encoding | First Byte Pattern | Size Range |
    /// |----------|-------------------|------------|
    /// | 1-byte   | `0bbbbbbb`        | 0-127      |
    /// | 2-byte   | `10bbbbbb`        | 128-16,383 |
    /// | 4-byte   | `110bbbbb`        | 16,384+    |
    ///
    /// # See Also
    /// - [`iter`](Self::iter): Iterate over all blobs sequentially
    /// - [`crate::file::parser::Parser`]: For compressed integer parsing
    /// - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Compressed integer format
    pub fn get(&self, index: usize) -> Result<&'a [u8]> {
        let (start, end) = self.range(index)?;
        self.data.get(start..end).ok_or_else(|| {
            Error::from(ParseFailure::HeapOutOfBounds {
                heap: HeapKind::Blob,
                index: u32::try_from(index).unwrap_or(u32::MAX),
            })
        })
    }

    /// The byte range in the heap of the blob whose length prefix is at `index`.
    ///
    /// # Errors
    /// Returns an error when `index` is past the heap, its length prefix does not read, or the
    /// blob runs past the heap's end.
    fn range(&self, index: usize) -> Result<(usize, usize)> {
        let oob = || ParseFailure::HeapOutOfBounds {
            heap: HeapKind::Blob,
            index: u32::try_from(index).unwrap_or(u32::MAX),
        };
        if index >= self.data.len() {
            return Err(oob().into());
        }

        let mut parser = Parser::new(self.data.get(index..).ok_or_else(oob)?);
        let len = parser.read_compressed_uint()? as usize;
        let skip = parser.pos();

        let Some(data_start) = index.checked_add(skip) else {
            return Err(oob().into());
        };

        let Some(data_end) = data_start.checked_add(len) else {
            return Err(oob().into());
        };
        if data_end > self.data.len() {
            return Err(oob().into());
        }
        Ok((data_start, data_end))
    }

    /// Retrieves a blob from the heap as [`SharedBytes`].
    ///
    /// Resolves the same blob as [`Self::get`], and fails where it fails, but returns a view
    /// of one copy of the heap shared by every blob taken this way: a metadata row keeps its
    /// blob for the cost of a reference, however long the blob is and however many rows name
    /// it. The first call copies the heap once.
    ///
    /// # Arguments
    /// * `index` - Byte offset of the blob's length prefix within the heap
    ///
    /// # Errors
    /// Returns an error when `index` is past the heap, its length prefix does not read, or the
    /// blob runs past the heap's end.
    pub fn get_shared(&self, index: usize) -> Result<SharedBytes> {
        let (start, end) = self.range(index)?;
        SharedBytes::view(self.shared_heap(), start, end.saturating_sub(start)).ok_or_else(|| {
            Error::from(ParseFailure::HeapOutOfBounds {
                heap: HeapKind::Blob,
                index: u32::try_from(index).unwrap_or(u32::MAX),
            })
        })
    }

    /// The Portable PDB document name whose DocumentNameBlob is at `index`.
    ///
    /// Checks the name blob and its parts once per index, however many Document rows name
    /// it, and returns a [`DocumentName`] that shares the heap's copy (see
    /// [`Self::get_shared`]), so a row costs the same whatever its name's length.
    ///
    /// # Errors
    /// Returns an error when the name blob does not read, its separator is not ASCII, or a
    /// part's index names no blob.
    pub fn document_name(&self, index: u32) -> Result<DocumentName> {
        self.document_names
            .entry(index)
            .or_insert_with(|| DocumentName::read(self, index))
            .clone()
    }

    /// The copy of the heap shared by [`Self::get_shared`] and the views built on it, made on
    /// the first call.
    pub fn shared_heap(&self) -> Arc<[u8]> {
        Arc::clone(self.shared.get_or_init(|| Arc::from(self.data)))
    }

    /// Returns an iterator over all blobs in the heap.
    ///
    /// Provides sequential access to every blob stored in the heap, yielding
    /// both the offset and binary data for each entry. This is useful for
    /// comprehensive analysis, validation, or debugging of blob heap contents.
    ///
    /// # Returns
    /// A [`BlobIterator`] that yields `(usize, &[u8])` tuples containing:
    /// - **Offset**: Byte position of the blob within the heap
    /// - **Data**: Zero-copy slice of the blob's binary content
    ///
    /// # Iteration Behavior
    /// - **Sequential access**: Blobs returned in heap order (not offset order)
    /// - **Skips null blob**: Iterator starts at offset 1, skipping the null blob at 0
    /// - **Error handling**: Iterator stops on malformed blobs rather than continuing
    /// - **Zero-copy**: Each blob is a direct slice reference to heap data
    ///
    /// # Examples
    ///
    /// ## Basic Iteration
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = &[
    ///     0x00,                    // Null blob (skipped by iterator)
    ///     0x03, 0x41, 0x42, 0x43, // "ABC" blob at offset 1
    ///     0x02, 0x44, 0x45,       // "DE" blob at offset 5
    ///     0x00,                   // Empty blob at offset 8
    /// ];
    ///
    /// let blob_heap = Blob::from(data)?;
    ///
    /// for (offset, blob_data) in blob_heap.iter() {
    ///     println!("Blob at offset {}: {} bytes", offset, blob_data.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling During Iteration
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = &[0x00, 0x05, 0x41, 0x42]; // Claims 5 bytes but only 2 available
    /// let blob_heap = Blob::from(data)?;
    ///
    /// for (offset, blob_data) in blob_heap.iter() {
    ///     println!("Valid blob at {}: {:02X?}", offset, blob_data);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Collecting All Valid Blobs
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = &[0x00, 0x02, 0x41, 0x42, 0x01, 0x43];
    /// let blob_heap = Blob::from(data)?;
    ///
    /// let blobs: Vec<_> = blob_heap.iter().collect();
    ///
    /// assert_eq!(blobs.len(), 2);
    /// assert_eq!(blobs[0], (1, &[0x41, 0x42][..]));
    /// assert_eq!(blobs[1], (4, &[0x43][..]));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Error Handling
    /// If a malformed blob is encountered, the iterator stops and returns None.
    /// This design prioritizes data integrity over partial processing of
    /// potentially corrupted metadata.
    ///
    ///
    /// # See Also
    /// - [`BlobIterator`]: The iterator implementation details
    /// - [`get`](Self::get): Direct access to specific blobs by offset
    /// - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Blob heap specification
    #[must_use]
    pub fn iter(&self) -> BlobIterator<'_> {
        BlobIterator::new(self)
    }

    /// Returns the raw underlying data of the blob heap.
    ///
    /// This provides access to the complete heap data including the null byte at offset 0
    /// and all blob entries in their original binary format.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Checks if the blob heap contains a specific byte sequence.
    ///
    /// Searches through all blobs in the heap to determine if any entry matches
    /// the provided byte data exactly. This is useful for quick existence checks
    /// when looking for specific signatures or custom attribute values.
    ///
    /// # Arguments
    /// * `data` - The byte sequence to search for
    ///
    /// # Returns
    /// `true` if the blob exists in the heap, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     0x03, 0x41, 0x42, 0x43,  // "ABC"
    ///     0x02, 0x44, 0x45,        // "DE"
    /// ];
    /// let blob = Blob::from(&heap_data)?;
    ///
    /// assert!(blob.contains(b"ABC"));
    /// assert!(blob.contains(b"DE"));
    /// assert!(!blob.contains(b"NotFound"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn contains(&self, data: &[u8]) -> bool {
        self.iter().any(|(_, value)| value == data)
    }

    /// Finds the first occurrence of a blob and returns its heap offset.
    ///
    /// Searches through all blobs in the heap and returns the byte offset of the
    /// first matching entry. This offset can be used with metadata table references.
    ///
    /// # Arguments
    /// * `data` - The byte sequence to search for
    ///
    /// # Returns
    /// `Some(offset)` if the blob is found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     0x03, 0x41, 0x42, 0x43,  // "ABC" at offset 1
    ///     0x02, 0x44, 0x45,        // "DE" at offset 5
    /// ];
    /// let blob = Blob::from(&heap_data)?;
    ///
    /// assert_eq!(blob.find(b"ABC"), Some(1));
    /// assert_eq!(blob.find(b"DE"), Some(5));
    /// assert_eq!(blob.find(b"NotFound"), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find(&self, data: &[u8]) -> Option<u32> {
        self.iter()
            .find(|(_, value)| *value == data)
            .and_then(|(offset, _)| u32::try_from(offset).ok())
    }

    /// Finds all occurrences of a blob and returns their heap offsets.
    ///
    /// Searches through all blobs in the heap and returns the byte offsets of all
    /// matching entries. This handles the case where duplicate blobs exist in the heap.
    ///
    /// # Arguments
    /// * `data` - The byte sequence to search for
    ///
    /// # Returns
    /// A vector of offsets where the blob was found. Empty if not found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Blob;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     0x02, 0x41, 0x42,  // "AB" at offset 1
    ///     0x02, 0x41, 0x42,  // "AB" at offset 4
    /// ];
    /// let blob = Blob::from(&heap_data)?;
    ///
    /// let offsets = blob.find_all(b"AB");
    /// assert_eq!(offsets.len(), 2);
    /// assert_eq!(offsets[0], 1);
    /// assert_eq!(offsets[1], 4);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<u32> {
        self.iter()
            .filter(|(_, value)| *value == data)
            .filter_map(|(offset, _)| u32::try_from(offset).ok())
            .collect()
    }
}

impl<'a> IntoIterator for &'a Blob<'a> {
    type Item = (usize, &'a [u8]);
    type IntoIter = BlobIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator providing sequential access to all blobs in the `#Blob` heap.
///
/// The `BlobIterator` traverses the blob heap in storage order, yielding each blob's
/// offset and binary data. It automatically handles the variable-length encoding
/// and provides comprehensive error reporting for malformed entries.
///
/// # Iteration Protocol
///
/// ## Yielded Items
/// Each successful iteration returns `Ok((offset, data))` where:
/// - **`offset`**: Byte position of the blob within the heap
/// - **`data`**: Zero-copy slice containing the blob's binary content
///
/// ## Error Handling
/// Malformed blobs yield `Err(Error)` with specific error information:
/// - **Truncated size encoding**: Invalid compressed integer format
/// - **Out of bounds data**: Blob extends beyond heap boundaries  
/// - **Parse failures**: Corrupted size headers or data alignment
///
/// ## Iteration Behavior
/// - **Starts at offset 1**: Skips the mandatory null blob at offset 0
/// - **Sequential processing**: Processes blobs in heap storage order
/// - **Lazy evaluation**: Size and data parsed only when accessed
/// - **Error recovery**: Attempts to continue after non-fatal errors
///
/// # Memory and Performance
///
/// - **Zero-copy access**: All blob data returned as direct slice references
/// - **Minimal state**: Iterator maintains only position and heap reference
/// - **Cache-friendly**: Sequential access pattern optimizes memory locality
/// - **Bounded iteration**: Always terminates when heap end is reached
///
/// # Examples
///
/// ## Basic Sequential Access
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// let data = &[0x00, 0x03, 0x41, 0x42, 0x43, 0x01, 0x44];
/// let blob_heap = Blob::from(data)?;
/// let mut iterator = blob_heap.iter();
///
/// // First blob: "ABC" at offset 1
/// let (offset1, blob1) = iterator.next().unwrap();
/// assert_eq!(offset1, 1);
/// assert_eq!(blob1, b"ABC");
///
/// // Second blob: "D" at offset 5
/// let (offset2, blob2) = iterator.next().unwrap();
/// assert_eq!(offset2, 5);
/// assert_eq!(blob2, b"D");
///
/// // No more blobs
/// assert!(iterator.next().is_none());
/// # Ok(())
/// # }
/// ```
///
/// ## Error Handling
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// // Malformed heap: blob claims 10 bytes but only 3 available
/// let data = &[0x00, 0x0A, 0x41, 0x42, 0x43];
/// let blob_heap = Blob::from(data)?;
///
/// for (offset, blob_data) in blob_heap.iter() {
///     println!("Valid blob at {}: {} bytes", offset, blob_data.len());
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Filtering and Processing
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// # fn example() -> dotscope::Result<()> {
/// let data = &[0x00, 0x00, 0x03, 0x41, 0x42, 0x43, 0x00];
/// let blob_heap = Blob::from(data)?;
///
/// // Find all non-empty blobs
/// let non_empty_blobs: Vec<_> = blob_heap
///     .iter()
///     .filter(|(_, data)| !data.is_empty())
///     .collect();
///
/// assert_eq!(non_empty_blobs.len(), 1);
/// assert_eq!(non_empty_blobs[0].1, b"ABC");
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// - **State management**: Tracks current position and source blob reference
/// - **Size parsing**: Uses [`crate::file::parser::Parser`] for compressed integers
/// - **Bounds checking**: Validates all offset and length calculations
/// - **Memory safety**: Lifetime bounds ensure heap data remains valid
///
/// # See Also
/// - [`Blob::iter`]: Creates new iterator instances
/// - [`Blob::get`]: Direct access to specific blobs by offset
/// - [`crate::file::parser::Parser`]: Compressed integer parsing implementation
/// - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Blob heap specification
pub struct BlobIterator<'a> {
    /// Reference to the blob heap being iterated
    blob: &'a Blob<'a>,
    /// Current position within the blob heap
    position: usize,
}

impl<'a> BlobIterator<'a> {
    /// Creates a new iterator for the given blob heap.
    ///
    /// Initializes the iterator to begin at offset 1, automatically skipping
    /// the mandatory null blob at offset 0 as required by ECMA-335.
    ///
    /// # Parameters
    /// * `blob` - Reference to the blob heap to iterate over
    ///
    /// # Returns
    /// A new `BlobIterator` positioned at the first non-null blob entry.
    ///
    /// # Note
    /// This method is internal and called by [`Blob::iter`]. Users should
    /// prefer the public `iter()` method for creating iterators.
    pub fn new(blob: &'a Blob<'a>) -> Self {
        Self {
            blob,
            position: 1, // Skip the initial null byte at position 0
        }
    }
}

impl<'a> Iterator for BlobIterator<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.blob.data.len() {
            return None;
        }

        let start_position = self.position;
        match self.blob.get(self.position) {
            Ok(blob_data) => {
                let remainder = self.blob.data.get(self.position..)?;
                let mut parser = Parser::new(remainder);
                if parser.read_compressed_uint().is_ok() {
                    let length_bytes = parser.pos();
                    self.position = self
                        .position
                        .saturating_add(length_bytes)
                        .saturating_add(blob_data.len());
                    Some((start_position, blob_data))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `#Blob` stream of no bytes (Mono's `ilasm`, an assembly with no method) is a heap with
    /// no entries: index 0 is the empty blob, any other index out of bounds.
    #[test]
    fn a_stream_of_no_bytes_is_a_heap_of_no_entries() {
        let heap = Blob::from(&[]).unwrap();

        assert_eq!(heap.get(0).unwrap(), &[] as &[u8]);
        assert!(heap.get(1).is_err());
        assert_eq!(heap.iter().count(), 0);
    }

    /// Bytes that do not begin with the sentinel stay corrupt: only the stream of no bytes
    /// changes meaning.
    #[test]
    fn bytes_without_the_sentinel_are_corrupt() {
        assert!(Blob::from(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data = { 
            let mut data = vec![0xCC; 262143];
            /* i - 0    - should always be 0    */ data[0]          = 0b_00000000_u8;

            /* i - 1    - len 10                */ data[1]          = 0b_00001010_u8;
            /* i - 1    - len 10                */ data[2..12]      .copy_from_slice(&[0x0A; 10]);
    
            /* i - 12   - len 5                 */ data[12]         = 0b_00000101_u8;
            /* i - 12   - len 5                 */ data[13..18]     .copy_from_slice(&[0xAB; 5]);

            /* i - 18   - len 0 - invalid       */ data[18]         = 0b_11111111_u8;
    
            /* i - 19   - len 256               */ data[19]         = 0b_10000001_u8;
            /* i - 19   - len 256               */ data[20]         = 0b_00000001_u8;
            /* i - 19   - len 256               */ data[21..278]    .copy_from_slice(&[0xBA; 257]);
            /* i - 2070 - len 2048              */ data[278]        = 0b_11000000_u8;
            /* i - 2070 - len 2048              */ data[279]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[280]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[281]        = 0b_00000001_u8;
            /* i - 2070 - len 2048              */ data[282..66075]  .copy_from_slice(&[0xBA; 65793]);

            data
        };

        let blob = Blob::from(&data).unwrap();

        {
            let indexed = blob.get(0).unwrap();
            assert_eq!(indexed.len(), 0);
        }

        {
            let indexed = blob.get(1).unwrap();
            assert_eq!(indexed.len(), 10);
            assert_eq!(indexed, &[0x0A; 10]);
        }

        {
            let indexed = blob.get(12).unwrap();
            assert_eq!(indexed.len(), 5);
            assert_eq!(indexed, &[0xAB; 5]);
        }

        {
            if blob.get(18).is_ok() {
                panic!("This should not be valid!")
            }
        }

        {
            let indexed = blob.get(19).unwrap();
            assert_eq!(indexed.len(), 257);
            assert_eq!(indexed, &[0xBA; 257]);
        }

        {
            let indexed = blob.get(278).unwrap();
            assert_eq!(indexed.len(), 65793);
            assert_eq!(indexed, &[0xBA; 65793]);
        }
    }

    #[test]
    fn test_blob_iterator_basic() {
        let data = [0x00, 0x02, 0x41, 0x42, 0x01, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.len(), 2);
        assert_eq!(first.1, &[0x41, 0x42]);

        let second = iter.next().unwrap();
        assert_eq!(second.0, 4);
        assert_eq!(second.1.len(), 1);
        assert_eq!(second.1, &[0x43]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_empty_blob() {
        let data = [0x00, 0x00, 0x02, 0x41, 0x42];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.len(), 0);
        assert_eq!(first.1, &[] as &[u8]);

        let second = iter.next().unwrap();
        assert_eq!(second.0, 2);
        assert_eq!(second.1.len(), 2);
        assert_eq!(second.1, &[0x41, 0x42]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_large_blob() {
        // Test with two-byte length encoding
        let mut data = vec![0x00, 0x81, 0x02]; // Length 258 (two-byte encoding)
        data.extend(vec![0xFF; 258]);
        data.push(0x01); // Single byte blob
        data.push(0xAA);

        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.len(), 258);
        assert_eq!(first.1, &vec![0xFF; 258]);

        let second = iter.next().unwrap();
        assert_eq!(second.0, 261);
        assert_eq!(second.1.len(), 1);
        assert_eq!(second.1, &[0xAA]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_truncated_data() {
        // Blob claims length 5 but only 3 bytes available
        let data = [0x00, 0x05, 0x41, 0x42, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_blob_iterator_single_item() {
        let data = [0x00, 0x03, 0x41, 0x42, 0x43];
        let blob = Blob::from(&data).unwrap();
        let mut iter = blob.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.len(), 3);
        assert_eq!(first.1, &[0x41, 0x42, 0x43]);

        assert!(iter.next().is_none());
    }
}

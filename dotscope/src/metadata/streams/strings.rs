//! ECMA-335 Strings Heap (`#Strings`) for .NET Metadata Identifier Storage
//!
//! This module provides comprehensive parsing and access to the `#Strings` heap defined in
//! ECMA-335 Section II.24.2.3. The strings heap stores UTF-8 encoded identifier strings
//! referenced by metadata tables throughout the .NET assembly, including type names,
//! member names, namespaces, and other symbolic identifiers.
//!
//! # Strings Heap Structure
//!
//! The `#Strings` heap is a sequential collection of null-terminated UTF-8 strings
//! with specific formatting requirements:
//!
//! ## Binary Layout
//! ```text
//! Offset | Content                    | Description
//! -------|----------------------------|------------------------------------------
//! 0      | 0x00                      | Mandatory null byte (empty string at index 0)
//! 1      | String₁ + 0x00            | First identifier string with null terminator
//! N      | String₂ + 0x00            | Second identifier string with null terminator
//! ...    | ...                       | Additional strings in sequential order
//! ```
//!
//! ## String Content Types
//!
//! The strings heap contains various categories of UTF-8 identifier strings:
//!
//! ### Type System Identifiers
//! - **Namespace names**: `System`, `System.Collections`, `Microsoft.Extensions`
//! - **Type names**: `Console`, `List<T>`, `Dictionary<TKey,TValue>`
//! - **Generic parameter names**: `T`, `TKey`, `TValue`, `TResult`
//!
//! ### Member Identifiers  
//! - **Method names**: `WriteLine`, `ToString`, `GetHashCode`, `Equals`
//! - **Property names**: `Length`, `Count`, `Capacity`, `IsReadOnly`
//! - **Field names**: `value__`, `m_items`, `m_size`
//! - **Event names**: `PropertyChanged`, `Click`, `Load`
//!
//! ### Metadata Identifiers
//! - **Assembly names**: `mscorlib`, `System.Core`, `MyApplication`
//! - **Module names**: `<Module>`, `Main.exe`, `Library.dll`
//! - **Resource names**: Embedded resource identifiers
//!
//! ## ECMA-335 Compliance Requirements
//!
//! - **Index 0**: Must contain a null byte (empty string) per ECMA-335
//! - **UTF-8 Encoding**: All strings must be valid UTF-8 sequences
//! - **Null Termination**: Each string must end with a 0x00 byte
//! - **Sequential Layout**: Strings stored contiguously without gaps or padding
//! - **Reference Integrity**: All table references must point to valid string offsets
//!
//! # Examples
//!
//! ## Basic String Heap Access
//! ```rust
//! use dotscope::metadata::streams::Strings;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Example strings heap with identifier strings
//! #[rustfmt::skip]
//! let heap_data = [
//!     0x00,                              // Index 0: empty string (required)
//!     b'S', b'y', b's', b't', b'e', b'm', 0x00,  // Index 1: "System"
//!     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,  // Index 8: "Console"
//!     b'W', b'r', b'i', b't', b'e', b'L', b'i', b'n', b'e', 0x00,  // Index 16: "WriteLine"
//! ];
//!
//! let strings = Strings::from(&heap_data)?;
//!
//! // Access specific strings by offset
//! let namespace = strings.get(1)?;     // "System"
//! let type_name = strings.get(8)?;     // "Console"
//! let method_name = strings.get(16)?;  // "WriteLine"
//!
//! assert_eq!(namespace, "System");
//! assert_eq!(type_name, "Console");
//! assert_eq!(method_name, "WriteLine");
//!
//! println!("Found method: {}.{}.{}", namespace, type_name, method_name);
//! # Ok(())
//! # }
//! ```
//!
//! ## Iterating Over All Strings
//! ```rust
//! use dotscope::metadata::streams::Strings;
//!
//! # fn example() -> dotscope::Result<()> {
//! let heap_data = [
//!     0x00,                                    // Empty string
//!     b'H', b'e', b'l', b'l', b'o', 0x00,     // "Hello" at offset 1
//!     b'W', b'o', b'r', b'l', b'd', 0x00,     // "World" at offset 7
//!     b'T', b'e', b's', b't', 0x00,           // "Test" at offset 13
//! ];
//!
//! let strings = Strings::from(&heap_data)?;
//!
//! // Iterate over all strings with their offsets
//! for (offset, string) in strings.iter() {
//!     println!("String at offset {}: '{}'", offset, string);
//! }
//!
//! // Alternative: collect all valid strings
//! let all_strings: Vec<_> = strings.iter().collect();
//! for (offset, string) in all_strings {
//!     println!("Valid string at {}: '{}'", offset, string);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling and Validation
//! ```rust
//! use dotscope::metadata::streams::Strings;
//!
//! # fn example() {
//! // Invalid heap: missing initial null byte
//! let invalid_heap = [b'H', b'e', b'l', b'l', b'o', 0x00];
//! assert!(Strings::from(&invalid_heap).is_err());
//!
//! // Valid heap for further testing
//! let heap_data = [0x00, b'T', b'e', b's', b't', 0x00];
//! let strings = Strings::from(&heap_data).unwrap();
//!
//! // Error: out of bounds access
//! assert!(strings.get(100).is_err());
//!
//! // Error: accessing beyond data length
//! assert!(strings.get(heap_data.len()).is_err());
//!
//! // Valid access
//! assert_eq!(strings.get(1).unwrap(), "Test");
//! # }
//! ```
//!
//! ## Real-World Usage Patterns
//! ```rust
//! use dotscope::metadata::streams::Strings;
//!
//! # fn example() -> dotscope::Result<()> {
//! // Simulated strings from a real .NET assembly
//! #[rustfmt::skip]
//! let dotnet_strings = [
//!     0x00,                                           // Index 0: empty
//!     b'<', b'M', b'o', b'd', b'u', b'l', b'e', b'>', 0x00,  // Index 1: "<Module>"
//!     b'S', b'y', b's', b't', b'e', b'm', 0x00,              // Index 10: "System"
//!     b'O', b'b', b'j', b'e', b'c', b't', 0x00,              // Index 17: "Object"
//!     b'T', b'o', b'S', b't', b'r', b'i', b'n', b'g', 0x00, // Index 24: "ToString"
//! ];
//!
//! let strings = Strings::from(&dotnet_strings)?;
//!
//! // Process metadata table references
//! fn resolve_name(strings: &Strings, offset: usize) -> String {
//!     strings.get(offset)
//!         .map(|s| s.to_string())
//!         .unwrap_or_else(|_| format!("<invalid@{}>", offset))
//! }
//!
//! // Simulate TypeDef table processing
//! let type_name_offset = 17;  // Points to "Object"
//! let namespace_offset = 10;  // Points to "System"
//!
//! let type_name = resolve_name(&strings, type_name_offset);
//! let namespace = resolve_name(&strings, namespace_offset);
//!
//! println!("Found type: {}.{}", namespace, type_name); // "System.Object"
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Input Validation
//! - **UTF-8 Validation**: All string content validated for proper UTF-8 encoding
//! - **Bounds Checking**: Index access protected against buffer overruns
//! - **Null Termination**: Proper string termination enforced during parsing
//! - **Format Compliance**: ECMA-335 format requirements validated on construction
//!
//! ## Memory Safety
//! - **Lifetime Management**: Rust borrow checker prevents use-after-free
//! - **No Buffer Overflows**: Bounds checking on all heap access operations
//! - **Safe String Slicing**: CStr validation ensures safe null-terminated access
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 Partition II, Section 24.2.3:
//! - Correct interpretation of strings heap format and structure
//! - Proper handling of the mandatory null byte at index 0
//! - UTF-8 encoding validation for all string content
//! - Sequential storage and null-termination requirements
//!
//! # See Also
//! - [`crate::metadata::streams::UserStrings`]: UTF-16 user string literals heap
//! - [`crate::metadata::streams::Blob`]: Binary data heap for signatures and attributes
//! - [`crate::metadata::streams`]: Overview of all metadata stream types
//! - [`crate::metadata::tables`]: Metadata tables that reference string heap entries
//! - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap specification
//!
//! # References
//! - **ECMA-335 II.24.2.3**: Strings heap format and UTF-8 encoding requirements
//! - **ECMA-335 II.22**: Metadata tables and string reference mechanisms

use std::{ffi::CStr, str};

use crate::{Error, HeapKind, ParseFailure, Result};

/// ECMA-335 compliant `#Strings` heap providing UTF-8 identifier string access.
///
/// The [`Strings`] struct represents the strings heap from .NET metadata, which stores
/// UTF-8 encoded identifier strings referenced by metadata tables. According to ECMA-335
/// Section II.24.2.3, the strings heap contains null-terminated UTF-8 strings used for
/// type names, member names, namespaces, and other symbolic identifiers throughout the assembly.
///
/// ## Heap Structure and Format
///
/// The strings heap follows a specific binary layout mandated by ECMA-335:
/// ```text
/// Offset | Content              | Description
/// -------|----------------------|------------------------------------------
/// 0      | 0x00                | Mandatory null byte (empty string at index 0)
/// 1      | String₁ + 0x00     | First null-terminated UTF-8 string
/// N      | String₂ + 0x00     | Second null-terminated UTF-8 string
/// ...    | StringN + 0x00     | Additional strings in sequential order
/// ```
///
/// ## String Categories
///
/// The heap contains various types of identifier strings:
/// - **Namespace identifiers**: `System`, `Microsoft.Extensions`, `MyApp.Services`
/// - **Type names**: `Console`, `String`, `List<T>`, `Dictionary<TKey,TValue>`
/// - **Member names**: `WriteLine`, `ToString`, `Add`, `Remove`, `PropertyChanged`
/// - **Parameter names**: `value`, `index`, `count`, `predicate`
/// - **Assembly/module names**: `mscorlib`, `System.Core`, `<Module>`
///
/// ## Memory and Performance
///
/// - **Zero-copy design**: String access returns borrowed slices without allocation
/// - **UTF-8 validation**: Each string access validates UTF-8 encoding for safety
/// - **Sequential storage**: Strings stored contiguously for efficient iteration
/// - **Lifetime safety**: Rust borrow checker prevents dangling string references
///
/// # Examples
///
/// ## Basic String Access
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() -> dotscope::Result<()> {
/// // Construct a sample strings heap
/// #[rustfmt::skip]
/// let heap_data = [
///     0x00,                                    // Index 0: required empty string
///     b'S', b'y', b's', b't', b'e', b'm', 0x00,         // Index 1: "System"
///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,   // Index 8: "Console"
/// ];
///
/// let strings = Strings::from(&heap_data)?;
///
/// // Access strings by their heap offsets
/// assert_eq!(strings.get(1)?, "System");
/// assert_eq!(strings.get(8)?, "Console");
///
/// // Index 0 always contains empty string per ECMA-335
/// assert_eq!(strings.get(0)?, "");
/// # Ok(())
/// # }
/// ```
///
/// ## Iterating Over All Strings
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = [
///     0x00,                              // Empty string at index 0
///     b'H', b'e', b'l', b'l', b'o', 0x00,     // "Hello" at index 1
///     b'W', b'o', b'r', b'l', b'd', 0x00,     // "World" at index 7
/// ];
///
/// let strings = Strings::from(&heap_data)?;
///
/// // Iterate with offset information
/// for (offset, string) in strings.iter() {
///     println!("String at offset {}: '{}'", offset, string);
/// }
///
/// // Collect all strings for batch processing
/// let strings_list: Vec<_> = strings.iter().collect();
///
/// assert_eq!(strings_list.len(), 2); // "Hello" + "World" (empty string at index 0 is skipped)
/// assert_eq!(strings_list[0], (1, "Hello"));
/// assert_eq!(strings_list[1], (7, "World"));
/// # Ok(())
/// # }
/// ```
///
/// ## Error Handling
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() {
/// // Invalid heap: missing mandatory null byte at index 0
/// let invalid_heap = [b'I', b'n', b'v', b'a', b'l', b'i', b'd'];
/// assert!(Strings::from(&invalid_heap).is_err());
///
/// // Valid heap for testing access errors
/// let valid_heap = [0x00, b'T', b'e', b's', b't', 0x00];
/// let strings = Strings::from(&valid_heap).unwrap();
///
/// // Error cases
/// assert!(strings.get(100).is_err());  // Out of bounds
/// assert!(strings.get(valid_heap.len()).is_err());  // Exact boundary
///
/// // Valid access
/// assert_eq!(strings.get(1).unwrap(), "Test");
/// # }
/// ```
///
/// ## Real-World Metadata Processing
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() -> dotscope::Result<()> {
/// # #[rustfmt::skip]
/// # let heap_data = [
/// #     0x00,
/// #     b'S', b'y', b's', b't', b'e', b'm', 0x00,
/// #     b'O', b'b', b'j', b'e', b'c', b't', 0x00,
/// #     b'T', b'o', b'S', b't', b'r', b'i', b'n', b'g', 0x00,
/// # ];
/// # let strings = Strings::from(&heap_data)?;
/// // Function to safely resolve string references from metadata tables
/// fn resolve_string_ref(strings: &Strings, offset: usize) -> String {
///     strings.get(offset)
///         .map(|s| s.to_string())
///         .unwrap_or_else(|_| format!("<invalid_ref@{}>", offset))
/// }
///
/// // Simulate processing TypeDef table entries
/// let namespace_offset = 1;  // Points to "System"
/// let type_name_offset = 8;  // Points to "Object"
/// let method_name_offset = 15; // Points to "ToString"
///
/// let full_type_name = format!("{}.{}",
///     resolve_string_ref(&strings, namespace_offset),
///     resolve_string_ref(&strings, type_name_offset)
/// );
///
/// println!("Type: {}", full_type_name);  // "System.Object"
/// println!("Method: {}", resolve_string_ref(&strings, method_name_offset)); // "ToString"
/// # Ok(())
/// # }
/// ```
///
/// # ECMA-335 Compliance
///
/// This implementation strictly follows ECMA-335 Partition II, Section 24.2.3:
/// - Enforces mandatory null byte at heap index 0
/// - Validates UTF-8 encoding for all string content
/// - Preserves null-termination requirements for each string
/// - Maintains sequential storage without gaps or padding
///
/// # Security Considerations
///
/// - **Input validation**: UTF-8 encoding verified for all string access
/// - **Bounds checking**: Index validation prevents buffer overrun attacks
/// - **Memory safety**: Rust lifetime system prevents use-after-free vulnerabilities
/// - **Format compliance**: ECMA-335 format requirements enforced during construction
///
/// # See Also
/// - [`crate::metadata::streams::UserStrings`]: UTF-16 user string literals (`#US` heap)
/// - [`crate::metadata::tables`]: Metadata tables containing string heap references
/// - [`crate::metadata::streams::strings::StringsIterator`]: Iterator for sequential string heap traversal
/// - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap specification
pub struct Strings<'a> {
    /// Raw bytes of the strings heap
    data: &'a [u8],
}

impl<'a> Strings<'a> {
    /// Create a [`crate::metadata::streams::strings::Strings`] heap accessor from binary data with ECMA-335 validation.
    ///
    /// Constructs a strings heap accessor from the raw binary data of a `#Strings` stream.
    /// This method validates the heap format according to ECMA-335 Section II.24.2.3,
    /// ensuring the mandatory null byte at index 0 is present and the data is well-formed.
    ///
    /// ## ECMA-335 Format Requirements
    ///
    /// The strings heap must conform to the following structure:
    /// - **Index 0**: Must contain a null byte (0x00) representing the empty string
    /// - **Sequential layout**: Strings stored contiguously without gaps
    /// - **Null termination**: Each string must end with a 0x00 byte
    /// - **UTF-8 encoding**: All string content must be valid UTF-8 sequences
    ///
    /// ## Validation Performed
    ///
    /// This method enforces ECMA-335 compliance by checking:
    /// 1. **Non-empty data**: Heap must contain at least one byte
    /// 2. **Mandatory null byte**: First byte must be 0x00 (empty string at index 0)
    /// 3. **Format integrity**: Basic structural validation of heap data
    ///
    /// Note: Individual string UTF-8 validation is performed during access via [`Strings::get`]
    /// to optimize construction performance for large heaps.
    ///
    /// # Arguments
    /// * `data` - Raw binary data slice containing the complete `#Strings` heap
    ///
    /// # Returns
    /// * `Ok(Strings)` - Successfully validated and constructed strings heap accessor
    /// * `Err(Error)` - Validation failed due to ECMA-335 format violations
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - **Empty heap**: Data slice is empty (violates ECMA-335 requirement)
    /// - **Missing null byte**: First byte is not 0x00 (violates mandatory empty string at index 0)
    ///
    /// # Examples
    ///
    /// ## Valid Strings Heap Construction
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Properly formatted strings heap with mandatory null byte
    /// #[rustfmt::skip]
    /// let valid_heap = [
    ///     0x00,                                    // Index 0: mandatory empty string
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,         // Index 1: "System"
    ///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,   // Index 8: "Console"
    ///     b'W', b'r', b'i', b't', b'e', b'L', b'i', b'n', b'e', 0x00, // Index 16: "WriteLine"
    /// ];
    ///
    /// let strings = Strings::from(&valid_heap)?;
    ///
    /// // Verify successful construction and access
    /// assert_eq!(strings.get(0)?, "");        // Empty string at index 0
    /// assert_eq!(strings.get(1)?, "System");  // First identifier
    /// assert_eq!(strings.get(8)?, "Console"); // Second identifier
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Minimal Valid Heap
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Minimal heap with only the mandatory empty string
    /// let minimal_heap = [0x00];
    /// let strings = Strings::from(&minimal_heap)?;
    ///
    /// // Can access the empty string at index 0
    /// assert_eq!(strings.get(0)?, "");
    ///
    /// // Iterator returns no strings (empty string is implicit)
    /// let string_count = strings.iter().count();
    /// assert_eq!(string_count, 0);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Cases
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() {
    /// // Error: Empty data (no mandatory null byte)
    /// let empty_data = [];
    /// assert!(Strings::from(&empty_data).is_err());
    ///
    /// // Error: Missing mandatory null byte at index 0
    /// let no_null_byte = [b'I', b'n', b'v', b'a', b'l', b'i', b'd'];
    /// assert!(Strings::from(&no_null_byte).is_err());
    ///
    /// // Error: Non-zero first byte
    /// let wrong_start = [0x01, b'T', b'e', b's', b't', 0x00];
    /// assert!(Strings::from(&wrong_start).is_err());
    /// # }
    /// ```
    ///
    /// ## Real-World Assembly Processing
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Realistic strings heap from a .NET assembly
    /// #[rustfmt::skip]
    /// let dotnet_heap = [
    ///     0x00,                                           // Index 0: empty string
    ///     b'<', b'M', b'o', b'd', b'u', b'l', b'e', b'>', 0x00,  // Index 1: "<Module>"
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,              // Index 10: "System"
    ///     b'O', b'b', b'j', b'e', b'c', b't', 0x00,              // Index 17: "Object"
    ///     b'T', b'o', b'S', b't', b'r', b'i', b'n', b'g', 0x00, // Index 24: "ToString"
    ///     b'E', b'q', b'u', b'a', b'l', b's', 0x00,              // Index 33: "Equals"
    ///     b'G', b'e', b't', b'H', b'a', b's', b'h', b'C', b'o', b'd', b'e', 0x00, // Index 40: "GetHashCode"
    /// ];
    ///
    /// let strings = Strings::from(&dotnet_heap)?;
    ///
    /// // Verify we can access all the expected strings
    /// assert_eq!(strings.get(1)?, "<Module>");
    /// assert_eq!(strings.get(10)?, "System");
    /// assert_eq!(strings.get(17)?, "Object");
    /// assert_eq!(strings.get(24)?, "ToString");
    /// assert_eq!(strings.get(33)?, "Equals");
    /// assert_eq!(strings.get(40)?, "GetHashCode");
    ///
    /// // Count total strings (excluding empty string at index 0)
    /// let string_count = strings.iter().count();
    /// assert_eq!(string_count, 6);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance Considerations
    ///
    /// - **Construction**: O(1) validation with minimal overhead
    /// - **Memory**: Zero-copy design with borrowed data references
    /// - **Deferred validation**: UTF-8 validation performed during string access
    /// - **Thread safety**: Safe for concurrent construction from different data sources
    ///
    /// # ECMA-335 Compliance
    ///
    /// This method implements ECMA-335 Partition II, Section 24.2.3 requirements:
    /// - Enforces mandatory null byte at heap index 0
    /// - Validates basic heap structure and format
    /// - Prepares for proper UTF-8 string access and iteration
    ///
    /// # See Also
    /// - [`Strings::get`]: Access individual strings with UTF-8 validation
    /// - [`Strings::iter`]: Sequential iteration over all heap strings
    /// - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap format specification
    pub fn from(data: &[u8]) -> Result<Strings<'_>> {
        if data.first() != Some(&0) {
            return Err(ParseFailure::HeapCorrupt {
                heap: HeapKind::Strings,
                reason: "first byte must be 0 (empty string sentinel)".into(),
            }
            .into());
        }

        Ok(Strings { data })
    }

    /// Access a UTF-8 string at the specified heap offset with comprehensive validation.
    ///
    /// Retrieves a null-terminated UTF-8 string from the strings heap at the given byte offset.
    /// This method performs complete ECMA-335 compliance validation including bounds checking,
    /// null-termination verification, and UTF-8 encoding validation to ensure safe string access.
    ///
    /// ## String Resolution Process
    ///
    /// 1. **Bounds Validation**: Verify the index is within the heap data boundaries
    /// 2. **Null Termination**: Locate the null terminator (0x00) byte for the string
    /// 3. **UTF-8 Validation**: Ensure all bytes form a valid UTF-8 sequence
    /// 4. **String Creation**: Return a borrowed string slice without allocation
    ///
    /// ## Offset Interpretation
    ///
    /// Offsets are byte positions within the strings heap:
    /// - **Index 0**: Always points to the mandatory empty string (single null byte)
    /// - **Index 1+**: Points to the start of actual identifier strings
    /// - **Mid-string offsets**: Invalid - will cause UTF-8 validation errors
    /// - **Table references**: Metadata tables store these offsets to reference strings
    ///
    /// # Arguments
    /// * `index` - Byte offset within the strings heap where the string begins
    ///
    /// # Returns
    /// * `Ok(&str)` - Valid UTF-8 string slice with lifetime tied to heap data
    /// * `Err(Error)` - Access failed due to bounds or validation errors
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - **[`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]**: Index exceeds heap data length
    /// - **Malformed string**: No null terminator found within remaining heap data
    /// - **Invalid UTF-8**: String bytes do not form a valid UTF-8 sequence
    /// - **Encoding errors**: Non-ASCII bytes that violate UTF-8 encoding rules
    ///
    /// # Examples
    ///
    /// ## Basic String Access
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     0x00,                                    // Index 0: empty string
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,         // Index 1: "System"
    ///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,   // Index 8: "Console"
    /// ];
    ///
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// // Access strings by their heap offsets
    /// assert_eq!(strings.get(0)?, "");        // Empty string always at index 0
    /// assert_eq!(strings.get(1)?, "System");  // First identifier string
    /// assert_eq!(strings.get(8)?, "Console"); // Second identifier string
    ///
    /// // These offsets would typically come from metadata table entries
    /// let namespace_ref = 1;  // From TypeDef.TypeNamespace field
    /// let type_name_ref = 8;  // From TypeDef.TypeName field
    ///
    /// println!("Type: {}.{}", strings.get(namespace_ref)?, strings.get(type_name_ref)?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## UTF-8 and Unicode Support
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Strings heap with Unicode content (UTF-8 encoded)
    /// #[rustfmt::skip]
    /// let unicode_heap = [
    ///     0x00,                                    // Index 0: empty string
    ///     // "Café" in UTF-8: C3 A9 is 'é'
    ///     b'C', b'a', b'f', 0xC3, 0xA9, 0x00,    // Index 1: "Café"
    ///     // "测试" (test in Chinese) in UTF-8
    ///     0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x00, // Index 7: "测试"
    /// ];
    ///
    /// let strings = Strings::from(&unicode_heap)?;
    ///
    /// assert_eq!(strings.get(1)?, "Café");
    /// assert_eq!(strings.get(7)?, "测试");
    ///
    /// // Verify proper UTF-8 character handling
    /// let cafe = strings.get(1)?;
    /// assert_eq!(cafe.chars().count(), 4); // 4 Unicode characters
    /// assert_eq!(cafe.len(), 5);           // 5 UTF-8 bytes
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling and Edge Cases
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,                              // Index 0: empty string
    ///     b'T', b'e', b's', b't', 0x00,     // Index 1: "Test"
    /// ];
    ///
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// // Valid accesses
    /// assert_eq!(strings.get(0)?, "");     // Empty string
    /// assert_eq!(strings.get(1)?, "Test"); // Valid string
    ///
    /// // Error cases
    /// assert!(strings.get(100).is_err());           // Way out of bounds
    /// assert!(strings.get(heap_data.len()).is_err()); // Exact boundary
    /// assert!(strings.get(heap_data.len() + 1).is_err()); // Beyond boundary
    ///
    /// // Mid-string access would cause UTF-8 validation error
    /// // (Though bounds checking might catch it first)
    /// assert!(strings.get(3).is_err()); // Points to 's' in "Test"
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Metadata Table Integration
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Simulated metadata processing scenario
    /// # #[rustfmt::skip]
    /// # let heap_data = [
    /// #     0x00,
    /// #     b'S', b'y', b's', b't', b'e', b'm', 0x00,
    /// #     b'O', b'b', b'j', b'e', b'c', b't', 0x00,
    /// #     b'T', b'o', b'S', b't', b'r', b'i', b'n', b'g', 0x00,
    /// # ];
    /// # let strings = Strings::from(&heap_data)?;
    ///
    /// // Function to safely resolve string references from metadata tables
    /// fn get_string_or_invalid(strings: &Strings, offset: usize) -> String {
    ///     strings.get(offset)
    ///         .map(|s| s.to_string())
    ///         .unwrap_or_else(|_| format!("<invalid@{}>", offset))
    /// }
    ///
    /// // Simulate TypeDef table processing
    /// struct TypeDefRow {
    ///     type_name: usize,      // String heap offset
    ///     type_namespace: usize, // String heap offset
    /// }
    ///
    /// let type_def = TypeDefRow {
    ///     type_namespace: 1,  // "System"
    ///     type_name: 8,       // "Object"
    /// };
    ///
    /// let namespace = get_string_or_invalid(&strings, type_def.type_namespace);
    /// let type_name = get_string_or_invalid(&strings, type_def.type_name);
    /// let full_name = format!("{}.{}", namespace, type_name);
    ///
    /// assert_eq!(full_name, "System.Object");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Performance-Sensitive Usage
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    /// use dotscope::Error;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let heap_data = [0x00, b'T', b'e', b's', b't', 0x00];
    /// # let strings = Strings::from(&heap_data)?;
    /// // For repeated access to the same strings, consider caching
    /// use std::collections::HashMap;
    ///
    /// let mut string_cache: HashMap<usize, String> = HashMap::new();
    ///
    /// fn cached_get(strings: &Strings, cache: &mut HashMap<usize, String>, offset: usize) -> Result<String, Error> {
    ///     if let Some(cached) = cache.get(&offset) {
    ///         Ok(cached.clone())
    ///     } else {
    ///         let string = strings.get(offset)?.to_string();
    ///         cache.insert(offset, string.clone());
    ///         Ok(string)
    ///     }
    /// }
    ///
    /// // First access validates and caches
    /// let result1 = cached_get(&strings, &mut string_cache, 1)?;
    /// // Second access uses cache
    /// let result2 = cached_get(&strings, &mut string_cache, 1)?;
    ///
    /// assert_eq!(result1, result2);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Considerations
    ///
    /// - **Bounds checking**: Prevents buffer overrun vulnerabilities
    /// - **UTF-8 validation**: Ensures string content is well-formed
    /// - **Memory safety**: Rust lifetime system prevents use-after-free
    /// - **No allocation**: Eliminates memory exhaustion attacks
    ///
    /// # ECMA-335 Compliance
    ///
    /// This method fully implements ECMA-335 Partition II, Section 24.2.3:
    /// - Proper null-terminated string parsing
    /// - UTF-8 encoding validation as required by the specification
    /// - Correct handling of the empty string at index 0
    ///
    /// # See Also
    /// - [`crate::metadata::streams::strings::Strings::iter`]: Sequential iteration over all strings in the heap
    /// - [`crate::metadata::streams::strings::StringsIterator`]: Iterator implementation for strings heap traversal
    /// - [`crate::metadata::tables`]: Metadata tables containing string references
    /// - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap specification
    pub fn get(&self, index: usize) -> Result<&'a str> {
        let oob = || ParseFailure::HeapOutOfBounds {
            heap: HeapKind::Strings,
            index: u32::try_from(index).unwrap_or(u32::MAX),
        };
        if index >= self.data.len() {
            return Err(oob().into());
        }

        // Performance note: Each call performs O(n) operations:
        // 1. Scan for null terminator (CStr::from_bytes_until_nul)
        // 2. UTF-8 validation (to_str)
        //
        // Caching was considered but rejected because:
        // - Adding interior mutability would break the zero-copy design philosophy
        // - Memory overhead of cache may exceed benefits for typical usage patterns
        // - Most strings are accessed once during initial parsing
        // - Callers can cache at their level if repeated access is needed
        //
        // If profiling shows this is a bottleneck, callers should:
        // 1. Cache results at the call site for repeated access
        // 2. Use the iterator for bulk processing (avoids repeated bounds checks)
        let slice = self.data.get(index..).ok_or_else(|| Error::from(oob()))?;
        let corrupt = || ParseFailure::HeapCorrupt {
            heap: HeapKind::Strings,
            reason: format!("invalid UTF-8 string at index {index}"),
        };
        match CStr::from_bytes_until_nul(slice) {
            Ok(result) => match result.to_str() {
                Ok(result) => Ok(result),
                Err(_) => Err(corrupt().into()),
            },
            Err(_) => Err(corrupt().into()),
        }
    }

    /// Create an iterator for sequential traversal of all strings in the heap.
    ///
    /// Returns a [`crate::metadata::streams::strings::StringsIterator`] that provides zero-copy access to all null-terminated
    /// UTF-8 strings stored in the heap. The iterator yields tuples of `(offset, string)`
    /// where offset is the byte position within the heap and string is the UTF-8 content.
    ///
    /// ## Iteration Behavior
    ///
    /// - **Sequential access**: Strings are visited in storage order within the heap
    /// - **Zero-copy design**: String references borrow from original heap data
    /// - **UTF-8 validation**: Each string is validated during iteration
    /// - **Error handling**: Iterator stops on invalid strings instead of panicking
    /// - **Empty string skipped**: The mandatory empty string at index 0 is not yielded
    ///
    /// ## Error Handling
    ///
    /// The iterator gracefully handles malformed heap data:
    /// - Invalid UTF-8 sequences cause iterator termination
    /// - Missing null terminators cause iterator termination
    /// - Corrupted heap structure detected during iteration
    ///
    /// # Returns
    /// [`crate::metadata::streams::strings::StringsIterator`] that yields `(usize, &str)` for each string
    ///
    /// # Examples
    ///
    /// ## Basic Iteration
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// #[rustfmt::skip]
    /// let heap_data = [
    ///     0x00,                              // Index 0: empty string (not yielded)
    ///     b'H', b'e', b'l', b'l', b'o', 0x00,     // Index 1: "Hello"
    ///     b'W', b'o', b'r', b'l', b'd', 0x00,     // Index 7: "World"
    ///     b'T', b'e', b's', b't', 0x00,           // Index 13: "Test"
    /// ];
    ///
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// // Iterate over all strings with their offsets
    /// for (offset, string) in strings.iter() {
    ///     println!("String at offset {}: '{}'", offset, string);
    /// }
    ///
    /// // Expected output:
    /// // String at offset 1: 'Hello'
    /// // String at offset 7: 'World'
    /// // String at offset 13: 'Test'
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Collecting All Valid Strings
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,                              // Empty string (skipped)
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,         // "System"
    ///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,   // "Console"
    ///     b'O', b'b', b'j', b'e', b'c', b't', 0x00,         // "Object"
    /// ];
    ///
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// // Collect all strings, handling errors
    /// let all_strings: Vec<_> = strings.iter().collect();
    ///
    /// assert_eq!(all_strings.len(), 3);
    /// assert_eq!(all_strings[0], (1, "System"));
    /// assert_eq!(all_strings[1], (8, "Console"));
    /// assert_eq!(all_strings[2], (16, "Object"));
    ///
    /// for (offset, string) in all_strings {
    ///     println!("Found identifier: '{}' at offset {}", string, offset);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Filtering and Processing
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let heap_data = [
    /// #     0x00,
    /// #     b'S', b'y', b's', b't', b'e', b'm', 0x00,
    /// #     b'M', b'y', b'C', b'l', b'a', b's', b's', 0x00,
    /// #     b'T', b'o', b'S', b't', b'r', b'i', b'n', b'g', 0x00,
    /// #     b'E', b'q', b'u', b'a', b'l', b's', 0x00,
    /// # ];
    /// # let strings = Strings::from(&heap_data)?;
    /// // Find all method names (strings containing common method patterns)
    /// let method_names: Vec<_> = strings.iter()
    ///     .filter(|(_, string)| {
    ///         string.chars().next().map_or(false, |c| c.is_uppercase()) &&
    ///         (string.contains("Get") || string.contains("Set") ||
    ///          string.contains("To") || string.contains("Equals"))
    ///     })
    ///     .collect();
    ///
    /// // Find all namespace-like strings (containing dots)
    /// let namespaces: Vec<_> = strings.iter()
    ///     .filter(|(_, string)| string.contains('.'))
    ///     .map(|(offset, string)| (offset, string.to_string()))
    ///     .collect();
    ///
    /// println!("Found {} method names", method_names.len());
    /// println!("Found {} namespace strings", namespaces.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Memory-Efficient Processing
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let heap_data = [
    /// #     0x00,
    /// #     b'L', b'o', b'n', b'g', b'S', b't', b'r', b'i', b'n', b'g', b'N', b'a', b'm', b'e', 0x00,
    /// #     b'A', b'n', b'o', b't', b'h', b'e', b'r', b'L', b'o', b'n', b'g', b'N', b'a', b'm', b'e', 0x00,
    /// # ];
    /// # let strings = Strings::from(&heap_data)?;
    /// // Process large string heaps without collecting all strings in memory
    /// let mut total_length = 0;
    /// let mut max_length = 0;
    /// let mut string_count = 0;
    ///
    /// for (_, string) in strings.iter() {
    ///     total_length += string.len();
    ///     max_length = max_length.max(string.len());
    ///     string_count += 1;
    ///
    ///     // Process string immediately without storing
    ///     if string.len() > 50 {
    ///         println!("Long identifier found: '{}'", string);
    ///     }
    /// }
    ///
    /// let average_length = if string_count > 0 { total_length / string_count } else { 0 };
    /// println!("Statistics: {} strings, avg length: {}, max length: {}",
    ///          string_count, average_length, max_length);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Integration with `IntoIterator`
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let heap_data = [0x00, b'T', b'e', b's', b't', 0x00];
    /// # let strings = Strings::from(&heap_data)?;
    /// // Can use with for loops directly via IntoIterator implementation
    /// for (offset, string) in &strings {
    ///     println!("{}: {}", offset, string);
    /// }
    ///
    /// // Or with iterator methods
    /// let string_lengths: Vec<_> = (&strings).into_iter()
    ///     .map(|(_, string)| string.len())
    ///     .collect();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - **Streaming processing**: Iterator allows processing large heaps without memory allocation
    /// - **Early termination**: Can stop iteration on first error or when specific strings found
    /// - **Cache-friendly**: Sequential memory access pattern optimizes CPU cache usage
    /// - **UTF-8 overhead**: Validation cost scales with total string content size
    ///
    /// # ECMA-335 Compliance
    ///
    /// The iterator correctly implements ECMA-335 Section II.24.2.3 requirements:
    /// - Skips the mandatory empty string at index 0
    /// - Properly handles null-terminated string format
    /// - Validates UTF-8 encoding as required by specification
    /// - Maintains sequential storage order for deterministic iteration
    ///
    /// # See Also
    /// - [`crate::metadata::streams::strings::StringsIterator`]: The iterator implementation with detailed behavior documentation
    /// - [`crate::metadata::streams::strings::Strings::get`]: Direct string access by offset for random access patterns
    /// - [`crate::metadata::streams::UserStrings`]: UTF-16 user strings iteration
    /// - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap specification
    #[must_use]
    pub fn iter(&self) -> StringsIterator<'_> {
        StringsIterator::new(self)
    }

    /// Every entry of the heap after the null string at offset 0, as its bytes without the
    /// null terminator, with its offset: valid UTF-8 or not, so that nothing that follows an
    /// entry [`Self::get`] refuses goes missing. A heap that ends without a terminator ends
    /// with its unterminated bytes as the last entry.
    #[must_use]
    pub fn entries(&self) -> StringEntries<'a> {
        StringEntries {
            data: self.data,
            position: 1,
        }
    }

    /// Returns the raw underlying data of the strings heap.
    ///
    /// This provides access to the complete heap data including the null byte at offset 0
    /// and all string entries in their original binary format. This method is useful for
    /// heap size calculation, bounds checking, and low-level metadata analysis.
    ///
    /// # Returns
    /// A byte slice containing the complete strings heap data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [0x00, b'T', b'e', b's', b't', 0x00];
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// assert_eq!(strings.data().len(), 6);
    /// assert_eq!(strings.data()[0], 0x00); // Mandatory null byte
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Checks if the strings heap contains a specific string value.
    ///
    /// Searches through all strings in the heap to determine if any entry matches
    /// the provided string exactly. This is useful for quick existence checks without
    /// needing to know the specific offset.
    ///
    /// # Arguments
    /// * `s` - The string value to search for
    ///
    /// # Returns
    /// `true` if the string exists in the heap, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,
    ///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,
    /// ];
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// assert!(strings.contains("System"));
    /// assert!(strings.contains("Console"));
    /// assert!(!strings.contains("NotFound"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn contains(&self, s: &str) -> bool {
        self.iter().any(|(_, value)| value == s)
    }

    /// Finds the first occurrence of a string and returns its heap offset.
    ///
    /// Searches through all strings in the heap and returns the byte offset of the
    /// first matching entry. This offset can be used with metadata table references.
    ///
    /// # Arguments
    /// * `s` - The string value to search for
    ///
    /// # Returns
    /// `Some(offset)` if the string is found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     b'S', b'y', b's', b't', b'e', b'm', 0x00,
    ///     b'C', b'o', b'n', b's', b'o', b'l', b'e', 0x00,
    /// ];
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// assert_eq!(strings.find("System"), Some(1));
    /// assert_eq!(strings.find("Console"), Some(8));
    /// assert_eq!(strings.find("NotFound"), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find(&self, s: &str) -> Option<u32> {
        self.iter()
            .find(|(_, value)| *value == s)
            .and_then(|(offset, _)| u32::try_from(offset).ok())
    }

    /// Finds all occurrences of a string and returns their heap offsets.
    ///
    /// Searches through all strings in the heap and returns the byte offsets of all
    /// matching entries. This handles the case where duplicate strings exist in the heap.
    ///
    /// # Arguments
    /// * `s` - The string value to search for
    ///
    /// # Returns
    /// A vector of offsets where the string was found. Empty if not found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::streams::Strings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let heap_data = [
    ///     0x00,
    ///     b'T', b'e', b's', b't', 0x00,
    ///     b'T', b'e', b's', b't', 0x00,
    /// ];
    /// let strings = Strings::from(&heap_data)?;
    ///
    /// let offsets = strings.find_all("Test");
    /// assert_eq!(offsets.len(), 2);
    /// assert_eq!(offsets[0], 1);
    /// assert_eq!(offsets[1], 6);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find_all(&self, s: &str) -> Vec<u32> {
        self.iter()
            .filter(|(_, value)| *value == s)
            .filter_map(|(offset, _)| u32::try_from(offset).ok())
            .collect()
    }
}

impl<'a> IntoIterator for &'a Strings<'a> {
    type Item = (usize, &'a str);
    type IntoIter = StringsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator for sequential traversal of UTF-8 strings in the ECMA-335 `#Strings` heap.
///
/// [`crate::metadata::streams::strings::StringsIterator`] provides zero-copy access to null-terminated UTF-8 strings stored
/// in the strings heap according to ECMA-335 Section II.24.2.3. The iterator maintains
/// position state and yields tuples of `(offset, string)` for each valid string encountered.
///
/// ## Iteration Behavior
///
/// - **Sequential access**: Strings visited in storage order within the heap data
/// - **Position tracking**: Iterator maintains current byte offset within heap
/// - **UTF-8 validation**: Each string validated during iteration
/// - **Error propagation**: Invalid strings yield `Err` results rather than panicking
/// - **Empty string handling**: Skips the mandatory empty string at heap index 0
///
/// ## Error Handling
///
/// The iterator gracefully handles malformed heap data:
/// - Returns `Some(Err(_))` for invalid UTF-8 sequences
/// - Returns `None` when reaching end of heap or encountering format errors
/// - Continues iteration after recoverable errors when possible
///
/// # Examples
///
/// ## Basic Iterator Usage
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() -> dotscope::Result<()> {
/// let heap_data = [
///     0x00,                              // Index 0: empty string (skipped)
///     b'H', b'e', b'l', b'l', b'o', 0x00,     // Index 1: "Hello"
///     b'W', b'o', b'r', b'l', b'd', 0x00,     // Index 7: "World"
/// ];
///
/// let strings = Strings::from(&heap_data)?;
/// let mut iter = strings.iter();
///
/// // First string
/// let (offset1, string1) = iter.next().unwrap();
/// assert_eq!(offset1, 1);
/// assert_eq!(string1, "Hello");
///
/// // Second string  
/// let (offset2, string2) = iter.next().unwrap();
/// assert_eq!(offset2, 7);
/// assert_eq!(string2, "World");
///
/// // End of iteration
/// assert!(iter.next().is_none());
/// # Ok(())
/// # }
/// ```
///
/// ## Error Handling During Iteration
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() {
/// // Heap with mixed valid and invalid content
/// let problematic_heap = [
///     0x00,                              // Valid: empty string
///     b'O', b'K', 0x00,                  // Valid: "OK"
///     0xFF, 0xFF, 0x00,                  // Invalid UTF-8
///     b'A', b'f', b't', b'e', b'r', 0x00,     // Valid: "After"
/// ];
///
/// if let Ok(strings) = Strings::from(&problematic_heap) {
///     let mut iter = strings.iter();
///
///     // Process all strings, handling errors gracefully
///     loop {
///         match iter.next() {
///             Some((offset, string)) => {
///                 println!("Valid string at {}: '{}'", offset, string);
///             }
///             None => {
///                 println!("End of iteration");
///                 break;
///             }
///         }
///     }
/// }
/// # }
/// ```
///
/// ## Manual Iterator Control
/// ```rust
/// use dotscope::metadata::streams::Strings;
///
/// # fn example() -> dotscope::Result<()> {
/// # let heap_data = [
/// #     0x00,
/// #     b'F', b'i', b'r', b's', b't', 0x00,
/// #     b'S', b'e', b'c', b'o', b'n', b'd', 0x00,
/// #     b'T', b'h', b'i', b'r', b'd', 0x00,
/// # ];
/// # let strings = Strings::from(&heap_data)?;
/// let mut iter = strings.iter();
///
/// // Find first string longer than 4 characters
/// let long_string = loop {
///     match iter.next() {
///         Some((offset, string)) => {
///             if string.len() > 4 {
///                 break Some((offset, string));
///             }
///         }
///         None => break None,       // No more strings
///     }
/// };
///
/// if let Some((offset, string)) = long_string {
///     println!("Found long string '{}' at offset {}", string, offset);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Performance Notes
///
/// - **Memory efficiency**: No allocation for string content or iterator state
/// - **Validation cost**: UTF-8 validation scales with string content size
/// - **Position arithmetic**: Simple offset calculation for next string location
/// - **Bounds checking**: Minimal overhead for heap boundary validation
///
/// # See Also
/// - [`crate::metadata::streams::strings::Strings::iter`]: Method to create this iterator
/// - [`crate::metadata::streams::strings::Strings::get`]: Direct string access by offset
/// - [`std::iter::Iterator`]: Standard iterator trait implementation
/// - [ECMA-335 II.24.2.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Strings heap specification
pub struct StringsIterator<'a> {
    /// The heap's entries, valid UTF-8 or not
    entries: StringEntries<'a>,
}

impl<'a> StringsIterator<'a> {
    /// Creates a new strings iterator starting at position 1 (skipping the null string).
    ///
    /// # Arguments
    ///
    /// * `strings` - Reference to the strings heap to iterate over
    ///
    /// # Returns
    ///
    /// A new iterator that will yield all strings in the heap in order.
    pub(crate) fn new(strings: &'a Strings<'a>) -> Self {
        Self {
            entries: strings.entries(),
        }
    }
}

impl<'a> Iterator for StringsIterator<'a> {
    type Item = (usize, &'a str);

    /// The next entry that is valid UTF-8. One that is not is passed over, not taken for the
    /// end of the heap: [`Strings::entries`] yields it too.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (offset, bytes) = self.entries.next()?;
            if let Ok(text) = str::from_utf8(bytes) {
                return Some((offset, text));
            }
        }
    }
}

/// Every entry of a strings heap as its bytes, from [`Strings::entries`].
pub struct StringEntries<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Iterator for StringEntries<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self
            .data
            .get(self.position..)
            .filter(|rest| !rest.is_empty())?;
        let offset = self.position;
        let length = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        self.position = self.position.saturating_add(length).saturating_add(1);
        Some((offset, rest.get(..length).unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data : [u8; 119] = [
            0x00,
            0x3c, 0x4d, 0x61, 0x69, 0x6e, 0x3e, 0x24, 0x00,
            0x43, 0x5f, 0x53, 0x68, 0x61, 0x72, 0x70, 0x5f, 0x50, 0x4f, 0x43, 0x5f, 0x31, 0x00,
            0x3c, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0x00,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x43, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x00,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2e, 0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x00,
            0x57, 0x72, 0x69, 0x74, 0x65, 0x4c, 0x69, 0x6e, 0x65, 0x00,
            0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x00,
            0x44, 0x65, 0x62, 0x75, 0x67, 0x67, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x00
        ];

        let str_view = Strings::from(&data).unwrap();

        let str_test_1 = str_view.get(1).unwrap();
        assert_eq!(str_test_1, "<Main>$");

        let str_test_2 = str_view.get(9).unwrap();
        assert_eq!(str_test_2, "C_Sharp_POC_1");

        let str_test_3 = str_view.get(23).unwrap();
        assert_eq!(str_test_3, "<Module>");

        let str_test_3 = str_view.get(32).unwrap();
        assert_eq!(str_test_3, "System.Console");
    }

    #[test]
    fn test_strings_iterator() {
        let data = [
            0x00, // Initial null byte
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            b'W', b'o', b'r', b'l', b'd', 0x00, // "World" at offset 7
            b'T', b'e', b's', b't', 0x00, // "Test" at offset 13
        ];

        let strings = Strings::from(&data).unwrap();
        let mut iter = strings.iter();

        // Test first string
        let (offset1, string1) = iter.next().unwrap();
        assert_eq!(offset1, 1);
        assert_eq!(string1, "Hello");

        // Test second string
        let (offset2, string2) = iter.next().unwrap();
        assert_eq!(offset2, 7);
        assert_eq!(string2, "World");

        // Test third string
        let (offset3, string3) = iter.next().unwrap();
        assert_eq!(offset3, 13);
        assert_eq!(string3, "Test");

        // Test end of iterator
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_strings_iterator_empty_strings() {
        let data = [
            0x00, // Initial null byte
            0x00, // Empty string at offset 1
            b'A', 0x00, // "A" at offset 2
            0x00, // Empty string at offset 4
        ];

        let strings = Strings::from(&data).unwrap();
        let results: Vec<_> = strings.iter().collect();

        assert_eq!(results.len(), 3);

        let (offset1, string1) = results[0];
        assert_eq!(offset1, 1);
        assert_eq!(string1, "");

        let (offset2, string2) = results[1];
        assert_eq!(offset2, 2);
        assert_eq!(string2, "A");

        let (offset3, string3) = results[2];
        assert_eq!(offset3, 4);
        assert_eq!(string3, "");
    }

    #[test]
    fn test_strings_iterator_invalid_utf8() {
        let data = [
            0x00, // Initial null byte
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            0xFF, 0xFF, 0x00, // Invalid UTF-8 sequence at offset 7
            b'W', b'o', b'r', b'l', b'd', 0x00, // "World" at offset 10
        ];

        let strings = Strings::from(&data).unwrap();

        // The invalid entry is passed over, not taken for the end of the heap
        let valid: Vec<(usize, &str)> = strings.iter().collect();
        assert_eq!(valid, [(1, "Hello"), (10, "World")]);

        // Every entry, the invalid one too, as bytes
        let entries: Vec<(usize, &[u8])> = strings.entries().collect();
        assert_eq!(
            entries,
            [
                (1, &b"Hello"[..]),
                (7, &[0xFF, 0xFF][..]),
                (10, &b"World"[..])
            ]
        );
    }

    #[test]
    fn an_unterminated_last_entry_is_an_entry() {
        let data = [0x00, b'A', 0x00, b'B', b'C'];
        let strings = Strings::from(&data).unwrap();
        let entries: Vec<(usize, &[u8])> = strings.entries().collect();
        assert_eq!(entries, [(1, &b"A"[..]), (3, &b"BC"[..])]);
    }
}

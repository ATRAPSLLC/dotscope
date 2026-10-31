//! User String Heap (`#US`) for .NET Metadata
//!
//! Provides access to the ECMA-335 `#US` heap, which stores user-defined string literals in UTF-16 encoding.
//! This module exposes the [`crate::metadata::streams::UserStrings`] struct for safe access and parsing of user strings referenced by metadata tables.
//!
//! The `#US` heap contains string literals that appear directly in user source code, stored with length prefixes
//! and encoded in UTF-16 format. This is distinct from the [`crate::metadata::streams::strings`] heap which
//! contains system identifiers and metadata names.
//!
//! # Format
//!
//! The user strings heap starts with a null byte (index 0), followed by length-prefixed UTF-16 strings.
//! Each string entry consists of:
//! - Length byte(s) indicating the total size including the terminal byte
//! - UTF-16 encoded string data (variable length)
//! - UTF-16 null terminator (0x0000)  
//! - Terminal byte (0x00)
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::streams::UserStrings;
//!
//! // Sample heap data with "Hello" string
//! let data = &[
//!     0x00,                                    // Null entry at index 0
//!     0x0D,                                    // Length: 13 bytes total
//!     0x48, 0x00, 0x65, 0x00, 0x6C, 0x00,    // "Hel" in UTF-16
//!     0x6C, 0x00, 0x6F, 0x00,                 // "lo" in UTF-16
//!     0x00, 0x00,                             // UTF-16 null terminator
//!     0x00                                    // Terminal byte
//! ];
//!
//! let heap = UserStrings::from(data)?;
//! let string = heap.get(1)?;
//! assert_eq!(string.to_string_lossy(), "Hello");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Reference
//! - [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)

use widestring::U16String;

use crate::{utils::read_compressed_int_at, Error, HeapKind, ParseFailure, Result};

/// The `UserStrings` object provides helper methods to access the data within the '#US' heap.
///
/// This heap contains all user-defined string literals from the source code, stored in UTF-16 encoding
/// with length prefixes. Each string is referenced by its byte offset from metadata tables like
/// the Constant table when the constant type is a string literal.
///
/// The heap format follows ECMA-335 specification with:
/// - Index 0 always contains a null byte
/// - Each string prefixed by its total byte length (including terminal byte)
/// - UTF-16 encoded string data followed by null terminator and terminal byte
///
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::streams::UserStrings;
///
/// // Create from heap data
/// let data = &[0u8, 65, 0, 0, 0];
/// let us = UserStrings::from(data)?;
/// let s = us.get(1)?;
/// assert_eq!(s.to_string_lossy(), "A");
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Iteration Example
///
/// ```rust,no_run
/// use dotscope::metadata::streams::UserStrings;
///
/// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // "Hi"
/// let heap = UserStrings::from(data)?;
///
/// for (offset, string) in heap.iter() {
///     println!("String at offset {}: {}", offset, string.to_string_lossy());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Reference
/// * [ECMA-335 II.24.2.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
///
/// User strings heap data accessor
///
/// Provides safe access to UTF-16 encoded string literals stored in the `#US` metadata heap.
/// The heap data must start with a null byte at index 0, followed by length-prefixed strings.
pub struct UserStrings<'a> {
    /// Raw heap data starting with null byte at index 0
    data: &'a [u8],
}

impl<'a> UserStrings<'a> {
    /// Create a `UserStrings` object from a sequence of bytes
    ///
    /// Validates that the heap data starts with the required null byte at index 0 according to
    /// ECMA-335 specification. The heap may contain multiple UTF-16 strings with length prefixes.
    ///
    /// # Arguments
    /// * `data` - The byte slice containing the user strings heap data
    ///
    /// # Returns
    /// * `Ok(UserStrings)` - Valid heap accessor
    ///
    /// # Errors
    /// * [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] - If data is empty or doesn't start with null byte
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// // Valid heap data
    /// let data = &[0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // null + "Hi"
    /// let heap = UserStrings::from(data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from(data: &'a [u8]) -> Result<UserStrings<'a>> {
        if data.first().copied() != Some(0) {
            return Err(ParseFailure::HeapCorrupt {
                heap: HeapKind::UserStrings,
                reason: "first byte must be 0 (empty string sentinel)".into(),
            }
            .into());
        }

        Ok(UserStrings { data })
    }

    /// Get a view into the string contained at the provided location.
    ///
    /// Retrieves a UTF-16 string reference from the heap at the specified byte offset.
    /// The method processes the length prefix and validates the string data according to
    /// the .NET runtime implementation researched from the official runtime source code.
    ///
    /// # Arguments
    /// * `index` - The byte offset within the heap (typically from metadata table references)
    ///
    /// # Returns
    /// * `Ok(U16String)` - The UTF-16 string at the specified offset
    ///
    /// # Errors
    /// * [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] - If index is out of bounds
    /// * [`crate::Error`] - If string data is malformed or has invalid UTF-16 length
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00]; // "Hi"
    /// let heap = UserStrings::from(data)?;
    /// let string = heap.get(1)?;
    /// assert_eq!(string.to_string_lossy(), "Hi");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Platform Notes
    /// ECMA-335 stores `#US` entries little-endian and guarantees no alignment for them, so the
    /// code points are decoded explicitly from byte pairs. Returning an owned string rather than
    /// a borrowed `&U16Str` is what makes that possible: a `&[u16]` borrowed from the heap would
    /// have to be reinterpreted from a possibly-odd byte offset, which is undefined behaviour
    /// regardless of what the hardware tolerates, and would read native-endian.
    pub fn get(&self, index: usize) -> Result<U16String> {
        let oob = || ParseFailure::HeapOutOfBounds {
            heap: HeapKind::UserStrings,
            index: u32::try_from(index).unwrap_or(u32::MAX),
        };
        let corrupt = |reason: String| ParseFailure::HeapCorrupt {
            heap: HeapKind::UserStrings,
            reason,
        };
        if index >= self.data.len() {
            return Err(oob().into());
        }

        let (total_bytes, compressed_length_size) = read_compressed_int_at(self.data, index)?;
        let data_start = index
            .checked_add(compressed_length_size)
            .ok_or_else(|| corrupt(format!("offset overflow at index {index}")))?;

        // The empty blob - the heap's first entry, ECMA-335 II.24.2.4 - and an
        // entry of no characters (its terminal byte alone) are both the empty
        // string: `ldstr` of offset 0 is how a compiler spells `""`.
        if total_bytes <= 1 {
            return Ok(U16String::new());
        }

        // Total bytes includes UTF-16 data + terminator byte (1 byte)
        // So actual UTF-16 data is total_bytes - 1
        let utf16_length = total_bytes
            .checked_sub(1)
            .ok_or_else(|| corrupt(format!("length underflow at index {index}")))?;

        let total_data_end = data_start
            .checked_add(total_bytes)
            .ok_or_else(|| corrupt(format!("end overflow at index {index}")))?;
        if total_data_end > self.data.len() {
            return Err(oob().into());
        }

        if utf16_length % 2 != 0 {
            return Err(corrupt(format!("odd UTF-16 byte count at index {index}")).into());
        }

        let utf16_data_end = data_start
            .checked_add(utf16_length)
            .ok_or_else(|| corrupt(format!("data end overflow at index {index}")))?;
        let utf16_data = self
            .data
            .get(data_start..utf16_data_end)
            .ok_or_else(|| Error::from(oob()))?;

        // Decode the code points from byte pairs rather than reinterpreting the bytes as
        // `&[u16]`.
        //
        // A cast would be wrong twice over. `data_start` is attacker-influenced - the compressed
        // length prefix is 1, 2 or 4 bytes depending on its first byte, so an odd offset is
        // reachable without touching the stream offset at all - and building a *reference* from a
        // pointer that is not aligned to its referent is undefined behaviour in Rust however the
        // hardware behaves. It also reads native-endian, while ECMA-335 §II.24.2.4 specifies
        // little-endian, so the same input would decode differently on a big-endian target.
        //
        // `utf16_data.len()` is even (rejected above otherwise), so `as_chunks::<2>` consumes it
        // fully and its remainder is empty. It yields the two-byte arrays themselves, so there is
        // no fallible conversion and no indexing that could panic.
        let code_units: Vec<u16> = utf16_data
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();

        Ok(U16String::from_vec(code_units))
    }

    /// Returns an iterator over all user strings in the heap
    ///
    /// Provides zero-copy access to all UTF-16 user strings with their byte offsets.
    /// Each iteration yields a `(usize, &U16CStr)` with the offset and string content.
    /// The iterator automatically handles length prefixes and skips the initial null entry.
    ///
    /// # Returns
    /// * [`crate::metadata::streams::userstrings::UserStringsIterator`] - Iterator over heap entries
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // "Hi" in UTF-16
    /// let user_strings = UserStrings::from(data)?;
    ///
    /// for (offset, string) in user_strings.iter() {
    ///     println!("String at {}: '{}'", offset, string.to_string_lossy());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> UserStringsIterator<'_> {
        UserStringsIterator::new(self)
    }

    /// Returns the raw underlying data of the userstring heap.
    ///
    /// This provides access to the complete heap data including the null byte at offset 0
    /// and all userstring entries in their original binary format.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Checks if the user strings heap contains a specific string value.
    ///
    /// Searches through all user strings in the heap to determine if any entry matches
    /// the provided string. The comparison is performed by converting the UTF-16 heap
    /// strings to UTF-8 using lossy conversion.
    ///
    /// # Arguments
    /// * `s` - The string value to search for
    ///
    /// # Returns
    /// `true` if the string exists in the heap, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Heap with "Hi" string
    /// let data = [
    ///     0x00,
    ///     0x05, 0x48, 0x00, 0x69, 0x00, 0x00,
    /// ];
    /// let user_strings = UserStrings::from(&data)?;
    ///
    /// assert!(user_strings.contains("Hi"));
    /// assert!(!user_strings.contains("NotFound"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn contains(&self, s: &str) -> bool {
        self.iter().any(|(_, value)| value.to_string_lossy() == s)
    }

    /// Finds the first occurrence of a user string and returns its heap offset.
    ///
    /// Searches through all user strings in the heap and returns the byte offset of the
    /// first matching entry. The comparison is performed by converting the UTF-16 heap
    /// strings to UTF-8 using lossy conversion.
    ///
    /// # Arguments
    /// * `s` - The string value to search for
    ///
    /// # Returns
    /// `Some(offset)` if the string is found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = [
    ///     0x00,
    ///     0x05, 0x48, 0x00, 0x69, 0x00, 0x00,  // "Hi" at offset 1
    /// ];
    /// let user_strings = UserStrings::from(&data)?;
    ///
    /// assert_eq!(user_strings.find("Hi"), Some(1));
    /// assert_eq!(user_strings.find("NotFound"), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find(&self, s: &str) -> Option<u32> {
        self.iter()
            .find(|(_, value)| value.to_string_lossy() == s)
            .and_then(|(offset, _)| u32::try_from(offset).ok())
    }

    /// Finds all occurrences of a user string and returns their heap offsets.
    ///
    /// Searches through all user strings in the heap and returns the byte offsets of all
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
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let data = [
    ///     0x00,
    ///     0x05, 0x48, 0x00, 0x69, 0x00, 0x00,  // "Hi" at offset 1
    ///     0x05, 0x48, 0x00, 0x69, 0x00, 0x00,  // "Hi" at offset 7
    /// ];
    /// let user_strings = UserStrings::from(&data)?;
    ///
    /// let offsets = user_strings.find_all("Hi");
    /// assert_eq!(offsets.len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn find_all(&self, s: &str) -> Vec<u32> {
        self.iter()
            .filter(|(_, value)| value.to_string_lossy() == s)
            .filter_map(|(offset, _)| u32::try_from(offset).ok())
            .collect()
    }
}

impl<'a> IntoIterator for &'a UserStrings<'a> {
    type Item = (usize, U16String);
    type IntoIter = UserStringsIterator<'a>;

    /// Create an iterator over the user strings heap.
    ///
    /// This allows using `for` loops directly on [`crate::metadata::streams::UserStrings`] references.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::streams::UserStrings;
    ///
    /// let data = &[0u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
    /// let heap = UserStrings::from(data)?;
    ///
    /// for (offset, string) in &heap {
    ///     println!("String: {}", string.to_string_lossy());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over entries in the `#US` (`UserStrings`) heap
///
/// Provides zero-copy access to UTF-16 user strings with their byte offsets.
/// Each iteration returns a `(usize, U16String)` containing the offset and string content.
/// The iterator automatically handles length prefixes and string format validation.
///
/// # Iteration Behavior
///
/// - Starts at offset 1 (skipping the null entry at offset 0)
/// - Reads length prefix to determine string size
/// - Advances position based on string length + overhead bytes
/// - Stops iteration on malformed string data
///
/// Create via [`crate::metadata::streams::UserStrings::iter()`] or using `&heap` in for loops.
pub struct UserStringsIterator<'a> {
    /// Reference to the user strings heap being iterated
    user_strings: &'a UserStrings<'a>,
    /// Current position within the user strings heap
    position: usize,
}

impl<'a> UserStringsIterator<'a> {
    /// Create a new iterator starting at position 1 (after the null entry)
    pub(crate) fn new(user_strings: &'a UserStrings<'a>) -> Self {
        Self {
            user_strings,
            position: 1,
        }
    }
}

impl<'a> Iterator for UserStringsIterator<'a> {
    type Item = (usize, U16String);

    /// The next entry that holds a string, as `(offset, string)`.
    ///
    /// Entries follow one another by their lengths (ECMA-335 II.24.2.4). One that holds no
    /// string (a zero length, as alignment padding has, or an even one, which leaves no room
    /// for the terminal byte) is passed over; iteration ends where the heap does, or where a
    /// length cannot be read or runs past it, since no entry after that point can be found.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = self.position;
            if start >= self.user_strings.data.len() {
                return None;
            }
            let (length, length_size) =
                read_compressed_int_at(self.user_strings.data, start).ok()?;
            let next = start.checked_add(length_size)?.checked_add(length)?;
            if next > self.user_strings.data.len() {
                return None;
            }
            self.position = next;
            if length == 0 {
                continue;
            }
            if let Ok(string) = self.user_strings.get(start) {
                return Some((start, string));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use widestring::u16str;

    use super::*;

    #[test]
    fn crafted() {
        #[rustfmt::skip]
        let data: [u8; 29] = [
            0x00, 0x1b, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00, 0x00
        ];

        let us_str = UserStrings::from(&data).unwrap();

        assert_eq!(us_str.get(1).unwrap(), u16str!("Hello, World!"));
    }

    /// A user string whose payload starts at an *odd* byte offset.
    ///
    /// This is the case that makes a zero-copy `&[u16]` unsound: building one from
    /// `utf16_data.as_ptr()` creates a reference from a pointer that is not aligned to its
    /// referent, which is UB in Rust no matter how tolerant the hardware is. Nothing upstream
    /// constrains the parity - a two-byte compressed length prefix at index 1 puts the payload
    /// at index 3 without touching the stream offset at all - so the decoder copies.
    ///
    /// A 0x81-byte entry forces that two-byte prefix: values >= 0x80 cannot use the one-byte form.
    #[test]
    fn payload_at_odd_offset_decodes() {
        const TOTAL_BYTES: usize = 0x81; // 128 bytes of UTF-16 + 1 terminator byte
        const CODE_UNITS: usize = 64;

        let mut data = vec![0x00];
        // Compressed-int encoding of 0x81 in the two-byte form.
        data.push(0x80);
        data.push(0x81);
        assert_eq!(data.len(), 3, "payload must begin at an odd offset");

        // 64 x 'A' (U+0041), little-endian as ECMA-335 requires.
        for _ in 0..CODE_UNITS {
            data.push(0x41);
            data.push(0x00);
        }
        data.push(0x00); // terminator byte

        assert_eq!(data.len(), 3 + TOTAL_BYTES);

        let heap = UserStrings::from(&data).unwrap();
        let s = heap.get(1).unwrap();

        assert_eq!(s.len(), CODE_UNITS);
        assert_eq!(s.to_string_lossy(), "A".repeat(CODE_UNITS));
    }

    /// Code units must be read little-endian regardless of host byte order (ECMA-335 II.24.2.4).
    ///
    /// U+3042 is asymmetric, so a native-endian read on a big-endian host would yield U+4230
    /// ('B0' as two bytes) instead. Reading it back correctly pins the byte order down.
    #[test]
    fn code_units_are_little_endian() {
        // 0x05 = 4 payload bytes + terminator; U+3042 U+3044 encoded little-endian.
        let data: [u8; 8] = [0x00, 0x05, 0x42, 0x30, 0x44, 0x30, 0x00, 0x00];

        let heap = UserStrings::from(&data).unwrap();
        let s = heap.get(1).unwrap();

        assert_eq!(s.as_slice(), &[0x3042, 0x3044]);
        assert_eq!(s.to_string_lossy(), "\u{3042}\u{3044}");
    }

    /// **The heap's first entry is the empty string.** ECMA-335 II.24.2.4
    /// makes it the empty blob, a single zero byte, and `ldstr` of offset 0 is
    /// how a compiler spells `""` (`crossgen2`'s `StringHandle` fixups of
    /// `System.Drawing.Primitives.dll` name it so); an entry of its terminal
    /// byte alone is empty too.
    #[test]
    fn the_first_entry_is_the_empty_string() {
        let data = [0x00, 0x01, 0x00, 0x05, 0x48, 0x00, 0x69, 0x00, 0x00];
        let heap = UserStrings::from(&data).unwrap();
        assert_eq!(heap.get(0).unwrap(), u16str!(""));
        assert_eq!(heap.get(1).unwrap(), u16str!(""));
        assert_eq!(heap.get(3).unwrap(), u16str!("Hi"));
    }

    #[test]
    fn invalid() {
        let data_empty = [];
        if UserStrings::from(&data_empty).is_ok() {
            panic!("This should not be valid!")
        }

        let data_invalid_first = [
            0x22, 0x1b, 0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x2c, 0x00,
            0x20, 0x00, 0x57, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6c, 0x00, 0x64, 0x00, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        if UserStrings::from(&data_invalid_first).is_ok() {
            panic!("This should not be valid!")
        }

        let data_invalid_first = [0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let us_str = UserStrings::from(&data_invalid_first).unwrap();
        if us_str.get(1).is_ok() {
            panic!("This should not be valid!")
        }
    }

    #[test]
    fn test_userstrings_iterator_basic() {
        // Simple test case - "Hi" in UTF-16 with compressed length prefix
        // Based on .NET runtime format: [compressed_length][utf16_data][terminator_byte]
        // Length 0x05 = 5 bytes: 4 bytes UTF-16 + 1 terminator byte
        let data = [
            0x00, // Initial null byte
            0x05, // Length: 5 bytes total (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte (no high chars)
        ];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_multiple() {
        // Two strings: "Hi" (length 5) and "Bye" (length 7)
        // Format: [compressed_length][utf16_data][terminator_byte]
        let data = [
            0x00, // Initial null byte
            0x05, // "Hi": len=5 (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte
            0x07, // "Bye": len=7 (6 UTF-16 + 1 terminator)
            0x42, 0x00, 0x79, 0x00, 0x65, 0x00, // "Bye" in UTF-16 LE
            0x00, // Terminator byte
        ];

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "Hi");

        let second = iter.next().unwrap();
        assert_eq!(second.0, 7); // Correct: 1 (start) + 1 (length byte) + 5 (data+terminator) = 7
        assert_eq!(second.1.to_string_lossy(), "Bye");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_empty_string() {
        // Empty string followed by "Hi"
        // Empty string: length 1 (0 UTF-16 + 1 terminator), then "Hi": length 5
        let data = [
            0x00, // Initial null byte
            0x01, // Empty string: len=1 (just terminator)
            0x00, // Terminator byte
            0x05, // "Hi": len=5 (4 UTF-16 + 1 terminator)
            0x48, 0x00, 0x69, 0x00, // "Hi" in UTF-16 LE
            0x00, // Terminator byte
        ];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "");

        let second = iter.next().unwrap();
        assert_eq!(second.0, 3);
        assert_eq!(second.1.to_string_lossy(), "Hi");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_long_string() {
        // Test with a longer string - 5 characters in UTF-16
        let mut data = vec![0x00]; // Initial null byte

        // "AAAAA" = 5 chars * 2 bytes + 1 terminator = 11 bytes total
        data.push(0x0B); // Length 11

        // Add 10 bytes of UTF-16 data (5 characters: "AAAAA")
        for _ in 0..5 {
            data.extend_from_slice(&[0x41, 0x00]);
        }
        data.push(0x00); // Terminator byte

        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        let first = iter.next().unwrap();
        assert_eq!(first.0, 1);
        assert_eq!(first.1.to_string_lossy(), "AAAAA");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_truncated_data() {
        // String claims length 7 but only 5 bytes available
        let data = [0x00, 0x07, 0x48, 0x00, 0x69];
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        // Iterator should stop on malformed data
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_userstrings_iterator_invalid_utf16_length() {
        // Odd number of bytes for UTF-16 data
        let data = [0x00, 0x04, 0x48, 0x00, 0x69]; // Length 3 but only 3 bytes (should be even)
        let user_strings = UserStrings::from(&data).unwrap();
        let mut iter = user_strings.iter();

        // Iterator should stop on malformed data
        assert!(iter.next().is_none());
    }

    /// Entries follow one another by their lengths: zero-length padding, however long, and an
    /// entry with no room for its terminal byte are passed over, and what follows them is
    /// still found.
    #[test]
    fn entries_after_padding_and_malformed_ones_are_found() {
        let mut data = vec![0x00, 0x03, b'A', 0x00, 0x00];
        data.extend_from_slice(&[0x00; 12]); // zero-length entries
        data.extend_from_slice(&[0x02, b'X', 0x00]); // even length: no terminal byte
        data.extend_from_slice(&[0x03, b'B', 0x00, 0x00]);
        let heap = UserStrings::from(&data).unwrap();

        let found: Vec<(usize, String)> = heap
            .iter()
            .map(|(offset, text)| (offset, text.to_string_lossy()))
            .collect();
        assert_eq!(found, [(1, "A".to_string()), (20, "B".to_string())]);
    }

    /// A length that runs past the heap ends iteration: nothing after it can be located.
    #[test]
    fn a_length_past_the_heap_ends_iteration() {
        let data = [0x00, 0x03, b'A', 0x00, 0x00, 0x7F, b'Z'];
        let heap = UserStrings::from(&data).unwrap();
        assert_eq!(heap.iter().count(), 1);
    }
}

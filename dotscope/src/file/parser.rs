//! Low-level byte stream parser for CIL and metadata decoding.
//!
//! This module provides the [`crate::file::parser::Parser`] type, a cursor-based binary data parser
//! specifically designed for reading .NET metadata structures and CIL bytecode. It offers bounds-checked
//! access to binary data with support for both little-endian and big-endian formats, compressed
//! encodings, and complex metadata structures defined by ECMA-335 specifications.
//!
//! # Architecture
//!
//! The parser is built around a simple cursor-based model that maintains a position within
//! a byte slice. The architecture provides:
//!
//! - **Position tracking** - Maintains current offset for sequential parsing operations
//! - **Bounds checking** - All operations validate data availability before reading
//! - **Type-safe reading** - Strongly typed methods for common data types
//! - **Metadata support** - Specialized methods for .NET metadata structures
//!
//! # Key Components
//!
//! ## Core Type
//! - [`crate::file::parser::Parser`] - Main parser struct for binary data reading
//!
//! ## Navigation Methods
//! - [`crate::file::parser::Parser::seek`] - Move to specific position
//! - [`crate::file::parser::Parser::advance`] - Move forward by one byte
//! - [`crate::file::parser::Parser::advance_by`] - Move forward by specified bytes
//! - [`crate::file::parser::Parser::pos`] - Get current position
//! - [`crate::file::parser::Parser::align`] - Align to byte boundaries
//!
//! ## Data Access Methods
//! - [`crate::file::parser::Parser::read_le`] - Read primitive types (little-endian)
//! - [`crate::file::parser::Parser::read_be`] - Read primitive types (big-endian)
//! - [`crate::file::parser::Parser::peek_byte`] - Peek at current byte without advancing
//! - [`crate::file::parser::Parser::data`] - Access remaining data slice
//!
//! ## Metadata Reading Methods
//! - [`crate::file::parser::Parser::read_compressed_uint`] - Read compressed unsigned integers
//! - [`crate::file::parser::Parser::read_compressed_int`] - Read compressed signed integers
//! - [`crate::file::parser::Parser::read_compressed_token`] - Read compressed metadata tokens
//! - [`crate::file::parser::Parser::read_7bit_encoded_int`] - Read 7-bit encoded integers
//! - [`crate::file::parser::Parser::read_string_utf8`] - Read UTF-8 strings
//! - [`crate::file::parser::Parser::read_prefixed_string_utf8`] - Read length-prefixed UTF-8 strings
//! - [`crate::file::parser::Parser::read_prefixed_string_utf16`] - Read length-prefixed UTF-16 strings
//!
//! # Usage Examples
//!
//! ## Basic Value Reading
//!
//! ```rust
//! use dotscope::Parser;
//!
//! let data = [0x01, 0x02, 0x03, 0x04];
//! let mut parser = Parser::new(&data);
//!
//! // Read little-endian values
//! let value = parser.read_le::<u16>()?;
//! assert_eq!(value, 0x0201);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Sequential Parsing with Navigation
//!
//! ```rust
//! use dotscope::Parser;
//!
//! let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
//! let mut parser = Parser::new(&data);
//!
//! // Read sequentially
//! let first = parser.read_le::<u32>()?;
//! assert_eq!(first, 0x04030201);
//!
//! // Seek to specific position
//! parser.seek(6)?;
//! let last_bytes = parser.read_le::<u16>()?;
//! assert_eq!(last_bytes, 0x0807);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Metadata Structure Parsing
//!
//! ```rust
//! use dotscope::Parser;
//!
//! // Example metadata with compressed integers
//! let metadata = [0x0C, 0x80, 0x95, 0x01]; // Compressed encoding example
//! let mut parser = Parser::new(&metadata);
//!
//! // Read compressed metadata values
//! let param_count = parser.read_compressed_uint()?;
//! let type_token = parser.read_compressed_token()?;
//!
//! println!("Parameter count: {}, Type token: {:?}", param_count, type_token);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::token::Token,
    utils::{read_be_at, read_le_at, CilIO},
    Error, ParseFailure, ParseStage, Result,
};

/// File-local helpers for converting parser failures into the crate's
/// [`Error`] without per-site verbosity. The parser is a generic
/// building block, so all errors carry [`ParseStage::Generic`].
#[inline]
fn oob_err() -> Error {
    ParseFailure::OutOfBounds {
        stage: ParseStage::Generic,
    }
    .into()
}

#[inline]
fn invalid_err(field: &'static str, reason: String) -> Error {
    ParseFailure::InvalidField {
        stage: ParseStage::Generic,
        field,
        reason,
    }
    .into()
}

/// A generic binary data parser for reading .NET metadata structures.
///
/// `Parser` provides a cursor-based interface for reading binary data in both
/// little-endian and big-endian formats. It's designed specifically for parsing
/// .NET metadata structures that follow ECMA-335 specifications, including
/// method signatures, type signatures, custom attributes, and marshalling data.
///
/// The parser maintains an internal position cursor and provides bounds checking
/// to prevent buffer overruns when reading malformed or truncated data.
///
/// # Features
///
/// - **Bounds checking**: All read operations validate data availability
/// - **Endianness support**: Both little-endian and big-endian reading
/// - **Position tracking**: Maintains current offset for sequential parsing
/// - **Flexible seeking**: Random access to any position within the data
/// - **Type safety**: Strongly typed reading methods for common data types
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::Parser;
///
/// let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let mut parser = Parser::new(&data);
///
/// // Read little-endian values
/// let first = parser.read_le::<u32>()?;
/// assert_eq!(first, 0x04030201);
///
/// // Seek to a specific position
/// parser.seek(6)?;
/// let last_bytes = parser.read_le::<u16>()?;
/// assert_eq!(last_bytes, 0x0807);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Metadata Parsing Usage
///
/// The Parser handles compressed integers, variable-length encodings, and complex metadata
/// structures found in .NET assemblies. It supports reading calling conventions, parameter
/// counts, type signatures, and other binary metadata formats efficiently.
pub struct Parser<'a> {
    /// The binary data being parsed
    data: &'a [u8],
    /// Current position within the data buffer
    position: usize,
}

impl<'a> Parser<'a> {
    /// Create a new [`crate::file::parser::Parser`] from a byte slice.
    ///
    /// # Arguments
    /// * `data` - The byte slice to read from
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let parser = Parser::new(&data);
    /// assert_eq!(parser.len(), 4);
    /// ```
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data, position: 0 }
    }

    /// Returns the length of the underlying data buffer.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let parser = Parser::new(&data);
    /// assert_eq!(parser.len(), 3);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the parser has no data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let empty_data = [];
    /// let parser = Parser::new(&empty_data);
    /// assert!(parser.is_empty());
    ///
    /// let data = [0x01];
    /// let parser = Parser::new(&data);
    /// assert!(!parser.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns `true` if there is more data available to parse.
    ///
    /// This checks if the current position is before the end of the data buffer.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02];
    /// let mut parser = Parser::new(&data);
    /// assert!(parser.has_more_data());
    ///
    /// let _byte = parser.read_le::<u8>()?;
    /// assert!(parser.has_more_data());
    ///
    /// let _byte = parser.read_le::<u8>()?;
    /// assert!(!parser.has_more_data());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn has_more_data(&self) -> bool {
        self.position < self.data.len()
    }

    /// Move the current position to the specified index.
    ///
    /// # Arguments
    /// * `pos` - The position to move the cursor to
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if position is beyond the data length.
    /// The end of the data itself is a position, the one a parser that has
    /// read everything is at.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let mut parser = Parser::new(&data);
    ///
    /// parser.seek(2)?;
    /// assert_eq!(parser.pos(), 2);
    /// let value = parser.read_le::<u8>()?;
    /// assert_eq!(value, 0x03);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(oob_err());
        }

        self.position = pos;
        Ok(())
    }

    /// Move the position forward by one byte.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if advancing would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let mut parser = Parser::new(&data);
    ///
    /// assert_eq!(parser.pos(), 0);
    /// parser.advance()?;
    /// assert_eq!(parser.pos(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn advance(&mut self) -> Result<()> {
        self.advance_by(1)
    }

    /// Move the position forward by the specified number of bytes.
    ///
    /// # Arguments
    /// * `step` - Amount of bytes to advance
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if advancing by step would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    /// let mut parser = Parser::new(&data);
    ///
    /// assert_eq!(parser.pos(), 0);
    /// parser.advance_by(3)?;
    /// assert_eq!(parser.pos(), 3);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn advance_by(&mut self, step: usize) -> Result<()> {
        let new_pos = self.position.checked_add(step).ok_or(oob_err())?;
        if new_pos > self.data.len() {
            return Err(oob_err());
        }
        self.position = new_pos;
        Ok(())
    }

    /// Get the current position of the parser within the data buffer.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let mut parser = Parser::new(&data);
    ///
    /// assert_eq!(parser.pos(), 0);
    /// let _byte = parser.read_le::<u8>()?;
    /// assert_eq!(parser.pos(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn pos(&self) -> usize {
        self.position
    }

    /// Get access to the underlying data buffer.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let parser = Parser::new(&data);
    /// assert_eq!(parser.data(), &[0x01, 0x02, 0x03]);
    /// ```
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Peek at the next byte without advancing the position.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if position is at or beyond the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let mut parser = Parser::new(&data);
    ///
    /// assert_eq!(parser.peek_byte()?, 0x01);
    /// assert_eq!(parser.pos(), 0); // Position unchanged
    /// let value = parser.read_le::<u8>()?;
    /// assert_eq!(value, 0x01);
    /// assert_eq!(parser.pos(), 1); // Now position advanced
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn peek_byte(&self) -> Result<u8> {
        self.data.get(self.position).copied().ok_or(oob_err())
    }

    /// Peek at a value of type `T` in little-endian format without advancing the position.
    ///
    /// This method reads a value from the current position but does not modify the
    /// parser state, allowing inspection of upcoming data before deciding how to proceed.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading `T` would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let mut parser = Parser::new(&data);
    ///
    /// // Peek at a u16 without advancing
    /// let peeked: u16 = parser.peek_le()?;
    /// assert_eq!(peeked, 0x0201);
    /// assert_eq!(parser.pos(), 0); // Position unchanged
    ///
    /// // Now read it for real
    /// let value: u16 = parser.read_le()?;
    /// assert_eq!(value, 0x0201);
    /// assert_eq!(parser.pos(), 2); // Position advanced
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn peek_le<T: CilIO>(&self) -> Result<T> {
        let mut temp_position = self.position;
        read_le_at::<T>(self.data, &mut temp_position)
    }

    /// Execute a closure transactionally, rolling back on failure.
    ///
    /// This method saves the current parser position, executes the provided closure,
    /// and only commits the position change if the closure succeeds. If the closure
    /// returns `Err`, the parser position is restored to its original value.
    ///
    /// This is useful for speculative parsing where you want to try parsing something
    /// and only consume the input if parsing succeeds.
    ///
    /// # Arguments
    /// * `f` - A closure that takes a mutable reference to the parser and returns a `Result<T>`
    ///
    /// # Returns
    /// Returns the result of the closure. On success, the parser position reflects any
    /// advances made during parsing. On failure, the parser position is restored.
    ///
    /// # Errors
    /// Returns any error produced by the closure `f`. When an error is returned,
    /// the parser position is automatically restored to its state before the call.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let mut parser = Parser::new(&data);
    ///
    /// // Try to parse - on success, position advances
    /// let result: Result<u16, _> = parser.transactional(|p| p.read_le());
    /// assert!(result.is_ok());
    /// assert_eq!(parser.pos(), 2); // Position advanced on success
    ///
    /// // Try to parse something that fails - position restored
    /// let mut parser2 = Parser::new(&[0x01]);
    /// let result: Result<u32, _> = parser2.transactional(|p| p.read_le());
    /// assert!(result.is_err());
    /// assert_eq!(parser2.pos(), 0); // Position restored on failure
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn transactional<T, F>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let saved_position = self.position;
        let result = f(self);
        if result.is_err() {
            self.position = saved_position;
        }
        result
    }

    /// Align the position to a specific boundary.
    ///
    /// This advances the position to the next multiple of the specified alignment,
    /// which is useful when parsing data structures that require specific memory alignment.
    ///
    /// # Arguments
    /// * `alignment` - The boundary to align to (must be a power of 2)
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if aligning would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    /// let mut parser = Parser::new(&data);
    ///
    /// parser.advance()?; // Position is now 1
    /// parser.align(4)?;  // Align to 4-byte boundary
    /// assert_eq!(parser.pos(), 4); // Position advanced to next 4-byte boundary
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let rem = self.position.checked_rem(alignment).ok_or(oob_err())?;
        let padding = alignment
            .wrapping_sub(rem)
            .checked_rem(alignment)
            .ok_or(oob_err())?;
        let new_pos = self.position.checked_add(padding).ok_or(oob_err())?;
        if new_pos > self.data.len() {
            return Err(oob_err());
        }
        self.position = new_pos;
        Ok(())
    }

    /// Read a type `T` from the current position in little-endian format and advance the position.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let mut parser = Parser::new(&data);
    ///
    /// let value: u16 = parser.read_le()?;
    /// assert_eq!(value, 0x0201); // Little-endian interpretation
    /// assert_eq!(parser.pos(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_le<T: CilIO>(&mut self) -> Result<T> {
        read_le_at::<T>(self.data, &mut self.position)
    }

    /// Read a type `T` from the current position in big-endian format and advance the position.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04];
    /// let mut parser = Parser::new(&data);
    ///
    /// let value: u16 = parser.read_be()?;
    /// assert_eq!(value, 0x0102); // Big-endian interpretation
    /// assert_eq!(parser.pos(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_be<T: CilIO>(&mut self) -> Result<T> {
        read_be_at::<T>(self.data, &mut self.position)
    }

    /// Read a compressed unsigned integer as defined in ECMA-335 II.23.2.
    ///
    /// Compressed integers use variable-length encoding to efficiently store small values:
    /// - Values 0-127: 1 byte (0xxxxxxx)
    /// - Values 128-16383: 2 bytes (10xxxxxx xxxxxxxx)  
    /// - Values 16384-536870911: 4 bytes (11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid compressed uint format.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Single byte encoding (value < 128)
    /// let data = [0x7F]; // Represents 127
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_compressed_uint()?, 127);
    ///
    /// // Two byte encoding
    /// let data = [0x80, 0x80]; // Represents 128
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_compressed_uint()?, 128);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_compressed_uint(&mut self) -> Result<u32> {
        let first_byte = self.read_le::<u8>()?;

        // 1-byte encoding: 0xxxxxxx
        if (first_byte & 0x80) == 0 {
            return Ok(u32::from(first_byte));
        }

        // 2-byte encoding: 10xxxxxx xxxxxxxx
        if (first_byte & 0xC0) == 0x80 {
            let second_byte = self.read_le::<u8>()?;
            let value = ((u32::from(first_byte) & 0x3F) << 8) | u32::from(second_byte);
            return Ok(value);
        }

        // 4-byte encoding: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if (first_byte & 0xE0) == 0xC0 {
            let b1 = u32::from(self.read_le::<u8>()?);
            let b2 = u32::from(self.read_le::<u8>()?);
            let b3 = u32::from(self.read_le::<u8>()?);
            let value = ((u32::from(first_byte) & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3;
            return Ok(value);
        }

        Err(invalid_err(
            "compressed_uint",
            format!("invalid compressed uint - {first_byte}"),
        ))
    }

    /// Read a compressed signed integer as defined in ECMA-335 II.23.2.
    ///
    /// The encoded bits are the value's two's complement form, 7, 14 or 29 bits
    /// wide by the length of the encoding, rotated left by one so the sign sits
    /// in the lowest bit; reading rotates them back and sign-extends.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // The examples of ECMA-335 II.23.2: 3 is 0x06, -3 is 0x7B.
    /// let data = [0x06];
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_compressed_int()?, 3);
    ///
    /// let data = [0x7B];
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_compressed_int()?, -3);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_compressed_int(&mut self) -> Result<i32> {
        let first_byte = self.peek_byte()?;
        // The value's top bit and the shift that sign-extends from it, for a
        // 7, 14 or 29 bit encoding.
        let (top_bit, shift): (u32, u32) = if (first_byte & 0x80) == 0 {
            (1 << 6, 25)
        } else if (first_byte & 0xC0) == 0x80 {
            (1 << 13, 18)
        } else {
            (1 << 28, 3)
        };
        let rotated = self.read_compressed_uint()?;
        let sign = if rotated & 1 == 0 { 0 } else { top_bit };
        let twos = (rotated >> 1) | sign;
        #[allow(clippy::cast_possible_wrap)]
        let value = ((twos << shift) as i32) >> shift;
        Ok(value)
    }

    /// Read a compressed token as defined in ECMA-335 II.23.2.4 (TypeDefOrRefOrSpecEncoded).
    ///
    /// Compressed tokens encode type references using the 2 lowest bits as a tag and the
    /// remaining bits as the table row index. The tag determines which metadata table:
    ///
    /// | Tag | Table | Token Prefix |
    /// |-----|-------|--------------|
    /// | 0x0 | TypeDef | 0x0200_0000 |
    /// | 0x1 | TypeRef | 0x0100_0000 |
    /// | 0x2 | TypeSpec | 0x1B00_0000 |
    /// | 0x3 | (reserved/invalid) | - |
    ///
    /// Tag 0x3 is reserved and currently unused by the ECMA-335 specification.
    /// Encountering this tag value indicates a malformed compressed token.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] if tag 0x3 is encountered (invalid encoding).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // TypeRef token (tag 0x1, index 1) encoded as (1 << 2) | 0x1 = 5
    /// let data = [5];
    /// let mut parser = Parser::new(&data);
    /// let token = parser.read_compressed_token()?;
    /// assert_eq!(token.value(), 0x01000001); // TypeRef table with index 1
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_compressed_token(&mut self) -> Result<Token> {
        let compressed_token = self.read_compressed_uint()?;

        let table: u32 = match compressed_token & 0x3 {
            0x0 => 0x0200_0000, // TypeDef
            0x1 => 0x0100_0000, // TypeRef
            0x2 => 0x1B00_0000, // TypeSpec
            _ => {
                return Err(invalid_err(
                    "compressed_token",
                    format!("invalid compressed token - {compressed_token}"),
                ))
            }
        };

        let table_index = compressed_token >> 2;
        let token = table.checked_add(table_index).ok_or_else(|| {
            invalid_err(
                "compressed_token",
                format!("token index overflows table base: {table} + {table_index}"),
            )
        })?;

        Ok(Token::new(token))
    }

    /// Read a 7-bit encoded integer (used in .NET for variable-length encoding).
    ///
    /// This encoding uses the most significant bit of each byte as a continuation flag.
    /// If set, the next byte is part of the value. The value is reconstructed by
    /// concatenating the lower 7 bits of each byte in little-endian order.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid encoding (overflow).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Single byte: 127 (0x7F)
    /// let data = [0x7F];
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_7bit_encoded_int()?, 127);
    ///
    /// // Two bytes: 128 (0x80 0x01)
    /// let data = [0x80, 0x01];
    /// let mut parser = Parser::new(&data);
    /// assert_eq!(parser.read_7bit_encoded_int()?, 128);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_7bit_encoded_int(&mut self) -> Result<u32> {
        let mut value = 0u32;
        let mut shift: u32 = 0;

        loop {
            let byte = *self.data.get(self.position).ok_or(oob_err())?;
            self.position = self.position.checked_add(1).ok_or(oob_err())?;

            value |= u32::from(byte & 0x7F) << shift;
            shift = shift
                .checked_add(7)
                .ok_or_else(|| invalid_err("varint", "7-bit encoded integer overflow".into()))?;

            if (byte & 0x80) == 0 {
                break;
            }

            // A u32 can hold at most 32 bits; after 4 bytes we've read 28 bits.
            // A 5th continuation byte would push past 32 bits, causing overflow.
            if shift >= 32 {
                return Err(invalid_err(
                    "varint",
                    format!(
                        "7-bit encoded integer overflow: value exceeds u32 capacity after {shift} bits",
                    ),
                ));
            }
        }

        Ok(value)
    }

    /// Read a UTF-8 encoded null-terminated string.
    ///
    /// Reads bytes from the current position until a null terminator (0x00) is found,
    /// then decodes the bytes as UTF-8. The position is advanced past the null terminator.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid UTF-8 encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// let data = b"Hello\0World\0";
    /// let mut parser = Parser::new(data);
    ///
    /// let first = parser.read_string_utf8()?;
    /// assert_eq!(first, "Hello");
    ///
    /// let second = parser.read_string_utf8()?;
    /// assert_eq!(second, "World");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_string_utf8(&mut self) -> Result<String> {
        let start = self.position;
        let mut end = start;

        while let Some(&b) = self.data.get(end) {
            if b == 0 {
                break;
            }
            end = end.checked_add(1).ok_or(oob_err())?;
        }

        // Handle two cases:
        // 1. Found null terminator (end < data.len()): normal null-terminated string
        // 2. Reached end of data (end == data.len()): string without null terminator (valid case)
        let string_data = self.data.get(start..end).ok_or(oob_err())?;

        if end < self.data.len() {
            self.position = end.checked_add(1).ok_or(oob_err())?;
        } else {
            self.position = end;
        }

        String::from_utf8(string_data.to_vec()).map_err(|e| {
            invalid_err(
                "utf8_string",
                format!(
                    "invalid UTF-8 string at offset {start}-{end}: {}",
                    e.utf8_error()
                ),
            )
        })
    }

    /// Read a length-prefixed UTF-8 string.
    ///
    /// The string length is encoded as a 7-bit encoded integer, followed by that many
    /// UTF-8 bytes. This format is commonly used in .NET metadata streams.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid UTF-8 encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Length 5, followed by "Hello"
    /// let data = [5, b'H', b'e', b'l', b'l', b'o'];
    /// let mut parser = Parser::new(&data);
    ///
    /// let result = parser.read_prefixed_string_utf8()?;
    /// assert_eq!(result, "Hello");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_prefixed_string_utf8(&mut self) -> Result<String> {
        let length = self.read_7bit_encoded_int()? as usize;
        let end = self.position.checked_add(length).ok_or(oob_err())?;

        let start = self.position;
        let string_data = self.data.get(start..end).ok_or(oob_err())?;
        self.position = end;

        String::from_utf8(string_data.to_vec()).map_err(|e| {
            invalid_err(
                "utf8_string",
                format!(
                    "invalid UTF-8 string at offset {start}-{end}: {}",
                    e.utf8_error()
                ),
            )
        })
    }

    /// Read a 7-bit encoded length-prefixed UTF-8 string as a borrowed slice (zero-copy).
    ///
    /// This is the zero-copy variant of [`read_prefixed_string_utf8`](Parser::read_prefixed_string_utf8).
    /// Instead of allocating a new `String`, it returns a borrowed `&str` slice directly into
    /// the underlying data buffer. This is ideal for large strings or performance-critical code
    /// where you want to avoid allocations.
    ///
    /// The string length is encoded as a 7-bit compressed integer (ECMA-335 format),
    /// followed by that many UTF-8 bytes.
    ///
    /// # Lifetime
    ///
    /// The returned string slice borrows from the parser's underlying data buffer and has
    /// the same lifetime `'a` as the parser.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid UTF-8 encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Length 5, followed by "Hello"
    /// let data = [5, b'H', b'e', b'l', b'l', b'o'];
    /// let mut parser = Parser::new(&data);
    ///
    /// let result = parser.read_prefixed_string_utf8_ref()?;
    /// assert_eq!(result, "Hello");
    /// // No allocation - result borrows from data
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_prefixed_string_utf8_ref(&mut self) -> Result<&'a str> {
        let length = self.read_7bit_encoded_int()? as usize;
        let start = self.position;
        let end = start.checked_add(length).ok_or(oob_err())?;

        let string_data = self.data.get(start..end).ok_or(oob_err())?;
        self.position = end;

        std::str::from_utf8(string_data).map_err(|_| {
            invalid_err(
                "utf8_string",
                format!("invalid UTF-8 string at position {start} - {end} - {string_data:?}"),
            )
        })
    }

    /// Read a compressed uint length-prefixed UTF-8 string.
    ///
    /// The string length is encoded as a compressed unsigned integer according to ECMA-335,
    /// followed by that many UTF-8 bytes. This format is used for strings in custom attributes,
    /// security permissions, and other metadata structures that follow ECMA-335 blob format.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid UTF-8 encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Length 5 (compressed uint), followed by "Hello"
    /// let data = [5, b'H', b'e', b'l', b'l', b'o'];
    /// let mut parser = Parser::new(&data);
    ///
    /// let result = parser.read_compressed_string_utf8()?;
    /// assert_eq!(result, "Hello");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_compressed_string_utf8(&mut self) -> Result<String> {
        let length = self.read_compressed_uint()? as usize;
        let start = self.position;
        let end = start.checked_add(length).ok_or(oob_err())?;

        let string_data = self.data.get(start..end).ok_or(oob_err())?;
        self.position = end;

        String::from_utf8(string_data.to_vec()).map_err(|e| {
            invalid_err(
                "utf8_compressed_string",
                format!(
                    "invalid UTF-8 compressed string at offset {start}-{end}: {}",
                    e.utf8_error()
                ),
            )
        })
    }

    /// Returns the number of bytes remaining from the current position.
    ///
    /// This is useful for checking available data before reading operations
    /// or for implementing consistent bounds checking patterns.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    /// let mut parser = Parser::new(&data);
    ///
    /// assert_eq!(parser.remaining(), 5);
    /// parser.advance_by(2)?;
    /// assert_eq!(parser.remaining(), 3);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Ensures that at least `needed` bytes are available from the current position.
    ///
    /// This method provides a standardized way to validate data availability before
    /// performing read operations. It returns a descriptive error when insufficient
    /// data is available.
    ///
    /// # Arguments
    /// * `needed` - The number of bytes required from the current position
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if fewer than `needed` bytes remain.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03];
    /// let mut parser = Parser::new(&data);
    ///
    /// parser.ensure_remaining(3)?;  // OK
    /// parser.advance()?;
    /// parser.ensure_remaining(2)?;  // OK
    /// // parser.ensure_remaining(3)?;  // Would fail - only 2 bytes remaining
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn ensure_remaining(&self, needed: usize) -> Result<()> {
        if self.remaining() < needed {
            return Err(oob_err());
        }
        Ok(())
    }

    /// Calculates an end position safely with overflow checking.
    ///
    /// Computes `self.position + length` while checking for arithmetic overflow
    /// and ensuring the result doesn't exceed the data bounds.
    ///
    /// # Arguments
    /// * `length` - The length to add to the current position
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the calculation would overflow
    /// or if the resulting position exceeds the data length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    /// let mut parser = Parser::new(&data);
    ///
    /// let end = parser.calc_end_position(3)?;
    /// assert_eq!(end, 3);
    ///
    /// parser.seek(2)?;
    /// let end = parser.calc_end_position(2)?;
    /// assert_eq!(end, 4);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn calc_end_position(&self, length: usize) -> Result<usize> {
        let end = self.position.checked_add(length).ok_or(oob_err())?;

        if end > self.data.len() {
            return Err(oob_err());
        }

        Ok(end)
    }

    /// Reads a slice of bytes of the specified length from the current position.
    ///
    /// This method performs bounds checking and advances the position after reading.
    /// It's useful when you need to read a chunk of raw bytes rather than a specific type.
    ///
    /// # Arguments
    /// * `length` - The number of bytes to read
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading `length` bytes would exceed the data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    /// let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    /// let mut parser = Parser::new(&data);
    ///
    /// let chunk = parser.read_bytes(3)?;
    /// assert_eq!(chunk, &[0x01, 0x02, 0x03]);
    /// assert_eq!(parser.pos(), 3);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.calc_end_position(length)?;
        let bytes = self.data.get(self.position..end).ok_or(oob_err())?;
        self.position = end;
        Ok(bytes)
    }

    /// Read a length-prefixed UTF-16 string.
    ///
    /// The string length is encoded as a 7-bit encoded integer (in bytes), followed by
    /// that many UTF-16 bytes in little-endian format. This format is used for wide
    /// character strings in .NET metadata.
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if reading would exceed the data length or
    /// [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] for invalid UTF-16 encoding or odd byte length.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::Parser;
    ///
    /// // Length 10 bytes (5 UTF-16 chars), followed by "Hello" in UTF-16 LE
    /// let data = [10, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
    /// let mut parser = Parser::new(&data);
    ///
    /// let result = parser.read_prefixed_string_utf16()?;
    /// assert_eq!(result, "Hello");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read_prefixed_string_utf16(&mut self) -> Result<String> {
        let length = self.read_7bit_encoded_int()? as usize;
        let end = self.position.checked_add(length).ok_or(oob_err())?;
        if end > self.data.len() {
            return Err(oob_err());
        }

        if !length.is_multiple_of(2) || length < 2 {
            return Err(invalid_err(
                "utf16_length",
                format!("invalid UTF-16 length - {length}"),
            ));
        }

        let char_count = length / 2;
        let mut utf16_chars: Vec<u16> = Vec::with_capacity(char_count);
        for _ in 0..char_count {
            let char = self.read_le::<u16>()?;
            utf16_chars.push(char);
        }

        match String::from_utf16(&utf16_chars) {
            Ok(s) => Ok(s),
            Err(_) => Err(invalid_err(
                "utf16_string",
                format!(
                    "invalid UTF-16 string at position {} (length {}): {utf16_chars:?}",
                    self.position, length
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, ParseFailure};

    #[test]
    fn test_read_compressed_uint() {
        let test_cases = vec![
            (vec![0x03], 3),                             // 1-byte format
            (vec![0x7F], 0x7F),                          // 1-byte format, max value
            (vec![0x80, 0x80], 0x80),                    // 2-byte format, min value
            (vec![0xBF, 0xFF], 0x3FFF),                  // 2-byte format, max value
            (vec![0xC0, 0x00, 0x00, 0x00], 0x00),        // 4-byte format, min value
            (vec![0xDF, 0xFF, 0xFF, 0xFF], 0x1FFF_FFFF), // 4-byte format, max value
        ];

        for (input, expected) in test_cases {
            let mut parser = Parser::new(&input);
            let result = parser.read_compressed_uint().unwrap();
            assert_eq!(result, expected);
        }

        // Error on empty data
        let mut parser = Parser::new(&[]);
        assert!(matches!(
            parser.read_compressed_uint(),
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn test_read_compressed_int() {
        // The signed examples of ECMA-335 II.23.2, with the ends of each width.
        let cases: &[(&[u8], i32)] = &[
            (&[0x00], 0),
            (&[0x06], 3),
            (&[0x7B], -3),
            (&[0x7E], 63),
            (&[0x7F], -1),
            (&[0x80, 0x80], 64),
            (&[0x01], -64),
            (&[0xBF, 0x7F], -65),
            (&[0xC0, 0x00, 0x40, 0x00], 8192),
            (&[0x80, 0x01], -8192),
            (&[0xDF, 0xFF, 0xFF, 0xFE], 268_435_455),
            (&[0xC0, 0x00, 0x00, 0x01], -268_435_456),
        ];
        for (bytes, expected) in cases {
            let mut parser = Parser::new(bytes);
            assert_eq!(
                parser.read_compressed_int().unwrap(),
                *expected,
                "{bytes:02x?}"
            );
            assert_eq!(parser.pos(), bytes.len(), "{bytes:02x?}");
        }
    }

    #[test]
    fn test_parse_string() {
        let test_cases = vec![
            (vec![0x61, 0x62, 0x63, 0x00], "abc"), // Simple string
            (vec![0x00], ""),                      // Empty string
            (vec![0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0x00], "中文"), // UTF-8 string
        ];

        for (input, expected) in test_cases {
            let mut parser = Parser::new(&input);
            let result = parser.read_string_utf8().unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_error_handling() {
        // Test unexpected end of data
        let mut parser = Parser::new(&[0x08]); // Just one byte
        assert!(matches!(parser.read_compressed_uint(), Ok(8)));
        assert!(matches!(
            parser.read_compressed_uint(),
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn test_read_7bit_encoded_int_single_byte() {
        {
            let input = &[0x00]; // Represents 0
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 0);
            assert_eq!(parser.pos(), 1);
        }

        {
            let input = &[0x7F]; // Represents 127 (max for single byte)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 127);
            assert_eq!(parser.pos(), 1);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_two_bytes() {
        {
            let input = &[0x80, 0x01]; // Represents 128
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 128);
            assert_eq!(parser.pos(), 2);
        }

        {
            let input = &[0xFF, 0x7F]; // Represents 16383 (max for two bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 16383);
            assert_eq!(parser.pos(), 2);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_three_bytes() {
        {
            let input = &[0x80, 0x80, 0x01]; // Represents 16384
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 16384);
            assert_eq!(parser.pos(), 3);
        }

        {
            let input = &[0xFF, 0xFF, 0x7F]; // Represents 2097151 (max for three bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 2_097_151);
            assert_eq!(parser.pos(), 3);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_four_bytes() {
        {
            let input = &[0x80, 0x80, 0x80, 0x01]; // Represents 2097152
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 2097152);
            assert_eq!(parser.pos(), 4);
        }

        {
            let input = &[0xFF, 0xFF, 0xFF, 0x7F]; // Represents 268435455 (max for four bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 268435455);
            assert_eq!(parser.pos(), 4);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_five_bytes() {
        {
            let input = &[0x80, 0x80, 0x80, 0x80, 0x01]; // Represents 268435456
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 268435456);
            assert_eq!(parser.pos(), 5);
        }

        {
            let input = &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]; // Represents max u32 (4294967295)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 4294967295);
            assert_eq!(parser.pos(), 5);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_truncated() {
        // Truncated data (should fail)
        let input = &[0x80];
        let mut parser = Parser::new(input);
        assert!(parser.read_7bit_encoded_int().is_err());
    }

    #[test]
    fn test_read_7bit_encoded_int_overflow() {
        // Too many continuation bits (would overflow u32)
        let input = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut parser = Parser::new(input);
        assert!(parser.read_7bit_encoded_int().is_err());
    }

    #[test]
    fn test_read_prefixed_string_utf8_ref() {
        // Test basic string
        let data = [5, b'H', b'e', b'l', b'l', b'o'];
        let mut parser = Parser::new(&data);
        let result = parser.read_prefixed_string_utf8_ref().unwrap();
        assert_eq!(result, "Hello");

        // Verify zero-copy: the string should point into the original data
        let data_ptr = data.as_ptr() as usize;
        let result_ptr = result.as_ptr() as usize;
        assert!(
            result_ptr >= data_ptr && result_ptr < data_ptr + data.len(),
            "String should be borrowed from source data (zero-copy)"
        );

        // Test empty string
        let data = [0];
        let mut parser = Parser::new(&data);
        let result = parser.read_prefixed_string_utf8_ref().unwrap();
        assert_eq!(result, "");

        // Test UTF-8 string
        let data = [9, 0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0xE2, 0x9C, 0x93]; // "中文✓"
        let mut parser = Parser::new(&data);
        let result = parser.read_prefixed_string_utf8_ref().unwrap();
        assert_eq!(result, "中文✓");

        // Test invalid UTF-8
        let data = [3, 0xFF, 0xFE, 0xFD];
        let mut parser = Parser::new(&data);
        assert!(parser.read_prefixed_string_utf8_ref().is_err());

        // Test out of bounds
        let data = [10, b'H', b'i']; // Claims 10 bytes but only has 2
        let mut parser = Parser::new(&data);
        assert!(matches!(
            parser.read_prefixed_string_utf8_ref(),
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn test_peek_le() {
        // Test peek_le with u8
        let data = [0x01, 0x02, 0x03, 0x04];
        let parser = Parser::new(&data);
        let peeked: u8 = parser.peek_le().unwrap();
        assert_eq!(peeked, 0x01);
        assert_eq!(parser.pos(), 0); // Position unchanged

        // Test peek_le with u16
        let peeked: u16 = parser.peek_le().unwrap();
        assert_eq!(peeked, 0x0201);
        assert_eq!(parser.pos(), 0); // Position unchanged

        // Test peek_le with u32
        let peeked: u32 = parser.peek_le().unwrap();
        assert_eq!(peeked, 0x04030201);
        assert_eq!(parser.pos(), 0); // Position unchanged

        // Test peek_le after advancing position
        let mut parser = Parser::new(&data);
        parser.advance_by(2).unwrap();
        let peeked: u16 = parser.peek_le().unwrap();
        assert_eq!(peeked, 0x0403);
        assert_eq!(parser.pos(), 2); // Position still at 2

        // Test peek_le out of bounds
        let data = [0x01];
        let parser = Parser::new(&data);
        let result: Result<u16> = parser.peek_le();
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        // Test peek_le at end of data
        let mut parser = Parser::new(&data);
        parser.advance().unwrap();
        let result: Result<u8> = parser.peek_le();
        assert!(matches!(
            result,
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));
    }

    #[test]
    fn test_transactional() {
        // Test transactional commits on success
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut parser = Parser::new(&data);

        let result: u16 = parser.transactional(|p| p.read_le()).unwrap();
        assert_eq!(result, 0x0201);
        assert_eq!(parser.pos(), 2); // Position advanced on success

        // Test transactional with multiple reads - commits all changes
        let mut parser = Parser::new(&data);
        let sum: u16 = parser
            .transactional(|p| {
                let a: u8 = p.read_le()?;
                let b: u8 = p.read_le()?;
                Ok(u16::from(a) + u16::from(b))
            })
            .unwrap();
        assert_eq!(sum, 3); // 0x01 + 0x02
        assert_eq!(parser.pos(), 2); // Position advanced to 2

        // Test transactional restores position on error
        let mut parser = Parser::new(&data);
        let result: Result<u32> = parser.transactional(|p| {
            p.read_le::<u16>()?; // This succeeds
            p.read_le::<u32>() // This fails - not enough data
        });
        assert!(result.is_err());
        assert_eq!(parser.pos(), 0); // Position restored on error

        // Test transactional from non-zero position
        let mut parser = Parser::new(&data);
        parser.advance_by(2).unwrap();
        let result: u16 = parser.transactional(|p| p.read_le()).unwrap();
        assert_eq!(result, 0x0403);
        assert_eq!(parser.pos(), 4); // Position advanced from 2 to 4

        // Test nested transactional - inner failure rolls back inner only
        let mut parser = Parser::new(&data);
        let result = parser
            .transactional(|p| {
                let outer: u8 = p.read_le()?;
                // Inner transactional that fails - should restore to pos 1
                let inner_result: Result<u32> = p.transactional(|p2| p2.read_le());
                assert!(inner_result.is_err());
                assert_eq!(p.pos(), 1); // Inner transactional restored to 1
                Ok(outer)
            })
            .unwrap();
        assert_eq!(result, 0x01);
        assert_eq!(parser.pos(), 1); // Outer transactional committed
    }
}

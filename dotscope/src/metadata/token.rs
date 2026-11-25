//! Metadata token implementation for .NET assembly analysis.
//!
//! This module provides the [`crate::metadata::token::Token`] type for representing metadata table references
//! within .NET assemblies. Tokens are fundamental to the .NET metadata system, providing
//! a standardized way to reference entries across different metadata tables according to
//! the ECMA-335 specification.
//!
//! # Architecture
//!
//! The token system implements the ECMA-335 metadata addressing scheme, enabling precise
//! and efficient referencing of metadata elements throughout .NET assemblies.
//!
//! ## Token Structure
//!
//! .NET metadata tokens are 32-bit values with a specific bit layout:
//!
//! ```text
//! ┌─────────────┬───────────────────────────────────┐
//! │ Table (8b)  │        Row Index (24b)            │
//! ├─────────────┼───────────────────────────────────┤
//! │   31-24     │            23-0                   │
//! └─────────────┴───────────────────────────────────┘
//! ```
//!
//! - **Table Identifier** (bits 24-31): Identifies the metadata table type
//! - **Row Index** (bits 0-23): 1-based index within the specified table
//!
//! # Key Components
//!
//! - [`crate::metadata::token::Token`] - Core token implementation with table and row addressing
//! - **Table Identification** - 8-bit table IDs according to ECMA-335 specification
//! - **Row Addressing** - 24-bit 1-based indexing supporting up to 16M entries per table
//! - **Null References** - Special token value (0) indicating absent references
//!
//! # Usage Examples
//!
//! ## Creating and Inspecting Tokens
//!
//! ```rust,no_run
//! use dotscope::metadata::token::Token;
//!
//! // Create a MethodDef token (table 0x06, row 1)
//! let method_token = Token::new(0x06000001);
//!
//! println!("Token: {}", method_token);        // Displays: 0x06000001
//! println!("Table: 0x{:02x}", method_token.table()); // Table: 0x06
//! println!("Row: {}", method_token.row());           // Row: 1
//!
//! // Check for null references
//! let null_token = Token::new(0);
//! assert!(null_token.is_null());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Different Token Types
//!
//! ```rust,no_run
//! use dotscope::metadata::token::Token;
//!
//! // Common .NET metadata token types
//! let typedef_token = Token::new(0x02000001);     // TypeDef
//! let typeref_token = Token::new(0x01000001);     // TypeRef  
//! let methoddef_token = Token::new(0x06000001);   // MethodDef
//! let memberref_token = Token::new(0x0A000001);   // MemberRef
//! let fielddef_token = Token::new(0x04000001);    // FieldDef
//!
//! // Convert between Token and u32
//! let raw_value: u32 = methoddef_token.into();
//! let token_from_raw = Token::from(raw_value);
//! assert_eq!(methoddef_token, token_from_raw);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Common Token Types
//!
//! | Table ID | Name           | Description                    | Example     |
//! |----------|----------------|--------------------------------|-------------|
//! | 0x01     | TypeRef        | External type references       | 0x01000001  |
//! | 0x02     | TypeDef        | Type definitions               | 0x02000001  |
//! | 0x04     | FieldDef       | Field definitions              | 0x04000001  |
//! | 0x06     | MethodDef      | Method definitions             | 0x06000001  |
//! | 0x08     | Param          | Parameter definitions          | 0x08000001  |
//! | 0x09     | InterfaceImpl  | Interface implementations      | 0x09000001  |
//! | 0x0A     | MemberRef      | External member references     | 0x0A000001  |
//! | 0x1B     | TypeSpec       | Type specifications            | 0x1B000001  |
//! | 0x2B     | MethodSpec     | Generic method instantiations  | 0x2B000001  |
//!
//!
//! # Usage in .NET Metadata
//!
//! Tokens serve multiple purposes in the .NET metadata system:
//!
//! - **IL Instructions**: Many IL opcodes reference metadata through tokens
//! - **Cross-References**: Tables reference entries in other tables via tokens
//! - **Debugging**: Debug information uses tokens to reference metadata
//! - **Reflection**: The .NET reflection API uses tokens internally
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with metadata token specification (§II.24.2.6)
//! - **Bit Layout**: Exact implementation of 8-bit table + 24-bit row format
//! - **Addressing**: Support for 1-based indexing with null reference semantics
//! - **Type Safety**: Strong typing prevents misuse of raw integer values
//!
//! # References
//!
//! - [ECMA-335 §II.22 - Metadata Logical Format](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [ECMA-335 §II.24.2.6 - Token](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)

use std::{
    fmt,
    hash::{Hash, Hasher},
};

use crate::metadata::tables::TableId;

/// A metadata token representing a reference to a specific entry within a metadata table.
///
/// Tokens are the fundamental addressing mechanism in .NET metadata, providing a uniform
/// way to reference entries across different metadata tables. Each token encodes both
/// the target table type and the specific row within that table.
///
/// ## Token Format
///
/// A token is a 32-bit value structured as follows:
///
/// ```text
/// ┌─────────────┬───────────────────────────────────┐
/// │ Table (8b)  │        Row Index (24b)            │
/// ├─────────────┼───────────────────────────────────┤
/// │   31-24     │            23-0                   │
/// └─────────────┴───────────────────────────────────┘
/// ```
///
/// ## Table Identification
///
/// The high byte identifies the metadata table type according to ECMA-335:
/// - 0x01: `TypeRef` - References to external types
/// - 0x02: `TypeDef` - Type definitions within this assembly
/// - 0x04: `FieldDef` - Field definitions
/// - 0x06: `MethodDef` - Method definitions
/// - 0x0A: `MemberRef` - References to external members
/// - And many others...
///
/// ## Row Addressing
///
/// The low 24 bits provide a 1-based index into the specified table, allowing
/// for up to 16,777,215 entries per table. A row index of 0 indicates a null reference.
///
/// ## Usage in IL and Metadata
///
/// Tokens appear in multiple contexts:
/// - **IL Instructions**: `call`, `newobj`, `ldtoken`, etc.
/// - **Table References**: Cross-references between metadata tables
/// - **Debug Information**: Linking debug data to metadata
/// - **Reflection API**: Internal representation of metadata references
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Token(pub u32);

impl Token {
    /// Creates a new token from a raw 32-bit value.
    ///
    /// This constructor accepts any 32-bit value and interprets it as a metadata token
    /// according to the ECMA-335 token format. No validation is performed on the input
    /// value, allowing for the creation of tokens that may not correspond to valid
    /// metadata entries.
    ///
    /// ## Arguments
    ///
    /// * `value` - The raw 32-bit token value with table ID in high byte and row index in low 24 bits
    ///
    /// ## Returns
    ///
    /// A new `Token` instance wrapping the provided value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Token(value)
    }

    /// Returns the raw 32-bit token value.
    ///
    /// This method provides access to the underlying token representation as used
    /// in IL instructions, metadata tables, and the .NET reflection API.
    ///
    /// ## Returns
    ///
    /// The complete 32-bit token value including both table identifier and row index.
    #[must_use]
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Extracts the table identifier from the token.
    ///
    /// Returns the high byte (bits 24-31) of the token, which identifies the metadata
    /// table type according to ECMA-335 specifications. This value corresponds to the
    /// table enumeration used throughout the metadata system.
    ///
    /// ## Returns
    ///
    /// The 8-bit table identifier (0x00-0xFF).
    ///
    /// ## Common Table IDs
    ///
    /// - 0x01: `TypeRef`
    /// - 0x02: `TypeDef`  
    /// - 0x04: `FieldDef`
    /// - 0x06: `MethodDef`
    /// - 0x0A: `MemberRef`
    /// - 0x1B: `TypeSpec`
    /// - 0x2B: `MethodSpec`
    #[must_use]
    pub fn table(&self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Extracts the row index from the token.
    ///
    /// Returns the low 24 bits (bits 0-23) of the token, which represent the 1-based
    /// row index within the specified metadata table. A value of 0 indicates a null
    /// reference that doesn't point to any table entry.
    ///
    /// ## Returns
    ///
    /// The 24-bit row index (0-16,777,215), where 0 represents null.
    ///
    /// ## Row Index Semantics
    ///
    /// - **1-based indexing**: Valid row indexes start from 1
    /// - **Null reference**: Row index 0 indicates no target entry
    /// - **Maximum capacity**: Up to 16,777,215 entries per table
    #[must_use]
    pub fn row(&self) -> u32 {
        self.0 & 0x00FF_FFFF
    }

    /// Returns `true` if this token represents a null reference.
    ///
    /// A null token has a value of 0, indicating that it doesn't reference any
    /// metadata table entry. Null tokens are used in metadata to represent
    /// optional or absent references.
    ///
    /// ## Returns
    ///
    /// `true` if the token value is 0, `false` otherwise.
    ///
    /// ## Usage in Metadata
    ///
    /// Null tokens commonly appear in:
    /// - Optional parent type references
    /// - Unused coded index entries
    /// - Default value placeholders
    /// - Conditional reference fields
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    /// Creates a new token with the specified table ID and row index.
    ///
    /// This constructor builds a token from its constituent parts, providing a
    /// more explicit alternative to creating tokens from raw values. The table ID
    /// and row index are combined according to the ECMA-335 token format.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The table identifier from the TableId enum
    /// * `row` - The 24-bit row index (0-16,777,215), must be 1-based for valid references
    ///
    /// ## Returns
    ///
    /// A new `Token` with the specified table and row.
    ///
    /// ## Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// // Create a MethodDef token (table MethodDef, row 1)
    /// let method_token = Token::from_parts(TableId::MethodDef, 1);
    /// assert_eq!(method_token.value(), 0x06000001);
    /// assert_eq!(method_token.table(), 0x06);
    /// assert_eq!(method_token.row(), 1);
    /// ```
    #[must_use]
    pub fn from_parts(table_id: TableId, row: u32) -> Self {
        Token(((table_id as u32) << 24) | (row & 0x00FF_FFFF))
    }

    /// Validates that this token belongs to the expected metadata table.
    ///
    /// This method checks if the token's table identifier matches the expected
    /// table ID, providing a type-safe way to validate token usage in contexts
    /// where only specific table types are valid.
    ///
    /// ## Arguments
    ///
    /// * `expected_table` - The expected table identifier from the TableId enum
    ///
    /// ## Returns
    ///
    /// `true` if the token's table matches the expected table, `false` otherwise.
    /// Null tokens (value 0) return `false` unless the expected table is Module (0).
    ///
    /// ## Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::token::Token;
    /// use dotscope::metadata::tables::TableId;
    ///
    /// let method_token = Token::new(0x06000001);
    /// assert!(method_token.is_table(TableId::MethodDef));  // MethodDef
    /// assert!(!method_token.is_table(TableId::TypeDef)); // Not TypeDef
    ///
    /// let null_token = Token::new(0);
    /// assert!(!null_token.is_table(TableId::MethodDef));   // Null token
    /// ```
    #[must_use]
    pub fn is_table(&self, expected_table: TableId) -> bool {
        self.table() == (expected_table as u8)
    }
}

impl From<u32> for Token {
    /// Converts a raw 32-bit value into a `Token`.
    ///
    /// This conversion allows for ergonomic token creation from integer literals
    /// and variables. The conversion is identical to `Token::new` but provides
    /// the standard Rust conversion trait interface.
    fn from(value: u32) -> Self {
        Token(value)
    }
}

impl From<Token> for u32 {
    /// Extracts the raw 32-bit value from a `Token`.
    ///
    /// This conversion provides access to the underlying token representation
    /// for use in contexts requiring raw token values, such as IL generation
    /// or metadata serialization.
    fn from(token: Token) -> Self {
        token.0
    }
}

impl fmt::Debug for Token {
    /// Formats the token for debugging output with detailed breakdown.
    ///
    /// The debug format includes the raw token value in hexadecimal, the table
    /// identifier, and the row index for comprehensive debugging information.
    ///
    /// ## Format
    ///
    /// `Token(0x{:08x}, table: 0x{:02x}, row: {})`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Token(0x{:08x}, table: 0x{:02x}, row: {})",
            self.0,
            self.table(),
            self.row()
        )
    }
}

impl fmt::Display for Token {
    /// Formats the token for user display as a hexadecimal value.
    ///
    /// The display format shows only the raw token value in standard hexadecimal
    /// notation, suitable for user-facing output and logging.
    ///
    /// ## Format
    ///
    /// `0x{:08x}` - 8-digit uppercase hexadecimal with 0x prefix
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl Hash for Token {
    /// Computes the hash value for this token.
    ///
    /// The hash is computed directly from the underlying 32-bit value, providing
    /// efficient and consistent hashing for use in hash-based collections like
    /// [`HashMap`](std::collections::HashMap) and [`HashSet`](std::collections::HashSet).
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_token_new() {
        let token = Token::new(0x06000001);
        assert_eq!(token.value(), 0x06000001);
    }

    #[test]
    fn test_token_value() {
        let token = Token(0x02000005);
        assert_eq!(token.value(), 0x02000005);
    }

    #[test]
    fn test_token_table() {
        let token = Token(0x06000001);
        assert_eq!(token.table(), 0x06);

        let token2 = Token(0x02000005);
        assert_eq!(token2.table(), 0x02);

        let token3 = Token(0x00000000);
        assert_eq!(token3.table(), 0x00);
    }

    #[test]
    fn test_token_row() {
        let token = Token(0x06000001);
        assert_eq!(token.row(), 1);

        let token2 = Token(0x02000005);
        assert_eq!(token2.row(), 5);

        let token3 = Token(0x06FFFFFF);
        assert_eq!(token3.row(), 0x00FFFFFF);
    }

    #[test]
    fn test_token_is_null() {
        let null_token = Token(0x00000000);
        assert!(null_token.is_null());

        let non_null_token = Token(0x06000001);
        assert!(!non_null_token.is_null());
    }

    #[test]
    fn test_token_from_conversion() {
        let value = 0x06000001u32;
        let token: Token = value.into();
        assert_eq!(token.value(), value);

        let back_to_u32: u32 = token.into();
        assert_eq!(back_to_u32, value);
    }

    #[test]
    fn test_token_display() {
        let token = Token(0x06000001);
        assert_eq!(format!("{token}"), "0x06000001");

        let token2 = Token(0x00000000);
        assert_eq!(format!("{token2}"), "0x00000000");
    }

    #[test]
    fn test_token_debug() {
        let token = Token(0x06000001);
        let debug_str = format!("{token:?}");
        assert!(debug_str.contains("Token(0x06000001"));
        assert!(debug_str.contains("table: 0x06"));
        assert!(debug_str.contains("row: 1"));
    }

    #[test]
    fn test_token_equality() {
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000001);
        let token3 = Token(0x06000002);

        assert_eq!(token1, token2);
        assert_ne!(token1, token3);
    }

    #[test]
    fn test_token_ordering() {
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000002);
        let token3 = Token(0x07000001);

        assert!(token1 < token2);
        assert!(token2 < token3);
        assert!(token1 < token3);
    }

    #[test]
    fn test_token_clone() {
        let token1 = Token(0x06000001);
        let token2 = token1;
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_token_copy() {
        let token1 = Token(0x06000001);
        let token2 = token1; // Copy semantics
        assert_eq!(token1, token2);
        // Both should still be usable
        assert_eq!(token1.value(), 0x06000001);
        assert_eq!(token2.value(), 0x06000001);
    }

    #[test]
    fn test_token_hash() {
        let mut map = HashMap::new();
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000002);

        map.insert(token1, "Method1");
        map.insert(token2, "Method2");

        assert_eq!(map.get(&token1), Some(&"Method1"));
        assert_eq!(map.get(&token2), Some(&"Method2"));
    }

    #[test]
    fn test_token_boundary_values() {
        // Test maximum values
        let max_token = Token(0xFFFFFFFF);
        assert_eq!(max_token.table(), 0xFF);
        assert_eq!(max_token.row(), 0x00FFFFFF);

        // Test minimum values
        let min_token = Token(0x00000000);
        assert_eq!(min_token.table(), 0x00);
        assert_eq!(min_token.row(), 0x00000000);

        // Test table boundary
        let table_boundary = Token(0x01000000);
        assert_eq!(table_boundary.table(), 0x01);
        assert_eq!(table_boundary.row(), 0x00000000);
    }

    #[test]
    fn test_common_token_types() {
        // Test common .NET metadata table tokens

        // TypeDef (0x02)
        let typedef_token = Token(0x02000001);
        assert_eq!(typedef_token.table(), 0x02);
        assert_eq!(typedef_token.row(), 1);

        // MethodDef (0x06)
        let methoddef_token = Token(0x06000001);
        assert_eq!(methoddef_token.table(), 0x06);
        assert_eq!(methoddef_token.row(), 1);

        // TypeRef (0x01)
        let typeref_token = Token(0x01000001);
        assert_eq!(typeref_token.table(), 0x01);
        assert_eq!(typeref_token.row(), 1);

        // MemberRef (0x0A)
        let memberref_token = Token(0x0A000001);
        assert_eq!(memberref_token.table(), 0x0A);
        assert_eq!(memberref_token.row(), 1);
    }

    #[test]
    fn test_token_from_parts() {
        // Test creating tokens from constituent parts
        let token = Token::from_parts(TableId::MethodDef, 1);
        assert_eq!(token.value(), 0x06000001);
        assert_eq!(token.table(), 0x06);
        assert_eq!(token.row(), 1);

        // Test with maximum row value (using a high table ID)
        let max_row_token = Token::from_parts(TableId::MethodSpec, 0x00FFFFFF);
        assert_eq!(max_row_token.value(), 0x2BFFFFFF);
        assert_eq!(max_row_token.table(), 0x2B);
        assert_eq!(max_row_token.row(), 0x00FFFFFF);

        // Test null token creation
        let null_token = Token::from_parts(TableId::Module, 0);
        assert_eq!(null_token.value(), 0x00000000);
        assert!(null_token.is_null());
    }

    #[test]
    fn test_token_is_table() {
        let method_token = Token::new(0x06000001);
        assert!(method_token.is_table(TableId::MethodDef)); // MethodDef
        assert!(!method_token.is_table(TableId::TypeDef)); // Not TypeDef
        assert!(!method_token.is_table(TableId::TypeRef)); // Not TypeRef

        let typedef_token = Token::new(0x02000001);
        assert!(typedef_token.is_table(TableId::TypeDef)); // TypeDef
        assert!(!typedef_token.is_table(TableId::MethodDef)); // Not MethodDef

        // Test null token
        let null_token = Token::new(0);
        assert!(!null_token.is_table(TableId::MethodDef)); // Null token
        assert!(null_token.is_table(TableId::Module)); // Null token matches table 0
    }

    // The `*Ptr` indirection tables are keyed by tokens built in their readers from literal
    // prefixes, while the consumers that look rows up build the same tokens independently.
    // These assert both halves agree, so a lookup key can never silently address the wrong
    // table - a mismatch makes every lookup miss, which reads as "the assembly has no methods"
    // rather than as an error.

    #[test]
    fn indirection_table_tokens_match_reader_prefixes() {
        // Left side: what `Token::from_parts` produces for each indirection table.
        // Right side: the literal prefix the corresponding reader keys its rows under.
        assert_eq!(
            Token::from_parts(TableId::FieldPtr, 1).value(),
            0x0300_0001,
            "FieldPtr"
        );
        assert_eq!(
            Token::from_parts(TableId::MethodPtr, 1).value(),
            0x0500_0001,
            "MethodPtr"
        );
        assert_eq!(
            Token::from_parts(TableId::EventPtr, 1).value(),
            0x1300_0001,
            "EventPtr"
        );
        assert_eq!(
            Token::from_parts(TableId::PropertyPtr, 1).value(),
            0x1600_0001,
            "PropertyPtr"
        );
    }

    #[test]
    fn indirection_targets_use_their_own_table_ids() {
        // The tables an indirection row resolves *to* are distinct from the indirection
        // tables themselves; transposing the two is the mistake this guards against.
        assert_eq!(Token::from_parts(TableId::Field, 1).value(), 0x0400_0001);
        assert_eq!(
            Token::from_parts(TableId::MethodDef, 1).value(),
            0x0600_0001
        );
        assert_eq!(Token::from_parts(TableId::Event, 1).value(), 0x1400_0001);
        assert_eq!(Token::from_parts(TableId::Property, 1).value(), 0x1700_0001);
    }

    #[test]
    fn indirection_and_target_tables_are_distinct() {
        for (ptr, target) in [
            (TableId::FieldPtr, TableId::Field),
            (TableId::MethodPtr, TableId::MethodDef),
            (TableId::EventPtr, TableId::Event),
            (TableId::PropertyPtr, TableId::Property),
        ] {
            assert_ne!(
                Token::from_parts(ptr, 1).value(),
                Token::from_parts(target, 1).value(),
                "{ptr:?} and {target:?} must not share a token space"
            );
        }
    }
}

//! Shared token validation utilities for the unified validation framework.
//!
//! This module provides common token validation operations that are used by both
//! raw and owned validators. It centralizes token bounds checking, type validation,
//! and cross-table reference analysis to avoid code duplication across validators.
//! The utilities ensure ECMA-335 compliance for token format, bounds, and reference integrity.
//!
//! # Architecture
//!
//! The token validation system provides comprehensive token integrity checking:
//! 1. **Bounds Validation** - Ensures tokens reference valid table rows within bounds
//! 2. **Type Validation** - Validates tokens belong to expected table types
//! 3. **Reference Analysis** - Analyzes cross-table token references and dependencies
//! 4. **Null Token Handling** - Validates nullable token references per ECMA-335 rules
//! 5. **Batch Validation** - Efficiently validates token collections and arrays
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::shared::tokens::TokenValidator`] - Main token validation orchestrator
//! - [`crate::metadata::validation::shared::tokens::TokenValidationResult`] - Aggregates multiple validation results
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{TokenValidator, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::token::Token;
//! use dotscope::metadata::tables::TableId;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//! let validator = TokenValidator::new(&scanner);
//!
//! // Validate token bounds
//! let token = Token::new(0x02000001);
//! validator.validate_token_bounds(token)?;
//!
//! // Validate token table type
//! validator.validate_token_table_type(token, TableId::TypeDef)?;
//!
//! // Validate typed token (multiple allowed tables)
//! let allowed_tables = &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec];
//! validator.validate_typed_token(token, allowed_tables)?;
//!
//! // Check token existence
//! if validator.token_exists(token) {
//!     println!("Token exists in metadata");
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`crate::metadata::validation::TokenValidator`] is stateless and implements [`Send`] + [`Sync`],
//! making it safe for concurrent use across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::scanner`] - Provides token existence and reference data
//! - Raw validators - Used by raw validators for token validation
//! - Owned validators - Used by owned validators for token consistency
//! - [`crate::metadata::token`] - Validates token format and encoding

use crate::{
    metadata::{tables::TableId, token::Token, validation::scanner::ReferenceScanner},
    Error, Result,
};

/// Shared token validation utilities.
///
/// This struct provides reusable token validation operations that can be used
/// by both raw and owned validators. It encapsulates common validation logic
/// to ensure consistency across the validation framework and operates on
/// pre-analyzed metadata from [`crate::metadata::validation::scanner::ReferenceScanner`] for efficient validation.
///
/// # Thread Safety
///
/// This type is stateless and implements [`Send`] + [`Sync`], making it safe for concurrent use.
pub struct TokenValidator<'a> {
    /// Reference scanner for efficient token validation
    scanner: &'a ReferenceScanner,
}

impl<'a> TokenValidator<'a> {
    /// Creates a new token validator using the provided reference scanner.
    ///
    /// # Arguments
    ///
    /// * `scanner` - The [`crate::metadata::validation::scanner::ReferenceScanner`] containing pre-analyzed metadata
    ///
    /// # Returns
    ///
    /// A new [`TokenValidator`] instance ready for validation operations.
    #[must_use]
    pub fn new(scanner: &'a ReferenceScanner) -> Self {
        Self { scanner }
    }

    /// Validates that a token exists and is within bounds.
    ///
    /// This method performs comprehensive token validation including:
    /// - Bounds checking against table row counts
    /// - RID validation (non-zero and within range)
    /// - Token type verification
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token is valid, or an error describing the validation failure.
    ///
    /// # Errors
    ///
    /// - `InvalidRid`: If the RID is 0 or exceeds the table row count
    /// - `ValidationInvalidTokenType`: If the token type is not recognized
    /// - `ValidationTableNotFound`: If the referenced table doesn't exist
    pub fn validate_token_bounds(&self, token: Token) -> Result<()> {
        self.scanner.validate_token_bounds(token)
    }

    /// Validates that a token exists in the metadata.
    ///
    /// This is a faster check than full bounds validation, useful when you only
    /// need to verify token existence without detailed validation.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check for existence
    ///
    /// # Returns
    ///
    /// Returns `true` if the token exists, `false` otherwise.
    #[must_use]
    pub fn token_exists(&self, token: Token) -> bool {
        self.scanner.token_exists(token)
    }

    /// Validates a collection of tokens for existence and bounds.
    ///
    /// This method efficiently validates multiple tokens in batch, providing
    /// detailed error information for any invalid tokens found.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of tokens to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all tokens are valid, or the first validation error encountered.
    ///
    /// # Errors
    ///
    /// Returns an error if any token in the collection is invalid or out of bounds.
    pub fn validate_token_collection<I>(&self, tokens: I) -> Result<()>
    where
        I: IntoIterator<Item = Token>,
    {
        for token in tokens {
            self.validate_token_bounds(token)?;
        }
        Ok(())
    }

    /// Validates that a token belongs to a specific table type.
    ///
    /// This method checks that the token's table type matches the expected table,
    /// useful for validating typed references between metadata tables.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    /// * `expected_table` - The expected table type
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token belongs to the expected table, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `ValidationInvalidTokenType`: If the token doesn't belong to the expected table
    pub fn validate_token_table_type(&self, token: Token, expected_table: TableId) -> Result<()> {
        let token_table_value = token.table();
        let expected_table_value = expected_table.token_type();

        if token_table_value != expected_table_value {
            return Err(Error::InvalidToken {
                token,
                message: format!(
                    "Token belongs to table {token_table_value:#x}, expected table {expected_table_value:#x}"
                ),
            });
        }

        // Also validate bounds for the specific table
        self.validate_token_bounds(token)
    }

    /// Checks if a token can be safely deleted without breaking references.
    ///
    /// This method analyzes the reference graph to determine if deleting a token
    /// would leave dangling references from other metadata entries.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check for safe deletion
    ///
    /// # Returns
    ///
    /// Returns `true` if the token can be safely deleted, `false` if it would break references.
    #[must_use]
    pub fn can_delete_token(&self, token: Token) -> bool {
        self.scanner.can_delete_token(token)
    }

    /// Returns a reference to the set of tokens that reference the given token.
    ///
    /// This method returns a reference to the internal set without cloning.
    /// Returns `None` if no tokens reference the given token.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references to
    ///
    /// # Returns
    ///
    /// Returns an optional reference to the internal set of referencing tokens.
    #[must_use]
    pub fn references_to(&self, token: Token) -> Option<&rustc_hash::FxHashSet<Token>> {
        self.scanner.references_to(token)
    }

    /// Returns a reference to the set of tokens that the given token references.
    ///
    /// This method returns a reference to the internal set without cloning.
    /// Returns `None` if the token doesn't reference any other tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to find references from
    ///
    /// # Returns
    ///
    /// Returns an optional reference to the internal set of referenced tokens.
    #[must_use]
    pub fn references_from(&self, token: Token) -> Option<&rustc_hash::FxHashSet<Token>> {
        self.scanner.references_from(token)
    }

    /// Checks if any tokens reference the given token.
    ///
    /// More efficient than checking if `references_to()` is empty.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if at least one token references the given token.
    #[must_use]
    pub fn has_references_to(&self, token: Token) -> bool {
        self.scanner.has_references_to(token)
    }

    /// Checks if the given token references any other tokens.
    ///
    /// More efficient than checking if `references_from()` is empty.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the token references at least one other token.
    #[must_use]
    pub fn has_references_from(&self, token: Token) -> bool {
        self.scanner.has_references_from(token)
    }

    /// Validates a null token reference.
    ///
    /// In ECMA-335, certain token references can be null (0) to indicate
    /// absence. This method validates whether a null token is acceptable
    /// in a given context.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check (should be 0 for null)
    /// * `nullable` - Whether null tokens are allowed in this context
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the null token is valid in this context, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `InvalidRid`: If a null token is not allowed in this context
    pub fn validate_null_token(&self, token: Token, nullable: bool) -> Result<()> {
        if token.value() == 0 {
            if nullable {
                Ok(())
            } else {
                Err(Error::InvalidRid {
                    table: TableId::Module, // Default table for error reporting
                    rid: 0,
                })
            }
        } else {
            // Non-null token, validate normally
            self.validate_token_bounds(token)
        }
    }

    /// Validates a typed token reference.
    ///
    /// This method validates a token that can belong to one of several table types,
    /// such as TypeDefOrRef tokens that can point to TypeDef, TypeRef, or TypeSpec.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    /// * `allowed_tables` - Slice of table types that are acceptable
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token belongs to one of the allowed tables, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `ValidationInvalidTokenType`: If the token doesn't belong to any allowed table
    pub fn validate_typed_token(&self, token: Token, allowed_tables: &[TableId]) -> Result<()> {
        let token_table_value = token.table();

        for &allowed_table in allowed_tables {
            if token_table_value == allowed_table.token_type() {
                return self.validate_token_bounds(token);
            }
        }

        // Token doesn't match any allowed table type
        Err(Error::InvalidToken {
            token,
            message: format!("Table type {token_table_value:#x} not in allowed tables"),
        })
    }

    /// Gets the row count for a specific table.
    ///
    /// This method returns the number of rows in the specified metadata table,
    /// useful for validation and bounds checking operations.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to query
    ///
    /// # Returns
    ///
    /// The number of rows in the table, or 0 if the table doesn't exist.
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        self.scanner.table_row_count(table_id)
    }

    /// Validates a token value directly from its u32 representation.
    ///
    /// This method provides a convenient way to validate tokens when working
    /// with raw u32 values, which is common in both raw and owned validators.
    ///
    /// # Arguments
    ///
    /// * `token_value` - The raw u32 token value to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token is valid, or an error describing the validation failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the token value is invalid or out of bounds for its table.
    pub fn validate_token_value(&self, token_value: u32) -> Result<()> {
        let token = Token::new(token_value);
        self.validate_token_bounds(token)
    }

    /// Validates a specific table row by table ID and RID.
    ///
    /// This method validates that a specific row exists in the given table.
    /// It's particularly useful for validators that work with table/row pairs.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the row
    /// * `rid` - The row ID to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the row exists, or an error if it doesn't.
    ///
    /// # Errors
    ///
    /// Returns an error if the RID is invalid (zero) or out of bounds for the table.
    pub fn validate_table_row(&self, table_id: TableId, rid: u32) -> Result<()> {
        if rid == 0 {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        let max_rid = self.scanner.table_row_count(table_id);
        if rid > max_rid {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        Ok(())
    }

    /// Validates multiple token values in a batch operation.
    ///
    /// This method efficiently validates multiple tokens and can be used
    /// to validate token arrays or collections.
    ///
    /// # Arguments
    ///
    /// * `token_values` - Iterator of u32 token values to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all tokens are valid, or the first error encountered.
    ///
    /// # Errors
    ///
    /// Returns an error if any token value in the collection is invalid or out of bounds.
    pub fn validate_token_values<I>(&self, token_values: I) -> Result<()>
    where
        I: IntoIterator<Item = u32>,
    {
        for token_value in token_values {
            self.validate_token_value(token_value)?;
        }
        Ok(())
    }
}

/// Token validation result aggregator.
///
/// This struct helps collect and report multiple token validation errors
/// in a single validation pass, useful for comprehensive error reporting.
#[derive(Debug, Default)]
pub struct TokenValidationResult {
    /// List of validation errors encountered
    errors: Vec<Error>,
}

impl TokenValidationResult {
    /// Creates a new empty validation result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a token validation result to the aggregator.
    ///
    /// If the result is an error, it's added to the error collection.
    /// Success results are ignored.
    ///
    /// # Arguments
    ///
    /// * `result` - The validation result to add
    pub fn add_result(&mut self, result: Result<()>) {
        if let Err(error) = result {
            self.errors.push(error);
        }
    }

    /// Checks if any validation errors were encountered.
    ///
    /// # Returns
    ///
    /// Returns `true` if there are validation errors, `false` otherwise.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Gets the number of validation errors.
    ///
    /// # Returns
    ///
    /// The number of validation errors encountered.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Converts the result into a standard Result type.
    ///
    /// If there are no errors, returns `Ok(())`. If there are errors,
    /// returns the first error encountered.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passed, or the first error if validation failed.
    pub fn into_result(self) -> Result<()> {
        if let Some(first_error) = self.errors.into_iter().next() {
            Err(first_error)
        } else {
            Ok(())
        }
    }

    /// Gets all validation errors.
    ///
    /// # Returns
    ///
    /// A slice containing all validation errors encountered.
    pub fn errors(&self) -> &[Error] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{metadata::cilassemblyview::CilAssemblyView, testkit::fixture};

    #[test]
    fn test_token_validator_creation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = TokenValidator::new(&scanner);

        // Test basic functionality - just ensure method works
        let _count = validator.table_row_count(TableId::TypeDef);
    }

    #[test]
    fn test_token_bounds_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = TokenValidator::new(&scanner);

        // Test invalid RID (0)
        let invalid_token = Token::new(0x02000000); // TypeDef with RID 0
        assert!(validator.validate_token_bounds(invalid_token).is_err());

        // Test valid token bounds (if TypeDef table has rows)
        if validator.table_row_count(TableId::TypeDef) > 0 {
            let valid_token = Token::new(0x02000001); // TypeDef with RID 1
            assert!(validator.validate_token_bounds(valid_token).is_ok());
        }
    }

    #[test]
    fn test_token_table_type_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = TokenValidator::new(&scanner);

        if validator.table_row_count(TableId::TypeDef) > 0 {
            let typedef_token = Token::new(0x02000001); // TypeDef with RID 1

            // Should pass for TypeDef table
            assert!(validator
                .validate_token_table_type(typedef_token, TableId::TypeDef)
                .is_ok());

            // Should fail for MethodDef table
            assert!(validator
                .validate_token_table_type(typedef_token, TableId::MethodDef)
                .is_err());
        }
    }

    #[test]
    fn test_token_validation_result() {
        let result = TokenValidationResult::new();

        // Initially no errors
        assert!(!result.has_errors());
        assert_eq!(result.error_count(), 0);
        assert!(result.into_result().is_ok());

        // Test with errors
        let mut result = TokenValidationResult::new();
        result.add_result(Ok(()));
        result.add_result(Err(Error::InvalidRid {
            table: TableId::TypeDef,
            rid: 0,
        }));

        assert!(result.has_errors());
        assert_eq!(result.error_count(), 1);
        assert!(result.into_result().is_err());
    }

    #[test]
    fn test_null_token_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = TokenValidator::new(&scanner);

        let null_token = Token::new(0);

        // Should pass when nullable is true
        assert!(validator.validate_null_token(null_token, true).is_ok());

        // Should fail when nullable is false
        assert!(validator.validate_null_token(null_token, false).is_err());
    }

    #[test]
    fn test_typed_token_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = TokenValidator::new(&scanner);

        if validator.table_row_count(TableId::TypeDef) > 0 {
            let typedef_token = Token::new(0x02000001); // TypeDef with RID 1
            let allowed_tables = &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec];

            // Should pass since TypeDef is in allowed tables
            assert!(validator
                .validate_typed_token(typedef_token, allowed_tables)
                .is_ok());

            // Should fail if TypeDef is not in allowed tables
            let not_allowed = &[TableId::MethodDef, TableId::Field];
            assert!(validator
                .validate_typed_token(typedef_token, not_allowed)
                .is_err());
        }
    }
}

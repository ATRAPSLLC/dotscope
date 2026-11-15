//! Builder for constructing `EncMap` table entries
//!
//! This module provides the [`crate::metadata::tables::encmap::EncMapBuilder`] which enables fluent construction
//! of `EncMap` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let encmap_token = EncMapBuilder::new()
//!     .original_token(0x06000001)    // MethodDef token before editing
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{EncMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `EncMap` table entries
///
/// Provides a fluent interface for building `EncMap` metadata table entries.
/// These entries provide token mapping during Edit-and-Continue operations,
/// correlating original tokens with their updated counterparts.
///
/// # Required Fields
/// - `original_token`: Original metadata token before editing
///
/// # Edit-and-Continue Mapping
///
/// The EncMap table is used by .NET's Edit-and-Continue debugging feature to
/// track token mappings. When developers modify code during debugging, new
/// metadata is generated with updated token values. The EncMap table preserves
/// the original tokens, using table position for implicit mapping correlation.
///
/// # Examples
///
/// ```
/// use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// // Map original method token
/// let method_map = EncMapBuilder::new()
///     .original_token(0x06000042)  // Original MethodDef token
///     .build(&mut assembly)?;
///
/// // Map original type token
/// let type_map = EncMapBuilder::new()
///     .original_token(0x02000010)  // Original TypeDef token
///     .build(&mut assembly)?;
///
/// // Map original field token
/// let field_map = EncMapBuilder::new()
///     .original_token(0x04000025)  // Original Field token
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct EncMapBuilder {
    /// Original metadata token before editing
    original_token: Option<u32>,
}

impl EncMapBuilder {
    /// Creates a new `EncMapBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required original token before calling build().
    ///
    /// # Returns
    /// A new `EncMapBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            original_token: None,
        }
    }

    /// Sets the original metadata token
    ///
    /// Specifies the metadata token that existed before the Edit-and-Continue
    /// operation occurred. This token is preserved in the EncMap table to
    /// enable correlation with updated tokens.
    ///
    /// # Parameters
    /// - `original_token`: The original metadata token value
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Using raw token value
    /// let builder = EncMapBuilder::new()
    ///     .original_token(0x06000001);  // MethodDef RID 1
    /// ```
    #[must_use]
    pub fn original_token(mut self, original_token: u32) -> Self {
        self.original_token = Some(original_token);
        self
    }

    /// Sets the original metadata token value
    ///
    /// Alternative method name for setting the original token value.
    /// This is an alias for `original_token()`.
    ///
    /// # Parameters
    /// - `original_token`: The original token value
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncMapBuilder::new()
    ///     .original_token_value(0x04000010);
    /// ```
    #[must_use]
    pub fn original_token_value(mut self, original_token: u32) -> Self {
        self.original_token = Some(original_token);
        self
    }

    /// Builds and adds the `EncMap` entry to the metadata
    ///
    /// Validates all required fields, creates the `EncMap` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this token mapping entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created token mapping entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (original_token)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = EncMapBuilder::new()
    ///     .original_token(0x06000001)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let original_token = self.original_token.ok_or_else(|| {
            Error::ModificationInvalid("Original token is required for EncMap".to_string())
        })?;

        let enc_map = EncMapRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            original_token: Token::new(original_token),
        };

        assembly.table_row_add(TableId::EncMap, TableDataOwned::EncMap(enc_map))
    }
}

impl Default for EncMapBuilder {
    /// Creates a default `EncMapBuilder`
    ///
    /// Equivalent to calling [`EncMapBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_encmap_builder_new() {
        let builder = EncMapBuilder::new();

        assert!(builder.original_token.is_none());
    }

    #[test]
    fn test_encmap_builder_default() {
        let builder = EncMapBuilder::default();

        assert!(builder.original_token.is_none());
    }

    #[test]
    fn test_encmap_builder_method_token() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncMapBuilder::new()
            .original_token(0x06000001) // MethodDef token
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_type_token() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncMapBuilder::new()
            .original_token(0x02000010) // TypeDef token
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_field_token() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncMapBuilder::new()
            .original_token(0x04000025) // Field token
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_token_value() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncMapBuilder::new()
            .original_token_value(0x08000005)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_missing_original_token() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = EncMapBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Original token is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_encmap_builder_clone() {
        let builder = EncMapBuilder::new().original_token(0x06000001);

        let cloned = builder.clone();
        assert_eq!(builder.original_token, cloned.original_token);
    }

    #[test]
    fn test_encmap_builder_debug() {
        let builder = EncMapBuilder::new().original_token(0x02000005);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EncMapBuilder"));
        assert!(debug_str.contains("original_token"));
    }

    #[test]
    fn test_encmap_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = EncMapBuilder::new()
            .original_token(0x17000001) // Property token
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first mapping entry
        let ref1 = EncMapBuilder::new()
            .original_token(0x06000001) // Method
            .build(&mut assembly)
            .expect("Should build first mapping entry");

        // Build second mapping entry
        let ref2 = EncMapBuilder::new()
            .original_token(0x02000001) // Type
            .build(&mut assembly)
            .expect("Should build second mapping entry");

        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        Ok(())
    }

    #[test]
    fn test_encmap_builder_various_tokens() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with different token types
        let tokens = [
            0x02000001, // TypeDef
            0x06000001, // MethodDef
            0x04000001, // Field
            0x08000001, // Param
            0x14000001, // Event
            0x17000001, // Property
        ];

        for &token_val in tokens.iter() {
            let ref_ = EncMapBuilder::new()
                .original_token(token_val)
                .build(&mut assembly)
                .expect("Should build successfully");

            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        }

        Ok(())
    }

    #[test]
    fn test_encmap_builder_large_token_values() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with large token values
        let large_tokens = [
            0x06FFFFFF, // Large MethodDef
            0x02FFFFFF, // Large TypeDef
            0x04FFFFFF, // Large Field
        ];

        for &token_val in large_tokens.iter() {
            let ref_ = EncMapBuilder::new()
                .original_token(token_val)
                .build(&mut assembly)
                .expect("Should handle large token values");

            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncMap));
        }

        Ok(())
    }
}

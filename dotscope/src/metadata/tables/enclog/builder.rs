//! Builder for constructing `EncLog` table entries
//!
//! This module provides the [`crate::metadata::tables::enclog::EncLogBuilder`] which enables fluent construction
//! of `EncLog` metadata table entries. The builder follows the established
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
//! let enc_token = EncLogBuilder::new()
//!     .token_value(0x06000001)       // MethodDef token
//!     .func_code(1)                  // Update operation
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{EncLogRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `EncLog` table entries
///
/// Provides a fluent interface for building `EncLog` metadata table entries.
/// These entries track Edit-and-Continue operations performed during debugging
/// sessions, recording which metadata elements were created, updated, or deleted.
///
/// # Required Fields
/// - `token_value`: Metadata token identifying the affected element
/// - `func_code`: Operation code (0=create, 1=update, 2=delete)
///
/// # Edit-and-Continue Context
///
/// The EncLog table is used by .NET's Edit-and-Continue debugging feature to track
/// all metadata changes made during debugging sessions. When developers modify code
/// while debugging, the compiler generates new metadata and records the changes.
///
/// # Examples
///
/// ```
/// use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// // Record creation of a new method
/// let create_method = EncLogBuilder::new()
///     .token_value(0x06000042)  // MethodDef token
///     .func_code(0)             // Create operation
///     .build(&mut assembly)?;
///
/// // Record update to an existing type
/// let update_type = EncLogBuilder::new()
///     .token_value(0x02000010)  // TypeDef token
///     .func_code(1)             // Update operation
///     .build(&mut assembly)?;
///
/// // Record deletion of a field
/// let delete_field = EncLogBuilder::new()
///     .token_value(0x04000025)  // Field token
///     .func_code(2)             // Delete operation
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct EncLogBuilder {
    /// Metadata token identifying the affected element
    token_value: Option<u32>,
    /// Operation code (0=create, 1=update, 2=delete)
    func_code: Option<u32>,
}

impl EncLogBuilder {
    /// Creates a new `EncLogBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide both required fields before calling build().
    ///
    /// # Returns
    /// A new `EncLogBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncLogBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            token_value: None,
            func_code: None,
        }
    }

    /// Sets the metadata token value
    ///
    /// Specifies the metadata token that identifies which metadata element
    /// was affected by this Edit-and-Continue operation. The token format
    /// follows the standard structure: table_id (upper byte) + row_id (lower 3 bytes).
    ///
    /// # Parameters
    /// - `token_value`: The metadata token identifying the affected element
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Method token
    /// let builder = EncLogBuilder::new()
    ///     .token_value(0x06000001);  // MethodDef RID 1
    ///
    /// // Type token
    /// let builder = EncLogBuilder::new()
    ///     .token_value(0x02000005);  // TypeDef RID 5
    ///
    /// // Field token
    /// let builder = EncLogBuilder::new()
    ///     .token_value(0x04000010);  // Field RID 16
    /// ```
    #[must_use]
    pub fn token_value(mut self, token_value: u32) -> Self {
        self.token_value = Some(token_value);
        self
    }

    /// Sets the function code
    ///
    /// Specifies the type of Edit-and-Continue operation that was performed
    /// on the metadata element identified by the token.
    ///
    /// # Parameters
    /// - `func_code`: The operation code
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Operation Codes
    /// - `0`: Create - New metadata item added during edit session
    /// - `1`: Update - Existing metadata item modified during edit session
    /// - `2`: Delete - Metadata item marked for deletion during edit session
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Create operation
    /// let builder = EncLogBuilder::new()
    ///     .func_code(0);
    ///
    /// // Update operation
    /// let builder = EncLogBuilder::new()
    ///     .func_code(1);
    ///
    /// // Delete operation
    /// let builder = EncLogBuilder::new()
    ///     .func_code(2);
    /// ```
    #[must_use]
    pub fn func_code(mut self, func_code: u32) -> Self {
        self.func_code = Some(func_code);
        self
    }

    /// Convenience method for create operations
    ///
    /// Sets the function code to 0 (create) for new metadata items.
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncLogBuilder::new()
    ///     .create();  // Equivalent to .func_code(0)
    /// ```
    #[must_use]
    pub fn create(mut self) -> Self {
        self.func_code = Some(0);
        self
    }

    /// Convenience method for update operations
    ///
    /// Sets the function code to 1 (update) for modified metadata items.
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncLogBuilder::new()
    ///     .update();  // Equivalent to .func_code(1)
    /// ```
    #[must_use]
    pub fn update(mut self) -> Self {
        self.func_code = Some(1);
        self
    }

    /// Convenience method for delete operations
    ///
    /// Sets the function code to 2 (delete) for removed metadata items.
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncLogBuilder::new()
    ///     .delete();  // Equivalent to .func_code(2)
    /// ```
    #[must_use]
    pub fn delete(mut self) -> Self {
        self.func_code = Some(2);
        self
    }

    /// Builds and adds the `EncLog` entry to the metadata
    ///
    /// Validates all required fields, creates the `EncLog` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this edit log entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created edit log entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (token_value or func_code)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = EncLogBuilder::new()
    ///     .token_value(0x06000001)
    ///     .func_code(1)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let token_value = self.token_value.ok_or_else(|| {
            Error::ModificationInvalid("Token value is required for EncLog".to_string())
        })?;

        let func_code = self.func_code.ok_or_else(|| {
            Error::ModificationInvalid("Function code is required for EncLog".to_string())
        })?;

        let enc_log = EncLogRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            token_value,
            func_code,
        };

        assembly.table_row_add(TableId::EncLog, TableDataOwned::EncLog(enc_log))
    }
}

impl Default for EncLogBuilder {
    /// Creates a default `EncLogBuilder`
    ///
    /// Equivalent to calling [`EncLogBuilder::new()`].
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
    fn test_enclog_builder_new() {
        let builder = EncLogBuilder::new();

        assert!(builder.token_value.is_none());
        assert!(builder.func_code.is_none());
    }

    #[test]
    fn test_enclog_builder_default() {
        let builder = EncLogBuilder::default();

        assert!(builder.token_value.is_none());
        assert!(builder.func_code.is_none());
    }

    #[test]
    fn test_enclog_builder_create_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncLogBuilder::new()
            .token_value(0x06000001) // MethodDef token
            .func_code(0) // Create
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_update_type() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncLogBuilder::new()
            .token_value(0x02000010) // TypeDef token
            .func_code(1) // Update
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_delete_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EncLogBuilder::new()
            .token_value(0x04000025) // Field token
            .func_code(2) // Delete
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_convenience_methods() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test create convenience method
        let ref1 = EncLogBuilder::new()
            .token_value(0x06000001)
            .create()
            .build(&mut assembly)
            .expect("Should build create operation");

        // Test update convenience method
        let ref2 = EncLogBuilder::new()
            .token_value(0x02000001)
            .update()
            .build(&mut assembly)
            .expect("Should build update operation");

        // Test delete convenience method
        let ref3 = EncLogBuilder::new()
            .token_value(0x04000001)
            .delete()
            .build(&mut assembly)
            .expect("Should build delete operation");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_missing_token_value() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = EncLogBuilder::new().func_code(0).build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Token value is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_enclog_builder_missing_func_code() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = EncLogBuilder::new()
            .token_value(0x06000001)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Function code is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_enclog_builder_clone() {
        let builder = EncLogBuilder::new().token_value(0x06000001).func_code(1);

        let cloned = builder.clone();
        assert_eq!(builder.token_value, cloned.token_value);
        assert_eq!(builder.func_code, cloned.func_code);
    }

    #[test]
    fn test_enclog_builder_debug() {
        let builder = EncLogBuilder::new().token_value(0x02000005).func_code(2);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EncLogBuilder"));
        assert!(debug_str.contains("token_value"));
        assert!(debug_str.contains("func_code"));
    }

    #[test]
    fn test_enclog_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = EncLogBuilder::new()
            .token_value(0x08000001) // Param token
            .func_code(1) // Update
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first log entry
        let ref1 = EncLogBuilder::new()
            .token_value(0x06000001) // Method
            .create()
            .build(&mut assembly)
            .expect("Should build first log entry");

        // Build second log entry
        let ref2 = EncLogBuilder::new()
            .token_value(0x02000001) // Type
            .update()
            .build(&mut assembly)
            .expect("Should build second log entry");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }

    #[test]
    fn test_enclog_builder_various_tokens() -> Result<()> {
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

        for (i, &token_val) in tokens.iter().enumerate() {
            let ref_ = EncLogBuilder::new()
                .token_value(token_val)
                .func_code(i as u32 % 3) // Cycle through 0, 1, 2
                .build(&mut assembly)
                .expect("Should build successfully");

            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EncLog));
        }

        Ok(())
    }
}

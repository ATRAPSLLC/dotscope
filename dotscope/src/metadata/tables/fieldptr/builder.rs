//! Builder for constructing `FieldPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::fieldptr::FieldPtrBuilder`] which enables fluent construction
//! of `FieldPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let fieldptr_token = FieldPtrBuilder::new()
//!     .field(5)                      // Points to Field table RID 5
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{FieldPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `FieldPtr` table entries
///
/// Provides a fluent interface for building `FieldPtr` metadata table entries.
/// These entries provide indirection for field access when logical and physical
/// field ordering differs, enabling metadata optimizations and edit-and-continue.
///
/// # Required Fields
/// - `field`: Field table RID that this pointer references
///
/// # Indirection Context
///
/// The FieldPtr table provides a mapping layer between logical field references
/// and physical field table entries. This enables:
/// - Field reordering for metadata optimization
/// - Edit-and-continue field additions without breaking references
/// - Platform-specific field layout optimizations
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut context = CilAssembly::new(view);
/// // Create field pointer for field reordering
/// let ptr1 = FieldPtrBuilder::new()
///     .field(10)  // Points to Field table entry 10
///     .build(&mut context)?;
///
/// // Create pointer for optimized field layout
/// let ptr2 = FieldPtrBuilder::new()
///     .field(25)  // Points to Field table entry 25
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = FieldPtrBuilder::new()
///     .field(3)   // Points to Field table entry 3
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct FieldPtrBuilder {
    /// Field table RID that this pointer references
    field: Option<u32>,
}

impl FieldPtrBuilder {
    /// Creates a new `FieldPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required field RID before calling build().
    ///
    /// # Returns
    /// A new `FieldPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = FieldPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { field: None }
    }

    /// Sets the Field table RID
    ///
    /// Specifies which Field table entry this pointer references. This creates
    /// the indirection mapping from the FieldPtr RID (logical index) to the
    /// actual Field table entry (physical index).
    ///
    /// # Parameters
    /// - `field`: The Field table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Point to first field
    /// let builder = FieldPtrBuilder::new()
    ///     .field(1);
    ///
    /// // Point to a later field for reordering
    /// let builder = FieldPtrBuilder::new()
    ///     .field(15);
    /// ```
    #[must_use]
    pub fn field(mut self, field: u32) -> Self {
        self.field = Some(field);
        self
    }

    /// Builds and adds the `FieldPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `FieldPtr` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this field pointer entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the assembly being modified
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created field pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (field RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = FieldPtrBuilder::new()
    ///     .field(5)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let field = self.field.ok_or_else(|| {
            Error::ModificationInvalid("Field RID is required for FieldPtr".to_string())
        })?;

        let field_ptr = FieldPtrRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            field,
        };

        assembly.table_row_add(TableId::FieldPtr, TableDataOwned::FieldPtr(field_ptr))
    }
}

impl Default for FieldPtrBuilder {
    /// Creates a default `FieldPtrBuilder`
    ///
    /// Equivalent to calling [`FieldPtrBuilder::new()`].
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
    fn test_fieldptr_builder_new() {
        let builder = FieldPtrBuilder::new();

        assert!(builder.field.is_none());
    }

    #[test]
    fn test_fieldptr_builder_default() {
        let builder = FieldPtrBuilder::default();

        assert!(builder.field.is_none());
    }

    #[test]
    fn test_fieldptr_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = FieldPtrBuilder::new()
            .field(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_reordering() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = FieldPtrBuilder::new()
            .field(10) // Point to later field for reordering
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_missing_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = FieldPtrBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Field RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_clone() {
        let builder = FieldPtrBuilder::new().field(5);

        let cloned = builder.clone();
        assert_eq!(builder.field, cloned.field);
    }

    #[test]
    fn test_fieldptr_builder_debug() {
        let builder = FieldPtrBuilder::new().field(8);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("FieldPtrBuilder"));
        assert!(debug_str.contains("field"));
    }

    #[test]
    fn test_fieldptr_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = FieldPtrBuilder::new()
            .field(25)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first pointer
        let ref1 = FieldPtrBuilder::new()
            .field(10)
            .build(&mut assembly)
            .expect("Should build first pointer");

        // Build second pointer
        let ref2 = FieldPtrBuilder::new()
            .field(5)
            .build(&mut assembly)
            .expect("Should build second pointer");

        // Build third pointer
        let ref3 = FieldPtrBuilder::new()
            .field(15)
            .build(&mut assembly)
            .expect("Should build third pointer");

        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_large_field_rid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = FieldPtrBuilder::new()
            .field(0xFFFF) // Large Field RID
            .build(&mut assembly)
            .expect("Should handle large field RID");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_field_ordering_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate field reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 3), (2, 1), (3, 2)];

        let mut refs = Vec::new();
        for (logical_idx, physical_field) in logical_to_physical {
            let ref_ = FieldPtrBuilder::new()
                .field(physical_field)
                .build(&mut assembly)
                .expect("Should build field pointer");
            refs.push((logical_idx, ref_));
        }

        // Verify all refs have correct kind
        for (i, (logical_idx, ref_)) in refs.iter().enumerate() {
            assert_eq!(*logical_idx, i + 1);
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::FieldPtr));
        }

        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_zero_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with field 0 (typically invalid but should not cause builder to fail)
        let result = FieldPtrBuilder::new().field(0).build(&mut assembly);

        // Should build successfully even with field 0
        assert!(result.is_ok());
        Ok(())
    }
}

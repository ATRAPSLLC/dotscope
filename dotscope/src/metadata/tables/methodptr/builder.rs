//! Builder for constructing `MethodPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::methodptr::MethodPtrBuilder`] which enables fluent construction
//! of `MethodPtr` metadata table entries. The builder follows the established
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
//! let methodptr_token = MethodPtrBuilder::new()
//!     .method(8)                     // Points to MethodDef table RID 8
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{MethodPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `MethodPtr` table entries
///
/// Provides a fluent interface for building `MethodPtr` metadata table entries.
/// These entries provide indirection for method access when logical and physical
/// method ordering differs, enabling method table optimizations and edit-and-continue.
///
/// # Required Fields
/// - `method`: MethodDef table RID that this pointer references
///
/// # Indirection Context
///
/// The MethodPtr table provides a mapping layer between logical method references
/// and physical MethodDef table entries. This enables:
/// - Method reordering for metadata optimization
/// - Edit-and-continue method additions without breaking references
/// - Runtime method hot-reload and debugging interception
/// - Incremental compilation with stable method references
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut context = CilAssembly::new(view);
/// // Create method pointer for method reordering
/// let ptr1 = MethodPtrBuilder::new()
///     .method(15)  // Points to MethodDef table entry 15
///     .build(&mut context)?;
///
/// // Create pointer for hot-reload scenario
/// let ptr2 = MethodPtrBuilder::new()
///     .method(42)  // Points to MethodDef table entry 42
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = MethodPtrBuilder::new()
///     .method(7)   // Points to MethodDef table entry 7
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct MethodPtrBuilder {
    /// MethodDef table RID that this pointer references
    method: Option<u32>,
}

impl MethodPtrBuilder {
    /// Creates a new `MethodPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required method RID before calling build().
    ///
    /// # Returns
    /// A new `MethodPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { method: None }
    }

    /// Sets the MethodDef table RID
    ///
    /// Specifies which MethodDef table entry this pointer references. This creates
    /// the indirection mapping from the MethodPtr RID (logical index) to the
    /// actual MethodDef table entry (physical index).
    ///
    /// # Parameters
    /// - `method`: The MethodDef table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Point to first method
    /// let builder = MethodPtrBuilder::new()
    ///     .method(1);
    ///
    /// // Point to a later method for reordering
    /// let builder = MethodPtrBuilder::new()
    ///     .method(25);
    /// ```
    #[must_use]
    pub fn method(mut self, method: u32) -> Self {
        self.method = Some(method);
        self
    }

    /// Builds and adds the `MethodPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `MethodPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this method pointer entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created method pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (method RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = MethodPtrBuilder::new()
    ///     .method(8)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let method = self.method.ok_or_else(|| {
            Error::ModificationInvalid("Method RID is required for MethodPtr".to_string())
        })?;

        let method_ptr = MethodPtrRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            method,
        };

        assembly.table_row_add(TableId::MethodPtr, TableDataOwned::MethodPtr(method_ptr))
    }
}

impl Default for MethodPtrBuilder {
    /// Creates a default `MethodPtrBuilder`
    ///
    /// Equivalent to calling [`MethodPtrBuilder::new()`].
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
    fn test_methodptr_builder_new() {
        let builder = MethodPtrBuilder::new();

        assert!(builder.method.is_none());
    }

    #[test]
    fn test_methodptr_builder_default() {
        let builder = MethodPtrBuilder::default();

        assert!(builder.method.is_none());
    }

    #[test]
    fn test_methodptr_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = MethodPtrBuilder::new()
            .method(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_reordering() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = MethodPtrBuilder::new()
            .method(25) // Point to later method for reordering
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_missing_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = MethodPtrBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Method RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_clone() {
        let builder = MethodPtrBuilder::new().method(8);

        let cloned = builder.clone();
        assert_eq!(builder.method, cloned.method);
    }

    #[test]
    fn test_methodptr_builder_debug() {
        let builder = MethodPtrBuilder::new().method(12);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("MethodPtrBuilder"));
        assert!(debug_str.contains("method"));
    }

    #[test]
    fn test_methodptr_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = MethodPtrBuilder::new()
            .method(42)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first pointer
        let ref1 = MethodPtrBuilder::new()
            .method(20)
            .build(&mut assembly)
            .expect("Should build first pointer");

        // Build second pointer
        let ref2 = MethodPtrBuilder::new()
            .method(10)
            .build(&mut assembly)
            .expect("Should build second pointer");

        // Build third pointer
        let ref3 = MethodPtrBuilder::new()
            .method(30)
            .build(&mut assembly)
            .expect("Should build third pointer");

        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_large_method_rid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = MethodPtrBuilder::new()
            .method(0xFFFF) // Large MethodDef RID
            .build(&mut assembly)
            .expect("Should handle large method RID");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_method_ordering_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate method reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 30), (2, 10), (3, 20)];

        let mut refs = Vec::new();
        for (logical_idx, physical_method) in logical_to_physical {
            let ref_ = MethodPtrBuilder::new()
                .method(physical_method)
                .build(&mut assembly)
                .expect("Should build method pointer");
            refs.push((logical_idx, ref_));
        }

        // Verify all refs have correct kind
        for (i, (logical_idx, ref_)) in refs.iter().enumerate() {
            assert_eq!(*logical_idx, i + 1);
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        }

        Ok(())
    }

    #[test]
    fn test_methodptr_builder_zero_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with method 0 (typically invalid but should not cause builder to fail)
        let result = MethodPtrBuilder::new().method(0).build(&mut assembly);

        // Should build successfully even with method 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_edit_continue_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate edit-and-continue scenario where methods are added/reordered
        let original_methods = [5, 10, 15];
        let mut refs = Vec::new();

        for &method_rid in &original_methods {
            let ref_ = MethodPtrBuilder::new()
                .method(method_rid)
                .build(&mut assembly)
                .expect("Should build method pointer for edit-continue");
            refs.push(ref_);
        }

        // Verify stable logical refs despite physical reordering
        for ref_ in refs.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        }

        Ok(())
    }

    #[test]
    fn test_methodptr_builder_hot_reload_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate hot-reload where new methods replace existing ones
        let new_method_implementations = [100, 200, 300];
        let mut pointer_refs = Vec::new();

        for &new_method in &new_method_implementations {
            let pointer_ref = MethodPtrBuilder::new()
                .method(new_method)
                .build(&mut assembly)
                .expect("Should build pointer for hot-reload");
            pointer_refs.push(pointer_ref);
        }

        // Verify pointer refs maintain stable references for hot-reload
        assert_eq!(pointer_refs.len(), 3);
        for ref_ in pointer_refs.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodPtr));
        }

        Ok(())
    }
}

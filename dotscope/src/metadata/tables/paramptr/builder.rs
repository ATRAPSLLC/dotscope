//! Builder for constructing `ParamPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::paramptr::ParamPtrBuilder`] which enables fluent construction
//! of `ParamPtr` metadata table entries. The builder follows the established
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
//! let paramptr_token = ParamPtrBuilder::new()
//!     .param(3)                      // Points to Param table RID 3
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{ParamPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `ParamPtr` table entries
///
/// Provides a fluent interface for building `ParamPtr` metadata table entries.
/// These entries provide indirection for parameter access when logical and physical
/// parameter ordering differs, enabling metadata optimizations and edit-and-continue.
///
/// # Required Fields
/// - `param`: Param table RID that this pointer references
///
/// # Indirection Context
///
/// The ParamPtr table provides a mapping layer between logical parameter references
/// and physical Param table entries. This enables:
/// - Parameter reordering for metadata optimization
/// - Edit-and-continue parameter additions without breaking references
/// - Compressed metadata streams with flexible parameter organization
/// - Runtime parameter hot-reload and debugging interception
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut context = CilAssembly::new(view);
/// // Create parameter pointer for parameter reordering
/// let ptr1 = ParamPtrBuilder::new()
///     .param(5)   // Points to Param table entry 5
///     .build(&mut context)?;
///
/// // Create pointer for optimized parameter layout
/// let ptr2 = ParamPtrBuilder::new()
///     .param(12)  // Points to Param table entry 12
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = ParamPtrBuilder::new()
///     .param(2)   // Points to Param table entry 2
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ParamPtrBuilder {
    /// Param table RID that this pointer references
    param: Option<u32>,
}

impl ParamPtrBuilder {
    /// Creates a new `ParamPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required param RID before calling build().
    ///
    /// # Returns
    /// A new `ParamPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ParamPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { param: None }
    }

    /// Sets the Param table RID
    ///
    /// Specifies which Param table entry this pointer references. This creates
    /// the indirection mapping from the ParamPtr RID (logical index) to the
    /// actual Param table entry (physical index).
    ///
    /// # Parameters
    /// - `param`: The Param table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Point to first parameter
    /// let builder = ParamPtrBuilder::new()
    ///     .param(1);
    ///
    /// // Point to a later parameter for reordering
    /// let builder = ParamPtrBuilder::new()
    ///     .param(10);
    /// ```
    #[must_use]
    pub fn param(mut self, param: u32) -> Self {
        self.param = Some(param);
        self
    }

    /// Builds and adds the `ParamPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `ParamPtr` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this parameter pointer entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created parameter pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (param RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = ParamPtrBuilder::new()
    ///     .param(3)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let param = self.param.ok_or_else(|| {
            Error::ModificationInvalid("Param RID is required for ParamPtr".to_string())
        })?;

        let param_ptr = ParamPtrRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            param,
        };

        assembly.table_row_add(TableId::ParamPtr, TableDataOwned::ParamPtr(param_ptr))
    }
}

impl Default for ParamPtrBuilder {
    /// Creates a default `ParamPtrBuilder`
    ///
    /// Equivalent to calling [`ParamPtrBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testkit::factories::table::assemblyref::get_test_assembly;

    #[test]
    fn test_paramptr_builder_new() {
        let builder = ParamPtrBuilder::new();

        assert!(builder.param.is_none());
    }

    #[test]
    fn test_paramptr_builder_default() {
        let builder = ParamPtrBuilder::default();

        assert!(builder.param.is_none());
    }

    #[test]
    fn test_paramptr_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = ParamPtrBuilder::new()
            .param(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_reordering() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = ParamPtrBuilder::new()
            .param(10) // Point to later parameter for reordering
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_missing_param() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = ParamPtrBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Param RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_clone() {
        let builder = ParamPtrBuilder::new().param(3);

        let cloned = builder.clone();
        assert_eq!(builder.param, cloned.param);
    }

    #[test]
    fn test_paramptr_builder_debug() {
        let builder = ParamPtrBuilder::new().param(7);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ParamPtrBuilder"));
        assert!(debug_str.contains("param"));
    }

    #[test]
    fn test_paramptr_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let _change_ref = ParamPtrBuilder::new()
            .param(15)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first pointer
        let ref1 = ParamPtrBuilder::new()
            .param(5)
            .build(&mut assembly)
            .expect("Should build first pointer");

        // Build second pointer
        let ref2 = ParamPtrBuilder::new()
            .param(2)
            .build(&mut assembly)
            .expect("Should build second pointer");

        // Build third pointer
        let ref3 = ParamPtrBuilder::new()
            .param(8)
            .build(&mut assembly)
            .expect("Should build third pointer");

        // Verify each build returns a unique change reference
        assert!(!Arc::ptr_eq(&ref1, &ref2));
        assert!(!Arc::ptr_eq(&ref2, &ref3));
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_large_param_rid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = ParamPtrBuilder::new()
            .param(0xFFFF) // Large Param RID
            .build(&mut assembly)
            .expect("Should handle large param RID");

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_param_ordering_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate parameter reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 8), (2, 3), (3, 6)];

        for (_logical_idx, physical_param) in logical_to_physical {
            let _change_ref = ParamPtrBuilder::new()
                .param(physical_param)
                .build(&mut assembly)
                .expect("Should build parameter pointer");
        }

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_zero_param() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with param 0 (typically invalid but should not cause builder to fail)
        let result = ParamPtrBuilder::new().param(0).build(&mut assembly);

        // Should build successfully even with param 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_method_parameter_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate method parameters with custom ordering
        let method_params = [4, 1, 7, 2]; // Parameters in custom order

        for &param_rid in &method_params {
            let _change_ref = ParamPtrBuilder::new()
                .param(param_rid)
                .build(&mut assembly)
                .expect("Should build parameter pointer");
        }

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_compressed_metadata_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate compressed metadata scenario with parameter indirection
        let compressed_order = [10, 5, 15, 1, 20];

        let mut pointer_refs = Vec::new();
        for &param_order in &compressed_order {
            let change_ref = ParamPtrBuilder::new()
                .param(param_order)
                .build(&mut assembly)
                .expect("Should build pointer for compressed metadata");
            pointer_refs.push(change_ref);
        }

        // Verify consistent indirection mapping
        assert_eq!(pointer_refs.len(), 5);

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_edit_continue_parameter_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate edit-and-continue where parameters are added/modified
        let original_params = [1, 2, 3];

        for &param_rid in &original_params {
            let _change_ref = ParamPtrBuilder::new()
                .param(param_rid)
                .build(&mut assembly)
                .expect("Should build parameter pointer for edit-continue");
        }

        // Add new parameter during edit session
        let _new_param_ref = ParamPtrBuilder::new()
            .param(100) // New parameter added during edit
            .build(&mut assembly)
            .expect("Should build new parameter pointer");

        Ok(())
    }
}

//! Builder for constructing `PropertyPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::propertyptr::PropertyPtrBuilder`] which enables fluent construction
//! of `PropertyPtr` metadata table entries. The builder follows the established
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
//! let propertyptr_token = PropertyPtrBuilder::new()
//!     .property(6)                   // Points to Property table RID 6
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{PropertyPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `PropertyPtr` table entries
///
/// Provides a fluent interface for building `PropertyPtr` metadata table entries.
/// These entries provide indirection for property access when logical and physical
/// property ordering differs, enabling metadata optimizations and compressed layouts.
///
/// # Required Fields
/// - `property`: Property table RID that this pointer references
///
/// # Indirection Context
///
/// The PropertyPtr table provides a mapping layer between logical property references
/// and physical Property table entries. This enables:
/// - Property reordering for metadata optimization
/// - Compressed metadata streams with flexible property organization
/// - Runtime property access pattern optimizations
/// - Edit-and-continue property modifications without breaking references
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut context = CilAssembly::new(view);
/// // Create property pointer for property reordering
/// let ptr1 = PropertyPtrBuilder::new()
///     .property(9)  // Points to Property table entry 9
///     .build(&mut context)?;
///
/// // Create pointer for optimized property layout
/// let ptr2 = PropertyPtrBuilder::new()
///     .property(4)  // Points to Property table entry 4
///     .build(&mut context)?;
///
/// // Multiple pointers for complex property arrangements
/// let ptr3 = PropertyPtrBuilder::new()
///     .property(18) // Points to Property table entry 18
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct PropertyPtrBuilder {
    /// Property table RID that this pointer references
    property: Option<u32>,
}

impl PropertyPtrBuilder {
    /// Creates a new `PropertyPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required property RID before calling build().
    ///
    /// # Returns
    /// A new `PropertyPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = PropertyPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { property: None }
    }

    /// Sets the Property table RID
    ///
    /// Specifies which Property table entry this pointer references. This creates
    /// the indirection mapping from the PropertyPtr RID (logical index) to the
    /// actual Property table entry (physical index).
    ///
    /// # Parameters
    /// - `property`: The Property table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Point to first property
    /// let builder = PropertyPtrBuilder::new()
    ///     .property(1);
    ///
    /// // Point to a later property for reordering
    /// let builder = PropertyPtrBuilder::new()
    ///     .property(15);
    /// ```
    #[must_use]
    pub fn property(mut self, property: u32) -> Self {
        self.property = Some(property);
        self
    }

    /// Builds and adds the `PropertyPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `PropertyPtr` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this property pointer entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created property pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (property RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = PropertyPtrBuilder::new()
    ///     .property(6)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let property = self.property.ok_or_else(|| {
            Error::ModificationInvalid("Property RID is required for PropertyPtr".to_string())
        })?;

        let property_ptr = PropertyPtrRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            property,
        };

        assembly.table_row_add(
            TableId::PropertyPtr,
            TableDataOwned::PropertyPtr(property_ptr),
        )
    }
}

impl Default for PropertyPtrBuilder {
    /// Creates a default `PropertyPtrBuilder`
    ///
    /// Equivalent to calling [`PropertyPtrBuilder::new()`].
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
    fn test_propertyptr_builder_new() {
        let builder = PropertyPtrBuilder::new();

        assert!(builder.property.is_none());
    }

    #[test]
    fn test_propertyptr_builder_default() {
        let builder = PropertyPtrBuilder::default();

        assert!(builder.property.is_none());
    }

    #[test]
    fn test_propertyptr_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = PropertyPtrBuilder::new()
            .property(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_reordering() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = PropertyPtrBuilder::new()
            .property(15) // Point to later property for reordering
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_missing_property() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = PropertyPtrBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Property RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_clone() {
        let builder = PropertyPtrBuilder::new().property(6);

        let cloned = builder.clone();
        assert_eq!(builder.property, cloned.property);
    }

    #[test]
    fn test_propertyptr_builder_debug() {
        let builder = PropertyPtrBuilder::new().property(11);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("PropertyPtrBuilder"));
        assert!(debug_str.contains("property"));
    }

    #[test]
    fn test_propertyptr_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let _change_ref = PropertyPtrBuilder::new()
            .property(25)
            .build(&mut assembly)
            .expect("Should build successfully");

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first pointer
        let ref1 = PropertyPtrBuilder::new()
            .property(9)
            .build(&mut assembly)
            .expect("Should build first pointer");

        // Build second pointer
        let ref2 = PropertyPtrBuilder::new()
            .property(4)
            .build(&mut assembly)
            .expect("Should build second pointer");

        // Build third pointer
        let ref3 = PropertyPtrBuilder::new()
            .property(18)
            .build(&mut assembly)
            .expect("Should build third pointer");

        // Verify each build returns a unique change reference
        assert!(!Arc::ptr_eq(&ref1, &ref2));
        assert!(!Arc::ptr_eq(&ref2, &ref3));
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_large_property_rid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let _change_ref = PropertyPtrBuilder::new()
            .property(0xFFFF) // Large Property RID
            .build(&mut assembly)
            .expect("Should handle large property RID");

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_property_ordering_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate property reordering: logical order 1,2,3 -> physical order 12,6,15
        let logical_to_physical = [(1, 12), (2, 6), (3, 15)];

        for (_logical_idx, physical_property) in logical_to_physical {
            let _change_ref = PropertyPtrBuilder::new()
                .property(physical_property)
                .build(&mut assembly)
                .expect("Should build property pointer");
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_zero_property() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with property 0 (typically invalid but should not cause builder to fail)
        let result = PropertyPtrBuilder::new().property(0).build(&mut assembly);

        // Should build successfully even with property 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_type_property_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate type with multiple properties that need indirection
        let type_properties = [7, 14, 3, 21, 9]; // Properties in custom order

        for &property_rid in &type_properties {
            let _change_ref = PropertyPtrBuilder::new()
                .property(property_rid)
                .build(&mut assembly)
                .expect("Should build property pointer");
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_compressed_metadata_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate compressed metadata scenario with property indirection
        let compressed_order = [25, 10, 30, 5, 40, 15];

        let mut pointer_refs = Vec::new();
        for &property_order in &compressed_order {
            let change_ref = PropertyPtrBuilder::new()
                .property(property_order)
                .build(&mut assembly)
                .expect("Should build pointer for compressed metadata");
            pointer_refs.push(change_ref);
        }

        // Verify consistent indirection mapping
        assert_eq!(pointer_refs.len(), 6);

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_optimization_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate property optimization with access pattern-based ordering
        let optimized_access_order = [100, 50, 200, 25, 150, 75, 300];

        let mut optimization_refs = Vec::new();
        for &optimized_property in &optimized_access_order {
            let change_ref = PropertyPtrBuilder::new()
                .property(optimized_property)
                .build(&mut assembly)
                .expect("Should build optimization pointer");
            optimization_refs.push(change_ref);
        }

        // Verify optimization indirection maintains consistency
        assert_eq!(optimization_refs.len(), 7);

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_interface_property_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate interface with properties requiring specific ordering
        let interface_properties = [1, 5, 3, 8, 2]; // Interface property order

        for &prop_rid in &interface_properties {
            let _change_ref = PropertyPtrBuilder::new()
                .property(prop_rid)
                .build(&mut assembly)
                .expect("Should build interface property pointer");
        }

        Ok(())
    }

    #[test]
    fn test_propertyptr_builder_edit_continue_property_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate edit-and-continue where properties are added/modified
        let original_properties = [10, 20, 30];

        for &property_rid in &original_properties {
            let _change_ref = PropertyPtrBuilder::new()
                .property(property_rid)
                .build(&mut assembly)
                .expect("Should build property pointer for edit-continue");
        }

        // Add new property during edit session
        let _new_property_ref = PropertyPtrBuilder::new()
            .property(500) // New property added during edit
            .build(&mut assembly)
            .expect("Should build new property pointer");

        Ok(())
    }
}

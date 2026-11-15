//! # PropertyMap Builder
//!
//! Provides a fluent API for building PropertyMap table entries that establish ownership relationships
//! between types and their properties. The PropertyMap table defines contiguous ranges of properties that
//! belong to specific types, enabling efficient enumeration and lookup of properties by owning type.
//!
//! ## Overview
//!
//! The `PropertyMapBuilder` enables creation of property map entries with:
//! - Parent type specification (required)
//! - Property list starting index specification (required)
//! - Validation of type row indices and property indices
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # fn main() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//! use dotscope::metadata::tables::PropertyBuilder;
//!
//! // Create a type first
//! let type_ref = TypeDefBuilder::new()
//!     .name("MyClass")
//!     .namespace("MyApp")
//!     .public_class()
//!     .build(&mut assembly)?;
//!
//! // Create property signatures
//! let string_property_sig = &[0x08, 0x1C]; // PROPERTY calling convention + ELEMENT_TYPE_OBJECT
//! let int_property_sig = &[0x08, 0x08]; // PROPERTY calling convention + ELEMENT_TYPE_I4
//!
//! // Create properties
//! let prop1_ref = PropertyBuilder::new()
//!     .name("Name")
//!     .signature(string_property_sig)
//!     .build(&mut assembly)?;
//!
//! let prop2_ref = PropertyBuilder::new()
//!     .name("Count")
//!     .signature(int_property_sig)
//!     .build(&mut assembly)?;
//!
//! // Create a property map entry for the type
//! let property_map_ref = PropertyMapBuilder::new()
//!     .parent(type_ref.placeholder())
//!     .property_list(prop1_ref.placeholder()) // Starting property index
//!     .build(&mut assembly)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Parent type and property list index are required and validated
//! - **Type Verification**: Ensures parent token is valid and points to TypeDef table
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Range Support**: Supports defining contiguous property ranges for efficient lookup

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{PropertyMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating PropertyMap table entries.
///
/// `PropertyMapBuilder` provides a fluent API for creating entries in the PropertyMap
/// metadata table, which establishes ownership relationships between types and their properties
/// through contiguous ranges of Property table entries.
///
/// # Purpose
///
/// The PropertyMap table serves several key functions:
/// - **Property Ownership**: Defines which types own which properties
/// - **Range Management**: Establishes contiguous ranges of properties owned by types
/// - **Efficient Lookup**: Enables O(log n) lookup of properties by owning type
/// - **Property Enumeration**: Supports efficient iteration through all properties of a type
/// - **Metadata Organization**: Maintains sorted order for optimal access patterns
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing PropertyMap entries:
///
/// ```no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
/// # let type_ref = TypeDefBuilder::new()
/// #     .name("MyClass")
/// #     .namespace("MyApp")
/// #     .public_class()
/// #     .build(&mut assembly)?;
///
/// let property_map_ref = PropertyMapBuilder::new()
///     .parent(type_ref.placeholder())
///     .property_list(1) // Starting property index
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Parent Required**: A parent type row index must be provided
/// - **Parent Validation**: Parent row index cannot be 0
/// - **Property List Required**: A property list starting index must be provided
/// - **Index Validation**: Property list index must be greater than 0
///
/// # Integration
///
/// PropertyMap entries integrate with other metadata structures:
/// - **TypeDef**: References specific types in the TypeDef table as parent
/// - **Property**: Points to starting positions in the Property table for range definition
/// - **PropertyPtr**: Supports indirection through PropertyPtr table when present
/// - **Metadata Loading**: Establishes property ownership during type loading
#[derive(Debug, Clone)]
pub struct PropertyMapBuilder {
    /// The row index or placeholder of the parent type that owns the properties
    parent: Option<u32>,
    /// The starting index in the Property table for this type's properties
    property_list: Option<u32>,
}

impl Default for PropertyMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PropertyMapBuilder {
    /// Creates a new `PropertyMapBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = PropertyMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            property_list: None,
        }
    }

    /// Sets the parent type row index that owns the properties.
    ///
    /// The parent must be a valid TypeDef row index that represents the type
    /// that declares and owns the properties in the specified range.
    ///
    /// # Arguments
    ///
    /// * `parent_row` - Row index or placeholder of the TypeDef table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let type_ref = TypeDefBuilder::new()
    ///     .name("PropertyfulClass")
    ///     .namespace("MyApp")
    ///     .public_class()
    ///     .build(&mut assembly)?;
    ///
    /// let builder = PropertyMapBuilder::new()
    ///     .parent(type_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn parent(mut self, parent_row: u32) -> Self {
        self.parent = Some(parent_row);
        self
    }

    /// Sets the starting index in the Property table for this type's properties.
    ///
    /// This index defines the beginning of the contiguous range of properties
    /// owned by the parent type. The range extends to the next PropertyMap entry's
    /// property_list index (or end of Property table for the final entry).
    ///
    /// # Arguments
    ///
    /// * `property_list_index` - 1-based index into the Property table
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = PropertyMapBuilder::new()
    ///     .property_list(1); // Start from first property
    /// ```
    #[must_use]
    pub fn property_list(mut self, property_list_index: u32) -> Self {
        self.property_list = Some(property_list_index);
        self
    }

    /// Builds the PropertyMap entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the parent row is valid,
    /// validates the property list index, creates the PropertyMap table entry, and returns the
    /// change reference for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// Returns the change reference for the newly created PropertyMap entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent row index is not set
    /// - The parent row index is 0
    /// - The property list index is not set
    /// - The property list index is 0
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let type_ref = TypeDefBuilder::new()
    /// #     .name("MyClass")
    /// #     .namespace("MyApp")
    /// #     .public_class()
    /// #     .build(&mut assembly)?;
    ///
    /// let property_map_ref = PropertyMapBuilder::new()
    ///     .parent(type_ref.placeholder())
    ///     .property_list(1)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created PropertyMap with placeholder: {}", property_map_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let parent_row = self.parent.ok_or_else(|| {
            Error::ModificationInvalid("Parent row index is required for PropertyMap".to_string())
        })?;

        let property_list_index = self.property_list.ok_or_else(|| {
            Error::ModificationInvalid(
                "Property list index is required for PropertyMap".to_string(),
            )
        })?;

        if parent_row == 0 {
            return Err(Error::ModificationInvalid(
                "Parent row index cannot be 0".to_string(),
            ));
        }

        if property_list_index == 0 {
            return Err(Error::ModificationInvalid(
                "Property list index cannot be 0".to_string(),
            ));
        }

        let property_map = PropertyMapRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            parent: parent_row,
            property_list: property_list_index,
        };

        assembly.table_row_add(
            TableId::PropertyMap,
            TableDataOwned::PropertyMap(property_map),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testkit::factories::table::assemblyref::get_test_assembly;

    #[test]
    fn test_property_map_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a valid TypeDef row index for testing
        let type_row = 1u32;

        let _change_ref = PropertyMapBuilder::new()
            .parent(type_row)
            .property_list(1)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_property_map_builder_default() -> Result<()> {
        let builder = PropertyMapBuilder::default();
        assert!(builder.parent.is_none());
        assert!(builder.property_list.is_none());
        Ok(())
    }

    #[test]
    fn test_property_map_builder_missing_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = PropertyMapBuilder::new()
            .property_list(1)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent row index is required"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_missing_property_list() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a valid TypeDef row index
        let type_row = 1u32;

        let result = PropertyMapBuilder::new()
            .parent(type_row)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Property list index is required"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_zero_row_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a zero row index
        let zero_row = 0u32;

        let result = PropertyMapBuilder::new()
            .parent(zero_row)
            .property_list(1)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent row index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_zero_property_list() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a valid TypeDef row index
        let type_row = 1u32;

        let result = PropertyMapBuilder::new()
            .parent(type_row)
            .property_list(0) // Zero property list index is invalid
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Property list index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_multiple_entries() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use valid TypeDef row indices
        let type1_row = 1u32;
        let type2_row = 2u32;

        let ref1 = PropertyMapBuilder::new()
            .parent(type1_row)
            .property_list(1)
            .build(&mut assembly)?;

        let ref2 = PropertyMapBuilder::new()
            .parent(type2_row)
            .property_list(3)
            .build(&mut assembly)?;

        // Verify change refs are different
        assert!(!Arc::ptr_eq(&ref1, &ref2));

        Ok(())
    }

    #[test]
    fn test_property_map_builder_various_property_indices() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with different property list indices
        let test_indices = [1, 5, 10, 20, 100];

        for (i, &index) in test_indices.iter().enumerate() {
            let type_row = 1u32 + i as u32;

            let _change_ref = PropertyMapBuilder::new()
                .parent(type_row)
                .property_list(index)
                .build(&mut assembly)?;
        }

        Ok(())
    }

    #[test]
    fn test_property_map_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a valid TypeDef row index
        let type_row = 1u32;

        // Test fluent API chaining
        let _change_ref = PropertyMapBuilder::new()
            .parent(type_row)
            .property_list(5)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_property_map_builder_clone() {
        let parent_row = 1u32;

        let builder1 = PropertyMapBuilder::new()
            .parent(parent_row)
            .property_list(1);
        let builder2 = builder1.clone();

        assert_eq!(builder1.parent, builder2.parent);
        assert_eq!(builder1.property_list, builder2.property_list);
    }

    #[test]
    fn test_property_map_builder_debug() {
        let parent_row = 1u32;

        let builder = PropertyMapBuilder::new()
            .parent(parent_row)
            .property_list(1);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("PropertyMapBuilder"));
    }
}

//! PropertyBuilder for creating property definitions.
//!
//! This module provides [`crate::metadata::tables::property::PropertyBuilder`] for creating Property table entries
//! with a fluent API. Properties define named attributes that can be accessed
//! through getter and setter methods, forming a fundamental part of the .NET
//! object model for encapsulated data access.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{PropertyAttributes, PropertyRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Property metadata entries.
///
/// `PropertyBuilder` provides a fluent API for creating Property table entries
/// with validation and automatic heap management. Property entries define
/// named attributes that can be accessed through getter and setter methods,
/// enabling encapsulated data access patterns in .NET types.
///
/// # Property Types
///
/// Properties can represent various data access patterns:
/// - **Instance Properties**: Bound to specific object instances
/// - **Static Properties**: Associated with the type itself
/// - **Indexed Properties**: Properties that accept parameters (indexers)
/// - **Auto-Properties**: Properties with compiler-generated backing fields
///
/// # Method Association
///
/// Properties are linked to their implementation methods through the
/// `MethodSemantics` table (created separately):
/// - **Getter Method**: Retrieves the property value
/// - **Setter Method**: Sets the property value  
/// - **Other Methods**: Additional property-related methods
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::PropertyBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// // Create a property signature for System.String
/// let string_property_sig = &[0x08, 0x1C]; // PROPERTY calling convention + ELEMENT_TYPE_OBJECT
///
/// // Create a public instance property
/// let property = PropertyBuilder::new()
///     .name("Value")
///     .flags(PropertyAttributes::ZERO)
///     .signature(string_property_sig)
///     .build(&mut assembly)?;
///
/// // Create a property with special naming
/// let special_property = PropertyBuilder::new()
///     .name("Item") // Indexer property
///     .flags(PropertyAttributes::SPECIAL_NAME)
///     .signature(string_property_sig)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct PropertyBuilder {
    name: Option<String>,
    flags: Option<PropertyAttributes>,
    signature: Option<Vec<u8>>,
}

impl Default for PropertyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PropertyBuilder {
    /// Creates a new PropertyBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::property::PropertyBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            signature: None,
        }
    }

    /// Sets the property name.
    ///
    /// Property names are used for reflection, debugging, and binding operations.
    /// Common naming patterns include Pascal case for public properties and
    /// special names like "Item" for indexer properties.
    ///
    /// # Arguments
    ///
    /// * `name` - The property name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the property flags (attributes).
    ///
    /// Property flags control special behaviors and characteristics.
    /// Common flag values from [`crate::metadata::tables::PropertyAttributes`]:
    /// - `0x0000`: No special flags (default for most properties)
    /// - `0x0200`: SPECIAL_NAME - Property has special naming conventions
    /// - `0x0400`: RT_SPECIAL_NAME - Runtime should verify name encoding
    /// - `0x1000`: HAS_DEFAULT - Property has default value in Constant table
    ///
    /// # Arguments
    ///
    /// * `flags` - The property attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: PropertyAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the property type signature.
    ///
    /// The signature defines the property's type and parameters using ECMA-335
    /// signature encoding. Property signatures start with a calling convention
    /// byte followed by the type information.
    ///
    /// Common property signature patterns:
    /// - `[0x08, 0x08]`: PROPERTY + int32 property
    /// - `[0x08, 0x0E]`: PROPERTY + string property  
    /// - `[0x28, 0x01, 0x08, 0x08]`: PROPERTY + HASTHIS + 1 param + int32 + int32 (indexer)
    /// - `[0x08, 0x1C]`: PROPERTY + object property
    ///
    /// # Arguments
    ///
    /// * `signature` - The property type signature bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Builds the property and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name and
    /// signature to the appropriate heaps, creates the raw property structure,
    /// and adds it to the Property table.
    ///
    /// Note: This only creates the Property table entry. Method associations
    /// (getter, setter) must be created separately using MethodSemantics builders.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created property, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if name is not set
    /// - Returns error if flags are not set
    /// - Returns error if signature is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalid("Property name is required".to_string()))?;

        let flags = self
            .flags
            .ok_or_else(|| Error::ModificationInvalid("Property flags are required".to_string()))?;

        let signature = self.signature.ok_or_else(|| {
            Error::ModificationInvalid("Property signature is required".to_string())
        })?;

        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let signature_index = assembly.blob_add(&signature)?.placeholder();
        let rid = assembly.next_rid(TableId::Property)?;

        let token = Token::from_parts(TableId::Property, rid);

        let property_raw = PropertyRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: flags.bits(),
            name: name_index,
            signature: signature_index,
        };

        assembly.table_row_add(TableId::Property, TableDataOwned::Property(property_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{PropertyAttributes, TableId},
        },
        testkit::fixture,
    };

    #[test]
    fn test_property_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a property signature for System.String (PROPERTY + ELEMENT_TYPE_STRING)
        let string_property_sig = &[0x08, 0x0E];

        let ref_ = PropertyBuilder::new()
            .name("TestProperty")
            .flags(PropertyAttributes::ZERO)
            .signature(string_property_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly - only check kind, not token value
        // (tokens are resolved at write time, not at creation time)
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Property));
    }

    #[test]
    fn test_property_builder_with_special_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an int32 property signature (PROPERTY + ELEMENT_TYPE_I4)
        let int32_property_sig = &[0x08, 0x08];

        // Create a property with special naming (like an indexer)
        let ref_ = PropertyBuilder::new()
            .name("Item")
            .flags(PropertyAttributes::SPECIAL_NAME)
            .signature(int32_property_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Property));
        let token = ref_.placeholder_token().unwrap();
        assert_eq!(token.value() & 0xFF000000, 0x17000000);
    }

    #[test]
    fn test_property_builder_indexer_signature() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an indexer signature: PROPERTY + HASTHIS + 1 param + string return + int32 param
        let indexer_sig = &[0x28, 0x01, 0x0E, 0x08]; // PROPERTY|HASTHIS, 1 param, string, int32

        let ref_ = PropertyBuilder::new()
            .name("Item")
            .flags(PropertyAttributes::SPECIAL_NAME)
            .signature(indexer_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Property));
    }

    #[test]
    fn test_property_builder_with_default() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a boolean property signature (PROPERTY + ELEMENT_TYPE_BOOLEAN)
        let bool_property_sig = &[0x08, 0x02];

        // Create a property with default value
        let ref_ = PropertyBuilder::new()
            .name("DefaultProperty")
            .flags(PropertyAttributes::HAS_DEFAULT)
            .signature(bool_property_sig)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Property));
    }

    #[test]
    fn test_property_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = PropertyBuilder::new()
            .flags(PropertyAttributes::ZERO)
            .signature(&[0x08, 0x08])
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_property_builder_missing_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = PropertyBuilder::new()
            .name("TestProperty")
            .signature(&[0x08, 0x08])
            .build(&mut assembly);

        // Should fail because flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_property_builder_missing_signature() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = PropertyBuilder::new()
            .name("TestProperty")
            .flags(PropertyAttributes::ZERO)
            .build(&mut assembly);

        // Should fail because signature is required
        assert!(result.is_err());
    }

    #[test]
    fn test_property_builder_multiple_properties() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let string_sig = &[0x08, 0x0E]; // PROPERTY + string
        let int_sig = &[0x08, 0x08]; // PROPERTY + int32

        // Create multiple properties
        let ref1 = PropertyBuilder::new()
            .name("Property1")
            .flags(PropertyAttributes::ZERO)
            .signature(string_sig)
            .build(&mut assembly)
            .unwrap();

        let ref2 = PropertyBuilder::new()
            .name("Property2")
            .flags(PropertyAttributes::SPECIAL_NAME)
            .signature(int_sig)
            .build(&mut assembly)
            .unwrap();

        let ref3 = PropertyBuilder::new()
            .name("Property3")
            .flags(PropertyAttributes::HAS_DEFAULT)
            .signature(string_sig)
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different references
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref3));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));

        // All should have Property table kind
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::Property));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::Property));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::Property));
    }
}

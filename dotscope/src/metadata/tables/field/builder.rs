//! FieldBuilder for creating field definitions.
//!
//! This module provides [`crate::metadata::tables::field::FieldBuilder`] for creating Field table entries
//! with a fluent API. Fields define data members for types including instance
//! fields, static fields, constants, and literals with their associated types
//! and characteristics.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{FieldAttributes, FieldRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Field metadata entries.
///
/// `FieldBuilder` provides a fluent API for creating Field table entries
/// with validation and automatic heap management. Field entries define
/// data members of types including instance fields, static fields, and
/// compile-time constants.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::FieldBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a field signature for System.String
/// let string_signature = &[0x12]; // ELEMENT_TYPE_STRING
///
/// // Create a private instance field
/// let my_field = FieldBuilder::new()
///     .name("myField")
///     .flags(FieldAttributes::PRIVATE)
///     .signature(string_signature)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldBuilder {
    name: Option<String>,
    flags: Option<FieldAttributes>,
    signature: Option<Vec<u8>>,
}

impl Default for FieldBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldBuilder {
    /// Creates a new FieldBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::field::FieldBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            signature: None,
        }
    }

    /// Sets the field name.
    ///
    /// # Arguments
    ///
    /// * `name` - The field name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the field flags (attributes).
    ///
    /// Field flags control accessibility, storage type, and special behaviors.
    /// Use [`FieldAttributes`] constants such as `FieldAttributes::PRIVATE`,
    /// `FieldAttributes::STATIC`, `FieldAttributes::LITERAL`, etc.
    ///
    /// # Arguments
    ///
    /// * `flags` - The field attribute flags
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: FieldAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the field type signature.
    ///
    /// The signature defines the field's type using ECMA-335 signature encoding.
    /// Common signatures:
    /// - `[0x08]`: ELEMENT_TYPE_I4 (int32)
    /// - `[0x0C]`: ELEMENT_TYPE_U4 (uint32)
    /// - `[0x0E]`: ELEMENT_TYPE_STRING (System.String)
    /// - `[0x1C]`: ELEMENT_TYPE_OBJECT (System.Object)
    ///
    /// # Arguments
    ///
    /// * `signature` - The field type signature bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Builds the field and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name and
    /// signature to the appropriate heaps, creates the raw field structure,
    /// and adds it to the Field table.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly being modified
    ///
    /// # Returns
    ///
    /// A [`Token`] representing the newly created field, or an error if
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
            .ok_or_else(|| Error::ModificationInvalid("Field name is required".to_string()))?;

        let flags = self
            .flags
            .ok_or_else(|| Error::ModificationInvalid("Field flags are required".to_string()))?;

        let signature = self
            .signature
            .ok_or_else(|| Error::ModificationInvalid("Field signature is required".to_string()))?;

        // Add name to string heap
        let name_index = assembly.string_get_or_add(&name)?.placeholder();

        // Add signature to blob heap
        let signature_index = assembly.blob_add(&signature)?.placeholder();

        // Get the next RID for the Field table
        let rid = assembly.next_rid(TableId::Field)?;

        // Create the token for this field
        let token = Token::from_parts(TableId::Field, rid);

        // Create the raw field structure
        let field_raw = FieldRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: flags.bits(),
            name: name_index,
            signature: signature_index,
        };

        // Add the field to the table
        assembly.table_row_add(TableId::Field, TableDataOwned::Field(field_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        testkit::fixture,
    };

    #[test]
    fn test_field_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Check existing Field table count
        let existing_field_count = assembly.original_table_row_count(TableId::Field);
        let _expected_rid = existing_field_count + 1;

        // Create a field signature for System.String (ELEMENT_TYPE_STRING = 0x0E)
        let string_signature = &[0x0E];

        let ref_ = FieldBuilder::new()
            .name("testField")
            .flags(FieldAttributes::PRIVATE)
            .signature(string_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Field));
    }

    #[test]
    fn test_field_builder_with_attributes() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an int32 signature (ELEMENT_TYPE_I4 = 0x08)
        let int32_signature = &[0x08];

        // Create a public static readonly field
        let ref_ = FieldBuilder::new()
            .name("PublicStaticField")
            .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC | FieldAttributes::INIT_ONLY)
            .signature(int32_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Field));
    }

    #[test]
    fn test_field_builder_literal_field() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a boolean signature (ELEMENT_TYPE_BOOLEAN = 0x02)
        let bool_signature = &[0x02];

        // Create a private const field
        let ref_ = FieldBuilder::new()
            .name("ConstField")
            .flags(FieldAttributes::PRIVATE | FieldAttributes::LITERAL | FieldAttributes::STATIC)
            .signature(bool_signature)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Field));
    }

    #[test]
    fn test_field_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = FieldBuilder::new()
            .flags(FieldAttributes::PRIVATE)
            .signature(&[0x08])
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_builder_missing_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = FieldBuilder::new()
            .name("testField")
            .signature(&[0x08])
            .build(&mut assembly);

        // Should fail because flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_builder_missing_signature() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = FieldBuilder::new()
            .name("testField")
            .flags(FieldAttributes::PRIVATE)
            .build(&mut assembly);

        // Should fail because signature is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_builder_multiple_fields() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let signature = &[0x08]; // int32

        // Create multiple fields - now this will work!
        let ref1 = FieldBuilder::new()
            .name("Field1")
            .flags(FieldAttributes::PRIVATE)
            .signature(signature)
            .build(&mut assembly)
            .unwrap();

        let ref2 = FieldBuilder::new()
            .name("Field2")
            .flags(FieldAttributes::PUBLIC)
            .signature(signature)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed and have different references
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::Field));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::Field));
    }
}

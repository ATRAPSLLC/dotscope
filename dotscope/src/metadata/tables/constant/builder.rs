//! ConstantBuilder for creating compile-time constant value definitions.
//!
//! This module provides [`crate::metadata::tables::constant::ConstantBuilder`] for creating Constant table entries
//! with a fluent API. Constants represent compile-time literal values associated
//! with fields, properties, and parameters, enabling default value initialization,
//! enumeration value definitions, and attribute argument specification.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, ConstantRaw, TableDataOwned, TableId},
        token::Token,
        typesystem::ELEMENT_TYPE,
    },
    Error, Result,
};

/// Builder for creating Constant metadata entries.
///
/// `ConstantBuilder` provides a fluent API for creating Constant table entries
/// with validation and automatic heap management. Constants define compile-time
/// literal values that can be associated with fields (const fields), parameters
/// (default values), and properties (constant properties), enabling efficient
/// value initialization and metadata-driven programming patterns.
///
/// # Constant Value Model
///
/// .NET constants follow a standard pattern:
/// - **Element Type**: The primitive type of the constant value (ELEMENT_TYPE_*)
/// - **Parent Entity**: The field, parameter, or property that owns this constant
/// - **Value Data**: Binary representation of the constant stored in the blob heap
/// - **Type Compatibility**: Ensures constant types match their container types
///
/// # Coded Index Types
///
/// Constants use the `HasConstant` coded index to specify the owning entity:
/// - **Field**: Constants for const fields and enumeration values
/// - **Param**: Default parameter values in method signatures
/// - **Property**: Compile-time constant properties
///
/// # Supported Constant Types
///
/// The following ELEMENT_TYPE values are supported for constants:
/// - **Boolean**: `ELEMENT_TYPE_BOOLEAN` (true/false values)
/// - **Integer Types**: I1, U1, I2, U2, I4, U4, I8, U8 (various integer sizes)
/// - **Floating Point**: R4 (float), R8 (double)
/// - **Character**: `ELEMENT_TYPE_CHAR` (16-bit Unicode characters)
/// - **String**: `ELEMENT_TYPE_STRING` (Unicode string literals)
/// - **Null Reference**: `ELEMENT_TYPE_CLASS` (null object references)
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{ConstantBuilder, CodedIndex, TableId};
/// # use dotscope::metadata::typesystem::ELEMENT_TYPE;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create an integer constant for a field
/// let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant); // Target field
/// let int_value = 42i32.to_le_bytes(); // Little-endian integer bytes
///
/// let field_constant = ConstantBuilder::new()
///     .element_type(ELEMENT_TYPE::I4)
///     .parent(field_ref)
///     .value(&int_value)
///     .build(&mut assembly)?;
///
/// // Create a string constant for a parameter default
/// let param_ref = CodedIndex::new(TableId::Param, 2, CodedIndexType::HasConstant); // Target parameter
/// let string_value = "Hello, World!"; // String will be encoded as UTF-16
///
/// let param_constant = ConstantBuilder::new()
///     .element_type(ELEMENT_TYPE::STRING)
///     .parent(param_ref)
///     .string_value(string_value)
///     .build(&mut assembly)?;
///
/// // Create a boolean constant for a property
/// let property_ref = CodedIndex::new(TableId::Property, 1, CodedIndexType::HasConstant); // Target property
/// let bool_value = [1u8]; // true = 1, false = 0
///
/// let property_constant = ConstantBuilder::new()
///     .element_type(ELEMENT_TYPE::BOOLEAN)
///     .parent(property_ref)
///     .value(&bool_value)
///     .build(&mut assembly)?;
///
/// // Create a null reference constant
/// let null_field = CodedIndex::new(TableId::Field, 3, CodedIndexType::HasConstant); // Target field
/// let null_value = [0u8, 0u8, 0u8, 0u8]; // 4-byte zero for null reference
///
/// let null_constant = ConstantBuilder::new()
///     .element_type(ELEMENT_TYPE::CLASS)
///     .parent(null_field)
///     .value(&null_value)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ConstantBuilder {
    element_type: Option<u8>,
    parent: Option<CodedIndex>,
    value: Option<Vec<u8>>,
}

impl Default for ConstantBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantBuilder {
    /// Creates a new ConstantBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::constant::ConstantBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            element_type: None,
            parent: None,
            value: None,
        }
    }

    /// Sets the element type of the constant value.
    ///
    /// The element type specifies the primitive type of the constant using ECMA-335
    /// element type constants. This determines how the blob value data should be
    /// interpreted and validated against the parent entity's type.
    ///
    /// Common element types for constants:
    /// - `ELEMENT_TYPE::BOOLEAN` - Boolean values (true/false)
    /// - `ELEMENT_TYPE::I4` - 32-bit signed integers
    /// - `ELEMENT_TYPE::U4` - 32-bit unsigned integers
    /// - `ELEMENT_TYPE::I8` - 64-bit signed integers
    /// - `ELEMENT_TYPE::R4` - 32-bit floating point
    /// - `ELEMENT_TYPE::R8` - 64-bit floating point
    /// - `ELEMENT_TYPE::CHAR` - 16-bit Unicode characters
    /// - `ELEMENT_TYPE::STRING` - Unicode string literals
    /// - `ELEMENT_TYPE::CLASS` - Null reference constants
    ///
    /// # Arguments
    ///
    /// * `element_type` - An ELEMENT_TYPE constant specifying the constant's type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn element_type(mut self, element_type: u8) -> Self {
        self.element_type = Some(element_type);
        self
    }

    /// Sets the parent entity that owns this constant.
    ///
    /// The parent must be a valid `HasConstant` coded index that references
    /// a field, parameter, or property that can have a constant value associated
    /// with it. This establishes which metadata entity the constant applies to.
    ///
    /// Valid parent types include:
    /// - `Field` - Constants for const fields and enumeration values
    /// - `Param` - Default parameter values in method signatures
    /// - `Property` - Compile-time constant properties
    ///
    /// # Arguments
    ///
    /// * `parent` - A `HasConstant` coded index pointing to the owning entity
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the binary value data for the constant.
    ///
    /// The value blob contains the binary representation of the constant according
    /// to the element type. The interpretation depends on the element type:
    ///
    /// Integer types (I1, U1, I2, U2, I4, U4, I8, U8):
    /// - Little-endian byte representation
    /// - Example: `42i32.to_le_bytes()` for I4
    ///
    /// Floating point types (R4, R8):
    /// - IEEE 754 little-endian representation
    /// - Example: `3.14f32.to_le_bytes()` for R4
    ///
    /// Boolean type:
    /// - Single byte: 0 = false, 1 = true
    /// - Example: `[1u8]` for true
    ///
    /// Character type:
    /// - 16-bit Unicode code point, little-endian
    /// - Example: `'A'.to_le_bytes()` for char
    ///
    /// String type:
    /// - UTF-16 encoded string data
    /// - Use `string_value()` method for convenience
    ///
    /// Class type (null references):
    /// - 4-byte zero value
    /// - Example: `[0u8, 0u8, 0u8, 0u8]` for null
    ///
    /// # Arguments
    ///
    /// * `value` - The binary representation of the constant value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn value(mut self, value: &[u8]) -> Self {
        self.value = Some(value.to_vec());
        self
    }

    /// Sets a string value for string constants.
    ///
    /// This is a convenience method for string constants that automatically
    /// encodes the string as UTF-16 bytes as required by the .NET metadata format.
    /// The element type is automatically set to `ELEMENT_TYPE::STRING`.
    ///
    /// # Arguments
    ///
    /// * `string_value` - The string literal value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn string_value(mut self, string_value: &str) -> Self {
        // Encode string as UTF-16 bytes (little-endian)
        let utf16_bytes: Vec<u8> = string_value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();

        self.element_type = Some(ELEMENT_TYPE::STRING);
        self.value = Some(utf16_bytes);
        self
    }

    /// Sets an integer value for integer constants.
    ///
    /// This is a convenience method for 32-bit integer constants that automatically
    /// converts the integer to little-endian bytes and sets the appropriate element type.
    ///
    /// # Arguments
    ///
    /// * `int_value` - The 32-bit integer value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn i4_value(mut self, int_value: i32) -> Self {
        self.element_type = Some(ELEMENT_TYPE::I4);
        self.value = Some(int_value.to_le_bytes().to_vec());
        self
    }

    /// Sets a boolean value for boolean constants.
    ///
    /// This is a convenience method for boolean constants that automatically
    /// converts the boolean to the appropriate byte representation and sets
    /// the element type to `ELEMENT_TYPE::BOOLEAN`.
    ///
    /// # Arguments
    ///
    /// * `bool_value` - The boolean value (true/false)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn boolean_value(mut self, bool_value: bool) -> Self {
        self.element_type = Some(ELEMENT_TYPE::BOOLEAN);
        self.value = Some(vec![u8::from(bool_value)]);
        self
    }

    /// Sets a null reference value for reference type constants.
    ///
    /// This is a convenience method for null reference constants that automatically
    /// sets the element type to `ELEMENT_TYPE::CLASS` and uses a 4-byte zero value
    /// as per ECMA-335 specification for null object references.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn null_reference_value(mut self) -> Self {
        self.element_type = Some(ELEMENT_TYPE::CLASS);
        self.value = Some(vec![0, 0, 0, 0]); // 4-byte zero value for null references
        self
    }

    /// Builds the constant and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the value blob to
    /// the blob heap, creates the raw constant structure, and adds it to the
    /// Constant table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created constant, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if element_type is not set
    /// - Returns error if parent is not set
    /// - Returns error if value is not set or empty
    /// - Returns error if parent is not a valid HasConstant coded index
    /// - Returns error if element type is invalid for constants
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let element_type = self.element_type.ok_or_else(|| {
            Error::ModificationInvalid("Constant element type is required".to_string())
        })?;

        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalid("Constant parent is required".to_string()))?;

        let value = self
            .value
            .ok_or_else(|| Error::ModificationInvalid("Constant value is required".to_string()))?;

        if value.is_empty() && element_type != ELEMENT_TYPE::CLASS {
            return Err(Error::ModificationInvalid(
                "Constant value cannot be empty (except for null references)".to_string(),
            ));
        }

        let valid_parent_tables = CodedIndexType::HasConstant.tables();
        if !valid_parent_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Parent must be a HasConstant coded index (Field/Param/Property), got {:?}",
                parent.tag
            )));
        }

        match element_type {
            ELEMENT_TYPE::BOOLEAN
            | ELEMENT_TYPE::CHAR
            | ELEMENT_TYPE::I1
            | ELEMENT_TYPE::U1
            | ELEMENT_TYPE::I2
            | ELEMENT_TYPE::U2
            | ELEMENT_TYPE::I4
            | ELEMENT_TYPE::U4
            | ELEMENT_TYPE::I8
            | ELEMENT_TYPE::U8
            | ELEMENT_TYPE::R4
            | ELEMENT_TYPE::R8
            | ELEMENT_TYPE::STRING
            | ELEMENT_TYPE::CLASS => {
                // Valid constant types
            }
            _ => {
                return Err(Error::ModificationInvalid(format!(
                    "Invalid element type for constant: 0x{element_type:02X}. Only primitive types, strings, and null references are allowed"
                )));
            }
        }

        let value_index = if value.is_empty() {
            0 // Empty blob for null references
        } else {
            assembly.blob_add(&value)?.placeholder()
        };

        let rid = assembly.next_rid(TableId::Constant)?;

        let token = Token::from_parts(TableId::Constant, rid);

        let constant_raw = ConstantRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            base: element_type,
            padding: 0,
            parent,
            value: value_index,
        };

        assembly.table_row_add(TableId::Constant, TableDataOwned::Constant(constant_raw))
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
    fn test_constant_builder_basic_integer() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an integer constant for a field
        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);
        let int_value = 42i32.to_le_bytes();

        let const_ref = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I4)
            .parent(field_ref)
            .value(&int_value)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(const_ref.kind(), ChangeRefKind::TableRow(TableId::Constant));
    }

    #[test]
    fn test_constant_builder_i4_convenience() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);

        let const_ref = ConstantBuilder::new()
            .parent(field_ref)
            .i4_value(42)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(const_ref.kind(), ChangeRefKind::TableRow(TableId::Constant));
    }

    #[test]
    fn test_constant_builder_boolean() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasConstant);

        let const_ref = ConstantBuilder::new()
            .parent(param_ref)
            .boolean_value(true)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(const_ref.kind(), ChangeRefKind::TableRow(TableId::Constant));
    }

    #[test]
    fn test_constant_builder_string() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let property_ref = CodedIndex::new(TableId::Property, 1, CodedIndexType::HasConstant);

        let const_ref = ConstantBuilder::new()
            .parent(property_ref)
            .string_value("Hello, World!")
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(const_ref.kind(), ChangeRefKind::TableRow(TableId::Constant));
    }

    #[test]
    fn test_constant_builder_null_reference() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 2, CodedIndexType::HasConstant);
        let null_value = [0u8, 0u8, 0u8, 0u8]; // 4-byte zero for null reference

        let const_ref = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::CLASS)
            .parent(field_ref)
            .value(&null_value)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(const_ref.kind(), ChangeRefKind::TableRow(TableId::Constant));
    }

    #[test]
    fn test_constant_builder_missing_element_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);
        let int_value = 42i32.to_le_bytes();

        let result = ConstantBuilder::new()
            .parent(field_ref)
            .value(&int_value)
            .build(&mut assembly);

        // Should fail because element type is required
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_builder_missing_parent() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let int_value = 42i32.to_le_bytes();

        let result = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I4)
            .value(&int_value)
            .build(&mut assembly);

        // Should fail because parent is required
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_builder_missing_value() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);

        let result = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I4)
            .parent(field_ref)
            .build(&mut assembly);

        // Should fail because value is required
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_builder_invalid_parent_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use a table type that's not valid for HasConstant
        let invalid_parent = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasConstant); // TypeDef not in HasConstant
        let int_value = 42i32.to_le_bytes();

        let result = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I4)
            .parent(invalid_parent)
            .value(&int_value)
            .build(&mut assembly);

        // Should fail because parent type is not valid for HasConstant
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_builder_invalid_element_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);
        let int_value = 42i32.to_le_bytes();

        let result = ConstantBuilder::new()
            .element_type(0xFF) // Invalid element type
            .parent(field_ref)
            .value(&int_value)
            .build(&mut assembly);

        // Should fail because element type is invalid for constants
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_builder_multiple_constants() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field1 = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasConstant);
        let field2 = CodedIndex::new(TableId::Field, 2, CodedIndexType::HasConstant);
        let param1 = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasConstant);
        let property1 = CodedIndex::new(TableId::Property, 1, CodedIndexType::HasConstant);

        // Create multiple constants with different types
        let const1_ref = ConstantBuilder::new()
            .parent(field1)
            .i4_value(42)
            .build(&mut assembly)
            .unwrap();

        let const2_ref = ConstantBuilder::new()
            .parent(field2)
            .boolean_value(true)
            .build(&mut assembly)
            .unwrap();

        let const3_ref = ConstantBuilder::new()
            .parent(param1)
            .string_value("default value")
            .build(&mut assembly)
            .unwrap();

        let const4_ref = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::R8)
            .parent(property1)
            .value(&std::f64::consts::PI.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different refs
        assert!(!std::sync::Arc::ptr_eq(&const1_ref, &const2_ref));
        assert!(!std::sync::Arc::ptr_eq(&const1_ref, &const3_ref));
        assert!(!std::sync::Arc::ptr_eq(&const1_ref, &const4_ref));
        assert!(!std::sync::Arc::ptr_eq(&const2_ref, &const3_ref));
        assert!(!std::sync::Arc::ptr_eq(&const2_ref, &const4_ref));
        assert!(!std::sync::Arc::ptr_eq(&const3_ref, &const4_ref));

        // All should have Constant table kind
        assert_eq!(
            const1_ref.kind(),
            ChangeRefKind::TableRow(TableId::Constant)
        );
        assert_eq!(
            const2_ref.kind(),
            ChangeRefKind::TableRow(TableId::Constant)
        );
        assert_eq!(
            const3_ref.kind(),
            ChangeRefKind::TableRow(TableId::Constant)
        );
        assert_eq!(
            const4_ref.kind(),
            ChangeRefKind::TableRow(TableId::Constant)
        );
    }

    #[test]
    fn test_constant_builder_all_primitive_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Test various primitive types
        let field_refs: Vec<_> = (1..=12)
            .map(|i| CodedIndex::new(TableId::Field, i, CodedIndexType::HasConstant))
            .collect();

        // Boolean
        let _bool_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::BOOLEAN)
            .parent(field_refs[0].clone())
            .value(&[1u8])
            .build(&mut assembly)
            .unwrap();

        // Char (16-bit Unicode)
        let _char_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::CHAR)
            .parent(field_refs[1].clone())
            .value(&('A' as u16).to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        // Signed integers
        let _i1_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I1)
            .parent(field_refs[2].clone())
            .value(&(-42i8).to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _i2_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I2)
            .parent(field_refs[3].clone())
            .value(&(-1000i16).to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _i4_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I4)
            .parent(field_refs[4].clone())
            .value(&(-100000i32).to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _i8_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::I8)
            .parent(field_refs[5].clone())
            .value(&(-1000000000000i64).to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        // Unsigned integers
        let _u1_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::U1)
            .parent(field_refs[6].clone())
            .value(&255u8.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _u2_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::U2)
            .parent(field_refs[7].clone())
            .value(&65535u16.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _u4_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::U4)
            .parent(field_refs[8].clone())
            .value(&4294967295u32.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _u8_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::U8)
            .parent(field_refs[9].clone())
            .value(&18446744073709551615u64.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        // Floating point
        let _r4_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::R4)
            .parent(field_refs[10].clone())
            .value(&std::f32::consts::PI.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        let _r8_const = ConstantBuilder::new()
            .element_type(ELEMENT_TYPE::R8)
            .parent(field_refs[11].clone())
            .value(&std::f64::consts::E.to_le_bytes())
            .build(&mut assembly)
            .unwrap();

        // All constants should be created successfully
    }
}

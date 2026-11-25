//! Owned Constant table representation.
//!
//! This module provides the [`crate::metadata::tables::constant::owned::Constant`] struct
//! which contains fully resolved compile-time constant values with owned data and resolved
//! table references. This is the primary data structure for representing constant values
//! in a usable form after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the Constant metadata table,
//! including resolved references to parent metadata elements. This eliminates the need for table
//! lookups during runtime access, providing immediate access to constant value metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::constant::owned::Constant`] - Main owned constant structure
//! - [`crate::metadata::typesystem::CilTypeReference`] - Referenced parent element
//! - [`crate::metadata::typesystem::CilPrimitive`] - Constant value data
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::constant::raw`] - Raw table representation
//! - [`crate::metadata::typesystem`] - Type system components
//! - [`crate::metadata::token`] - Token-based metadata references

use std::sync::Arc;

use crate::{
    metadata::{
        token::Token,
        typesystem::{CilPrimitive, CilTypeReference},
    },
    Result,
};

/// Represents a compile-time constant value from the Constant metadata table
///
/// This structure contains the complete constant information from the Constant metadata
/// table (0x0B), with all table references resolved to owned type instances. Unlike
/// [`crate::metadata::tables::constant::raw::ConstantRaw`], this provides immediate
/// access to resolved constant data without requiring table lookups.
///
/// # Constant Value Storage
///
/// Constants contain compile-time literal values that are embedded in the metadata:
/// - **Element type**: The primitive type of the constant (`ELEMENT_TYPE`_*)
/// - **Parent reference**: The field, property, or parameter that owns this constant
/// - **Binary value**: The actual constant data stored as a primitive value
/// - **Type safety**: Ensures constant types match their target containers
///
/// Constants are primarily used for:
/// - **const fields**: Compile-time field initializers in C# (`const int MaxValue = 100`)
/// - **Default parameters**: Optional parameter values in method signatures
/// - **Property defaults**: Compile-time constant property values
/// - **Enum backing values**: Underlying primitive values for enum members
/// - **Attribute parameters**: Constant arguments for custom attribute constructors
pub struct Constant {
    /// Row identifier in the Constant metadata table
    ///
    /// This is the 1-based row index where this constant was defined in the metadata table.
    pub rid: u32,

    /// Metadata token uniquely identifying this constant
    ///
    /// The token provides a unique identifier for this constant entry within the assembly,
    /// constructed from the table ID and row number.
    pub token: Token,

    /// File offset where this constant's data begins
    ///
    /// The byte offset in the metadata file where this constant's binary representation starts.
    pub offset: usize,

    /// Element type of the constant value
    ///
    /// Specifies the primitive type of the constant using `ELEMENT_TYPE`_* enumeration values
    /// (see ECMA-335 II.23.1.16). This determines how the constant value should be interpreted.
    /// For null reference constants, this is `ELEMENT_TYPE_CLASS` with a 4-byte zero value.
    pub c_type: u8,

    /// Resolved reference to the parent metadata element
    ///
    /// Points to the field, property, or parameter that owns this constant. This is resolved
    /// from the original `HasConstant` coded index to provide direct access to the parent entity.
    pub parent: CilTypeReference,

    /// The constant value data
    ///
    /// Contains the actual constant value as a strongly-typed primitive. The value is wrapped
    /// in Arc for efficient sharing and is guaranteed to be type-compatible with the parent entity.
    pub value: Arc<CilPrimitive>,
}

impl Constant {
    /// Apply this constant value to its parent metadata element
    ///
    /// Associates this constant with its parent field, property, or parameter by setting
    /// the default value. This method performs type compatibility validation to ensure
    /// the constant value is appropriate for the target element's type.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the constant is successfully applied, or [`crate::Error`] if:
    /// - The constant type is incompatible with the parent type
    /// - A default value is already set for the parent element
    /// - The parent element type is invalid or unsupported
    ///
    /// # Errors
    /// Returns an error if the default value is already set for the parent entity,
    /// or if the constant value is not compatible with the target type
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::Field(field) => {
                if !field.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with field type: {:?} (token: {})",
                        self.value.kind,
                        field.signature.base,
                        self.token.value()
                    ));
                }

                field
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for field"))
            }
            CilTypeReference::Param(param) => {
                if let Some(param_type) = param.base.get() {
                    if let Some(param_type_strong) = param_type.upgrade() {
                        if !param_type_strong.accepts_constant(&self.value) {
                            return Err(malformed_error!(
                                "Constant type {:?} is not compatible with parameter type {} (token: {})",
                                self.value.kind,
                                param_type_strong.fullname(),
                                self.token.value()
                            ));
                        }
                    }
                }

                param
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for param"))
            }
            CilTypeReference::Property(property) => {
                if !property.signature.base.accepts_constant(&self.value) {
                    return Err(malformed_error!(
                        "Constant type {:?} is not compatible with property type: {:?} (token: {})",
                        self.value.kind,
                        property.signature.base,
                        self.token.value()
                    ));
                }

                property
                    .default
                    .set(self.value.as_ref().clone())
                    .map_err(|_| malformed_error!("Default value already set for property"))
            }
            _ => Err(malformed_error!(
                "Invalid parent type for constant - {}",
                self.token.value()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            signatures::TypeSignature,
            typesystem::{CilPrimitive, CilPrimitiveKind, ELEMENT_TYPE},
        },
        testkit::{
            builders::ConstantBuilder,
            factories::table::constant::{
                create_boolean_field, create_i4_field, create_object_field, create_r4_field,
                create_string_field, create_test_param, create_test_property,
            },
        },
    };

    #[test]
    fn test_apply_field_constant_success() {
        let field = create_i4_field("test_field");
        let constant = ConstantBuilder::field_i4_constant(1, field.clone(), 42).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to field"
        );

        // Verify the default value was set
        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(42));
    }

    #[test]
    fn test_apply_field_string_constant_success() {
        let field = create_string_field("test_field");
        let constant =
            ConstantBuilder::field_string_constant(1, field.clone(), "test_value").build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of string constant to field"
        );

        // Verify the default value was set
        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::String);
        assert_eq!(default_value.as_string(), Some("test_value".to_string()));
    }

    #[test]
    fn test_apply_field_constant_already_set() {
        let field = create_i4_field("test_field");

        // Set a default value first
        let _ = field.default.set(CilPrimitive::i4(100));

        // Try to apply another constant
        let constant = ConstantBuilder::field_i4_constant(1, field, 42).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for field"));
    }

    #[test]
    fn test_apply_property_constant_success() {
        let property = create_test_property("test_property", TypeSignature::I4);
        let constant = ConstantBuilder::property_i4_constant(1, property.clone(), 123).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to property"
        );

        // Verify the default value was set
        let default_value = property.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(123));
    }

    #[test]
    fn test_apply_property_constant_already_set() {
        let property = create_test_property("test_property", TypeSignature::I4);

        // Set a default value first
        let _ = property.default.set(CilPrimitive::i4(200));

        // Try to apply another constant
        let constant = ConstantBuilder::property_i4_constant(1, property, 123).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for property"));
    }

    #[test]
    fn test_apply_param_constant_success() {
        let param = create_test_param("test_param");
        let constant = ConstantBuilder::param_i4_constant(1, param.clone(), 456).build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Expected successful application of constant to parameter"
        );

        // Verify the default value was set
        let default_value = param.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::I4);
        assert_eq!(default_value.as_i32(), Some(456));
    }

    #[test]
    fn test_apply_param_constant_already_set() {
        let param = create_test_param("test_param");

        // Set a default value first
        let _ = param.default.set(CilPrimitive::i4(300));

        // Try to apply another constant
        let constant = ConstantBuilder::param_i4_constant(1, param, 456).build();

        let result = constant.apply();
        assert!(
            result.is_err(),
            "Expected error when default value already set"
        );

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Default value already set for param"));
    }

    #[test]
    fn test_apply_invalid_parent() {
        let constant = ConstantBuilder::invalid_parent_constant(1, 42).build();

        let result = constant.apply();
        assert!(result.is_err(), "Expected error for invalid parent type");

        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Invalid parent type for constant"));
    }

    #[test]
    fn test_multiple_constant_applications() {
        // Test applying constants to multiple fields of the same type
        let field1 = create_i4_field("field1");
        let field2 = create_i4_field("field2");

        let constant1 = ConstantBuilder::field_i4_constant(1, field1.clone(), 100).build();
        let constant2 = ConstantBuilder::field_i4_constant(2, field2.clone(), 200).build();

        // Both should succeed
        assert!(constant1.apply().is_ok());
        assert!(constant2.apply().is_ok());

        // Verify different values were set
        assert_eq!(field1.default.get().unwrap().as_i32(), Some(100));
        assert_eq!(field2.default.get().unwrap().as_i32(), Some(200));
    }

    #[test]
    fn test_edge_case_values() {
        // Test edge case values for different types

        // Test min/max i32 values
        let field_max = create_i4_field("field_max");
        let constant_max =
            ConstantBuilder::field_i4_constant(1, field_max.clone(), i32::MAX).build();
        assert!(constant_max.apply().is_ok());
        assert_eq!(field_max.default.get().unwrap().as_i32(), Some(i32::MAX));

        let field_min = create_i4_field("field_min");
        let constant_min =
            ConstantBuilder::field_i4_constant(2, field_min.clone(), i32::MIN).build();
        assert!(constant_min.apply().is_ok());
        assert_eq!(field_min.default.get().unwrap().as_i32(), Some(i32::MIN));

        // Test empty string
        let field_empty = create_string_field("field_empty");
        let constant_empty =
            ConstantBuilder::field_string_constant(3, field_empty.clone(), "").build();
        assert!(constant_empty.apply().is_ok());
        assert_eq!(
            field_empty.default.get().unwrap().as_string(),
            Some(String::new())
        );
    }

    #[test]
    fn test_apply_different_primitive_types() {
        // Test boolean constant
        let field_bool = create_boolean_field("field_bool");
        let constant_bool = ConstantBuilder::new(
            1,
            ELEMENT_TYPE::BOOLEAN,
            CilTypeReference::Field(field_bool.clone()),
            Arc::new(CilPrimitive::boolean(true)),
        )
        .build();

        let result = constant_bool.apply();
        assert!(result.is_ok());

        let default_value = field_bool.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::Boolean);
        if let crate::metadata::typesystem::CilPrimitiveData::Boolean(value) = &default_value.data {
            assert!(*value);
        } else {
            panic!("Expected Boolean primitive data");
        }

        // Test float constant
        let field_r4 = create_r4_field("field_r4");
        let constant_r4 = ConstantBuilder::new(
            2,
            ELEMENT_TYPE::R4,
            CilTypeReference::Field(field_r4.clone()),
            Arc::new(CilPrimitive::r4(std::f32::consts::PI)),
        )
        .build();

        let result = constant_r4.apply();
        assert!(result.is_ok());

        let default_value = field_r4.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::R4);
        if let crate::metadata::typesystem::CilPrimitiveData::R4(value) = &default_value.data {
            assert!((value - std::f32::consts::PI).abs() < f32::EPSILON);
        } else {
            panic!("Expected R4 primitive data");
        }
    }

    #[test]
    fn test_apply_null_constant() {
        let field = create_object_field("field_object");
        let constant = ConstantBuilder::new(
            1,
            ELEMENT_TYPE::CLASS,
            CilTypeReference::Field(field.clone()),
            Arc::new(CilPrimitive::null()),
        )
        .build();

        let result = constant.apply();
        assert!(
            result.is_ok(),
            "Null constants should be applicable to reference types"
        );

        let default_value = field.default.get().unwrap();
        assert_eq!(default_value.kind, CilPrimitiveKind::Null);
    }
}

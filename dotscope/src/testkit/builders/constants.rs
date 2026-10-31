//! Constant builders for creating mock Constant and ConstantRaw instances  
//!
//! This module provides builders for creating constant table entries with various
//! parent types (fields, parameters, properties) and constant values.

use std::sync::Arc;

use crate::metadata::{
    tables::{
        CodedIndex, CodedIndexType, Constant, ConstantRaw, ConstantRc, FieldRc, ParamRc,
        PropertyRc, TableId,
    },
    token::Token,
    typesystem::{CilPrimitive, CilTypeReference, ELEMENT_TYPE},
};

/// Builder for creating mock Constant instances
pub struct ConstantBuilder {
    rid: u32,
    token: Token,
    offset: usize,
    c_type: u8,
    parent: CilTypeReference,
    value: Arc<CilPrimitive>,
}

impl ConstantBuilder {
    pub fn new(rid: u32, c_type: u8, parent: CilTypeReference, value: Arc<CilPrimitive>) -> Self {
        Self {
            rid,
            token: Token::new(0x0B000000 + rid),
            offset: 0,
            c_type,
            parent,
            value,
        }
    }

    /// Create a constant for a field with int32 value
    pub fn field_i4_constant(rid: u32, field: FieldRc, value: i32) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::I4,
            CilTypeReference::Field(field),
            Arc::new(CilPrimitive::i4(value)),
        )
    }

    /// Create a constant for a parameter with int32 value
    pub fn param_i4_constant(rid: u32, param: ParamRc, value: i32) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::I4,
            CilTypeReference::Param(param),
            Arc::new(CilPrimitive::i4(value)),
        )
    }

    /// Create a constant for a property with int32 value
    pub fn property_i4_constant(rid: u32, property: PropertyRc, value: i32) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::I4,
            CilTypeReference::Property(property),
            Arc::new(CilPrimitive::i4(value)),
        )
    }

    /// Create a constant for a field with string value
    pub fn field_string_constant(rid: u32, field: FieldRc, value: &str) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::STRING,
            CilTypeReference::Field(field),
            Arc::new(CilPrimitive::string(value)),
        )
    }

    /// Create a constant with invalid parent (for error testing)
    pub fn invalid_parent_constant(rid: u32, value: i32) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::I4,
            CilTypeReference::None,
            Arc::new(CilPrimitive::i4(value)),
        )
    }

    /// Build the Constant instance
    pub fn build(self) -> ConstantRc {
        Arc::new(Constant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            c_type: self.c_type,
            parent: self.parent,
            value: self.value,
        })
    }
}

/// Builder for creating mock ConstantRaw instances
pub struct ConstantRawBuilder {
    rid: u32,
    token: Token,
    offset: usize,
    base: u8,
    parent: CodedIndex,
    value: u32,
}

impl ConstantRawBuilder {
    pub fn new(rid: u32, base: u8, parent: CodedIndex, value: u32) -> Self {
        Self {
            rid,
            token: Token::new(0x0B000000 + rid),
            offset: 0,
            base,
            parent,
            value,
        }
    }

    /// Create a ConstantRaw for a field with int32 value at blob offset
    pub fn field_i4_raw(rid: u32, field_rid: u32, blob_offset: u32) -> Self {
        Self::new(
            rid,
            ELEMENT_TYPE::I4,
            CodedIndex::new(TableId::Field, field_rid, CodedIndexType::HasConstant),
            blob_offset,
        )
    }

    /// Build the ConstantRaw instance
    pub fn build(self) -> ConstantRaw {
        ConstantRaw {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            base: self.base,
            padding: 0,
            parent: self.parent,
            value: self.value,
        }
    }
}

/// Create a test blob heap with some constant values
pub fn create_test_blob_with_values() -> Vec<u8> {
    let mut data = vec![0u8; 32];

    // i32 value (42) at offset 4
    data[4..8].copy_from_slice(&42i32.to_le_bytes());

    // i32 value (123) at offset 8
    data[8..12].copy_from_slice(&123i32.to_le_bytes());

    // String "Hello" at offset 12
    data[12] = 5; // String length
    data[13..18].copy_from_slice(b"Hello");

    // i32 value (999) at offset 20
    data[20..24].copy_from_slice(&999i32.to_le_bytes());

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_raw_builder() {
        let constant_raw = ConstantRawBuilder::field_i4_raw(1, 1, 4).build();

        assert_eq!(constant_raw.rid, 1);
        assert_eq!(constant_raw.base, ELEMENT_TYPE::I4);
        assert_eq!(constant_raw.parent.tag, TableId::Field);
        assert_eq!(constant_raw.parent.row, 1);
        assert_eq!(constant_raw.value, 4);
    }

    #[test]
    fn test_blob_creation() {
        let data = create_test_blob_with_values();

        // Verify we can read the values back
        let value_at_4 = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        assert_eq!(value_at_4, 42);
    }
}

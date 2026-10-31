//! Property builders for creating mock Property instances with various configurations
//!
//! This module provides builders for creating Property instances with getters, setters,
//! default values, and custom attributes.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        signatures::{SignatureProperty, TypeSignature},
        tables::{Property, PropertyAttributes, PropertyRc},
        token::Token,
        typesystem::CilPrimitive,
    },
    utils::RowList,
};

/// Property constant value types for default values
#[derive(Debug, Clone)]
pub enum PropertyConstant {
    /// 32-bit signed integer
    I4(i32),
}

impl PropertyConstant {
    /// Convert to CilPrimitive for use in tests
    pub fn to_primitive(&self) -> CilPrimitive {
        match self {
            PropertyConstant::I4(val) => CilPrimitive::i4(*val),
        }
    }
}

/// Builder for creating mock Property instances with various configurations
pub struct PropertyBuilder {
    rid: u32,
    name: String,
    signature: SignatureProperty,
    flags: PropertyAttributes,
    default_value: Option<PropertyConstant>,
}

impl PropertyBuilder {
    pub fn new(name: &str, return_type: TypeSignature) -> Self {
        Self {
            rid: 1,
            name: name.to_string(),
            signature: SignatureProperty {
                has_this: false,
                modifiers: Vec::new(),
                params: Vec::new(),
                base: return_type,
            },
            flags: PropertyAttributes::ZERO,
            default_value: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_default(mut self, default: PropertyConstant) -> Self {
        self.default_value = Some(default);
        self
    }

    /// Create a simple property with no parameters (getter/setter property)
    pub fn simple_property(name: &str, property_type: TypeSignature) -> Self {
        Self::new(name, property_type)
    }

    /// Create a property with a default constant value
    pub fn property_with_default(
        name: &str,
        property_type: TypeSignature,
        default: PropertyConstant,
    ) -> Self {
        Self::new(name, property_type).with_default(default)
    }

    /// Build the Property instance
    pub fn build(self) -> PropertyRc {
        let token = Token::new(0x17000000 + self.rid);
        let property = Property {
            token,
            flags: self.flags,
            name: self.name,
            signature: self.signature,
            default: OnceLock::new(),
            fn_setter: OnceLock::new(),
            fn_getter: OnceLock::new(),
            fn_other: RowList::new(),
            custom_attributes: Default::default(),
        };

        let property_rc = Arc::new(property);

        // Set default value if provided
        if let Some(default) = self.default_value {
            let _ = property_rc.default.set(default.to_primitive());
        }

        property_rc
    }
}

/// Create a property that accepts constants (int32 type)
pub fn property_accepting_constants(name: &str) -> PropertyRc {
    PropertyBuilder::simple_property(name, TypeSignature::I4).build()
}

/// Create a property that doesn't accept certain constants (object type)
pub fn property_rejecting_constants(name: &str) -> PropertyRc {
    PropertyBuilder::simple_property(name, TypeSignature::Object).build()
}

/// Create a property with a pre-set default value
pub fn property_with_default_set(name: &str, default: PropertyConstant) -> PropertyRc {
    PropertyBuilder::property_with_default(name, TypeSignature::I4, default).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_builder_basic() {
        let property = PropertyBuilder::new("TestProperty", TypeSignature::I4)
            .with_rid(42)
            .build();

        assert_eq!(property.name, "TestProperty");
        assert_eq!(property.signature.base, TypeSignature::I4);
        assert_eq!(property.token.value(), 0x1700002A);
    }

    #[test]
    fn test_property_with_default() {
        let property = PropertyBuilder::property_with_default(
            "DefaultProp",
            TypeSignature::I4,
            PropertyConstant::I4(123),
        )
        .build();

        assert!(property.default.get().is_some());
        let default = property.default.get().unwrap();
        assert_eq!(
            default.data,
            crate::metadata::typesystem::CilPrimitiveData::I4(123)
        );
    }

    #[test]
    fn test_helper_functions() {
        let accepting = property_accepting_constants("AcceptsProp");
        assert_eq!(accepting.signature.base, TypeSignature::I4);

        let rejecting = property_rejecting_constants("RejectsProp");
        assert_eq!(rejecting.signature.base, TypeSignature::Object);

        let with_default = property_with_default_set("DefaultProp", PropertyConstant::I4(456));
        assert!(with_default.default.get().is_some());
    }
}

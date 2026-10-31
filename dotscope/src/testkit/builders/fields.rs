//! Field builders for creating mock field instances with various configurations
//!
//! This module provides builders for creating Field instances with access modifiers,
//! layouts, marshalling descriptors, constants, and other field-related metadata.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        signatures::{SignatureField, TypeSignature},
        tables::{Field, FieldAttributes, FieldRc, TypeAttributes},
        token::Token,
        typesystem::{CilFlavor, CilTypeRc},
    },
    utils::LazyList,
};

/// Builder for creating mock Field instances with various configurations
pub struct FieldBuilder {
    rid: u32,
    name: String,
    field_type: Option<CilTypeRc>,
    flags: FieldAttributes,
    rva: Option<u32>, // For fields with RVA (static data)
}

impl FieldBuilder {
    pub fn new(name: &str, field_type: CilTypeRc) -> Self {
        Self {
            rid: 1,
            name: name.to_string(),
            field_type: Some(field_type),
            flags: FieldAttributes::PUBLIC,
            rva: None,
        }
    }

    /// The field's attributes (public by default).
    #[must_use]
    pub fn flags(mut self, flags: FieldAttributes) -> Self {
        self.flags = flags;
        self
    }

    /// Create a simple int32 field
    pub fn simple_i4_field(name: &str) -> Self {
        let i4_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000001),
            "System".to_string(),
            "Int32".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::I4),
        ));
        Self::new(name, i4_type)
    }

    /// Create a simple string field
    pub fn simple_string_field(name: &str) -> Self {
        let string_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000002),
            "System".to_string(),
            "String".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::String),
        ));
        Self::new(name, string_type)
    }

    /// Create a simple boolean field
    pub fn simple_boolean_field(name: &str) -> Self {
        let bool_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000003),
            "System".to_string(),
            "Boolean".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::Boolean),
        ));
        Self::new(name, bool_type)
    }

    /// Create a simple float32 field
    pub fn simple_r4_field(name: &str) -> Self {
        let r4_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000004),
            "System".to_string(),
            "Single".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::R4),
        ));
        Self::new(name, r4_type)
    }

    /// Create a simple object field
    pub fn simple_object_field(name: &str) -> Self {
        let object_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000005),
            "System".to_string(),
            "Object".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::Object),
        ));
        Self::new(name, object_type)
    }

    pub fn build(self) -> FieldRc {
        // Create field signature based on the field type
        // The field's type as a signature: primitives and strings by their element type, any
        // other type as int32
        let base = match self
            .field_type
            .as_ref()
            .map(|field_type| field_type.flavor())
        {
            Some(CilFlavor::Void) => TypeSignature::Void,
            Some(CilFlavor::Boolean) => TypeSignature::Boolean,
            Some(CilFlavor::Char) => TypeSignature::Char,
            Some(CilFlavor::I1) => TypeSignature::I1,
            Some(CilFlavor::U1) => TypeSignature::U1,
            Some(CilFlavor::I2) => TypeSignature::I2,
            Some(CilFlavor::U2) => TypeSignature::U2,
            Some(CilFlavor::U4) => TypeSignature::U4,
            Some(CilFlavor::I8) => TypeSignature::I8,
            Some(CilFlavor::U8) => TypeSignature::U8,
            Some(CilFlavor::R4) => TypeSignature::R4,
            Some(CilFlavor::R8) => TypeSignature::R8,
            Some(CilFlavor::I) => TypeSignature::I,
            Some(CilFlavor::U) => TypeSignature::U,
            Some(CilFlavor::String) => TypeSignature::String,
            Some(CilFlavor::Object) => TypeSignature::Object,
            _ => TypeSignature::I4,
        };
        let signature = SignatureField {
            modifiers: Vec::new(),
            base,
        };

        // Create field with OnceLock fields
        let field = Field {
            rid: self.rid,
            token: Token::new(0x04000000 + self.rid),
            offset: self.rid as usize,
            flags: self.flags,
            name: self.name,
            signature,
            default: OnceLock::new(),
            rva: OnceLock::new(),
            layout: OnceLock::new(),
            marshal: OnceLock::new(),
            custom_attributes: Default::default(),
            declaring_type: OnceLock::new(),
        };

        let field_rc = Arc::new(field);

        if let Some(rva_val) = self.rva {
            let _ = field_rc.rva.set(rva_val);
        }

        field_rc
    }
}

impl Default for FieldBuilder {
    fn default() -> Self {
        // We need a default type, let's create a simple one
        let default_type = Arc::new(crate::metadata::typesystem::CilType::new(
            Token::new(0x02000001),
            "System".to_string(),
            "Int32".to_string(),
            None,
            None,
            TypeAttributes::ZERO,
            Arc::new(boxcar::Vec::new()),
            LazyList::new(),
            Some(CilFlavor::I4),
        ));

        Self::new("DefaultField", default_type)
    }
}

//! Parameter builders for creating mock Param instances for method testing
//!
//! This module provides builders for creating Param instances with various
//! characteristics including input/output parameters, defaults, and marshalling.

use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    metadata::{
        marshalling::MarshallingInfo,
        tables::{Param, ParamRc},
        token::Token,
        typesystem::{CilFlavor, CilTypeRef, CompleteTypeSpec, TypeRegistry, TypeSource},
    },
    prelude::{CilPrimitiveKind, ParamAttributes},
    testkit::{
        builders::FieldBuilder, factories::metadata::customattributes::get_test_type_registry,
    },
};

/// Builder for creating mock Param instances
pub struct ParamBuilder {
    rid: u32,
    sequence: u32,
    name: Option<String>,
    flags: ParamAttributes,
    marshal_info: Option<MarshallingInfo>,
    is_optional: bool,
    type_flavor: Option<CilFlavor>,
}

impl ParamBuilder {
    /// Create a new parameter builder
    pub fn new(sequence: u32, name: Option<String>) -> Self {
        Self {
            rid: sequence,
            sequence,
            name,
            flags: ParamAttributes::ZERO,
            marshal_info: None,
            is_optional: false,
            type_flavor: None,
        }
    }

    /// Create a named input parameter
    pub fn input_param(sequence: u32, name: &str) -> Self {
        Self::new(sequence, Some(name.to_string()))
    }

    /// Set the parameter type from a CilFlavor
    pub fn with_type_from_flavor(mut self, flavor: CilFlavor) -> Self {
        // Store the flavor - it will be resolved to an actual type during build()
        self.type_flavor = Some(flavor);
        self
    }

    /// Build the Param instance
    ///
    /// # Arguments
    /// * `type_registry` - Optional TypeRegistry for resolving parameter types.
    ///   If None, uses a shared default test registry.
    pub fn build(self, type_registry: Option<&Arc<TypeRegistry>>) -> ParamRc {
        let mut flags = self.flags;

        // Every builder parameter is an input parameter
        flags |= ParamAttributes::IN;

        // Set optional flag
        if self.is_optional {
            flags |= ParamAttributes::OPTIONAL;
        }

        // Set marshal flag
        if self.marshal_info.is_some() {
            flags |= ParamAttributes::HAS_FIELD_MARSHAL;
        }

        let param = Arc::new(Param {
            rid: self.rid,
            token: Token::new(0x08000000 + self.rid),
            offset: 0,
            flags,
            sequence: self.sequence,
            name: self.name.map(Into::into),
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(false),
            custom_attributes: Default::default(),
        });

        // Set marshal info if provided
        if let Some(marshal) = self.marshal_info {
            let _ = param.marshal.set(marshal);
        }

        // Set parameter type if provided
        if let Some(flavor) = self.type_flavor {
            // Use provided registry or get the shared test registry for backwards compatibility
            let registry = type_registry
                .cloned()
                .unwrap_or_else(get_test_type_registry);

            let param_type = match flavor {
                CilFlavor::Boolean => registry.get_primitive(CilPrimitiveKind::Boolean).unwrap(),
                CilFlavor::Char => registry.get_primitive(CilPrimitiveKind::Char).unwrap(),
                CilFlavor::I1 => registry.get_primitive(CilPrimitiveKind::I1).unwrap(),
                CilFlavor::U1 => registry.get_primitive(CilPrimitiveKind::U1).unwrap(),
                CilFlavor::I2 => registry.get_primitive(CilPrimitiveKind::I2).unwrap(),
                CilFlavor::U2 => registry.get_primitive(CilPrimitiveKind::U2).unwrap(),
                CilFlavor::I4 => registry.get_primitive(CilPrimitiveKind::I4).unwrap(),
                CilFlavor::U4 => registry.get_primitive(CilPrimitiveKind::U4).unwrap(),
                CilFlavor::I8 => registry.get_primitive(CilPrimitiveKind::I8).unwrap(),
                CilFlavor::U8 => registry.get_primitive(CilPrimitiveKind::U8).unwrap(),
                CilFlavor::R4 => registry.get_primitive(CilPrimitiveKind::R4).unwrap(),
                CilFlavor::R8 => registry.get_primitive(CilPrimitiveKind::R8).unwrap(),
                CilFlavor::I => registry.get_primitive(CilPrimitiveKind::I).unwrap(),
                CilFlavor::U => registry.get_primitive(CilPrimitiveKind::U).unwrap(),
                CilFlavor::String => registry.get_primitive(CilPrimitiveKind::String).unwrap(),
                CilFlavor::Object => registry.get_primitive(CilPrimitiveKind::Object).unwrap(),
                CilFlavor::Void => registry.get_primitive(CilPrimitiveKind::Void).unwrap(),
                CilFlavor::Class => {
                    // For Class flavor, use System.Type (the most common Class parameter type)
                    // This is correct because custom attributes typically use System.Type parameters
                    registry
                        .get_or_create_type(&CompleteTypeSpec {
                            token_init: None,
                            flavor: CilFlavor::Class,
                            namespace: "System".into(),
                            name: "Type".into(),
                            source: TypeSource::Unknown,
                            generic_args: None,
                            base_type: None,
                            flags: None,
                        })
                        .unwrap()
                }
                CilFlavor::ValueType => {
                    // For ValueType flavor in tests, create an enum type
                    // Use a unique name to avoid conflicts with Class flavor tests
                    // First get System.Enum as the base type
                    let enum_base = registry
                        .get_or_create_type(&CompleteTypeSpec {
                            token_init: None,
                            flavor: CilFlavor::Class,
                            namespace: "System".into(),
                            name: "Enum".into(),
                            source: TypeSource::Unknown,
                            generic_args: None,
                            base_type: None,
                            flags: None,
                        })
                        .unwrap();

                    // Get System.Int32 as the underlying type for the value__ field
                    let int32_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();

                    // Create test enum type that inherits from System.Enum
                    // Use TestEnum instead of TestType to avoid collision with Class flavor
                    let test_enum = registry
                        .get_or_create_type(&CompleteTypeSpec {
                            token_init: None,
                            flavor: CilFlavor::ValueType,
                            namespace: "System".into(),
                            name: "TestEnum".into(),
                            source: TypeSource::Unknown,
                            generic_args: None,
                            base_type: Some(enum_base),
                            flags: None,
                        })
                        .unwrap();

                    // Add required value__ field for enum types (ECMA-335 requirement)
                    let value_field = FieldBuilder::new("value__", int32_type).build();

                    // Add the value__ field to the enum type
                    test_enum.fields.push(value_field);

                    test_enum
                }
                other_flavor => registry
                    .get_or_create_type(&CompleteTypeSpec {
                        token_init: None,
                        flavor: other_flavor,
                        namespace: "System".into(),
                        name: "TestType".into(),
                        source: TypeSource::Unknown,
                        generic_args: None,
                        base_type: None,
                        flags: None,
                    })
                    .unwrap(),
            };

            let _ = param.base.set(CilTypeRef::from(param_type));
        }

        param
    }
}

impl Default for ParamBuilder {
    fn default() -> Self {
        Self::new(1, Some("param".to_string()))
    }
}

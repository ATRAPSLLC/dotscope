//! Utilities for handling .NET enum types across the metadata system.
//!
//! This module provides centralized functionality for determining enum underlying types
//! and parsing enum values from binary data. It's used by custom attributes, security
//! permissions, and other metadata parsers that need to handle enum values.

use std::sync::Arc;

use crate::{
    file::parser::Parser,
    metadata::{
        signatures::TypeSignature,
        typesystem::{CilTypeRc, TypeRegistry},
    },
    ParseFailure, ParseStage, Result,
};

/// Utilities for working with .NET enum types
pub struct EnumUtils;

impl EnumUtils {
    /// Determines if a type name represents an enum using TypeRegistry lookup
    ///
    /// # Arguments
    /// * `type_name` - Full type name to check
    /// * `registry` - Type registry for cross-assembly lookups
    ///
    /// # Returns
    /// `true` if the type is an enum, `false` otherwise
    pub fn is_enum_type_by_name(type_name: &str, registry: &Arc<TypeRegistry>) -> bool {
        if let Some(type_ref) = registry.resolve_type_global(type_name) {
            Self::is_enum_type(&type_ref, Some(registry))
        } else {
            false
        }
    }

    /// Whether a type is an enum (ECMA-335 II.14.3): it derives from `System.Enum` and has
    /// exactly one instance field, which holds the value whatever it is named (compilers name
    /// it `value__`; renaming obfuscators need not keep that). An array of enums, whose base
    /// is its element type, has none.
    ///
    /// # Arguments
    /// * `type_ref` - The type to check
    /// * `registry` - Optional type registry for cross-assembly lookups
    ///
    /// # Returns
    /// `true` if the type is an enum, `false` otherwise
    pub fn is_enum_type(type_ref: &CilTypeRc, registry: Option<&Arc<TypeRegistry>>) -> bool {
        let instance_fields = type_ref
            .fields
            .iter()
            .filter(|(_, field)| !field.flags.is_static())
            .count();
        if instance_fields != 1 {
            return false;
        }

        // System.Enum's derivation
        if let Some(parent_type) = type_ref.base() {
            parent_type.name == "Enum" && parent_type.namespace == "System"
        } else {
            // Try registry-based lookup if available
            if let Some(reg) = registry {
                Self::check_enum_inheritance_with_registry(type_ref, reg)
            } else {
                false
            }
        }
    }

    /// Gets the underlying type size of an enum by name using TypeRegistry lookup
    ///
    /// # Arguments
    /// * `type_name` - Full type name of the enum
    /// * `registry` - Type registry for cross-assembly lookups
    ///
    /// # Returns
    /// Size in bytes (1, 2, 4, or 8), or 0 if cannot be determined
    pub fn get_enum_underlying_type_size_by_name(
        type_name: &str,
        registry: &Arc<TypeRegistry>,
    ) -> usize {
        if let Some(type_ref) = registry.resolve_type_global(type_name) {
            Self::get_enum_underlying_type_size(&type_ref)
        } else {
            0
        }
    }

    /// The size in bytes of an enum's underlying type: the type of its one instance field
    /// (ECMA-335 II.14.3), whatever the field is named.
    ///
    /// # Arguments
    /// * `type_ref` - The enum type to analyze
    ///
    /// # Returns
    /// 1, 2, 4 or 8; 0 when the type has no instance field of a sized type. A native integer
    /// (`IntPtr`, `UIntPtr`) is as wide as the target's pointers, which the type does not
    /// say, and no custom attribute can hold one (II.23.3), so it is 0 as well.
    pub fn get_enum_underlying_type_size(type_ref: &CilTypeRc) -> usize {
        let Some((_, field)) = type_ref
            .fields
            .iter()
            .find(|(_, field)| !field.flags.is_static())
        else {
            return 0;
        };
        match &field.signature.base {
            TypeSignature::I1 | TypeSignature::U1 | TypeSignature::Boolean => 1,
            TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
            TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
            TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,
            _ => 0,
        }
    }

    /// Parses an enum value from binary data based on its underlying type size.
    ///
    /// # Arguments
    /// * `parser` - The parser to read from
    /// * `size_bytes` - Size of the underlying type in bytes
    ///
    /// # Returns
    /// The enum value as an i64, or an error if parsing fails
    pub fn parse_enum_value(parser: &mut Parser, size_bytes: usize) -> Result<i64> {
        match size_bytes {
            1 => Ok(i64::from(parser.read_le::<u8>()?)),
            2 => Ok(i64::from(parser.read_le::<u16>()?)),
            4 => Ok(i64::from(parser.read_le::<i32>()?)),
            8 => parser.read_le::<i64>(),
            _ => Err(ParseFailure::InvalidField {
                stage: ParseStage::Generic,
                field: "enum_underlying_type_size",
                reason: format!("invalid size: {size_bytes} bytes"),
            }
            .into()),
        }
    }

    /// Formats an enum value for display purposes.
    ///
    /// # Arguments
    /// * `type_name` - Name of the enum type
    /// * `value` - The enum value
    ///
    /// # Returns
    /// A formatted string representation
    pub fn format_enum_value(type_name: &str, value: i64) -> String {
        format!("{type_name}({value})")
    }

    /// Helper method to check enum inheritance using the type registry
    fn check_enum_inheritance_with_registry(
        type_ref: &CilTypeRc,
        registry: &Arc<TypeRegistry>,
    ) -> bool {
        Self::check_enum_inheritance_with_registry_recursive(type_ref, registry, 0)
    }

    /// Recursive helper with depth limit for enum inheritance checking
    fn check_enum_inheritance_with_registry_recursive(
        type_ref: &CilTypeRc,
        registry: &Arc<TypeRegistry>,
        depth: u32,
    ) -> bool {
        const MAX_INHERITANCE_DEPTH: u32 = 32;

        if depth >= MAX_INHERITANCE_DEPTH {
            return false;
        }

        if let Some(base_type) = type_ref.base() {
            if base_type.name == "Enum" && base_type.namespace == "System" {
                return true;
            }

            let base_fullname = base_type.fullname();
            if let Some(resolved_base) = registry.resolve_type_global(&base_fullname) {
                if resolved_base.name == "Enum" && resolved_base.namespace == "System" {
                    return true;
                }

                return Self::check_enum_inheritance_with_registry_recursive(
                    &resolved_base,
                    registry,
                    depth.saturating_add(1),
                );
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            identity::AssemblyIdentity,
            tables::{FieldAttributes, FieldRc},
            typesystem::{CilFlavor, CilPrimitiveKind, CompleteTypeSpec, TypeSource},
        },
        testkit::builders::FieldBuilder,
    };

    /// A value type named `name` deriving from `System.Enum`, with `fields`.
    fn enum_with(registry: &TypeRegistry, name: &str, fields: Vec<FieldRc>) -> CilTypeRc {
        let spec = |flavor, namespace: &str, name: &str, base_type| CompleteTypeSpec {
            token_init: None,
            flavor,
            namespace: namespace.to_string(),
            name: name.to_string(),
            source: TypeSource::Unknown,
            generic_args: None,
            base_type,
            flags: None,
        };
        let system_enum = registry
            .get_or_create_type(&spec(CilFlavor::Class, "System", "Enum", None))
            .unwrap();
        let ty = registry
            .get_or_create_type(&spec(CilFlavor::ValueType, "Test", name, Some(system_enum)))
            .unwrap();
        for field in fields {
            ty.fields.push(field);
        }
        ty
    }

    fn registry() -> TypeRegistry {
        TypeRegistry::new(AssemblyIdentity::parse("EnumTests, Version=1.0.0.0").unwrap()).unwrap()
    }

    /// An enum's underlying type is its one instance field's, whatever its name: a renaming
    /// obfuscator's `a` holds the value as `value__` does, and static fields (the members)
    /// are not it.
    #[test]
    fn an_enum_is_its_one_instance_field_whatever_its_name() {
        let registry = registry();
        let byte = registry.get_primitive(CilPrimitiveKind::I1).unwrap();
        let int = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
        let renamed = enum_with(
            &registry,
            "Renamed",
            vec![
                FieldBuilder::new("Member", int)
                    .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC)
                    .build(),
                FieldBuilder::new("a", byte).build(),
            ],
        );
        assert!(EnumUtils::is_enum_type(&renamed, None));
        assert_eq!(EnumUtils::get_enum_underlying_type_size(&renamed), 1);

        // Deriving from System.Enum without one instance field (an array of enums) is not one
        let fieldless = enum_with(&registry, "Fieldless", Vec::new());
        assert!(!EnumUtils::is_enum_type(&fieldless, None));
    }

    /// A native integer is as wide as the target's pointers, which the type does not state:
    /// not the host's, and no custom attribute holds one.
    #[test]
    fn a_native_integer_enum_has_no_size() {
        let registry = registry();
        let native = registry.get_primitive(CilPrimitiveKind::I).unwrap();
        let ty = enum_with(
            &registry,
            "Native",
            vec![FieldBuilder::new("value__", native).build()],
        );
        assert!(EnumUtils::is_enum_type(&ty, None));
        assert_eq!(EnumUtils::get_enum_underlying_type_size(&ty), 0);
    }

    #[test]
    fn test_format_enum_value() {
        assert_eq!(
            EnumUtils::format_enum_value("System.AttributeTargets", 1),
            "System.AttributeTargets(1)"
        );
        assert_eq!(EnumUtils::format_enum_value("MyEnum", -1), "MyEnum(-1)");
    }
}

//! Encoding permissions as a permission set blob, in the formats
//! [`crate::metadata::security::PermissionSet`] decodes.
//!
//! The binary format writes each permission's class name and its properties as custom
//! attribute named arguments, so a binary set decoded and encoded again is its own bytes. The
//! XML format writes UTF-16 text whose attribute values are the properties' values as text;
//! it has no types, so encoding a binary set's permissions as XML is not what the runtime
//! would make of them (a binary set names attribute classes, an XML set permission classes).
//!
//! # Examples
//!
//! ```rust
//! use dotscope::metadata::{
//!     customattributes::{CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType},
//!     security::{encode_permission_set, Permission, PermissionSet, PermissionSetFormat},
//! };
//!
//! let permissions = vec![Permission::new(
//!     "System.Security.Permissions.SecurityPermissionAttribute, mscorlib",
//!     vec![CustomAttributeNamedArgument {
//!         is_field: false,
//!         name: "SkipVerification".to_string(),
//!         arg_type: FieldOrPropType::Bool,
//!         value: CustomAttributeArgument::Bool(true),
//!     }],
//! )];
//!
//! let blob = encode_permission_set(&permissions, PermissionSetFormat::Binary)?;
//! assert_eq!(PermissionSet::new(&blob)?.permissions(), &permissions[..]);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::{
        customattributes::{encode_named_arguments, CustomAttributeArgument},
        security::{security_classes, Permission, PermissionSetFormat},
    },
    utils::write_compressed_uint,
    Result,
};

/// Encodes `permissions` as a permission set blob in `format`.
///
/// # Errors
///
/// - [`PermissionSetFormat::Unknown`], which has no encoding.
/// - A count, name or property blob longer than a compressed integer can state.
/// - A property the named argument grammar cannot encode (see
///   [`crate::metadata::customattributes::encode_custom_attribute_argument`]).
/// - For XML: a property name that is not an XML name, or a value that has no text form (a
///   null, an array or a boxed value).
pub fn encode_permission_set(
    permissions: &[Permission],
    format: PermissionSetFormat,
) -> Result<Vec<u8>> {
    match format {
        PermissionSetFormat::Binary => encode_binary_format(permissions),
        PermissionSetFormat::Xml => encode_xml_format(permissions),
        PermissionSetFormat::Unknown => Err(malformed_error!(
            "Cannot encode unknown permission set format"
        )),
    }
}

/// Writes `length` as a compressed unsigned integer (ECMA-335 II.23.2).
fn write_length(length: usize, buffer: &mut Vec<u8>) -> Result<()> {
    let length = u32::try_from(length)
        .map_err(|_| malformed_error!("{} is too long for a compressed length", length))?;
    write_compressed_uint(length, buffer)
}

/// The binary format: `.`, the permission count, and per permission its class name (a
/// compressed length and UTF-8) and its property blob (a compressed length, then the
/// property count and the properties as named arguments), all lengths and counts compressed.
fn encode_binary_format(permissions: &[Permission]) -> Result<Vec<u8>> {
    let mut buffer = vec![b'.'];
    write_length(permissions.len(), &mut buffer)?;
    for permission in permissions {
        write_length(permission.class_name.len(), &mut buffer)?;
        buffer.extend_from_slice(permission.class_name.as_bytes());

        let mut properties = Vec::new();
        write_length(permission.named_arguments.len(), &mut properties)?;
        encode_named_arguments(&permission.named_arguments, &mut properties)?;
        write_length(properties.len(), &mut buffer)?;
        buffer.extend_from_slice(&properties);
    }
    Ok(buffer)
}

/// The XML format, as the runtime reads it: UTF-16LE text without a byte order mark, a
/// `PermissionSet` element holding an `IPermission` element per permission whose attributes
/// are its class, `version="1"` and its properties.
fn encode_xml_format(permissions: &[Permission]) -> Result<Vec<u8>> {
    let mut text = format!(
        "<PermissionSet class=\"{}\"\r\nversion=\"1\">\r\n",
        security_classes::PERMISSION_SET
    );
    for permission in permissions {
        text.push_str(&format!(
            "<IPermission class=\"{}\"\r\nversion=\"1\"",
            attribute_text(&permission.class_name)?
        ));
        for arg in &permission.named_arguments {
            let mut characters = arg.name.chars();
            let is_name = characters
                .next()
                .is_some_and(|first| first.is_alphabetic() || first == '_')
                && characters.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'));
            if !is_name {
                return Err(malformed_error!(
                    "Property '{}' of {} is not an XML attribute name",
                    arg.name,
                    permission.class_name
                ));
            }
            let value = xml_value(&arg.value).ok_or_else(|| {
                malformed_error!(
                    "Property '{}' of {} has no XML text form: {}",
                    arg.name,
                    permission.class_name,
                    arg.value
                )
            })?;
            text.push_str(&format!("\r\n{}=\"{}\"", arg.name, attribute_text(&value)?));
        }
        text.push_str("/>\r\n");
    }
    text.push_str("</PermissionSet>\r\n");
    Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect())
}

/// `value` as an XML attribute value reads it back: markup characters as entities, and a tab,
/// newline or carriage return as a character reference, which attribute-value normalization
/// keeps where it turns the characters themselves into spaces.
///
/// # Errors
///
/// When `value` holds a character XML 1.0 cannot represent at all: another control
/// character, or U+FFFE or U+FFFF.
fn attribute_text(value: &str) -> Result<String> {
    let mut text = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => text.push_str("&amp;"),
            '<' => text.push_str("&lt;"),
            '>' => text.push_str("&gt;"),
            '"' => text.push_str("&quot;"),
            '\'' => text.push_str("&apos;"),
            '\t' => text.push_str("&#9;"),
            '\n' => text.push_str("&#10;"),
            '\r' => text.push_str("&#13;"),
            '\u{0}'..='\u{1F}' | '\u{FFFE}' | '\u{FFFF}' => {
                return Err(malformed_error!(
                    "U+{:04X} cannot be written in an XML permission set",
                    u32::from(character)
                ))
            }
            other => text.push(other),
        }
    }
    Ok(text)
}

/// The text an XML permission set gives `value`: a string as itself, a number in decimal,
/// an enum as its underlying number. `None` for what has no text form.
fn xml_value(value: &CustomAttributeArgument) -> Option<String> {
    Some(match value {
        CustomAttributeArgument::Bool(v) => v.to_string(),
        CustomAttributeArgument::Char(v) => char::from_u32(u32::from(*v))?.to_string(),
        CustomAttributeArgument::I1(v) => v.to_string(),
        CustomAttributeArgument::U1(v) => v.to_string(),
        CustomAttributeArgument::I2(v) => v.to_string(),
        CustomAttributeArgument::U2(v) => v.to_string(),
        CustomAttributeArgument::I4(v) => v.to_string(),
        CustomAttributeArgument::U4(v) => v.to_string(),
        CustomAttributeArgument::I8(v) => v.to_string(),
        CustomAttributeArgument::U8(v) => v.to_string(),
        CustomAttributeArgument::R4(v) => v.to_string(),
        CustomAttributeArgument::R8(v) => v.to_string(),
        CustomAttributeArgument::String(Some(v)) | CustomAttributeArgument::Type(Some(v)) => {
            v.clone()
        }
        CustomAttributeArgument::Enum(_, underlying) => return xml_value(underlying),
        CustomAttributeArgument::String(None)
        | CustomAttributeArgument::Type(None)
        | CustomAttributeArgument::Array(..)
        | CustomAttributeArgument::Boxed(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{
        metadata::{
            customattributes::{CustomAttributeNamedArgument, FieldOrPropType},
            security::PermissionSet,
        },
        testkit::{arb, arb::check},
    };

    fn property(name: &str, value: CustomAttributeArgument) -> CustomAttributeNamedArgument {
        CustomAttributeNamedArgument {
            is_field: false,
            name: name.to_string(),
            arg_type: value.field_or_prop_type().unwrap(),
            value,
        }
    }

    #[test]
    fn a_binary_set_encodes_to_the_bytes_it_decodes_from() {
        let flag = "System.Security.Permissions.SecurityPermissionFlag, mscorlib".to_string();
        let permissions = vec![
            Permission::new(
                "System.Security.Permissions.SecurityPermissionAttribute, mscorlib",
                vec![
                    property(
                        "Flags",
                        CustomAttributeArgument::Enum(
                            flag,
                            Box::new(CustomAttributeArgument::I4(0x0A)),
                        ),
                    ),
                    property("Unrestricted", CustomAttributeArgument::Bool(false)),
                ],
            ),
            Permission::new(
                "System.Security.Permissions.UIPermissionAttribute, mscorlib",
                Vec::new(),
            ),
            Permission::new(
                "System.Security.Permissions.FileIOPermissionAttribute, mscorlib",
                vec![CustomAttributeNamedArgument {
                    is_field: true,
                    name: "Read".to_string(),
                    arg_type: FieldOrPropType::String,
                    value: CustomAttributeArgument::String(Some("C:\\Data".to_string())),
                }],
            ),
        ];
        let blob = encode_permission_set(&permissions, PermissionSetFormat::Binary).unwrap();
        let set = PermissionSet::new(&blob).unwrap();
        assert_eq!(set.permissions(), &permissions[..]);
        assert_eq!(
            encode_permission_set(set.permissions(), PermissionSetFormat::Binary).unwrap(),
            blob
        );

        // The property blob is the count and the named arguments, and its length precedes it
        let ui = b"System.Security.Permissions.UIPermissionAttribute, mscorlib";
        let at = blob
            .windows(ui.len())
            .position(|window| window == ui)
            .unwrap()
            + ui.len();
        assert_eq!(&blob[at..at + 2], &[0x01, 0x00]);
    }

    #[test]
    fn an_empty_binary_set_is_the_marker_and_a_zero_count() {
        assert_eq!(
            encode_permission_set(&[], PermissionSetFormat::Binary).unwrap(),
            vec![b'.', 0x00]
        );
    }

    #[test]
    fn an_xml_set_is_utf16_text_the_decoder_reads_back_as_strings() {
        let permissions = vec![Permission::new(
            "System.Security.Permissions.FileIOPermission, mscorlib",
            vec![
                property("Unrestricted", CustomAttributeArgument::Bool(false)),
                property(
                    "Read",
                    CustomAttributeArgument::String(Some("C:\\a&\"b\"".to_string())),
                ),
                property(
                    "Flags",
                    CustomAttributeArgument::Enum(
                        "Ns.Access".to_string(),
                        Box::new(CustomAttributeArgument::I4(3)),
                    ),
                ),
            ],
        )];
        let blob = encode_permission_set(&permissions, PermissionSetFormat::Xml).unwrap();
        assert_eq!(&blob[..4], &[b'<', 0x00, b'P', 0x00]);

        let set = PermissionSet::new(&blob).unwrap();
        assert_eq!(set.format(), &PermissionSetFormat::Xml);
        let permission = &set.permissions()[0];
        assert_eq!(permission.class_name, permissions[0].class_name);
        let values: Vec<_> = permission
            .named_arguments
            .iter()
            .map(|arg| (arg.name.as_str(), arg.value.clone()))
            .collect();
        let text = |s: &str| CustomAttributeArgument::String(Some(s.to_string()));
        assert_eq!(
            values,
            vec![
                ("Unrestricted", text("false")),
                ("Read", text("C:\\a&\"b\"")),
                ("Flags", text("3")),
            ]
        );
    }

    #[test]
    fn what_xml_cannot_hold_is_an_error() {
        let with = |name: &str, value| {
            encode_permission_set(
                &[Permission::new("A", vec![property(name, value)])],
                PermissionSetFormat::Xml,
            )
        };
        assert!(with("Read", CustomAttributeArgument::String(None)).is_err());
        assert!(with(
            "Paths",
            CustomAttributeArgument::Array(FieldOrPropType::String, Some(Vec::new()))
        )
        .is_err());
        assert!(with("Bad Name", CustomAttributeArgument::Bool(true)).is_err());
        assert!(with("a=\"b", CustomAttributeArgument::Bool(true)).is_err());
        assert!(with("Ok", CustomAttributeArgument::Bool(true)).is_ok());
    }

    #[test]
    fn the_unknown_format_has_no_encoding() {
        assert!(encode_permission_set(&[], PermissionSetFormat::Unknown).is_err());
    }

    /// Every binary permission set decodes to the permissions it was encoded from, compared
    /// by what they print (NaN payloads aside) and by their bytes written again.
    #[test]
    fn every_binary_set_decodes_to_what_was_encoded() {
        check(arb::permissions(), |permissions| {
            let bytes = encode_permission_set(&permissions, PermissionSetFormat::Binary)
                .map_err(|error| TestCaseError::fail(format!("does not encode: {error}")))?;
            let set = PermissionSet::new(&bytes).map_err(|error| {
                TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
            })?;
            prop_assert_eq!(
                format!("{:?}", set.permissions()),
                format!("{permissions:?}")
            );
            prop_assert_eq!(
                encode_permission_set(set.permissions(), PermissionSetFormat::Binary).ok(),
                Some(bytes)
            );
            Ok(())
        });
    }

    /// Every set the XML encoder accepts decodes to its permissions with each value as its
    /// text: XML holds no types.
    #[test]
    fn every_xml_set_decodes_to_the_text_of_its_values() {
        check(arb::permissions(), |permissions| {
            let Ok(bytes) = encode_permission_set(&permissions, PermissionSetFormat::Xml) else {
                return Ok(());
            };
            let set = PermissionSet::new(&bytes).map_err(|error| {
                TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
            })?;
            prop_assert_eq!(set.format(), &PermissionSetFormat::Xml);
            prop_assert_eq!(set.permissions().len(), permissions.len());
            for (decoded, encoded) in set.permissions().iter().zip(&permissions) {
                prop_assert_eq!(&decoded.class_name, &encoded.class_name);
                let texts: Vec<_> = encoded
                    .named_arguments
                    .iter()
                    .map(|arg| (arg.name.clone(), xml_value(&arg.value)))
                    .collect();
                let decoded_texts: Vec<_> = decoded
                    .named_arguments
                    .iter()
                    .map(|arg| match &arg.value {
                        CustomAttributeArgument::String(text) => (arg.name.clone(), text.clone()),
                        other => (arg.name.clone(), Some(format!("not a string: {other}"))),
                    })
                    .collect();
                prop_assert_eq!(decoded_texts, texts);
            }
            Ok(())
        });
    }

    /// XML normalizes whitespace in attribute values: a tab, newline or carriage return the
    /// value holds is written as a character reference, which survives.
    #[test]
    fn whitespace_in_an_xml_value_survives() {
        let text = "a\tb\nc\r\nd  e";
        let permissions = vec![Permission::new(
            "A",
            vec![property(
                "Read",
                CustomAttributeArgument::String(Some(text.to_string())),
            )],
        )];
        let bytes = encode_permission_set(&permissions, PermissionSetFormat::Xml).unwrap();
        let set = PermissionSet::new(&bytes).unwrap();
        assert_eq!(
            set.permissions()[0].named_arguments[0].value,
            CustomAttributeArgument::String(Some(text.to_string()))
        );
    }
}

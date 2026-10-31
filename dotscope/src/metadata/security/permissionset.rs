//! A `DeclSecurity` row's permission set (ECMA-335 II.22.11), decoded from its blob.
//!
//! The blob comes in two formats, which its first byte tells apart:
//!
//! - **Binary** (`.`, what compilers write since .NET Framework 2.0): a compressed count, then
//!   per permission its attribute class's assembly-qualified name (a compressed length and
//!   UTF-8), and a length-prefixed blob holding a compressed property count and the
//!   properties, each a custom attribute named argument (ECMA-335 II.23.3).
//! - **XML** (.NET Framework 1.x): UTF-16 text, a `<PermissionSet>` element with an
//!   `<IPermission class="..." version="1" .../>` element per permission. An attribute's value
//!   is text: the set does not say its type, so it decodes as a string.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::metadata::security::{PermissionSet, PermissionSetFormat};
//!
//! // `[assembly: SecurityPermission(SecurityAction.RequestMinimum, SkipVerification = true)]`
//! let mut blob = vec![b'.', 0x01];
//! let class = b"System.Security.Permissions.SecurityPermissionAttribute, mscorlib";
//! blob.push(class.len() as u8);
//! blob.extend_from_slice(class);
//! let properties = [&[0x01, 0x54, 0x02, 0x10][..], b"SkipVerification", &[0x01]].concat();
//! blob.push(properties.len() as u8);
//! blob.extend_from_slice(&properties);
//!
//! let set = PermissionSet::new(&blob)?;
//! assert_eq!(set.format(), &PermissionSetFormat::Binary);
//! assert!(set.has_security());
//! assert_eq!(set.permissions()[0].named_arguments[0].name, "SkipVerification");
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::fmt;

use quick_xml::{
    events::{attributes::Attributes, Event},
    Reader, XmlVersion,
};

use crate::{
    file::parser::Parser,
    metadata::{
        customattributes::{
            CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeParser,
            FieldOrPropType,
        },
        security::{security_classes, Permission, PermissionSetFormat, SecurityPermissionFlags},
    },
    Result,
};

/// The permissions a permission set blob names.
#[derive(Debug, Clone)]
pub struct PermissionSet {
    /// The format of the blob
    format: PermissionSetFormat,
    /// The permissions, in the order the blob names them
    permissions: Vec<Permission>,
    /// Whether an XML set's root says `Unrestricted="true"`
    unrestricted: bool,
    /// The blob
    data: Vec<u8>,
}

impl PermissionSet {
    /// Decodes a permission set blob.
    ///
    /// A blob in neither format decodes as [`PermissionSetFormat::Unknown`] with no
    /// permissions.
    ///
    /// # Errors
    ///
    /// When `data` is empty, or a binary or XML set does not decode.
    pub fn new(data: &[u8]) -> Result<Self> {
        let first = *data
            .first()
            .ok_or_else(|| malformed_error!("PermissionSet data is empty"))?;

        let (format, permissions, unrestricted) = if first == b'.' {
            (
                PermissionSetFormat::Binary,
                Self::parse_binary_format(data)?,
                false,
            )
        } else if let Some(text) = Self::xml_text(data) {
            let (permissions, unrestricted) = Self::parse_xml_format(&text?)?;
            (PermissionSetFormat::Xml, permissions, unrestricted)
        } else {
            (PermissionSetFormat::Unknown, Vec::new(), false)
        };

        Ok(PermissionSet {
            format,
            permissions,
            unrestricted,
            data: data.to_vec(),
        })
    }

    /// Decodes a binary permission set: `.`, a compressed permission count, and per
    /// permission its class name (a compressed length and UTF-8) and its property blob (a
    /// compressed length, then a compressed property count and the properties as custom
    /// attribute named arguments).
    fn parse_binary_format(data: &[u8]) -> Result<Vec<Permission>> {
        let mut parser = Parser::new(data);
        parser.advance()?;
        let count = parser.read_compressed_uint()? as usize;

        // Each permission takes at least two bytes, so what is left bounds the count
        let mut permissions = Vec::with_capacity(count.min(parser.remaining()));
        for index in 0..count {
            let name_length = parser.read_compressed_uint()? as usize;
            let name = parser.read_bytes(name_length).map_err(|_| {
                malformed_error!(
                    "Permission {}: a class name of {} bytes runs past the permission set",
                    index,
                    name_length
                )
            })?;
            let class_name = std::str::from_utf8(name)
                .map_err(|e| {
                    malformed_error!("Permission {}: class name is not UTF-8: {}", index, e)
                })?
                .to_string();

            let blob_length = parser.read_compressed_uint()? as usize;
            let blob = parser.read_bytes(blob_length).map_err(|_| {
                malformed_error!(
                    "Permission '{}': a property blob of {} bytes runs past the permission set",
                    class_name,
                    blob_length
                )
            })?;
            let named_arguments = if blob.is_empty() {
                Vec::new()
            } else {
                let mut properties = Parser::new(blob);
                let property_count = properties.read_compressed_uint()? as usize;
                CustomAttributeParser::new(blob.get(properties.pos()..).unwrap_or_default())
                    .parse_named_arguments(property_count)
                    .map_err(|e| {
                        malformed_error!("Permission '{}': properties: {}", class_name, e)
                    })?
            };

            permissions.push(Permission::new(class_name, named_arguments));
        }

        Ok(permissions)
    }

    /// The text of an XML permission set, or `None` when `data` is not XML: UTF-16LE (what
    /// the runtime reads, with or without a byte order mark) when its first character is
    /// `<` in UTF-16, else UTF-8 when it starts with `<` or the UTF-8 byte order mark.
    fn xml_text(data: &[u8]) -> Option<Result<String>> {
        let utf16 = |bytes: &[u8]| -> Result<String> {
            let (pairs, odd) = bytes.as_chunks::<2>();
            if !odd.is_empty() {
                return Err(malformed_error!(
                    "UTF-16 permission set of odd length {}",
                    bytes.len()
                ));
            }
            let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
            String::from_utf16(&units)
                .map_err(|e| malformed_error!("Permission set is not UTF-16: {}", e))
        };
        let utf8 = |bytes: &[u8]| -> Result<String> {
            String::from_utf8(bytes.to_vec())
                .map_err(|e| malformed_error!("Permission set is not UTF-8: {}", e))
        };
        match data {
            [0xFF, 0xFE, rest @ ..] => Some(utf16(rest)),
            [b'<', 0x00, ..] => Some(utf16(data)),
            [0xEF, 0xBB, 0xBF, rest @ ..] => Some(utf8(rest)),
            [b'<', ..] => Some(utf8(data)),
            _ => None,
        }
    }

    /// Decodes an XML permission set: a `PermissionSet` root, which may say
    /// `Unrestricted="true"`, holding an `IPermission` element per permission. Each element's
    /// `class` attribute names the permission and its other attributes but `version` are
    /// its properties, as strings. Elements an `IPermission` holds are not decoded.
    fn parse_xml_format(text: &str) -> Result<(Vec<Permission>, bool)> {
        let mut reader = Reader::from_str(text);
        reader.config_mut().trim_text(true);

        let mut permissions = Vec::new();
        let mut unrestricted = false;
        let mut depth = 0usize;
        loop {
            let (element, opens) = match reader.read_event() {
                Ok(Event::Start(element)) => (element, true),
                Ok(Event::Empty(element)) => (element, false),
                Ok(Event::End(_)) => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                Ok(Event::Eof) => break,
                Ok(_) => continue,
                Err(e) => return Err(malformed_error!("XML parsing error: {}", e)),
            };
            match (depth, element.name().as_ref()) {
                (0, "PermissionSet") => {
                    for attribute in element.attributes() {
                        let attribute = attribute
                            .map_err(|e| malformed_error!("Invalid XML attribute: {}", e))?;
                        if attribute.key.as_ref() == "Unrestricted" {
                            let value = attribute
                                .normalized_value(XmlVersion::Implicit1_0)
                                .map_err(|e| malformed_error!("Invalid XML attribute: {}", e))?;
                            unrestricted = value.eq_ignore_ascii_case("true");
                        }
                    }
                }
                (0, root) => {
                    return Err(malformed_error!(
                        "XML permission set has root element '{}', not PermissionSet",
                        root
                    ))
                }
                (1, "IPermission") => {
                    permissions.push(Self::parse_xml_permission(element.attributes())?);
                }
                _ => {}
            }
            if opens {
                depth = depth.saturating_add(1);
            }
        }

        Ok((permissions, unrestricted))
    }

    /// The permission an `IPermission` element's attributes describe.
    fn parse_xml_permission(attributes: Attributes) -> Result<Permission> {
        let mut class_name = None;
        let mut named_arguments = Vec::new();
        for attribute in attributes {
            let attribute =
                attribute.map_err(|e| malformed_error!("Invalid XML attribute: {}", e))?;
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|e| malformed_error!("Invalid XML attribute: {}", e))?
                .into_owned();
            match attribute.key.as_ref() {
                "class" => class_name = Some(value),
                "version" => {}
                name => named_arguments.push(CustomAttributeNamedArgument {
                    is_field: false,
                    name: name.to_string(),
                    arg_type: FieldOrPropType::String,
                    value: CustomAttributeArgument::String(Some(value)),
                }),
            }
        }
        let class_name = class_name
            .ok_or_else(|| malformed_error!("Missing class attribute in IPermission element"))?;
        Ok(Permission::new(class_name, named_arguments))
    }

    /// The format of the blob
    #[must_use]
    pub fn format(&self) -> &PermissionSetFormat {
        &self.format
    }

    /// The permissions, in the order the blob names them
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// The blob
    #[must_use]
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Whether the set holds a permission of class `class_name`, a full name without its
    /// assembly (see [`Permission::is_class`]).
    #[must_use]
    pub fn contains_permission(&self, class_name: &str) -> bool {
        self.get_permission(class_name).is_some()
    }

    /// The first permission of class `class_name`, a full name without its assembly (see
    /// [`Permission::is_class`]).
    #[must_use]
    pub fn get_permission(&self, class_name: &str) -> Option<&Permission> {
        self.permissions.iter().find(|p| p.is_class(class_name))
    }

    /// Whether this is the unrestricted permission set, which grants every permission: an
    /// XML set whose root says `Unrestricted="true"`, or a binary one holding an
    /// unrestricted `PermissionSetAttribute`.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
            || self.permissions.iter().any(|permission| {
                permission.type_name() == security_classes::PERMISSION_SET_ATTRIBUTE
                    && permission.is_unrestricted()
            })
    }

    /// Whether the set holds a `FileIOPermission`
    #[must_use]
    pub fn has_file_io(&self) -> bool {
        self.contains_permission(security_classes::FILE_IO_PERMISSION)
    }

    /// Whether the set holds a `RegistryPermission`
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.contains_permission(security_classes::REGISTRY_PERMISSION)
    }

    /// Whether the set holds a `ReflectionPermission`
    #[must_use]
    pub fn has_reflection(&self) -> bool {
        self.contains_permission(security_classes::REFLECTION_PERMISSION)
    }

    /// Whether the set holds an `EnvironmentPermission`
    #[must_use]
    pub fn has_environment(&self) -> bool {
        self.contains_permission(security_classes::ENVIRONMENT_PERMISSION)
    }

    /// Whether the set holds a `SecurityPermission`
    #[must_use]
    pub fn has_security(&self) -> bool {
        self.contains_permission(security_classes::SECURITY_PERMISSION)
    }

    /// Whether the set holds a `UIPermission`
    #[must_use]
    pub fn has_ui(&self) -> bool {
        self.contains_permission(security_classes::UI_PERMISSION)
    }

    /// Whether the set holds a `DnsPermission`
    #[must_use]
    pub fn has_dns(&self) -> bool {
        self.contains_permission(security_classes::DNS_PERMISSION)
    }

    /// Whether the set holds a `SocketPermission`
    #[must_use]
    pub fn has_socket(&self) -> bool {
        self.contains_permission(security_classes::SOCKET_PERMISSION)
    }

    /// Whether the set holds a `WebPermission`
    #[must_use]
    pub fn has_web(&self) -> bool {
        self.contains_permission(security_classes::WEB_PERMISSION)
    }

    /// Whether the set holds an `IsolatedStorageFilePermission`
    #[must_use]
    pub fn has_isolated_storage(&self) -> bool {
        self.contains_permission(security_classes::STORAGE_PERMISSION)
    }

    /// Whether the set holds a `KeyContainerPermission`
    #[must_use]
    pub fn has_key_container(&self) -> bool {
        self.contains_permission(security_classes::KEY_CONTAINER_PERMISSION)
    }

    /// Whether the set grants full trust: it is unrestricted, or it holds a
    /// `SecurityPermission` that is unrestricted or has every flag, which includes
    /// `ControlPolicy` and so the means to grant itself the rest.
    #[must_use]
    pub fn is_full_trust(&self) -> bool {
        self.is_unrestricted()
            || self
                .permissions
                .iter()
                .filter(|permission| permission.is_security())
                .any(|permission| {
                    permission.is_unrestricted()
                        || permission
                            .get_security_flags()
                            .is_some_and(SecurityPermissionFlags::is_all)
                })
    }

    /// The paths every `FileIOPermission` in the set grants read access to
    #[must_use]
    pub fn get_all_file_read_paths(&self) -> Vec<String> {
        self.permissions
            .iter()
            .filter_map(Permission::get_file_read_paths)
            .flatten()
            .collect()
    }

    /// The paths every `FileIOPermission` in the set grants write access to
    #[must_use]
    pub fn get_all_file_write_paths(&self) -> Vec<String> {
        self.permissions
            .iter()
            .filter_map(Permission::get_file_write_paths)
            .flatten()
            .collect()
    }
}

impl fmt::Display for PermissionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permission Set ({:?}", self.format)?;
        if self.unrestricted {
            write!(f, ", unrestricted")?;
        }
        writeln!(f, "):")?;
        for permission in &self.permissions {
            writeln!(f, "\t - {}", permission.class_name)?;
            for arg in &permission.named_arguments {
                writeln!(f, "\t  * {} = {}", arg.name, arg.value)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURITY_ATTRIBUTE: &str = "System.Security.Permissions.SecurityPermissionAttribute, \
         mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

    /// A binary set of the given permissions, each a class name and its property blob
    /// (the property count and properties).
    fn binary(permissions: &[(&str, &[u8])]) -> Vec<u8> {
        let mut blob = vec![b'.', u8::try_from(permissions.len()).unwrap()];
        for (class, properties) in permissions {
            crate::utils::write_compressed_uint(u32::try_from(class.len()).unwrap(), &mut blob)
                .unwrap();
            blob.extend_from_slice(class.as_bytes());
            crate::utils::write_compressed_uint(
                u32::try_from(properties.len()).unwrap(),
                &mut blob,
            )
            .unwrap();
            blob.extend_from_slice(properties);
        }
        blob
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn a_binary_set_decodes_its_properties_with_the_named_argument_grammar() {
        // Mono 2.0's System.Core: SecurityPermission(Flags = UnmanagedCode), the enum
        // assembly-qualified and its size decided by where the blob ends
        let flag = "System.Security.Permissions.SecurityPermissionFlag, mscorlib, \
                    Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        let mut properties = vec![0x01, 0x54, 0x55];
        crate::utils::write_compressed_uint(u32::try_from(flag.len()).unwrap(), &mut properties)
            .unwrap();
        properties.extend_from_slice(flag.as_bytes());
        properties.push(5);
        properties.extend_from_slice(b"Flags");
        properties.extend_from_slice(&2i32.to_le_bytes());
        let set = PermissionSet::new(&binary(&[(SECURITY_ATTRIBUTE, &properties)])).unwrap();

        assert_eq!(set.format(), &PermissionSetFormat::Binary);
        let permission = &set.permissions()[0];
        assert_eq!(permission.class_name, SECURITY_ATTRIBUTE);
        assert!(set.has_security());
        let flags = &permission.named_arguments[0];
        assert!(!flags.is_field);
        assert_eq!(flags.arg_type, FieldOrPropType::Enum(flag.to_string()));
        assert_eq!(
            flags.value,
            CustomAttributeArgument::Enum(
                flag.to_string(),
                Box::new(CustomAttributeArgument::I4(2))
            )
        );
        assert_eq!(
            permission.get_security_flags(),
            Some(SecurityPermissionFlags::SECURITY_FLAG_UNMANAGED_CODE)
        );
        assert!(!set.is_full_trust());
    }

    #[test]
    fn a_binary_set_holds_every_permission_and_its_properties() {
        let file_io = "System.Security.Permissions.FileIOPermissionAttribute, mscorlib";
        let skip = [&[0x01, 0x54, 0x02, 0x10][..], b"SkipVerification", &[0x01]].concat();
        let read = [&[0x01, 0x54, 0x0E, 0x04][..], b"Read", &[0x07], b"C:\\Data"].concat();
        let set = PermissionSet::new(&binary(&[
            (SECURITY_ATTRIBUTE, &skip),
            (file_io, &read),
            (SECURITY_ATTRIBUTE, &[0x00]),
            (file_io, &[]),
        ]))
        .unwrap();

        assert_eq!(set.permissions().len(), 4);
        assert_eq!(
            set.permissions()[0]
                .get_argument("SkipVerification")
                .unwrap()
                .value,
            CustomAttributeArgument::Bool(true)
        );
        assert_eq!(set.get_all_file_read_paths(), vec!["C:\\Data".to_string()]);
        assert!(set.permissions()[2].named_arguments.is_empty());
        assert!(set.permissions()[3].named_arguments.is_empty());
    }

    #[test]
    fn an_unrestricted_permission_set_attribute_is_full_trust() {
        let unrestricted = [&[0x01, 0x54, 0x02, 0x0C][..], b"Unrestricted", &[0x01]].concat();
        let set = PermissionSet::new(&binary(&[(
            "System.Security.Permissions.PermissionSetAttribute, mscorlib",
            &unrestricted,
        )]))
        .unwrap();
        assert!(set.is_unrestricted());
        assert!(set.is_full_trust());
    }

    #[test]
    fn a_malformed_binary_set_is_an_error() {
        // A class name past the end
        assert!(PermissionSet::new(&[b'.', 0x01, 0x10, b'A']).is_err());
        // A property blob past the end
        assert!(PermissionSet::new(&[b'.', 0x01, 0x01, b'A', 0x05, 0x00]).is_err());
        // A class name that is not UTF-8
        assert!(PermissionSet::new(&[b'.', 0x01, 0x01, 0xFF, 0x00]).is_err());
        // A property marker other than FIELD or PROPERTY
        assert!(
            PermissionSet::new(&binary(&[("A", &[0x01, 0x00, 0x02, 0x01, b'X', 0x01])])).is_err()
        );
        // A count no data backs does not allocate for it
        assert!(PermissionSet::new(&[b'.', 0xDF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn an_empty_binary_set_has_no_permissions() {
        let set = PermissionSet::new(&[b'.', 0x00]).unwrap();
        assert_eq!(set.format(), &PermissionSetFormat::Binary);
        assert!(set.permissions().is_empty());
        assert!(!set.is_full_trust());
    }

    #[test]
    fn an_xml_set_is_utf16_text_whose_attributes_are_strings() {
        let xml = "<PermissionSet class=\"System.Security.PermissionSet\"\r\nversion=\"1\">\r\n\
                   <IPermission class=\"System.Security.Permissions.SecurityPermission, mscorlib, Version=1.0.5000.0\"\r\n\
                   version=\"1\"\r\nFlags=\"UnmanagedCode, SkipVerification\"/>\r\n\
                   <IPermission class=\"System.Security.Permissions.FileIOPermission, mscorlib\" version=\"1\" \
                   Read=\"C:\\a &amp; b;C:\\c\"><Child Ignored=\"1\"/></IPermission>\r\n\
                   </PermissionSet>\r\n";
        for blob in [
            utf16(xml),
            [&[0xFF, 0xFE][..], &utf16(xml)].concat(),
            xml.as_bytes().to_vec(),
        ] {
            let set = PermissionSet::new(&blob).unwrap();
            assert_eq!(set.format(), &PermissionSetFormat::Xml);
            assert_eq!(set.permissions().len(), 2);
            let security = set
                .get_permission(security_classes::SECURITY_PERMISSION)
                .unwrap();
            assert_eq!(security.assembly_name(), Some("mscorlib"));
            assert_eq!(security.named_arguments.len(), 1);
            assert_eq!(
                security
                    .get_security_flags()
                    .map(SecurityPermissionFlags::bits),
                Some(6)
            );
            assert_eq!(
                set.get_all_file_read_paths(),
                vec!["C:\\a & b".to_string(), "C:\\c".to_string()]
            );
            assert!(!set.is_unrestricted());
        }
    }

    #[test]
    fn an_xml_root_that_says_unrestricted_is_the_unrestricted_set() {
        let xml = "<PermissionSet class=\"System.Security.PermissionSet\" version=\"1\" Unrestricted=\"true\"/>";
        let set = PermissionSet::new(&utf16(xml)).unwrap();
        assert!(set.permissions().is_empty());
        assert!(set.is_unrestricted());
        assert!(set.is_full_trust());
    }

    #[test]
    fn malformed_xml_is_an_error() {
        // No class on a permission
        assert!(PermissionSet::new(&utf16(
            "<PermissionSet><IPermission version=\"1\"/></PermissionSet>"
        ))
        .is_err());
        // A root other than PermissionSet
        assert!(PermissionSet::new(&utf16("<NamedPermissionSet/>")).is_err());
        // Odd-length UTF-16 and unpaired surrogates
        assert!(PermissionSet::new(&[b'<', 0x00, b'P']).is_err());
        assert!(PermissionSet::new(&[b'<', 0x00, 0x00, 0xD8]).is_err());
        // Unclosed markup
        assert!(PermissionSet::new(&utf16("<PermissionSet><IPermission class=\"A\"")).is_err());
    }

    #[test]
    fn other_data_is_an_unknown_set_and_no_data_an_error() {
        let set = PermissionSet::new(&[0x01, 0x02]).unwrap();
        assert_eq!(set.format(), &PermissionSetFormat::Unknown);
        assert!(set.permissions().is_empty());
        assert!(PermissionSet::new(&[]).is_err());
    }
}

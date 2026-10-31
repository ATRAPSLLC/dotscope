//! One permission of a permission set: its class and the properties it sets.
//!
//! A binary permission set names each permission by its permission attribute's class
//! (`System.Security.Permissions.SecurityPermissionAttribute, mscorlib, ...`) and holds the
//! attribute's properties as custom attribute named arguments; an XML one names the
//! permission class (`System.Security.Permissions.SecurityPermission, mscorlib, ...`) and holds
//! its attributes as strings. [`Permission`] keeps the name as the set writes it and its
//! properties as [`CustomAttributeNamedArgument`]s.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::metadata::{
//!     customattributes::{CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType},
//!     security::Permission,
//! };
//!
//! let permission = Permission::new(
//!     "System.Security.Permissions.FileIOPermissionAttribute, mscorlib, Version=4.0.0.0, \
//!      Culture=neutral, PublicKeyToken=b77a5c561934e089",
//!     vec![CustomAttributeNamedArgument {
//!         is_field: false,
//!         name: "Read".to_string(),
//!         arg_type: FieldOrPropType::String,
//!         value: CustomAttributeArgument::String(Some("C:\\Data;C:\\Logs".to_string())),
//!     }],
//! );
//!
//! assert!(permission.is_file_io());
//! assert_eq!(permission.assembly_name(), Some("mscorlib"));
//! assert_eq!(
//!     permission.get_file_read_paths(),
//!     Some(vec!["C:\\Data".to_string(), "C:\\Logs".to_string()])
//! );
//! ```

use std::fmt;

use crate::metadata::{
    customattributes::{CustomAttributeArgument, CustomAttributeNamedArgument},
    security::{security_classes, SecurityPermissionFlags},
};

/// A permission in a permission set.
#[derive(Debug, Clone, PartialEq)]
pub struct Permission {
    /// The class the set names the permission by, as it writes it: in a binary set the
    /// permission attribute's assembly-qualified name, in an XML set the permission's class.
    pub class_name: String,

    /// The properties (or fields) the permission sets, in the order the set writes them.
    pub named_arguments: Vec<CustomAttributeNamedArgument>,
}

impl Permission {
    /// A permission of class `class_name` that sets `named_arguments`.
    #[must_use]
    pub fn new(
        class_name: impl Into<String>,
        named_arguments: Vec<CustomAttributeNamedArgument>,
    ) -> Self {
        Permission {
            class_name: class_name.into(),
            named_arguments,
        }
    }

    /// The class's full name without its assembly: what precedes the first comma outside
    /// brackets (a generic type's arguments are bracketed, and qualified in turn).
    #[must_use]
    pub fn type_name(&self) -> &str {
        let end = self.qualifier_start().unwrap_or(self.class_name.len());
        self.class_name.get(..end).unwrap_or_default().trim()
    }

    /// The simple name of the assembly that qualifies the class, when it is qualified.
    #[must_use]
    pub fn assembly_name(&self) -> Option<&str> {
        let start = self.qualifier_start()?.saturating_add(1);
        let qualifier = self.class_name.get(start..)?;
        let name = qualifier.split(',').next().unwrap_or_default().trim();
        (!name.is_empty()).then_some(name)
    }

    /// The position of the comma that ends the type name, outside any brackets.
    fn qualifier_start(&self) -> Option<usize> {
        let mut depth = 0usize;
        for (position, character) in self.class_name.char_indices() {
            match character {
                '[' => depth = depth.saturating_add(1),
                ']' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => return Some(position),
                _ => {}
            }
        }
        None
    }

    /// Whether this is a permission of class `permission_class` (a full name without its
    /// assembly, such as [`security_classes::SECURITY_PERMISSION`]): named by that class, as
    /// in an XML set, or by its attribute class, as in a binary one.
    #[must_use]
    pub fn is_class(&self, permission_class: &str) -> bool {
        let type_name = self.type_name();
        type_name == permission_class
            || type_name
                .strip_suffix("Attribute")
                .is_some_and(|stem| stem == permission_class)
    }

    /// Whether this is a `FileIOPermission`.
    #[must_use]
    pub fn is_file_io(&self) -> bool {
        self.is_class(security_classes::FILE_IO_PERMISSION)
    }

    /// Whether this is a `SecurityPermission`.
    #[must_use]
    pub fn is_security(&self) -> bool {
        self.is_class(security_classes::SECURITY_PERMISSION)
    }

    /// Whether this is a `ReflectionPermission`.
    #[must_use]
    pub fn is_reflection(&self) -> bool {
        self.is_class(security_classes::REFLECTION_PERMISSION)
    }

    /// Whether this is a `RegistryPermission`.
    #[must_use]
    pub fn is_registry(&self) -> bool {
        self.is_class(security_classes::REGISTRY_PERMISSION)
    }

    /// Whether this is a `UIPermission`.
    #[must_use]
    pub fn is_ui(&self) -> bool {
        self.is_class(security_classes::UI_PERMISSION)
    }

    /// Whether this is an `EnvironmentPermission`.
    #[must_use]
    pub fn is_environment(&self) -> bool {
        self.is_class(security_classes::ENVIRONMENT_PERMISSION)
    }

    /// The property named `name`.
    #[must_use]
    pub fn get_argument(&self, name: &str) -> Option<&CustomAttributeNamedArgument> {
        self.named_arguments.iter().find(|arg| arg.name == name)
    }

    /// The paths a `FileIOPermission` grants read access to: its `Read` property, a list
    /// separated by semicolons. `None` for another permission or one without the property.
    #[must_use]
    pub fn get_file_read_paths(&self) -> Option<Vec<String>> {
        self.file_io_paths("Read")
    }

    /// The paths a `FileIOPermission` grants write access to: its `Write` property.
    #[must_use]
    pub fn get_file_write_paths(&self) -> Option<Vec<String>> {
        self.file_io_paths("Write")
    }

    /// The paths a `FileIOPermission` lets code discover: its `PathDiscovery` property.
    #[must_use]
    pub fn get_file_path_discovery(&self) -> Option<Vec<String>> {
        self.file_io_paths("PathDiscovery")
    }

    /// The paths a `FileIOPermission`'s property `name` lists: a string of paths separated by
    /// semicolons, or an array of such strings.
    fn file_io_paths(&self, name: &str) -> Option<Vec<String>> {
        if !self.is_file_io() {
            return None;
        }
        let split = |list: &str| {
            list.split(';')
                .filter(|path| !path.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        match &self.get_argument(name)?.value {
            CustomAttributeArgument::String(Some(list)) => Some(split(list)),
            CustomAttributeArgument::Array(_, Some(lists)) => Some(
                lists
                    .iter()
                    .filter_map(|list| match list {
                        CustomAttributeArgument::String(Some(list)) => Some(split(list)),
                        _ => None,
                    })
                    .flatten()
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Whether the permission's `Unrestricted` property is true: it grants all the access
    /// its class controls.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.get_argument("Unrestricted")
            .is_some_and(|arg| match &arg.value {
                CustomAttributeArgument::Bool(value) => *value,
                CustomAttributeArgument::String(Some(text)) => text.eq_ignore_ascii_case("true"),
                _ => false,
            })
    }

    /// The flags a `SecurityPermission` grants: its `Flags` property, an enum (binary sets)
    /// or flag names (XML sets), and the boolean property per flag (`SkipVerification =
    /// true`), each applied in the order the set writes them as the attribute's setters
    /// apply them, from no flags.
    ///
    /// `None` for another permission, one that sets neither, or flags that do not parse.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::{
    ///     customattributes::{CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType},
    ///     security::{Permission, SecurityPermissionFlags},
    /// };
    ///
    /// let flag = "System.Security.Permissions.SecurityPermissionFlag, mscorlib".to_string();
    /// let permission = Permission::new(
    ///     "System.Security.Permissions.SecurityPermissionAttribute, mscorlib",
    ///     vec![CustomAttributeNamedArgument {
    ///         is_field: false,
    ///         name: "Flags".to_string(),
    ///         arg_type: FieldOrPropType::Enum(flag.clone()),
    ///         value: CustomAttributeArgument::Enum(flag, Box::new(CustomAttributeArgument::I4(2))),
    ///     }],
    /// );
    ///
    /// let flags = permission.get_security_flags().unwrap();
    /// assert!(flags.contains(SecurityPermissionFlags::SECURITY_FLAG_UNMANAGED_CODE));
    /// ```
    #[must_use]
    pub fn get_security_flags(&self) -> Option<SecurityPermissionFlags> {
        if !self.is_security() {
            return None;
        }
        let flags = |value: &CustomAttributeArgument| match value {
            CustomAttributeArgument::I4(bits) => Some(SecurityPermissionFlags::new(*bits)),
            CustomAttributeArgument::String(Some(names)) => SecurityPermissionFlags::parse(names),
            _ => None,
        };
        let mut granted = None;
        for arg in &self.named_arguments {
            match (arg.name.as_str(), &arg.value) {
                ("Flags", CustomAttributeArgument::Enum(_, underlying)) => {
                    granted = Some(flags(underlying)?);
                }
                ("Flags", value) => granted = Some(flags(value)?),
                (name, CustomAttributeArgument::Bool(set)) => {
                    let Some(flag) = SecurityPermissionFlags::parse(name)
                        .filter(|flag| !flag.is_empty() && !flag.is_all())
                    else {
                        continue;
                    };
                    let bits = granted.unwrap_or(SecurityPermissionFlags::ZERO).bits();
                    granted = Some(SecurityPermissionFlags::new(if *set {
                        bits | flag.bits()
                    } else {
                        bits & !flag.bits()
                    }));
                }
                _ => {}
            }
        }
        granted
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.class_name)?;
        for (i, arg) in self.named_arguments.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{} = {}", arg.name, arg.value)?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::customattributes::FieldOrPropType;

    const ATTRIBUTE_QUALIFIER: &str =
        ", mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

    fn property(name: &str, value: CustomAttributeArgument) -> CustomAttributeNamedArgument {
        let arg_type = value.field_or_prop_type().unwrap();
        CustomAttributeNamedArgument {
            is_field: false,
            name: name.to_string(),
            arg_type,
            value,
        }
    }

    fn string(text: &str) -> CustomAttributeArgument {
        CustomAttributeArgument::String(Some(text.to_string()))
    }

    #[test]
    fn a_class_is_named_by_its_attribute_or_itself_with_or_without_an_assembly() {
        let binary = Permission::new(
            format!("System.Security.Permissions.SecurityPermissionAttribute{ATTRIBUTE_QUALIFIER}"),
            Vec::new(),
        );
        assert_eq!(
            binary.type_name(),
            "System.Security.Permissions.SecurityPermissionAttribute"
        );
        assert_eq!(binary.assembly_name(), Some("mscorlib"));
        assert!(binary.is_security());
        assert!(!binary.is_file_io());

        let xml = Permission::new("System.Security.Permissions.FileIOPermission", Vec::new());
        assert_eq!(xml.assembly_name(), None);
        assert!(xml.is_file_io());
        assert!(!xml.is_security());

        // Commas inside a generic type's brackets do not end its name
        let generic = Permission::new(
            "Ns.Permission`1[[System.Int32, mscorlib]], Lib, Version=1.0.0.0",
            Vec::new(),
        );
        assert_eq!(
            generic.type_name(),
            "Ns.Permission`1[[System.Int32, mscorlib]]"
        );
        assert_eq!(generic.assembly_name(), Some("Lib"));
    }

    #[test]
    fn file_io_paths_are_the_semicolon_separated_lists_of_its_properties() {
        let permission = Permission::new(
            format!("System.Security.Permissions.FileIOPermissionAttribute{ATTRIBUTE_QUALIFIER}"),
            vec![
                property("Read", string("C:\\Data;C:\\Config")),
                property(
                    "Write",
                    CustomAttributeArgument::Array(
                        FieldOrPropType::String,
                        Some(vec![string("C:\\Logs"), string("D:\\Out;")]),
                    ),
                ),
            ],
        );
        assert_eq!(
            permission.get_file_read_paths(),
            Some(vec!["C:\\Data".to_string(), "C:\\Config".to_string()])
        );
        assert_eq!(
            permission.get_file_write_paths(),
            Some(vec!["C:\\Logs".to_string(), "D:\\Out".to_string()])
        );
        assert_eq!(permission.get_file_path_discovery(), None);

        let other = Permission::new(
            security_classes::REGISTRY_PERMISSION,
            vec![property("Read", string("HKEY_LOCAL_MACHINE"))],
        );
        assert_eq!(other.get_file_read_paths(), None);
    }

    #[test]
    fn unrestricted_is_a_true_property_in_either_format() {
        let binary = Permission::new(
            security_classes::FILE_IO_PERMISSION,
            vec![property(
                "Unrestricted",
                CustomAttributeArgument::Bool(true),
            )],
        );
        assert!(binary.is_unrestricted());
        let xml = Permission::new(
            security_classes::FILE_IO_PERMISSION,
            vec![property("Unrestricted", string("true"))],
        );
        assert!(xml.is_unrestricted());
        let restricted = Permission::new(
            security_classes::FILE_IO_PERMISSION,
            vec![property(
                "Unrestricted",
                CustomAttributeArgument::Bool(false),
            )],
        );
        assert!(!restricted.is_unrestricted());
    }

    #[test]
    fn security_flags_come_from_the_flags_enum_or_its_names() {
        let enum_name =
            format!("System.Security.Permissions.SecurityPermissionFlag{ATTRIBUTE_QUALIFIER}");
        let binary = Permission::new(
            format!("System.Security.Permissions.SecurityPermissionAttribute{ATTRIBUTE_QUALIFIER}"),
            vec![property(
                "Flags",
                CustomAttributeArgument::Enum(
                    enum_name,
                    Box::new(CustomAttributeArgument::I4(0x0200)),
                ),
            )],
        );
        assert_eq!(
            binary.get_security_flags(),
            Some(SecurityPermissionFlags::SECURITY_FLAG_CONTROL_PRINCIPAL)
        );

        let xml = Permission::new(
            security_classes::SECURITY_PERMISSION,
            vec![property("Flags", string("UnmanagedCode, SkipVerification"))],
        );
        assert_eq!(
            xml.get_security_flags().map(SecurityPermissionFlags::bits),
            Some(6)
        );

        // crafted_2 and most compilers' output: a boolean property per flag, folded in order
        let booleans = Permission::new(
            security_classes::SECURITY_PERMISSION,
            vec![
                property("Assertion", CustomAttributeArgument::Bool(true)),
                property("Flags", CustomAttributeArgument::I4(0x0C)),
                property("SkipVerification", CustomAttributeArgument::Bool(false)),
                property("UnmanagedCode", CustomAttributeArgument::Bool(true)),
                property("Unrestricted", CustomAttributeArgument::Bool(false)),
            ],
        );
        assert_eq!(
            booleans
                .get_security_flags()
                .map(SecurityPermissionFlags::bits),
            Some(0x0A)
        );
        let unset = Permission::new(
            security_classes::SECURITY_PERMISSION,
            vec![property(
                "Unrestricted",
                CustomAttributeArgument::Bool(true),
            )],
        );
        assert_eq!(unset.get_security_flags(), None);

        let other = Permission::new(
            security_classes::REFLECTION_PERMISSION,
            vec![property("Flags", CustomAttributeArgument::I4(1))],
        );
        assert_eq!(other.get_security_flags(), None);
    }

    #[test]
    fn display_lists_the_properties() {
        let permission = Permission::new(
            security_classes::SECURITY_PERMISSION,
            vec![
                property("Unrestricted", CustomAttributeArgument::Bool(true)),
                property("Flags", string("Execution")),
            ],
        );
        assert_eq!(
            permission.to_string(),
            "System.Security.Permissions.SecurityPermission(Unrestricted = bool(true), Flags = \"Execution\")"
        );
    }
}

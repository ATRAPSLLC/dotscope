//! Builders for binary permission sets, as a compiler writes them for .NET Framework 4.
//!
//! A permission in a binary set is named by its permission attribute's assembly-qualified
//! class and sets the attribute's properties; these builders name the attributes in
//! `mscorlib` 4.0 ([`CORLIB`]), where the framework defines them, and type each property as
//! the attribute declares it.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::metadata::security::{PermissionSet, PermissionSetBuilder, SecurityPermissionFlags};
//!
//! let blob = PermissionSetBuilder::new()
//!     .add_security_permission()
//!     .flags(SecurityPermissionFlags::SECURITY_FLAG_UNMANAGED_CODE)
//!     .build()
//!     .add_file_io_permission()
//!     .read_paths(&["C:\\Data", "C:\\Config"])
//!     .build()
//!     .encode()?;
//!
//! let set = PermissionSet::new(&blob)?;
//! assert!(set.has_security() && set.has_file_io());
//! assert_eq!(set.get_all_file_read_paths(), vec!["C:\\Data", "C:\\Config"]);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::{
        customattributes::{
            CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType,
        },
        security::{
            encode_permission_set, security_classes, Permission, PermissionSetFormat,
            SecurityPermissionFlags,
        },
    },
    Result,
};

/// The assembly the builders qualify the permission attributes and their enums with:
/// `mscorlib` of .NET Framework 4.
pub const CORLIB: &str =
    "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

/// A property of type `value`'s, named `name`.
fn property(
    name: &str,
    arg_type: FieldOrPropType,
    value: CustomAttributeArgument,
) -> CustomAttributeNamedArgument {
    CustomAttributeNamedArgument {
        is_field: false,
        name: name.to_string(),
        arg_type,
        value,
    }
}

/// The attribute class of permission class `permission_class`, qualified with [`CORLIB`].
fn attribute_class(permission_class: &str) -> String {
    format!("{permission_class}Attribute, {CORLIB}")
}

/// Builds the permissions of a binary permission set.
#[derive(Debug, Clone, Default)]
pub struct PermissionSetBuilder {
    permissions: Vec<Permission>,
}

impl PermissionSetBuilder {
    /// A builder without permissions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `permission` as it is.
    #[must_use]
    pub fn add_permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Adds the unrestricted permission set: a `PermissionSetAttribute` with
    /// `Unrestricted = true`, which grants every permission.
    #[must_use]
    pub fn add_unrestricted_permission_set(self) -> Self {
        self.add_permission(Permission::new(
            format!("{}, {CORLIB}", security_classes::PERMISSION_SET_ATTRIBUTE),
            vec![property(
                "Unrestricted",
                FieldOrPropType::Bool,
                CustomAttributeArgument::Bool(true),
            )],
        ))
    }

    /// Starts a `SecurityPermission`, which [`SecurityPermissionBuilder::build`] adds.
    #[must_use]
    pub fn add_security_permission(self) -> SecurityPermissionBuilder {
        SecurityPermissionBuilder {
            parent: self,
            named_arguments: Vec::new(),
        }
    }

    /// Starts a `FileIOPermission`, which [`FileIOPermissionBuilder::build`] adds.
    #[must_use]
    pub fn add_file_io_permission(self) -> FileIOPermissionBuilder {
        FileIOPermissionBuilder {
            parent: self,
            named_arguments: Vec::new(),
        }
    }

    /// The permission set blob, in the binary format.
    ///
    /// # Errors
    ///
    /// When a permission does not encode (see [`encode_permission_set`]).
    pub fn encode(self) -> Result<Vec<u8>> {
        encode_permission_set(&self.permissions, PermissionSetFormat::Binary)
    }

    /// The permissions added.
    #[must_use]
    pub fn permissions(self) -> Vec<Permission> {
        self.permissions
    }
}

/// Builds a `SecurityPermission` (its attribute, `SecurityPermissionAttribute`).
#[derive(Debug, Clone)]
pub struct SecurityPermissionBuilder {
    parent: PermissionSetBuilder,
    named_arguments: Vec<CustomAttributeNamedArgument>,
}

impl SecurityPermissionBuilder {
    /// Sets `Unrestricted`: whether the permission grants every flag.
    #[must_use]
    pub fn unrestricted(mut self, value: bool) -> Self {
        self.named_arguments.push(property(
            "Unrestricted",
            FieldOrPropType::Bool,
            CustomAttributeArgument::Bool(value),
        ));
        self
    }

    /// Sets `Flags`, a `SecurityPermissionFlag`.
    #[must_use]
    pub fn flags(mut self, flags: SecurityPermissionFlags) -> Self {
        let enum_name = format!("System.Security.Permissions.SecurityPermissionFlag, {CORLIB}");
        self.named_arguments.push(property(
            "Flags",
            FieldOrPropType::Enum(enum_name.clone()),
            CustomAttributeArgument::Enum(
                enum_name,
                Box::new(CustomAttributeArgument::I4(flags.bits())),
            ),
        ));
        self
    }

    /// Adds the permission to the set.
    #[must_use]
    pub fn build(self) -> PermissionSetBuilder {
        self.parent.add_permission(Permission::new(
            attribute_class(security_classes::SECURITY_PERMISSION),
            self.named_arguments,
        ))
    }
}

/// Builds a `FileIOPermission` (its attribute, `FileIOPermissionAttribute`).
#[derive(Debug, Clone)]
pub struct FileIOPermissionBuilder {
    parent: PermissionSetBuilder,
    named_arguments: Vec<CustomAttributeNamedArgument>,
}

impl FileIOPermissionBuilder {
    /// The string property `name` listing `paths`, separated by semicolons.
    fn paths(mut self, name: &str, paths: &[&str]) -> Self {
        self.named_arguments.push(property(
            name,
            FieldOrPropType::String,
            CustomAttributeArgument::String(Some(paths.join(";"))),
        ));
        self
    }

    /// Sets `Read`: the paths the permission grants read access to.
    #[must_use]
    pub fn read_paths(self, paths: &[&str]) -> Self {
        self.paths("Read", paths)
    }

    /// Sets `Write`: the paths the permission grants write access to.
    #[must_use]
    pub fn write_paths(self, paths: &[&str]) -> Self {
        self.paths("Write", paths)
    }

    /// Sets `Unrestricted`: whether the permission grants access to every file.
    #[must_use]
    pub fn unrestricted(mut self, value: bool) -> Self {
        self.named_arguments.push(property(
            "Unrestricted",
            FieldOrPropType::Bool,
            CustomAttributeArgument::Bool(value),
        ));
        self
    }

    /// Adds the permission to the set.
    #[must_use]
    pub fn build(self) -> PermissionSetBuilder {
        self.parent.add_permission(Permission::new(
            attribute_class(security_classes::FILE_IO_PERMISSION),
            self.named_arguments,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::PermissionSet;

    #[test]
    fn a_security_permission_is_its_attribute_with_typed_properties() {
        let permissions = PermissionSetBuilder::new()
            .add_security_permission()
            .unrestricted(false)
            .flags(SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION)
            .build()
            .permissions();

        let permission = &permissions[0];
        assert_eq!(
            permission.type_name(),
            "System.Security.Permissions.SecurityPermissionAttribute"
        );
        assert_eq!(permission.assembly_name(), Some("mscorlib"));
        assert!(permission.is_security());
        assert_eq!(
            permission.named_arguments[0].arg_type,
            FieldOrPropType::Bool
        );
        assert_eq!(
            permission.get_security_flags(),
            Some(SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION)
        );
    }

    #[test]
    fn a_built_set_decodes_to_the_permissions_built() {
        let builder = PermissionSetBuilder::new()
            .add_security_permission()
            .flags(SecurityPermissionFlags::ALL)
            .build()
            .add_file_io_permission()
            .read_paths(&["C:\\Data", "C:\\Config"])
            .write_paths(&["C:\\Logs"])
            .unrestricted(false)
            .build();
        let blob = builder.clone().encode().unwrap();
        let set = PermissionSet::new(&blob).unwrap();

        assert_eq!(set.permissions(), &builder.permissions()[..]);
        assert!(set.is_full_trust());
        assert_eq!(
            set.get_all_file_read_paths(),
            vec!["C:\\Data", "C:\\Config"]
        );
        assert_eq!(set.get_all_file_write_paths(), vec!["C:\\Logs"]);
    }

    #[test]
    fn the_unrestricted_set_is_an_unrestricted_permission_set_attribute() {
        let blob = PermissionSetBuilder::new()
            .add_unrestricted_permission_set()
            .encode()
            .unwrap();
        let set = PermissionSet::new(&blob).unwrap();
        assert!(set.is_unrestricted());
        assert_eq!(
            set.permissions()[0].type_name(),
            security_classes::PERMISSION_SET_ATTRIBUTE
        );
    }
}

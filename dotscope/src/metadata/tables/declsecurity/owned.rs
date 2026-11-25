//! Owned `DeclSecurity` table representation.
//!
//! This module provides the [`crate::metadata::tables::declsecurity::DeclSecurity`] struct
//! which contains fully resolved security declaration metadata with owned data and resolved references.
//! This is the primary data structure for representing .NET Code Access Security (CAS) declarations
//! in a usable form after the dual variant resolution phase.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::declsecurity::DeclSecurity`] - Main struct representing resolved security declarations
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`], enabling safe sharing
//! across threads through reference counting and immutable data structures.

use std::sync::Arc;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        security::{PermissionSet, Security, SecurityAction},
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Represents a .NET CIL security declaration with fully resolved metadata and owned data
///
/// This structure contains complete security declaration information from the `DeclSecurity`
/// metadata table (0x0E), with all references resolved to concrete types and permission
/// sets. Unlike [`crate::metadata::tables::declsecurity::DeclSecurityRaw`], this
/// provides immediate access to security data without requiring additional lookups.
///
/// # .NET Code Access Security
///
/// Security declarations in .NET implement Code Access Security (CAS), which allows code
/// to declaratively specify required permissions or security restrictions. Declarations
/// are applied at three levels:
///
/// 1. **Assembly Level**: Applied to the entire assembly, often to request minimum permissions
/// 2. **Type Level**: Applied to a class or interface, affecting all its members  
/// 3. **Method Level**: Applied to a specific method for fine-grained control
///
/// # Security Actions
///
/// Security declarations specify how permissions are enforced:
/// - **Demand**: Code must have the specified permission to execute
/// - **Assert**: Code temporarily elevates permissions for trusted operations
/// - **Deny**: Code cannot use the specified permission, even if granted
/// - **`LinkDemand`**: Direct callers must have the permission (compile-time check)
/// - **`InheritanceDemand`**: Classes inheriting from this type must have permission
///
/// # Reference
/// - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification
pub struct DeclSecurity {
    /// Row identifier within the `DeclSecurity` metadata table
    ///
    /// The 1-based index of this security declaration row. Used for metadata
    /// token generation and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this security declaration  
    ///
    /// Combines the table identifier (0x0E for `DeclSecurity`) with the row ID to create
    /// a unique token that can be used to reference this declaration from other metadata.
    pub token: Token,

    /// Byte offset of this declaration row within the metadata tables stream
    ///
    /// Physical location of the raw security declaration data within the metadata
    /// binary format. Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Security action specifying how the permission is enforced
    ///
    /// Determines the enforcement behavior for the associated permission set.
    /// See [`crate::metadata::security::SecurityAction`] for available actions like Demand, Assert, Deny, etc.
    /// This controls whether permissions are checked at runtime, link time, or inheritance.
    pub action: SecurityAction,

    /// Reference to the entity this security declaration applies to
    ///
    /// Can reference a Type (`TypeDef`), Method (`MethodDef`), or Assembly through
    /// a `HasDeclSecurity` coded index. This determines the scope of the security
    /// declaration - whether it applies to an entire assembly, a specific type,
    /// or an individual method.
    pub parent: CilTypeReference,

    /// The parsed permission set containing the security permissions
    ///
    /// Contains the actual permissions being declared, parsed from the raw
    /// permission blob in the metadata. Uses [`Arc`] for efficient sharing
    /// since permission sets can be referenced from multiple contexts.
    /// See [`crate::metadata::security::PermissionSet`] for permission details.
    pub permission_set: Arc<PermissionSet>,

    /// Custom attributes attached to this security declaration
    ///
    /// Contains additional metadata attributes that may provide context or
    /// modify the behavior of this security declaration. These are typically
    /// used for tooling or framework-specific annotations.
    pub custom_attributes: CustomAttributeValueList,
}

impl DeclSecurity {
    /// Check if this is a demand security declaration
    ///
    /// Returns `true` if this declaration requires the specified permissions
    /// to be present for code execution. Demand checks are performed at runtime
    /// when the protected code is accessed.
    #[must_use]
    pub fn is_demand(&self) -> bool {
        matches!(self.action, SecurityAction::Demand)
    }

    /// Check if this is an assert security declaration
    ///
    /// Returns `true` if this declaration allows code to temporarily elevate
    /// permissions for trusted operations. Assert declarations enable code
    /// to perform operations that callers might not have permission for.
    ///
    /// # Security Implications
    ///
    /// Assert declarations should be used carefully as they can bypass normal
    /// security checks. They are typically used in trusted library code that
    /// needs to perform privileged operations on behalf of less-trusted callers.
    #[must_use]
    pub fn is_assert(&self) -> bool {
        matches!(self.action, SecurityAction::Assert)
    }

    /// Check if this is a deny security declaration
    ///
    /// Returns `true` if this declaration prevents the use of specified
    /// permissions, even if they have been granted to the code. Deny declarations
    /// provide defense in depth by limiting the capabilities of potentially
    /// dangerous code.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self.action, SecurityAction::Deny)
    }

    /// Check if this is a link demand security declaration
    ///
    /// Returns `true` if this declaration requires direct callers to have
    /// the specified permissions. Link demands are checked at JIT compilation
    /// time rather than runtime, providing better performance for security-critical
    /// operations.
    #[must_use]
    pub fn is_link_demand(&self) -> bool {
        matches!(self.action, SecurityAction::LinkDemand)
    }

    /// Check if this is an inheritance demand security declaration
    ///
    /// Returns `true` if this declaration requires classes that inherit from
    /// this type to have the specified permissions. This provides security
    /// control over class inheritance hierarchies.
    #[must_use]
    pub fn is_inheritance_demand(&self) -> bool {
        matches!(self.action, SecurityAction::InheritanceDemand)
    }

    /// Whether the declaration's permission set is the unrestricted one, which holds every
    /// permission (see [`crate::metadata::security::PermissionSet::is_unrestricted`]).
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.permission_set.is_unrestricted()
    }

    /// Check if this declaration includes file I/O permissions
    ///
    /// Returns `true` if the permission set includes file system access rights.
    /// This is useful for analyzing what file operations protected code can perform.
    #[must_use]
    pub fn has_file_io(&self) -> bool {
        self.permission_set.has_file_io()
    }

    /// Check if this declaration includes registry permissions
    ///
    /// Returns `true` if the permission set includes Windows registry access rights.
    /// This helps identify code that can read or modify system registry settings.
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.permission_set.has_registry()
    }

    /// Check if this declaration includes reflection permissions
    ///
    /// Returns `true` if the permission set includes reflection access rights.
    /// This identifies code that can inspect or modify type metadata, invoke
    /// methods dynamically, or access private members through reflection.
    ///
    /// # Security Implications
    ///
    /// Reflection permissions can be used to bypass normal access controls
    /// and should be carefully controlled in security-sensitive environments.
    #[must_use]
    pub fn has_reflection(&self) -> bool {
        self.permission_set.has_reflection()
    }

    /// Apply this security declaration to its target entity
    ///
    /// This method processes the security declaration and applies it to the appropriate
    /// entity (type, method, or assembly) by parsing the permission set and setting up
    /// the security context. The security information is stored in the target entity's
    /// security field for runtime enforcement.
    ///
    /// # Implementation Details
    ///
    /// The security information is set using [`std::sync::OnceLock::set`] which ensures thread-safe
    /// initialization. If security has already been set for the target entity, the
    /// operation succeeds silently without overwriting existing security configuration.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful application or if security was already configured.
    /// Returns an error if the parent reference is invalid or points to an unsupported
    /// entity type.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error`] - When the parent reference is not a valid target type
    /// - [`crate::Error`] - When weak references to parent entities cannot be upgraded
    pub fn apply(&self) -> Result<()> {
        match &self.parent {
            CilTypeReference::TypeDef(typedef) => {
                if let Some(strong_ref) = typedef.upgrade() {
                    strong_ref.security.push_row(
                        self.token,
                        Security {
                            action: self.action,
                            permission_set: self.permission_set.clone(),
                        },
                    );
                }
                Ok(())
            }
            CilTypeReference::MethodDef(method) => {
                if let Some(method) = method.upgrade() {
                    method.security.push_row(
                        self.token,
                        Security {
                            action: self.action,
                            permission_set: self.permission_set.clone(),
                        },
                    );
                }

                Ok(())
            }
            CilTypeReference::Assembly(assembly) => {
                assembly.security.push_row(
                    self.token,
                    Security {
                        action: self.action,
                        permission_set: self.permission_set.clone(),
                    },
                );

                Ok(())
            }
            _ => Err(malformed_error!(
                "Invalid parent for {0}",
                self.token.value()
            )),
        }
    }
}

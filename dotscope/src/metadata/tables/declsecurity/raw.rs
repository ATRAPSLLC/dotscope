//! Raw `DeclSecurity` table representation.
//!
//! This module provides the [`crate::metadata::tables::declsecurity::DeclSecurityRaw`] struct
//! for low-level access to `DeclSecurity` metadata table data with unresolved heap indexes and coded indices.
//! This represents the binary format of security declaration records as they appear in the metadata
//! tables stream, requiring resolution to create usable data structures.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::declsecurity::DeclSecurityRaw`] - Raw binary representation with unresolved indices
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Clone`], enabling safe sharing
//! across threads and efficient copying when needed.
//!
//! # `DeclSecurity` Table Format
//!
//! The `DeclSecurity` table (0x0E) contains security declarations for assemblies, types, and methods
//! with these fields:
//! - **Action** (2 bytes): Security action enumeration value
//! - **Parent** (2/4 bytes): `HasDeclSecurity` coded index to target entity
//! - **`PermissionSet`** (2/4 bytes): Blob heap index for serialized permission data
//!
//! # Usage
//!
//! This type is used internally for metadata parsing and should typically be converted
//! to [`crate::metadata::tables::declsecurity::DeclSecurity`] via [`crate::metadata::tables::declsecurity::DeclSecurityRaw::to_owned`] for practical use.
//! The [`crate::metadata::tables::declsecurity::DeclSecurityRaw::apply`] method can directly process security declarations
//! without creating intermediate owned structures.
//!
//! # Reference
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        security::{PermissionSet, Security, SecurityAction},
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, DeclSecurity, DeclSecurityRc, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `DeclSecurity` table row with unresolved indexes and coded indices
///
/// Represents the binary format of a `DeclSecurity` metadata table entry (table ID 0x0E) as stored
/// in the metadata tables stream. All blob references and parent entity references are stored as
/// indexes that must be resolved using the appropriate heaps and coded index resolution.
///
/// Security declarations specify permissions and security actions that are enforced by the .NET
/// runtime's Code Access Security (CAS) system. Each declaration targets a specific entity
/// (assembly, type, or method) and specifies how certain permissions should be handled.
///
/// # Reference
/// - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification
pub struct DeclSecurityRaw {
    /// Row identifier within the `DeclSecurity` metadata table
    ///
    /// The 1-based index of this security declaration row. Used for metadata
    /// token generation and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this security declaration row
    ///
    /// Combines the table identifier (0x0E for `DeclSecurity`) with the row ID to create
    /// a unique token. Format: `0x0E000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw security declaration data within the metadata
    /// binary format. Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Security action enumeration value (unresolved)
    ///
    /// 2-byte value representing the security action to be taken. Must be converted
    /// to [`SecurityAction`] for interpretation. Determines whether permissions are
    /// demanded, asserted, denied, etc.
    pub action: u16,

    /// `HasDeclSecurity` coded index to the target entity (unresolved)
    ///
    /// References the entity this security declaration applies to through a coded index.
    /// Can point to `TypeDef`, `MethodDef`, or Assembly tables. Must be resolved using
    /// appropriate coded index resolution to obtain the actual target reference.
    pub parent: CodedIndex,

    /// Blob heap index for serialized permission data (unresolved)
    ///
    /// Index into the Blob heap containing the serialized permission set data.
    /// The blob contains the actual security permissions in binary format that
    /// must be parsed to create a [`PermissionSet`].
    pub permission_set: u32,
}

impl DeclSecurityRaw {
    /// Apply this security declaration directly to its target entity
    ///
    /// This method processes the raw security declaration and applies it to the appropriate
    /// entity (type, method, or assembly) by parsing the permission set and setting up the
    /// security context. This provides a direct path from raw metadata to applied security
    /// without creating intermediate owned structures.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `blob` - The blob heap containing serialized permission data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful application. The security information is stored
    /// in the target entity's security field using [`std::sync::OnceLock`] for thread-safe
    /// initialization.
    ///
    /// # Errors
    ///
    /// - The blob heap lookup fails for the permission set index
    /// - The permission set data cannot be parsed from the blob
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The parent reference points to an unsupported entity type
    pub fn apply<F>(&self, get_ref: F, blob: &Blob) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);
        let parent = get_ref(&self.parent);

        match parent {
            CilTypeReference::TypeDef(typedef) => {
                if let Some(strong_ref) = typedef.upgrade() {
                    strong_ref.security.push_row(
                        self.token,
                        Security {
                            action,
                            permission_set,
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
                            action,
                            permission_set,
                        },
                    );
                }
                Ok(())
            }
            CilTypeReference::Assembly(assembly) => {
                assembly.security.push_row(
                    self.token,
                    Security {
                        action,
                        permission_set,
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

    /// Convert to owned `DeclSecurity` with resolved references and owned data
    ///
    /// This method converts the raw security declaration into a fully resolved
    /// [`DeclSecurity`] structure with owned data and resolved references. The resulting
    /// structure provides immediate access to security information without requiring
    /// additional heap lookups or coded index resolution.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `blob` - The blob heap containing serialized permission data
    ///
    /// # Returns
    ///
    /// Returns [`DeclSecurityRc`] (Arc-wrapped [`DeclSecurity`]) on success, providing
    /// shared ownership of the resolved security declaration data.
    ///
    /// # Errors
    ///
    /// - The blob heap lookup fails for the permission set index
    /// - The permission set data cannot be parsed from the blob
    /// - The parent reference cannot be resolved to a valid type reference
    /// - The resolved parent reference is [`CilTypeReference::None`]
    pub fn to_owned<F>(&self, get_ref: F, blob: &Blob) -> Result<DeclSecurityRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let blob_data = blob.get(self.permission_set as usize)?;
        let permission_set = Arc::new(PermissionSet::new(blob_data)?);
        let action = SecurityAction::from(self.action);

        let parent = get_ref(&self.parent);
        if matches!(parent, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent.token.value()
            ));
        }

        Ok(Arc::new(DeclSecurity {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            action,
            parent,
            permission_set,
            custom_attributes: Default::default(),
        }))
    }
}

impl TableRow for DeclSecurityRaw {
    /// Calculate the byte size of a DeclSecurity table row
    ///
    /// Computes the total size based on fixed-size fields and variable-size indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.11)
    /// - `action`: 2 bytes (fixed size security action enumeration)
    /// - `parent`: 2 or 4 bytes (`HasDeclSecurity` coded index)
    /// - `permission_set`: 2 or 4 bytes (Blob heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one DeclSecurity table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* action */         2u8
            /* parent */         .saturating_add(sizes.coded_index_bytes(CodedIndexType::HasDeclSecurity))
            /* permission_set */ .saturating_add(sizes.blob_bytes())

        )
    }
}

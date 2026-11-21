//! .NET declarative security: the permission sets `DeclSecurity` rows attach to assemblies,
//! types and methods (ECMA-335 II.22.11).
//!
//! Code Access Security is a .NET Framework model: .NET Core and later read these rows but do
//! not enforce them. Compilers still write them, chiefly the assembly-level request for
//! `SkipVerification`.
//!
//! # Key Components
//!
//! - [`PermissionSet`](crate::metadata::security::PermissionSet) decodes a permission set blob, binary or XML, into its [`Permission`](crate::metadata::security::Permission)s.
//! - [`Permission`](crate::metadata::security::Permission) is a permission's class and the properties it sets, as custom attribute
//!   named arguments ([`crate::metadata::customattributes::CustomAttributeNamedArgument`]).
//! - [`encode_permission_set`](crate::metadata::security::encode_permission_set) writes permissions back as a blob; a binary set decoded and
//!   encoded again is its own bytes.
//! - [`PermissionSetBuilder`](crate::metadata::security::PermissionSetBuilder) builds a binary set as a compiler writes it.
//! - [`SecurityAction`](crate::metadata::security::SecurityAction) is a row's action, [`SecurityPermissionFlags`](crate::metadata::security::SecurityPermissionFlags) the
//!   `SecurityPermissionFlag` enum.
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("legacy_app.dll")?;
//! for entry in assembly.types().iter() {
//!     let type_def = entry.value();
//!     for (_, security) in type_def.security.iter() {
//!         println!("{} {}: {}", security.action, type_def.name, security.permission_set);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

pub mod builders;
mod encoder;
mod permission;
mod permissionset;
mod types;

pub use builders::*;
pub use encoder::*;
pub use permission::Permission;
pub use permissionset::PermissionSet;
pub use types::*;

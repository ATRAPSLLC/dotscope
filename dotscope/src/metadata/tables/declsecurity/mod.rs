//! `DeclSecurity` table module.
//!
//! This module provides complete support for the ECMA-335 `DeclSecurity` metadata table (0x0E),
//! which contains declarative security declarations for assemblies, types, and methods. It includes
//! raw table access, resolved data structures, permission set parsing for .NET Code Access Security (CAS),
//! and integration with the broader metadata system.
//!
//! # Architecture
//!
//! The `DeclSecurity` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved coded indices, while owned entries
//! provide fully resolved references with parsed permission sets integrated with target
//! metadata elements.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::DeclSecurityRaw`] - Raw table structure with unresolved coded indexes
//! - [`crate::metadata::tables::DeclSecurity`] - Owned variant with resolved references and parsed permission sets
//! - [`crate::metadata::loader::tables::DeclSecurityLoader`] - Internal loader for processing `DeclSecurity` table data
//! - [`crate::metadata::tables::DeclSecurityMap`] - Token-based lookup map
//! - [`crate::metadata::tables::DeclSecurityList`] - Collection type
//! - [`crate::metadata::tables::DeclSecurityRc`] - Reference-counted pointer
//!
//! # `DeclSecurity` Table Structure
//!
//! Each `DeclSecurity` table row contains these fields:
//! - **Action**: Security action type (Demand, Assert, Deny, etc.)
//! - **Parent**: Target element where security is applied (coded index)
//! - **`PermissionSet`**: Serialized security permissions (blob)
//!
//! The parent can be any metadata element that supports the `HasDeclSecurity` coded index,
//! including assemblies, types (`TypeDef`), and methods (`MethodDef`).
//!
//! # Security Actions
//!
//! The .NET security model supports various declarative actions:
//! - **Demand**: Require callers to have specific permissions at runtime
//! - **Assert**: Temporarily escalate permissions for trusted code paths
//! - **Deny**: Prevent code from using certain permissions even if granted
//! - **`LinkDemand`**: Check permissions at JIT compilation time
//! - **`InheritanceDemand`**: Require permissions for type inheritance
//! - **`PermitOnly`**: Restrict permissions to only those specified
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::DeclSecurity;
//! use dotscope::metadata::token::Token;
//! use dotscope::Result;
//!
//! # fn example(decl_security: &DeclSecurity) -> Result<()> {
//! // Access security declaration for a method
//! let method_token = Token::new(0x06000001); // MethodDef token
//!
//! if decl_security.token == method_token {
//!     println!("Security action: {:?}", decl_security.action);
//!     println!("Permission set: {} items", decl_security.permission_set.permissions().len());
//!     // Process the security declaration...
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! This module defines error conditions for security processing:
//! - Permission set parsing errors when blob data is malformed
//! - Coded index resolution errors for invalid parent references
//! - Security action validation errors for unsupported actions
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe through the use of atomic operations
//! and concurrent data structures. Security declarations can be safely accessed
//! and processed from multiple threads simultaneously.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - [`crate::metadata::streams::Blob`] - Blob heap for permission set data
//!
//! # References
//!
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification
//! - [ECMA-335 II.23.1.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `SecurityAction` enumeration

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::declsecurity::DeclSecurity`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `DeclSecurity` entries indexed by their metadata tokens.
pub type DeclSecurityMap = SkipMap<Token, DeclSecurityRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::declsecurity::DeclSecurity`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `DeclSecurity` collections.
pub type DeclSecurityList = Arc<boxcar::Vec<DeclSecurityRc>>;

/// Reference-counted smart pointer to a [`crate::metadata::tables::declsecurity::DeclSecurity`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `DeclSecurity` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type DeclSecurityRc = Arc<DeclSecurity>;

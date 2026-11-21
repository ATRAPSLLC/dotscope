//! `TypeRef` table support for .NET metadata.
//!
//! This module provides comprehensive support for the `TypeRef` metadata table (ID 0x01),
//! which contains references to types defined in external assemblies or modules.
//! `TypeRef` entries are essential for cross-assembly type resolution and linking.
//!
//! ## Table Structure
//! The `TypeRef` table contains the following columns:
//! - **`ResolutionScope`** (coded index): Parent scope (`Module`, `ModuleRef`, `AssemblyRef`, or `TypeRef`)
//! - **`TypeName`** (string heap index): Simple name of the referenced type
//! - **`TypeNamespace`** (string heap index): Namespace containing the referenced type
//!
//! ## Module Contents
//! - [`crate::metadata::tables::typeref::raw::TypeRefRaw`] - Raw table entry representation
//! - [`crate::metadata::loader::tables::TypeRefLoader`] - Table loading and processing functionality
//!
//! ## ECMA-335 Reference
//! See ECMA-335, Partition II, Section 22.38 for the complete `TypeRef` table specification.

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

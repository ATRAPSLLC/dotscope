//! `LocalConstant` table module for Portable PDB format
//!
//! This module provides complete support for the Portable PDB `LocalConstant` metadata table (0x34),
//! which stores information about local constants within method scopes, including their names,
//! signatures, and constant values. It includes raw table access, resolved data structures, constant
//! analysis, and integration with the broader metadata system.
//!
//! # Components
//!
//! - [`LocalConstantRaw`]: Raw table structure with unresolved heap indices
//! - [`LocalConstant`]: Owned variant with resolved references and constant information
//! - [`LocalConstantLoader`]: Internal loader for processing `LocalConstant` table data
//! - Type aliases for efficient collections and reference management
//!
//! # `LocalConstant` Table Structure
//!
//! Each `LocalConstant` table row contains these fields:
//! - **Name**: Index into #Strings heap for the constant name
//! - **Signature**: Index into #Blob heap for the constant signature
//!
//! This table is part of the Portable PDB format and provides essential information
//! for debuggers to display constant names and values during code execution.
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::LocalConstant;
//! # fn example(local_constant: &LocalConstant) {
//! // Display constant information
//! println!("Constant '{}' with signature: {:?}", local_constant.name, local_constant.signature);
//!
//! // Check for anonymous constants
//! if local_constant.name.is_empty() {
//!     println!("Anonymous or compiler-generated constant");
//! }
//!
//! // Analyze the signature: its custom modifiers, then the type and value
//! if !local_constant.signature.modifiers.is_empty() {
//!     println!("Constant has {} custom modifiers", local_constant.signature.modifiers.len());
//! }
//! # }
//! ```
//!
//! # Reference
//! - [Portable PDB Format - LocalConstant Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localconstant-table-0x34)

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod loader;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`LocalConstant`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved local constant information by their metadata tokens.
pub type LocalConstantMap = SkipMap<Token, LocalConstantRc>;

/// A vector that holds a list of [`LocalConstant`] references
///
/// Thread-safe append-only vector for storing local constant collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type LocalConstantList = Arc<boxcar::Vec<LocalConstantRc>>;

/// A reference-counted pointer to a [`LocalConstant`]
///
/// Provides shared ownership and automatic memory management for local constant instances.
/// Multiple references can safely point to the same local constant data across threads.
pub type LocalConstantRc = Arc<LocalConstant>;

//! `LocalVariable` table module for Portable PDB format
//!
//! This module provides complete support for the Portable PDB `LocalVariable` metadata table (0x33),
//! which stores information about local variables within method scopes, including their names,
//! signatures, and attributes. It includes raw table access, resolved data structures, variable
//! analysis, and integration with the broader metadata system.
//!
//! # Components
//!
//! - [`LocalVariableRaw`]: Raw table structure with unresolved heap indices
//! - [`LocalVariable`]: Owned variant with resolved references and variable information
//! - [`LocalVariableLoader`](crate::metadata::loader::tables::LocalVariableLoader): Internal loader for processing `LocalVariable` table data
//! - Type aliases for efficient collections and reference management
//!
//! # `LocalVariable` Table Structure
//!
//! Each `LocalVariable` table row contains these fields:
//! - **Attributes**: 2-byte flags indicating variable characteristics
//! - **Index**: 2-byte variable index within the method
//! - **Name**: Index into #Strings heap for the variable name
//!
//! This table is part of the Portable PDB format and provides essential information
//! for debuggers to display variable names and values during code execution.
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! # use dotscope::metadata::tables::LocalVariable;
//! # fn example(local_variable: &LocalVariable) {
//! // Display variable information
//! println!("Variable '{}' at index {}", local_variable.name, local_variable.index);
//! println!("Variable attributes: 0x{:X}", local_variable.attributes);
//!
//! // Check if variable has special attributes
//! if local_variable.attributes != 0 {
//!     println!("Variable has special attributes");
//! }
//!
//! // Check for anonymous variables
//! if local_variable.name.is_empty() {
//!     println!("Anonymous or compiler-generated variable");
//! }
//! # }
//! ```
//!
//! # Reference
//! - [Portable PDB Format - LocalVariable Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localvariable-table-0x33)

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

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`LocalVariable`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved local variable information by their metadata tokens.
pub type LocalVariableMap = SkipMap<Token, LocalVariableRc>;

/// A vector that holds a list of [`LocalVariable`] references
///
/// Thread-safe append-only vector for storing local variable collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type LocalVariableList = Arc<boxcar::Vec<LocalVariableRc>>;

/// A reference-counted pointer to a [`LocalVariable`]
///
/// Provides shared ownership and automatic memory management for local variable instances.
/// Multiple references can safely point to the same local variable data across threads.
pub type LocalVariableRc = Arc<LocalVariable>;

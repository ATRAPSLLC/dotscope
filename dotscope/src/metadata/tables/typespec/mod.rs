//! `TypeSpec` table support for .NET metadata parsing and type specification handling.
//!
//! This module provides comprehensive support for the `TypeSpec` metadata table, which contains
//! type specifications for complex type constructions that cannot be represented by simple
//! `TypeRef` or `TypeDef` entries. `TypeSpec` entries are essential for handling modern .NET
//! features like generics, arrays, pointers, and custom type modifiers.
//!
//! ## `TypeSpec` Table Overview
//!
//! The `TypeSpec` table stores blob signatures for complex type constructions:
//!
//! ### Generic Type Instantiations
//! ```text
//! List<string>                    → Generic class with single type argument
//! Dictionary<int, string>         → Generic class with multiple type arguments
//! IEnumerable<T>                  → Generic interface specification
//! Nullable<DateTime>              → Generic value type instantiation
//! ```
//!
//! ### Array Types
//! ```text
//! int[]                          → Single-dimensional zero-based array
//! string[,]                      → Multi-dimensional array (2D)
//! byte[1..10]                    → Array with explicit bounds
//! float[0..5, 0..3]              → Multi-dimensional array with bounds
//! ```
//!
//! ### Pointer and Reference Types
//! ```text
//! int*                           → Unmanaged pointer to int
//! void*                          → Generic unmanaged pointer
//! ref int                        → Managed reference (byref)
//! out string                     → Output parameter reference
//! ```
//!
//! ### Function Pointer Types
//! ```text
//! delegate*<int, string, bool>   → Function pointer with signature
//! delegate* managed<void>        → Managed function pointer
//! delegate* unmanaged<int>       → Unmanaged function pointer
//! ```
//!
//! ### Modified Types
//! ```text
//! volatile int                   → Type with volatile modifier
//! const string                   → Type with const modifier
//! pinned byte[]                  → Type with pinned modifier
//! ```
//!
//! ## Module Components
//!
//! - [`TypeSpecRaw`] - Raw table entry format for binary parsing
//! - [`TypeSpec`] - Fully parsed and validated type specification
//! - [`TypeSpecLoader`](crate::metadata::loader::tables::TypeSpecLoader) - Parallel loading and validation logic
//! - [`TypeSpecMap`] - Token-indexed storage for efficient lookup
//! - [`TypeSpecList`] - Sequential storage for iteration
//! - [`TypeSpecRc`] - Reference-counted shared access
//!
//! ## ECMA-335 Specification
//!
//! From ECMA-335, Partition II, Section 22.39:
//! > The TypeSpec table has the following column:
//! > - Signature (an index into the Blob heap, where the blob is formatted according to the TypeSpec signature format)
//!
//! The `TypeSpec` signature format supports:
//! - Generic instantiations (`ELEMENT_TYPE_GENERICINST`)
//! - Arrays (`ELEMENT_TYPE_ARRAY`, `ELEMENT_TYPE_SZARRAY`)
//! - Pointers (`ELEMENT_TYPE_PTR`)
//! - References (`ELEMENT_TYPE_BYREF`)
//! - Function pointers (`ELEMENT_TYPE_FNPTR`)
//! - Custom modifiers (`ELEMENT_TYPE_CMOD_OPT`, `ELEMENT_TYPE_CMOD_REQD`)
//!
//! ## Reference
//!
//! * [ECMA-335 Partition II, Section 22.39](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `TypeSpec` Table
//! * [ECMA-335 Partition II, Section 23.2.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `TypeSpec` Signatures
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

/// Token-indexed map for efficient `TypeSpec` lookup and storage.
///
/// This concurrent skip list provides thread-safe storage for type specifications
/// indexed by their metadata tokens. The data structure is optimized for concurrent
/// access patterns common in metadata parsing scenarios.
pub type TypeSpecMap = SkipMap<Token, TypeSpecRc>;

/// Thread-safe vector for sequential `TypeSpec` storage and iteration.
///
/// This append-only vector provides efficient sequential access to type specifications
/// while maintaining thread safety for concurrent operations. The vector is optimized
/// for scenarios where specifications are added during parsing and later iterated.
pub type TypeSpecList = Arc<boxcar::Vec<TypeSpecRc>>;

/// Reference-counted shared access to `TypeSpec` instances.
///
/// This type alias provides convenient shared ownership of type specifications,
/// enabling zero-copy sharing across multiple threads and data structures without
/// lifetime management complexity.
pub type TypeSpecRc = Arc<TypeSpec>;

//! `MemberRef` table implementation for external member references.
//!
//! This module provides complete support for the `MemberRef` metadata table, which defines
//! references to members (fields and methods) in external assemblies or modules. The `MemberRef`
//! table is essential for cross-assembly interoperability, late binding, and dynamic member
//! access in .NET applications.
//!
//! # Module Components
//! - [`MemberRefRaw`] - Raw table structure with unresolved coded indexes and heap references
//! - [`MemberRef`] - Owned variant with resolved references and parsed signatures
//! - [`MemberRefLoader`](crate::metadata::loader::tables::MemberRefLoader) - Internal loader for processing table entries (crate-private)
//! - [`MemberRefSignature`] - Union type for method and field signature representations
//! - Type aliases for collections: [`MemberRefMap`], [`MemberRefList`], [`MemberRefRc`]
//!
//! # Table Structure (ECMA-335 §22.25)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Class | `MemberRefParent` coded index | Declaring type or module reference |
//! | Name | String heap index | Member name identifier |
//! | Signature | Blob heap index | Member signature (method or field) |
//!
//! # Member Reference Types
//! The `MemberRef` table supports references to different kinds of external members:
//! - **Field references**: External field access with type information and metadata
//! - **Method references**: External method calls with parameter and return type signatures
//! - **Constructor references**: Object creation with parameter specifications
//! - **Generic member references**: Generic methods and fields with type parameter resolution
//! - **Vararg method references**: Variable argument method calls with parameter lists
//!
//! # Parent Reference Types
//! The Class column uses `MemberRefParent` coded index encoding to specify the declaring context:
//! - **`TypeDef`**: Members declared in the current assembly's types
//! - **`TypeRef`**: Members declared in external assembly types
//! - **`ModuleRef`**: Global members declared in external modules
//! - **`MethodDef`**: Vararg method signatures referencing specific method definitions
//! - **`TypeSpec`**: Members of generic type instantiations
//!
//! # Signature Resolution
//! Member signatures in the blob heap are parsed according to their type:
//! - **Method signatures**: Include calling convention, parameter count, return type, and parameter types
//! - **Field signatures**: Include field type information and modifiers
//! - **Generic signatures**: Include type parameter specifications and constraints
//! - **Vararg signatures**: Include fixed and variable parameter specifications
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.25: `MemberRef` table specification
//! - ECMA-335, Partition II, §23.2.6: `MemberRefParent` coded index encoding
//! - ECMA-335, Partition II, §23.2: Method and field signature specifications
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::{
    signatures::{SignatureField, SignatureMethod},
    streams::SharedStr,
    token::Token,
};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Concurrent map for storing `MemberRef` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of member references by their
/// associated tokens during metadata processing and member resolution operations.
pub type MemberRefMap = SkipMap<Token, MemberRefRc>;

/// Thread-safe list for storing collections of `MemberRef` entries.
///
/// Used for maintaining ordered sequences of member references during metadata
/// loading and for iteration over all members in an assembly.
pub type MemberRefList = Arc<boxcar::Vec<MemberRefRc>>;

/// Reference-counted pointer to a [`MemberRef`] instance.
///
/// Enables efficient sharing of member reference data across multiple contexts
/// without duplication, supporting concurrent access patterns in member resolution.
pub type MemberRefRc = Arc<MemberRef>;

/// Returns the name of the member reference for the given token, if it exists in the map.
///
/// This is a convenience function that performs a lookup in a [`MemberRefMap`] and extracts
/// the member name without requiring callers to deal with the `Entry` guard returned
/// by the underlying [`crossbeam_skiplist::SkipMap`].
///
/// # Arguments
///
/// * `map` - The member reference map to search in.
/// * `token` - The metadata token (table 0x0A) identifying the member reference.
///
/// # Returns
///
/// The member name, shared with the reference, if a reference with the given token exists,
/// `None` otherwise.
pub fn member_ref_name_by_token(map: &MemberRefMap, token: &Token) -> Option<SharedStr> {
    map.get(token).map(|e| e.value().name.clone())
}

/// Member signature type union for `MemberRef` entries.
///
/// This enum represents the two possible signature types for member references:
/// method signatures (including constructors) and field signatures. The signature
/// type is determined by parsing the blob heap data according to the signature
/// calling convention and type encoding.
///
/// # Signature Determination
/// The signature type is determined by the first byte of the blob heap data:
/// - **Method signatures**: Have calling convention flags (0x00-0x0F, 0x20, 0x30)
/// - **Field signatures**: Have field signature marker (0x06)
/// - **Property signatures**: Have property signature marker (0x08, handled as field)
// ToDo: Verify if we handle this properly (Field vs Property)
pub enum MemberRefSignature {
    /// Method signature including calling convention, parameters, and return type.
    ///
    /// Used for method calls, constructor invocations, and function pointer operations.
    /// Contains complete parameter and return type information for type checking
    /// and invocation parameter validation.
    Method(SignatureMethod),

    /// Field signature including field type and modifiers.
    ///
    /// Used for field access operations and property implementations.
    /// Contains type information for field value validation and conversion operations.
    Field(SignatureField),
}

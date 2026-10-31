//! Owned `LocalConstant` table representation
//!
//! This module provides the [`LocalConstant`] struct that represents
//! the high-level, resolved form of `LocalConstant` table entries with
//! all heap references resolved to actual string and binary data.

use crate::metadata::{pdb::LocalConstantSig, token::Token};

/// High-level representation of a `LocalConstant` table entry
///
/// This structure provides the resolved form of `LocalConstant` table data
/// with all heap indices resolved to their actual values. The name field
/// contains the resolved string data from the #Strings heap, and the
/// signature field contains the parsed type signature from the #Blob heap.
///
/// # Usage Examples
///
/// ```no_run
/// use dotscope::metadata::tables::LocalConstant;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// // Access constant information with parsed signature
/// println!("Constant '{}' with type: {:?}", constant.name, constant.signature.base);
///
/// // Check the constant's type
/// match &constant.signature.base {
///     TypeSignature::I4 => println!("Integer constant"),
///     TypeSignature::String => println!("String constant"),
///     TypeSignature::R8 => println!("Double constant"),
///     _ => println!("Other type constant"),
/// }
///
/// // Check for custom modifiers
/// if !constant.signature.modifiers.is_empty() {
///     println!("Constant has {} custom modifiers", constant.signature.modifiers.len());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LocalConstant {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `LocalConstant` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Constant name resolved from #Strings heap
    ///
    /// The actual name string for this local constant. May be empty for
    /// anonymous or compiler-generated constants where no name was specified.
    pub name: String,

    /// Parsed constant signature: the constant's type and its value
    ///
    /// The structured representation of the LocalConstantSig blob the Signature column
    /// names. Unlike a field signature, it holds the value as well as the type:
    ///
    /// - **Custom modifiers**: the modifiers on the constant's type, in signature order
    /// - **Primitive constants**: `bool`, `char`, the integer and floating-point types and
    ///   `string`, with their value
    /// - **Enum constants**: the underlying value, with the enum type's token
    /// - **General constants**: `decimal` and `DateTime` values, a null reference of any
    ///   class type, and the default value of any other type
    ///
    /// [`LocalConstantSig`] documents each form. A row has to have a signature: a nil
    /// Signature column fails the row, since a constant has no meaning without its value.
    pub signature: LocalConstantSig,
}

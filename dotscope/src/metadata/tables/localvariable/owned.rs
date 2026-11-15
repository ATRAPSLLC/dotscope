//! Owned `LocalVariable` table representation
//!
//! This module provides the [`LocalVariable`] struct that represents
//! the high-level, resolved form of `LocalVariable` table entries with
//! all heap references resolved to actual string data.

use crate::metadata::token::Token;

/// High-level representation of a `LocalVariable` table entry
///
/// This structure provides the resolved form of `LocalVariable` table data
/// with all heap indices resolved to their actual values. The name field
/// contains the resolved string data from the #Strings heap.
///
/// # Usage
///
/// ```no_run
/// use dotscope::metadata::tables::LocalVariable;
///
/// # fn example(variable: &LocalVariable) {
/// // Access variable information
/// println!("Variable '{}' at index {} with attributes 0x{:X}",
///          variable.name, variable.index, variable.attributes);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LocalVariable {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `LocalVariable` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Variable attribute flags
    ///
    /// A bitfield containing flags that describe characteristics of the local variable.
    /// Common flags include whether the variable is a compiler-generated temporary,
    /// whether it's a pinned variable, etc.
    pub attributes: u16,

    /// Variable index within the method
    ///
    /// Zero-based index that identifies this variable within the containing method.
    /// This index corresponds to the variable's position in the method's local
    /// variable signature and IL instructions.
    pub index: u16,

    /// Variable name resolved from #Strings heap
    ///
    /// The actual name string for this local variable. May be empty for
    /// anonymous or compiler-generated variables where no name was specified.
    pub name: String,
}

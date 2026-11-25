//! Raw `LocalVariable` table representation for Portable PDB format
//!
//! This module provides the [`LocalVariableRaw`] struct that represents
//! the binary format of `LocalVariable` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use std::sync::Arc;

use crate::{
    metadata::{
        streams::{SharedStr, Strings},
        tables::{LocalVariable, LocalVariableRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw binary representation of a `LocalVariable` table entry
///
/// This structure matches the exact binary layout of `LocalVariable` table
/// entries in the metadata tables stream. The Name field contains an unresolved
/// index into the #Strings heap that must be resolved during conversion
/// to the owned [`LocalVariable`] variant.
///
/// # Binary Format
///
/// Each `LocalVariable` table entry consists of:
/// - Attributes: 2-byte unsigned integer with variable flags
/// - Index: 2-byte unsigned integer (variable index within method)
/// - Name: Index into #Strings heap for the variable name
#[derive(Debug, Clone)]
pub struct LocalVariableRaw {
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

    /// Index into #Strings heap for variable name
    ///
    /// Points to the variable's name string in the metadata #Strings heap.
    /// This index must be resolved to get the actual variable name string.
    /// May be 0 for anonymous or compiler-generated variables.
    pub name: u32,
}

impl LocalVariableRaw {
    /// Converts this raw `LocalVariable` entry to an owned [`LocalVariable`] instance
    ///
    /// This method resolves the raw `LocalVariable` entry to create a complete `LocalVariable`
    /// object by resolving the name string from the #Strings heap.
    ///
    /// # Parameters
    /// - `strings`: Reference to the #Strings heap for resolving the name index
    ///
    /// # Returns
    /// Returns `Ok(LocalVariableRc)` with the resolved variable data, or an error if
    /// the name index is invalid or points to malformed string data.
    ///
    /// # Errors
    /// Returns an error if the name index is invalid or points to malformed string data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::LocalVariableRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example(strings: &dotscope::metadata::streams::Strings) -> dotscope::Result<()> {
    /// let variable_raw = LocalVariableRaw {
    ///     rid: 1,
    ///     token: Token::new(0x33000001),
    ///     offset: 0,
    ///     attributes: 0,      // No special attributes
    ///     index: 0,           // First local variable
    ///     name: 42,           // Index into #Strings heap
    /// };
    ///
    /// let variable = variable_raw.to_owned(strings)?;
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_owned(&self, strings: &Strings) -> Result<LocalVariableRc> {
        let name = if self.name == 0 {
            SharedStr::default()
        } else {
            strings.get_shared(self.name as usize)?
        };

        let variable = LocalVariable {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            attributes: self.attributes,
            index: self.index,
            name,
        };

        Ok(Arc::new(variable))
    }
}

impl TableRow for LocalVariableRaw {
    /// Calculate the row size for `LocalVariable` table entries
    ///
    /// Returns the total byte size of a single `LocalVariable` table row based on the
    /// table configuration. The size varies depending on the size of heap indexes in the metadata.
    ///
    /// # Size Breakdown
    /// - `attributes`: 2 bytes (variable attribute flags)
    /// - `index`: 2 bytes (variable index within method)
    /// - `name`: 2 or 4 bytes (string heap index for variable name)
    ///
    /// Total: 6-8 bytes depending on heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* attributes */ 2u8
            /* index */      .saturating_add(2)
            /* name */       .saturating_add(sizes.str_bytes())

        )
    }
}

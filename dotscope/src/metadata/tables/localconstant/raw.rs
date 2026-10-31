//! Raw `LocalConstant` table representation for Portable PDB format
//!
//! This module provides the [`LocalConstantRaw`] struct that represents
//! the binary format of `LocalConstant` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use std::sync::Arc;

use crate::{
    metadata::{
        pdb::LocalConstantSig,
        streams::{Blob, Strings},
        tables::{LocalConstant, LocalConstantRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw binary representation of a `LocalConstant` table entry
///
/// This structure matches the exact binary layout of `LocalConstant` table
/// entries in the metadata tables stream. Both Name and Signature fields contain
/// unresolved indices into their respective heaps that must be resolved during
/// conversion to the owned [`LocalConstant`] variant.
///
/// # Binary Format
///
/// Each `LocalConstant` table entry consists of:
/// - Name: Index into #Strings heap for the constant name
/// - Signature: Index into #Blob heap for the constant signature
#[derive(Debug, Clone)]
pub struct LocalConstantRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `LocalConstant` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Index into #Strings heap for constant name
    ///
    /// Points to the constant's name string in the metadata #Strings heap.
    /// This index must be resolved to get the actual constant name string.
    /// May be 0 for anonymous or compiler-generated constants.
    pub name: u32,

    /// Index into #Blob heap for constant signature
    ///
    /// Points to the constant's signature blob in the metadata #Blob heap.
    /// The signature describes the constant's type and value information.
    /// This index must be resolved to get the actual signature data.
    pub signature: u32,
}

impl LocalConstantRaw {
    /// Converts this raw `LocalConstant` entry to an owned [`LocalConstant`] instance
    ///
    /// This method resolves the raw `LocalConstant` entry to create a complete `LocalConstant`
    /// object by resolving the name string from the #Strings heap and signature data
    /// from the #Blob heap.
    ///
    /// # Parameters
    /// - `strings`: Reference to the #Strings heap for resolving the name index
    /// - `blobs`: Reference to the #Blob heap for resolving the signature index
    ///
    /// # Returns
    /// Returns `Ok(LocalConstantRc)` with the resolved constant data, or an error if
    /// the name or signature indices are invalid or point to malformed data.
    ///
    /// # Errors
    /// Returns an error if the name or signature indices are invalid or if the data is malformed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dotscope::metadata::tables::LocalConstantRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example() -> dotscope::Result<()> {
    /// let constant_raw = LocalConstantRaw {
    ///     rid: 1,
    ///     token: Token::new(0x34000001),
    ///     offset: 0,
    ///     name: 42,           // Index into #Strings heap
    ///     signature: 100,     // Index into #Blob heap
    /// };
    ///
    /// let constant = constant_raw.to_owned(strings, blobs)?;
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_owned(&self, strings: &Strings, blobs: &Blob) -> Result<LocalConstantRc> {
        let name = if self.name == 0 {
            String::new()
        } else {
            strings.get(self.name as usize)?.to_string()
        };

        // A constant's signature is its type and value: there is no constant without one
        if self.signature == 0 {
            return Err(malformed_error!(
                "LocalConstant row {} has no signature",
                self.rid
            ));
        }
        let signature = LocalConstantSig::parse(blobs.get(self.signature as usize)?)?;

        let constant = LocalConstant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name,
            signature,
        };

        Ok(Arc::new(constant))
    }
}

impl TableRow for LocalConstantRaw {
    /// Calculate the byte size of a LocalConstant table row
    ///
    /// Returns the total size of one row in the LocalConstant table, including:
    /// - name: 2 or 4 bytes (String heap index)
    /// - signature: 2 or 4 bytes (Blob heap index)
    ///
    /// The index sizes depend on the metadata heap requirements.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* name */      sizes.str_bytes()
            /* signature */ .saturating_add(sizes.blob_bytes())

        )
    }
}

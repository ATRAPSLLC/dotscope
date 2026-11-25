//! Raw Field structures for the Field metadata table.
//!
//! This module provides the [`crate::metadata::tables::field::raw::FieldRaw`] struct for reading field definition data
//! directly from metadata tables before index resolution. The Field table defines
//! data members for types, including instance fields, static fields, and literals.
//!
//! # Table Structure
//! The Field table (`TableId` = 0x04) contains these columns:
//! - `Flags`: 2-byte `FieldAttributes` bitmask
//! - `Name`: Index into String heap for field name
//! - `Signature`: Index into Blob heap for field type signature
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.15 for the Field table specification.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        signatures::parse_field_signature,
        streams::{Blob, Strings},
        tables::{Field, FieldAttributes, FieldRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw field definition data read directly from the Field metadata table.
///
/// This structure represents a field entry before index resolution and string/blob
/// dereferencing. Fields define data members of types including instance fields,
/// static fields, and compile-time constants.
///
/// # Binary Format
/// Each row in the Field table has this layout:
/// ```text
/// Offset | Size | Field      | Description
/// -------|------|------------|----------------------------------
/// 0      | 2    | Flags      | FieldAttributes bitmask
/// 2      | 2/4  | Name       | String heap index
/// 4/6    | 2/4  | Signature  | Blob heap index
/// ```
///
/// The Name and Signature field sizes depend on the heap index sizes in the metadata.
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.15 for the complete Field table specification.
#[derive(Clone, Debug)]
pub struct FieldRaw {
    /// The row identifier in the Field table.
    ///
    /// This 1-based index uniquely identifies this field within the Field table.
    pub rid: u32,

    /// The metadata token for this field.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field across the entire assembly.
    /// The token value is calculated as `0x04000000 + rid`.
    pub token: Token,

    /// The byte offset of this field in the metadata tables stream.
    ///
    /// This offset points to the start of this field's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Field attributes and flags.
    ///
    /// A 2-byte bitmask of type `FieldAttributes` as defined in ECMA-335, §II.23.1.5.
    /// This includes accessibility, static/instance designation, and special flags.
    ///
    /// Common values:
    /// - `0x0001`: `CompilerControlled`
    /// - `0x0002`: Private
    /// - `0x0007`: Public
    /// - `0x0010`: Static
    /// - `0x0020`: Literal
    /// - `0x0080`: `HasFieldRVA`
    /// - `0x1000`: `HasDefault`
    /// - `0x2000`: `HasFieldMarshal`
    pub flags: u32,

    /// Index into the String heap for the field name.
    ///
    /// This index points to a null-terminated UTF-8 string in the String heap
    /// containing the field's identifier name.
    pub name: u32,

    /// Index into the Blob heap for the field type signature.
    ///
    /// This index points to a binary signature in the Blob heap that describes
    /// the field's type according to ECMA-335 signature encoding rules.
    pub signature: u32,
}

impl FieldRaw {
    /// Convert this raw field to an owned [`crate::metadata::tables::field::owned::Field`] with resolved indexes.
    ///
    /// This method resolves string and blob heap indexes to actual data and
    /// parses the field signature into a structured format.
    ///
    /// # Arguments
    /// * `blob` - The Blob heap for signature resolution
    /// * `strings` - The String heap for name resolution
    ///
    /// # Returns
    /// Returns an [`crate::metadata::tables::FieldRc`] with resolved data and lazy-initialized optional fields.
    ///
    /// # Errors
    /// Returns an error if:
    /// - String or blob heap lookup fails
    /// - Field signature parsing fails
    /// - Memory allocation fails
    pub fn to_owned(&self, blob: &Blob, strings: &Strings) -> Result<FieldRc> {
        Ok(Arc::new(Field {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: FieldAttributes::new(self.flags),
            name: strings.get_shared(self.name as usize)?,
            signature: parse_field_signature(blob.get(self.signature as usize)?)?,
            default: OnceLock::new(),
            rva: OnceLock::new(),
            layout: OnceLock::new(),
            marshal: OnceLock::new(),
            custom_attributes: Default::default(),
            declaring_type: OnceLock::new(),
        }))
    }

    /// Apply field-specific logic during metadata loading.
    ///
    /// Field entries define data members of types but don't modify other metadata
    /// structures during the dual variant resolution phase. Field-specific metadata
    /// such as default values, RVA data, layout information, and marshalling details
    /// are resolved separately through their respective tables.
    ///
    /// # Returns
    /// Always returns `Ok(())` as Field entries don't directly modify other tables.
    ///
    /// # Errors
    /// This function never returns an error but maintains the standard `apply()` signature
    /// for consistency with other metadata table implementations.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for FieldRaw {
    /// Calculate the byte size of a Field table row
    ///
    /// Computes the total size based on fixed-size fields plus variable-size heap indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.15)
    /// - `flags`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (string heap index)
    /// - `signature`: 2 or 4 bytes (blob heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for heap index widths
    ///
    /// # Returns
    /// Total byte size of one Field table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2u8
            /* name */      .saturating_add(sizes.str_bytes())
            /* signature */ .saturating_add(sizes.blob_bytes())

        )
    }
}

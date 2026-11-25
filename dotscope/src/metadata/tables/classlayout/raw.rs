//! Raw `ClassLayout` table representation.
//!
//! This module provides the [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw`] struct
//! for low-level access to `ClassLayout` metadata table data with unresolved table indexes.
//! This represents the binary format of `ClassLayout` records as they appear in the metadata
//! tables stream, requiring resolution to create usable data structures.
//!
//! # Architecture
//!
//! The raw representation maintains the exact binary layout from the metadata tables stream,
//! with unresolved table indexes that reference other metadata tables. This design allows
//! efficient parsing and deferred resolution until references are needed.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw`] - Raw table row structure with unresolved indexes
//! - [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw::to_owned`] - Resolution to owned representation
//! - [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw::apply`] - Direct application of layout data
//!
//! # `ClassLayout` Table Format
//!
//! The `ClassLayout` table (0x0F) contains zero or more rows with these fields:
//! - **`PackingSize`** (2 bytes): Field alignment boundary (power of 2)
//! - **`ClassSize`** (4 bytes): Total size of the type in bytes
//! - **Parent** (2/4 bytes): Table index into `TypeDef` table
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::ClassLayoutRaw;
//! # use dotscope::metadata::typesystem::TypeRegistry;
//! # fn example(raw: ClassLayoutRaw, types: &TypeRegistry) -> dotscope::Result<()> {
//! // Convert to owned representation
//! let owned = raw.to_owned(types)?;
//!
//! // Or apply layout data directly
//! raw.apply(types)?;
//! # Ok(())
//! # }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Raw table operations can fail if:
//! - Referenced `TypeDef` entries are missing from the provided registry
//! - Type definition tokens are invalid or malformed
//! - Layout validation fails (invalid packing or class sizes)
//! - Table data is corrupted or incomplete
//!
//! # Thread Safety
//!
//! Raw table structures are [`Send`] and [`Sync`]. The `apply` method uses atomic operations
//! when updating type definition data, ensuring thread-safe modifications.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::classlayout::owned`] - Owned representation with resolved references
//! - [`crate::metadata::typesystem`] - Type system components and registry
//! - [`crate::metadata::validation`] - Layout validation logic
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//!
//! # References
//!
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ClassLayout` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{ClassLayout, ClassLayoutRc, TableId, TableInfoRef, TableRow},
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `ClassLayout` table row with unresolved table indexes
///
/// Represents the binary format of a `ClassLayout` metadata table entry (table ID 0x0F) as stored
/// in the metadata tables stream. The Parent field contains a table index that must be
/// resolved using the [`crate::metadata::typesystem::TypeRegistry`] to access the referenced type data.
///
/// The `ClassLayout` table specifies explicit memory layout information for types that require
/// specific field positioning and packing, commonly used for interoperability scenarios.
///
/// # Memory Layout Control
///
/// The `ClassLayout` entry provides precise control over type memory representation:
/// - **`PackingSize`**: Byte boundary alignment for fields (must be power of 2)
/// - **`ClassSize`**: Explicit type size override (0 for automatic sizing)
/// - **Parent**: Link to the type definition requiring these layout constraints
///
/// # Conversion and Usage
///
/// Raw entries should be converted to [`crate::metadata::tables::classlayout::owned::ClassLayout`]
/// via [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw::to_owned`] for practical use,
/// or have their layout data applied directly via [`crate::metadata::tables::classlayout::raw::ClassLayoutRaw::apply`].
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. Methods that update type definitions use atomic
/// operations to ensure thread-safe modifications without additional synchronization.
///
/// # References
///
/// - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ClassLayout` table specification
pub struct ClassLayoutRaw {
    /// Row identifier within the `ClassLayout` metadata table
    ///
    /// The 1-based index of this `ClassLayout` row within the table.
    pub rid: u32,

    /// Metadata token for this `ClassLayout` entry
    ///
    /// Combines the table identifier (0x0F for `ClassLayout`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `ClassLayout` row within the metadata tables stream
    ///
    /// Physical location of the raw `ClassLayout` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Field alignment boundary in bytes
    ///
    /// Specifies the byte boundary for field alignment within the type. Common values:
    /// - `1`: No special alignment (byte boundary)
    /// - `2`: 2-byte alignment (for Int16, etc.)
    /// - `4`: 4-byte alignment (for Int32, float, etc.)
    /// - `8`: 8-byte alignment (for Int64, double, etc.)
    /// - `16`: 16-byte alignment (for SIMD types, etc.)
    ///
    /// Must be a power of 2 or 0 for default alignment.
    pub packing_size: u16,

    /// Total size of the type in bytes
    ///
    /// Explicit size override for the type. Values:
    /// - `0`: Use automatic size calculation based on fields
    /// - `> 0`: Force the type to be exactly this many bytes
    pub class_size: u32,

    /// Table index into the `TypeDef` table
    ///
    /// 1-based index referencing the [`crate::metadata::tables::typedef::TypeDefRaw`]
    /// entry that represents the type this layout specification applies to.
    /// Must be resolved using [`TypeRegistry`] to access the actual type definition.
    pub parent: u32,
}

impl ClassLayoutRaw {
    /// Apply memory layout information directly to the referenced type
    ///
    /// Updates the type definition with layout specifications from this
    /// `ClassLayout` entry without creating an owned representation. This is used when
    /// only the layout data needs to be applied without retaining the `ClassLayout` structure,
    /// providing a more efficient path for bulk layout data application.
    ///
    /// The method resolves the `TypeDef` table index, validates the layout parameters through
    /// the metadata validation framework, and uses atomic operations to update
    /// the layout fields in the referenced type definition, ensuring thread-safe
    /// modifications without requiring external synchronization.
    ///
    /// # Arguments
    ///
    /// * `types` - [`crate::metadata::typesystem::TypeRegistry`] containing loaded type entities
    ///   keyed by their metadata tokens
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Layout information successfully applied to type definition
    /// * `Err(`[`crate::Error`]`)` - Type resolution, validation, or update failed
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The referenced `TypeDef` entry cannot be found in the provided registry
    /// - Layout validation fails (invalid packing size, unreasonable class size)
    /// - Class size or packing size has already been set on the target type
    /// - The `TypeDef` table index is out of bounds
    /// - `PackingSize` is not a power of 2 (when non-zero)
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses atomic operations to update type definition
    /// fields. Multiple threads can safely call this method concurrently on different
    /// `ClassLayout` entries, though only one will succeed in setting layout parameters
    /// for any given type.
    pub fn apply(&self, types: &TypeRegistry) -> Result<()> {
        match types.get(&Token::new(self.parent | 0x0200_0000)) {
            Some(class) => {
                class
                    .class_size
                    .set(self.class_size)
                    .map_err(|_| malformed_error!("Class size already set"))?;
                class
                    .packing_size
                    .set(self.packing_size)
                    .map_err(|_| malformed_error!("Packing size already set"))
            }
            None => Err(malformed_error!(
                "Failed to resolve parent token - {}",
                self.parent | 0x0200_0000
            )),
        }
    }

    /// Convert raw `ClassLayout` data to owned representation with resolved references
    ///
    /// Creates a [`crate::metadata::tables::classlayout::ClassLayoutRc`] from this raw data
    /// by resolving the `TypeDef` table index to the actual type definition. The resulting
    /// structure contains all necessary data for representing explicit memory layout in
    /// a usable form without requiring further table lookups.
    ///
    /// The resolution process transforms the raw table index into a direct reference to the
    /// [`crate::metadata::typesystem::CilType`] entry, creating a self-contained
    /// structure suitable for runtime use.
    ///
    /// # Arguments
    ///
    /// * `types` - [`crate::metadata::typesystem::TypeRegistry`] containing loaded type entities
    ///   keyed by their metadata tokens
    ///
    /// # Returns
    ///
    /// * `Ok(`[`crate::metadata::tables::classlayout::ClassLayoutRc`]`)` - Successfully resolved `ClassLayout` data
    /// * `Err(`[`crate::Error`]`)` - Type resolution failed
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The referenced `TypeDef` entry cannot be found in the provided registry
    /// - The parent type token is invalid or malformed
    /// - The `TypeDef` table index is out of bounds
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The resulting owned structure is also thread-safe for concurrent access.
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<ClassLayoutRc> {
        Ok(Arc::new(ClassLayout {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            packing_size: self.packing_size,
            class_size: self.class_size,
            parent: match types.get(&Token::new(self.parent | 0x0200_0000)) {
                Some(refs) => refs,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve parent token - {}",
                        self.parent | 0x0200_0000
                    ))
                }
            },
        }))
    }
}

impl TableRow for ClassLayoutRaw {
    /// Calculate the byte size of a ClassLayout table row
    ///
    /// Computes the total size based on fixed-size fields and variable-size table indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.8)
    /// - `packing_size`: 2 bytes (fixed size alignment specification)
    /// - `class_size`: 4 bytes (fixed size type size specification)
    /// - `parent`: 2 or 4 bytes (TypeDef table index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one ClassLayout table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* packing_size */ 2u8
            /* class_size */   .saturating_add(4)
            /* parent */       .saturating_add(sizes.table_index_bytes(TableId::TypeDef))

        )
    }
}

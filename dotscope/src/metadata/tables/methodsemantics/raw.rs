//! Raw `MethodSemantics` table implementation for .NET metadata parsing.
//!
//! This module provides the raw variant of [`crate::metadata::tables::methodsemantics::raw::MethodSemanticsRaw`] table entries with unresolved
//! indexes for initial parsing and memory-efficient storage. The `MethodSemantics` table is a critical
//! component of .NET metadata that defines the semantic relationships between methods and properties/events,
//! enabling the .NET runtime to understand accessor patterns and event handling mechanisms.
//!
//! # Architecture
//!
//! The raw implementation provides the foundation for method semantic parsing:
//! - **Unresolved References**: Contains raw table indices that require resolution
//! - **Memory Efficiency**: Minimal footprint during initial parsing phases
//! - **Binary Format**: Direct representation of ECMA-335 table structure
//! - **Batch Processing**: Optimized for parsing multiple entries efficiently
//!
//! # Binary Format
//!
//! Each `MethodSemantics` table row follows the ECMA-335 §II.22.28 specification:
//!
//! ```text
//! Offset | Size    | Field       | Description
//! -------|---------|-------------|--------------------------------------------
//! 0x00   | 2 bytes | Semantics   | Bitmask of semantic attributes
//! 0x02   | 2-4     | Method      | Index into MethodDef table
//! 0x04   | 2-4     | Association | HasSemantics coded index (Event/Property)
//! ```
//!
//! # Semantic Types
//!
//! The table supports the following semantic relationships:
//!
//! **Property Semantics**:
//! - `SETTER` (0x0001) - Property setter method
//! - `GETTER` (0x0002) - Property getter method
//! - `OTHER` (0x0004) - Other property-related method
//!
//! **Event Semantics**:
//! - `ADD_ON` (0x0008) - Event subscription method
//! - `REMOVE_ON` (0x0010) - Event unsubscription method
//! - `FIRE` (0x0020) - Event trigger method
//! - `OTHER` (0x0004) - Other event-related method
//!
//! # Processing Pipeline
//!
//! 1. **Parsing**: Raw entries are read from metadata tables stream
//! 2. **Validation**: Semantic attributes and indices are validated
//! 3. **Resolution**: Raw indices are resolved to actual metadata objects
//! 4. **Application**: Semantic relationships are applied to properties/events
//! 5. **Conversion**: Raw entries are converted to owned representations
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe for concurrent read access:
//! - [`crate::metadata::tables::methodsemantics::raw::MethodSemanticsRaw`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - Raw parsing operations can be performed concurrently
//! - Conversion methods are thread-safe with proper synchronization
//! - No shared mutable state during parsing operations
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::methodsemantics`] - Owned representation for runtime use
//! - [`crate::metadata::method`] - Method definition resolution and access
//! - [`crate::metadata::tables::property`] - Property table for semantic application
//! - [`crate::metadata::tables::event`] - Event table for semantic application
//! - [`crate::metadata::typesystem`] - Type reference resolution for coded indices

use std::sync::Arc;

use crate::{
    metadata::{
        method::MethodMap,
        tables::{
            CodedIndex, CodedIndexType, MethodSemantics, MethodSemanticsAttributes,
            MethodSemanticsRc, TableId, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a `MethodSemantics` table entry with unresolved indexes.
///
/// This structure represents an unprocessed entry from the `MethodSemantics` metadata table
/// (ID 0x18), which specifies the relationship between methods and events or properties.
/// It contains raw index values that require resolution to actual metadata objects.
///
/// # Purpose
///
/// The `MethodSemantics` table defines which methods serve specific semantic roles for
/// properties and events:
/// - **Property Accessors**: Getters, setters, and other property-related methods
/// - **Event Handlers**: Add, remove, fire, and other event-related methods
/// - **Runtime Binding**: Enables proper method dispatch for property/event operations
/// - **Language Integration**: Supports C#, VB.NET, and other language property/event syntax
///
/// # Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - **Unresolved Indexes**: Table indices requiring lookup in related tables
/// - **Memory Efficiency**: Minimal footprint for large-scale parsing operations
/// - **Binary Compatibility**: Direct representation of ECMA-335 file format
/// - **Batch Processing**: Optimized for processing multiple entries sequentially
///
/// Use [`crate::metadata::tables::methodsemantics::MethodSemantics`] for resolved references and runtime access.
///
/// # Usage Patterns
///
/// ```no_run
/// use dotscope::metadata::tables::MethodSemanticsRaw;
/// use dotscope::metadata::tables::MethodSemanticsAttributes;
///
/// # fn process_semantic_entry(raw_entry: &MethodSemanticsRaw) {
/// // Check semantic type
/// match raw_entry.semantics {
///     MethodSemanticsAttributes::GETTER => {
///         println!("Property getter method: {}", raw_entry.method);
///     }
///     MethodSemanticsAttributes::ADD_ON => {
///         println!("Event add method: {}", raw_entry.method);
///     }
///     _ => println!("Other semantic type"),
/// }
///
/// // Access coded index for association
/// println!("Associated with: {:?}", raw_entry.association.tag);
/// # }
/// ```
///
/// # Thread Safety
///
/// [`MethodSemanticsRaw`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data types.
/// Instances can be safely shared across threads and accessed concurrently without synchronization.
///
/// # ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.28 `MethodSemantics` table structure.
/// - [ECMA-335 Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - Table ID: 0x18
/// - Purpose: Define semantic relationships between methods and properties/events
pub struct MethodSemanticsRaw {
    /// Row identifier within the `MethodSemantics` table.
    ///
    /// This 1-based index uniquely identifies this entry within the table.
    /// Combined with table ID 0x18, forms the metadata token 0x18XXXXXX.
    pub rid: u32,

    /// Metadata token for this `MethodSemantics` entry.
    ///
    /// Format: 0x18XXXXXX where XXXXXX is the row ID.
    /// Used for cross-referencing this entry from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Semantic relationship type bitmask.
    ///
    /// 2-byte value defining the method's semantic role using [`MethodSemanticsAttributes`]:
    /// - `SETTER` (0x0001) - Property setter method
    /// - `GETTER` (0x0002) - Property getter method
    /// - `OTHER` (0x0004) - Other property/event method
    /// - `ADD_ON` (0x0008) - Event add method
    /// - `REMOVE_ON` (0x0010) - Event remove method
    /// - `FIRE` (0x0020) - Event fire method
    ///
    /// As specified in ECMA-335 §II.23.1.12.
    pub semantics: u32,

    /// Raw index into the `MethodDef` table.
    ///
    /// This unresolved index identifies the method that implements the semantic
    /// behavior. Must be resolved using the `MethodDef` table to get the actual
    /// [`Method`](crate::metadata::method::Method) reference.
    ///
    /// Index size depends on table size (2 or 4 bytes).
    pub method: u32,

    /// Raw `HasSemantics` coded index.
    ///
    /// This coded index identifies the associated property or event that this
    /// method provides semantic behavior for. The encoding combines:
    /// - Low 2 bits: Table tag (0=Event, 1=Property)
    /// - High bits: Row index in the target table
    ///
    /// Must be resolved using the appropriate table to get the actual type reference.
    pub association: CodedIndex,
}

impl MethodSemanticsRaw {
    /// Applies the semantic relationship directly using raw data.
    ///
    /// This method resolves the raw indexes and applies the semantic relationship
    /// to the associated property or event without creating an owned instance.
    /// It's more memory-efficient than conversion to owned form when only applying
    /// relationships is needed.
    ///
    /// ## Process
    ///
    /// 1. Resolves the method index to an actual [`Method`](crate::metadata::method::Method) reference
    /// 2. Resolves the association coded index to a property or event
    /// 3. Applies the semantic relationship based on the semantics bitmask
    /// 4. Sets the appropriate method reference on the property/event
    ///
    /// ## Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `methods` - Map of all parsed `MethodDef` entries for method resolution
    ///
    /// ## Errors
    ///
    /// - Method token cannot be resolved (invalid index or missing entry)
    /// - Association coded index is malformed or points to invalid entry
    /// - Semantic attributes are invalid or unsupported
    /// - Method is already assigned for this semantic role (duplicate)
    /// - Property/event assignment fails due to type constraints
    pub fn apply<F>(&self, get_ref: F, methods: &MethodMap) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let Some(method) = methods.get(&Token::new(self.method | 0x0600_0000)) else {
            return Err(malformed_error!(
                "Failed to resolve method token - {}",
                self.method | 0x0600_0000
            ));
        };

        let association = get_ref(&self.association);
        match association {
            CilTypeReference::Property(property) => {
                match MethodSemanticsAttributes::new(self.semantics) {
                    MethodSemanticsAttributes::SETTER => {
                        property
                            .fn_setter
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Property `setter` already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::GETTER => {
                        property
                            .fn_getter
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Property `getter` already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::OTHER => {
                        property
                            .fn_other
                            .push_row(self.token, method.value().clone().into());
                        Ok(())
                    }
                    _ => Err(malformed_error!("Invalid property semantics")),
                }
            }
            CilTypeReference::Event(event) => {
                match MethodSemanticsAttributes::new(self.semantics) {
                    MethodSemanticsAttributes::ADD_ON => {
                        event
                            .fn_on_add
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `add` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::REMOVE_ON => {
                        event
                            .fn_on_remove
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `remove` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::FIRE => {
                        event
                            .fn_on_raise
                            .set(method.value().clone().into())
                            .map_err(|_| malformed_error!("Event `raise` method already set"))?;
                        Ok(())
                    }
                    MethodSemanticsAttributes::OTHER => {
                        event
                            .fn_on_other
                            .push_row(self.token, method.value().clone().into());
                        Ok(())
                    }
                    _ => Err(malformed_error!("Invalid event semantics")),
                }
            }
            _ => Err(malformed_error!(
                "Invalid association token - {}",
                self.association.token.value()
            )),
        }
    }

    /// Converts this raw entry to an owned [`MethodSemantics`] with resolved references.
    ///
    /// This method performs the conversion from raw indexes to resolved object references,
    /// creating a fully usable [`MethodSemantics`] instance with owned data. The resulting
    /// instance contains resolved method and association references for efficient runtime access.
    ///
    /// ## Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `methods` - Map of all parsed `MethodDef` entries for method resolution
    ///
    /// ## Returns
    ///
    /// A reference-counted [`MethodSemanticsRc`] containing the resolved entry.
    ///
    /// ## Errors
    ///
    /// - Method token cannot be resolved (0x06XXXXXX format expected)
    /// - Method index points to non-existent `MethodDef` entry
    /// - Association coded index is malformed or invalid
    /// - Association resolves to `CilTypeReference::None`
    /// - Required dependency data is missing or corrupted
    pub fn to_owned<F>(&self, get_ref: F, methods: &MethodMap) -> Result<MethodSemanticsRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let method = match methods.get(&Token::new(self.method | 0x0600_0000)) {
            Some(method) => method.value().clone(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve methoddef token - {}",
                    self.method | 0x0600_0000
                ))
            }
        };

        let association = get_ref(&self.association);
        if matches!(association, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve association token - {}",
                self.association.token.value()
            ));
        }

        Ok(Arc::new(MethodSemantics {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            semantics: MethodSemanticsAttributes::new(self.semantics),
            method,
            association,
        }))
    }
}

impl TableRow for MethodSemanticsRaw {
    /// Calculates the byte size of a `MethodSemantics` table row.
    ///
    /// The row size depends on the metadata table sizes and is calculated as:
    /// - `semantics`: 2 bytes (fixed)
    /// - `method`: 2 or 4 bytes (depends on `MethodDef` table size)
    /// - `association`: 2 or 4 bytes (depends on `HasSemantics` coded index size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* semantics */   2u8
            /* method */      .saturating_add(sizes.table_index_bytes(TableId::MethodDef))
            /* association */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::HasSemantics))

        )
    }
}

//! Raw `CustomAttribute` table representation.
//!
//! This module provides the [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw`] struct
//! for low-level access to `CustomAttribute` metadata table data with unresolved coded indexes and blob references.
//! This represents the binary format of custom attribute records as they appear in the metadata tables stream,
//! requiring resolution to create usable data structures.
//!
//! # Architecture
//!
//! The raw representation maintains the exact binary layout from the metadata tables stream,
//! with unresolved coded indexes that reference other metadata tables and blob heap entries.
//! This design allows efficient parsing and deferred resolution until references are needed.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw`] - Raw table row structure with unresolved indexes
//! - [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw::to_owned`] - Resolution to owned representation
//! - [`crate::metadata::customattributes::parse_custom_attribute_blob`] - Binary blob parsing for attribute values
//!
//! # `CustomAttribute` Table Format
//!
//! The `CustomAttribute` table (0x0C) contains rows with these fields:
//! - **Parent** (2/4 bytes): `HasCustomAttribute` coded index to the target metadata element
//! - **Type** (2/4 bytes): `CustomAttributeType` coded index to the constructor method
//! - **Value** (2/4 bytes): Blob heap index for the serialized attribute arguments
//!
//! # Usage Examples
//!
//! ```text
//! // Convert to owned representation with resolved references
//! let owned = raw.to_owned(|coded_index| context.get_ref(coded_index), blob, context.types)?;
//!
//! // Apply the custom attribute to its parent element
//! owned.apply()?;
//! ```
//!
//! # Error Handling
//!
//! Raw table operations can fail if:
//! - Coded index resolution fails for parent or constructor references
//! - Constructor references are not valid constructor methods
//! - Binary blob parsing fails due to corrupted data
//! - Table data is incomplete or malformed
//!
//! # Thread Safety
//!
//! Raw table structures are [`Send`] and [`Sync`]. Resolution operations are thread-safe
//! and can be performed concurrently across multiple custom attributes.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::customattribute::owned`] - Owned representation with resolved references
//! - [`crate::metadata::customattributes`] - Custom attribute value parsing and representation
//! - [`crate::metadata::typesystem`] - Type system components and references
//! - [`crate::metadata::streams::Blob`] - Blob heap for attribute value data
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//!
//! # References
//!
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `CustomAttribute` table specification
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding

use std::sync::Arc;

use crate::{
    metadata::{
        customattributes::{parse_custom_attribute_blob_with_registry, CustomAttributeValue},
        streams::Blob,
        tables::{
            CodedIndex, CodedIndexType, CustomAttribute, CustomAttributeRc, MemberRefSignature,
            Param, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `CustomAttribute` table row with unresolved coded indexes and blob references
///
/// Represents the binary format of a `CustomAttribute` metadata table entry (table ID 0x0C) as stored
/// in the metadata tables stream. All coded indexes and blob references are stored as raw values
/// that must be resolved using the appropriate context and heaps to access the actual data.
///
/// The `CustomAttribute` table associates custom attributes with metadata elements throughout the
/// assembly, providing a mechanism for storing declarative information about types, methods,
/// fields, and other metadata entities.
///
/// # Reference
/// - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `CustomAttribute` table specification
/// - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding
pub struct CustomAttributeRaw {
    /// Row identifier within the `CustomAttribute` metadata table
    ///
    /// The 1-based index of this custom attribute row within the table.
    /// Used to generate the metadata token and for table iteration.
    pub rid: u32,

    /// Metadata token for this custom attribute row
    ///
    /// Combines the table identifier (0x0C for `CustomAttribute`) with the row ID to create
    /// a unique token. Format: `0x0C000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw custom attribute data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// `HasCustomAttribute` coded index to the target metadata element (unresolved)
    ///
    /// Identifies the metadata element to which this custom attribute is applied.
    /// This can reference types, methods, fields, assemblies, modules, parameters,
    /// and many other metadata entities. Must be resolved using coded index lookup.
    pub parent: CodedIndex,

    /// `CustomAttributeType` coded index to the constructor method (unresolved)
    ///
    /// References the constructor method (`MethodDef` or `MemberRef`) used to instantiate
    /// this custom attribute. The constructor's signature determines how to interpret
    /// the attribute's value blob. Must be resolved using coded index lookup.
    pub constructor: CodedIndex,

    /// Blob heap index for the serialized attribute arguments (unresolved)
    ///
    /// Index into the blob heap containing the custom attribute's serialized value,
    /// including fixed constructor arguments and named field/property values.
    /// A value of 0 indicates an empty attribute with no arguments.
    pub value: u32,
}

impl CustomAttributeRaw {
    /// Convert a raw `CustomAttribute` to an owned `CustomAttribute` with resolved indexes and parsed value data
    ///
    /// This method transforms the raw table entry into a fully usable custom attribute by:
    /// 1. Resolving the parent and constructor coded indexes to concrete type references
    /// 2. Validating that the constructor is indeed a constructor method (.ctor or .cctor)
    /// 3. Parsing the binary attribute blob using the constructor's parameter signature
    /// 4. Creating an owned `CustomAttribute` with all resolved data
    ///
    /// The method performs comprehensive validation to ensure metadata integrity, including
    /// constructor name validation and type checking to prevent malformed custom attributes.
    ///
    /// # Arguments
    ///
    /// * `get_ref` - A closure that resolves coded indexes to [`CilTypeReference`] objects.
    ///   This function should handle all coded index types used by custom attributes.
    /// * `blob` - The blob heap containing the serialized custom attribute value data
    /// * `type_registry` - The type registry the constructor's parameter types resolve in
    ///
    /// # Returns
    ///
    /// * `Ok(`[`crate::metadata::tables::customattribute::CustomAttributeRc`]`)` - Successfully resolved `CustomAttribute` data
    /// * `Err(`[`crate::Error`]`)` - Resolution or parsing failed
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - Coded index resolution fails for parent or constructor references
    /// - The constructor reference is not a `MethodDef` or `MemberRef`
    /// - The constructor is not actually a constructor method (.ctor or .cctor)
    /// - The constructor name is empty (indicating malformed metadata)
    /// - Binary blob parsing fails due to corrupted or invalid data
    /// - Constructor method references become invalid during processing
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The resulting owned structure is also thread-safe for concurrent access.
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        blob: &Blob,
        type_registry: &Arc<TypeRegistry>,
    ) -> Result<CustomAttributeRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let constructor_ref = get_ref(&self.constructor);
        match &constructor_ref {
            CilTypeReference::MethodDef(method_ref) => {
                if let Some(constructor) = method_ref.upgrade() {
                    if !constructor.is_constructor() {
                        return Err(malformed_error!(
                            "CustomAttribute constructor must be a .ctor or .cctor method, found '{}' (token: {})",
                            constructor.name,
                            self.token.value()
                        ));
                    }

                    if constructor.name.is_empty() {
                        return Err(malformed_error!(
                            "Constructor name cannot be empty for CustomAttribute token {}",
                            self.token.value()
                        ));
                    }
                } else {
                    return Err(malformed_error!(
                        "CustomAttribute constructor method reference is no longer valid (token: {})",
                        self.token.value()
                    ));
                }
            }
            CilTypeReference::MemberRef(member_ref) => {
                if !member_ref.is_constructor() {
                    return Err(malformed_error!(
                        "CustomAttribute constructor must be a .ctor or .cctor method, found '{}' (token: {})",
                        member_ref.name,
                        self.token.value()
                    ));
                }

                if member_ref.name.is_empty() {
                    return Err(malformed_error!(
                        "Constructor name cannot be empty for CustomAttribute token {}",
                        self.token.value()
                    ));
                }
            }
            CilTypeReference::None => {
                return Err(malformed_error!(
                    "CustomAttribute constructor reference cannot be None (token: {})",
                    self.token.value()
                ));
            }
            _ => {
                return Err(malformed_error!(
                    "CustomAttribute constructor must be MethodDef or MemberRef (token: {})",
                    self.token.value()
                ));
            }
        }

        let mut value = if self.value == 0 {
            CustomAttributeValue {
                fixed_args: vec![],
                named_args: vec![],
                constructor: CilTypeReference::None,
                blob_index: 0,
            }
        } else {
            match &constructor_ref {
                // The fixed arguments follow the constructor's signature, not its Param rows: a
                // parameter need not have a row (ECMA-335 §22.33), and still takes an argument.
                CilTypeReference::MethodDef(method_ref) => match method_ref.upgrade() {
                    Some(constructor) => parse_custom_attribute_blob_with_registry(
                        blob,
                        self.value,
                        &Param::from_signature(&constructor.signature, type_registry)?,
                        type_registry,
                    )?,
                    None => CustomAttributeValue {
                        fixed_args: vec![],
                        named_args: vec![],
                        constructor: CilTypeReference::None,
                        blob_index: 0,
                    },
                },
                CilTypeReference::MemberRef(member_ref) => match &member_ref.signature {
                    MemberRefSignature::Method(_) => parse_custom_attribute_blob_with_registry(
                        blob,
                        self.value,
                        &member_ref.params,
                        type_registry,
                    )?,
                    MemberRefSignature::Field(_) => CustomAttributeValue {
                        fixed_args: vec![],
                        named_args: vec![],
                        constructor: CilTypeReference::None,
                        blob_index: 0,
                    },
                },
                _ => CustomAttributeValue {
                    fixed_args: vec![],
                    named_args: vec![],
                    constructor: CilTypeReference::None,
                    blob_index: 0,
                },
            }
        };

        value.constructor = constructor_ref.clone();
        value.blob_index = self.value as usize;

        Ok(Arc::new(CustomAttribute {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            parent: get_ref(&self.parent),
            constructor: constructor_ref,
            value,
        }))
    }
}

impl TableRow for CustomAttributeRaw {
    /// Calculate the byte size of a CustomAttribute table row
    ///
    /// Computes the total size based on variable-size coded indexes and heap indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.10)
    /// - `parent`: 2 or 4 bytes (`HasCustomAttribute` coded index)
    /// - `constructor`: 2 or 4 bytes (`CustomAttributeType` coded index)
    /// - `value`: 2 or 4 bytes (blob heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one CustomAttribute table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* parent */      sizes.coded_index_bytes(CodedIndexType::HasCustomAttribute)
            /* constructor */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::CustomAttributeType))
            /* value */       .saturating_add(sizes.blob_bytes())

        )
    }
}

//! Owned `CustomAttribute` table representation.
//!
//! This module provides the [`crate::metadata::tables::customattribute::owned::CustomAttribute`] struct
//! which contains fully resolved custom attribute metadata with owned data and resolved references.
//! This is the primary data structure for representing .NET custom attributes in a usable form,
//! with parsed attribute values and resolved parent relationships after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the `CustomAttribute` metadata table,
//! including resolved references to parent metadata elements and parsed attribute values. This
//! eliminates the need for table lookups during runtime access, providing immediate access to
//! structured custom attribute metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customattribute::owned::CustomAttribute`] - Main owned attribute structure
//! - [`crate::metadata::typesystem::CilTypeReference`] - Referenced parent and constructor elements
//! - [`crate::metadata::customattributes::CustomAttributeValue`] - Parsed attribute value data
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::CustomAttribute;
//! # fn example(attribute: &CustomAttribute) -> dotscope::Result<()> {
//! // Apply the custom attribute to its parent element
//! attribute.apply()?;
//!
//! // Access structured attribute data
//! println!("Attribute constructor: {:?}", attribute.constructor);
//! println!("Fixed arguments: {:?}", attribute.value.fixed_args);
//! println!("Named arguments: {:?}", attribute.value.named_args);
//! # Ok(())
//! # }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`]. The `apply` method uses atomic operations when updating
//! parent element collections, ensuring thread-safe modifications without additional synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::customattribute::raw`] - Raw table representation
//! - [`crate::metadata::customattributes`] - Custom attribute value parsing and representation
//! - [`crate::metadata::typesystem`] - Type system components and references
//! - [`crate::metadata::token`] - Token-based metadata references

use std::sync::Arc;

use crate::{
    metadata::{
        customattributes::CustomAttributeValue, token::Token, typesystem::CilTypeReference,
    },
    Result,
};

/// Represents a .NET custom attribute with fully resolved metadata and parsed value data
///
/// This structure contains the complete custom attribute information from the `CustomAttribute`
/// metadata table (0x0C), with all coded indexes resolved to concrete type references and
/// attribute values parsed from their binary blob representation.
/// Unlike [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw`], this provides
/// immediate access to structured attribute data without requiring additional parsing.
///
/// # Custom Attribute Structure
///
/// A custom attribute consists of:
/// - **Parent**: The metadata element (type, method, field, etc.) to which the attribute is applied
/// - **Constructor**: The constructor method used to instantiate the attribute
/// - **Value**: Parsed fixed arguments and named parameters from the attribute's binary representation
///
/// # Reference
/// - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `CustomAttribute` table specification
/// - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding
pub struct CustomAttribute {
    /// Row identifier within the `CustomAttribute` metadata table
    ///
    /// The 1-based index of this custom attribute row. Used to uniquely identify
    /// this specific custom attribute instance within the table.
    pub rid: u32,

    /// Metadata token for this custom attribute
    ///
    /// Combines the table identifier (0x0C for `CustomAttribute`) with the row ID to create
    /// a unique token that can be used to reference this custom attribute from other metadata.
    pub token: Token,

    /// Byte offset of this custom attribute row within the metadata tables stream
    ///
    /// Physical location of the raw custom attribute data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Resolved parent object that has this custom attribute attached
    ///
    /// The metadata element to which this custom attribute is applied. This can be any
    /// element that supports the `HasCustomAttribute` coded index, including:
    /// - Types (`TypeDef`, `TypeRef`, `TypeSpec`)
    /// - Methods and method signatures
    /// - Fields and properties
    /// - Parameters and events
    /// - Assemblies and modules
    /// - And many other metadata elements
    pub parent: CilTypeReference,

    /// Resolved constructor method for this custom attribute
    ///
    /// The constructor method (`MethodDef` or `MemberRef`) that is used to instantiate
    /// this custom attribute. This determines the attribute type and the signature
    /// for interpreting the attribute's fixed arguments.
    pub constructor: CilTypeReference,

    /// Parsed custom attribute value containing arguments and named parameters
    ///
    /// The structured representation of the custom attribute's binary blob data,
    /// including fixed constructor arguments and named field/property values.
    /// See [`CustomAttributeValue`] for the complete value structure.
    pub value: CustomAttributeValue,
}

impl CustomAttribute {
    /// Apply a custom attribute to its parent metadata element
    ///
    /// This method attaches the custom attribute value to its resolved parent object by adding it
    /// to the parent's custom attribute collection. The custom attribute value is stored as an
    /// [`Arc<CustomAttributeValue>`] for efficient memory usage and sharing across threads.
    ///
    /// The application process involves matching the parent type and adding the attribute to the
    /// appropriate custom attribute collection. This enables metadata consumers to query all
    /// custom attributes applied to any given metadata element.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Custom attribute successfully applied to parent element
    /// * `Err(`[`crate::Error`]`)` - Application failed due to invalid or missing parent reference
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The parent type reference is no longer valid (weakly referenced objects have been dropped)
    /// - The parent type is not supported for custom attributes (should not occur with valid metadata)
    /// - Internal collection operations fail
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses atomic operations to update the parent element's
    /// custom attribute collection. Multiple threads can safely call this method concurrently
    /// on different custom attributes.
    pub fn apply(&self) -> Result<()> {
        let mut value = self.value.clone();
        value.constructor = self.constructor.clone();
        let attribute_value = Arc::new(value);

        match &self.parent {
            CilTypeReference::TypeDef(entry)
            | CilTypeReference::TypeSpec(entry)
            | CilTypeReference::TypeRef(entry) => {
                if let Some(type_ref) = entry.upgrade() {
                    type_ref
                        .custom_attributes
                        .push_row(self.token, attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Type reference is no longer valid"))
                }
            }
            CilTypeReference::MethodDef(entry) => {
                if let Some(method) = entry.upgrade() {
                    method
                        .custom_attributes
                        .push_row(self.token, attribute_value);
                    Ok(())
                } else {
                    Err(malformed_error!("Method reference is no longer valid"))
                }
            }
            CilTypeReference::Field(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::Param(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::Property(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::Event(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::Assembly(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::Module(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::InterfaceImpl(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::MemberRef(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::DeclSecurity(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::StandAloneSig(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::ModuleRef(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::AssemblyRef(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::File(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::ExportedType(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParam(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::GenericParamConstraint(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            CilTypeReference::MethodSpec(entry) => {
                entry
                    .custom_attributes
                    .push_row(self.token, attribute_value);
                Ok(())
            }
            //CilTypeReference::ManifestResource(entry) => {},
            CilTypeReference::None => {
                // For now, just return Ok() for unsupported parent types
                Ok(())
            }
        }
    }
}

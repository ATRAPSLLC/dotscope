//! # `MethodSemantics` Owned Implementation
//!
//! This module provides the owned variant of `MethodSemantics` table entries with resolved
//! references and owned data structures for efficient runtime access.

use crate::{
    metadata::{
        method::MethodRc, tables::MethodSemanticsAttributes, token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Owned representation of a `MethodSemantics` table entry with resolved references.
///
/// This structure represents a processed entry from the `MethodSemantics` metadata table,
/// which specifies the relationship between methods and events or properties. Unlike
/// [`MethodSemanticsRaw`](crate::metadata::tables::MethodSemanticsRaw), this version contains resolved references
/// to actual method and type objects for efficient runtime access.
///
/// ## Purpose
///
/// `MethodSemantics` entries define the semantic role of methods in relation to properties
/// and events, such as:
/// - Property getters and setters
/// - Event add, remove, and fire methods
/// - Other custom semantic relationships
pub struct MethodSemantics {
    /// Row identifier within the `MethodSemantics` table.
    ///
    /// This 1-based index uniquely identifies this entry within the table.
    /// Combined with the table ID, it forms the complete metadata token.
    pub rid: u32,

    /// Metadata token for this `MethodSemantics` entry.
    ///
    /// Format: 0x18XXXXXX where XXXXXX is the row ID.
    /// This token uniquely identifies this entry across the entire metadata.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Semantic relationship type bitmask.
    ///
    /// Defines the role this method plays for the associated property or event.
    /// Uses [`MethodSemanticsAttributes`] constants which can be combined:
    /// - `SETTER` (0x0001) - Property setter method
    /// - `GETTER` (0x0002) - Property getter method
    /// - `OTHER` (0x0004) - Other property/event method
    /// - `ADD_ON` (0x0008) - Event add method
    /// - `REMOVE_ON` (0x0010) - Event remove method
    /// - `FIRE` (0x0020) - Event fire method
    pub semantics: MethodSemanticsAttributes,

    /// Resolved reference to the associated method.
    ///
    /// Points to the actual [`Method`](crate::metadata::method::Method) that implements
    /// the semantic behavior for the associated property or event.
    pub method: MethodRc,

    /// Resolved reference to the associated property or event.
    ///
    /// Contains either a [`Property`](crate::metadata::tables::Property) or
    /// [`Event`](crate::metadata::tables::Event) that this method provides
    /// semantic behavior for, resolved from the `HasSemantics` coded index.
    pub association: CilTypeReference,
}

impl MethodSemantics {
    /// Applies the semantic relationship to the associated property or event.
    ///
    /// This method establishes the actual semantic binding by setting the appropriate
    /// method reference on the associated property or event. For properties, this sets
    /// getter, setter, or other methods. For events, this sets add, remove, fire, or
    /// other methods.
    ///
    /// ## Semantic Mappings
    ///
    /// ### Property Semantics
    /// - [`SETTER`](MethodSemanticsAttributes::SETTER) → Sets property's setter method
    /// - [`GETTER`](MethodSemanticsAttributes::GETTER) → Sets property's getter method
    /// - [`OTHER`](MethodSemanticsAttributes::OTHER) → Sets property's other method
    ///
    /// ### Event Semantics
    /// - [`ADD_ON`](MethodSemanticsAttributes::ADD_ON) → Sets event's add method
    /// - [`REMOVE_ON`](MethodSemanticsAttributes::REMOVE_ON) → Sets event's remove method
    /// - [`FIRE`](MethodSemanticsAttributes::FIRE) → Sets event's fire method
    /// - [`OTHER`](MethodSemanticsAttributes::OTHER) → Sets event's other method
    ///
    /// ## Errors
    ///
    /// - The semantic attributes are invalid or unknown
    /// - The method is already set for this semantic role (duplicate assignment)
    /// - The association is neither a property nor an event
    /// - The property/event assignment fails due to internal constraints
    ///
    pub fn apply(&self) -> Result<()> {
        match &self.association {
            CilTypeReference::Property(property) => match self.semantics {
                MethodSemanticsAttributes::SETTER => property
                    .fn_setter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property setter already set".to_string())),
                MethodSemanticsAttributes::GETTER => property
                    .fn_getter
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Property getter already set".to_string())),
                MethodSemanticsAttributes::OTHER => {
                    property
                        .fn_other
                        .push_row(self.token, self.method.clone().into());
                    Ok(())
                }
                _ => Err(malformed_error!("Invalid property semantics".to_string())),
            },
            CilTypeReference::Event(event) => match self.semantics {
                MethodSemanticsAttributes::ADD_ON => event
                    .fn_on_add
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event add method already set".to_string())),
                MethodSemanticsAttributes::REMOVE_ON => event
                    .fn_on_remove
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event remove method already set".to_string())),
                MethodSemanticsAttributes::FIRE => event
                    .fn_on_raise
                    .set(self.method.clone().into())
                    .map_err(|_| malformed_error!("Event raise method already set".to_string())),
                MethodSemanticsAttributes::OTHER => {
                    event
                        .fn_on_other
                        .push_row(self.token, self.method.clone().into());
                    Ok(())
                }
                _ => Err(malformed_error!("Invalid event semantics".to_string())),
            },
            _ => Err(malformed_error!("Invalid association".to_string())),
        }
    }
}

//! # Property Owned Implementation
//!
//! This module provides the owned variant of Property table entries with resolved
//! references and complete metadata context for application use.

use std::sync::OnceLock;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, method::MethodRef,
        signatures::SignatureProperty, tables::PropertyAttributes, token::Token,
        typesystem::CilPrimitive,
    },
    utils::RowList,
};

/// Owned representation of a Property table entry with complete metadata context.
///
/// This structure represents a fully processed entry from the Property metadata table
/// (ID 0x17), which defines properties exposed by types in .NET assemblies. It contains
/// resolved names, parsed signatures, and lazy-loaded associated methods and values.
///
/// ## Purpose
///
/// The Property table serves as the foundation for .NET property system:
/// - **Property Definition**: Defines property names, types, and characteristics
/// - **Method Association**: Links to getter, setter, and other associated methods
/// - **Type Integration**: Integrates properties into the type system through `PropertyMap`
/// - **Reflection Support**: Enables property-based reflection and metadata queries
///
/// ## Owned vs Raw
///
/// This owned variant provides:
/// - Resolved property names from the string heap
/// - Parsed property signatures with complete type information
/// - Lazy-loaded associated methods and default values
/// - Custom attribute resolution and accessibility
/// - Integration with the broader metadata resolution system
///
/// ## Property Methods
///
/// Properties can be associated with various methods:
/// - **Getter**: Method that retrieves the property value (`get_PropertyName`)
/// - **Setter**: Method that sets the property value (`set_PropertyName`)
/// - **Other**: Additional methods related to property functionality
///
/// ## References
///
/// - ECMA-335, Partition II, §22.34 - Property table specification
/// - [`crate::metadata::tables::PropertyRaw`] - Raw variant for comparison
/// - [`crate::metadata::tables::PropertyMap`] - Property to type mapping
/// - [`crate::metadata::signatures::SignatureProperty`] - Property signature details
pub struct Property {
    /// Metadata token uniquely identifying this Property entry.
    ///
    /// The token combines the table identifier (Property = 0x17) with the row ID,
    /// providing a unique reference for this property across the entire metadata system.
    pub token: Token,

    /// Property attribute flags defining characteristics and behavior.
    ///
    /// A 2-byte bitmask of `PropertyAttributes` (§II.23.1.14) that controls various
    /// aspects of the property including special naming, default values, and runtime
    /// behavior. See [`super::PropertyAttributes`] for flag definitions.
    pub flags: PropertyAttributes,

    /// The resolved name of this property.
    ///
    /// This field contains the property name as resolved from the string heap,
    /// providing the identifier used for property access and reflection operations.
    pub name: String,

    /// The complete type signature of this property.
    ///
    /// Contains the parsed property signature including the property type,
    /// parameter types (for indexers), and calling conventions. This signature
    /// defines how the property can be accessed and what types it works with.
    pub signature: SignatureProperty,

    /// The default value of this property (lazy-loaded).
    ///
    /// When `flags.HAS_DEFAULT` is set, this field contains the default value
    /// as defined in the Constant table. The value is loaded on-demand to
    /// optimize memory usage and loading performance.
    pub default: OnceLock<CilPrimitive>,

    /// The setter method for this property (lazy-loaded).
    ///
    /// Reference to the method that sets this property value, typically named
    /// `set_PropertyName`. Loaded on-demand from the `MethodSemantics` table
    /// when property method access is required.
    pub fn_setter: OnceLock<MethodRef>,

    /// The getter method for this property (lazy-loaded).
    ///
    /// Reference to the method that retrieves this property value, typically named
    /// `get_PropertyName`. Loaded on-demand from the `MethodSemantics` table
    /// when property method access is required.
    pub fn_getter: OnceLock<MethodRef>,

    /// The property's other methods, beyond its getter and setter, in `MethodSemantics`
    /// table order. ECMA-335 II.22.28 allows any number of them.
    pub fn_other: RowList<MethodRef>,

    /// Custom attributes applied to this property.
    ///
    /// Collection of custom attributes that provide additional metadata and
    /// annotations for this property, supporting attribute-based programming
    /// patterns and metadata-driven functionality.
    pub custom_attributes: CustomAttributeValueList,
}

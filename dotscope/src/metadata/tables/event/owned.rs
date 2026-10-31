//! Owned Event table representation.
//!
//! This module provides the [`crate::metadata::tables::event::owned::Event`] struct
//! which contains fully resolved event metadata with owned data and resolved references.
//! This is the primary data structure for representing .NET event definitions in a usable
//! form after the dual variant resolution phase.

use std::sync::OnceLock;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, method::MethodRef, tables::EventAttributes,
        token::Token, typesystem::CilTypeRef,
    },
    utils::RowList,
};

/// Represents a .NET CIL event with fully resolved metadata and owned data
///
/// This structure contains complete event information from the Event metadata table (0x14),
/// with all heap references resolved to owned strings and type references. Unlike
/// [`crate::metadata::tables::event::raw::EventRaw`], this provides immediate access to
/// event data without requiring heap lookups or coded index resolution.
///
/// # .NET Event Model
///
/// Events in .NET provide a standardized notification mechanism with these characteristics:
/// - **Type Safety**: Event handler type is enforced at compile time
/// - **Multicast Support**: Multiple subscribers can attach to a single event
/// - **Standard Accessors**: Add/remove methods with optional raise and other operations
/// - **Observer Pattern**: Clean separation between event source and subscribers
///
/// # Event Accessor Methods
///
/// Events are associated with accessor methods that implement the event semantics:
/// - **Add**: Subscribe a handler to the event (required)
/// - **Remove**: Unsubscribe a handler from the event (required)
/// - **Raise**: Trigger the event (optional, often fire_ or on_ prefixed)
/// - **Other**: Additional custom operations (optional)
///
/// # Reference
/// - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Event table specification
pub struct Event {
    /// Row identifier within the Event metadata table
    ///
    /// The 1-based index of this event row. Used for metadata token generation
    /// and cross-referencing with other metadata structures like `MethodSemantics`.
    pub rid: u32,

    /// Metadata token for this event
    ///
    /// Combines the table identifier (0x14 for `Event`) with the row ID to create
    /// a unique token that can be used to reference this event from other metadata.
    pub token: Token,

    /// Byte offset of this event row within the metadata tables stream
    ///
    /// Physical location of the raw event data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Event flags bitmask controlling event behavior.
    ///
    /// Specifies event attributes using [`crate::metadata::tables::event::EventAttributes`]
    /// constants. Controls special naming and runtime behavior.
    /// See [ECMA-335 II.23.1.4] for flag definitions.
    pub flags: EventAttributes,

    /// Event name identifier
    ///
    /// The name of the event as it appears in source code. Event names typically
    /// follow C# conventions (`PascalCase`) and should be descriptive of the notification
    /// being provided. This name is used for reflection and debugging.
    pub name: String,

    /// Type reference for the event handler delegate
    ///
    /// References the delegate type that defines the event handler signature through
    /// a `TypeDef`, `TypeRef`, or `TypeSpec`. This enforces type safety for event subscribers
    /// and determines the method signature that event handlers must implement.
    pub event_type: CilTypeRef,

    /// Add accessor method reference
    ///
    /// References the method that implements event subscription (adding handlers).
    /// This method is required for all events and typically follows the pattern
    /// `add_EventName`. Uses [`OnceLock`] for thread-safe lazy initialization
    /// since accessor binding occurs after event loading.
    pub fn_on_add: OnceLock<MethodRef>,

    /// Remove accessor method reference
    ///
    /// References the method that implements event unsubscription (removing handlers).
    /// This method is required for all events and typically follows the pattern
    /// `remove_EventName`. Uses [`OnceLock`] for thread-safe lazy initialization.
    pub fn_on_remove: OnceLock<MethodRef>,

    /// Raise accessor method reference (optional)
    ///
    /// References the method that triggers the event. This is optional and many
    /// events do not have an explicit raise method. When present, it typically
    /// follows patterns like `raise_EventName`, `fire_EventName`, or `on_EventName`.
    pub fn_on_raise: OnceLock<MethodRef>,

    /// The event's other methods, beyond add, remove and raise, in `MethodSemantics` table
    /// order. ECMA-335 II.22.28 allows any number of them.
    pub fn_on_other: RowList<MethodRef>,

    /// Custom attributes attached to this event
    ///
    /// Contains all custom attributes applied to the event declaration, such as
    /// `ObsoleteAttribute`, `DescriptionAttribute`, or custom application-specific
    /// attributes that provide additional metadata.
    pub custom_attributes: CustomAttributeValueList,
}

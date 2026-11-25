//! EventBuilder for creating event definitions.
//!
//! This module provides [`crate::metadata::tables::event::EventBuilder`] for creating Event table entries
//! with a fluent API. Events define notification mechanisms that allow objects
//! to communicate state changes to interested observers using the observer
//! pattern with type-safe delegate-based handlers.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, EventAttributes, EventRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Event metadata entries.
///
/// `EventBuilder` provides a fluent API for creating Event table entries
/// with validation and automatic heap management. Event entries define
/// notification mechanisms that enable objects to communicate state changes
/// and important occurrences to observers using type-safe delegate handlers.
///
/// # Event Model
///
/// .NET events follow a standard pattern with:
/// - **Event Declaration**: Name, attributes, and delegate type
/// - **Add Accessor**: Method to subscribe to the event
/// - **Remove Accessor**: Method to unsubscribe from the event
/// - **Raise Accessor**: Optional method to trigger the event
/// - **Other Accessors**: Additional event-related methods
///
/// # Method Association
///
/// Events are linked to their implementation methods through the
/// `MethodSemantics` table (created separately):
/// - **Add Method**: Subscribes handlers to the event
/// - **Remove Method**: Unsubscribes handlers from the event
/// - **Raise Method**: Triggers the event (optional)
/// - **Other Methods**: Additional event-related operations
///
/// # Examples
///
/// ```no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{
/// #     CodedIndex, CodedIndexType, EventAttributes, EventBuilder, TableId,
/// # };
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a coded index for System.EventHandler delegate type
/// let event_handler_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // TypeRef to EventHandler
///
/// // Create a standard event
/// let click_event = EventBuilder::new()
///     .name("Click")
///     .flags(EventAttributes::ZERO) // No special flags
///     .event_type(event_handler_type.clone())
///     .build(&mut assembly)?;
///
/// // Create an event with special naming
/// let special_event = EventBuilder::new()
///     .name("PropertyChanged")
///     .flags(EventAttributes::SPECIAL_NAME)
///     .event_type(event_handler_type)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct EventBuilder {
    name: Option<String>,
    flags: Option<EventAttributes>,
    event_type: Option<CodedIndex>,
}

impl Default for EventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBuilder {
    /// Creates a new EventBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::event::EventBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            event_type: None,
        }
    }

    /// Sets the event name.
    ///
    /// Event names are used for reflection, debugging, and binding operations.
    /// Common naming patterns include descriptive verbs like "Click", "Changed",
    /// "Loading", or property names with "Changed" suffix for property notifications.
    ///
    /// # Arguments
    ///
    /// * `name` - The event name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the event flags (attributes).
    ///
    /// Event flags control special behaviors and characteristics.
    /// Common flag values from [`EventAttributes`]:
    /// - `0x0000`: No special flags (default for most events)
    /// - `0x0200`: SPECIAL_NAME - Event has special naming conventions
    /// - `0x0400`: RTSPECIAL_NAME - Runtime provides special behavior based on name
    ///
    /// # Arguments
    ///
    /// * `flags` - The event attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: EventAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the event handler delegate type.
    ///
    /// The event type defines the signature for event handlers that can be
    /// subscribed to this event. This must be a delegate type that specifies
    /// the parameters passed to event handlers when the event is raised.
    ///
    /// Common delegate types:
    /// - `System.EventHandler` - Standard parameterless event handler
    /// - `System.EventHandler<T>` - Generic event handler with typed event args
    /// - Custom delegate types for specialized event signatures
    ///
    /// # Arguments
    ///
    /// * `event_type` - A `TypeDefOrRef` coded index pointing to the delegate type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn event_type(mut self, event_type: CodedIndex) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Builds the event and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name to
    /// the string heap, creates the raw event structure, and adds it to the
    /// Event table.
    ///
    /// Note: This only creates the Event table entry. Method associations
    /// (add, remove, raise) must be created separately using MethodSemantics builders.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created event, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if name is not set
    /// - Returns error if flags are not set
    /// - Returns error if event_type is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalid("Event name is required".to_string()))?;

        let flags = self
            .flags
            .ok_or_else(|| Error::ModificationInvalid("Event flags are required".to_string()))?;

        let event_type = self
            .event_type
            .ok_or_else(|| Error::ModificationInvalid("Event type is required".to_string()))?;

        let valid_tables = CodedIndexType::TypeDefOrRef.tables();
        if !valid_tables.contains(&event_type.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Event type must be a TypeDefOrRef coded index (TypeDef/TypeRef/TypeSpec), got {:?}",
                event_type.tag
            )));
        }

        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let rid = assembly.next_rid(TableId::Event)?;
        let token = Token::from_parts(TableId::Event, rid);

        let event_raw = EventRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: flags.bits(),
            name: name_index,
            event_type,
        };

        assembly.table_row_add(TableId::Event, TableDataOwned::Event(event_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::EventAttributes},
        testkit::fixture,
    };

    #[test]
    fn test_event_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a TypeDefOrRef coded index (System.EventHandler)
        let event_handler_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let ref_ = EventBuilder::new()
            .name("TestEvent")
            .flags(EventAttributes::ZERO)
            .event_type(event_handler_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Event));
    }

    #[test]
    fn test_event_builder_with_special_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a TypeDefOrRef coded index
        let event_handler_type = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef);

        // Create an event with special naming
        let ref_ = EventBuilder::new()
            .name("PropertyChanged")
            .flags(EventAttributes::SPECIAL_NAME)
            .event_type(event_handler_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Event));
    }

    #[test]
    fn test_event_builder_with_rtspecial_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a TypeDefOrRef coded index
        let event_handler_type = CodedIndex::new(TableId::TypeRef, 3, CodedIndexType::TypeDefOrRef);

        // Create an event with runtime special naming
        let ref_ = EventBuilder::new()
            .name("RuntimeSpecialEvent")
            .flags(EventAttributes::RTSPECIAL_NAME)
            .event_type(event_handler_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Event));
    }

    #[test]
    fn test_event_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let event_handler_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = EventBuilder::new()
            .flags(EventAttributes::ZERO)
            .event_type(event_handler_type)
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_event_builder_missing_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let event_handler_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = EventBuilder::new()
            .name("TestEvent")
            .event_type(event_handler_type)
            .build(&mut assembly);

        // Should fail because flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_event_builder_missing_event_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = EventBuilder::new()
            .name("TestEvent")
            .flags(EventAttributes::ZERO)
            .build(&mut assembly);

        // Should fail because event_type is required
        assert!(result.is_err());
    }

    #[test]
    fn test_event_builder_invalid_coded_index_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use wrong coded index type (not TypeDefOrRef)
        let wrong_type = CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::TypeDefOrRef); // MethodDef is not valid for TypeDefOrRef

        let result = EventBuilder::new()
            .name("TestEvent")
            .flags(EventAttributes::ZERO)
            .event_type(wrong_type)
            .build(&mut assembly);

        // Should fail because event_type must be TypeDefOrRef
        assert!(result.is_err());
    }

    #[test]
    fn test_event_builder_multiple_events() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let event_handler_type1 =
            CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);
        let event_handler_type2 =
            CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef);
        let event_handler_type3 =
            CodedIndex::new(TableId::TypeRef, 3, CodedIndexType::TypeDefOrRef);

        // Create multiple events
        let ref1 = EventBuilder::new()
            .name("Event1")
            .flags(EventAttributes::ZERO)
            .event_type(event_handler_type1)
            .build(&mut assembly)
            .unwrap();

        let ref2 = EventBuilder::new()
            .name("Event2")
            .flags(EventAttributes::SPECIAL_NAME)
            .event_type(event_handler_type2)
            .build(&mut assembly)
            .unwrap();

        let ref3 = EventBuilder::new()
            .name("Event3")
            .flags(EventAttributes::RTSPECIAL_NAME)
            .event_type(event_handler_type3)
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different refs
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref3));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));

        // All should have Event table kind
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::Event));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::Event));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::Event));
    }
}

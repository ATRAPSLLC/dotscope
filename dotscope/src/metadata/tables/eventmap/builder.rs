//! # EventMap Builder
//!
//! Provides a fluent API for building EventMap table entries that establish ownership relationships
//! between types and their events. The EventMap table defines contiguous ranges of events that belong
//! to specific types, enabling efficient enumeration and lookup of events by owning type.
//!
//! ## Overview
//!
//! The `EventMapBuilder` enables creation of event map entries with:
//! - Parent type row index specification (required)
//! - Event list starting index specification (required)
//! - Validation of row indices
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```no_run
//! # use dotscope::prelude::*;
//! # use dotscope::metadata::tables::EventBuilder;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create a type first
//! let type_ref = TypeDefBuilder::new()
//!     .name("MyClass")
//!     .namespace("MyApp")
//!     .public_class()
//!     .build(&mut assembly)?;
//!
//! // Create handler type reference
//! let handler_ref = TypeRefBuilder::new()
//!     .name("EventHandler")
//!     .namespace("System")
//!     .resolution_scope(CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope))
//!     .build(&mut assembly)?;
//!
//! // Create events of the handler type
//! let handler = CodedIndex::new(
//!     TableId::TypeRef,
//!     handler_ref.placeholder(),
//!     CodedIndexType::TypeDefOrRef,
//! );
//! let event1_ref = EventBuilder::new()
//!     .name("OnDataChanged")
//!     .event_type(handler.clone())
//!     .build(&mut assembly)?;
//!
//! let event2_ref = EventBuilder::new()
//!     .name("OnSizeChanged")
//!     .event_type(handler)
//!     .build(&mut assembly)?;
//!
//! // Create an event map entry for the type
//! let event_map_ref = EventMapBuilder::new()
//!     .parent(type_ref.placeholder())
//!     .event_list(event1_ref.placeholder()) // Starting event index
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Parent row index and event list index are required and validated
//! - **Index Verification**: Ensures row indices are non-zero
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Range Support**: Supports defining contiguous event ranges for efficient lookup

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{EventMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating EventMap table entries.
///
/// `EventMapBuilder` provides a fluent API for creating entries in the EventMap
/// metadata table, which establishes ownership relationships between types and their events
/// through contiguous ranges of Event table entries.
///
/// # Purpose
///
/// The EventMap table serves several key functions:
/// - **Event Ownership**: Defines which types own which events
/// - **Range Management**: Establishes contiguous ranges of events owned by types
/// - **Efficient Lookup**: Enables O(log n) lookup of events by owning type
/// - **Event Enumeration**: Supports efficient iteration through all events of a type
/// - **Metadata Organization**: Maintains sorted order for optimal access patterns
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing EventMap entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
/// # let type_ref = TypeDefBuilder::new()
/// #     .name("MyClass")
/// #     .namespace("MyApp")
/// #     .public_class()
/// #     .build(&mut assembly)?;
///
/// let event_map_ref = EventMapBuilder::new()
///     .parent(type_ref.placeholder())
///     .event_list(1) // Starting event index
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Parent Required**: A parent row index must be provided
/// - **Parent Validation**: Parent row index must be greater than 0
/// - **Event List Required**: An event list starting index must be provided
/// - **Index Validation**: Event list index must be greater than 0
///
/// # Integration
///
/// EventMap entries integrate with other metadata structures:
/// - **TypeDef**: References specific types in the TypeDef table as parent
/// - **Event**: Points to starting positions in the Event table for range definition
/// - **EventPtr**: Supports indirection through EventPtr table when present
/// - **Metadata Loading**: Establishes event ownership during type loading
#[derive(Debug, Clone)]
pub struct EventMapBuilder {
    /// The row index of the parent type that owns the events (TypeDef table)
    parent: Option<u32>,
    /// The starting index in the Event table for this type's events
    event_list: Option<u32>,
}

impl Default for EventMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventMapBuilder {
    /// Creates a new `EventMapBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = EventMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            event_list: None,
        }
    }

    /// Sets the parent type row index that owns the events.
    ///
    /// The parent must be a valid row index into the TypeDef table that represents the type
    /// that declares and owns the events in the specified range. This can be a resolved row
    /// index or a placeholder that will be resolved at write time.
    ///
    /// # Arguments
    ///
    /// * `parent_row` - Row index or placeholder for the TypeDef table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let type_ref = TypeDefBuilder::new()
    ///     .name("EventfulClass")
    ///     .namespace("MyApp")
    ///     .public_class()
    ///     .build(&mut assembly)?;
    ///
    /// let builder = EventMapBuilder::new()
    ///     .parent(type_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn parent(mut self, parent_row: u32) -> Self {
        self.parent = Some(parent_row);
        self
    }

    /// Sets the starting index in the Event table for this type's events.
    ///
    /// This index defines the beginning of the contiguous range of events
    /// owned by the parent type. The range extends to the next EventMap entry's
    /// event_list index (or end of Event table for the final entry).
    ///
    /// # Arguments
    ///
    /// * `event_list_index` - 1-based index into the Event table
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = EventMapBuilder::new()
    ///     .event_list(1); // Start from first event
    /// ```
    #[must_use]
    pub fn event_list(mut self, event_list_index: u32) -> Self {
        self.event_list = Some(event_list_index);
        self
    }

    /// Builds the EventMap entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the parent row index is valid,
    /// validates the event list index, creates the EventMap table entry, and returns a
    /// reference to the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns a reference to the newly created EventMap entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent row index is not set
    /// - The parent row index is 0
    /// - The event list index is not set
    /// - The event list index is 0
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let type_ref = TypeDefBuilder::new()
    /// #     .name("MyClass")
    /// #     .namespace("MyApp")
    /// #     .public_class()
    /// #     .build(&mut assembly)?;
    ///
    /// let event_map_ref = EventMapBuilder::new()
    ///     .parent(type_ref.placeholder())
    ///     .event_list(1)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created EventMap entry");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let parent_row = self.parent.ok_or_else(|| {
            Error::ModificationInvalid("Parent row index is required for EventMap".to_string())
        })?;

        let event_list_index = self.event_list.ok_or_else(|| {
            Error::ModificationInvalid("Event list index is required for EventMap".to_string())
        })?;

        if parent_row == 0 {
            return Err(Error::ModificationInvalid(
                "Parent row index cannot be 0".to_string(),
            ));
        }

        if event_list_index == 0 {
            return Err(Error::ModificationInvalid(
                "Event list index cannot be 0".to_string(),
            ));
        }

        let event_map = EventMapRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            parent: parent_row,
            event_list: event_list_index,
        };

        assembly.table_row_add(TableId::EventMap, TableDataOwned::EventMap(event_map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, metadata::tables::TableId,
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_event_map_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a TypeDef for testing
        let type_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        let map_ref = EventMapBuilder::new()
            .parent(type_ref.placeholder())
            .event_list(1)
            .build(&mut assembly)?;

        // Verify the ref has the correct kind
        assert_eq!(map_ref.kind(), ChangeRefKind::TableRow(TableId::EventMap));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_default() -> Result<()> {
        let builder = EventMapBuilder::default();
        assert!(builder.parent.is_none());
        assert!(builder.event_list.is_none());
        Ok(())
    }

    #[test]
    fn test_event_map_builder_missing_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = EventMapBuilder::new().event_list(1).build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent row index is required"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_missing_event_list() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a TypeDef for testing
        let type_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        let result = EventMapBuilder::new()
            .parent(type_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Event list index is required"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_zero_parent_row() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = EventMapBuilder::new()
            .parent(0) // Zero row index is invalid
            .event_list(1)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Parent row index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_zero_event_list() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a TypeDef for testing
        let type_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        let result = EventMapBuilder::new()
            .parent(type_ref.placeholder())
            .event_list(0) // Zero event list index is invalid
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Event list index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_multiple_entries() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create TypeDefs for testing
        let type1_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass1")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        let type2_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("EventfulClass2")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        let map1_ref = EventMapBuilder::new()
            .parent(type1_ref.placeholder())
            .event_list(1)
            .build(&mut assembly)?;

        let map2_ref = EventMapBuilder::new()
            .parent(type2_ref.placeholder())
            .event_list(3)
            .build(&mut assembly)?;

        // Verify refs are different
        assert!(!std::sync::Arc::ptr_eq(&map1_ref, &map2_ref));
        assert_eq!(map1_ref.kind(), ChangeRefKind::TableRow(TableId::EventMap));
        assert_eq!(map2_ref.kind(), ChangeRefKind::TableRow(TableId::EventMap));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_various_event_indices() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with different event list indices
        let test_indices = [1, 5, 10, 20, 100];

        for (i, &index) in test_indices.iter().enumerate() {
            let type_ref = crate::metadata::tables::TypeDefBuilder::new()
                .name(format!("EventfulClass{i}"))
                .namespace("MyApp")
                .public_class()
                .build(&mut assembly)?;

            let map_ref = EventMapBuilder::new()
                .parent(type_ref.placeholder())
                .event_list(index)
                .build(&mut assembly)?;

            assert_eq!(map_ref.kind(), ChangeRefKind::TableRow(TableId::EventMap));
        }

        Ok(())
    }

    #[test]
    fn test_event_map_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a TypeDef for testing
        let type_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentTestClass")
            .namespace("MyApp")
            .public_class()
            .build(&mut assembly)?;

        // Test fluent API chaining
        let map_ref = EventMapBuilder::new()
            .parent(type_ref.placeholder())
            .event_list(5)
            .build(&mut assembly)?;

        assert_eq!(map_ref.kind(), ChangeRefKind::TableRow(TableId::EventMap));

        Ok(())
    }

    #[test]
    fn test_event_map_builder_clone() {
        let builder1 = EventMapBuilder::new().parent(1).event_list(1);
        let builder2 = builder1.clone();

        assert_eq!(builder1.parent, builder2.parent);
        assert_eq!(builder1.event_list, builder2.event_list);
    }

    #[test]
    fn test_event_map_builder_debug() {
        let builder = EventMapBuilder::new().parent(1).event_list(1);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EventMapBuilder"));
    }
}

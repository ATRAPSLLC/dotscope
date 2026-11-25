//! Builder for constructing `EventPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::eventptr::EventPtrBuilder`] which enables fluent construction
//! of `EventPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let eventptr_token = EventPtrBuilder::new()
//!     .event(4)                      // Points to Event table RID 4
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{EventPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `EventPtr` table entries
///
/// Provides a fluent interface for building `EventPtr` metadata table entries.
/// These entries provide indirection for event access when logical and physical
/// event ordering differs, primarily in edit-and-continue scenarios.
///
/// # Required Fields
/// - `event`: Event table RID that this pointer references
///
/// # Indirection Context
///
/// The EventPtr table provides a mapping layer between logical event references
/// and physical Event table entries. This enables:
/// - Event reordering during edit-and-continue operations
/// - Non-sequential event arrangements while maintaining logical consistency
/// - Runtime event hot-reload and debugging interception
/// - Stable event references across code modification sessions
///
/// # Examples
///
/// ```
/// use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("tests/samples/crafted_2.exe"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// // Create event pointer for edit-and-continue
/// let ptr1 = EventPtrBuilder::new()
///     .event(8)   // Points to Event table entry 8
///     .build(&mut assembly)?;
///
/// // Create pointer for reordered event layout
/// let ptr2 = EventPtrBuilder::new()
///     .event(3)   // Points to Event table entry 3
///     .build(&mut assembly)?;
///
/// // Multiple pointers for complex event arrangements
/// let ptr3 = EventPtrBuilder::new()
///     .event(15)  // Points to Event table entry 15
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct EventPtrBuilder {
    /// Event table RID that this pointer references
    event: Option<u32>,
}

impl EventPtrBuilder {
    /// Creates a new `EventPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required event RID before calling build().
    ///
    /// # Returns
    /// A new `EventPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { event: None }
    }

    /// Sets the Event table RID
    ///
    /// Specifies which Event table entry this pointer references. This creates
    /// the indirection mapping from the EventPtr RID (logical index) to the
    /// actual Event table entry (physical index).
    ///
    /// # Parameters
    /// - `event`: The Event table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Point to first event
    /// let builder = EventPtrBuilder::new()
    ///     .event(1);
    ///
    /// // Point to a later event for reordering
    /// let builder = EventPtrBuilder::new()
    ///     .event(12);
    /// ```
    #[must_use]
    pub fn event(mut self, event: u32) -> Self {
        self.event = Some(event);
        self
    }

    /// Builds and adds the `EventPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `EventPtr` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this event pointer entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created event pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (event RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = EventPtrBuilder::new()
    ///     .event(4)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let event = self.event.ok_or_else(|| {
            Error::ModificationInvalid("Event RID is required for EventPtr".to_string())
        })?;

        let event_ptr = EventPtrRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            event,
        };

        assembly.table_row_add(TableId::EventPtr, TableDataOwned::EventPtr(event_ptr))
    }
}

impl Default for EventPtrBuilder {
    /// Creates a default `EventPtrBuilder`
    ///
    /// Equivalent to calling [`EventPtrBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_eventptr_builder_new() {
        let builder = EventPtrBuilder::new();

        assert!(builder.event.is_none());
    }

    #[test]
    fn test_eventptr_builder_default() {
        let builder = EventPtrBuilder::default();

        assert!(builder.event.is_none());
    }

    #[test]
    fn test_eventptr_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EventPtrBuilder::new()
            .event(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_reordering() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EventPtrBuilder::new()
            .event(12) // Point to later event for reordering
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_missing_event() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = EventPtrBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Event RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_clone() {
        let builder = EventPtrBuilder::new().event(4);

        let cloned = builder.clone();
        assert_eq!(builder.event, cloned.event);
    }

    #[test]
    fn test_eventptr_builder_debug() {
        let builder = EventPtrBuilder::new().event(9);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EventPtrBuilder"));
        assert!(debug_str.contains("event"));
    }

    #[test]
    fn test_eventptr_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = EventPtrBuilder::new()
            .event(20)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first pointer
        let ref1 = EventPtrBuilder::new()
            .event(8)
            .build(&mut assembly)
            .expect("Should build first pointer");

        // Build second pointer
        let ref2 = EventPtrBuilder::new()
            .event(3)
            .build(&mut assembly)
            .expect("Should build second pointer");

        // Build third pointer
        let ref3 = EventPtrBuilder::new()
            .event(15)
            .build(&mut assembly)
            .expect("Should build third pointer");

        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_large_event_rid() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = EventPtrBuilder::new()
            .event(0xFFFF) // Large Event RID
            .build(&mut assembly)
            .expect("Should handle large event RID");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_event_ordering_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate event reordering: logical order 1,2,3 -> physical order 10,5,12
        let logical_to_physical = [(1, 10), (2, 5), (3, 12)];

        let mut refs = Vec::new();
        for (logical_idx, physical_event) in logical_to_physical {
            let ref_ = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut assembly)
                .expect("Should build event pointer");
            refs.push((logical_idx, ref_));
        }

        // Verify all refs have correct kind
        for (_logical_idx, ref_) in refs.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_zero_event() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with event 0 (typically invalid but should not cause builder to fail)
        let result = EventPtrBuilder::new().event(0).build(&mut assembly);

        // Should build successfully even with event 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_eventptr_builder_edit_continue_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate edit-and-continue where events are reordered after code modifications
        let reordered_events = [3, 1, 2]; // Physical reordering

        let mut event_pointers = Vec::new();
        for &physical_event in &reordered_events {
            let pointer_ref = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut assembly)
                .expect("Should build event pointer for edit-continue");
            event_pointers.push(pointer_ref);
        }

        // Verify stable logical references despite physical reordering
        for ref_ in event_pointers.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_type_event_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate type with multiple events that need indirection
        let type_events = [5, 10, 7, 15, 2]; // Events in custom order

        let mut event_pointers = Vec::new();
        for &event_rid in &type_events {
            let pointer_ref = EventPtrBuilder::new()
                .event(event_rid)
                .build(&mut assembly)
                .expect("Should build event pointer");
            event_pointers.push(pointer_ref);
        }

        // Verify event pointers maintain logical sequence
        for ref_ in event_pointers.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_hot_reload_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate hot-reload where new event implementations replace existing ones
        let new_event_implementations = [100, 200, 300];
        let mut pointer_refs = Vec::new();

        for &new_event in &new_event_implementations {
            let pointer_ref = EventPtrBuilder::new()
                .event(new_event)
                .build(&mut assembly)
                .expect("Should build pointer for hot-reload");
            pointer_refs.push(pointer_ref);
        }

        // Verify pointer references maintain stable references for hot-reload
        assert_eq!(pointer_refs.len(), 3);
        for ref_ in pointer_refs.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        }

        Ok(())
    }

    #[test]
    fn test_eventptr_builder_complex_indirection_scenario() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Simulate complex indirection with non-sequential event arrangement
        let complex_mapping = [25, 1, 50, 10, 75, 5, 100];

        let mut pointer_sequence = Vec::new();
        for &physical_event in &complex_mapping {
            let ref_ = EventPtrBuilder::new()
                .event(physical_event)
                .build(&mut assembly)
                .expect("Should build complex indirection mapping");
            pointer_sequence.push(ref_);
        }

        // Verify complex indirection maintains logical consistency
        assert_eq!(pointer_sequence.len(), 7);
        for ref_ in pointer_sequence.iter() {
            assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::EventPtr));
        }

        Ok(())
    }
}

//! MethodSemanticsBuilder for creating method semantic relationship metadata entries.
//!
//! This module provides [`crate::metadata::tables::methodsemantics::MethodSemanticsBuilder`] for creating MethodSemantics table entries
//! with a fluent API. Method semantic relationships define which concrete methods provide
//! semantic behavior for properties (getters/setters) and events (add/remove/fire handlers),
//! enabling the .NET runtime to understand accessor patterns and event handling mechanisms.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, MethodSemanticsAttributes, MethodSemanticsRaw,
            TableDataOwned, TableId,
        },
        token::Token,
    },
    Error, Result,
};

/// Represents the association target for a method semantic entry.
///
/// This enum captures both the row index (which can be a placeholder or actual row ID)
/// and the target table type. The `CodedIndex` is constructed at write time, not at
/// builder time, to ensure proper placeholder resolution.
#[derive(Debug, Clone, Copy)]
enum AssociationTarget {
    /// Association to a Property table entry
    Property(u32),
    /// Association to an Event table entry
    Event(u32),
}

/// Builder for creating MethodSemantics metadata entries.
///
/// `MethodSemanticsBuilder` provides a fluent API for creating MethodSemantics table entries
/// with validation and automatic relationship management. Method semantic relationships are
/// essential for connecting properties and events to their associated accessor methods,
/// enabling proper encapsulation and event handling in .NET programming models.
///
/// # Method Semantics Model
///
/// .NET method semantics follow this pattern:
/// - **Semantic Type**: The role the method plays (getter, setter, adder, etc.)
/// - **Method**: The concrete method that implements the semantic behavior
/// - **Association**: The property or event that the method provides behavior for
/// - **Runtime Integration**: The .NET runtime uses these relationships for proper dispatch
///
/// # Semantic Relationship Categories
///
/// Different categories of semantic relationships serve various purposes:
/// - **Property Semantics**: Getters, setters, and other property-related methods
/// - **Event Semantics**: Add, remove, fire, and other event-related methods
/// - **Custom Semantics**: Other specialized semantic relationships
/// - **Multiple Semantics**: Methods can have multiple semantic roles
///
/// # Coded Index Management
///
/// Method semantic relationships use HasSemantics coded indices:
/// - **Event References**: Links to event definitions in the Event table
/// - **Property References**: Links to property definitions in the Property table
/// - **Cross-Assembly Scenarios**: Support for semantic relationships across assembly boundaries
/// - **Type Safety**: Compile-time and runtime validation of semantic contracts
///
/// # Examples
///
/// ## Property Getter/Setter Relationship
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example(assembly: &mut CilAssembly) -> Result<()> {
/// // Create getter semantic relationship
/// let getter_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::GETTER)
///     .method(1) // MethodDef row index
///     .association_from_property(1) // Property row index
///     .build(assembly)?;
///
/// // Create setter semantic relationship
/// let setter_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::SETTER)
///     .method(2) // MethodDef row index
///     .association_from_property(1) // Same property
///     .build(assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Event Add/Remove Relationship
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example(assembly: &mut CilAssembly) -> Result<()> {
/// // Create event add handler relationship
/// let add_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::ADD_ON)
///     .method(3) // Add method row index
///     .association_from_event(1) // Event row index
///     .build(assembly)?;
///
/// // Create event remove handler relationship
/// let remove_semantic = MethodSemanticsBuilder::new()
///     .semantics(MethodSemanticsAttributes::REMOVE_ON)
///     .method(4) // Remove method row index
///     .association_from_event(1) // Same event
///     .build(assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `MethodSemanticsBuilder` follows the established builder pattern:
/// - No internal state requiring synchronization
/// - Context passed to build() method handles concurrency
/// - Can be created and used across thread boundaries
/// - Final build() operation is atomic within the context
pub struct MethodSemanticsBuilder {
    /// Semantic relationship type bitmask.
    ///
    /// Defines the method's semantic role using MethodSemanticsAttributes constants.
    /// Can combine multiple semantic types using bitwise OR operations.
    semantics: Option<MethodSemanticsAttributes>,

    /// Method that implements the semantic behavior.
    ///
    /// Row index referencing a MethodDef entry that provides the concrete implementation
    /// for the semantic relationship. Can be a placeholder or actual row ID.
    method: Option<u32>,

    /// Association target capturing the row index and target table type.
    ///
    /// The row index can be a placeholder or actual row ID. The `CodedIndex`
    /// is constructed at write time, not at builder time.
    association: Option<AssociationTarget>,
}

impl MethodSemanticsBuilder {
    /// Creates a new `MethodSemanticsBuilder` instance.
    ///
    /// Initializes all fields to `None`, requiring explicit configuration
    /// through the fluent API methods before building.
    ///
    /// # Returns
    ///
    /// New builder instance ready for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            semantics: None,
            method: None,
            association: None,
        }
    }

    /// Sets the semantic relationship type.
    ///
    /// Specifies the role this method plays in relation to the associated
    /// property or event using MethodSemanticsAttributes constants.
    ///
    /// # Arguments
    ///
    /// * `semantics` - Bitmask of semantic attributes (can combine multiple values)
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER);
    ///
    /// // Multiple semantics can be combined
    /// let combined = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER | MethodSemanticsAttributes::OTHER);
    /// ```
    #[must_use]
    pub fn semantics(mut self, semantics: MethodSemanticsAttributes) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Sets the method that implements the semantic behavior.
    ///
    /// Specifies the MethodDef row index for the method that provides the concrete
    /// implementation of the semantic relationship.
    ///
    /// # Arguments
    ///
    /// * `method` - Row index referencing a MethodDef table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .method(1); // MethodDef row index
    /// ```
    #[must_use]
    pub fn method(mut self, method: u32) -> Self {
        self.method = Some(method);
        self
    }

    /// Sets the association to a property using its row index or placeholder.
    ///
    /// Stores the property row index for later construction of a HasSemantics coded index
    /// during the write phase. The `CodedIndex` is NOT created at builder time to ensure
    /// proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `property` - Row index or placeholder referencing a Property table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .association_from_property(1); // Property row index
    /// ```
    #[must_use]
    pub fn association_from_property(mut self, property: u32) -> Self {
        self.association = Some(AssociationTarget::Property(property));
        self
    }

    /// Sets the association to an event using its row index or placeholder.
    ///
    /// Stores the event row index for later construction of a HasSemantics coded index
    /// during the write phase. The `CodedIndex` is NOT created at builder time to ensure
    /// proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `event` - Row index or placeholder referencing an Event table entry
    ///
    /// # Returns
    ///
    /// Updated builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodSemanticsBuilder::new()
    ///     .association_from_event(1); // Event row index
    /// ```
    #[must_use]
    pub fn association_from_event(mut self, event: u32) -> Self {
        self.association = Some(AssociationTarget::Event(event));
        self
    }

    /// Builds the MethodSemantics entry and adds it to the assembly.
    ///
    /// Validates all required fields, creates the raw MethodSemantics entry,
    /// and adds it to the MethodSemantics table through the builder assembly.
    /// Returns the token for the newly created entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Mutable reference to the CilAssembly for assembly modification
    ///
    /// # Returns
    ///
    /// `Result<Token>` - Token for the created MethodSemantics entry or error if validation fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required semantics field is not set
    /// - Required method field is not set  
    /// - Required association field is not set
    /// - Context operations fail (heap allocation, table modification)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn example(assembly: &mut CilAssembly) -> Result<()> {
    /// let semantic_ref = MethodSemanticsBuilder::new()
    ///     .semantics(MethodSemanticsAttributes::GETTER)
    ///     .method(1)
    ///     .association_from_property(1)
    ///     .build(assembly)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Validate required fields
        let semantics = self.semantics.ok_or_else(|| {
            Error::ModificationInvalid("MethodSemantics semantics field is required".to_string())
        })?;

        let method = self.method.ok_or_else(|| {
            Error::ModificationInvalid("MethodSemantics method field is required".to_string())
        })?;

        let association_target = self.association.ok_or_else(|| {
            Error::ModificationInvalid("MethodSemantics association field is required".to_string())
        })?;

        // Construct the CodedIndex from the stored target information.
        // The row value may be a placeholder that will be resolved at write time
        // by the ResolvePlaceholders implementation.
        let association = match association_target {
            AssociationTarget::Property(row) => {
                CodedIndex::new(TableId::Property, row, CodedIndexType::HasSemantics)
            }
            AssociationTarget::Event(row) => {
                CodedIndex::new(TableId::Event, row, CodedIndexType::HasSemantics)
            }
        };

        let method_semantics_raw = MethodSemanticsRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            semantics: semantics.bits(),
            method,
            association,
        };

        assembly.table_row_add(
            TableId::MethodSemantics,
            TableDataOwned::MethodSemantics(method_semantics_raw),
        )
    }
}

impl Default for MethodSemanticsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::MethodSemanticsAttributes},
        testkit::fixture,
    };

    #[test]
    fn test_methodsemantics_builder_creation() {
        let builder = MethodSemanticsBuilder::new();
        assert!(builder.semantics.is_none());
        assert!(builder.method.is_none());
        assert!(builder.association.is_none());
    }

    #[test]
    fn test_methodsemantics_builder_default() {
        let builder = MethodSemanticsBuilder::default();
        assert!(builder.semantics.is_none());
        assert!(builder.method.is_none());
        assert!(builder.association.is_none());
    }

    #[test]
    fn test_property_getter_semantic() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER)
            .method(1)
            .association_from_property(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_property_setter_semantic() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::SETTER)
            .method(2)
            .association_from_property(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_event_add_semantic() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::ADD_ON)
            .method(3)
            .association_from_event(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_event_remove_semantic() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::REMOVE_ON)
            .method(4)
            .association_from_event(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_event_fire_semantic() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::FIRE)
            .method(5)
            .association_from_event(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_combined_semantics() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER | MethodSemanticsAttributes::OTHER)
            .method(6)
            .association_from_property(2)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_association_with_row_index() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        // Test using direct row index (not a placeholder)
        let semantic_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER)
            .method(7)
            .association_from_property(1)
            .build(&mut assembly)?;

        assert_eq!(
            semantic_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        Ok(())
    }

    #[test]
    fn test_multiple_method_semantics() -> Result<()> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        let mut assembly = CilAssembly::new(view);

        // Create multiple semantic relationships for the same property
        let getter_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER)
            .method(1)
            .association_from_property(1)
            .build(&mut assembly)?;

        let setter_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::SETTER)
            .method(2)
            .association_from_property(1)
            .build(&mut assembly)?;

        let other_ref = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::OTHER)
            .method(3)
            .association_from_property(1)
            .build(&mut assembly)?;

        assert_eq!(
            getter_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        assert_eq!(
            setter_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        assert_eq!(
            other_ref.kind(),
            ChangeRefKind::TableRow(TableId::MethodSemantics)
        );
        assert!(!std::sync::Arc::ptr_eq(&getter_ref, &setter_ref));
        assert!(!std::sync::Arc::ptr_eq(&setter_ref, &other_ref));
        Ok(())
    }

    #[test]
    fn test_build_without_semantics_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodSemanticsBuilder::new()
            .method(1)
            .association_from_property(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("semantics field is required"));
    }

    #[test]
    fn test_build_without_method_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER)
            .association_from_property(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("method field is required"));
    }

    #[test]
    fn test_build_without_association_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodSemanticsBuilder::new()
            .semantics(MethodSemanticsAttributes::GETTER)
            .method(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("association field is required"));
    }
}

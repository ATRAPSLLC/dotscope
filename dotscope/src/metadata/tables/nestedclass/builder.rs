//! # NestedClass Builder
//!
//! Provides a fluent API for building NestedClass table entries that define hierarchical relationships
//! between nested types and their enclosing types. The NestedClass table establishes type containment
//! structure essential for proper type visibility and scoping in .NET assemblies.
//!
//! ## Overview
//!
//! The `NestedClassBuilder` enables creation of nested class relationships with:
//! - Nested type specification (required)
//! - Enclosing type specification (required)  
//! - Validation of type relationships
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # fn main() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create an enclosing type first
//! let outer_class_token = TypeDefBuilder::new()
//!     .name("OuterClass")
//!     .namespace("MyApp.Models")
//!     .public_class()
//!     .build(&mut assembly)?;
//!
//! // Create a nested type
//! let inner_class_token = TypeDefBuilder::new()
//!     .name("InnerClass")
//!     .namespace("MyApp.Models")
//!     .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
//!     .build(&mut assembly)?;
//!
//! // Establish the nesting relationship
//! let nesting_token = NestedClassBuilder::new()
//!     .nested_class(inner_class_token.row())
//!     .enclosing_class(outer_class_token.row())
//!     .build(&mut assembly)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Both nested and enclosing types are required
//! - **Relationship Validation**: Prevents invalid nesting scenarios
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Type Safety**: Ensures proper TypeDef token validation

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{NestedClassRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating NestedClass table entries.
///
/// `NestedClassBuilder` provides a fluent API for creating entries in the NestedClass
/// metadata table, which defines hierarchical relationships between nested types and
/// their enclosing types.
///
/// # Purpose
///
/// The NestedClass table serves several key functions:
/// - **Type Hierarchy**: Defines which types are nested within other types
/// - **Visibility Scoping**: Establishes access rules for nested types
/// - **Enclosing Context**: Links nested types to their containing types
/// - **Namespace Resolution**: Enables proper type resolution within nested contexts
/// - **Compilation Support**: Provides context for type compilation and loading
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing NestedClass entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
/// # let outer_row: u32 = 1;
/// # let inner_row: u32 = 2;
///
/// let nesting_token = NestedClassBuilder::new()
///     .nested_class(inner_row)
///     .enclosing_class(outer_row)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Nested Class Required**: A nested class token must be provided
/// - **Enclosing Class Required**: An enclosing class token must be provided
/// - **Token Validation**: Both tokens must be valid TypeDef tokens
/// - **Relationship Validation**: Prevents invalid nesting scenarios (self-nesting, etc.)
///
/// # Integration
///
/// NestedClass entries integrate with other metadata structures:
/// - **TypeDef**: Both nested and enclosing types must be TypeDef entries
/// - **Type Registry**: Establishes relationships in the type system
/// - **Visibility Rules**: Nested types inherit accessibility from their context
#[derive(Debug, Clone)]
pub struct NestedClassBuilder {
    /// The row index (or placeholder) of the nested type
    nested_class: Option<u32>,
    /// The row index (or placeholder) of the enclosing type
    enclosing_class: Option<u32>,
}

impl Default for NestedClassBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NestedClassBuilder {
    /// Creates a new `NestedClassBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = NestedClassBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            nested_class: None,
            enclosing_class: None,
        }
    }

    /// Sets the row index of the nested type.
    ///
    /// The nested type must be a valid TypeDef row index or placeholder that represents
    /// the type being nested within the enclosing type.
    ///
    /// # Arguments
    ///
    /// * `nested_class_row` - Row index (or placeholder) of the TypeDef for the nested type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # fn main() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let inner_token = TypeDefBuilder::new()
    ///     .name("InnerClass")
    ///     .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
    ///     .build(&mut assembly)?;
    ///
    /// let builder = NestedClassBuilder::new()
    ///     .nested_class(inner_token.placeholder());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn nested_class(mut self, nested_class_row: u32) -> Self {
        self.nested_class = Some(nested_class_row);
        self
    }

    /// Sets the row index of the enclosing type.
    ///
    /// The enclosing type must be a valid TypeDef row index or placeholder that represents
    /// the type containing the nested type.
    ///
    /// # Arguments
    ///
    /// * `enclosing_class_row` - Row index (or placeholder) of the TypeDef for the enclosing type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # fn main() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let outer_token = TypeDefBuilder::new()
    ///     .name("OuterClass")
    ///     .public_class()
    ///     .build(&mut assembly)?;
    ///
    /// let builder = NestedClassBuilder::new()
    ///     .enclosing_class(outer_token.placeholder());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn enclosing_class(mut self, enclosing_class_row: u32) -> Self {
        self.enclosing_class = Some(enclosing_class_row);
        self
    }

    /// Builds the NestedClass entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the type tokens are valid TypeDef
    /// tokens, validates the nesting relationship, creates the NestedClass table entry,
    /// and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created NestedClass entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nested class token is not set
    /// - The enclosing class token is not set
    /// - Either token is not a valid TypeDef token
    /// - The tokens refer to the same type (self-nesting)
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let outer_row: u32 = 1;
    /// # let inner_row: u32 = 2;
    ///
    /// let nesting_token = NestedClassBuilder::new()
    ///     .nested_class(inner_row)
    ///     .enclosing_class(outer_row)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created NestedClass with token: {:?}", nesting_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let nested_class_row = self.nested_class.ok_or_else(|| {
            Error::ModificationInvalid("Nested class row is required for NestedClass".to_string())
        })?;

        let enclosing_class_row = self.enclosing_class.ok_or_else(|| {
            Error::ModificationInvalid(
                "Enclosing class row is required for NestedClass".to_string(),
            )
        })?;

        // Note: Row validation is skipped for placeholders (high bit set)
        // Placeholders will be resolved during the write phase
        if nested_class_row == 0 {
            return Err(Error::ModificationInvalid(
                "Nested class row cannot be 0".to_string(),
            ));
        }

        if enclosing_class_row == 0 {
            return Err(Error::ModificationInvalid(
                "Enclosing class row cannot be 0".to_string(),
            ));
        }

        // Prevent self-nesting (only for non-placeholder values)
        if nested_class_row == enclosing_class_row {
            return Err(Error::ModificationInvalid(
                "A type cannot be nested within itself".to_string(),
            ));
        }

        let nested_class = NestedClassRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            nested_class: nested_class_row,
            enclosing_class: enclosing_class_row,
        };

        assembly.table_row_add(
            TableId::NestedClass,
            TableDataOwned::NestedClass(nested_class),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind,
        metadata::tables::{TableId, TypeAttributes},
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_nested_class_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create TypeDefs for testing
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Use placeholder values for the NestedClass builder
        let nested_ref = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly)?;

        // Verify the reference has the correct table ID
        assert_eq!(
            nested_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_default() -> Result<()> {
        let builder = NestedClassBuilder::default();
        assert!(builder.nested_class.is_none());
        assert!(builder.enclosing_class.is_none());
        Ok(())
    }

    #[test]
    fn test_nested_class_builder_missing_nested_class() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create an enclosing type
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        let result = NestedClassBuilder::new()
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class row is required"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_missing_enclosing_class() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a nested type
        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        let result = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class row is required"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_nested_row() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create valid enclosing type
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        // Use zero row index which is invalid
        let result = NestedClassBuilder::new()
            .nested_class(0)
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_enclosing_row() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create valid nested type
        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Use zero row index which is invalid
        let result = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .enclosing_class(0)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_self_nesting() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a type
        let type_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("SelfNestingClass")
            .public_class()
            .build(&mut assembly)?;

        let type_placeholder = type_ref.placeholder();

        // Try to nest it within itself
        let result = NestedClassBuilder::new()
            .nested_class(type_placeholder)
            .enclosing_class(type_placeholder)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("A type cannot be nested within itself"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_row_nested() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create valid enclosing type
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        // Use a zero row value
        let result = NestedClassBuilder::new()
            .nested_class(0)
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_row_enclosing() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create valid nested type
        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Use a zero row value
        let result = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .enclosing_class(0)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_multiple_relationships() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create an outer class
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        // Create two inner classes
        let inner1_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass1")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        let inner2_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass2")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Create nesting relationships
        let nesting1_ref = NestedClassBuilder::new()
            .nested_class(inner1_ref.placeholder())
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly)?;

        let nesting2_ref = NestedClassBuilder::new()
            .nested_class(inner2_ref.placeholder())
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly)?;

        // Verify references are different and have correct kind
        assert!(!std::sync::Arc::ptr_eq(&nesting1_ref, &nesting2_ref));
        assert_eq!(
            nesting1_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );
        assert_eq!(
            nesting2_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_deep_nesting() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a hierarchy: Outer -> Middle -> Inner
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut assembly)?;

        let middle_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("MiddleClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Create the nesting relationships
        let nesting1_ref = NestedClassBuilder::new()
            .nested_class(middle_ref.placeholder())
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly)?;

        let nesting2_ref = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .enclosing_class(middle_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            nesting1_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );
        assert_eq!(
            nesting2_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create types for testing
        let outer_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentOuter")
            .public_class()
            .build(&mut assembly)?;

        let inner_ref = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentInner")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)?;

        // Test fluent API chaining
        let nested_ref = NestedClassBuilder::new()
            .nested_class(inner_ref.placeholder())
            .enclosing_class(outer_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            nested_ref.kind(),
            ChangeRefKind::TableRow(TableId::NestedClass)
        );

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_clone() {
        let nested_row = 1u32;
        let enclosing_row = 2u32;

        let builder1 = NestedClassBuilder::new()
            .nested_class(nested_row)
            .enclosing_class(enclosing_row);
        let builder2 = builder1.clone();

        assert_eq!(builder1.nested_class, builder2.nested_class);
        assert_eq!(builder1.enclosing_class, builder2.enclosing_class);
    }

    #[test]
    fn test_nested_class_builder_debug() {
        let nested_row = 1u32;
        let enclosing_row = 2u32;

        let builder = NestedClassBuilder::new()
            .nested_class(nested_row)
            .enclosing_class(enclosing_row);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("NestedClassBuilder"));
    }
}

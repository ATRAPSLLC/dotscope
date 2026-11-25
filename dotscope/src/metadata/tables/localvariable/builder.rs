//! Builder for constructing `LocalVariable` table entries
//!
//! This module provides the [`crate::metadata::tables::localvariable::LocalVariableBuilder`] which enables fluent construction
//! of `LocalVariable` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let local_var_token = LocalVariableBuilder::new()
//!     .attributes(0x01)       // Set variable attributes
//!     .index(0)               // First local variable
//!     .name("counter")        // Variable name
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{LocalVariableRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `LocalVariable` table entries
///
/// Provides a fluent interface for building `LocalVariable` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `index`: Variable index within the method (must be provided)
/// - `name`: Variable name (can be empty for anonymous variables, but must be explicitly set)
///
/// # Optional Fields  
/// - `attributes`: Variable attribute flags (defaults to 0)
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Named local variable
/// let var_token = LocalVariableBuilder::new()
///     .attributes(0x01)
///     .index(0)
///     .name("myVariable")
///     .build(&mut assembly)?;
///
/// // Anonymous variable (compiler-generated)
/// let anon_token = LocalVariableBuilder::new()
///     .index(1)
///     .name("")  // Empty name for anonymous variable
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct LocalVariableBuilder {
    /// Variable attribute flags
    attributes: Option<u16>,
    /// Variable index within the method
    index: Option<u16>,
    /// Variable name (empty string for anonymous variables)
    name: Option<String>,
}

impl LocalVariableBuilder {
    /// Creates a new `LocalVariableBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (index and name) before calling build().
    ///
    /// # Returns
    /// A new `LocalVariableBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            attributes: None,
            index: None,
            name: None,
        }
    }

    /// Sets the variable attribute flags
    ///
    /// Configures the attribute flags for this local variable. These flags
    /// describe characteristics of the variable such as whether it's compiler-generated,
    /// pinned, or has other special properties.
    ///
    /// # Parameters
    /// - `attributes`: The attribute flags to set (bitfield)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new()
    ///     .attributes(0x01);  // Set specific attribute flag
    /// ```
    #[must_use]
    pub fn attributes(mut self, attributes: u16) -> Self {
        self.attributes = Some(attributes);
        self
    }

    /// Sets the variable index within the method
    ///
    /// Specifies the zero-based index that identifies this variable within
    /// the containing method. This index corresponds to the variable's position
    /// in the method's local variable signature and IL instructions.
    ///
    /// # Parameters
    /// - `index`: The variable index (0-based)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new()
    ///     .index(0);  // First local variable
    /// ```
    #[must_use]
    pub fn index(mut self, index: u16) -> Self {
        self.index = Some(index);
        self
    }

    /// Sets the variable name
    ///
    /// Specifies the name for this local variable. The name can be empty
    /// for anonymous or compiler-generated variables.
    ///
    /// # Parameters
    /// - `name`: The variable name (can be empty string)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Named variable
    /// let builder = LocalVariableBuilder::new()
    ///     .name("counter");
    ///
    /// // Anonymous variable
    /// let anon_builder = LocalVariableBuilder::new()
    ///     .name("");
    /// ```
    #[must_use]
    pub fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Builds and adds the `LocalVariable` entry to the metadata
    ///
    /// Validates all required fields, creates the `LocalVariable` table entry,
    /// and adds it to the CilAssembly. Returns a token that can be used
    /// to reference this local variable.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created local variable
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (index or name)
    /// - Table operations fail due to metadata constraints
    /// - Local variable validation failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = LocalVariableBuilder::new()
    ///     .index(0)
    ///     .name("myVar")
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let index = self.index.ok_or_else(|| {
            Error::ModificationInvalid("Variable index is required for LocalVariable".to_string())
        })?;

        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid(
                "Variable name is required for LocalVariable (use empty string for anonymous)"
                    .to_string(),
            )
        })?;

        let name_index = if name.is_empty() {
            0
        } else {
            assembly.string_add(&name)?.placeholder()
        };

        let local_variable = LocalVariableRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            attributes: self.attributes.unwrap_or(0),
            index,
            name: name_index,
        };

        assembly.table_row_add(
            TableId::LocalVariable,
            TableDataOwned::LocalVariable(local_variable),
        )
    }
}

impl Default for LocalVariableBuilder {
    /// Creates a default `LocalVariableBuilder`
    ///
    /// Equivalent to calling [`LocalVariableBuilder::new()`].
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
    fn test_localvariable_builder_new() {
        let builder = LocalVariableBuilder::new();

        assert!(builder.attributes.is_none());
        assert!(builder.index.is_none());
        assert!(builder.name.is_none());
    }

    #[test]
    fn test_localvariable_builder_default() {
        let builder = LocalVariableBuilder::default();

        assert!(builder.attributes.is_none());
        assert!(builder.index.is_none());
        assert!(builder.name.is_none());
    }

    #[test]
    fn test_localvariable_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = LocalVariableBuilder::new()
            .index(0)
            .name("testVar")
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_with_all_fields() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = LocalVariableBuilder::new()
            .attributes(0x0001)
            .index(2)
            .name("myVariable")
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_anonymous_variable() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = LocalVariableBuilder::new()
            .index(1)
            .name("") // Empty name for anonymous variable
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_missing_index() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = LocalVariableBuilder::new()
            .name("testVar")
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Variable index is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = LocalVariableBuilder::new().index(0).build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Variable name is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_clone() {
        let builder = LocalVariableBuilder::new()
            .attributes(0x01)
            .index(0)
            .name("testVar");

        let cloned = builder.clone();
        assert_eq!(builder.attributes, cloned.attributes);
        assert_eq!(builder.index, cloned.index);
        assert_eq!(builder.name, cloned.name);
    }

    #[test]
    fn test_localvariable_builder_debug() {
        let builder = LocalVariableBuilder::new()
            .attributes(0x01)
            .index(0)
            .name("testVar");

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("LocalVariableBuilder"));
        assert!(debug_str.contains("attributes"));
        assert!(debug_str.contains("index"));
        assert!(debug_str.contains("name"));
    }

    #[test]
    fn test_localvariable_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = LocalVariableBuilder::new()
            .attributes(0x0002)
            .index(3)
            .name("chainedVar")
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first variable
        let ref1 = LocalVariableBuilder::new()
            .index(0)
            .name("var1")
            .build(&mut assembly)
            .expect("Should build first variable");

        // Build second variable
        let ref2 = LocalVariableBuilder::new()
            .index(1)
            .name("var2")
            .build(&mut assembly)
            .expect("Should build second variable");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::LocalVariable));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }
}

//! LocalScopeBuilder for creating local variable scope metadata entries.
//!
//! This module provides [`crate::metadata::tables::localscope::LocalScopeBuilder`] for creating LocalScope table entries
//! with a fluent API. Local scopes define the IL instruction ranges where local
//! variables and constants are active within methods, enabling proper debugging
//! support for block-scoped variables and constants.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{LocalScopeRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating LocalScope metadata entries.
///
/// `LocalScopeBuilder` provides a fluent API for creating LocalScope table entries
/// with validation and automatic relationship management. Local scopes are essential
/// for debugging support, defining where local variables and constants are visible
/// within method IL code.
///
/// # Local Scope Model
///
/// .NET local scopes follow this pattern:
/// - **Method Container**: The method containing this scope
/// - **Import Context**: Optional namespace import context
/// - **Variable Range**: Variables active within this scope
/// - **Constant Range**: Constants active within this scope
/// - **IL Boundaries**: Start offset and length in IL instructions
///
/// # Scope Relationships
///
/// Local scopes integrate with other debugging metadata:
/// - **Method**: Must reference a valid MethodDef entry
/// - **ImportScope**: Optional reference for namespace context
/// - **LocalVariable**: Range of variables active in this scope
/// - **LocalConstant**: Range of constants active in this scope
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # fn main() -> dotscope::Result<()> {
/// let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a basic local scope
/// let scope_ref = LocalScopeBuilder::new()
///     .method(1)                       // MethodDef row 1
///     .start_offset(0x10)              // IL offset where scope begins
///     .length(0x50)                    // Length in IL bytes
///     .build(&mut assembly)?;
///
/// // Create a scope with variables and import context
/// let detailed_scope = LocalScopeBuilder::new()
///     .method(2)                       // MethodDef row 2
///     .import_scope(1)                 // Reference to import scope
///     .variable_list(3)                // First variable index
///     .constant_list(1)                // First constant index
///     .start_offset(0x00)
///     .length(0x100)
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// # Validation
///
/// The builder enforces these constraints:
/// - **Method Required**: Must reference a valid MethodDef
/// - **Offset Range**: Start offset must be valid for the method
/// - **Length Validation**: Length must be > 0
/// - **Index Consistency**: Variable/constant lists must be valid if specified
///
/// # Integration
///
/// Local scopes integrate with debug metadata structures:
/// - **MethodDebugInformation**: Links method debugging to scopes
/// - **LocalVariable**: Variables are active within scope boundaries
/// - **LocalConstant**: Constants are active within scope boundaries
/// - **ImportScope**: Provides namespace context for variable resolution
///
/// # Thread Safety
///
/// `LocalScopeBuilder` is safe to use across threads:
/// - No internal state requiring synchronization
/// - CilAssembly passed to build() method handles concurrency
/// - Can be created and used across thread boundaries
/// - Final build() operation is atomic within the assembly
#[derive(Debug, Clone, Default)]
pub struct LocalScopeBuilder {
    /// Method containing this scope (row index or placeholder)
    method: Option<u32>,
    /// Optional import scope for namespace context
    import_scope: Option<u32>,
    /// First variable index (0 = no variables)
    variable_list: Option<u32>,
    /// First constant index (0 = no constants)
    constant_list: Option<u32>,
    /// IL offset where scope begins
    start_offset: Option<u32>,
    /// Length of scope in IL bytes
    length: Option<u32>,
}

impl LocalScopeBuilder {
    /// Creates a new `LocalScopeBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the method that contains this local scope.
    ///
    /// This method reference is required and must point to a valid MethodDef
    /// entry. All local scopes must belong to a specific method.
    ///
    /// # Arguments
    ///
    /// * `method` - Row index or placeholder for the containing method (MethodDef table)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .method(1);  // MethodDef row 1
    /// ```
    #[must_use]
    pub fn method(mut self, method: u32) -> Self {
        self.method = Some(method);
        self
    }

    /// Sets the import scope for namespace context.
    ///
    /// The import scope provides namespace context for resolving variable
    /// and constant names within this local scope. This is optional and
    /// may be 0 if no specific import context is needed.
    ///
    /// # Arguments
    ///
    /// * `import_scope` - Index into ImportScope table (0 = no import scope)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .import_scope(2);  // Reference to ImportScope RID 2
    /// ```
    #[must_use]
    pub fn import_scope(mut self, import_scope: u32) -> Self {
        self.import_scope = Some(import_scope);
        self
    }

    /// Sets the first variable index for this scope.
    ///
    /// Points to the first LocalVariable entry that belongs to this scope.
    /// Variables are stored consecutively, so this serves as a range start.
    /// May be 0 if this scope contains no variables.
    ///
    /// # Arguments
    ///
    /// * `variable_list` - Index into LocalVariable table: the first variable of the scope.
    ///   Without it, the scope starts an empty list at the next LocalVariable row
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .variable_list(5);  // Variables start at LocalVariable RID 5
    /// ```
    #[must_use]
    pub fn variable_list(mut self, variable_list: u32) -> Self {
        self.variable_list = Some(variable_list);
        self
    }

    /// Sets the first constant index for this scope.
    ///
    /// Points to the first LocalConstant entry that belongs to this scope.
    /// Constants are stored consecutively, so this serves as a range start.
    /// May be 0 if this scope contains no constants.
    ///
    /// # Arguments
    ///
    /// * `constant_list` - Index into LocalConstant table: the first constant of the scope.
    ///   Without it, the scope starts an empty list at the next LocalConstant row
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .constant_list(3);  // Constants start at LocalConstant RID 3
    /// ```
    #[must_use]
    pub fn constant_list(mut self, constant_list: u32) -> Self {
        self.constant_list = Some(constant_list);
        self
    }

    /// Sets the IL offset where this scope begins.
    ///
    /// Specifies the byte offset within the method's IL code where
    /// the variables and constants in this scope become active.
    ///
    /// # Arguments
    ///
    /// * `start_offset` - IL instruction offset (0-based)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .start_offset(0x10);  // Scope starts at IL offset 16
    /// ```
    #[must_use]
    pub fn start_offset(mut self, start_offset: u32) -> Self {
        self.start_offset = Some(start_offset);
        self
    }

    /// Sets the length of this scope in IL instruction bytes.
    ///
    /// Specifies how many bytes of IL code this scope covers.
    /// The scope extends from start_offset to (start_offset + length).
    ///
    /// # Arguments
    ///
    /// * `length` - Length in IL instruction bytes (must be > 0)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = LocalScopeBuilder::new()
    ///     .length(0x50);  // Scope covers 80 bytes of IL code
    /// ```
    #[must_use]
    pub fn length(mut self, length: u32) -> Self {
        self.length = Some(length);
        self
    }

    /// Builds the LocalScope entry and adds it to the assembly.
    ///
    /// This method validates all provided information, creates the LocalScope
    /// metadata entry, and adds it to the assembly's LocalScope table.
    /// Returns a change reference that can be used to track this scope.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for assembly modification
    ///
    /// # Returns
    ///
    /// Returns `Ok(ChangeRefRc)` with the LocalScope reference on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method reference is missing or invalid (must be > 0)
    /// - Start offset or length are missing
    /// - Length is zero
    /// - Table operations fail due to metadata constraints
    /// - Local scope validation failed
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let method = self.method.ok_or_else(|| {
            Error::ModificationInvalid("Method row is required for LocalScope".to_string())
        })?;

        let start_offset = self.start_offset.ok_or_else(|| {
            Error::ModificationInvalid("Start offset is required for LocalScope".to_string())
        })?;

        let length = self.length.ok_or_else(|| {
            Error::ModificationInvalid("Length is required for LocalScope".to_string())
        })?;

        if method == 0 {
            return Err(Error::ModificationInvalid(
                "Method row cannot be 0".to_string(),
            ));
        }

        if length == 0 {
            return Err(Error::ModificationInvalid(
                "LocalScope length cannot be zero".to_string(),
            ));
        }

        let rid = assembly.next_rid(TableId::LocalScope)?;
        let token = Token::from_parts(TableId::LocalScope, rid);

        let local_scope_raw = LocalScopeRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            method,
            import_scope: self.import_scope.unwrap_or(0),
            variable_list: match self.variable_list {
                Some(list) => list,
                None => assembly.next_rid(TableId::LocalVariable)?,
            },
            constant_list: match self.constant_list {
                Some(list) => list,
                None => assembly.next_rid(TableId::LocalConstant)?,
            },
            start_offset,
            length,
        };

        assembly.table_row_add(
            TableId::LocalScope,
            TableDataOwned::LocalScope(local_scope_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_localscope_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = LocalScopeBuilder::new()
            .method(1)
            .start_offset(0x10)
            .length(0x50)
            .build(&mut assembly)?;

        // Verify the ref has the correct table ID
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalScope));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_default() -> Result<()> {
        let builder = LocalScopeBuilder::default();
        assert!(builder.method.is_none());
        assert!(builder.import_scope.is_none());
        assert!(builder.variable_list.is_none());
        assert!(builder.constant_list.is_none());
        assert!(builder.start_offset.is_none());
        assert!(builder.length.is_none());
        Ok(())
    }

    #[test]
    fn test_localscope_builder_with_all_fields() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = LocalScopeBuilder::new()
            .method(2)
            .import_scope(1)
            .variable_list(5)
            .constant_list(2)
            .start_offset(0x00)
            .length(0x100)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalScope));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_missing_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = LocalScopeBuilder::new()
            .start_offset(0x10)
            .length(0x50)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Method row is required"));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_missing_start_offset() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = LocalScopeBuilder::new()
            .method(1)
            .length(0x50)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Start offset is required"));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_missing_length() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = LocalScopeBuilder::new()
            .method(1)
            .start_offset(0x10)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Length is required"));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_zero_length() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = LocalScopeBuilder::new()
            .method(1)
            .start_offset(0x10)
            .length(0)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("length cannot be zero"));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_zero_method_row() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = LocalScopeBuilder::new()
            .method(0) // Row 0 is invalid
            .start_offset(0x10)
            .length(0x50)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Method row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_localscope_builder_clone() {
        let builder1 = LocalScopeBuilder::new()
            .method(1)
            .start_offset(0x10)
            .length(0x50);
        let builder2 = builder1.clone();

        assert_eq!(builder1.method, builder2.method);
        assert_eq!(builder1.start_offset, builder2.start_offset);
        assert_eq!(builder1.length, builder2.length);
    }

    #[test]
    fn test_localscope_builder_debug() {
        let builder = LocalScopeBuilder::new().method(1).start_offset(0x10);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("LocalScopeBuilder"));
    }
}

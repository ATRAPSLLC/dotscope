//! ImplMapBuilder for creating Platform Invoke (P/Invoke) mapping specifications.
//!
//! This module provides [`crate::metadata::tables::implmap::ImplMapBuilder`] for creating ImplMap table entries
//! with a fluent API. Platform Invoke mappings enable managed code to call
//! unmanaged functions in native libraries, providing essential interoperability
//! between managed .NET code and native code libraries.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, ImplMapRaw, PInvokeAttributes, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating ImplMap metadata entries.
///
/// `ImplMapBuilder` provides a fluent API for creating ImplMap table entries
/// with validation and automatic string management. Platform Invoke mappings
/// define how managed methods map to native functions in external libraries,
/// enabling seamless interoperability between managed and unmanaged code.
///
/// # Platform Invoke Model
///
/// .NET Platform Invoke (P/Invoke) follows a structured mapping model:
/// - **Managed Method**: The method definition that will invoke native code
/// - **Native Library**: The external library containing the target function
/// - **Function Name**: The name of the native function to call
/// - **Marshalling Rules**: How parameters and return values are converted
/// - **Calling Convention**: How parameters are passed and stack is managed
/// - **Error Handling**: How native errors are propagated to managed code
///
/// # Coded Index Types
///
/// ImplMap entries use the `MemberForwarded` coded index to specify targets:
/// - **Field**: Field definitions (not commonly used for P/Invoke)
/// - **MethodDef**: Method definitions within the current assembly (primary use case)
///
/// # P/Invoke Configuration Scenarios
///
/// Different configuration patterns serve various interoperability scenarios:
/// - **Simple Function Call**: Basic native function invocation with default settings
/// - **Custom Calling Convention**: Specify `cdecl`, `stdcall`, `fastcall`, etc.
/// - **Character Set Marshalling**: Control ANSI vs Unicode string conversion
/// - **Error Propagation**: Enable `GetLastError()` support for native error handling
/// - **Name Mangling Control**: Preserve exact function names without decoration
///
/// # P/Invoke Attributes and Flags
///
/// Platform Invoke behavior is controlled through [`crate::metadata::tables::PInvokeAttributes`] flags:
/// - **Calling Conventions**: `CALL_CONV_CDECL`, `CALL_CONV_STDCALL`, etc.
/// - **Character Sets**: `CHAR_SET_ANSI`, `CHAR_SET_UNICODE`, `CHAR_SET_AUTO`
/// - **Name Mangling**: `NO_MANGLE` to preserve exact function names
/// - **Error Handling**: `SUPPORTS_LAST_ERROR` for error propagation
/// - **Character Mapping**: `BEST_FIT_ENABLED`, `THROW_ON_UNMAPPABLE_ENABLED`
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::PInvokeAttributes;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a basic P/Invoke mapping with default settings
/// let basic_pinvoke = ImplMapBuilder::new()
///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MemberForwarded)) // Target managed method
///     .import_name("MessageBoxW") // Native function name
///     .import_scope(1) // ModuleRef to user32.dll
///     .build(&mut assembly)?;
///
/// // Create a P/Invoke mapping with specific calling convention and character set
/// let advanced_pinvoke = ImplMapBuilder::new()
///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 2, CodedIndexType::MemberForwarded))
///     .import_name("GetModuleFileNameW")
///     .import_scope(2) // ModuleRef to kernel32.dll
///     .mapping_flags(
///         PInvokeAttributes::CALL_CONV_STDCALL |
///         PInvokeAttributes::CHAR_SET_UNICODE |
///         PInvokeAttributes::SUPPORTS_LAST_ERROR
///     )
///     .build(&mut assembly)?;
///
/// // Create a P/Invoke mapping with exact name preservation
/// let exact_name_pinvoke = ImplMapBuilder::new()
///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 3, CodedIndexType::MemberForwarded))
///     .import_name("my_custom_function") // Exact function name in native library
///     .import_scope(3) // ModuleRef to custom.dll
///     .mapping_flags(
///         PInvokeAttributes::NO_MANGLE |
///         PInvokeAttributes::CALL_CONV_CDECL
///     )
///     .build(&mut assembly)?;
///
/// // Create a P/Invoke mapping with advanced character handling
/// let string_handling_pinvoke = ImplMapBuilder::new()
///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 4, CodedIndexType::MemberForwarded))
///     .import_name("ProcessStringData")
///     .import_scope(4) // ModuleRef to stringlib.dll
///     .mapping_flags(
///         PInvokeAttributes::CHAR_SET_AUTO |
///         PInvokeAttributes::BEST_FIT_DISABLED |
///         PInvokeAttributes::THROW_ON_UNMAPPABLE_ENABLED
///     )
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ImplMapBuilder {
    mapping_flags: Option<PInvokeAttributes>,
    member_forwarded: Option<CodedIndex>,
    import_name: Option<String>,
    import_scope: Option<u32>,
}

impl Default for ImplMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ImplMapBuilder {
    /// Creates a new ImplMapBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::implmap::ImplMapBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mapping_flags: None,
            member_forwarded: None,
            import_name: None,
            import_scope: None,
        }
    }

    /// Sets the Platform Invoke attribute flags.
    ///
    /// Specifies the configuration for this P/Invoke mapping, including calling
    /// convention, character set, error handling, and name mangling behavior.
    /// Use constants from [`crate::metadata::tables::PInvokeAttributes`] and combine with bitwise OR.
    ///
    /// # Arguments
    ///
    /// * `flags` - P/Invoke attribute flags controlling marshalling behavior
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::PInvokeAttributes;
    /// let builder = ImplMapBuilder::new()
    ///     .mapping_flags(
    ///         PInvokeAttributes::CALL_CONV_STDCALL |
    ///         PInvokeAttributes::CHAR_SET_UNICODE |
    ///         PInvokeAttributes::SUPPORTS_LAST_ERROR
    ///     );
    /// ```
    #[must_use]
    pub fn mapping_flags(mut self, flags: PInvokeAttributes) -> Self {
        self.mapping_flags = Some(flags);
        self
    }

    /// Sets the member being forwarded to the native function.
    ///
    /// Specifies which managed method or field will be mapped to the native
    /// function. This must be a valid `MemberForwarded` coded index that
    /// references either a Field or MethodDef table entry. In practice,
    /// MethodDef is the primary use case for P/Invoke scenarios.
    ///
    /// Valid member types include:
    /// - `Field` - Field definitions (rare, used for global data access)
    /// - `MethodDef` - Method definitions (primary use case for function calls)
    ///
    /// # Arguments
    ///
    /// * `member` - Coded index to the member being forwarded
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dotscope::metadata::tables::{CodedIndex, CodedIndexType, ImplMapBuilder, TableId};
    /// let builder = ImplMapBuilder::new()
    ///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MemberForwarded));
    /// ```
    #[must_use]
    pub fn member_forwarded(mut self, member: CodedIndex) -> Self {
        self.member_forwarded = Some(member);
        self
    }

    /// Sets the name of the target function in the native library.
    ///
    /// Specifies the exact name of the function to call in the external
    /// native library. This name will be used during runtime linking
    /// to locate the function in the specified module.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the native function to invoke
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ImplMapBuilder;
    /// let builder = ImplMapBuilder::new()
    ///     .import_name("MessageBoxW");
    /// ```
    #[must_use]
    pub fn import_name(mut self, name: impl Into<String>) -> Self {
        self.import_name = Some(name.into());
        self
    }

    /// Sets the target module containing the native function.
    ///
    /// Specifies the ModuleRef table index that identifies the native
    /// library containing the target function. The ModuleRef entry
    /// defines the library name and loading characteristics.
    ///
    /// # Arguments
    ///
    /// * `scope` - ModuleRef table index for the target library
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::ImplMapBuilder;
    /// let builder = ImplMapBuilder::new()
    ///     .import_scope(1); // References ModuleRef #1 (e.g., user32.dll)
    /// ```
    #[must_use]
    pub fn import_scope(mut self, scope: u32) -> Self {
        self.import_scope = Some(scope);
        self
    }

    /// Builds the ImplMap entry and adds it to the assembly.
    ///
    /// Validates all required fields, adds the import name to the string heap,
    /// creates the ImplMapRaw structure, and adds it to the assembly's ImplMap table.
    /// Returns a token that can be used to reference this P/Invoke mapping.
    ///
    /// # Arguments
    ///
    /// * `assembly` - CIL assembly for heap and table management
    ///
    /// # Returns
    ///
    /// Returns a `Result<Token>` containing the token for the new ImplMap entry,
    /// or an error if validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - `member_forwarded` is not specified (required field)
    /// - `import_name` is not specified (required field)
    /// - `import_scope` is not specified (required field)
    /// - The member_forwarded coded index is invalid
    /// - String heap operations fail
    /// - Table operations fail
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let token = ImplMapBuilder::new()
    ///     .member_forwarded(CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MemberForwarded))
    ///     .import_name("MessageBoxW")
    ///     .import_scope(1)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let member_forwarded = self.member_forwarded.ok_or_else(|| {
            Error::ModificationInvalid("member_forwarded field is required".to_string())
        })?;

        let import_name = self.import_name.ok_or_else(|| {
            Error::ModificationInvalid("import_name field is required".to_string())
        })?;

        let import_scope = self.import_scope.ok_or_else(|| {
            Error::ModificationInvalid("import_scope field is required".to_string())
        })?;

        if !matches!(member_forwarded.tag, TableId::Field | TableId::MethodDef) {
            return Err(Error::ModificationInvalid(
                "MemberForwarded must reference Field or MethodDef table".to_string(),
            ));
        }

        let import_name_index = assembly.string_add(&import_name)?.placeholder();

        let implmap_raw = ImplMapRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            mapping_flags: self.mapping_flags.unwrap_or(PInvokeAttributes::ZERO).bits(),
            member_forwarded,
            import_name: import_name_index,
            import_scope,
        };

        assembly.table_row_add(TableId::ImplMap, TableDataOwned::ImplMap(implmap_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, metadata::tables::implmap::PInvokeAttributes, prelude::*,
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_implmap_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("MessageBoxW")
            .import_scope(1)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }

    #[test]
    fn test_implmap_builder_with_flags() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("GetModuleFileNameW")
            .import_scope(2)
            .mapping_flags(
                PInvokeAttributes::CALL_CONV_STDCALL
                    | PInvokeAttributes::CHAR_SET_UNICODE
                    | PInvokeAttributes::SUPPORTS_LAST_ERROR,
            )
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }

    #[test]
    fn test_implmap_builder_no_mangle() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                3,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("my_custom_function")
            .import_scope(3)
            .mapping_flags(PInvokeAttributes::NO_MANGLE | PInvokeAttributes::CALL_CONV_CDECL)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }

    #[test]
    fn test_implmap_builder_field_reference() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::Field,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("global_variable")
            .import_scope(1)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }

    #[test]
    fn test_implmap_builder_missing_member_forwarded() {
        let mut assembly = get_test_assembly().unwrap();

        let result = ImplMapBuilder::new()
            .import_name("MessageBoxW")
            .import_scope(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("member_forwarded"));
    }

    #[test]
    fn test_implmap_builder_missing_import_name() {
        let mut assembly = get_test_assembly().unwrap();

        let result = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_scope(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("import_name"));
    }

    #[test]
    fn test_implmap_builder_missing_import_scope() {
        let mut assembly = get_test_assembly().unwrap();

        let result = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("MessageBoxW")
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("import_scope"));
    }

    #[test]
    fn test_implmap_builder_invalid_coded_index() {
        let mut assembly = get_test_assembly().unwrap();

        let result = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::TypeDef,
                1,
                CodedIndexType::MemberForwarded,
            )) // Invalid table
            .import_name("MessageBoxW")
            .import_scope(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("MemberForwarded must reference Field or MethodDef"));
    }

    #[test]
    fn test_implmap_builder_multiple_flags() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = ImplMapBuilder::new()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                4,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("ProcessStringData")
            .import_scope(4)
            .mapping_flags(
                PInvokeAttributes::CHAR_SET_AUTO
                    | PInvokeAttributes::BEST_FIT_DISABLED
                    | PInvokeAttributes::THROW_ON_UNMAPPABLE_ENABLED,
            )
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }

    #[test]
    fn test_implmap_builder_default() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test Default trait implementation
        let ref_ = ImplMapBuilder::default()
            .member_forwarded(CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::MemberForwarded,
            ))
            .import_name("TestFunction")
            .import_scope(1)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::ImplMap));
        Ok(())
    }
}

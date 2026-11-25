//! Builder for native PE imports that integrates with the dotscope builder pattern.
//!
//! This module provides [`NativeImportsBuilder`] for creating native PE import tables
//! with a fluent API. The builder follows the established dotscope pattern of not holding
//! references to CilAssembly and instead taking it as a parameter to the build() method.

use crate::{cilassembly::CilAssembly, Result};

/// Builder for creating native PE import tables.
///
/// `NativeImportsBuilder` provides a fluent API for creating native PE import tables
/// with validation and automatic integration into the assembly. The builder follows
/// the established dotscope pattern where the assembly is passed to build() rather
/// than being held by the builder.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::imports::NativeImportsBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// NativeImportsBuilder::new()
///     .add_dll("kernel32.dll")?
///     .add_function("kernel32.dll", "GetCurrentProcessId")?
///     .add_function("kernel32.dll", "ExitProcess")?
///     .add_dll("user32.dll")?
///     .add_function_by_ordinal("user32.dll", 120)? // MessageBoxW
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct NativeImportsBuilder {
    /// DLLs to add to the import table
    dlls: Vec<String>,

    /// Named function imports to add (dll_name, function_name)
    functions: Vec<(String, String)>,

    /// Ordinal function imports to add (dll_name, ordinal)
    ordinal_functions: Vec<(String, u16)>,
}

impl NativeImportsBuilder {
    /// Creates a new native imports builder.
    ///
    /// # Returns
    ///
    /// A new [`NativeImportsBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dlls: Vec::new(),
            functions: Vec::new(),
            ordinal_functions: Vec::new(),
        }
    }

    /// Validates a DLL name for invalid characters or format issues.
    ///
    /// # Arguments
    /// * `name` - The DLL name to validate
    ///
    /// # Returns
    /// `Ok(())` if the name is valid, `Err` with a description if invalid.
    fn validate_dll_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(malformed_error!("DLL name cannot be empty"));
        }
        if name.contains('\0') {
            return Err(malformed_error!("DLL name contains null character"));
        }

        if name.contains('/') || name.contains('\\') {
            return Err(malformed_error!(
                "DLL name contains path separators - use filename only"
            ));
        }
        Ok(())
    }

    /// Validates a function name for invalid characters.
    ///
    /// # Arguments
    /// * `name` - The function name to validate
    ///
    /// # Returns
    /// `Ok(())` if the name is valid, `Err` with a description if invalid.
    fn validate_function_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(malformed_error!("Function name cannot be empty"));
        }
        if name.contains('\0') {
            return Err(malformed_error!("Function name contains null character"));
        }
        Ok(())
    }

    /// Adds a DLL to the import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// Multiple calls with the same DLL name will reuse the existing descriptor.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Returns
    ///
    /// `Ok(Self)` for method chaining on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty, contains null characters,
    /// or contains path separators.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::NativeImportsBuilder;
    /// let builder = NativeImportsBuilder::new()
    ///     .add_dll("kernel32.dll")?
    ///     .add_dll("user32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_dll(mut self, dll_name: impl Into<String>) -> Result<Self> {
        let dll_name = dll_name.into();
        Self::validate_dll_name(&dll_name)?;

        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name);
        }
        Ok(self)
    }

    /// Adds a named function import from a specific DLL.
    ///
    /// Adds a named function import to the specified DLL's import descriptor.
    /// The DLL will be automatically added if it hasn't been added already.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Returns
    ///
    /// `Ok(Self)` for method chaining on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name or function name is empty or contains
    /// invalid characters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::NativeImportsBuilder;
    /// let builder = NativeImportsBuilder::new()
    ///     .add_function("kernel32.dll", "GetCurrentProcessId")?
    ///     .add_function("kernel32.dll", "ExitProcess")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_function(
        mut self,
        dll_name: impl Into<String>,
        function_name: impl Into<String>,
    ) -> Result<Self> {
        let dll_name = dll_name.into();
        let function_name = function_name.into();

        Self::validate_dll_name(&dll_name)?;
        Self::validate_function_name(&function_name)?;

        // Ensure DLL is added
        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name.clone());
        }

        self.functions.push((dll_name, function_name));
        Ok(self)
    }

    /// Adds an ordinal-based function import.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient but is less portable across DLL versions.
    /// The DLL will be automatically added if it hasn't been added already.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table (must be non-zero)
    ///
    /// # Returns
    ///
    /// `Ok(Self)` for method chaining on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name is empty or contains invalid characters
    /// - The ordinal is 0 (invalid)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::NativeImportsBuilder;
    /// let builder = NativeImportsBuilder::new()
    ///     .add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_function_by_ordinal(
        mut self,
        dll_name: impl Into<String>,
        ordinal: u16,
    ) -> Result<Self> {
        let dll_name = dll_name.into();

        Self::validate_dll_name(&dll_name)?;

        if ordinal == 0 {
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        // Ensure DLL is added
        if !self.dlls.contains(&dll_name) {
            self.dlls.push(dll_name.clone());
        }

        self.ordinal_functions.push((dll_name, ordinal));
        Ok(self)
    }

    /// Builds the native imports and integrates them into the assembly.
    ///
    /// This method validates the configuration and integrates all specified DLLs and
    /// functions into the assembly through the CilAssembly. The builder automatically
    /// handles DLL dependency management and function import setup.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly for modification
    ///
    /// # Returns
    ///
    /// `Ok(())` if the import table was created successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - DLL names are invalid or empty
    /// - Function names are invalid or empty
    /// - Ordinal values are invalid (0)
    /// - Duplicate functions are specified
    /// - Integration with the assembly fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::imports::NativeImportsBuilder;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// NativeImportsBuilder::new()
    ///     .add_dll("kernel32.dll")?
    ///     .add_function("kernel32.dll", "GetCurrentProcessId")?
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<()> {
        for dll_name in &self.dlls {
            assembly.add_native_import_dll(dll_name)?;
        }

        for (dll_name, function_name) in &self.functions {
            assembly.add_native_import_function(dll_name, function_name)?;
        }

        for (dll_name, ordinal) in &self.ordinal_functions {
            assembly.add_native_import_function_by_ordinal(dll_name, *ordinal)?;
        }

        Ok(())
    }
}

impl Default for NativeImportsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{cilassembly::CilAssembly, testkit::fixture};

    #[test]
    fn test_native_imports_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .and_then(|b| b.add_function("kernel32.dll", "GetCurrentProcessId"))
            .and_then(|b| b.add_function("kernel32.dll", "ExitProcess"))
            .and_then(|b| b.build(&mut assembly));

        assert!(result.is_ok());
    }

    #[test]
    fn test_native_imports_builder_with_ordinals() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeImportsBuilder::new()
            .add_dll("user32.dll")
            .and_then(|b| b.add_function_by_ordinal("user32.dll", 120))
            .and_then(|b| b.add_function("user32.dll", "GetWindowTextW"))
            .and_then(|b| b.build(&mut assembly));

        assert!(result.is_ok());
    }

    #[test]
    fn test_native_imports_builder_auto_dll_addition() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeImportsBuilder::new()
            .add_function("kernel32.dll", "GetCurrentProcessId")
            .and_then(|b| b.add_function_by_ordinal("user32.dll", 120))
            .and_then(|b| b.build(&mut assembly));

        assert!(result.is_ok());
    }

    #[test]
    fn test_native_imports_builder_empty() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeImportsBuilder::new().build(&mut assembly);

        assert!(result.is_ok());
    }

    #[test]
    fn test_native_imports_builder_duplicate_dlls() {
        let builder = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .and_then(|b| b.add_dll("kernel32.dll"))
            .and_then(|b| b.add_dll("user32.dll"))
            .expect("Should not fail for valid DLL names");

        assert_eq!(builder.dlls.len(), 2);
        assert!(builder.dlls.contains(&"kernel32.dll".to_string()));
        assert!(builder.dlls.contains(&"user32.dll".to_string()));
    }

    #[test]
    fn test_native_imports_builder_fluent_api() {
        let builder = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .and_then(|b| b.add_function("kernel32.dll", "GetCurrentProcessId"))
            .and_then(|b| b.add_function("kernel32.dll", "ExitProcess"))
            .and_then(|b| b.add_dll("user32.dll"))
            .and_then(|b| b.add_function_by_ordinal("user32.dll", 120))
            .expect("Should not fail for valid inputs");

        assert_eq!(builder.dlls.len(), 2);
        assert_eq!(builder.functions.len(), 2);
        assert_eq!(builder.ordinal_functions.len(), 1);

        assert!(builder.dlls.contains(&"kernel32.dll".to_string()));
        assert!(builder.dlls.contains(&"user32.dll".to_string()));

        assert!(builder.functions.contains(&(
            "kernel32.dll".to_string(),
            "GetCurrentProcessId".to_string()
        )));
        assert!(builder
            .functions
            .contains(&("kernel32.dll".to_string(), "ExitProcess".to_string())));

        assert!(builder
            .ordinal_functions
            .contains(&("user32.dll".to_string(), 120)));
    }

    #[test]
    fn test_native_imports_builder_validation_empty_dll() {
        let result = NativeImportsBuilder::new().add_dll("");
        assert!(result.is_err());
    }

    #[test]
    fn test_native_imports_builder_validation_empty_function() {
        let result = NativeImportsBuilder::new()
            .add_dll("kernel32.dll")
            .and_then(|b| b.add_function("kernel32.dll", ""));
        assert!(result.is_err());
    }

    #[test]
    fn test_native_imports_builder_validation_ordinal_zero() {
        let result = NativeImportsBuilder::new()
            .add_dll("user32.dll")
            .and_then(|b| b.add_function_by_ordinal("user32.dll", 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_native_imports_builder_validation_dll_with_path() {
        let result = NativeImportsBuilder::new().add_dll("C:\\Windows\\kernel32.dll");
        assert!(result.is_err());
    }
}

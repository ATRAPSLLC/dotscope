//! Builder for native PE exports that integrates with the dotscope builder pattern.
//!
//! This module provides [`NativeExportsBuilder`] for creating native PE export tables
//! with a fluent API. The builder follows the established dotscope pattern of not holding
//! references to CilAssembly and instead taking it as a parameter to the build() method.

use crate::{cilassembly::CilAssembly, Result};

/// Builder for creating native PE export tables.
///
/// `NativeExportsBuilder` provides a fluent API for creating native PE export tables
/// with validation and automatic integration into the assembly. The builder follows
/// the established dotscope pattern where the assembly is passed to build() rather
/// than being held by the builder.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::exports::NativeExportsBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// NativeExportsBuilder::new("MyLibrary.dll")
///     .add_function("MyFunction", 1, 0x1000)
///     .add_function("AnotherFunction", 2, 0x2000)
///     .add_function_by_ordinal(3, 0x3000)
///     .add_forwarder("ForwardedFunc", 4, "kernel32.dll.GetCurrentProcessId")
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct NativeExportsBuilder {
    /// DLL name for the export table
    dll_name: String,

    /// Named function exports to add (name, ordinal, address)
    functions: Vec<(String, u16, u32)>,

    /// Ordinal-only function exports to add (ordinal, address)
    ordinal_functions: Vec<(u16, u32)>,

    /// Export forwarders to add (name, ordinal, target)
    forwarders: Vec<(String, u16, String)>,

    /// Next ordinal to assign automatically
    next_ordinal: u16,
}

impl NativeExportsBuilder {
    /// Creates a new native exports builder with the specified DLL name.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL for the export table (e.g., "MyLibrary.dll")
    ///
    /// # Returns
    ///
    /// A new [`NativeExportsBuilder`] ready for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll");
    /// ```
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            functions: Vec::new(),
            ordinal_functions: Vec::new(),
            forwarders: Vec::new(),
            next_ordinal: 1,
        }
    }

    /// Adds a named function export with explicit ordinal and address.
    ///
    /// Adds a named function export to the export table with the specified
    /// ordinal and function address. The function will be accessible by both
    /// name and ordinal.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the exported function
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address (RVA)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_function("MyFunction", 1, 0x1000)
    ///     .add_function("AnotherFunc", 2, 0x2000);
    /// ```
    #[must_use]
    pub fn add_function(mut self, name: impl Into<String>, ordinal: u16, address: u32) -> Self {
        self.functions.push((name.into(), ordinal, address));
        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal.saturating_add(1);
        }
        self
    }

    /// Adds a named function export with automatic ordinal assignment.
    ///
    /// Adds a named function export to the export table with an automatically
    /// assigned ordinal number. The next available ordinal will be used.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the exported function
    /// * `address` - Function address (RVA)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_function_auto("MyFunction", 0x1000)
    ///     .add_function_auto("AnotherFunc", 0x2000);
    /// ```
    #[must_use]
    pub fn add_function_auto(mut self, name: impl Into<String>, address: u32) -> Self {
        let ordinal = self.next_ordinal;
        self.functions.push((name.into(), ordinal, address));
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        self
    }

    /// Adds a function export by ordinal only.
    ///
    /// Adds a function export that is accessible by ordinal number only,
    /// without a symbolic name. This can be more efficient but is less
    /// portable across DLL versions.
    ///
    /// # Arguments
    ///
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address (RVA)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_function_by_ordinal(100, 0x1000)
    ///     .add_function_by_ordinal(101, 0x2000);
    /// ```
    #[must_use]
    pub fn add_function_by_ordinal(mut self, ordinal: u16, address: u32) -> Self {
        self.ordinal_functions.push((ordinal, address));
        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal.saturating_add(1);
        }
        self
    }

    /// Adds a function export by ordinal with automatic ordinal assignment.
    ///
    /// Adds a function export that is accessible by ordinal number only,
    /// using an automatically assigned ordinal.
    ///
    /// # Arguments
    ///
    /// * `address` - Function address (RVA)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_function_by_ordinal_auto(0x1000)
    ///     .add_function_by_ordinal_auto(0x2000);
    /// ```
    #[must_use]
    pub fn add_function_by_ordinal_auto(mut self, address: u32) -> Self {
        let ordinal = self.next_ordinal;
        self.ordinal_functions.push((ordinal, address));
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        self
    }

    /// Adds an export forwarder with explicit ordinal.
    ///
    /// Adds a function export that forwards calls to a function in another DLL.
    /// The target specification can be either "DllName.FunctionName" or
    /// "DllName.#Ordinal" for ordinal-based forwarding.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the exported function (can be empty for ordinal-only)
    /// * `ordinal` - Ordinal number for the export
    /// * `target` - Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_forwarder("GetProcessId", 1, "kernel32.dll.GetCurrentProcessId")
    ///     .add_forwarder("MessageBox", 2, "user32.dll.#120");
    /// ```
    #[must_use]
    pub fn add_forwarder(
        mut self,
        name: impl Into<String>,
        ordinal: u16,
        target: impl Into<String>,
    ) -> Self {
        self.forwarders.push((name.into(), ordinal, target.into()));
        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal.saturating_add(1);
        }
        self
    }

    /// Adds an export forwarder with automatic ordinal assignment.
    ///
    /// Adds a function export that forwards calls to a function in another DLL,
    /// using an automatically assigned ordinal number.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the exported function
    /// * `target` - Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_forwarder_auto("GetProcessId", "kernel32.dll.GetCurrentProcessId")
    ///     .add_forwarder_auto("MessageBox", "user32.dll.MessageBoxW");
    /// ```
    #[must_use]
    pub fn add_forwarder_auto(
        mut self,
        name: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        let ordinal = self.next_ordinal;
        self.forwarders.push((name.into(), ordinal, target.into()));
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        self
    }

    /// Sets the DLL name for the export table.
    ///
    /// Updates the DLL name that will appear in the PE export directory.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - New DLL name to use
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// let builder = NativeExportsBuilder::new("temp.dll")
    ///     .dll_name("MyLibrary.dll");
    /// ```
    #[must_use]
    pub fn dll_name(mut self, dll_name: impl Into<String>) -> Self {
        self.dll_name = dll_name.into();
        self
    }

    /// Builds the native exports and integrates them into the assembly.
    ///
    /// This method validates the configuration and integrates all specified functions
    /// and forwarders into the assembly through the CilAssembly. The builder
    /// automatically handles ordinal management and export table setup.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly for modification
    ///
    /// # Returns
    ///
    /// `Ok(())` if the export table was created successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name is empty or holds a null byte
    /// - Function names are invalid or empty
    /// - Ordinal values are invalid (0)
    /// - Duplicate ordinals are specified
    /// - Forwarder targets are invalid
    /// - Integration with the assembly fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::exports::NativeExportsBuilder;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// NativeExportsBuilder::new("MyLibrary.dll")
    ///     .add_function("MyFunction", 1, 0x1000)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<()> {
        assembly.set_native_export_dll_name(&self.dll_name)?;

        // Add all named functions
        for (name, ordinal, address) in &self.functions {
            assembly.add_native_export_function(name, *ordinal, *address)?;
        }

        // Add all ordinal-only functions
        for (ordinal, address) in &self.ordinal_functions {
            assembly.add_native_export_function_by_ordinal(*ordinal, *address)?;
        }

        // Add all forwarders
        for (name, ordinal, target) in &self.forwarders {
            assembly.add_native_export_forwarder(name, *ordinal, target)?;
        }

        Ok(())
    }
}

impl Default for NativeExportsBuilder {
    fn default() -> Self {
        Self::new("Unknown.dll")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{cilassembly::CilAssembly, testkit::fixture};

    #[test]
    fn test_native_exports_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("MyFunction", 1, 0x1000)
            .add_function("AnotherFunction", 2, 0x2000)
            .build(&mut assembly);

        // Should succeed with current placeholder implementation
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_exports_builder_with_ordinals() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function_by_ordinal(100, 0x1000)
            .add_function("NamedFunction", 101, 0x2000)
            .build(&mut assembly);

        // Should succeed with current placeholder implementation
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_exports_builder_with_forwarders() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("RegularFunction", 1, 0x1000)
            .add_forwarder("ForwardedFunc", 2, "kernel32.dll.GetCurrentProcessId")
            .add_forwarder("OrdinalForward", 3, "user32.dll.#120")
            .build(&mut assembly);

        // Should succeed with current placeholder implementation
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_exports_builder_auto_ordinals() {
        let builder = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function_auto("Function1", 0x1000)
            .add_function_auto("Function2", 0x2000)
            .add_function_by_ordinal_auto(0x3000)
            .add_forwarder_auto("Forwarder1", "kernel32.dll.GetTick");

        // Verify auto ordinal assignment
        assert_eq!(builder.functions.len(), 2);
        assert_eq!(builder.ordinal_functions.len(), 1);
        assert_eq!(builder.forwarders.len(), 1);

        // Check that ordinals were assigned automatically
        assert_eq!(builder.functions[0].1, 1); // First function gets ordinal 1
        assert_eq!(builder.functions[1].1, 2); // Second function gets ordinal 2
        assert_eq!(builder.ordinal_functions[0].0, 3); // Ordinal function gets ordinal 3
        assert_eq!(builder.forwarders[0].1, 4); // Forwarder gets ordinal 4

        // Next ordinal should be 5
        assert_eq!(builder.next_ordinal, 5);
    }

    #[test]
    fn test_native_exports_builder_mixed_ordinals() {
        let builder = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("Function1", 10, 0x1000) // Explicit ordinal 10
            .add_function_auto("Function2", 0x2000) // Should get ordinal 11
            .add_function("Function3", 5, 0x3000) // Explicit ordinal 5 (lower than current)
            .add_function_auto("Function4", 0x4000); // Should get ordinal 12

        // Verify ordinal tracking
        assert_eq!(builder.functions[0].1, 10); // Explicit
        assert_eq!(builder.functions[1].1, 11); // Auto after 10
        assert_eq!(builder.functions[2].1, 5); // Explicit (lower)
        assert_eq!(builder.functions[3].1, 12); // Auto after 11

        // Next ordinal should be 13
        assert_eq!(builder.next_ordinal, 13);
    }

    #[test]
    fn test_native_exports_builder_dll_name_change() {
        let builder = NativeExportsBuilder::new("Original.dll")
            .dll_name("Changed.dll")
            .add_function("MyFunction", 1, 0x1000);

        assert_eq!(builder.dll_name, "Changed.dll");
    }

    #[test]
    fn test_native_exports_builder_empty() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let result = NativeExportsBuilder::new("EmptyLibrary.dll").build(&mut assembly);

        // Should succeed even with no exports
        assert!(result.is_ok());
    }

    #[test]
    fn test_native_exports_builder_fluent_api() {
        let builder = NativeExportsBuilder::new("TestLibrary.dll")
            .add_function("Function1", 1, 0x1000)
            .add_function_auto("Function2", 0x2000)
            .add_function_by_ordinal(10, 0x3000)
            .add_function_by_ordinal_auto(0x4000)
            .add_forwarder("Forwarder1", 20, "kernel32.dll.GetCurrentProcessId")
            .add_forwarder_auto("Forwarder2", "user32.dll.MessageBoxW")
            .dll_name("FinalName.dll");

        // Verify builder state
        assert_eq!(builder.dll_name, "FinalName.dll");
        assert_eq!(builder.functions.len(), 2);
        assert_eq!(builder.ordinal_functions.len(), 2);
        assert_eq!(builder.forwarders.len(), 2);

        // Verify specific entries
        assert!(builder
            .functions
            .iter()
            .any(|(name, ord, _)| name == "Function1" && *ord == 1));
        assert!(builder
            .functions
            .iter()
            .any(|(name, ord, _)| name == "Function2" && *ord == 2));
        assert!(builder.ordinal_functions.iter().any(|(ord, _)| *ord == 10));
        assert!(builder
            .forwarders
            .iter()
            .any(|(name, ord, target)| name == "Forwarder1"
                && *ord == 20
                && target == "kernel32.dll.GetCurrentProcessId"));

        // Should have set next_ordinal to be after the highest used ordinal
        assert!(builder.next_ordinal > 20);
    }
}

//! Builder for constructing `AssemblyProcessor` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyprocessor::builder::AssemblyProcessorBuilder`] which enables fluent construction
//! of `AssemblyProcessor` metadata table entries. The builder follows the established
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
//! let processor_token = AssemblyProcessorBuilder::new()
//!     .processor(0x014C)             // x86 processor architecture
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{AssemblyProcessorRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyProcessor` table entries
///
/// Provides a fluent interface for building `AssemblyProcessor` metadata table entries.
/// These entries specify processor architecture targeting information for assemblies,
/// though they are rarely used in modern .NET applications which typically use AnyCPU.
///
/// # Required Fields
/// - `processor`: Processor architecture identifier (must be provided)
///
/// # Historical Context
///
/// The AssemblyProcessor table was designed for early .NET Framework scenarios where
/// assemblies might need explicit CPU architecture declarations. Modern applications
/// typically use AnyCPU compilation and rely on runtime JIT optimization.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // x86 processor targeting
/// let x86_proc = AssemblyProcessorBuilder::new()
///     .processor(0x014C)  // x86 architecture
///     .build(&mut assembly)?;
///
/// // x64 processor targeting
/// let x64_proc = AssemblyProcessorBuilder::new()
///     .processor(0x8664)  // x64 architecture
///     .build(&mut assembly)?;
///
/// // Custom processor identifier
/// let custom_proc = AssemblyProcessorBuilder::new()
///     .processor(0x1234)  // Custom architecture identifier
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyProcessorBuilder {
    /// Processor architecture identifier
    processor: Option<u32>,
}

impl AssemblyProcessorBuilder {
    /// Creates a new `AssemblyProcessorBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the processor field before calling build().
    ///
    /// # Returns
    /// A new `AssemblyProcessorBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyProcessorBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { processor: None }
    }

    /// Sets the processor architecture identifier
    ///
    /// Specifies the target CPU architecture for this assembly. While ECMA-335
    /// doesn't standardize exact values, common historical identifiers include
    /// x86, x64, and IA64 architectures.
    ///
    /// # Parameters
    /// - `processor`: The processor architecture identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `0x014C`: x86 (32-bit Intel)
    /// - `0x8664`: x64 (64-bit AMD/Intel)
    /// - `0x0200`: IA64 (Intel Itanium, deprecated)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // x86 targeting
    /// let builder = AssemblyProcessorBuilder::new()
    ///     .processor(0x014C);
    ///
    /// // x64 targeting
    /// let builder = AssemblyProcessorBuilder::new()
    ///     .processor(0x8664);
    /// ```
    #[must_use]
    pub fn processor(mut self, processor: u32) -> Self {
        self.processor = Some(processor);
        self
    }

    /// Builds and adds the `AssemblyProcessor` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyProcessor` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this assembly processor entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly processor
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (processor)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = AssemblyProcessorBuilder::new()
    ///     .processor(0x014C)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let processor = self.processor.ok_or_else(|| {
            Error::ModificationInvalid(
                "Processor architecture identifier is required for AssemblyProcessor".to_string(),
            )
        })?;

        let assembly_processor = AssemblyProcessorRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            processor,
        };

        assembly.table_row_add(
            TableId::AssemblyProcessor,
            TableDataOwned::AssemblyProcessor(assembly_processor),
        )
    }
}

impl Default for AssemblyProcessorBuilder {
    /// Creates a default `AssemblyProcessorBuilder`
    ///
    /// Equivalent to calling [`AssemblyProcessorBuilder::new()`].
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
    fn test_assemblyprocessor_builder_new() {
        let builder = AssemblyProcessorBuilder::new();

        assert!(builder.processor.is_none());
    }

    #[test]
    fn test_assemblyprocessor_builder_default() {
        let builder = AssemblyProcessorBuilder::default();

        assert!(builder.processor.is_none());
    }

    #[test]
    fn test_assemblyprocessor_builder_x86() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0x014C) // x86
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_x64() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0x8664) // x64
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_ia64() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0x0200) // IA64
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_custom() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0x1234) // Custom processor ID
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_missing_processor() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyProcessorBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Processor architecture identifier is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_clone() {
        let builder = AssemblyProcessorBuilder::new().processor(0x014C);

        let cloned = builder.clone();
        assert_eq!(builder.processor, cloned.processor);
    }

    #[test]
    fn test_assemblyprocessor_builder_debug() {
        let builder = AssemblyProcessorBuilder::new().processor(0x8664);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyProcessorBuilder"));
        assert!(debug_str.contains("processor"));
    }

    #[test]
    fn test_assemblyprocessor_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0x9999)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first processor
        let ref1 = AssemblyProcessorBuilder::new()
            .processor(0x014C) // x86
            .build(&mut assembly)
            .expect("Should build first processor");

        // Build second processor
        let ref2 = AssemblyProcessorBuilder::new()
            .processor(0x8664) // x64
            .build(&mut assembly)
            .expect("Should build second processor");

        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(
            ref1.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        assert_eq!(
            ref2.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_zero_processor() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(0) // Zero processor ID
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_max_processor() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyProcessorBuilder::new()
            .processor(u32::MAX) // Maximum processor ID
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::AssemblyProcessor)
        );
        Ok(())
    }
}

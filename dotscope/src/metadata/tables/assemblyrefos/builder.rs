//! Builder for constructing `AssemblyRefOS` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyrefos::AssemblyRefOSBuilder`] which enables fluent construction
//! of `AssemblyRefOS` metadata table entries. The builder follows the established
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
//! let os_token = AssemblyRefOSBuilder::new()
//!     .os_platform_id(1)             // Windows platform
//!     .os_major_version(10)          // Windows 10
//!     .os_minor_version(0)           // Windows 10.0
//!     .assembly_ref(1)               // AssemblyRef RID
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{AssemblyRefOsRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyRefOS` table entries
///
/// Provides a fluent interface for building `AssemblyRefOS` metadata table entries.
/// These entries specify operating system compatibility requirements for external
/// assembly references, though they are rarely used in modern .NET applications.
///
/// # Required Fields
/// - `os_platform_id`: Operating system platform identifier
/// - `os_major_version`: Major version number of the target OS
/// - `os_minor_version`: Minor version number of the target OS
/// - `assembly_ref`: AssemblyRef table RID
///
/// # Historical Context
///
/// The AssemblyRefOS table was designed for early .NET Framework scenarios where
/// assemblies might need to declare explicit OS version dependencies for external
/// references. Modern applications typically rely on runtime platform detection.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Windows 10 requirement for external assembly
/// let win10_ref = AssemblyRefOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(10)  // Windows 10
///     .os_minor_version(0)   // Windows 10.0
///     .assembly_ref(1)       // References first AssemblyRef
///     .build(&mut assembly)?;
///
/// // Windows 7 requirement
/// let win7_ref = AssemblyRefOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(6)   // Windows 7
///     .os_minor_version(1)   // Windows 7.1
///     .assembly_ref(2)       // References second AssemblyRef
///     .build(&mut assembly)?;
///
/// // Custom OS requirement
/// let custom_ref = AssemblyRefOSBuilder::new()
///     .os_platform_id(99)    // Custom platform
///     .os_major_version(2)    // Custom major
///     .os_minor_version(5)    // Custom minor
///     .assembly_ref(3)        // References third AssemblyRef
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyRefOSBuilder {
    /// Operating system platform identifier
    os_platform_id: Option<u32>,
    /// Major version number of the target OS
    os_major_version: Option<u32>,
    /// Minor version number of the target OS
    os_minor_version: Option<u32>,
    /// AssemblyRef table RID
    assembly_ref: Option<u32>,
}

impl AssemblyRefOSBuilder {
    /// Creates a new `AssemblyRefOSBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide all required fields before calling build().
    ///
    /// # Returns
    /// A new `AssemblyRefOSBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyRefOSBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            os_platform_id: None,
            os_major_version: None,
            os_minor_version: None,
            assembly_ref: None,
        }
    }

    /// Sets the operating system platform identifier
    ///
    /// Specifies the target operating system platform for the referenced
    /// external assembly. Common values include Windows 32-bit, Windows 64-bit,
    /// and other platform designations.
    ///
    /// # Parameters
    /// - `os_platform_id`: The operating system platform identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `1`: Windows 32-bit platforms
    /// - `2`: Windows 64-bit platforms
    /// - Custom values for other platforms
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Windows platform
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_platform_id(1);
    ///
    /// // Custom platform
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_platform_id(99);
    /// ```
    #[must_use]
    pub fn os_platform_id(mut self, os_platform_id: u32) -> Self {
        self.os_platform_id = Some(os_platform_id);
        self
    }

    /// Sets the major version number of the target OS
    ///
    /// Specifies the major version of the target operating system required
    /// for the referenced external assembly.
    ///
    /// # Parameters
    /// - `os_major_version`: The major version number
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Windows 10 (major version 10)
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_major_version(10);
    ///
    /// // Windows 7 (major version 6)
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_major_version(6);
    /// ```
    #[must_use]
    pub fn os_major_version(mut self, os_major_version: u32) -> Self {
        self.os_major_version = Some(os_major_version);
        self
    }

    /// Sets the minor version number of the target OS
    ///
    /// Specifies the minor version of the target operating system required
    /// for the referenced external assembly.
    ///
    /// # Parameters
    /// - `os_minor_version`: The minor version number
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Windows 10.0 (minor version 0)
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_minor_version(0);
    ///
    /// // Windows 7.1 (minor version 1)
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .os_minor_version(1);
    /// ```
    #[must_use]
    pub fn os_minor_version(mut self, os_minor_version: u32) -> Self {
        self.os_minor_version = Some(os_minor_version);
        self
    }

    /// Sets the AssemblyRef table RID
    ///
    /// Specifies the AssemblyRef table row ID that these OS requirements
    /// apply to. This must reference a valid AssemblyRef entry.
    ///
    /// # Parameters
    /// - `assembly_ref`: The AssemblyRef table RID
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyRefOSBuilder::new()
    ///     .assembly_ref(1);  // References first AssemblyRef
    /// ```
    #[must_use]
    pub fn assembly_ref(mut self, assembly_ref: u32) -> Self {
        self.assembly_ref = Some(assembly_ref);
        self
    }

    /// Builds and adds the `AssemblyRefOS` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyRefOS` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this assembly ref OS entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly ref OS entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (os_platform_id, os_major_version, os_minor_version, or assembly_ref)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = AssemblyRefOSBuilder::new()
    ///     .os_platform_id(1)
    ///     .os_major_version(10)
    ///     .os_minor_version(0)
    ///     .assembly_ref(1)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let os_platform_id = self.os_platform_id.ok_or_else(|| {
            Error::ModificationInvalid(
                "OS platform identifier is required for AssemblyRefOS".to_string(),
            )
        })?;

        let os_major_version = self.os_major_version.ok_or_else(|| {
            Error::ModificationInvalid("OS major version is required for AssemblyRefOS".to_string())
        })?;

        let os_minor_version = self.os_minor_version.ok_or_else(|| {
            Error::ModificationInvalid("OS minor version is required for AssemblyRefOS".to_string())
        })?;

        let assembly_ref = self.assembly_ref.ok_or_else(|| {
            Error::ModificationInvalid("AssemblyRef RID is required for AssemblyRefOS".to_string())
        })?;

        let assembly_ref_os = AssemblyRefOsRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            os_platform_id,
            os_major_version,
            os_minor_version,
            assembly_ref,
        };

        assembly.table_row_add(
            TableId::AssemblyRefOS,
            TableDataOwned::AssemblyRefOS(assembly_ref_os),
        )
    }
}

impl Default for AssemblyRefOSBuilder {
    /// Creates a default `AssemblyRefOSBuilder`
    ///
    /// Equivalent to calling [`AssemblyRefOSBuilder::new()`].
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
    fn test_assemblyrefos_builder_new() {
        let builder = AssemblyRefOSBuilder::new();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
        assert!(builder.assembly_ref.is_none());
    }

    #[test]
    fn test_assemblyrefos_builder_default() {
        let builder = AssemblyRefOSBuilder::default();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
        assert!(builder.assembly_ref.is_none());
    }

    #[test]
    fn test_assemblyrefos_builder_windows10() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10) // Windows 10
            .os_minor_version(0) // Windows 10.0
            .assembly_ref(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_windows7() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(6) // Windows 7
            .os_minor_version(1) // Windows 7.1
            .assembly_ref(2)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_custom_os() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(99) // Custom platform
            .os_major_version(2) // Custom major
            .os_minor_version(5) // Custom minor
            .assembly_ref(3)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_missing_platform_id() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyRefOSBuilder::new()
            .os_major_version(10)
            .os_minor_version(0)
            .assembly_ref(1)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("OS platform identifier is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_missing_major_version() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyRefOSBuilder::new()
            .os_platform_id(1)
            .os_minor_version(0)
            .assembly_ref(1)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("OS major version is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_missing_minor_version() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyRefOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .assembly_ref(1)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("OS minor version is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_missing_assembly_ref() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyRefOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .os_minor_version(0)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("AssemblyRef RID is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_clone() {
        let builder = AssemblyRefOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .os_minor_version(0)
            .assembly_ref(1);

        let cloned = builder.clone();
        assert_eq!(builder.os_platform_id, cloned.os_platform_id);
        assert_eq!(builder.os_major_version, cloned.os_major_version);
        assert_eq!(builder.os_minor_version, cloned.os_minor_version);
        assert_eq!(builder.assembly_ref, cloned.assembly_ref);
    }

    #[test]
    fn test_assemblyrefos_builder_debug() {
        let builder = AssemblyRefOSBuilder::new()
            .os_platform_id(2)
            .os_major_version(5)
            .os_minor_version(4)
            .assembly_ref(2);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyRefOSBuilder"));
        assert!(debug_str.contains("os_platform_id"));
        assert!(debug_str.contains("os_major_version"));
        assert!(debug_str.contains("os_minor_version"));
        assert!(debug_str.contains("assembly_ref"));
    }

    #[test]
    fn test_assemblyrefos_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(2)
            .os_major_version(12)
            .os_minor_version(5)
            .assembly_ref(4)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first OS entry
        let ref1 = AssemblyRefOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10)
            .os_minor_version(0)
            .assembly_ref(1)
            .build(&mut assembly)
            .expect("Should build first OS entry");

        // Build second OS entry
        let ref2 = AssemblyRefOSBuilder::new()
            .os_platform_id(2) // Custom platform
            .os_major_version(5)
            .os_minor_version(4)
            .assembly_ref(2)
            .build(&mut assembly)
            .expect("Should build second OS entry");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_zero_values() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(0) // Zero platform
            .os_major_version(0) // Zero major
            .os_minor_version(0) // Zero minor
            .assembly_ref(1)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }

    #[test]
    fn test_assemblyrefos_builder_large_assembly_ref() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyRefOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .os_minor_version(0)
            .assembly_ref(0xFFFF) // Large AssemblyRef RID
            .build(&mut assembly)
            .expect("Should handle large assembly ref RID");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRefOS));
        Ok(())
    }
}

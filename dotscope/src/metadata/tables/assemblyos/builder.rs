//! Builder for constructing `AssemblyOS` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyos::builder::AssemblyOSBuilder`] which enables fluent construction
//! of `AssemblyOS` metadata table entries. The builder follows the established
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
//! let os_token = AssemblyOSBuilder::new()
//!     .os_platform_id(1)             // Windows platform
//!     .os_major_version(10)          // Windows 10
//!     .os_minor_version(0)           // Windows 10.0
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{AssemblyOsRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyOS` table entries
///
/// Provides a fluent interface for building `AssemblyOS` metadata table entries.
/// These entries specify operating system targeting information for assemblies,
/// though they are rarely used in modern .NET applications which rely on runtime
/// platform abstraction.
///
/// # Required Fields
/// - `os_platform_id`: Operating system platform identifier
/// - `os_major_version`: Major version number of the target OS
/// - `os_minor_version`: Minor version number of the target OS
///
/// # Historical Context
///
/// The AssemblyOS table was designed for early .NET Framework scenarios where
/// assemblies might need explicit OS compatibility declarations. Modern applications
/// typically rely on runtime platform abstraction instead of metadata-level OS targeting.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Windows 10 targeting
/// let win10_os = AssemblyOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(10)  // Windows 10
///     .os_minor_version(0)   // Windows 10.0
///     .build(&mut assembly)?;
///
/// // Windows 7 targeting
/// let win7_os = AssemblyOSBuilder::new()
///     .os_platform_id(1)    // Windows platform
///     .os_major_version(6)   // Windows 7
///     .os_minor_version(1)   // Windows 7.1
///     .build(&mut assembly)?;
///
/// // Custom OS targeting
/// let custom_os = AssemblyOSBuilder::new()
///     .os_platform_id(99)    // Custom platform
///     .os_major_version(1)    // Major version
///     .os_minor_version(0)    // Minor version
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct AssemblyOSBuilder {
    /// Operating system platform identifier
    os_platform_id: Option<u32>,
    /// Major version number of the target OS
    os_major_version: Option<u32>,
    /// Minor version number of the target OS
    os_minor_version: Option<u32>,
}

impl AssemblyOSBuilder {
    /// Creates a new `AssemblyOSBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide all required fields before calling build().
    ///
    /// # Returns
    /// A new `AssemblyOSBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyOSBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            os_platform_id: None,
            os_major_version: None,
            os_minor_version: None,
        }
    }

    /// Sets the operating system platform identifier
    ///
    /// Specifies the target operating system platform. While ECMA-335 doesn't
    /// standardize exact values, common historical identifiers include
    /// Windows, Unix, and other platform designations.
    ///
    /// # Parameters
    /// - `os_platform_id`: The operating system platform identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `1`: Windows platforms
    /// - `2`: Unix/Linux platforms  
    /// - `3`: macOS platforms
    /// - Custom values for proprietary platforms
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Windows platform
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_platform_id(1);
    ///
    /// // Unix/Linux platform
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_platform_id(2);
    /// ```
    #[must_use]
    pub fn os_platform_id(mut self, os_platform_id: u32) -> Self {
        self.os_platform_id = Some(os_platform_id);
        self
    }

    /// Sets the major version number of the target OS
    ///
    /// Specifies the major version of the target operating system.
    /// Combined with minor version to specify exact OS version requirements.
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
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_major_version(10);
    ///
    /// // Windows 7 (major version 6)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_major_version(6);
    /// ```
    #[must_use]
    pub fn os_major_version(mut self, os_major_version: u32) -> Self {
        self.os_major_version = Some(os_major_version);
        self
    }

    /// Sets the minor version number of the target OS
    ///
    /// Specifies the minor version of the target operating system.
    /// Combined with major version to specify exact OS version requirements.
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
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_minor_version(0);
    ///
    /// // Windows 7.1 (minor version 1)
    /// let builder = AssemblyOSBuilder::new()
    ///     .os_minor_version(1);
    /// ```
    #[must_use]
    pub fn os_minor_version(mut self, os_minor_version: u32) -> Self {
        self.os_minor_version = Some(os_minor_version);
        self
    }

    /// Builds and adds the `AssemblyOS` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyOS` table entry,
    /// and adds it to the assembly. Returns a token that can be used
    /// to reference this assembly OS entry.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly OS entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (os_platform_id, os_major_version, or os_minor_version)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let token = AssemblyOSBuilder::new()
    ///     .os_platform_id(1)
    ///     .os_major_version(10)
    ///     .os_minor_version(0)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let os_platform_id = self.os_platform_id.ok_or_else(|| {
            Error::ModificationInvalid(
                "OS platform identifier is required for AssemblyOS".to_string(),
            )
        })?;

        let os_major_version = self.os_major_version.ok_or_else(|| {
            Error::ModificationInvalid("OS major version is required for AssemblyOS".to_string())
        })?;

        let os_minor_version = self.os_minor_version.ok_or_else(|| {
            Error::ModificationInvalid("OS minor version is required for AssemblyOS".to_string())
        })?;

        let assembly_os = AssemblyOsRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            os_platform_id,
            os_major_version,
            os_minor_version,
        };

        assembly.table_row_add(TableId::AssemblyOS, TableDataOwned::AssemblyOS(assembly_os))
    }
}

impl Default for AssemblyOSBuilder {
    /// Creates a default `AssemblyOSBuilder`
    ///
    /// Equivalent to calling [`AssemblyOSBuilder::new()`].
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
    fn test_assemblyos_builder_new() {
        let builder = AssemblyOSBuilder::new();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
    }

    #[test]
    fn test_assemblyos_builder_default() {
        let builder = AssemblyOSBuilder::default();

        assert!(builder.os_platform_id.is_none());
        assert!(builder.os_major_version.is_none());
        assert!(builder.os_minor_version.is_none());
    }

    #[test]
    fn test_assemblyos_builder_windows10() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10) // Windows 10
            .os_minor_version(0) // Windows 10.0
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_windows7() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(6) // Windows 7
            .os_minor_version(1) // Windows 7.1
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_linux() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(2) // Unix/Linux
            .os_major_version(5) // Linux kernel 5
            .os_minor_version(4) // Linux kernel 5.4
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_custom() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(99) // Custom platform
            .os_major_version(1) // Custom major
            .os_minor_version(0) // Custom minor
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_missing_platform_id() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyOSBuilder::new()
            .os_major_version(10)
            .os_minor_version(0)
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
    fn test_assemblyos_builder_missing_major_version() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_minor_version(0)
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
    fn test_assemblyos_builder_missing_minor_version() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
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
    fn test_assemblyos_builder_clone() {
        let builder = AssemblyOSBuilder::new()
            .os_platform_id(1)
            .os_major_version(10)
            .os_minor_version(0);

        let cloned = builder.clone();
        assert_eq!(builder.os_platform_id, cloned.os_platform_id);
        assert_eq!(builder.os_major_version, cloned.os_major_version);
        assert_eq!(builder.os_minor_version, cloned.os_minor_version);
    }

    #[test]
    fn test_assemblyos_builder_debug() {
        let builder = AssemblyOSBuilder::new()
            .os_platform_id(2)
            .os_major_version(5)
            .os_minor_version(4);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyOSBuilder"));
        assert!(debug_str.contains("os_platform_id"));
        assert!(debug_str.contains("os_major_version"));
        assert!(debug_str.contains("os_minor_version"));
    }

    #[test]
    fn test_assemblyos_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test method chaining
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(3)
            .os_major_version(12)
            .os_minor_version(5)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Build first OS entry
        let ref1 = AssemblyOSBuilder::new()
            .os_platform_id(1) // Windows
            .os_major_version(10)
            .os_minor_version(0)
            .build(&mut assembly)
            .expect("Should build first OS entry");

        // Build second OS entry
        let ref2 = AssemblyOSBuilder::new()
            .os_platform_id(2) // Unix/Linux
            .os_major_version(5)
            .os_minor_version(4)
            .build(&mut assembly)
            .expect("Should build second OS entry");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_zero_values() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(0) // Zero platform
            .os_major_version(0) // Zero major
            .os_minor_version(0) // Zero minor
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }

    #[test]
    fn test_assemblyos_builder_max_values() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let ref_ = AssemblyOSBuilder::new()
            .os_platform_id(u32::MAX) // Max platform
            .os_major_version(u32::MAX) // Max major
            .os_minor_version(u32::MAX) // Max minor
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyOS));
        Ok(())
    }
}

//! AssemblyBuilder for creating assembly metadata.
//!
//! This module provides [`crate::metadata::tables::assembly::AssemblyBuilder`] for creating Assembly table entries
//! with a fluent API. The Assembly table contains the identity information for
//! the current assembly, including version numbers, flags, and references to
//! the assembly name and public key data.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{AssemblyRaw, TableDataOwned, TableId},
        token::Token,
    },
    Result,
};

/// Builder for creating Assembly metadata entries.
///
/// `AssemblyBuilder` provides a fluent API for creating Assembly table entries
/// with validation and automatic heap management. Since there can be at most
/// one Assembly entry per assembly, this builder ensures proper constraints.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::AssemblyBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// let assembly_token = AssemblyBuilder::new()
///     .name("MyAssembly")
///     .version(1, 2, 3, 4)
///     .culture("neutral")
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct AssemblyBuilder {
    hash_alg_id: Option<u32>,
    major_version: Option<u32>,
    minor_version: Option<u32>,
    build_number: Option<u32>,
    revision_number: Option<u32>,
    flags: Option<u32>,
    name: Option<String>,
    culture: Option<String>,
    public_key: Option<Vec<u8>>,
}

impl AssemblyBuilder {
    /// Creates a new AssemblyBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::assembly::AssemblyBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hash_alg_id: None,
            major_version: None,
            minor_version: None,
            build_number: None,
            revision_number: None,
            flags: None,
            name: None,
            culture: None,
            public_key: None,
        }
    }

    /// Sets the assembly name.
    ///
    /// # Arguments
    ///
    /// * `name` - The simple name of the assembly
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the assembly version as individual components.
    ///
    /// # Arguments
    ///
    /// * `major` - Major version number
    /// * `minor` - Minor version number  
    /// * `build` - Build number
    /// * `revision` - Revision number
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn version(mut self, major: u16, minor: u16, build: u16, revision: u16) -> Self {
        self.major_version = Some(u32::from(major));
        self.minor_version = Some(u32::from(minor));
        self.build_number = Some(u32::from(build));
        self.revision_number = Some(u32::from(revision));
        self
    }

    /// Sets the assembly culture.
    ///
    /// # Arguments
    ///
    /// * `culture` - The culture name for localized assemblies, or "neutral" for culture-neutral
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn culture(mut self, culture: impl Into<String>) -> Self {
        self.culture = Some(culture.into());
        self
    }

    /// Sets the assembly flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Assembly flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the hash algorithm ID.
    ///
    /// # Arguments
    ///
    /// * `hash_alg_id` - Hash algorithm identifier
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn hash_algorithm(mut self, hash_alg_id: u32) -> Self {
        self.hash_alg_id = Some(hash_alg_id);
        self
    }

    /// Sets the public key for strong naming.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key data for strong naming
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Builds the Assembly entry and adds it to the assembly.
    ///
    /// This method validates the configuration, adds required strings/blobs
    /// to the appropriate heaps, creates the AssemblyRaw entry, and adds it
    /// to the assembly via the CilAssembly.
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::token::Token`] for the newly created Assembly entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing (name)
    /// - Heap operations fail
    /// - Assembly table row creation fails
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| malformed_error!("Assembly name is required"))?;

        // Add strings to heaps and get placeholder indices
        let name_ref = assembly.string_add(&name)?;
        let name_index = name_ref.placeholder();

        let culture_index = if let Some(culture) = &self.culture {
            if culture == "neutral" || culture.is_empty() {
                0 // Culture-neutral assembly
            } else {
                assembly.string_add(culture)?.placeholder()
            }
        } else {
            0 // Default to culture-neutral
        };

        let public_key_index = if let Some(public_key) = &self.public_key {
            assembly.blob_add(public_key)?.placeholder()
        } else {
            0 // No public key (unsigned assembly)
        };

        // Get the next RID for the Assembly table
        let rid = assembly.next_rid(TableId::Assembly)?;

        // Create the AssemblyRaw entry
        let assembly_raw = AssemblyRaw {
            rid,
            token: Token::new(rid | 0x2000_0000), // Assembly table token prefix
            offset: 0,                            // Will be set during binary generation
            hash_alg_id: self.hash_alg_id.unwrap_or(0x8004), // Default to SHA1
            major_version: self.major_version.unwrap_or(1),
            minor_version: self.minor_version.unwrap_or(0),
            build_number: self.build_number.unwrap_or(0),
            revision_number: self.revision_number.unwrap_or(0),
            flags: self.flags.unwrap_or(0),
            public_key: public_key_index,
            name: name_index,
            culture: culture_index,
        };

        // Add the row to the assembly and return the token
        assembly.table_row_add(TableId::Assembly, TableDataOwned::Assembly(assembly_raw))
    }
}

impl Default for AssemblyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        testkit::fixture,
    };

    #[test]
    fn test_assembly_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = AssemblyBuilder::new()
            .name("TestAssembly")
            .version(1, 2, 3, 4)
            .culture("neutral")
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Assembly));
    }

    #[test]
    fn test_assembly_builder_with_public_key() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let ref_ = AssemblyBuilder::new()
            .name("SignedAssembly")
            .version(2, 0, 0, 0)
            .public_key(public_key)
            .hash_algorithm(0x8004) // SHA1
            .flags(0x0001) // Public key flag
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Assembly));
    }

    #[test]
    fn test_assembly_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = AssemblyBuilder::new()
            .version(1, 0, 0, 0)
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }
}

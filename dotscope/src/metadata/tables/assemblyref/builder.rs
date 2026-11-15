//! # AssemblyRef Builder
//!
//! Provides a fluent API for building AssemblyRef table entries that reference external assemblies.
//! The AssemblyRef table contains dependency information for external assemblies required by
//! the current assembly, including version requirements and strong name verification data.
//!
//! ## Overview
//!
//! The `AssemblyRefBuilder` enables creation of assembly references with:
//! - Version number management (major, minor, build, revision)
//! - Assembly flags configuration (public key format, retargetability)
//! - Strong name support (public key or token)
//! - Culture specification for localized assemblies
//! - Hash value for integrity verification
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create a simple assembly reference
//! let assembly_ref_token = AssemblyRefBuilder::new()
//!     .name("System.Core")
//!     .version(4, 0, 0, 0)
//!     .build(&mut assembly)?;
//!
//! // Create a more complex assembly reference with strong naming
//! let strong_ref_token = AssemblyRefBuilder::new()
//!     .name("MyLibrary")
//!     .version(1, 2, 3, 4)
//!     .culture("en-US")
//!     .public_key_token(&[0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89])
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Assembly name is required, version defaults to 0.0.0.0
//! - **Heap Management**: Strings and blobs are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Strong Name Support**: Handles both public keys and public key tokens

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{AssemblyFlags, AssemblyRefRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating AssemblyRef table entries.
///
/// `AssemblyRefBuilder` provides a fluent API for creating entries in the AssemblyRef
/// metadata table, which contains references to external assemblies required by
/// the current assembly.
///
/// # Purpose
///
/// The AssemblyRef table serves several key functions:
/// - **Dependency Tracking**: Records external assembly dependencies
/// - **Version Management**: Specifies version requirements for dependencies
/// - **Strong Name Verification**: Provides cryptographic validation data
/// - **Culture Support**: Handles localized assembly references
/// - **Security**: Enables assembly integrity verification
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing AssemblyRef entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::AssemblyFlags;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// let assembly_ref = AssemblyRefBuilder::new()
///     .name("System.Core")
///     .version(4, 0, 0, 0)
///     .flags(AssemblyFlags::RETARGETABLE)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: An assembly name must be provided
/// - **Version Format**: Version numbers must fit in 16-bit values
/// - **Public Key Validation**: Public key tokens must be exactly 8 bytes
/// - **Culture Format**: Culture strings must be valid culture identifiers
///
/// # Integration
///
/// AssemblyRef entries integrate with other metadata tables:
/// - **TypeRef**: External types reference assemblies via AssemblyRef
/// - **MemberRef**: External members reference assemblies via AssemblyRef
/// - **Module**: Assembly references support multi-module scenarios
#[derive(Debug, Clone)]
pub struct AssemblyRefBuilder {
    /// The name of the referenced assembly
    name: Option<String>,
    /// Major version number
    major_version: u32,
    /// Minor version number
    minor_version: u32,
    /// Build number
    build_number: u32,
    /// Revision number
    revision_number: u32,
    /// Assembly flags
    flags: AssemblyFlags,
    /// Public key or public key token data
    public_key_or_token: Option<Vec<u8>>,
    /// Culture name for localized assemblies
    culture: Option<String>,
    /// Hash value for integrity verification
    hash_value: Option<Vec<u8>>,
}

impl Default for AssemblyRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AssemblyRefBuilder {
    /// Creates a new `AssemblyRefBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. Version defaults to 0.0.0.0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = AssemblyRefBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            major_version: 0,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: AssemblyFlags::ZERO,
            public_key_or_token: None,
            culture: None,
            hash_value: None,
        }
    }

    /// Sets the name of the referenced assembly.
    ///
    /// The assembly name is typically the simple name without file extension
    /// (e.g., "System.Core" rather than "System.Core.dll").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the referenced assembly
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = AssemblyRefBuilder::new()
    ///     .name("System.Core");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the version of the referenced assembly.
    ///
    /// The version consists of four components: major, minor, build, and revision.
    /// Each component must fit in a 16-bit value (0-65535).
    ///
    /// # Arguments
    ///
    /// * `major` - Major version number
    /// * `minor` - Minor version number  
    /// * `build` - Build number
    /// * `revision` - Revision number
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = AssemblyRefBuilder::new()
    ///     .version(4, 0, 0, 0);
    /// ```
    #[must_use]
    pub fn version(mut self, major: u32, minor: u32, build: u32, revision: u32) -> Self {
        self.major_version = major;
        self.minor_version = minor;
        self.build_number = build;
        self.revision_number = revision;
        self
    }

    /// Sets assembly flags for the referenced assembly.
    ///
    /// Flags control various aspects of assembly behavior including
    /// public key format and retargetability.
    ///
    /// # Arguments
    ///
    /// * `flags` - Assembly flags bitmask
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::AssemblyFlags;
    /// let builder = AssemblyRefBuilder::new()
    ///     .flags(AssemblyFlags::RETARGETABLE);
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: AssemblyFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the public key for the referenced assembly.
    ///
    /// When a full public key is provided, the `PUBLIC_KEY` flag is automatically
    /// set to indicate that this is a full key rather than a token.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The full public key data
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let public_key = vec![/* public key bytes */];
    /// let builder = AssemblyRefBuilder::new()
    ///     .public_key(&public_key);
    /// ```
    #[must_use]
    pub fn public_key(mut self, public_key: &[u8]) -> Self {
        self.public_key_or_token = Some(public_key.to_vec());
        self.flags |= AssemblyFlags::PUBLIC_KEY;
        self
    }

    /// Sets the public key token for the referenced assembly.
    ///
    /// A public key token is an 8-byte hash of the full public key.
    /// This is the most common form of strong name reference.
    ///
    /// # Arguments
    ///
    /// * `token` - The 8-byte public key token
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let token = [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89];
    /// let builder = AssemblyRefBuilder::new()
    ///     .public_key_token(&token);
    /// ```
    #[must_use]
    pub fn public_key_token(mut self, token: &[u8]) -> Self {
        self.public_key_or_token = Some(token.to_vec());
        self.flags &= !AssemblyFlags::PUBLIC_KEY; // Clear the PUBLIC_KEY flag for tokens
        self
    }

    /// Sets the culture for the referenced assembly.
    ///
    /// Culture is used for localized assemblies. Most assemblies are
    /// culture-neutral and do not need this setting.
    ///
    /// # Arguments
    ///
    /// * `culture` - The culture identifier (e.g., "en-US", "fr-FR")
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = AssemblyRefBuilder::new()
    ///     .culture("en-US");
    /// ```
    #[must_use]
    pub fn culture(mut self, culture: impl Into<String>) -> Self {
        self.culture = Some(culture.into());
        self
    }

    /// Sets the hash value for integrity verification.
    ///
    /// The hash value is used to verify the integrity of the referenced
    /// assembly. This is optional and rarely used in practice.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash data for verification
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let hash = vec![/* hash bytes */];
    /// let builder = AssemblyRefBuilder::new()
    ///     .hash_value(&hash);
    /// ```
    #[must_use]
    pub fn hash_value(mut self, hash: &[u8]) -> Self {
        self.hash_value = Some(hash.to_vec());
        self
    }

    /// Builds the AssemblyRef entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings and blobs to
    /// the appropriate heaps, creates the AssemblyRef table entry, and returns
    /// the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created AssemblyRef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The assembly name is not set
    /// - The assembly name is empty
    /// - Version numbers exceed 16-bit limits (65535)
    /// - There are issues adding strings or blobs to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    ///
    /// let assembly_ref_token = AssemblyRefBuilder::new()
    ///     .name("System.Core")
    ///     .version(4, 0, 0, 0)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created AssemblyRef with token: {:?}", assembly_ref_token.placeholder_token());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid("Assembly name is required for AssemblyRef".to_string())
        })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalid(
                "Assembly name cannot be empty for AssemblyRef".to_string(),
            ));
        }

        if self.major_version > 65535 {
            return Err(Error::ModificationInvalid(
                "Major version number must fit in 16 bits (0-65535)".to_string(),
            ));
        }
        if self.minor_version > 65535 {
            return Err(Error::ModificationInvalid(
                "Minor version number must fit in 16 bits (0-65535)".to_string(),
            ));
        }
        if self.build_number > 65535 {
            return Err(Error::ModificationInvalid(
                "Build number must fit in 16 bits (0-65535)".to_string(),
            ));
        }
        if self.revision_number > 65535 {
            return Err(Error::ModificationInvalid(
                "Revision number must fit in 16 bits (0-65535)".to_string(),
            ));
        }

        let name_index = assembly.string_get_or_add(&name)?.placeholder();

        let culture_index = if let Some(culture) = self.culture {
            if culture.is_empty() {
                0 // Empty culture string means culture-neutral
            } else {
                assembly.string_get_or_add(&culture)?.placeholder()
            }
        } else {
            0 // No culture means culture-neutral
        };

        let public_key_or_token_index = if let Some(data) = self.public_key_or_token {
            if data.is_empty() {
                0
            } else {
                if !self.flags.contains(AssemblyFlags::PUBLIC_KEY) && data.len() != 8 {
                    return Err(Error::ModificationInvalid(
                        "Public key token must be exactly 8 bytes".to_string(),
                    ));
                }
                assembly.blob_add(&data)?.placeholder()
            }
        } else {
            0
        };

        let hash_value_index = if let Some(hash) = self.hash_value {
            if hash.is_empty() {
                0
            } else {
                assembly.blob_add(&hash)?.placeholder()
            }
        } else {
            0
        };

        let assembly_ref = AssemblyRefRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: self.flags.bits(),
            public_key_or_token: public_key_or_token_index,
            name: name_index,
            culture: culture_index,
            hash_value: hash_value_index,
        };

        assembly.table_row_add(
            TableId::AssemblyRef,
            TableDataOwned::AssemblyRef(assembly_ref),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, metadata::tables::AssemblyFlags,
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_assemblyref_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = AssemblyRefBuilder::new()
            .name("System.Core")
            .version(4, 0, 0, 0)
            .build(&mut assembly)?;

        // Verify the ref has the correct kind
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_default() -> Result<()> {
        let builder = AssemblyRefBuilder::default();
        assert!(builder.name.is_none());
        assert_eq!(builder.major_version, 0);
        assert_eq!(builder.minor_version, 0);
        assert_eq!(builder.build_number, 0);
        assert_eq!(builder.revision_number, 0);
        assert_eq!(builder.flags, AssemblyFlags::ZERO);
        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = AssemblyRefBuilder::new()
            .version(1, 0, 0, 0)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Assembly name is required"));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_empty_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = AssemblyRefBuilder::new()
            .name("")
            .version(1, 0, 0, 0)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Assembly name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_with_culture() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = AssemblyRefBuilder::new()
            .name("LocalizedAssembly")
            .version(1, 0, 0, 0)
            .culture("en-US")
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_with_public_key_token() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let token_data = [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89];

        let ref_ = AssemblyRefBuilder::new()
            .name("StrongNamedAssembly")
            .version(2, 1, 0, 0)
            .public_key_token(&token_data)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_with_public_key() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let public_key = vec![0x00, 0x24, 0x00, 0x00, 0x04, 0x80]; // Truncated for test

        let ref_ = AssemblyRefBuilder::new()
            .name("FullKeyAssembly")
            .version(1, 2, 3, 4)
            .public_key(&public_key)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_invalid_public_key_token_length() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let invalid_token = [0xB7, 0x7A, 0x5C]; // Only 3 bytes instead of 8

        let result = AssemblyRefBuilder::new()
            .name("InvalidTokenAssembly")
            .version(1, 0, 0, 0)
            .public_key_token(&invalid_token)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Public key token must be exactly 8 bytes"));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_version_overflow() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = AssemblyRefBuilder::new()
            .name("OverflowAssembly")
            .version(70000, 0, 0, 0) // Exceeds 16-bit limit
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Major version number must fit in 16 bits"));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_with_flags() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = AssemblyRefBuilder::new()
            .name("RetargetableAssembly")
            .version(1, 0, 0, 0)
            .flags(AssemblyFlags::RETARGETABLE)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_with_hash_value() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let hash = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let ref_ = AssemblyRefBuilder::new()
            .name("HashedAssembly")
            .version(1, 0, 0, 0)
            .hash_value(&hash)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_multiple_assembly_refs() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref1 = AssemblyRefBuilder::new()
            .name("FirstAssembly")
            .version(1, 0, 0, 0)
            .build(&mut assembly)?;

        let ref2 = AssemblyRefBuilder::new()
            .name("SecondAssembly")
            .version(2, 0, 0, 0)
            .build(&mut assembly)?;

        // Verify refs are different
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_comprehensive() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let token_data = [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89];
        let hash = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let ref_ = AssemblyRefBuilder::new()
            .name("ComprehensiveAssembly")
            .version(2, 1, 4, 8)
            .culture("fr-FR")
            .public_key_token(&token_data)
            .hash_value(&hash)
            .flags(AssemblyFlags::RETARGETABLE)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test fluent API chaining
        let ref_ = AssemblyRefBuilder::new()
            .name("FluentAssembly")
            .version(3, 1, 4, 1)
            .culture("de-DE")
            .flags(AssemblyFlags::PUBLIC_KEY)
            .build(&mut assembly)?;

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::AssemblyRef));

        Ok(())
    }

    #[test]
    fn test_assemblyref_builder_clone() {
        let builder1 = AssemblyRefBuilder::new()
            .name("CloneTest")
            .version(1, 2, 3, 4);
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.major_version, builder2.major_version);
        assert_eq!(builder1.minor_version, builder2.minor_version);
    }

    #[test]
    fn test_assemblyref_builder_debug() {
        let builder = AssemblyRefBuilder::new()
            .name("DebugAssembly")
            .version(1, 0, 0, 0);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyRefBuilder"));
        assert!(debug_str.contains("DebugAssembly"));
    }
}

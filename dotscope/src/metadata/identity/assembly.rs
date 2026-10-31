//! Assembly identity system for multi-assembly .NET analysis.
//!
//! This module provides comprehensive assembly identification and version management
//! for .NET assemblies according to ECMA-335 specifications. It serves as the
//! foundation for cross-assembly resolution and multi-assembly project management.
//!
//! # ECMA-335 References
//!
//! This module implements identity concepts defined in the ECMA-335 specification:
//! - **Section II.6.1**: Overview of assemblies - defines assembly identity components
//! - **Section II.6.2.1**: Assembly versioning - four-part version number semantics
//! - **Section II.6.2.1.3**: Public key and token - strong name identity format
//! - **Section II.6.2.3**: Processor architecture - platform-specific assembly targeting
//! - **Section II.22.2**: Assembly table - assembly metadata structure
//! - **Section II.22.5**: AssemblyRef table - assembly reference structure
//!
//! See: <https://ecma-international.org/publications-and-standards/standards/ecma-335/>
//!
//! # Key Components
//!
//! - [`AssemblyIdentity`] - Complete assembly identification with name, version, culture, and strong name
//! - [`AssemblyVersion`] - Four-part version numbering (major.minor.build.revision)  
//! - [`ProcessorArchitecture`] - Processor architecture specification
//!
//! # Identity Components
//!
//! .NET assemblies are uniquely identified by the combination of:
//! - **Simple Name**: The primary assembly name (e.g., "mscorlib", "System.Core")
//! - **Version**: Four-part version number for binding and compatibility
//! - **Culture**: Localization culture (None for culture-neutral assemblies)
//! - **Strong Name**: Cryptographic identity for verification and GAC storage
//! - **Architecture**: Target processor architecture for platform-specific assemblies
//!
//! # Assembly Versioning
//!
//! Assembly versions follow the .NET convention of four 16-bit components:
//! - **Major**: Significant API changes, breaking compatibility
//! - **Minor**: Feature additions, backward compatible
//! - **Build**: Bug fixes and minor updates
//! - **Revision**: Emergency patches and hotfixes
//!
//! # Examples
//!
//! ## Creating Assembly Identities
//!
//! ```rust,no_run
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//!
//! // Simple assembly without strong name
//! let simple = AssemblyIdentity::new(
//!     "MyLibrary",
//!     AssemblyVersion::new(1, 2, 3, 4),
//!     None,
//!     None,
//!     None,
//! );
//!
//! // Strong-named framework assembly
//! let mscorlib = AssemblyIdentity::parse(
//!     "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Parsing from Metadata
//!
//! ```no_run
//! use dotscope::metadata::tables::AssemblyRef;
//! use dotscope::metadata::identity::AssemblyIdentity;
//!
//! // Parse from AssemblyRef table entry
//! let assembly_ref: AssemblyRef = // ... loaded from metadata
//! let identity = AssemblyIdentity::from_assembly_ref(&assembly_ref);
//!
//! // Parse from Assembly table entry
//! let assembly: Assembly = // ... loaded from metadata
//! let identity = AssemblyIdentity::from_assembly(&assembly);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Version Parsing and Display
//!
//! ```rust,no_run
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//!
//! // Parse version string
//! let version = AssemblyVersion::parse("1.2.3.4")?;
//! assert_eq!(version.major, 1);
//! assert_eq!(version.minor, 2);
//!
//! // Display name generation
//! let identity = AssemblyIdentity::parse("System.Core, Version=3.5.0.0")?;
//! println!("Display name: {}", identity.display_name());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration with CilProject
//!
//! This identity system serves as the foundation for:
//! - **Multi-assembly dependency tracking** in AssemblyDependencyGraph
//! - **Cross-assembly type resolution** in GlobalTypeResolver  
//! - **Assembly loading and management** in CilProject container
//! - **Version binding and compatibility** analysis
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`Send`] and [`Sync`].
//! Assembly identities can be safely shared across threads and used as keys in
//! concurrent collections like `DashMap` and `HashMap`.

use std::{fmt, fmt::Write as _, str::FromStr, sync::atomic::Ordering};

use crate::{
    metadata::{
        identity::cryptographic::Identity,
        tables::{Assembly, AssemblyHashAlgorithm, AssemblyRef},
    },
    Error, Result,
};

/// Complete identity information for a .NET assembly.
///
/// Provides comprehensive identification for .NET assemblies including name, version,
/// culture, strong name, and architecture information. This serves as the primary
/// identifier for assemblies in multi-assembly analysis and cross-assembly resolution.
///
/// # Identity Components
///
/// - **Name**: Simple assembly name used for basic identification
/// - **Version**: Four-part version for compatibility and binding decisions
/// - **Culture**: Localization culture (None for culture-neutral assemblies)
/// - **Strong Name**: Cryptographic identity for verification and security
/// - **Architecture**: Target processor architecture specification
///
/// # Equality Semantics
///
/// **Important**: The [`strong_name`](Self::strong_name) field is **excluded** from equality
/// comparison and hashing. This is an intentional design decision that enables:
///
/// - Assemblies with different strong name representations (Token vs PubKey vs EcmaKey)
///   to be considered equal for dependency resolution purposes
/// - Consistent [`HashMap`](std::collections::HashMap) behavior when the same assembly
///   is referenced with different key formats
/// - Matching dependencies by name+version+culture+architecture regardless of how
///   the strong name is stored in metadata
///
/// Two `AssemblyIdentity` instances are equal if and only if their `name`, `version`,
/// `culture`, and `processor_architecture` fields are equal. The `strong_name` field
/// is ignored in both `PartialEq` and `Hash` implementations.
///
/// If you need to compare strong names, access the `strong_name` field directly or use
/// a custom comparison function.
///
/// # Uniqueness
///
/// Two assemblies with identical identity components (excluding strong name) are
/// considered the same assembly. The combination of name, version, culture, and
/// architecture provides sufficient uniqueness for practical assembly identification
/// and resolution scenarios.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
///
/// // Create identity for a simple library
/// let identity = AssemblyIdentity {
///     name: "MyLibrary".to_string(),
///     version: AssemblyVersion::new(1, 0, 0, 0),
///     culture: None,
///     strong_name: None,
///     processor_architecture: None,
/// };
///
/// // Use as key in collections
/// let mut assembly_map = std::collections::HashMap::new();
/// let assembly_data = "path/to/assembly.dll";
/// assembly_map.insert(identity, assembly_data);
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyIdentity {
    /// Simple assembly name (e.g., "mscorlib", "System.Core").
    ///
    /// The primary identifier used for basic assembly lookup and display.
    /// This name appears in assembly references and is used for file system
    /// resolution when no culture or architecture specificity is required.
    pub name: String,

    /// Four-part version number for compatibility and binding.
    ///
    /// Used by the .NET runtime for version binding decisions, compatibility
    /// analysis, and side-by-side deployment scenarios. Version policies can
    /// specify exact, minimum, or range-based version requirements.
    pub version: AssemblyVersion,

    /// Culture information for localized assemblies.
    ///
    /// Specifies the localization culture for satellite assemblies containing
    /// culture-specific resources. `None` indicates a culture-neutral assembly
    /// that contains the default/fallback resources and executable code.
    ///
    /// # Examples
    /// - `None` - Culture-neutral assembly (default)
    /// - `Some("en-US")` - US English localized assembly
    /// - `Some("fr-FR")` - French (France) localized assembly
    pub culture: Option<String>,

    /// Cryptographic strong name identity.
    ///
    /// Provides cryptographic verification for assembly integrity and origin.
    /// Strong-named assemblies can be stored in the Global Assembly Cache (GAC)
    /// and provide security guarantees about assembly authenticity.
    ///
    /// Uses the existing cryptographic [`Identity`] system for public key
    /// or token-based identification.
    pub strong_name: Option<Identity>,

    /// Target processor architecture specification.
    ///
    /// Indicates the processor architecture for which the assembly was compiled.
    /// Used for platform-specific assemblies and deployment scenarios requiring
    /// architecture-specific code or optimizations.
    pub processor_architecture: Option<ProcessorArchitecture>,
}

impl PartialEq for AssemblyIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.version == other.version
            && self.culture == other.culture
            && self.processor_architecture == other.processor_architecture
        // Note: strong_name is excluded from equality comparison
        // This allows assemblies with different strong name representations
        // (PubKey vs Token) to be considered equal for dependency resolution
    }
}

impl Eq for AssemblyIdentity {}

impl std::hash::Hash for AssemblyIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.version.hash(state);
        self.culture.hash(state);
        self.processor_architecture.hash(state);
        // Note: strong_name is excluded from hash calculation
        // This ensures assemblies with different strong name representations
        // hash to the same value for consistent HashMap behavior
    }
}

/// Four-part version numbering for .NET assemblies.
///
/// Implements the standard .NET assembly versioning scheme with four 16-bit components.
/// This versioning system supports semantic versioning concepts while maintaining
/// compatibility with .NET runtime version binding and resolution mechanisms.
///
/// # Version Components
///
/// - **Major**: Significant API changes, potentially breaking compatibility
/// - **Minor**: Feature additions, maintaining backward compatibility  
/// - **Build**: Bug fixes, patches, and minor improvements
/// - **Revision**: Emergency fixes and hotfixes
///
/// # Version Comparison
///
/// Versions are compared component-wise in order: major, minor, build, revision.
/// This ordering enables proper version precedence and compatibility analysis
/// for assembly binding and dependency resolution.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::identity::AssemblyVersion;
///
/// // Create version programmatically
/// let version = AssemblyVersion::new(1, 2, 3, 4);
/// assert_eq!(version.to_string(), "1.2.3.4");
///
/// // Parse from string representation
/// let parsed = AssemblyVersion::parse("2.0.0.0")?;
/// assert!(parsed > version);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssemblyVersion {
    /// Major version component.
    ///
    /// Indicates significant changes that may break compatibility with previous versions.
    /// Typically incremented for major feature releases or API redesigns.
    pub major: u16,

    /// Minor version component.
    ///
    /// Indicates feature additions that maintain backward compatibility.
    /// New functionality is added without breaking existing public APIs.
    pub minor: u16,

    /// Build version component.
    ///
    /// Indicates bug fixes, performance improvements, and minor feature updates.
    /// Changes at this level should not affect public API compatibility.
    pub build: u16,

    /// Revision version component.
    ///
    /// Indicates emergency fixes, security patches, and critical hotfixes.
    /// Typically used for minimal changes addressing urgent issues.
    pub revision: u16,
}

/// Processor architecture specification for .NET assemblies.
///
/// Indicates the target processor architecture for platform-specific assemblies.
/// This information guides deployment decisions and runtime loading behavior
/// for architecture-sensitive code and optimizations.
///
/// # Architecture Types
///
/// - **MSIL**: Managed code, architecture-neutral (most common)
/// - **X86**: 32-bit Intel x86 architecture
/// - **IA64**: Intel Itanium 64-bit architecture  
/// - **AMD64**: 64-bit x86-64 architecture (Intel/AMD)
/// - **ARM**: ARM processor architecture
/// - **ARM64**: 64-bit ARM architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorArchitecture {
    /// Microsoft Intermediate Language - architecture neutral.
    ///
    /// Managed code that can run on any processor architecture supported
    /// by the .NET runtime. This is the most common architecture type
    /// for typical .NET assemblies.
    MSIL,

    /// 32-bit Intel x86 architecture.
    ///
    /// Platform-specific assemblies compiled for 32-bit Intel x86 processors.
    /// May contain P/Invoke calls or unsafe code specific to this architecture.
    X86,

    /// Intel Itanium 64-bit architecture.
    ///
    /// Platform-specific assemblies for Intel Itanium processors.
    /// Largely deprecated but may appear in legacy enterprise environments.
    IA64,

    /// 64-bit x86-64 architecture (Intel/AMD).
    ///
    /// Platform-specific assemblies for modern 64-bit Intel and AMD processors.
    /// Common for performance-critical code requiring 64-bit optimizations.
    ///
    /// # Parsing Alias
    ///
    /// Both "AMD64" and "x64" are accepted when parsing, but the canonical display
    /// name is "AMD64". This means `ProcessorArchitecture::parse("x64")` returns
    /// `AMD64`, which displays as "AMD64", not "x64".
    AMD64,

    /// ARM processor architecture.
    ///
    /// Platform-specific assemblies for ARM processors, common in mobile
    /// and embedded scenarios where .NET Core/5+ provides ARM support.
    ARM,

    /// 64-bit ARM architecture.
    ///
    /// Platform-specific assemblies for 64-bit ARM processors, increasingly
    /// common with ARM-based servers and Apple Silicon support.
    ARM64,
}

impl AssemblyIdentity {
    /// Create a new assembly identity with the specified components.
    ///
    /// This constructor provides a convenient way to create assembly identities
    /// programmatically with all required and optional components.
    ///
    /// # Arguments
    ///
    /// * `name` - Simple assembly name for identification
    /// * `version` - Four-part version number
    /// * `culture` - Optional culture for localized assemblies
    /// * `strong_name` - Optional cryptographic identity
    /// * `processor_architecture` - Optional architecture specification
    ///
    /// # Returns
    ///
    /// A new `AssemblyIdentity` with the specified components.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let identity = AssemblyIdentity::new(
    ///     "MyLibrary",
    ///     AssemblyVersion::new(1, 0, 0, 0),
    ///     None,
    ///     None,
    ///     None,
    /// );
    /// ```
    pub fn new(
        name: impl Into<String>,
        version: AssemblyVersion,
        culture: Option<String>,
        strong_name: Option<Identity>,
        processor_architecture: Option<ProcessorArchitecture>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            culture,
            strong_name,
            processor_architecture,
        }
    }

    /// Create assembly identity from an AssemblyRef table entry.
    ///
    /// Extracts complete assembly identity information from a metadata
    /// AssemblyRef entry, including version, culture, and strong name data.
    /// This is the primary method for creating identities during metadata loading.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref` - AssemblyRef table entry from metadata
    ///
    /// # Returns
    ///
    /// Complete `AssemblyIdentity` derived from the AssemblyRef data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let assembly_ref = // ... loaded from metadata
    /// let identity = AssemblyIdentity::from_assembly_ref(&assembly_ref);
    /// ```
    pub fn from_assembly_ref(assembly_ref: &AssemblyRef) -> Self {
        // Extract processor architecture from the AssemblyRefProcessor table data if present.
        // A value of 0 typically means MSIL/AnyCPU (architecture-neutral), but we only
        // set the architecture if a non-zero processor value is present to distinguish
        // between "no processor info" and "explicitly MSIL".
        let processor_value = assembly_ref.processor.load(Ordering::Relaxed);
        let processor_architecture = if processor_value != 0 {
            ProcessorArchitecture::try_from(processor_value).ok()
        } else {
            None
        };

        Self {
            name: assembly_ref.name.clone(),
            version: Self::version_from_u32(
                assembly_ref.major_version,
                assembly_ref.minor_version,
                assembly_ref.build_number,
                assembly_ref.revision_number,
            ),
            culture: assembly_ref.culture.clone(),
            strong_name: assembly_ref.identifier.clone(),
            processor_architecture,
        }
    }

    /// Create assembly identity from an Assembly table entry.
    ///
    /// Extracts complete assembly identity information from a metadata
    /// Assembly entry for the current assembly being analyzed.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly table entry from metadata
    ///
    /// # Returns
    ///
    /// Complete `AssemblyIdentity` derived from the Assembly data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let assembly = // ... loaded from metadata
    /// let identity = AssemblyIdentity::from_assembly(&assembly);
    /// ```
    pub fn from_assembly(assembly: &Assembly) -> Self {
        // Note: Processor architecture for the Assembly table is stored in the separate
        // AssemblyProcessor table (0x21), not in the Assembly flags. This table is rarely
        // used in modern .NET assemblies which typically use AnyCPU compilation.
        // The AssemblyProcessor table would need to be correlated separately if needed.
        Self {
            name: assembly.name.clone(),
            version: Self::version_from_u32(
                assembly.major_version,
                assembly.minor_version,
                assembly.build_number,
                assembly.revision_number,
            ),
            culture: assembly.culture.clone(),
            strong_name: assembly
                .public_key
                .as_ref()
                .and_then(|key| Identity::from(key, true).ok()),
            processor_architecture: None,
        }
    }

    /// Create an `AssemblyVersion` from u32 components with saturating conversion.
    ///
    /// Per ECMA-335, assembly version components should fit within u16 range (0-65535).
    /// However, the metadata stores them as u32 for alignment. This method uses
    /// saturating conversion (`u16::try_from` with `unwrap_or(u16::MAX)`) to handle
    /// potentially malformed metadata gracefully without panicking.
    #[inline]
    fn version_from_u32(major: u32, minor: u32, build: u32, revision: u32) -> AssemblyVersion {
        AssemblyVersion::new(
            u16::try_from(major).unwrap_or(u16::MAX),
            u16::try_from(minor).unwrap_or(u16::MAX),
            u16::try_from(build).unwrap_or(u16::MAX),
            u16::try_from(revision).unwrap_or(u16::MAX),
        )
    }

    /// Parse assembly identity from display name string.
    ///
    /// Parses .NET assembly display names in the standard format used by
    /// the .NET runtime and development tools. Supports both simple names
    /// and fully-qualified names with version, culture, and public key token.
    ///
    /// # Arguments
    ///
    /// * `display_name` - Assembly display name string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(AssemblyIdentity)` - Successfully parsed identity
    /// * `Err(Error)` - Parsing failed due to invalid format
    ///
    /// # Format
    ///
    /// ```text
    /// AssemblyName[, Version=Major.Minor.Build.Revision][, Culture=culture][, PublicKeyToken=token]
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// // Simple name only
    /// let simple = AssemblyIdentity::parse("MyLibrary")?;
    ///
    /// // Full specification
    /// let full = AssemblyIdentity::parse(
    ///     "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the display name cannot be parsed.
    pub fn parse(display_name: &str) -> Result<Self> {
        let mut version = AssemblyVersion::new(0, 0, 0, 0);
        let mut culture = None;
        let mut strong_name = None;
        let mut processor_architecture = None;

        let parts: Vec<&str> = display_name.split(',').map(str::trim).collect();

        let name = parts
            .first()
            .ok_or_else(|| malformed_error!("Empty assembly display name"))?
            .to_string();
        if name.is_empty() {
            return Err(malformed_error!("Assembly name cannot be empty"));
        }

        // Process optional components
        for part in parts.iter().skip(1) {
            if let Some(value) = part.strip_prefix("Version=") {
                version = AssemblyVersion::parse(value)?;
            } else if let Some(value) = part.strip_prefix("Culture=") {
                if value != "neutral" {
                    culture = Some(value.to_string());
                }
            } else if let Some(value) = part.strip_prefix("PublicKeyToken=") {
                if value != "null" && !value.is_empty() {
                    let token_bytes = hex::decode(value).map_err(|e| {
                        malformed_error!("Invalid hex in PublicKeyToken '{}': {}", value, e)
                    })?;

                    if token_bytes.len() != 8 {
                        return Err(malformed_error!(
                            "PublicKeyToken must be exactly 8 bytes (16 hex characters), got {} bytes from '{}'",
                            token_bytes.len(),
                            value
                        ));
                    }

                    let mut token = [0u8; 8];
                    token.copy_from_slice(&token_bytes);
                    strong_name = Some(Identity::Token(token));
                }
            } else if let Some(value) = part.strip_prefix("ProcessorArchitecture=") {
                processor_architecture = Some(ProcessorArchitecture::parse(value)?);
            }
        }

        Ok(Self {
            name,
            version,
            culture,
            strong_name,
            processor_architecture,
        })
    }

    /// Generate display name string for this assembly identity.
    ///
    /// Creates a .NET-compatible assembly display name that includes all
    /// available identity components. This format is compatible with .NET
    /// runtime assembly loading and resolution mechanisms.
    ///
    /// # Returns
    ///
    /// A formatted display name string suitable for assembly loading.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let identity = AssemblyIdentity::new(
    ///     "MyLibrary",
    ///     AssemblyVersion::new(1, 2, 3, 4),
    ///     Some("en-US".to_string()),
    ///     None,
    ///     None,
    /// );
    ///
    /// let display_name = identity.display_name();
    /// // Result: "MyLibrary, Version=1.2.3.4, Culture=en-US, PublicKeyToken=null"
    /// ```
    #[must_use]
    pub fn display_name(&self) -> String {
        // Pre-allocate with estimated capacity to minimize reallocations
        // Typical format: "Name, Version=x.x.x.x, Culture=neutral, PublicKeyToken=xxxxxxxxxxxxxxxx"
        let mut result = String::with_capacity(self.name.len().saturating_add(80));

        result.push_str(&self.name);

        let _ = write!(result, ", Version={}", self.version);

        let culture_str = self.culture.as_deref().unwrap_or("neutral");
        let _ = write!(result, ", Culture={culture_str}");

        // A key's token is computed with SHA-1, as .NET computes it
        result.push_str(", PublicKeyToken=");
        let token = match &self.strong_name {
            Some(Identity::Token(token)) => Some(*token),
            Some(identity @ (Identity::PubKey(_) | Identity::EcmaKey(_))) => {
                identity.to_token(AssemblyHashAlgorithm::SHA1).ok()
            }
            None => None,
        };
        match token {
            Some(token) => result.push_str(&hex::encode(token)),
            None => result.push_str("null"),
        }

        // Add processor architecture if specified
        if let Some(arch) = &self.processor_architecture {
            let _ = write!(result, ", ProcessorArchitecture={arch}");
        }

        result
    }

    /// Get the simple assembly name without version or culture information.
    ///
    /// Returns just the primary assembly name component for cases where
    /// version and culture information is not needed.
    ///
    /// # Returns
    ///
    /// The simple assembly name string.
    #[must_use]
    pub fn simple_name(&self) -> &str {
        &self.name
    }

    /// Check if this assembly is strong-named.
    ///
    /// Strong-named assemblies have cryptographic identity that can be verified
    /// and are eligible for Global Assembly Cache (GAC) storage.
    ///
    /// # Returns
    ///
    /// `true` if the assembly has a strong name, `false` otherwise.
    #[must_use]
    pub fn is_strong_named(&self) -> bool {
        self.strong_name.is_some()
    }

    /// Check if this assembly is culture-neutral.
    ///
    /// Culture-neutral assemblies contain the default resources and executable
    /// code, while culture-specific assemblies contain localized resources.
    ///
    /// # Returns
    ///
    /// `true` if the assembly is culture-neutral, `false` if culture-specific.
    #[must_use]
    pub fn is_culture_neutral(&self) -> bool {
        self.culture.is_none()
    }

    /// Check if this assembly identity satisfies a dependency requirement.
    ///
    /// This method determines whether this assembly can be used to satisfy a
    /// reference to another assembly. It checks name, culture, and version
    /// compatibility according to .NET binding rules.
    ///
    /// # Matching Rules
    ///
    /// 1. **Name**: Must match case-insensitively
    /// 2. **Culture**: Must match exactly (None matches None, "en-US" matches "en-US")
    /// 3. **Version**: Must be compatible per [`AssemblyVersion::is_compatible_with`]
    ///
    /// # Arguments
    ///
    /// * `required` - The assembly identity required by a dependency
    ///
    /// # Returns
    ///
    /// `true` if this assembly can satisfy the requirement, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let available = AssemblyIdentity::new(
    ///     "System.Core",
    ///     AssemblyVersion::new(4, 5, 0, 0),
    ///     None,
    ///     None,
    ///     None,
    /// );
    ///
    /// let required = AssemblyIdentity::new(
    ///     "System.Core",
    ///     AssemblyVersion::new(4, 0, 0, 0),
    ///     None,
    ///     None,
    ///     None,
    /// );
    ///
    /// // v4.5 satisfies requirement for v4.0
    /// assert!(available.satisfies(&required));
    ///
    /// // But v4.0 does NOT satisfy requirement for v4.5
    /// assert!(!required.satisfies(&available));
    /// ```
    #[must_use]
    pub fn satisfies(&self, required: &AssemblyIdentity) -> bool {
        // Name must match (case-insensitive)
        if !self.name.eq_ignore_ascii_case(&required.name) {
            return false;
        }

        // Culture must match exactly
        if self.culture != required.culture {
            return false;
        }

        // Version must be compatible
        self.version.is_compatible_with(&required.version)
    }
}

impl AssemblyVersion {
    /// Sentinel value representing an unknown or unspecified version.
    ///
    /// This constant (0.0.0.0) is used when version information is not available, such as when
    /// creating assembly identities from `ModuleRef` or `File` table entries where
    /// version information is not stored in the metadata.
    ///
    /// Use [`is_unknown()`](Self::is_unknown) to check if a version represents this sentinel.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let unknown = AssemblyVersion::UNKNOWN;
    /// assert!(unknown.is_unknown());
    ///
    /// let known = AssemblyVersion::new(1, 0, 0, 0);
    /// assert!(!known.is_unknown());
    /// ```
    pub const UNKNOWN: Self = Self {
        major: 0,
        minor: 0,
        build: 0,
        revision: 0,
    };

    /// Create a new assembly version with the specified components.
    ///
    /// # Arguments
    ///
    /// * `major` - Major version component
    /// * `minor` - Minor version component
    /// * `build` - Build version component
    /// * `revision` - Revision version component
    ///
    /// # Returns
    ///
    /// A new `AssemblyVersion` with the specified components.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let version = AssemblyVersion::new(1, 2, 3, 4);
    /// assert_eq!(version.major, 1);
    /// assert_eq!(version.minor, 2);
    /// ```
    #[must_use]
    pub const fn new(major: u16, minor: u16, build: u16, revision: u16) -> Self {
        Self {
            major,
            minor,
            build,
            revision,
        }
    }

    /// Check if this version represents an unknown/unspecified version.
    ///
    /// Returns `true` if this version equals [`UNKNOWN`](Self::UNKNOWN) (0.0.0.0).
    /// This is useful for detecting dependencies where version information could not
    /// be determined from the metadata, such as `ModuleRef` or `File` entries.
    ///
    /// # Note
    ///
    /// While version 0.0.0.0 is technically a valid .NET version, it is extremely
    /// rare in practice. This method treats it as a sentinel for "version unknown".
    /// If you need to distinguish between "truly version 0.0.0.0" and "unknown",
    /// consider using additional context from the dependency source.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// assert!(AssemblyVersion::UNKNOWN.is_unknown());
    /// assert!(AssemblyVersion::new(0, 0, 0, 0).is_unknown());
    /// assert!(!AssemblyVersion::new(1, 0, 0, 0).is_unknown());
    /// ```
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        self.major == 0 && self.minor == 0 && self.build == 0 && self.revision == 0
    }

    /// Check if this version is compatible with a required version.
    ///
    /// .NET uses version unification where a higher version can satisfy a lower
    /// requirement if they share the same major version. This follows the standard
    /// .NET binding policy for strong-named assemblies.
    ///
    /// # Compatibility Rules
    ///
    /// - If the required version is unknown (0.0.0.0), any version is compatible
    /// - Otherwise, the major versions must match and this version must be >= required
    ///
    /// # Arguments
    ///
    /// * `required` - The version that is required by a dependency
    ///
    /// # Returns
    ///
    /// `true` if this version can satisfy the requirement, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let v4_0 = AssemblyVersion::new(4, 0, 0, 0);
    /// let v4_5 = AssemblyVersion::new(4, 5, 0, 0);
    /// let v5_0 = AssemblyVersion::new(5, 0, 0, 0);
    ///
    /// // v4.5 is compatible with requirement for v4.0 (same major, higher version)
    /// assert!(v4_5.is_compatible_with(&v4_0));
    ///
    /// // v4.0 is NOT compatible with requirement for v4.5 (same major, but lower)
    /// assert!(!v4_0.is_compatible_with(&v4_5));
    ///
    /// // v5.0 is NOT compatible with requirement for v4.0 (different major)
    /// assert!(!v5_0.is_compatible_with(&v4_0));
    ///
    /// // Any version is compatible with unknown (0.0.0.0)
    /// assert!(v4_0.is_compatible_with(&AssemblyVersion::UNKNOWN));
    /// ```
    #[must_use]
    pub fn is_compatible_with(&self, required: &AssemblyVersion) -> bool {
        // Unknown version requirement accepts any version
        if required.is_unknown() {
            return true;
        }

        // Major version must match, and this version must be >= required
        self.major == required.major && *self >= *required
    }

    /// Check if this version is closer to a target than another version.
    ///
    /// Used for selecting the best fallback when no compatible version exists.
    /// The comparison prioritizes:
    ///
    /// 1. Same major version as target (strongly preferred)
    /// 2. For same major: higher version is better (closer to being compatible)
    /// 3. For different major: closer major number is better
    ///
    /// # Arguments
    ///
    /// * `other` - The version to compare against
    /// * `target` - The target version we're trying to match
    ///
    /// # Returns
    ///
    /// `true` if `self` is a better match for `target` than `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let target = AssemblyVersion::new(4, 5, 0, 0);
    /// let v4_0 = AssemblyVersion::new(4, 0, 0, 0);
    /// let v3_0 = AssemblyVersion::new(3, 0, 0, 0);
    /// let v5_0 = AssemblyVersion::new(5, 0, 0, 0);
    ///
    /// // Same major is preferred over different major
    /// assert!(v4_0.is_closer_to(&v3_0, &target));
    /// assert!(v4_0.is_closer_to(&v5_0, &target));
    ///
    /// // For same major, higher version is better
    /// let v4_2 = AssemblyVersion::new(4, 2, 0, 0);
    /// assert!(v4_2.is_closer_to(&v4_0, &target));
    ///
    /// // For different majors, closer major number wins
    /// let v2_0 = AssemblyVersion::new(2, 0, 0, 0);
    /// assert!(v3_0.is_closer_to(&v2_0, &target)); // v3 is closer to v4 than v2
    /// ```
    #[must_use]
    pub fn is_closer_to(&self, other: &AssemblyVersion, target: &AssemblyVersion) -> bool {
        let self_same_major = self.major == target.major;
        let other_same_major = other.major == target.major;

        match (self_same_major, other_same_major) {
            (true, false) => true,
            (false, true) => false,
            (true, true) => {
                // Both have same major as target - prefer higher (closer to compatible)
                self > other
            }
            (false, false) => {
                // Both have different major - prefer closer major number
                let self_dist = self.major.abs_diff(target.major);
                let other_dist = other.major.abs_diff(target.major);
                self_dist < other_dist
            }
        }
    }

    /// Parse assembly version from string representation.
    ///
    /// Supports various version string formats:
    /// - "1.2.3.4" - Full four-part version
    /// - "1.2.3" - Three-part version (revision defaults to 0)
    /// - "1.2" - Two-part version (build and revision default to 0)
    /// - "1" - Single component (others default to 0)
    ///
    /// # Arguments
    ///
    /// * `version_str` - Version string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(AssemblyVersion)` - Successfully parsed version
    /// * `Err(Error)` - Parsing failed due to invalid format
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let full = AssemblyVersion::parse("1.2.3.4")?;
    /// let partial = AssemblyVersion::parse("2.0")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the version string has an invalid format.
    pub fn parse(version_str: &str) -> Result<Self> {
        let parts: Vec<&str> = version_str.split('.').collect();

        if parts.is_empty() || parts.len() > 4 {
            return Err(malformed_error!("Invalid version format: {}", version_str));
        }

        let mut components = [0u16; 4];

        for (i, part) in parts.iter().enumerate() {
            let slot = components
                .get_mut(i)
                .ok_or_else(|| malformed_error!("Invalid version format: {}", version_str))?;
            *slot = part
                .parse::<u16>()
                .map_err(|_| malformed_error!("Invalid version component: {}", part))?;
        }

        Ok(Self::new(
            components[0],
            components[1],
            components[2],
            components[3],
        ))
    }
}

impl ProcessorArchitecture {
    /// Parse processor architecture from string representation.
    ///
    /// Supports standard .NET processor architecture names:
    /// - "MSIL" or "msil" - Microsoft Intermediate Language
    /// - "x86" or "X86" - 32-bit Intel x86
    /// - "IA64" or "ia64" - Intel Itanium 64-bit
    /// - "AMD64" or "amd64" or "x64" - 64-bit x86-64 (note: "x64" is an alias, displays as "AMD64")
    /// - "ARM" or "arm" - ARM architecture
    /// - "ARM64" or "arm64" - 64-bit ARM architecture
    ///
    /// # Arguments
    ///
    /// * `arch_str` - Architecture string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(ProcessorArchitecture)` - Successfully parsed architecture
    /// * `Err(Error)` - Parsing failed due to unrecognized architecture
    ///
    /// # Errors
    /// Returns an error if the architecture string is not recognized.
    pub fn parse(arch_str: &str) -> Result<Self> {
        match arch_str.trim().to_lowercase().as_str() {
            "msil" => Ok(Self::MSIL),
            "x86" => Ok(Self::X86),
            "ia64" => Ok(Self::IA64),
            "amd64" | "x64" => Ok(Self::AMD64),
            "arm" => Ok(Self::ARM),
            "arm64" => Ok(Self::ARM64),
            _ => Err(malformed_error!(
                "Unknown processor architecture: '{}'",
                arch_str.trim()
            )),
        }
    }
}

// Display implementations
impl fmt::Display for AssemblyVersion {
    /// Format assembly version as standard dotted notation.
    ///
    /// Produces version strings in the format "major.minor.build.revision"
    /// compatible with .NET version string conventions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

impl fmt::Display for ProcessorArchitecture {
    /// Format processor architecture as string.
    ///
    /// Uses standard .NET processor architecture names for consistency
    /// with runtime and development tool conventions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arch_str = match self {
            Self::MSIL => "MSIL",
            Self::X86 => "x86",
            Self::IA64 => "IA64",
            Self::AMD64 => "AMD64",
            Self::ARM => "ARM",
            Self::ARM64 => "ARM64",
        };
        write!(f, "{arch_str}")
    }
}

impl fmt::Display for AssemblyIdentity {
    /// Format assembly identity as display name.
    ///
    /// Delegates to the `display_name()` method for consistent formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// String parsing support
impl FromStr for AssemblyVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl FromStr for AssemblyIdentity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl FromStr for ProcessorArchitecture {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<u32> for ProcessorArchitecture {
    type Error = Error;

    /// Convert a processor ID from the AssemblyProcessor table to ProcessorArchitecture.
    ///
    /// The AssemblyProcessor table uses processor ID values that align with PE/COFF
    /// machine types. This implementation maps those values to the .NET ProcessorArchitecture enum.
    ///
    /// # Arguments
    ///
    /// * `value` - The processor value from the AssemblyProcessor table
    ///
    /// # Returns
    ///
    /// * `Ok(ProcessorArchitecture)` - Successfully mapped processor architecture
    /// * `Err(Error)` - Unknown or unsupported processor ID
    ///
    /// # Processor ID Mapping
    ///
    /// Based on PE/COFF specification (IMAGE_FILE_MACHINE_* constants):
    /// - `0x0000` - IMAGE_FILE_MACHINE_UNKNOWN (treated as MSIL/AnyCPU)
    /// - `0x014C` - IMAGE_FILE_MACHINE_I386 (x86)
    /// - `0x0200` - IMAGE_FILE_MACHINE_IA64 (Intel Itanium)
    /// - `0x8664` - IMAGE_FILE_MACHINE_AMD64 (x86-64)
    /// - `0x01C0` - IMAGE_FILE_MACHINE_ARM (32-bit ARM)
    /// - `0xAA64` - IMAGE_FILE_MACHINE_ARM64 (64-bit ARM)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::identity::ProcessorArchitecture;
    ///
    /// // x86 processor
    /// let arch = ProcessorArchitecture::try_from(0x014C)?;
    /// assert_eq!(arch, ProcessorArchitecture::X86);
    ///
    /// // AMD64/x64 processor
    /// let arch = ProcessorArchitecture::try_from(0x8664)?;
    /// assert_eq!(arch, ProcessorArchitecture::AMD64);
    ///
    /// // Unknown processor type
    /// assert!(ProcessorArchitecture::try_from(0xFFFF).is_err());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::MSIL),
            0x014C => Ok(Self::X86),
            0x0200 => Ok(Self::IA64),
            0x8664 => Ok(Self::AMD64),
            0x01C0 => Ok(Self::ARM),
            0xAA64 => Ok(Self::ARM64),
            _ => Err(malformed_error!(
                "Unknown processor architecture ID: 0x{:04X}",
                value
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{testkit::fixture, CilAssemblyView};

    /// A key's token prints as .NET prints it: the ECMA key as `b77a5c561934e089`, not its
    /// bytes reversed.
    #[cfg(feature = "legacy-crypto")]
    #[test]
    fn a_key_prints_its_token_in_dotnet_order() {
        let identity = AssemblyIdentity::new(
            "mscorlib",
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            Some(Identity::EcmaKey(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
            ])),
            None,
        );
        assert!(identity
            .display_name()
            .ends_with("PublicKeyToken=b77a5c561934e089"));
    }

    /// WindowsBase is signed with Microsoft's key, whose token is `31bf3856ad364e35`; the
    /// mscorlib it references carries the ECMA token.
    #[cfg(feature = "legacy-crypto")]
    #[test]
    fn windowsbase_identities_print_their_tokens() {
        let view = CilAssemblyView::from_path(fixture("WindowsBase.dll")).unwrap();
        let identity = view.identity().unwrap().unwrap();
        assert!(
            identity
                .display_name()
                .contains("PublicKeyToken=31bf3856ad364e35"),
            "{}",
            identity.display_name()
        );
    }

    #[test]
    fn test_assembly_version_new() {
        let version = AssemblyVersion::new(1, 2, 3, 4);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.build, 3);
        assert_eq!(version.revision, 4);
    }

    #[test]
    fn test_assembly_version_parse_full() {
        let version = AssemblyVersion::parse("4.0.0.0").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 0);
        assert_eq!(version.build, 0);
        assert_eq!(version.revision, 0);
    }

    #[test]
    fn test_assembly_version_parse_partial() {
        // Three parts
        let v3 = AssemblyVersion::parse("1.2.3").unwrap();
        assert_eq!(v3, AssemblyVersion::new(1, 2, 3, 0));

        // Two parts
        let v2 = AssemblyVersion::parse("1.2").unwrap();
        assert_eq!(v2, AssemblyVersion::new(1, 2, 0, 0));

        // Single part
        let v1 = AssemblyVersion::parse("1").unwrap();
        assert_eq!(v1, AssemblyVersion::new(1, 0, 0, 0));
    }

    #[test]
    fn test_assembly_version_parse_invalid() {
        // Empty string
        assert!(AssemblyVersion::parse("").is_err());

        // Too many parts
        assert!(AssemblyVersion::parse("1.2.3.4.5").is_err());

        // Invalid component
        assert!(AssemblyVersion::parse("1.2.abc.4").is_err());

        // Overflow
        assert!(AssemblyVersion::parse("1.2.99999.4").is_err());
    }

    #[test]
    fn test_assembly_version_display() {
        let version = AssemblyVersion::new(4, 0, 0, 0);
        assert_eq!(version.to_string(), "4.0.0.0");

        let version = AssemblyVersion::new(1, 2, 3, 4);
        assert_eq!(version.to_string(), "1.2.3.4");
    }

    #[test]
    fn test_assembly_version_ordering() {
        let v1 = AssemblyVersion::new(1, 0, 0, 0);
        let v2 = AssemblyVersion::new(2, 0, 0, 0);
        let v1_1 = AssemblyVersion::new(1, 1, 0, 0);

        assert!(v1 < v2);
        assert!(v1 < v1_1);
        assert!(v1_1 < v2);
    }

    #[test]
    fn test_assembly_version_from_str() {
        let version: AssemblyVersion = "4.0.0.0".parse().unwrap();
        assert_eq!(version, AssemblyVersion::new(4, 0, 0, 0));
    }

    #[test]
    fn test_processor_architecture_parse() {
        assert_eq!(
            ProcessorArchitecture::parse("MSIL").unwrap(),
            ProcessorArchitecture::MSIL
        );
        assert_eq!(
            ProcessorArchitecture::parse("msil").unwrap(),
            ProcessorArchitecture::MSIL
        );
        assert_eq!(
            ProcessorArchitecture::parse("x86").unwrap(),
            ProcessorArchitecture::X86
        );
        assert_eq!(
            ProcessorArchitecture::parse("X86").unwrap(),
            ProcessorArchitecture::X86
        );
        assert_eq!(
            ProcessorArchitecture::parse("AMD64").unwrap(),
            ProcessorArchitecture::AMD64
        );
        assert_eq!(
            ProcessorArchitecture::parse("amd64").unwrap(),
            ProcessorArchitecture::AMD64
        );
        assert_eq!(
            ProcessorArchitecture::parse("x64").unwrap(),
            ProcessorArchitecture::AMD64
        );
        assert_eq!(
            ProcessorArchitecture::parse("IA64").unwrap(),
            ProcessorArchitecture::IA64
        );
        assert_eq!(
            ProcessorArchitecture::parse("ARM").unwrap(),
            ProcessorArchitecture::ARM
        );
        assert_eq!(
            ProcessorArchitecture::parse("arm").unwrap(),
            ProcessorArchitecture::ARM
        );
        assert_eq!(
            ProcessorArchitecture::parse("ARM64").unwrap(),
            ProcessorArchitecture::ARM64
        );
        assert_eq!(
            ProcessorArchitecture::parse("arm64").unwrap(),
            ProcessorArchitecture::ARM64
        );
    }

    #[test]
    fn test_processor_architecture_parse_invalid() {
        assert!(ProcessorArchitecture::parse("unknown").is_err());
        assert!(ProcessorArchitecture::parse("").is_err());
        assert!(ProcessorArchitecture::parse("PowerPC").is_err());
    }

    #[test]
    fn test_processor_architecture_parse_whitespace() {
        // Whitespace should be trimmed
        assert_eq!(
            ProcessorArchitecture::parse(" x86 ").unwrap(),
            ProcessorArchitecture::X86
        );
        assert_eq!(
            ProcessorArchitecture::parse("\tAMD64\n").unwrap(),
            ProcessorArchitecture::AMD64
        );
        // Whitespace-only should fail
        assert!(ProcessorArchitecture::parse("   ").is_err());
    }

    #[test]
    fn test_processor_architecture_display() {
        assert_eq!(ProcessorArchitecture::MSIL.to_string(), "MSIL");
        assert_eq!(ProcessorArchitecture::X86.to_string(), "x86");
        assert_eq!(ProcessorArchitecture::AMD64.to_string(), "AMD64");
        assert_eq!(ProcessorArchitecture::IA64.to_string(), "IA64");
        assert_eq!(ProcessorArchitecture::ARM.to_string(), "ARM");
        assert_eq!(ProcessorArchitecture::ARM64.to_string(), "ARM64");
    }

    #[test]
    fn test_processor_architecture_from_str() {
        let arch: ProcessorArchitecture = "x86".parse().unwrap();
        assert_eq!(arch, ProcessorArchitecture::X86);
    }

    #[test]
    fn test_assembly_identity_new() {
        let identity = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        assert_eq!(identity.name, "TestAssembly");
        assert_eq!(identity.version, AssemblyVersion::new(1, 0, 0, 0));
        assert!(identity.culture.is_none());
        assert!(identity.strong_name.is_none());
        assert!(identity.processor_architecture.is_none());
    }

    #[test]
    fn test_assembly_identity_parse_simple_name() {
        let identity = AssemblyIdentity::parse("MyLibrary").unwrap();
        assert_eq!(identity.name, "MyLibrary");
        assert_eq!(identity.version, AssemblyVersion::new(0, 0, 0, 0));
        assert!(identity.culture.is_none());
        assert!(identity.strong_name.is_none());
    }

    #[test]
    fn test_assembly_identity_parse_with_version() {
        let identity = AssemblyIdentity::parse("MyLibrary, Version=1.2.3.4").unwrap();
        assert_eq!(identity.name, "MyLibrary");
        assert_eq!(identity.version, AssemblyVersion::new(1, 2, 3, 4));
    }

    #[test]
    fn test_assembly_identity_parse_full_mscorlib() {
        let identity = AssemblyIdentity::parse(
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        )
        .unwrap();

        assert_eq!(identity.name, "mscorlib");
        assert_eq!(identity.version, AssemblyVersion::new(4, 0, 0, 0));
        assert!(identity.culture.is_none()); // "neutral" maps to None
        assert!(identity.strong_name.is_some());

        if let Some(Identity::Token(token)) = identity.strong_name {
            // The token's bytes in the order the name shows them
            assert_eq!(token, [0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89]);
        } else {
            panic!("Expected Token identity");
        }
    }

    #[test]
    fn test_assembly_identity_parse_with_culture() {
        let identity = AssemblyIdentity::parse(
            "Resources, Version=1.0.0.0, Culture=en-US, PublicKeyToken=null",
        )
        .unwrap();

        assert_eq!(identity.name, "Resources");
        assert_eq!(identity.culture, Some("en-US".to_string()));
        assert!(identity.strong_name.is_none());
    }

    #[test]
    fn test_assembly_identity_parse_with_architecture() {
        let identity =
            AssemblyIdentity::parse("NativeLib, Version=1.0.0.0, ProcessorArchitecture=x86")
                .unwrap();

        assert_eq!(identity.name, "NativeLib");
        assert_eq!(
            identity.processor_architecture,
            Some(ProcessorArchitecture::X86)
        );
    }

    #[test]
    fn test_assembly_identity_parse_empty_returns_error() {
        // Empty assembly names are invalid per ECMA-335
        let result = AssemblyIdentity::parse("");
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot be empty"),
            "Error message should mention empty name: {}",
            err_msg
        );
    }

    #[test]
    fn test_assembly_identity_parse_whitespace_only_returns_error() {
        // Whitespace-only assembly names should also be rejected (trim happens first)
        let result = AssemblyIdentity::parse("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_assembly_identity_parse_invalid_hex_token() {
        // Invalid hex characters in PublicKeyToken should return an error
        let result =
            AssemblyIdentity::parse("MyLib, Version=1.0.0.0, PublicKeyToken=xyz_not_hex_123");
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid hex"),
            "Error message should mention invalid hex: {}",
            err_msg
        );
    }

    #[test]
    fn test_assembly_identity_parse_wrong_length_token() {
        // Wrong length PublicKeyToken (not 8 bytes) should return an error
        let result = AssemblyIdentity::parse(
            "MyLib, Version=1.0.0.0, PublicKeyToken=b77a5c56", // Only 4 bytes
        );
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("8 bytes"),
            "Error message should mention expected length: {}",
            err_msg
        );
    }

    #[test]
    fn test_assembly_identity_parse_too_long_token() {
        // Too long PublicKeyToken should return an error
        let result = AssemblyIdentity::parse(
            "MyLib, Version=1.0.0.0, PublicKeyToken=b77a5c561934e089aabbccdd", // 12 bytes
        );
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("8 bytes"),
            "Error message should mention expected length: {}",
            err_msg
        );
    }

    #[test]
    fn test_assembly_identity_parse_invalid_processor_architecture() {
        // Invalid ProcessorArchitecture should return an error
        let result =
            AssemblyIdentity::parse("MyLib, Version=1.0.0.0, ProcessorArchitecture=PowerPC");
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Unknown processor architecture"),
            "Error message should mention unknown architecture: {}",
            err_msg
        );
    }

    #[test]
    fn test_assembly_identity_display_name_simple() {
        let identity = AssemblyIdentity::new(
            "MyLibrary",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        let display = identity.display_name();
        assert!(display.contains("MyLibrary"));
        assert!(display.contains("Version=1.0.0.0"));
        assert!(display.contains("Culture=neutral"));
        assert!(display.contains("PublicKeyToken=null"));
    }

    #[test]
    fn test_assembly_identity_display_name_with_culture() {
        let identity = AssemblyIdentity::new(
            "Resources",
            AssemblyVersion::new(1, 0, 0, 0),
            Some("fr-FR".to_string()),
            None,
            None,
        );

        let display = identity.display_name();
        assert!(display.contains("Culture=fr-FR"));
    }

    #[test]
    #[cfg(feature = "legacy-crypto")]
    fn test_assembly_identity_display_name_with_pubkey() {
        // Test that PubKey variants compute and display their token using SHA1
        // Note: This test requires legacy-crypto because token computation uses SHA1
        let pubkey_data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let identity = AssemblyIdentity::new(
            "StrongLib",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            Some(Identity::PubKey(pubkey_data)),
            None,
        );

        let display = identity.display_name();
        // Should NOT contain "null" for PublicKeyToken since we have a PubKey
        assert!(
            !display.contains("PublicKeyToken=null"),
            "PubKey should compute a token, not show null: {}",
            display
        );
        // Should contain a 16-character hex token
        assert!(
            display.contains("PublicKeyToken="),
            "Should have PublicKeyToken in display: {}",
            display
        );
    }

    #[test]
    #[cfg(feature = "legacy-crypto")]
    fn test_assembly_identity_display_name_with_ecma_key() {
        // Test that EcmaKey variants compute and display their token using SHA1
        // Note: This test requires legacy-crypto because token computation uses SHA1
        let ecma_data = vec![
            0x06, 0x28, 0xAC, 0x03, 0x00, 0x06, 0x7A, 0x06, 0x6F, 0xAB, 0x02, 0x00, 0x0A, 0x0B,
            0x17, 0x6A,
        ];
        let identity = AssemblyIdentity::new(
            "FrameworkLib",
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            Some(Identity::EcmaKey(ecma_data)),
            None,
        );

        let display = identity.display_name();
        // Should NOT contain "null" for PublicKeyToken since we have an EcmaKey
        assert!(
            !display.contains("PublicKeyToken=null"),
            "EcmaKey should compute a token, not show null: {}",
            display
        );
    }

    #[test]
    fn test_assembly_identity_simple_name() {
        let identity = AssemblyIdentity::new(
            "System.Core",
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        assert_eq!(identity.simple_name(), "System.Core");
    }

    #[test]
    fn test_assembly_identity_is_strong_named() {
        let weak = AssemblyIdentity::new(
            "WeakAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );
        assert!(!weak.is_strong_named());

        let strong = AssemblyIdentity::new(
            "StrongAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            Some(Identity::Token([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            ])),
            None,
        );
        assert!(strong.is_strong_named());
    }

    #[test]
    fn test_assembly_identity_is_culture_neutral() {
        let neutral = AssemblyIdentity::new(
            "MainAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );
        assert!(neutral.is_culture_neutral());

        let localized = AssemblyIdentity::new(
            "Resources",
            AssemblyVersion::new(1, 0, 0, 0),
            Some("de-DE".to_string()),
            None,
            None,
        );
        assert!(!localized.is_culture_neutral());
    }

    #[test]
    fn test_assembly_identity_equality() {
        let id1 = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        let id2 = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        let id_different_version = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(2, 0, 0, 0),
            None,
            None,
            None,
        );

        let id_different_name = AssemblyIdentity::new(
            "OtherAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        assert_eq!(id1, id2);
        assert_ne!(id1, id_different_version);
        assert_ne!(id1, id_different_name);
    }

    #[test]
    fn test_assembly_identity_equality_ignores_strong_name_difference() {
        // Strong name differences should NOT affect equality
        // (as per the PartialEq implementation comment)
        let id_with_token = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            Some(Identity::Token([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            ])),
            None,
        );

        let id_without_token = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        // These should be equal because strong_name is excluded from equality
        assert_eq!(id_with_token, id_without_token);
    }

    #[test]
    fn test_assembly_identity_hash_consistency() {
        let id1 = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            Some(Identity::Token([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
            ])),
            None,
        );

        let id2 = AssemblyIdentity::new(
            "TestAssembly",
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None, // Different strong_name
            None,
        );

        // Since they are equal, they should hash to the same value
        // and work correctly as HashMap keys
        let mut map = HashMap::new();
        map.insert(id1.clone(), "value1");

        // Should find the same entry with id2 since they're equal
        assert!(map.contains_key(&id2));
    }

    #[test]
    fn test_assembly_identity_from_str() {
        let identity: AssemblyIdentity = "System.Core, Version=3.5.0.0".parse().unwrap();
        assert_eq!(identity.name, "System.Core");
        assert_eq!(identity.version, AssemblyVersion::new(3, 5, 0, 0));
    }

    #[test]
    fn test_assembly_identity_roundtrip_parse_display() {
        let original = AssemblyIdentity::new(
            "TestLib",
            AssemblyVersion::new(2, 1, 3, 4),
            None,
            None,
            Some(ProcessorArchitecture::AMD64),
        );

        let display = original.display_name();
        let parsed = AssemblyIdentity::parse(&display).unwrap();

        assert_eq!(original.name, parsed.name);
        assert_eq!(original.version, parsed.version);
        assert_eq!(original.culture, parsed.culture);
        assert_eq!(
            original.processor_architecture,
            parsed.processor_architecture
        );
    }

    #[test]
    fn test_assembly_identity_roundtrip_with_token() {
        // Test round-trip with a token-based strong name
        // The token value should be fully preserved through parse/display cycles
        let original = AssemblyIdentity::new(
            "StrongLib",
            AssemblyVersion::new(1, 2, 3, 4),
            Some("en-US".to_string()),
            Some(Identity::Token([
                0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89,
            ])),
            Some(ProcessorArchitecture::X86),
        );

        let display = original.display_name();
        let parsed = AssemblyIdentity::parse(&display).unwrap();

        assert_eq!(original.name, parsed.name);
        assert_eq!(original.version, parsed.version);
        assert_eq!(original.culture, parsed.culture);
        assert_eq!(
            original.processor_architecture,
            parsed.processor_architecture
        );

        // Strong name should be fully preserved
        assert_eq!(original.strong_name, parsed.strong_name);

        // Verify the display string is stable (same after multiple roundtrips)
        let display2 = parsed.display_name();
        assert_eq!(
            display, display2,
            "Display string should be stable across roundtrips"
        );

        // Parse again and verify everything is still equal
        let parsed2 = AssemblyIdentity::parse(&display2).unwrap();
        assert_eq!(parsed.strong_name, parsed2.strong_name);
    }

    #[test]
    fn test_assembly_identity_token_format_consistency() {
        // Test that tokens parsed from standard .NET format work correctly
        // The standard format is big-endian hex (e.g., "b77a5c561934e089")
        let identity = AssemblyIdentity::parse(
            "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        )
        .unwrap();

        // Verify the token was parsed
        assert!(identity.strong_name.is_some());
        if let Some(Identity::Token(token)) = identity.strong_name {
            // The token's bytes in the order the name shows them
            assert_eq!(token, [0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89]);
        }
    }

    #[test]
    fn test_assembly_identity_parse_extra_whitespace() {
        // Parts are trimmed, so extra whitespace around commas should work
        let identity = AssemblyIdentity::parse(
            "MyLib ,  Version=1.0.0.0 ,  Culture=neutral ,  PublicKeyToken=null",
        )
        .unwrap();

        assert_eq!(identity.name, "MyLib");
        assert_eq!(identity.version, AssemblyVersion::new(1, 0, 0, 0));
    }

    #[test]
    fn test_assembly_identity_parse_case_insensitive_culture() {
        // Culture value should be preserved as-is (case-sensitive)
        let identity = AssemblyIdentity::parse("MyLib, Version=1.0.0.0, Culture=EN-us").unwrap();
        assert_eq!(identity.culture, Some("EN-us".to_string()));
    }

    #[test]
    fn test_assembly_identity_parse_unknown_fields_ignored() {
        // Unknown fields should be silently ignored
        let identity =
            AssemblyIdentity::parse("MyLib, Version=1.0.0.0, UnknownField=value, Culture=neutral")
                .unwrap();

        assert_eq!(identity.name, "MyLib");
        assert_eq!(identity.version, AssemblyVersion::new(1, 0, 0, 0));
        assert!(identity.culture.is_none());
    }

    #[test]
    fn test_assembly_version_unknown_sentinel() {
        let unknown = AssemblyVersion::UNKNOWN;
        assert!(unknown.is_unknown());
        assert_eq!(unknown.major, 0);
        assert_eq!(unknown.minor, 0);
        assert_eq!(unknown.build, 0);
        assert_eq!(unknown.revision, 0);

        let not_unknown = AssemblyVersion::new(0, 0, 0, 1);
        assert!(!not_unknown.is_unknown());
    }

    #[test]
    fn test_processor_architecture_full_coverage() {
        // This test ensures all ProcessorArchitecture variants are covered by both
        // parse() and try_from(), and that Display outputs match parse() inputs.
        // If a new variant is added, this test will fail until both implementations
        // are updated.
        let all_variants = [
            (ProcessorArchitecture::MSIL, "MSIL", 0x0000_u32),
            (ProcessorArchitecture::X86, "x86", 0x014C),
            (ProcessorArchitecture::IA64, "IA64", 0x0200),
            (ProcessorArchitecture::AMD64, "AMD64", 0x8664),
            (ProcessorArchitecture::ARM, "ARM", 0x01C0),
            (ProcessorArchitecture::ARM64, "ARM64", 0xAA64),
        ];

        for (expected_arch, display_name, machine_code) in all_variants {
            // Test parse() accepts the display name (case-insensitive)
            let parsed = ProcessorArchitecture::parse(display_name)
                .unwrap_or_else(|_| panic!("Failed to parse '{}'", display_name));
            assert_eq!(
                parsed, expected_arch,
                "parse('{}') returned wrong variant",
                display_name
            );

            // Test parse() accepts lowercase version
            let parsed_lower = ProcessorArchitecture::parse(&display_name.to_lowercase())
                .unwrap_or_else(|_| panic!("Failed to parse lowercase '{}'", display_name));
            assert_eq!(
                parsed_lower, expected_arch,
                "parse('{}') lowercase returned wrong variant",
                display_name
            );

            // Test try_from() accepts the machine code
            let from_code = ProcessorArchitecture::try_from(machine_code)
                .unwrap_or_else(|_| panic!("Failed try_from(0x{:04X})", machine_code));
            assert_eq!(
                from_code, expected_arch,
                "try_from(0x{:04X}) returned wrong variant",
                machine_code
            );

            // Test Display outputs the expected name
            let displayed = expected_arch.to_string();
            // Display should output a name that can be parsed back
            let roundtrip = ProcessorArchitecture::parse(&displayed)
                .unwrap_or_else(|_| panic!("Failed to roundtrip '{}'", displayed));
            assert_eq!(
                roundtrip, expected_arch,
                "Display roundtrip failed for {:?}",
                expected_arch
            );
        }

        // Also test the x64 alias for AMD64
        let x64_parsed = ProcessorArchitecture::parse("x64").unwrap();
        assert_eq!(x64_parsed, ProcessorArchitecture::AMD64);
    }

    #[test]
    fn test_assembly_version_is_compatible_with() {
        let v4_0 = AssemblyVersion::new(4, 0, 0, 0);
        let v4_5 = AssemblyVersion::new(4, 5, 0, 0);
        let v4_5_1 = AssemblyVersion::new(4, 5, 1, 0);
        let v5_0 = AssemblyVersion::new(5, 0, 0, 0);
        let v_unknown = AssemblyVersion::UNKNOWN;

        // Same version is always compatible
        assert!(v4_0.is_compatible_with(&v4_0));
        assert!(v4_5.is_compatible_with(&v4_5));

        // Higher minor version is compatible with lower requirement (same major)
        assert!(v4_5.is_compatible_with(&v4_0));
        assert!(v4_5_1.is_compatible_with(&v4_0));
        assert!(v4_5_1.is_compatible_with(&v4_5));

        // Lower version is NOT compatible with higher requirement
        assert!(!v4_0.is_compatible_with(&v4_5));
        assert!(!v4_5.is_compatible_with(&v4_5_1));

        // Different major version is NOT compatible
        assert!(!v5_0.is_compatible_with(&v4_0));
        assert!(!v4_0.is_compatible_with(&v5_0));
        assert!(!v5_0.is_compatible_with(&v4_5));

        // Any version is compatible with unknown (0.0.0.0)
        assert!(v4_0.is_compatible_with(&v_unknown));
        assert!(v4_5.is_compatible_with(&v_unknown));
        assert!(v5_0.is_compatible_with(&v_unknown));
        assert!(v_unknown.is_compatible_with(&v_unknown));
    }

    #[test]
    fn test_assembly_identity_satisfies() {
        let system_core_v4_0 = AssemblyIdentity::new(
            "System.Core".to_string(),
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        let system_core_v4_5 = AssemblyIdentity::new(
            "System.Core".to_string(),
            AssemblyVersion::new(4, 5, 0, 0),
            None,
            None,
            None,
        );

        let system_core_v5_0 = AssemblyIdentity::new(
            "System.Core".to_string(),
            AssemblyVersion::new(5, 0, 0, 0),
            None,
            None,
            None,
        );

        let system_v4_0 = AssemblyIdentity::new(
            "System".to_string(),
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        // Same identity satisfies itself
        assert!(system_core_v4_0.satisfies(&system_core_v4_0));

        // Higher version satisfies lower requirement (same name)
        assert!(system_core_v4_5.satisfies(&system_core_v4_0));

        // Lower version does NOT satisfy higher requirement
        assert!(!system_core_v4_0.satisfies(&system_core_v4_5));

        // Different major version does NOT satisfy
        assert!(!system_core_v5_0.satisfies(&system_core_v4_0));

        // Different name does NOT satisfy
        assert!(!system_v4_0.satisfies(&system_core_v4_0));
        assert!(!system_core_v4_0.satisfies(&system_v4_0));
    }

    #[test]
    fn test_assembly_identity_satisfies_case_insensitive() {
        let lower = AssemblyIdentity::new(
            "system.core".to_string(),
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        let upper = AssemblyIdentity::new(
            "System.Core".to_string(),
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        let mixed = AssemblyIdentity::new(
            "SYSTEM.CORE".to_string(),
            AssemblyVersion::new(4, 0, 0, 0),
            None,
            None,
            None,
        );

        // Name comparison should be case-insensitive
        assert!(lower.satisfies(&upper));
        assert!(upper.satisfies(&lower));
        assert!(mixed.satisfies(&lower));
        assert!(lower.satisfies(&mixed));
    }

    #[test]
    fn test_assembly_identity_satisfies_culture() {
        let neutral = AssemblyIdentity::new(
            "MyLib".to_string(),
            AssemblyVersion::new(1, 0, 0, 0),
            None,
            None,
            None,
        );

        let en_us = AssemblyIdentity::new(
            "MyLib".to_string(),
            AssemblyVersion::new(1, 0, 0, 0),
            Some("en-US".to_string()),
            None,
            None,
        );

        let fr_fr = AssemblyIdentity::new(
            "MyLib".to_string(),
            AssemblyVersion::new(1, 0, 0, 0),
            Some("fr-FR".to_string()),
            None,
            None,
        );

        // Same culture satisfies
        assert!(neutral.satisfies(&neutral));
        assert!(en_us.satisfies(&en_us));

        // Different cultures do NOT satisfy
        assert!(!neutral.satisfies(&en_us));
        assert!(!en_us.satisfies(&neutral));
        assert!(!en_us.satisfies(&fr_fr));
    }
}

//! Assembly table module
//!
//! Provides complete support for the ECMA-335 Assembly metadata table (0x20), which contains
//! the identity and versioning information for the current assembly. This module includes
//! raw table access, resolved data structures, and collection types.
//!
//! # Components
//!
//! - [`crate::metadata::tables::assembly::AssemblyRaw`]: Raw table structure with unresolved heap indexes
//! - [`crate::metadata::tables::assembly::Assembly`]: Owned variant with resolved strings/blobs and full metadata
//! - [`crate::metadata::loader::tables::AssemblyLoader`]: Internal loader for processing Assembly table data
//! - Type aliases for efficient collections and reference management
//!
//! # Assembly Table Structure
//!
//! The Assembly table contains exactly one row (if present) with these fields:
//! - **`HashAlgId`**: Hash algorithm identifier (see [`crate::metadata::tables::assembly::AssemblyHashAlgorithm`])
//! - **Version**: Four-part version number (Major.Minor.Build.Revision)
//! - **Flags**: Assembly attributes (see [`crate::metadata::tables::assembly::AssemblyFlags`])
//! - **`PublicKey`**: Strong name public key for assembly verification
//! - **Name**: Simple assembly name (e.g., "System.Core")
//! - **Culture**: Localization culture (empty for culture-neutral assemblies)
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification
use std::{fmt, sync::Arc};

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

metadata_flags! {
    /// Hash algorithm identifier for assembly strong name signing.
    ///
    /// Specifies the algorithm used to hash the assembly's content for
    /// strong name verification. Defined in ECMA-335 II.23.1.1.
    pub struct HashAlgorithmId(u32);
}

impl HashAlgorithmId {
    /// No hash algorithm specified.
    pub const NONE: Self = Self(0x0000);
    /// MD5 message-digest algorithm (128-bit).
    pub const MD5: Self = Self(0x8003);
    /// SHA-1 secure hash algorithm (160-bit). Default for strong name signing.
    pub const SHA1: Self = Self(0x8004);
    /// SHA-256 secure hash algorithm (256-bit).
    pub const SHA256: Self = Self(0x800C);
    /// SHA-384 secure hash algorithm (384-bit).
    pub const SHA384: Self = Self(0x800D);
    /// SHA-512 secure hash algorithm (512-bit).
    pub const SHA512: Self = Self(0x800E);
}

impl fmt::Display for HashAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NONE => write!(f, "None"),
            Self::MD5 => write!(f, "MD5"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::SHA384 => write!(f, "SHA384"),
            Self::SHA512 => write!(f, "SHA512"),
            _ => write!(f, "0x{:08X}", self.bits()),
        }
    }
}

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assembly::Assembly`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved assembly references by their metadata tokens.
pub type AssemblyMap = SkipMap<Token, AssemblyRc>;

/// A vector that holds a list of [`crate::metadata::tables::assembly::Assembly`] references
///
/// Thread-safe append-only vector for storing assembly collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type AssemblyList = Arc<boxcar::Vec<AssemblyRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::assembly::Assembly`]
///
/// Provides shared ownership and automatic memory management for assembly instances.
/// Multiple references can safely point to the same assembly data across threads.
pub type AssemblyRc = Arc<Assembly>;

metadata_flags! {
    /// Assembly flags bit field
    ///
    /// Defines assembly-level attributes that control loading behavior, security requirements,
    /// and compatibility settings. These flags are stored in the Assembly table's Flags field
    /// and can be combined using bitwise OR operations.
    ///
    /// # Reference
    /// - [ECMA-335 II.23.1.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyFlags` enumeration
    pub struct AssemblyFlags(u32);
}

impl AssemblyFlags {
    /// The assembly reference holds the full (unhashed) public key
    ///
    /// When set, the `PublicKey` field contains the complete public key.
    /// When clear, the `PublicKey` field contains only the public key token (last 8 bytes of hash).
    pub const PUBLIC_KEY: Self = Self(0x0001);

    /// The implementation of this assembly used at runtime is not expected to match the version seen at compile time
    ///
    /// Allows the runtime to substitute a different version of this assembly if available.
    /// Commonly used for platform assemblies that may have runtime-specific implementations.
    pub const RETARGETABLE: Self = Self(0x0100);

    /// Processor architecture mask (bits 4-6).
    pub const PA_MASK: Self = Self(0x0070);
    /// MSIL (architecture-neutral) processor architecture.
    pub const PA_MSIL: Self = Self(0x0010);
    /// x86 (32-bit Intel) processor architecture.
    pub const PA_X86: Self = Self(0x0020);
    /// Reserved (IA-64) processor architecture.
    pub const PA_IA64: Self = Self(0x0030);
    /// AMD64 (x86-64) processor architecture.
    pub const PA_AMD64: Self = Self(0x0040);
    /// ARM processor architecture.
    pub const PA_ARM: Self = Self(0x0050);
    /// ARM64 processor architecture.
    pub const PA_ARM64: Self = Self(0x0060);
    /// No platform specified flag (bit 7).
    pub const PA_NO_PLATFORM: Self = Self(0x0070);

    /// Content type mask (bits 9-11).
    pub const CONTENT_TYPE_MASK: Self = Self(0x0E00);
    /// Windows Runtime assembly content type.
    pub const CONTENT_TYPE_WINDOWS_RUNTIME: Self = Self(0x0200);

    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    ///
    /// Legacy flag for JIT compiler optimization control. Modern runtimes typically ignore this setting.
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: Self = Self(0x4000);

    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    ///
    /// Legacy flag for JIT compiler tracking control. Modern runtimes typically ignore this setting.
    pub const ENABLE_JIT_COMPILE_TRACKING: Self = Self(0x8000);

    /// Extract the processor architecture bits from the flags.
    #[inline]
    #[must_use]
    pub const fn processor_architecture(self) -> Self {
        Self(self.0 & Self::PA_MASK.0)
    }

    /// Extract the content type bits from the flags.
    #[inline]
    #[must_use]
    pub const fn content_type(self) -> Self {
        Self(self.0 & Self::CONTENT_TYPE_MASK.0)
    }

    /// Return the ILAsm keyword for the processor architecture.
    #[must_use]
    pub fn processor_architecture_keyword(self) -> &'static str {
        match self.processor_architecture() {
            Self::PA_MSIL => "cil",
            Self::PA_X86 => "x86",
            Self::PA_IA64 => "ia64",
            Self::PA_AMD64 => "amd64",
            Self::PA_ARM => "arm",
            Self::PA_ARM64 => "arm64",
            Self::PA_NO_PLATFORM => "noplatform",
            _ => "",
        }
    }
}

impl fmt::Display for AssemblyFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::PUBLIC_KEY) {
            parts.push("PublicKey");
        }
        if self.contains(Self::RETARGETABLE) {
            parts.push("Retargetable");
        }
        if self.contains(Self::DISABLE_JIT_COMPILE_OPTIMIZER) {
            parts.push("DisableJITOptimizer");
        }
        if self.contains(Self::ENABLE_JIT_COMPILE_TRACKING) {
            parts.push("EnableJITTracking");
        }
        if parts.is_empty() {
            write!(f, "None")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[allow(non_snake_case)]
/// Assembly hash algorithm constants
///
/// Defines cryptographic hash algorithms used for assembly integrity verification.
/// The hash algorithm is specified in the Assembly table's `HashAlgId` field and
/// determines how file hashes in the manifest are computed.
///
/// # Security Note
///
/// MD5 is considered cryptographically weak and should not be used for new assemblies.
/// SHA1 is also deprecated for security purposes. Modern assemblies should use stronger
/// hash algorithms, though ECMA-335 hasn't been updated to reflect this.
///
/// # Reference
/// - [ECMA-335 II.23.1.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyHashAlgorithm` enumeration
///
/// Note: Microsoft has extended this enumeration beyond ECMA-335 to include SHA-2 family algorithms.
pub mod AssemblyHashAlgorithm {
    /// No hash algorithm specified
    ///
    /// Indicates that no file integrity checking should be performed.
    /// This is appropriate for assemblies that don't require verification.
    pub const NONE: u32 = 0x0000;

    /// MD5 hash algorithm (RFC 1321)
    ///
    /// **Security Warning**: MD5 is cryptographically broken and should not be used
    /// for security-sensitive applications. Included for compatibility with legacy assemblies.
    pub const MD5: u32 = 0x8003;

    /// SHA1 hash algorithm (FIPS 180-1)
    ///
    /// **Security Warning**: SHA1 is deprecated due to known collision vulnerabilities.
    /// While stronger than MD5, it should be avoided for new assemblies.
    pub const SHA1: u32 = 0x8004;

    /// SHA256 hash algorithm (FIPS 180-2)
    ///
    /// Modern secure hash algorithm. Recommended for new assemblies.
    /// Supported in .NET Framework 4.5+ and all .NET Core/.NET 5+ versions.
    pub const SHA256: u32 = 0x800C;

    /// SHA384 hash algorithm (FIPS 180-2)
    ///
    /// Modern secure hash algorithm with 384-bit output.
    /// Supported in .NET Framework 4.5+ and all .NET Core/.NET 5+ versions.
    pub const SHA384: u32 = 0x800D;

    /// SHA512 hash algorithm (FIPS 180-2)
    ///
    /// Modern secure hash algorithm with 512-bit output.
    /// Supported in .NET Framework 4.5+ and all .NET Core/.NET 5+ versions.
    pub const SHA512: u32 = 0x800E;
}

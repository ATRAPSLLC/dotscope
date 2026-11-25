//! Assembly identity and cryptographic verification for .NET assemblies.
//!
//! This module provides comprehensive identity management for .NET assemblies,
//! supporting both cryptographic verification and multi-assembly identification.
//! It serves as the foundation for cross-assembly resolution, dependency tracking,
//! and multi-assembly project management.
//!
//! # ECMA-335 References
//!
//! This module implements identity concepts defined in the ECMA-335 specification:
//! - **Section II.6.3**: Referencing assemblies - defines assembly reference format
//! - **Section II.22.2**: Assembly table - defines assembly metadata structure
//! - **Section II.22.5**: AssemblyRef table - defines assembly reference structure
//! - **Section II.6.2.1.3**: PublicKeyToken - defines public key token computation
//!
//! See: <https://ecma-international.org/publications-and-standards/standards/ecma-335/>
//!
//! # Module Structure
//!
//! - `assembly` - Complete assembly identity with name, version, culture, and strong name
//! - `cryptographic` - Cryptographic identity and verification (public keys and tokens)
//!
//! # Key Components
//!
//! ## Assembly Identity
//! - [`AssemblyIdentity`](crate::metadata::identity::AssemblyIdentity) - Complete assembly identification for multi-assembly scenarios
//! - [`AssemblyVersion`](crate::metadata::identity::AssemblyVersion) - Four-part version numbering with parsing and comparison
//! - [`ProcessorArchitecture`](crate::metadata::identity::ProcessorArchitecture) - Processor architecture specification
//!
//! ## Cryptographic Identity
//! - [`Identity`](crate::metadata::identity::Identity) - Public key and token-based cryptographic identity
//! - Strong name verification and token generation
//! - Support for MD5, SHA1, and custom hash algorithms
//!
//! # Usage Examples
//!
//! ## Assembly Identity Management
//!
//! ```rust,no_run
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//!
//! // Create assembly identity
//! let identity = AssemblyIdentity::new(
//!     "MyLibrary",
//!     AssemblyVersion::new(1, 0, 0, 0),
//!     None, // culture-neutral
//!     None, // no strong name
//!     None, // architecture-neutral
//! );
//!
//! // Parse from display name
//! let mscorlib = AssemblyIdentity::parse(
//!     "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Cryptographic Verification
//!
//! ```rust,no_run
//! use dotscope::metadata::identity::Identity;
//! use dotscope::metadata::tables::AssemblyHashAlgorithm;
//!
//! // Create identity from public key
//! let pubkey_data = vec![0x30, 0x82, 0x01, 0x0A]; // RSA public key
//! let identity = Identity::from(&pubkey_data, true)?;
//!
//! // Generate public key token
//! let token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
//! println!("Public key token: {:02x?}", token);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Integration with Metadata
//!
//! ```
//! use dotscope::metadata::dependencies::{
//!     AssemblyDependency, AssemblyDependencyGraph, DependencyResolutionState, DependencySource,
//!     DependencyType, VersionRequirement,
//! };
//! use dotscope::metadata::identity::AssemblyIdentity;
//! use dotscope::CilObject;
//!
//! // Extract identities from metadata: the assembly's own, and each it references
//! let assembly = CilObject::from_path("tests/samples/crafted_2.exe")?;
//! let source_identity =
//!     AssemblyIdentity::from_assembly(assembly.assembly().expect("an assembly manifest"));
//!
//! // Use in dependency tracking
//! let dependency_graph = AssemblyDependencyGraph::new();
//! for entry in assembly.refs_assembly() {
//!     let assembly_ref = entry.value().clone();
//!     let dependency = AssemblyDependency {
//!         target_identity: AssemblyIdentity::from_assembly_ref(&assembly_ref),
//!         source: DependencySource::AssemblyRef(assembly_ref),
//!         dependency_type: DependencyType::Reference,
//!         version_requirement: VersionRequirement::Compatible,
//!         is_optional: false,
//!         resolution_state: DependencyResolutionState::Unresolved,
//!     };
//!     dependency_graph.add_dependency_with_source(&source_identity, dependency)?;
//! }
//! assert_eq!(dependency_graph.dependency_count(), assembly.refs_assembly().len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration with CilProject
//!
//! This identity system provides the foundation for:
//! - **Multi-assembly containers** in CilProject
//! - **Cross-assembly type resolution** in GlobalTypeResolver
//! - **Dependency tracking and analysis** in AssemblyDependencyGraph
//! - **Version binding and compatibility** analysis
//! - **Assembly loading and management** strategies
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and can be safely shared across
//! threads. Assembly identities serve as keys in concurrent collections and
//! participate in lock-free data structures throughout the system.

pub use assembly::{AssemblyIdentity, AssemblyVersion, ProcessorArchitecture};
pub use cryptographic::Identity;

mod assembly;
mod cryptographic;

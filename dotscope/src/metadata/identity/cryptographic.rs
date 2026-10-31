//! Assembly identity and verification for .NET CIL assemblies.
//!
//! This module provides cryptographic identity representation and verification for .NET assemblies
//! according to ECMA-335 specifications. It supports both full public key storage and compact
//! token-based identity through standardized hashing algorithms (MD5, SHA1).
//!
//! # ECMA-335 References
//!
//! - **Section II.6.2.1.3**: PublicKeyToken - defines how tokens are computed from public keys
//! - **Section II.6.3**: Referencing assemblies - describes strong name verification
//! - **Section II.22.2**: Assembly.HashAlgId - defines supported hash algorithm identifiers
//!
//! # Identity Types
//!
//! .NET assemblies can be identified in two ways:
//! - **Public Key**: Full RSA public key data for strong-named assemblies
//! - **Public Key Token**: 8-byte hash of the public key for compact representation
//!
//! # Supported Hash Algorithms
//!
//! - **MD5**: Legacy hash algorithm (0x8003) still supported for compatibility
//! - **SHA1**: Standard hash algorithm (0x8004) used by most .NET tools
//! - **Custom**: Framework for additional algorithms (future extension)
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::identity::Identity;
//! use dotscope::metadata::tables::AssemblyHashAlgorithm;
//!
//! // Create identity from public key
//! let pubkey_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
//! let identity = Identity::from(&pubkey_data, true)?;
//!
//! // Generate token using SHA1
//! let token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
//! println!("Public key token: {:02x?}", token);
//!
//! // Create identity directly from token
//! let token_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
//! let token_identity = Identity::from(&token_data, false)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Security Considerations
//!
//! - **Strong Naming**: Public keys provide cryptographic verification of assembly integrity
//! - **Token Collision**: 8-byte tokens may have collisions but are sufficient for most use cases
//! - **Algorithm Choice**: SHA1 is recommended over MD5 for new assemblies
//!
//! # Thread Safety
//!
//! All types and functions in this module are thread-safe. The [`crate::metadata::identity::Identity`]
//! enum contains only owned data and is [`std::marker::Send`] and [`std::marker::Sync`].
//! Hashing operations are stateless and can be called concurrently from multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Assembly and AssemblyRef table identity verification
//! - Binary data reading utilities for key material parsing
//! - External cryptographic libraries (`md5`, `sha1`) for token generation
//!
//! # Assembly Loading
//!
//! The .NET runtime uses assembly identity for:
//! - Version resolution and binding policies
//! - Security policy enforcement
//! - Global Assembly Cache (GAC) storage and retrieval
//! - Type loading and assembly isolation
//! - Cross-assembly type reference resolution

#[cfg(feature = "legacy-crypto")]
use crate::utils::{compute_md5, compute_sha1};
use crate::{
    metadata::tables::AssemblyHashAlgorithm,
    utils::{compute_sha256, compute_sha384, compute_sha512},
    ParseFailure, ParseStage, Result,
};

/// Assembly identity representation for .NET CIL assemblies.
///
/// Represents the cryptographic identity of a .NET assembly using one of three standardized
/// identity mechanisms defined by ECMA-335. This enum supports all primary assembly
/// identification types used throughout the .NET ecosystem.
///
/// # Variants
///
/// - [`Identity::PubKey`]: Stores the complete RSA public key data for strong-named assemblies
/// - [`Identity::Token`]: Stores an 8-byte hash of the public key for compact representation
/// - [`Identity::EcmaKey`]: Stores a 16-byte ECMA key used by framework assemblies
///
/// # Usage in .NET
///
/// - **Strong-named assemblies**: Use public keys for cryptographic verification
/// - **Assembly references**: Often use tokens for compact storage in metadata
/// - **GAC storage**: Uses tokens as part of the unique assembly identifier
/// - **Security policies**: May require full public key validation
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::identity::Identity;
/// use dotscope::metadata::tables::AssemblyHashAlgorithm;
///
/// // Full public key identity
/// let pubkey_data = vec![0x30, 0x82, 0x01, 0x0A]; // RSA public key start
/// let identity = Identity::from(&pubkey_data, true)?;
///
/// // Generate token for compact representation
/// match identity {
///     Identity::PubKey(ref key_data) => {
///         let token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
///         println!("Key length: {} bytes, Token: {:02x?}", key_data.len(), token);
///     }
///     Identity::Token(token) => {
///         println!("Direct token: {:02x?}", token);
///     }
///     _ => {}
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    /// Complete RSA public key data for strong-named assemblies.
    ///
    /// Contains the full binary representation of an RSA public key as stored in .NET
    /// assembly metadata. This data can be used for cryptographic verification of
    /// assembly signatures and strong name validation.
    ///
    /// # Format
    /// The data typically follows the standard RSA public key format used by .NET:
    /// - ASN.1 DER encoding for the public key structure
    /// - May include additional .NET-specific metadata
    /// - Variable length depending on key size (typically 1024-4096 bits)
    PubKey(Vec<u8>),

    /// Compact 8-byte token derived from hashing the public key.
    ///
    /// The bytes are in the order metadata stores them and .NET prints them: the ECMA
    /// key's token `b77a5c561934e089` is `[0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89]`.
    ///
    /// # Token Generation
    /// 1. Hash the complete public key using the specified algorithm
    /// 2. Take the last 8 bytes of the hash result
    /// 3. Reverse them
    ///
    /// # Collision Resistance
    /// While 8 bytes provides only 64 bits of collision resistance, this is
    /// considered sufficient for .NET assembly identification in practice.
    Token([u8; 8]),

    /// ECMA standard 16-byte key for framework assemblies.
    ///
    /// ECMA keys are special shortened cryptographic identities used by core
    /// framework assemblies as defined in ECMA-335. These 16-byte keys provide
    /// a standardized identity mechanism for system assemblies while being more
    /// compact than full RSA public keys.
    ///
    /// # Usage Context
    /// - **Framework assemblies**: mscorlib, System.Core, System.dll, etc.
    /// - **Standard libraries**: Core .NET framework components
    /// - **Platform assemblies**: Mono framework assemblies
    /// - **Compatibility**: Legacy and cross-platform .NET implementations
    ///
    /// # Format
    /// ECMA keys are exactly 16 bytes in length and follow the ECMA-335 specification
    /// for standard assembly identification. Unlike full public keys, they cannot
    /// be used for cryptographic verification but provide reliable assembly identification.
    ///
    /// # Examples
    /// Common ECMA key patterns found in framework assemblies:
    /// - Fixed byte sequences for standard framework components
    /// - Platform-specific variations for Mono/Unity implementations
    /// - Standardized keys for cross-platform compatibility
    EcmaKey(Vec<u8>),
}

impl Identity {
    /// Create an [`Identity`] from raw binary data.
    ///
    /// Constructs the appropriate identity type based on data length and the `is_pub` flag.
    /// This method automatically detects ECMA keys and provides the primary constructor
    /// for identity objects parsed from .NET metadata.
    ///
    /// # Arguments
    /// * `data` - Raw binary data from assembly metadata
    /// * `is_pub` - `true` for public key data, `false` for token data
    ///
    /// # Detection Logic
    /// - **8 bytes + `is_pub=false`**: [`Identity::Token`] (standard token)
    /// - **16 bytes + `is_pub=true`**: [`Identity::EcmaKey`] (ECMA framework key)
    /// - **Other sizes + `is_pub=true`**: [`Identity::PubKey`] (full RSA public key)
    ///
    /// # Returns
    /// - [`Identity::Token`] for 8-byte token data
    /// - [`Identity::EcmaKey`] for 16-byte ECMA keys
    /// - [`Identity::PubKey`] for other public key sizes
    ///
    /// # Errors
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if:
    /// - Token creation requested but data has fewer than 8 bytes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::Identity;
    ///
    /// // Create full RSA public key identity (>16 bytes)
    /// let pubkey_data = vec![0x30, 0x82, 0x01, 0x0A, /* ... rest of 160+ byte key ... */];
    /// let pubkey_identity = Identity::from(&pubkey_data, true)?;
    ///
    /// // Create ECMA key identity (exactly 16 bytes)
    /// let ecma_data = vec![0x06, 0x28, 0xAC, 0x03, 0x00, 0x06, 0x7A, 0x06,
    ///                      0x6F, 0xAB, 0x02, 0x00, 0x0A, 0x0B, 0x17, 0x6A];
    /// let ecma_identity = Identity::from(&ecma_data, true)?;
    ///
    /// // Create token identity (8 bytes)
    /// let token_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    /// let token_identity = Identity::from(&token_data, false)?;
    ///
    /// match ecma_identity {
    ///     Identity::EcmaKey(ref key) => println!("ECMA key: {} bytes", key.len()),
    ///     Identity::PubKey(ref key) => println!("Public key: {} bytes", key.len()),
    ///     Identity::Token(token) => println!("Token: {:02x?}", token),
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from(data: &[u8], is_pub: bool) -> Result<Self> {
        Ok(if is_pub {
            match data.len() {
                16 => Identity::EcmaKey(data.to_vec()),
                _ => Identity::PubKey(data.to_vec()),
            }
        } else {
            let token = data.first_chunk::<8>().ok_or(ParseFailure::Truncated {
                stage: ParseStage::Generic,
                expected: 8,
                found: data.len(),
            })?;
            Identity::Token(*token)
        })
    }

    /// Generate a token from this identity using the specified hash algorithm.
    ///
    /// Computes an 8-byte token that uniquely identifies this assembly. For public key
    /// identities, this involves hashing the key data. For token identities, this
    /// returns the stored token value regardless of the algorithm specified.
    ///
    /// # Algorithm Support
    /// - **MD5** ([`crate::metadata::tables::AssemblyHashAlgorithm::MD5`]): Legacy algorithm, 16-byte hash
    /// - **SHA1** ([`crate::metadata::tables::AssemblyHashAlgorithm::SHA1`]): Standard algorithm, 20-byte hash
    /// - **Others**: Returns an error for unsupported algorithms
    ///
    /// # Token Extraction
    /// The token is the **last 8 bytes** of the hash result in reverse order, as the .NET
    /// runtime computes it: the ECMA key's token is `b77a5c561934e089`.
    ///
    /// # Arguments
    /// * `algo` - Hash algorithm identifier from [`crate::metadata::tables::AssemblyHashAlgorithm`]
    ///
    /// # Returns
    /// The 8 token bytes, in the order .NET prints them.
    ///
    /// # Errors
    /// Returns an error if the hash algorithm is not supported.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::identity::Identity;
    /// use dotscope::metadata::tables::AssemblyHashAlgorithm;
    ///
    /// let pubkey_data = vec![0x30, 0x82, /* ... public key data ... */];
    /// let identity = Identity::from(&pubkey_data, true)?;
    ///
    /// // Generate token using SHA1 (recommended)
    /// let sha1_token = identity.to_token(AssemblyHashAlgorithm::SHA1)?;
    /// println!("SHA1 token: {:02x?}", sha1_token);
    ///
    /// // Generate token using MD5 (legacy)
    /// let md5_token = identity.to_token(AssemblyHashAlgorithm::MD5)?;
    /// println!("MD5 token: {:02x?}", md5_token);
    ///
    /// // Different algorithms produce different tokens
    /// assert_ne!(sha1_token, md5_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Hash operations are stateless and do not modify the identity instance.
    pub fn to_token(&self, algo: u32) -> Result<[u8; 8]> {
        match &self {
            Identity::PubKey(data) | Identity::EcmaKey(data) => {
                Self::compute_token_from_data(data, algo)
            }
            Identity::Token(token) => Ok(*token),
        }
    }

    /// Compute a token from raw key data using the specified hash algorithm.
    ///
    /// This is a helper method that performs the actual hashing operation for
    /// public key and ECMA key data. The token is the last 8 bytes of the hash result,
    /// reversed.
    ///
    /// # Arguments
    /// * `data` - Raw key data to hash
    /// * `algo` - Hash algorithm identifier from [`AssemblyHashAlgorithm`]
    ///
    /// # Returns
    /// The 8 token bytes derived from the hash.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The hash algorithm is not supported
    /// - The `legacy-crypto` feature is disabled and MD5/SHA1 is requested
    fn compute_token_from_data(data: &[u8], algo: u32) -> Result<[u8; 8]> {
        let hash = match algo {
            #[cfg(feature = "legacy-crypto")]
            AssemblyHashAlgorithm::MD5 => compute_md5(data),
            #[cfg(feature = "legacy-crypto")]
            AssemblyHashAlgorithm::SHA1 => compute_sha1(data),
            #[cfg(not(feature = "legacy-crypto"))]
            AssemblyHashAlgorithm::MD5 | AssemblyHashAlgorithm::SHA1 => {
                return Err(malformed_error!(
                    "Hash algorithm 0x{:08X} requires the 'legacy-crypto' feature. \
                     Compile with `features = [\"legacy-crypto\"]` to enable MD5/SHA1 support.",
                    algo
                ));
            }
            AssemblyHashAlgorithm::SHA256 => compute_sha256(data),
            AssemblyHashAlgorithm::SHA384 => compute_sha384(data),
            AssemblyHashAlgorithm::SHA512 => compute_sha512(data),
            _ => {
                return Err(malformed_error!(
                    "Unsupported hash algorithm: 0x{:08X}",
                    algo
                ));
            }
        };
        // The token is the hash's last 8 bytes, reversed
        let mut token = *hash.last_chunk::<8>().ok_or(ParseFailure::Truncated {
            stage: ParseStage::Generic,
            expected: 8,
            found: hash.len(),
        })?;
        token.reverse();
        Ok(token)
    }
}

#[cfg(all(test, feature = "legacy-crypto"))]
mod tests {
    use super::*;
    use crate::metadata::tables::AssemblyHashAlgorithm;

    /// A hash's last 8 bytes, reversed: how .NET derives a token from it.
    fn reversed(tail: &[u8]) -> [u8; 8] {
        let mut token: [u8; 8] = tail.try_into().unwrap();
        token.reverse();
        token
    }

    /// The ECMA standard key's token is the one every framework reference carries,
    /// `b77a5c561934e089`, in the order .NET prints it.
    #[cfg(feature = "legacy-crypto")]
    #[test]
    fn the_ecma_key_token_is_b77a5c561934e089() {
        let ecma = Identity::from(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0], true).unwrap();
        assert!(matches!(ecma, Identity::EcmaKey(_)));
        assert_eq!(
            ecma.to_token(AssemblyHashAlgorithm::SHA1).unwrap(),
            [0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89]
        );
    }

    #[test]
    fn test_identity_from_pubkey() {
        // Use more than 16 bytes to ensure PubKey variant (not EcmaKey)
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let identity = Identity::from(&data, true).unwrap();

        let Identity::PubKey(pubkey_data) = identity else {
            panic!("Expected PubKey variant, got {:?}", identity);
        };
        assert_eq!(pubkey_data, data);
    }

    #[test]
    fn test_identity_from_ecma_key() {
        // Exactly 16 bytes should create EcmaKey variant
        let data = vec![
            0x06, 0x28, 0xAC, 0x03, 0x00, 0x06, 0x7A, 0x06, 0x6F, 0xAB, 0x02, 0x00, 0x0A, 0x0B,
            0x17, 0x6A,
        ];
        let identity = Identity::from(&data, true).unwrap();

        let Identity::EcmaKey(ecma_data) = identity else {
            panic!("Expected EcmaKey variant, got {:?}", identity);
        };
        assert_eq!(ecma_data, data);
        assert_eq!(ecma_data.len(), 16);
    }

    #[test]
    fn test_identity_from_token() {
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let identity = Identity::from(&data, false).unwrap();

        let Identity::Token(token) = identity else {
            panic!("Expected Token variant, got {:?}", identity);
        };
        // The token is the bytes as stored
        assert_eq!(token, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    }

    #[test]
    fn test_identity_from_empty_pubkey() {
        let data = vec![];
        let identity = Identity::from(&data, true).unwrap();

        let Identity::PubKey(pubkey_data) = identity else {
            panic!("Expected PubKey variant, got {:?}", identity);
        };
        assert!(pubkey_data.is_empty());
    }

    #[test]
    fn test_identity_from_token_insufficient_data() {
        let data = vec![1, 2, 3]; // Less than 8 bytes
        let result = Identity::from(&data, false);

        // A token is 8 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_to_token_from_pubkey_md5() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // Verify using centralized hash function
        let result = compute_md5(&pubkey_data);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_pubkey_sha1() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // Verify using centralized hash function
        let result = compute_sha1(&pubkey_data);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_pubkey_sha256() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::SHA256).unwrap();

        // Verify using centralized hash function
        let result = compute_sha256(&pubkey_data);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_pubkey_sha384() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::SHA384).unwrap();

        // Verify using centralized hash function
        let result = compute_sha384(&pubkey_data);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_pubkey_sha512() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let identity = Identity::PubKey(pubkey_data.clone());

        let token = identity.to_token(AssemblyHashAlgorithm::SHA512).unwrap();

        // Verify using centralized hash function
        let result = compute_sha512(&pubkey_data);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_from_token_identity() {
        let original_token = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let identity = Identity::Token(original_token);

        // When called on a Token identity, should return the original token regardless of algorithm
        let result_md5 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let result_sha1 = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();
        let result_none = identity.to_token(AssemblyHashAlgorithm::NONE).unwrap();

        assert_eq!(result_md5, original_token);
        assert_eq!(result_sha1, original_token);
        assert_eq!(result_none, original_token);
    }

    #[test]
    fn test_to_token_unsupported_algorithm() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let identity = Identity::PubKey(pubkey_data);

        // Using an unsupported algorithm should return an error
        let result = identity.to_token(0x9999);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Unsupported hash algorithm"),
            "Error message should mention unsupported algorithm: {}",
            err_msg
        );
    }

    #[test]
    fn test_to_token_unsupported_algorithm_ecma_key() {
        // Test that EcmaKey also returns an error for unsupported algorithms
        let ecma_data = vec![
            0x06, 0x28, 0xAC, 0x03, 0x00, 0x06, 0x7A, 0x06, 0x6F, 0xAB, 0x02, 0x00, 0x0A, 0x0B,
            0x17, 0x6A,
        ];
        let identity = Identity::EcmaKey(ecma_data);

        let result = identity.to_token(0x9999);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_token_empty_pubkey_md5() {
        let identity = Identity::PubKey(vec![]);
        let token = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // Hash of empty data should still produce a valid token
        let result = compute_md5(&[]);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_to_token_empty_pubkey_sha1() {
        let identity = Identity::PubKey(vec![]);
        let token = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // Hash of empty data should still produce a valid token
        let result = compute_sha1(&[]);
        let last_8_bytes = &result[result.len() - 8..];
        let expected_token = reversed(last_8_bytes);

        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_large_pubkey_data() {
        // Test with a larger public key (typical RSA key size)
        let large_pubkey: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let identity = Identity::PubKey(large_pubkey.clone());

        let token_md5 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let token_sha1 = identity.to_token(AssemblyHashAlgorithm::SHA1).unwrap();

        // MD5 and SHA1 should produce different tokens for the same data
        assert_ne!(token_md5, token_sha1);

        // Both tokens should be valid (non-zero in this case since we have substantial input data)
        assert_ne!(token_md5, [0; 8]);
        assert_ne!(token_sha1, [0; 8]);
    }

    #[test]
    fn test_hash_algorithm_consistency() {
        let pubkey_data = vec![42, 123, 255, 0, 17, 88, 99, 200];
        let identity = Identity::PubKey(pubkey_data);

        // Multiple calls with the same algorithm should produce the same result
        let token1 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();
        let token2 = identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        assert_eq!(token1, token2);
    }

    #[test]
    fn test_from_exact_8_bytes() {
        let data = vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88];
        let identity = Identity::from(&data, false).unwrap();

        match identity {
            Identity::Token(token) => {
                // Exactly the 8 bytes, as stored
                assert_eq!(token, [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88]);
            }
            Identity::PubKey(_) => panic!("Expected Token variant"),
            Identity::EcmaKey(_) => panic!("Expected Token variant"),
        }
    }

    #[test]
    fn test_from_more_than_8_bytes_token() {
        // When creating a token from more than 8 bytes, only the first 8 should be used
        let data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let identity = Identity::from(&data, false).unwrap();

        match identity {
            Identity::Token(token) => {
                // Should only use the first 8 bytes
                assert_eq!(token, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            }
            Identity::PubKey(_) => panic!("Expected Token variant"),
            Identity::EcmaKey(_) => panic!("Expected Token variant"),
        }
    }

    #[test]
    fn test_identity_variants_different_behavior() {
        let pubkey_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let pubkey_identity = Identity::from(&pubkey_data, true).unwrap();
        let token_identity = Identity::from(&pubkey_data, false).unwrap();

        // The PubKey identity will hash the data
        let pubkey_token = pubkey_identity
            .to_token(AssemblyHashAlgorithm::MD5)
            .unwrap();

        // The Token identity will return the direct interpretation
        let direct_token = token_identity.to_token(AssemblyHashAlgorithm::MD5).unwrap();

        // These should be different values
        assert_ne!(pubkey_token, direct_token);
    }
}

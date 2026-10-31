//! Cryptographic utilities for deobfuscation and .NET compatibility.
//!
//! This module provides implementations of cryptographic functions used by .NET's
//! cryptographic primitives. These are essential for deobfuscation scenarios where
//! protected code uses encryption to hide payloads, as well as for assembly identity
//! verification and hash computation.
//!
//! # Hash Functions
//!
//! - **MD5** (128-bit, legacy) - Used for assembly hash verification
//! - **SHA1** (160-bit, legacy) - Used for public key tokens and assembly verification
//! - **SHA256/384/512** - Modern hash algorithms for assembly verification
//!
//! # Key Derivation
//!
//! - **PBKDF2** (RFC 2898 Section 5.2) - Used by `Rfc2898DeriveBytes`
//! - **PBKDF1** (RFC 2898 Section 5.1) - Used by `PasswordDeriveBytes`
//!
//! # Symmetric Encryption
//!
//! - **AES** (128/192/256-bit CBC mode with PKCS7 padding)
//! - **DES** (56-bit CBC mode with PKCS7 padding)
//! - **TripleDES** (168-bit CBC mode with PKCS7 padding)

#[cfg(feature = "emulation")]
use std::iter::repeat_n;

#[cfg(feature = "emulation")]
use aes::Aes128;
#[cfg(feature = "emulation")]
use cbc::{
    cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    },
    Decryptor, Encryptor,
};
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
use des::{Des, TdesEde3};
#[cfg(feature = "emulation")]
use ecb::{Decryptor as EcbDecryptor, Encryptor as EcbEncryptor};
#[cfg(feature = "emulation")]
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
#[cfg(feature = "legacy-crypto")]
use md5::{Digest as Md5Digest, Md5};
#[cfg(feature = "emulation")]
use num_bigint::BigUint;
#[cfg(feature = "emulation")]
use pbkdf2::pbkdf2_hmac;
#[cfg(feature = "legacy-crypto")]
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};

#[cfg(feature = "emulation")]
use crate::{Error::TypeError, Result};

// Type aliases for AES CBC modes
#[cfg(feature = "emulation")]
type Aes128CbcEnc = Encryptor<Aes128>;
#[cfg(feature = "emulation")]
type Aes128CbcDec = Decryptor<Aes128>;
#[cfg(feature = "emulation")]
type Aes192CbcEnc = Encryptor<aes::Aes192>;
#[cfg(feature = "emulation")]
type Aes192CbcDec = Decryptor<aes::Aes192>;
#[cfg(feature = "emulation")]
type Aes256CbcEnc = Encryptor<aes::Aes256>;
#[cfg(feature = "emulation")]
type Aes256CbcDec = Decryptor<aes::Aes256>;

// Type aliases for AES ECB modes
#[cfg(feature = "emulation")]
type Aes128EcbEnc = EcbEncryptor<Aes128>;
#[cfg(feature = "emulation")]
type Aes128EcbDec = EcbDecryptor<Aes128>;
#[cfg(feature = "emulation")]
type Aes192EcbEnc = EcbEncryptor<aes::Aes192>;
#[cfg(feature = "emulation")]
type Aes192EcbDec = EcbDecryptor<aes::Aes192>;
#[cfg(feature = "emulation")]
type Aes256EcbEnc = EcbEncryptor<aes::Aes256>;
#[cfg(feature = "emulation")]
type Aes256EcbDec = EcbDecryptor<aes::Aes256>;

// Type aliases for DES CBC modes (legacy-crypto feature)
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type DesCbcEnc = Encryptor<Des>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type DesCbcDec = Decryptor<Des>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type TdesCbcEnc = Encryptor<TdesEde3>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type TdesCbcDec = Decryptor<TdesEde3>;

// Type aliases for DES ECB modes (legacy-crypto feature)
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type DesEcbEnc = EcbEncryptor<Des>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type DesEcbDec = EcbDecryptor<Des>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type TdesEcbEnc = EcbEncryptor<TdesEde3>;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
type TdesEcbDec = EcbDecryptor<TdesEde3>;

/// Computes the MD5 hash of input bytes.
///
/// **Security Warning**: MD5 is cryptographically broken and should not be used
/// for security purposes. This function exists for compatibility with legacy
/// .NET assemblies and forensic analysis.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 16-byte vector containing the MD5 hash.
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature.
#[cfg(feature = "legacy-crypto")]
#[must_use]
pub fn compute_md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-1 hash of input bytes.
///
/// **Security Warning**: SHA-1 is cryptographically broken and should not be used
/// for security purposes. This function exists for compatibility with legacy
/// .NET assemblies (public key tokens, assembly verification) and forensic analysis.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 20-byte vector containing the SHA-1 hash.
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature.
#[cfg(feature = "legacy-crypto")]
#[must_use]
pub fn compute_sha1(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    Sha1Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-256 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 32-byte vector containing the SHA-256 hash.
#[must_use]
pub fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-384 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 48-byte vector containing the SHA-384 hash.
#[must_use]
pub fn compute_sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the SHA-512 hash of input bytes.
///
/// # Arguments
///
/// * `data` - The input bytes to hash
///
/// # Returns
///
/// A 64-byte vector containing the SHA-512 hash.
#[must_use]
pub fn compute_sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    Sha2Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

/// Computes the HMAC-SHA256 of input bytes with the given key.
///
/// # Arguments
///
/// * `key` - The HMAC key bytes
/// * `data` - The input bytes to authenticate
///
/// # Returns
///
/// A 32-byte vector containing the HMAC-SHA256 result.
#[cfg(feature = "emulation")]
#[must_use]
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;

    // HMAC accepts keys of any size (per RFC 2104), so this never fails.
    let Ok(mut mac) = <HmacSha256 as HmacKeyInit>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Computes the HMAC-SHA512 of input bytes with the given key.
///
/// # Arguments
///
/// * `key` - The HMAC key bytes
/// * `data` - The input bytes to authenticate
///
/// # Returns
///
/// A 64-byte vector containing the HMAC-SHA512 result.
#[cfg(feature = "emulation")]
#[must_use]
pub fn compute_hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha512 = Hmac<Sha512>;

    // HMAC accepts keys of any size (per RFC 2104), so this never fails.
    let Ok(mut mac) = <HmacSha512 as HmacKeyInit>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The work [`derive_pbkdf2_key`] does, in PRF (HMAC) invocations: `iterations` for each
/// hash-sized block of the `key_len` bytes asked for.
///
/// The count and the length come from emulated or analysed code, bounded only by `i32::MAX`,
/// and the derivation is native work with nothing to interrupt it, so callers charge this to
/// their budget before deriving.
///
/// # Errors
///
/// Returns [`crate::Error::TypeError`] for a hash algorithm PBKDF2 is not derived with here.
#[cfg(feature = "emulation")]
pub fn pbkdf2_work(iterations: u32, key_len: usize, hash_algorithm: &str) -> Result<u64> {
    let block: usize = match hash_algorithm.to_uppercase().as_str() {
        "SHA1" => 20,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        other => {
            return Err(TypeError(format!(
                "Unsupported PBKDF2 hash algorithm: {other}"
            )))
        }
    };
    let blocks = u64::try_from(key_len.div_ceil(block)).unwrap_or(u64::MAX);
    Ok(u64::from(iterations).saturating_mul(blocks))
}

/// Derives a key using PBKDF2 (RFC 2898 Section 5.2).
///
/// PBKDF2 is the algorithm used by .NET's `Rfc2898DeriveBytes` class.
/// It uses HMAC as the pseudorandom function.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - The salt bytes
/// * `iterations` - Number of iterations, at least 1
/// * `key_len` - Desired length of the derived key
///
/// It runs [`pbkdf2_work`] PRF invocations, which callers bound.
/// * `hash_algorithm` - Hash algorithm: "SHA1", "SHA256", "SHA384", "SHA512"
///
/// # Returns
///
/// The derived key bytes of the specified length.
///
/// # Errors
///
/// Returns [`crate::Error::NotSupported`] if `hash_algorithm` is not one of the recognised
/// names, or if it is "SHA1" in a build without the `legacy-crypto` feature. Returns
/// [`crate::Error::TypeError`] if `iterations` is 0.
///
/// Unknown algorithms are an error rather than a silent fallback on purpose: substituting a
/// different hash yields plausible-looking bytes of the right length and the wrong value, which
/// an analyst then consumes as ground truth.
///
/// # Example
///
/// The `examples::derive_pbkdf2_key_example` test in this module runs this example.
#[cfg(feature = "emulation")]
pub fn derive_pbkdf2_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    hash_algorithm: &str,
) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(TypeError("PBKDF2 needs at least one iteration".to_string()));
    }

    let mut key = vec![0u8; key_len];

    match hash_algorithm.to_uppercase().as_str() {
        "SHA256" => {
            pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut key);
        }
        "SHA384" => {
            pbkdf2_hmac::<sha2::Sha384>(password, salt, iterations, &mut key);
        }
        "SHA512" => {
            pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key);
        }
        #[cfg(feature = "legacy-crypto")]
        "SHA1" => {
            pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut key);
        }
        #[cfg(not(feature = "legacy-crypto"))]
        "SHA1" => {
            // Deriving with SHA-256 instead would return the right number of bytes and the
            // wrong ones. `Rfc2898DeriveBytes` defaults to SHA-1, so this is the common path
            // in such a build, not a corner case — name the feature that fixes it.
            return Err(TypeError(
                "PBKDF2-HMAC-SHA1 requires the `legacy-crypto` feature; \
                 rebuild with it enabled to derive this key"
                    .to_string(),
            ));
        }
        other => {
            return Err(TypeError(format!(
                "Unsupported PBKDF2 hash algorithm: {other}"
            )));
        }
    }

    Ok(key)
}

/// Derives a key using PBKDF1 (RFC 2898 Section 5.1).
///
/// PBKDF1 is the algorithm used by .NET's `PasswordDeriveBytes` class.
///
/// # Algorithm
///
/// 1. T_1 = SHA1(Password || Salt)
/// 2. For i = 2 to iterations: T_i = SHA1(T_{i-1})
/// 3. Output first key_len bytes of T_iterations
///
/// # Extended Output
///
/// For output longer than the hash size (20 bytes for SHA1), .NET uses a proprietary
/// extension that derives additional blocks using: SHA1(counter_string || T_iterations)
/// where counter_string is "1", "2", "3", etc.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - The salt bytes
/// * `iterations` - Number of iterations (default 100 for PasswordDeriveBytes)
/// * `key_len` - Desired length of the derived key
///
/// # Returns
///
/// The derived key bytes of the specified length.
///
/// # Example
///
/// The `examples::derive_pbkdf1_key_example` test in this module runs this example.
///
/// # Feature Requirements
///
/// This function requires the `legacy-crypto` feature because PBKDF1 is
/// inherently SHA1-based per RFC 2898.
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
pub fn derive_pbkdf1_key(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    // Step 1: T_1 = SHA1(Password || Salt)
    let mut hasher = sha1::Sha1::new();
    hasher.update(password);
    hasher.update(salt);
    let mut t = hasher.finalize();

    // Step 2: For i = 2 to iterations: T_i = SHA1(T_{i-1})
    for _ in 1..iterations {
        let mut hasher = sha1::Sha1::new();
        hasher.update(t);
        t = hasher.finalize();
    }

    // The base key (first 20 bytes from PBKDF1)
    let base_key: [u8; 20] = t.into();

    if key_len <= 20 {
        // Simple case: just return the first key_len bytes
        base_key.get(..key_len).unwrap_or(&[]).to_vec()
    } else {
        // Extended output using .NET's proprietary extension
        // For each additional block: SHA1(counter_string || base_key)
        let mut result = base_key.to_vec();
        let mut counter: u32 = 1;

        while result.len() < key_len {
            let mut hasher = sha1::Sha1::new();
            // .NET uses the string representation of the counter
            hasher.update(counter.to_string().as_bytes());
            hasher.update(base_key);
            let block = hasher.finalize();
            result.extend_from_slice(&block);
            counter = counter.saturating_add(1);
        }

        result.truncate(key_len);
        result
    }
}

/// Applies a crypto transformation (encryption or decryption) to data.
///
/// This function handles the actual cryptographic operations for AES, DES, and
/// TripleDES in CBC and ECB modes with configurable padding.
///
/// # Arguments
///
/// * `algorithm` - The algorithm name (e.g., "AES", "Rijndael", "DES", "TripleDES")
/// * `key` - The encryption/decryption key
/// * `iv` - The initialization vector (ignored for ECB mode)
/// * `is_encryptor` - True for encryption, false for decryption
/// * `data` - The input data to transform
/// * `mode` - Cipher mode: 1=CBC (default), 2=ECB
/// * `padding` - Padding mode: 1=None, 2=PKCS7 (default), 3=Zeros
///
/// # Returns
///
/// The transformed data, or `None` if the algorithm/key size is unsupported.
///
/// # Supported Algorithms
///
/// | Algorithm | Key Sizes | Block Size |
/// |-----------|-----------|------------|
/// | AES/Rijndael | 16, 24, 32 bytes | 16 bytes |
/// | DES | 8 bytes | 8 bytes |
/// | TripleDES/3DES | 24 bytes | 8 bytes |
#[cfg(feature = "emulation")]
pub fn apply_crypto_transform(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    is_encryptor: bool,
    data: &[u8],
    mode: u8,
    padding: u8,
) -> Option<Vec<u8>> {
    // Normalize algorithm name
    let alg_upper = algorithm.to_uppercase();
    let is_ecb = mode == 2;

    if alg_upper.contains("AES") || alg_upper.contains("RIJNDAEL") {
        return if is_ecb {
            aes_ecb_transform(key, is_encryptor, data, padding)
        } else {
            // CBC mode (default)
            aes_cbc_transform(key, iv, is_encryptor, data, padding)
        };
    }

    // DES/3DES support requires legacy-crypto feature
    #[cfg(feature = "legacy-crypto")]
    if alg_upper.contains("TRIPLEDES") || alg_upper.contains("3DES") {
        if key.len() == 24 {
            return if is_ecb {
                tdes_ecb_transform(key, is_encryptor, data, padding)
            } else if iv.len() >= 8 {
                tdes_cbc_transform(key, iv, is_encryptor, data, padding)
            } else {
                None
            };
        }
        return None;
    }

    #[cfg(feature = "legacy-crypto")]
    if alg_upper.contains("DES") {
        if key.len() == 8 {
            return if is_ecb {
                des_ecb_transform(key, is_encryptor, data, padding)
            } else if iv.len() >= 8 {
                des_cbc_transform(key, iv, is_encryptor, data, padding)
            } else {
                None
            };
        }
        return None;
    }

    // DES/3DES not available without legacy-crypto
    #[cfg(not(feature = "legacy-crypto"))]
    if alg_upper.contains("DES") {
        return None;
    }

    // Unknown algorithm - return None (passthrough handled by caller)
    None
}

/// AES CBC mode transform with configurable padding.
#[cfg(feature = "emulation")]
fn aes_cbc_transform(
    key: &[u8],
    iv: &[u8],
    is_encryptor: bool,
    data: &[u8],
    padding: u8,
) -> Option<Vec<u8>> {
    match key.len() {
        16 => cbc_transform::<Aes128CbcEnc, Aes128CbcDec>(key, iv, 16, is_encryptor, data, padding),
        24 => cbc_transform::<Aes192CbcEnc, Aes192CbcDec>(key, iv, 16, is_encryptor, data, padding),
        32 => cbc_transform::<Aes256CbcEnc, Aes256CbcDec>(key, iv, 16, is_encryptor, data, padding),
        _ => None,
    }
}

/// AES ECB mode transform with configurable padding.
#[cfg(feature = "emulation")]
fn aes_ecb_transform(key: &[u8], is_encryptor: bool, data: &[u8], padding: u8) -> Option<Vec<u8>> {
    match key.len() {
        16 => ecb_transform::<Aes128EcbEnc, Aes128EcbDec>(key, 16, is_encryptor, data, padding),
        24 => ecb_transform::<Aes192EcbEnc, Aes192EcbDec>(key, 16, is_encryptor, data, padding),
        32 => ecb_transform::<Aes256EcbEnc, Aes256EcbDec>(key, 16, is_encryptor, data, padding),
        _ => None,
    }
}

/// Generic CBC mode transform with configurable padding.
#[cfg(feature = "emulation")]
fn cbc_transform<E, D>(
    key: &[u8],
    iv: &[u8],
    block_size: usize,
    is_encryptor: bool,
    data: &[u8],
    padding: u8,
) -> Option<Vec<u8>>
where
    E: BlockModeEncrypt + KeyIvInit,
    D: BlockModeDecrypt + KeyIvInit,
{
    if iv.len() < block_size {
        return None;
    }
    if is_encryptor {
        let iv_slice = iv.get(..block_size)?;
        let cipher = E::new_from_slices(key, iv_slice).ok()?;
        // block_size is small (8 or 16); checked arithmetic guards against overflow
        // for absurdly large `data.len()` from adversarial input.
        let padded_len = data
            .len()
            .checked_div(block_size)?
            .checked_add(1)?
            .checked_mul(block_size)?;
        let mut buf = vec![0u8; padded_len];
        let buf_prefix = buf.get_mut(..data.len())?;
        buf_prefix.copy_from_slice(data);
        let result = match padding {
            1 => cipher
                .encrypt_padded::<NoPadding>(&mut buf, data.len())
                .ok()?,
            3 => {
                // Zeros padding: pad with zeros to block boundary
                let result = cipher
                    .encrypt_padded::<NoPadding>(&mut buf, padded_len)
                    .ok()?;
                return Some(result.to_vec());
            }
            _ => cipher.encrypt_padded::<Pkcs7>(&mut buf, data.len()).ok()?,
        };
        Some(result.to_vec())
    } else {
        if data.is_empty() {
            return None;
        }
        let iv_slice = iv.get(..block_size)?;
        let cipher = D::new_from_slices(key, iv_slice).ok()?;
        let mut buf = data.to_vec();
        let result = match padding {
            1 | 3 => cipher.decrypt_padded::<NoPadding>(&mut buf).ok()?,
            _ => cipher.decrypt_padded::<Pkcs7>(&mut buf).ok()?,
        };
        Some(result.to_vec())
    }
}

/// Generic ECB mode transform with configurable padding.
#[cfg(feature = "emulation")]
fn ecb_transform<E, D>(
    key: &[u8],
    block_size: usize,
    is_encryptor: bool,
    data: &[u8],
    padding: u8,
) -> Option<Vec<u8>>
where
    E: BlockModeEncrypt + KeyInit,
    D: BlockModeDecrypt + KeyInit,
{
    if is_encryptor {
        let cipher = E::new_from_slice(key).ok()?;
        // block_size is small (8 or 16); checked arithmetic guards against overflow
        // for absurdly large `data.len()` from adversarial input.
        let padded_len = data
            .len()
            .checked_div(block_size)?
            .checked_add(1)?
            .checked_mul(block_size)?;
        let mut buf = vec![0u8; padded_len];
        let buf_prefix = buf.get_mut(..data.len())?;
        buf_prefix.copy_from_slice(data);
        let result = match padding {
            1 => cipher
                .encrypt_padded::<NoPadding>(&mut buf, data.len())
                .ok()?,
            3 => {
                let result = cipher
                    .encrypt_padded::<NoPadding>(&mut buf, padded_len)
                    .ok()?;
                return Some(result.to_vec());
            }
            _ => cipher.encrypt_padded::<Pkcs7>(&mut buf, data.len()).ok()?,
        };
        Some(result.to_vec())
    } else {
        if data.is_empty() {
            return None;
        }
        let cipher = D::new_from_slice(key).ok()?;
        let mut buf = data.to_vec();
        let result = match padding {
            1 | 3 => cipher.decrypt_padded::<NoPadding>(&mut buf).ok()?,
            _ => cipher.decrypt_padded::<Pkcs7>(&mut buf).ok()?,
        };
        Some(result.to_vec())
    }
}

/// DES CBC mode transform (legacy-crypto feature).
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
fn des_cbc_transform(
    key: &[u8],
    iv: &[u8],
    is_encryptor: bool,
    data: &[u8],
    padding: u8,
) -> Option<Vec<u8>> {
    cbc_transform::<DesCbcEnc, DesCbcDec>(key, iv, 8, is_encryptor, data, padding)
}

/// DES ECB mode transform (legacy-crypto feature).
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
fn des_ecb_transform(key: &[u8], is_encryptor: bool, data: &[u8], padding: u8) -> Option<Vec<u8>> {
    ecb_transform::<DesEcbEnc, DesEcbDec>(key, 8, is_encryptor, data, padding)
}

/// TripleDES CBC mode transform (legacy-crypto feature).
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
fn tdes_cbc_transform(
    key: &[u8],
    iv: &[u8],
    is_encryptor: bool,
    data: &[u8],
    padding: u8,
) -> Option<Vec<u8>> {
    cbc_transform::<TdesCbcEnc, TdesCbcDec>(key, iv, 8, is_encryptor, data, padding)
}

/// TripleDES ECB mode transform (legacy-crypto feature).
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
fn tdes_ecb_transform(key: &[u8], is_encryptor: bool, data: &[u8], padding: u8) -> Option<Vec<u8>> {
    ecb_transform::<TdesEcbEnc, TdesEcbDec>(key, 8, is_encryptor, data, padding)
}

// TODO: Replace this manual implementation with the `rsa` crate once its Marvin Attack
// CVE (RUSTSEC-2023-0071) is fixed in a stable release (expected in rsa 0.10.0).
/// Verifies an RSA PKCS#1 v1.5 signature against a pre-computed hash.
///
/// Implements RSASSA-PKCS1-v1_5 verification per RFC 8017 §8.2.2 using raw
/// modular exponentiation, avoiding the `rsa` crate (which has an unpatched
/// Marvin Attack CVE on PKCS#1 v1.5 decryption).
///
/// Used by the emulator to implement `RSACryptoServiceProvider.VerifyHash()`. It does
/// [`rsa_verify_work`] work, which callers bound.
///
/// # Arguments
///
/// * `modulus` - The RSA public key modulus (big-endian bytes)
/// * `exponent` - The RSA public key exponent (big-endian bytes)
/// * `hash` - The hash value to verify
/// * `signature` - The RSA signature bytes
/// * `hash_algorithm` - Hash algorithm name or OID (e.g., "SHA256", "2.16.840.1.101.3.4.2.1")
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
///
/// # Feature Requirements
///
/// This function requires the `emulation` feature.
/// The work [`verify_rsa_pkcs1v15`] does, in units of 64 limb products: the modular
/// exponentiation squares, and may multiply, once per exponent bit, each a product of two
/// numbers the modulus's size.
///
/// The key comes from emulated code (`RSA.FromXmlString`), of any size, and the
/// exponentiation is native work with nothing to interrupt it, so callers charge this to
/// their budget before verifying.
#[cfg(feature = "emulation")]
#[must_use]
pub fn rsa_verify_work(modulus: &[u8], exponent: &[u8]) -> u64 {
    let limbs = BigUint::from_bytes_be(modulus).bits().div_ceil(64);
    BigUint::from_bytes_be(exponent)
        .bits()
        .saturating_mul(2)
        .saturating_mul(limbs.saturating_mul(limbs))
        / 64
}

#[cfg(feature = "emulation")]
pub fn verify_rsa_pkcs1v15(
    modulus: &[u8],
    exponent: &[u8],
    hash: &[u8],
    signature: &[u8],
    hash_algorithm: &str,
) -> bool {
    // DER-encoded DigestInfo prefixes per RFC 8017 §9.2 Note 1.
    let digest_prefix: &[u8] = match hash_algorithm.to_uppercase().as_str() {
        "SHA256" | "2.16.840.1.101.3.4.2.1" => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        "SHA384" | "2.16.840.1.101.3.4.2.2" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        "SHA512" | "2.16.840.1.101.3.4.2.3" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        #[cfg(feature = "legacy-crypto")]
        "SHA1" | "1.3.14.3.2.26" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        _ => return false,
    };

    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let s = BigUint::from_bytes_be(signature);

    // RFC 8017 §5.2.2: RSAVP1 — m = s^e mod n
    if s >= n {
        return false;
    }
    let m = s.modpow(&e, &n);

    // Convert to big-endian bytes, zero-padded to modulus length.
    let k = modulus.len();
    let m_bytes = m.to_bytes_be();
    if m_bytes.len() > k {
        return false;
    }
    let mut em = vec![0u8; k];
    // k >= m_bytes.len() was just verified above; subtraction is safe.
    let Some(em_offset) = k.checked_sub(m_bytes.len()) else {
        return false;
    };
    let Some(em_tail) = em.get_mut(em_offset..) else {
        return false;
    };
    em_tail.copy_from_slice(&m_bytes);

    // RFC 8017 §9.2: EMSA-PKCS1-v1.5 verification
    // Expected: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo prefix] [hash]
    let Some(t_len) = digest_prefix.len().checked_add(hash.len()) else {
        return false;
    };
    let Some(min_k) = t_len.checked_add(11) else {
        return false;
    };
    if k < min_k {
        return false;
    }

    // Build expected encoding and compare in constant position.
    // k >= t_len + 11 implies k - t_len - 3 >= 8, so this subtraction is safe.
    let Some(ps_len) = k.checked_sub(t_len).and_then(|v| v.checked_sub(3)) else {
        return false;
    };
    let mut expected = Vec::with_capacity(k);
    expected.push(0x00);
    expected.push(0x01);
    expected.extend(repeat_n(0xFF, ps_len));
    expected.push(0x00);
    expected.extend_from_slice(digest_prefix);
    expected.extend_from_slice(hash);

    em == expected
}

/// PBKDF2 / symmetric cipher parameters for key derivation and decryption.
///
/// Encapsulates the parameters needed to derive key material via PBKDF2 and
/// split the output into a symmetric key and IV. These parameters are typically
/// extracted from an obfuscator's decryptor method body by resolving constant
/// arguments to `Rfc2898DeriveBytes::.ctor()` and `GetBytes()` in SSA form.
///
/// When extraction fails for a specific parameter, the [`Default`] implementation
/// provides values matching .NET's `Rfc2898DeriveBytes` defaults (SHA1, 1000
/// iterations) and AES-256-CBC (32-byte key, 16-byte IV).
#[cfg(feature = "deobfuscation")]
#[derive(Debug, Clone)]
pub struct CryptoParameters {
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Symmetric key size in bytes (e.g., 32 for AES-256).
    pub key_size: usize,
    /// IV size in bytes (e.g., 16 for AES block size).
    pub iv_size: usize,
    /// HMAC hash algorithm name for PBKDF2 (e.g., `"SHA1"`, `"SHA256"`).
    pub hash_algorithm: &'static str,
}

#[cfg(feature = "deobfuscation")]
impl Default for CryptoParameters {
    /// Returns defaults matching .NET's `Rfc2898DeriveBytes` default constructor
    /// (SHA1, 1000 iterations) and AES-256-CBC (32-byte key, 16-byte IV).
    fn default() -> Self {
        Self {
            iterations: 1000,
            key_size: 32,
            iv_size: 16,
            hash_algorithm: "SHA1",
        }
    }
}

/// Derives a symmetric key and IV from password and salt using PBKDF2.
///
/// Wraps [`derive_pbkdf2_key`] with the parameters from a [`CryptoParameters`]
/// struct, splitting the output into `(key, iv)` based on the configured sizes.
///
/// # Arguments
///
/// * `password` - Raw key material (e.g., from a FieldRVA entry).
/// * `salt` - Raw salt (e.g., from a FieldRVA entry).
/// * `params` - PBKDF2 and cipher parameters (iterations, key/IV sizes, hash algorithm).
/// * `max_work` - The most [`pbkdf2_work`] the derivation may take, 0 for no bound: `params`
///   is extracted from an attacker-supplied decryptor body.
///
/// # Returns
///
/// A tuple `(key, iv)` of the derived key material.
///
/// # Errors
///
/// When the derivation's work is more than `max_work`, and any error from
/// [`derive_pbkdf2_key`]: no iterations, or an unsupported hash algorithm.
#[cfg(all(feature = "deobfuscation", feature = "legacy-crypto"))]
pub fn derive_key_iv(
    password: &[u8],
    salt: &[u8],
    params: &CryptoParameters,
    max_work: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Sizes and the iteration count are constants lifted from a decryptor body: the work is
    // checked against the budget before any of it is done
    let output_len = params.key_size.saturating_add(params.iv_size);
    let work = pbkdf2_work(params.iterations, output_len, params.hash_algorithm)?;
    if max_work != 0 && work > max_work {
        return Err(TypeError(format!(
            "deriving {output_len} bytes in {} iterations is {work} PRF invocations, \
             more than the budget of {max_work}",
            params.iterations
        )));
    }
    let derived = derive_pbkdf2_key(
        password,
        salt,
        params.iterations,
        output_len,
        params.hash_algorithm,
    )?;
    let key = derived.get(..params.key_size).unwrap_or(&[]).to_vec();
    let iv = derived
        .get(params.key_size..output_len)
        .unwrap_or(&[])
        .to_vec();
    Ok((key, iv))
}

#[cfg(all(test, feature = "emulation"))]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1, 32, "SHA256").unwrap();

        // Verify length
        assert_eq!(key.len(), 32);

        // The result should be deterministic
        let key2 = derive_pbkdf2_key(password, salt, 1, 32, "SHA256").unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf2_sha384() {
        let password = b"test";
        let salt = b"salt123";
        let key = derive_pbkdf2_key(password, salt, 1000, 48, "SHA384").unwrap();
        assert_eq!(key.len(), 48);
    }

    #[test]
    fn test_pbkdf2_sha512() {
        let password = b"test";
        let salt = b"salt123";
        let key = derive_pbkdf2_key(password, salt, 1000, 64, "SHA512").unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";

        let key_1 = derive_pbkdf2_key(password, salt, 1, 20, "SHA256").unwrap();
        let key_1000 = derive_pbkdf2_key(password, salt, 1000, 20, "SHA256").unwrap();

        // Different iteration counts should produce different keys
        assert_ne!(key_1, key_1000);
    }

    #[test]
    fn test_pbkdf2_salt_affects_output() {
        let password = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";

        let key1 = derive_pbkdf2_key(password, salt1, 1000, 20, "SHA256").unwrap();
        let key2 = derive_pbkdf2_key(password, salt2, 1000, 20, "SHA256").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf2_case_insensitive_algorithm() {
        let password = b"test";
        let salt = b"salt";

        let key_upper = derive_pbkdf2_key(password, salt, 1, 32, "SHA256").unwrap();
        let key_lower = derive_pbkdf2_key(password, salt, 1, 32, "sha256").unwrap();
        let key_mixed = derive_pbkdf2_key(password, salt, 1, 32, "Sha256").unwrap();

        assert_eq!(key_upper, key_lower);
        assert_eq!(key_upper, key_mixed);
    }

    #[test]
    fn test_pbkdf2_empty_password() {
        let password = b"";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1000, 16, "SHA256").unwrap();

        assert_eq!(key.len(), 16);
        // Empty password should still produce non-zero key
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_pbkdf2_empty_salt() {
        let password = b"password";
        let salt = b"";
        let key = derive_pbkdf2_key(password, salt, 1000, 16, "SHA256").unwrap();

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf2_variable_key_length() {
        let password = b"password";
        let salt = b"salt";

        for len in [1, 16, 20, 32, 48, 64, 100] {
            let key = derive_pbkdf2_key(password, salt, 1, len, "SHA256").unwrap();
            assert_eq!(key.len(), len);
        }
    }

    /// The work is the iteration count for each hash-sized block asked for, so a count and
    /// a length that each look small multiply.
    #[test]
    fn test_pbkdf2_work_is_iterations_times_blocks() {
        assert_eq!(pbkdf2_work(1000, 32, "SHA256").unwrap(), 1000);
        assert_eq!(pbkdf2_work(1000, 33, "SHA256").unwrap(), 2000);
        assert_eq!(pbkdf2_work(1000, 48, "SHA1").unwrap(), 3000);
        assert_eq!(pbkdf2_work(7, 0, "sha512").unwrap(), 0);
        assert_eq!(
            pbkdf2_work(i32::MAX.unsigned_abs(), 1 << 31, "SHA256").unwrap(),
            u64::from(i32::MAX.unsigned_abs()) * (1 << 26)
        );
        assert!(pbkdf2_work(1, 32, "MD5").is_err());
    }

    /// The exponentiation's work grows with the exponent's bits and the square of the
    /// modulus's limbs, leading zeros aside: a 2048-bit key with e = 65537 is small, a
    /// 16384-bit modulus raised to a 16384-bit exponent is not.
    #[test]
    fn test_rsa_verify_work() {
        let modulus = [0xFFu8; 256];
        assert_eq!(
            rsa_verify_work(&modulus, &[0x01, 0x00, 0x01]),
            17 * 2 * 32 * 32 / 64
        );
        let mut padded = vec![0u8; 100];
        padded.extend_from_slice(&modulus);
        assert_eq!(
            rsa_verify_work(&padded, &[0, 0, 0x01, 0x00, 0x01]),
            rsa_verify_work(&modulus, &[0x01, 0x00, 0x01])
        );
        assert_eq!(
            rsa_verify_work(&[0xFF; 2048], &[0xFF; 2048]),
            16384 * 2 * 256 * 256 / 64
        );
    }

    /// A derivation of no iterations is refused rather than handed to the PRF loop.
    #[test]
    fn test_pbkdf2_rejects_zero_iterations() {
        assert!(derive_pbkdf2_key(b"password", b"salt", 0, 32, "SHA256").is_err());
    }

    // NOTE: PBKDF1 tests are in the legacy_tests module below
    // because they require the legacy-crypto feature (PBKDF1 uses SHA1)

    #[test]
    fn test_aes_128_encrypt_decrypt() {
        let key = [0u8; 16]; // 128-bit key
        let iv = [0u8; 16]; // 128-bit IV
        let plaintext = b"Hello, World!";

        // Encrypt
        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2);
        assert!(ciphertext.is_some(), "Encryption should succeed");
        let ciphertext = ciphertext.unwrap();
        assert_ne!(
            ciphertext.as_slice(),
            plaintext,
            "Ciphertext should differ from plaintext"
        );

        // Decrypt
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext, 1, 2);
        assert!(decrypted.is_some(), "Decryption should succeed");
        assert_eq!(
            decrypted.unwrap(),
            plaintext,
            "Decrypted should match original"
        );
    }

    #[test]
    fn test_aes_192_encrypt_decrypt() {
        let key = [0u8; 24]; // 192-bit key
        let iv = [0u8; 16];
        let plaintext = b"Test message for AES-192";

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_encrypt_decrypt() {
        let key = [0u8; 32]; // 256-bit key
        let iv = [0u8; 16];
        let plaintext = b"Test message for AES-256";

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rijndael_alias() {
        // Rijndael should work the same as AES
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"Test for Rijndael";

        let ciphertext =
            apply_crypto_transform("Rijndael", &key, &iv, true, plaintext, 1, 2).unwrap();
        let decrypted =
            apply_crypto_transform("Rijndael", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);

        // Should produce same output as "AES"
        let aes_ciphertext =
            apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        assert_eq!(ciphertext, aes_ciphertext);
    }

    #[test]
    fn test_unsupported_key_size() {
        let bad_key = [0u8; 15]; // Invalid AES key size
        let iv = [0u8; 16];
        let plaintext = b"test";

        let result = apply_crypto_transform("AES", &bad_key, &iv, true, plaintext, 1, 2);
        assert!(result.is_none(), "Should fail with invalid key size");
    }

    #[test]
    fn test_unsupported_algorithm() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"test";

        let result = apply_crypto_transform("UNKNOWN_ALGO", &key, &iv, true, plaintext, 1, 2);
        assert!(result.is_none(), "Should return None for unknown algorithm");
    }

    #[test]
    fn test_case_insensitive_algorithm() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"case test";

        let ct1 = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let ct2 = apply_crypto_transform("aes", &key, &iv, true, plaintext, 1, 2).unwrap();
        let ct3 = apply_crypto_transform("Aes", &key, &iv, true, plaintext, 1, 2).unwrap();

        assert_eq!(ct1, ct2);
        assert_eq!(ct1, ct3);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"test";

        let ct1 = apply_crypto_transform("AES", &key1, &iv, true, plaintext, 1, 2).unwrap();
        let ct2 = apply_crypto_transform("AES", &key2, &iv, true, plaintext, 1, 2).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_ivs_produce_different_ciphertext() {
        let key = [0u8; 16];
        let iv1 = [0u8; 16];
        let iv2 = [1u8; 16];
        let plaintext = b"test";

        let ct1 = apply_crypto_transform("AES", &key, &iv1, true, plaintext, 1, 2).unwrap();
        let ct2 = apply_crypto_transform("AES", &key, &iv2, true, plaintext, 1, 2).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"";

        // Encryption of empty data should produce padding block
        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        assert_eq!(ciphertext.len(), 16); // One full block of padding

        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_block_aligned_plaintext() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0u8; 32]; // Exactly 2 blocks

        let ciphertext = apply_crypto_transform("AES", &key, &iv, true, &plaintext, 1, 2).unwrap();
        // PKCS7 adds another block for padding
        assert_eq!(ciphertext.len(), 48);

        let decrypted = apply_crypto_transform("AES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

/// Tests for PBKDF1 and SHA1-based operations that require the legacy-crypto feature
#[cfg(test)]
#[cfg(feature = "legacy-crypto")]
mod legacy_tests {
    use sha1::Digest;

    use super::*;

    #[cfg(feature = "emulation")]
    #[test]
    fn test_pbkdf2_sha1_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf2_key(password, salt, 1, 20, "SHA1").unwrap();

        // Verify length
        assert_eq!(key.len(), 20);

        // The result should be deterministic
        let key2 = derive_pbkdf2_key(password, salt, 1, 20, "SHA1").unwrap();
        assert_eq!(key, key2);
    }

    #[cfg(feature = "emulation")]
    #[test]
    fn test_pbkdf2_sha256_vs_sha1() {
        let password = b"password";
        let salt = b"salt";
        let key_sha256 = derive_pbkdf2_key(password, salt, 1, 32, "SHA256").unwrap();
        let key_sha1 = derive_pbkdf2_key(password, salt, 1, 32, "SHA1").unwrap();

        // Different algorithms produce different keys
        assert_ne!(key_sha256, key_sha1);
    }

    /// An unrecognised algorithm name must be an error, not a silent substitution.
    ///
    /// A fallback to SHA-1 would return bytes of the correct length and the wrong value, which
    /// an analyst then consumes as ground truth with no signal that the crypto was substituted.
    #[cfg(feature = "emulation")]
    #[test]
    fn test_pbkdf2_unknown_algorithm_is_rejected() {
        let password = b"test";
        let salt = b"salt";

        assert!(derive_pbkdf2_key(password, salt, 1000, 20, "UNKNOWN").is_err());
        assert!(derive_pbkdf2_key(password, salt, 1000, 20, "").is_err());
        assert!(derive_pbkdf2_key(password, salt, 1000, 20, "MD5").is_err());
    }

    #[test]
    fn test_pbkdf1_basic() {
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);

        // Should be deterministic
        let key2 = derive_pbkdf1_key(password, salt, 100, 16);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_pbkdf1_max_natural_length() {
        // PBKDF1 with SHA1 can naturally produce up to 20 bytes
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 20);

        assert_eq!(key.len(), 20);
    }

    #[test]
    fn test_pbkdf1_extended_length() {
        // Request more than 20 bytes (extended mode)
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 32);

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf1_very_long_key() {
        // Request a very long key (requires multiple extension blocks)
        let password = b"password";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 100);

        assert_eq!(key.len(), 100);
    }

    #[test]
    fn test_pbkdf1_iterations_affect_output() {
        let password = b"password";
        let salt = b"salt";

        let key_1 = derive_pbkdf1_key(password, salt, 1, 20);
        let key_100 = derive_pbkdf1_key(password, salt, 100, 20);

        assert_ne!(key_1, key_100);
    }

    #[test]
    fn test_pbkdf1_salt_affects_output() {
        let password = b"password";
        let salt1 = b"salt1";
        let salt2 = b"salt2";

        let key1 = derive_pbkdf1_key(password, salt1, 100, 20);
        let key2 = derive_pbkdf1_key(password, salt2, 100, 20);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf1_password_affects_output() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = b"salt";

        let key1 = derive_pbkdf1_key(password1, salt, 100, 20);
        let key2 = derive_pbkdf1_key(password2, salt, 100, 20);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pbkdf1_empty_password() {
        let password = b"";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf1_empty_salt() {
        let password = b"password";
        let salt = b"";
        let key = derive_pbkdf1_key(password, salt, 100, 16);

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_pbkdf1_single_iteration() {
        // With 1 iteration, the result is just SHA1(password || salt)
        let password = b"test";
        let salt = b"salt";
        let key = derive_pbkdf1_key(password, salt, 1, 20);

        // Verify it matches SHA1(password || salt)
        let mut hasher = sha1::Sha1::new();
        hasher.update(password);
        hasher.update(salt);
        let expected: [u8; 20] = hasher.finalize().into();

        assert_eq!(key, expected);
    }

    #[test]
    fn test_pbkdf1_variable_key_length() {
        let password = b"password";
        let salt = b"salt";

        for len in [1, 8, 16, 20, 32, 48, 64] {
            let key = derive_pbkdf1_key(password, salt, 100, len);
            assert_eq!(key.len(), len);
        }
    }

    #[cfg(feature = "emulation")]
    #[test]
    fn test_pbkdf1_different_from_pbkdf2() {
        let password = b"password";
        let salt = b"salt";

        let key1 = derive_pbkdf1_key(password, salt, 100, 20);
        let key2 = derive_pbkdf2_key(password, salt, 100, 20, "SHA1").unwrap();

        // PBKDF1 and PBKDF2 are different algorithms
        assert_ne!(key1, key2);
    }

    // DES encryption tests

    #[cfg(feature = "emulation")]
    #[test]
    fn test_des_encrypt_decrypt() {
        let key = [0u8; 8]; // 56-bit key (8 bytes with parity)
        let iv = [0u8; 8]; // 64-bit IV
        let plaintext = b"DES test";

        let ciphertext = apply_crypto_transform("DES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let decrypted = apply_crypto_transform("DES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "emulation")]
    #[test]
    fn test_tripledes_encrypt_decrypt() {
        let key = [0u8; 24]; // 168-bit key (24 bytes)
        let iv = [0u8; 8]; // 64-bit IV
        let plaintext = b"TripleDES test message";

        let ciphertext =
            apply_crypto_transform("TripleDES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let decrypted =
            apply_crypto_transform("TripleDES", &key, &iv, false, &ciphertext, 1, 2).unwrap();
        assert_eq!(decrypted, plaintext);

        // 3DES alias
        let ciphertext_3des =
            apply_crypto_transform("3DES", &key, &iv, true, plaintext, 1, 2).unwrap();
        assert_eq!(ciphertext, ciphertext_3des);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn derive_pbkdf2_key_example() -> Result<()> {
        let password = b"mypassword";
        let salt = b"somesalt";
        let key = derive_pbkdf2_key(password, salt, 1000, 32, "SHA256")?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn derive_pbkdf1_key_example() -> Result<()> {
        let password = b"mypassword";
        let salt = b"somesalt";
        let key = derive_pbkdf1_key(password, salt, 100, 16);
        assert_eq!(key.len(), 16);
        Ok(())
    }
}

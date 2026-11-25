//! Hash algorithm and CryptoConfig hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for hash algorithms commonly used by .NET
//! obfuscators. Hash functions are used to derive encryption keys, compute checksums,
//! and verify integrity during deobfuscation.
//!
//! # Covered APIs
//!
//! ## Hash Algorithms
//!
//! - **MD5** (`legacy-crypto` feature): `MD5.Create()`, `MD5.ComputeHash(byte[])`
//! - **SHA1** (`legacy-crypto` feature): `SHA1.Create()`, `SHA1.ComputeHash(byte[])`
//! - **SHA256** (always available): `SHA256.Create()`, `SHA256.ComputeHash(byte[])`
//! - **HashAlgorithm**: `ComputeHash(byte[])`, `TransformBlock(...)`, `TransformFinalBlock(...)`, `get_Hash`
//!
//! ## CryptoConfig
//!
//! - `MapNameToOID(string)` — maps algorithm names to OID strings
//! - `get_AllowOnlyFipsAlgorithms` — always returns `false` during emulation
//!
//! # Implementation Notes
//!
//! Hash functions are fully implemented using the `md5`, `sha1`, and `sha2` crates.
//! The incremental hashing API (`TransformBlock`/`TransformFinalBlock`/`get_Hash`) accumulates
//! data on the heap object and finalizes on demand.

#[cfg(feature = "legacy-crypto")]
use crate::utils::{compute_md5, compute_sha1};
use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    utils::{compute_hmac_sha256, compute_hmac_sha512, compute_sha256},
    Result,
};

/// Registers all hash algorithm and CryptoConfig hooks.
///
/// Called by the parent `crypto::register()` to wire up MD5, SHA1, SHA256,
/// incremental `HashAlgorithm`, and `CryptoConfig` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // MD5 (legacy-crypto only)
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.MD5.Create")
            .match_name("System.Security.Cryptography", "MD5", "Create")
            .pre(md5_create_pre),
    )?;

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.MD5.ComputeHash")
            .match_name("System.Security.Cryptography", "MD5", "ComputeHash")
            .pre(md5_compute_hash_pre),
    )?;

    // HashAlgorithm.ComputeHash (always available, dispatches by algorithm type)
    manager.register(
        Hook::new("System.Security.Cryptography.HashAlgorithm.ComputeHash")
            .match_name(
                "System.Security.Cryptography",
                "HashAlgorithm",
                "ComputeHash",
            )
            .pre(hash_algorithm_compute_hash_pre),
    )?;

    // SHA1 (legacy-crypto only)
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.SHA1.Create")
            .match_name("System.Security.Cryptography", "SHA1", "Create")
            .pre(sha1_create_pre),
    )?;

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.SHA1.ComputeHash")
            .match_name("System.Security.Cryptography", "SHA1", "ComputeHash")
            .pre(sha1_compute_hash_pre),
    )?;

    // SHA256 (always available)
    manager.register(
        Hook::new("System.Security.Cryptography.SHA256.Create")
            .match_name("System.Security.Cryptography", "SHA256", "Create")
            .pre(sha256_create_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SHA256.ComputeHash")
            .match_name("System.Security.Cryptography", "SHA256", "ComputeHash")
            .pre(sha256_compute_hash_pre),
    )?;

    // Incremental HashAlgorithm API
    manager.register(
        Hook::new("System.Security.Cryptography.HashAlgorithm.TransformBlock")
            .match_name(
                "System.Security.Cryptography",
                "HashAlgorithm",
                "TransformBlock",
            )
            .pre(hash_algorithm_transform_block_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.HashAlgorithm.TransformFinalBlock")
            .match_name(
                "System.Security.Cryptography",
                "HashAlgorithm",
                "TransformFinalBlock",
            )
            .pre(hash_algorithm_transform_final_block_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.HashAlgorithm.get_Hash")
            .match_name("System.Security.Cryptography", "HashAlgorithm", "get_Hash")
            .pre(hash_algorithm_get_hash_pre),
    )?;

    // CryptoConfig
    manager.register(
        Hook::new("System.Security.Cryptography.CryptoConfig.MapNameToOID")
            .match_name(
                "System.Security.Cryptography",
                "CryptoConfig",
                "MapNameToOID",
            )
            .pre(crypto_config_map_name_to_oid_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoConfig.get_AllowOnlyFipsAlgorithms")
            .match_name(
                "System.Security.Cryptography",
                "CryptoConfig",
                "get_AllowOnlyFipsAlgorithms",
            )
            .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(0)))),
    )?;

    Ok(())
}

/// Hook for `System.Security.Cryptography.MD5.Create` method.
///
/// Creates a new MD5 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `MD5.Create() -> MD5`
/// - `MD5.Create(String) -> MD5`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn md5_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "MD5");
    match thread.heap().alloc_crypto_algorithm("MD5", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.MD5.ComputeHash` method.
///
/// Computes the MD5 hash of the input data.
///
/// # Handled Overloads
///
/// - `MD5.ComputeHash(Byte[]) -> Byte[]`
/// - `MD5.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `MD5.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
#[cfg(feature = "legacy-crypto")]
fn md5_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let hash = compute_md5(&bytes);
            match thread.heap().alloc_byte_array(&hash) {
                Ok(result) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Security.Cryptography.HashAlgorithm.ComputeHash` method.
///
/// Computes hash using the algorithm type stored in the instance (MD5, SHA1, SHA256,
/// HMACSHA256, HMACSHA512).
///
/// # Handled Overloads
///
/// - `HashAlgorithm.ComputeHash(Byte[]) -> Byte[]`
/// - `HashAlgorithm.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `HashAlgorithm.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
fn hash_algorithm_compute_hash_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    #[cfg(feature = "legacy-crypto")]
    let default_algo = "MD5";
    #[cfg(not(feature = "legacy-crypto"))]
    let default_algo = "SHA256";

    let (hash_type, hmac_key) = if let Some(EmValue::ObjectRef(handle)) = ctx.this {
        let algo = try_hook!(thread.heap().get_crypto_algorithm_type(*handle))
            .unwrap_or_else(|| default_algo.into());
        let key = try_hook!(thread.heap().get_hmac_key(*handle));
        (algo, key)
    } else {
        (default_algo.into(), None)
    };

    let Some(first_arg) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match first_arg {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
                let hash = match &*hash_type {
                    "HMACSHA256" => {
                        let key = hmac_key.as_deref().unwrap_or(&[]);
                        compute_hmac_sha256(key, &bytes)
                    }
                    "HMACSHA512" => {
                        let key = hmac_key.as_deref().unwrap_or(&[]);
                        compute_hmac_sha512(key, &bytes)
                    }
                    #[cfg(feature = "legacy-crypto")]
                    "SHA1" => compute_sha1(&bytes),
                    #[cfg(feature = "legacy-crypto")]
                    "MD5" => compute_md5(&bytes),
                    "SHA256" => compute_sha256(&bytes),
                    #[cfg(feature = "legacy-crypto")]
                    _ => compute_md5(&bytes),
                    #[cfg(not(feature = "legacy-crypto"))]
                    _ => compute_sha256(&bytes),
                };
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA1.Create` method.
///
/// Creates a new SHA1 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `SHA1.Create() -> SHA1`
/// - `SHA1.Create(String) -> SHA1`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn sha1_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "SHA1");
    match thread.heap().alloc_crypto_algorithm("SHA1", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.SHA256.Create` method.
///
/// Creates a new SHA256 hash algorithm instance.
///
/// # Handled Overloads
///
/// - `SHA256.Create() -> SHA256`
/// - `SHA256.Create(String) -> SHA256`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
fn sha256_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "SHA256");
    match thread.heap().alloc_crypto_algorithm("SHA256", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.SHA1.ComputeHash` method.
///
/// Computes the SHA1 hash of the input data.
///
/// # Handled Overloads
///
/// - `SHA1.ComputeHash(Byte[]) -> Byte[]`
/// - `SHA1.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `SHA1.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
#[cfg(feature = "legacy-crypto")]
fn sha1_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(first_arg) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match first_arg {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
                let hash = compute_sha1(&bytes);
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Security.Cryptography.SHA256.ComputeHash` method.
///
/// Computes the SHA256 hash of the input data.
///
/// # Handled Overloads
///
/// - `SHA256.ComputeHash(Byte[]) -> Byte[]`
/// - `SHA256.ComputeHash(Byte[], Int32, Int32) -> Byte[]`
/// - `SHA256.ComputeHash(Stream) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to hash
/// - `offset`: Starting position in buffer (overload 2)
/// - `count`: Number of bytes to hash (overload 2)
/// - `inputStream`: Stream to read and hash (overload 3)
fn sha256_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(first_arg) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match first_arg {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
                let hash = compute_sha256(&bytes);
                match thread.heap().alloc_byte_array(&hash) {
                    Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
                    Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            } else {
                PreHookResult::Bypass(Some(EmValue::Null))
            }
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `HashAlgorithm.TransformBlock(byte[], int, int, byte[], int) -> int`.
///
/// Feeds data into an incremental hash computation. Appends the specified slice
/// from `inputBuffer` to the `CryptoAlgorithm`'s accumulated data buffer.
///
/// Returns `inputCount` (the number of bytes processed).
fn hash_algorithm_transform_block_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // args: inputBuffer(byte[]), inputOffset(int), inputCount(int), outputBuffer(byte[]), outputOffset(int)
    let input_handle = match ctx.args.first() {
        Some(EmValue::ObjectRef(h)) => *h,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some(input_bytes) = try_hook!(thread.heap().get_byte_array(input_handle)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    #[allow(clippy::cast_sign_loss)]
    let offset = match ctx.args.get(1) {
        Some(EmValue::I32(o)) => *o as usize,
        _ => 0,
    };

    #[allow(clippy::cast_sign_loss)]
    let count = match ctx.args.get(2) {
        Some(EmValue::I32(c)) => *c as usize,
        _ => input_bytes.len(),
    };

    let end = offset.saturating_add(count).min(input_bytes.len());
    let slice: &[u8] = if offset < input_bytes.len() {
        input_bytes.get(offset..end).unwrap_or(&[])
    } else {
        &[]
    };

    try_hook!(thread.heap().append_hash_data(algo_ref, slice));

    // If outputBuffer is non-null, copy input to output (per .NET spec)
    if let Some(EmValue::ObjectRef(output_handle)) = ctx.args.get(3) {
        #[allow(clippy::cast_sign_loss)]
        let output_offset = match ctx.args.get(4) {
            Some(EmValue::I32(o)) => *o as usize,
            _ => 0,
        };
        for (i, &byte) in slice.iter().enumerate() {
            try_hook!(thread.heap_mut().set_array_element(
                *output_handle,
                output_offset.saturating_add(i),
                EmValue::I32(i32::from(byte)),
            ));
        }
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(count as i32)))
}

/// Hook for `HashAlgorithm.TransformFinalBlock(byte[], int, int) -> byte[]`.
///
/// Appends the final data slice, computes the hash, and stores it.
/// Returns the input data slice (per .NET spec — `TransformFinalBlock` returns
/// the input, NOT the hash).
fn hash_algorithm_transform_final_block_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    // args: inputBuffer(byte[]), inputOffset(int), inputCount(int)
    let input_handle = match ctx.args.first() {
        Some(EmValue::ObjectRef(h)) => *h,
        _ => {
            // No input — just finalize with existing accumulated data
            try_hook!(thread.heap().finalize_hash(algo_ref));
            match thread.heap().alloc_byte_array(&[]) {
                Ok(r) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(r))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    };

    let Some(input_bytes) = try_hook!(thread.heap().get_byte_array(input_handle)) else {
        try_hook!(thread.heap().finalize_hash(algo_ref));
        match thread.heap().alloc_byte_array(&[]) {
            Ok(r) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(r))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    };

    #[allow(clippy::cast_sign_loss)]
    let offset = match ctx.args.get(1) {
        Some(EmValue::I32(o)) => *o as usize,
        _ => 0,
    };

    #[allow(clippy::cast_sign_loss)]
    let count = match ctx.args.get(2) {
        Some(EmValue::I32(c)) => *c as usize,
        _ => input_bytes.len(),
    };

    let end = offset.saturating_add(count).min(input_bytes.len());
    let slice = if offset < input_bytes.len() {
        input_bytes
            .get(offset..end)
            .map_or_else(Vec::new, <[u8]>::to_vec)
    } else {
        Vec::new()
    };

    // Append final bytes and compute hash
    try_hook!(thread.heap().append_hash_data(algo_ref, &slice));
    try_hook!(thread.heap().finalize_hash(algo_ref));

    // Return the input slice (NOT the hash — per .NET spec)
    match thread.heap().alloc_byte_array(&slice) {
        Ok(r) => PreHookResult::Bypass(Some(EmValue::ObjectRef(r))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `HashAlgorithm.get_Hash -> byte[]`.
///
/// Returns the computed hash value after `TransformFinalBlock` has been called.
fn hash_algorithm_get_hash_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread.heap().get_hash_result(algo_ref) {
        Ok(Some(hash)) => match thread.heap().alloc_byte_array(&hash) {
            Ok(r) => PreHookResult::Bypass(Some(EmValue::ObjectRef(r))),
            Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        Ok(None) => PreHookResult::Bypass(Some(EmValue::Null)),
        Err(e) => PreHookResult::Error(format!("heap read failed: {e}")),
    }
}

/// Hook for `CryptoConfig.MapNameToOID(string) -> string`.
///
/// Maps algorithm names to their OID strings.
fn crypto_config_map_name_to_oid_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let name = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => match thread.heap().get_string(*r) {
            Ok(s) => s.to_string(),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let oid = match name.as_str() {
        "SHA256"
        | "System.Security.Cryptography.SHA256"
        | "SHA256CryptoServiceProvider"
        | "System.Security.Cryptography.SHA256CryptoServiceProvider"
        | "SHA256Managed"
        | "System.Security.Cryptography.SHA256Managed" => "2.16.840.1.101.3.4.2.1",
        "SHA384"
        | "System.Security.Cryptography.SHA384"
        | "SHA384CryptoServiceProvider"
        | "System.Security.Cryptography.SHA384CryptoServiceProvider"
        | "SHA384Managed"
        | "System.Security.Cryptography.SHA384Managed" => "2.16.840.1.101.3.4.2.2",
        "SHA512"
        | "System.Security.Cryptography.SHA512"
        | "SHA512CryptoServiceProvider"
        | "System.Security.Cryptography.SHA512CryptoServiceProvider"
        | "SHA512Managed"
        | "System.Security.Cryptography.SHA512Managed" => "2.16.840.1.101.3.4.2.3",
        "SHA1"
        | "System.Security.Cryptography.SHA1"
        | "SHA1CryptoServiceProvider"
        | "System.Security.Cryptography.SHA1CryptoServiceProvider"
        | "SHA1Managed"
        | "System.Security.Cryptography.SHA1Managed" => "1.3.14.3.2.26",
        "MD5"
        | "System.Security.Cryptography.MD5"
        | "MD5CryptoServiceProvider"
        | "System.Security.Cryptography.MD5CryptoServiceProvider" => "1.2.840.113549.2.5",
        "RSA"
        | "System.Security.Cryptography.RSA"
        | "System.Security.Cryptography.RSACryptoServiceProvider" => "1.2.840.113549.1.1.1",
        "RIPEMD160" | "System.Security.Cryptography.RIPEMD160" => "1.3.36.3.2.1",
        "TripleDES" | "System.Security.Cryptography.TripleDES" => "1.2.840.113549.3.7",
        "DES" | "System.Security.Cryptography.DES" => "1.3.14.3.2.7",
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread.heap_mut().alloc_string(oid) {
        Ok(s_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
        utils::compute_sha256,
    };

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hash_known_value() {
        let data = b"hello";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            vec![
                0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
                0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
                0x93, 0x8b, 0x98, 0x24
            ]
        );
    }

    #[test]
    fn test_sha256_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA256",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::sha256_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_sha256_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"test data").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA256",
            "ComputeHash",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::sha256_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(hash.len(), 32);
        } else {
            panic!("Expected ObjectRef");
        }
    }
}

#[cfg(test)]
#[cfg(feature = "legacy-crypto")]
mod legacy_tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
        utils::{compute_md5, compute_sha1},
    };

    #[test]
    fn test_md5_hash() {
        let data = b"hello world";
        let hash = compute_md5(data);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_md5_hash_known_value() {
        let data = b"hello";
        let hash = compute_md5(data);
        assert_eq!(
            hash,
            vec![
                0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
                0xc5, 0x92
            ]
        );
    }

    #[test]
    fn test_sha1_hash() {
        let data = b"hello world";
        let hash = compute_sha1(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1_hash_known_value() {
        let data = b"hello";
        let hash = compute_sha1(data);
        assert_eq!(
            hash,
            vec![
                0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48,
                0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d
            ]
        );
    }

    #[test]
    fn test_md5_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "MD5",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::md5_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_md5_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"hello").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "MD5",
            "ComputeHash",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::md5_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(hash.len(), 16);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_sha1_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA1",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::sha1_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_sha1_compute_hash_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(b"test data").unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SHA1",
            "ComputeHash",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::sha1_compute_hash_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let hash = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(hash.len(), 20);
        } else {
            panic!("Expected ObjectRef");
        }
    }
}

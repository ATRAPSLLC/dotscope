//! HMAC keyed hashing hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for HMAC (Hash-based Message Authentication Code)
//! algorithms used by .NET obfuscators. HMAC combines a secret key with a hash function to
//! produce authenticated message digests.
//!
//! # Covered APIs
//!
//! - **HMACSHA256**: `.ctor(byte[])`, `ComputeHash(byte[])` — 256-bit keyed hash
//! - **HMACSHA512**: `.ctor(byte[])`, `ComputeHash(byte[])` — 512-bit keyed hash
//!
//! # Implementation Notes
//!
//! HMAC functions are fully implemented using the `hmac` crate with `sha2`.
//! The key is stored on the heap object and used for subsequent `ComputeHash` calls.

use crate::{
    emulation::{
        runtime::{
            bcl::crypto::bytes_argument,
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue, HeapObject,
    },
    utils::{compute_hmac_sha256, compute_hmac_sha512},
    Result,
};

/// Registers all HMAC algorithm hooks.
///
/// Called by the parent `crypto::register()` to wire up HMACSHA256 and HMACSHA512 hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // HMACSHA256
    manager.register(
        Hook::new("System.Security.Cryptography.HMACSHA256..ctor")
            .match_name("System.Security.Cryptography", "HMACSHA256", ".ctor")
            .pre(hmacsha256_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.HMACSHA256.ComputeHash")
            .match_name("System.Security.Cryptography", "HMACSHA256", "ComputeHash")
            .pre(hmac_compute_hash_pre),
    )?;

    // HMACSHA512
    manager.register(
        Hook::new("System.Security.Cryptography.HMACSHA512..ctor")
            .match_name("System.Security.Cryptography", "HMACSHA512", ".ctor")
            .pre(hmacsha512_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.HMACSHA512.ComputeHash")
            .match_name("System.Security.Cryptography", "HMACSHA512", "ComputeHash")
            .pre(hmac_compute_hash_pre),
    )?;

    Ok(())
}

/// Hook for `System.Security.Cryptography.HMACSHA256..ctor(byte[] key)`.
///
/// Initializes the object `newobj` allocated as an HMAC-SHA256 algorithm with the given key.
///
/// # Handled Overloads
///
/// - `HMACSHA256..ctor(Byte[])` — stores key for later `ComputeHash` calls
///
/// # Parameters
///
/// - `key`: The HMAC key bytes
fn hmacsha256_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // `HMACSHA*()` draws a random key; for emulation a fixed (empty) one is as good a key
    let key = match bytes_argument(thread, ctx.args.first(), "key", false) {
        Ok(key) => key.unwrap_or_default(),
        Err(result) => return result,
    };

    // The constructor initializes `this`, the object `newobj` pushes, and returns nothing
    let Some(EmValue::ObjectRef(this_ref)) = ctx.this else {
        return PreHookResult::Error("HMACSHA256..ctor without `this`".into());
    };
    let algorithm = HeapObject::CryptoAlgorithm {
        algorithm_type: "HMACSHA256".into(),
        accumulated_data: Vec::new(),
        hash_result: None,
        rsa_public_key: None,
        hmac_key: Some(key),
    };
    match thread.heap().replace_object(*this_ref, algorithm) {
        Ok(()) => PreHookResult::Bypass(None),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.HMACSHA512..ctor(byte[] key)`.
///
/// Initializes the object `newobj` allocated as an HMAC-SHA512 algorithm with the given key.
///
/// # Handled Overloads
///
/// - `HMACSHA512..ctor(Byte[])` — stores key for later `ComputeHash` calls
///
/// # Parameters
///
/// - `key`: The HMAC key bytes
fn hmacsha512_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // `HMACSHA*()` draws a random key; for emulation a fixed (empty) one is as good a key
    let key = match bytes_argument(thread, ctx.args.first(), "key", false) {
        Ok(key) => key.unwrap_or_default(),
        Err(result) => return result,
    };

    // The constructor initializes `this`, the object `newobj` pushes, and returns nothing
    let Some(EmValue::ObjectRef(this_ref)) = ctx.this else {
        return PreHookResult::Error("HMACSHA512..ctor without `this`".into());
    };
    let algorithm = HeapObject::CryptoAlgorithm {
        algorithm_type: "HMACSHA512".into(),
        accumulated_data: Vec::new(),
        hash_result: None,
        rsa_public_key: None,
        hmac_key: Some(key),
    };
    match thread.heap().replace_object(*this_ref, algorithm) {
        Ok(()) => PreHookResult::Bypass(None),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `HMACSHA256.ComputeHash(byte[])` / `HMACSHA512.ComputeHash(byte[])`.
///
/// Computes the HMAC of the input data using the key stored on the instance.
/// Dispatches to HMAC-SHA256 or HMAC-SHA512 based on the algorithm type stored
/// in the `CryptoAlgorithm` heap object.
///
/// # Handled Overloads
///
/// - `ComputeHash(Byte[]) -> Byte[]`
///
/// # Parameters
///
/// - `buffer`: Input byte array to authenticate
fn hmac_compute_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (algo_type, hmac_key) = match ctx.this {
        Some(EmValue::ObjectRef(handle)) => {
            // An object no HMAC constructor initialized has no key to hash with: hashing it
            // with an empty one, as SHA-256, answered for an object the emulation lost
            let (Some(algo), Some(key)) = (
                try_hook!(thread.heap().get_crypto_algorithm_type(*handle)),
                try_hook!(thread.heap().get_hmac_key(*handle)),
            ) else {
                return PreHookResult::Error(
                    "HMAC ComputeHash on an object no HMAC constructor initialized".into(),
                );
            };
            (algo, key)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let Some(arg0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };
    match arg0 {
        EmValue::ObjectRef(handle) => {
            if let Some(bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
                let key = hmac_key.as_slice();
                let hash = match algo_type.as_ref() {
                    "HMACSHA512" => compute_hmac_sha512(key, &bytes),
                    _ => compute_hmac_sha256(key, &bytes),
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

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
        utils::{compute_hmac_sha256, compute_hmac_sha512},
    };

    #[test]
    fn test_hmacsha256_ctor_hook() {
        let mut thread = create_test_thread();
        let key_data = thread.heap().alloc_byte_array(b"secret-key").unwrap();
        let args = [EmValue::ObjectRef(key_data)];
        let handle = thread.heap().alloc_object(Token::new(0x0100_0001)).unwrap();
        let this = EmValue::ObjectRef(handle);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA256",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        // The constructor initializes `this`, the object `newobj` pushes, and returns nothing
        let result = super::hmacsha256_ctor_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(None) = result {
            let algo_type = thread
                .heap()
                .get_crypto_algorithm_type(handle)
                .unwrap()
                .unwrap();
            assert_eq!(algo_type.as_ref(), "HMACSHA256");
            let stored_key = thread.heap().get_hmac_key(handle).unwrap().unwrap();
            assert_eq!(stored_key, b"secret-key");
        } else {
            panic!("HMACSHA256..ctor initializes `this` and returns nothing");
        }
    }

    #[test]
    fn test_hmacsha512_ctor_hook() {
        let mut thread = create_test_thread();
        let key_data = thread.heap().alloc_byte_array(b"another-key").unwrap();
        let args = [EmValue::ObjectRef(key_data)];
        let handle = thread.heap().alloc_object(Token::new(0x0100_0001)).unwrap();
        let this = EmValue::ObjectRef(handle);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA512",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        // The constructor initializes `this`, the object `newobj` pushes, and returns nothing
        let result = super::hmacsha512_ctor_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(None) = result {
            let algo_type = thread
                .heap()
                .get_crypto_algorithm_type(handle)
                .unwrap()
                .unwrap();
            assert_eq!(algo_type.as_ref(), "HMACSHA512");
            let stored_key = thread.heap().get_hmac_key(handle).unwrap().unwrap();
            assert_eq!(stored_key, b"another-key");
        } else {
            panic!("HMACSHA512..ctor initializes `this` and returns nothing");
        }
    }

    #[test]
    fn test_hmacsha256_compute_hash_hook() {
        let mut thread = create_test_thread();
        let key_bytes = b"test-key";
        let data_bytes = b"hello world";

        // Create HMAC instance
        let key_ref = thread.heap().alloc_byte_array(key_bytes).unwrap();
        let ctor_args = [EmValue::ObjectRef(key_ref)];
        let hmac_ref = thread.heap().alloc_object(Token::new(0x0100_0001)).unwrap();
        let hmac = EmValue::ObjectRef(hmac_ref);
        let ctor_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA256",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&hmac))
        .with_args(&ctor_args);
        assert!(matches!(
            super::hmacsha256_ctor_pre(&ctor_ctx, &mut thread),
            PreHookResult::Bypass(None)
        ));

        // ComputeHash
        let input = thread.heap().alloc_byte_array(data_bytes).unwrap();
        let compute_args = [EmValue::ObjectRef(input)];
        let this = EmValue::ObjectRef(hmac_ref);
        let compute_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA256",
            "ComputeHash",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&compute_args);

        let result = super::hmac_compute_hash_pre(&compute_ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(hash_ref))) = result {
            let hash = thread.heap().get_byte_array(hash_ref).unwrap().unwrap();
            let expected = compute_hmac_sha256(key_bytes, data_bytes);
            assert_eq!(hash, expected);
            assert_eq!(hash.len(), 32);
        } else {
            panic!("Expected ObjectRef from ComputeHash");
        }
    }

    #[test]
    fn test_hmacsha512_compute_hash_hook() {
        let mut thread = create_test_thread();
        let key_bytes = b"test-key-512";
        let data_bytes = b"hello world";

        // Create HMAC instance
        let key_ref = thread.heap().alloc_byte_array(key_bytes).unwrap();
        let ctor_args = [EmValue::ObjectRef(key_ref)];
        let hmac_ref = thread.heap().alloc_object(Token::new(0x0100_0001)).unwrap();
        let hmac = EmValue::ObjectRef(hmac_ref);
        let ctor_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA512",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&hmac))
        .with_args(&ctor_args);
        assert!(matches!(
            super::hmacsha512_ctor_pre(&ctor_ctx, &mut thread),
            PreHookResult::Bypass(None)
        ));

        // ComputeHash
        let input = thread.heap().alloc_byte_array(data_bytes).unwrap();
        let compute_args = [EmValue::ObjectRef(input)];
        let this = EmValue::ObjectRef(hmac_ref);
        let compute_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "HMACSHA512",
            "ComputeHash",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&compute_args);

        let result = super::hmac_compute_hash_pre(&compute_ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(hash_ref))) = result {
            let hash = thread.heap().get_byte_array(hash_ref).unwrap().unwrap();
            let expected = compute_hmac_sha512(key_bytes, data_bytes);
            assert_eq!(hash, expected);
            assert_eq!(hash.len(), 64);
        } else {
            panic!("Expected ObjectRef from ComputeHash");
        }
    }
}

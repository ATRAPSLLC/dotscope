//! `System.Security.Cryptography` method hooks for deobfuscation.
//!
//! This module provides hook implementations for cryptographic methods commonly used by
//! obfuscators to encrypt strings, resources, and code. These hooks are essential for
//! analyzing protected .NET assemblies that use encryption to hide their payloads.
//!
//! # Module Hierarchy
//!
//! The crypto hooks are organized into five submodules by category:
//!
//! - [`hashing`] — Hash algorithms (MD5, SHA1, SHA256, HashAlgorithm) and CryptoConfig.
//!   Hash functions are the foundation of key derivation and checksum
//!   verification in obfuscated assemblies.
//!
//! - [`hmac`] — HMAC keyed hashing (HMACSHA256, HMACSHA512). Combines a secret key
//!   with a hash function to produce authenticated message digests.
//!
//! - [`rng`] — Random number generation (RNGCryptoServiceProvider, RandomNumberGenerator).
//!   Implemented as a deterministic xorshift64 PRNG for reproducible emulation.
//!
//! - [`symmetric`] — Symmetric ciphers (AES, DES, TripleDES), asymmetric algorithms (RSA),
//!   and crypto transform/stream operations. These perform the actual encryption and
//!   decryption of protected payloads.
//!
//! - [`derivation`] — Key derivation functions (PBKDF1 via `PasswordDeriveBytes`, PBKDF2
//!   via `Rfc2898DeriveBytes`). Obfuscators use these to derive encryption keys from
//!   embedded password strings.
//!
//! # Shared Helpers
//!
//! This root module exports two helpers used across submodules:
//!
//! - [`resolve_crypto_key_iv`] — Resolves algorithm name, key, IV, cipher mode, and
//!   padding from a `CreateDecryptor`/`CreateEncryptor` call context. Used by the
//!   symmetric module's decryptor/encryptor hooks.
//!
//! - [`extract_xml_element`] — Simple string-based XML element extraction. Used by the
//!   symmetric module's RSA `FromXmlString` hook to parse public key XML.
//!
//! # Overview
//!
//! Obfuscators frequently use cryptography to:
//! - Encrypt string literals to prevent static analysis
//! - Protect embedded resources containing code or data
//! - Derive decryption keys from assembly metadata or passwords
//! - Implement license checking and tamper detection
//!
//! # Emulated .NET Methods
//!
//! ## Hash Algorithms
//!
//! | Class | Methods | Output Size |
//! |-------|---------|-------------|
//! | `MD5` | `Create()`, `ComputeHash(byte[])` | 16 bytes |
//! | `SHA1` | `Create()`, `ComputeHash(byte[])` | 20 bytes |
//! | `SHA256` | `Create()`, `ComputeHash(byte[])` | 32 bytes |
//! | `HashAlgorithm` | `ComputeHash(byte[])` | Varies by type |
//!
//! ## Symmetric Encryption
//!
//! | Class | Methods |
//! |-------|---------|
//! | `Aes` | `Create()` |
//! | `RijndaelManaged` | `.ctor`, `CreateDecryptor()`, `CreateEncryptor()` |
//! | `DES` | `Create()` |
//! | `TripleDES` | `Create()` |
//! | `SymmetricAlgorithm` | `get_Key`, `get_IV`, `set_Key`, `set_IV`, `set_Mode`, `set_Padding` |
//!
//! ## Transforms and Streams
//!
//! | Class | Methods |
//! |-------|---------|
//! | `ICryptoTransform` | `TransformBlock(byte[], int, int, byte[], int)`, `TransformFinalBlock(byte[], int, int)` |
//! | `CryptoStream` | `.ctor`, `Read()`, `Write()`, `FlushFinalBlock()` |
//!
//! ## Key Derivation
//!
//! | Class | Methods |
//! |-------|---------|
//! | `PasswordDeriveBytes` | `.ctor`, `GetBytes(int)` |
//! | `Rfc2898DeriveBytes` | `.ctor`, `GetBytes(int)` (PBKDF2) |
//!
//! # Deobfuscation Use Cases
//!
//! ## Capturing Encryption Keys
//!
//! The `set_Key` and `set_IV` hooks capture cryptographic keys and initialization
//! vectors for later analysis:
//!
//! ```csharp
//! // Obfuscator code pattern
//! var aes = Aes.Create();
//! aes.Key = derivedKey;  // <-- Captured by set_Key hook
//! aes.IV = derivedIV;    // <-- Captured by set_IV hook
//! var decryptor = aes.CreateDecryptor();
//! ```
//!
//! ## Hash-Based Key Derivation
//!
//! Many obfuscators derive keys from MD5/SHA1 hashes of strings:
//!
//! ```csharp
//! // Common pattern
//! string password = "obfuscated_key";
//! byte[] keyBytes = Encoding.UTF8.GetBytes(password);
//! byte[] key = MD5.Create().ComputeHash(keyBytes);  // <-- Real hash computed
//! ```
//!
//! # Implementation Notes
//!
//! - **Hash functions are fully implemented** using the `md5`, `sha1`, and `sha2` crates
//! - **Symmetric encryption hooks capture keys/IVs** but don't perform actual encryption
//! - **Transform hooks pass through input data** for analysis
//! - **Full key derivation support** - PBKDF1 and PBKDF2 with SHA1/256/384/512

mod derivation;
mod hashing;
mod hmac;
mod rng;
mod symmetric;

use crate::{
    emulation::{
        capture::{BufferSource, CaptureSource},
        engine::synthetic_exception,
        runtime::hook::{HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::token::Token,
    utils::{apply_crypto_transform, CryptoFailure},
    Result,
};

/// Registers all cryptographic method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Categories
///
/// - **Hashing**: MD5, SHA1, SHA256, HashAlgorithm, CryptoConfig
/// - **HMAC**: HMACSHA256, HMACSHA512
/// - **RNG**: RNGCryptoServiceProvider, RandomNumberGenerator
/// - **Symmetric/Asymmetric**: AES, Rijndael, DES, TripleDES, RSA, ICryptoTransform, CryptoStream
/// - **Key Derivation**: PasswordDeriveBytes (PBKDF1), Rfc2898DeriveBytes (PBKDF2)
pub fn register(manager: &HookManager) -> Result<()> {
    hashing::register(manager)?;
    hmac::register(manager)?;
    rng::register(manager)?;
    symmetric::register(manager)?;
    derivation::register(manager)?;
    Ok(())
}

/// Resolves the algorithm name, key, IV, mode, and padding for a `CreateDecryptor`/`CreateEncryptor` call.
///
/// Handles both overloads:
/// - No-arg: reads key/IV from the `SymmetricAlgorithm` heap object
/// - Two-arg `(byte[] rgbKey, byte[] rgbIV)`: extracts key/IV from the explicit arguments
///
/// Returns `(algorithm, Option<key>, Option<iv>, mode, padding)`.
pub fn resolve_crypto_key_iv(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
    algo_ref: HeapRef,
) -> (String, Option<Vec<u8>>, Option<Vec<u8>>, u8, u8) {
    // Try explicit arguments first (2-arg overload: CreateDecryptor(byte[], byte[]))
    if ctx.args.len() == 2 {
        let arg_key = match ctx.args.first() {
            Some(EmValue::ObjectRef(h)) => thread.heap().get_byte_array(*h).ok().flatten(),
            _ => None,
        };
        let arg_iv = match ctx.args.get(1) {
            Some(EmValue::ObjectRef(h)) => thread.heap().get_byte_array(*h).ok().flatten(),
            _ => None,
        };

        if let Some(key) = arg_key {
            // Get algo name and mode/padding from the object, but use explicit key/IV
            let (algorithm, _, _, mode, padding) = thread
                .heap()
                .get_symmetric_algorithm_info(algo_ref)
                .ok()
                .flatten()
                .unwrap_or_else(|| (String::new().into(), None, None, 1, 2));
            let iv = arg_iv.unwrap_or_else(|| {
                let iv_len = if algorithm.contains("DES") { 8 } else { 16 };
                vec![0u8; iv_len]
            });
            return (algorithm.to_string(), Some(key), Some(iv), mode, padding);
        }
    }

    // Fall back to stored key/IV on the algorithm object
    match thread.heap().get_symmetric_algorithm_info(algo_ref) {
        Ok(Some((alg, Some(k), Some(i), m, p))) => (alg.to_string(), Some(k), Some(i), m, p),
        Ok(Some((alg, Some(k), None, m, p))) => {
            let iv_len = if alg.contains("DES") { 8 } else { 16 };
            (alg.to_string(), Some(k), Some(vec![0u8; iv_len]), m, p)
        }
        Ok(Some((alg, None, iv, m, p))) => (alg.to_string(), None, iv, m, p),
        // Not a symmetric algorithm the heap knows: no algorithm, which the transform reports
        // as not emulated rather than computing some other cipher
        _ => (String::new(), None, None, 1, 2),
    }
}

/// The whole of `data` through the transform `transform_ref`, as a `CryptoStream` passes
/// what it reads or writes through it: padded when encrypting, unpadded when decrypting. The
/// output is recorded in the capture (`encrypted_stream` or `decrypted_stream`); a failure is
/// the hook result [`transform_failure`] gives, and a `transform_ref` that is no emulated
/// transform an emulation error. Never the input handed back as the output.
///
/// # Arguments
///
/// * `thread` - The emulation thread, for the heap and the capture
/// * `transform_ref` - The stream's `ICryptoTransform`
/// * `data` - What the stream reads or writes
pub fn transform_stream_data(
    thread: &mut EmulationThread,
    transform_ref: HeapRef,
    data: &[u8],
) -> std::result::Result<Vec<u8>, PreHookResult> {
    let (algorithm, key, iv, is_encryptor, mode, padding) =
        match thread.heap().get_crypto_transform_info(transform_ref) {
            Ok(Some(info)) => info,
            Ok(None) => {
                return Err(PreHookResult::Error(
                    "a CryptoStream whose transform is no emulated transform".to_string(),
                ))
            }
            Err(e) => return Err(PreHookResult::Error(format!("heap read failed: {e}"))),
        };
    let output = apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, data, mode, padding)
        .map_err(transform_failure)?;
    let source = CaptureSource::new(
        thread.current_method().unwrap_or(Token::new(0)),
        thread.id(),
        thread.current_offset().unwrap_or(0),
        0,
    );
    thread.capture().capture_buffer(
        output.clone(),
        source,
        BufferSource::CryptoTransform {
            algorithm: algorithm.to_string(),
        },
        if is_encryptor {
            "encrypted_stream"
        } else {
            "decrypted_stream"
        },
    );
    Ok(output)
}

/// Completes the CryptoStream `stream_ref` as the runtime's `FlushFinalBlock` does: a
/// write-mode stream passes what it buffered through its transform's final block (padding
/// it when encrypting, unpadding it when decrypting) into the stream beneath, and a
/// CryptoStream beneath is completed in turn, unless it already is.
///
/// `explicit` is a `FlushFinalBlock` call, for which a stream already completed is the
/// `NotSupportedException` the runtime throws; otherwise it is `Dispose` or `Close`, which
/// complete a stream only once, so a `using` block or `Close()` without `FlushFinalBlock`
/// still writes the final block, as the runtime does.
///
/// # Returns
///
/// Whether `stream_ref` is a CryptoStream. A failure is the hook result to give.
///
/// # Arguments
///
/// * `thread` - The emulation thread, for the heap and the capture
/// * `stream_ref` - The stream being completed
/// * `explicit` - Whether this is `FlushFinalBlock` rather than `Dispose` or `Close`
pub fn finish_crypto_stream(
    thread: &mut EmulationThread,
    stream_ref: HeapRef,
    explicit: bool,
) -> std::result::Result<bool, PreHookResult> {
    let heap_error = |e| PreHookResult::Error(format!("heap access failed: {e}"));
    let Some(done) = thread
        .heap()
        .mark_crypto_stream_final_block(stream_ref)
        .map_err(heap_error)?
    else {
        return Ok(false);
    };
    if done {
        return if explicit {
            Err(PreHookResult::Throw {
                exception_type: synthetic_exception::NOT_SUPPORTED,
                message: "FlushFinalBlock() method was called twice on a CryptoStream. It can \
                          only be called once."
                    .to_string(),
            })
        } else {
            Ok(true)
        };
    }
    let Some((underlying, transform_ref, mode)) = thread
        .heap()
        .get_crypto_stream_info(stream_ref)
        .map_err(heap_error)?
    else {
        return Err(PreHookResult::Error(
            "a CryptoStream without its stream and transform".to_string(),
        ));
    };
    if mode == 1 {
        let buffered = thread
            .heap()
            .get_crypto_stream_write_buffer(stream_ref)
            .map_err(heap_error)?
            .unwrap_or_default();
        // Even no data is a final block: a padding encryptor writes a block of padding
        let final_block = transform_stream_data(thread, transform_ref, &buffered)?;
        let heap = thread.heap();
        if !heap
            .crypto_stream_append_write(underlying, &final_block)
            .map_err(heap_error)?
        {
            if heap
                .get_stream_data(underlying)
                .map_err(heap_error)?
                .is_none()
            {
                return Err(PreHookResult::Error(
                    "a CryptoStream over no emulated stream".to_string(),
                ));
            }
            heap.write_to_stream(underlying, &final_block)
                .map_err(heap_error)?;
        }
        heap.clear_crypto_stream_write_buffer(stream_ref)
            .map_err(heap_error)?;
    }
    finish_crypto_stream(thread, underlying, false)?;
    Ok(true)
}

/// The bytes a cryptography argument holds: a byte array, or, where `string` is set (a
/// password), a string as its UTF-8, as the runtime encodes it. `Ok(None)` when the call
/// passes no such argument. A null argument is the `ArgumentNullException` the runtime
/// throws, and an argument of another type the `ArgumentException`.
///
/// # Arguments
///
/// * `thread` - The emulation thread, for the heap
/// * `arg` - The argument, if the call has it
/// * `name` - The parameter's name, for the exception
/// * `string` - Whether a string is accepted (and encoded as UTF-8)
pub fn bytes_argument(
    thread: &EmulationThread,
    arg: Option<&EmValue>,
    name: &str,
    string: bool,
) -> std::result::Result<Option<Vec<u8>>, PreHookResult> {
    match arg {
        None => Ok(None),
        Some(EmValue::ObjectRef(handle)) => {
            if string {
                if let Some(text) = thread.heap().get_string_opt(*handle) {
                    return Ok(Some(text.as_bytes().to_vec()));
                }
            }
            match thread.heap().get_byte_array(*handle) {
                Ok(Some(bytes)) => Ok(Some(bytes)),
                Ok(None) => Err(PreHookResult::Throw {
                    exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
                    message: format!("{name} is not a byte array"),
                }),
                Err(e) => Err(PreHookResult::Error(format!("heap read failed: {e}"))),
            }
        }
        Some(EmValue::Null) => Err(PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_NULL,
            message: name.to_string(),
        }),
        Some(other) => Err(PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_EXCEPTION,
            message: format!("{name} is {}, not a byte array", other.cil_flavor()),
        }),
    }
}

/// The hook result for a symmetric transform that produced nothing: the
/// `CryptographicException` the runtime throws for what it refuses (a key of the wrong size,
/// input that is not whole blocks, bad padding), or an emulation error for what the emulator
/// does not compute. Never the input handed back as if it were the output.
pub fn transform_failure(failure: CryptoFailure) -> PreHookResult {
    match failure {
        CryptoFailure::Invalid(message) => PreHookResult::Throw {
            exception_type: synthetic_exception::CRYPTOGRAPHIC,
            message,
        },
        CryptoFailure::Unsupported(what) => {
            PreHookResult::Error(format!("symmetric transform not emulated: {what}"))
        }
    }
}

/// Extracts the text content of an XML element by tag name.
///
/// Simple string-based extraction (no full XML parser needed).
pub fn extract_xml_element(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?.saturating_add(open.len());
    let tail = xml.get(start..)?;
    let end = tail.find(&close)?.saturating_add(start);
    Some(xml.get(start..end)?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::{bcl::crypto::register, hook::HookManager};

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        // Should have registered many hooks
        assert!(manager.len() >= 15);
    }
}

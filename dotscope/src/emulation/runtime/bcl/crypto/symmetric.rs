//! Symmetric and asymmetric encryption hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for symmetric ciphers (AES, DES, TripleDES),
//! asymmetric algorithms (RSA), and crypto transform/stream operations. These are the
//! core encryption primitives that .NET obfuscators use to protect strings, resources,
//! and method bodies.
//!
//! # Covered APIs
//!
//! ## Symmetric Algorithms
//!
//! - **AES/Rijndael**: `Aes.Create()`, `RijndaelManaged..ctor`, `CreateDecryptor()`, `CreateEncryptor()`
//! - **DES** (`legacy-crypto`): `DES.Create()`, `TripleDES.Create()`
//! - **SymmetricAlgorithm**: `get_Key`, `get_IV`, `set_Key`, `set_IV`, `set_Mode`, `set_Padding`
//!
//! ## Asymmetric Algorithms
//!
//! - **RSA**: `RSACryptoServiceProvider..ctor`, `RSA.Create()`, `FromXmlString()`, `VerifyHash()`
//!
//! ## Transforms and Streams
//!
//! - **ICryptoTransform**: `TransformBlock(byte[], int, int, byte[], int)` — incremental
//!   block-by-block encryption/decryption with CBC IV chaining;
//!   `TransformFinalBlock(byte[], int, int)` — final block with padding
//! - **CryptoStream**: `.ctor`, `Read()`, `Write()`, `FlushFinalBlock()` — wraps a stream
//!   with a crypto transform for streaming encryption/decryption
//!
//! # Key Capture
//!
//! The `set_Key` and `set_IV` hooks capture cryptographic keys and initialization vectors
//! for later analysis, making them available in the deobfuscation capture log.

use crate::{
    emulation::{
        capture::{BufferSource, CaptureSource},
        runtime::{
            bcl::crypto::{extract_xml_element, resolve_crypto_key_iv},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    metadata::token::Token,
    utils::{apply_crypto_transform, base64_decode, rsa_verify_work, verify_rsa_pkcs1v15},
    Result,
};

/// Registers all symmetric encryption, asymmetric encryption, and transform hooks.
///
/// Called by the parent `crypto::register()` to wire up AES/Rijndael, DES/TripleDES,
/// RSA, `ICryptoTransform`, and `CryptoStream` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // AES / Rijndael
    manager.register(
        Hook::new("System.Security.Cryptography.Aes.Create")
            .match_name("System.Security.Cryptography", "Aes", "Create")
            .pre(aes_create_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RijndaelManaged..ctor")
            .match_name("System.Security.Cryptography", "RijndaelManaged", ".ctor")
            .pre(rijndael_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.AesManaged..ctor")
            .match_name("System.Security.Cryptography", "AesManaged", ".ctor")
            .pre(aes_managed_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.Aes..ctor")
            .match_name("System.Security.Cryptography", "Aes", ".ctor")
            .pre(aes_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.CreateDecryptor")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "CreateDecryptor",
            )
            .pre(create_decryptor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.CreateEncryptor")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "CreateEncryptor",
            )
            .pre(create_encryptor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RijndaelManaged.CreateDecryptor")
            .match_name(
                "System.Security.Cryptography",
                "RijndaelManaged",
                "CreateDecryptor",
            )
            .pre(create_decryptor_pre),
    )?;

    // SymmetricAlgorithm property setters
    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Key")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Key",
            )
            .pre(set_key_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_IV")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_IV",
            )
            .pre(set_iv_pre),
    )?;

    // SymmetricAlgorithm property getters
    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.get_Key")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "get_Key",
            )
            .pre(get_key_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.get_IV")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "get_IV",
            )
            .pre(get_iv_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Mode")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Mode",
            )
            .pre(set_mode_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.SymmetricAlgorithm.set_Padding")
            .match_name(
                "System.Security.Cryptography",
                "SymmetricAlgorithm",
                "set_Padding",
            )
            .pre(set_padding_pre),
    )?;

    // DES / TripleDES (legacy-crypto only)
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.DES.Create")
            .match_name("System.Security.Cryptography", "DES", "Create")
            .pre(des_create_pre),
    )?;

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.TripleDES.Create")
            .match_name("System.Security.Cryptography", "TripleDES", "Create")
            .pre(triple_des_create_pre),
    )?;

    // RSA
    manager.register(
        Hook::new("System.Security.Cryptography.RSACryptoServiceProvider..ctor")
            .match_name(
                "System.Security.Cryptography",
                "RSACryptoServiceProvider",
                ".ctor",
            )
            .pre(rsa_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RSA.Create")
            .match_name("System.Security.Cryptography", "RSA", "Create")
            .pre(rsa_create_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RSACryptoServiceProvider.set_UseMachineKeyStore")
            .match_name(
                "System.Security.Cryptography",
                "RSACryptoServiceProvider",
                "set_UseMachineKeyStore",
            )
            .pre(rsa_set_use_machine_key_store_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RSA.FromXmlString")
            .match_name("System.Security.Cryptography", "RSA", "FromXmlString")
            .pre(rsa_from_xml_string_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.AsymmetricAlgorithm.FromXmlString")
            .match_name(
                "System.Security.Cryptography",
                "AsymmetricAlgorithm",
                "FromXmlString",
            )
            .pre(rsa_from_xml_string_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RSACryptoServiceProvider.VerifyHash")
            .match_name(
                "System.Security.Cryptography",
                "RSACryptoServiceProvider",
                "VerifyHash",
            )
            .pre(rsa_verify_hash_pre),
    )?;

    // ICryptoTransform / CryptoStream
    manager.register(
        Hook::new("System.Security.Cryptography.ICryptoTransform.TransformBlock")
            .match_name(
                "System.Security.Cryptography",
                "ICryptoTransform",
                "TransformBlock",
            )
            .pre(transform_block_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.ICryptoTransform.TransformFinalBlock")
            .match_name(
                "System.Security.Cryptography",
                "ICryptoTransform",
                "TransformFinalBlock",
            )
            .pre(transform_final_block_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream..ctor")
            .match_name("System.Security.Cryptography", "CryptoStream", ".ctor")
            .pre(crypto_stream_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.Read")
            .match_name("System.Security.Cryptography", "CryptoStream", "Read")
            .pre(crypto_stream_read_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.Write")
            .match_name("System.Security.Cryptography", "CryptoStream", "Write")
            .pre(crypto_stream_write_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.CryptoStream.FlushFinalBlock")
            .match_name(
                "System.Security.Cryptography",
                "CryptoStream",
                "FlushFinalBlock",
            )
            .pre(crypto_stream_flush_final_block_pre),
    )?;

    Ok(())
}

/// Hook for `System.Security.Cryptography.Aes.Create` method.
///
/// Creates a new AES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `Aes.Create() -> Aes`
/// - `Aes.Create(String) -> Aes`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
fn aes_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "Aes");
    match thread.heap().alloc_symmetric_algorithm("AES", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.RijndaelManaged..ctor` constructor.
///
/// Replaces the generic `Object` allocated by `newobj` with a `SymmetricAlgorithm`
/// heap object so that subsequent `set_Key`, `set_IV`, `set_Mode`, `set_Padding`,
/// `CreateDecryptor`, and `CreateEncryptor` calls can operate on it.
///
/// # Handled Overloads
///
/// - `RijndaelManaged..ctor() -> void`
fn rijndael_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        try_hook!(thread
            .heap()
            .replace_with_symmetric_algorithm(*this_ref, "Rijndael"));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.AesManaged..ctor` constructor.
///
/// Replaces the generic `Object` allocated by `newobj` with a `SymmetricAlgorithm`
/// heap object (AES algorithm).
fn aes_managed_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        try_hook!(thread
            .heap()
            .replace_with_symmetric_algorithm(*this_ref, "AES"));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.Aes..ctor` constructor.
///
/// Replaces the generic `Object` allocated by `newobj` with a `SymmetricAlgorithm`
/// heap object (AES algorithm). This covers subclasses that call `base()`.
fn aes_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        try_hook!(thread
            .heap()
            .replace_with_symmetric_algorithm(*this_ref, "AES"));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.RSACryptoServiceProvider..ctor` constructor.
///
/// The RSA provider cannot be instantiated during static emulation (it requires
/// OS-level cryptographic key stores). This hook bypasses the constructor so the
/// allocated object can serve as a placeholder in initialization chains.
///
/// # Handled Overloads
///
/// - `RSACryptoServiceProvider..ctor() -> void`
/// - `RSACryptoServiceProvider..ctor(int) -> void`
/// - `RSACryptoServiceProvider..ctor(CspParameters) -> void`
fn rsa_ctor_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.RSA.Create` factory method.
///
/// Allocates a `CryptoAlgorithm("RSA")` heap object so the RSA instance can
/// participate in key-setting and signature-verification hooks.
fn rsa_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "RSA");
    match thread.heap().alloc_crypto_algorithm("RSA", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `RSACryptoServiceProvider.set_UseMachineKeyStore` property setter.
///
/// No-op — machine key store configuration is irrelevant during emulation.
fn rsa_set_use_machine_key_store_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.CreateDecryptor` method.
///
/// Creates a decryptor transform using the algorithm's key and IV.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.CreateDecryptor() -> ICryptoTransform`
/// - `SymmetricAlgorithm.CreateDecryptor(Byte[], Byte[]) -> ICryptoTransform`
///
/// # Parameters
///
/// - `rgbKey`: Secret key for decryption (overload 2)
/// - `rgbIV`: Initialization vector (overload 2)
fn create_decryptor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::throw_invalid_operation(
                "CreateDecryptor: no valid SymmetricAlgorithm instance",
            );
        }
    };

    let (algorithm, key, iv, mode, padding) = resolve_crypto_key_iv(ctx, thread, algo_ref);

    let (Some(key), Some(iv)) = (key, iv) else {
        return PreHookResult::throw_invalid_operation("CreateDecryptor: Key and IV must be set");
    };

    let type_token = thread.resolve_type_token("System.Security.Cryptography", "ICryptoTransform");
    match thread
        .heap()
        .alloc_crypto_transform(&algorithm, key, iv, false, mode, padding, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.CreateEncryptor` method.
///
/// Creates an encryptor transform using the algorithm's key and IV.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.CreateEncryptor() -> ICryptoTransform`
/// - `SymmetricAlgorithm.CreateEncryptor(Byte[], Byte[]) -> ICryptoTransform`
///
/// # Parameters
///
/// - `rgbKey`: Secret key for encryption (overload 2)
/// - `rgbIV`: Initialization vector (overload 2)
fn create_encryptor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            return PreHookResult::throw_invalid_operation(
                "CreateEncryptor: no valid SymmetricAlgorithm instance",
            );
        }
    };

    let (algorithm, key, iv, mode, padding) = resolve_crypto_key_iv(ctx, thread, algo_ref);

    let (Some(key), Some(iv)) = (key, iv) else {
        return PreHookResult::throw_invalid_operation("CreateEncryptor: Key and IV must be set");
    };

    let type_token = thread.resolve_type_token("System.Security.Cryptography", "ICryptoTransform");
    match thread
        .heap()
        .alloc_crypto_transform(&algorithm, key, iv, true, mode, padding, type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Key` property setter.
///
/// Captures the encryption key for analysis and stores it in the algorithm instance.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Key(Byte[]) -> void`
///
/// # Parameters
///
/// - `value`: The secret key byte array
fn set_key_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(key_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_buffer(
                key_bytes.clone(),
                source,
                BufferSource::Unknown,
                "crypto_key",
            );

            if let Some(EmValue::ObjectRef(algo_ref)) = ctx.this {
                let _ = thread.heap().set_symmetric_key(*algo_ref, key_bytes);
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_IV` property setter.
///
/// Captures the initialization vector for analysis and stores it in the algorithm instance.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_IV(Byte[]) -> void`
///
/// # Parameters
///
/// - `value`: The initialization vector byte array
fn set_iv_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(handle)) = ctx.args.first() {
        if let Some(iv_bytes) = try_hook!(thread.heap().get_byte_array(*handle)) {
            let source = CaptureSource::new(
                thread.current_method().unwrap_or(Token::new(0)),
                thread.id(),
                thread.current_offset().unwrap_or(0),
                0,
            );
            thread.capture().capture_buffer(
                iv_bytes.clone(),
                source,
                BufferSource::Unknown,
                "crypto_iv",
            );

            if let Some(EmValue::ObjectRef(algo_ref)) = ctx.this {
                let _ = thread.heap().set_symmetric_iv(*algo_ref, iv_bytes);
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.get_Key` property getter.
///
/// Returns the stored key from the `SymmetricAlgorithm` heap object as a byte array.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.get_Key() -> Byte[]`
fn get_key_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(algo_ref)) = ctx.this {
        if let Some((_, Some(key), _, _, _)) =
            try_hook!(thread.heap().get_symmetric_algorithm_info(*algo_ref))
        {
            let array_ref = try_hook!(thread.heap().alloc_byte_array(&key));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.get_IV` property getter.
///
/// Returns the stored IV from the `SymmetricAlgorithm` heap object as a byte array.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.get_IV() -> Byte[]`
fn get_iv_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(algo_ref)) = ctx.this {
        if let Some((_, _, Some(iv), _, _)) =
            try_hook!(thread.heap().get_symmetric_algorithm_info(*algo_ref))
        {
            let array_ref = try_hook!(thread.heap().alloc_byte_array(&iv));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Mode` property setter.
///
/// Sets the cipher mode (CBC=1, ECB=2, etc.) on the SymmetricAlgorithm heap object.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Mode(CipherMode) -> void`
///
/// # Parameters
///
/// - `value`: The cipher mode enumeration value
fn set_mode_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let (Some(EmValue::ObjectRef(algo_ref)), Some(EmValue::I32(mode))) =
        (ctx.this, ctx.args.first())
    {
        #[allow(clippy::cast_sign_loss)]
        let mode_u8 = *mode as u8;
        try_hook!(thread
            .heap()
            .set_symmetric_algorithm_mode(*algo_ref, mode_u8));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.SymmetricAlgorithm.set_Padding` property setter.
///
/// Sets the padding mode (None=1, PKCS7=2, Zeros=3) on the SymmetricAlgorithm heap object.
///
/// # Handled Overloads
///
/// - `SymmetricAlgorithm.set_Padding(PaddingMode) -> void`
///
/// # Parameters
///
/// - `value`: The padding mode enumeration value
fn set_padding_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let (Some(EmValue::ObjectRef(algo_ref)), Some(EmValue::I32(padding))) =
        (ctx.this, ctx.args.first())
    {
        #[allow(clippy::cast_sign_loss)]
        let padding_u8 = *padding as u8;
        try_hook!(thread
            .heap()
            .set_symmetric_algorithm_padding(*algo_ref, padding_u8));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.DES.Create` method.
///
/// Creates a new DES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `DES.Create() -> DES`
/// - `DES.Create(String) -> DES`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn des_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "DES");
    match thread.heap().alloc_symmetric_algorithm("DES", type_token) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.TripleDES.Create` method.
///
/// Creates a new TripleDES symmetric algorithm instance.
///
/// # Handled Overloads
///
/// - `TripleDES.Create() -> TripleDES`
/// - `TripleDES.Create(String) -> TripleDES`
///
/// # Parameters
///
/// - `algName`: (optional) Algorithm name, ignored in this implementation
#[cfg(feature = "legacy-crypto")]
fn triple_des_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.Security.Cryptography", "TripleDES");
    match thread
        .heap()
        .alloc_symmetric_algorithm("TripleDES", type_token)
    {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.ICryptoTransform.TransformBlock` method.
///
/// Transforms a single block of data incrementally. Unlike `TransformFinalBlock`, this
/// does not apply padding and is used for streaming block-by-block encryption/decryption.
///
/// For CBC mode, the IV on the transform object is updated after each call to maintain
/// proper chaining:
/// - **Encryption**: the new IV is set to the ciphertext output block.
/// - **Decryption**: the new IV is set to the ciphertext input block (before decryption).
///
/// # Handled Overloads
///
/// - `ICryptoTransform.TransformBlock(Byte[], Int32, Int32, Byte[], Int32) -> Int32`
///
/// # Parameters
///
/// - `inputBuffer`: Input byte array containing data to transform
/// - `inputOffset`: Offset in inputBuffer to start reading
/// - `inputCount`: Number of bytes to transform
/// - `outputBuffer`: Output byte array to receive transformed data
/// - `outputOffset`: Offset in outputBuffer to start writing
fn transform_block_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    let Some(EmValue::ObjectRef(input_handle)) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Some(input_bytes) = try_hook!(thread.heap().get_byte_array(*input_handle)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // Extract offset and count
    #[allow(clippy::cast_sign_loss)]
    let (offset, count) = match (ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::I32(o)), Some(EmValue::I32(c))) => (*o as usize, *c as usize),
        _ => (0, input_bytes.len()),
    };

    let end = offset
        .checked_add(count)
        .unwrap_or(input_bytes.len())
        .min(input_bytes.len());
    let data = if offset < input_bytes.len() {
        let Some(slice) = input_bytes.get(offset..end) else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };
        slice.to_vec()
    } else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let actual_count = data.len();

    // Get output buffer and offset
    let (output_handle, output_offset) = match (ctx.args.get(3), ctx.args.get(4)) {
        #[allow(clippy::cast_sign_loss)]
        (Some(EmValue::ObjectRef(h)), Some(EmValue::I32(o))) => (*h, *o as usize),
        (Some(EmValue::ObjectRef(h)), _) => (*h, 0),
        _ => {
            // No output buffer — just return the count as a no-op
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(actual_count as i32)));
        }
    };

    // Try to get transform info from `this` (the ICryptoTransform object)
    let transform_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => {
            // No transform — passthrough: copy input to output
            for (i, &byte) in data.iter().enumerate() {
                let Some(idx) = output_offset.checked_add(i) else {
                    break;
                };
                try_hook!(thread.heap_mut().set_array_element(
                    output_handle,
                    idx,
                    EmValue::I32(i32::from(byte)),
                ));
            }
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(actual_count as i32)));
        }
    };

    let result_bytes = if let Some((algorithm, key, iv, is_encryptor, mode, padding)) =
        try_hook!(thread.heap().get_crypto_transform_info(transform_ref))
    {
        // Save original ciphertext for CBC IV chaining on decryption
        let original_input = if !is_encryptor && mode == 1 {
            Some(data.clone())
        } else {
            None
        };

        // Use NoPadding (1) for TransformBlock — padding is only applied in TransformFinalBlock
        let _ = padding; // suppress unused warning; we intentionally override
        let transform_result =
            apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &data, mode, 1);

        match transform_result {
            Some(transformed) => {
                // Update IV for CBC chaining
                if mode == 1 {
                    let new_iv = if is_encryptor {
                        // For encryption, new IV = ciphertext output
                        transformed.clone()
                    } else {
                        // For decryption, new IV = original ciphertext input
                        original_input.unwrap_or_else(|| data.clone())
                    };
                    try_hook!(thread
                        .heap()
                        .update_crypto_transform_iv(transform_ref, new_iv));
                }
                transformed
            }
            None => data,
        }
    } else {
        data
    };

    // Write result to output buffer
    for (i, &byte) in result_bytes.iter().enumerate() {
        let Some(idx) = output_offset.checked_add(i) else {
            break;
        };
        try_hook!(thread.heap_mut().set_array_element(
            output_handle,
            idx,
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(result_bytes.len() as i32)))
}

/// Hook for `System.Security.Cryptography.ICryptoTransform.TransformFinalBlock` method.
///
/// Transforms the final block of data using the associated crypto transform's algorithm,
/// key, IV, mode, and padding. Falls back to passthrough if the transform fails.
///
/// # Handled Overloads
///
/// - `ICryptoTransform.TransformFinalBlock(Byte[], Int32, Int32) -> Byte[]`
///
/// # Parameters
///
/// - `inputBuffer`: Input byte array containing data to transform
/// - `inputOffset`: Offset in inputBuffer to start reading
/// - `inputCount`: Number of bytes to transform
fn transform_final_block_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    let Some(EmValue::ObjectRef(input_handle)) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let Some(input_bytes) = try_hook!(thread.heap().get_byte_array(*input_handle)) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    // Apply offset/count if provided
    #[allow(clippy::cast_sign_loss)]
    let data = match (ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::I32(offset)), Some(EmValue::I32(count))) => {
            let offset = *offset as usize;
            let count = *count as usize;
            match offset.checked_add(count) {
                Some(end) if end <= input_bytes.len() => input_bytes
                    .get(offset..end)
                    .map_or_else(|| input_bytes.clone(), <[u8]>::to_vec),
                _ => input_bytes.clone(),
            }
        }
        _ => input_bytes.clone(),
    };

    // Try to get transform info from `this` (the ICryptoTransform object)
    let result_bytes = if let Some(EmValue::ObjectRef(transform_ref)) = ctx.this {
        if let Some((algorithm, key, iv, is_encryptor, mode, padding)) =
            try_hook!(thread.heap().get_crypto_transform_info(*transform_ref))
        {
            let transform_result =
                apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &data, mode, padding);

            match transform_result {
                Some(transformed) => {
                    let label = if is_encryptor {
                        "encrypted_block"
                    } else {
                        "decrypted_block"
                    };
                    let source = CaptureSource::new(
                        thread.current_method().unwrap_or(Token::new(0)),
                        thread.id(),
                        thread.current_offset().unwrap_or(0),
                        0,
                    );
                    thread.capture().capture_buffer(
                        transformed.clone(),
                        source,
                        BufferSource::CryptoTransform {
                            algorithm: algorithm.to_string(),
                        },
                        label,
                    );
                    transformed
                }
                None => data,
            }
        } else {
            data
        }
    } else {
        data
    };

    match thread.heap().alloc_byte_array(&result_bytes) {
        Ok(result) => PreHookResult::Bypass(Some(EmValue::ObjectRef(result))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.CryptoStream..ctor` constructor.
///
/// Initializes a CryptoStream wrapping another stream with a crypto transform.
///
/// # Handled Overloads
///
/// - `CryptoStream..ctor(Stream, ICryptoTransform, CryptoStreamMode) -> void`
/// - `CryptoStream..ctor(Stream, ICryptoTransform, CryptoStreamMode, Boolean) -> void`
///
/// # Parameters
///
/// - `stream`: The underlying stream to wrap
/// - `transform`: The cryptographic transform to apply
/// - `mode`: Read (0) or Write (1) mode
/// - `leaveOpen`: Whether to leave the underlying stream open (overload 2)
fn crypto_stream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let underlying_stream = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let transform = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Intentional cast for CryptoStreamMode enum (0=Read, 1=Write)
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let mode = match ctx.args.get(2) {
        Some(EmValue::I32(m)) => *m as u8,
        _ => 0,
    };

    try_hook!(thread.heap_mut().replace_with_crypto_stream(
        crypto_stream_ref,
        underlying_stream,
        transform,
        mode,
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.CryptoStream.Read` method.
///
/// Reads and decrypts data from the underlying stream.
///
/// # Handled Overloads
///
/// - `CryptoStream.Read(Byte[], Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `buffer`: Destination byte array for decrypted data
/// - `offset`: Offset in buffer to start writing
/// - `count`: Maximum number of bytes to read
fn crypto_stream_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some((underlying_stream, transform_ref, mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(crypto_stream_ref))
    else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    if mode != 0 {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    }

    // Intentional cast: array indices are always non-negative in .NET
    #[allow(clippy::cast_sign_loss)]
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    if try_hook!(thread
        .heap()
        .get_crypto_stream_transformed(crypto_stream_ref))
    .is_none()
    {
        let Some((stream_data, underlying_pos)) =
            try_hook!(thread.heap().get_stream_data(underlying_stream))
        else {
            return PreHookResult::Bypass(Some(EmValue::I32(0)));
        };

        // Use data from the underlying stream's current position, not from offset 0
        let effective_data: &[u8] = stream_data.get(underlying_pos..).unwrap_or(&[]);

        let transformed_data = if let Some((algorithm, key, iv, is_encryptor, mode, padding)) =
            try_hook!(thread.heap().get_crypto_transform_info(transform_ref))
        {
            let transform_result = apply_crypto_transform(
                &algorithm,
                &key,
                &iv,
                is_encryptor,
                effective_data,
                mode,
                padding,
            );

            match transform_result {
                Some(data) => {
                    if !is_encryptor {
                        let source = CaptureSource::new(
                            thread.current_method().unwrap_or(Token::new(0)),
                            thread.id(),
                            thread.current_offset().unwrap_or(0),
                            0,
                        );
                        thread.capture().capture_buffer(
                            data.clone(),
                            source,
                            BufferSource::CryptoTransform {
                                algorithm: algorithm.to_string(),
                            },
                            "decrypted_stream",
                        );
                    }
                    data
                }
                None => effective_data.to_vec(),
            }
        } else {
            effective_data.to_vec()
        };

        try_hook!(thread
            .heap()
            .set_crypto_stream_transformed(crypto_stream_ref, transformed_data));
    }

    let Some(bytes) = try_hook!(thread.heap().read_crypto_stream(crypto_stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    for (i, &byte) in bytes.iter().enumerate() {
        let Some(idx) = offset.checked_add(i) else {
            break;
        };
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            idx,
            EmValue::I32(i32::from(byte)),
        ));
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(bytes.len() as i32)))
}

/// Hook for `System.Security.Cryptography.CryptoStream.Write` method.
///
/// Writes data to the stream, buffering for encryption on flush.
///
/// # Handled Overloads
///
/// - `CryptoStream.Write(Byte[], Int32, Int32) -> void`
///
/// # Parameters
///
/// - `buffer`: Source byte array containing data to encrypt
/// - `offset`: Offset in buffer to start reading
/// - `count`: Number of bytes to write
fn crypto_stream_write_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some((_, _, mode)) = try_hook!(thread.heap().get_crypto_stream_info(crypto_stream_ref))
    else {
        return PreHookResult::Bypass(None);
    };

    if mode != 1 {
        return PreHookResult::Bypass(None);
    }

    // Intentional cast: array indices are always non-negative in .NET
    #[allow(clippy::cast_sign_loss)]
    let (buffer_ref, offset, count) = match (ctx.args.first(), ctx.args.get(1), ctx.args.get(2)) {
        (Some(EmValue::ObjectRef(b)), Some(EmValue::I32(o)), Some(EmValue::I32(c))) => {
            (*b, *o as usize, *c as usize)
        }
        _ => return PreHookResult::Bypass(None),
    };

    let Some(buffer_data) = try_hook!(thread.heap().get_byte_array(buffer_ref)) else {
        return PreHookResult::Bypass(None);
    };

    let end = offset
        .checked_add(count)
        .unwrap_or(buffer_data.len())
        .min(buffer_data.len());
    let bytes_to_write = if offset < buffer_data.len() {
        let Some(slice) = buffer_data.get(offset..end) else {
            return PreHookResult::Bypass(None);
        };
        slice.to_vec()
    } else {
        return PreHookResult::Bypass(None);
    };

    try_hook!(thread
        .heap()
        .crypto_stream_append_write(crypto_stream_ref, &bytes_to_write));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.CryptoStream.FlushFinalBlock` method.
///
/// Flushes the final block, applying padding and completing encryption.
///
/// # Handled Overloads
///
/// - `CryptoStream.FlushFinalBlock() -> void`
fn crypto_stream_flush_final_block_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let crypto_stream_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let Some((underlying_stream, transform_ref, mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(crypto_stream_ref))
    else {
        return PreHookResult::Bypass(None);
    };

    if mode != 1 {
        return PreHookResult::Bypass(None);
    }

    let Some(write_buffer) = try_hook!(thread
        .heap()
        .get_crypto_stream_write_buffer(crypto_stream_ref))
    else {
        return PreHookResult::Bypass(None);
    };

    if write_buffer.is_empty() {
        return PreHookResult::Bypass(None);
    }

    let transformed_data = if let Some((algorithm, key, iv, is_encryptor, mode, padding)) =
        try_hook!(thread.heap().get_crypto_transform_info(transform_ref))
    {
        let transform_result = apply_crypto_transform(
            &algorithm,
            &key,
            &iv,
            is_encryptor,
            &write_buffer,
            mode,
            padding,
        );

        match transform_result {
            Some(data) => {
                if is_encryptor {
                    let source = CaptureSource::new(
                        thread.current_method().unwrap_or(Token::new(0)),
                        thread.id(),
                        thread.current_offset().unwrap_or(0),
                        0,
                    );
                    thread.capture().capture_buffer(
                        data.clone(),
                        source,
                        BufferSource::CryptoTransform {
                            algorithm: algorithm.to_string(),
                        },
                        "encrypted_stream",
                    );
                }
                data
            }
            None => write_buffer,
        }
    } else {
        write_buffer
    };

    try_hook!(thread
        .heap_mut()
        .write_to_stream(underlying_stream, &transformed_data));

    try_hook!(thread
        .heap()
        .clear_crypto_stream_write_buffer(crypto_stream_ref));

    PreHookResult::Bypass(None)
}

/// Hook for `RSA.FromXmlString(string)`.
///
/// Parses an RSA XML key string and stores the modulus + exponent on the heap object.
/// Supports the standard `<RSAKeyValue><Modulus>...</Modulus><Exponent>...</Exponent></RSAKeyValue>` format.
fn rsa_from_xml_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let xml_string = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => match thread.heap().get_string(*r) {
            Ok(s) => s.to_string(),
            Err(_) => return PreHookResult::Bypass(None),
        },
        _ => return PreHookResult::Bypass(None),
    };

    // Simple XML parsing for <Modulus> and <Exponent> base64 values
    let modulus = extract_xml_element(&xml_string, "Modulus").and_then(|b64| base64_decode(&b64));
    let exponent = extract_xml_element(&xml_string, "Exponent").and_then(|b64| base64_decode(&b64));

    if let (Some(mod_bytes), Some(exp_bytes)) = (modulus, exponent) {
        try_hook!(thread
            .heap()
            .set_rsa_public_key(algo_ref, mod_bytes, exp_bytes));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `RSACryptoServiceProvider.VerifyHash(byte[], string, byte[]) -> bool`.
///
/// Verifies an RSA PKCS#1 v1.5 signature using the imported public key.
fn rsa_verify_hash_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let algo_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    // args: rgbHash(byte[]), str(string — OID or algorithm name), rgbSignature(byte[])
    let hash_bytes = match ctx.args.first() {
        Some(EmValue::ObjectRef(h)) => match try_hook!(thread.heap().get_byte_array(*h)) {
            Some(b) => b,
            None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let oid_or_name = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(r)) => match thread.heap().get_string(*r) {
            Ok(s) => s.to_string(),
            Err(_) => "SHA256".to_string(),
        },
        _ => "SHA256".to_string(),
    };

    let signature_bytes = match ctx.args.get(2) {
        Some(EmValue::ObjectRef(h)) => match try_hook!(thread.heap().get_byte_array(*h)) {
            Some(b) => b,
            None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Some((modulus, exponent)) = try_hook!(thread.heap().get_rsa_public_key(algo_ref)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    // The key came from emulated code, of any size
    if !thread.charge_work(rsa_verify_work(&modulus, &exponent)) {
        return PreHookResult::Bypass(None);
    }
    let result = verify_rsa_pkcs1v15(
        &modulus,
        &exponent,
        &hash_bytes,
        &signature_bytes,
        &oid_or_name,
    );

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(result))))
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
    };

    #[test]
    fn test_aes_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "Aes",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::aes_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_rijndael_ctor_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RijndaelManaged",
            ".ctor",
            PointerSize::Bit64,
        );

        let result = super::rijndael_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_create_decryptor_hook() {
        let mut thread = create_test_thread();

        let algo_ref = thread
            .heap()
            .alloc_symmetric_algorithm("AES", None)
            .unwrap();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        thread.heap().set_symmetric_key(algo_ref, key).unwrap();
        thread.heap().set_symmetric_iv(algo_ref, iv).unwrap();

        let this = EmValue::ObjectRef(algo_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "CreateDecryptor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = super::create_decryptor_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_set_key_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "set_Key",
            PointerSize::Bit64,
        )
        .with_args(&[EmValue::Null]);

        let result = super::set_key_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_set_iv_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "SymmetricAlgorithm",
            "set_IV",
            PointerSize::Bit64,
        )
        .with_args(&[EmValue::Null]);

        let result = super::set_iv_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_transform_block_passthrough() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(&[1, 2, 3, 4]).unwrap();
        let output = thread.heap().alloc_byte_array(&[0, 0, 0, 0]).unwrap();

        let args = [
            EmValue::ObjectRef(input),
            EmValue::I32(0),
            EmValue::I32(4),
            EmValue::ObjectRef(output),
            EmValue::I32(0),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "ICryptoTransform",
            "TransformBlock",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::transform_block_pre(&ctx, &mut thread);

        // Without a transform `this`, passthrough copies input to output
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));
        let out_bytes = thread.heap().get_byte_array(output).unwrap().unwrap();
        assert_eq!(out_bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_transform_block_with_crypto() {
        let mut thread = create_test_thread();

        // Create a decryptor transform with a known key/IV
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let transform_ref = thread
            .heap()
            .alloc_crypto_transform("AES", key, iv, false, 1, 2, None)
            .unwrap();

        // A full AES block of zeros — encrypted with key=0, IV=0 in CBC mode
        // this is a well-known test vector
        let input_data = vec![
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let input = thread.heap().alloc_byte_array(&input_data).unwrap();
        let output = thread.heap().alloc_byte_array(&[0u8; 16]).unwrap();

        let this_val = EmValue::ObjectRef(transform_ref);
        let args = [
            EmValue::ObjectRef(input),
            EmValue::I32(0),
            EmValue::I32(16),
            EmValue::ObjectRef(output),
            EmValue::I32(0),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "ICryptoTransform",
            "TransformBlock",
            PointerSize::Bit64,
        )
        .with_this(Some(&this_val))
        .with_args(&args);

        let result = super::transform_block_pre(&ctx, &mut thread);

        // Should return 16 (one block processed)
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(16)))
        ));

        // The output should contain decrypted data (all zeros for this test vector)
        let out_bytes = thread.heap().get_byte_array(output).unwrap().unwrap();
        assert_eq!(out_bytes.len(), 16);
        assert_eq!(out_bytes, vec![0u8; 16]);

        // After decryption in CBC mode, the IV should be updated to the input ciphertext
        let updated_info = thread
            .heap()
            .get_crypto_transform_info(transform_ref)
            .unwrap()
            .unwrap();
        assert_eq!(updated_info.2, input_data); // IV should now be the ciphertext input
    }

    #[test]
    fn test_transform_final_block_hook() {
        let mut thread = create_test_thread();
        let input = thread.heap().alloc_byte_array(&[1, 2, 3, 4]).unwrap();

        let args = [EmValue::ObjectRef(input)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "ICryptoTransform",
            "TransformFinalBlock",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::transform_final_block_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(bytes, vec![1, 2, 3, 4]);
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
    };

    #[test]
    fn test_des_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "DES",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::des_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_triple_des_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "TripleDES",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::triple_des_create_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }
}

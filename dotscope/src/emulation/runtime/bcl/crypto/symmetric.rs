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
        engine::synthetic_exception,
        runtime::{
            bcl::{
                crypto::{
                    extract_xml_element, finish_crypto_stream, resolve_crypto_key_iv,
                    transform_failure, transform_stream_data,
                },
                limits::buffer_range,
            },
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::token::Token,
    utils::{
        apply_crypto_transform, base64_decode, rsa_verify_work, symmetric_block_size,
        verify_rsa_pkcs1v15, CryptoFailure,
    },
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

/// The exception the runtime throws for an argument of a transform call.
fn argument_error(exception_type: Token, message: String) -> PreHookResult {
    PreHookResult::Throw {
        exception_type,
        message,
    }
}

/// A transform's parameters, as the heap gives them: algorithm, key, IV, whether it
/// encrypts, cipher mode, padding mode.
type TransformParameters = (std::sync::Arc<str>, Vec<u8>, Vec<u8>, bool, u8, u8);

/// The `ICryptoTransform` a transform call is made on, and its parameters; an emulation
/// error when `this` is no transform the heap holds.
fn this_transform(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
) -> std::result::Result<(HeapRef, TransformParameters), PreHookResult> {
    let Some(EmValue::ObjectRef(transform_ref)) = ctx.this else {
        return Err(PreHookResult::Error(format!(
            "ICryptoTransform.{} called without a transform object",
            ctx.method_name
        )));
    };
    match thread.heap().get_crypto_transform_info(*transform_ref) {
        Ok(Some(info)) => Ok((*transform_ref, info)),
        Ok(None) => Err(PreHookResult::Error(format!(
            "ICryptoTransform.{} called on an object that is no emulated transform",
            ctx.method_name
        ))),
        Err(e) => Err(PreHookResult::Error(format!("heap read failed: {e}"))),
    }
}

/// The input bytes a transform call names, `(inputBuffer, inputOffset, inputCount)` as its
/// first three arguments, checked as the runtime's `UniversalCryptoTransform` checks them
/// before any work: a null buffer is the `ArgumentNullException` it throws, and a negative
/// or too large offset, a negative count, or a count past the buffer's end the
/// `ArgumentOutOfRangeException`. `TransformBlock` (`whole_blocks` the block size) also
/// refuses a count that is not positive or not whole blocks, with the same exception.
/// Arguments of any other shape are no call the runtime makes: an emulation error.
fn input_range(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
    whole_blocks: Option<usize>,
) -> std::result::Result<Vec<u8>, PreHookResult> {
    let out_of_range = |message: String| {
        Err(argument_error(
            synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            message,
        ))
    };
    let bytes = match ctx.args.first() {
        Some(EmValue::ObjectRef(handle)) => match thread.heap().get_byte_array(*handle) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(PreHookResult::Error(format!(
                    "ICryptoTransform.{} of an object that is no byte[]",
                    ctx.method_name
                )))
            }
            Err(e) => return Err(PreHookResult::Error(format!("heap read failed: {e}"))),
        },
        Some(EmValue::Null) => {
            return Err(argument_error(
                synthetic_exception::ARGUMENT_NULL,
                "inputBuffer".to_string(),
            ))
        }
        other => {
            return Err(PreHookResult::Error(format!(
                "ICryptoTransform.{} with inputBuffer {other:?}, no byte array",
                ctx.method_name
            )))
        }
    };
    let (Some(EmValue::I32(offset)), Some(EmValue::I32(count))) =
        (ctx.args.get(1), ctx.args.get(2))
    else {
        return Err(PreHookResult::Error(format!(
            "ICryptoTransform.{} without int32 inputOffset and inputCount",
            ctx.method_name
        )));
    };
    let Some(offset) = usize::try_from(*offset).ok().filter(|o| *o <= bytes.len()) else {
        return out_of_range(format!(
            "inputOffset {offset} is outside the input buffer's {} bytes",
            bytes.len()
        ));
    };
    let Ok(count) = usize::try_from(*count) else {
        return out_of_range(format!("inputCount {count} must be non-negative"));
    };
    if let Some(block) = whole_blocks {
        if count == 0 || !count.is_multiple_of(block) {
            return out_of_range(format!(
                "inputCount {count} is not a positive multiple of the block size {block}"
            ));
        }
    }
    match bytes.get(offset..offset.saturating_add(count)) {
        Some(input) => Ok(input.to_vec()),
        None => out_of_range(format!(
            "{count} bytes from {offset} pass the input buffer's {} bytes",
            bytes.len()
        )),
    }
}

/// Records a transform's output for the capture of decrypted and encrypted buffers.
fn capture_transformed(thread: &mut EmulationThread, data: &[u8], algorithm: &str, label: &str) {
    let source = CaptureSource::new(
        thread.current_method().unwrap_or(Token::new(0)),
        thread.id(),
        thread.current_offset().unwrap_or(0),
        0,
    );
    thread.capture().capture_buffer(
        data.to_vec(),
        source,
        BufferSource::CryptoTransform {
            algorithm: algorithm.to_string(),
        },
        label,
    );
}

/// Hook for `System.Security.Cryptography.ICryptoTransform.TransformBlock` method.
///
/// Transforms whole blocks of data incrementally, without padding, as the runtime's
/// transforms do:
///
/// - the input count must be a positive multiple of the block size, and the output buffer
///   must have room for as many bytes from its offset;
/// - a decryptor whose padding is removed (PKCS7, ANSIX923, ISO10126) keeps the latest block
///   back until the next call or `TransformFinalBlock`, since only the final block's padding
///   is removed, and returns the blocks before it;
/// - in CBC mode the next call chains from the last ciphertext block: the output for an
///   encryptor, the input for a decryptor.
///
/// What the runtime refuses is thrown, checked in its order before any work: a null buffer
/// is `ArgumentNullException`, every offset and count it refuses `ArgumentOutOfRangeException`,
/// and a key of the wrong size `CryptographicException`. A call on no emulated transform, or
/// a cipher the emulator does not compute, is an emulation error. The input is never handed
/// back as the output.
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
    let (transform_ref, (algorithm, key, iv, is_encryptor, mode, padding)) =
        match this_transform(ctx, thread) {
            Ok(transform) => transform,
            Err(result) => return result,
        };
    let Some(block) = symmetric_block_size(&algorithm) else {
        return transform_failure(CryptoFailure::Unsupported(format!(
            "symmetric algorithm {algorithm}"
        )));
    };
    let data = match input_range(ctx, thread, Some(block)) {
        Ok(data) => data,
        Err(result) => return result,
    };
    // The output must have room for `inputCount` bytes from `outputOffset`, before any work
    let output_handle = match ctx.args.get(3) {
        Some(EmValue::ObjectRef(handle)) => *handle,
        Some(EmValue::Null) => {
            return argument_error(
                synthetic_exception::ARGUMENT_NULL,
                "outputBuffer".to_string(),
            )
        }
        other => {
            return PreHookResult::Error(format!(
                "ICryptoTransform.TransformBlock with outputBuffer {other:?}, no byte array"
            ))
        }
    };
    let Some(EmValue::I32(output_offset)) = ctx.args.get(4) else {
        return PreHookResult::Error(
            "ICryptoTransform.TransformBlock without an int32 outputOffset".to_string(),
        );
    };
    let room = try_hook!(thread.heap().get_array_length(output_handle));
    let Some(output_offset) = usize::try_from(*output_offset)
        .ok()
        .filter(|o| room.checked_sub(*o).is_some_and(|left| data.len() <= left))
    else {
        return argument_error(
            synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            format!(
                "{} bytes from outputOffset {output_offset} pass the output buffer's {room} bytes",
                data.len()
            ),
        );
    };

    // A depadding decryptor keeps the latest block back for the final call to unpad.
    let input = if is_encryptor {
        data
    } else {
        let mut input = try_hook!(thread.heap().take_crypto_transform_held_back(transform_ref));
        input.extend_from_slice(&data);
        if matches!(padding, 2 | 4 | 5) && !input.is_empty() {
            let keep = input.split_off(input.len().saturating_sub(block));
            try_hook!(thread
                .heap()
                .set_crypto_transform_held_back(transform_ref, keep));
        }
        input
    };

    let output = match apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &input, mode, 1)
    {
        Ok(output) => output,
        Err(failure) => return transform_failure(failure),
    };
    // CBC chains from the last ciphertext block
    if mode == 1 {
        let ciphertext = if is_encryptor { &output } else { &input };
        if let Some(last) = ciphertext
            .len()
            .checked_sub(block)
            .and_then(|at| ciphertext.get(at..))
        {
            try_hook!(thread
                .heap()
                .update_crypto_transform_iv(transform_ref, last.to_vec()));
        }
    }

    for (i, &byte) in output.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            output_handle,
            output_offset.saturating_add(i),
            EmValue::I32(i32::from(byte)),
        ));
    }
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    PreHookResult::Bypass(Some(EmValue::I32(output.len() as i32)))
}

/// Hook for `System.Security.Cryptography.ICryptoTransform.TransformFinalBlock` method.
///
/// Transforms the final input, with what a decryptor kept back from `TransformBlock` before
/// it, padding when encrypting and checking and removing the padding when decrypting, then
/// returns the transform to its initial IV so it can be used again, as the runtime does.
///
/// What the runtime refuses is thrown: a null buffer is `ArgumentNullException`, an offset or
/// count it refuses `ArgumentOutOfRangeException`, and a wrong-sized key, input that is not
/// whole blocks, or padding that does not check out (the failure decrypting with the wrong
/// key gives) `CryptographicException`. A call on no emulated transform, or a cipher the
/// emulator does not compute, is an emulation error. The input is never handed back as the
/// output.
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
    let (transform_ref, (algorithm, key, iv, is_encryptor, mode, padding)) =
        match this_transform(ctx, thread) {
            Ok(transform) => transform,
            Err(result) => return result,
        };
    let data = match input_range(ctx, thread, None) {
        Ok(data) => data,
        Err(result) => return result,
    };
    let mut input = try_hook!(thread.heap().take_crypto_transform_held_back(transform_ref));
    input.extend_from_slice(&data);

    let result = apply_crypto_transform(&algorithm, &key, &iv, is_encryptor, &input, mode, padding);
    try_hook!(thread.heap().reset_crypto_transform(transform_ref));
    let output = match result {
        Ok(output) => output,
        Err(failure) => return transform_failure(failure),
    };
    let label = if is_encryptor {
        "encrypted_block"
    } else {
        "decrypted_block"
    };
    capture_transformed(thread, &output, &algorithm, label);

    match thread.heap().alloc_byte_array(&output) {
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
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::Error("CryptoStream.Read without a stream".to_string()),
    };
    // The runtime checks the arguments, then whether the stream reads
    let (buffer_ref, offset, count) =
        match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
            Ok(range) => range,
            Err(result) => return result,
        };
    let Some((underlying_stream, transform_ref, mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(crypto_stream_ref))
    else {
        return PreHookResult::Error("CryptoStream.Read on no emulated CryptoStream".to_string());
    };
    if mode != 0 {
        return argument_error(
            synthetic_exception::NOT_SUPPORTED,
            "Stream does not support reading.".to_string(),
        );
    }

    if try_hook!(thread
        .heap()
        .get_crypto_stream_transformed(crypto_stream_ref))
    .is_none()
    {
        let Some((stream_data, underlying_pos)) =
            try_hook!(thread.heap().get_stream_data(underlying_stream))
        else {
            return PreHookResult::Error("CryptoStream.Read over no emulated stream".to_string());
        };
        // From the underlying stream's current position, not from offset 0
        let remaining = stream_data.get(underlying_pos..).unwrap_or(&[]).to_vec();
        let transformed = match transform_stream_data(thread, transform_ref, &remaining) {
            Ok(transformed) => transformed,
            Err(result) => return result,
        };
        try_hook!(thread
            .heap()
            .set_crypto_stream_transformed(crypto_stream_ref, transformed));
    }

    let Some(bytes) = try_hook!(thread.heap().read_crypto_stream(crypto_stream_ref, count)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };
    for (i, &byte) in bytes.iter().enumerate() {
        try_hook!(thread.heap_mut().set_array_element(
            buffer_ref,
            offset.saturating_add(i),
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
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => return PreHookResult::Error("CryptoStream.Write without a stream".to_string()),
    };
    // The runtime checks the arguments, then whether the stream writes
    let (buffer_ref, offset, count) =
        match buffer_range(ctx, thread, synthetic_exception::ARGUMENT_OUT_OF_RANGE) {
            Ok(range) => range,
            Err(result) => return result,
        };
    let Some((_, _, mode)) = try_hook!(thread.heap().get_crypto_stream_info(crypto_stream_ref))
    else {
        return PreHookResult::Error("CryptoStream.Write on no emulated CryptoStream".to_string());
    };
    if mode != 1 {
        return argument_error(
            synthetic_exception::NOT_SUPPORTED,
            "Stream does not support writing.".to_string(),
        );
    }
    let Some(buffer_data) = try_hook!(thread.heap().get_byte_array(buffer_ref)) else {
        return PreHookResult::Error(
            "CryptoStream.Write from an array that is no byte[]".to_string(),
        );
    };
    // In range: `buffer_range` checked it against the buffer's length
    let bytes_to_write = buffer_data
        .get(offset..offset.saturating_add(count))
        .unwrap_or_default();

    try_hook!(thread
        .heap()
        .crypto_stream_append_write(crypto_stream_ref, bytes_to_write));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.CryptoStream.FlushFinalBlock` method.
///
/// Flushes the final block, applying padding and completing encryption (or checking and
/// removing it, for a decryptor), into the stream beneath, as
/// [`finish_crypto_stream`] describes. A second call is the `NotSupportedException` the
/// runtime throws.
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
        Some(EmValue::Null) => return PreHookResult::throw_null_reference(),
        _ => {
            return PreHookResult::Error(
                "CryptoStream.FlushFinalBlock without a stream".to_string(),
            )
        }
    };
    match finish_crypto_stream(thread, crypto_stream_ref, true) {
        Ok(true) => PreHookResult::Bypass(None),
        Ok(false) => PreHookResult::Error(
            "CryptoStream.FlushFinalBlock on no emulated CryptoStream".to_string(),
        ),
        Err(result) => result,
    }
}

/// Hook for `RSA.FromXmlString(string)`.
///
/// Parses an RSA XML key string and stores the modulus + exponent on the heap object.
/// Supports the standard `<RSAKeyValue><Modulus>...</Modulus><Exponent>...</Exponent></RSAKeyValue>` format.
fn rsa_from_xml_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(algo_ref)) = ctx.this else {
        return PreHookResult::Error("RSA.FromXmlString without an RSA object".to_string());
    };
    let algo_ref = *algo_ref;

    let xml_string = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => match thread.heap().get_string(*r) {
            Ok(s) => s.to_string(),
            Err(e) => return PreHookResult::Error(format!("heap read failed: {e}")),
        },
        _ => return argument_error(synthetic_exception::ARGUMENT_NULL, "xmlString".to_string()),
    };

    // The public key's <Modulus> and <Exponent>, base64. A key without them, or not base64,
    // is the CryptographicException the runtime throws, not a key left unset.
    let modulus = extract_xml_element(&xml_string, "Modulus").and_then(|b64| base64_decode(&b64));
    let exponent = extract_xml_element(&xml_string, "Exponent").and_then(|b64| base64_decode(&b64));
    let (Some(mod_bytes), Some(exp_bytes)) = (modulus, exponent) else {
        return argument_error(
            synthetic_exception::CRYPTOGRAPHIC,
            "Input string does not contain a valid encoding of the 'RSA' 'Modulus' and \
             'Exponent' parameters."
                .to_string(),
        );
    };
    try_hook!(thread
        .heap()
        .set_rsa_public_key(algo_ref, mod_bytes, exp_bytes));

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
            engine::synthetic_exception,
            runtime::{
                bcl::io::stream::stream_dispose_pre,
                hook::{HookContext, PreHookResult},
            },
            EmValue, EmulationThread, HeapRef,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
        utils::apply_crypto_transform,
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

    /// A transform call without a transform object is no call the runtime makes: an
    /// emulation error, not the input copied to the output.
    #[test]
    fn a_transform_without_a_transform_object_is_an_error() {
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
        let block = transform_context("TransformBlock", None, &args);
        assert!(matches!(
            super::transform_block_pre(&block, &mut thread),
            PreHookResult::Error(_)
        ));
        let final_block = transform_context("TransformFinalBlock", None, &args[..3]);
        assert!(matches!(
            super::transform_final_block_pre(&final_block, &mut thread),
            PreHookResult::Error(_)
        ));
        assert_eq!(
            thread.heap().get_byte_array(output).unwrap().unwrap(),
            vec![0, 0, 0, 0]
        );
    }

    #[test]
    fn test_transform_block_with_crypto() {
        let mut thread = create_test_thread();

        // Create a decryptor transform with a known key/IV
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let transform_ref = thread
            .heap()
            .alloc_crypto_transform("AES", key, iv, false, 1, 1, None)
            .unwrap();

        // A full AES block of zeros, encrypted with key=0, IV=0 in CBC mode; without padding
        // to remove, the decryptor returns the block at once
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

    /// A hook context for `ICryptoTransform.method` on `this` with `args`.
    fn transform_context<'a>(
        method: &'a str,
        this: Option<&'a EmValue>,
        args: &'a [EmValue],
    ) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "ICryptoTransform",
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    /// `TransformFinalBlock` of `data` on `transform`: the bytes, or the hook's result.
    fn final_block(
        thread: &mut EmulationThread,
        transform: HeapRef,
        data: &[u8],
    ) -> Result<Vec<u8>, PreHookResult> {
        let input = thread.heap().alloc_byte_array(data).unwrap();
        let this = EmValue::ObjectRef(transform);
        let len = i32::try_from(data.len()).unwrap();
        let args = [
            EmValue::ObjectRef(input),
            EmValue::I32(0),
            EmValue::I32(len),
        ];
        let ctx = transform_context("TransformFinalBlock", Some(&this), &args);
        match super::transform_final_block_pre(&ctx, thread) {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) => {
                Ok(thread.heap().get_byte_array(handle).unwrap().unwrap())
            }
            other => Err(other),
        }
    }

    /// `TransformBlock` of `data` on `transform` into a fresh output of `room` bytes at
    /// `output_offset`: the hook's result, and the output buffer.
    fn transform_block(
        thread: &mut EmulationThread,
        transform: HeapRef,
        data: &[u8],
        room: usize,
        output_offset: i32,
    ) -> (PreHookResult, HeapRef) {
        let input = thread.heap().alloc_byte_array(data).unwrap();
        let output = thread.heap().alloc_byte_array(&vec![0u8; room]).unwrap();
        let this = EmValue::ObjectRef(transform);
        let len = i32::try_from(data.len()).unwrap();
        let args = [
            EmValue::ObjectRef(input),
            EmValue::I32(0),
            EmValue::I32(len),
            EmValue::ObjectRef(output),
            EmValue::I32(output_offset),
        ];
        let ctx = transform_context("TransformBlock", Some(&this), &args);
        (super::transform_block_pre(&ctx, thread), output)
    }

    /// `TransformBlock` chains the IV forward; `TransformFinalBlock` then returns the
    /// transform to the IV it was created with, so the next use encrypts as a fresh one.
    #[test]
    fn a_transform_returns_to_its_first_iv_after_the_final_block() {
        let mut thread = create_test_thread();
        let (key, iv) = (vec![7u8; 16], vec![9u8; 16]);
        let alloc = |thread: &mut EmulationThread| {
            thread
                .heap()
                .alloc_crypto_transform("AES", key.clone(), iv.clone(), true, 1, 2, None)
                .unwrap()
        };
        let encryptor = alloc(&mut thread);
        let fresh = alloc(&mut thread);
        let plaintext = b"after a block";
        let (result, _) = transform_block(&mut thread, encryptor, &[1u8; 16], 16, 0);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(16)))
        ));
        let chained = final_block(&mut thread, encryptor, plaintext).unwrap();
        let expected = final_block(&mut thread, fresh, plaintext).unwrap();
        assert_ne!(
            chained, expected,
            "the first final block chains from the block"
        );
        assert_eq!(
            final_block(&mut thread, encryptor, plaintext).unwrap(),
            expected
        );
    }

    /// `TransformBlock` checks its arguments as the runtime does, before any work: a count
    /// that is zero or not whole blocks, and an output without room for the input count, are
    /// `ArgumentOutOfRangeException`, and the transform's state is left as it was.
    #[test]
    fn transform_block_refuses_what_the_runtime_refuses() {
        let mut thread = create_test_thread();
        let encryptor = thread
            .heap()
            .alloc_crypto_transform("AES", vec![7u8; 16], vec![9u8; 16], true, 1, 2, None)
            .unwrap();
        let out_of_range = |result: &PreHookResult| {
            matches!(
                result,
                PreHookResult::Throw { exception_type, .. }
                    if *exception_type == synthetic_exception::ARGUMENT_OUT_OF_RANGE
            )
        };
        assert!(out_of_range(
            &transform_block(&mut thread, encryptor, &[], 16, 0).0
        ));
        assert!(out_of_range(
            &transform_block(&mut thread, encryptor, &[1; 15], 16, 0).0
        ));
        assert!(out_of_range(
            &transform_block(&mut thread, encryptor, &[1; 16], 31, 16).0
        ));
        assert!(out_of_range(
            &transform_block(&mut thread, encryptor, &[1; 16], 16, -1).0
        ));
        let (iv, untouched) = {
            let info = thread
                .heap()
                .get_crypto_transform_info(encryptor)
                .unwrap()
                .unwrap();
            (info.2, vec![9u8; 16])
        };
        assert_eq!(iv, untouched, "a refused call leaves the IV as it was");
        let (result, output) = transform_block(&mut thread, encryptor, &[1; 16], 32, 16);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(16)))
        ));
        let written = thread.heap().get_byte_array(output).unwrap().unwrap();
        assert_eq!(written.get(..16), Some([0u8; 16].as_slice()));
    }

    /// A write-mode CryptoStream disposed without `FlushFinalBlock`, as a `using` block
    /// leaves it, still writes its final padded block, as the runtime's `Dispose` does; once
    /// complete, `FlushFinalBlock` is the `NotSupportedException` the runtime throws, and a
    /// second `Dispose` writes nothing more.
    #[test]
    fn disposing_a_crypto_stream_writes_its_final_block() {
        let mut thread = create_test_thread();
        let (key, iv) = (vec![7u8; 16], vec![9u8; 16]);
        let plaintext = b"written in a using block";
        let expected = apply_crypto_transform("AES", &key, &iv, true, plaintext, 1, 2).unwrap();
        let encryptor = thread
            .heap()
            .alloc_crypto_transform("AES", key, iv, true, 1, 2, None)
            .unwrap();
        let underlying = thread.heap().alloc_stream(Vec::new(), None).unwrap();
        let stream = thread
            .heap()
            .alloc_crypto_stream(underlying, encryptor, 1, None)
            .unwrap();
        let buffer = thread.heap().alloc_byte_array(plaintext).unwrap();
        let this = EmValue::ObjectRef(stream);
        let len = i32::try_from(plaintext.len()).unwrap();
        let args = [
            EmValue::ObjectRef(buffer),
            EmValue::I32(0),
            EmValue::I32(len),
        ];
        let stream_call = |method| {
            HookContext::new(
                Token::new(0x0A000001),
                "System.Security.Cryptography",
                "CryptoStream",
                method,
                PointerSize::Bit64,
            )
        };
        let write = stream_call("Write").with_this(Some(&this)).with_args(&args);
        assert!(matches!(
            super::crypto_stream_write_pre(&write, &mut thread),
            PreHookResult::Bypass(None)
        ));
        let dispose = stream_call("Dispose").with_this(Some(&this));
        assert!(matches!(
            stream_dispose_pre(&dispose, &mut thread),
            PreHookResult::Bypass(None)
        ));
        let written = |thread: &EmulationThread| {
            thread
                .heap()
                .get_stream_data(underlying)
                .unwrap()
                .unwrap()
                .0
        };
        assert_eq!(written(&thread), expected);
        assert!(matches!(
            stream_dispose_pre(&dispose, &mut thread),
            PreHookResult::Bypass(None)
        ));
        assert_eq!(written(&thread), expected);
        let flush = stream_call("FlushFinalBlock").with_this(Some(&this));
        assert!(matches!(
            super::crypto_stream_flush_final_block_pre(&flush, &mut thread),
            PreHookResult::Throw { exception_type, .. }
                if exception_type == synthetic_exception::NOT_SUPPORTED
        ));
    }

    /// A PKCS7 decryptor keeps the latest block back from `TransformBlock`, since only the
    /// final block carries padding, and `TransformFinalBlock` unpads it; the transform is
    /// then back at its first IV, so it encrypts the same input to the same output again.
    #[test]
    fn a_padding_decryptor_holds_the_last_block_back() {
        let mut thread = create_test_thread();
        let (key, iv) = (vec![7u8; 16], vec![9u8; 16]);
        let plaintext: Vec<u8> = (0u8..20).collect();
        let encryptor = thread
            .heap()
            .alloc_crypto_transform("AES", key.clone(), iv.clone(), true, 1, 2, None)
            .unwrap();
        let ciphertext = final_block(&mut thread, encryptor, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 32);
        assert_eq!(
            final_block(&mut thread, encryptor, &plaintext).unwrap(),
            ciphertext
        );

        let decryptor = thread
            .heap()
            .alloc_crypto_transform("AES", key, iv, false, 1, 2, None)
            .unwrap();
        let input = thread.heap().alloc_byte_array(&ciphertext).unwrap();
        let output = thread.heap().alloc_byte_array(&[0u8; 32]).unwrap();
        let this = EmValue::ObjectRef(decryptor);
        let args = [
            EmValue::ObjectRef(input),
            EmValue::I32(0),
            EmValue::I32(32),
            EmValue::ObjectRef(output),
            EmValue::I32(0),
        ];
        let ctx = transform_context("TransformBlock", Some(&this), &args);
        assert!(matches!(
            super::transform_block_pre(&ctx, &mut thread),
            PreHookResult::Bypass(Some(EmValue::I32(16)))
        ));
        let first = thread.heap().get_byte_array(output).unwrap().unwrap();
        assert_eq!(first.get(..16), plaintext.get(..16));
        assert_eq!(
            final_block(&mut thread, decryptor, &[]).unwrap(),
            plaintext.get(16..).unwrap()
        );
    }

    /// Decrypting with the wrong key leaves padding that does not check out: the
    /// `CryptographicException` the runtime throws, not the ciphertext as the plaintext.
    /// So is input that is not whole blocks, and a key of the wrong size.
    #[test]
    fn what_the_runtime_refuses_is_a_cryptographic_exception() {
        let mut thread = create_test_thread();
        let iv = vec![0u8; 16];
        let encryptor = thread
            .heap()
            .alloc_crypto_transform("AES", vec![1u8; 16], iv.clone(), true, 1, 2, None)
            .unwrap();
        let ciphertext = final_block(&mut thread, encryptor, b"the secret").unwrap();
        let cryptographic = |result: Result<Vec<u8>, PreHookResult>| {
            matches!(
                result,
                Err(PreHookResult::Throw { exception_type, .. })
                    if exception_type == synthetic_exception::CRYPTOGRAPHIC
            )
        };

        let wrong_key = thread
            .heap()
            .alloc_crypto_transform("AES", vec![2u8; 16], iv.clone(), false, 1, 2, None)
            .unwrap();
        assert!(cryptographic(final_block(
            &mut thread,
            wrong_key,
            &ciphertext
        )));
        let right_key = thread
            .heap()
            .alloc_crypto_transform("AES", vec![1u8; 16], iv.clone(), false, 1, 2, None)
            .unwrap();
        assert!(cryptographic(final_block(
            &mut thread,
            right_key,
            &ciphertext[..15]
        )));
        let short_key = thread
            .heap()
            .alloc_crypto_transform("AES", vec![1u8; 15], iv, true, 1, 2, None)
            .unwrap();
        assert!(cryptographic(final_block(&mut thread, short_key, b"x")));
    }

    /// An RSA key whose XML has no base64 modulus and exponent is the
    /// `CryptographicException` the runtime throws, not a key left unset.
    #[test]
    fn a_malformed_rsa_key_is_refused() {
        let mut thread = create_test_thread();
        let rsa = thread.heap().alloc_crypto_algorithm("RSA", None).unwrap();
        let xml = thread
            .heap()
            .alloc_string("<RSAKeyValue><Modulus>not base64!</Modulus></RSAKeyValue>")
            .unwrap();
        let this = EmValue::ObjectRef(rsa);
        let args = [EmValue::ObjectRef(xml)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RSA",
            "FromXmlString",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        assert!(matches!(
            super::rsa_from_xml_string_pre(&ctx, &mut thread),
            PreHookResult::Throw { exception_type, .. }
                if exception_type == synthetic_exception::CRYPTOGRAPHIC
        ));
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

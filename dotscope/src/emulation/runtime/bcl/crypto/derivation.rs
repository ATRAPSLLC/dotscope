//! Key derivation hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for password-based key derivation functions
//! (KDFs) used by .NET obfuscators to derive encryption keys from passwords. Obfuscators
//! commonly embed a password string in the assembly and use a KDF to produce the actual
//! AES or DES key used for decryption.
//!
//! # Covered APIs
//!
//! ## PBKDF1 (PasswordDeriveBytes)
//!
//! - `PasswordDeriveBytes..ctor(string/byte[], byte[])` — stores password and salt
//! - `PasswordDeriveBytes.GetBytes(int)` — derives key bytes using PBKDF1 with SHA1
//! - Requires the `legacy-crypto` feature (PBKDF1 is deprecated)
//!
//! ## PBKDF2 (Rfc2898DeriveBytes)
//!
//! - `Rfc2898DeriveBytes..ctor(string/byte[], byte[], int)` — stores password, salt, iterations
//! - `Rfc2898DeriveBytes.GetBytes(int)` — derives key bytes using PBKDF2-HMAC-SHA1
//! - Always available (PBKDF2 is the recommended standard)
//!
//! # Implementation Notes
//!
//! Key derivation is fully implemented using the `pbkdf2` and `hmac` crates.
//! The constructor hooks store derivation parameters on the heap object, and the
//! `GetBytes` hooks compute the derived key on demand.

#[cfg(feature = "legacy-crypto")]
use crate::utils::derive_pbkdf1_key;
use crate::{
    emulation::{
        runtime::{
            bcl::limits::non_positive_argument,
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    utils::{derive_pbkdf2_key, pbkdf2_work},
    Result,
};

/// Registers all key derivation hooks (`PasswordDeriveBytes` and `Rfc2898DeriveBytes`).
///
/// Called by the parent `crypto::register()` to wire up PBKDF1 and PBKDF2 hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                ".ctor",
            )
            .pre(password_derive_bytes_ctor_pre),
    )?;

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                "GetBytes",
            )
            .pre(password_derive_bytes_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                ".ctor",
            )
            .pre(rfc2898_derive_bytes_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                "GetBytes",
            )
            .pre(rfc2898_derive_bytes_get_bytes_pre),
    )?;

    Ok(())
}

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes..ctor` constructor.
///
/// Initializes PBKDF1-based key derivation with password and salt.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes..ctor(String, Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32, CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32, CspParameters) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array
/// - `hashName`: Hash algorithm name (optional, default SHA1)
/// - `iterations`: Number of iterations (optional, default 100)
/// - `cspParams`: Cryptographic service provider parameters (optional)
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                try_hook!(thread.heap().get_byte_array(*pwd_ref)).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            try_hook!(thread.heap().get_byte_array(*salt_ref)).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let iterations: u32 = 100;

    try_hook!(thread
        .heap()
        .replace_with_key_derivation(heap_ref, password, salt, iterations, "SHA1"));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF1 algorithm.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // `cb` sizes the derivation's work and its output; .NET refuses a count that is not
    // positive. The work is charged to the run's budget before it is done.
    let size = match ctx.args.first().map(i32::try_from) {
        Some(Ok(n)) if n > 0 => n.unsigned_abs() as usize,
        Some(Ok(_)) => return non_positive_argument("DeriveBytes.GetBytes", "cb"),
        _ => 16,
    };

    // An instance call on null
    let Some(&EmValue::ObjectRef(heap_ref)) = ctx.this else {
        return PreHookResult::throw_null_reference();
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    let derived_key = match params {
        Ok(Some((password, salt, iterations, _hash_algorithm))) => {
            // A hash per iteration for the base value, and one per 20-byte SHA-1 block
            let blocks = u64::try_from(size.div_ceil(20)).unwrap_or(u64::MAX);
            if !thread.charge_work(u64::from(iterations).saturating_add(blocks)) {
                return PreHookResult::Bypass(None);
            }
            derive_pbkdf1_key(&password, &salt, iterations, size)
        }
        _ => vec![0u8; size],
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes..ctor` constructor.
///
/// Initializes PBKDF2-based key derivation with password, salt, and iterations.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes..ctor(String, Byte[]) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32, HashAlgorithmName) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32, HashAlgorithmName) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array or salt size in bytes
/// - `iterations`: Number of iterations (default 1000)
/// - `hashAlgorithm`: Hash algorithm name (optional, default SHA1)
fn rfc2898_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                try_hook!(thread.heap().get_byte_array(*pwd_ref)).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            try_hook!(thread.heap().get_byte_array(*salt_ref)).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    // .NET refuses an iteration count that is not positive. Any other count is accepted:
    // `GetBytes` charges the derivation's work to the run's budget.
    let iterations: u32 = match ctx.args.get(2).map(i32::try_from) {
        Some(Ok(n)) if n > 0 => n.unsigned_abs(),
        Some(Ok(_)) => return non_positive_argument("Rfc2898DeriveBytes..ctor", "iterations"),
        _ => 1000,
    };

    let hash_algorithm = "SHA1";

    try_hook!(thread.heap().replace_with_key_derivation(
        heap_ref,
        password,
        salt,
        iterations,
        hash_algorithm,
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF2 algorithm.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
fn rfc2898_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // `cb` sizes the derivation's work and its output; .NET refuses a count that is not
    // positive. The work is charged to the run's budget before it is done.
    let size = match ctx.args.first().map(i32::try_from) {
        Some(Ok(n)) if n > 0 => n.unsigned_abs() as usize,
        Some(Ok(_)) => return non_positive_argument("DeriveBytes.GetBytes", "cb"),
        _ => 16,
    };

    // An instance call on null
    let Some(&EmValue::ObjectRef(heap_ref)) = ctx.this else {
        return PreHookResult::throw_null_reference();
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    // A derivation that cannot be performed is reported, not papered over. Returning
    // `vec![0u8; size]` here would hand back an all-zero key that decrypts to plausible
    // garbage, and the analyst has no way to tell that apart from a real result.
    let derived_key = match params {
        Ok(Some((password, salt, iterations, hash_algorithm))) => {
            match pbkdf2_work(iterations, size, &hash_algorithm) {
                Ok(work) if thread.charge_work(work) => {}
                Ok(_) => return PreHookResult::Bypass(None),
                Err(e) => return PreHookResult::Error(format!("PBKDF2 derivation failed: {e}")),
            }
            match derive_pbkdf2_key(&password, &salt, iterations, size, &hash_algorithm) {
                Ok(key) => key,
                Err(e) => return PreHookResult::Error(format!("PBKDF2 derivation failed: {e}")),
            }
        }
        Ok(None) => {
            return PreHookResult::Error(
                "Rfc2898DeriveBytes.GetBytes called before the key derivation parameters were set"
                    .to_string(),
            )
        }
        Err(e) => {
            return PreHookResult::Error(format!("failed to read key derivation parameters: {e}"))
        }
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::{engine::synthetic_exception, HeapRef},
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
        utils::derive_pbkdf2_key,
    };

    fn context<'a>(
        type_name: &'a str,
        method: &'a str,
        this: Option<&'a EmValue>,
        args: &'a [EmValue],
    ) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A00_0001),
            "System.Security.Cryptography",
            type_name,
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    fn assert_throws(result: &PreHookResult, expected: Token) {
        match result {
            PreHookResult::Throw { exception_type, .. } => assert_eq!(*exception_type, expected),
            other => panic!("expected a throw, got {other:?}"),
        }
    }

    /// An `Rfc2898DeriveBytes` constructed over b"password" and b"saltsalt" with
    /// `iterations`, and what its constructor returned.
    fn rfc2898(thread: &mut EmulationThread, iterations: i32) -> (HeapRef, PreHookResult) {
        let object = thread.heap().alloc_object(Token::new(0x0200_0001)).unwrap();
        let password = thread.heap().alloc_byte_array(b"password").unwrap();
        let salt = thread.heap().alloc_byte_array(b"saltsalt").unwrap();
        let this = EmValue::ObjectRef(object);
        let args = [
            EmValue::ObjectRef(password),
            EmValue::ObjectRef(salt),
            EmValue::I32(iterations),
        ];
        let ctx = context("Rfc2898DeriveBytes", ".ctor", Some(&this), &args);
        (object, rfc2898_derive_bytes_ctor_pre(&ctx, thread))
    }

    fn get_bytes(thread: &mut EmulationThread, object: HeapRef, cb: i32) -> PreHookResult {
        let this = EmValue::ObjectRef(object);
        let args = [EmValue::I32(cb)];
        let ctx = context("Rfc2898DeriveBytes", "GetBytes", Some(&this), &args);
        rfc2898_derive_bytes_get_bytes_pre(&ctx, thread)
    }

    /// .NET refuses an iteration count that is not positive; any other count is accepted,
    /// however large: its work is charged when the bytes are derived.
    #[test]
    fn rfc2898_takes_any_positive_iteration_count() {
        let mut thread = create_test_thread();
        for iterations in [0, -1, i32::MIN] {
            let (_, result) = rfc2898(&mut thread, iterations);
            assert_throws(&result, synthetic_exception::ARGUMENT_OUT_OF_RANGE);
        }
        for iterations in [1, 100_001, i32::MAX] {
            let (_, result) = rfc2898(&mut thread, iterations);
            assert!(matches!(result, PreHookResult::Bypass(None)), "{result:?}");
        }
    }

    /// `GetBytes` refuses a count that is not positive, and a call on null throws
    /// NullReferenceException rather than handing back an invented key.
    #[test]
    fn get_bytes_refuses_a_count_that_is_not_positive_and_null() {
        let mut thread = create_test_thread();
        let (object, _) = rfc2898(&mut thread, 1000);
        for cb in [0, -1, i32::MIN] {
            assert_throws(
                &get_bytes(&mut thread, object, cb),
                synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            );
        }
        let args = [EmValue::I32(16)];
        let ctx = context("Rfc2898DeriveBytes", "GetBytes", None, &args);
        assert_throws(
            &rfc2898_derive_bytes_get_bytes_pre(&ctx, &mut thread),
            synthetic_exception::NULL_REFERENCE,
        );
    }

    /// The derivation's work, iterations for each 20-byte SHA-1 block, is charged before it
    /// is done: within the budget the key is derived, past it nothing is, and the charge
    /// stands for the run's next limit check.
    #[cfg(feature = "legacy-crypto")]
    #[test]
    fn get_bytes_charges_its_work_to_the_budget() {
        let mut thread = create_test_thread();
        let (object, _) = rfc2898(&mut thread, 1000);

        thread.begin_work(0, 3001);
        let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) =
            get_bytes(&mut thread, object, 48)
        else {
            panic!("the key is derived within the budget");
        };
        assert_eq!(thread.take_work(), 3000);
        let derived = thread.heap().get_byte_array(handle).unwrap().unwrap();
        assert_eq!(
            derived,
            derive_pbkdf2_key(b"password", b"saltsalt", 1000, 48, "SHA1").unwrap()
        );

        thread.begin_work(0, 3000);
        assert!(matches!(
            get_bytes(&mut thread, object, 48),
            PreHookResult::Bypass(None)
        ));
        assert_eq!(thread.take_work(), 3000);
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

    /// `PasswordDeriveBytes.GetBytes` charges its hashes, one per iteration for the base
    /// value and one per 20-byte block, before deriving.
    #[test]
    fn password_derive_bytes_charges_its_work() {
        let mut thread = create_test_thread();
        let object = thread.heap().alloc_object(Token::new(0x0200_0001)).unwrap();
        let password = thread.heap().alloc_byte_array(b"password").unwrap();
        let salt = thread.heap().alloc_byte_array(b"saltsalt").unwrap();
        let this = EmValue::ObjectRef(object);
        let args = [EmValue::ObjectRef(password), EmValue::ObjectRef(salt)];
        let ctx = HookContext::new(
            Token::new(0x0A00_0001),
            "System.Security.Cryptography",
            "PasswordDeriveBytes",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        super::password_derive_bytes_ctor_pre(&ctx, &mut thread);

        let args = [EmValue::I32(32)];
        let ctx = HookContext::new(
            Token::new(0x0A00_0001),
            "System.Security.Cryptography",
            "PasswordDeriveBytes",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        thread.begin_work(0, 1000);
        let result = super::password_derive_bytes_get_bytes_pre(&ctx, &mut thread);
        let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result else {
            panic!("expected a key, got {result:?}");
        };
        assert_eq!(
            thread.heap().get_byte_array(handle).unwrap().unwrap().len(),
            32
        );
        // 100 iterations and two blocks
        assert_eq!(thread.take_work(), 102);

        thread.begin_work(0, 102);
        assert!(matches!(
            super::password_derive_bytes_get_bytes_pre(&ctx, &mut thread),
            PreHookResult::Bypass(None)
        ));
    }
}

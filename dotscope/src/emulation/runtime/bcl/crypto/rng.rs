//! Random number generation hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for .NET's cryptographic random number
//! generators. RNG is implemented as a deterministic xorshift64 PRNG so that emulation
//! produces reproducible results across runs.
//!
//! # Covered APIs
//!
//! - **RNGCryptoServiceProvider**: `.ctor()`, `GetBytes(byte[])`
//! - **RandomNumberGenerator**: `Create()`, `GetBytes(byte[])`
//!
//! # Implementation Notes
//!
//! The xorshift64 PRNG state is stored as a field on the heap object, seeded with
//! [`RNG_XORSHIFT64_SEED`]. Successive calls to `GetBytes` advance the state,
//! producing a deterministic sequence.

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::typesystem::CilFlavor,
    Result,
};

/// Fixed seed for the deterministic xorshift64 PRNG used by `RNGCryptoServiceProvider`.
///
/// During emulation we need reproducible "random" bytes so that string decryption
/// and other crypto operations produce consistent results across runs.
const RNG_XORSHIFT64_SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Registers all RNG hooks.
///
/// Called by the parent `crypto::register()` to wire up `RNGCryptoServiceProvider`
/// and `RandomNumberGenerator` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // RNGCryptoServiceProvider
    manager.register(
        Hook::new("System.Security.Cryptography.RNGCryptoServiceProvider..ctor")
            .match_name(
                "System.Security.Cryptography",
                "RNGCryptoServiceProvider",
                ".ctor",
            )
            .pre(rng_crypto_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.RNGCryptoServiceProvider.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "RNGCryptoServiceProvider",
                "GetBytes",
            )
            .pre(rng_crypto_get_bytes_pre),
    )?;

    // RandomNumberGenerator.Create() — often used as factory for RNG
    manager.register(
        Hook::new("System.Security.Cryptography.RandomNumberGenerator.Create")
            .match_name(
                "System.Security.Cryptography",
                "RandomNumberGenerator",
                "Create",
            )
            .pre(rng_create_pre),
    )?;

    // RandomNumberGenerator.GetBytes(byte[]) — base class virtual
    manager.register(
        Hook::new("System.Security.Cryptography.RandomNumberGenerator.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "RandomNumberGenerator",
                "GetBytes",
            )
            .pre(rng_crypto_get_bytes_pre),
    )?;

    Ok(())
}

// RNG tokens defined in crate::emulation::tokens::{helpers::RNG, rng_fields::STATE}.

/// Hook for `RNGCryptoServiceProvider..ctor()`.
///
/// Initializes the object `newobj` allocated (`this`) with the xorshift64 state field, set to
/// [`RNG_XORSHIFT64_SEED`]. A constructor returns nothing: the object it initializes is the
/// one `newobj` pushes.
fn rng_crypto_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(this_ref)) = ctx.this else {
        return PreHookResult::Error("RNGCryptoServiceProvider..ctor without `this`".into());
    };
    #[allow(clippy::cast_possible_wrap)]
    let seed = EmValue::I64(RNG_XORSHIFT64_SEED as i64);
    try_hook!(thread
        .heap()
        .set_field(*this_ref, tokens::rng_fields::STATE, seed));
    PreHookResult::Bypass(None)
}

/// Hook for `RandomNumberGenerator.Create()`.
///
/// Allocates a heap object with a single field storing the xorshift64 state, initialised to
/// [`RNG_XORSHIFT64_SEED`], and returns it.
fn rng_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let state_field = tokens::rng_fields::STATE;
    let type_token = tokens::helpers::RNG;

    let fields = vec![(state_field, CilFlavor::I8)];

    match thread
        .heap_mut()
        .alloc_object_with_fields(type_token, &fields)
    {
        Ok(obj_ref) => {
            #[allow(clippy::cast_possible_wrap)]
            let seed_val = EmValue::I64(RNG_XORSHIFT64_SEED as i64);
            try_hook!(thread.heap().set_field(obj_ref, state_field, seed_val));
            PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref)))
        }
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `RNGCryptoServiceProvider.GetBytes(byte[])` and
/// `RandomNumberGenerator.GetBytes(byte[])`.
///
/// Fills the output byte array with deterministic pseudo-random bytes generated
/// by a xorshift64 PRNG. The state is stored as a field on the RNG heap object
/// so that successive calls produce a predictable sequence.
///
/// # Handled Overloads
///
/// - `GetBytes(Byte[])` — fills the entire array
///
/// # Parameters
///
/// - `data`: Output byte array to fill with pseudo-random bytes
fn rng_crypto_get_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let rng_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let arr_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(h)) => *h,
        _ => return PreHookResult::Bypass(None),
    };

    let arr_len = try_hook!(thread.heap().get_array_length(arr_ref));

    // Read current PRNG state
    let state_field = tokens::rng_fields::STATE;
    #[allow(clippy::cast_sign_loss)]
    let mut state: u64 = match try_hook!(thread.heap().get_field(rng_ref, state_field)) {
        EmValue::I64(v) => v as u64,
        _ => RNG_XORSHIFT64_SEED,
    };

    // Generate bytes using xorshift64
    for i in 0..arr_len {
        // xorshift64 step
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        #[allow(clippy::cast_possible_truncation)]
        let byte_val = (state & 0xFF) as u8;
        try_hook!(thread
            .heap()
            .set_array_element(arr_ref, i, EmValue::I32(i32::from(byte_val))));
    }

    // Store updated state
    #[allow(clippy::cast_possible_wrap)]
    let state_val = EmValue::I64(state as i64);
    try_hook!(thread.heap().set_field(rng_ref, state_field, state_val));

    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            thread::EmulationThread,
            tokens, EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    /// The constructor initializes `this`, the object `newobj` pushes, and returns nothing.
    #[test]
    fn test_rng_crypto_ctor_hook() {
        let mut thread = create_test_thread();
        let this = EmValue::ObjectRef(thread.heap().alloc_object(Token::new(0x0100_0001)).unwrap());
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RNGCryptoServiceProvider",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = super::rng_crypto_ctor_pre(&ctx, &mut thread);

        assert!(matches!(result, PreHookResult::Bypass(None)));
        let EmValue::ObjectRef(this_ref) = this else {
            unreachable!()
        };
        assert_eq!(
            thread
                .heap()
                .get_field(this_ref, tokens::rng_fields::STATE)
                .unwrap(),
            EmValue::I64(super::RNG_XORSHIFT64_SEED.cast_signed())
        );
    }

    /// `RandomNumberGenerator.Create()` is a factory: it returns the generator it makes.
    #[test]
    fn test_rng_create_hook() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RandomNumberGenerator",
            "Create",
            PointerSize::Bit64,
        );

        let result = super::rng_create_pre(&ctx, &mut thread);

        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_rng_crypto_get_bytes_fills_array() {
        let mut thread = create_test_thread();

        // Create RNG instance
        let create_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RandomNumberGenerator",
            "Create",
            PointerSize::Bit64,
        );

        let rng_ref = match super::rng_create_pre(&create_ctx, &mut thread) {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(h))) => h,
            _ => panic!("Expected ObjectRef"),
        };

        // Allocate output byte array (16 bytes)
        let output = thread.heap().alloc_byte_array(&[0u8; 16]).unwrap();

        // Call GetBytes
        let args = [EmValue::ObjectRef(output)];
        let this = EmValue::ObjectRef(rng_ref);
        let get_bytes_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RNGCryptoServiceProvider",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);

        let result = super::rng_crypto_get_bytes_pre(&get_bytes_ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));

        // Verify the array was filled (not all zeros)
        let bytes = thread.heap().get_byte_array(output).unwrap().unwrap();
        assert_eq!(bytes.len(), 16);
        assert!(
            bytes.iter().any(|&b| b != 0),
            "RNG should produce non-zero bytes"
        );
    }

    #[test]
    fn test_rng_crypto_is_deterministic() {
        let mut thread1 = create_test_thread();
        let mut thread2 = create_test_thread();

        // Helper to get RNG output from a fresh thread
        fn get_rng_bytes(thread: &mut EmulationThread, len: usize) -> Vec<u8> {
            let create_ctx = HookContext::new(
                Token::new(0x0A000001),
                "System.Security.Cryptography",
                "RandomNumberGenerator",
                "Create",
                PointerSize::Bit64,
            );

            let rng_ref = match super::rng_create_pre(&create_ctx, thread) {
                PreHookResult::Bypass(Some(EmValue::ObjectRef(h))) => h,
                _ => panic!("Expected ObjectRef"),
            };

            let output = thread.heap().alloc_byte_array(&vec![0u8; len]).unwrap();
            let args = [EmValue::ObjectRef(output)];
            let this = EmValue::ObjectRef(rng_ref);
            let ctx = HookContext::new(
                Token::new(0x0A000001),
                "System.Security.Cryptography",
                "RNGCryptoServiceProvider",
                "GetBytes",
                PointerSize::Bit64,
            )
            .with_this(Some(&this))
            .with_args(&args);

            super::rng_crypto_get_bytes_pre(&ctx, thread);
            thread.heap().get_byte_array(output).unwrap().unwrap()
        }

        let bytes1 = get_rng_bytes(&mut thread1, 32);
        let bytes2 = get_rng_bytes(&mut thread2, 32);
        assert_eq!(bytes1, bytes2, "RNG should be deterministic across runs");
    }

    #[test]
    fn test_rng_crypto_successive_calls_differ() {
        let mut thread = create_test_thread();

        let create_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RandomNumberGenerator",
            "Create",
            PointerSize::Bit64,
        );

        let rng_ref = match super::rng_create_pre(&create_ctx, &mut thread) {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(h))) => h,
            _ => panic!("Expected ObjectRef"),
        };

        // First call
        let output1 = thread.heap().alloc_byte_array(&[0u8; 8]).unwrap();
        let args1 = [EmValue::ObjectRef(output1)];
        let this = EmValue::ObjectRef(rng_ref);
        let ctx1 = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RNGCryptoServiceProvider",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args1);
        super::rng_crypto_get_bytes_pre(&ctx1, &mut thread);

        // Second call (same RNG instance, state should have advanced)
        let output2 = thread.heap().alloc_byte_array(&[0u8; 8]).unwrap();
        let args2 = [EmValue::ObjectRef(output2)];
        let ctx2 = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "RNGCryptoServiceProvider",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args2);
        super::rng_crypto_get_bytes_pre(&ctx2, &mut thread);

        let bytes1 = thread.heap().get_byte_array(output1).unwrap().unwrap();
        let bytes2 = thread.heap().get_byte_array(output2).unwrap().unwrap();
        assert_ne!(
            bytes1, bytes2,
            "Successive RNG calls should produce different bytes"
        );
    }
}

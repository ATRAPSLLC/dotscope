//! Consolidated decryptor tracking and management.
//!
//! This module provides the [`DecryptorContext`] which acts as a bridge between
//! obfuscator-specific detection and generic SSA passes. It consolidates all
//! decryptor-related state into a single, well-organized structure.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        DecryptorContext Flow                            │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  1. DETECTION (Obfuscator-Specific)                                     │
//! │     └─> ctx.decryptors.register(token, info)                            │
//! │                                                                         │
//! │  2. SSA PASSES (Generic)                                                │
//! │     └─> if ctx.decryptors.is_decryptor(target) { ... }                  │
//! │     └─> ctx.decryptors.with_cached(target, args, |v| ...)               │
//! │     └─> ctx.decryptors.cache_value(target, args, value)                 │
//! │     └─> ctx.decryptors.record_success(...) / record_failure(...)        │
//! │     └─> Events logged: ConstantDecrypted, Warning (on failure)          │
//! │                                                                         │
//! │  3. CLEANUP (Obfuscator-Specific)                                       │
//! │     └─> for token in ctx.decryptors.removable_decryptors() { ... }      │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use dotscope::analysis::ConstValue;
//! use dotscope::deobfuscation::DecryptorContext;
//! use dotscope::metadata::token::Token;
//!
//! // The analysis context's decryptors (`ctx.decryptors`)
//! let decryptors = DecryptorContext::new();
//! let (call_target, caller) = (Token::new(0x0600_0010), Token::new(0x0600_0001));
//!
//! // During obfuscator detection:
//! decryptors.register(call_target);
//!
//! // During SSA pass: a call to the decryptor with these arguments
//! let args = [ConstValue::I32(7)];
//! if decryptors.is_decryptor(call_target) {
//!     if let Some(cached) = decryptors.with_cached(call_target, &args, |v| v.clone()) {
//!         // Use cached value
//!         println!("cached: {:?}", cached);
//!     } else {
//!         // Emulate and cache
//!         let value = ConstValue::I32(42);
//!         decryptors.cache_value(call_target, &args, value.clone());
//!         decryptors.record_success(call_target, caller, None, value);
//!     }
//! }
//! assert!(decryptors.is_cached(call_target, &args));
//!
//! // During cleanup: each decryptor whose every call was decrypted
//! for token in decryptors.removable_decryptors() {
//!     println!("dead: {}", token);
//! }
//! ```

use std::{
    collections::HashSet,
    sync::atomic::{AtomicUsize, Ordering},
};

use dashmap::{DashMap, DashSet};

use crate::{
    analysis::{ConstValue, InstrId},
    metadata::token::Token,
};

/// Consolidated context for all decryptor-related tracking.
///
/// This structure bridges obfuscator-specific detection with generic SSA passes,
/// providing a clean interface for:
/// - Registering known decryptor methods (from detection)
/// - Caching decrypted values (to avoid re-emulation)
/// - Tracking decryption results (for cleanup decisions)
/// - Querying cleanup eligibility (which decryptors can be removed)
///
/// # Design Note
///
/// Detection only registers which tokens are decryptors - it does NOT cache
/// call site information. This is intentional because the assembly may be
/// modified by other passes (anti-tamper decryption, control flow unflattening)
/// before the decryption pass runs, which would invalidate cached call sites.
/// The decryption pass scans SSA fresh each time it runs.
#[derive(Debug, Default)]
pub struct DecryptorContext {
    /// Known decryptor methods, registered by obfuscator modules.
    registered: DashSet<Token>,

    /// Successfully decrypted call sites per decryptor method.
    decrypted: DashMap<Token, boxcar::Vec<DecryptedCall>>,

    /// Failed decryption attempts (for diagnostics and cleanup decisions).
    failed: DashMap<Token, boxcar::Vec<FailedCall>>,

    /// Cache: (decryptor_token, args_repr) → decrypted value.
    /// Avoids re-emulating the same call with same arguments.
    cache: DashMap<CacheKey, ConstValue>,

    /// Maps MethodSpec tokens to their base MethodDef decryptor.
    /// This is needed because generic decryptors like `T Get<T>(int32)` are
    /// called via MethodSpec tokens that instantiate the generic.
    methodspec_to_decryptor: DashMap<Token, Token>,

    /// Call sites that failed permanently, keyed by the call's identity.
    ///
    /// By identity rather than position: a permanent failure is a fact about
    /// *this call* - its target cannot be emulated, or does not exist - and
    /// every rewrite above it moves where it sits. A positional key made the
    /// record describe whichever call inherited the position, which skips a
    /// site that was never tried and retries one that was.
    permanent_failure_index: DashSet<(Token, InstrId)>,

    /// Call sites already decrypted, keyed by the call's identity.
    decrypted_index: DashSet<(Token, InstrId)>,

    /// Emulations performed so far in this run.
    ///
    /// The per-emulation instruction and wall-clock budgets bound one call; nothing bounds
    /// how many calls a run makes. The decryption pass emulates once per distinct call site
    /// with constant arguments, and [`Self::cache`] is keyed on `(decryptor, args)`, so
    /// distinct arguments always miss - a method that calls a decryptor in a loop with a
    /// varying key produces one emulation per iteration. This counter is what gives the run
    /// as a whole a ceiling.
    emulations_performed: AtomicUsize,
}

/// Record of a successfully decrypted call.
#[derive(Debug, Clone)]
pub struct DecryptedCall {
    /// Method containing the call.
    pub caller: Token,
    /// The call instruction's identity, when it had one.
    pub location: Option<InstrId>,
    /// The decrypted constant value.
    pub value: ConstValue,
}

/// Record of a failed decryption attempt.
#[derive(Debug, Clone)]
pub struct FailedCall {
    /// Method containing the call.
    pub caller: Token,
    /// The call instruction's identity, when it had one.
    pub location: Option<InstrId>,
    /// Why decryption failed.
    pub reason: FailureReason,
}

/// Reasons why decryption might fail.
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// Not all arguments were known constants.
    NonConstantArgs,
    /// Emulation failed or timed out.
    EmulationFailed(String),
    /// The run's total emulation budget was exhausted before this site was reached.
    EmulationBudgetExhausted,
    /// Couldn't resolve the method target.
    UnresolvedTarget,
    /// Return value couldn't be converted to a constant.
    InvalidReturnValue,
    /// Method not found in assembly.
    MethodNotFound,
    /// No initialization of the state machine was found for the call site, so the state
    /// its decryptor reads is unknown. Decrypting from an assumed seed answers a wrong value
    /// that looks like a right one.
    SeedNotFound,
}

impl FailureReason {
    /// Returns `true` if this failure is permanent and should not be retried.
    ///
    /// Permanent failures include:
    /// - `EmulationFailed` - the method couldn't be emulated
    /// - `UnresolvedTarget` - the target method couldn't be found
    /// - `InvalidReturnValue` - the return value couldn't be converted
    /// - `MethodNotFound` - the method doesn't exist
    ///
    /// Retriable failures include:
    /// - `NonConstantArgs` - the arguments might become constant in later passes
    /// - `SeedNotFound` - the seed's argument might become constant in later passes
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        // Budget exhaustion is a property of the run, not of the call site: with a larger
        // budget the same site could succeed, so it must not be cached as permanent.
        !matches!(
            self,
            Self::NonConstantArgs | Self::EmulationBudgetExhausted | Self::SeedNotFound
        )
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonConstantArgs => write!(f, "arguments not constant"),
            Self::EmulationFailed(msg) => write!(f, "emulation failed: {msg}"),
            Self::UnresolvedTarget => write!(f, "unresolved call target"),
            Self::InvalidReturnValue => write!(f, "invalid return value"),
            Self::MethodNotFound => write!(f, "method not found"),
            Self::EmulationBudgetExhausted => write!(f, "run emulation budget exhausted"),
            Self::SeedNotFound => write!(f, "no state machine seed found for the call site"),
        }
    }
}

/// Cache key combining a decryptor token with a string representation of its arguments.
///
/// Uses a string representation of arguments since `ConstValue` may contain
/// floats which don't implement `Hash`/`Eq`.
///
/// **Stability contract**: The cache key depends on `ConstValue`'s `Debug` formatting
/// for argument serialization. If `Debug` changes, existing cache entries become unreachable
/// (causing redundant emulation, not incorrect results).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The token the call names: the decryptor, or for a generic one its instantiation (a
    /// MethodSpec), so `Get<int>(5)` and `Get<string>(5)` are cached apart.
    pub decryptor: Token,
    /// String representation of arguments for hashing.
    pub args_repr: String,
}

impl CacheKey {
    /// Creates a new cache key from a decryptor token and arguments.
    #[must_use]
    pub fn new(decryptor: Token, args: &[ConstValue]) -> Self {
        Self {
            decryptor,
            args_repr: Self::args_to_string(args),
        }
    }

    /// Converts arguments to a string representation for hashing.
    ///
    /// See [`CacheKey`] stability contract - correctness depends on `ConstValue::Debug`
    /// producing deterministic output for equal values.
    fn args_to_string(args: &[ConstValue]) -> String {
        args.iter()
            .map(|arg| format!("{arg:?}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl DecryptorContext {
    /// Creates a new, empty decryptor context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves one emulation against the run budget.
    ///
    /// Returns `false` once `max` emulations have been performed, at which point callers
    /// should stop emulating and report the remaining sites as failures rather than
    /// continuing. A `max` of 0 means unlimited.
    ///
    /// The reservation is taken before the emulation runs, so a concurrent pair of callers
    /// cannot both pass the check at the limit.
    pub fn try_reserve_emulation(&self, max: usize) -> bool {
        if max == 0 {
            return true;
        }
        self.emulations_performed
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n >= max {
                    None
                } else {
                    Some(n.saturating_add(1))
                }
            })
            .is_ok()
    }

    /// Returns how many emulations this run has performed.
    #[must_use]
    pub fn emulations_performed(&self) -> usize {
        self.emulations_performed.load(Ordering::Relaxed)
    }

    /// Registers a method as a known decryptor.
    ///
    /// # Arguments
    ///
    /// * `token` - The MethodDef token of the decryptor method.
    pub fn register(&self, token: Token) {
        self.registered.insert(token);
    }

    /// Registers multiple decryptors.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of MethodDef tokens.
    pub fn register_many(&self, tokens: impl IntoIterator<Item = Token>) {
        for token in tokens {
            self.register(token);
        }
    }

    /// Unregisters a decryptor method.
    ///
    /// This is useful if a detected decryptor turns out not to be one.
    ///
    /// # Arguments
    ///
    /// * `token` - The MethodDef token to unregister.
    ///
    /// # Returns
    ///
    /// `true` if the token was registered and is now removed.
    #[must_use]
    pub fn unregister(&self, token: Token) -> bool {
        self.registered.remove(&token).is_some()
    }

    /// Returns a snapshot of all registered decryptor tokens.
    ///
    /// This is useful for passes that need to check multiple call targets
    /// against the set of registered decryptors.
    #[must_use]
    pub fn registered_tokens(&self) -> HashSet<Token> {
        self.registered.iter().map(|r| *r).collect()
    }

    /// Returns all tokens that resolve to registered decryptors.
    ///
    /// This includes:
    /// - Directly registered MethodDef tokens
    /// - MethodSpec tokens mapped to registered decryptors
    ///
    /// Use this when you need to match call targets against decryptors
    /// in a set-based check (e.g., in `find_decryptor_call_sites`).
    pub fn all_resolvable_tokens(&self) -> HashSet<Token> {
        let mut tokens = self.registered_tokens();
        for entry in self.methodspec_to_decryptor.iter() {
            if self.registered.contains(entry.value()) {
                tokens.insert(*entry.key());
            }
        }
        tokens
    }

    /// Maps a MethodSpec token to its base MethodDef decryptor.
    ///
    /// Generic decryptors like `T Get<T>(int32)` are called via MethodSpec
    /// tokens that instantiate the generic with a specific type argument.
    /// This mapping allows the SSA pass to resolve those calls.
    ///
    /// # Arguments
    ///
    /// * `methodspec` - The MethodSpec token (from call instruction).
    /// * `decryptor` - The base MethodDef token of the decryptor.
    pub fn map_methodspec(&self, methodspec: Token, decryptor: Token) {
        self.methodspec_to_decryptor.insert(methodspec, decryptor);
    }

    /// Maps multiple MethodSpec tokens to the same decryptor.
    pub fn map_methodspecs(&self, methodspecs: impl IntoIterator<Item = Token>, decryptor: Token) {
        for ms in methodspecs {
            self.map_methodspec(ms, decryptor);
        }
    }

    /// Resolves a call target to a registered decryptor.
    ///
    /// This handles both direct MethodDef calls and indirect MethodSpec calls.
    ///
    /// # Arguments
    ///
    /// * `target` - The call target token (MethodDef, MemberRef, or MethodSpec).
    ///
    /// # Returns
    ///
    /// The decryptor's MethodDef token if the target resolves to a registered
    /// decryptor, `None` otherwise.
    #[must_use]
    pub fn resolve_decryptor(&self, target: Token) -> Option<Token> {
        // First check if it's directly registered
        if self.registered.contains(&target) {
            return Some(target);
        }

        // Then check if it's a MethodSpec mapped to a decryptor
        if let Some(decryptor_ref) = self.methodspec_to_decryptor.get(&target) {
            let decryptor = *decryptor_ref;
            if self.registered.contains(&decryptor) {
                return Some(decryptor);
            }
        }

        None
    }

    /// Checks if a method is a registered decryptor (directly or via MethodSpec).
    ///
    /// # Arguments
    ///
    /// * `token` - The method token to check.
    ///
    /// # Returns
    ///
    /// `true` if the method is a known decryptor.
    #[must_use]
    pub fn is_decryptor(&self, token: Token) -> bool {
        self.resolve_decryptor(token).is_some()
    }

    /// Returns all registered decryptor tokens.
    #[must_use]
    pub fn all_decryptors(&self) -> Vec<Token> {
        self.registered.iter().map(|r| *r).collect()
    }

    /// Returns the number of registered decryptors.
    #[must_use]
    pub fn decryptor_count(&self) -> usize {
        self.registered.len()
    }

    /// Checks if any decryptors are registered.
    #[must_use]
    pub fn has_decryptors(&self) -> bool {
        !self.registered.is_empty()
    }

    /// Returns the number of MethodSpec mappings.
    #[must_use]
    pub fn methodspec_mapping_count(&self) -> usize {
        self.methodspec_to_decryptor.len()
    }

    /// Returns an iterator over all MethodSpec to MethodDef mappings.
    ///
    /// This is useful for checking if a call target is a generic instantiation
    /// of a known decryptor.
    pub fn all_methodspec_mappings(&self) -> impl Iterator<Item = (Token, Token)> + '_ {
        self.methodspec_to_decryptor
            .iter()
            .map(|r| (*r.key(), *r.value()))
    }

    /// Executes a closure with a reference to the cached value.
    ///
    /// This is the preferred way to access cached values as it avoids cloning.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The token the call names: the decryptor, or for a generic one its
    ///   instantiation, whose results differ by type argument.
    /// * `args` - The constant arguments.
    /// * `f` - A closure that receives a reference to the cached value.
    ///
    /// # Returns
    ///
    /// The result of the closure if the value is cached, `None` otherwise.
    pub fn with_cached<R, F>(&self, decryptor: Token, args: &[ConstValue], f: F) -> Option<R>
    where
        F: FnOnce(&ConstValue) -> R,
    {
        let key = CacheKey::new(decryptor, args);
        self.cache.get(&key).map(|r| f(&r))
    }

    /// Caches a decrypted value.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The token the call names: the decryptor, or for a generic one its
    ///   instantiation, whose results differ by type argument.
    /// * `args` - The constant arguments.
    /// * `value` - The decrypted value to cache.
    pub fn cache_value(&self, decryptor: Token, args: &[ConstValue], value: ConstValue) {
        let key = CacheKey::new(decryptor, args);
        self.cache.insert(key, value);
    }

    /// Checks if a value is cached for the given decryptor and arguments.
    #[must_use]
    pub fn is_cached(&self, decryptor: Token, args: &[ConstValue]) -> bool {
        let key = CacheKey::new(decryptor, args);
        self.cache.contains_key(&key)
    }

    /// Clears the decryption cache.
    ///
    /// Useful if the assembly has been modified and cached values may be stale.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Records a successful decryption.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The decryptor method token.
    /// * `caller` - The method containing the call.
    /// * `location` - The call instruction's identity.
    /// * `value` - The decrypted value.
    pub fn record_success(
        &self,
        decryptor: Token,
        caller: Token,
        location: Option<InstrId>,
        value: ConstValue,
    ) {
        self.decrypted
            .entry(decryptor)
            .or_default()
            .push(DecryptedCall {
                caller,
                location,
                value,
            });
        if let Some(id) = location {
            self.decrypted_index.insert((caller, id));
        }
    }

    /// Records a failed decryption attempt.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The decryptor method token.
    /// * `caller` - The method containing the call.
    /// * `location` - The call instruction's identity.
    /// * `reason` - Why decryption failed.
    pub fn record_failure(
        &self,
        decryptor: Token,
        caller: Token,
        location: Option<InstrId>,
        reason: FailureReason,
    ) {
        let is_permanent = reason.is_permanent();
        self.failed.entry(decryptor).or_default().push(FailedCall {
            caller,
            location,
            reason,
        });
        if is_permanent {
            if let Some(id) = location {
                self.permanent_failure_index.insert((caller, id));
            }
        }
    }

    /// Gets all successful decryptions for a decryptor.
    #[must_use]
    pub fn get_decrypted(&self, decryptor: Token) -> Option<Vec<DecryptedCall>> {
        self.decrypted
            .get(&decryptor)
            .map(|r| r.iter().map(|(_, v)| v.clone()).collect())
    }

    /// Gets all failed decryptions for a decryptor.
    #[must_use]
    pub fn get_failed(&self, decryptor: Token) -> Option<Vec<FailedCall>> {
        self.failed
            .get(&decryptor)
            .map(|r| r.iter().map(|(_, v)| v.clone()).collect())
    }

    /// Checks if a call site has a permanent failure recorded.
    ///
    /// This is used to skip call sites that have already failed with a
    /// permanent failure reason (e.g., emulation failed, method not found).
    /// Call sites with retriable failures (e.g., non-constant args) are not
    /// considered permanently failed and may be retried in later passes.
    ///
    /// # Arguments
    ///
    /// * `caller` - The method containing the call.
    /// * `location` - The call instruction's identity.
    ///
    /// # Returns
    ///
    /// `true` if a permanent failure was recorded for this call site.
    #[must_use]
    pub fn has_permanent_failure(&self, caller: Token, location: Option<InstrId>) -> bool {
        // A call with no identity is one this run has never recorded anything
        // about, so nothing is known against it.
        location.is_some_and(|id| self.permanent_failure_index.contains(&(caller, id)))
    }

    /// Checks if a call site has already been successfully decrypted.
    ///
    /// This is used to skip call sites that have already been decrypted
    /// in a previous iteration/pass.
    ///
    /// # Arguments
    ///
    /// * `caller` - The method containing the call.
    /// * `location` - The call instruction's identity.
    ///
    /// # Returns
    ///
    /// `true` if a successful decryption was recorded for this call site.
    #[must_use]
    pub fn is_already_decrypted(&self, caller: Token, location: Option<InstrId>) -> bool {
        location.is_some_and(|id| self.decrypted_index.contains(&(caller, id)))
    }

    /// Returns the total number of successful decryptions.
    #[must_use]
    pub fn total_decrypted(&self) -> usize {
        self.decrypted
            .iter()
            .map(|entry| entry.value().count())
            .sum()
    }

    /// Returns the total number of failed decryptions.
    #[must_use]
    pub fn total_failed(&self) -> usize {
        self.failed.iter().map(|entry| entry.value().count()).sum()
    }

    /// Checks if all calls to a decryptor were successfully handled.
    ///
    /// Returns `true` if there are no failed calls for this decryptor.
    ///
    /// Note that this is not on its own sufficient to justify deleting the
    /// method: a decryptor that was never exercised also has no failures.
    /// Removal additionally requires that nothing still calls it - see
    /// `decryptors_still_called` in the cleanup builder.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The decryptor method token.
    ///
    /// # Returns
    ///
    /// `true` if no call site failed to decrypt.
    #[must_use]
    pub fn is_fully_decrypted(&self, decryptor: Token) -> bool {
        self.failed.get(&decryptor).is_none_or(|r| r.count() == 0)
    }

    /// Gets decryptors that are safe to remove (all calls were decrypted).
    ///
    /// # Returns
    ///
    /// A vector of decryptor tokens that can be safely removed.
    #[must_use]
    pub fn removable_decryptors(&self) -> Vec<Token> {
        self.registered
            .iter()
            .map(|r| *r.key())
            .filter(|t| self.is_fully_decrypted(*t))
            .collect()
    }

    /// Gets decryptors that had at least one successful decryption.
    ///
    /// # Returns
    ///
    /// A vector of decryptor tokens that decrypted at least one call.
    #[must_use]
    pub fn active_decryptors(&self) -> Vec<Token> {
        self.registered
            .iter()
            .map(|r| *r.key())
            .filter(|t| self.decrypted.get(t).is_some_and(|r| r.count() > 0))
            .collect()
    }

    /// Gets decryptors that had failures (may need manual review).
    ///
    /// # Returns
    ///
    /// A vector of decryptor tokens that had at least one failed call.
    #[must_use]
    pub fn problematic_decryptors(&self) -> Vec<Token> {
        self.registered
            .iter()
            .map(|r| *r.key())
            .filter(|t| self.failed.get(t).is_some_and(|r| r.count() > 0))
            .collect()
    }

    /// Clears all results but keeps registrations.
    ///
    /// Useful for re-running passes without re-detecting decryptors.
    pub fn clear_results(&self) {
        self.decrypted.clear();
        self.failed.clear();
        self.cache.clear();
        self.permanent_failure_index.clear();
        self.decrypted_index.clear();
    }

    /// Clears everything including registrations.
    pub fn clear_all(&mut self) {
        self.registered.clear();
        self.decrypted.clear();
        self.failed.clear();
        self.cache.clear();
        self.methodspec_to_decryptor.clear();
        self.permanent_failure_index.clear();
        self.decrypted_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    /// A stand-in instruction identity, for the records these tests make.
    ///
    /// Identities come from a function's allocator; a test with no function
    /// builds one directly so the record it makes is keyed the way a real one
    /// would be.
    fn identity(raw: u32) -> Option<InstrId> {
        InstrId::from_raw(raw)
    }
    use super::*;

    #[test]
    fn test_register_and_query() {
        let ctx = DecryptorContext::new();
        let token = Token::new(0x06000001);

        // Not registered initially
        assert!(!ctx.is_decryptor(token));

        // Register
        ctx.register(token);

        // Now registered
        assert!(ctx.is_decryptor(token));
    }

    #[test]
    fn test_register_many() {
        let ctx = DecryptorContext::new();
        let tokens = vec![
            Token::new(0x06000001),
            Token::new(0x06000002),
            Token::new(0x06000003),
        ];

        ctx.register_many(tokens.iter().copied());

        assert_eq!(ctx.decryptor_count(), 3);
        for token in &tokens {
            assert!(ctx.is_decryptor(*token));
        }
    }

    #[test]
    fn test_methodspec_resolution() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let methodspec1 = Token::new(0x2b000001);
        let methodspec2 = Token::new(0x2b000002);

        // Register the base decryptor
        ctx.register(decryptor);

        // Map MethodSpecs to the decryptor
        ctx.map_methodspec(methodspec1, decryptor);
        ctx.map_methodspec(methodspec2, decryptor);

        // Both MethodSpecs should resolve to the decryptor
        assert!(ctx.is_decryptor(methodspec1));
        assert!(ctx.is_decryptor(methodspec2));
        assert_eq!(ctx.resolve_decryptor(methodspec1), Some(decryptor));
        assert_eq!(ctx.resolve_decryptor(methodspec2), Some(decryptor));
    }

    #[test]
    fn test_caching() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let args = vec![ConstValue::I32(42)];
        let value = ConstValue::I32(100);

        // Not cached initially
        assert!(!ctx.is_cached(decryptor, &args));

        // Cache value
        ctx.cache_value(decryptor, &args, value.clone());

        // Now cached
        assert!(ctx.is_cached(decryptor, &args));
        assert!(ctx
            .with_cached(decryptor, &args, |v| *v == value)
            .unwrap_or(false));

        // Different args not cached
        let other_args = vec![ConstValue::I32(43)];
        assert!(!ctx.is_cached(decryptor, &other_args));
    }

    #[test]
    fn test_result_tracking() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let caller = Token::new(0x06000002);

        ctx.register(decryptor);

        // Record success
        ctx.record_success(decryptor, caller, identity(100), ConstValue::I32(42));
        ctx.record_success(decryptor, caller, identity(200), ConstValue::I32(43));

        assert_eq!(ctx.total_decrypted(), 2);
        assert_eq!(ctx.total_failed(), 0);
        assert!(ctx.is_fully_decrypted(decryptor));

        // Record failure
        ctx.record_failure(
            decryptor,
            caller,
            identity(300),
            FailureReason::NonConstantArgs,
        );

        assert_eq!(ctx.total_decrypted(), 2);
        assert_eq!(ctx.total_failed(), 1);
        assert!(!ctx.is_fully_decrypted(decryptor));
    }

    #[test]
    fn test_removable_decryptors() {
        let ctx = DecryptorContext::new();
        let decryptor1 = Token::new(0x06000001);
        let decryptor2 = Token::new(0x06000002);
        let caller = Token::new(0x06000003);

        ctx.register(decryptor1);
        ctx.register(decryptor2);

        // decryptor1: all successes
        ctx.record_success(decryptor1, caller, identity(100), ConstValue::I32(1));

        // decryptor2: has a failure
        ctx.record_success(decryptor2, caller, identity(200), ConstValue::I32(2));
        ctx.record_failure(
            decryptor2,
            caller,
            identity(300),
            FailureReason::NonConstantArgs,
        );

        let removable = ctx.removable_decryptors();
        assert!(removable.contains(&decryptor1));
        assert!(!removable.contains(&decryptor2));
    }

    #[test]
    fn test_stats() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let caller = Token::new(0x06000002);
        let methodspec = Token::new(0x2b000001);

        ctx.register(decryptor);
        ctx.map_methodspec(methodspec, decryptor);
        ctx.cache_value(decryptor, &[ConstValue::I32(1)], ConstValue::I32(10));
        ctx.record_success(decryptor, caller, identity(100), ConstValue::I32(10));
        ctx.record_failure(
            decryptor,
            caller,
            identity(200),
            FailureReason::NonConstantArgs,
        );

        // Verify registration
        assert!(ctx.is_decryptor(decryptor));
        assert!(ctx.has_decryptors());

        // Verify methodspec mapping
        assert_eq!(ctx.resolve_decryptor(methodspec), Some(decryptor));

        // Verify success/failure tracking (for operational checks, not stats)
        assert!(ctx.is_already_decrypted(caller, identity(100)));
        assert!(!ctx.is_already_decrypted(caller, identity(200))); // failure, not success

        // Verify decryption counts via internal methods
        assert_eq!(ctx.total_decrypted(), 1);
        assert_eq!(ctx.total_failed(), 1);
    }

    #[test]
    fn test_unregister() {
        let ctx = DecryptorContext::new();
        let token = Token::new(0x06000001);

        ctx.register(token);
        assert!(ctx.is_decryptor(token));

        let removed = ctx.unregister(token);
        assert!(removed);
        assert!(!ctx.is_decryptor(token));

        // Unregistering non-existent returns false
        assert!(!ctx.unregister(token));
    }

    #[test]
    fn test_clear_results() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let caller = Token::new(0x06000002);

        ctx.register(decryptor);
        ctx.cache_value(decryptor, &[ConstValue::I32(1)], ConstValue::I32(10));
        ctx.record_success(decryptor, caller, identity(100), ConstValue::I32(10));

        ctx.clear_results();

        // Registration preserved
        assert!(ctx.is_decryptor(decryptor));
        // Results cleared
        assert_eq!(ctx.total_decrypted(), 0);
        assert!(!ctx.is_cached(decryptor, &[ConstValue::I32(1)]));
    }

    #[test]
    fn test_cache_key_equality() {
        let key1 = CacheKey::new(Token::new(0x06000001), &[ConstValue::I32(42)]);
        let key2 = CacheKey::new(Token::new(0x06000001), &[ConstValue::I32(42)]);
        let key3 = CacheKey::new(Token::new(0x06000001), &[ConstValue::I32(43)]);
        let key4 = CacheKey::new(Token::new(0x06000002), &[ConstValue::I32(42)]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_failure_reason_display() {
        assert_eq!(
            FailureReason::NonConstantArgs.to_string(),
            "arguments not constant"
        );
        assert_eq!(
            FailureReason::EmulationFailed("timeout".to_string()).to_string(),
            "emulation failed: timeout"
        );
    }

    #[test]
    fn test_failure_reason_is_permanent() {
        // NonConstantArgs is retriable (not permanent)
        assert!(!FailureReason::NonConstantArgs.is_permanent());

        // All other failures are permanent
        assert!(FailureReason::EmulationFailed("timeout".to_string()).is_permanent());
        assert!(FailureReason::UnresolvedTarget.is_permanent());
        assert!(FailureReason::InvalidReturnValue.is_permanent());
        assert!(FailureReason::MethodNotFound.is_permanent());
    }

    #[test]
    fn test_has_permanent_failure() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let caller = Token::new(0x06000002);

        ctx.register(decryptor);

        // Initially no failures
        assert!(!ctx.has_permanent_failure(caller, identity(100)));

        // Record a non-permanent failure
        ctx.record_failure(
            decryptor,
            caller,
            identity(100),
            FailureReason::NonConstantArgs,
        );
        // Still no permanent failure
        assert!(!ctx.has_permanent_failure(caller, identity(100)));

        // Record a permanent failure at different location
        ctx.record_failure(
            decryptor,
            caller,
            identity(200),
            FailureReason::EmulationFailed("timeout".to_string()),
        );
        // Location 100 still not permanently failed
        assert!(!ctx.has_permanent_failure(caller, identity(100)));
        // Location 200 is permanently failed
        assert!(ctx.has_permanent_failure(caller, identity(200)));
    }

    #[test]
    fn test_is_already_decrypted() {
        let ctx = DecryptorContext::new();
        let decryptor = Token::new(0x06000001);
        let caller = Token::new(0x06000002);

        ctx.register(decryptor);

        // Initially not decrypted
        assert!(!ctx.is_already_decrypted(caller, identity(100)));

        // Record a success
        ctx.record_success(decryptor, caller, identity(100), ConstValue::I32(42));
        // Now it's marked as decrypted
        assert!(ctx.is_already_decrypted(caller, identity(100)));
        // Different location is not decrypted
        assert!(!ctx.is_already_decrypted(caller, identity(200)));
        // Different caller is not decrypted
        assert!(!ctx.is_already_decrypted(Token::new(0x06000003), identity(100)));
    }

    #[test]
    fn test_thread_safe_access() {
        let ctx = Arc::new(DecryptorContext::new());
        let mut handles = vec![];

        // Spawn multiple threads that access the same context
        for i in 0..4 {
            let ctx_clone = Arc::clone(&ctx);
            handles.push(thread::spawn(move || {
                for j in 0..50_i32 {
                    let decryptor = Token::new(0x06000000 + (i * 50 + j) as u32);
                    ctx_clone.register(decryptor);
                    ctx_clone.record_success(
                        decryptor,
                        Token::new(0x06001000),
                        identity(j.saturating_add(1) as u32),
                        ConstValue::I32(j),
                    );
                    ctx_clone.cache_value(decryptor, &[ConstValue::I32(j)], ConstValue::I32(j * 2));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 200 decryptors should be registered
        assert_eq!(ctx.decryptor_count(), 200);
        assert_eq!(ctx.total_decrypted(), 200);
    }

    /// The per-emulation instruction and wall-clock budgets bound one call; nothing bounded
    /// how many calls a run makes, and the value cache is keyed on `(decryptor, args)` so a
    /// varying key misses it every time. This is that ceiling.
    #[test]
    fn emulation_budget_stops_the_run_at_the_limit() {
        let ctx = DecryptorContext::new();

        assert!(ctx.try_reserve_emulation(2));
        assert!(ctx.try_reserve_emulation(2));
        assert!(
            !ctx.try_reserve_emulation(2),
            "third reservation must be refused"
        );
        assert_eq!(ctx.emulations_performed(), 2);
    }

    /// A limit of zero means unlimited, matching the config's documented encoding.
    #[test]
    fn emulation_budget_of_zero_is_unlimited() {
        let ctx = DecryptorContext::new();

        for _ in 0..1000 {
            assert!(ctx.try_reserve_emulation(0));
        }
    }

    /// Reservations must not race: with N threads competing for M slots, exactly M succeed.
    #[test]
    fn emulation_budget_is_not_oversubscribed_under_contention() {
        let ctx = Arc::new(DecryptorContext::new());
        let granted = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let ctx = Arc::clone(&ctx);
                let granted = Arc::clone(&granted);
                thread::spawn(move || {
                    for _ in 0..50 {
                        if ctx.try_reserve_emulation(100) {
                            granted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(granted.load(Ordering::Relaxed), 100);
    }

    /// Budget exhaustion is a property of the run, not the call site, so it must not be
    /// cached as a permanent failure - a larger budget would let the same site succeed.
    #[test]
    fn budget_exhaustion_is_not_a_permanent_failure() {
        assert!(!FailureReason::EmulationBudgetExhausted.is_permanent());
        assert!(FailureReason::MethodNotFound.is_permanent());
    }
}

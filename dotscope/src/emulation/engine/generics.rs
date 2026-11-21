//! Generic type and method instantiation tracking for the emulation engine.
//!
//! .NET generics require tracking which type arguments are bound to each
//! generic type or method instantiation at runtime. The CLR creates distinct
//! runtime types for each unique combination of open type + type arguments
//! (e.g., `List<int>` and `List<string>` are different runtime types). This
//! module provides the [`GenericRegistry`] to replicate that behavior.
//!
//! # Type Identity
//!
//! The registry guarantees **type identity**: two instantiations with the
//! same open type and the same type arguments always produce the same
//! synthetic token. This means `List<int>` created in two different places
//! will share a single token, matching CLR semantics.
//!
//! # Synthetic Tokens
//!
//! Instantiated types and methods receive tokens in the `0xF100_xxxx` range
//! (a table ID that does not exist in ECMA-335). These tokens can be passed
//! through the emulation pipeline — call frames, heap objects, reflection —
//! and resolved back to their open type + arguments via [`GenericRegistry::lookup`].
//!
//! # Usage
//!
//! ```text
//! let registry = GenericRegistry::new();
//!
//! let list_int = registry.get_or_create_type(list_token, vec![int_token]);
//! let list_str = registry.get_or_create_type(list_token, vec![str_token]);
//! assert_ne!(list_int, list_str);
//!
//! let (open, args) = registry.lookup(list_int).unwrap();
//! assert_eq!(open, list_token);
//! assert_eq!(args, vec![int_token]);
//! ```
//!
//! # Thread Safety
//!
//! All operations use lock-free [`DashMap`] internally, making the registry
//! `Send + Sync`. The atomic token counter ensures unique token allocation
//! without external synchronization.

use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use log::warn;

use crate::{
    emulation::tokens,
    metadata::{
        tables::{GenericParamAttributes, GenericParamVariance},
        token::Token,
    },
};

/// Tracks generic type and method instantiations during emulation.
///
/// The registry is constructed once by the [`EmulationController`](super::controller::EmulationController)
/// and shared for the lifetime of the emulation process. It maintains three
/// concurrent maps:
///
/// - **Type instantiations**: `(open_type, [args]) → synthetic_token`
/// - **Method instantiations**: `(open_method, [args]) → synthetic_token`
/// - **Reverse lookup**: `synthetic_token → (open_token, [args])`
///
/// The type and method maps share a single atomic counter for token
/// allocation, so all synthetic tokens in the `0xF100_xxxx` range are
/// globally unique within a single emulation process.
pub struct GenericRegistry {
    /// (open_type_token, \[type_arg_tokens\]) → instantiated type token
    type_instantiations: DashMap<(Token, Vec<Token>), Token>,
    /// (open_method_token, \[type_arg_tokens\]) → instantiated method token
    method_instantiations: DashMap<(Token, Vec<Token>), Token>,
    /// Reverse lookup: instantiated token → (open token, args)
    reverse_lookup: DashMap<Token, (Token, Vec<Token>)>,
    /// Next synthetic token counter (0xF100_0001, 0xF100_0002, ...)
    next_token: AtomicU32,
}

impl GenericRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_instantiations: DashMap::new(),
            method_instantiations: DashMap::new(),
            reverse_lookup: DashMap::new(),
            next_token: AtomicU32::new(1),
        }
    }

    /// Gets or creates an instantiated type token for the given open type and
    /// type arguments.
    ///
    /// If the same `(open_type, args)` combination has been seen before, returns
    /// the previously assigned token (type identity guarantee).
    ///
    /// # Arguments
    ///
    /// * `open_type` — Token of the generic type definition (e.g., `List<T>`).
    /// * `args` — Concrete type argument tokens (e.g., `[System.Int32]`).
    ///
    /// # Returns
    ///
    /// A synthetic token in the `0xF100_xxxx` range uniquely identifying this
    /// instantiation. Subsequent calls with the same arguments return the same
    /// token.
    pub fn get_or_create_type(&self, open_type: Token, args: Vec<Token>) -> Token {
        let key = (open_type, args.clone());
        if let Some(existing) = self.type_instantiations.get(&key) {
            return *existing;
        }

        let id = self.next_token.fetch_add(1, Ordering::SeqCst);
        let token = Token::new(tokens::ranges::GENERIC_INSTANTIATION_BASE | id);

        self.type_instantiations.insert(key, token);
        self.reverse_lookup.insert(token, (open_type, args));
        token
    }

    /// Gets or creates an instantiated method token for the given open method
    /// and type arguments.
    ///
    /// # Arguments
    ///
    /// * `open_method` — Token of the generic method definition.
    /// * `args` — Concrete type argument tokens for the method's generic
    ///   parameters (`!!0`, `!!1`, etc.).
    ///
    /// # Returns
    ///
    /// A synthetic token in the `0xF100_xxxx` range uniquely identifying this
    /// instantiation.
    pub fn get_or_create_method(&self, open_method: Token, args: Vec<Token>) -> Token {
        let key = (open_method, args.clone());
        if let Some(existing) = self.method_instantiations.get(&key) {
            return *existing;
        }

        let id = self.next_token.fetch_add(1, Ordering::SeqCst);
        let token = Token::new(tokens::ranges::GENERIC_INSTANTIATION_BASE | id);

        self.method_instantiations.insert(key, token);
        self.reverse_lookup.insert(token, (open_method, args));
        token
    }

    /// Looks up the open token and type arguments for an instantiated token.
    ///
    /// # Arguments
    ///
    /// * `instantiated` — A synthetic token previously returned by
    ///   [`get_or_create_type`](Self::get_or_create_type) or
    ///   [`get_or_create_method`](Self::get_or_create_method).
    ///
    /// # Returns
    ///
    /// `Some((open_token, args))` if the token is a known instantiation,
    /// `None` otherwise.
    #[must_use]
    pub fn lookup(&self, instantiated: Token) -> Option<(Token, Vec<Token>)> {
        self.reverse_lookup
            .get(&instantiated)
            .map(|entry| entry.value().clone())
    }

    /// Checks if a token is a synthetic generic instantiation (in the
    /// `0xF100_xxxx` range).
    ///
    /// This is a fast bit-mask check that does not require a map lookup.
    #[must_use]
    pub fn is_instantiation(&self, token: Token) -> bool {
        token.value() & tokens::ranges::GENERIC_INSTANTIATION_MASK
            == tokens::ranges::GENERIC_INSTANTIATION_BASE
    }
}

/// Validates generic parameter constraints for a type or method instantiation.
///
/// Checks each type argument against the corresponding generic parameter's
/// constraints (reference type, value type, default constructor). Violations
/// are logged as warnings but do not prevent instantiation — the emulator
/// proceeds permissively to handle obfuscated code that may violate constraints.
///
/// # Arguments
///
/// * `param_name` — Human-readable name for the generic definition (for logging).
/// * `generic_params` — The generic parameter definitions with constraint flags.
/// * `type_args` — The concrete type argument tokens being checked.
/// * `is_value_type` — Callback to check if a token represents a value type.
pub fn validate_constraints<F>(
    param_name: &str,
    generic_params: &[(u32, GenericParamAttributes, String)],
    type_args: &[Token],
    is_value_type: F,
) where
    F: Fn(Token) -> Option<bool>,
{
    for (i, arg_token) in type_args.iter().enumerate() {
        let Some((_, flags, name)) = generic_params.get(i) else {
            continue;
        };

        // Check reference type constraint (where T : class)
        if flags.contains(GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT) {
            if let Some(true) = is_value_type(*arg_token) {
                warn!(
                    "Generic constraint violation in {param_name}: type arg {name} (!!{i}) \
                     requires reference type but got value type 0x{:08X}",
                    arg_token.value()
                );
            }
        }

        // Check value type constraint (where T : struct)
        if flags.contains(GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT) {
            if let Some(false) = is_value_type(*arg_token) {
                warn!(
                    "Generic constraint violation in {param_name}: type arg {name} (!!{i}) \
                     requires value type but got reference type 0x{:08X}",
                    arg_token.value()
                );
            }
        }

        // Note: DEFAULT_CONSTRUCTOR_CONSTRAINT requires checking if the type has a
        // parameterless .ctor — this is non-trivial and rarely causes issues in
        // emulation, so we skip it for now.
    }
}

/// Checks generic variance compatibility between two instantiations of the same
/// open type.
///
/// For each type parameter, examines the variance flag:
/// - **Covariant** (`out`): derived → base assignment is allowed
/// - **Contravariant** (`in`): base → derived assignment is allowed
/// - **Invariant**: exact match required
///
/// Returns `true` if the assignment `source → target` is compatible considering
/// variance. When variance information is unavailable, defaults to permissive
/// (returns `true`).
///
/// # Arguments
///
/// * `generic_params` — The generic parameter definitions with variance flags.
/// * `source_args` — Type arguments of the source (right-hand side).
/// * `target_args` — Type arguments of the target (left-hand side).
/// * `is_assignable` — Callback: `is_assignable(from, to)` returns `true` if
///   `from` can be assigned to `to` (i.e., `from` derives from `to`).
pub fn check_variance_compatibility<F>(
    generic_params: &[(u32, GenericParamAttributes, String)],
    source_args: &[Token],
    target_args: &[Token],
    is_assignable: F,
) -> bool
where
    F: Fn(Token, Token) -> bool,
{
    if source_args.len() != target_args.len() {
        return false;
    }

    for (i, (src, tgt)) in source_args.iter().zip(target_args.iter()).enumerate() {
        if src == tgt {
            continue;
        }

        let Some((_, flags, _)) = generic_params.get(i) else {
            // No parameter info — be permissive
            continue;
        };

        match flags.variance() {
            GenericParamVariance::Covariant => {
                // Covariant (out): source must be assignable to target (derived → base)
                if !is_assignable(*src, *tgt) {
                    warn!(
                        "Generic variance mismatch at position {i}: covariant parameter \
                         requires 0x{:08X} assignable to 0x{:08X}",
                        src.value(),
                        tgt.value()
                    );
                    return false;
                }
            }
            GenericParamVariance::Contravariant => {
                // Contravariant (in): target must be assignable to source (base → derived)
                if !is_assignable(*tgt, *src) {
                    warn!(
                        "Generic variance mismatch at position {i}: contravariant parameter \
                         requires 0x{:08X} assignable to 0x{:08X}",
                        tgt.value(),
                        src.value()
                    );
                    return false;
                }
            }
            GenericParamVariance::Invariant => {
                warn!(
                    "Generic variance mismatch at position {i}: invariant parameter \
                     requires exact match but got 0x{:08X} vs 0x{:08X}",
                    src.value(),
                    tgt.value()
                );
                return false;
            }
        }
    }

    true
}

impl Default for GenericRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{emulation::engine::generics::GenericRegistry, metadata::token::Token};

    #[test]
    fn test_type_identity() {
        let registry = GenericRegistry::new();
        let open = Token::new(0x0200_0001);
        let arg_int = Token::new(0x0100_0010);
        let arg_str = Token::new(0x0100_0011);

        let list_int_1 = registry.get_or_create_type(open, vec![arg_int]);
        let list_int_2 = registry.get_or_create_type(open, vec![arg_int]);
        let list_str = registry.get_or_create_type(open, vec![arg_str]);

        // Same open type + same args → same token
        assert_eq!(list_int_1, list_int_2);
        // Different args → different token
        assert_ne!(list_int_1, list_str);
    }

    #[test]
    fn test_reverse_lookup() {
        let registry = GenericRegistry::new();
        let open = Token::new(0x0200_0001);
        let args = vec![Token::new(0x0100_0010)];

        let instantiated = registry.get_or_create_type(open, args.clone());
        let (found_open, found_args) = registry.lookup(instantiated).unwrap();

        assert_eq!(found_open, open);
        assert_eq!(found_args, args);
    }

    #[test]
    fn test_method_instantiation() {
        let registry = GenericRegistry::new();
        let open = Token::new(0x0600_0001);
        let args = vec![Token::new(0x0100_0010)];

        let inst1 = registry.get_or_create_method(open, args.clone());
        let inst2 = registry.get_or_create_method(open, args.clone());
        assert_eq!(inst1, inst2);

        let (found_open, found_args) = registry.lookup(inst1).unwrap();
        assert_eq!(found_open, open);
        assert_eq!(found_args, args);
    }

    #[test]
    fn test_is_instantiation() {
        let registry = GenericRegistry::new();
        let open = Token::new(0x0200_0001);
        let inst = registry.get_or_create_type(open, vec![Token::new(0x0100_0010)]);

        assert!(registry.is_instantiation(inst));
        assert!(!registry.is_instantiation(open));
    }

    #[test]
    fn test_unknown_lookup_returns_none() {
        let registry = GenericRegistry::new();
        assert!(registry.lookup(Token::new(0xF100_9999)).is_none());
    }
}

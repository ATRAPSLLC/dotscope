//! Argument validation and allocation ceilings shared by BCL method hooks.
//!
//! # Why hooks need their own ceilings
//!
//! The emulator's instruction budget is evaluated between CIL instructions, in the dispatch
//! loop. A BCL hook runs entirely *inside* one such instruction: once dispatch enters
//! `String.PadLeft` or `Rfc2898DeriveBytes.GetBytes`, no budget is consulted again until the
//! hook returns. A hook that loops or allocates in proportion to an argument it took from the
//! emulated evaluation stack is therefore unbounded by construction, no matter how small the
//! configured instruction limit is.
//!
//! Every hook that sizes work from an emulated value must bound that value itself, before
//! doing the work. The helpers here provide the two checks that need to happen together:
//!
//! 1. **Sign.** Emulated counts arrive as `int32`/`int64`. A bare `as usize` turns `-1` into
//!    `usize::MAX`, which downstream code then tries to honour. Use [`checked_len`], which
//!    converts with `TryFrom` and reports a negative argument as the managed exception .NET
//!    itself raises.
//! 2. **Magnitude.** A positive but absurd count is just as effective — `int.MaxValue` is a
//!    perfectly valid `usize`. [`checked_len`] also enforces a ceiling.
//!
//! Failures are returned as [`PreHookResult::Throw`] rather than
//! [`PreHookResult::Error`](crate::emulation::runtime::hook::PreHookResult::Error), so they
//! flow through CIL exception handling. Emulated code that guards a large allocation with
//! `try`/`catch` — which obfuscator runtimes and packers routinely do — then behaves as it
//! would on a real runtime, instead of the whole emulation being abandoned.

use crate::emulation::{engine::synthetic_exception, runtime::hook::PreHookResult};

/// Ceiling for a general-purpose buffer materialised inside a single hook.
///
/// Sized to be far above anything real code asks for in one call while staying small enough
/// that a rejected request costs nothing. Hooks whose output has a naturally tighter bound
/// should use a more specific constant rather than this one.
pub(crate) const MAX_HOOK_BUFFER: usize = 16 * 1024 * 1024;

/// Ceiling for a single string built by a hook, in `char`s.
///
/// Padding and repeat operations take a target width from emulated code; this bounds the
/// resulting string independently of [`MAX_HOOK_BUFFER`] because strings are measured in
/// scalars rather than bytes.
pub(crate) const MAX_HOOK_STRING_CHARS: usize = 4 * 1024 * 1024;

/// Builds the exception thrown when an emulated count argument is negative.
pub(crate) fn negative_argument(method: &str, param: &str) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
        message: format!("{method}: '{param}' must be non-negative"),
    }
}

/// Builds the exception thrown when an emulated count argument that must be positive is not.
pub(crate) fn non_positive_argument(method: &str, param: &str) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
        message: format!("{method}: '{param}' must be positive"),
    }
}

/// Builds the exception thrown when an emulated count argument exceeds its ceiling.
pub(crate) fn oversized_argument(
    method: &str,
    param: &str,
    requested: usize,
    max: usize,
) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::OUT_OF_MEMORY,
        message: format!(
            "{method}: '{param}' of {requested} exceeds the emulator's per-call limit of {max}"
        ),
    }
}

/// Converts an emulated count to `usize`, rejecting negative and oversized values.
///
/// This is the single entry point hooks should use for any argument that will size an
/// allocation or bound a loop.
///
/// # Arguments
///
/// * `value` — the count as it came off the emulated evaluation stack.
/// * `max` — the ceiling to enforce; see the constants in this module.
/// * `method` — the .NET method name, for the exception message (e.g. `"String.PadLeft"`).
/// * `param` — the .NET parameter name, for the exception message (e.g. `"totalWidth"`).
///
/// # Errors
///
/// Returns the [`PreHookResult`] the caller should return directly: an
/// `ArgumentOutOfRangeException` for a negative value, or an `OutOfMemoryException` for one
/// above `max`.
// The `Err` variant is a `PreHookResult`, which is large because it can carry an `EmValue`.
// That is inherent rather than incidental: the error here *is* the value the calling hook
// returns, and every hook in the tree already returns `PreHookResult` by value. Boxing it
// would add a deref at each of these call sites without removing the cost anywhere.
#[allow(clippy::result_large_err)]
pub(crate) fn checked_len<T>(
    value: T,
    max: usize,
    method: &str,
    param: &str,
) -> Result<usize, PreHookResult>
where
    usize: TryFrom<T>,
{
    let Ok(len) = usize::try_from(value) else {
        return Err(negative_argument(method, param));
    };
    if len > max {
        return Err(oversized_argument(method, param, len, max));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that `result` is a throw of `expected` exception type.
    fn assert_throws(result: &PreHookResult, expected: crate::metadata::token::Token) {
        match result {
            PreHookResult::Throw { exception_type, .. } => assert_eq!(*exception_type, expected),
            other => panic!("expected a throw, got {other:?}"),
        }
    }

    #[test]
    fn accepts_a_reasonable_count() {
        assert_eq!(
            checked_len(1024_i32, MAX_HOOK_BUFFER, "M", "count").unwrap(),
            1024
        );
    }

    #[test]
    fn accepts_zero() {
        assert_eq!(
            checked_len(0_i32, MAX_HOOK_BUFFER, "M", "count").unwrap(),
            0
        );
    }

    #[test]
    fn rejects_negative_i32_as_argument_out_of_range() {
        let err = checked_len(-1_i32, MAX_HOOK_BUFFER, "M", "count").unwrap_err();
        assert_throws(&err, synthetic_exception::ARGUMENT_OUT_OF_RANGE);
    }

    #[test]
    fn rejects_negative_i64_as_argument_out_of_range() {
        let err = checked_len(i64::MIN, MAX_HOOK_BUFFER, "M", "count").unwrap_err();
        assert_throws(&err, synthetic_exception::ARGUMENT_OUT_OF_RANGE);
    }

    #[test]
    fn rejects_oversized_count_as_out_of_memory() {
        let err = checked_len(i32::MAX, 1024, "M", "count").unwrap_err();
        assert_throws(&err, synthetic_exception::OUT_OF_MEMORY);
    }

    #[test]
    fn accepts_exactly_the_ceiling() {
        assert_eq!(checked_len(1024_i32, 1024, "M", "count").unwrap(), 1024);
    }

    #[test]
    fn message_names_the_method_and_parameter() {
        let err = checked_len(-5_i32, MAX_HOOK_BUFFER, "String.PadLeft", "totalWidth").unwrap_err();
        match err {
            PreHookResult::Throw { message, .. } => {
                assert!(message.contains("String.PadLeft"), "got: {message}");
                assert!(message.contains("totalWidth"), "got: {message}");
            }
            other => panic!("expected a throw, got {other:?}"),
        }
    }
}

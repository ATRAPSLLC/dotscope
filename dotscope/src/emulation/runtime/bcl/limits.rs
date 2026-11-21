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
//! [`PreHookResult::Error`], so they
//! flow through CIL exception handling. Emulated code that guards a large allocation with
//! `try`/`catch` — which obfuscator runtimes and packers routinely do — then behaves as it
//! would on a real runtime, instead of the whole emulation being abandoned.

use crate::{
    emulation::{
        engine::synthetic_exception,
        runtime::hook::{HookContext, PreHookResult},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::token::Token,
};

/// Ceiling for a general-purpose buffer materialised inside a single hook.
///
/// Sized to be far above anything real code asks for in one call while staying small enough
/// that a rejected request costs nothing. Hooks whose output has a naturally tighter bound
/// should use a more specific constant rather than this one.
pub const MAX_HOOK_BUFFER: usize = 16 * 1024 * 1024;

/// Ceiling for a single string built by a hook, in `char`s.
///
/// Padding and repeat operations take a target width from emulated code; this bounds the
/// resulting string independently of [`MAX_HOOK_BUFFER`] because strings are measured in
/// scalars rather than bytes.
pub const MAX_HOOK_STRING_CHARS: usize = 4 * 1024 * 1024;

/// The `(byte[] buffer, int offset, int count)` arguments of a stream method, checked as the
/// runtime's `Stream.ValidateBufferArguments` checks them before any data moves: the buffer's
/// handle, the offset and the count.
///
/// A null buffer is the `ArgumentNullException` the runtime throws, a negative offset or
/// count the `ArgumentOutOfRangeException`, and a count past the buffer's end from the offset
/// the exception `past_end` names: `ArgumentOutOfRangeException` for a `Stream`,
/// `ArgumentException` for `BinaryReader.Read`. Arguments of any other shape (no array, no
/// `int32`) are no call the runtime makes, so they are an emulation error rather than an
/// exception the program could catch.
///
/// # Arguments
///
/// * `ctx` - The hook context, whose first three arguments are the buffer, offset and count
/// * `thread` - The emulation thread, for the buffer's length
/// * `past_end` - The exception a range past the buffer's end throws
pub fn buffer_range(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
    past_end: Token,
) -> std::result::Result<(HeapRef, usize, usize), PreHookResult> {
    let throw = |exception_type, message: String| PreHookResult::Throw {
        exception_type,
        message,
    };
    let buffer = match ctx.args.first() {
        Some(EmValue::ObjectRef(handle)) => *handle,
        Some(EmValue::Null) => {
            return Err(throw(
                synthetic_exception::ARGUMENT_NULL,
                "buffer".to_string(),
            ))
        }
        other => {
            return Err(PreHookResult::Error(format!(
                "{}.{} with buffer {other:?}, no byte array",
                ctx.type_name, ctx.method_name
            )))
        }
    };
    let (Some(EmValue::I32(offset)), Some(EmValue::I32(count))) =
        (ctx.args.get(1), ctx.args.get(2))
    else {
        return Err(PreHookResult::Error(format!(
            "{}.{} without int32 offset and count",
            ctx.type_name, ctx.method_name
        )));
    };
    let (Ok(offset), Ok(count)) = (usize::try_from(*offset), usize::try_from(*count)) else {
        return Err(throw(
            synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            format!("offset {offset} and count {count} must be non-negative"),
        ));
    };
    let length = thread
        .heap()
        .get_array_length(buffer)
        .map_err(|e| PreHookResult::Error(format!("buffer is no array: {e}")))?;
    if length.checked_sub(offset).is_none_or(|room| count > room) {
        return Err(throw(
            past_end,
            format!("{count} bytes from offset {offset} pass the buffer's {length} bytes"),
        ));
    }
    Ok((buffer, offset, count))
}

/// Builds the exception thrown when an emulated count argument is negative.
pub fn negative_argument(method: &str, param: &str) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
        message: format!("{method}: '{param}' must be non-negative"),
    }
}

/// Builds the exception thrown when an emulated count argument that must be positive is not.
pub fn non_positive_argument(method: &str, param: &str) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
        message: format!("{method}: '{param}' must be positive"),
    }
}

/// Builds the exception thrown when an emulated count argument exceeds its ceiling.
pub fn oversized_argument(
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
pub fn checked_len<T>(
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
    use crate::{metadata::typesystem::PointerSize, testkit::emulation::create_test_thread};

    /// Asserts that `result` is a throw of `expected` exception type.
    fn assert_throws(result: &PreHookResult, expected: Token) {
        match result {
            PreHookResult::Throw { exception_type, .. } => assert_eq!(*exception_type, expected),
            other => panic!("expected a throw, got {other:?}"),
        }
    }

    /// `buffer_range` of `(buffer, offset, count)` over a 16-byte array, or a null buffer.
    fn range_of(
        buffer: bool,
        offset: i32,
        count: i32,
        past_end: Token,
    ) -> std::result::Result<(HeapRef, usize, usize), PreHookResult> {
        let thread = create_test_thread();
        let array = thread.heap().alloc_byte_array(&[0u8; 16]).unwrap();
        let args = [
            if buffer {
                EmValue::ObjectRef(array)
            } else {
                EmValue::Null
            },
            EmValue::I32(offset),
            EmValue::I32(count),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Stream",
            "Read",
            PointerSize::Bit64,
        )
        .with_args(&args);
        buffer_range(&ctx, &thread, past_end)
    }

    /// The buffer arguments of a stream call are checked as `Stream.ValidateBufferArguments`
    /// checks them: null, negative, and past the end each the exception the runtime throws,
    /// with the past-end exception the caller names (`BinaryReader` throws
    /// `ArgumentException`). A range that ends at the buffer's end is accepted.
    #[test]
    fn buffer_ranges_are_checked_as_the_runtime_checks_them() {
        let range = synthetic_exception::ARGUMENT_OUT_OF_RANGE;
        assert_throws(
            &range_of(false, 0, 1, range).unwrap_err(),
            synthetic_exception::ARGUMENT_NULL,
        );
        assert_throws(&range_of(true, -1, 1, range).unwrap_err(), range);
        assert_throws(&range_of(true, 0, -1, range).unwrap_err(), range);
        assert_throws(&range_of(true, 8, 9, range).unwrap_err(), range);
        assert_throws(&range_of(true, 17, 0, range).unwrap_err(), range);
        // Where the past-end exception differs, a negative argument still throws
        // `ArgumentOutOfRangeException`, as `BinaryReader.Read` does
        let argument = synthetic_exception::ARGUMENT_EXCEPTION;
        assert_throws(&range_of(true, 8, 9, argument).unwrap_err(), argument);
        assert_throws(&range_of(true, -1, 1, argument).unwrap_err(), range);
        assert_throws(&range_of(true, 0, -1, argument).unwrap_err(), range);
        let (_, offset, count) = range_of(true, 8, 8, range).unwrap();
        assert_eq!((offset, count), (8, 8));
        assert!(range_of(true, 16, 0, range).is_ok());
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

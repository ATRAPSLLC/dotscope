//! `System.String` method hooks.
//!
//! This module provides hook implementations for string manipulation methods commonly
//! used by obfuscators for string construction, transformation, and comparison.

use crate::{
    emulation::{
        engine::synthetic_exception,
        memory::{HeapObject, ManagedString},
        runtime::{
            bcl::limits::{oversized_argument, MAX_HOOK_STRING_CHARS},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    metadata::typesystem::CilFlavor,
    Result,
};

/// Registers all `System.String` method hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // Static methods
    manager.register(
        Hook::new("System.String.Concat")
            .match_name("System", "String", "Concat")
            .pre(string_concat_pre),
    )?;
    manager.register(
        Hook::new("System.String.IsNullOrEmpty")
            .match_name("System", "String", "IsNullOrEmpty")
            .pre(string_is_null_or_empty_pre),
    )?;
    manager.register(
        Hook::new("System.String.Join")
            .match_name("System", "String", "Join")
            .pre(string_join_pre),
    )?;
    manager.register(
        Hook::new("System.String.Format")
            .match_name("System", "String", "Format")
            .pre(string_format_pre),
    )?;
    manager.register(
        Hook::new("System.String.Intern")
            .match_name("System", "String", "Intern")
            .pre(string_intern_pre),
    )?;
    manager.register(
        Hook::new("System.String.IsInterned")
            .match_name("System", "String", "IsInterned")
            .pre(string_is_interned_pre),
    )?;
    manager.register(
        Hook::new("System.String.op_Equality")
            .match_name("System", "String", "op_Equality")
            .pre(string_op_equality_pre),
    )?;
    manager.register(
        Hook::new("System.String.op_Inequality")
            .match_name("System", "String", "op_Inequality")
            .pre(string_op_inequality_pre),
    )?;

    // Instance properties
    manager.register(
        Hook::new("System.String.get_Length")
            .match_name("System", "String", "get_Length")
            .pre(string_get_length_pre),
    )?;
    manager.register(
        Hook::new("System.String.get_Chars")
            .match_name("System", "String", "get_Chars")
            .pre(string_get_chars_pre),
    )?;

    // Instance methods
    manager.register(
        Hook::new("System.String.Substring")
            .match_name("System", "String", "Substring")
            .pre(string_substring_pre),
    )?;
    manager.register(
        Hook::new("System.String.ToCharArray")
            .match_name("System", "String", "ToCharArray")
            .pre(string_to_char_array_pre),
    )?;
    manager.register(
        Hook::new("System.String.ToUpper")
            .match_name("System", "String", "ToUpper")
            .pre(string_to_upper_pre),
    )?;
    manager.register(
        Hook::new("System.String.ToLower")
            .match_name("System", "String", "ToLower")
            .pre(string_to_lower_pre),
    )?;
    manager.register(
        Hook::new("System.String.Trim")
            .match_name("System", "String", "Trim")
            .pre(string_trim_pre),
    )?;
    manager.register(
        Hook::new("System.String.Replace")
            .match_name("System", "String", "Replace")
            .pre(string_replace_pre),
    )?;
    manager.register(
        Hook::new("System.String.Split")
            .match_name("System", "String", "Split")
            .pre(string_split_pre),
    )?;
    manager.register(
        Hook::new("System.String.Contains")
            .match_name("System", "String", "Contains")
            .pre(string_contains_pre),
    )?;
    manager.register(
        Hook::new("System.String.StartsWith")
            .match_name("System", "String", "StartsWith")
            .pre(string_starts_with_pre),
    )?;
    manager.register(
        Hook::new("System.String.EndsWith")
            .match_name("System", "String", "EndsWith")
            .pre(string_ends_with_pre),
    )?;
    manager.register(
        Hook::new("System.String.IndexOf")
            .match_name("System", "String", "IndexOf")
            .pre(string_index_of_pre),
    )?;
    manager.register(
        Hook::new("System.String.PadLeft")
            .match_name("System", "String", "PadLeft")
            .pre(string_pad_left_pre),
    )?;
    manager.register(
        Hook::new("System.String.PadRight")
            .match_name("System", "String", "PadRight")
            .pre(string_pad_right_pre),
    )?;

    Ok(())
}

/// Hook for `System.String.Concat` method.
///
/// # Handled Overloads
///
/// - `String.Concat(Object) -> String`
/// - `String.Concat(Object, Object) -> String`
/// - `String.Concat(Object, Object, Object) -> String`
/// - `String.Concat(Object[]) -> String`
/// - `String.Concat(String, String) -> String`
/// - `String.Concat(String, String, String) -> String`
/// - `String.Concat(String, String, String, String) -> String`
/// - `String.Concat(String[]) -> String`
///
/// # Parameters
///
/// - `args`: Variable number of objects or strings to concatenate
///
/// # Returns
///
/// A new string containing the concatenated values
fn string_concat_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let mut result = String::new();

    for arg in ctx.args {
        match arg {
            EmValue::ObjectRef(href) => {
                if let Ok(s) = thread.heap().get_string(*href) {
                    result.push_str(&s);
                }
            }
            EmValue::Null => {}
            EmValue::I32(v) => result.push_str(&v.to_string()),
            EmValue::I64(v) => result.push_str(&v.to_string()),
            EmValue::Bool(v) => result.push_str(if *v { "True" } else { "False" }),
            EmValue::Char(c) => result.push(*c),
            _ => result.push_str("[object]"),
        }
    }

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.get_Length` property.
///
/// # Handled Overloads
///
/// - `String.Length { get; } -> Int32`
///
/// # Returns
///
/// The number of UTF-16 code units in the string, as .NET counts them (a character outside
/// the Basic Multilingual Plane is two), in O(1) (see [`ManagedString`]). A null string throws
/// `NullReferenceException`; a receiver the emulation does not know (symbolic) leaves the
/// call unanswered.
///
/// [`ManagedString`]: crate::emulation::ManagedString
fn string_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let string = match string_receiver(ctx, thread) {
        Ok(string) => string,
        Err(result) => return result,
    };
    let length = i32::try_from(string.utf16_len()).unwrap_or(i32::MAX);
    PreHookResult::Bypass(Some(EmValue::I32(length)))
}

/// Hook for `System.String.get_Chars` indexer property.
///
/// # Handled Overloads
///
/// - `String.Chars[Int32] { get; } -> Char`
/// - `String.this[Int32] { get; } -> Char`
///
/// # Parameters
///
/// - `index`: Zero-based position of the UTF-16 code unit
///
/// # Returns
///
/// The UTF-16 code unit at `index`, in O(1) (see [`ManagedString`]): a `Char`, or for half of
/// a surrogate pair, which no Rust `char` holds, its value as the `int32` a `char` is on the
/// evaluation stack (ECMA-335 §III.1.1). An index outside the string throws
/// `IndexOutOfRangeException` and a null string `NullReferenceException`, as the runtime
/// does; a receiver or index the emulation does not know (symbolic) leaves the call
/// unanswered.
///
/// [`ManagedString`]: crate::emulation::ManagedString
fn string_get_chars_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let string = match string_receiver(ctx, thread) {
        Ok(string) => string,
        Err(result) => return result,
    };
    let Some(EmValue::I32(index)) = ctx.args.first() else {
        return PreHookResult::Continue;
    };
    match usize::try_from(*index)
        .ok()
        .and_then(|index| string.unit_at(index))
    {
        Some(unit) => PreHookResult::Bypass(Some(code_unit_value(unit))),
        None => PreHookResult::Throw {
            exception_type: synthetic_exception::INDEX_OUT_OF_RANGE,
            message: format!(
                "index {index} is outside the string of {} characters",
                string.utf16_len()
            ),
        },
    }
}

/// The string a `String` instance method is called on, for the hooks that index or measure it.
///
/// # Errors
///
/// The hook's result instead: `NullReferenceException` for a null receiver, `Continue` (the
/// call stays unanswered) for one the emulation does not know (symbolic), and an error for a
/// reference to something that is not a string.
fn string_receiver(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
) -> std::result::Result<ManagedString, PreHookResult> {
    match ctx.this {
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_managed_string(*href)
            .map_err(|e| PreHookResult::Error(format!("{e}"))),
        Some(EmValue::Null) => Err(PreHookResult::throw_null_reference()),
        _ => Err(PreHookResult::Continue),
    }
}

/// A UTF-16 code unit as a `char` value: a `Char`, or for half of a surrogate pair, which no
/// Rust `char` holds, the unit as the `int32` a `char` is on the evaluation stack
/// (ECMA-335 §III.1.1).
fn code_unit_value(unit: u16) -> EmValue {
    char::from_u32(u32::from(unit)).map_or(EmValue::I32(i32::from(unit)), EmValue::Char)
}

/// The `ArgumentOutOfRangeException` a `String` method throws for an index or length outside
/// the string.
fn argument_out_of_range(message: String) -> PreHookResult {
    PreHookResult::Throw {
        exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
        message,
    }
}

/// The range `[start, start + length)` of a string of `len` code units that `start` and the
/// optional `length` (the rest of the string by default) name, as `Substring` and
/// `ToCharArray` take them.
///
/// # Errors
///
/// `ArgumentOutOfRangeException` when `start` or `length` is negative or the range passes the
/// end, as the runtime throws.
fn code_unit_range(
    start: i32,
    length: Option<i32>,
    len: usize,
) -> std::result::Result<std::ops::Range<usize>, PreHookResult> {
    let start = usize::try_from(start)
        .ok()
        .filter(|&start| start <= len)
        .ok_or_else(|| {
            argument_out_of_range(format!("start {start} is outside a string of {len}"))
        })?;
    let length = match length {
        None => len.saturating_sub(start),
        Some(length) => usize::try_from(length)
            .ok()
            .filter(|&length| length <= len.saturating_sub(start))
            .ok_or_else(|| {
                argument_out_of_range(format!(
                    "length {length} from {start} passes the end of a string of {len}"
                ))
            })?,
    };
    Ok(start..start.saturating_add(length))
}

/// Hook for `System.String.Substring` method.
///
/// # Handled Overloads
///
/// - `String.Substring(Int32) -> String`
/// - `String.Substring(Int32, Int32) -> String`
///
/// # Parameters
///
/// - `startIndex`: Zero-based starting position
/// - `length`: Optional number of characters to extract
///
/// # Returns
///
/// A substring starting at the specified position
fn string_substring_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let string = match string_receiver(ctx, thread) {
        Ok(string) => string,
        Err(result) => return result,
    };
    // Indices count UTF-16 code units, as .NET's do
    let (Some(EmValue::I32(start)), length) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Continue;
    };
    let length = match length {
        None => None,
        Some(EmValue::I32(length)) => Some(*length),
        Some(_) => return PreHookResult::Continue,
    };
    let units = string.utf16_units();
    let range = match code_unit_range(*start, length, units.len()) {
        Ok(range) => range,
        Err(result) => return result,
    };
    // A range that splits a surrogate pair keeps the half as U+FFFD: the emulator's strings
    // are UTF-8, which has no lone surrogates
    let substring = String::from_utf16_lossy(units.get(range).unwrap_or_default());
    match thread.heap_mut().alloc_string(&substring) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.ToCharArray` method.
///
/// # Handled Overloads
///
/// - `String.ToCharArray() -> Char[]`
/// - `String.ToCharArray(Int32, Int32) -> Char[]`
///
/// # Parameters
///
/// - `startIndex`: Optional starting position (default 0)
/// - `length`: Optional number of characters (default all)
///
/// # Returns
///
/// A character array containing the string characters
fn string_to_char_array_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let string = match string_receiver(ctx, thread) {
        Ok(string) => string,
        Err(result) => return result,
    };
    let units = string.utf16_units();
    // `ToCharArray(startIndex, length)` copies that range, counted in UTF-16 code units
    let range = match (ctx.args.first(), ctx.args.get(1)) {
        (None, _) => 0..units.len(),
        (Some(EmValue::I32(start)), Some(EmValue::I32(length))) => {
            match code_unit_range(*start, Some(*length), units.len()) {
                Ok(range) => range,
                Err(result) => return result,
            }
        }
        _ => return PreHookResult::Continue,
    };
    let chars: Vec<EmValue> = units
        .get(range)
        .unwrap_or_default()
        .iter()
        .map(|&unit| code_unit_value(unit))
        .collect();

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Char, chars)
    {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.ToUpper` method.
///
/// # Handled Overloads
///
/// - `String.ToUpper() -> String`
/// - `String.ToUpper(CultureInfo) -> String`
///
/// # Returns
///
/// A copy of the string converted to uppercase
fn string_to_upper_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let upper = s.to_uppercase();
            match thread.heap_mut().alloc_string(&upper) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.ToLower` method.
///
/// # Handled Overloads
///
/// - `String.ToLower() -> String`
/// - `String.ToLower(CultureInfo) -> String`
///
/// # Returns
///
/// A copy of the string converted to lowercase
fn string_to_lower_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let lower = s.to_lowercase();
            match thread.heap_mut().alloc_string(&lower) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Trim` method.
///
/// # Handled Overloads
///
/// - `String.Trim() -> String`
/// - `String.Trim(Char[]) -> String`
///
/// # Parameters
///
/// - `trimChars`: Optional array of characters to trim (default whitespace)
///
/// # Returns
///
/// A new string with leading and trailing characters removed
fn string_trim_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match thread.heap().get_string(*href) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            match thread.heap_mut().alloc_string(&trimmed) {
                Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Replace` method.
///
/// # Handled Overloads
///
/// - `String.Replace(Char, Char) -> String`
/// - `String.Replace(String, String) -> String`
///
/// # Parameters
///
/// - `oldValue`: Character or string to be replaced
/// - `newValue`: Character or string to replace all occurrences
///
/// # Returns
///
/// A new string with all occurrences replaced
fn string_replace_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(*href)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
    };

    let result = match (arg0, arg1) {
        (EmValue::Char(old), EmValue::Char(new)) => s.replace(*old, &new.to_string()),
        (EmValue::ObjectRef(old_ref), EmValue::ObjectRef(new_ref)) => {
            let old_str = thread
                .heap()
                .get_string(*old_ref)
                .map(|s| s.to_string())
                .unwrap_or_default();
            let new_str = thread
                .heap()
                .get_string(*new_ref)
                .map(|s| s.to_string())
                .unwrap_or_default();
            s.replace(&old_str, &new_str)
        }
        _ => s,
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Split` method.
///
/// # Handled Overloads
///
/// - `String.Split(Char[]) -> String[]`
/// - `String.Split(Char[], Int32) -> String[]`
/// - `String.Split(Char[], StringSplitOptions) -> String[]`
///
/// # Parameters
///
/// - `separator`: Array of delimiter characters (or single char)
/// - `count`: Optional maximum number of substrings
/// - `options`: Optional split options
///
/// # Returns
///
/// An array of substrings delimited by the separator
fn string_split_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
    };

    let separator = match ctx.args.first() {
        Some(EmValue::Char(c)) => *c,
        Some(EmValue::ObjectRef(href)) => {
            if let Ok(HeapObject::Array { elements, .. }) =
                thread.heap().get_shared(*href).as_deref()
            {
                elements
                    .first()
                    .and_then(|e| {
                        if let EmValue::Char(c) = e {
                            Some(*c)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(' ')
            } else {
                ' '
            }
        }
        _ => ' ',
    };

    let parts: Vec<&str> = s.split(separator).collect();
    let mut string_refs = Vec::with_capacity(parts.len());
    for part in parts {
        match thread.heap_mut().alloc_string(part) {
            Ok(string_ref) => string_refs.push(EmValue::ObjectRef(string_ref)),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::String, string_refs)
    {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Contains` method.
///
/// # Handled Overloads
///
/// - `String.Contains(String) -> Boolean`
/// - `String.Contains(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to search for
///
/// # Returns
///
/// `true` if the value is found; otherwise `false`
fn string_contains_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let contains = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.contains(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|substr| s.contains(&*substr))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(contains)))
}

/// Hook for `System.String.StartsWith` method.
///
/// # Handled Overloads
///
/// - `String.StartsWith(String) -> Boolean`
/// - `String.StartsWith(String, StringComparison) -> Boolean`
/// - `String.StartsWith(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to compare
/// - `comparisonType`: Optional comparison rules
///
/// # Returns
///
/// `true` if the string starts with the value; otherwise `false`
fn string_starts_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let starts_with = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.starts_with(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|prefix| s.starts_with(&*prefix))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(starts_with)))
}

/// Hook for `System.String.EndsWith` method.
///
/// # Handled Overloads
///
/// - `String.EndsWith(String) -> Boolean`
/// - `String.EndsWith(String, StringComparison) -> Boolean`
/// - `String.EndsWith(Char) -> Boolean`
///
/// # Parameters
///
/// - `value`: String or character to compare
/// - `comparisonType`: Optional comparison rules
///
/// # Returns
///
/// `true` if the string ends with the value; otherwise `false`
fn string_ends_with_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Bool(false)));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Bool(false))),
    };

    let ends_with = match ctx.args.first() {
        Some(EmValue::Char(c)) => s.ends_with(*c),
        Some(EmValue::ObjectRef(href)) => thread
            .heap()
            .get_string(*href)
            .map(|suffix| s.ends_with(&*suffix))
            .unwrap_or(false),
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::Bool(ends_with)))
}

/// Hook for `System.String.IndexOf` method.
///
/// # Handled Overloads
///
/// - `String.IndexOf(Char) -> Int32`
/// - `String.IndexOf(String) -> Int32`
/// - `String.IndexOf(Char, Int32) -> Int32`
/// - `String.IndexOf(String, Int32) -> Int32`
///
/// # Parameters
///
/// - `value`: Character or string to search for
/// - `startIndex`: Optional starting search position
///
/// # Returns
///
/// Zero-based index of the first occurrence, or -1 if not found
fn string_index_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let string = match string_receiver(ctx, thread) {
        Ok(string) => string,
        Err(result) => return result,
    };
    let units = string.utf16_units();
    // The search starts at `startIndex`, a UTF-16 code unit index no greater than the length
    let start = match ctx.args.get(1) {
        None => 0,
        Some(EmValue::I32(start)) => match usize::try_from(*start)
            .ok()
            .filter(|&start| start <= units.len())
        {
            Some(start) => start,
            None => {
                return argument_out_of_range(format!(
                    "startIndex {start} is outside a string of {}",
                    units.len()
                ))
            }
        },
        Some(_) => return PreHookResult::Continue,
    };
    let rest = units.get(start..).unwrap_or_default();
    let found = match ctx.args.first() {
        Some(EmValue::Char(c)) => {
            // A char argument is one code unit
            let mut buffer = [0u16; 2];
            let encoded = c.encode_utf16(&mut buffer);
            match encoded {
                [unit] => rest.iter().position(|u| u == unit),
                _ => None,
            }
        }
        Some(EmValue::I32(unit)) => u16::try_from(*unit)
            .ok()
            .and_then(|unit| rest.iter().position(|&u| u == unit)),
        Some(EmValue::ObjectRef(needle)) => {
            let needle = try_hook!(thread.heap().get_managed_string(*needle));
            let needle = needle.utf16_units();
            if needle.is_empty() {
                Some(0)
            } else {
                rest.windows(needle.len())
                    .position(|window| window == &*needle)
            }
        }
        Some(EmValue::Null) => return PreHookResult::throw_argument_null("value"),
        _ => return PreHookResult::Continue,
    };
    let index = found.map_or(-1, |offset| {
        i32::try_from(start.saturating_add(offset)).unwrap_or(i32::MAX)
    });
    PreHookResult::Bypass(Some(EmValue::I32(index)))
}

/// Hook for `System.String.PadLeft` method.
///
/// # Handled Overloads
///
/// - `String.PadLeft(Int32) -> String`
/// - `String.PadLeft(Int32, Char) -> String`
///
/// # Parameters
///
/// - `totalWidth`: Total length of resulting string
/// - `paddingChar`: Optional padding character (default space)
///
/// # Returns
///
/// A new string padded on the left to the specified width
fn string_pad_left_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
    };

    // `totalWidth` comes off the emulated stack; without a ceiling an `int.MaxValue` argument
    // builds a multi-gigabyte string inside a single hook call, where no emulation budget is
    // evaluated.
    let total_width = match ctx.args.first().map(usize::try_from).and_then(|r| r.ok()) {
        Some(w) if w > MAX_HOOK_STRING_CHARS => {
            return oversized_argument("String.Pad", "totalWidth", w, MAX_HOOK_STRING_CHARS)
        }
        Some(w) => w,
        None => 0,
    };
    let pad_char = ctx
        .args
        .get(1)
        .and_then(|v| {
            if let EmValue::Char(c) = v {
                Some(*c)
            } else {
                None
            }
        })
        .unwrap_or(' ');

    // .NET measures `totalWidth` in UTF-16 code units, not UTF-8 bytes or scalars: comparing
    // against `s.len()` under-pads any string containing a multi-byte scalar.
    let char_count = s.encode_utf16().count();
    let result = if char_count >= total_width {
        s
    } else {
        let pad_count = total_width.saturating_sub(char_count);
        let mut padded = String::with_capacity(
            s.len()
                .saturating_add(pad_count.saturating_mul(pad_char.len_utf8())),
        );
        padded.extend(std::iter::repeat_n(pad_char, pad_count));
        padded.push_str(&s);
        padded
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.PadRight` method.
///
/// # Handled Overloads
///
/// - `String.PadRight(Int32) -> String`
/// - `String.PadRight(Int32, Char) -> String`
///
/// # Parameters
///
/// - `totalWidth`: Total length of resulting string
/// - `paddingChar`: Optional padding character (default space)
///
/// # Returns
///
/// A new string padded on the right to the specified width
fn string_pad_right_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let s = match thread.heap().get_string(*href) {
        Ok(s) => s.to_string(),
        Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
    };

    // `totalWidth` comes off the emulated stack; without a ceiling an `int.MaxValue` argument
    // builds a multi-gigabyte string inside a single hook call, where no emulation budget is
    // evaluated.
    let total_width = match ctx.args.first().map(usize::try_from).and_then(|r| r.ok()) {
        Some(w) if w > MAX_HOOK_STRING_CHARS => {
            return oversized_argument("String.Pad", "totalWidth", w, MAX_HOOK_STRING_CHARS)
        }
        Some(w) => w,
        None => 0,
    };
    let pad_char = ctx
        .args
        .get(1)
        .and_then(|v| {
            if let EmValue::Char(c) = v {
                Some(*c)
            } else {
                None
            }
        })
        .unwrap_or(' ');

    // .NET measures `totalWidth` in UTF-16 code units, not UTF-8 bytes or scalars: comparing
    // against `s.len()` under-pads any string containing a multi-byte scalar.
    let char_count = s.encode_utf16().count();
    let result = if char_count >= total_width {
        s
    } else {
        let pad_count = total_width.saturating_sub(char_count);
        let mut padded = String::with_capacity(
            s.len()
                .saturating_add(pad_count.saturating_mul(pad_char.len_utf8())),
        );
        padded.push_str(&s);
        padded.extend(std::iter::repeat_n(pad_char, pad_count));
        padded
    };

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.IsNullOrEmpty` static method.
///
/// # Handled Overloads
///
/// - `String.IsNullOrEmpty(String) -> Boolean`
///
/// # Parameters
///
/// - `value`: The string to test
///
/// # Returns
///
/// `true` if the string is null or empty; otherwise `false`
fn string_is_null_or_empty_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let is_null_or_empty = if let Some(EmValue::ObjectRef(href)) = ctx.args.first() {
        thread
            .heap()
            .get_string(*href)
            .map(|s| s.is_empty())
            .unwrap_or(true)
    } else {
        true
    };

    PreHookResult::Bypass(Some(EmValue::Bool(is_null_or_empty)))
}

/// Hook for `System.String.Join` static method.
///
/// # Handled Overloads
///
/// - `String.Join(String, String[]) -> String`
/// - `String.Join(String, Object[]) -> String`
/// - `String.Join(String, IEnumerable<String>) -> String`
///
/// # Parameters
///
/// - `separator`: String to insert between elements
/// - `value`: Array or collection of strings to join
///
/// # Returns
///
/// A single string with elements separated by the separator
fn string_join_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let separator = if let EmValue::ObjectRef(href) = arg0 {
        thread
            .heap()
            .get_string(*href)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let array_ref = match arg1 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let Ok(obj) = thread.heap().get_shared(array_ref) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let parts: Vec<String> = match &*obj {
        HeapObject::Array { elements, .. } => elements
            .iter()
            .filter_map(|e| match e {
                EmValue::ObjectRef(href) => {
                    thread.heap().get_string(*href).ok().map(|s| s.to_string())
                }
                EmValue::Null => Some(String::new()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let result = parts.join(&separator);
    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Format` static method.
///
/// # Handled Overloads
///
/// - `String.Format(String, Object) -> String`
/// - `String.Format(String, Object, Object) -> String`
/// - `String.Format(String, Object, Object, Object) -> String`
/// - `String.Format(String, Object[]) -> String`
///
/// # Parameters
///
/// - `format`: Composite format string with placeholders like `{0}`, `{1}`
/// - `args`: Objects to format into the placeholders
///
/// # Returns
///
/// A formatted string with placeholders replaced by argument values
fn string_format_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(first_arg) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let format_str = match first_arg {
        EmValue::ObjectRef(href) => match thread.heap().get_string(*href) {
            Ok(s) => s.to_string(),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let mut result = format_str;
    for (i, arg) in ctx.args.iter().skip(1).enumerate() {
        let placeholder = format!("{{{i}}}");
        let value_str = match arg {
            EmValue::ObjectRef(href) => thread
                .heap()
                .get_string(*href)
                .map_or_else(|_| "[object]".to_string(), |s| s.to_string()),
            EmValue::Null => String::new(),
            EmValue::I32(v) => v.to_string(),
            EmValue::I64(v) => v.to_string(),
            EmValue::F32(v) => v.to_string(),
            EmValue::F64(v) => v.to_string(),
            EmValue::Bool(v) => if *v { "True" } else { "False" }.to_string(),
            EmValue::Char(c) => c.to_string(),
            _ => "[value]".to_string(),
        };
        result = result.replace(&placeholder, &value_str);
    }

    match thread.heap_mut().alloc_string(&result) {
        Ok(href) => PreHookResult::Bypass(Some(EmValue::ObjectRef(href))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.String.Intern` static method.
///
/// # Handled Overloads
///
/// - `String.Intern(String) -> String`
///
/// # Parameters
///
/// - `str`: The string to intern
///
/// # Returns
///
/// The interned string (in our emulation, we just return the same string)
///
/// # Notes
///
/// In the CLR, interning ensures that all strings with the same content share
/// the same reference. For emulation purposes, we simply pass through the string.
fn string_intern_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Simply return the input string - we don't need actual interning for emulation
    if let Some(s) = ctx.args.first() {
        PreHookResult::Bypass(Some(s.clone()))
    } else {
        PreHookResult::Bypass(Some(EmValue::Null))
    }
}

/// Hook for `System.String.IsInterned` static method.
///
/// # Handled Overloads
///
/// - `String.IsInterned(String) -> String`
///
/// # Parameters
///
/// - `str`: The string to check
///
/// # Returns
///
/// The interned string if found, or null if not interned.
/// For emulation, we assume all strings are interned.
fn string_is_interned_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Return the input string (assume all strings are interned)
    if let Some(s) = ctx.args.first() {
        PreHookResult::Bypass(Some(s.clone()))
    } else {
        PreHookResult::Bypass(Some(EmValue::Null))
    }
}

/// Hook for `String.op_Equality(String, String) -> Boolean`.
///
/// Compares two string values for equality. Handles null cases:
/// both null = true, one null = false.
fn string_op_equality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let equal = string_values_equal(ctx, thread);
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for `String.op_Inequality(String, String) -> Boolean`.
///
/// Inverse of `op_Equality`.
fn string_op_inequality_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let equal = string_values_equal(ctx, thread);
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(!equal))))
}

/// Shared helper for `String.op_Equality` / `String.op_Inequality`.
///
/// Returns `true` if both string args are equal (including both-null case).
fn string_values_equal(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> bool {
    let lhs = ctx.args.first().unwrap_or(&EmValue::Null);
    let rhs = ctx.args.get(1).unwrap_or(&EmValue::Null);

    match (lhs, rhs) {
        (EmValue::Null, EmValue::Null) => true,
        (EmValue::Null, _) | (_, EmValue::Null) => false,
        (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => {
            if a.id() == b.id() {
                return true;
            }
            match (
                thread.heap().get_string_opt(*a),
                thread.heap().get_string_opt(*b),
            ) {
                (Some(sa), Some(sb)) => *sa == *sb,
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 23);
    }

    #[test]
    fn test_string_concat_hook() {
        let mut thread = create_test_thread();
        let s1 = thread.heap_mut().alloc_string("Hello ").unwrap();
        let s2 = thread.heap_mut().alloc_string("World").unwrap();

        let args = [EmValue::ObjectRef(s1), EmValue::ObjectRef(s2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Concat",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = string_concat_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_length_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();

        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = string_get_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_string_to_upper_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("hello").unwrap();

        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "ToUpper",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = string_to_upper_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "HELLO");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_to_lower_hook() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("HELLO").unwrap();
        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "ToLower",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = string_to_lower_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "hello");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_substring_one_arg() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(6)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Substring",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_substring_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_substring_two_args() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(0), EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Substring",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_substring_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_get_chars() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("ABC").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(1)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "get_Chars",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_get_chars_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Char('B')))
        ));
    }

    #[test]
    fn test_string_get_chars_oob() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("AB").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "get_Chars",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        // The runtime throws for an index past the end; '\0' answered a character the string
        // does not have
        let result = string_get_chars_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Throw { exception_type, .. }
                if exception_type == synthetic_exception::INDEX_OUT_OF_RANGE
        ));
    }

    #[test]
    fn test_string_to_char_array() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("AB").unwrap();
        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "ToCharArray",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = string_to_char_array_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            assert_eq!(
                thread.heap().get_array_element(arr, 0).unwrap(),
                EmValue::Char('A')
            );
            assert_eq!(
                thread.heap().get_array_element(arr, 1).unwrap(),
                EmValue::Char('B')
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_trim() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("  hello  ").unwrap();
        let this = EmValue::ObjectRef(s);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Trim",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = string_trim_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "hello");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_replace_string() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let old = thread.heap_mut().alloc_string("World").unwrap();
        let new = thread.heap_mut().alloc_string("Rust").unwrap();
        let args = [EmValue::ObjectRef(old), EmValue::ObjectRef(new)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Replace",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_replace_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello Rust");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_replace_char() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("a.b.c").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::Char('.'), EmValue::Char('_')];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Replace",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_replace_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "a_b_c");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_split_by_char() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("a,b,c").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::Char(',')];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Split",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_split_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(arr))) = result {
            let len = thread.heap().get_array_length(arr).unwrap_or(0);
            assert_eq!(len, 3);
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_contains_true() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let sub = thread.heap_mut().alloc_string("World").unwrap();
        let args = [EmValue::ObjectRef(sub)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Contains",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_contains_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));
    }

    #[test]
    fn test_string_contains_false() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let this = EmValue::ObjectRef(s);
        let sub = thread.heap_mut().alloc_string("xyz").unwrap();
        let args = [EmValue::ObjectRef(sub)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Contains",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_contains_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(false)))
        ));
    }

    #[test]
    fn test_string_starts_with() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let prefix = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(prefix)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "StartsWith",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_starts_with_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));
    }

    #[test]
    fn test_string_ends_with() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let suffix = thread.heap_mut().alloc_string("World").unwrap();
        let args = [EmValue::ObjectRef(suffix)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "EndsWith",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_ends_with_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));
    }

    #[test]
    fn test_string_index_of_found() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::Char('W')];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IndexOf",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_index_of_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(6)))
        ));
    }

    #[test]
    fn test_string_index_of_not_found() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::Char('Z')];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IndexOf",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_index_of_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_string_pad_left() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("42").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(5), EmValue::Char('0')];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "PadLeft",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_pad_left_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "00042");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_pad_right() {
        let mut thread = create_test_thread();
        let s = thread.heap_mut().alloc_string("hi").unwrap();
        let this = EmValue::ObjectRef(s);
        let args = [EmValue::I32(5)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "PadRight",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = string_pad_right_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "hi   ");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_join() {
        let mut thread = create_test_thread();
        let sep = thread.heap_mut().alloc_string(", ").unwrap();
        let s1 = thread.heap_mut().alloc_string("a").unwrap();
        let s2 = thread.heap_mut().alloc_string("b").unwrap();
        let s3 = thread.heap_mut().alloc_string("c").unwrap();
        let arr = thread
            .heap_mut()
            .alloc_array_with_values(
                CilFlavor::String,
                vec![
                    EmValue::ObjectRef(s1),
                    EmValue::ObjectRef(s2),
                    EmValue::ObjectRef(s3),
                ],
            )
            .unwrap();
        let args = [EmValue::ObjectRef(sep), EmValue::ObjectRef(arr)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Join",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_join_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "a, b, c");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_format_basic() {
        let mut thread = create_test_thread();
        let fmt = thread.heap_mut().alloc_string("Hello {0}!").unwrap();
        let name = thread.heap_mut().alloc_string("World").unwrap();
        let args = [EmValue::ObjectRef(fmt), EmValue::ObjectRef(name)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "Format",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_format_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello World!");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_string_is_null_or_empty_hook() {
        let mut thread = create_test_thread();
        let empty = thread.heap_mut().alloc_string("").unwrap();
        let non_empty = thread.heap_mut().alloc_string("test").unwrap();

        // Test null
        let args = [EmValue::Null];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));

        // Test empty
        let args = [EmValue::ObjectRef(empty)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));

        // Test non-empty
        let args = [EmValue::ObjectRef(non_empty)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "String",
            "IsNullOrEmpty",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = string_is_null_or_empty_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(false)))
        ));
    }

    /// Runs the `String` hook `hook` on `text` (or a null receiver) with `args`.
    fn on_string(
        hook: fn(&HookContext<'_>, &mut EmulationThread) -> PreHookResult,
        text: Option<&str>,
        args: &[EmValue],
    ) -> (PreHookResult, EmulationThread) {
        let mut thread = create_test_thread();
        let this = match text {
            Some(text) => EmValue::ObjectRef(thread.heap_mut().alloc_string(text).unwrap()),
            None => EmValue::Null,
        };
        let ctx = HookContext::new(
            Token::new(0x0A00_0001),
            "System",
            "String",
            "method",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(args);
        let result = hook(&ctx, &mut thread);
        (result, thread)
    }

    /// The string a hook returned.
    fn returned_string(result: &PreHookResult, thread: &EmulationThread) -> String {
        match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(href))) => {
                thread.heap().get_string(*href).unwrap().to_string()
            }
            other => panic!("expected a string: {other:?}"),
        }
    }

    /// Whether a hook threw `exception`.
    fn threw(result: &PreHookResult, exception: Token) -> bool {
        matches!(result, PreHookResult::Throw { exception_type, .. } if *exception_type == exception)
    }

    /// .NET counts and indexes a string in UTF-16 code units: a character outside the Basic
    /// Multilingual Plane is two of them. Counting the text's `char`s gave "é😀x" 3, not 4,
    /// and shifted every index after the emoji.
    #[test]
    fn length_and_chars_count_utf16_code_units() {
        let (length, _) = on_string(string_get_length_pre, Some("é😀x"), &[]);
        assert!(matches!(
            length,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));

        let (high, _) = on_string(string_get_chars_pre, Some("é😀x"), &[EmValue::I32(1)]);
        assert!(matches!(
            high,
            PreHookResult::Bypass(Some(EmValue::I32(0xD83D)))
        ));
        let (x, _) = on_string(string_get_chars_pre, Some("é😀x"), &[EmValue::I32(3)]);
        assert!(matches!(x, PreHookResult::Bypass(Some(EmValue::Char('x')))));
        let (negative, _) = on_string(string_get_chars_pre, Some("ab"), &[EmValue::I32(-1)]);
        assert!(threw(&negative, synthetic_exception::INDEX_OUT_OF_RANGE));
    }

    /// A null string throws `NullReferenceException`; it answered a length of 0.
    #[test]
    fn a_null_string_throws() {
        let (length, _) = on_string(string_get_length_pre, None, &[]);
        assert!(threw(&length, synthetic_exception::NULL_REFERENCE));
        let (index, _) = on_string(string_index_of_pre, None, &[EmValue::Char('a')]);
        assert!(threw(&index, synthetic_exception::NULL_REFERENCE));
    }

    /// `Substring` takes UTF-16 indices and throws for a range outside the string; it clamped
    /// the range and counted `char`s.
    #[test]
    fn substring_takes_utf16_indices() {
        let (after, thread) = on_string(string_substring_pre, Some("é😀xy"), &[EmValue::I32(3)]);
        assert_eq!(returned_string(&after, &thread), "xy");
        let (middle, thread) = on_string(
            string_substring_pre,
            Some("é😀xy"),
            &[EmValue::I32(1), EmValue::I32(3)],
        );
        assert_eq!(returned_string(&middle, &thread), "😀x");

        let (past, _) = on_string(string_substring_pre, Some("abc"), &[EmValue::I32(4)]);
        assert!(threw(&past, synthetic_exception::ARGUMENT_OUT_OF_RANGE));
        let (long, _) = on_string(
            string_substring_pre,
            Some("abc"),
            &[EmValue::I32(1), EmValue::I32(3)],
        );
        assert!(threw(&long, synthetic_exception::ARGUMENT_OUT_OF_RANGE));
    }

    /// `ToCharArray(startIndex, length)` copies that range; it ignored the arguments and
    /// copied the whole string.
    #[test]
    fn to_char_array_copies_the_range() {
        let (result, thread) = on_string(
            string_to_char_array_pre,
            Some("abcd"),
            &[EmValue::I32(1), EmValue::I32(2)],
        );
        let PreHookResult::Bypass(Some(EmValue::ObjectRef(array))) = result else {
            panic!("expected an array: {result:?}");
        };
        assert_eq!(thread.heap().get_array_length(array).unwrap(), 2);
        assert_eq!(
            thread.heap().get_array_element(array, 0).unwrap(),
            EmValue::Char('b')
        );
    }

    /// `IndexOf` answers a UTF-16 index and searches from `startIndex`; it answered the UTF-8
    /// byte offset and ignored the start.
    #[test]
    fn index_of_answers_utf16_indices_from_the_start() {
        // 'x' is byte 6 of "é😀x" in UTF-8 and code unit 3
        let (x, _) = on_string(string_index_of_pre, Some("é😀x"), &[EmValue::Char('x')]);
        assert!(matches!(x, PreHookResult::Bypass(Some(EmValue::I32(3)))));

        let (second, _) = on_string(
            string_index_of_pre,
            Some("abab"),
            &[EmValue::Char('a'), EmValue::I32(1)],
        );
        assert!(matches!(
            second,
            PreHookResult::Bypass(Some(EmValue::I32(2)))
        ));
        let (past, _) = on_string(
            string_index_of_pre,
            Some("ab"),
            &[EmValue::Char('a'), EmValue::I32(3)],
        );
        assert!(threw(&past, synthetic_exception::ARGUMENT_OUT_OF_RANGE));
    }
}

//! `System.Text.StringBuilder` method hooks.
//!
//! This module provides hook implementations for `StringBuilder` operations
//! commonly used by obfuscators for string building, decryption routines,
//! and control flow state.
//!
//! # Emulated Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `.ctor()` | Create empty StringBuilder |
//! | `.ctor(int)` | Create with capacity |
//! | `.ctor(string)` | Create from initial string |
//! | `.ctor(string, int)` | Create from string with capacity |
//! | `Append(...)` | Append string/char/int/etc. |
//! | `AppendLine(...)` | Append with newline |
//! | `Insert(int, ...)` | Insert at index |
//! | `Remove(int, int)` | Remove range |
//! | `Replace(...)` | Replace occurrences |
//! | `Clear()` | Clear buffer |
//! | `ToString()` | Get result string |
//! | `ToString(int, int)` | Get substring |
//! | `get_Length` | Get character count |
//! | `set_Length` | Truncate or pad |
//! | `get_Chars(int)` | Get character at index |
//! | `set_Chars(int, char)` | Set character at index |
//! | `get_Capacity` / `set_Capacity` | Capacity management (informational) |

use crate::{
    emulation::{
        memory::HeapObject,
        runtime::{
            bcl::limits::{checked_len, MAX_HOOK_STRING_CHARS},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all StringBuilder method hooks with the given hook manager.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Text.StringBuilder..ctor")
            .match_name("System.Text", "StringBuilder", ".ctor")
            .pre(stringbuilder_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.Append")
            .match_name("System.Text", "StringBuilder", "Append")
            .pre(stringbuilder_append_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.AppendLine")
            .match_name("System.Text", "StringBuilder", "AppendLine")
            .pre(stringbuilder_append_line_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.Insert")
            .match_name("System.Text", "StringBuilder", "Insert")
            .pre(stringbuilder_insert_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.Remove")
            .match_name("System.Text", "StringBuilder", "Remove")
            .pre(stringbuilder_remove_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.Replace")
            .match_name("System.Text", "StringBuilder", "Replace")
            .pre(stringbuilder_replace_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.Clear")
            .match_name("System.Text", "StringBuilder", "Clear")
            .pre(stringbuilder_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.ToString")
            .match_name("System.Text", "StringBuilder", "ToString")
            .pre(stringbuilder_to_string_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.get_Length")
            .match_name("System.Text", "StringBuilder", "get_Length")
            .pre(stringbuilder_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.set_Length")
            .match_name("System.Text", "StringBuilder", "set_Length")
            .pre(stringbuilder_set_length_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.get_Chars")
            .match_name("System.Text", "StringBuilder", "get_Chars")
            .pre(stringbuilder_get_chars_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.set_Chars")
            .match_name("System.Text", "StringBuilder", "set_Chars")
            .pre(stringbuilder_set_chars_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.get_Capacity")
            .match_name("System.Text", "StringBuilder", "get_Capacity")
            .pre(stringbuilder_get_capacity_pre),
    )?;

    manager.register(
        Hook::new("System.Text.StringBuilder.set_Capacity")
            .match_name("System.Text", "StringBuilder", "set_Capacity")
            .pre(stringbuilder_set_capacity_pre),
    )?;

    Ok(())
}

/// Reads the StringBuilder buffer from the heap. Returns (buffer, capacity).
fn read_sb(thread: &EmulationThread, href: crate::emulation::HeapRef) -> Option<(String, usize)> {
    if let Ok(HeapObject::StringBuilder { buffer, capacity }) =
        thread.heap().get_shared(href).as_deref()
    {
        Some((buffer.to_string(), *capacity))
    } else {
        None
    }
}

/// Writes back the modified StringBuilder buffer.
fn write_sb(
    thread: &EmulationThread,
    href: crate::emulation::HeapRef,
    buffer: String,
    capacity: usize,
) -> Result<()> {
    thread
        .heap()
        .replace_object(href, HeapObject::StringBuilder { buffer, capacity })
}

/// Converts an EmValue argument to a string for Append/Insert operations.
fn arg_to_string(value: &EmValue, thread: &EmulationThread) -> String {
    match value {
        EmValue::I32(v) => v.to_string(),
        EmValue::I64(v) => v.to_string(),
        EmValue::F32(v) => v.to_string(),
        EmValue::F64(v) => v.to_string(),
        EmValue::Bool(v) => if *v { "True" } else { "False" }.to_string(),
        EmValue::Char(v) => v.to_string(),
        EmValue::NativeInt(v) => v.to_string(),
        EmValue::NativeUInt(v) => v.to_string(),
        EmValue::ObjectRef(href) => {
            if let Ok(s) = thread.heap().get_string(*href) {
                s.to_string()
            } else {
                String::new()
            }
        }
        EmValue::Null => String::new(),
        _ => String::new(),
    }
}

/// Hook for `StringBuilder..ctor(...)`.
///
/// Dispatches multiple overloads by argument pattern:
/// - `()` — empty buffer
/// - `(int)` — empty with capacity
/// - `(string)` — initial string
/// - `(string, int)` — initial string with capacity
fn stringbuilder_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        let (buffer, capacity) = match ctx.args.len() {
            0 => (String::new(), 16),
            1 => match ctx.args.first() {
                Some(EmValue::I32(cap)) => (String::new(), (*cap).max(0) as usize),
                Some(EmValue::ObjectRef(href)) => {
                    let s = thread
                        .heap()
                        .get_string(*href)
                        .map_or_else(|_| String::new(), |s| s.to_string());
                    let cap = s.len().max(16);
                    (s, cap)
                }
                _ => (String::new(), 16),
            },
            _ => {
                // (string, int) or (int, int) overloads
                let s = if let Some(EmValue::ObjectRef(href)) = ctx.args.first() {
                    thread
                        .heap()
                        .get_string(*href)
                        .map_or_else(|_| String::new(), |s| s.to_string())
                } else {
                    String::new()
                };
                let cap = ctx
                    .args
                    .get(1)
                    .and_then(EmValue::as_i32)
                    .map_or(16, |c| c.max(0) as usize)
                    .max(s.len());
                (s, cap)
            }
        };

        try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
    }
    PreHookResult::Bypass(None)
}

/// Hook for `StringBuilder.Append(...)`.
///
/// Appends the string representation of the argument. Returns `this` for fluent chaining.
fn stringbuilder_append_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((mut buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let Some(arg) = ctx.args.first() {
                buffer.push_str(&arg_to_string(arg, thread));
            }
            try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.AppendLine(...)`.
///
/// Appends optional string argument + `\r\n`. Returns `this` for fluent chaining.
fn stringbuilder_append_line_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((mut buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let Some(arg) = ctx.args.first() {
                buffer.push_str(&arg_to_string(arg, thread));
            }
            buffer.push_str("\r\n");
            try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.Insert(int, ...)`.
///
/// Inserts the string representation at the given character index. Returns `this`.
fn stringbuilder_insert_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((mut buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let (Some(EmValue::I32(index)), Some(arg)) = (ctx.args.first(), ctx.args.get(1)) {
                let s = arg_to_string(arg, thread);
                let idx = (*index).max(0) as usize;
                // Find byte position from char index
                if let Some(byte_pos) = buffer.char_indices().nth(idx).map(|(p, _)| p) {
                    buffer.insert_str(byte_pos, &s);
                } else {
                    // Index beyond end: append
                    buffer.push_str(&s);
                }
            }
            try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.Remove(int startIndex, int length)`.
///
/// Removes characters from the buffer. Returns `this`.
fn stringbuilder_remove_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((mut buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let (Some(EmValue::I32(start)), Some(EmValue::I32(length))) =
                (ctx.args.first(), ctx.args.get(1))
            {
                let start_idx = (*start).max(0) as usize;
                let len = (*length).max(0) as usize;
                // Find byte positions from char indices
                let byte_start = buffer
                    .char_indices()
                    .nth(start_idx)
                    .map_or(buffer.len(), |(p, _)| p);
                let byte_end = buffer
                    .char_indices()
                    .nth(start_idx.saturating_add(len))
                    .map_or(buffer.len(), |(p, _)| p);
                buffer.drain(byte_start..byte_end);
            }
            try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.Replace(...)`.
///
/// Supports `Replace(string, string)` and `Replace(char, char)`. Returns `this`.
fn stringbuilder_replace_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((mut buffer, capacity)) = read_sb(thread, *sb_ref) {
            match (ctx.args.first(), ctx.args.get(1)) {
                (Some(EmValue::Char(old)), Some(EmValue::Char(new))) => {
                    buffer = buffer.replace(*old, &new.to_string());
                }
                (Some(old_arg), Some(new_arg)) => {
                    let old_str = arg_to_string(old_arg, thread);
                    let new_str = arg_to_string(new_arg, thread);
                    if !old_str.is_empty() {
                        buffer = buffer.replace(&old_str, &new_str);
                    }
                }
                _ => {}
            }
            try_hook!(write_sb(thread, *sb_ref, buffer, capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.Clear()`. Returns `this`.
fn stringbuilder_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((_, capacity)) = read_sb(thread, *sb_ref) {
            try_hook!(write_sb(thread, *sb_ref, String::new(), capacity));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(*sb_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.ToString()` and `ToString(int, int)`.
///
/// Allocates a new string from the buffer (or a substring).
fn stringbuilder_to_string_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((buffer, _)) = read_sb(thread, *sb_ref) {
            let result = if let (Some(EmValue::I32(start)), Some(EmValue::I32(length))) =
                (ctx.args.first(), ctx.args.get(1))
            {
                let start_idx = (*start).max(0) as usize;
                let len = (*length).max(0) as usize;
                buffer.chars().skip(start_idx).take(len).collect::<String>()
            } else {
                buffer
            };
            if let Ok(str_ref) = thread.heap().alloc_string(&result) {
                return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref)));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `StringBuilder.get_Length`.
fn stringbuilder_get_length_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((buffer, _)) = read_sb(thread, *sb_ref) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(buffer.chars().count() as i32)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `StringBuilder.set_Length(int)`.
///
/// Truncates the buffer if shorter, pads with null chars if longer.
fn stringbuilder_set_length_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let Some(EmValue::I32(new_len)) = ctx.args.first() {
                // The growth branch pads one character at a time, bounded only by the
                // caller's Int32, so the target width needs a ceiling before it is used.
                let target = match checked_len(
                    *new_len,
                    MAX_HOOK_STRING_CHARS,
                    "StringBuilder.set_Length",
                    "value",
                ) {
                    Ok(n) => n,
                    Err(result) => return result,
                };
                let current = buffer.chars().count();
                let new_buffer = if target <= current {
                    buffer.chars().take(target).collect()
                } else {
                    let pad = target.saturating_sub(current);
                    let mut s = buffer;
                    s.reserve(pad);
                    s.extend(std::iter::repeat_n('\0', pad));
                    s
                };
                try_hook!(write_sb(thread, *sb_ref, new_buffer, capacity));
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `StringBuilder.get_Chars(int)` — indexer getter.
fn stringbuilder_get_chars_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((buffer, _)) = read_sb(thread, *sb_ref) {
            if let Some(EmValue::I32(index)) = ctx.args.first() {
                let idx = (*index).max(0) as usize;
                if let Some(ch) = buffer.chars().nth(idx) {
                    return PreHookResult::Bypass(Some(EmValue::Char(ch)));
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Char('\0')))
}

/// Hook for `StringBuilder.set_Chars(int, char)` — indexer setter.
fn stringbuilder_set_chars_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((buffer, capacity)) = read_sb(thread, *sb_ref) {
            if let (Some(EmValue::I32(index)), Some(EmValue::Char(ch))) =
                (ctx.args.first(), ctx.args.get(1))
            {
                let idx = (*index).max(0) as usize;
                let mut chars: Vec<char> = buffer.chars().collect();
                if let Some(slot) = chars.get_mut(idx) {
                    *slot = *ch;
                    let new_buffer: String = chars.into_iter().collect();
                    try_hook!(write_sb(thread, *sb_ref, new_buffer, capacity));
                }
            }
        }
    }
    PreHookResult::Bypass(None)
}

/// Hook for `StringBuilder.get_Capacity`.
fn stringbuilder_get_capacity_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(sb_ref)) = ctx.this {
        if let Some((_, capacity)) = read_sb(thread, *sb_ref) {
            #[allow(clippy::cast_possible_truncation)]
            return PreHookResult::Bypass(Some(EmValue::I32(capacity as i32)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(16)))
}

/// Hook for `StringBuilder.set_Capacity(int)` — no-op.
fn stringbuilder_set_capacity_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    fn ctx<'a>(method: &'a str, this: Option<&'a EmValue>, args: &'a [EmValue]) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System.Text",
            "StringBuilder",
            method,
            PointerSize::Bit64,
        )
        .with_this(this)
        .with_args(args)
    }

    fn make_sb(
        thread: &mut crate::emulation::thread::EmulationThread,
    ) -> crate::emulation::HeapRef {
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        stringbuilder_ctor_pre(&ctx(".ctor", Some(&this), &[]), thread);
        obj
    }

    fn sb_string(
        thread: &crate::emulation::thread::EmulationThread,
        sb: crate::emulation::HeapRef,
    ) -> String {
        if let Some((buffer, _)) = read_sb(thread, sb) {
            buffer
        } else {
            panic!("Not a StringBuilder");
        }
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        crate::emulation::runtime::bcl::text::stringbuilder::register(&manager).unwrap();
        assert_eq!(manager.len(), 14);
    }

    #[test]
    fn test_sb_ctor_empty() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        assert_eq!(sb_string(&thread, sb), "");
    }

    #[test]
    fn test_sb_ctor_with_capacity() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let args = [EmValue::I32(256)];
        stringbuilder_ctor_pre(&ctx(".ctor", Some(&this), &args), &mut thread);

        let result =
            stringbuilder_get_capacity_pre(&ctx("get_Capacity", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(256)))
        ));
    }

    #[test]
    fn test_sb_ctor_with_string() {
        let mut thread = create_test_thread();
        let obj = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        let this = EmValue::ObjectRef(obj);
        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_ctor_pre(&ctx(".ctor", Some(&this), &args), &mut thread);

        assert_eq!(sb_string(&thread, obj), "Hello");
    }

    #[test]
    fn test_sb_append_string() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(s)];
        let result = stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) if r == sb));
        assert_eq!(sb_string(&thread, sb), "Hello");
    }

    #[test]
    fn test_sb_append_int() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let args = [EmValue::I32(42)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "42");
    }

    #[test]
    fn test_sb_append_char() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let args = [EmValue::Char('X')];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "X");
    }

    #[test]
    fn test_sb_append_returns_this() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("test").unwrap();
        let args = [EmValue::ObjectRef(s)];
        let result = stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) if r == sb));
    }

    #[test]
    fn test_sb_append_line_with_string() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_line_pre(&ctx("AppendLine", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "Hello\r\n");
    }

    #[test]
    fn test_sb_append_line_empty() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        stringbuilder_append_line_pre(&ctx("AppendLine", Some(&this), &[]), &mut thread);
        assert_eq!(sb_string(&thread, sb), "\r\n");
    }

    #[test]
    fn test_sb_insert() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s1 = thread.heap_mut().alloc_string("AC").unwrap();
        let args = [EmValue::ObjectRef(s1)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let s2 = thread.heap_mut().alloc_string("B").unwrap();
        let args = [EmValue::I32(1), EmValue::ObjectRef(s2)];
        stringbuilder_insert_pre(&ctx("Insert", Some(&this), &args), &mut thread);

        assert_eq!(sb_string(&thread, sb), "ABC");
    }

    #[test]
    fn test_sb_remove() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(5), EmValue::I32(6)];
        stringbuilder_remove_pre(&ctx("Remove", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "Hello");
    }

    #[test]
    fn test_sb_replace_string() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let old = thread.heap_mut().alloc_string("World").unwrap();
        let new = thread.heap_mut().alloc_string("Rust").unwrap();
        let args = [EmValue::ObjectRef(old), EmValue::ObjectRef(new)];
        stringbuilder_replace_pre(&ctx("Replace", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "Hello Rust");
    }

    #[test]
    fn test_sb_replace_char() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("a.b.c").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::Char('.'), EmValue::Char('_')];
        stringbuilder_replace_pre(&ctx("Replace", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "a_b_c");
    }

    #[test]
    fn test_sb_clear() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("data").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);
        stringbuilder_clear_pre(&ctx("Clear", Some(&this), &[]), &mut thread);
        assert_eq!(sb_string(&thread, sb), "");
    }

    #[test]
    fn test_sb_to_string() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let result = stringbuilder_to_string_pre(&ctx("ToString", Some(&this), &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "Hello");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_sb_to_string_with_range() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(6), EmValue::I32(5)];
        let result = stringbuilder_to_string_pre(&ctx("ToString", Some(&this), &args), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(&*thread.heap().get_string(r).unwrap(), "World");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_sb_get_length() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let result =
            stringbuilder_get_length_pre(&ctx("get_Length", Some(&this), &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_sb_set_length_truncate() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("Hello World").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(5)];
        stringbuilder_set_length_pre(&ctx("set_Length", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "Hello");
    }

    #[test]
    fn test_sb_get_chars() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("ABC").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1)];
        let result =
            stringbuilder_get_chars_pre(&ctx("get_Chars", Some(&this), &args), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Char('B')))
        ));
    }

    #[test]
    fn test_sb_set_chars() {
        let mut thread = create_test_thread();
        let sb = make_sb(&mut thread);
        let this = EmValue::ObjectRef(sb);

        let s = thread.heap_mut().alloc_string("ABC").unwrap();
        let args = [EmValue::ObjectRef(s)];
        stringbuilder_append_pre(&ctx("Append", Some(&this), &args), &mut thread);

        let args = [EmValue::I32(1), EmValue::Char('X')];
        stringbuilder_set_chars_pre(&ctx("set_Chars", Some(&this), &args), &mut thread);
        assert_eq!(sb_string(&thread, sb), "AXC");
    }
}

//! Character-boundary-safe text helpers.
//!
//! Rust's `str` indexing is by *byte* offset, so the natural-looking `&s[..n]` panics whenever
//! byte `n` lands inside a multi-byte UTF-8 character. Nearly every string this crate handles —
//! user-string literals, type and member names, emulated heap contents — comes from an
//! attacker-controlled assembly, so that panic is reachable input-driven behaviour rather than a
//! programming edge case.
//!
//! This is a blind spot in the crate's lint set: `clippy::indexing_slicing` only fires for types
//! that deref to a slice or array, and neither `str` nor `String` does. `clippy::string_slice` is
//! denied crate-wide to close it; use the helpers here instead of range-indexing text.

/// Truncates `s` to at most `max_chars` characters without splitting a UTF-8 character.
///
/// Returns `s` unchanged when it is already `max_chars` characters or shorter.
///
/// # Arguments
///
/// * `s` - The string to truncate.
/// * `max_chars` - Maximum number of characters to keep.
///
/// # Returns
///
/// A prefix of `s` containing at most `max_chars` characters.
///
/// # Note
///
/// The bound is in characters, not bytes, so the returned slice may be up to four times
/// `max_chars` bytes long. Callers truncating for display or for identifier length want the
/// character count; a caller that must respect a hard byte budget needs a different helper.
///
/// # Examples
///
/// The `examples::truncate_chars_example` test in this module runs this example.
pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => s.split_at(byte_idx).0,
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorter_than_limit_is_unchanged() {
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(truncate_chars("", 5), "");
    }

    #[test]
    fn exact_length_is_unchanged() {
        assert_eq!(truncate_chars("abc", 3), "abc");
    }

    #[test]
    fn ascii_truncates_at_limit() {
        assert_eq!(truncate_chars("abcdef", 3), "abc");
        assert_eq!(truncate_chars("abc", 0), "");
    }

    /// The case that panics with `&s[..n]`: the limit falls inside a multi-byte character.
    #[test]
    fn multibyte_never_splits_a_character() {
        // Each of these is 3 bytes, so byte offset 2 is mid-character.
        assert_eq!(truncate_chars("日本語", 2), "日本");
        assert_eq!(truncate_chars("日本語", 1), "日");
        assert_eq!(truncate_chars("日本語", 3), "日本語");
        assert_eq!(truncate_chars("日本語", 99), "日本語");
    }

    /// Four-byte characters (astral plane) are the widest case.
    #[test]
    fn handles_four_byte_characters() {
        let s = "𝄞𝄞𝄞";
        assert_eq!(s.len(), 12);
        assert_eq!(truncate_chars(s, 1), "𝄞");
        assert_eq!(truncate_chars(s, 2).chars().count(), 2);
    }

    /// A mixed string where the boundary lands differently than the byte count suggests.
    #[test]
    fn mixed_width_input() {
        let s = "ab日cd";
        assert_eq!(s.len(), 7);
        assert_eq!(truncate_chars(s, 3), "ab日");
        assert_eq!(truncate_chars(s, 4), "ab日c");
    }

    /// Every prefix length must be valid UTF-8 and round-trip through `chars()`.
    #[test]
    fn all_prefixes_are_valid_for_adversarial_input() {
        let s = "a日b𝄞c\u{0301}d";
        for n in 0..=s.chars().count().saturating_add(3) {
            let got = truncate_chars(s, n);
            assert!(
                s.starts_with(got),
                "prefix {n} is not a prefix of the input"
            );
            assert!(got.chars().count() <= n);
        }
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn truncate_chars_example() -> Result<()> {
        assert_eq!(truncate_chars("hello", 3), "hel");
        assert_eq!(truncate_chars("hello", 10), "hello");
        // A byte-offset slice would panic here; this splits between characters.
        assert_eq!(truncate_chars("日本語", 2), "日本");
        Ok(())
    }
}

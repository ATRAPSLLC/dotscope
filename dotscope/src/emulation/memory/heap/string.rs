//! A .NET string on the managed heap: its text, and the UTF-16 code units .NET counts and
//! indexes.
//!
//! The emulator keeps a string's text as UTF-8 (`Arc<str>`), which every hook reads. .NET,
//! though, measures and indexes a string in UTF-16 code units: `String.Length` counts them,
//! `String.Chars[i]` returns the `i`-th, and a character outside the Basic Multilingual Plane
//! is two of them (a surrogate pair). Counting the text's `char`s instead took O(n) per call,
//! which made a decryption loop over `s[i]` for `i < s.Length` quadratic, and miscounted every
//! string with such a character.
//!
//! [`ManagedString`] answers both in O(1): an ASCII string's code units are its bytes, and the
//! code units of any other string are computed when it is made, shared by every copy of it.
//! (Computing them on first use would compute them again in every copy a hook reads.)

use std::{borrow::Cow, fmt, sync::Arc};

/// A .NET string: its text and, for a string that is not ASCII, its UTF-16 code units.
#[derive(Clone)]
pub struct ManagedString {
    /// The string's text.
    text: Arc<str>,
    /// The UTF-16 code units of a text that is not ASCII; `None` for ASCII, whose bytes are
    /// its code units.
    units: Option<Arc<[u16]>>,
}

impl ManagedString {
    /// Creates a string holding `text`.
    #[must_use]
    pub fn new(text: Arc<str>) -> Self {
        let units = (!text.is_ascii()).then(|| text.encode_utf16().collect::<Vec<_>>().into());
        Self { text, units }
    }

    /// The string's text.
    #[must_use]
    pub fn text(&self) -> &Arc<str> {
        &self.text
    }

    /// The number of UTF-16 code units in the string: .NET's `String.Length`.
    #[must_use]
    pub fn utf16_len(&self) -> usize {
        match &self.units {
            None => self.text.len(),
            Some(units) => units.len(),
        }
    }

    /// The string's UTF-16 code units, the sequence .NET indexes: borrowed for a string that is
    /// not ASCII, and widened from the bytes of one that is.
    #[must_use]
    pub fn utf16_units(&self) -> Cow<'_, [u16]> {
        match &self.units {
            None => Cow::Owned(self.text.bytes().map(u16::from).collect()),
            Some(units) => Cow::Borrowed(units),
        }
    }

    /// The UTF-16 code unit at `index`: .NET's `String.Chars[index]`, or `None` past the end.
    #[must_use]
    pub fn unit_at(&self, index: usize) -> Option<u16> {
        match &self.units {
            None => self.text.as_bytes().get(index).map(|&byte| u16::from(byte)),
            Some(units) => units.get(index).copied(),
        }
    }
}

impl fmt::Debug for ManagedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.text, f)
    }
}

impl From<Arc<str>> for ManagedString {
    fn from(text: Arc<str>) -> Self {
        Self::new(text)
    }
}

impl From<&str> for ManagedString {
    fn from(text: &str) -> Self {
        Self::new(Arc::from(text))
    }
}

impl From<String> for ManagedString {
    fn from(text: String) -> Self {
        Self::new(Arc::from(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ASCII string's code units are its bytes.
    #[test]
    fn an_ascii_string_counts_its_bytes() {
        let string = ManagedString::from("abc");
        assert_eq!(string.utf16_len(), 3);
        assert_eq!(string.unit_at(1), Some(u16::from(b'b')));
        assert_eq!(string.unit_at(3), None);
    }

    /// A character outside the Basic Multilingual Plane is two code units (a surrogate pair),
    /// and one in it, however many UTF-8 bytes it takes, is one.
    #[test]
    fn a_string_counts_utf16_code_units() {
        // 'é' is two UTF-8 bytes and one code unit; '😀' (U+1F600) is four bytes and two units
        let string = ManagedString::from("é😀x");
        assert_eq!(string.utf16_len(), 4);
        assert_eq!(string.unit_at(0), Some(0x00E9));
        assert_eq!(string.unit_at(1), Some(0xD83D));
        assert_eq!(string.unit_at(2), Some(0xDE00));
        assert_eq!(string.unit_at(3), Some(u16::from(b'x')));
        assert_eq!(string.unit_at(4), None);
        assert_eq!(
            &*string.utf16_units(),
            &[0x00E9, 0xD83D, 0xDE00, u16::from(b'x')]
        );
        assert_eq!(&*ManagedString::from("ab").utf16_units(), &[0x61, 0x62]);
    }
}

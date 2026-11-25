//! A hash of text that extends: the hash of a concatenation follows from the hashes of its
//! parts, and the hash of any suffix of a hashed run follows in constant time.
//!
//! Type names are joined from parts that many rows share (`Namespace.Name`, `Outer/Inner`),
//! and hashing every joined name byte by byte made indexing them cost rows times length. A
//! [`TextHash`] is two polynomial hashes modulo the Mersenne prime 2^61 - 1, with bases drawn
//! at random once per process, and the length: joining two names hashes in `O(log n)`, and a
//! [`crate::metadata::streams::SharedStr`] hashes in `O(1)` once its run is hashed.
//!
//! Two different texts of length at most `n` share a [`TextHash`] with probability at most
//! `(n / 2^61)^2` whatever the texts, since the bases are unknown to whoever wrote them: the
//! hash serves as the identity of a full name, and no text is compared to find one.

use std::{
    hash::{BuildHasher, Hasher},
    sync::OnceLock,
};

/// The modulus, the Mersenne prime 2^61 - 1.
const MODULUS: u64 = (1 << 61) - 1;

/// The hash of a text: two polynomial hashes and the length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TextHash {
    /// The text under the first base
    first: u64,
    /// The text under the second base
    second: u64,
    /// The text's length in bytes
    len: u64,
}

/// The two bases, drawn at random on first use.
fn bases() -> (u64, u64) {
    static BASES: OnceLock<(u64, u64)> = OnceLock::new();
    *BASES.get_or_init(|| {
        let draw = |salt: u64| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u64(salt);
            // A base in [256, MODULUS - 1]: past every byte value, so no byte is a root
            hasher
                .finish()
                .wrapping_rem(MODULUS - 257)
                .wrapping_add(256)
        };
        (draw(1), draw(2))
    })
}

/// `a * b` modulo 2^61 - 1.
fn mul(a: u64, b: u64) -> u64 {
    let product = u128::from(a).wrapping_mul(u128::from(b));
    let low = u64::try_from(product & u128::from(MODULUS)).unwrap_or(0);
    let high = u64::try_from(product >> 61).unwrap_or(0);
    reduce(low.wrapping_add(high))
}

/// `a + b` modulo 2^61 - 1, for `a` and `b` below it.
fn add(a: u64, b: u64) -> u64 {
    reduce(a.wrapping_add(b))
}

/// `a - b` modulo 2^61 - 1, for `a` and `b` below it.
fn sub(a: u64, b: u64) -> u64 {
    reduce(a.wrapping_add(MODULUS).wrapping_sub(b))
}

/// `value` modulo 2^61 - 1, for `value` below twice the modulus.
fn reduce(value: u64) -> u64 {
    if value >= MODULUS {
        value.wrapping_sub(MODULUS)
    } else {
        value
    }
}

/// `base` to the power `exponent`, modulo 2^61 - 1.
fn pow(base: u64, mut exponent: u64) -> u64 {
    let mut result = 1;
    let mut square = base;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul(result, square);
        }
        square = mul(square, square);
        exponent >>= 1;
    }
    result
}

impl TextHash {
    /// The hash of the empty text.
    pub const EMPTY: TextHash = TextHash {
        first: 0,
        second: 0,
        len: 0,
    };

    /// The hash of `bytes`, in `O(bytes.len())`.
    pub fn of(bytes: &[u8]) -> Self {
        let (first_base, second_base) = bases();
        let mut hash = Self::EMPTY;
        for &byte in bytes {
            hash.first = add(mul(hash.first, first_base), u64::from(byte));
            hash.second = add(mul(hash.second, second_base), u64::from(byte));
        }
        hash.len = bytes.len() as u64;
        hash
    }

    /// The hash of this text followed by `next`, in `O(log next.len)`.
    #[must_use]
    pub fn then(self, next: TextHash) -> Self {
        let (first_base, second_base) = bases();
        TextHash {
            first: add(mul(self.first, pow(first_base, next.len)), next.first),
            second: add(mul(self.second, pow(second_base, next.len)), next.second),
            len: self.len.saturating_add(next.len),
        }
    }

    /// The text's length in bytes.
    pub fn len(self) -> u64 {
        self.len
    }

    /// Whether the text is empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// The prefix hashes of a run, from which the hash of any suffix follows.
pub struct PrefixHashes {
    /// The hash of the first `i` bytes, for every `i` from 0 to the run's length
    prefixes: Vec<(u64, u64)>,
}

impl PrefixHashes {
    /// The prefix hashes of `bytes`, in `O(bytes.len())`.
    pub fn of(bytes: &[u8]) -> Self {
        let (first_base, second_base) = bases();
        let mut prefixes = Vec::with_capacity(bytes.len().saturating_add(1));
        let (mut first, mut second) = (0, 0);
        prefixes.push((first, second));
        for &byte in bytes {
            first = add(mul(first, first_base), u64::from(byte));
            second = add(mul(second, second_base), u64::from(byte));
            prefixes.push((first, second));
        }
        Self { prefixes }
    }

    /// The hash of the bytes from `start` to the run's end, in `O(log len)`.
    ///
    /// # Returns
    /// `None` when `start` is past the run's end.
    pub fn suffix(&self, start: usize) -> Option<TextHash> {
        let (first_base, second_base) = bases();
        let &(end_first, end_second) = self.prefixes.last()?;
        let &(start_first, start_second) = self.prefixes.get(start)?;
        let len = self.prefixes.len().checked_sub(1)?.checked_sub(start)? as u64;
        Some(TextHash {
            first: sub(end_first, mul(start_first, pow(first_base, len))),
            second: sub(end_second, mul(start_second, pow(second_base, len))),
            len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_concatenation_hashes_as_its_text() {
        let whole = TextHash::of(b"System.Collections.Generic/List`1");
        let joined = TextHash::of(b"System.Collections.Generic")
            .then(TextHash::of(b"/"))
            .then(TextHash::of(b"List`1"));
        assert_eq!(whole, joined);
        assert_eq!(TextHash::EMPTY.then(whole), whole);
        assert_eq!(whole.then(TextHash::EMPTY), whole);
        assert_ne!(TextHash::of(b"ab"), TextHash::of(b"ba"));
        assert_ne!(TextHash::of(b"a"), TextHash::of(b"a\0"));
    }

    #[test]
    fn every_suffix_hashes_as_its_text() {
        let text = b"Namespace.Type\xff\x00tail";
        let prefixes = PrefixHashes::of(text);
        for start in 0..=text.len() {
            assert_eq!(
                prefixes.suffix(start),
                Some(TextHash::of(&text[start..])),
                "{start}"
            );
        }
        assert_eq!(prefixes.suffix(text.len() + 1), None);
    }

    #[test]
    fn arithmetic_stays_below_the_modulus() {
        let big = MODULUS - 1;
        assert_eq!(mul(big, big), 1, "(-1) * (-1)");
        assert_eq!(add(big, 1), 0);
        assert_eq!(sub(0, 1), big);
        assert_eq!(pow(3, 0), 1);
        assert_eq!(pow(2, 61), 1, "2^61 is 1 modulo 2^61 - 1");
    }
}

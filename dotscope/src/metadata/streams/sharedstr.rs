//! A string shared by every metadata row that names the same `#Strings` entry.
//!
//! Metadata rows refer to their names by `#Strings` offset, and any number of rows may name
//! one entry: a hostile image can point a million rows at one string of a megabyte. Copying
//! the string into each row made that cost rows times length in memory, and reading it once
//! per row cost as much in time. [`SharedStr`] holds one copy of a NUL-terminated run of the
//! heap, shared through an [`Arc`](std::sync::Arc), and the offset within it where this name starts, so a row
//! costs the same whatever the name's length (see [`crate::metadata::streams::Strings::get_shared`]).
//!
//! A `SharedStr` reads as the `str` it holds: it dereferences to `str`, compares with `str`,
//! `&str` and `String` either way round, hashes and orders as its text, and converts into a
//! `String`.

use std::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc,
};

use crate::metadata::texthash::{PrefixHashes, TextHash};

/// An immutable string sharing its storage with every other `SharedStr` of the same
/// `#Strings` run.
///
/// Cloning is a reference count increment. Text built outside a heap (a synthetic name, a
/// rename) converts with [`From`], holding a run of its own.
///
/// # Examples
///
/// ```
/// use dotscope::metadata::streams::SharedStr;
///
/// let name = SharedStr::from("Program");
/// assert_eq!(name, "Program");
/// assert_eq!(name.len(), 7);
/// assert!(name.starts_with("Pro"));
/// let owned: String = name.clone().into();
/// assert_eq!(owned, "Program");
/// ```
#[derive(Clone)]
pub struct SharedStr {
    /// The run of the heap this string is a suffix of
    run: Arc<Run>,
    /// The byte offset in the run where this string starts; always a char boundary
    start: u32,
}

/// The longest run whose strings are hashed byte by byte rather than from prefix hashes.
///
/// A prefix table costs 16 bytes per byte of its run, while hashing a short name directly
/// costs no more than a table lookup: the tables are kept for the long runs, where hashing
/// each string directly would cost rows times length.
const HASHED_DIRECTLY: usize = 64;

/// A run of text every [`SharedStr`] inside it shares, with what makes its strings' hashes
/// and last `/` constant-time, computed once when the run is made. A run never changes, so a
/// `SharedStr` is a plain value: it hashes and compares by its text alone.
pub struct Run {
    /// The text
    text: Box<str>,
    /// The hashes of the text's prefixes, for a run longer than [`HASHED_DIRECTLY`], from
    /// which every string of the run hashes in constant time
    hashes: Option<PrefixHashes>,
    /// The offset of the text's last `/`
    last_slash: Option<usize>,
}

impl Run {
    /// A run of `text`.
    pub fn new(text: impl Into<Box<str>>) -> Arc<Self> {
        let text: Box<str> = text.into();
        let hashes = (text.len() > HASHED_DIRECTLY).then(|| PrefixHashes::of(text.as_bytes()));
        let last_slash = text.rfind('/');
        Arc::new(Self {
            text,
            hashes,
            last_slash,
        })
    }
}

impl SharedStr {
    /// A string that is the suffix of `run` starting at byte `start`.
    ///
    /// # Returns
    /// `None` when `start` is past the end of `run` or not on a char boundary.
    pub fn suffix(run: Arc<Run>, start: usize) -> Option<Self> {
        if !run.text.is_char_boundary(start) {
            return None;
        }
        let start = u32::try_from(start).ok()?;
        Some(Self { run, start })
    }

    /// The [`TextHash`] of the last `len` bytes of the text, as [`Self::text_hash`] computes
    /// it.
    ///
    /// # Returns
    /// `None` when the text is shorter than `len`.
    pub fn suffix_hash(&self, len: usize) -> Option<TextHash> {
        let start = usize::try_from(self.start).ok()?;
        let run_len = self.run.text.len();
        let from = run_len.checked_sub(len)?;
        if from < start {
            return None;
        }
        match &self.run.hashes {
            Some(hashes) => hashes.suffix(from),
            None => self.run.text.as_bytes().get(from..).map(TextHash::of),
        }
    }

    /// The part of the text after its last `/`, `None` when it has none. The run's last `/`
    /// was found when the run was made, so this costs the same whatever the text's length.
    pub fn after_last_slash(&self) -> Option<SharedStr> {
        let start = usize::try_from(self.start).ok()?;
        let slash = self.run.last_slash?;
        if slash < start {
            return None;
        }
        Self::suffix(Arc::clone(&self.run), slash.checked_add(1)?)
    }

    /// The [`TextHash`] of the text: constant time from a long run's prefix hashes, and at
    /// most 64 bytes (`HASHED_DIRECTLY`) of hashing for a short run.
    pub fn text_hash(&self) -> TextHash {
        usize::try_from(self.start)
            .ok()
            .and_then(|start| self.run.hashes.as_ref()?.suffix(start))
            .unwrap_or_else(|| TextHash::of(self.as_str().as_bytes()))
    }

    /// The text, as a `str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        usize::try_from(self.start)
            .ok()
            .and_then(|start| self.run.text.get(start..))
            .unwrap_or_default()
    }
}

impl Default for SharedStr {
    fn default() -> Self {
        Self {
            run: Run::new(""),
            start: 0,
        }
    }
}

impl Deref for SharedStr {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for SharedStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SharedStr {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SharedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Debug for SharedStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for SharedStr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SharedStr {}

impl PartialOrd for SharedStr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SharedStr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for SharedStr {
    /// Hashes as the `str` it holds, which [`Borrow<str>`] requires: a map keyed by
    /// `SharedStr` is looked up with a `&str`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl PartialEq<str> for SharedStr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for SharedStr {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for SharedStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<SharedStr> for str {
    fn eq(&self, other: &SharedStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<SharedStr> for &str {
    fn eq(&self, other: &SharedStr) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<SharedStr> for String {
    fn eq(&self, other: &SharedStr) -> bool {
        self.as_str() == other.as_str()
    }
}

impl From<&str> for SharedStr {
    fn from(text: &str) -> Self {
        Self {
            run: Run::new(text),
            start: 0,
        }
    }
}

impl From<String> for SharedStr {
    fn from(text: String) -> Self {
        Self {
            run: Run::new(text),
            start: 0,
        }
    }
}

impl From<&String> for SharedStr {
    fn from(text: &String) -> Self {
        Self::from(text.as_str())
    }
}

impl From<Arc<str>> for SharedStr {
    fn from(text: Arc<str>) -> Self {
        Self {
            run: Run::new(&*text),
            start: 0,
        }
    }
}

impl From<SharedStr> for String {
    fn from(text: SharedStr) -> Self {
        text.as_str().to_string()
    }
}

impl From<&SharedStr> for String {
    fn from(text: &SharedStr) -> Self {
        text.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn a_suffix_reads_from_its_start_and_shares_the_run() {
        let run = Run::new("Namespace.Type");
        let whole = SharedStr::suffix(Arc::clone(&run), 0).unwrap();
        let tail = SharedStr::suffix(Arc::clone(&run), 10).unwrap();
        assert_eq!(whole, "Namespace.Type");
        assert_eq!(tail, "Type");
        assert_eq!(&*tail, "Type");
        assert_eq!(Arc::strong_count(&run), 3, "both share the one run");
        assert!(SharedStr::suffix(Arc::clone(&run), 14).unwrap().is_empty());
        assert!(SharedStr::suffix(run, 15).is_none());
    }

    #[test]
    fn a_suffix_starts_on_a_char_boundary() {
        let run = Run::new("é!");
        assert!(SharedStr::suffix(Arc::clone(&run), 1).is_none());
        assert_eq!(SharedStr::suffix(run, 2).unwrap(), "!");
    }

    #[test]
    fn it_compares_hashes_and_orders_as_its_text() {
        let run = Run::new("xAb");
        let a = SharedStr::suffix(run, 1).unwrap();
        assert_eq!(a, SharedStr::from("Ab"));
        assert!(a == "Ab" && "Ab" == a && a == *"Ab" && *"Ab" == a);
        let owned = String::from("Ab");
        assert!(a == owned && owned == a);
        let (lower, higher) = (SharedStr::from("Aa"), SharedStr::from("B"));
        assert!(lower < a && a < higher);

        let mut map = HashMap::new();
        map.insert(a.clone(), 1);
        assert_eq!(map.get("Ab"), Some(&1), "looked up by &str");
        assert_eq!(format!("{a} {a:?}"), "Ab \"Ab\"");
        assert_eq!(String::from(a), "Ab");
        assert_eq!(SharedStr::default(), "");
    }

    /// A string's hash is its text's, from the run's prefixes or from its own text.
    #[test]
    fn a_string_hashes_as_its_text() {
        let run = Run::new("Namespace.Type");
        for start in [0, 10, 14] {
            let suffix = SharedStr::suffix(Arc::clone(&run), start).unwrap();
            assert_eq!(suffix.text_hash(), TextHash::of(suffix.as_bytes()));
            assert_eq!(
                suffix.text_hash(),
                SharedStr::from(suffix.as_str()).text_hash()
            );
        }
    }

    /// A string of a long run hashes from the run's prefixes, one of a short run directly,
    /// and both as their text; only the long run keeps a prefix table.
    #[test]
    fn long_runs_keep_prefix_tables_and_short_ones_do_not() {
        let long = Run::new("x".repeat(HASHED_DIRECTLY + 10));
        let short = Run::new("Namespace");
        for (run, start) in [(&long, 0), (&long, 30), (&short, 0), (&short, 4)] {
            let suffix = SharedStr::suffix(Arc::clone(run), start).unwrap();
            assert_eq!(suffix.text_hash(), TextHash::of(suffix.as_bytes()));
            assert_eq!(
                suffix.suffix_hash(3),
                Some(TextHash::of(&suffix.as_bytes()[suffix.len() - 3..]))
            );
        }
        assert!(long.hashes.is_some());
        assert!(short.hashes.is_none());
    }
}

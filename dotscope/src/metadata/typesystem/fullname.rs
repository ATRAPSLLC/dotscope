//! The full name of a type, joined from the shared names it is made of only when shown.
//!
//! A type's full name is its namespace and name (`System.String`), or its enclosing type's
//! full name and its name (`System.Collections.Generic.List`1/Enumerator`). Joining it for
//! every type while loading cost the types times their names' length: a hostile image with
//! many TypeRefs in one long namespace grew without bound. A [`FullName`] is a node that
//! holds the type's name, its namespace or its enclosing type's `FullName`, and the
//! [`TextHash`] of the joined text, so a type costs the same whatever its names' length,
//! and an index of full names is built and searched without joining any of them.
//!
//! The joined text is built on first use of [`FullName::as_str`] (or a `str` method through
//! `Deref`) and kept; [`std::fmt::Display`] and comparisons with text do not build it.

use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::{Arc, LazyLock, OnceLock},
};

use crate::metadata::{streams::SharedStr, texthash::TextHash};

/// The full name of a type: `Namespace.Name`, `Name` without a namespace, or
/// `Enclosing/Name` for a nested type.
///
/// Cloning is a reference count increment. Two full names are equal when their texts are
/// (as [`TextHash`]es, see that type for the odds of a collision), and a full name compares
/// with a `str`, `&str` or `String` by its text.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_path("tests/samples/crafted_2.exe")?;
/// for entry in assembly.types().iter() {
///     let full_name = entry.value().fullname();
///     if full_name == "System.Object" {
///         println!("{full_name} has {} bytes", full_name.len());
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone)]
pub struct FullName(Arc<Node>);

/// One full name.
struct Node {
    /// What the name is within: a namespace (possibly empty) or an enclosing type
    scope: Scope,
    /// The type's own name
    name: SharedStr,
    /// The hash of the joined text
    hash: TextHash,
    /// The joined text, built on first use
    text: OnceLock<Arc<str>>,
}

impl Drop for Node {
    /// Unlinks the chain of enclosing names one at a time while this node holds the only
    /// reference to the next, so a deeply nested name drops without recursing once per level.
    fn drop(&mut self) {
        /// A scope to leave behind in a node being taken apart.
        static DETACHED: LazyLock<SharedStr> = LazyLock::new(SharedStr::default);
        let mut next = std::mem::replace(&mut self.scope, Scope::Namespace(DETACHED.clone()));
        while let Scope::Enclosing(FullName(parent)) = next {
            match Arc::try_unwrap(parent) {
                Ok(mut node) => {
                    next = std::mem::replace(&mut node.scope, Scope::Namespace(DETACHED.clone()));
                }
                Err(_) => break,
            }
        }
    }
}

/// What a [`FullName`]'s name is within.
enum Scope {
    /// A top-level type's namespace, empty for none
    Namespace(SharedStr),
    /// A nested type's enclosing type
    Enclosing(FullName),
}

/// The hash of `.`.
fn dot() -> TextHash {
    TextHash::of(b".")
}

/// The hash of `/`.
fn slash() -> TextHash {
    TextHash::of(b"/")
}

impl FullName {
    /// The full name of a top-level type: `namespace.name`, or `name` without a namespace.
    #[must_use]
    pub fn top_level(namespace: SharedStr, name: SharedStr) -> Self {
        let hash = if namespace.is_empty() {
            name.text_hash()
        } else {
            namespace.text_hash().then(dot()).then(name.text_hash())
        };
        Self::node(Scope::Namespace(namespace), name, hash)
    }

    /// The full name of a type nested in `enclosing`: `enclosing/name`.
    #[must_use]
    pub fn nested(enclosing: FullName, name: SharedStr) -> Self {
        let hash = enclosing.0.hash.then(slash()).then(name.text_hash());
        Self::node(Scope::Enclosing(enclosing), name, hash)
    }

    /// A node of `scope` and `name` whose joined text hashes to `hash`.
    fn node(scope: Scope, name: SharedStr, hash: TextHash) -> Self {
        Self(Arc::new(Node {
            scope,
            name,
            hash,
            text: OnceLock::new(),
        }))
    }

    /// The hash of the joined text, the identity of the name.
    pub fn text_hash(&self) -> TextHash {
        self.0.hash
    }

    /// The type's own name, the last component.
    #[must_use]
    pub fn name(&self) -> &SharedStr {
        &self.0.name
    }

    /// The enclosing type's full name, for a nested type.
    #[must_use]
    pub fn enclosing(&self) -> Option<&FullName> {
        match &self.0.scope {
            Scope::Enclosing(enclosing) => Some(enclosing),
            Scope::Namespace(_) => None,
        }
    }

    /// The namespace of the outermost enclosing type, or of the type itself when it is not
    /// nested; empty for none.
    #[must_use]
    pub fn namespace(&self) -> &SharedStr {
        let mut current = self;
        loop {
            match &current.0.scope {
                Scope::Namespace(namespace) => return namespace,
                Scope::Enclosing(enclosing) => current = enclosing,
            }
        }
    }

    /// The length of the joined text in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.0.hash.len()).unwrap_or(usize::MAX)
    }

    /// Whether the joined text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.hash.len() == 0
    }

    /// The joined text, built on the first call and kept.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text()
    }

    /// The joined text as a shared `str`, built on the first call and kept.
    #[must_use]
    pub fn as_arc_str(&self) -> Arc<str> {
        Arc::clone(self.text())
    }

    /// The joined text, built on the first call and kept.
    fn text(&self) -> &Arc<str> {
        self.0.text.get_or_init(|| {
            let mut text = String::with_capacity(self.len());
            self.for_each_piece(|piece| text.push_str(piece));
            Arc::from(text)
        })
    }

    /// The outermost-first chain of names, ending with this one.
    fn chain(&self) -> Vec<&FullName> {
        let mut chain = vec![self];
        let mut current = self;
        while let Scope::Enclosing(enclosing) = &current.0.scope {
            chain.push(enclosing);
            current = enclosing;
        }
        chain.reverse();
        chain
    }

    /// Calls `piece` with each piece of the joined text in order.
    fn for_each_piece(&self, mut piece: impl FnMut(&str)) {
        for (index, node) in self.chain().into_iter().enumerate() {
            if index > 0 {
                piece("/");
            } else if let Scope::Namespace(namespace) = &node.0.scope {
                if !namespace.is_empty() {
                    piece(namespace);
                    piece(".");
                }
            }
            piece(&node.0.name);
        }
    }

    /// Whether the joined text starts with `prefix`, compared piece by piece without joining
    /// it. (A `FullName` derefs to `str`; this inherent method is found first, so
    /// `name.starts_with("System.")` does not build the text.)
    #[must_use]
    pub fn starts_with(&self, prefix: &str) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        let mut rest = prefix.as_bytes();
        let mut matches = true;
        self.for_each_piece(|piece| {
            if !matches || rest.is_empty() {
                return;
            }
            let piece = piece.as_bytes();
            let take = piece.len().min(rest.len());
            if piece.get(..take) == rest.get(..take) {
                rest = rest.get(take..).unwrap_or_default();
            } else {
                matches = false;
            }
        });
        matches && rest.is_empty()
    }

    /// Whether the joined text ends with `suffix`, by hash without joining it. (Found before
    /// `str::ends_with`, as [`Self::starts_with`] is.)
    #[must_use]
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.suffix_hash(suffix.len() as u64) == Some(TextHash::of(suffix.as_bytes()))
    }

    /// The pieces of the joined text, last first: each name and namespace, and the `/` and
    /// `.` between them.
    fn pieces_from_the_end(&self) -> Vec<Piece<'_>> {
        let mut pieces = Vec::new();
        let mut current = self;
        loop {
            pieces.push(Piece::Text(&current.0.name));
            match &current.0.scope {
                Scope::Enclosing(enclosing) => {
                    pieces.push(Piece::Separator(b'/'));
                    current = enclosing;
                }
                Scope::Namespace(namespace) => {
                    if !namespace.is_empty() {
                        pieces.push(Piece::Separator(b'.'));
                        pieces.push(Piece::Text(namespace));
                    }
                    return pieces;
                }
            }
        }
    }

    /// The [`TextHash`] of the last `len` bytes of the joined text, without joining it.
    ///
    /// # Returns
    /// `None` when the text is shorter than `len`.
    fn suffix_hash(&self, len: u64) -> Option<TextHash> {
        if len > self.0.hash.len() {
            return None;
        }
        let mut tail = TextHash::EMPTY;
        let mut remaining = len;
        for piece in self.pieces_from_the_end() {
            if remaining == 0 {
                break;
            }
            let piece_len = piece.len();
            if piece_len >= remaining {
                let part = match piece {
                    Piece::Text(text) => text.suffix_hash(usize::try_from(remaining).ok()?)?,
                    Piece::Separator(byte) => TextHash::of(&[byte]),
                };
                return Some(part.then(tail));
            }
            tail = piece.hash().then(tail);
            remaining = remaining.saturating_sub(piece_len);
        }
        (remaining == 0).then_some(tail)
    }

    /// Whether the joined text ends with the text whose hash is `suffix`, and is longer.
    ///
    /// This is how a TypeRef naming a nested type by its inner name alone, or by
    /// `Enclosing/Name`, finds the TypeDef whose full name carries the whole path.
    pub fn ends_with_proper(&self, suffix: TextHash) -> bool {
        suffix.len() < self.0.hash.len() && self.suffix_hash(suffix.len()) == Some(suffix)
    }

    /// The [`TextHash`] of the joined text's last component, after its last `/`; `None` when
    /// the text has no `/`.
    pub fn last_component_hash(&self) -> Option<TextHash> {
        let name = &self.0.name;
        if let Some(after) = name.after_last_slash() {
            return Some(after.text_hash());
        }
        match &self.0.scope {
            Scope::Enclosing(_) => Some(name.text_hash()),
            Scope::Namespace(namespace) => namespace
                .after_last_slash()
                .map(|after| after.text_hash().then(dot()).then(name.text_hash())),
        }
    }
}

/// A piece of a [`FullName`]'s joined text.
enum Piece<'a> {
    /// A name or namespace
    Text(&'a SharedStr),
    /// The `/` or `.` between two
    Separator(u8),
}

impl Piece<'_> {
    /// The piece's length in bytes.
    fn len(&self) -> u64 {
        match self {
            Piece::Text(text) => text.len() as u64,
            Piece::Separator(_) => 1,
        }
    }

    /// The piece's [`TextHash`].
    fn hash(&self) -> TextHash {
        match self {
            Piece::Text(text) => text.text_hash(),
            Piece::Separator(byte) => TextHash::of(&[*byte]),
        }
    }
}

impl Default for FullName {
    /// The empty name.
    fn default() -> Self {
        Self::top_level(SharedStr::default(), SharedStr::default())
    }
}

impl Deref for FullName {
    type Target = str;

    /// The joined text; see [`FullName::as_str`].
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for FullName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for FullName {
    /// Writes the joined text without building it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = Ok(());
        self.for_each_piece(|piece| {
            if result.is_ok() {
                result = f.write_str(piece);
            }
        });
        result
    }
}

impl fmt::Debug for FullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string(), f)
    }
}

impl PartialEq for FullName {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0.hash == other.0.hash
    }
}

impl Eq for FullName {}

impl Hash for FullName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash.hash(state);
    }
}

impl PartialOrd for FullName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FullName {
    /// Orders by the joined texts, building them.
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            Ordering::Equal
        } else {
            self.as_str().cmp(other.as_str())
        }
    }
}

impl PartialEq<str> for FullName {
    /// Compares by the text's hash, without joining this name.
    fn eq(&self, other: &str) -> bool {
        self.len() == other.len() && self.0.hash == TextHash::of(other.as_bytes())
    }
}

impl PartialEq<&str> for FullName {
    fn eq(&self, other: &&str) -> bool {
        *self == **other
    }
}

impl PartialEq<String> for FullName {
    fn eq(&self, other: &String) -> bool {
        *self == *other.as_str()
    }
}

impl PartialEq<Arc<str>> for FullName {
    fn eq(&self, other: &Arc<str>) -> bool {
        *self == **other
    }
}

impl PartialEq<FullName> for str {
    fn eq(&self, other: &FullName) -> bool {
        *other == *self
    }
}

impl PartialEq<FullName> for &str {
    fn eq(&self, other: &FullName) -> bool {
        *other == **self
    }
}

impl PartialEq<FullName> for String {
    fn eq(&self, other: &FullName) -> bool {
        *other == *self.as_str()
    }
}

impl From<FullName> for String {
    fn from(name: FullName) -> Self {
        name.to_string()
    }
}

impl From<&FullName> for String {
    fn from(name: &FullName) -> Self {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top(namespace: &str, name: &str) -> FullName {
        FullName::top_level(SharedStr::from(namespace), SharedStr::from(name))
    }

    #[test]
    fn a_full_name_joins_as_the_runtime_writes_it() {
        let list = top("System.Collections.Generic", "List`1");
        let enumerator = FullName::nested(list.clone(), SharedStr::from("Enumerator"));
        let global = top("", "<Module>");

        assert_eq!(list.to_string(), "System.Collections.Generic.List`1");
        assert_eq!(
            enumerator.to_string(),
            "System.Collections.Generic.List`1/Enumerator"
        );
        assert_eq!(global.to_string(), "<Module>");
        for name in [&list, &enumerator, &global] {
            assert_eq!(name.as_str(), name.to_string());
            assert_eq!(name.len(), name.to_string().len());
            let text = name.to_string();
            assert!(*name == *text.as_str());
            assert!(text == *name);
        }
        assert_eq!(enumerator.namespace(), "System.Collections.Generic");
        assert_eq!(enumerator.name(), "Enumerator");
        assert_eq!(enumerator.enclosing(), Some(&list));
        assert!(list != *"System.Collections.Generic.List`2");
    }

    #[test]
    fn names_with_the_same_text_are_equal_and_hash_alike() {
        let a = top("A.B", "C");
        let b = top("A", "B.C");
        assert_eq!(a, b, "the same text, split differently");
        let hash_of = |name: &FullName| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_ne!(top("A", "C"), top("A", "D"));
        assert!(top("A", "B") < top("A", "C"));
    }

    #[test]
    fn a_name_ends_with_its_proper_suffixes() {
        let hash = |text: &str| TextHash::of(text.as_bytes());
        let outer = top("System.Collections.Concurrent", "Partitioner");
        let inner = FullName::nested(outer.clone(), SharedStr::from("Enumerator"));
        let text = inner.to_string();

        for start in 1..text.len() {
            let suffix = text.get(start..).unwrap();
            assert!(inner.ends_with_proper(hash(suffix)), "{suffix}");
        }
        assert!(
            !inner.ends_with_proper(hash(&text)),
            "not a proper suffix of itself"
        );
        assert!(!inner.ends_with_proper(hash("Other/Enumerator")));
        assert!(!inner.ends_with_proper(hash(&format!("x{text}"))));

        assert_eq!(inner.last_component_hash(), Some(hash("Enumerator")));
        assert_eq!(outer.last_component_hash(), None);
        let slashed = top("N/S", "T");
        assert_eq!(slashed.last_component_hash(), Some(hash("S.T")));
        let in_name = top("NS", "Outer/Inner");
        assert_eq!(in_name.last_component_hash(), Some(hash("Inner")));
        assert_eq!(
            in_name,
            FullName::nested(top("NS", "Outer"), SharedStr::from("Inner"))
        );
    }

    /// `starts_with` and `ends_with` agree with the joined text's, without building it.
    #[test]
    fn prefixes_and_suffixes_match_the_text() {
        let name = FullName::nested(
            top("System.Collections", "Dictionary`2"),
            SharedStr::from("Entry"),
        );
        let text = name.to_string();
        for cut in 0..=text.len() {
            let (head, tail) = text.split_at(cut);
            assert!(name.starts_with(head), "{head}");
            assert!(name.ends_with(tail), "{tail}");
        }
        assert!(!name.starts_with("System.Collections.Dictionary`2/Entry!"));
        assert!(!name.starts_with("System.Collections/"));
        assert!(!name.ends_with("XEntry"));
        assert!(name.0.text.get().is_none(), "the text was never built");
    }

    /// A name nested hundreds of thousands deep drops without overflowing the stack.
    #[test]
    fn a_deeply_nested_name_drops_iteratively() {
        let mut name = top("NS", "T");
        for _ in 0..200_000 {
            name = FullName::nested(name, SharedStr::from("N"));
        }
        assert_eq!(name.len(), "NS.T".len() + 200_000 * 2);
        drop(name);
    }
}

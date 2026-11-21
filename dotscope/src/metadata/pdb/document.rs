//! The DocumentNameBlob: a source file's path, as the separator and the blob-heap parts it is
//! joined from.
//!
//! ```text
//! Blob ::= separator part+
//! separator ::= byte   (an ASCII character; 0: the parts are joined with nothing between them)
//! part ::= compressed #Blob index of the part's UTF-8 bytes (0: an empty part)
//! ```
//!
//! System.Reflection.Metadata, the reader debuggers use, reads a blob with a separator and no
//! parts as the empty name, and refuses a separator that is not ASCII; dotscope reads both as
//! it does.
//!
//! A path such as `/_/src/Program.cs` is `/` and the parts `""`, `"_"`, `"src"` and
//! `"Program.cs"`, each part's blob shared by every document that names it.
//!
//! # Reference
//!
//! The Portable PDB v1.0 format specification, "Document Name Blob".

use std::{fmt, sync::Arc};

use crate::{
    file::parser::Parser,
    metadata::streams::{Blob, SharedStr},
    utils::write_compressed_uint,
    Result,
};

/// A DocumentNameBlob as it is stored: the separator and each part's `#Blob` index.
///
/// This is the level a writer works at: the parts are blob indices, which move when the
/// `#Blob` heap is rebuilt, so the blob is decoded to them, they are renumbered, and it is
/// encoded again. [`document_name`] resolves them into the path.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::pdb::DocumentNameBlob;
///
/// let name = DocumentNameBlob::parse(&[b'/', 0, 1, 5])?;
/// assert_eq!(name.separator, b'/');
/// assert_eq!(name.parts, [0, 1, 5]);
/// assert_eq!(name.encode()?, [b'/', 0, 1, 5]);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentNameBlob {
    /// The separator the parts are joined with: an ASCII character, or 0 for none
    pub separator: u8,
    /// Each part's `#Blob` index, in order; 0 is an empty part
    pub parts: Vec<u32>,
}

impl DocumentNameBlob {
    /// Reads a DocumentNameBlob.
    ///
    /// # Arguments
    ///
    /// * `blob` - The blob a Document row's Name column names
    ///
    /// # Returns
    ///
    /// The separator and the parts' indices; a blob with a separator and no parts has none,
    /// as System.Reflection.Metadata reads it.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob is empty, its separator is not an ASCII character, or
    /// it ends inside a part's index.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut parser = Parser::new(blob);
        let separator = parser.read_le::<u8>()?;
        if !separator.is_ascii() {
            return Err(malformed_error!(
                "a document name's separator 0x{separator:02X} is not an ASCII character"
            ));
        }
        let mut parts = Vec::new();
        while parser.has_more_data() {
            parts.push(parser.read_compressed_uint()?);
        }
        Ok(DocumentNameBlob { separator, parts })
    }

    /// Writes the blob: the inverse of [`DocumentNameBlob::parse`].
    ///
    /// # Errors
    ///
    /// Returns an error when the separator is not an ASCII character, or a part's index is
    /// past what a compressed integer holds.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !self.separator.is_ascii() {
            return Err(malformed_error!(
                "a document name's separator 0x{:02X} is not an ASCII character",
                self.separator
            ));
        }
        let mut blob = vec![self.separator];
        for &part in &self.parts {
            write_compressed_uint(part, &mut blob)?;
        }
        Ok(blob)
    }
}

/// Splits a path into the separator and the parts a DocumentNameBlob stores it as, as
/// System.Reflection.Metadata's `MetadataBuilder.GetOrAddDocumentName` splits it.
///
/// The separator is `/` unless the path holds more `\` than `/`; the parts are the path split
/// at every separator, so a leading, doubled or trailing separator gives an empty part, which
/// a writer stores as blob index 0.
///
/// # Arguments
///
/// * `name` - The document's path
///
/// # Returns
///
/// The separator, and the parts in order.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::pdb::split_document_name;
///
/// assert_eq!(split_document_name("/_/src/a.cs"), (b'/', vec!["", "_", "src", "a.cs"]));
/// assert_eq!(split_document_name(r"C:\src\a.cs"), (b'\\', vec!["C:", "src", "a.cs"]));
/// assert_eq!(split_document_name("a.cs"), (b'/', vec!["a.cs"]));
/// ```
#[must_use]
pub fn split_document_name(name: &str) -> (u8, Vec<&str>) {
    let slashes = name.bytes().filter(|&byte| byte == b'/').count();
    let backslashes = name.bytes().filter(|&byte| byte == b'\\').count();
    let separator = if slashes >= backslashes { b'/' } else { b'\\' };
    (separator, name.split(char::from(separator)).collect())
}

/// Decodes a DocumentNameBlob against the PDB's `#Blob` heap.
///
/// The parts are looked up in `blobs` and joined by the separator, as
/// System.Reflection.Metadata joins them: each part is read as UTF-8 on its own, an invalid
/// sequence as U+FFFD, since a path is for display and lookup and a document with an odd
/// name is still a document. A blob with a separator and no parts is the empty name.
///
/// # Arguments
///
/// * `blob` - The DocumentNameBlob a Document row's Name column names
/// * `blobs` - The PDB's `#Blob` heap, which the parts index
///
/// # Returns
///
/// The document's path.
///
/// # Errors
///
/// Returns an error when the blob is empty, its separator is not an ASCII character, it ends
/// inside a part's index, or a part's index is not in `blobs`.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::{pdb::document_name, streams::Blob};
///
/// // A heap holding "src" at index 1 and "a.cs" at index 5
/// let heap = [0, 3, b's', b'r', b'c', 4, b'a', b'.', b'c', b's'];
/// let blobs = Blob::from(&heap)?;
/// assert_eq!(document_name(&[b'/', 1, 5], &blobs)?, "src/a.cs");
/// // A leading empty part gives a rooted path
/// assert_eq!(document_name(&[b'/', 0, 1, 5], &blobs)?, "/src/a.cs");
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn document_name(blob: &[u8], blobs: &Blob<'_>) -> Result<String> {
    let stored = DocumentNameBlob::parse(blob)?;
    let mut name = String::new();
    for (index, &part) in stored.parts.iter().enumerate() {
        if index > 0 && stored.separator != 0 {
            name.push(char::from(stored.separator));
        }
        if part != 0 {
            name.push_str(&String::from_utf8_lossy(blobs.get(part as usize)?));
        }
    }
    Ok(name)
}

/// A Document row's name: its DocumentNameBlob, read against the PDB's `#Blob` heap when the
/// name is used.
///
/// The name is a separator and the `#Blob` indices of its parts, and the path is their
/// join (see [`document_name`]). A name blob of N parts naming one long part blob joins to N
/// times its length, so joining every row's name while loading let a small heap grow into
/// gigabytes. A `DocumentName` instead keeps a reference to a shared copy of the heap and the
/// index of its name blob, a few bytes per row, and joins the parts only when displayed or
/// compared, as System.Reflection.Metadata reads a `DocumentNameBlobHandle` on request.
///
/// The name blob and every part were checked when the row was read, so displaying cannot
/// fail. It displays as the joined path; [`ToString::to_string`] gives it as a `String`, and
/// it compares with a `str` part by part, without joining. A name built outside a heap (a
/// [`Document::new`](crate::metadata::tables::Document::new) of a path) converts from a
/// `String` or `&str` and holds the path itself.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::streams::Blob;
///
/// // Blobs "src" at 1 and "a.cs" at 5, and the name blob `/ 1 5` at 10
/// let heap = [0, 3, b's', b'r', b'c', 4, b'a', b'.', b'c', b's', 3, b'/', 1, 5];
/// let blobs = Blob::from(&heap)?;
/// let name = blobs.document_name(10)?;
/// assert_eq!(name, "src/a.cs");
/// assert_eq!(name.to_string(), "src/a.cs");
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone)]
pub struct DocumentName(NameSource);

/// Where a [`DocumentName`]'s path comes from.
#[derive(Clone)]
enum NameSource {
    /// A DocumentNameBlob of a heap
    Heap {
        /// A copy of the `#Blob` heap, shared by every name and blob read from it
        heap: Arc<[u8]>,
        /// The index of the name's DocumentNameBlob in `heap`
        blob: u32,
    },
    /// A path given as text
    Path(SharedStr),
}

impl DocumentName {
    /// The name whose DocumentNameBlob is at `blob` in `blobs`, after checking that the blob
    /// reads and that every part is a blob of the heap.
    ///
    /// # Errors
    ///
    /// Returns the error [`document_name`] gives for the blob: it does not read, its
    /// separator is not ASCII, or a part's index names no blob.
    pub fn read(blobs: &Blob<'_>, blob: u32) -> Result<Self> {
        let stored = DocumentNameBlob::parse(blobs.get(blob as usize)?)?;
        for &part in &stored.parts {
            if part != 0 {
                blobs.get(part as usize)?;
            }
        }
        Ok(Self(NameSource::Heap {
            heap: blobs.shared_heap(),
            blob,
        }))
    }

    /// Calls `part` with the separator (as its own piece) and each part of the name in order,
    /// each part decoded as UTF-8 with an invalid sequence as U+FFFD.
    ///
    /// Stops at the first error `part` returns.
    fn for_each_piece<E>(
        &self,
        mut part: impl FnMut(&str) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        let (heap, blob) = match &self.0 {
            NameSource::Heap { heap, blob } => (heap, *blob),
            NameSource::Path(path) => return part(path),
        };
        // The heap was checked when the name was read: a lookup that fails here leaves the
        // piece out rather than failing a display.
        let Ok(heap) = Blob::from(heap) else {
            return Ok(());
        };
        let Some(stored) = heap
            .get(blob as usize)
            .ok()
            .and_then(|blob| DocumentNameBlob::parse(blob).ok())
        else {
            return Ok(());
        };
        let separator = char::from(stored.separator);
        let mut buffer = [0u8; 4];
        for (index, &index_of_part) in stored.parts.iter().enumerate() {
            if index > 0 && stored.separator != 0 {
                part(separator.encode_utf8(&mut buffer))?;
            }
            if index_of_part != 0 {
                if let Ok(bytes) = heap.get(index_of_part as usize) {
                    for chunk in bytes.utf8_chunks() {
                        part(chunk.valid())?;
                        if !chunk.invalid().is_empty() {
                            part("\u{FFFD}")?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The separator the parts of a heap name are joined with; `None` for none, and for a
    /// name given as a path.
    #[must_use]
    pub fn separator(&self) -> Option<char> {
        let NameSource::Heap { heap, blob } = &self.0 else {
            return None;
        };
        Blob::from(heap)
            .ok()
            .and_then(|heap| {
                heap.get(*blob as usize)
                    .ok()
                    .and_then(|b| b.first().copied())
            })
            .filter(|&separator| separator != 0)
            .map(char::from)
    }
}

impl fmt::Display for DocumentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.for_each_piece(|piece| f.write_str(piece))
    }
}

impl fmt::Debug for DocumentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string(), f)
    }
}

impl PartialEq<str> for DocumentName {
    /// Compares part by part, stopping at the first difference, without joining the name.
    fn eq(&self, other: &str) -> bool {
        let mut rest = other;
        let matched = self.for_each_piece(|piece| match rest.strip_prefix(piece) {
            Some(after) => {
                rest = after;
                Ok(())
            }
            None => Err(()),
        });
        matched.is_ok() && rest.is_empty()
    }
}

impl PartialEq<&str> for DocumentName {
    fn eq(&self, other: &&str) -> bool {
        *self == **other
    }
}

impl PartialEq<String> for DocumentName {
    fn eq(&self, other: &String) -> bool {
        *self == *other.as_str()
    }
}

impl PartialEq for DocumentName {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                NameSource::Heap { heap, blob },
                NameSource::Heap {
                    heap: other_heap,
                    blob: other_blob,
                },
            ) if Arc::ptr_eq(heap, other_heap) && blob == other_blob => true,
            (_, NameSource::Path(path)) => *self == **path,
            _ => *other == *self.to_string(),
        }
    }
}

impl Eq for DocumentName {}

impl From<String> for DocumentName {
    fn from(path: String) -> Self {
        Self(NameSource::Path(SharedStr::from(path)))
    }
}

impl From<&str> for DocumentName {
    fn from(path: &str) -> Self {
        Self(NameSource::Path(SharedStr::from(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A heap of the blobs `parts`, at the indexes it returns.
    fn heap(parts: &[&[u8]]) -> (Vec<u8>, Vec<u32>) {
        let mut data = vec![0u8];
        let mut indexes = Vec::new();
        for part in parts {
            indexes.push(u32::try_from(data.len()).unwrap());
            data.push(u8::try_from(part.len()).unwrap());
            data.extend_from_slice(part);
        }
        (data, indexes)
    }

    /// A heap holding `parts` and then each name blob of `names`, with the index of each name
    /// blob.
    fn heap_with_names(parts: &[&[u8]], names: &[Vec<u8>]) -> (Vec<u8>, Vec<u32>, Vec<u32>) {
        let (mut data, at) = heap(parts);
        let mut name_at = Vec::new();
        for name in names {
            name_at.push(u32::try_from(data.len()).unwrap());
            let mut prefix = Vec::new();
            write_compressed_uint(u32::try_from(name.len()).unwrap(), &mut prefix).unwrap();
            data.extend_from_slice(&prefix);
            data.extend_from_slice(name);
        }
        (data, at, name_at)
    }

    /// A [`DocumentName`] displays, and compares, as the path [`document_name`] joins, for
    /// rooted, separator-less, backslashed and invalid-UTF-8 names.
    #[test]
    fn a_document_name_reads_as_document_name_joins_it() {
        let parts: [&[u8]; 4] = [b"_", b"src", b"a\xffb", b"x.cs"];
        let (_, at) = heap(&parts);
        let byte = |i: usize| u8::try_from(at[i]).unwrap();
        let names = vec![
            vec![b'/', 0, byte(0), byte(1), byte(3)],
            vec![0, byte(1), byte(3)],
            vec![b'\\', byte(1), byte(2)],
            vec![b'/'],
        ];
        let (data, _, name_at) = heap_with_names(&parts, &names);
        let blobs = Blob::from(&data).unwrap();
        for (name, &index) in names.iter().zip(&name_at) {
            let joined = document_name(name, &blobs).unwrap();
            let shared = blobs.document_name(index).unwrap();
            assert_eq!(shared.to_string(), joined);
            assert_eq!(shared, *joined.as_str());
            assert_eq!(shared, DocumentName::from(joined.as_str()));
            assert!(shared != *format!("{joined}!").as_str());
            if let Some((last, _)) = joined.char_indices().last() {
                assert!(shared != *joined.get(..last).unwrap());
            }
        }
        assert_eq!(
            blobs.document_name(name_at[2]).unwrap().separator(),
            Some('\\')
        );
        assert_eq!(blobs.document_name(name_at[1]).unwrap().separator(), None);
    }

    /// A name of many parts naming one long blob is a view: reading it does not join it, and
    /// every name shares the one copy of the heap.
    #[test]
    fn a_long_name_is_a_view_of_the_shared_heap() {
        let long = vec![b'a'; 100];
        let (_, at) = heap(&[&long]);
        let part = u8::try_from(at[0]).unwrap();
        let mut name = vec![b'/'];
        name.extend(std::iter::repeat_n(part, 1000));
        let (data, _, name_at) = heap_with_names(&[&long], &[name]);
        let blobs = Blob::from(&data).unwrap();

        let names: Vec<DocumentName> = (0..100)
            .map(|_| blobs.document_name(name_at[0]).unwrap())
            .collect();
        let heap = blobs.shared_heap();
        assert_eq!(
            Arc::strong_count(&heap),
            names.len() + 3,
            "the names, the cached one, the heap's own copy and this handle share one heap"
        );
        assert_eq!(names[0].to_string().len(), 1000 * 100 + 999);
    }

    /// A name blob that does not read, or names a part that is no blob, fails when read.
    #[test]
    fn a_bad_name_blob_fails_when_read() {
        let (data, _, name_at) = heap_with_names(&[b"x"], &[vec![0xFF, 1], vec![b'/', 0x7F]]);
        let blobs = Blob::from(&data).unwrap();
        assert!(
            blobs.document_name(name_at[0]).is_err(),
            "a non-ASCII separator"
        );
        assert!(
            blobs.document_name(name_at[1]).is_err(),
            "a part past the heap"
        );
    }

    /// A path joins its parts with the separator; an empty first part (index 0) gives the
    /// leading separator, as the probe's `/_/PdbProbe/Program.cs` is written.
    #[test]
    fn parts_join_with_the_separator() {
        let (data, at) = heap(&[b"_", b"PdbProbe", b"Program.cs"]);
        let blobs = Blob::from(&data).unwrap();
        let blob = [b'/', 0, at[0] as u8, at[1] as u8, at[2] as u8];
        assert_eq!(
            document_name(&blob, &blobs).unwrap(),
            "/_/PdbProbe/Program.cs"
        );

        // No separator: the parts run together
        let joined = [0, at[1] as u8, at[2] as u8];
        assert_eq!(
            document_name(&joined, &blobs).unwrap(),
            "PdbProbeProgram.cs"
        );

        // A Windows path's separator
        let windows = [b'\\', at[0] as u8, at[2] as u8];
        assert_eq!(document_name(&windows, &blobs).unwrap(), "_\\Program.cs");
    }

    /// Bytes that are not UTF-8 read as U+FFFD, as SRM reads them.
    #[test]
    fn invalid_utf8_reads_as_replacement() {
        let (data, at) = heap(&[b"a\xFFb"]);
        let blobs = Blob::from(&data).unwrap();
        assert_eq!(
            document_name(&[0, at[0] as u8], &blobs).unwrap(),
            "a\u{FFFD}b"
        );
    }

    /// Each part is decoded on its own, as System.Reflection.Metadata decodes it: a character
    /// split across two parts is two invalid sequences. A separator that is not ASCII is
    /// refused, and a separator with no parts is the empty name, as SRM reads them.
    #[test]
    fn parts_decode_on_their_own() {
        // "é" is C3 A9 in UTF-8
        let (data, at) = heap(&[b"x\xC3", b"\xA9y"]);
        let blobs = Blob::from(&data).unwrap();
        let split = [0, at[0] as u8, at[1] as u8];
        assert_eq!(document_name(&split, &blobs).unwrap(), "x\u{FFFD}\u{FFFD}y");
        assert!(document_name(&[0xE9, at[0] as u8], &blobs).is_err());
        assert!(document_name(&[0x80, at[0] as u8], &blobs).is_err());
        assert_eq!(document_name(b"/", &blobs).unwrap(), "");
    }

    /// A blob with no parts, or a part index past the heap, is refused.
    #[test]
    fn malformed_names_are_refused() {
        let (data, _) = heap(&[b"x"]);
        let blobs = Blob::from(&data).unwrap();
        assert!(document_name(&[], &blobs).is_err());
        assert!(document_name(&[b'/', 0x7F], &blobs).is_err());
    }
}

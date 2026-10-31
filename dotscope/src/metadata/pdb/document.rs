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

use crate::{file::parser::Parser, metadata::streams::Blob, utils::write_compressed_uint, Result};

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

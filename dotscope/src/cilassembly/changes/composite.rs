//! Blobs whose content names other blobs: written once those blobs have offsets.
//!
//! A Portable PDB's DocumentNameBlob and imports blob store blob heap offsets inside their
//! bytes: the parts of a document's path, the aliases and namespaces of its imports. A blob a
//! change adds has no offset until the writer lays out the heap, and a heap placeholder
//! (`0x8000_0000 | id`) does not fit the compressed integers the blob stores offsets as, so
//! such a blob cannot be encoded when it is added.
//!
//! A [`BlobComposite`] holds what the blob says, with the blobs it names as the
//! [`ChangeRefRc`]s of their additions. The assembly's changes record it under the change id
//! of an appended placeholder blob ([`AssemblyChanges::blob_composites`]), and the blob heap
//! writer encodes it after every other blob is placed, from the offsets its parts resolved to.
//!
//! [`AssemblyChanges::blob_composites`]: crate::cilassembly::AssemblyChanges

use crate::{
    cilassembly::changes::ChangeRefRc,
    metadata::{importscope::ImportKind, token::Token},
};

/// A blob the writer encodes from the offsets of the blobs it names.
#[derive(Debug, Clone)]
pub(crate) enum BlobComposite {
    /// A DocumentNameBlob: the separator and each part, `None` for an empty part (index 0)
    DocumentName {
        /// The separator: an ASCII character, or 0 for none
        separator: u8,
        /// The parts' blobs, in order
        parts: Vec<Option<ChangeRefRc>>,
    },
    /// An imports blob: its declarations, in order
    Imports(Vec<CompositeImport>),
}

/// An import declaration whose alias and namespace are blobs a change adds.
#[derive(Debug, Clone)]
pub(crate) struct CompositeImport {
    /// The declaration's kind
    pub kind: ImportKind,
    /// The alias's blob, for the kinds that have one; `None` for the empty alias (index 0)
    pub alias: Option<ChangeRefRc>,
    /// The AssemblyRef row, for the kinds that name an assembly
    pub assembly: u32,
    /// The namespace's blob, for the kinds that have one; `None` for the empty namespace
    pub namespace: Option<ChangeRefRc>,
    /// The type (a TypeDef, TypeRef or TypeSpec token), for the kinds that name one
    pub target: Option<Token>,
}

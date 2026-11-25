//! Document table implementation for Portable PDB format
//!
//! This module provides access to Document table data, which stores information about
//! source documents referenced in debug information. It includes raw table access,
//! resolved data structures, document name parsing, and integration with the broader
//! metadata system.
//!
//! The Document table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`crate::metadata::tables::document::DocumentRaw`] for raw binary data with unresolved heap indices
//! - [`crate::metadata::tables::document::Document`] for processed data with resolved string and blob values
//!
//! # Architecture
//!
//! The Document table is part of the Portable PDB format and provides essential information
//! for mapping debug information back to source code locations. Each document entry contains
//! the document name/path, hash information for integrity verification, and language
//! identification for proper syntax highlighting and debugging support.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::document::DocumentRaw`] - Raw table structure with unresolved heap indices
//! - [`crate::metadata::tables::document::Document`] - Owned variant with resolved references and parsed document data
//! - [`crate::metadata::loader::tables::DocumentLoader`] - Internal loader for processing Document table data
//! - [`crate::metadata::tables::document::DocumentMap`] - Thread-safe concurrent map for caching document entries
//! - [`crate::metadata::tables::document::DocumentList`] - Thread-safe append-only vector for document collections
//! - [`crate::metadata::tables::document::DocumentRc`] - Reference-counted pointer for shared ownership
//!
//! # Document Table Structure
//!
//! Each Document table row contains these fields:
//! - **Name**: Document name/path stored as blob (typically a file path)
//! - **`HashAlgorithm`**: Hash algorithm identifier stored as GUID
//! - **Hash**: Document content hash stored as blob
//! - **Language**: Source language identifier stored as GUID
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{Document, DocumentMap};
//! use dotscope::metadata::token::Token;
//!
//! # fn example(documents: &DocumentMap) -> dotscope::Result<()> {
//! // Get a specific document by token
//! let token = Token::new(0x30000001); // Document table token
//! if let Some(document) = documents.get(&token) {
//!     println!("Document name: {:?}", document.value().name);
//!     println!("Hash algorithm: {:?}", document.value().hash_algorithm);
//!     println!("Language: {:?}", document.value().language);
//! }
//! # Ok(())
//! # }
//! ```
//!
//!
//! # Error Handling
//!
//! This module handles error conditions during document processing:
//! - Document name parsing errors when blob data is malformed (returns [`crate::Error`])
//! - Hash validation errors for invalid hash algorithms or data (returns [`crate::Error`])
//! - Language identifier resolution errors for unsupported GUIDs (returns [`crate::Error`])
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`crate::metadata::tables::document::DocumentMap`] and [`crate::metadata::tables::document::DocumentList`]
//! use lock-free concurrent data structures for efficient multi-threaded access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - [`crate::metadata::streams::Blob`] - Blob heap for document names and hashes
//! - [`crate::metadata::streams::Guid`] - GUID heap for algorithms and languages
//!
//! # References
//!
//! - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::document::Document`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `Document` entries indexed by their metadata tokens.
pub type DocumentMap = SkipMap<Token, DocumentRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::document::Document`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `Document` collections.
pub type DocumentList = Arc<boxcar::Vec<DocumentRc>>;

/// Reference-counted smart pointer to a [`crate::metadata::tables::document::Document`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `Document` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type DocumentRc = Arc<Document>;

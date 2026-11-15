//! `CustomDebugInformation` table module.
//!
//! This module provides complete support for the Portable PDB `CustomDebugInformation` metadata table (0x37),
//! which contains custom debugging information that extends the standard debugging metadata with
//! compiler and language-specific debugging data. It includes raw table access, resolved data structures,
//! and integration with the broader debugging system.
//!
//! # Architecture
//!
//! The `CustomDebugInformation` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved heap indexes, while owned entries
//! provide fully resolved references integrated with target metadata elements and parsed
//! debugging data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customdebuginformation::raw::CustomDebugInformationRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::customdebuginformation::owned::CustomDebugInformation`] - Owned variant with resolved references
//! - [`crate::metadata::tables::customdebuginformation::loader::CustomDebugInformationLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformationMap`] - Token-based lookup map
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformationList`] - Collection type
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRc`] - Reference-counted pointer
//!
//! # `CustomDebugInformation` Table Structure
//!
//! The `CustomDebugInformation` table contains zero or more rows with these fields:
//! - **Parent**: Coded index referencing the metadata element with custom debug info
//! - **Kind**: GUID heap reference identifying the custom debug info format
//! - **Value**: Blob heap reference containing the custom debug data
//!
//! # Usage Context
//!
//! Custom debugging information is used for:
//! - **State machine debugging**: Async/await and iterator state tracking
//! - **Dynamic type debugging**: Information for dynamically typed variables
//! - **Edit-and-continue**: Mapping information for debugging sessions
//! - **Embedded sources**: Source code embedding for portable debugging
//! - **Source link**: URL mapping for source server integration
//! - **Language-specific data**: Compiler-specific debugging extensions
//!
//! # Common Custom Debug Information Types
//!
//! Several well-known custom debug information types are defined by Microsoft compilers:
//! - **State Machine Hoisted Local Scopes**: Scope information for variables hoisted to state machine fields
//! - **Edit and Continue Local Slot Map**: Maps local variables to their syntax positions for edit-and-continue
//! - **Edit and Continue Lambda and Closure Map**: Maps lambdas and closures to their implementing methods
//! - **Dynamic Local Variables**: Tracks which types were originally declared as `dynamic` in C#
//! - **Default Namespace**: VB.NET project default namespace information
//! - **Embedded Source**: Source code embedded directly in the PDB
//! - **Source Link**: JSON configuration for retrieving source from version control
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::CustomDebugInformation;
//! # use dotscope::metadata::token::Token;
//! # fn example(custom_info: &CustomDebugInformation) -> dotscope::Result<()> {
//! // Access custom debug information for a method
//! let method_token = Token::new(0x06000001); // MethodDef token
//!
//! if custom_info.parent_token == method_token {
//!     println!("Found custom debug info kind: {:?}", custom_info.kind);
//!     // Process the custom information: parsed by the GUID in `kind`
//!     let data = &custom_info.value;
//!     println!("{:?}", data);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - [`crate::metadata::streams::Guid`] - GUID heap for debug info kinds
//! - [`crate::metadata::streams::Blob`] - Blob heap for debug data
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe through the use of atomic operations
//! and concurrent data structures. Custom debugging information can be safely accessed
//! and processed from multiple threads simultaneously.
//!
//! # References
//!
//! - [Portable PDB v1.1](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37) - `CustomDebugInformation` table specification

mod builder;
mod loader;
mod owned;
mod raw;
mod reader;
mod writer;

use std::sync::Arc;

pub use builder::*;
use crossbeam_skiplist::SkipMap;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

use crate::metadata::token::Token;

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `CustomDebugInformation` entries indexed by their metadata tokens.
pub type CustomDebugInformationMap = SkipMap<Token, CustomDebugInformationRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `CustomDebugInformation` collections.
pub type CustomDebugInformationList = Arc<boxcar::Vec<CustomDebugInformationRc>>;

/// Reference-counted smart pointer to a [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `CustomDebugInformation` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type CustomDebugInformationRc = Arc<CustomDebugInformation>;

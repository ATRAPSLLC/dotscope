//! Custom debug information for the Portable PDB format.
//!
//! Custom debug information lets compilers and tools record debugging data the standard
//! Portable PDB tables do not: the Source Link mapping of documents to URLs, embedded source
//! files, the options and references a module was compiled with, which locals were `dynamic`
//! or named tuples, async stepping points, and the maps Edit and Continue needs to match a
//! method's locals, lambdas and states across edits.
//!
//! # Architecture
//!
//! Each row of the `CustomDebugInformation` table (`0x37`) has three columns:
//!
//! - **Parent**: the entity the information is about, through the
//!   `HasCustomDebugInformation` coded index: a method, type, field, the module or assembly,
//!   or one of the PDB's own rows (a document, local scope, local variable or constant, or
//!   import scope)
//! - **Kind**: a GUID in the `#GUID` heap naming the information's format
//! - **Value**: a blob in the `#Blob` heap, in that format
//!
//! The GUID is both type and version: a format that changes gets a new GUID, so a reader that
//! does not know a GUID skips the row rather than misreading it. This module decodes every
//! kind the Portable PDB specification and the C#, Visual Basic and F# compilers define into
//! typed values, and keeps the blob of any other kind as it is so that nothing is lost.
//!
//! # Key Components
//!
//! - [`CustomDebugKind`] - the kinds, each with its GUID ([`crate::metadata::pdb::guids`])
//! - [`CustomDebugInfo`] - a blob decoded by its kind, one variant per kind
//! - [`parse_custom_debug_blob`] - decodes a blob of a kind
//! - [`encode_custom_debug_blob`] - writes a value back to its blob, byte for byte as the
//!   compilers write it
//! - [`CustomDebugInfo::embedded_source_text`] - an embedded source's text, inflated on
//!   request and bounded by the size the blob states
//! - The record types the variants hold: [`HoistedLocalScope`], [`EncLocalSlot`],
//!   [`EncLambda`], [`EncStateMachineState`], [`MetadataReferenceInfo`], [`AsyncAwait`]
//!
//! # Formats
//!
//! `cu` is an ECMA-335 compressed unsigned integer and `ci` a compressed signed one; fixed-size
//! integers are little-endian. *Syntax offsets* (Edit and Continue) are distances from the
//! start of the method body's syntax, stored relative to a baseline, which is stored negated.
//!
//! ## StateMachineHoistedLocalScopes (`6DA9A61E-F8C7-4874-BE62-68BC5630DF71`)
//! ```text
//! Blob ::= { start-offset:u32 length:u32 }*
//! ```
//! One IL range of the MoveNext method per hoisted local, in hoisted-field order.
//!
//! ## DynamicLocalVariables (`83C563C4-B4F3-47D5-B824-BA5441477EA8`)
//! ```text
//! Blob ::= flags:u8*
//! ```
//! A bit per type in the local's type signature, in the prefix order `DynamicAttribute`'s
//! flags use (`dynamic[]` is the array type, then its element type), least significant bit
//! first; set for an `object` the source declared `dynamic`. Trailing zero bytes may be left
//! out.
//!
//! ## DefaultNamespace (`58B2EAB6-209F-4E4E-A22C-B2D0F910C782`)
//! ```text
//! Blob ::= namespace:utf8
//! ```
//!
//! ## EncLocalSlotMap (`755F52A8-91C5-45BE-B4B8-209571E552BD`)
//! ```text
//! Blob ::= ( 0xFF -baseline:cu )? slot*
//! slot ::= 0x00                                         -- a slot with no syntax
//!        | kind:u8 syntax-offset:cu ( ordinal:cu )?     -- ordinal when kind & 0x80
//! ```
//! The baseline is -1 when the blob does not state one. `kind & 0x7F` is the compiler's
//! synthesized local kind plus one (1 for a user-declared local).
//!
//! ## EncLambdaAndClosureMap (`A643004C-0240-496F-A783-30D64F4979DE`)
//! ```text
//! Blob ::= method-ordinal+1:cu -baseline:cu closure-count:cu
//!          closure-syntax-offset:cu{closure-count}
//!          { lambda-syntax-offset:cu closure-ordinal:cu }*
//! ```
//!
//! ## EncStateMachineStateMap (`8B78CD68-2EDE-420B-980B-E15884B8AAA3`)
//! ```text
//! Blob ::= count:cu ( -baseline:cu { state:ci syntax-offset:cu }{count} )?
//! ```
//! The baseline is present only when the count is not zero.
//!
//! ## EmbeddedSource (`0E8A571B-6926-466E-B4AD-8AB04611F5FE`)
//! ```text
//! Blob ::= format:i32 content:u8*
//! ```
//! `format` 0 stores the source as it is; a positive `format` stores it deflated, `format`
//! being its inflated size; negative values are reserved. The file name is not in the blob:
//! it is the parent Document's.
//!
//! ## SourceLink (`CC110556-A091-4D38-9FEC-25AB9A351A6A`)
//! ```text
//! Blob ::= json:utf8
//! ```
//! The Source Link JSON, mapping document paths to URLs; there is no length prefix.
//!
//! ## CompilationMetadataReferences (`7E4D4708-096E-4C5C-AEDA-CB10BA6A740D`)
//! ```text
//! Blob ::= { file-name:utf8 NUL aliases:utf8 NUL flags:u8
//!            timestamp:u32 image-size:u32 mvid:guid }*
//! ```
//! `aliases` is comma-separated; `flags` bit 0 marks an assembly (not a module) and bit 1
//! embedded interop types.
//!
//! ## CompilationOptions (`B5FEEC05-8CD0-4A83-96DA-466284BB4BD8`)
//! ```text
//! Blob ::= { name:utf8 NUL value:utf8 NUL }*
//! ```
//!
//! ## TupleElementNames (`ED9FDF71-8879-4747-8ED3-FE5EDE3CE710`)
//! ```text
//! Blob ::= { name:utf8 NUL }*
//! ```
//! One name per tuple element in signature order; an empty name is an unnamed element.
//!
//! ## TypeDefinitionDocuments (`932E74BC-DBA9-4478-8D46-0F32A7BAB3D3`)
//! ```text
//! Blob ::= document-row:cu*
//! ```
//!
//! ## AsyncMethodSteppingInformation (`54FD2AC5-E925-401A-9C2A-F94F171072F8`)
//! ```text
//! Blob ::= catch-handler-offset+1:u32 { yield-offset:u32 resume-offset:u32 method-row:cu }*
//! ```
//! A stored catch handler of 0 means the method has none.
//!
//! ## PrimaryConstructorInformation (`9D40ACE1-C703-4D0E-BF41-7243060A8FB5`)
//! ```text
//! Blob ::= (empty)
//! ```
//!
//! # Usage Examples
//!
//! ## Decoding and encoding a blob
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{
//!     encode_custom_debug_blob, parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
//! };
//!
//! let blob = b"language\0CSharp\0compiler-version\04.12.0\0";
//! let info = parse_custom_debug_blob(blob, CustomDebugKind::CompilationOptions)?;
//! let CustomDebugInfo::CompilationOptions(options) = &info else {
//!     unreachable!()
//! };
//! assert_eq!(options[0], ("language".to_string(), "CSharp".to_string()));
//! assert_eq!(encode_custom_debug_blob(&info)?, blob);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Identifying a kind by its GUID
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::CustomDebugKind;
//!
//! let guid = uguid::guid!("CC110556-A091-4D38-9FEC-25AB9A351A6A");
//! assert_eq!(CustomDebugKind::from_guid(guid), CustomDebugKind::SourceLink);
//! assert_eq!(CustomDebugKind::SourceLink.guid(), guid);
//!
//! // A GUID no compiler defines keeps its blob
//! let other = uguid::guid!("01234567-89AB-CDEF-0123-456789ABCDEF");
//! assert_eq!(CustomDebugKind::from_guid(other), CustomDebugKind::Unknown(other));
//! ```
//!
//! ## Reading an assembly's custom debug information
//!
//! ```rust,no_run
//! use dotscope::{metadata::customdebuginformation::CustomDebugInfo, CilObject};
//!
//! let assembly = CilObject::from_path("tests/samples/pdb/embedded/PdbProbe.dll")?;
//! if let Some(pdb) = assembly.pdb() {
//!     for entry in pdb.custom_debug_information().iter() {
//!         match &entry.value().value {
//!             CustomDebugInfo::SourceLink(json) => println!("Source Link: {json}"),
//!             CustomDebugInfo::CompilationOptions(options) => {
//!                 for (name, value) in options {
//!                     println!("{name} = {value}");
//!                 }
//!             }
//!             other => println!("{:?}", other.kind()),
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Decoding returns [`crate::Error::Malformed`] for a blob that is not in its kind's format
//! (truncated, with trailing bytes, an out-of-range count or offset, or text that is not
//! UTF-8). An embedded source's content is checked only when it is read: its value holds the
//! stored bytes, and inflating them fails if they do not inflate to the size they state.
//!
//! # Thread Safety
//!
//! The values own their data and are [`Send`] and [`Sync`]; the functions are stateless and
//! can be called from any number of threads at once.
//!
//! # Integration
//!
//! - [`crate::metadata::tables::CustomDebugInformation`] - the table row holding a decoded value
//! - [`crate::metadata::pdb::PortablePdb`] - an assembly's PDB, with its rows by parent
//! - [`crate::metadata::pdb::guids`] - the kind, hash algorithm and language GUIDs
//!
//! # References
//!
//! - The Portable PDB v1.0 format specification: "CustomDebugInformation Table (0x37)" and
//!   "Language Specific Custom Debug Information Records"
//! - Roslyn's `PortableCustomDebugInfoKinds`, for the kinds the specification does not describe

mod parser;
mod types;

pub use parser::{encode_custom_debug_blob, parse_custom_debug_blob};
pub use types::{
    AsyncAwait, CustomDebugInfo, CustomDebugKind, EncLambda, EncLocalSlot, EncStateMachineState,
    HoistedLocalScope, MetadataReferenceInfo,
};

#[cfg(test)]
mod tests;

//! Owned `CustomDebugInformation` table representation for Portable PDB format.
//!
//! This module provides the [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] struct that represents
//! a fully resolved `CustomDebugInformation` table entry with all indices converted
//! to actual data for immediate use in debugging scenarios. The owned representation
//! enables direct access to custom debug information without requiring additional
//! heap lookups or index resolution.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformation`] - Main struct representing resolved custom debug information
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Clone`], enabling safe sharing
//! across threads and efficient copying when needed.

use uguid::Guid;

use crate::metadata::{
    customdebuginformation::CustomDebugInfo, token::Token, typesystem::CilTypeReference,
};

/// Owned representation of a `CustomDebugInformation` table entry (table `0x37`)
///
/// This structure holds a `CustomDebugInformation` row with its heap indices resolved: the
/// kind's GUID read from the `#GUID` heap, and the value's blob decoded by that kind.
/// Custom debug information carries debugging data beyond the standard Portable PDB tables,
/// recorded by compilers and tools under a GUID of their choosing.
///
/// # Custom Debug Information Kinds
///
/// The Kind column names a GUID that decides how the Value blob is read.
/// [`CustomDebugKind`](crate::metadata::customdebuginformation::CustomDebugKind) has a variant
/// for each kind the Portable PDB specification and the C#, Visual Basic and F# compilers
/// define, and the [module documentation](crate::metadata::customdebuginformation) gives each
/// blob's layout. They fall into these groups:
///
/// ## Source and Build Information
/// - **`{CC110556-A091-4D38-9FEC-25AB9A351A6A}`**: Source Link (Module)
///   JSON mapping document paths to the URLs their sources can be fetched from.
/// - **`{0E8A571B-6926-466E-B4AD-8AB04611F5FE}`**: Embedded Source (Document)
///   The document's source, stored as it is or deflated.
/// - **`{B5FEEC05-8CD0-4A83-96DA-466284BB4BD8}`**: Compilation Options (Module)
///   The compiler's name, version, language version and the options it was run with.
/// - **`{7E4D4708-096E-4C5C-AEDA-CB10BA6A740D}`**: Compilation Metadata References (Module)
///   Each assembly the module was compiled against, by name, time stamp, size and MVID.
/// - **`{58B2EAB6-209F-4E4E-A22C-B2D0F910C782}`**: Default Namespace (Module)
///   A Visual Basic project's root namespace.
/// - **`{932E74BC-DBA9-4478-8D46-0F32A7BAB3D3}`**: Type Definition Documents (TypeDef)
///   The documents of a type that has no method bodies to name them through sequence points.
///
/// ## Local Information
/// - **`{83C563C4-B4F3-47D5-B824-BA5441477EA8}`**: Dynamic Local Variables (LocalVariable,
///   LocalConstant) Which types in the local's type the source declared `dynamic`.
/// - **`{ED9FDF71-8879-4747-8ED3-FE5EDE3CE710}`**: Tuple Element Names (LocalVariable,
///   LocalConstant) The element names of the tuple types in the local's type.
///
/// ## State Machine Information
/// - **`{6DA9A61E-F8C7-4874-BE62-68BC5630DF71}`**: State Machine Hoisted Local Scopes (MethodDef)
///   The IL scope of each local an async method or iterator hoisted to a field.
/// - **`{54FD2AC5-E925-401A-9C2A-F94F171072F8}`**: Async Method Stepping Information (MethodDef)
///   The yield and resume offsets of each `await`, so a debugger can step over it.
///
/// ## Edit and Continue Information
/// - **`{755F52A8-91C5-45BE-B4B8-209571E552BD}`**: Local Slot Map (MethodDef)
///   The syntax that declared each local slot.
/// - **`{A643004C-0240-496F-A783-30D64F4979DE}`**: Lambda and Closure Map (MethodDef)
///   The syntax of each lambda and closure in the method.
/// - **`{8B78CD68-2EDE-420B-980B-E15884B8AAA3}`**: State Machine State Map (MethodDef)
///   The syntax each state of a state machine suspends at.
/// - **`{9D40ACE1-C703-4D0E-BF41-7243060A8FB5}`**: Primary Constructor Information (MethodDef)
///   Marks a C# primary constructor.
///
/// A GUID none of these name decodes to
/// [`CustomDebugInfo::Unknown`](crate::metadata::customdebuginformation::CustomDebugInfo::Unknown),
/// which keeps its blob.
///
/// # Parent Element
///
/// The Parent column names the entity the information is about through the
/// `HasCustomDebugInformation` coded index: any of the assembly's tables that
/// `HasCustomAttribute` names, and the PDB's Document, LocalScope, LocalVariable,
/// LocalConstant and ImportScope tables. [`parent`](Self::parent) resolves a parent in the
/// assembly's tables; [`parent_token`](Self::parent_token) names every parent, including one
/// in the PDB's own tables, and is what
/// [`PortablePdb::custom_debug_info_of`](crate::metadata::pdb::PortablePdb::custom_debug_info_of)
/// looks rows up by.
///
/// # Usage Examples
///
/// ```no_run
/// use dotscope::metadata::{customdebuginformation::CustomDebugInfo, tables::CustomDebugInformation};
///
/// fn describe(row: &CustomDebugInformation) {
///     match &row.value {
///         CustomDebugInfo::SourceLink(json) => println!("Source Link JSON: {json}"),
///         CustomDebugInfo::EmbeddedSource { .. } => match row.value.embedded_source_text() {
///             Some(Ok(text)) => println!("Embedded source: {} characters", text.len()),
///             Some(Err(e)) => println!("Embedded source that does not inflate: {e}"),
///             None => {}
///         },
///         CustomDebugInfo::CompilationOptions(options) => {
///             for (name, value) in options {
///                 println!("{name}: {value}");
///             }
///         }
///         CustomDebugInfo::Unknown { kind, data } => {
///             // Custom or newer kinds keep their blob
///             println!("Unknown debug info {kind}: {} bytes", data.len());
///         }
///         other => println!("{:?} on 0x{:08X}", other.kind(), row.parent_token.value()),
///     }
/// }
/// ```
///
/// # References
///
/// - Portable PDB v1.0: CustomDebugInformation Table (0x37)
/// - Portable PDB v1.0: Language Specific Custom Debug Information Records
#[derive(Clone)]
pub struct CustomDebugInformation {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this `CustomDebugInformation` entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// The parent, resolved in the assembly's tables (a method, type, field, the module,
    /// ...); [`CilTypeReference::None`] for a parent in the PDB's own tables, which
    /// [`parent_token`](Self::parent_token) names
    pub parent: CilTypeReference,

    /// The parent's token, as the row names it. [`parent`](Self::parent) resolves only the
    /// assembly's own tables, so a parent in the PDB's tables (a document, local scope,
    /// local variable or constant, or import scope) is known by this token alone.
    pub parent_token: Token,

    /// GUID identifying the type of custom debug information
    ///
    /// This GUID determines how the Value blob was read. Well-known GUIDs are defined by
    /// the Portable PDB specification and the compilers ([`crate::metadata::pdb::guids`]),
    /// and tools can define their own by choosing a new GUID.
    ///
    /// The GUID serves as both a type identifier and a versioning mechanism: when a format
    /// needs to change, a new GUID is defined rather than the existing format modified.
    pub kind: Guid,

    /// Parsed custom debug information data
    ///
    /// The Value blob decoded by [`kind`](Self::kind): the Source Link JSON, an embedded
    /// source (kept as stored, deflated or not, until its text is asked for), the
    /// compilation options and references, a method's Edit and Continue maps, a local's
    /// `dynamic` flags or tuple names, and so on. A kind dotscope does not know keeps its blob
    /// as [`CustomDebugInfo::Unknown`].
    ///
    /// Decoding happens when the row is loaded; a blob that is not in its kind's format fails
    /// the row.
    pub value: CustomDebugInfo,
}

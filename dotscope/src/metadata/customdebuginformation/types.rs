//! Custom debug information kinds and their decoded values.
//!
//! A CustomDebugInformation row's kind is a GUID and its value a blob in that kind's format.
//! This module holds the types the blobs decode to.
//!
//! # Architecture
//!
//! - **Kind identification**: [`CustomDebugKind`] has a variant per kind the Portable PDB
//!   specification and the C#, Visual Basic and F# compilers define, mapped to and from its
//!   GUID; any other GUID is [`CustomDebugKind::Unknown`], so a newer compiler's kinds are
//!   kept rather than refused
//! - **Typed values**: [`CustomDebugInfo`] has a variant per kind holding the blob's content
//!   as fields (offsets, names, flags), with nothing left to parse
//! - **Records**: the structs the variants hold a list of, one per record in the blob
//!
//! The values hold what the blob stores, as it stores it, so that encoding a value gives back
//! its blob: an embedded source keeps its deflated bytes, a closure ordinal keeps the
//! compilers' bias, and a missing catch handler is `None` rather than the stored 0.
//!
//! # Key Components
//!
//! - [`CustomDebugKind`] - a kind, by GUID, with [`CustomDebugKind::from_guid`] and
//!   [`CustomDebugKind::guid`]
//! - [`CustomDebugInfo`] - a decoded value, with [`CustomDebugInfo::kind`],
//!   [`CustomDebugInfo::is_known`], [`CustomDebugInfo::data_size`],
//!   [`CustomDebugInfo::was_compressed`] and [`CustomDebugInfo::is_dynamic`]
//! - [`HoistedLocalScope`], [`EncLocalSlot`], [`EncLambda`], [`EncStateMachineState`],
//!   [`MetadataReferenceInfo`], [`AsyncAwait`] - the records the values list
//!
//! # Supported Kinds
//!
//! | Kind | GUID | Parent |
//! |------|------|--------|
//! | StateMachineHoistedLocalScopes | `6DA9A61E-F8C7-4874-BE62-68BC5630DF71` | MethodDef (MoveNext) |
//! | DynamicLocalVariables | `83C563C4-B4F3-47D5-B824-BA5441477EA8` | LocalVariable, LocalConstant |
//! | DefaultNamespace | `58B2EAB6-209F-4E4E-A22C-B2D0F910C782` | Module |
//! | EncLocalSlotMap | `755F52A8-91C5-45BE-B4B8-209571E552BD` | MethodDef |
//! | EncLambdaAndClosureMap | `A643004C-0240-496F-A783-30D64F4979DE` | MethodDef |
//! | EncStateMachineStateMap | `8B78CD68-2EDE-420B-980B-E15884B8AAA3` | MethodDef |
//! | EmbeddedSource | `0E8A571B-6926-466E-B4AD-8AB04611F5FE` | Document |
//! | SourceLink | `CC110556-A091-4D38-9FEC-25AB9A351A6A` | Module |
//! | CompilationMetadataReferences | `7E4D4708-096E-4C5C-AEDA-CB10BA6A740D` | Module |
//! | CompilationOptions | `B5FEEC05-8CD0-4A83-96DA-466284BB4BD8` | Module |
//! | TupleElementNames | `ED9FDF71-8879-4747-8ED3-FE5EDE3CE710` | LocalVariable, LocalConstant |
//! | TypeDefinitionDocuments | `932E74BC-DBA9-4478-8D46-0F32A7BAB3D3` | TypeDef |
//! | AsyncMethodSteppingInformation | `54FD2AC5-E925-401A-9C2A-F94F171072F8` | MethodDef (MoveNext) |
//! | PrimaryConstructorInformation | `9D40ACE1-C703-4D0E-BF41-7243060A8FB5` | MethodDef |
//!
//! # Usage Examples
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{CustomDebugInfo, CustomDebugKind};
//!
//! fn describe(info: &CustomDebugInfo) -> String {
//!     match info {
//!         CustomDebugInfo::SourceLink(json) => format!("Source Link ({} bytes)", json.len()),
//!         CustomDebugInfo::TupleElementNames(names) => format!("{} tuple names", names.len()),
//!         CustomDebugInfo::Unknown { kind, data } => format!("{kind}: {} bytes", data.len()),
//!         other => format!("{:?}", other.kind()),
//!     }
//! }
//!
//! let info = CustomDebugInfo::DefaultNamespace("VbProbe.Root".to_string());
//! assert_eq!(info.kind(), CustomDebugKind::DefaultNamespace);
//! assert_eq!(describe(&info), "DefaultNamespace");
//! ```
//!
//! # Thread Safety
//!
//! Every type here owns its data and is [`Send`] and [`Sync`].
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: every kind the specification defines, with the GUID it gives
//! - **Compilers**: the kinds the C#, Visual Basic and F# compilers add, with Roslyn's GUIDs
//! - **Extensibility**: a GUID no one defines is kept, with its blob, rather than refused
//!
//! # Serialization
//!
//! [`CustomDebugKind`] and [`CustomDebugInfo`] implement [`std::fmt::Display`] for a short,
//! human-readable summary (the kind's name, and the value's size or count). The values encode
//! back to their blobs with
//! [`encode_custom_debug_blob`](crate::metadata::customdebuginformation::encode_custom_debug_blob);
//! Serde is not supported.
//!
//! # Integration
//!
//! - The parser module decodes blobs into these types and encodes them back
//! - [`crate::metadata::pdb::guids`] - the GUID constants the kinds map to
//! - [`crate::metadata::tables::CustomDebugInformation`] - the table row holding a value

use std::fmt;

use uguid::Guid;

use crate::{
    metadata::{customdebuginformation::encode_custom_debug_blob, pdb::guids},
    Result,
};

/// A custom debug information kind, identified by its GUID.
///
/// The GUID in a CustomDebugInformation row's Kind column decides how its Value blob is
/// read. Each variant is a kind the Portable PDB specification or the C#, Visual Basic and F#
/// compilers define; the entity each is attached to is given in brackets. A GUID no compiler
/// defines is [`CustomDebugKind::Unknown`], which keeps the GUID so that the row can be
/// written back unchanged.
///
/// # GUID Format
///
/// GUIDs are compared as values ([`uguid::Guid`]), not as their bytes in the `#GUID` heap,
/// so the variant constants match the textual GUIDs the specification gives. The heap stores
/// a GUID with its first three fields little-endian (`{CC110556-A091-...}` is stored
/// `56 05 11 CC 91 A0 ...`), which [`uguid::Guid::from_bytes`] and
/// [`uguid::Guid::to_bytes`] read and write.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::{customdebuginformation::CustomDebugKind, pdb::guids};
///
/// let kind = CustomDebugKind::from_guid(guids::EMBEDDED_SOURCE);
/// assert_eq!(kind, CustomDebugKind::EmbeddedSource);
/// assert_eq!(kind.guid(), guids::EMBEDDED_SOURCE);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustomDebugKind {
    /// The IL scopes of locals a state machine hoisted to fields (MethodDef)
    StateMachineHoistedLocalScopes,
    /// Which types in a local's type are `dynamic` (LocalVariable or LocalConstant)
    DynamicLocalVariables,
    /// A Visual Basic project's root namespace (Module)
    DefaultNamespace,
    /// Edit and Continue's map of local slots to syntax (MethodDef)
    EncLocalSlotMap,
    /// Edit and Continue's map of lambdas and closures to syntax (MethodDef)
    EncLambdaAndClosureMap,
    /// Edit and Continue's map of state machine states to syntax (MethodDef)
    EncStateMachineStateMap,
    /// A document's source, embedded (Document)
    EmbeddedSource,
    /// The Source Link JSON mapping documents to URLs (Module)
    SourceLink,
    /// The metadata references the module was compiled against (Module)
    CompilationMetadataReferences,
    /// The options the module was compiled with (Module)
    CompilationOptions,
    /// The element names of a local's tuple types (LocalVariable or LocalConstant)
    TupleElementNames,
    /// The documents of a type with no method bodies (TypeDef)
    TypeDefinitionDocuments,
    /// An async method's yield and resume offsets (MethodDef, the MoveNext method)
    AsyncMethodSteppingInformation,
    /// Marks a method as a primary constructor (MethodDef)
    PrimaryConstructorInformation,
    /// A kind dotscope does not know
    Unknown(Guid),
}

impl CustomDebugKind {
    /// Every kind dotscope knows, with its GUID: the one table both directions of the
    /// mapping read, so they cannot disagree.
    const KNOWN: [(Guid, CustomDebugKind); 14] = [
        (
            guids::STATE_MACHINE_HOISTED_LOCAL_SCOPES,
            Self::StateMachineHoistedLocalScopes,
        ),
        (guids::DYNAMIC_LOCAL_VARIABLES, Self::DynamicLocalVariables),
        (guids::DEFAULT_NAMESPACE, Self::DefaultNamespace),
        (guids::ENC_LOCAL_SLOT_MAP, Self::EncLocalSlotMap),
        (
            guids::ENC_LAMBDA_AND_CLOSURE_MAP,
            Self::EncLambdaAndClosureMap,
        ),
        (
            guids::ENC_STATE_MACHINE_STATE_MAP,
            Self::EncStateMachineStateMap,
        ),
        (guids::EMBEDDED_SOURCE, Self::EmbeddedSource),
        (guids::SOURCE_LINK, Self::SourceLink),
        (
            guids::COMPILATION_METADATA_REFERENCES,
            Self::CompilationMetadataReferences,
        ),
        (guids::COMPILATION_OPTIONS, Self::CompilationOptions),
        (guids::TUPLE_ELEMENT_NAMES, Self::TupleElementNames),
        (
            guids::TYPE_DEFINITION_DOCUMENTS,
            Self::TypeDefinitionDocuments,
        ),
        (
            guids::ASYNC_METHOD_STEPPING_INFORMATION,
            Self::AsyncMethodSteppingInformation,
        ),
        (
            guids::PRIMARY_CONSTRUCTOR_INFORMATION,
            Self::PrimaryConstructorInformation,
        ),
    ];

    /// The kind a GUID names.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID from a row's Kind column
    ///
    /// # Returns
    ///
    /// The kind's variant, or [`CustomDebugKind::Unknown`] holding `guid` for a GUID
    /// dotscope does not know.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugKind;
    ///
    /// let guid = uguid::guid!("54FD2AC5-E925-401A-9C2A-F94F171072F8");
    /// assert_eq!(
    ///     CustomDebugKind::from_guid(guid),
    ///     CustomDebugKind::AsyncMethodSteppingInformation
    /// );
    /// assert!(matches!(
    ///     CustomDebugKind::from_guid(uguid::Guid::ZERO),
    ///     CustomDebugKind::Unknown(_)
    /// ));
    /// ```
    #[must_use]
    pub fn from_guid(guid: Guid) -> Self {
        Self::KNOWN
            .iter()
            .find(|(known, _)| *known == guid)
            .map_or(CustomDebugKind::Unknown(guid), |(_, kind)| *kind)
    }

    /// The kind's GUID, as a row's Kind column names it.
    ///
    /// The inverse of [`CustomDebugKind::from_guid`]: for every GUID `g`,
    /// `CustomDebugKind::from_guid(g).guid() == g`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugKind;
    ///
    /// let kind = CustomDebugKind::TupleElementNames;
    /// assert_eq!(CustomDebugKind::from_guid(kind.guid()), kind);
    /// ```
    #[must_use]
    pub fn guid(&self) -> Guid {
        match self {
            CustomDebugKind::Unknown(guid) => *guid,
            known => Self::KNOWN
                .iter()
                .find(|(_, kind)| kind == known)
                .map_or(Guid::ZERO, |(guid, _)| *guid),
        }
    }
}

/// A hoisted local's IL scope: `[start, start + length)` of the MoveNext method.
///
/// An async method's or iterator's locals live in fields of its state machine, so they have no
/// local slot for a LocalScope to name. Each record of a StateMachineHoistedLocalScopes blob
/// gives the IL range of one hoisted field, in field order, so a debugger can show the local
/// only where it is in scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoistedLocalScope {
    /// The scope's first IL offset
    pub start: u32,
    /// The scope's length in IL bytes; 0 with `start` 0 for a local the compiler gave no scope
    pub length: u32,
}

/// A local slot in an Edit and Continue local slot map.
///
/// The map says which syntax declared each of a method's local slots, so that after an edit
/// the compiler can give a local the slot it had before and keep its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncLocalSlot {
    /// The 7-bit kind field: the C# and Visual Basic compilers write their synthesized local
    /// kind plus one (1 for a user-declared local)
    pub kind: u8,
    /// The distance of the declaring syntax from the method body's start (may be negative)
    pub syntax_offset: i32,
    /// Orders slots of the same syntax offset, when there are several
    pub ordinal: Option<u32>,
}

/// A lambda in an Edit and Continue lambda and closure map.
///
/// The map lets the compiler keep a lambda's generated method, and the closure holding its
/// captured variables, across an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncLambda {
    /// The distance of the lambda's syntax from the method body's start (may be negative)
    pub syntax_offset: i32,
    /// The closure field as written: the C# and Visual Basic compilers write the closure
    /// ordinal minus their minimum ordinal (-2), so 0 is a lambda capturing only `this`, 1 a
    /// static lambda, and 2 and up the closures in order
    pub closure: u32,
}

/// A state in an Edit and Continue state machine state map.
///
/// The map ties each suspension state of an async method or iterator to the `await` or
/// `yield` it suspends at, so a state machine suspended before an edit resumes at the same
/// point after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncStateMachineState {
    /// The state number
    pub state: i32,
    /// The distance of the state's syntax (an `await` or `yield`) from the method body's start
    pub syntax_offset: i32,
}

/// A metadata reference a module was compiled against.
///
/// A record of a CompilationMetadataReferences blob, which with the CompilationOptions blob
/// lets a tool rebuild the module from its sources and check it is identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataReferenceInfo {
    /// The referenced file's name, with its extension
    pub file_name: String,
    /// The reference's extern aliases
    pub aliases: Vec<String>,
    /// Flags: 1 an assembly (not a netmodule), 2 embed interop types
    pub flags: u8,
    /// The referenced file's PE time stamp
    pub timestamp: u32,
    /// The referenced file's SizeOfImage
    pub image_size: u32,
    /// The referenced module's MVID
    pub mvid: Guid,
}

/// An await in an async method's stepping information.
///
/// Lets a debugger step over an `await`: from the yield, where the state machine suspends,
/// to the offset where it resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncAwait {
    /// The IL offset of the yield (the await's suspension) in MoveNext
    pub yield_offset: u32,
    /// The IL offset execution resumes at
    pub resume_offset: u32,
    /// The row of the MethodDef the offsets are in (MoveNext)
    pub method: u32,
}

/// A custom debug information value, decoded by its kind.
///
/// Each variant holds the content of one kind's blob, as the blob stores it, so that
/// [`encode_custom_debug_blob`](crate::metadata::customdebuginformation::encode_custom_debug_blob)
/// writes it back unchanged. A kind dotscope does not know is [`CustomDebugInfo::Unknown`],
/// with its GUID and blob.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::{
///     parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
/// };
///
/// // An `async` method's stepping information: no catch handler, one await
/// let blob = [0, 0, 0, 0, 0x5A, 0, 0, 0, 0x79, 0, 0, 0, 0x1F];
/// match parse_custom_debug_blob(&blob, CustomDebugKind::AsyncMethodSteppingInformation)? {
///     CustomDebugInfo::AsyncMethodSteppingInformation { catch_handler, awaits } => {
///         assert_eq!(catch_handler, None);
///         assert_eq!(awaits[0].resume_offset, 0x79);
///     }
///     other => panic!("{other:?}"),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomDebugInfo {
    /// The IL scope of each hoisted local, in hoisted-field order
    StateMachineHoistedLocalScopes(Vec<HoistedLocalScope>),
    /// The `dynamic` flags as written: a bit per type in the local's type signature, in
    /// prefix order, least significant bit first; trailing zero bytes may be left out
    DynamicLocalVariables(Vec<u8>),
    /// The root namespace
    DefaultNamespace(String),
    /// The local slots, in local signature order; `None` for a slot recorded without syntax
    EncLocalSlotMap(Vec<Option<EncLocalSlot>>),
    /// The method's lambdas and closures
    EncLambdaAndClosureMap {
        /// The method's ordinal, -1 for none
        method_ordinal: i32,
        /// The syntax offset of each closure
        closures: Vec<i32>,
        /// The lambdas
        lambdas: Vec<EncLambda>,
    },
    /// The state machine's states, by syntax offset
    EncStateMachineStateMap(Vec<EncStateMachineState>),
    /// The document's source: its bytes as stored (`format` 0), or deflated to `format` bytes
    EmbeddedSource {
        /// 0 for the source as it is; positive for deflated, the inflated size
        format: i32,
        /// The source, or its deflated form
        content: Vec<u8>,
    },
    /// The Source Link JSON
    SourceLink(String),
    /// The metadata references
    CompilationMetadataReferences(Vec<MetadataReferenceInfo>),
    /// The compilation options, `(name, value)` in blob order
    CompilationOptions(Vec<(String, String)>),
    /// The tuple element names in signature order; `None` for an unnamed element
    TupleElementNames(Vec<Option<String>>),
    /// The type's documents, as Document rows
    TypeDefinitionDocuments(Vec<u32>),
    /// An async method's stepping information
    AsyncMethodSteppingInformation {
        /// The IL offset of the method's catch handler, when it has one
        catch_handler: Option<u32>,
        /// The method's awaits
        awaits: Vec<AsyncAwait>,
    },
    /// A primary constructor (the blob is empty)
    PrimaryConstructorInformation,
    /// A kind dotscope does not know, with its blob as it is
    Unknown {
        /// The kind
        kind: Guid,
        /// The blob
        data: Vec<u8>,
    },
}

impl CustomDebugInfo {
    /// The kind of this value: the kind whose blob it decodes from and encodes to.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::{CustomDebugInfo, CustomDebugKind};
    ///
    /// assert_eq!(
    ///     CustomDebugInfo::PrimaryConstructorInformation.kind(),
    ///     CustomDebugKind::PrimaryConstructorInformation
    /// );
    /// ```
    #[must_use]
    pub fn kind(&self) -> CustomDebugKind {
        match self {
            CustomDebugInfo::StateMachineHoistedLocalScopes(_) => {
                CustomDebugKind::StateMachineHoistedLocalScopes
            }
            CustomDebugInfo::DynamicLocalVariables(_) => CustomDebugKind::DynamicLocalVariables,
            CustomDebugInfo::DefaultNamespace(_) => CustomDebugKind::DefaultNamespace,
            CustomDebugInfo::EncLocalSlotMap(_) => CustomDebugKind::EncLocalSlotMap,
            CustomDebugInfo::EncLambdaAndClosureMap { .. } => {
                CustomDebugKind::EncLambdaAndClosureMap
            }
            CustomDebugInfo::EncStateMachineStateMap(_) => CustomDebugKind::EncStateMachineStateMap,
            CustomDebugInfo::EmbeddedSource { .. } => CustomDebugKind::EmbeddedSource,
            CustomDebugInfo::SourceLink(_) => CustomDebugKind::SourceLink,
            CustomDebugInfo::CompilationMetadataReferences(_) => {
                CustomDebugKind::CompilationMetadataReferences
            }
            CustomDebugInfo::CompilationOptions(_) => CustomDebugKind::CompilationOptions,
            CustomDebugInfo::TupleElementNames(_) => CustomDebugKind::TupleElementNames,
            CustomDebugInfo::TypeDefinitionDocuments(_) => CustomDebugKind::TypeDefinitionDocuments,
            CustomDebugInfo::AsyncMethodSteppingInformation { .. } => {
                CustomDebugKind::AsyncMethodSteppingInformation
            }
            CustomDebugInfo::PrimaryConstructorInformation => {
                CustomDebugKind::PrimaryConstructorInformation
            }
            CustomDebugInfo::Unknown { kind, .. } => CustomDebugKind::Unknown(*kind),
        }
    }

    /// Whether the `index`th type in a local's type signature is `dynamic`.
    ///
    /// Reads the flag bits of [`CustomDebugInfo::DynamicLocalVariables`]; a bit past the
    /// stored bytes is clear, since trailing zero bytes may be left out.
    ///
    /// # Arguments
    ///
    /// * `index` - The type's position in a prefix walk of the local's type signature, the
    ///   order `DynamicAttribute`'s flags use: for `dynamic[]`, the array type is position 0
    ///   and its element type position 1
    ///
    /// # Returns
    ///
    /// Whether that type is an `object` declared `dynamic`; `false` for any other kind.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugInfo;
    ///
    /// // `dynamic[] values`
    /// let flags = CustomDebugInfo::DynamicLocalVariables(vec![0b10]);
    /// assert!(!flags.is_dynamic(0) && flags.is_dynamic(1) && !flags.is_dynamic(40));
    /// ```
    #[must_use]
    pub fn is_dynamic(&self, index: usize) -> bool {
        match self {
            CustomDebugInfo::DynamicLocalVariables(bits) => bits
                .get(index / 8)
                .is_some_and(|byte| byte & (1 << (index % 8)) != 0),
            _ => false,
        }
    }

    /// Check if this is a known debug information type.
    ///
    /// # Returns
    ///
    /// `true` for a kind dotscope decodes, `false` for [`CustomDebugInfo::Unknown`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugInfo;
    ///
    /// assert!(CustomDebugInfo::SourceLink(String::new()).is_known());
    /// let unknown = CustomDebugInfo::Unknown {
    ///     kind: uguid::Guid::ZERO,
    ///     data: vec![1, 2, 3],
    /// };
    /// assert!(!unknown.is_known());
    /// ```
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, CustomDebugInfo::Unknown { .. })
    }

    /// Get the size of the debug data in bytes: the length of the blob the value is stored
    /// as, which for a decoded value is the length of the blob it was read from.
    ///
    /// # Errors
    ///
    /// As [`encode_custom_debug_blob`], for a value that cannot be written in its format.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugInfo;
    ///
    /// let names = CustomDebugInfo::TupleElementNames(vec![Some("a".to_string()), None]);
    /// assert_eq!(names.data_size()?, 3); // "a\0" and "\0"
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn data_size(&self) -> Result<usize> {
        Ok(encode_custom_debug_blob(self)?.len())
    }

    /// Check if this embedded source was compressed in the original blob.
    ///
    /// # Returns
    ///
    /// - `Some(true)` if this is `EmbeddedSource` and its content is deflated (a positive
    ///   format)
    /// - `Some(false)` if this is `EmbeddedSource` and its content is stored as it is
    /// - `None` if this is not an `EmbeddedSource` variant
    #[must_use]
    pub fn was_compressed(&self) -> Option<bool> {
        match self {
            CustomDebugInfo::EmbeddedSource { format, .. } => Some(*format > 0),
            _ => None,
        }
    }
}

impl fmt::Display for CustomDebugKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomDebugKind::Unknown(guid) => write!(f, "Unknown({guid})"),
            known => write!(f, "{known:?}"),
        }
    }
}

impl fmt::Display for CustomDebugInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomDebugInfo::StateMachineHoistedLocalScopes(scopes) => {
                write!(f, "StateMachineHoistedLocalScopes({} scopes)", scopes.len())
            }
            CustomDebugInfo::DynamicLocalVariables(flags) => {
                write!(f, "DynamicLocalVariables({} flag bytes)", flags.len())
            }
            CustomDebugInfo::DefaultNamespace(namespace) => {
                write!(f, "DefaultNamespace('{namespace}')")
            }
            CustomDebugInfo::EncLocalSlotMap(slots) => {
                write!(f, "EncLocalSlotMap({} slots)", slots.len())
            }
            CustomDebugInfo::EncLambdaAndClosureMap {
                closures, lambdas, ..
            } => write!(
                f,
                "EncLambdaAndClosureMap({} closures, {} lambdas)",
                closures.len(),
                lambdas.len()
            ),
            CustomDebugInfo::EncStateMachineStateMap(states) => {
                write!(f, "EncStateMachineStateMap({} states)", states.len())
            }
            CustomDebugInfo::EmbeddedSource { format, content } => {
                if *format > 0 {
                    write!(
                        f,
                        "EmbeddedSource({} bytes, compressed from {format})",
                        content.len()
                    )
                } else {
                    write!(f, "EmbeddedSource({} bytes, uncompressed)", content.len())
                }
            }
            CustomDebugInfo::SourceLink(json) => write!(f, "SourceLink({} bytes)", json.len()),
            CustomDebugInfo::CompilationMetadataReferences(references) => write!(
                f,
                "CompilationMetadataReferences({} references)",
                references.len()
            ),
            CustomDebugInfo::CompilationOptions(options) => {
                write!(f, "CompilationOptions({} options)", options.len())
            }
            CustomDebugInfo::TupleElementNames(names) => {
                write!(f, "TupleElementNames({} elements)", names.len())
            }
            CustomDebugInfo::TypeDefinitionDocuments(documents) => {
                write!(f, "TypeDefinitionDocuments({} documents)", documents.len())
            }
            CustomDebugInfo::AsyncMethodSteppingInformation { awaits, .. } => {
                write!(f, "AsyncMethodSteppingInformation({} awaits)", awaits.len())
            }
            CustomDebugInfo::PrimaryConstructorInformation => {
                write!(f, "PrimaryConstructorInformation")
            }
            CustomDebugInfo::Unknown { kind, data } => {
                write!(f, "Unknown({kind}, {} bytes)", data.len())
            }
        }
    }
}

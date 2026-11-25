//! The GUIDs a Portable PDB names things by: custom debug information kinds, document hash
//! algorithms and source languages.
//!
//! The kinds are the ones the Portable PDB specification and the C#, Visual Basic and F#
//! compilers define (Roslyn's `PortableCustomDebugInfoKinds`).

use uguid::{guid, Guid};

/// `{6DA9A61E-F8C7-4874-BE62-68BC5630DF71}`: the IL scopes of locals hoisted to a state
/// machine's fields.
pub const STATE_MACHINE_HOISTED_LOCAL_SCOPES: Guid = guid!("6DA9A61E-F8C7-4874-BE62-68BC5630DF71");
/// `{83C563C4-B4F3-47D5-B824-BA5441477EA8}`: which `object`s in a local's type are `dynamic`.
pub const DYNAMIC_LOCAL_VARIABLES: Guid = guid!("83C563C4-B4F3-47D5-B824-BA5441477EA8");
/// `{58B2EAB6-209F-4E4E-A22C-B2D0F910C782}`: a Visual Basic project's root namespace.
pub const DEFAULT_NAMESPACE: Guid = guid!("58B2EAB6-209F-4E4E-A22C-B2D0F910C782");
/// `{755F52A8-91C5-45BE-B4B8-209571E552BD}`: Edit and Continue's map of local slots to syntax.
pub const ENC_LOCAL_SLOT_MAP: Guid = guid!("755F52A8-91C5-45BE-B4B8-209571E552BD");
/// `{A643004C-0240-496F-A783-30D64F4979DE}`: Edit and Continue's map of lambdas and closures.
pub const ENC_LAMBDA_AND_CLOSURE_MAP: Guid = guid!("A643004C-0240-496F-A783-30D64F4979DE");
/// `{8B78CD68-2EDE-420B-980B-E15884B8AAA3}`: Edit and Continue's map of state machine states.
pub const ENC_STATE_MACHINE_STATE_MAP: Guid = guid!("8B78CD68-2EDE-420B-980B-E15884B8AAA3");
/// `{0E8A571B-6926-466E-B4AD-8AB04611F5FE}`: a document's source, embedded.
pub const EMBEDDED_SOURCE: Guid = guid!("0E8A571B-6926-466E-B4AD-8AB04611F5FE");
/// `{CC110556-A091-4D38-9FEC-25AB9A351A6A}`: the Source Link JSON mapping documents to URLs.
pub const SOURCE_LINK: Guid = guid!("CC110556-A091-4D38-9FEC-25AB9A351A6A");
/// `{7E4D4708-096E-4C5C-AEDA-CB10BA6A740D}`: the metadata references a module was compiled
/// against.
pub const COMPILATION_METADATA_REFERENCES: Guid = guid!("7E4D4708-096E-4C5C-AEDA-CB10BA6A740D");
/// `{B5FEEC05-8CD0-4A83-96DA-466284BB4BD8}`: the options a module was compiled with.
pub const COMPILATION_OPTIONS: Guid = guid!("B5FEEC05-8CD0-4A83-96DA-466284BB4BD8");
/// `{ED9FDF71-8879-4747-8ED3-FE5EDE3CE710}`: the element names of a local's tuple types.
pub const TUPLE_ELEMENT_NAMES: Guid = guid!("ED9FDF71-8879-4747-8ED3-FE5EDE3CE710");
/// `{932E74BC-DBA9-4478-8D46-0F32A7BAB3D3}`: the documents of a type with no method bodies.
pub const TYPE_DEFINITION_DOCUMENTS: Guid = guid!("932E74BC-DBA9-4478-8D46-0F32A7BAB3D3");
/// `{54FD2AC5-E925-401A-9C2A-F94F171072F8}`: an async method's yield and resume offsets.
pub const ASYNC_METHOD_STEPPING_INFORMATION: Guid = guid!("54FD2AC5-E925-401A-9C2A-F94F171072F8");
/// `{9D40ACE1-C703-4D0E-BF41-7243060A8FB5}`: marks a method as a primary constructor.
pub const PRIMARY_CONSTRUCTOR_INFORMATION: Guid = guid!("9D40ACE1-C703-4D0E-BF41-7243060A8FB5");

/// `{FF1816EC-AA5E-4D10-87F7-6F4963833460}`: a document hashed with SHA-1.
pub const HASH_SHA1: Guid = guid!("FF1816EC-AA5E-4D10-87F7-6F4963833460");
/// `{8829D00F-11B8-4213-878B-770E8597AC16}`: a document hashed with SHA-256.
pub const HASH_SHA256: Guid = guid!("8829D00F-11B8-4213-878B-770E8597AC16");

/// `{3F5162F8-07C6-11D3-9053-00C04FA302A1}`: a C# document.
pub const LANGUAGE_CSHARP: Guid = guid!("3F5162F8-07C6-11D3-9053-00C04FA302A1");
/// `{3A12D0B8-C26C-11D0-B442-00A0244A1DD2}`: a Visual Basic document.
pub const LANGUAGE_VISUAL_BASIC: Guid = guid!("3A12D0B8-C26C-11D0-B442-00A0244A1DD2");
/// `{AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3}`: an F# document.
pub const LANGUAGE_FSHARP: Guid = guid!("AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3");

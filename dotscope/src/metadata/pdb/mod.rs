//! Portable PDB: the debug information .NET compilers write, as a standalone `.pdb` file or
//! embedded in the image.
//!
//! A Portable PDB maps an assembly's IL back to its source: which document and line each IL
//! offset came from (sequence points), the names and scopes of locals, the values of
//! constants, the namespaces each scope imports, which methods are state machines, and the
//! compilers' custom debug information (Source Link, embedded sources, compilation options,
//! Edit and Continue maps, ...).
//!
//! # Architecture
//!
//! A Portable PDB is ECMA-335 metadata of its own: a metadata root, a `#Pdb` stream
//! ([`PdbStream`]), a tables stream holding only the debug tables (Document,
//! MethodDebugInformation, LocalScope, LocalVariable, LocalConstant, ImportScope,
//! StateMachineMethod and CustomDebugInformation, tables `0x30` to `0x37`) and its own
//! `#Strings`, `#Blob` and `#GUID` heaps. Its columns that index the assembly's tables (a
//! method, a type, the module) are sized by the assembly's row counts, which the `#Pdb`
//! stream records, so a PDB can only be read against the image it was written for.
//!
//! ## Where the PDB comes from
//!
//! - **Embedded**: the image's debug directory holds the PDB deflated
//!   (`EMBEDDED_PORTABLE_PDB`, `MPDB`, its size, then the deflate stream), as
//!   `<DebugType>embedded</DebugType>` writes it
//! - **Standalone**: a `.pdb` file beside the image, which its CodeView debug directory entry
//!   names by path and identity
//! - **In-image**: the debug tables in the image's own metadata, with its heaps (tools that
//!   write debug information into the assembly itself)
//!
//! Every [`CilObject`](crate::CilObject) load reads the embedded PDB, or else the image's own
//! debug tables, as [`PortablePdb`] ([`CilObject::pdb`](crate::CilObject::pdb)). A standalone
//! PDB is never looked for on disk: [`CilObject::with_pdb`](crate::CilObject::with_pdb)
//! attaches one. The loaders that read the debug tables resolve the methods and types they
//! name in the assembly that was loaded, so a sequence point's method is the assembly's
//! [`Method`](crate::metadata::method::Method).
//!
//! # Key Components
//!
//! - [`PortablePdb`] - an assembly's PDB, with every table decoded and queries by method,
//!   document and parent
//! - [`PdbOrigin`] - where the PDB was read from
//! - [`PdbMetadata`] - a PDB's metadata read from its bytes: root, `#Pdb` stream, tables and
//!   heaps
//! - [`embedded_portable_pdb`] - the PDB an image embeds, inflated no further than its size
//! - [`codeview_pdb_id`] - the identity of the PDB an image was built with
//! - [`LocalConstantSig`] - a constant local's type and value
//! - [`document_name`] - a Document's path from its DocumentNameBlob
//! - [`guids`] - the custom debug information kind, hash algorithm and language GUIDs
//!
//! # Usage Examples
//!
//! ## Reading an assembly's debug information
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/pdb/embedded/PdbProbe.dll")?;
//! let Some(pdb) = assembly.pdb() else {
//!     return Ok(());
//! };
//! for entry in assembly.methods().iter() {
//!     let method = entry.value();
//!     if let Some(points) = pdb.sequence_points(method.token) {
//!         println!("{}: {} sequence points", method.name, points.points.len());
//!     }
//!     for scope in pdb.method_scopes(method.token) {
//!         println!("  scope at IL_{:04X}, {} bytes", scope.start_offset, scope.length);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Attaching a standalone PDB
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/pdb/portable/PdbProbe.dll")?
//!     .with_pdb("tests/samples/pdb/portable/PdbProbe.pdb")?;
//! let pdb = assembly.pdb().expect("the PDB is attached");
//! for entry in pdb.documents().iter() {
//!     let document = entry.value();
//!     match pdb.embedded_source(document.rid) {
//!         Some(Ok(text)) => println!("{}: {} lines embedded", document.name, text.lines().count()),
//!         Some(Err(e)) => println!("{}: embedded source does not inflate: {e}", document.name),
//!         None => println!("{}: not embedded", document.name),
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Reading PDB metadata directly
//!
//! ```rust,no_run
//! use dotscope::metadata::{pdb::PdbMetadata, tables::TableId};
//!
//! let data = std::fs::read("tests/samples/pdb/portable/PdbProbe.pdb")?;
//! let pdb = PdbMetadata::read(&data)?;
//! println!("entry point: {:?}", pdb.pdb_stream.entry_point);
//! if let Some(tables) = &pdb.tables {
//!     println!("{} documents", tables.table_row_count(TableId::Document));
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The runtime never reads debug information to load an assembly, so the PDB the image
//! carries never fails a load: an embedded PDB that does not inflate or was written for
//! another image, and a malformed row in it or in the image's own debug tables, are
//! [diagnostics](crate::metadata::diagnostics) and the rest of the PDB is read. A standalone
//! PDB is something the caller asked for, so it is read in the load's mode: in strict mode
//! the same faults fail the load. A PDB whose identity is not the one the image names (a PDB
//! of another build) is read with a diagnostic, since its rows are well-formed; one whose
//! row counts differ is refused, since its columns cannot be read against this image.
//!
//! # Thread Safety
//!
//! [`PortablePdb`] is [`Send`] and [`Sync`]: its maps are lock-free skip lists filled once
//! while the assembly loads and only read afterwards.
//!
//! # References
//!
//! - The Portable PDB v1.0 format specification
//! - ECMA-335, Partition II, sections 24 (metadata physical layout) and 23.2 (blobs)
//! - The PE format's debug directory: `IMAGE_DEBUG_TYPE_CODEVIEW` and
//!   `IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB`

mod constant;
mod document;
pub mod guids;

pub use constant::{GeneralValue, LocalConstantSig, LocalConstantValue, PrimitiveConstant};
pub use document::{document_name, split_document_name, DocumentNameBlob};

use std::{collections::HashMap, fmt, io::Read, sync::OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    file::{debug::debug_type, File},
    metadata::{
        customdebuginformation::CustomDebugInfo,
        root::Root,
        sequencepoints::SequencePoints,
        streams::{Blob, Guid, PdbStream, Strings, TablesHeader},
        tables::{
            CustomDebugInformationMap, CustomDebugInformationRc, DocumentMap, DocumentRc,
            ImportScopeMap, LocalConstantMap, LocalScopeMap, LocalScopeRc, LocalVariableMap,
            MethodDebugInformationMap, MethodDebugInformationRc, StateMachineMethodMap, TableId,
        },
        token::Token,
    },
    utils::read_le_at,
    Result,
};

/// The signature an embedded Portable PDB's debug data starts with (`MPDB`).
const EMBEDDED_PDB_SIGNATURE: u32 = 0x4244_504D;

/// The signature a CodeView record starts with (`RSDS`).
const CODEVIEW_SIGNATURE: u32 = 0x5344_5352;

/// The minor version of a CodeView debug directory entry that names a Portable PDB (`PM`).
const PORTABLE_CODEVIEW_MINOR_VERSION: u16 = 0x504D;

/// The Portable PDB's tables, in table order.
pub(crate) const PDB_TABLES: [TableId; 8] = [
    TableId::Document,
    TableId::MethodDebugInformation,
    TableId::LocalScope,
    TableId::LocalVariable,
    TableId::LocalConstant,
    TableId::ImportScope,
    TableId::StateMachineMethod,
    TableId::CustomDebugInformation,
];

/// Where an assembly's Portable PDB was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbOrigin {
    /// The debug tables in the image's own metadata
    InImage,
    /// The PDB the image embeds in its debug directory
    Embedded,
    /// A standalone `.pdb` file attached to the assembly
    Standalone,
}

impl fmt::Display for PdbOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbOrigin::InImage => write!(f, "in-image"),
            PdbOrigin::Embedded => write!(f, "embedded"),
            PdbOrigin::Standalone => write!(f, "standalone"),
        }
    }
}

/// An assembly's Portable PDB: its debug tables, each row decoded, and the `#Pdb` stream's
/// identity and entry point when the PDB has one.
///
/// [`CilObject::pdb`](crate::CilObject::pdb) gives an assembly's. Each table is a map keyed by
/// its rows' tokens (tables `0x30` to `0x37`), holding the owned rows with their heap values
/// decoded and the assembly's methods and types they name resolved:
///
/// - **Documents**: each source file's path, language and hash
/// - **Method debug information**: one row per MethodDef, same rid, with its sequence points
/// - **Local scopes**: a method's IL ranges, each with its variables, constants and imports
/// - **Local variables and constants**: names, slots, and the constants' types and values
/// - **Import scopes**: the namespaces, types and aliases each scope imports
/// - **State machine methods**: each async or iterator MoveNext with its kickoff method
/// - **Custom debug information**: every row decoded by its kind
///
/// The queries ([`method_debug_info`](Self::method_debug_info),
/// [`sequence_points`](Self::sequence_points), [`method_scopes`](Self::method_scopes),
/// [`custom_debug_info_of`](Self::custom_debug_info_of),
/// [`embedded_source`](Self::embedded_source)) look rows up by what a debugger asks for.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{metadata::customdebuginformation::CustomDebugInfo, CilObject};
///
/// let assembly = CilObject::from_path("tests/samples/pdb/embedded/PdbProbe.dll")?;
/// let pdb = assembly.pdb().expect("the image embeds a PDB");
/// let module = assembly.module().expect("an assembly has a module").token;
/// for info in pdb.custom_debug_info_of(module) {
///     if let CustomDebugInfo::SourceLink(json) = &info.value {
///         println!("Source Link: {json}");
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct PortablePdb {
    pub(crate) origin: PdbOrigin,
    pub(crate) pdb_stream: Option<PdbStream>,
    pub(crate) documents: DocumentMap,
    pub(crate) method_debug_information: MethodDebugInformationMap,
    pub(crate) local_scopes: LocalScopeMap,
    pub(crate) local_variables: LocalVariableMap,
    pub(crate) local_constants: LocalConstantMap,
    pub(crate) import_scopes: ImportScopeMap,
    pub(crate) state_machine_methods: StateMachineMethodMap,
    pub(crate) custom_debug_information: CustomDebugInformationMap,
    /// Each method's local scopes, in table order, built on the first query
    scopes_by_method: OnceLock<HashMap<Token, Vec<LocalScopeRc>>>,
    /// The custom debug information attached to each parent, in table order, built on the
    /// first query
    custom_debug_info_by_parent: OnceLock<HashMap<Token, Vec<CustomDebugInformationRc>>>,
}

impl PortablePdb {
    /// An empty PDB of `origin`, its `#Pdb` stream `pdb_stream`, for the loaders to fill.
    pub(crate) fn new(origin: PdbOrigin, pdb_stream: Option<PdbStream>) -> Self {
        PortablePdb {
            origin,
            pdb_stream,
            documents: SkipMap::new(),
            method_debug_information: SkipMap::new(),
            local_scopes: SkipMap::new(),
            local_variables: SkipMap::new(),
            local_constants: SkipMap::new(),
            import_scopes: SkipMap::new(),
            state_machine_methods: SkipMap::new(),
            custom_debug_information: SkipMap::new(),
            scopes_by_method: OnceLock::new(),
            custom_debug_info_by_parent: OnceLock::new(),
        }
    }

    /// Where the PDB was read from.
    #[must_use]
    pub fn origin(&self) -> PdbOrigin {
        self.origin
    }

    /// The PDB's identity (the GUID and stamp the image's CodeView entry names); `None` for
    /// debug tables in the image's own metadata, which have no `#Pdb` stream.
    #[must_use]
    pub fn id(&self) -> Option<[u8; 20]> {
        self.pdb_stream.as_ref().map(|stream| stream.id)
    }

    /// The entry point's MethodDef token the `#Pdb` stream records.
    #[must_use]
    pub fn entry_point(&self) -> Option<Token> {
        self.pdb_stream
            .as_ref()
            .and_then(|stream| stream.entry_point)
    }

    /// The `#Pdb` stream, when the PDB has one.
    #[must_use]
    pub fn pdb_stream(&self) -> Option<&PdbStream> {
        self.pdb_stream.as_ref()
    }

    /// The Document rows: each source file, its language and hash.
    #[must_use]
    pub fn documents(&self) -> &DocumentMap {
        &self.documents
    }

    /// The MethodDebugInformation rows, one per MethodDef row, in its order.
    #[must_use]
    pub fn method_debug_information(&self) -> &MethodDebugInformationMap {
        &self.method_debug_information
    }

    /// The LocalScope rows.
    #[must_use]
    pub fn local_scopes(&self) -> &LocalScopeMap {
        &self.local_scopes
    }

    /// The LocalVariable rows.
    #[must_use]
    pub fn local_variables(&self) -> &LocalVariableMap {
        &self.local_variables
    }

    /// The LocalConstant rows, each with its type and value.
    #[must_use]
    pub fn local_constants(&self) -> &LocalConstantMap {
        &self.local_constants
    }

    /// The ImportScope rows, each with its imports.
    #[must_use]
    pub fn import_scopes(&self) -> &ImportScopeMap {
        &self.import_scopes
    }

    /// The StateMachineMethod rows: each MoveNext method with its kickoff method.
    #[must_use]
    pub fn state_machine_methods(&self) -> &StateMachineMethodMap {
        &self.state_machine_methods
    }

    /// The CustomDebugInformation rows, each decoded by its kind.
    #[must_use]
    pub fn custom_debug_information(&self) -> &CustomDebugInformationMap {
        &self.custom_debug_information
    }

    /// The document of row `rid`.
    #[must_use]
    pub fn document(&self, rid: u32) -> Option<DocumentRc> {
        self.documents
            .get(&Token::from_parts(TableId::Document, rid))
            .map(|entry| entry.value().clone())
    }

    /// A method's debug information: the MethodDebugInformation row of the same rid as its
    /// MethodDef `method`; `None` for a token of another table.
    #[must_use]
    pub fn method_debug_info(&self, method: Token) -> Option<MethodDebugInformationRc> {
        if method.table() != TableId::MethodDef as u8 {
            return None;
        }
        self.method_debug_information
            .get(&Token::from_parts(
                TableId::MethodDebugInformation,
                method.row(),
            ))
            .map(|entry| entry.value().clone())
    }

    /// A method's sequence points, when it has any.
    ///
    /// # Arguments
    ///
    /// * `method` - The method's MethodDef token
    ///
    /// # Returns
    ///
    /// The sequence points of the method's MethodDebugInformation row, mapping its IL offsets
    /// to document lines and columns; `None` for a method without a row or without sequence
    /// points (an abstract method, or one the compiler gave no source for).
    #[must_use]
    pub fn sequence_points(&self, method: Token) -> Option<SequencePoints> {
        self.method_debug_info(method)
            .and_then(|info| info.sequence_points.clone())
    }

    /// A method's local scopes, outermost first.
    ///
    /// The LocalScope table is sorted by method, then by start offset ascending and length
    /// descending, so the scopes come in nesting order. The first query indexes the scopes by
    /// method, so each query after it is a lookup.
    ///
    /// # Arguments
    ///
    /// * `method` - The method's MethodDef token
    #[must_use]
    pub fn method_scopes(&self, method: Token) -> Vec<LocalScopeRc> {
        self.scopes_by_method
            .get_or_init(|| {
                let mut index: HashMap<Token, Vec<LocalScopeRc>> = HashMap::new();
                for entry in &self.local_scopes {
                    let scope = entry.value();
                    index
                        .entry(scope.method.token)
                        .or_default()
                        .push(scope.clone());
                }
                index
            })
            .get(&method)
            .cloned()
            .unwrap_or_default()
    }

    /// The custom debug information attached to `parent`.
    ///
    /// # Arguments
    ///
    /// * `parent` - A token of any table the HasCustomDebugInformation coded index names: a
    ///   method, type or field, the module or assembly, or one of the PDB's own rows (a
    ///   document, local scope, local variable or constant, or import scope)
    ///
    /// # Returns
    ///
    /// The rows whose parent is `parent`, in table order; none when nothing is attached. The
    /// first query indexes the rows by parent, so each query after it is a lookup.
    #[must_use]
    pub fn custom_debug_info_of(&self, parent: Token) -> Vec<CustomDebugInformationRc> {
        self.custom_debug_info_by_parent
            .get_or_init(|| {
                let mut index: HashMap<Token, Vec<CustomDebugInformationRc>> = HashMap::new();
                for entry in &self.custom_debug_information {
                    let info = entry.value();
                    index
                        .entry(info.parent_token)
                        .or_default()
                        .push(info.clone());
                }
                index
            })
            .get(&parent)
            .cloned()
            .unwrap_or_default()
    }

    /// A document's embedded source text, when the PDB embeds it.
    ///
    /// The text is inflated on each call, no further than the size the blob states; nothing
    /// is inflated while the assembly loads.
    ///
    /// # Arguments
    ///
    /// * `document` - The document's Document row
    ///
    /// # Returns
    ///
    /// `None` when the PDB does not embed the document's source; otherwise its text, or the
    /// reason it cannot be read.
    ///
    /// # Errors
    ///
    /// The inner result is an error as [`CustomDebugInfo::embedded_source_text`] gives one.
    pub fn embedded_source(&self, document: u32) -> Option<Result<String>> {
        self.custom_debug_info_of(Token::from_parts(TableId::Document, document))
            .iter()
            .find_map(|info| match &info.value {
                source @ CustomDebugInfo::EmbeddedSource { .. } => source.embedded_source_text(),
                _ => None,
            })
    }
}

/// A Portable PDB's metadata, read from the bytes it borrows.
///
/// The physical layer of a PDB: its streams located and parsed, its tables sized by the row
/// counts its `#Pdb` stream records. [`CilObject`](crate::CilObject) loads build a
/// [`PortablePdb`] from it; reading it directly gives the raw rows, as
/// [`TablesHeader::table`] does for an assembly's tables.
pub struct PdbMetadata<'a> {
    /// The metadata root
    pub root: Root,
    /// The `#Pdb` stream: identity, entry point, and the assembly tables' row counts
    pub pdb_stream: PdbStream,
    /// The debug tables, when the PDB has a tables stream
    pub tables: Option<TablesHeader<'a>>,
    /// The `#Strings` heap
    pub strings: Option<Strings<'a>>,
    /// The `#Blob` heap
    pub blobs: Option<Blob<'a>>,
    /// The `#GUID` heap
    pub guids: Option<Guid<'a>>,
}

impl<'a> PdbMetadata<'a> {
    /// Reads a Portable PDB's metadata: a standalone `.pdb` file's bytes, or an embedded PDB
    /// as [`embedded_portable_pdb`] inflates it.
    ///
    /// The metadata root is read as an assembly's is, each stream located within the bytes,
    /// the `#Pdb` stream parsed, and the tables stream sized by the `#Pdb` stream's row counts
    /// rather than by tables of its own.
    ///
    /// # Arguments
    ///
    /// * `data` - The PDB's bytes, which the result borrows
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not metadata, have no `#Pdb` stream, a stream lies
    /// outside them, or a stream does not parse.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::pdb::PdbMetadata;
    ///
    /// let data = std::fs::read("tests/samples/pdb/portable/PdbProbe.pdb")?;
    /// let pdb = PdbMetadata::read(&data)?;
    /// assert!(pdb.tables.is_some());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn read(data: &'a [u8]) -> Result<Self> {
        let root = Root::read(data)?;
        let stream = |name: &str| -> Result<Option<&'a [u8]>> {
            root.stream(name)
                .map(|header| {
                    let start = header.offset as usize;
                    let end = start
                        .checked_add(header.size as usize)
                        .ok_or(out_of_bounds_error!())?;
                    data.get(start..end).ok_or(out_of_bounds_error!())
                })
                .transpose()
        };
        let pdb_stream = PdbStream::from(
            stream("#Pdb")?.ok_or_else(|| malformed_error!("the metadata has no #Pdb stream"))?,
        )?;
        let tables = match root.tables_stream() {
            Some(header) => Some(TablesHeader::from_pdb(
                stream(&header.name)?.ok_or(out_of_bounds_error!())?,
                &pdb_stream.type_system_rows,
            )?),
            None => None,
        };
        Ok(PdbMetadata {
            tables,
            strings: stream("#Strings")?.map(Strings::from).transpose()?,
            blobs: stream("#Blob")?.map(Blob::from).transpose()?,
            guids: stream("#GUID")?.map(Guid::from).transpose()?,
            root,
            pdb_stream,
        })
    }

    /// Checks the PDB was written for the image whose tables are `image`.
    ///
    /// A PDB's columns that index the image's tables are sized by the row counts its `#Pdb`
    /// stream records, not by the image's, so a PDB read against an image with other counts
    /// reads every such column wrong. The counts of every table the PDB references must
    /// therefore be the image's; a table it does not reference has no count to compare.
    ///
    /// # Arguments
    ///
    /// * `image` - The image's tables stream, `None` for an image without one
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] naming the first table whose count differs.
    pub fn check_rows(&self, image: Option<&TablesHeader<'_>>) -> Result<()> {
        for (index, &rows) in self.pdb_stream.type_system_rows.iter().enumerate() {
            if self.pdb_stream.referenced_tables & (1u64 << index) == 0 {
                continue;
            }
            let Some(table) = u8::try_from(index).ok().and_then(TableId::from_token_type) else {
                continue;
            };
            let image_rows = image.map_or(0, |tables| tables.table_row_count(table));
            if rows != image_rows {
                return Err(malformed_error!(
                    "the PDB records {rows} {table:?} rows and the image has {image_rows}: it \
                     was written for another image"
                ));
            }
        }
        Ok(())
    }
}

/// The identity of the Portable PDB `file` was built with, as its CodeView entry names it.
///
/// A Portable PDB's id is 20 bytes: a GUID and a stamp. The image's CodeView debug directory
/// entry for a Portable PDB (minor version `0x504D`, `PM`) names the same id: its `RSDS`
/// record holds the GUID, and the entry's time stamp is the stamp. A debugger only pairs an
/// image with a PDB whose `#Pdb` stream ([`PdbStream::id`]) holds that id.
///
/// # Arguments
///
/// * `file` - The image
///
/// # Returns
///
/// The id, or `None` when the image has no CodeView entry for a Portable PDB (a Windows PDB
/// names its PDB by a GUID and an age, which a Portable PDB's id is not).
///
/// # Errors
///
/// Returns an error when the entry's data is not in the file, or it is not an `RSDS` record.
pub fn codeview_pdb_id(file: &File) -> Result<Option<[u8; 20]>> {
    let Some(entry) = file.debug_directory()?.into_iter().find(|entry| {
        entry.kind == debug_type::CODEVIEW && entry.minor_version == PORTABLE_CODEVIEW_MINOR_VERSION
    }) else {
        return Ok(None);
    };
    let data = file.debug_data(&entry)?;
    let mut offset = 0;
    let signature: u32 = read_le_at(&data, &mut offset)?;
    if signature != CODEVIEW_SIGNATURE {
        return Err(malformed_error!(
            "a CodeView record starts with 0x{signature:08X}, not RSDS"
        ));
    }
    let mut id = [0u8; 20];
    id[..16].copy_from_slice(data.get(4..20).ok_or(out_of_bounds_error!())?);
    id[16..].copy_from_slice(&entry.timestamp.to_le_bytes());
    Ok(Some(id))
}

/// The Portable PDB `file` embeds in its debug directory, inflated; `None` when it embeds none.
///
/// The entry's data is `MPDB`, the PDB's size, then the PDB deflated. Inflating stops at that
/// size: a stream that would inflate past it, or falls short of it, is refused.
///
/// # Errors
///
/// When the entry's data is not in the file, does not start with `MPDB`, or does not inflate
/// to the size it states.
pub fn embedded_portable_pdb(file: &File) -> Result<Option<Vec<u8>>> {
    let Some(entry) = file
        .debug_directory()?
        .into_iter()
        .find(|entry| entry.kind == debug_type::EMBEDDED_PORTABLE_PDB)
    else {
        return Ok(None);
    };
    let data = file.debug_data(&entry)?;
    let mut offset = 0;
    let signature: u32 = read_le_at(&data, &mut offset)?;
    if signature != EMBEDDED_PDB_SIGNATURE {
        return Err(malformed_error!(
            "an embedded Portable PDB starts with 0x{signature:08X}, not MPDB"
        ));
    }
    let size: u32 = read_le_at(&data, &mut offset)?;
    let compressed = data.get(offset..).unwrap_or_default();
    let mut pdb = Vec::new();
    flate2::read::DeflateDecoder::new(compressed)
        .take(u64::from(size).saturating_add(1))
        .read_to_end(&mut pdb)
        .map_err(|e| malformed_error!("the embedded Portable PDB does not inflate: {e}"))?;
    if pdb.len() > size as usize {
        return Err(malformed_error!(
            "the embedded Portable PDB states {size} bytes and inflates to more"
        ));
    }
    if pdb.len() < size as usize {
        return Err(malformed_error!(
            "the embedded Portable PDB states {size} bytes and inflates to {}",
            pdb.len()
        ));
    }
    Ok(Some(pdb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metadata::validation::ValidationConfig, testkit::fixture, CilObject};

    /// Row counts SRM reports for the probe's PDB (`tests/samples/factory`, `pdb` family).
    const PROBE_ROWS: [(TableId, u32); 8] = [
        (TableId::Document, 12),
        (TableId::MethodDebugInformation, 56),
        (TableId::LocalScope, 26),
        (TableId::LocalVariable, 19),
        (TableId::LocalConstant, 22),
        (TableId::ImportScope, 14),
        (TableId::StateMachineMethod, 4),
        (TableId::CustomDebugInformation, 50),
    ];

    fn assert_probe_rows(pdb: &PdbMetadata<'_>) {
        let tables = pdb.tables.as_ref().unwrap();
        for (table, rows) in PROBE_ROWS {
            assert_eq!(tables.table_row_count(table), rows, "{table:?}");
        }
    }

    /// A standalone PDB reads with its `#Pdb` stream and the debug tables SRM reads.
    #[test]
    fn a_standalone_pdb_reads() {
        let data = std::fs::read(fixture("pdb/portable/PdbProbe.pdb")).unwrap();
        let pdb = PdbMetadata::read(&data).unwrap();
        assert!(pdb.pdb_stream.entry_point.is_some());
        assert_ne!(pdb.pdb_stream.referenced_tables, 0);
        assert_probe_rows(&pdb);
    }

    /// An embedded PDB inflates to the standalone one's tables; an image without one has none.
    #[test]
    fn an_embedded_pdb_inflates() {
        let file = File::from_path(fixture("pdb/embedded/PdbProbe.dll")).unwrap();
        let data = embedded_portable_pdb(&file).unwrap().unwrap();
        assert_probe_rows(&PdbMetadata::read(&data).unwrap());

        let portable = File::from_path(fixture("pdb/portable/PdbProbe.dll")).unwrap();
        assert!(embedded_portable_pdb(&portable).unwrap().is_none());
    }

    /// Metadata without a `#Pdb` stream is an assembly's, not a PDB.
    #[test]
    fn assembly_metadata_is_not_a_pdb() {
        let file = File::from_path(fixture("WindowsBase.dll")).unwrap();
        let (rva, size) = file.clr().unwrap();
        let cor20 = file.rva_slice(rva, size).unwrap();
        let mut offset = 8;
        let metadata_rva: u32 = read_le_at(&cor20, &mut offset).unwrap();
        let metadata_size: u32 = read_le_at(&cor20, &mut offset).unwrap();
        let metadata = file
            .rva_slice(metadata_rva as usize, metadata_size as usize)
            .unwrap();
        assert!(PdbMetadata::read(&metadata).is_err());
    }

    /// The rows a loaded PDB holds: each table's, as SRM counts them.
    fn assert_loaded_rows(pdb: &PortablePdb) {
        let loaded = [
            pdb.documents().len(),
            pdb.method_debug_information().len(),
            pdb.local_scopes().len(),
            pdb.local_variables().len(),
            pdb.local_constants().len(),
            pdb.import_scopes().len(),
            pdb.state_machine_methods().len(),
            pdb.custom_debug_information().len(),
        ];
        for ((table, rows), loaded) in PROBE_ROWS.iter().zip(loaded) {
            assert_eq!(loaded, *rows as usize, "{table:?}");
        }
    }

    /// Every load reads the PDB the image embeds, every row of every table, and it is the
    /// PDB the image's CodeView entry names.
    #[test]
    fn a_load_reads_the_embedded_pdb() {
        let assembly = CilObject::from_path(fixture("pdb/embedded/PdbProbe.dll")).unwrap();
        let pdb = assembly.pdb().expect("the image embeds a PDB");
        assert_eq!(pdb.origin(), PdbOrigin::Embedded);
        assert_loaded_rows(pdb);
        assert_eq!(pdb.id(), codeview_pdb_id(assembly.file()).unwrap());
        assert!(pdb.entry_point().is_some());
        assert!(
            assembly.diagnostics().warnings().is_empty(),
            "{:?}",
            assembly.diagnostics().warnings()
        );
    }

    /// A standalone PDB is read only when it is attached, and then it is read whole.
    #[test]
    fn a_standalone_pdb_is_attached_explicitly() {
        let assembly = CilObject::from_path(fixture("pdb/portable/PdbProbe.dll")).unwrap();
        assert!(assembly.pdb().is_none());

        let assembly = assembly
            .with_pdb(fixture("pdb/portable/PdbProbe.pdb"))
            .unwrap();
        let pdb = assembly.pdb().expect("the PDB is attached");
        assert_eq!(pdb.origin(), PdbOrigin::Standalone);
        assert_loaded_rows(pdb);
        assert_eq!(pdb.id(), codeview_pdb_id(assembly.file()).unwrap());
        assert!(assembly.diagnostics().warnings().is_empty());
    }

    /// A PDB written for another image fails a strict reload and is a diagnostic in a lenient
    /// one.
    #[test]
    fn a_pdb_for_another_image_is_refused() {
        let vb = std::fs::read(fixture("pdb/vb/PdbProbeVb.pdb")).unwrap();
        let strict = CilObject::from_path(fixture("pdb/portable/PdbProbe.dll")).unwrap();
        let error = strict.with_pdb_bytes(&vb).err().unwrap();
        assert!(
            error.to_string().contains("written for another image"),
            "{error}"
        );

        let lenient = CilObject::from_path_with_validation(
            fixture("pdb/portable/PdbProbe.dll"),
            ValidationConfig {
                lenient: true,
                ..ValidationConfig::production()
            },
        )
        .unwrap()
        .with_pdb_bytes(&vb)
        .unwrap();
        assert!(lenient.pdb().is_none());
        assert!(lenient
            .diagnostics()
            .warnings()
            .iter()
            .any(|warning| warning.message.contains("written for another image")));
    }

    /// Another build's PDB with the image's row counts reads, with a diagnostic naming it;
    /// one of a build with other row counts (Release against Debug) is refused.
    #[test]
    fn another_builds_pdb_reads_with_a_diagnostic() {
        // The same source built without the SourceLink path map: other document paths, so
        // another id, and the same tables
        let unmapped = std::fs::read(fixture("pdb/unmapped/PdbProbe.pdb")).unwrap();
        let assembly = CilObject::from_path(fixture("pdb/portable/PdbProbe.dll"))
            .unwrap()
            .with_pdb_bytes(&unmapped);
        match assembly {
            Ok(assembly) => {
                assert!(assembly.pdb().is_some());
                assert!(assembly
                    .diagnostics()
                    .warnings()
                    .iter()
                    .any(|warning| warning.message.contains("from another build")));
            }
            Err(error) => panic!("{error}"),
        }

        let release = std::fs::read(fixture("pdb/release/PdbProbe.pdb")).unwrap();
        let error = CilObject::from_path(fixture("pdb/portable/PdbProbe.dll"))
            .unwrap()
            .with_pdb_bytes(&release)
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("written for another image"),
            "{error}"
        );
    }
}

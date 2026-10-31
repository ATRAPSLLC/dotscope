//! A canonical dump of an assembly: what it holds, independent of where in the file and in its
//! heaps each part happens to sit.
//!
//! Two assemblies with equal dumps hold the same metadata, code and resources: the dump names
//! every table row by `(table, rid)` with its heap columns resolved to the strings, blobs and
//! GUIDs they point at, each method body decoded with its branch targets and protected regions
//! as instruction positions, each field's initial data and each embedded resource by content,
//! and the PE and CLI facts a loader reads. Offsets into heaps, method body and field data
//! RVAs, and resource offsets are not part of it: a writer is free to move what they point at.
//!
//! [`CanonicalDump::diff`] lists the differences between two dumps, path by path
//! (`TypeDef[12]: ... != ...`).
//!
//! # Format
//!
//! A dump is a map of path to value, as JSON an object of strings
//! ([`CanonicalDump::to_json`]). Its format is written down here because a second
//! implementation writes it from another reader: `tests/oracle/srm-dump` dumps a file as
//! System.Reflection.Metadata reads it, and the oracle tier compares the two. Nothing in a
//! value depends on how Rust formats a type.
//!
//! | Path | Value |
//! |------|-------|
//! | `Section[<name>]` | `characteristics 0x<8 hex digits>`, for each section but `.reloc` |
//! | `Directory[<kind>]` | `present`, for each data directory with an RVA or a size, but the certificate table and the base relocations |
//! | `Debug[<i>]` | `type <n>, characteristics 0x<hex>, version <major>.<minor>, <n> bytes, sha256 <hex>` |
//! | `Cli` | `runtime <major>.<minor>, flags 0x<hex>, entry point 0x<8 hex digits>` |
//! | `Metadata.version` | the metadata root's version, quoted |
//! | `<table>.rows` | the row count of each table the tables stream declares |
//! | `<table>[<rid>]` | the row's columns in order under a layout with every index four bytes wide: each heap column as what it names, the bytes between them in hex, the parts separated by a space. MethodDef's RVA, FieldRVA's RVA and ManifestResource's Offset are left out |
//! | `MethodDef[<rid>].body` | `max stack <n>, init locals <bool>, locals 0x<8 hex digits>;` and ` <mnemonic>[ <operand>];` per instruction and ` handler <kind> try <a>..<b> handler <c>..<d>[ class 0x<8 hex digits>\| filter <e>];` per protected region |
//! | `FieldRVA[<rid>].data` | the field's initial data in hex, as many bytes as its type takes |
//! | `Resource[<quoted name>]` | `<n> bytes, sha256 <hex>`, for each resource embedded in the file |
//! | `Document[<rid>].name` | a Document row's path, decoded from its DocumentNameBlob, quoted |
//! | `MethodDebugInformation[<rid>].points` | `locals 0x<8 hex digits>;` (the local signature's StandAloneSig token, 0 for none) and ` IL_<4+ uppercase hex digits> doc <rid> <start line>:<start column>-<end line>:<end column>;` per sequence point, ` IL_<hex> doc <rid> hidden;` for a hidden one; absent for a row without sequence points |
//! | `ImportScope[<rid>].imports` | `<kind>[ alias <quoted>][ assembly 0x<8 hex digits>][ namespace <quoted>][ type 0x<8 hex digits>];` per import, separated by a space, the kind its number (1 to 9) |
//! | `Pdb` | `unreadable: <why>`, for an embedded Portable PDB that does not read |
//! | `Pdb.id` | the PDB's 20-byte id in hex |
//! | `Pdb.entryPoint` | the entry point's token, `0x<8 hex digits>`, 0 for none |
//! | `Pdb.typeSystemRows[<table>]` | the row count the `#Pdb` stream records for each table it references |
//! | `Pdb.<path>` | each path above that a Portable PDB's tables have (`<table>.rows`, `<table>[<rid>]` and the decoded debug paths), for the PDB the image embeds |
//!
//! A standalone `.pdb` file is dumped on its own ([`CanonicalDump::of_pdb`]), as the `Pdb.`
//! paths alone; debug tables in an assembly's own metadata are dumped without the prefix.
//!
//! Text from the file is quoted: `\`, `"` and the control characters (below U+0020, and
//! U+007F) escaped as `\\`, `\"` and `\u{<hex>}`, a UTF-16 surrogate without its pair as
//! `\u{<hex>}`, and every other character as it is. A `#Strings` entry that is not UTF-8 is
//! `bytes[<hex>]`. A blob is `blob[<hex>]`, a GUID `guid[<lowercase hyphenated>]` and GUID
//! index 0 `null`. A heap index that names nothing is `str#<n>`, `blob#<n>` or `guid#<n>`.
//!
//! In a body, a branch target is an instruction position `#<i>`, `end` for the end of the code,
//! or `@0x<hex>` for an offset inside an instruction; a short branch is named by its long form
//! (`br.s` as `br`). An integer operand is decimal, a floating-point one its bits in hex, a
//! token `0x<8 hex digits>`, and a `#US` token (table `0x70`) its string, quoted, or
//! `us#0x<hex>`. A protected region's kind is its flags, `0` catch, `1` filter, `2` finally and
//! `4` fault; a catch names its class token, a filter the position its filter starts at.
//!
//! What cannot be read is `unreadable` or, for code that does not decode, `undecodable`; this
//! dump adds a reason after a colon, which [`CanonicalDump::without_reasons`] drops. A reader
//! that refuses the whole file writes the one entry `Image`, `unreadable: <why>`.

use std::{collections::BTreeMap, sync::Arc};

use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;

use crate::{
    assembly::{decode_stream, Immediate, Operand},
    cilassembly::calculate_field_size,
    file::{parser::Parser, pe::DataDirectoryType, File},
    metadata::{
        importscope::{parse_imports_blob, ImportDeclaration},
        method::MethodBody,
        pdb::{document_name, embedded_portable_pdb, PdbMetadata},
        sequencepoints::parse_sequence_points,
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tablefields::{get_heap_fields, HeapType},
        tables::*,
        typesystem::PointerSize,
    },
    testkit::corpus::raw_tables,
    CilAssemblyView,
};

/// An assembly's canonical dump: a value per path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalDump {
    entries: BTreeMap<String, String>,
}

impl CanonicalDump {
    /// The dump of the assembly `view` reads.
    #[must_use]
    pub fn of(view: &CilAssemblyView) -> Self {
        let mut dump = Self::default();
        dump.structure(view);
        if let Some(tables) = view.tables() {
            dump.tables(view, tables);
        }
        match embedded_portable_pdb(view.file()) {
            Ok(Some(pdb)) => dump.pdb(&pdb),
            Ok(None) => {}
            Err(error) => dump.put("Pdb".to_string(), format!("unreadable: {error}")),
        }
        dump
    }

    /// The dump of the standalone Portable PDB `data`: the `Pdb.` paths alone, or the one
    /// entry `Image` when the bytes are not a Portable PDB.
    #[must_use]
    pub fn of_pdb(data: &[u8]) -> Self {
        let mut dump = Self::default();
        match PdbMetadata::read(data) {
            Ok(_) => dump.pdb(data),
            Err(error) => dump.put("Image".to_string(), format!("unreadable: {error}")),
        }
        dump
    }

    /// The dump's entries, by path.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.entries
    }

    /// The dump with each `unreadable` or `undecodable` value cut to that word: the reason
    /// after it is how this reader failed, not what the file holds.
    #[must_use]
    pub fn without_reasons(&self) -> Self {
        let entries = self
            .entries
            .iter()
            .map(|(path, value)| {
                let value = ["unreadable", "undecodable"]
                    .into_iter()
                    .find(|word| value.starts_with(&format!("{word}: ")))
                    .map_or_else(|| value.clone(), str::to_string);
                (path.clone(), value)
            })
            .collect();
        Self { entries }
    }

    /// The dump as a JSON object of path to value, an entry per line, paths in order.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut text = String::from("{\n");
        for (index, (path, value)) in self.entries.iter().enumerate() {
            if index > 0 {
                text.push_str(",\n");
            }
            text.push_str("  ");
            json_string(&mut text, path);
            text.push_str(": ");
            json_string(&mut text, value);
        }
        text.push_str("\n}\n");
        text
    }

    /// The dump a JSON object of path to value holds.
    ///
    /// # Errors
    ///
    /// When `json` is not an object whose every value is a string, naming where it fails.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut reader = JsonReader {
            chars: json.chars().peekable(),
            at: 0,
        };
        let mut entries = BTreeMap::new();
        reader.expect('{')?;
        if reader.skip_whitespace() == Some('}') {
            reader.bump();
        } else {
            loop {
                let path = reader.string()?;
                reader.expect(':')?;
                let value = reader.string()?;
                entries.insert(path, value);
                match reader.next_token()? {
                    ',' => {}
                    '}' => break,
                    other => return Err(reader.error(&format!("`{other}` after a value"))),
                }
            }
        }
        if reader.skip_whitespace().is_some() {
            return Err(reader.error("text after the object"));
        }
        Ok(Self { entries })
    }

    /// Where `self` and `other` differ, a line per path: the value each holds, or which one
    /// lacks the path.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut differences = Vec::new();
        for (path, value) in &self.entries {
            match other.entries.get(path) {
                Some(theirs) if theirs == value => {}
                Some(theirs) => differences.push(format!("{path}: {value} != {theirs}")),
                None => differences.push(format!("{path}: {value}, and absent from the other")),
            }
        }
        for (path, value) in &other.entries {
            if !self.entries.contains_key(path) {
                differences.push(format!("{path}: absent, and {value} in the other"));
            }
        }
        differences
    }

    fn put(&mut self, path: String, value: String) {
        self.entries.insert(path, value);
    }

    /// The PE and CLI facts a loader reads: sections, data directories, the CLI header and
    /// the metadata root.
    fn structure(&mut self, view: &CilAssemblyView) {
        let file = view.file();
        for section in file
            .sections()
            .iter()
            .filter(|s| !s.name.starts_with(".reloc"))
        {
            self.put(
                format!("Section[{}]", section.name),
                format!("characteristics {:#010x}", section.characteristics),
            );
        }
        for (kind, directory) in file.directories() {
            // A writer cannot keep a signature over bytes it moved, and lays out the
            // relocations its own code needs: neither says what the assembly holds
            if matches!(
                kind,
                DataDirectoryType::CertificateTable | DataDirectoryType::BaseRelocationTable
            ) {
                continue;
            }
            if directory.virtual_address != 0 || directory.size != 0 {
                self.put(format!("Directory[{kind:?}]"), "present".to_string());
            }
        }
        self.debug_entries(file);
        let header = view.cor20header();
        self.put(
            "Cli".to_string(),
            format!(
                "runtime {}.{}, flags {:#x}, entry point {:#010x}",
                header.major_runtime_version,
                header.minor_runtime_version,
                header.flags.bits(),
                header.entry_point_token
            ),
        );
        // The streams themselves are how the heaps and tables are stored, which the rows'
        // resolved columns already compare
        self.put(
            "Metadata.version".to_string(),
            quoted(view.metadata_root().version.chars().map(Ok)),
        );
    }

    /// Each debug directory entry: its kind, and its data by content.
    fn debug_entries(&mut self, file: &File) {
        let Some((rva, size)) = file.get_data_directory(DataDirectoryType::Debug) else {
            return;
        };
        if rva == 0 || size == 0 {
            return;
        }
        let Ok(directory) = file.rva_slice(rva as usize, size as usize) else {
            self.put("Debug".to_string(), "unreadable".to_string());
            return;
        };
        let field =
            |entry: &[u8], at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
        for (index, entry) in directory.as_chunks::<28>().0.iter().enumerate() {
            let (kind, data_size, pointer) = (field(entry, 12), field(entry, 16), field(entry, 24));
            let data = file
                .data_slice(pointer as usize, data_size as usize)
                .map_or_else(
                    |_| "unreadable".to_string(),
                    |data| hex(&Sha256::digest(data)),
                );
            self.put(
                format!("Debug[{index}]"),
                format!(
                    "type {kind}, characteristics {:#x}, version {}.{}, {data_size} bytes, sha256 {data}",
                    field(entry, 0),
                    u16::from_le_bytes([entry[8], entry[9]]),
                    u16::from_le_bytes([entry[10], entry[11]]),
                ),
            );
        }
    }

    /// Every row of every table, and what its RVA and offset columns point at.
    fn tables(&mut self, view: &CilAssemblyView, tables: &TablesHeader<'_>) {
        let heaps = Heaps {
            strings: view.strings(),
            blobs: view.blobs(),
            guids: view.guids(),
        };
        let layout = canonical_layout();
        macro_rules! rows {
            ($($raw:ty),* $(,)?) => {
                $(
                    if let Some(table) = tables.table::<$raw>() {
                        self.rows("", table, &heaps, &layout);
                    }
                )*
            };
        }
        raw_tables!(rows);
        self.debug_values("", tables, &heaps);
        self.method_bodies(view, tables);
        self.field_data(view, tables);
        self.resources(view, tables, &heaps);
    }

    /// The rows of `table`, each written again under [`canonical_layout`], so that column
    /// widths do not show, with its heap columns resolved and its RVA or offset column, which
    /// the parts below dump by content, left out.
    fn rows<T: RowReadable + RowWritable>(
        &mut self,
        prefix: &str,
        table: &MetadataTable<'_, T>,
        heaps: &Heaps<'_>,
        layout: &TableInfoRef,
    ) {
        let id = T::TABLE_ID;
        let size = T::row_size(layout) as usize;
        let mut fields = get_heap_fields(id, layout);
        fields.sort_by_key(|field| field.offset);
        // MethodDef's RVA, FieldRVA's RVA and ManifestResource's Offset open their rows
        let moved = match id {
            TableId::MethodDef | TableId::FieldRVA | TableId::ManifestResource => 4,
            _ => 0,
        };
        self.put(format!("{prefix}{id:?}.rows"), table.row_count.to_string());
        for (index, read) in table.iter().enumerate() {
            let rid = index + 1;
            let mut row = vec![0u8; size];
            let written =
                read.and_then(|value| value.row_write(&mut row, &mut 0, rid as u32, layout));
            if let Err(error) = written {
                self.put(
                    format!("{prefix}{id:?}[{rid}]"),
                    format!("unreadable: {error}"),
                );
                continue;
            }
            let mut parts = Vec::new();
            let mut at = moved;
            for field in &fields {
                if field.offset > at {
                    parts.push(hex(&row[at..field.offset]));
                }
                let value = row[field.offset..field.offset + field.size]
                    .iter()
                    .rev()
                    .fold(0usize, |value, &byte| value << 8 | usize::from(byte));
                parts.push(heaps.resolve(field.heap_type, value));
                at = field.offset + field.size;
            }
            if at < size {
                parts.push(hex(&row[at..]));
            }
            self.put(format!("{prefix}{id:?}[{rid}]"), parts.join(" "));
        }
    }

    /// A Portable PDB's identity, its `#Pdb` stream's row counts, and its tables, under
    /// `Pdb.`.
    fn pdb(&mut self, data: &[u8]) {
        let pdb = match PdbMetadata::read(data) {
            Ok(pdb) => pdb,
            Err(error) => {
                self.put("Pdb".to_string(), format!("unreadable: {error}"));
                return;
            }
        };
        let stream = &pdb.pdb_stream;
        self.put("Pdb.id".to_string(), hex(&stream.id));
        self.put(
            "Pdb.entryPoint".to_string(),
            format!(
                "{:#010x}",
                stream.entry_point.map_or(0, |token| token.value())
            ),
        );
        for table in TableId::iter() {
            if stream.referenced_tables & (1u64 << (table as u8)) != 0 {
                self.put(
                    format!("Pdb.typeSystemRows[{table:?}]"),
                    stream.type_system_rows[table as usize].to_string(),
                );
            }
        }
        let Some(tables) = &pdb.tables else {
            return;
        };
        let heaps = Heaps {
            strings: pdb.strings.as_ref(),
            blobs: pdb.blobs.as_ref(),
            guids: pdb.guids.as_ref(),
        };
        let layout = canonical_layout();
        macro_rules! rows {
            ($($raw:ty),* $(,)?) => {
                $(
                    if let Some(table) = tables.table::<$raw>() {
                        self.rows("Pdb.", table, &heaps, &layout);
                    }
                )*
            };
        }
        rows!(
            DocumentRaw,
            MethodDebugInformationRaw,
            LocalScopeRaw,
            LocalVariableRaw,
            LocalConstantRaw,
            ImportScopeRaw,
            StateMachineMethodRaw,
            CustomDebugInformationRaw,
        );
        self.debug_values("Pdb.", tables, &heaps);
    }

    /// The debug tables' values a reader decodes from their blobs: each document's path,
    /// each method's sequence points and each import scope's imports.
    fn debug_values(&mut self, prefix: &str, tables: &TablesHeader<'_>, heaps: &Heaps<'_>) {
        let blob = |index: u32| {
            heaps
                .blobs
                .ok_or_else(|| "no #Blob heap".to_string())
                .and_then(|blobs| blobs.get(index as usize).map_err(|e| e.to_string()))
        };
        if let Some(documents) = tables.table::<DocumentRaw>() {
            for row in documents.iter().flatten() {
                let name = blob(row.name)
                    .and_then(|data| {
                        document_name(data, heaps.blobs.unwrap()).map_err(|e| e.to_string())
                    })
                    .map_or_else(
                        |error| format!("unreadable: {error}"),
                        |name| quoted(name.chars().map(Ok)),
                    );
                self.put(format!("{prefix}Document[{}].name", row.rid), name);
            }
        }
        if let Some(methods) = tables.table::<MethodDebugInformationRaw>() {
            for row in methods.iter().flatten() {
                if row.sequence_points == 0 {
                    continue;
                }
                let points = blob(row.sequence_points)
                    .and_then(|data| {
                        parse_sequence_points(data, row.document).map_err(|e| e.to_string())
                    })
                    .map_or_else(
                        |error| format!("undecodable: {error}"),
                        |points| {
                            // The StandAloneSig row, as its token
                            let locals = if points.local_signature == 0 {
                                0
                            } else {
                                0x1100_0000 | points.local_signature
                            };
                            let mut text = format!("locals {locals:#010x};");
                            for point in &points.points {
                                text.push_str(&format!(
                                    " IL_{:04X} doc {}",
                                    point.il_offset, point.document
                                ));
                                if point.is_hidden {
                                    text.push_str(" hidden;");
                                } else {
                                    text.push_str(&format!(
                                        " {}:{}-{}:{};",
                                        point.start_line,
                                        point.start_col,
                                        point.end_line,
                                        point.end_col
                                    ));
                                }
                            }
                            text
                        },
                    );
                self.put(
                    format!("{prefix}MethodDebugInformation[{}].points", row.rid),
                    points,
                );
            }
        }
        if let Some(scopes) = tables.table::<ImportScopeRaw>() {
            for row in scopes.iter().flatten() {
                if row.imports == 0 {
                    continue;
                }
                let imports = blob(row.imports)
                    .and_then(|data| {
                        parse_imports_blob(data, heaps.blobs.unwrap()).map_err(|e| e.to_string())
                    })
                    .map_or_else(
                        |error| format!("undecodable: {error}"),
                        |imports| imports.iter().map(import).collect::<Vec<_>>().join(" "),
                    );
                self.put(format!("{prefix}ImportScope[{}].imports", row.rid), imports);
            }
        }
    }

    /// Each method body: its header's facts, its instructions with branch targets as
    /// instruction positions and user strings as their text, and its protected regions.
    fn method_bodies(&mut self, view: &CilAssemblyView, tables: &TablesHeader<'_>) {
        let Some(methods) = tables.table::<MethodDefRaw>() else {
            return;
        };
        let file = view.file();
        let userstrings = view.userstrings();
        for method in methods.iter().flatten() {
            if method.rva == 0 {
                continue;
            }
            let path = format!("MethodDef[{}].body", method.rid);
            // Native and runtime-provided code has no CIL body to read
            if method.impl_flags & 0x0003 != 0 {
                continue;
            }
            self.put(path, body(file, method.rva, userstrings));
        }
    }

    /// Each field's initial data, as many bytes as its type takes.
    fn field_data(&mut self, view: &CilAssemblyView, tables: &TablesHeader<'_>) {
        let Some(rvas) = tables.table::<FieldRvaRaw>() else {
            return;
        };
        let file = view.file();
        let pointer = PointerSize::from_is_64bit(file.pe().is_64bit);
        for row in rvas.iter().flatten() {
            let value = calculate_field_size(view, row.field, pointer)
                .map_err(|error| error.to_string())
                .and_then(|size| {
                    file.rva_slice(row.rva as usize, size)
                        .map(|data| hex(&data))
                        .map_err(|e| e.to_string())
                })
                .unwrap_or_else(|error| format!("unreadable: {error}"));
            self.put(format!("FieldRVA[{}].data", row.rid), value);
        }
    }

    /// Each embedded resource by name, as its content's hash.
    fn resources(&mut self, view: &CilAssemblyView, tables: &TablesHeader<'_>, heaps: &Heaps<'_>) {
        let Some(resources) = tables.table::<ManifestResourceRaw>() else {
            return;
        };
        let file = view.file();
        let directory = view.cor20header().resource_rva;
        for row in resources.iter().flatten() {
            let name = heaps.resolve(HeapType::String, row.name as usize);
            if !row.implementation.is_null() || directory == 0 {
                continue;
            }
            let at = directory as usize + row.offset_field as usize;
            let value = file
                .rva_slice(at, 4)
                .map_err(|e| e.to_string())
                .and_then(|length| {
                    let length = u32::from_le_bytes(length.as_ref().try_into().unwrap()) as usize;
                    let data = file.rva_slice(at + 4, length).map_err(|e| e.to_string())?;
                    Ok(format!(
                        "{length} bytes, sha256 {}",
                        hex(&Sha256::digest(&data))
                    ))
                })
                .unwrap_or_else(|error| format!("unreadable: {error}"));
            self.put(format!("Resource[{name}]"), value);
        }
    }
}

/// The heaps a row's heap columns point into.
struct Heaps<'a> {
    strings: Option<&'a Strings<'a>>,
    blobs: Option<&'a Blob<'a>>,
    guids: Option<&'a Guid<'a>>,
}

impl Heaps<'_> {
    /// What the heap index `value` names: a string's bytes, a blob's, or a GUID.
    fn resolve(&self, heap: HeapType, value: usize) -> String {
        match heap {
            HeapType::String => match self.strings.and_then(|s| s.data().get(value..)) {
                Some(bytes) => {
                    let bytes = &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())];
                    std::str::from_utf8(bytes).map_or_else(
                        |_| format!("bytes[{}]", hex(bytes)),
                        |text| quoted(text.chars().map(Ok)),
                    )
                }
                None => format!("str#{value}"),
            },
            HeapType::Blob => match self.blobs.map(|blobs| blobs.get(value)) {
                Some(Ok(blob)) => format!("blob[{}]", hex(blob)),
                Some(Err(_)) | None => format!("blob#{value}"),
            },
            HeapType::Guid if value == 0 => "null".to_string(),
            HeapType::Guid => match self.guids.map(|guids| guids.get(value)) {
                Some(Ok(guid)) => format!("guid[{guid}]"),
                Some(Err(_)) | None => format!("guid#{value}"),
            },
        }
    }
}

/// An import as the dump writes it: its kind's number, then its alias, assembly, namespace
/// and type, those it has.
fn import(declaration: &ImportDeclaration) -> String {
    let text = |value: &str| quoted(value.chars().map(Ok));
    let (kind, alias, assembly, namespace, target) = match declaration {
        ImportDeclaration::ImportNamespace { namespace } => (1, None, None, Some(namespace), None),
        ImportDeclaration::ImportAssemblyNamespace {
            assembly_ref,
            namespace,
        } => (2, None, Some(assembly_ref), Some(namespace), None),
        ImportDeclaration::ImportType { type_ref } => (3, None, None, None, Some(type_ref)),
        ImportDeclaration::ImportXmlNamespace { alias, namespace } => {
            (4, Some(alias), None, Some(namespace), None)
        }
        ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
            (5, Some(alias), None, None, None)
        }
        ImportDeclaration::DefineAssemblyAlias {
            alias,
            assembly_ref,
        } => (6, Some(alias), Some(assembly_ref), None, None),
        ImportDeclaration::DefineNamespaceAlias { alias, namespace } => {
            (7, Some(alias), None, Some(namespace), None)
        }
        ImportDeclaration::DefineAssemblyNamespaceAlias {
            alias,
            assembly_ref,
            namespace,
        } => (8, Some(alias), Some(assembly_ref), Some(namespace), None),
        ImportDeclaration::DefineTypeAlias { alias, type_ref } => {
            (9, Some(alias), None, None, Some(type_ref))
        }
    };
    let mut out = kind.to_string();
    if let Some(alias) = alias {
        out.push_str(&format!(" alias {}", text(alias)));
    }
    if let Some(assembly) = assembly {
        out.push_str(&format!(" assembly {:#010x}", assembly.value()));
    }
    if let Some(namespace) = namespace {
        out.push_str(&format!(" namespace {}", text(namespace)));
    }
    if let Some(target) = target {
        out.push_str(&format!(" type {:#010x}", target.value()));
    }
    out.push(';');
    out
}

/// The layout rows are compared under: every index four bytes wide.
fn canonical_layout() -> TableInfoRef {
    let tables: Vec<(TableId, u32)> = TableId::iter().map(|table| (table, 0x0001_0000)).collect();
    Arc::new(TableInfo::new_test(&tables, true, true, true))
}

/// A method body at `rva`, decoded.
fn body(file: &File, rva: u32, userstrings: Option<&UserStrings<'_>>) -> String {
    let data = match file.section_bounded(rva as usize) {
        Ok(data) => data,
        Err(error) => return format!("unreadable: {error}"),
    };
    let header = match MethodBody::from(data) {
        Ok(header) => header,
        Err(error) => return format!("unreadable: {error}"),
    };
    let Some(code) = data.get(header.size_header..header.size_header + header.size_code) else {
        return "unreadable: its code runs past its section's data".to_string();
    };
    let instructions = match decode_stream(&mut Parser::new(code), 0) {
        Ok(instructions) => instructions,
        Err(error) => return format!("undecodable: {error}"),
    };
    // A position for every instruction offset, and the end of the code
    let position = |offset: u64| -> String {
        instructions
            .iter()
            .position(|instruction| instruction.offset == offset)
            .map_or_else(
                || {
                    if offset == header.size_code as u64 {
                        "end".to_string()
                    } else {
                        format!("@{offset:#x}")
                    }
                },
                |index| format!("#{index}"),
            )
    };
    // A tiny header stands for a maximum stack of 8
    let max_stack = if header.is_fat { header.max_stack } else { 8 };
    let mut text = format!(
        "max stack {max_stack}, init locals {}, locals {:#010x};",
        header.is_init_local, header.local_var_sig_token
    );
    for instruction in &instructions {
        let mut mnemonic = instruction.mnemonic;
        let operand = match &instruction.operand {
            Operand::None => String::new(),
            Operand::Target(target) => {
                // A short branch and its long form are one branch
                mnemonic = mnemonic.trim_end_matches(".s");
                position(*target)
            }
            Operand::Switch(offsets) => {
                let next = instruction.offset + instruction.size;
                offsets
                    .iter()
                    .map(|delta| position(next.wrapping_add_signed(i64::from(*delta))))
                    .collect::<Vec<_>>()
                    .join(",")
            }
            Operand::Token(token) if token.table() == 0x70 => {
                match userstrings.map(|heap| heap.get(token.row() as usize)) {
                    Some(Ok(text)) => quoted(
                        char::decode_utf16(text.into_vec())
                            .map(|unit| unit.map_err(|unpaired| unpaired.unpaired_surrogate())),
                    ),
                    _ => format!("us#{:#x}", token.row()),
                }
            }
            Operand::Token(token) => format!("{:#010x}", token.value()),
            Operand::Immediate(Immediate::Float32(value)) => format!("{:#010x}", value.to_bits()),
            Operand::Immediate(Immediate::Float64(value)) => format!("{:#018x}", value.to_bits()),
            Operand::Immediate(value) => value.to_string(),
            Operand::Local(index) | Operand::Argument(index) => index.to_string(),
        };
        text.push(' ');
        text.push_str(mnemonic);
        if !operand.is_empty() {
            text.push(' ');
            text.push_str(&operand);
        }
        text.push(';');
    }
    for handler in &header.exception_handlers {
        let span = |start: u32, length: u32| {
            format!(
                "{}..{}",
                position(u64::from(start)),
                position(u64::from(start) + u64::from(length))
            )
        };
        let kind = handler.flags.bits();
        text.push_str(&format!(
            " handler {kind} try {} handler {}",
            span(handler.try_offset, handler.try_length),
            span(handler.handler_offset, handler.handler_length),
        ));
        // A catch names its class, a filter where its filter starts: the field holds either
        match kind {
            0 => text.push_str(&format!(" class {:#010x}", handler.filter_offset)),
            1 => text.push_str(&format!(
                " filter {}",
                position(u64::from(handler.filter_offset))
            )),
            _ => {}
        }
        text.push(';');
    }
    text
}

/// Text as the dump quotes it (see the module's format): `chars` are its characters, and a
/// UTF-16 surrogate without its pair.
fn quoted(chars: impl IntoIterator<Item = Result<char, u16>>) -> String {
    let mut text = String::from('"');
    for char in chars {
        match char {
            Ok(c @ ('"' | '\\')) => {
                text.push('\\');
                text.push(c);
            }
            Ok(c) if c < ' ' || c == '\u{7f}' => {
                text.push_str(&format!("\\u{{{:x}}}", u32::from(c)))
            }
            Ok(c) => text.push(c),
            Err(unpaired) => text.push_str(&format!("\\u{{{unpaired:x}}}")),
        }
    }
    text.push('"');
    text
}

/// `text` as a JSON string.
fn json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A reader of the JSON [`CanonicalDump::from_json`] reads: an object of strings.
struct JsonReader<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    at: usize,
}

impl JsonReader<'_> {
    fn error(&self, what: &str) -> String {
        format!("a dump's JSON at character {}: {what}", self.at)
    }

    fn bump(&mut self) -> Option<char> {
        self.at += 1;
        self.chars.next()
    }

    /// The next character that is not whitespace, left unread.
    fn skip_whitespace(&mut self) -> Option<char> {
        while let Some(&c) = self.chars.peek() {
            if !c.is_ascii_whitespace() {
                return Some(c);
            }
            self.bump();
        }
        None
    }

    fn next_token(&mut self) -> Result<char, String> {
        self.skip_whitespace();
        self.bump().ok_or_else(|| self.error("the text ends"))
    }

    fn expect(&mut self, wanted: char) -> Result<(), String> {
        match self.next_token()? {
            c if c == wanted => Ok(()),
            c => Err(self.error(&format!("`{c}` where `{wanted}` belongs"))),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut text = String::new();
        loop {
            match self
                .bump()
                .ok_or_else(|| self.error("a string does not end"))?
            {
                '"' => return Ok(text),
                '\\' => match self
                    .bump()
                    .ok_or_else(|| self.error("an escape does not end"))?
                {
                    c @ ('"' | '\\' | '/') => text.push(c),
                    'b' => text.push('\u{8}'),
                    'f' => text.push('\u{c}'),
                    'n' => text.push('\n'),
                    'r' => text.push('\r'),
                    't' => text.push('\t'),
                    'u' => {
                        let unit = self.code_unit()?;
                        let c = if (0xD800..0xDC00).contains(&unit) {
                            if self.bump() != Some('\\') || self.bump() != Some('u') {
                                return Err(self.error("a surrogate without its pair"));
                            }
                            let low = self.code_unit()?;
                            char::decode_utf16([unit, low]).next().and_then(Result::ok)
                        } else {
                            char::from_u32(u32::from(unit))
                        };
                        text.push(c.ok_or_else(|| self.error("a surrogate without its pair"))?);
                    }
                    other => return Err(self.error(&format!("the escape `\\{other}`"))),
                },
                c => text.push(c),
            }
        }
    }

    fn code_unit(&mut self) -> Result<u16, String> {
        let digits: String = (0..4).filter_map(|_| self.bump()).collect();
        u16::from_str_radix(&digits, 16).map_err(|_| self.error(&format!("`\\u{digits}`")))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::fixture_bytes;

    /// The dump of one file, loaded twice, is one dump: it depends on nothing but the file.
    #[test]
    fn a_dump_depends_only_on_the_file() {
        for name in ["crafted_2.exe", "WindowsBase.dll"] {
            let dump = || {
                CanonicalDump::of(&CilAssemblyView::from_mem(fixture_bytes(name).to_vec()).unwrap())
            };
            let (first, second) = (dump(), dump());
            assert!(
                first.entries().len() > 100,
                "{name}: a dump of {} entries",
                first.entries().len()
            );
            assert_eq!(first.diff(&second), Vec::<String>::new(), "{name}");
        }
    }

    /// Every table the file has is in the dump, row count and rows.
    #[test]
    fn every_table_is_in_the_dump() {
        let view = CilAssemblyView::from_mem(fixture_bytes("WindowsBase.dll").to_vec()).unwrap();
        let dump = CanonicalDump::of(&view);
        let tables = view.tables().unwrap();
        for table in tables.present_tables() {
            let rows = tables.table_row_count(table);
            assert_eq!(
                dump.entries().get(&format!("{table:?}.rows")),
                Some(&rows.to_string())
            );
            assert!(
                dump.entries().contains_key(&format!("{table:?}[{rows}]")),
                "{table:?}"
            );
        }
    }

    /// Text is quoted with only `\\`, `"`, the control characters and lone surrogates
    /// escaped, as the format states.
    #[test]
    fn text_is_quoted_as_the_format_states() {
        assert_eq!(
            quoted("a\"b\\c\u{1}\u{7f}é😀".chars().map(Ok)),
            "\"a\\\"b\\\\c\\u{1}\\u{7f}é😀\""
        );
        let units = [0x61, 0xD800, 0x62, 0xD83D, 0xDE00];
        let text =
            quoted(char::decode_utf16(units).map(|unit| unit.map_err(|e| e.unpaired_surrogate())));
        assert_eq!(text, "\"a\\u{d800}b😀\"");
    }

    /// A dump survives JSON: every character, escaped or not, reads back as itself.
    #[test]
    fn a_dump_reads_back_from_its_json() {
        let mut dump = CanonicalDump::default();
        dump.put(
            "Resource[\"a\\b\"]".to_string(),
            "\u{0}\u{1f} \t\n😀é".to_string(),
        );
        dump.put("TypeDef[1]".to_string(), String::new());
        let json = dump.to_json();
        assert_eq!(CanonicalDump::from_json(&json), Ok(dump));
        assert_eq!(
            CanonicalDump::from_json("{ \"a\" : \"\\ud83d\\ude00\\/\" }")
                .unwrap()
                .entries()
                .get("a"),
            Some(&"😀/".to_string())
        );
        assert_eq!(CanonicalDump::from_json("{}"), Ok(CanonicalDump::default()));
        for broken in [
            "",
            "{",
            "{\"a\": 1}",
            "{\"a\": \"b\"} x",
            "{\"a\": \"\\ud800\"}",
        ] {
            assert!(CanonicalDump::from_json(broken).is_err(), "{broken}");
        }
    }

    /// Only the reason after `unreadable: ` or `undecodable: ` goes.
    #[test]
    fn without_reasons_keeps_the_failure_word() {
        let mut dump = CanonicalDump::default();
        dump.put("a".to_string(), "unreadable: past the file".to_string());
        dump.put("b".to_string(), "undecodable: bad opcode".to_string());
        dump.put("c".to_string(), "\"unreadable: text\"".to_string());
        let cut = dump.without_reasons();
        assert_eq!(cut.entries()["a"], "unreadable");
        assert_eq!(cut.entries()["b"], "undecodable");
        assert_eq!(cut.entries()["c"], "\"unreadable: text\"");
    }

    /// A difference names its path and both values.
    #[test]
    fn a_difference_names_its_path() {
        let mut first = CanonicalDump::default();
        first.put("TypeDef[1]".to_string(), "\"A\"".to_string());
        let mut second = first.clone();
        second.put("TypeDef[1]".to_string(), "\"B\"".to_string());
        second.put("TypeDef[2]".to_string(), "\"C\"".to_string());
        assert_eq!(
            first.diff(&second),
            [
                "TypeDef[1]: \"A\" != \"B\"".to_string(),
                "TypeDef[2]: absent, and \"C\" in the other".to_string()
            ]
        );
    }
}

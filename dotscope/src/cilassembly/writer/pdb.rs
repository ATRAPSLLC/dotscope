//! Regenerating the Portable PDB an image embeds, for a write that moves what it describes.
//!
//! # What goes stale
//!
//! An embedded Portable PDB (the debug directory's `EMBEDDED_PORTABLE_PDB` entry, `MPDB` and
//! the PDB deflated) is a metadata image of its own whose rows name the assembly's rows:
//!
//! - `MethodDebugInformation` holds one row per MethodDef, in MethodDef order, and its
//!   sequence points name a StandAloneSig row (the method's local signature);
//! - `LocalScope` and `StateMachineMethod` name MethodDef rows; `CustomDebugInformation`'s
//!   parent is any row of the `HasCustomDebugInformation` coded index, assembly rows
//!   included;
//! - import declarations name AssemblyRef rows and types, local constants name types, and
//!   async stepping information names MethodDef rows;
//! - the `#Pdb` stream holds the entry point's token and the row count of every type-system
//!   table, by which its own columns are sized and by which a reader matches it to the image.
//!
//! A write that deletes rows renumbers the ones after them, and the PDB names the old
//! numbers. A write that replaces a method's body leaves the method's sequence points, its
//! scopes and its offset-bearing custom debug information describing IL that no longer
//! exists.
//!
//! # What the rebuild does
//!
//! [`rebuild_embedded_pdb`] reads the PDB and writes a new one in which every row it keeps
//! names the row the write gives its target:
//!
//! - a `MethodDebugInformation` row per output MethodDef: the input row of the method it was,
//!   with its sequence points renumbered, or an empty row for a method the write adds or
//!   whose body it replaces;
//! - the scopes, state machines and custom debug information of methods that survive with
//!   their bodies, renumbered and sorted as the format requires, with each scope's variables
//!   and constants following it; what names a deleted row or a replaced body is dropped;
//! - documents and import scopes kept, imports naming a deleted row dropped from their blob;
//! - a `#Pdb` stream with the output's row counts and entry point, and the id derived from
//!   the new content the way a deterministic compiler derives it (`BlobContentId.FromHash`
//!   over SHA-256), so that the CodeView entry can name it.
//!
//! The `#Strings`, `#US` and `#GUID` heaps are kept as they are; a blob that changes is
//! appended to `#Blob`, which otherwise keeps every offset.
//!
//! # Reference
//!
//! * [Portable PDB v1.0](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md)
//! * [PE/COFF debug directory entries](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md)

use std::{
    collections::{HashMap, HashSet},
    io::Write,
};

use sha2::{Digest, Sha256, Sha384, Sha512};
use strum::IntoEnumIterator;

use crate::{
    cilassembly::writer::blobs::{remap_debug_tokens, BlobKind},
    metadata::{
        customdebuginformation::CustomDebugKind,
        importscope::{encode_import_records, parse_import_records},
        pdb::PdbMetadata,
        streams::{PdbStream, StreamHeader},
        tables::{
            CodedIndex, CodedIndexType, CustomDebugInformationRaw, DocumentRaw, ImportScopeRaw,
            LocalConstantRaw, LocalScopeRaw, LocalVariableRaw, MemberList, MetadataTable,
            MethodDebugInformationRaw, RowReadable, RowWritable, StateMachineMethodRaw, TableId,
            TableInfoRef, TableRow,
        },
        token::Token,
    },
    utils::write_compressed_uint,
    Error, Result,
};

/// What the write did to the assembly the PDB describes.
pub struct ImageChanges<'a> {
    /// The token an input row has in the output, `None` for a row the write deletes.
    pub token: &'a dyn Fn(Token) -> Option<Token>,
    /// The input MethodDef rows whose bodies the write replaces.
    pub replaced_bodies: &'a HashSet<u32>,
    /// The output's row count of every table, by [`TableId`].
    pub rows: [u32; 64],
}

impl ImageChanges<'_> {
    /// The output's row count of `table`.
    fn rows(&self, table: TableId) -> u32 {
        self.rows.get(table as usize).copied().unwrap_or(0)
    }
}

/// A regenerated Portable PDB.
pub struct RebuiltPdb {
    /// The PDB's bytes.
    pub bytes: Vec<u8>,
    /// Its id, as its `#Pdb` stream holds it: the CodeView entry's GUID, then its time stamp.
    pub id: [u8; 20],
    /// Where the id lies in [`Self::bytes`], for a checksum over the PDB with it zeroed.
    id_offset: usize,
}

impl RebuiltPdb {
    /// The PDB checksum a `PDB_CHECKSUM` debug entry names `algorithm` for: the hash of the
    /// PDB with its id zeroed, as the format defines it. `None` for an algorithm the
    /// format does not name.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The entry's algorithm name: `SHA256`, `SHA384` or `SHA512`
    #[must_use]
    pub fn checksum(&self, algorithm: &str) -> Option<Vec<u8>> {
        let zeroed = self.with_zeroed_id();
        match algorithm {
            "SHA256" => Some(Sha256::digest(&zeroed).to_vec()),
            "SHA384" => Some(Sha384::digest(&zeroed).to_vec()),
            "SHA512" => Some(Sha512::digest(&zeroed).to_vec()),
            _ => None,
        }
    }

    /// The PDB as an `EMBEDDED_PORTABLE_PDB` entry holds it: `MPDB`, its size, then the PDB
    /// deflated.
    ///
    /// # Errors
    ///
    /// When the PDB is larger than a `u32` can state, or deflating fails.
    pub fn embedded_entry(&self) -> Result<Vec<u8>> {
        let size = u32::try_from(self.bytes.len())
            .map_err(|_| Error::LayoutFailed("embedded Portable PDB exceeds u32".to_string()))?;
        let mut data = Vec::with_capacity(self.bytes.len() / 2);
        data.extend_from_slice(b"MPDB");
        data.extend_from_slice(&size.to_le_bytes());
        let mut encoder = flate2::write::DeflateEncoder::new(data, flate2::Compression::default());
        encoder.write_all(&self.bytes)?;
        Ok(encoder.finish()?)
    }

    /// The PDB with its id's 20 bytes zeroed.
    fn with_zeroed_id(&self) -> Vec<u8> {
        let mut zeroed = self.bytes.clone();
        if let Some(id) = zeroed.get_mut(self.id_offset..self.id_offset.saturating_add(20)) {
            id.fill(0);
        }
        zeroed
    }
}

/// The `#Blob` heap of the rebuilt PDB: the input's bytes, then the blobs the rebuild
/// changes.
struct BlobHeap {
    /// The heap's bytes.
    data: Vec<u8>,
    /// Each appended blob's offset, so that a blob appended twice is stored once.
    appended: HashMap<Vec<u8>, u32>,
}

impl BlobHeap {
    /// Appends `blob` (its compressed length, then its bytes) and returns its offset.
    fn add(&mut self, blob: Vec<u8>) -> Result<u32> {
        if let Some(&offset) = self.appended.get(&blob) {
            return Ok(offset);
        }
        let offset = u32::try_from(self.data.len())
            .map_err(|_| Error::LayoutFailed("PDB #Blob heap exceeds u32".to_string()))?;
        let length = u32::try_from(blob.len())
            .map_err(|_| Error::LayoutFailed("PDB blob exceeds u32".to_string()))?;
        write_compressed_uint(length, &mut self.data)?;
        self.data.extend_from_slice(&blob);
        self.appended.insert(blob, offset);
        Ok(offset)
    }
}

/// Every row of `table`, in order; none when the PDB has no such table.
fn rows<T: RowReadable>(table: Option<&MetadataTable<'_, T>>) -> Result<Vec<T>> {
    table.map_or_else(|| Ok(Vec::new()), |table| table.iter().collect())
}

/// Regenerates the Portable PDB `pdb` (an embedded PDB, inflated) for the output of a write
/// that changed `image` as [`ImageChanges`] states.
///
/// # Errors
///
/// When the PDB does not read (its metadata, streams or rows), or the rebuilt PDB cannot be
/// laid out (a heap or table past what its widths can index).
pub fn rebuild_embedded_pdb(pdb: &[u8], image: &ImageChanges<'_>) -> Result<RebuiltPdb> {
    let meta = PdbMetadata::read(pdb)?;
    let blob = |index: u32| -> Result<&[u8]> {
        meta.blobs
            .as_ref()
            .ok_or_else(|| malformed_error!("the PDB has rows naming blobs and no #Blob heap"))?
            .get(index as usize)
    };
    let mut heap = BlobHeap {
        data: meta
            .blobs
            .as_ref()
            .map_or_else(|| vec![0], |blobs| blobs.data().to_vec()),
        appended: HashMap::new(),
    };

    // An input token as the output names it; a deleted row becomes the null row of its
    // table, which the callers that cannot keep it check for.
    let renumber = |token: u32| -> u32 {
        (image.token)(Token::new(token)).map_or(token & 0xFF00_0000, |token| token.value())
    };
    let method = |row: u32| -> Option<u32> {
        (image.token)(Token::from_parts(TableId::MethodDef, row)).map(|token| token.row())
    };
    let keeps_body = |row: u32| method(row).is_some() && !image.replaced_bodies.contains(&row);

    let tables = meta.tables.as_ref();
    let documents: Vec<DocumentRaw> = rows(tables.and_then(|t| t.table::<DocumentRaw>()))?;
    let method_debug: Vec<MethodDebugInformationRaw> =
        rows(tables.and_then(|t| t.table::<MethodDebugInformationRaw>()))?;
    let scopes: Vec<LocalScopeRaw> = rows(tables.and_then(|t| t.table::<LocalScopeRaw>()))?;
    let variables: Vec<LocalVariableRaw> =
        rows(tables.and_then(|t| t.table::<LocalVariableRaw>()))?;
    let constants: Vec<LocalConstantRaw> =
        rows(tables.and_then(|t| t.table::<LocalConstantRaw>()))?;
    let mut import_scopes: Vec<ImportScopeRaw> =
        rows(tables.and_then(|t| t.table::<ImportScopeRaw>()))?;
    let state_machines: Vec<StateMachineMethodRaw> =
        rows(tables.and_then(|t| t.table::<StateMachineMethodRaw>()))?;
    let custom: Vec<CustomDebugInformationRaw> =
        rows(tables.and_then(|t| t.table::<CustomDebugInformationRaw>()))?;

    // MethodDebugInformation: one row per output MethodDef, or none at all when the input
    // had none (the format allows either).
    let output_methods = image.rows(TableId::MethodDef);
    let mut new_method_debug: Vec<MethodDebugInformationRaw> = Vec::new();
    if !method_debug.is_empty() {
        let mut by_output: Vec<Option<&MethodDebugInformationRaw>> =
            vec![None; output_methods as usize];
        for row in &method_debug {
            if !keeps_body(row.rid) {
                continue;
            }
            if let Some(slot) = method(row.rid)
                .and_then(|new| (new as usize).checked_sub(1))
                .and_then(|index| by_output.get_mut(index))
            {
                *slot = Some(row);
            }
        }
        for (index, input) in by_output.into_iter().enumerate() {
            let rid = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            let (document, sequence_points) = match input {
                None => (0, 0),
                Some(row) if row.sequence_points == 0 => (row.document, 0),
                Some(row) => {
                    let blob = blob(row.sequence_points)?;
                    let kind = BlobKind::SequencePoints {
                        document: row.document,
                    };
                    let points = match remap_debug_tokens(blob, kind, &mut |t| Ok(renumber(t)))? {
                        Some(remapped) => heap.add(remapped)?,
                        None => row.sequence_points,
                    };
                    (row.document, points)
                }
            };
            new_method_debug.push(MethodDebugInformationRaw {
                rid,
                token: Token::from_parts(TableId::MethodDebugInformation, rid),
                offset: 0,
                document,
                sequence_points,
            });
        }
    }

    // LocalScope, with each kept scope's variables and constants following it in order.
    let variable_runs = tables.map(|t| t.member_ranges(MemberList::LocalScopeVariables));
    let constant_runs = tables.map(|t| t.member_ranges(MemberList::LocalScopeConstants));
    let mut kept_scopes: Vec<&LocalScopeRaw> = scopes
        .iter()
        .filter(|scope| keeps_body(scope.method))
        .collect();
    kept_scopes.sort_by_key(|scope| {
        (
            method(scope.method).unwrap_or(0),
            scope.start_offset,
            std::cmp::Reverse(scope.length),
        )
    });
    let mut scope_map: HashMap<u32, u32> = HashMap::new();
    let mut variable_map: HashMap<u32, u32> = HashMap::new();
    let mut constant_map: HashMap<u32, u32> = HashMap::new();
    let mut new_variables: Vec<LocalVariableRaw> = Vec::new();
    let mut new_constants: Vec<LocalConstantRaw> = Vec::new();
    let mut new_scopes: Vec<LocalScopeRaw> = Vec::new();
    for scope in kept_scopes {
        let rid = next_rid(new_scopes.len());
        scope_map.insert(scope.rid, rid);
        let variable_list = next_rid(new_variables.len());
        for old in variable_runs
            .as_ref()
            .map(|runs| runs.range(scope.rid))
            .unwrap_or_default()
        {
            let Some(variable) = variables.get((old as usize).wrapping_sub(1)) else {
                continue;
            };
            let new = next_rid(new_variables.len());
            variable_map.insert(old, new);
            new_variables.push(LocalVariableRaw {
                rid: new,
                token: Token::from_parts(TableId::LocalVariable, new),
                ..variable.clone()
            });
        }
        let constant_list = next_rid(new_constants.len());
        for old in constant_runs
            .as_ref()
            .map(|runs| runs.range(scope.rid))
            .unwrap_or_default()
        {
            let Some(constant) = constants.get((old as usize).wrapping_sub(1)) else {
                continue;
            };
            let signature = if constant.signature == 0 {
                0
            } else {
                match remap_debug_tokens(
                    blob(constant.signature)?,
                    BlobKind::LocalConstant,
                    &mut |t| Ok(renumber(t)),
                )? {
                    Some(remapped) => heap.add(remapped)?,
                    None => constant.signature,
                }
            };
            let new = next_rid(new_constants.len());
            constant_map.insert(old, new);
            new_constants.push(LocalConstantRaw {
                rid: new,
                token: Token::from_parts(TableId::LocalConstant, new),
                signature,
                ..constant.clone()
            });
        }
        new_scopes.push(LocalScopeRaw {
            rid,
            token: Token::from_parts(TableId::LocalScope, rid),
            method: method(scope.method).unwrap_or(0),
            variable_list,
            constant_list,
            ..scope.clone()
        });
    }

    // ImportScope: every scope kept; a declaration naming a deleted row is dropped from its
    // blob.
    for scope in &mut import_scopes {
        if scope.imports == 0 {
            continue;
        }
        let Ok(records) = parse_import_records(blob(scope.imports)?) else {
            continue;
        };
        let mut changed = false;
        let mut kept = Vec::with_capacity(records.len());
        for mut record in records {
            if record.assembly != 0 {
                let Some(assembly) =
                    (image.token)(Token::from_parts(TableId::AssemblyRef, record.assembly))
                else {
                    changed = true;
                    continue;
                };
                changed |= assembly.row() != record.assembly;
                record.assembly = assembly.row();
            }
            if let Some(target) = record.target {
                let Some(new) = (image.token)(target) else {
                    changed = true;
                    continue;
                };
                changed |= new != target;
                record.target = Some(new);
            }
            kept.push(record);
        }
        if changed {
            scope.imports = heap.add(encode_import_records(&kept)?)?;
        }
    }

    // StateMachineMethod: kept while both methods are, sorted by the MoveNext method.
    let mut new_state_machines: Vec<StateMachineMethodRaw> = state_machines
        .iter()
        .filter_map(|row| {
            Some(StateMachineMethodRaw {
                move_next_method: method(row.move_next_method)?,
                kickoff_method: method(row.kickoff_method)?,
                ..row.clone()
            })
        })
        .collect();
    new_state_machines.sort_by_key(|row| row.move_next_method);
    for (index, row) in new_state_machines.iter_mut().enumerate() {
        row.rid = next_rid(index);
        row.token = Token::from_parts(TableId::StateMachineMethod, row.rid);
    }

    // CustomDebugInformation: kept while its parent is, and, on a method, while the method
    // keeps its body (what describes a method describes its IL).
    let mut new_custom: Vec<CustomDebugInformationRaw> = Vec::new();
    for row in &custom {
        let parent = row.parent.row;
        let new_parent = match row.parent.tag {
            TableId::LocalScope => scope_map.get(&parent).copied(),
            TableId::LocalVariable => variable_map.get(&parent).copied(),
            TableId::LocalConstant => constant_map.get(&parent).copied(),
            TableId::Document | TableId::ImportScope => Some(parent),
            TableId::MethodDef if !keeps_body(parent) => None,
            tag => (image.token)(Token::from_parts(tag, parent)).map(|token| token.row()),
        };
        let Some(new_parent) = new_parent else {
            continue;
        };
        let kind = meta
            .guids
            .as_ref()
            .and_then(|guids| guids.get(row.kind as usize).ok())
            .map(CustomDebugKind::from_guid);
        let mut value = row.value;
        if kind == Some(CustomDebugKind::AsyncMethodSteppingInformation) && value != 0 {
            let mut dangles = false;
            let remapped =
                remap_debug_tokens(blob(value)?, BlobKind::AsyncMethodStepping, &mut |token| {
                    let new = renumber(token);
                    dangles |= new & 0x00FF_FFFF == 0;
                    Ok(new)
                })?;
            if dangles {
                continue;
            }
            if let Some(remapped) = remapped {
                value = heap.add(remapped)?;
            }
        }
        new_custom.push(CustomDebugInformationRaw {
            parent: CodedIndex::new(
                row.parent.tag,
                new_parent,
                CodedIndexType::HasCustomDebugInformation,
            ),
            value,
            ..row.clone()
        });
    }

    // The output's widths: the PDB's own row counts, the output assembly's row counts for
    // the columns indexing it, and the heaps as written.
    let own_rows: [(TableId, u32); 8] = [
        (TableId::Document, count(documents.len())?),
        (
            TableId::MethodDebugInformation,
            count(new_method_debug.len())?,
        ),
        (TableId::LocalScope, count(new_scopes.len())?),
        (TableId::LocalVariable, count(new_variables.len())?),
        (TableId::LocalConstant, count(new_constants.len())?),
        (TableId::ImportScope, count(import_scopes.len())?),
        (
            TableId::StateMachineMethod,
            count(new_state_machines.len())?,
        ),
        (TableId::CustomDebugInformation, count(new_custom.len())?),
    ];
    let type_system = |table: TableId| (table as u8) < TableId::Document as u8;
    let heap_len = |name: &str| {
        meta.root
            .stream_headers
            .iter()
            .find(|stream| stream.name == name)
            .map_or(0, |stream| stream.size as usize)
    };
    let info: Option<TableInfoRef> = tables.map(|t| {
        let external = TableId::iter()
            .filter(|table| type_system(*table))
            .map(|table| (table, image.rows(table)));
        std::sync::Arc::new(
            t.info
                .with_modified_row_counts(own_rows.iter().copied().chain(external))
                .with_modified_heap_sizes(heap_len("#Strings"), heap_len("#GUID"), heap.data.len()),
        )
    });

    // CustomDebugInformation is sorted by its parent's encoded value.
    if let Some(info) = &info {
        let mut keyed = new_custom
            .into_iter()
            .map(|row| Ok((row.parent.encode(info)?, row)))
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by_key(|(key, _)| *key);
        new_custom = keyed.into_iter().map(|(_, row)| row).collect();
    }
    for (index, row) in new_custom.iter_mut().enumerate() {
        row.rid = next_rid(index);
        row.token = Token::from_parts(TableId::CustomDebugInformation, row.rid);
    }

    // The tables stream.
    let tables_stream = match (tables, &info) {
        (Some(header), Some(info)) => {
            let valid = own_rows
                .iter()
                .filter(|(_, rows)| *rows > 0)
                .fold(0u64, |mask, (table, _)| mask | (1u64 << (*table as u8)));
            let mut data = Vec::new();
            data.extend_from_slice(&0u32.to_le_bytes());
            data.push(header.major_version);
            data.push(header.minor_version);
            data.push(info.heap_sizes());
            data.push(1);
            data.extend_from_slice(&valid.to_le_bytes());
            data.extend_from_slice(&header.sorted.to_le_bytes());
            for (_, rows) in own_rows.iter().filter(|(_, rows)| *rows > 0) {
                data.extend_from_slice(&rows.to_le_bytes());
            }
            write_rows(&mut data, &documents, info)?;
            write_rows(&mut data, &new_method_debug, info)?;
            write_rows(&mut data, &new_scopes, info)?;
            write_rows(&mut data, &new_variables, info)?;
            write_rows(&mut data, &new_constants, info)?;
            write_rows(&mut data, &import_scopes, info)?;
            write_rows(&mut data, &new_state_machines, info)?;
            write_rows(&mut data, &new_custom, info)?;
            Some(data)
        }
        _ => None,
    };

    // The `#Pdb` stream: the output's entry point and type-system row counts, the id zeroed
    // until the content it is derived from is complete.
    let referenced = TableId::iter()
        .filter(|table| type_system(*table) && image.rows(*table) > 0)
        .fold(0u64, |mask, table| mask | (1u64 << (table as u8)));
    let mut type_system_rows = [0u32; 64];
    for (index, slot) in type_system_rows.iter_mut().enumerate() {
        if referenced & (1u64 << index) != 0 {
            *slot = image.rows.get(index).copied().unwrap_or(0);
        }
    }
    let pdb_stream = PdbStream {
        id: [0; 20],
        entry_point: meta
            .pdb_stream
            .entry_point
            .and_then(|entry| (image.token)(entry)),
        referenced_tables: referenced,
        type_system_rows,
    }
    .to_bytes();

    // The metadata root and its streams, in the input's order.
    let stream_bytes = |header: &StreamHeader| -> Option<Vec<u8>> {
        match header.name.as_str() {
            "#Pdb" => Some(pdb_stream.clone()),
            "#~" | "#-" => tables_stream.clone(),
            "#Blob" => Some(heap.data.clone()),
            _ => pdb
                .get(
                    header.offset as usize
                        ..(header.offset as usize).saturating_add(header.size as usize),
                )
                .map(<[u8]>::to_vec),
        }
    };
    let mut root = meta.root.clone();
    let mut streams: Vec<(StreamHeader, Vec<u8>)> = Vec::new();
    for header in &meta.root.stream_headers {
        let Some(mut bytes) = stream_bytes(header) else {
            continue;
        };
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        let name = if header.name == "#-" {
            "#~".to_string()
        } else {
            header.name.clone()
        };
        streams.push((
            StreamHeader {
                offset: 0,
                size: count(bytes.len())?,
                name,
            },
            bytes,
        ));
    }
    root.stream_number = u16::try_from(streams.len())
        .map_err(|_| Error::LayoutFailed("PDB stream count exceeds u16".to_string()))?;
    root.stream_headers = streams.iter().map(|(header, _)| header.clone()).collect();
    let mut position = root.serialized_size();
    for (header, bytes) in &mut streams {
        header.offset = count(position)?;
        position = position.saturating_add(bytes.len());
    }
    root.stream_headers = streams.iter().map(|(header, _)| header.clone()).collect();

    let mut bytes = Vec::with_capacity(position);
    root.write_to(&mut bytes)?;
    let mut id_offset = None;
    for (header, data) in &streams {
        if header.name == "#Pdb" {
            id_offset = Some(bytes.len());
        }
        bytes.extend_from_slice(data);
    }
    let id_offset = id_offset.ok_or_else(|| malformed_error!("the PDB has no #Pdb stream"))?;

    // The id, from the content with the id zeroed (Roslyn's `BlobContentId.FromHash`): the
    // hash's first 16 bytes as a version-4 GUID, then its next 4 with the top bit set.
    let hash = Sha256::digest(&bytes);
    let mut id = [0u8; 20];
    id.copy_from_slice(
        hash.get(..20)
            .ok_or_else(|| malformed_error!("short hash"))?,
    );
    id[7] = (id[7] & 0x0F) | (4 << 4);
    id[8] = (id[8] & 0x3F) | (2 << 6);
    id[19] |= 0x80;
    if let Some(slot) = bytes.get_mut(id_offset..id_offset.saturating_add(20)) {
        slot.copy_from_slice(&id);
    }

    Ok(RebuiltPdb {
        bytes,
        id,
        id_offset,
    })
}

/// The rid of the row after `len` rows.
fn next_rid(len: usize) -> u32 {
    u32::try_from(len.saturating_add(1)).unwrap_or(u32::MAX)
}

/// `len` as a row count or size.
fn count(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::LayoutFailed(format!("{len} exceeds u32")))
}

/// Appends `rows`, each written at its rid with `info`'s widths.
fn write_rows<T: RowWritable + TableRow>(
    data: &mut Vec<u8>,
    rows: &[T],
    info: &TableInfoRef,
) -> Result<()> {
    let size = T::row_size(info) as usize;
    let start = data.len();
    data.resize(start.saturating_add(size.saturating_mul(rows.len())), 0);
    let mut offset = start;
    for (index, row) in rows.iter().enumerate() {
        row.row_write(data, &mut offset, next_rid(index), info)?;
    }
    Ok(())
}

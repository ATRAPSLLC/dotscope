//! Identity checks: what dotscope reads from an assembly's tables and heaps is what is there.
//!
//! [`TableRows`] holds every row codec to its own bytes: a row reads exactly its table's row
//! size, and writing it back gives the bytes it was read from. [`Heaps`] walks each heap as
//! ECMA-335 II.24.2 lays it out, independently of dotscope's heap readers, and holds those
//! readers to the walk: every entry is found, at its offset, with its content.

use std::collections::HashSet;

use crate::{
    metadata::{
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tables::*,
    },
    testkit::corpus::{CorpusCheck, CorpusItem},
};

/// How many findings one table or heap reports before it counts the rest.
const FINDINGS_PER_PART: usize = 3;

/// Every row of every table reads back to its own bytes.
pub struct TableRows;

impl CorpusCheck for TableRows {
    fn id(&self) -> &'static str {
        "tables.row_identity"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Some(tables) = item.metadata().and_then(|metadata| metadata.tables) else {
            return Vec::new();
        };
        table_row_findings(tables)
    }
}

/// Applies the macro `$apply` to the row type of every table, `$apply!(ModuleRaw, ...)`: one
/// list of the tables for every check that covers them all.
macro_rules! raw_tables {
    ($apply:ident) => {
        $apply!(
            ModuleRaw,
            TypeRefRaw,
            TypeDefRaw,
            FieldPtrRaw,
            FieldRaw,
            MethodPtrRaw,
            MethodDefRaw,
            ParamPtrRaw,
            ParamRaw,
            InterfaceImplRaw,
            MemberRefRaw,
            ConstantRaw,
            CustomAttributeRaw,
            FieldMarshalRaw,
            DeclSecurityRaw,
            ClassLayoutRaw,
            FieldLayoutRaw,
            StandAloneSigRaw,
            EventMapRaw,
            EventPtrRaw,
            EventRaw,
            PropertyMapRaw,
            PropertyPtrRaw,
            PropertyRaw,
            MethodSemanticsRaw,
            MethodImplRaw,
            ModuleRefRaw,
            TypeSpecRaw,
            ImplMapRaw,
            FieldRvaRaw,
            EncLogRaw,
            EncMapRaw,
            AssemblyRaw,
            AssemblyProcessorRaw,
            AssemblyOsRaw,
            AssemblyRefRaw,
            AssemblyRefProcessorRaw,
            AssemblyRefOsRaw,
            FileRaw,
            ExportedTypeRaw,
            ManifestResourceRaw,
            NestedClassRaw,
            GenericParamRaw,
            MethodSpecRaw,
            GenericParamConstraintRaw,
            DocumentRaw,
            MethodDebugInformationRaw,
            LocalScopeRaw,
            LocalVariableRaw,
            LocalConstantRaw,
            ImportScopeRaw,
            StateMachineMethodRaw,
            CustomDebugInformationRaw,
        )
    };
}
pub(crate) use raw_tables;

/// What the rows of `tables` get wrong, every table checked.
fn table_row_findings(tables: &TablesHeader<'_>) -> Vec<String> {
    let mut findings = Vec::new();
    let mut visited = HashSet::new();
    macro_rules! check {
        ($($raw:ty),* $(,)?) => {
            $(
                if let Some(table) = tables.table::<$raw>() {
                    visited.insert(<$raw as RowReadable>::TABLE_ID);
                    findings.extend(rows_of(table));
                }
            )*
        };
    }
    raw_tables!(check);
    // A table this check has no row type for is a table it did not check
    for table in tables.present_tables() {
        if !visited.contains(&table) {
            findings.push(format!("{table:?}: present, and not checked"));
        }
    }
    findings
}

/// What the rows of `table` get wrong: a row that does not read, reads more or fewer bytes
/// than the table's row size, or writes back to bytes other than its own.
fn rows_of<T: RowReadable + RowWritable>(table: &MetadataTable<'_, T>) -> Vec<String> {
    let id = T::TABLE_ID;
    let size = table.row_size as usize;
    let mut findings = Vec::new();
    let mut failing = 0usize;
    for rid in 1..=table.row_count {
        let start = (rid as usize - 1) * size;
        let Some(bytes) = table.data.get(start..start + size) else {
            findings.push(format!("{id:?} row {rid}: lies past the table's data"));
            break;
        };
        let mut offset = start;
        let problem = match T::row_read(table.data, &mut offset, rid, &table.sizes) {
            Err(error) => Some(format!("does not read: {error}")),
            Ok(_) if offset - start != size => Some(format!(
                "reads {} bytes of a {size}-byte row",
                offset - start
            )),
            Ok(row) => {
                let mut written = vec![0u8; size];
                let mut end = 0;
                match row.row_write(&mut written, &mut end, rid, &table.sizes) {
                    Err(error) => Some(format!("does not write: {error}")),
                    Ok(()) if end != size => {
                        Some(format!("writes {end} bytes of a {size}-byte row"))
                    }
                    Ok(()) if written != bytes => Some(format!(
                        "writes {written:02x?} back, read from {bytes:02x?}"
                    )),
                    Ok(()) => None,
                }
            }
        };
        if let Some(problem) = problem {
            failing += 1;
            if failing <= FINDINGS_PER_PART {
                findings.push(format!("{id:?} row {rid}: {problem}"));
            }
        }
    }
    if failing > FINDINGS_PER_PART {
        findings.push(format!(
            "{id:?}: {} more rows like these",
            failing - FINDINGS_PER_PART
        ));
    }
    findings
}

/// Every heap reads as ECMA-335 II.24.2 lays it out.
pub struct Heaps;

impl CorpusCheck for Heaps {
    fn id(&self) -> &'static str {
        "heaps.identity"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Some(metadata) = item.metadata() else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        if let Some(strings) = metadata.strings {
            findings.extend(strings_findings(strings));
        }
        if let Some(userstrings) = metadata.userstrings {
            findings.extend(userstrings_findings(userstrings));
        }
        if let Some(blobs) = metadata.blobs {
            findings.extend(blob_findings(blobs));
        }
        if let Some(guids) = metadata.guids {
            findings.extend(guid_findings(guids));
        }
        findings
    }
}

/// The findings `found` holds, the first [`FINDINGS_PER_PART`] and a count of the rest.
fn capped(heap: &str, found: Vec<String>) -> Vec<String> {
    let more = found.len().saturating_sub(FINDINGS_PER_PART);
    let mut findings: Vec<String> = found
        .into_iter()
        .take(FINDINGS_PER_PART)
        .map(|finding| format!("{heap}: {finding}"))
        .collect();
    if more > 0 {
        findings.push(format!("{heap}: {more} more findings like these"));
    }
    findings
}

/// `#Strings`: entries from offset 1, each up to its null terminator (II.24.2.3).
fn strings_findings(strings: &Strings<'_>) -> Vec<String> {
    let data = strings.data();
    let mut walked: Vec<(usize, &[u8])> = Vec::new();
    let mut position = 1;
    while position < data.len() {
        let rest = &data[position..];
        let length = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        walked.push((position, &rest[..length]));
        position += length + 1;
    }

    let mut found = Vec::new();
    let entries: Vec<(usize, &[u8])> = strings.entries().collect();
    if entries != walked {
        found.push(format!(
            "{} entries read, {} in the heap; the first that differs is at offset {}",
            entries.len(),
            walked.len(),
            entries
                .iter()
                .zip(&walked)
                .find(|(read, walk)| read != walk)
                .map_or(entries.len().min(walked.len()), |(_, walk)| walk.0)
        ));
    }
    let utf8: Vec<(usize, &str)> = walked
        .iter()
        .filter_map(|&(offset, bytes)| Some((offset, std::str::from_utf8(bytes).ok()?)))
        .collect();
    let iterated: Vec<(usize, &str)> = strings.iter().collect();
    if iterated != utf8 {
        found.push(format!(
            "iteration finds {} strings, the heap holds {} that are UTF-8",
            iterated.len(),
            utf8.len()
        ));
    }
    for &(offset, text) in &utf8 {
        // An unterminated last entry is not a string `get` can return
        if data.get(offset + text.len()) != Some(&0) {
            continue;
        }
        match strings.get(offset) {
            Ok(read) if read == text => {}
            Ok(read) => found.push(format!("offset {offset} reads {read:?}, holds {text:?}")),
            Err(error) => found.push(format!("offset {offset} does not read: {error}")),
        }
    }
    capped("#Strings", found)
}

/// One entry of a heap whose entries are length-prefixed (`#US`, `#Blob`, II.24.2.4): its
/// offset and the bytes the length covers; or where the chain breaks.
fn length_chain(data: &[u8], from: usize) -> (Vec<(usize, &[u8])>, Option<String>) {
    let mut entries = Vec::new();
    let mut position = from;
    while position < data.len() {
        let first = data[position];
        let (length, prefix) = match first {
            b if b & 0x80 == 0 => (usize::from(b), 1),
            b if b & 0xC0 == 0x80 => match data.get(position + 1) {
                Some(&next) => ((usize::from(b & 0x3F) << 8) | usize::from(next), 2),
                None => return (entries, Some(format!("a length at {position} is cut off"))),
            },
            b if b & 0xE0 == 0xC0 => match data.get(position + 1..position + 4) {
                Some(rest) => (
                    (usize::from(b & 0x1F) << 24)
                        | (usize::from(rest[0]) << 16)
                        | (usize::from(rest[1]) << 8)
                        | usize::from(rest[2]),
                    4,
                ),
                None => return (entries, Some(format!("a length at {position} is cut off"))),
            },
            _ => {
                return (
                    entries,
                    Some(format!(
                        "no length can start with {first:#04x} at {position}"
                    )),
                )
            }
        };
        let start = position + prefix;
        let Some(bytes) = data.get(start..start + length) else {
            return (
                entries,
                Some(format!(
                    "the {length}-byte entry at {position} runs past the heap"
                )),
            );
        };
        entries.push((position, bytes));
        position = start + length;
    }
    (entries, None)
}

/// `#US`: length-prefixed entries from offset 1, each UTF-16 code units and a terminal byte.
fn userstrings_findings(userstrings: &UserStrings<'_>) -> Vec<String> {
    let (walked, broken) = length_chain(userstrings.data(), 1);
    let mut found: Vec<String> = broken.into_iter().collect();
    // An entry holds a string when its length is odd: code units and the terminal byte
    let strings: Vec<(usize, Vec<u16>)> = walked
        .iter()
        .filter(|(_, bytes)| bytes.len() % 2 == 1)
        .map(|&(offset, bytes)| {
            let units = bytes[..bytes.len() - 1]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            (offset, units)
        })
        .collect();
    let iterated: Vec<(usize, Vec<u16>)> = userstrings
        .iter()
        .map(|(offset, text)| (offset, text.into_vec()))
        .collect();
    if iterated != strings {
        let first = iterated
            .iter()
            .zip(&strings)
            .find(|(read, walk)| read != walk)
            .map_or(iterated.len().min(strings.len()), |(_, walk)| walk.0);
        found.push(format!(
            "iteration finds {} strings, the heap holds {}; the first that differs is at {first}",
            iterated.len(),
            strings.len()
        ));
    }
    for (offset, units) in &strings {
        match userstrings.get(*offset) {
            Ok(read) if read.as_slice() == units.as_slice() => {}
            Ok(_) => found.push(format!("offset {offset} reads another string")),
            Err(error) => found.push(format!("offset {offset} does not read: {error}")),
        }
    }
    capped("#US", found)
}

/// `#Blob`: length-prefixed entries from offset 0.
fn blob_findings(blobs: &Blob<'_>) -> Vec<String> {
    let (walked, broken) = length_chain(blobs.data(), 0);
    let mut found: Vec<String> = broken.into_iter().collect();
    let iterated: Vec<(usize, &[u8])> = blobs.iter().collect();
    // The iterator starts after the empty blob at offset 0
    let expected: Vec<(usize, &[u8])> = walked
        .iter()
        .copied()
        .filter(|(offset, _)| *offset >= iterated.first().map_or(0, |first| first.0))
        .collect();
    if iterated != expected {
        found.push(format!(
            "iteration finds {} blobs, the heap holds {}",
            iterated.len(),
            expected.len()
        ));
    }
    for &(offset, bytes) in &walked {
        match blobs.get(offset) {
            Ok(read) if read == bytes => {}
            Ok(_) => found.push(format!("offset {offset} reads another blob")),
            Err(error) => found.push(format!("offset {offset} does not read: {error}")),
        }
    }
    capped("#Blob", found)
}

/// `#GUID`: 16-byte entries, numbered from 1.
fn guid_findings(guids: &Guid<'_>) -> Vec<String> {
    let data = guids.data();
    let mut found = Vec::new();
    if !data.len().is_multiple_of(16) {
        found.push(format!("{} bytes, not a whole number of GUIDs", data.len()));
    }
    let iterated: Vec<(usize, [u8; 16])> = guids
        .iter()
        .map(|(index, guid)| (index, guid.to_bytes()))
        .collect();
    let walked: Vec<(usize, [u8; 16])> = data
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
        .map(|(index, chunk)| (index + 1, *chunk))
        .collect();
    if iterated != walked {
        found.push(format!(
            "iteration finds {} GUIDs, the heap holds {}",
            iterated.len(),
            walked.len()
        ));
    }
    capped("#GUID", found)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strum::IntoEnumIterator;

    use super::*;
    use crate::metadata::{
        tablefields::{get_heap_fields, HeapFieldDescriptor, HeapType},
        tables::{CodedIndexType, TableId, TableInfo, TableInfoRef},
    };

    /// Rows read from random bytes, per table and layout.
    const ROWS: usize = 64;

    /// A deterministic stream of pseudo-random bytes (xorshift64*).
    struct Bytes(u64);

    impl Bytes {
        fn fill(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                *byte = (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
            }
        }
    }

    /// Every column width a table can have: every table at one row (2-byte indices) and at
    /// 0x10000 rows (4-byte), with small and large heaps, and each coded index family on both
    /// sides of the row count past which it widens.
    fn layouts() -> Vec<(String, TableInfoRef)> {
        let tables: Vec<TableId> = TableId::iter().collect();
        let all =
            |rows: u32| -> Vec<(TableId, u32)> { tables.iter().map(|&t| (t, rows)).collect() };
        let mut layouts = Vec::new();
        for (rows, heaps) in [(1u32, false), (0x10000, true), (1, true), (0x10000, false)] {
            layouts.push((
                format!("{rows} rows, large heaps {heaps}"),
                Arc::new(TableInfo::new_test(&all(rows), heaps, heaps, heaps)),
            ));
        }
        for coded in CodedIndexType::iter() {
            let limit = 1u32 << (16 - u32::from(coded.tag_bits()));
            for rows in [limit - 1, limit] {
                let mut counts = all(1);
                for table in coded.tables() {
                    if let Some(entry) = counts.iter_mut().find(|(t, _)| t == table) {
                        entry.1 = rows;
                    }
                }
                layouts.push((
                    format!("{coded:?} tables at {rows} rows"),
                    Arc::new(TableInfo::new_test(&counts, false, false, false)),
                ));
            }
        }
        layouts
    }

    /// What random rows of `T` get wrong under each layout: a row that reads must be its
    /// row size long and write back to the bytes it was read from.
    fn random_rows<T: RowReadable + RowWritable>(
        layouts: &[(String, TableInfoRef)],
        bytes: &mut Bytes,
    ) -> Vec<String> {
        let mut findings = Vec::new();
        for (layout, sizes) in layouts {
            let size = T::row_size(sizes) as usize;
            let mut read_none = true;
            for _ in 0..ROWS {
                let mut row = vec![0u8; size];
                bytes.fill(&mut row);
                let mut offset = 0;
                let Ok(value) = T::row_read(&row, &mut offset, 1, sizes) else {
                    continue;
                };
                read_none = false;
                let mut written = vec![0u8; size];
                let mut end = 0;
                let outcome = value.row_write(&mut written, &mut end, 1, sizes);
                if offset != size || outcome.is_err() || end != size || written != row {
                    findings.push(format!(
                        "{:?} under {layout}: {row:02x?} reads {offset} bytes and writes \
                         {written:02x?} ({outcome:?})",
                        T::TABLE_ID
                    ));
                    break;
                }
            }
            if read_none {
                findings.push(format!(
                    "{:?} under {layout}: no random row reads",
                    T::TABLE_ID
                ));
            }
        }
        findings
    }

    /// Every table's rows round-trip under every column width (ECMA-335 II.24.2.6).
    #[test]
    fn rows_round_trip_under_every_layout() {
        let layouts = layouts();
        let mut bytes = Bytes(0x9E37_79B9_7F4A_7C15);
        let mut findings = Vec::new();
        macro_rules! round_trip {
            ($($raw:ty),* $(,)?) => {
                $( findings.extend(random_rows::<$raw>(&layouts, &mut bytes)); )*
            };
        }
        raw_tables!(round_trip);
        assert!(findings.is_empty(), "{}", findings.join("\n"));
    }

    /// What `tablefields` says about `T`'s heap columns that its row codec contradicts: read a
    /// random row under `narrow`, write it under `wide` (one heap's indices widened), and the
    /// heap columns `get_heap_fields` names under each layout must hold the same values, every
    /// other byte the same bytes in the same order.
    fn heap_fields_of<T: RowReadable + RowWritable>(
        narrow: &TableInfoRef,
        wide: &TableInfoRef,
        layout: &str,
        bytes: &mut Bytes,
    ) -> Vec<String> {
        let id = T::TABLE_ID;
        let narrow_fields = get_heap_fields(id, narrow);
        let wide_fields = get_heap_fields(id, wide);
        let kinds = |fields: &[HeapFieldDescriptor]| -> Vec<HeapType> {
            fields.iter().map(|field| field.heap_type).collect()
        };
        if kinds(&narrow_fields) != kinds(&wide_fields) {
            return vec![format!(
                "{id:?} under {layout}: the heap columns differ by layout"
            )];
        }
        let value = |row: &[u8], field: &HeapFieldDescriptor| -> u32 {
            row[field.offset..field.offset + field.size]
                .iter()
                .rev()
                .fold(0, |value, &byte| value << 8 | u32::from(byte))
        };
        let rest = |row: &[u8], fields: &[HeapFieldDescriptor]| -> Vec<u8> {
            row.iter()
                .enumerate()
                .filter(|(at, _)| {
                    !fields
                        .iter()
                        .any(|field| (field.offset..field.offset + field.size).contains(at))
                })
                .map(|(_, &byte)| byte)
                .collect()
        };
        let narrow_size = T::row_size(narrow) as usize;
        let wide_size = T::row_size(wide) as usize;
        for _ in 0..ROWS {
            let mut row = vec![0u8; narrow_size];
            bytes.fill(&mut row);
            let Ok(value_read) = T::row_read(&row, &mut 0, 1, narrow) else {
                continue;
            };
            let mut written = vec![0u8; wide_size];
            if value_read.row_write(&mut written, &mut 0, 1, wide).is_err() {
                return vec![format!("{id:?} under {layout}: a row does not write")];
            }
            for (narrow_field, wide_field) in narrow_fields.iter().zip(&wide_fields) {
                if value(&row, narrow_field) != value(&written, wide_field) {
                    return vec![format!(
                        "{id:?} under {layout}: the {:?} column at {} holds another value \
                         than the codec writes there",
                        wide_field.heap_type, wide_field.offset
                    )];
                }
            }
            if rest(&row, &narrow_fields) != rest(&written, &wide_fields) {
                return vec![format!(
                    "{id:?} under {layout}: the columns outside the named heap columns differ \
                     (a heap column is missing or misplaced)"
                )];
            }
            return Vec::new();
        }
        vec![format!("{id:?} under {layout}: no random row reads")]
    }

    /// `get_heap_fields`, which the writer patches heap references through, names exactly the
    /// heap columns each row codec reads and writes, at the offsets it uses.
    #[test]
    fn heap_fields_name_the_heap_columns_the_codecs_use() {
        let tables: Vec<TableId> = TableId::iter().collect();
        let mut bytes = Bytes(0xD1B5_4A32_D192_ED03);
        let mut findings = Vec::new();
        for rows in [1u32, 0x10000] {
            let counts: Vec<(TableId, u32)> = tables.iter().map(|&t| (t, rows)).collect();
            let layout = |str_large, blob_large, guid_large| -> TableInfoRef {
                Arc::new(TableInfo::new_test(
                    &counts, str_large, blob_large, guid_large,
                ))
            };
            for (heap, wide) in [
                ("#Strings", layout(true, false, false)),
                ("#Blob", layout(false, true, false)),
                ("#GUID", layout(false, false, true)),
            ] {
                let narrow = layout(false, false, false);
                let name = format!("{rows} rows, {heap} widened");
                macro_rules! heap_fields {
                    ($($raw:ty),* $(,)?) => {
                        $( findings.extend(heap_fields_of::<$raw>(&narrow, &wide, &name, &mut bytes)); )*
                    };
                }
                raw_tables!(heap_fields);
            }
        }
        assert!(findings.is_empty(), "{}", findings.join("\n"));
    }
}

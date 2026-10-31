//! The import and export directories, read entry by entry as the Windows loader walks them.
//!
//! goblin's lists leave out what it cannot read: an import whose hint/name RVA maps nowhere,
//! a descriptor whose lookup tables do not map, an export directory that does not parse.
//! They list only the named exports, with no ordinals. A table rebuilt from them is a smaller
//! table, so these readers read every entry, and say where a table cannot be read in full:
//! what wrote it back would otherwise drop the rest.
//!
//! RVAs are mapped by [`SectionMap`]: an entry in a section's zero-filled part reads as zero,
//! and one no section holds cannot be read.
//!
//! The loader accepts tables that share their parts: descriptors that share a lookup table,
//! entries that share a name or name a suffix of another's. These readers read them as the
//! loader does, but what a walk produces is bounded by the file's size (see
//! [`Image::charge`]): sharing lets a small file describe more entries and name bytes than
//! any consumer could hold.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::file::{
    pe::{DataDirectory, Export, ExportHeader, Import},
    sectionmap::{RvaMapping, SectionMap},
};

/// The size of an import directory entry (`IMAGE_IMPORT_DESCRIPTOR`).
const IMPORT_DESCRIPTOR_SIZE: u32 = 20;

/// The size of the export directory (`IMAGE_EXPORT_DIRECTORY`).
const EXPORT_DIRECTORY_SIZE: u32 = 40;

/// An import directory as read: every entry, in table order, and why the walk stopped short,
/// when it did.
#[derive(Debug, Default)]
pub(crate) struct ImportTable {
    pub imports: Vec<Import>,
    /// Each DLL the table names, once, in table order.
    pub libraries: Vec<String>,
    pub error: Option<String>,
}

/// An export directory as read: its header and every exported ordinal (an ordinal with
/// several names once per name), in ordinal order, and why the walk stopped short, when it
/// did.
#[derive(Debug, Default)]
pub(crate) struct ExportTable {
    pub header: Option<ExportHeader>,
    pub exports: Vec<Export>,
    pub error: Option<String>,
}

/// The loaded image's bytes, through its RVA mapping, and how much more a walk may produce.
struct Image<'a> {
    map: SectionMap<'a>,
    data: &'a [u8],
    /// The bytes a walk may still produce, the file's size to start with
    budget: usize,
}

impl<'a> Image<'a> {
    fn new(map: SectionMap<'a>, data: &'a [u8]) -> Self {
        Image {
            map,
            data,
            budget: data.len(),
        }
    }

    /// Counts `bytes` of what the walk produces against the file's size: each import's lookup
    /// entry, and each name an entry holds, every time an entry holds it. When no two entries
    /// share them these are distinct bytes of the file, so a table laid out entry by entry
    /// always fits. Shared, they can describe far more: descriptors sharing one lookup table
    /// give descriptors x entries imports, and names that are suffixes of one string a
    /// suffix each. Counting them as if unshared bounds both the walk and every consumer
    /// that holds an entry's name per entry.
    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        self.budget = self.budget.checked_sub(bytes).ok_or_else(|| {
            format!(
                "its entries and names, counted once per entry, are more than the file's {} \
                 bytes",
                self.data.len()
            )
        })?;
        Ok(())
    }

    /// The `width`-byte little-endian value at `rva`.
    fn value(&self, rva: u32, width: usize) -> Result<u64, String> {
        let bytes = self
            .map
            .read(self.data, rva, width)
            .map_err(|_| format!("RVA {rva:#x} is not a byte of the image"))?;
        let mut value = [0u8; 8];
        value
            .get_mut(..width)
            .ok_or_else(|| format!("a {width}-byte value"))?
            .copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(value))
    }

    /// The four-byte value at `offset` past `base`.
    fn dword(&self, base: u32, offset: u32) -> Result<u32, String> {
        let rva = at(base, offset)?;
        // A four-byte read holds four bytes
        Ok(u32::try_from(self.value(rva, 4)?).unwrap_or(u32::MAX))
    }

    /// The two-byte value at `offset` past `base`.
    fn word(&self, base: u32, offset: u32) -> Result<u16, String> {
        let rva = at(base, offset)?;
        Ok(u16::try_from(self.value(rva, 2)?).unwrap_or(u16::MAX))
    }

    /// The zero-terminated name at `rva`, charged to the walk. Zero bytes past a section's
    /// raw data end it as well as a terminator in the file does.
    fn name(&mut self, rva: u32) -> Result<String, String> {
        let backed = self
            .map
            .section_bounded(self.data, rva)
            .map_err(|_| format!("the name at RVA {rva:#x} is not in the image"))?;
        let bytes = match backed.iter().position(|&byte| byte == 0) {
            Some(end) => backed.get(..end).unwrap_or_default(),
            None => {
                let after = u32::try_from(backed.len())
                    .ok()
                    .and_then(|len| rva.checked_add(len));
                if after.map(|after| self.map.map(after)) != Some(RvaMapping::ZeroFill) {
                    return Err(format!("the name at RVA {rva:#x} has no terminator"));
                }
                backed
            }
        };
        self.charge(bytes.len())?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| format!("the name at RVA {rva:#x} is not UTF-8"))
    }
}

/// `base + offset`, where an RVA cannot reach past 4 GB.
fn at(base: u32, offset: u32) -> Result<u32, String> {
    base.checked_add(offset)
        .ok_or_else(|| format!("RVA {base:#x} + {offset:#x} is past 4 GB"))
}

/// The import directory `directory` names, read as the loader walks it: descriptors up to
/// the first without a name or an import address table, each one's lookup table (its import
/// address table when it has none) up to its zero entry.
pub(crate) fn read_imports(
    map: SectionMap<'_>,
    data: &[u8],
    directory: Option<&DataDirectory>,
    is_64bit: bool,
) -> ImportTable {
    let mut table = ImportTable::default();
    if let Some(directory) = directory.filter(|directory| directory.virtual_address != 0) {
        let mut image = Image::new(map, data);
        if let Err(error) =
            walk_imports(&mut image, directory.virtual_address, is_64bit, &mut table)
        {
            table.error = Some(format!("the import table cannot be read: {error}"));
        }
    }
    table
}

fn walk_imports(
    image: &mut Image<'_>,
    start: u32,
    is_64bit: bool,
    table: &mut ImportTable,
) -> Result<(), String> {
    let (width, ordinal_flag): (u32, u64) = if is_64bit { (8, 1 << 63) } else { (4, 1 << 31) };
    let mut libraries = HashSet::new();
    let mut descriptor = start;
    loop {
        let lookup = image.dword(descriptor, 0)?;
        let name = image.dword(descriptor, 12)?;
        let first_thunk = image.dword(descriptor, 16)?;
        if name == 0 || first_thunk == 0 {
            return Ok(());
        }
        // The descriptor's entries share its DLL's name
        let dll: Arc<str> = image.name(name)?.into();
        if libraries.insert(Arc::clone(&dll)) {
            table.libraries.push(dll.to_string());
        }
        let thunks = if lookup == 0 { first_thunk } else { lookup };
        let mut slot = 0u32;
        loop {
            let value = image.value(at(thunks, slot)?, width as usize)?;
            if value == 0 {
                break;
            }
            image.charge(width as usize)?;
            let rva = at(first_thunk, slot)?;
            let import = if value & ordinal_flag == 0 {
                // Bits 30 to 0 are the hint/name entry's RVA
                let entry = u32::try_from(value & 0x7FFF_FFFF).unwrap_or(u32::MAX);
                Import {
                    dll: Arc::clone(&dll),
                    name: Some(image.name(at(entry, 2)?)?),
                    ordinal: None,
                    rva,
                    hint: image.word(entry, 0)?,
                    ilt_value: value,
                }
            } else {
                Import {
                    dll: Arc::clone(&dll),
                    name: None,
                    ordinal: Some(u16::try_from(value & 0xFFFF).unwrap_or(u16::MAX)),
                    rva,
                    hint: 0,
                    ilt_value: value,
                }
            };
            table.imports.push(import);
            slot = at(slot, width)?;
        }
        descriptor = at(descriptor, IMPORT_DESCRIPTOR_SIZE)?;
    }
}

/// The export directory `directory` names: its header, and every entry of its export address
/// table with an address, by ordinal, with the names the name pointer table gives it. An
/// address inside the directory is a forwarder, the name of what it forwards to.
pub(crate) fn read_exports(
    map: SectionMap<'_>,
    data: &[u8],
    directory: Option<&DataDirectory>,
) -> ExportTable {
    let mut table = ExportTable::default();
    if let Some(directory) = directory.filter(|directory| directory.virtual_address != 0) {
        let mut image = Image::new(map, data);
        if let Err(error) = walk_exports(&mut image, directory, &mut table) {
            table.error = Some(format!("the export table cannot be read: {error}"));
        }
    }
    table
}

fn walk_exports(
    image: &mut Image<'_>,
    directory: &DataDirectory,
    table: &mut ExportTable,
) -> Result<(), String> {
    let start = directory.virtual_address;
    let forwarders = start..start.saturating_add(directory.size);
    // The directory's last field must be in the image before any of it is
    image.dword(start, EXPORT_DIRECTORY_SIZE - 4)?;
    let base = image.dword(start, 16)?;
    let function_count = image.dword(start, 20)?;
    let name_count = image.dword(start, 24)?;
    let functions = image.dword(start, 28)?;
    let names = image.dword(start, 32)?;
    let ordinals = image.dword(start, 36)?;
    let name = image.dword(start, 12)?;
    table.header = Some(ExportHeader {
        name: image.name(name)?,
        base,
        timestamp: image.dword(start, 4)?,
        major_version: image.word(start, 8)?,
        minor_version: image.word(start, 10)?,
    });

    let mut names_of: HashMap<u32, Vec<String>> = HashMap::new();
    for index in 0..name_count {
        let name = image.dword(names, index.checked_mul(4).ok_or("too many names")?)?;
        let name = image.name(name)?;
        let slot = u32::from(image.word(ordinals, index.checked_mul(2).ok_or("too many names")?)?);
        if slot >= function_count {
            return Err(format!(
                "the name {name:?} names export slot {slot}, past the {function_count} slots"
            ));
        }
        names_of.entry(slot).or_default().push(name);
    }

    let mut slot = 0u32;
    while slot < function_count {
        let entry = at(functions, slot.checked_mul(4).ok_or("too many exports")?)?;
        // A run of zero-filled slots holds no export: skip to its end in one step
        if let Some(end) = image.map.zero_fill_end(entry) {
            let skipped = end.saturating_sub(entry) / 4;
            if skipped > 0 {
                slot = slot.saturating_add(skipped);
                continue;
            }
        }
        let address = image.dword(entry, 0)?;
        if address != 0 {
            let ordinal = base
                .checked_add(slot)
                .and_then(|ordinal| u16::try_from(ordinal).ok())
                .ok_or_else(|| format!("export slot {slot} has an ordinal past 16 bits"))?;
            let forwarder = if forwarders.contains(&address) {
                Some(image.name(address)?)
            } else {
                None
            };
            let offset = match image.map.map(address) {
                RvaMapping::File(offset) => u32::try_from(offset).ok(),
                RvaMapping::ZeroFill | RvaMapping::Unmapped => None,
            };
            let export = |name| Export {
                name,
                ordinal,
                rva: address,
                offset,
                forwarder: forwarder.clone(),
            };
            match names_of.remove(&slot) {
                Some(names) => table
                    .exports
                    .extend(names.into_iter().map(Some).map(export)),
                None => table.exports.push(export(None)),
            }
        }
        slot = slot.saturating_add(1);
    }
    if let Some(slot) = names_of.keys().min() {
        return Err(format!(
            "a name names export slot {slot}, which has no address"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::pe::SectionTable;

    /// Where the test image's one section starts.
    const VA: u32 = 0x1000;

    /// One section holding all of `data` at [`VA`].
    fn section(data: &[u8]) -> [SectionTable; 1] {
        let len = u32::try_from(data.len()).unwrap();
        [SectionTable {
            name: ".s".to_string(),
            virtual_size: len,
            virtual_address: VA,
            size_of_raw_data: len,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0,
        }]
    }

    fn put(data: &mut [u8], rva: u32, bytes: &[u8]) {
        let at = usize::try_from(rva - VA).unwrap();
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn imports(data: &[u8]) -> ImportTable {
        let sections = section(data);
        let directory = DataDirectory {
            virtual_address: VA,
            size: 20,
        };
        read_imports(
            SectionMap::new(&sections, data.len()),
            data,
            Some(&directory),
            false,
        )
    }

    fn exports(data: &[u8], size: u32) -> ExportTable {
        let sections = section(data);
        let directory = DataDirectory {
            virtual_address: VA,
            size,
        };
        read_exports(
            SectionMap::new(&sections, data.len()),
            data,
            Some(&directory),
        )
    }

    /// A PE32 image whose `descriptors` import descriptors, each naming its own DLL, share one
    /// lookup table of `entries` entries, all naming one hint/name entry.
    fn shared_lookup_table(len: usize, descriptors: u32, entries: u32) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let lookup = VA + descriptors * 20 + 20;
        let hint_name = lookup + entries * 4 + 4;
        put(&mut data, hint_name, b"\x07\0Function\0");
        let names = hint_name + 12;
        for index in 0..descriptors {
            let descriptor = VA + index * 20;
            let name = names + index * 8;
            put(&mut data, name, format!("{index:03}.dll\0").as_bytes());
            put(&mut data, descriptor, &lookup.to_le_bytes());
            put(&mut data, descriptor + 12, &name.to_le_bytes());
            put(
                &mut data,
                descriptor + 16,
                &(0x8000 + index * 0x100).to_le_bytes(),
            );
        }
        for entry in 0..entries {
            put(&mut data, lookup + entry * 4, &hint_name.to_le_bytes());
        }
        data
    }

    /// Descriptors that share a lookup table and a hint/name entry each import every entry
    /// of it, as the loader binds them: each into its own import address table.
    #[test]
    fn descriptors_sharing_a_lookup_table_each_import_it() {
        let table = imports(&shared_lookup_table(0x400, 3, 2));
        assert_eq!(table.error, None);
        assert_eq!(table.libraries, ["000.dll", "001.dll", "002.dll"]);
        let read: Vec<_> = table
            .imports
            .iter()
            .map(|import| {
                (
                    &*import.dll,
                    import.name.as_deref(),
                    import.hint,
                    import.rva,
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                ("000.dll", Some("Function"), 7, 0x8000),
                ("000.dll", Some("Function"), 7, 0x8004),
                ("001.dll", Some("Function"), 7, 0x8100),
                ("001.dll", Some("Function"), 7, 0x8104),
                ("002.dll", Some("Function"), 7, 0x8200),
                ("002.dll", Some("Function"), 7, 0x8204),
            ]
        );
        // A descriptor's imports share its DLL's name
        assert!(Arc::ptr_eq(&table.imports[0].dll, &table.imports[1].dll));
    }

    /// Descriptors sharing a lookup table describe descriptors x entries imports from a file
    /// that holds descriptors + entries: the walk stops where the imports, each counted at its
    /// lookup entry and its name, would be more than the file, and says so.
    #[test]
    fn a_shared_lookup_table_is_not_expanded_past_the_file() {
        let len = 0x4000;
        let data = shared_lookup_table(len, 64, 1024);
        let table = imports(&data);
        let error = table.error.expect("the walk stops");
        assert!(error.contains("more than the file's"), "{error}");
        // Each import cost its lookup entry and its name: no more of them than fit
        assert!(!table.imports.is_empty());
        assert!(table.imports.len() * (4 + "Function".len()) <= len);
    }

    /// A DLL that several descriptors import from is listed once, in table order.
    #[test]
    fn a_library_is_listed_once() {
        let mut data = shared_lookup_table(0x400, 3, 1);
        // The third descriptor names the first one's DLL
        let first = u32::from_le_bytes(data[12..16].try_into().unwrap());
        put(&mut data, VA + 2 * 20 + 12, &first.to_le_bytes());
        let table = imports(&data);
        assert_eq!(table.error, None);
        assert_eq!(table.libraries, ["000.dll", "001.dll"]);
        assert_eq!(table.imports.len(), 3);
    }

    /// An export directory of one function, ordinal 1, named by `names` name pointers, the
    /// one at `index` to the RVA `name_rva(index)`.
    fn named_exports(len: usize, names: u32, name_rva: impl Fn(u32) -> u32) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let functions = VA + 0x40;
        let pointers = functions + 4;
        let ordinals = pointers + names * 4;
        put(&mut data, VA + 12, &(VA + 0x30).to_le_bytes());
        put(&mut data, VA + 0x30, b"a.dll\0");
        put(&mut data, VA + 16, &1u32.to_le_bytes());
        put(&mut data, VA + 20, &1u32.to_le_bytes());
        put(&mut data, VA + 24, &names.to_le_bytes());
        put(&mut data, VA + 28, &functions.to_le_bytes());
        put(&mut data, VA + 32, &pointers.to_le_bytes());
        put(&mut data, VA + 36, &ordinals.to_le_bytes());
        put(&mut data, functions, &0x9000u32.to_le_bytes());
        for index in 0..names {
            put(
                &mut data,
                pointers + index * 4,
                &name_rva(index).to_le_bytes(),
            );
        }
        data
    }

    /// Export names that are suffixes of one string read as the loader reads them, each to
    /// the one terminator.
    #[test]
    fn export_names_that_overlap_are_read() {
        let string = VA + 0x200;
        let mut data = named_exports(0x400, 3, |index| string + index);
        put(&mut data, string, b"Export\0");
        let table = exports(&data, 40);
        assert_eq!(table.error, None);
        let names: Vec<_> = table.exports.iter().map(|e| e.name.as_deref()).collect();
        assert_eq!(names, [Some("Export"), Some("xport"), Some("port")]);
    }

    /// Names that are each a suffix of one long string describe a quadratic number of name
    /// bytes: the walk stops where they would be more than the file, and says so.
    #[test]
    fn overlapping_export_names_are_not_expanded_past_the_file() {
        let len = 0x4000;
        let names = 0x800;
        let string = VA + 0x40 + 4 + names * 6;
        let mut data = named_exports(len, names, |index| string + index);
        let end = VA + u32::try_from(len).unwrap() - 1;
        for rva in string..end {
            put(&mut data, rva, b"a");
        }
        let table = exports(&data, 40);
        let error = table.error.expect("the walk stops");
        assert!(error.contains("more than the file's"), "{error}");
        let bytes: usize = table
            .exports
            .iter()
            .filter_map(|export| export.name.as_ref().map(String::len))
            .sum();
        assert!(bytes <= len);
    }

    /// An export directory of `slots` functions, all forwarders to the one string at the
    /// directory's end.
    fn shared_forwarder(len: usize, slots: u32, target: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let functions = VA + 0x40;
        let string = functions + slots * 4;
        put(&mut data, VA + 12, &(VA + 0x30).to_le_bytes());
        put(&mut data, VA + 0x30, b"a.dll\0");
        put(&mut data, VA + 16, &1u32.to_le_bytes());
        put(&mut data, VA + 20, &slots.to_le_bytes());
        put(&mut data, VA + 28, &functions.to_le_bytes());
        for slot in 0..slots {
            put(&mut data, functions + slot * 4, &string.to_le_bytes());
        }
        put(&mut data, string, target);
        data
    }

    /// Ordinals that forward to one string each forward to it.
    #[test]
    fn ordinals_sharing_a_forwarder_each_forward() {
        let data = shared_forwarder(0x400, 3, b"other.Target\0");
        let table = exports(&data, 0x400);
        assert_eq!(table.error, None);
        let read: Vec<_> = table
            .exports
            .iter()
            .map(|export| (export.ordinal, export.forwarder.as_deref()))
            .collect();
        assert_eq!(
            read,
            [
                (1, Some("other.Target")),
                (2, Some("other.Target")),
                (3, Some("other.Target"))
            ]
        );
    }

    /// Ordinals forwarding to one long string describe slots x its length bytes: the walk
    /// stops where they would be more than the file, and says so.
    #[test]
    fn a_shared_forwarder_is_not_expanded_past_the_file() {
        let len = 0x4000;
        let slots = 0x400;
        let target = vec![b'a'; len - 0x40 - 0x1000 - 1];
        let table = exports(&shared_forwarder(len, slots, &target), 0x4000);
        let error = table.error.expect("the walk stops");
        assert!(error.contains("more than the file's"), "{error}");
        let bytes: usize = table
            .exports
            .iter()
            .filter_map(|export| export.forwarder.as_ref().map(String::len))
            .sum();
        assert!(bytes <= len);
    }
}

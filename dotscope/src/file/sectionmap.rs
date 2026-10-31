//! Where the runtime finds each RVA of an image: the one mapping from RVAs to the file.
//!
//! A section is `VirtualSize` bytes of the loaded image from its `VirtualAddress`: the first
//! `SizeOfRawData` of them come from the file at `PointerToRawData`, the rest are zero. No
//! other RVA is read: past `VirtualSize`, and in the headers, the .NET Framework and CoreCLR
//! read different bytes, and both refuse a method body past `VirtualSize`.
//!
//! These rules were measured on the .NET Framework 4.8 (under Wine), CoreCLR 10 and Mono 6.12
//! with `tests/samples/metadata/sections`, a probe whose field data and method body are moved
//! into a section of chosen layout (`factory/oracle.tsv` holds what each runtime printed):
//!
//! | Where the bytes are | .NET Framework | CoreCLR | Mono | Here |
//! |---|---|---|---|---|
//! | before `SizeOfRawData` and `VirtualSize` | the file's | the file's | the file's | [`RvaMapping::File`] |
//! | past `SizeOfRawData`, before `VirtualSize` | zero | zero | zero | [`RvaMapping::ZeroFill`] |
//! | field data past `VirtualSize` | the file's | zero | the file's | [`RvaMapping::Unmapped`] |
//! | a method body past `VirtualSize`, in part or whole | refused | refused | runs | [`RvaMapping::Unmapped`] |
//! | in the headers, outside every section | the bytes 16 before | the header's | crashes | [`RvaMapping::Unmapped`] |
//!
//! Both Microsoft runtimes refuse an image with a section of `VirtualSize` 0, a
//! `PointerToRawData` that is not a multiple of `FileAlignment`, or raw data past the end of
//! the file. Such an image is still read here, leniently: a section of `VirtualSize` 0 takes
//! its `SizeOfRawData`, the pointer is taken as it stands, and the bytes the file lacks are
//! [`RvaMapping::Unmapped`].

use std::borrow::Cow;

use crate::{file::pe::SectionTable, Error, ParseFailure, ParseStage, Result};

/// Where an RVA lies in the loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RvaMapping {
    /// The file's byte at this offset.
    File(usize),
    /// A byte of a section past its raw data, which the loader zeroes.
    ZeroFill,
    /// No byte the image defines.
    Unmapped,
}

/// The RVA mapping of an image: its section table, read with the loader's rules (see the
/// module documentation).
#[derive(Debug, Clone, Copy)]
pub struct SectionMap<'a> {
    sections: &'a [SectionTable],
    file_len: usize,
}

/// A section's part of the image: where it starts, how far it reaches, and how much of it the
/// file holds from where.
struct Extent {
    start: u32,
    size: u32,
    raw: u32,
    pointer: u32,
}

impl Extent {
    fn of(section: &SectionTable) -> Self {
        let size = if section.virtual_size == 0 {
            section.size_of_raw_data
        } else {
            section.virtual_size
        };
        Self {
            start: section.virtual_address,
            size,
            raw: section.size_of_raw_data.min(size),
            pointer: section.pointer_to_raw_data,
        }
    }

    /// `rva`'s distance from the start, when the extent holds it.
    fn delta(&self, rva: u32) -> Option<u32> {
        rva.checked_sub(self.start)
            .filter(|delta| *delta < self.size)
    }
}

impl<'a> SectionMap<'a> {
    /// The mapping of an image with `sections` and `file_len` bytes.
    #[must_use]
    pub fn new(sections: &'a [SectionTable], file_len: usize) -> Self {
        Self { sections, file_len }
    }

    /// The first section holding `rva`, as the runtime picks it, and `rva`'s distance into it.
    fn locate(&self, rva: u32) -> Option<(Extent, u32)> {
        self.sections.iter().find_map(|section| {
            let extent = Extent::of(section);
            extent.delta(rva).map(|delta| (extent, delta))
        })
    }

    /// Where `rva` lies.
    #[must_use]
    pub fn map(&self, rva: u32) -> RvaMapping {
        match self.locate(rva) {
            Some((extent, delta)) if delta >= extent.raw => RvaMapping::ZeroFill,
            Some((extent, delta)) => match extent.pointer.checked_add(delta) {
                Some(offset) if (offset as usize) < self.file_len => {
                    RvaMapping::File(offset as usize)
                }
                _ => RvaMapping::Unmapped,
            },
            None => RvaMapping::Unmapped,
        }
    }

    /// Where the zero-filled part `rva` is in ends, when it is in one: every RVA from `rva` up
    /// to it reads as zero.
    pub(crate) fn zero_fill_end(&self, rva: u32) -> Option<u32> {
        match self.locate(rva) {
            Some((extent, delta)) if delta >= extent.raw => {
                Some(extent.start.saturating_add(extent.size))
            }
            _ => None,
        }
    }

    /// The file bytes from `rva` to the end of what the file holds of its section: empty when
    /// `rva` is in the section's zero-filled part.
    ///
    /// A structure read from here, such as a method body, cannot reach into the zero-filled
    /// part: zero bytes do not end one (a zero byte of code is `nop`, which runs off the end,
    /// and a zero section header is no exception table).
    ///
    /// # Errors
    ///
    /// When no byte of the image is at `rva`.
    pub fn section_bounded(&self, data: &'a [u8], rva: u32) -> Result<&'a [u8]> {
        let end = match self.locate(rva) {
            Some((extent, delta)) if delta >= extent.raw => return Ok(&[]),
            Some((extent, delta)) => {
                let start = extent.pointer.checked_add(delta).map(|s| s as usize);
                let end = (extent.pointer as usize).saturating_add(extent.raw as usize);
                start.zip(Some(end.min(self.file_len)))
            }
            None => None,
        };
        end.and_then(|(start, end)| data.get(start..end))
            .ok_or_else(|| unmapped(rva))
    }

    /// The `len` bytes the image holds from `rva`, within one section: the file's, then zero
    /// where the section's raw data ends.
    ///
    /// # Errors
    ///
    /// When a byte of the range is not the image's.
    pub fn read(&self, data: &'a [u8], rva: u32, len: usize) -> Result<Cow<'a, [u8]>> {
        let (extent, delta) = self.locate(rva).ok_or_else(|| unmapped(rva))?;
        if (extent.size.saturating_sub(delta) as usize) < len {
            return Err(unmapped(rva));
        }
        let backed = self.section_bounded(data, rva)?;
        if let Some(bytes) = backed.get(..len) {
            return Ok(Cow::Borrowed(bytes));
        }
        // A file shorter than the raw data claims leaves bytes no one defines
        let claimed = extent.raw.saturating_sub(delta) as usize;
        if backed.len() < claimed.min(len) {
            return Err(unmapped(rva));
        }
        let mut bytes = backed.to_vec();
        bytes.resize(len, 0);
        Ok(Cow::Owned(bytes))
    }

    /// `section`'s size in the image, and the bytes of it the file holds: its raw data within
    /// that size, as much of it as the file has.
    #[must_use]
    pub fn contents(&self, data: &'a [u8], section: &SectionTable) -> (u32, &'a [u8]) {
        let extent = Extent::of(section);
        let start = (extent.pointer as usize).min(self.file_len);
        let end = (extent.pointer as usize)
            .saturating_add(extent.raw as usize)
            .min(self.file_len);
        (extent.size, data.get(start..end).unwrap_or_default())
    }

    /// The RVA the file byte at `offset` is loaded at: a section's raw data within its
    /// `VirtualSize`, at an RVA no section before it in the table holds (an RVA two sections
    /// hold is the first one's, as [`map`](Self::map) has it).
    #[must_use]
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32> {
        let byte = u32::try_from(offset).ok()?;
        self.sections.iter().find_map(|section| {
            let extent = Extent::of(section);
            let rva = byte
                .checked_sub(extent.pointer)
                .filter(|delta| *delta < extent.raw)
                .and_then(|delta| extent.start.checked_add(delta))?;
            (self.map(rva) == RvaMapping::File(offset)).then_some(rva)
        })
    }
}

fn unmapped(rva: u32) -> Error {
    ParseFailure::InvalidField {
        stage: ParseStage::SectionTable,
        field: "rva",
        reason: format!("RVA {rva:#x} is not a byte the image defines"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(va: u32, vsize: u32, pointer: u32, raw: u32) -> SectionTable {
        SectionTable {
            name: ".s".to_string(),
            virtual_size: vsize,
            virtual_address: va,
            size_of_raw_data: raw,
            pointer_to_raw_data: pointer,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0,
        }
    }

    fn file(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The section's file bytes, then zero to its VirtualSize, then nothing.
    #[test]
    fn a_section_is_its_raw_data_then_zeros_to_its_virtual_size() {
        let sections = [section(0x2000, 0x300, 0x400, 0x200)];
        let map = SectionMap::new(&sections, 0x800);
        assert_eq!(map.map(0x2000), RvaMapping::File(0x400));
        assert_eq!(map.map(0x21FF), RvaMapping::File(0x5FF));
        assert_eq!(map.map(0x2200), RvaMapping::ZeroFill);
        assert_eq!(map.map(0x22FF), RvaMapping::ZeroFill);
        assert_eq!(map.map(0x2300), RvaMapping::Unmapped);
    }

    /// Raw data past VirtualSize is not the section's: the runtimes disagree on it.
    #[test]
    fn raw_data_past_the_virtual_size_is_unmapped() {
        let data = file(0x800);
        let sections = [section(0x2000, 0x100, 0x400, 0x200)];
        let map = SectionMap::new(&sections, data.len());
        assert_eq!(map.map(0x2100), RvaMapping::Unmapped);
        assert_eq!(map.section_bounded(&data, 0x2080).unwrap().len(), 0x80);
        assert!(map.read(&data, 0x20F0, 0x20).is_err());
        assert_eq!(map.offset_to_rva(0x4FF), Some(0x20FF));
        assert_eq!(map.offset_to_rva(0x500), None);
    }

    /// A read reaching past the raw data gets zeros for the rest.
    #[test]
    fn a_read_into_the_zero_fill_gets_zeros() {
        let data = file(0x800);
        let sections = [section(0x2000, 0x1000, 0x400, 0x200)];
        let map = SectionMap::new(&sections, data.len());
        let bytes = map.read(&data, 0x21F0, 0x20).unwrap();
        assert_eq!(&bytes[..0x10], &data[0x5F0..0x600]);
        assert_eq!(&bytes[0x10..], &[0; 0x10]);
        assert!(map.read(&data, 0x2FF0, 0x20).is_err());
        assert!(map.section_bounded(&data, 0x2300).unwrap().is_empty());
    }

    /// An RVA outside every section is no byte of the image, headers included.
    #[test]
    fn an_rva_outside_every_section_is_unmapped() {
        let data = file(0x800);
        let sections = [section(0x2000, 0x100, 0x400, 0x200)];
        let map = SectionMap::new(&sections, data.len());
        assert_eq!(map.map(0x100), RvaMapping::Unmapped);
        assert!(map.read(&data, 0x100, 4).is_err());
        assert!(map.section_bounded(&data, 0x100).is_err());
        assert_eq!(map.offset_to_rva(0x100), None);
    }

    /// Where an earlier section holds an RVA, a later section's byte for it is not loaded
    /// there: B's first 0x100 bytes sit under A, and only B's bytes past A's end are loaded.
    #[test]
    fn an_offset_maps_to_an_rva_that_maps_back() {
        let sections = [
            section(0x2000, 0x200, 0x400, 0x200),
            section(0x2100, 0x200, 0x800, 0x200),
        ];
        let map = SectionMap::new(&sections, 0xA00);
        assert_eq!(map.offset_to_rva(0x480), Some(0x2080));
        assert_eq!(map.offset_to_rva(0x800), None);
        assert_eq!(map.offset_to_rva(0x900), Some(0x2200));
        for offset in 0..0xA00 {
            if let Some(rva) = map.offset_to_rva(offset) {
                assert_eq!(map.map(rva), RvaMapping::File(offset), "offset {offset:#x}");
            }
        }
    }

    /// A section of VirtualSize 0 takes its raw size; raw data the file lacks is unmapped;
    /// the first of overlapping sections holds an RVA.
    #[test]
    fn degenerate_tables_read_leniently() {
        let data = file(0x500);
        let sections = [
            section(0x2000, 0, 0x400, 0x200),
            section(0x2000, 0x1000, 0x200, 0x200),
        ];
        let map = SectionMap::new(&sections, data.len());
        assert_eq!(map.map(0x2000), RvaMapping::File(0x400));
        assert_eq!(map.map(0x2100), RvaMapping::Unmapped);
        assert!(map.read(&data, 0x20F0, 0x20).is_err());
        assert_eq!(map.section_bounded(&data, 0x2080).unwrap().len(), 0x80);
        assert_eq!(map.map(0x2200), RvaMapping::ZeroFill);
        assert_eq!(map.map(u32::MAX), RvaMapping::Unmapped);
    }
}

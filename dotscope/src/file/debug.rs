//! The debug directory: the entries a PE image lists in its Debug data directory (CodeView,
//! deterministic build, embedded Portable PDB, PDB checksum, ...).
//!
//! Each entry is an `IMAGE_DEBUG_DIRECTORY` of 28 bytes: characteristics, time stamp, major
//! and minor version, type, data size, the data's RVA and its file offset.

use crate::{
    file::{pe::DataDirectoryType, File},
    utils::read_le_at,
    Result,
};

/// The size of one debug directory entry.
const ENTRY_SIZE: usize = 28;

/// Debug directory entry types (`IMAGE_DEBUG_TYPE_*`) dotscope reads.
pub mod debug_type {
    /// A CodeView record: the PDB's identity and path (`RSDS`).
    pub const CODEVIEW: u32 = 2;
    /// A deterministic build marker, with or without a hash.
    pub const REPRO: u32 = 16;
    /// An embedded Portable PDB: `MPDB`, its size, then the PDB deflated.
    pub const EMBEDDED_PORTABLE_PDB: u32 = 17;
    /// A checksum of the PDB the CodeView record names.
    pub const PDB_CHECKSUM: u32 = 19;
}

/// One `IMAGE_DEBUG_DIRECTORY` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugDirectoryEntry {
    /// Reserved; 0
    pub characteristics: u32,
    /// The entry's time stamp
    pub timestamp: u32,
    /// The entry's major version (for a Portable PDB CodeView entry, the PDB format version)
    pub major_version: u16,
    /// The entry's minor version (`0x504D` for a Portable PDB CodeView entry)
    pub minor_version: u16,
    /// The entry's type ([`debug_type`])
    pub kind: u32,
    /// The size of the entry's data
    pub size: u32,
    /// The data's RVA, 0 when it is not mapped
    pub rva: u32,
    /// The data's file offset
    pub file_offset: u32,
}

impl File {
    /// The entries of the image's debug directory, in order; none without one.
    ///
    /// The Debug data directory points at an array of 28-byte `IMAGE_DEBUG_DIRECTORY`
    /// entries; a size that is not a multiple of 28 leaves the partial entry out, as the
    /// loader and debuggers do.
    ///
    /// # Returns
    ///
    /// Each entry, in directory order; empty when the image has no debug directory or it is
    /// empty.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory's bytes are not in the image.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::file::{debug::debug_type, File};
    ///
    /// let file = File::from_path("tests/samples/pdb/embedded/PdbProbe.dll")?;
    /// for entry in file.debug_directory()? {
    ///     if entry.kind == debug_type::CODEVIEW {
    ///         println!("CodeView entry, {} bytes at RVA 0x{:X}", entry.size, entry.rva);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn debug_directory(&self) -> Result<Vec<DebugDirectoryEntry>> {
        let Some((rva, size)) = self.get_data_directory(DataDirectoryType::Debug) else {
            return Ok(Vec::new());
        };
        if rva == 0 || size == 0 {
            return Ok(Vec::new());
        }
        let directory = self.rva_slice(rva as usize, size as usize)?;
        directory
            .as_chunks::<ENTRY_SIZE>()
            .0
            .iter()
            .map(|entry| {
                let mut offset = 0;
                Ok(DebugDirectoryEntry {
                    characteristics: read_le_at(entry, &mut offset)?,
                    timestamp: read_le_at(entry, &mut offset)?,
                    major_version: read_le_at(entry, &mut offset)?,
                    minor_version: read_le_at(entry, &mut offset)?,
                    kind: read_le_at(entry, &mut offset)?,
                    size: read_le_at(entry, &mut offset)?,
                    rva: read_le_at(entry, &mut offset)?,
                    file_offset: read_le_at(entry, &mut offset)?,
                })
            })
            .collect()
    }

    /// An entry's data, read from its file offset as a debugger reads a file on disk, or at
    /// its RVA when it has no file offset.
    ///
    /// # Arguments
    ///
    /// * `entry` - An entry of [`File::debug_directory`]
    ///
    /// # Returns
    ///
    /// The entry's `size` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the data is not in the file.
    pub fn debug_data(&self, entry: &DebugDirectoryEntry) -> Result<Vec<u8>> {
        if entry.file_offset != 0 {
            return Ok(self
                .data_slice(entry.file_offset as usize, entry.size as usize)?
                .to_vec());
        }
        Ok(self
            .rva_slice(entry.rva as usize, entry.size as usize)?
            .into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::fixture;

    /// An image with an embedded Portable PDB lists a CodeView entry, a deterministic build
    /// marker, the embedded PDB and a checksum, as the compiler writes them; one built with no
    /// debug information lists none of them.
    #[test]
    fn the_debug_directory_lists_its_entries() {
        let file = File::from_path(fixture("pdb/embedded/PdbProbe.dll")).unwrap();
        let kinds: Vec<u32> = file
            .debug_directory()
            .unwrap()
            .iter()
            .map(|entry| entry.kind)
            .collect();
        assert!(kinds.contains(&debug_type::CODEVIEW), "{kinds:?}");
        assert!(
            kinds.contains(&debug_type::EMBEDDED_PORTABLE_PDB),
            "{kinds:?}"
        );

        let embedded = file
            .debug_directory()
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind == debug_type::EMBEDDED_PORTABLE_PDB)
            .unwrap();
        assert_eq!(&file.debug_data(&embedded).unwrap()[..4], b"MPDB");

        let none = File::from_path(fixture("debug/none/TestApp.exe")).unwrap();
        assert!(none
            .debug_directory()
            .unwrap()
            .iter()
            .all(|entry| entry.kind != debug_type::CODEVIEW));
    }
}

//! Factory methods for file-related test helpers.
//!
//! Contains helper methods migrated from file source files
//! for creating and verifying test data related to file operations.

use goblin::pe::header::DOS_MAGIC;

use crate::{file::File, DataDirectoryType};

/// Verifies the correctness of a loaded [`crate::file::File`] instance.
///
/// This function checks various properties of the loaded PE file, including headers,
/// sections, and .NET-specific metadata.
///
/// Originally from: `src/file/mod.rs`
pub fn verify_file(file: &File) {
    assert_eq!(file.data()[0..2], [0x4D, 0x5A]);

    let slice = file.data_slice(0, 2).unwrap();
    assert_eq!(slice, [0x4D, 0x5A]);

    assert_eq!(file.imagebase(), 0x180000000);

    assert_eq!(file.va_to_offset(0x180001010).unwrap(), 0x1010);
    assert_eq!(file.va_to_offset(0x180205090).unwrap(), 0x205090);

    assert_eq!(file.rva_to_offset(0x1010).unwrap(), 0x1010);

    assert_eq!(file.offset_to_rva(0x1010).unwrap(), 0x1010);

    let header_dos = file.header_dos();
    assert_eq!(header_dos.signature, DOS_MAGIC);
    assert_eq!(header_dos.checksum, 0);

    let header_optional = file.header_optional().as_ref().unwrap();
    let clr_header = header_optional
        .data_directories
        .get_clr_runtime_header()
        .unwrap();
    assert_eq!(clr_header.size, 0x48);
    assert_eq!(clr_header.virtual_address, 0x1420);

    assert!(
        file.sections()
            .iter()
            .any(|section| section.name.as_str() == ".text"),
        "Text section missing!"
    );
    assert!(
        file.directories()
            .iter()
            .any(|directory| directory.0 == DataDirectoryType::ClrRuntimeHeader),
        "CLR runtime header directory missing!"
    );

    let (clr_rva, clr_size) = file.clr().expect("Should have CLR header");
    assert_eq!(clr_rva, 0x1420);
    assert_eq!(clr_size, 0x48);
}

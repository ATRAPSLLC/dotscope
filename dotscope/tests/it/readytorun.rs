#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! ReadyToRun images: the compiled methods' entries and the import cells, read
//! against an independent decode of the fixtures.

use std::collections::BTreeMap;

use dotscope::{
    metadata::{
        readytorun::{FixupNames, FixupSubject, ReadyToRun},
        token::Token,
    },
    testkit::fixture,
    CilObject,
};

/// **A ReadyToRun image places its compiled methods and describes its import
/// cells.** The oracle is an independent decode of
/// `System.Collections.Concurrent.dll` (ARM64 for macOS, machine `0xEC20`):
/// 394 runtime functions, 56 of 439 methods compiled, rows 6, 8 and 10 at
/// `0x157c0`, `0x15800` and `0x15890`; 671 cells in four sections with
/// signatures, by fixup kind as counted below, the helper `WriteBarrier`
/// (`0x30`) at `0x57c60`.
#[test]
fn a_readytorun_image_places_its_methods_and_describes_its_cells() {
    let path = fixture("dotnet_10.0/System.Collections.Concurrent.dll");
    let asm = CilObject::from_path(&path).expect("loads");
    let image = ReadyToRun::read(&asm)
        .expect("reads")
        .expect("a ReadyToRun image");
    assert_eq!(
        image.machine, 0xaa64,
        "ARM64 read through the macOS override"
    );

    let entries = image.method_entries(&asm).expect("the entries read");
    assert_eq!(entries.len(), 56);
    for (row, rva) in [(6, 0x157c0), (8, 0x15800), (10, 0x15890)] {
        let token = Token::new(0x0600_0000 | row);
        assert!(
            entries
                .iter()
                .any(|entry| entry.token == token && entry.rva == rva),
            "row {row} at {rva:#x}"
        );
    }

    let cells = image.import_cells(&asm).expect("the cells read");
    assert_eq!(cells.len(), 671);
    let mut kinds = BTreeMap::new();
    for cell in &cells {
        let fixup = cell.fixup.as_ref().expect("every signature reads");
        *kinds.entry(fixup.kind).or_insert(0) += 1;
    }
    assert_eq!(
        kinds,
        BTreeMap::from([
            (0x07, 156),
            (0x08, 41),
            (0x09, 12),
            (0x10, 46),
            (0x13, 126),
            (0x14, 44),
            (0x15, 64),
            (0x16, 48),
            (0x1a, 21),
            (0x1b, 53),
            (0x1c, 25),
            (0x1d, 2),
            (0x1e, 4),
            (0x22, 1),
            (0x23, 2),
            (0x27, 13),
            (0x29, 3),
            (0x2a, 7),
            (0x2b, 2),
            (0x30, 1),
        ])
    );
    let names = FixupNames::new(&asm);
    let named = |rva: u32| {
        let cell = cells.iter().find(|cell| cell.rva == rva)?;
        names.subject(cell.fixup.as_ref().ok()?)
    };
    assert_eq!(named(0x57c60).as_deref(), Some("WriteBarrier"));
    for cell in &cells {
        let fixup = cell.fixup.as_ref().unwrap();
        let local = match &fixup.subject {
            FixupSubject::Method(token) | FixupSubject::Field(token) => token.module.is_none(),
            FixupSubject::Helper(_) | FixupSubject::String(_) => true,
            _ => false,
        };
        if local {
            assert!(
                names.subject(fixup).is_some(),
                "the cell at {:#x} ({:?}) is named",
                cell.rva,
                fixup.kind_name()
            );
        }
    }
}

/// **An IL-only assembly states no ReadyToRun header.**
#[test]
fn an_il_only_assembly_has_no_readytorun_header() {
    let asm = CilObject::from_path(fixture("crafted_2.exe")).expect("loads");
    assert!(ReadyToRun::read(&asm).expect("reads").is_none());
}

mod full {
    use std::collections::BTreeSet;

    use dotscope::{
        metadata::readytorun::{FixupNames, FixupSubject, ReadyToRun},
        testkit::fixture,
        CilObject,
    };

    /// **Every .NET 10 runtime assembly's ReadyToRun tables read whole** (92
    /// images):
    /// each compiled method's entry is distinct and in an executable section,
    /// every import cell's signature reads, and every method, field, helper
    /// and string a cell takes from the image's own metadata is named.
    #[test]
    fn every_dotnet10_readytorun_image_reads_whole() {
        let mut images = 0;
        for entry in std::fs::read_dir(fixture("dotnet_10.0")).expect("the corpus") {
            let path = entry.expect("an entry").path();
            if path.extension().is_none_or(|extension| extension != "dll") {
                continue;
            }
            let Ok(asm) = CilObject::from_path(&path) else {
                continue;
            };
            let Some(image) = ReadyToRun::read(&asm).expect("the header reads") else {
                continue;
            };
            images += 1;
            let label = path.display();
            let sections = asm.file().sections();
            let entries = image.method_entries(&asm).expect("the entries read");
            let distinct: BTreeSet<u32> = entries.iter().map(|entry| entry.rva).collect();
            assert_eq!(distinct.len(), entries.len(), "{label}: distinct entries");
            for entry in &entries {
                assert!(
                    sections.iter().any(|section| {
                        section.characteristics & 0x2000_0000 != 0
                            && (section.virtual_address
                                ..section.virtual_address + section.virtual_size)
                                .contains(&entry.rva)
                    }),
                    "{label}: {:#x} is executable",
                    entry.rva
                );
            }
            let names = FixupNames::new(&asm);
            for cell in image.import_cells(&asm).expect("the cells read") {
                let fixup = cell
                    .fixup
                    .unwrap_or_else(|e| panic!("{label}: the cell at {:#x}: {e}", cell.rva));
                let local = match &fixup.subject {
                    FixupSubject::Method(token) | FixupSubject::Field(token) => {
                        token.module.is_none()
                    }
                    FixupSubject::Helper(_) | FixupSubject::String(_) => true,
                    _ => false,
                };
                assert!(
                    !local || names.subject(&fixup).is_some(),
                    "{label}: the cell at {:#x} ({:?}) is named",
                    cell.rva,
                    fixup.kind_name()
                );
            }
        }
        // An independent count of the CLR headers naming a ManagedNativeHeader:
        // 92 of the 172 assemblies (80 are IL only).
        assert_eq!(images, 92, "ReadyToRun images");
    }
}

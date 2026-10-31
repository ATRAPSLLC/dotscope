#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

//! dotscope reads the bytes at an RVA as the runtimes do.
//!
//! `tests/samples/metadata/sections` holds SectionProbe with a section `.probe` of chosen
//! layout, its field data `A` and the body of its method `F` moved into it, and
//! `factory/oracle.tsv` records what each runtime printed: the 32 bytes it read for `A`, and
//! whether it ran `F` (see `factory/generators/SectionLayouts`). For an image both the .NET
//! Framework and CoreCLR run, dotscope reads `A` as the bytes both read, or reads nothing
//! where they read different bytes, and reads `F`'s body exactly where both run it. An image
//! both refuse is read leniently, as `file::sectionmap` states, and each such image is listed
//! here with what dotscope reads in it.

use std::collections::BTreeMap;

use dotscope::{
    metadata::{
        method::MethodBody,
        tables::{FieldRvaRaw, MethodDefRaw},
        validation::ValidationConfig,
    },
    testkit::{fixture, fixture_bytes},
    CilAssemblyView, CilObject, RvaMapping,
};

/// What a runtime printed for an image: `A`'s bytes (`None` when it refused them) and whether
/// it ran `F`; `None` when it refused the image.
type Printed = Option<(Option<Vec<u8>>, bool)>;

/// The oracle's rows for the section experiments, by file name: what the .NET Framework and
/// CoreCLR printed.
fn oracle() -> BTreeMap<String, (Printed, Printed)> {
    let text = std::fs::read_to_string(fixture("factory/oracle.tsv")).unwrap();
    let mut lines = text.lines().filter(|line| !line.starts_with('#'));
    let header: Vec<&str> = lines.next().unwrap().split('\t').collect();
    let column = |name: &str| header.iter().position(|c| *c == name).unwrap();
    let printed = |row: &[&str], runtime: &str| -> Printed {
        if row[column(&format!("{runtime}_runs"))] != "yes" {
            return None;
        }
        let output = row[column(&format!("{runtime}_output"))];
        let line = |prefix: &str| {
            output
                .split('|')
                .find(|line| line.starts_with(prefix))
                .unwrap_or_else(|| panic!("{runtime} printed no {prefix} line: {output}"))
        };
        let a = line("A").strip_prefix("A=").map(|bytes| {
            bytes
                .split('-')
                .map(|byte| u8::from_str_radix(byte, 16).unwrap())
                .collect()
        });
        Some((a, line("F") == "F=7"))
    };
    lines
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter_map(|row| {
            let name = row[column("path")].strip_prefix("metadata/sections/")?;
            Some((
                name.to_string(),
                (printed(&row, "netfx"), printed(&row, "coreclr")),
            ))
        })
        .collect()
}

/// The pattern the experiments fill `.probe` with: byte `k` names its offset.
fn pattern(from: usize, len: usize) -> Vec<u8> {
    (from..from.saturating_add(len))
        .map(|k| (k ^ (k >> 8) ^ 0x5A) as u8)
        .collect()
}

/// What dotscope reads in `name`: `A`'s 32 bytes (`None` when it reads none) and `F`'s body
/// (whether it reads one of two code bytes).
fn read(name: &str) -> (Option<Vec<u8>>, bool) {
    let view = CilAssemblyView::from_mem_with_validation(
        fixture_bytes(&format!("metadata/sections/{name}")).to_vec(),
        ValidationConfig::disabled(),
    )
    .unwrap();
    let tables = view.tables().unwrap();
    let a = tables
        .table::<FieldRvaRaw>()
        .unwrap()
        .get(1)
        .unwrap()
        .unwrap()
        .rva;
    let f = tables
        .table::<MethodDefRaw>()
        .unwrap()
        .iter()
        .map(Result::unwrap)
        .find(|row| view.strings().unwrap().get(row.name as usize).unwrap() == "F")
        .unwrap()
        .rva;
    let file = view.file();
    let a = file
        .rva_slice(a as usize, 32)
        .ok()
        .map(|bytes| bytes.into_owned());
    let f = file
        .section_bounded(f as usize)
        .ok()
        .and_then(|data| MethodBody::from(data).ok())
        .is_some_and(|body| body.size_code == 2);
    (a, f)
}

/// The images both Microsoft runtimes refuse, and what dotscope reads in each.
fn lenient(name: &str) -> (Option<Vec<u8>>, bool) {
    match name {
        // A section of VirtualSize 0 takes its raw size
        "virtual_size_zero.exe" => (Some(pattern(0x180, 32)), true),
        // The pointer stands as it is: 0x10 past the bytes, so F is not there
        "pointer_unaligned.exe" => (Some(pattern(0x110, 32)), false),
        // The raw data the file holds is read, and only it
        "raw_past_file.exe" => (Some(pattern(0x100, 32)), true),
        other => panic!("{other}: the runtimes refuse it, and it is not listed here"),
    }
}

#[test]
fn every_section_layout_is_read_as_the_runtimes_read_it() {
    let oracle = oracle();
    assert!(
        oracle.len() >= 12,
        "the oracle lists the section experiments"
    );
    let mut mismatches = Vec::new();
    for (name, printed) in &oracle {
        let expected = match printed {
            (Some((netfx_a, netfx_f)), Some((coreclr_a, coreclr_f))) => {
                assert_eq!(
                    netfx_f, coreclr_f,
                    "{name}: the runtimes disagree on F; the map has no rule for that"
                );
                (
                    Some(netfx_a.clone()).filter(|a| a == coreclr_a).flatten(),
                    *netfx_f,
                )
            }
            (None, None) => lenient(name),
            _ => panic!("{name}: only one Microsoft runtime runs it; the map has no rule for that"),
        };
        let actual = read(name);
        if actual != expected {
            mismatches.push(format!(
                "{name}: dotscope reads {actual:?}, the runtimes {expected:?}"
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// The runtimes read the bytes past a section's raw data as zeros, and dotscope maps them so.
#[test]
fn a_section_past_its_raw_data_is_zero_filled() {
    let view = CilAssemblyView::from_mem(fixture_bytes("metadata/sections/zero_fill.exe").to_vec())
        .unwrap();
    let file = view.file();
    let probe = file.sections().iter().find(|s| s.name == ".probe").unwrap();
    let map = file.section_map();
    assert!(matches!(
        map.map(probe.virtual_address + 0x1FF),
        RvaMapping::File(_)
    ));
    assert_eq!(map.map(probe.virtual_address + 0x200), RvaMapping::ZeroFill);
    assert_eq!(
        map.map(probe.virtual_address + 0x1000),
        RvaMapping::Unmapped
    );
}

/// A method body that runs past its section's end is refused by a strict load, as it is by
/// the runtimes when the method is called. A lenient load keeps the assembly: only that
/// method goes without a body, and a diagnostic names it.
#[test]
fn a_body_past_its_section_fails_only_a_strict_load() {
    for name in [
        "body_past_virtual_size.exe",
        "body_straddles_virtual_size.exe",
    ] {
        let bytes = fixture_bytes(&format!("metadata/sections/{name}")).to_vec();
        assert!(
            CilObject::from_mem(bytes.clone()).is_err(),
            "{name}: a strict load refuses the body"
        );

        let lenient =
            CilObject::from_mem_with_validation(bytes, ValidationConfig::analysis()).unwrap();
        let method = |name: &str| {
            lenient
                .methods()
                .iter()
                .find(|entry| entry.value().name == name)
                .map(|entry| entry.value().clone())
                .unwrap()
        };
        let f = method("F");
        assert!(f.body.get().is_none(), "{name}: F has no body");
        assert!(
            method("Main").body.get().is_some(),
            "{name}: the other methods keep theirs"
        );
        let named = format!("method body 0x{:08x}", f.token.value());
        assert!(
            lenient
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.message.contains(&named)),
            "{name}: a diagnostic names {named}"
        );
    }
}

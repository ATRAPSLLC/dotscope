//! A ReadyToRun image's header, the methods it compiled ahead of time, and
//! its import cells.
//!
//! `crossgen2` compiles a .NET assembly's methods to native code and keeps the
//! code in the PE beside the IL. The image has no native entry point and no
//! exports for that code: the CLR header's `ManagedNativeHeader` names a
//! ReadyToRun header (`READYTORUN_HEADER`, opening `RTR\0`), whose sections
//! place it. The `RuntimeFunctions` section is a table of `RUNTIME_FUNCTION`
//! records of the machine's own shape, one per function and per funclet; the
//! `MethodDefEntryPoints` section, a NativeFormat array, pairs each compiled
//! method, by its `MethodDef` row, with the record of its entry. The
//! `ImportSections` section lists the cells the runtime fills for the code
//! (see [`ImportCell`]).
//!
//! A ReadyToRun image built for another OS states its machine XOR that OS's
//! override (the runtime's `MachineOSOverride`), so an ARM64 image for macOS
//! states `0xEC20`; [`ReadyToRun::machine`] is the machine read through it.
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::{metadata::readytorun::{FixupNames, ReadyToRun}, CilObject};
//!
//! let assembly = CilObject::from_path("System.Collections.dll")?;
//! if let Some(image) = ReadyToRun::read(&assembly)? {
//!     for entry in image.method_entries(&assembly)? {
//!         println!("{:#x} {:?}", entry.rva, entry.token);
//!     }
//!     let names = FixupNames::new(&assembly);
//!     for cell in image.import_cells(&assembly)? {
//!         if let Ok(fixup) = &cell.fixup {
//!             println!("{:#x} {:?} {:?}", cell.rva, fixup.kind_name(), names.subject(fixup));
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! Every type here is [`Send`] and [`Sync`], and immutable once read.

mod imports;
mod names;
mod native;
mod signature;

pub use crate::metadata::readytorun::{
    imports::{helper_name, Fixup, FixupSubject, ImportCell},
    names::FixupNames,
    signature::{ModuleToken, SignatureElement, SignatureType},
};
use crate::{
    metadata::{
        readytorun::native::{read_u16, read_u32, NativeReader},
        tables::TableId,
        token::Token,
    },
    CilObject, Result,
};

/// The signature a ReadyToRun header opens with, `RTR\0` read little-endian.
const SIGNATURE: u32 = 0x0052_5452;

/// `ReadyToRunSectionType::ImportSections`.
const IMPORT_SECTIONS: u32 = 101;

/// `ReadyToRunSectionType::RuntimeFunctions`.
const RUNTIME_FUNCTIONS: u32 = 102;

/// `ReadyToRunSectionType::MethodDefEntryPoints`.
const METHOD_DEF_ENTRY_POINTS: u32 = 103;

/// `IMAGE_FILE_MACHINE_I386`.
const MACHINE_I386: u16 = 0x014c;

/// `IMAGE_FILE_MACHINE_AMD64`.
const MACHINE_AMD64: u16 = 0x8664;

/// `IMAGE_FILE_MACHINE_ARMNT`.
const MACHINE_ARMNT: u16 = 0x01c4;

/// `IMAGE_FILE_MACHINE_ARM64`.
const MACHINE_ARM64: u16 = 0xaa64;

/// `IMAGE_FILE_MACHINE_LOONGARCH64`.
const MACHINE_LOONGARCH64: u16 = 0x6264;

/// `IMAGE_FILE_MACHINE_RISCV64`.
const MACHINE_RISCV64: u16 = 0x5064;

/// The machines the runtime builds a ReadyToRun image for.
const MACHINES: [u16; 6] = [
    MACHINE_I386,
    MACHINE_AMD64,
    MACHINE_ARMNT,
    MACHINE_ARM64,
    MACHINE_LOONGARCH64,
    MACHINE_RISCV64,
];

/// The runtime's `MachineOSOverride` values: Linux, Apple, FreeBSD, NetBSD,
/// OpenBSD and SunOS (Windows is 0).
const OS_OVERRIDES: [u16; 6] = [0x7b79, 0x4644, 0xadc4, 0x1993, 0xadc5, 0x1992];

/// One section a ReadyToRun header lists: its type and where its bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyToRunSection {
    /// The section's `ReadyToRunSectionType`.
    pub kind: u32,
    /// The RVA of its first byte.
    pub rva: u32,
    /// Its size in bytes.
    pub size: u32,
}

/// A method compiled ahead of time and the RVA its code is entered at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodEntry {
    /// The method's `MethodDef` token.
    pub token: Token,
    /// The begin address of its entry's `RUNTIME_FUNCTION` record, less an
    /// ARM record's Thumb bit (which says how the code executes, not where it
    /// starts).
    pub rva: u32,
}

/// A ReadyToRun header (`READYTORUN_HEADER`): its version, its sections, and
/// the machine its code is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyToRun {
    /// The format's major version.
    pub major_version: u16,
    /// The format's minor version.
    pub minor_version: u16,
    /// The sections, in the header's order.
    pub sections: Vec<ReadyToRunSection>,
    /// The machine the code is for: the PE's machine field read through the
    /// OS override that explains it, or the field itself.
    pub machine: u16,
}

impl ReadyToRun {
    /// Reads the ReadyToRun header `asm`'s CLR header names; `None` for an
    /// image with none (IL only).
    ///
    /// # Errors
    ///
    /// When the header the CLR header names does not read: not in the image,
    /// not opening with `RTR\0`, or ending before the sections it states.
    pub fn read(asm: &CilObject) -> Result<Option<Self>> {
        let cor20 = asm.cor20header();
        if cor20.managed_native_header_rva == 0 {
            return Ok(None);
        }
        let file = asm.file();
        let bytes = file.rva_slice(
            cor20.managed_native_header_rva as usize,
            cor20.managed_native_header_size as usize,
        )?;
        Self::parse(&bytes, file.header().machine.bits()).map(Some)
    }

    /// Reads a header from `bytes`, its first byte at `bytes[0]`, for an image
    /// whose machine field is `machine_field`.
    ///
    /// # Errors
    ///
    /// When the bytes do not open with `RTR\0`, or end before the section
    /// list the header states.
    pub fn parse(bytes: &[u8], machine_field: u16) -> Result<Self> {
        let signature =
            read_u32(bytes, 0).ok_or_else(|| malformed_error!("ReadyToRun header: truncated"))?;
        if signature != SIGNATURE {
            return Err(malformed_error!(
                "ReadyToRun header: signature {signature:#010x} is not RTR"
            ));
        }
        let (Some(major_version), Some(minor_version), Some(count)) =
            (read_u16(bytes, 4), read_u16(bytes, 6), read_u32(bytes, 12))
        else {
            return Err(malformed_error!("ReadyToRun header: truncated"));
        };
        // Each section is a type and a directory entry, twelve bytes, after
        // the sixteen-byte fixed header.
        let sections = (0..count as usize)
            .map(|index| {
                let at = index.checked_mul(12)?.checked_add(16)?;
                Some(ReadyToRunSection {
                    kind: read_u32(bytes, at)?,
                    rva: read_u32(bytes, at.checked_add(4)?)?,
                    size: read_u32(bytes, at.checked_add(8)?)?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                malformed_error!("ReadyToRun header: {count} sections overrun the header")
            })?;
        Ok(Self {
            major_version,
            minor_version,
            sections,
            machine: native_machine(machine_field),
        })
    }

    /// The first section of type `kind` (a `ReadyToRunSectionType`).
    #[must_use]
    pub fn section(&self, kind: u32) -> Option<ReadyToRunSection> {
        self.sections
            .iter()
            .find(|section| section.kind == kind)
            .copied()
    }

    /// Each compiled method and the RVA its code is entered at: the begin
    /// address of the `RuntimeFunctions` record its `MethodDefEntryPoints`
    /// element names, in row order.
    ///
    /// The record's shape is the machine's: twelve bytes on x64 (begin, end,
    /// unwind), eight on ARM64, ARM and x86 (begin, unwind).
    ///
    /// # Errors
    ///
    /// When a section is missing or does not read, a record the array names
    /// is past the table, or the machine is one whose record shape the
    /// runtime does not state.
    pub fn method_entries(&self, asm: &CilObject) -> Result<Vec<MethodEntry>> {
        let file = asm.file();
        self.method_entries_in(|section| {
            file.section_bounded(section.rva as usize)
                .ok()?
                .get(..section.size as usize)
        })
    }

    /// [`Self::method_entries`], `bytes` resolving a section to its bytes.
    fn method_entries_in<'a>(
        &self,
        bytes: impl Fn(ReadyToRunSection) -> Option<&'a [u8]>,
    ) -> Result<Vec<MethodEntry>> {
        let record: usize = match self.machine {
            MACHINE_AMD64 => 12,
            MACHINE_ARM64 | MACHINE_ARMNT | MACHINE_I386 => 8,
            other => {
                return Err(malformed_error!(
                    "ReadyToRun: no record shape for machine {other:#06x}"
                ));
            }
        };
        let thumb = self.machine == MACHINE_ARMNT;
        let section = |kind: u32, name: &str| {
            let section = self
                .section(kind)
                .ok_or_else(|| malformed_error!("ReadyToRun: no {name} section"))?;
            bytes(section).ok_or_else(|| {
                malformed_error!(
                    "ReadyToRun: the {name} section at {:#x} does not read",
                    section.rva
                )
            })
        };
        let functions = section(RUNTIME_FUNCTIONS, "RuntimeFunctions")?;
        let entries = section(METHOD_DEF_ENTRY_POINTS, "MethodDefEntryPoints")?;
        let reader = NativeReader(entries);
        reader
            .array()?
            .into_iter()
            .map(|(index, offset)| {
                let (id, _) = reader.unsigned(offset)?;
                // Bit 0 says the method's code has fixups, which a further
                // number locates; the record's index sits above the flags
                // either way.
                let runtime_function = if id & 1 != 0 { id >> 2 } else { id >> 1 };
                let row = index.saturating_add(1);
                let begin = (runtime_function as usize)
                    .checked_mul(record)
                    .and_then(|at| read_u32(functions, at))
                    .ok_or_else(|| {
                        malformed_error!(
                            "ReadyToRun: method row {row} names record {runtime_function} of {}",
                            functions.len().checked_div(record).unwrap_or(0)
                        )
                    })?;
                Ok(MethodEntry {
                    token: Token::from_parts(TableId::MethodDef, row),
                    rva: if thumb { begin & !1 } else { begin },
                })
            })
            .collect()
    }

    /// Every import cell the `ImportSections` section describes, with the
    /// fixup that fills it; none when the image states no such section.
    ///
    /// # Errors
    ///
    /// When the section table or a signature array does not read. A cell
    /// whose own signature does not read carries the error instead.
    pub fn import_cells(&self, asm: &CilObject) -> Result<Vec<ImportCell>> {
        let Some(sections) = self.section(IMPORT_SECTIONS) else {
            return Ok(Vec::new());
        };
        let file = asm.file();
        let at = |rva: u32| file.section_bounded(rva as usize).ok();
        let table = at(sections.rva)
            .and_then(|bytes| bytes.get(..sections.size as usize))
            .ok_or_else(|| {
                malformed_error!(
                    "ReadyToRun imports: the section table at {:#x} does not read",
                    sections.rva
                )
            })?;
        imports::read_cells(table, at)
    }
}

/// The machine a PE's machine `field` states, read through the runtime's OS
/// override: the field itself when it names a machine or when no override
/// explains it, else the machine it is that override of.
#[must_use]
pub fn native_machine(field: u16) -> u16 {
    if MACHINES.contains(&field) {
        return field;
    }
    OS_OVERRIDES
        .iter()
        .map(|salt| field ^ salt)
        .find(|machine| MACHINES.contains(machine))
        .unwrap_or(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A header reads its sections and its machine, and anything else is
    /// refused.**
    #[test]
    fn a_header_opens_with_rtr_and_lists_its_sections() {
        let mut bytes = vec![0x52, 0x54, 0x52, 0x00, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0];
        for (kind, rva, size) in [(102u32, 0x3000u32, 24u32), (103, 0x4000, 9)] {
            bytes.extend(kind.to_le_bytes());
            bytes.extend(rva.to_le_bytes());
            bytes.extend(size.to_le_bytes());
        }
        let header = ReadyToRun::parse(&bytes, 0xec20).expect("a header");
        assert_eq!((header.major_version, header.minor_version), (16, 0));
        assert_eq!(header.machine, MACHINE_ARM64, "ARM64 for macOS");
        assert_eq!(
            header.section(RUNTIME_FUNCTIONS).map(|s| s.rva),
            Some(0x3000)
        );
        assert_eq!(
            header.section(METHOD_DEF_ENTRY_POINTS).map(|s| s.size),
            Some(9)
        );
        assert!(
            ReadyToRun::parse(&bytes[..30], 0x8664).is_err(),
            "truncated"
        );
        bytes[0] = 0x51;
        assert!(ReadyToRun::parse(&bytes, 0x8664).is_err(), "not RTR");
    }

    /// **A machine reads through every OS override, and a machine field no
    /// override explains stands.**
    #[test]
    fn a_machine_reads_through_its_os_override() {
        assert_eq!(native_machine(0x8664), MACHINE_AMD64);
        assert_eq!(native_machine(0x8664 ^ 0x7b79), MACHINE_AMD64, "Linux");
        assert_eq!(native_machine(0xaa64 ^ 0x4644), MACHINE_ARM64, "macOS");
        assert_eq!(native_machine(0x014c ^ 0xadc4), MACHINE_I386, "FreeBSD");
        assert_eq!(native_machine(0x1234), 0x1234);
    }

    /// **The method entries resolve each compiled row to its record's begin**,
    /// in the machine's record shape, an ARM begin without its Thumb bit.
    #[test]
    fn method_entries_resolve_through_the_runtime_functions() {
        // Two ARM records (begin, unwind), and an array of one block whose
        // tree holds rows 1 and 3 (indices 0 and 2).
        let functions = [0x1001u32, 0x9000, 0x2001, 0x9010]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let entries = native_array(&[Some(0), None, Some(1), None]);
        let header = ReadyToRun {
            major_version: 9,
            minor_version: 0,
            sections: vec![
                ReadyToRunSection {
                    kind: RUNTIME_FUNCTIONS,
                    rva: 0x100,
                    size: 16,
                },
                ReadyToRunSection {
                    kind: METHOD_DEF_ENTRY_POINTS,
                    rva: 0x200,
                    size: 0,
                },
            ],
            machine: MACHINE_ARMNT,
        };
        let read = header
            .method_entries_in(|section| match section.kind {
                RUNTIME_FUNCTIONS => Some(functions.as_slice()),
                _ => Some(entries.as_slice()),
            })
            .expect("the entries read");
        assert_eq!(
            read,
            vec![
                MethodEntry {
                    token: Token::new(0x0600_0001),
                    rva: 0x1000
                },
                MethodEntry {
                    token: Token::new(0x0600_0003),
                    rva: 0x2000
                },
            ]
        );
        // The same table read as x64's twelve-byte records puts record 1 at
        // byte 12: the shape is the machine's.
        let x64 = ReadyToRun {
            machine: MACHINE_AMD64,
            ..header.clone()
        };
        let read = x64
            .method_entries_in(|section| match section.kind {
                RUNTIME_FUNCTIONS => Some(functions.as_slice()),
                _ => Some(entries.as_slice()),
            })
            .expect("the entries read");
        assert_eq!(
            read.iter().map(|entry| entry.rva).collect::<Vec<_>>(),
            [0x1001, 0x9010]
        );
        let unknown = ReadyToRun {
            machine: 0x1234,
            ..header
        };
        assert!(
            unknown
                .method_entries_in(|_| Some(functions.as_slice()))
                .is_err(),
            "a machine with no record shape"
        );
    }

    /// A NativeFormat array of `elements` (each a runtime function index or
    /// absent), in one block, as `crossgen2` lays one out: the header, a
    /// one-byte block index, then the block's tree.
    fn native_array(elements: &[Option<u32>]) -> Vec<u8> {
        // The tree for one block: a node per level whose low bits say which
        // children exist (1 = the lower half follows at once, 2 = the upper
        // half at the offset above the flags), leaves `index << 2`.
        fn subtree(elements: &[(u32, u32)], bit: u32, out: &mut Vec<u8>) {
            if let [(index, value)] = elements {
                out.push(((index % 16) << 3) as u8);
                out.push((value << 2) as u8);
                return;
            }
            let (low, high): (Vec<_>, Vec<_>) = elements
                .iter()
                .copied()
                .partition(|(index, _)| index & bit == 0);
            let mut low_bytes = Vec::new();
            if !low.is_empty() {
                subtree(&low, bit >> 1, &mut low_bytes);
            }
            let flags = u32::from(!low.is_empty()) | (u32::from(!high.is_empty()) << 1);
            let skip = 1 + low_bytes.len() as u32;
            out.push((((skip << 2) | flags) << 1) as u8);
            out.extend(low_bytes);
            if !high.is_empty() {
                subtree(&high, bit >> 1, out);
            }
        }
        let present: Vec<(u32, u32)> = elements
            .iter()
            .enumerate()
            .filter_map(|(index, value)| Some((index as u32, (*value)?)))
            .collect();
        // The block index's one entry places the tree just past itself.
        let mut out = vec![((elements.len() as u32) << 3) as u8, 1];
        subtree(&present, 8, &mut out);
        out
    }
}

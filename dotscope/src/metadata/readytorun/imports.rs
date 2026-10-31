//! A ReadyToRun image's import cells and the fixups that fill them.
//!
//! Code that reaches outside its own method - a call to another method, a
//! runtime helper, a type handle, a string - reads an **import cell**, a
//! pointer-sized slot the runtime fills. The `ImportSections` section lists
//! the cells in sections (`READYTORUN_IMPORT_SECTION`), and pairs each cell
//! with a fixup signature saying what fills it: a fixup kind
//! (`ReadyToRunFixupKind`), then the method, field, type, helper or string
//! the kind takes, read here as R2RDump's `ReadyToRunSignature.cs` reads it.

use crate::{
    metadata::readytorun::{
        native::{read_u16, read_u32},
        signature::{
            ModuleToken, SignatureReader, SignatureType, MEMBER_REF_TABLE, METHOD_DEF_TABLE,
        },
    },
    Result,
};

/// The bytes of one `READYTORUN_IMPORT_SECTION`.
pub(crate) const IMPORT_SECTION_SIZE: usize = 20;

/// `ReadyToRunImportSectionFlags::GCRefMap`: each cell's signature is
/// prefixed by its argument GC reference map.
pub(crate) const GC_REF_MAP: u16 = 0x0008;

/// `READYTORUN_FIXUP_ModuleOverride`, or-ed into a fixup's kind: the kind is
/// followed by the index of the module whose metadata its tokens are in.
const MODULE_OVERRIDE: u8 = 0x80;

/// An import cell: a pointer-sized slot the runtime fills, and what fills it.
#[derive(Debug, Clone)]
pub struct ImportCell {
    /// The cell's RVA.
    pub rva: u32,
    /// What fills it, or why its signature does not read.
    pub fixup: Result<Fixup>,
}

/// A fixup signature: what the runtime fills an import cell with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixup {
    /// The fixup's kind (`ReadyToRunFixupKind`), less the module override.
    pub kind: u8,
    /// The thing the kind takes.
    pub subject: FixupSubject,
}

/// What a fixup names, read as far as naming it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixupSubject {
    /// A method, by its `MethodDef` or `MemberRef` token.
    Method(ModuleToken),
    /// A field, by its `Field` or `MemberRef` token.
    Field(ModuleToken),
    /// A type.
    Type(SignatureType),
    /// A runtime helper, by its `ReadyToRunHelper` number.
    Helper(u32),
    /// A string literal, by its offset in the `#US` heap.
    String(u32),
    /// A subject this reader does not name: a dictionary lookup, a layout
    /// check, a method named by its vtable slot.
    Unnamed,
}

impl Fixup {
    /// Reads the fixup signature at the start of `bytes`, past its GC
    /// reference map when `gc_ref_map` says the section prefixes one.
    ///
    /// The map is a bit stream whose bytes carry seven bits each and say in
    /// the eighth whether another follows (`GCRefMapDecoder`), so it ends
    /// with the first byte whose high bit is clear.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedInput`] when the signature ends before the subject
    /// its kind takes.
    pub fn read(bytes: &[u8], gc_ref_map: bool) -> Result<Self> {
        let mut reader = SignatureReader { bytes, at: 0 };
        if gc_ref_map {
            while reader.byte()? & 0x80 != 0 {}
        }
        let first = reader.byte()?;
        let kind = first & !MODULE_OVERRIDE;
        let module = if first & MODULE_OVERRIDE != 0 {
            Some(reader.unsigned()?)
        } else {
            None
        };
        let token = |table: u32, rid: u32| ModuleToken::new(table, rid, module);
        let subject = match kind {
            // MethodHandle, MethodEntry, VirtualEntry, MethodDictionary,
            // DelegateCtor, IndirectPInvokeTarget, PInvokeTarget,
            // MethodEntry_ReadyToRun: a method signature.
            0x11 | 0x13 | 0x16 | 0x29 | 0x2c | 0x2e | 0x2f | 0x3b => reader
                .method(module)?
                .map_or(FixupSubject::Unnamed, FixupSubject::Method),
            // MethodEntry_DefToken, VirtualEntry_DefToken.
            0x14 | 0x17 => FixupSubject::Method(token(METHOD_DEF_TABLE, reader.unsigned()?)),
            // MethodEntry_RefToken, VirtualEntry_RefToken.
            0x15 | 0x18 => FixupSubject::Method(token(MEMBER_REF_TABLE, reader.unsigned()?)),
            // FieldHandle, FieldAddress, FieldOffset.
            0x12 | 0x20 | 0x27 => FixupSubject::Field(reader.field(module)?),
            // Check_FieldOffset: the offset, then the field.
            0x2b => {
                reader.unsigned()?;
                FixupSubject::Field(reader.field(module)?)
            }
            // Verify_FieldOffset: the offsets, then the field.
            0x31 => {
                reader.unsigned()?;
                reader.unsigned()?;
                FixupSubject::Field(reader.field(module)?)
            }
            // TypeHandle, NewObject, NewArray, IsInstanceOf, ChkCast,
            // CctorTrigger, the four static bases, FieldBaseOffset,
            // TypeDictionary, Check_TypeLayout, Verify_TypeLayout,
            // Continuation_Layout: a type (a layout may follow it).
            0x10 | 0x1c..=0x1f | 0x21..=0x26 | 0x28 | 0x2a | 0x32 | 0x37 => {
                FixupSubject::Type(SignatureType::read(&mut reader, module)?)
            }
            0x1a => FixupSubject::Helper(reader.unsigned()?),
            0x1b if module.is_none() => FixupSubject::String(reader.unsigned()?),
            _ => FixupSubject::Unnamed,
        };
        Ok(Self { kind, subject })
    }

    /// The fixup kind's name in `ReadyToRunFixupKind`, `None` for a number
    /// the runtime does not define.
    #[must_use]
    pub fn kind_name(&self) -> Option<&'static str> {
        Some(match self.kind {
            0x07 => "ThisObjDictionaryLookup",
            0x08 => "TypeDictionaryLookup",
            0x09 => "MethodDictionaryLookup",
            0x10 => "TypeHandle",
            0x11 => "MethodHandle",
            0x12 => "FieldHandle",
            0x13 => "MethodEntry",
            0x14 => "MethodEntry_DefToken",
            0x15 => "MethodEntry_RefToken",
            0x16 => "VirtualEntry",
            0x17 => "VirtualEntry_DefToken",
            0x18 => "VirtualEntry_RefToken",
            0x19 => "VirtualEntry_Slot",
            0x1a => "Helper",
            0x1b => "StringHandle",
            0x1c => "NewObject",
            0x1d => "NewArray",
            0x1e => "IsInstanceOf",
            0x1f => "ChkCast",
            0x20 => "FieldAddress",
            0x21 => "CctorTrigger",
            0x22 => "StaticBaseNonGC",
            0x23 => "StaticBaseGC",
            0x24 => "ThreadStaticBaseNonGC",
            0x25 => "ThreadStaticBaseGC",
            0x26 => "FieldBaseOffset",
            0x27 => "FieldOffset",
            0x28 => "TypeDictionary",
            0x29 => "MethodDictionary",
            0x2a => "Check_TypeLayout",
            0x2b => "Check_FieldOffset",
            0x2c => "DelegateCtor",
            0x2d => "DeclaringTypeHandle",
            0x2e => "IndirectPInvokeTarget",
            0x2f => "PInvokeTarget",
            0x30 => "Check_InstructionSetSupport",
            0x31 => "Verify_FieldOffset",
            0x32 => "Verify_TypeLayout",
            0x33 => "Check_VirtualFunctionOverride",
            0x34 => "Verify_VirtualFunctionOverride",
            0x35 => "Check_IL_Body",
            0x36 => "Verify_IL_Body",
            0x37 => "Continuation_Layout",
            0x38 => "ResumptionStubEntryPoint",
            0x39 => "InjectStringThunks",
            0x3a => "StoreMultiCallableAddrOfCode",
            0x3b => "MethodEntry_ReadyToRun",
            _ => return None,
        })
    }

    /// Whether the cell holds a method's code: a call through it calls the
    /// method itself, so the cell is named as the method is.
    #[must_use]
    pub fn is_method_code(&self) -> bool {
        matches!(self.kind, 0x13..=0x18 | 0x2e | 0x2f | 0x3b)
    }

    /// Whether the runtime fills the cell with the entry of exactly the method
    /// it names: a call through it, unlike a virtual one, runs no override.
    #[must_use]
    pub fn enters_named_method(&self) -> bool {
        matches!(self.kind, 0x13 | 0x14 | 0x15 | 0x3b)
    }
}

/// The name `ReadyToRunHelper` gives helper `number`, `None` for a number the
/// runtime does not define.
#[must_use]
pub fn helper_name(number: u32) -> Option<&'static str> {
    Some(match number {
        0x01 => "Module",
        0x02 => "GSCookie",
        0x03 => "IndirectTrapThreads",
        0x08 => "DelayLoad_MethodCall",
        0x10 => "DelayLoad_Helper",
        0x11 => "DelayLoad_Helper_Obj",
        0x12 => "DelayLoad_Helper_ObjObj",
        0x20 => "Throw",
        0x21 => "Rethrow",
        0x22 => "Overflow",
        0x23 => "RngChkFail",
        0x24 => "FailFast",
        0x25 => "ThrowNullRef",
        0x26 => "ThrowDivZero",
        0x27 => "ThrowExact",
        0x28 => "ThrowArgument",
        0x29 => "ThrowArgumentOutOfRange",
        0x2a => "ThrowPlatformNotSupported",
        0x2b => "ThrowNotImplemented",
        0x30 => "WriteBarrier",
        0x31 => "CheckedWriteBarrier",
        0x32 => "ByRefWriteBarrier",
        0x33 => "BulkWriteBarrier",
        0x34 => "BulkWriteBarrierSmall",
        0x38 => "Stelem_Ref",
        0x39 => "Ldelema_Ref",
        0x3e => "MemZero",
        0x3f => "MemSet",
        0x40 => "NativeMemSet",
        0x41 => "MemCpy",
        0x42 => "PInvokeBegin",
        0x43 => "PInvokeEnd",
        0x44 => "GCPoll",
        0x45 => "ReversePInvokeEnter",
        0x46 => "ReversePInvokeExit",
        0x47 => "ResumeAfterCatch",
        0x50 => "GetString",
        0x51 => "LogMethodEnter",
        0x54 => "GetRuntimeTypeHandle",
        0x55 => "GetRuntimeMethodHandle",
        0x56 => "GetRuntimeFieldHandle",
        0x58 => "Box",
        0x59 => "Box_Nullable",
        0x5a => "Unbox",
        0x5b => "Unbox_Nullable",
        0x5c => "NewMultiDimArr",
        0x5d => "Unbox_TypeTest",
        0x60 => "NewObject",
        0x61 => "NewArray",
        0x62 => "CheckCastAny",
        0x63 => "CheckInstanceAny",
        0x64 => "GenericGcStaticBase",
        0x65 => "GenericNonGcStaticBase",
        0x66 => "GenericGcTlsBase",
        0x67 => "GenericNonGcTlsBase",
        0x68 => "VirtualFuncPtr",
        0x69 => "IsInstanceOfException",
        0x6a => "NewMaybeFrozenArray",
        0x6b => "NewMaybeFrozenObject",
        0xc0 => "LMul",
        0xc1 => "LMulOfv",
        0xc2 => "ULMulOvf",
        0xc3 => "LDiv",
        0xc4 => "LMod",
        0xc5 => "ULDiv",
        0xc6 => "ULMod",
        0xc7 => "LLsh",
        0xc8 => "LRsh",
        0xc9 => "LRsz",
        0xca => "Lng2Dbl",
        0xcb => "ULng2Dbl",
        0xcc => "Div",
        0xcd => "Mod",
        0xce => "UDiv",
        0xcf => "UMod",
        0xd0 => "Dbl2Int",
        0xd1 => "Dbl2IntOvf",
        0xd2 => "Dbl2Lng",
        0xd3 => "Dbl2LngOvf",
        0xd4 => "Dbl2UInt",
        0xd5 => "Dbl2UIntOvf",
        0xd6 => "Dbl2ULng",
        0xd7 => "Dbl2ULngOvf",
        0xd8 => "Lng2Flt",
        0xd9 => "ULng2Flt",
        0xe0 => "DblRem",
        0xe1 => "FltRem",
        0xe2 => "DblRound",
        0xe3 => "FltRound",
        0xf0 => "PersonalityRoutine",
        0xf1 => "PersonalityRoutineFilterFunclet",
        0xf8 => "MonitorEnter",
        0xf9 => "MonitorExit",
        0x100 => "WriteBarrier_EAX",
        0x101 => "WriteBarrier_EBX",
        0x102 => "WriteBarrier_ECX",
        0x103 => "WriteBarrier_ESI",
        0x104 => "WriteBarrier_EDI",
        0x105 => "WriteBarrier_EBP",
        0x106 => "CheckedWriteBarrier_EAX",
        0x107 => "CheckedWriteBarrier_EBX",
        0x108 => "CheckedWriteBarrier_ECX",
        0x109 => "CheckedWriteBarrier_ESI",
        0x10a => "CheckedWriteBarrier_EDI",
        0x10b => "CheckedWriteBarrier_EBP",
        0x110 => "EndCatch",
        0x111 => "StackProbe",
        0x112 => "GetCurrentManagedThreadId",
        0x113 => "AllocContinuation",
        0x114 => "AllocContinuationClass",
        0x115 => "AllocContinuationMethod",
        0x116 => "InitClass",
        0x117 => "InitInstClass",
        0x118 => "R2RToInterpreter",
        _ => return None,
    })
}

/// Reads every cell the import section `table` (the `ImportSections`
/// section's bytes) describes, `at` resolving an RVA to the image's bytes from
/// there to the end of its section. A section with no signatures describes no
/// cells. A cell whose signature does not read carries the error, and the
/// cells after it still read.
///
/// # Errors
///
/// When a section's signature array does not read.
pub(crate) fn read_cells<'a>(
    table: &[u8],
    at: impl Fn(u32) -> Option<&'a [u8]>,
) -> Result<Vec<ImportCell>> {
    let mut cells = Vec::new();
    for entry in table.as_chunks::<IMPORT_SECTION_SIZE>().0 {
        let (Some(rva), Some(size), Some(flags), Some(&entry_size), Some(signatures)) = (
            read_u32(entry, 0),
            read_u32(entry, 4),
            read_u16(entry, 8),
            entry.get(11),
            read_u32(entry, 12),
        ) else {
            continue;
        };
        if signatures == 0 || entry_size == 0 {
            continue;
        }
        let count = size.checked_div(u32::from(entry_size)).unwrap_or(0);
        let rvas = at(signatures).ok_or_else(|| {
            malformed_error!(
                "ReadyToRun imports: the signatures of the cells at {rva:#x} do not read"
            )
        })?;
        for index in 0..count {
            let cell = index
                .checked_mul(u32::from(entry_size))
                .and_then(|offset| rva.checked_add(offset))
                .ok_or_else(|| {
                    malformed_error!("ReadyToRun imports: cell {index} at {rva:#x} overflows")
                })?;
            let signature = (index as usize)
                .checked_mul(4)
                .and_then(|offset| read_u32(rvas, offset))
                .ok_or_else(|| {
                    malformed_error!(
                        "ReadyToRun imports: the signature of the cell at {cell:#x} is past its array"
                    )
                })?;
            let fixup = at(signature)
                .ok_or_else(|| {
                    malformed_error!(
                        "ReadyToRun imports: the signature of the cell at {cell:#x} does not read"
                    )
                })
                .and_then(|bytes| Fixup::read(bytes, flags & GC_REF_MAP != 0));
            cells.push(ImportCell { rva: cell, fixup });
        }
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A fixup reads the subject its kind takes**, past a GC reference map
    /// when its section prefixes one, and with the module a module override
    /// names.
    #[test]
    fn a_fixup_reads_the_subject_its_kind_takes() {
        let read = |bytes: &[u8], gc: bool| Fixup::read(bytes, gc).expect("reads");
        // MethodEntry_DefToken of row 0x20, behind a two-byte GC map.
        let entry = read(&[0x85, 0x01, 0x14, 0x20], true);
        assert_eq!(entry.kind, 0x14);
        assert_eq!(
            entry.subject,
            FixupSubject::Method(ModuleToken::new(0x06, 0x20, None))
        );
        assert!(entry.enters_named_method() && entry.is_method_code());
        // The same bytes with no map read the map as the kind.
        assert_ne!(read(&[0x85, 0x01, 0x14, 0x20], false).kind, 0x14);
        // VirtualEntry_RefToken in module 2: code, but not one method's.
        let virtual_call = read(&[0x98, 0x02, 0x81, 0x00], false);
        assert_eq!(
            virtual_call.subject,
            FixupSubject::Method(ModuleToken::new(0x0a, 0x100, Some(2)))
        );
        assert!(virtual_call.is_method_code() && !virtual_call.enters_named_method());
        // MethodEntry: flags OwnerType | MemberRefToken, the owner
        // `List<__Canon>`, then the token.
        assert_eq!(
            read(&[0x13, 0x50, 0x15, 0x12, 0x6d, 0x01, 0x3e, 0x1f], false).subject,
            FixupSubject::Method(ModuleToken::new(0x0a, 0x1f, None))
        );
        // A method named by its slot names no token.
        assert_eq!(
            read(&[0x13, 0x08, 0x05], false).subject,
            FixupSubject::Unnamed
        );
        // FieldAddress: flags MemberRefToken, then the token.
        assert_eq!(
            read(&[0x20, 0x10, 0x20], false).subject,
            FixupSubject::Field(ModuleToken::new(0x0a, 0x20, None))
        );
        // Verify_FieldOffset: two offsets, then the field.
        assert_eq!(
            read(&[0x31, 0x08, 0x10, 0x00, 0x03], false).subject,
            FixupSubject::Field(ModuleToken::new(0x04, 0x03, None))
        );
        assert_eq!(
            read(&[0x1a, 0x81, 0x18], false).subject,
            FixupSubject::Helper(0x118)
        );
        assert_eq!(
            read(&[0x1b, 0x4f], false).subject,
            FixupSubject::String(0x4f)
        );
        // A string of another module's heap is not this image's to read.
        assert_eq!(
            read(&[0x9b, 0x01, 0x4f], false).subject,
            FixupSubject::Unnamed
        );
        assert!(
            Fixup::read(&[0x14], false).is_err(),
            "ends before its token"
        );
        assert!(
            Fixup::read(&[0x85, 0x81], true).is_err(),
            "ends inside its map"
        );
    }

    /// **An import section's cells each read their own fixup**, a cell whose
    /// signature does not read carrying the error while the others read.
    #[test]
    fn an_import_section_lists_its_cells_and_their_fixups() {
        // Image: the section table at 0x100, signature RVAs at 0x200, the
        // signatures at 0x300 and 0x304.
        let mut image = vec![0u8; 0x400];
        // The cells at 0x1000, 16 bytes; flags GCRefMap; type StubDispatch;
        // 8-byte cells; signatures at 0x200; no auxiliary data.
        let mut entry = Vec::new();
        entry.extend(0x1000u32.to_le_bytes());
        entry.extend(16u32.to_le_bytes());
        entry.extend(GC_REF_MAP.to_le_bytes());
        entry.extend([2u8, 8u8]);
        entry.extend(0x200u32.to_le_bytes());
        entry.extend(0u32.to_le_bytes());
        image[0x100..0x114].copy_from_slice(&entry);
        image[0x200..0x204].copy_from_slice(&0x300u32.to_le_bytes());
        image[0x204..0x208].copy_from_slice(&0x3fcu32.to_le_bytes());
        image[0x300..0x303].copy_from_slice(&[0x00, 0x1a, 0x30]);
        image[0x3fc..0x400].copy_from_slice(&[0x80, 0x80, 0x80, 0x80]);
        let cells = read_cells(&image[0x100..0x114], |rva| image.get(rva as usize..))
            .expect("the table reads");
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0].rva, 0x1000);
        assert_eq!(
            cells[0]
                .fixup
                .as_ref()
                .map(|fixup| fixup.subject.clone())
                .ok(),
            Some(FixupSubject::Helper(0x30))
        );
        assert_eq!(cells[1].rva, 0x1008);
        assert!(cells[1].fixup.is_err(), "its map runs off the image");
        assert_eq!(helper_name(0x30), Some("WriteBarrier"));
    }
}

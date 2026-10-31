//! Assembly and module header directive formatting (`.assembly`, `.module`).
//!
//! Emits ILAsm-compatible assembly and module header directives including
//! version information, custom attributes, security declarations, `.corflags`,
//! PE header directives (`.imagebase`, `.file alignment`, `.stackreserve`,
//! `.subsystem`), `.assembly extern` references, `.module extern` directives,
//! `.file` directives, and `.class extern` (exported/forwarded types).

use std::io::{self, Write};

use crate::{
    file::sectionmap::RvaMapping,
    formatting::{
        attributes,
        helpers::{data_label_for_rva, hex_bytes, quote_identifier},
        security, FormatterOptions,
    },
    metadata::{
        identity::Identity,
        signatures::TypeSignature,
        tables::{AssemblyFlags, FileAttributes, HashAlgorithmId, TableId, TypeAttributes},
        typesystem::CilTypeReference,
    },
    CilObject,
};

/// Write assembly processor architecture and content type flags.
///
/// Emits ILDasm-compatible flags like `cil`, `x86`, `amd64`, `arm`, `arm64`,
/// `windowsruntime`, `noplatform` based on the assembly flags bitmask.
fn write_assembly_arch_flags(w: &mut dyn Write, flags: AssemblyFlags) -> io::Result<()> {
    let kw = flags.processor_architecture_keyword();
    if !kw.is_empty() {
        write!(w, " {kw}")?;
    }
    if flags.content_type() == AssemblyFlags::CONTENT_TYPE_WINDOWS_RUNTIME {
        write!(w, " windowsruntime")?;
    }
    Ok(())
}

/// Write `.assembly` and `.module` header directives with PE metadata.
///
/// Emits the `.assembly` block (name, version, custom attributes, security),
/// the `.module` directive, `.corflags`, and PE header directives
/// (`.imagebase`, `.file alignment`, `.stackreserve`, `.subsystem`)
/// from the optional header's Windows-specific fields.
pub(super) fn format_header(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    asm: &CilObject,
) -> io::Result<()> {
    if let Some(asm_meta) = asm.assembly() {
        write!(w, ".assembly")?;
        write_assembly_arch_flags(w, asm_meta.flags)?;
        writeln!(w, " '{}' {{", asm_meta.name)?;

        if asm_meta.hash_alg_id != HashAlgorithmId::NONE {
            writeln!(w, "  .hash algorithm 0x{:08X}", asm_meta.hash_alg_id.bits())?;
        }
        writeln!(
            w,
            "  .ver {}:{}:{}:{}",
            asm_meta.major_version,
            asm_meta.minor_version,
            asm_meta.build_number,
            asm_meta.revision_number
        )?;

        if opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &asm_meta.custom_attributes, "  ", asm)?;
        }
        if opts.show_security {
            for (_, sec) in asm_meta.security.iter() {
                security::format_security(w, sec, "  ")?;
            }
        }

        writeln!(w, "}}")?;
    }
    if let Some(module) = asm.module() {
        writeln!(w, ".module {}", module.name)?;
    }

    // .corflags
    let flags = asm.cor20header().flags;
    writeln!(w, ".corflags 0x{:08X}    // {flags}", flags.bits())?;

    // PE header directives
    if let Some(oh) = &asm.file().pe().optional_header {
        let wf = &oh.windows_fields;
        writeln!(w, ".imagebase 0x{:08X}", wf.image_base)?;
        writeln!(w, ".file alignment 0x{:08X}", wf.file_alignment)?;
        writeln!(w, ".stackreserve 0x{:08X}", wf.size_of_stack_reserve)?;
        writeln!(
            w,
            ".subsystem 0x{:04X}    // {}",
            wf.subsystem.bits(),
            wf.subsystem
        )?;
    }

    writeln!(w)?;
    Ok(())
}

/// Write `.assembly extern` directives for all referenced assemblies.
///
/// Each external assembly reference is emitted with its name, optional
/// `retargetable` flag, public key token or public key (when available),
/// `.hash`, `.culture`, and version information.
pub(super) fn format_assembly_refs(w: &mut dyn Write, asm: &CilObject) -> io::Result<()> {
    for entry in asm.refs_assembly().iter() {
        let aref = entry.value();

        // .assembly extern [flags] 'Name'
        write!(w, ".assembly extern")?;
        if aref.flags.contains(AssemblyFlags::RETARGETABLE) {
            write!(w, " retargetable")?;
        }
        write_assembly_arch_flags(w, aref.flags)?;
        writeln!(w, " '{}' {{", aref.name)?;

        if let Some(ref ident) = aref.identifier {
            match ident {
                Identity::Token(token) => {
                    writeln!(w, "  .publickeytoken = ({})", hex_bytes(token))?;
                }
                Identity::PubKey(key) => {
                    writeln!(w, "  .publickey = ({})", hex_bytes(key))?;
                }
                Identity::EcmaKey(key) => {
                    writeln!(w, "  .publickey = ({})", hex_bytes(key))?;
                }
            }
        }

        // .hash
        if let Some(ref hash) = aref.hash {
            let hash_data = hash.data();
            if !hash_data.is_empty() {
                writeln!(w, "  .hash = ({})", hex_bytes(hash_data))?;
            }
        }

        // .culture
        if let Some(ref culture) = aref.culture {
            if !culture.is_empty() {
                writeln!(w, "  .culture \"{culture}\"")?;
            }
        }

        writeln!(
            w,
            "  .ver {}:{}:{}:{}",
            aref.major_version, aref.minor_version, aref.build_number, aref.revision_number
        )?;
        writeln!(w, "}}")?;
    }
    Ok(())
}

/// Write `.module extern` directives for all referenced external modules.
///
/// Module references represent external unmanaged modules (native DLLs) used
/// by P/Invoke declarations. Each is emitted as `.module extern 'ModuleName'`.
pub(super) fn format_module_refs(w: &mut dyn Write, asm: &CilObject) -> io::Result<()> {
    for entry in asm.refs_module().iter() {
        let mref = entry.value();
        writeln!(w, ".module extern '{}'", mref.name)?;
    }
    Ok(())
}

/// Write `.file` directives for multi-file assembly entries.
///
/// Each file entry has flags (nometadata), name, and hash value.
/// ILAsm syntax: `.file nometadata 'ResourceFile.dat'`
///               `.file 'Module2.netmodule' .hash = (XX XX ...)`
pub(super) fn format_file_directives(w: &mut dyn Write, asm: &CilObject) -> io::Result<()> {
    for entry in asm.refs_file().iter() {
        let file = entry.value();

        write!(w, ".file")?;

        // ContainsNoMetaData flag = 0x0001
        if file.flags.contains(FileAttributes::CONTAINS_NO_META_DATA) {
            write!(w, " nometadata")?;
        }

        write!(w, " '{}'", file.name)?;

        // .hash
        let hash_data = file.hash_value.data();
        if !hash_data.is_empty() {
            write!(w, " .hash = ({})", hex_bytes(hash_data))?;
        }

        writeln!(w)?;
    }
    Ok(())
}

/// Write `.class extern` directives for exported and forwarded types.
///
/// Exported types reference types in other modules of the same assembly
/// or type forwarders to other assemblies. Each entry specifies the
/// implementation (`.file` or `.assembly extern`) and nested type parent.
pub(super) fn format_exported_types(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    asm: &CilObject,
) -> io::Result<()> {
    let cil_exports = asm.exports().cil();

    for entry in cil_exports.iter() {
        let exported = entry.value();
        let flags = exported.flags;

        // Build visibility string from flags
        let vis = match flags & TypeAttributes::VISIBILITY_MASK {
            TypeAttributes::PUBLIC => "public",
            TypeAttributes::NESTED_PUBLIC => "nested public",
            TypeAttributes::NESTED_PRIVATE => "nested private",
            TypeAttributes::NESTED_FAMILY => "nested family",
            TypeAttributes::NESTED_ASSEMBLY => "nested assembly",
            TypeAttributes::NESTED_FAM_AND_ASSEM => "nested famandassem",
            TypeAttributes::NESTED_FAM_OR_ASSEM => "nested famorassem",
            _ => "private",
        };

        let is_forwarder = flags.contains(TypeAttributes::FORWARDER);

        // Build full type name
        let fullname = match &exported.namespace {
            Some(ns) if !ns.is_empty() => format!("{ns}.{}", exported.name),
            _ => exported.name.clone(),
        };

        if is_forwarder {
            writeln!(
                w,
                ".class extern forwarder {} {{",
                quote_identifier(&fullname)
            )?;
        } else {
            writeln!(w, ".class extern {vis} {} {{", quote_identifier(&fullname))?;
        }

        // Implementation reference
        if let Some(implementation) = exported.get_implementation() {
            match implementation {
                CilTypeReference::File(file) => {
                    writeln!(w, "  .file '{}'", file.name)?;
                }
                CilTypeReference::AssemblyRef(aref) => {
                    writeln!(w, "  .assembly extern '{}'", aref.name)?;
                }
                CilTypeReference::ExportedType(parent) => {
                    let parent_fullname = match &parent.namespace {
                        Some(ns) if !ns.is_empty() => format!("{ns}.{}", parent.name),
                        _ => parent.name.clone(),
                    };
                    writeln!(w, "  .class extern {}", quote_identifier(&parent_fullname))?;
                }
                _ => {}
            }
        }

        if opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &exported.custom_attributes, "  ", asm)?;
        }

        writeln!(w, "}}")?;
    }
    Ok(())
}

/// Write `.data` directives for fields with RVA-based initial data.
///
/// Scans all TypeDef types for fields that have an RVA (initial data embedded
/// in the PE file). For each such field, reads the raw bytes from the PE file
/// at the field's RVA and emits a `.data D_XXXXXXXX = bytearray (...)` directive.
/// The data size is determined by the field type's `class_size` property.
///
/// Section-aware labeling: fields in `.tls` sections get `T_` prefix and `tls`
/// qualifier, fields in `.text` get `I_` prefix and `cil` qualifier, all others
/// get `D_` prefix. Uninitialized data (RVA within virtual size but beyond raw
/// data) is emitted as `int8[count]` instead of `bytearray(...)`.
pub(super) fn format_data_directives(w: &mut dyn Write, asm: &CilObject) -> io::Result<()> {
    let file = asm.file();
    let sections = file.sections();

    // Collect all field RVAs from TypeDef entries.
    // Each entry is (rva, size, Option<bytes>) — None means uninitialized.
    let mut data_entries: Vec<(u32, usize, Option<Vec<u8>>)> = Vec::new();

    for cil_type in asm
        .query_types()
        .filter(|t| t.token.is_table(TableId::TypeDef))
        .find_all()
    {
        for (_, field) in cil_type.fields.iter() {
            let Some(&rva) = field.rva.get() else {
                continue;
            };

            // Extract the type token from the field's type signature
            let type_token = match &field.signature.base {
                TypeSignature::ValueType(token) | TypeSignature::Class(token) => Some(*token),
                _ => None,
            };

            // Determine data size from the field type's class_size
            let size = type_token
                .and_then(|token| asm.types().get(&token))
                .and_then(|t| t.class_size.get().copied())
                .unwrap_or(0) as usize;

            if size == 0 {
                continue;
            }

            // Uninitialized (BSS) data lives in a section's zero-filled part, past its raw data
            match file.section_map().map(rva) {
                RvaMapping::ZeroFill => data_entries.push((rva, size, None)),
                RvaMapping::File(_) => {
                    let Ok(bytes) = file.rva_slice(rva as usize, size) else {
                        continue;
                    };
                    data_entries.push((rva, size, Some(bytes.into_owned())));
                }
                RvaMapping::Unmapped => {}
            }
        }
    }

    // Sort by RVA for deterministic output
    data_entries.sort_by_key(|&(rva, _, _)| rva);
    data_entries.dedup_by_key(|entry| entry.0);

    for (rva, size, bytes_opt) in &data_entries {
        let (prefix, qualifier) = data_label_for_rva(sections, *rva);
        match bytes_opt {
            Some(bytes) => {
                write!(w, ".data{qualifier} {prefix}{rva:08X} = bytearray (")?;
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(w, " ")?;
                    }
                    write!(w, "{b:02X}")?;
                }
                writeln!(w, ")")?;
            }
            None => {
                writeln!(w, ".data{qualifier} {prefix}{rva:08X} = int8[{size}]")?;
            }
        }
    }

    if !data_entries.is_empty() {
        writeln!(w)?;
    }

    Ok(())
}

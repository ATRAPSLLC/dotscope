//! Manifest resource (`.mresource`) directive formatting.
//!
//! Emits ILAsm-compatible `.mresource` directives with visibility,
//! resource name, and source directives for external files or assemblies.

use std::io::{self, Write};

use crate::{
    formatting::helpers::quoted_name,
    metadata::{tables::ManifestResourceAttributes, typesystem::CilTypeReference},
    CilObject,
};

/// Write `.mresource` directives for all manifest resources.
///
/// Each resource is emitted with its visibility (`public`/`private`),
/// name, and source directive indicating where the resource data lives:
/// - No source: embedded in the current module
/// - `.file 'name' at 0xOFFSET`: in an external file
/// - `.assembly extern 'name'`: in an external assembly
pub fn format_resources(w: &mut dyn Write, assembly: &CilObject) -> io::Result<()> {
    for entry in assembly.resources().iter() {
        let resource = entry.value();
        let name = &resource.name;
        let vis = if resource.flags.contains(ManifestResourceAttributes::PUBLIC) {
            "public"
        } else {
            "private"
        };
        writeln!(w, ".mresource {vis} {} {{", quoted_name(name))?;

        // Source directive based on implementation
        match &resource.source {
            Some(CilTypeReference::File(file)) => {
                if resource.data_offset > 0 {
                    writeln!(
                        w,
                        "  .file {} at 0x{:08X}",
                        quoted_name(&file.name),
                        resource.data_offset
                    )?;
                } else {
                    writeln!(w, "  .file {}", quoted_name(&file.name))?;
                }
            }
            Some(CilTypeReference::AssemblyRef(aref)) => {
                writeln!(w, "  .assembly extern {}", quoted_name(&aref.name))?;
            }
            _ => {
                // Embedded resource — no source directive needed
            }
        }

        writeln!(w, "}}")?;
    }
    Ok(())
}

//! VTableFixup directive formatting (`.vtfixup`, `.vtentry`, `.export`).
//!
//! Renders ILAsm-compatible `.vtfixup` assembly-level directives and per-method
//! `.vtentry` / `.export` directives from a pre-parsed [`VtFixupContext`].

use std::io::{self, Write};

use crate::{
    file::pe::SectionTable,
    formatting::helpers::data_label_for_rva,
    metadata::vtfixup::{
        VtFixupContext, COR_VTABLE_64BIT, COR_VTABLE_CALL_MOST_DERIVED, COR_VTABLE_FROM_UNMANAGED,
        COR_VTABLE_RETAIN_APPDOMAIN,
    },
};

/// Write `.vtfixup` assembly-level directives.
///
/// Emits one `.vtfixup` directive per VTableFixup entry:
/// ```text
/// .vtfixup [Count] int32 fromunmanaged at D_XXXXXXXX
/// ```
pub fn format_vtfixup_directives(
    w: &mut dyn Write,
    ctx: &VtFixupContext,
    sections: &[SectionTable],
) -> io::Result<()> {
    for entry in &ctx.entries {
        let (prefix, _) = data_label_for_rva(sections, entry.rva);
        let width = if entry.flags & COR_VTABLE_64BIT != 0 {
            "int64"
        } else {
            "int32"
        };

        write!(w, ".vtfixup [{:>4}] {width}", entry.count)?;

        if entry.flags & COR_VTABLE_FROM_UNMANAGED != 0 {
            write!(w, " fromunmanaged")?;
        }
        if entry.flags & COR_VTABLE_RETAIN_APPDOMAIN != 0 {
            write!(w, " retainappdomain")?;
        }
        if entry.flags & COR_VTABLE_CALL_MOST_DERIVED != 0 {
            write!(w, " callmostderived")?;
        }

        writeln!(w, " at {prefix}{:08X}", entry.rva)?;
    }

    Ok(())
}

/// Write `.vtentry` and `.export` directives for a single method.
///
/// Called within the method body to emit per-method vtable and export directives:
/// ```text
///     .vtentry 1 : 1
///     .export [1] as MyFunction
/// ```
pub fn format_method_vtentry_export(
    w: &mut dyn Write,
    method_token: u32,
    ctx: &VtFixupContext,
) -> io::Result<()> {
    // .vtentry directives
    if let Some(positions) = ctx.vtentry_map.get(&method_token) {
        for &(entry, slot) in positions {
            writeln!(w, "    .vtentry {entry} : {slot}")?;
        }
    }

    // .export directive
    if let Some((ordinal, ref name)) = ctx.export_map.get(&method_token) {
        match name {
            Some(n) => writeln!(w, "    .export [{ordinal}] as {n}")?,
            None => writeln!(w, "    .export [{ordinal}]")?,
        }
    }

    Ok(())
}

//! Type (`.class`) directive formatting.
//!
//! Emits ILAsm-compatible `.class` directives with visibility, layout, string format,
//! interface/abstract/sealed flags, generic parameters, base type, implemented interfaces,
//! and class layout directives (`.pack` and `.size`).

use std::io::{self, Write};

use crate::{
    formatting::{
        generics,
        helpers::{assembly_scoped_name, quote_identifier},
    },
    metadata::{tables::TypeAttributes, typesystem::CilType},
    CilObject,
};

/// Write the opening `.class` directive for a type with full attribute flags.
///
/// Emits the complete type header including visibility, layout mode, string format,
/// semantic flags, type name with generic parameters, `extends` clause, and
/// `implements` clause. After the opening brace, emits `.pack` and `.size`
/// directives when the type has explicit packing or class size from the
/// `ClassLayout` table.
pub(super) fn format_type_begin(
    w: &mut dyn Write,
    cil_type: &CilType,
    asm: &CilObject,
) -> io::Result<()> {
    let flags = cil_type.flags;

    write!(w, ".class")?;

    // Visibility
    match flags & TypeAttributes::VISIBILITY_MASK {
        TypeAttributes::NOT_PUBLIC => write!(w, " private")?,
        TypeAttributes::PUBLIC => write!(w, " public")?,
        TypeAttributes::NESTED_PUBLIC => write!(w, " nested public")?,
        TypeAttributes::NESTED_PRIVATE => write!(w, " nested private")?,
        TypeAttributes::NESTED_FAMILY => write!(w, " nested family")?,
        TypeAttributes::NESTED_ASSEMBLY => write!(w, " nested assembly")?,
        TypeAttributes::NESTED_FAM_AND_ASSEM => write!(w, " nested famandassem")?,
        TypeAttributes::NESTED_FAM_OR_ASSEM => write!(w, " nested famorassem")?,
        _ => {}
    }

    // Layout
    match flags & TypeAttributes::LAYOUT_MASK {
        TypeAttributes::SEQUENTIAL_LAYOUT => write!(w, " sequential")?,
        TypeAttributes::EXPLICIT_LAYOUT => write!(w, " explicit")?,
        _ => write!(w, " auto")?,
    }

    // String format
    match flags & TypeAttributes::STRING_FORMAT_MASK {
        TypeAttributes::UNICODE_CLASS => write!(w, " unicode")?,
        TypeAttributes::AUTO_CLASS => write!(w, " autochar")?,
        _ => write!(w, " ansi")?,
    }

    // Interface
    if flags.contains(TypeAttributes::INTERFACE) {
        write!(w, " interface")?;
    }

    // Abstract
    if flags.contains(TypeAttributes::ABSTRACT) {
        write!(w, " abstract")?;
    }

    // Sealed
    if flags.contains(TypeAttributes::SEALED) {
        write!(w, " sealed")?;
    }

    // BeforeFieldInit
    if flags.contains(TypeAttributes::BEFORE_FIELD_INIT) {
        write!(w, " beforefieldinit")?;
    }

    // Serializable
    if flags.contains(TypeAttributes::SERIALIZABLE) {
        write!(w, " serializable")?;
    }

    // SpecialName
    if flags.contains(TypeAttributes::SPECIAL_NAME) {
        write!(w, " specialname")?;
    }

    // RTSpecialName
    if flags.contains(TypeAttributes::RT_SPECIAL_NAME) {
        write!(w, " rtspecialname")?;
    }

    // Import
    if flags.contains(TypeAttributes::IMPORT) {
        write!(w, " import")?;
    }

    // Type name + generic parameters
    // Nested types use their simple name — the nesting hierarchy is established
    // by physical containment within the enclosing type's class body.
    let type_name = if cil_type.enclosing_type().is_some() {
        quote_identifier(&cil_type.name)
    } else {
        quote_identifier(&cil_type.fullname())
    };
    write!(w, " {type_name}")?;
    generics::write_generic_params(w, &cil_type.generic_params, asm)?;

    // Extends — ILDasm always emits `extends` for any non-nil base type,
    // including System.Object. Only types with no base (like <Module> and
    // System.Object itself) omit this clause.
    if let Some(base) = cil_type.base() {
        let base_name = assembly_scoped_name(&base, asm);
        write!(w, "\n       extends {base_name}")?;
    }

    // Implements
    let interfaces: Vec<_> = cil_type.interfaces.iter().collect();
    if !interfaces.is_empty() {
        write!(w, "\n       implements ")?;
        for (i, (_, entry)) in interfaces.iter().enumerate() {
            if i > 0 {
                write!(w, ", ")?;
            }
            if let Some(iface_type) = entry.interface.upgrade() {
                write!(w, "{}", assembly_scoped_name(&iface_type, asm))?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "{{")?;

    // .pack and .size for sequential/explicit layout types
    if let Some(&packing) = cil_type.packing_size.get() {
        if packing > 0 {
            writeln!(w, "  .pack {packing}")?;
        }
    }
    if let Some(&size) = cil_type.class_size.get() {
        if size > 0 {
            writeln!(w, "  .size {size}")?;
        }
    }

    Ok(())
}

/// Write the closing brace and end-of-class comment for a type.
pub(super) fn format_type_end(w: &mut dyn Write, cil_type: &CilType) -> io::Result<()> {
    // Use simple name for nested types (same as in the .class directive)
    let display_name = if cil_type.enclosing_type().is_some() {
        cil_type.name.clone()
    } else {
        cil_type.fullname().to_string()
    };
    writeln!(w, "}} // end of class {display_name}")?;
    writeln!(w)?;
    Ok(())
}

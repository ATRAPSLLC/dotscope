//! Field (`.field`) directive formatting.
//!
//! Emits ILAsm-compatible `.field` directives including access modifiers, type signatures,
//! marshalling information, field RVA data references, default values, explicit layout
//! offsets, and custom attributes.

use std::io::{self, Write};

use crate::{
    formatting::{
        attributes,
        helpers::{data_label_for_rva, format_constant, format_type_sig, quote_identifier},
        FormatterOptions,
    },
    metadata::{tables::TypeAttributes, typesystem::CilType},
    CilObject,
};

/// Write all `.field` directives for a type's fields.
///
/// Each field is emitted with its full ILAsm syntax including optional explicit
/// layout offset `[N]`, access modifiers, modifier flags (`static`, `initonly`,
/// `literal`), optional `marshal(...)` info, type signature, name, optional
/// `at D_XXXXXXXX` RVA reference, optional `= <value>` default value, and
/// custom attributes.
pub fn format_fields(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    cil_type: &CilType,
    asm: &CilObject,
) -> io::Result<()> {
    let is_explicit_layout = cil_type.flags.layout() == TypeAttributes::EXPLICIT_LAYOUT;

    for (_, field) in cil_type.fields.iter() {
        let flags = field.flags;

        write!(w, "  .field")?;

        // Explicit layout offset
        if is_explicit_layout {
            if let Some(&offset) = field.layout.get() {
                write!(w, " [{offset}]")?;
            }
        }

        // Access
        let kw = flags.access_keyword();
        if !kw.is_empty() {
            write!(w, " {kw}")?;
        }

        // Modifiers
        if flags.is_static() {
            write!(w, " static")?;
        }
        if flags.is_init_only() {
            write!(w, " initonly")?;
        }
        if flags.is_literal() {
            write!(w, " literal")?;
        }
        if flags.is_not_serialized() {
            write!(w, " notserialized")?;
        }
        if flags.is_special_name() {
            write!(w, " specialname")?;
        }
        if flags.is_rt_special_name() {
            write!(w, " rtspecialname")?;
        }

        // Marshal info
        if flags.has_field_marshal() {
            if let Some(marshal) = field.marshal.get() {
                write!(w, " marshal({marshal})")?;
            }
        }

        // Type and name
        write!(
            w,
            " {} {}",
            format_type_sig(&field.signature.base, asm),
            quote_identifier(&field.name)
        )?;

        // Field RVA
        if let Some(&rva) = field.rva.get() {
            let (prefix, _) = data_label_for_rva(asm.file().sections(), rva);
            write!(w, " at {prefix}{rva:08X}")?;
        }

        // Default value (for any field with HAS_DEFAULT, not just literals)
        if flags.has_default() {
            if let Some(default) = field.default.get() {
                write!(w, " = {}", format_constant(default))?;
            }
        }

        writeln!(w)?;

        // Custom attributes on fields
        if opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &field.custom_attributes, "  ", asm)?;
        }
    }
    Ok(())
}

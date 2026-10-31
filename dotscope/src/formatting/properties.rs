//! Property (`.property`) directive formatting.
//!
//! Emits ILAsm-compatible `.property` directives with `instance` prefix,
//! property type, default values, `.get`, `.set`, and `.other` accessor
//! methods using full method reference signatures, and custom attributes.

use std::io::{self, Write};

use crate::{
    formatting::{
        attributes,
        helpers::{
            format_constant, format_method_ref, format_sig_param, format_type_sig, quote_identifier,
        },
        FormatterOptions,
    },
    metadata::typesystem::CilType,
    CilObject,
};

/// Write all `.property` directives for a type's properties.
///
/// Each property is emitted with its type, name, optional default value,
/// accessor methods (`.get`, `.set`, `.other`), and custom attributes.
pub(super) fn format_properties(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    cil_type: &CilType,
    asm: &CilObject,
) -> io::Result<()> {
    for (_, prop) in cil_type.properties.iter() {
        // Property signature type
        let prop_type = format_type_sig(&prop.signature.base, asm);

        write!(w, "  .property")?;

        // Check if property accessors are instance methods
        let is_instance = prop
            .fn_getter
            .get()
            .and_then(|mr| mr.upgrade())
            .is_some_and(|m| !m.is_static());
        if is_instance {
            write!(w, " instance")?;
        }

        write!(w, " {prop_type} {}", quote_identifier(&prop.name))?;
        // Property parameter list (empty for normal properties, non-empty for indexers)
        write!(w, "(")?;
        for (i, param) in prop.signature.params.iter().enumerate() {
            if i > 0 {
                write!(w, ", ")?;
            }
            write!(w, "{}", format_sig_param(param, asm))?;
        }
        write!(w, ")")?;

        // Default value on the .property line
        if let Some(default) = prop.default.get() {
            write!(w, " = {}", format_constant(default))?;
        }

        writeln!(w)?;
        writeln!(w, "  {{")?;

        // Custom attributes on property
        if opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &prop.custom_attributes, "    ", asm)?;
        }

        // .get accessor
        if let Some(getter_ref) = prop.fn_getter.get() {
            if let Some(getter) = getter_ref.upgrade() {
                writeln!(w, "    .get {}", format_method_ref(&getter, asm))?;
            }
        }

        // .set accessor
        if let Some(setter_ref) = prop.fn_setter.get() {
            if let Some(setter) = setter_ref.upgrade() {
                writeln!(w, "    .set {}", format_method_ref(&setter, asm))?;
            }
        }

        // .other accessors
        for (_, other_ref) in prop.fn_other.iter() {
            if let Some(other) = other_ref.upgrade() {
                writeln!(w, "    .other {}", format_method_ref(&other, asm))?;
            }
        }

        writeln!(
            w,
            "  }} // end of property {}::{}",
            cil_type.fullname(),
            prop.name
        )?;
    }
    Ok(())
}

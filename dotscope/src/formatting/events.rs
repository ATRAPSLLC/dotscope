//! Event (`.event`) directive formatting.
//!
//! Emits ILAsm-compatible `.event` directives with the event type,
//! `.addon`, `.removeon`, `.fire`, and `.other` accessor methods using
//! full method reference signatures, and custom attributes.

use std::io::{self, Write};

use crate::{
    formatting::{
        attributes,
        helpers::{assembly_scoped_name, format_method_ref, quote_identifier},
        FormatterOptions,
    },
    metadata::typesystem::CilType,
    CilObject,
};

/// Write all `.event` directives for a type's events.
///
/// Each event is emitted with its delegate type, name, accessor methods
/// (`.addon`, `.removeon`, `.fire`, `.other`), and custom attributes.
pub(super) fn format_events(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    cil_type: &CilType,
    asm: &CilObject,
) -> io::Result<()> {
    for (_, event) in cil_type.events.iter() {
        let event_type_name = event
            .event_type
            .upgrade()
            .map_or_else(|| "[?]".to_string(), |t| assembly_scoped_name(&t, asm));

        writeln!(
            w,
            "  .event {event_type_name} {}",
            quote_identifier(&event.name)
        )?;
        writeln!(w, "  {{")?;

        // Custom attributes on event
        if opts.show_custom_attributes {
            attributes::format_custom_attributes(w, &event.custom_attributes, "    ", asm)?;
        }

        // .addon
        if let Some(add_ref) = event.fn_on_add.get() {
            if let Some(add_method) = add_ref.upgrade() {
                writeln!(w, "    .addon {}", format_method_ref(&add_method, asm))?;
            }
        }

        // .removeon
        if let Some(remove_ref) = event.fn_on_remove.get() {
            if let Some(remove_method) = remove_ref.upgrade() {
                writeln!(
                    w,
                    "    .removeon {}",
                    format_method_ref(&remove_method, asm)
                )?;
            }
        }

        // .fire
        if let Some(raise_ref) = event.fn_on_raise.get() {
            if let Some(raise_method) = raise_ref.upgrade() {
                writeln!(w, "    .fire {}", format_method_ref(&raise_method, asm))?;
            }
        }

        // .other
        for (_, other_ref) in event.fn_on_other.iter() {
            if let Some(other_method) = other_ref.upgrade() {
                writeln!(w, "    .other {}", format_method_ref(&other_method, asm))?;
            }
        }

        writeln!(
            w,
            "  }} // end of event {}::{}",
            cil_type.fullname(),
            event.name
        )?;
    }
    Ok(())
}

//! Custom attribute (`.custom`) rendering.
//!
//! Emits ILAsm-compatible `.custom` directives with constructor references,
//! raw blob bytes, and human-readable argument comments.

use std::io::{self, Write};

use crate::{
    formatting::{
        helpers::{assembly_scoped_name, format_method_call_sig, write_blob_hex},
        tokens::resolve_declaring_type,
    },
    metadata::{
        customattributes::{CustomAttributeValueList, CustomAttributeValueRc},
        tables::MemberRefSignature,
        typesystem::CilTypeReference,
    },
    CilObject,
};

/// Write all `.custom` directives from a [`CustomAttributeValueList`].
///
/// Each custom attribute is emitted at the given indentation level with its
/// constructor reference, raw blob bytes, and human-readable comment.
pub fn format_custom_attributes(
    w: &mut dyn Write,
    attrs: &CustomAttributeValueList,
    indent: &str,
    asm: &CilObject,
) -> io::Result<()> {
    for (_, attr) in attrs.iter() {
        write_custom_attribute(w, attr, indent, asm)?;
    }
    Ok(())
}

/// Format a constructor reference as an ILAsm string.
///
/// Produces a string like `instance void [mscorlib]System.ObsoleteAttribute::.ctor(string)`
/// from the constructor's `CilTypeReference`.
fn format_constructor_ref(constructor: &CilTypeReference, asm: &CilObject) -> Option<String> {
    match constructor {
        CilTypeReference::MemberRef(mref) => {
            let method_sig = match &mref.signature {
                MemberRefSignature::Method(sig) => sig,
                _ => return None,
            };

            let declaring = resolve_declaring_type(&mref.declaredby, asm);
            Some(format_method_call_sig(
                method_sig.has_this,
                &method_sig.return_type,
                Some(&declaring),
                &mref.name,
                &method_sig.params,
                asm,
            ))
        }
        CilTypeReference::MethodDef(method_ref) => {
            let method = method_ref.upgrade()?;
            let declaring_type = method
                .declaring_type_rc()
                .map(|t| assembly_scoped_name(&t, asm));
            Some(format_method_call_sig(
                method.signature.has_this && !method.is_static(),
                &method.signature.return_type,
                declaring_type.as_deref(),
                &method.name,
                &method.signature.params,
                asm,
            ))
        }
        _ => None,
    }
}

/// Write a single `.custom` directive with constructor reference and raw blob.
///
/// Output format:
/// ```text
///     // ("Hello World")
///     .custom instance void [mscorlib]System.ObsoleteAttribute::.ctor(string) = (
///         01 00 0B 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 )
/// ```
fn write_custom_attribute(
    w: &mut dyn Write,
    attr: &CustomAttributeValueRc,
    indent: &str,
    asm: &CilObject,
) -> io::Result<()> {
    // Human-readable comment with decoded arguments (before the directive).
    // Build the comment as a string first so we can sanitize embedded newlines
    // (which would break the // comment and confuse ilasm).
    if !attr.fixed_args.is_empty() || !attr.named_args.is_empty() {
        let mut comment = String::new();

        if !attr.fixed_args.is_empty() {
            comment.push('(');
            for (i, arg) in attr.fixed_args.iter().enumerate() {
                if i > 0 {
                    comment.push_str(", ");
                }
                comment.push_str(&format!("{arg}"));
            }
            comment.push(')');
        }

        if !attr.named_args.is_empty() {
            if !attr.fixed_args.is_empty() {
                comment.push(' ');
            }
            for (i, named) in attr.named_args.iter().enumerate() {
                if i > 0 {
                    comment.push(' ');
                }
                let kind = if named.is_field { "field" } else { "property" };
                comment.push_str(&format!(
                    "{kind} {} {} = {}",
                    named.arg_type, named.name, named.value
                ));
            }
        }

        // Escape embedded newlines so the comment stays on one line
        let comment = comment.replace('\n', "\\n").replace('\r', "\\r");
        writeln!(w, "{indent}// {comment}")?;
    }

    write!(w, "{indent}.custom ")?;

    // Constructor reference
    if let Some(ctor_ref) = format_constructor_ref(&attr.constructor, asm) {
        write!(w, "{ctor_ref}")?;
    }

    // Raw blob bytes
    if attr.blob_index > 0 {
        if let Some(blob_data) = asm.blob().and_then(|b| b.get(attr.blob_index).ok()) {
            if !blob_data.is_empty() {
                writeln!(w, " = (")?;
                write_blob_hex(w, indent, blob_data)?;
                write!(w, ")")?;
            }
        }
    }

    writeln!(w)?;

    Ok(())
}

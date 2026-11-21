//! Method header (`.method`) directive formatting.
//!
//! Emits ILAsm-compatible `.method` directives with access modifiers, vtable flags,
//! calling convention, return type, method name with generic parameters, parameter
//! list, and implementation code type.

use std::{
    io::{self, Write},
    sync::atomic::Ordering,
};

use crate::{
    formatting::{
        generics,
        helpers::{format_sig_param, quote_identifier, quoted_string},
    },
    metadata::{
        imports::{ImportSourceId, ImportType},
        method::{
            Method, MethodImplCodeType, MethodImplOptions, MethodModifiers, MethodVtableFlags,
        },
        tables::PInvokeAttributes,
    },
    CilObject,
};

/// Write the `.method` directive header line with all modifiers.
///
/// Emits the complete method signature including access level, `hidebysig`,
/// `newslot`, `static`/`virtual`/`final`/`abstract`, `specialname`/`rtspecialname`,
/// `pinvokeimpl`, calling convention (`instance`), return type, method name with
/// generic parameters, parameter list, and code type (`cil`/`native`/`runtime`
/// `managed`/`unmanaged`). Does not emit the opening brace.
pub fn format_method_header(w: &mut dyn Write, method: &Method, asm: &CilObject) -> io::Result<()> {
    let access = method.flags_access.ilasm_keyword();
    write!(w, "  .method {access}")?;

    if method
        .flags_modifiers
        .contains(MethodModifiers::HIDE_BY_SIG)
    {
        write!(w, " hidebysig")?;
    }

    if method.flags_vtable.contains(MethodVtableFlags::NEW_SLOT) {
        write!(w, " newslot")?;
    }

    if method.is_static() {
        write!(w, " static")?;
    }
    if method.is_virtual() {
        write!(w, " virtual")?;
    }
    if method.flags_modifiers.contains(MethodModifiers::FINAL) {
        write!(w, " final")?;
    }
    if method.is_abstract() {
        write!(w, " abstract")?;
    }
    if method
        .flags_modifiers
        .contains(MethodModifiers::SPECIAL_NAME)
    {
        write!(w, " specialname")?;
    }
    if method
        .flags_modifiers
        .contains(MethodModifiers::RTSPECIAL_NAME)
    {
        write!(w, " rtspecialname")?;
    }
    if method
        .flags_modifiers
        .contains(MethodModifiers::UNMANAGED_EXPORT)
    {
        write!(w, " unmanagedexp")?;
    }
    if method
        .flags_modifiers
        .contains(MethodModifiers::REQUIRE_SEC_OBJECT)
    {
        write!(w, " reqsecobj")?;
    }
    if method
        .flags_modifiers
        .contains(MethodModifiers::PINVOKE_IMPL)
    {
        write!(w, " pinvokeimpl")?;
        format_pinvoke_spec(w, method, asm)?;
    }

    // Calling convention
    if method.signature.has_this && !method.is_static() {
        write!(w, " instance")?;
    }

    // Return type
    write!(
        w,
        " {} ",
        format_sig_param(&method.signature.return_type, asm)
    )?;

    // Method name + generic parameters
    write!(w, "{}", quote_identifier(&method.name))?;
    generics::write_generic_params(w, &method.generic_params, asm)?;
    write!(w, "(")?;
    for (i, param) in method.signature.params.iter().enumerate() {
        if i > 0 {
            write!(w, ", ")?;
        }
        write!(w, "{}", format_sig_param(param, asm))?;
    }
    write!(w, ")")?;

    // preservesig
    if method
        .impl_options
        .contains(MethodImplOptions::PRESERVE_SIG)
    {
        write!(w, " preservesig")?;
    }

    // Code type (skip for P/Invoke methods — they have no CIL code body)
    let is_pinvoke = method
        .flags_modifiers
        .contains(MethodModifiers::PINVOKE_IMPL);
    if !is_pinvoke {
        if method.impl_code_type == MethodImplCodeType::IL {
            write!(w, " cil")?;
        } else if method.impl_code_type == MethodImplCodeType::NATIVE {
            write!(w, " native")?;
        } else if method.impl_code_type == MethodImplCodeType::RUNTIME {
            write!(w, " runtime")?;
        }
    }

    if method.is_code_unmanaged() {
        write!(w, " unmanaged")?;
    } else {
        write!(w, " managed")?;
    }

    // Implementation option flags
    if method.impl_options.contains(MethodImplOptions::FORWARD_REF) {
        write!(w, " forwardref")?;
    }
    if method
        .impl_options
        .contains(MethodImplOptions::SYNCHRONIZED)
    {
        write!(w, " synchronized")?;
    }
    if method.impl_options.contains(MethodImplOptions::NO_INLINING) {
        write!(w, " noinlining")?;
    }
    if method
        .impl_options
        .contains(MethodImplOptions::NO_OPTIMIZATION)
    {
        write!(w, " nooptimization")?;
    }
    if method
        .impl_options
        .contains(MethodImplOptions::AGGRESSIVE_INLINING)
    {
        write!(w, " aggressiveinlining")?;
    }
    if method
        .impl_options
        .contains(MethodImplOptions::AGGRESSIVE_OPTIMIZATION)
    {
        write!(w, " aggressiveoptimization")?;
    }

    writeln!(w)?;
    Ok(())
}

/// Write the `pinvokeimpl(...)` specification with DLL name, entry point, and attributes.
///
/// Produces: `("kernel32.dll" as "LoadLibrary" winapi lasterr)`
/// The DLL name and entry point are resolved from the imports system; the calling
/// convention and charset come from the method's P/Invoke attribute flags.
fn format_pinvoke_spec(w: &mut dyn Write, method: &Method, asm: &CilObject) -> io::Result<()> {
    let imports = asm.imports().cil();

    // Find the import entry for this method by matching the method token
    // (imports are keyed by ImplMap token, not MethodDef token)
    let import = imports.iter().find(|entry| {
        if let ImportType::Method(m) = &entry.value().import {
            m.token == method.token
        } else {
            false
        }
    });

    // Resolve DLL name and entry point from the import system
    let (dll_name, entry_name) = if let Some(ref entry) = import {
        let imp = entry.value();
        let dll = match &imp.source_id {
            ImportSourceId::ModuleRef(token) => {
                imports.get_module_ref(*token).map(|m| m.name.clone())
            }
            _ => None,
        };
        (dll, Some(imp.name.clone()))
    } else {
        (None, None)
    };

    write!(w, "(")?;

    // DLL name
    if let Some(ref dll) = dll_name {
        write!(w, "{}", quoted_string(dll))?;
    }

    // Entry point (only if it differs from the method name)
    if let Some(ref entry) = entry_name {
        if entry != &method.name {
            write!(w, " as {}", quoted_string(entry))?;
        }
    }

    // P/Invoke attribute flags
    let flags = PInvokeAttributes::new(method.flags_pinvoke.load(Ordering::Relaxed));

    // No mangle
    if flags.contains(PInvokeAttributes::NO_MANGLE) {
        write!(w, " nomangle")?;
    }

    // Character set
    let cs = flags.char_set_keyword();
    if !cs.is_empty() {
        write!(w, " {cs}")?;
    }

    // Supports last error
    if flags.contains(PInvokeAttributes::SUPPORTS_LAST_ERROR) {
        write!(w, " lasterr")?;
    }

    // Calling convention
    let cc = flags.call_conv_keyword();
    if !cc.is_empty() {
        write!(w, " {cc}")?;
    }

    // Best-fit mapping
    match flags.best_fit() {
        PInvokeAttributes::BEST_FIT_ENABLED => write!(w, " bestfit:on")?,
        PInvokeAttributes::BEST_FIT_DISABLED => write!(w, " bestfit:off")?,
        _ => {}
    }

    // Throw on unmappable char
    match flags.throw_on_unmappable() {
        PInvokeAttributes::THROW_ON_UNMAPPABLE_ENABLED => write!(w, " charmaperror:on")?,
        PInvokeAttributes::THROW_ON_UNMAPPABLE_DISABLED => write!(w, " charmaperror:off")?,
        _ => {}
    }

    write!(w, ")")?;
    Ok(())
}

/// Build the closing brace and end-of-method comment string.
///
/// Returns a string like `  } // end of method Namespace.Type::MethodName`.
pub fn method_end_comment(method: &Method) -> String {
    if let Some(type_name) = method.declaring_type_fullname() {
        format!("  }} // end of method {}::{}", type_name, method.name)
    } else {
        format!("  }} // end of method {}", method.name)
    }
}

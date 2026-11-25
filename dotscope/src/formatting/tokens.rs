//! Metadata token resolution for ILDasm-style output.
//!
//! Resolves metadata tokens embedded in IL instructions to full ILAsm-compatible
//! signatures, handling method definitions, member references, type references,
//! fields, type specifications, method specifications, standalone signatures,
//! and user strings.

use crate::{
    formatting::helpers::{
        assembly_scoped_name, format_method_call_sig, format_type_sig, format_typespec_from_blob,
        quote_identifier, user_string_literal,
    },
    metadata::{
        method::Method,
        tables::{MemberRef, MemberRefSignature},
        token::Token,
        typesystem::{CilFlavor, CilTypeReference},
    },
    CilObject,
};

/// Resolve a metadata token to a full ILAsm-compatible signature.
///
/// Handles MethodDef (0x06), MemberRef (0x0A), TypeRef/TypeDef (0x01/0x02),
/// Field (0x04), TypeSpec (0x1B), MethodSpec (0x2B), StandAloneSig (0x11),
/// and UserString (0x70) tokens.
pub fn resolve_token(assembly: &CilObject, token: Token) -> Option<String> {
    match token.table() {
        0x06 => {
            // MethodDef — full ILAsm method signature
            assembly.methods().get(&token).map(|entry| {
                let method = entry.value();
                format_methoddef_ref(method, assembly)
            })
        }
        0x0A => {
            // MemberRef — method or field reference with full signature
            assembly
                .member_ref(&token)
                .map(|mref| format_memberref(&mref, assembly))
        }
        0x01 | 0x02 => {
            // TypeRef or TypeDef — assembly-scoped name for external types
            assembly
                .types()
                .get(&token)
                .map(|t| assembly_scoped_name(&t, assembly))
        }
        0x04 => {
            // Field — type + assembly-scoped declaring type + field name
            assembly.types().iter().find_map(|entry| {
                let cil_type = entry.value();
                cil_type.fields.iter().find_map(|(_, field)| {
                    if field.token == token {
                        let type_name = assembly_scoped_name(cil_type, assembly);
                        let field_type = format_type_sig(&field.signature.base, assembly);
                        Some(format!(
                            "{field_type} {type_name}::{}",
                            quote_identifier(&field.name)
                        ))
                    } else {
                        None
                    }
                })
            })
        }
        0x1B => {
            // TypeSpec — may be a generic parameter, generic instantiation, or other constructed type.
            // Prefer formatting from the raw TypeSpec signature blob, which preserves the
            // full TypeSignature structure (including generic parameter indices). This avoids
            // the CilType.fullname() path which replaces `!!0` with metadata parameter names
            // like `TM0`, producing invalid ILAsm for composite types (e.g. `TM0[]` instead
            // of `!!0[]`).
            if let Some(formatted) = format_typespec_from_blob(assembly, &token) {
                return Some(formatted);
            }
            assembly.types().get(&token).map(|t| match t.flavor() {
                CilFlavor::GenericParameter { index, method } => {
                    if *method {
                        format!("!!{index}")
                    } else {
                        format!("!{index}")
                    }
                }
                _ => assembly_scoped_name(&t, assembly),
            })
        }
        0x2B => {
            // MethodSpec — resolve underlying method + generic type args
            format_methodspec(assembly, &token)
        }
        0x11 => {
            // StandAloneSig
            Some(format!("(0x{:08X})", token.value()))
        }
        0x70 => {
            // UserString — emit full string with ILAsm escaping
            assembly
                .userstrings()
                .and_then(|us| us.get(token.row() as usize).ok())
                .map(|s| user_string_literal(s.as_slice()))
        }
        _ => None,
    }
}

/// Format a MethodDef token as a full ILAsm method reference.
///
/// Produces: `instance void [asm]Namespace.Type::MethodName(param1, param2)`
fn format_methoddef_ref(method: &Method, asm: &CilObject) -> String {
    let declaring_type = method
        .declaring_type_rc()
        .map(|t| assembly_scoped_name(&t, asm));
    format_method_call_sig(
        method.signature.has_this && !method.is_static(),
        &method.signature.return_type,
        declaring_type.as_deref(),
        &method.name,
        &method.signature.params,
        asm,
    )
}

/// Format a MemberRef token as a full ILAsm method or field reference.
///
/// For methods: `instance void [asm]Type::Name(params)`
/// For fields: `type [asm]Type::Name`
fn format_memberref(mref: &MemberRef, asm: &CilObject) -> String {
    match &mref.signature {
        MemberRefSignature::Method(sig) => {
            let declaring = resolve_declaring_type(&mref.declaredby, asm);
            format_method_call_sig(
                sig.has_this,
                &sig.return_type,
                Some(&declaring),
                &mref.name,
                &sig.params,
                asm,
            )
        }
        MemberRefSignature::Field(sig) => {
            let field_type = format_type_sig(&sig.base, asm);
            let declaring = resolve_declaring_type(&mref.declaredby, asm);
            format!("{field_type} {declaring}::{}", quote_identifier(&mref.name))
        }
    }
}

/// Format a MethodSpec token as a full ILAsm method reference with generic args.
///
/// Resolves the underlying method (MethodDef or MemberRef) and appends
/// the generic type arguments: `instance void Type::Method<int32, string>(params)`
fn format_methodspec(assembly: &CilObject, token: &Token) -> Option<String> {
    let spec = assembly.method_spec(token).ok()?;

    // Format the underlying method reference
    let base_ref = match &spec.method {
        CilTypeReference::MethodDef(method_ref) => {
            let method = method_ref.upgrade()?;
            Some(format_methoddef_ref(&method, assembly))
        }
        CilTypeReference::MemberRef(mref) => Some(format_memberref(mref, assembly)),
        _ => None,
    }?;

    // Append generic type arguments if present
    if spec.instantiation.generic_args.is_empty() {
        return Some(base_ref);
    }

    let mut result = base_ref;
    // Insert generic args before the parameter list '('
    if let Some(paren_pos) = result.rfind('(') {
        let generic_args: Vec<String> = spec
            .instantiation
            .generic_args
            .iter()
            .map(|arg| format_type_sig(arg, assembly))
            .collect();
        let generic_str = format!("<{}>", generic_args.join(", "));
        result.insert_str(paren_pos, &generic_str);
    }

    Some(result)
}

/// Resolve a declaring type reference to an assembly-scoped name.
///
/// For TypeSpec references, prefers the raw signature blob which preserves generic
/// instantiation details and nested type paths (e.g. `` List`1/Enumerator<T> ``).
pub fn resolve_declaring_type(declaredby: &CilTypeReference, asm: &CilObject) -> String {
    match declaredby {
        CilTypeReference::TypeSpec(r) => {
            // Try blob-based formatting first — it preserves generic args and nested paths
            if let Some(token) = r.upgrade().map(|t| t.token) {
                if let Some(formatted) = format_typespec_from_blob(asm, &token) {
                    return formatted;
                }
            }
            r.upgrade()
                .map(|t| assembly_scoped_name(&t, asm))
                .unwrap_or_else(|| "[?]".to_string())
        }
        CilTypeReference::TypeRef(r) | CilTypeReference::TypeDef(r) => r
            .upgrade()
            .map(|t| assembly_scoped_name(&t, asm))
            .unwrap_or_else(|| "[?]".to_string()),
        _ => {
            if let Some(token) = declaredby.token() {
                asm.types()
                    .get(&token)
                    .map(|t| assembly_scoped_name(&t, asm))
                    .unwrap_or_else(|| {
                        declaredby
                            .fullname()
                            .map_or_else(|| "[?]".to_string(), |name| name.to_string())
                    })
            } else {
                declaredby
                    .fullname()
                    .map_or_else(|| "[?]".to_string(), |name| name.to_string())
            }
        }
    }
}

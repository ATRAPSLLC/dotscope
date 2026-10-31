//! Indentation, name formatting, and hex utility helpers for ILDasm output.
//!
//! Provides reusable formatting primitives shared across the formatting submodules:
//! indentation, IL offset labels, hex byte rendering, method reference signatures,
//! assembly-scoped type names, and context-aware type signature formatting.

use std::{
    collections::HashSet,
    io::{self, Write},
    sync::LazyLock,
};

use crate::{
    assembly::{INSTRUCTIONS, INSTRUCTIONS_FE, INSTRUCTIONS_FE_MAX, INSTRUCTIONS_MAX},
    file::pe::SectionTable,
    metadata::{
        method::Method,
        signatures::{parse_type_spec_signature, SignatureParameter, TypeSignature},
        tables::{TableId, TypeSpecRaw},
        token::Token,
        typesystem::{CilPrimitive, CilPrimitiveData, CilType, CilTypeReference},
    },
    CilObject,
};

/// Set of all ILAsm reserved words that must be single-quoted when used as identifiers.
///
/// Includes all CIL instruction mnemonics (from the opcode tables) and ILAsm grammar
/// keywords. Identifiers matching these words would be misinterpreted by the ILAsm
/// assembler without quoting.
static ILASM_RESERVED: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::with_capacity(512);

    // All CIL instruction mnemonics from the opcode tables
    if let Some(slice) = INSTRUCTIONS.get(..INSTRUCTIONS_MAX as usize) {
        for instr in slice {
            if !instr.instr.is_empty() {
                set.insert(instr.instr);
            }
        }
    }
    if let Some(slice) = INSTRUCTIONS_FE.get(..INSTRUCTIONS_FE_MAX as usize) {
        for instr in slice {
            if !instr.instr.is_empty() {
                set.insert(instr.instr);
            }
        }
    }

    // ILAsm grammar keywords (non-directive, non-dotted keywords that could
    // conflict with identifiers in operand/signature positions)
    for &kw in ILASM_KEYWORDS {
        set.insert(kw);
    }

    set
});

/// ILAsm keywords beyond instruction mnemonics that need quoting as identifiers.
///
/// Sourced from the .NET runtime's `il_kywd.h` master keyword definition file.
const ILASM_KEYWORDS: &[&str] = &[
    // Type keywords
    "void",
    "bool",
    "char",
    "wchar",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "float",
    "float32",
    "float64",
    "refany",
    "typedref",
    "object",
    "string",
    "native",
    "unsigned",
    "value",
    "valuetype",
    "class",
    "byreflike",
    // Calling conventions
    "vararg",
    "default",
    "stdcall",
    "thiscall",
    "fastcall",
    "unmanaged",
    "cdecl",
    // Class/method/field modifiers
    "static",
    "public",
    "private",
    "family",
    "final",
    "sealed",
    "abstract",
    "auto",
    "sequential",
    "explicit",
    "extended",
    "ansi",
    "unicode",
    "autochar",
    "import",
    "enum",
    "virtual",
    "strict",
    "forwarder",
    "synchronized",
    "interface",
    "instance",
    "specialname",
    "rtspecialname",
    "hidebysig",
    "newslot",
    "aggressiveinlining",
    "pinvokeimpl",
    "unmanagedexp",
    "reqsecobj",
    "noinlining",
    "nooptimization",
    "aggressiveoptimization",
    "async",
    "nested",
    "assembly",
    "famandassem",
    "famorassem",
    "privatescope",
    // Implementation attributes
    "cil",
    "il",
    "optil",
    "managed",
    "preservesig",
    "runtime",
    "internalcall",
    "beforefieldinit",
    "forwardref",
    // Inheritance/exception
    "extends",
    "implements",
    "handler",
    "finally",
    "fault",
    "catch",
    "filter",
    // Security action keywords
    "request",
    "demand",
    "assert",
    "deny",
    "permitonly",
    "linkcheck",
    "inheritcheck",
    "reqmin",
    "reqopt",
    "reqrefuse",
    "prejitgrant",
    "prejitdeny",
    "noncasdemand",
    "noncaslinkdemand",
    "noncasinheritance",
    // PInvoke keywords
    "nomangle",
    "lasterr",
    "winapi",
    "as",
    "bestfit",
    "charmaperror",
    "on",
    "off",
    // Field marshaling keywords
    "marshal",
    "custom",
    "sysstring",
    "fixed",
    "variant",
    "currency",
    "syschar",
    "decimal",
    "date",
    "bstr",
    "tbstr",
    "lpstr",
    "lpwstr",
    "lptstr",
    "objectref",
    "iunknown",
    "idispatch",
    "iidparam",
    "struct",
    "safearray",
    "byvalstr",
    "lpvoid",
    "any",
    "array",
    "lpstruct",
    // VTable keywords
    "fromunmanaged",
    "retainappdomain",
    "callmostderived",
    // Parameter keywords
    "in",
    "out",
    "opt",
    // Variant type keywords
    "null",
    "error",
    "hresult",
    "carray",
    "userdefined",
    "record",
    "filetime",
    "blob",
    "stream",
    "storage",
    "streamed_object",
    "stored_object",
    "blob_object",
    "cf",
    "clsid",
    "vector",
    // Manifest/assembly keywords
    "nometadata",
    "retargetable",
    "windowsruntime",
    "noplatform",
    "legacy",
    "library",
    "x86",
    "amd64",
    "arm",
    "arm64",
    "extern",
    "algorithm",
    "tls",
    // Boolean/special values
    "true",
    "false",
    "nullref",
    // Type/signature keywords
    "method",
    "field",
    "property",
    "bytearray",
    "to",
    "at",
    "pinned",
    "modreq",
    "modopt",
    "serializable",
    "type",
    "initonly",
    "literal",
    "notserialized",
    "flags",
    "callconv",
    "mdtoken",
    // Other
    "constraint",
    "with",
    "wrapper",
    "init",
    "alignment",
];

/// Write `depth` levels of indentation (2 spaces per level).
pub(super) fn write_indent(w: &mut dyn Write, depth: usize) -> io::Result<()> {
    for _ in 0..depth {
        write!(w, "  ")?;
    }
    Ok(())
}

/// Quote an identifier for ILAsm if it contains special characters.
///
/// ILAsm identifiers that contain characters outside the normal `[A-Za-z0-9_$@?.]`
/// set (such as `<`, `>`, `-`, `=`) must be wrapped in single quotes.
/// Returns the identifier unchanged if no quoting is needed.
pub(super) fn quote_identifier(name: &str) -> String {
    // For nested type paths (contains '/'), quote each component individually
    // so the '/' separator stays outside quotes: 'Outer'/'Inner'
    if name.contains('/') {
        return name
            .split('/')
            .map(quote_single)
            .collect::<Vec<_>>()
            .join("/");
    }
    quote_single(name)
}

/// Quote a single identifier component if it contains ILAsm special characters
/// or matches a reserved word (instruction mnemonic or grammar keyword).
fn quote_single(name: &str) -> String {
    let needs_quoting = name.contains('<')
        || name.contains('>')
        || name.contains('-')
        || name.contains('=')
        || name.contains('`')
        || name.starts_with(|c: char| c.is_ascii_digit())
        || ILASM_RESERVED.contains(name);
    if needs_quoting {
        format!("'{name}'")
    } else {
        name.to_string()
    }
}

/// Format a byte slice as a hex string: `XX XX XX`.
pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format a full ILAsm method reference signature with resolved type names.
///
/// Produces a string like `instance string MyClass::get_Name()` suitable for
/// use in `.get`, `.set`, `.addon`, `.removeon`, and `.fire` property/event
/// accessor directives. Includes the `instance` prefix when the method has
/// a `this` parameter, the return type, declaring type, method name, and
/// the full parameter type list from the method signature.
pub(super) fn format_method_ref(method: &Method, asm: &CilObject) -> String {
    let declaring_type = method
        .declaring_type_fullname()
        .map(|n| quote_identifier(&n));
    format_method_call_sig(
        method.signature.has_this && !method.is_static(),
        &method.signature.return_type,
        declaring_type.as_deref(),
        &method.name,
        &method.signature.params,
        asm,
    )
}

/// Build an assembly-scoped name for a type, as an ILAsm `typeSpec` names it.
///
/// For types defined in an external assembly, returns a name like
/// `[mscorlib]System.Object` with the assembly reference prefix.
/// For types defined in the current assembly, returns just the fullname.
/// For nested external types, traverses the resolution scope chain to find
/// the assembly reference (nested TypeRefs have their parent TypeRef as
/// resolution scope, not the assembly ref directly).
///
/// A TypeSpec entry is written from its signature, which states what the type is: a generic
/// instance as `class Name<args>`, an array or pointer by its element type.
pub(super) fn assembly_scoped_name(cil_type: &CilType, asm: &CilObject) -> String {
    if cil_type.token.is_table(TableId::TypeSpec) {
        if let Some(formatted) = format_typespec_from_blob(asm, &cil_type.token) {
            return formatted;
        }
    }
    format_assembly_scoped(cil_type)
}

/// Format an assembly-scoped name without TypeSpec resolution (internal helper).
fn format_assembly_scoped(cil_type: &CilType) -> String {
    let fullname = quote_identifier(&cil_type.fullname());

    if let Some(asm_name) = find_assembly_ref(cil_type) {
        return format!("[{asm_name}]{fullname}");
    }

    fullname
}

/// Walk the external reference and enclosing type chains to find the assembly ref name.
fn find_assembly_ref(cil_type: &CilType) -> Option<String> {
    // Check direct external reference (resolution scope)
    match cil_type.external() {
        Some(CilTypeReference::AssemblyRef(aref)) => return Some(aref.name.clone()),
        // For nested TypeRefs, the resolution scope points to the parent TypeRef.
        // Walk up that chain to find the assembly ref.
        Some(CilTypeReference::TypeRef(parent_ref) | CilTypeReference::TypeDef(parent_ref)) => {
            if let Some(parent) = parent_ref.upgrade() {
                if let Some(name) = find_assembly_ref(&parent) {
                    return Some(name);
                }
            }
        }
        _ => {}
    }

    // Also check via enclosing type chain (for TypeDefs with NestedClass relationships)
    if let Some(enclosing) = cil_type.enclosing_type() {
        if let Some(name) = find_assembly_ref(&enclosing) {
            return Some(name);
        }
    }

    None
}

/// Format a type signature with resolved type names from the assembly context.
///
/// Unlike `TypeSignature::Display` which outputs raw token values like `class[02000001]`,
/// this function resolves `Class(token)` and `ValueType(token)` to assembly-scoped names
/// like `class [mscorlib]System.Object`. Recursively resolves composite types (arrays,
/// pointers, generics, modifiers).
pub(super) fn format_type_sig(sig: &TypeSignature, asm: &CilObject) -> String {
    match sig {
        TypeSignature::Class(token) => {
            let name = asm
                .types()
                .get(token)
                .map(|t| assembly_scoped_name(&t, asm))
                .unwrap_or_else(|| format!("[{:08X}]", token.value()));
            format!("class {name}")
        }
        TypeSignature::ValueType(token) => {
            let name = asm
                .types()
                .get(token)
                .map(|t| assembly_scoped_name(&t, asm))
                .unwrap_or_else(|| format!("[{:08X}]", token.value()));
            format!("valuetype {name}")
        }
        TypeSignature::SzArray(inner) => {
            format!("{}[]", format_type_sig(&inner.base, asm))
        }
        TypeSignature::Array(arr) => {
            format!("{}[{}]", format_type_sig(&arr.base, asm), arr.rank)
        }
        TypeSignature::Ptr(ptr) => {
            format!("{}*", format_type_sig(&ptr.base, asm))
        }
        TypeSignature::ByRef(inner) => {
            format!("{}&", format_type_sig(inner, asm))
        }
        TypeSignature::GenericInst(base, args) => {
            let mut result = format_type_sig(base, asm);
            result.push('<');
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    result.push_str(", ");
                }
                result.push_str(&format_type_sig(arg, asm));
            }
            result.push('>');
            result
        }
        TypeSignature::Pinned(inner) => {
            format!("pinned {}", format_type_sig(inner, asm))
        }
        TypeSignature::ModifiedRequired(modifiers) => {
            let mut parts = Vec::new();
            for m in modifiers {
                let mod_name = asm
                    .types()
                    .get(&m.modifier_type)
                    .map(|t| assembly_scoped_name(&t, asm))
                    .unwrap_or_else(|| format!("{:08X}", m.modifier_type.value()));
                parts.push(format!("modreq({mod_name})"));
            }
            parts.join(" ")
        }
        TypeSignature::ModifiedOptional(modifiers) => {
            let mut parts = Vec::new();
            for m in modifiers {
                let mod_name = asm
                    .types()
                    .get(&m.modifier_type)
                    .map(|t| assembly_scoped_name(&t, asm))
                    .unwrap_or_else(|| format!("{:08X}", m.modifier_type.value()));
                parts.push(format!("modopt({mod_name})"));
            }
            parts.join(" ")
        }
        // ILAsm primitive type names (differ from C#-style Display output)
        TypeSignature::Void => "void".to_string(),
        TypeSignature::Boolean => "bool".to_string(),
        TypeSignature::Char => "char".to_string(),
        TypeSignature::I1 => "int8".to_string(),
        TypeSignature::U1 => "uint8".to_string(),
        TypeSignature::I2 => "int16".to_string(),
        TypeSignature::U2 => "uint16".to_string(),
        TypeSignature::I4 => "int32".to_string(),
        TypeSignature::U4 => "uint32".to_string(),
        TypeSignature::I8 => "int64".to_string(),
        TypeSignature::U8 => "uint64".to_string(),
        TypeSignature::R4 => "float32".to_string(),
        TypeSignature::R8 => "float64".to_string(),
        TypeSignature::I => "native int".to_string(),
        TypeSignature::U => "native uint".to_string(),
        TypeSignature::String => "string".to_string(),
        TypeSignature::Object => "object".to_string(),
        TypeSignature::TypedByRef => "typedref".to_string(),
        // Remaining variants delegate to Display
        _ => sig.to_string(),
    }
}

/// Format a signature parameter with resolved type names.
///
/// Handles `by_ref` prefix and delegates to [`format_type_sig`] for the base type.
pub(super) fn format_sig_param(param: &SignatureParameter, asm: &CilObject) -> String {
    let base = format_type_sig(&param.base, asm);
    if param.by_ref {
        format!("{base}&")
    } else {
        base
    }
}

/// Core method signature formatter: `instance ReturnType DeclType::Name(params)`.
///
/// All method-reference-building functions delegate here with their specific
/// `declaring_type` string (assembly-scoped, quoted, etc.).
pub(super) fn format_method_call_sig(
    has_this: bool,
    return_type: &SignatureParameter,
    declaring_type: Option<&str>,
    method_name: &str,
    params: &[SignatureParameter],
    asm: &CilObject,
) -> String {
    let mut result = String::new();

    // instance prefix
    if has_this {
        result.push_str("instance ");
    }

    // Return type
    result.push_str(&format_sig_param(return_type, asm));
    result.push(' ');

    // Declaring type
    if let Some(decl) = declaring_type {
        result.push_str(decl);
        result.push_str("::");
    }

    // Method name
    result.push_str(&quote_identifier(method_name));

    // Parameters
    result.push('(');
    for (i, param) in params.iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }
        result.push_str(&format_sig_param(param, asm));
    }
    result.push(')');

    result
}

/// Format a TypeSpec token by reading and parsing its raw signature blob.
///
/// Returns `None` if the TypeSpec blob cannot be accessed or parsed.
/// When successful, uses `format_type_sig` which correctly handles generic
/// parameter positional notation (`!0`, `!!0`) in composite types.
pub(super) fn format_typespec_from_blob(asm: &CilObject, token: &Token) -> Option<String> {
    let tables = asm.tables()?;
    let table = tables.table::<TypeSpecRaw>()?;
    let row = table.get(token.row()).ok().flatten()?;
    let blob = asm.blob()?;
    let sig_data = blob.get(row.signature as usize).ok()?;
    let parsed = parse_type_spec_signature(sig_data).ok()?;
    Some(format_type_sig(&parsed.base, asm))
}

/// Format a constant value with ILAsm type wrapper.
///
/// Produces strings like `int32(0x00000064)`, `bool(true)`, `"hello"`.
/// ILDasm uses hex format for all integer constants. ILAsm requires the type
/// prefix for all constant values except strings and nullref.
pub(super) fn format_constant(value: &CilPrimitive) -> String {
    match &value.data {
        CilPrimitiveData::None => "nullref".to_string(),
        CilPrimitiveData::Boolean(v) => format!("bool({v})"),
        CilPrimitiveData::Char(v) => format!("char(0x{v:04X})"),
        CilPrimitiveData::I1(v) => format!("int8(0x{:02X})", *v as u8),
        CilPrimitiveData::U1(v) => format!("uint8(0x{v:02X})"),
        CilPrimitiveData::I2(v) => format!("int16(0x{:04X})", *v as u16),
        CilPrimitiveData::U2(v) => format!("uint16(0x{v:04X})"),
        CilPrimitiveData::I4(v) => format!("int32(0x{:08X})", *v as u32),
        CilPrimitiveData::U4(v) => format!("uint32(0x{v:08X})"),
        CilPrimitiveData::I8(v) => format!("int64(0x{:X})", *v as u64),
        CilPrimitiveData::U8(v) => format!("uint64(0x{v:X})"),
        CilPrimitiveData::R4(v) => {
            // ILDasm uses the decimal representation if it round-trips exactly,
            // otherwise falls back to hex representation of the raw bits.
            let formatted = format!("{v:.8}");
            let round_tripped: f32 = formatted.parse().unwrap_or(f32::NAN);
            if round_tripped.to_bits() == v.to_bits() {
                format!("float32({formatted})")
            } else {
                format!("float32(0x{:08X})", v.to_bits())
            }
        }
        CilPrimitiveData::R8(v) => {
            let formatted = format!("{v:.17}");
            let round_tripped: f64 = formatted.parse().unwrap_or(f64::NAN);
            if round_tripped.to_bits() == v.to_bits() {
                format!("float64({formatted})")
            } else {
                format!("float64(0x{:016X})", v.to_bits())
            }
        }
        CilPrimitiveData::I(v) => format!("int32(0x{:08X})", *v as u32),
        CilPrimitiveData::U(v) => format!("uint32(0x{:08X})", *v as u32),
        CilPrimitiveData::String(v) => format!("\"{v}\""),
        CilPrimitiveData::Bytes(v) => {
            let mut result = String::from("bytearray (");
            for (i, byte) in v.iter().enumerate() {
                if i > 0 {
                    result.push(' ');
                }
                result.push_str(&format!("{byte:02X}"));
            }
            result.push(')');
            result
        }
    }
}

/// Find which PE section contains a given RVA.
pub(super) fn find_section_for_rva(sections: &[SectionTable], rva: u32) -> Option<&SectionTable> {
    sections.iter().find(|s| {
        let end = s.virtual_address.saturating_add(s.virtual_size);
        rva >= s.virtual_address && rva < end
    })
}

/// Write raw bytes as hex in rows of 16, indented.
///
/// Produces output like:
/// ```text
///     01 00 0B 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00
///     01 02 03 )
/// ```
pub(super) fn write_blob_hex(w: &mut dyn Write, indent: &str, data: &[u8]) -> io::Result<()> {
    write!(w, "{indent}    ")?;
    for (i, byte) in data.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            writeln!(w)?;
            write!(w, "{indent}    ")?;
        }
        write!(w, "{byte:02X} ")?;
    }
    Ok(())
}

/// ILDasm-style data label prefix and `.data` qualifier for a field RVA.
///
/// Returns `(prefix, qualifier)`:
/// - `("D_", "")` for `.data` section (standard initialized data)
/// - `("T_", " tls")` for `.tls` section (thread-local storage)
/// - `("I_", " cil")` for `.text` section (CIL-embedded data)
pub(super) fn data_label_for_rva(
    sections: &[SectionTable],
    rva: u32,
) -> (&'static str, &'static str) {
    match find_section_for_rva(sections, rva) {
        Some(s) if s.name.starts_with(".tls") => ("T_", " tls"),
        Some(s) if s.name.starts_with(".text") => ("I_", " cil"),
        _ => ("D_", ""),
    }
}

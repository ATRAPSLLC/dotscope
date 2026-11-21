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
        typesystem::{ArrayDimensions, CilPrimitive, CilPrimitiveData, CilType, CilTypeReference},
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
pub fn write_indent(w: &mut dyn Write, depth: usize) -> io::Result<()> {
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
pub fn quote_identifier(name: &str) -> String {
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
    if needs_quoting
        || name
            .chars()
            .any(|c| c == '\'' || c == '\\' || c.is_control())
    {
        quoted_name(name)
    } else {
        name.to_string()
    }
}

/// `name` as a single-quoted ILAsm name (`SQSTRING`), whatever it holds: an assembly, module,
/// file or resource name, or an identifier [`quote_identifier`] decides to quote.
///
/// The characters the quoting would end or misread are escaped (see [`push_escaped`]): a name
/// with a `'` in it was written as two names and the rest, and a `\` read as an escape.
pub fn quoted_name(name: &str) -> String {
    let mut quoted = String::with_capacity(name.len().saturating_add(2));
    quoted.push('\'');
    push_escaped(&mut quoted, name, '\'');
    quoted.push('\'');
    quoted
}

/// `text` as a double-quoted ILAsm string (`QSTRING`): a string constant, a P/Invoke module
/// or entry point name, a culture, or a user string that is valid UTF-16.
///
/// One escaper for every string the output quotes: they were written unescaped, so a `"`
/// ended the string early and a control character went out raw.
pub fn quoted_string(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len().saturating_add(2));
    quoted.push('"');
    push_escaped(&mut quoted, text, '"');
    quoted.push('"');
    quoted
}

/// Appends `text` to `out` escaped for an ILAsm string quoted by `quote`: the quote and `\`
/// by a backslash, the usual control characters by their C escapes, and any other control
/// character as a three-digit octal escape, the form ILAsm reads for any byte. Other
/// characters, ASCII or not, go out as they are.
fn push_escaped(out: &mut String, text: &str, quote: char) {
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_control() => {
                out.push_str(&format!("\\{:03o}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
}

/// A user string as `ldstr` takes it: a quoted string ([`quoted_string`]) when its UTF-16
/// code units are valid UTF-16, and otherwise `bytearray (...)` of the code units little
/// endian, the form ILAsm reads for any string. A string with a lone surrogate (which
/// obfuscators produce) was decoded lossily, and the output assembled to another string.
pub fn user_string_literal(units: &[u16]) -> String {
    match String::from_utf16(units) {
        Ok(text) => quoted_string(&text),
        Err(_) => {
            let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            format!("bytearray ({})", hex_bytes(&bytes))
        }
    }
}

/// The decimal ILAsm literal of a float Rust's `Debug` wrote (the shortest decimal that reads
/// back as the same value), with a decimal point: ILAsm reads a number without one, `1e300`
/// or `5`, as an integer.
fn with_decimal_point(mut decimal: String) -> String {
    if !decimal.contains('.') {
        match decimal.find('e') {
            Some(exponent) => decimal.insert_str(exponent, ".0"),
            None => decimal.push_str(".0"),
        }
    }
    decimal
}

/// `value` as an ILAsm decimal literal, or `None` when it has none: an infinity, a NaN or
/// negative zero, which ILAsm writes as their bits. A decimal is the shortest that reads back
/// as the same value, so a value no fixed precision reaches still round-trips.
fn decimal_f32(value: f32) -> Option<String> {
    (value.is_finite() && !(value == 0.0 && value.is_sign_negative()))
        .then(|| with_decimal_point(format!("{value:?}")))
}

/// [`decimal_f32`] for a `float64`.
fn decimal_f64(value: f64) -> Option<String> {
    (value.is_finite() && !(value == 0.0 && value.is_sign_negative()))
        .then(|| with_decimal_point(format!("{value:?}")))
}

/// The operand of `ldc.r4`: a decimal literal, or `float32(0x...)`, the value's bits, for an
/// infinity, a NaN or negative zero. `inf`, `NaN` and `-0` are no ILAsm, and a large value
/// written out in full has hundreds of digits.
pub fn ldc_r4_operand(value: f32) -> String {
    decimal_f32(value).unwrap_or_else(|| format!("float32(0x{:08X})", value.to_bits()))
}

/// The operand of `ldc.r8`, as [`ldc_r4_operand`] writes `ldc.r4`'s.
pub fn ldc_r8_operand(value: f64) -> String {
    decimal_f64(value).unwrap_or_else(|| format!("float64(0x{:016X})", value.to_bits()))
}

/// Format a byte slice as a hex string: `XX XX XX`.
pub fn hex_bytes(bytes: &[u8]) -> String {
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
pub fn format_method_ref(method: &Method, asm: &CilObject) -> String {
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
pub fn assembly_scoped_name(cil_type: &CilType, asm: &CilObject) -> String {
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
        Some(CilTypeReference::AssemblyRef(aref)) => return Some(aref.name.to_string()),
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
pub fn format_type_sig(sig: &TypeSignature, asm: &CilObject) -> String {
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
            format!(
                "{}[{}]",
                format_type_sig(&arr.base, asm),
                array_bounds(arr.rank, &arr.dimensions)
            )
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
        // ILAsm writes a modifier after the type it modifies: `int32 modreq(IsVolatile)`
        TypeSignature::ModifiedRequired(modifiers, base)
        | TypeSignature::ModifiedOptional(modifiers, base) => {
            let kind = if matches!(sig, TypeSignature::ModifiedRequired(..)) {
                "modreq"
            } else {
                "modopt"
            };
            let mut result = format_type_sig(base, asm);
            for m in modifiers {
                let mod_name = asm
                    .types()
                    .get(&m.modifier_type)
                    .map(|t| assembly_scoped_name(&t, asm))
                    .unwrap_or_else(|| format!("{:08X}", m.modifier_type.value()));
                result.push_str(&format!(" {kind}({mod_name})"));
            }
            result
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

/// The bounds of a general array (`ELEMENT_TYPE_ARRAY`) as ILAsm writes them between its
/// brackets, one per dimension: `lo...hi` for a lower bound and a size, `lo...` for a lower
/// bound alone, the size alone, or nothing; a rank-one array with no bounds is `...`, since `[]`
/// is the single-dimensional array. It rendered as `[rank]`, which ILAsm reads as a
/// single-dimensional array of that size, its bounds lost.
fn array_bounds(rank: u32, dimensions: &[ArrayDimensions]) -> String {
    let bounds: Vec<String> = (0..rank as usize)
        .map(|dimension| match dimensions.get(dimension) {
            None
            | Some(ArrayDimensions {
                size: None,
                lower_bound: None,
            }) => String::new(),
            Some(ArrayDimensions {
                size: Some(size),
                lower_bound: None,
            }) => size.to_string(),
            Some(ArrayDimensions {
                size: None,
                lower_bound: Some(lower),
            }) => format!("{lower}..."),
            Some(ArrayDimensions {
                size: Some(size),
                lower_bound: Some(lower),
            }) => {
                // An i32 bound and a u32 size cannot overflow an i64
                let upper = i64::from(*lower)
                    .saturating_add(i64::from(*size))
                    .saturating_sub(1);
                format!("{lower}...{upper}")
            }
        })
        .collect();
    if rank == 1 && bounds.first().is_some_and(String::is_empty) {
        "...".to_string()
    } else {
        bounds.join(",")
    }
}

/// Format a signature parameter with resolved type names.
///
/// Handles `by_ref` prefix and delegates to [`format_type_sig`] for the base type.
pub fn format_sig_param(param: &SignatureParameter, asm: &CilObject) -> String {
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
pub fn format_method_call_sig(
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
pub fn format_typespec_from_blob(asm: &CilObject, token: &Token) -> Option<String> {
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
pub fn format_constant(value: &CilPrimitive) -> String {
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
        // The shortest decimal that reads back as the value, or its bits for an infinity, a
        // NaN and negative zero, which have no ILAsm decimal
        CilPrimitiveData::R4(v) => match decimal_f32(*v) {
            Some(decimal) => format!("float32({decimal})"),
            None => format!("float32(0x{:08X})", v.to_bits()),
        },
        CilPrimitiveData::R8(v) => match decimal_f64(*v) {
            Some(decimal) => format!("float64({decimal})"),
            None => format!("float64(0x{:016X})", v.to_bits()),
        },
        CilPrimitiveData::I(v) => format!("int32(0x{:08X})", *v as u32),
        CilPrimitiveData::U(v) => format!("uint32(0x{:08X})", *v as u32),
        CilPrimitiveData::String(v) => quoted_string(v),
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
pub fn find_section_for_rva(sections: &[SectionTable], rva: u32) -> Option<&SectionTable> {
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
pub fn write_blob_hex(w: &mut dyn Write, indent: &str, data: &[u8]) -> io::Result<()> {
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
pub fn data_label_for_rva(sections: &[SectionTable], rva: u32) -> (&'static str, &'static str) {
    match find_section_for_rva(sections, rva) {
        Some(s) if s.name.starts_with(".tls") => ("T_", " tls"),
        Some(s) if s.name.starts_with(".text") => ("I_", " cil"),
        _ => ("D_", ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One escaper for every quoted string: the quote and `\` are escaped, control characters
    /// by their C escapes or in octal, and other text, ASCII or not, goes out as it is.
    #[test]
    fn a_quoted_string_escapes_what_ends_or_breaks_it() {
        assert_eq!(quoted_string(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quoted_string(r"C:\dir"), r#""C:\\dir""#);
        assert_eq!(quoted_string("a\nb\tc"), r#""a\nb\tc""#);
        assert_eq!(quoted_string("\u{1}x\u{7f}"), r#""\001x\177""#);
        assert_eq!(quoted_string("é"), "\"é\"");
        assert_eq!(quoted_name("O'Brien"), r"'O\'Brien'");
    }

    /// An identifier holding a quote or backslash is quoted with them escaped: it was written
    /// as is, the quote ending the name.
    #[test]
    fn an_identifier_with_a_quote_is_quoted_and_escaped() {
        assert_eq!(quote_identifier("plain"), "plain");
        assert_eq!(quote_identifier("it's"), r"'it\'s'");
        assert_eq!(quote_identifier("<Module>"), "'<Module>'");
    }

    /// A user string with a lone surrogate, which no UTF-8 text holds, goes out as its code
    /// units: decoded lossily it assembled to another string.
    #[test]
    fn a_user_string_that_is_not_utf16_is_a_bytearray() {
        assert_eq!(user_string_literal(&[0x68, 0x69]), "\"hi\"");
        assert_eq!(
            user_string_literal(&[0x61, 0xD800]),
            "bytearray (61 00 00 D8)"
        );
    }

    /// A float's decimal is the shortest that reads back as the same value, always with a
    /// decimal point; an infinity, a NaN and negative zero are written as their bits.
    #[test]
    fn floats_are_written_as_ilasm_reads_them() {
        assert_eq!(ldc_r8_operand(1.5), "1.5");
        assert_eq!(ldc_r8_operand(5.0), "5.0");
        assert_eq!(ldc_r8_operand(1e300), "1.0e300");
        assert_eq!(ldc_r8_operand(f64::INFINITY), "float64(0x7FF0000000000000)");
        assert_eq!(ldc_r8_operand(-0.0), "float64(0x8000000000000000)");
        assert_eq!(ldc_r4_operand(f32::NEG_INFINITY), "float32(0xFF800000)");
        assert!(ldc_r4_operand(f32::NAN).starts_with("float32(0x"));

        for value in [
            0.1f64,
            1e-7,
            123_456_789.123,
            f64::MAX,
            f64::MIN_POSITIVE,
            5e-324,
        ] {
            let decimal = ldc_r8_operand(value);
            assert!(decimal.contains('.'), "{decimal}");
            assert_eq!(decimal.parse::<f64>().unwrap().to_bits(), value.to_bits());
        }
        for value in [0.1f32, 3.4e38, 1e-45] {
            let decimal = ldc_r4_operand(value);
            assert!(decimal.contains('.'), "{decimal}");
            assert_eq!(decimal.parse::<f32>().unwrap().to_bits(), value.to_bits());
        }
    }

    /// A float constant is `float32(...)`/`float64(...)` around the same literal; a string
    /// constant is quoted and escaped.
    #[test]
    fn constants_are_written_as_ilasm_reads_them() {
        assert_eq!(format_constant(&CilPrimitive::r8(2.5)), "float64(2.5)");
        assert_eq!(
            format_constant(&CilPrimitive::r4(f32::INFINITY)),
            "float32(0x7F800000)"
        );
        assert_eq!(format_constant(&CilPrimitive::string("a\"b")), r#""a\"b""#);
    }

    /// A general array is written with its bounds: `lo...hi` for a lower bound and a size,
    /// `lo...` for a lower bound alone, the size alone, nothing for neither, and `...` for an
    /// unbounded rank-one array (`[]` is the single-dimensional one). It was `[rank]`.
    #[test]
    fn a_general_array_is_written_with_its_bounds() {
        let dim = |size, lower_bound| ArrayDimensions { size, lower_bound };
        assert_eq!(array_bounds(2, &[]), ",");
        assert_eq!(
            array_bounds(2, &[dim(None, Some(0)), dim(None, Some(0))]),
            "0...,0..."
        );
        assert_eq!(array_bounds(1, &[dim(Some(5), Some(1))]), "1...5");
        assert_eq!(array_bounds(1, &[dim(Some(5), None)]), "5");
        assert_eq!(array_bounds(1, &[]), "...");
        assert_eq!(array_bounds(3, &[dim(Some(2), Some(-1))]), "-1...0,,");
    }
}

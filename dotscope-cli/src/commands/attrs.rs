use std::path::Path;

use anyhow::Context;
use dotscope::{
    metadata::{
        customattributes::{
            parse_custom_attribute_blob, CustomAttributeArgument, CustomAttributeNamedArgument,
            CustomAttributeValue,
        },
        streams::{Blob, Strings},
        tables::{
            CodedIndex, CustomAttributeRaw, EventRaw, FieldRaw, MemberRefRaw, ParamRaw,
            PropertyRaw, TableId, TypeRefRaw,
        },
        token::Token,
    },
    CilObject,
};
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::{
        common::{load_assembly, name_contains_ignore_case},
        resolution::parse_token_filter,
    },
    output::print_output,
};

#[derive(Debug, Serialize)]
struct AttrEntry {
    owner_kind: String,
    owner_name: String,
    owner_token: String,
    attr_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixed_args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    named_args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AttrsOutput {
    attrs: Vec<AttrEntry>,
}

pub fn run(path: &Path, owner_filter: Option<&str>, opts: &GlobalOptions) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let tables = assembly
        .tables()
        .with_context(|| "assembly has no tables stream")?;

    let ca_table = tables
        .table::<CustomAttributeRaw>()
        .with_context(|| "assembly has no CustomAttribute table")?;

    let blob = assembly.blob();
    let strings = assembly.strings();

    let mut entries: Vec<AttrEntry> = Vec::new();

    for row in ca_table {
        let Ok(row) = row else {
            continue;
        };
        let (owner_kind, owner_name) = resolve_owner(&assembly, &row.parent, strings);
        let attr_type = resolve_constructor_type(&assembly, &row.constructor, strings);

        // Apply owner filter
        if let Some(filter) = owner_filter {
            if let Some(token) = parse_token_filter(filter) {
                if row.parent.token != token {
                    continue;
                }
            } else {
                let haystack = format!("{owner_kind} {owner_name}");
                if !name_contains_ignore_case(&haystack, filter) {
                    continue;
                }
            }
        }

        // Try to decode the attribute value
        let (fixed_args, named_args) = decode_attr_value(&assembly, &row, blob);

        entries.push(AttrEntry {
            owner_kind,
            owner_name,
            owner_token: row.parent.token.to_string(),
            attr_type,
            fixed_args,
            named_args,
        });
    }

    let output = AttrsOutput { attrs: entries };

    print_output(&output, opts, |out| {
        if out.attrs.is_empty() {
            println!("No custom attributes found.");
            return;
        }

        // Group by owner
        let mut current_owner = String::new();
        for entry in &out.attrs {
            let owner_header = format!("[{}] {}", entry.owner_kind, entry.owner_name);
            if owner_header != current_owner {
                if !current_owner.is_empty() {
                    println!();
                }
                println!("{owner_header}");
                current_owner = owner_header;
            }

            let value_str =
                format_attr_display(&entry.attr_type, &entry.fixed_args, &entry.named_args);
            println!("  {value_str}");
        }
    })
}

/// Resolve the owner (parent) of a custom attribute to a human-readable description.
fn resolve_owner(
    assembly: &CilObject,
    parent: &CodedIndex,
    strings: Option<&Strings<'_>>,
) -> (String, String) {
    match parent.tag {
        TableId::TypeDef => {
            let name = resolve_type_name(assembly, parent.token);
            ("type".to_string(), name)
        }
        TableId::MethodDef => {
            let name = assembly.methods().get(&parent.token).map_or_else(
                || parent.token.to_string(),
                |entry| entry.value().fullname(),
            );
            ("method".to_string(), name)
        }
        TableId::Assembly => {
            let name = assembly
                .assembly()
                .map_or_else(|| parent.token.to_string(), |a| a.name.clone());
            ("assembly".to_string(), name)
        }
        TableId::Field => {
            let name = resolve_string_from_raw_table(assembly, parent, strings, "field");
            ("field".to_string(), name)
        }
        TableId::Param => {
            let name = resolve_string_from_raw_table(assembly, parent, strings, "param");
            ("param".to_string(), name)
        }
        TableId::Property => {
            let name = resolve_string_from_raw_table(assembly, parent, strings, "property");
            ("property".to_string(), name)
        }
        TableId::Event => {
            let name = resolve_string_from_raw_table(assembly, parent, strings, "event");
            ("event".to_string(), name)
        }
        TableId::InterfaceImpl => ("interfaceimpl".to_string(), parent.token.to_string()),
        TableId::MemberRef => ("memberref".to_string(), parent.token.to_string()),
        TableId::Module => ("module".to_string(), parent.token.to_string()),
        TableId::TypeSpec => ("typespec".to_string(), parent.token.to_string()),
        TableId::GenericParam => ("genericparam".to_string(), parent.token.to_string()),
        TableId::GenericParamConstraint => (
            "genericparamconstraint".to_string(),
            parent.token.to_string(),
        ),
        TableId::MethodSpec => ("methodspec".to_string(), parent.token.to_string()),
        _ => (parent.tag.to_string(), parent.token.to_string()),
    }
}

/// Resolve a TypeDef token to "Namespace.Name".
fn resolve_type_name(assembly: &CilObject, token: Token) -> String {
    let types = assembly.types();
    if let Some(t) = types.get(&token) {
        let ns = &t.namespace;
        let name = &t.name;
        if ns.is_empty() {
            name.clone()
        } else {
            format!("{ns}.{name}")
        }
    } else {
        token.to_string()
    }
}

/// Try to resolve field/param/property/event names via the raw tables + strings heap.
fn resolve_string_from_raw_table(
    assembly: &CilObject,
    ci: &CodedIndex,
    strings: Option<&Strings<'_>>,
    kind: &str,
) -> String {
    let Some(tables) = assembly.tables() else {
        return ci.token.to_string();
    };
    let Some(strings) = strings else {
        return ci.token.to_string();
    };

    match kind {
        "field" => {
            if let Some(table) = tables.table::<FieldRaw>() {
                for row in table {
                    let Ok(row) = row else {
                        continue;
                    };
                    if row.rid == ci.row {
                        if let Ok(s) = strings.get(row.name as usize) {
                            return s.to_string();
                        }
                    }
                }
            }
        }
        "param" => {
            if let Some(table) = tables.table::<ParamRaw>() {
                for row in table {
                    let Ok(row) = row else {
                        continue;
                    };
                    if row.rid == ci.row {
                        if let Ok(s) = strings.get(row.name as usize) {
                            return s.to_string();
                        }
                    }
                }
            }
        }
        "property" => {
            if let Some(table) = tables.table::<PropertyRaw>() {
                for row in table {
                    let Ok(row) = row else {
                        continue;
                    };
                    if row.rid == ci.row {
                        if let Ok(s) = strings.get(row.name as usize) {
                            return s.to_string();
                        }
                    }
                }
            }
        }
        "event" => {
            if let Some(table) = tables.table::<EventRaw>() {
                for row in table {
                    let Ok(row) = row else {
                        continue;
                    };
                    if row.rid == ci.row {
                        if let Ok(s) = strings.get(row.name as usize) {
                            return s.to_string();
                        }
                    }
                }
            }
        }
        _ => {}
    }
    ci.token.to_string()
}

/// Resolve the constructor CodedIndex to the attribute type name.
fn resolve_constructor_type(
    assembly: &CilObject,
    constructor: &CodedIndex,
    strings: Option<&Strings<'_>>,
) -> String {
    match constructor.tag {
        TableId::MemberRef => {
            // Look up in resolved member refs
            if let Some(mr) = assembly.member_ref(&constructor.token) {
                return mr
                    .declaredby
                    .fullname()
                    .or_else(|| mr.declaredby.token().map(|t| t.to_string()))
                    .unwrap_or_else(|| "?".to_string());
            }
            // Fallback: raw table lookup
            resolve_memberref_class_name(assembly, constructor, strings)
        }
        TableId::MethodDef => {
            // Look up the method and get its declaring type
            if let Ok(method) = assembly.method(&constructor.token) {
                if let Some(name) = method.declaring_type_fullname() {
                    return name;
                }
            }
            constructor.token.to_string()
        }
        _ => format!("{}[{}]", constructor.tag, constructor.row),
    }
}

/// Fallback: resolve MemberRef class name via raw table.
fn resolve_memberref_class_name(
    assembly: &CilObject,
    ci: &CodedIndex,
    strings: Option<&Strings<'_>>,
) -> String {
    let Some(tables) = assembly.tables() else {
        return ci.token.to_string();
    };
    let Some(strings) = strings else {
        return ci.token.to_string();
    };

    // Find the MemberRef row
    let Some(mr_table) = tables.table::<MemberRefRaw>() else {
        return ci.token.to_string();
    };

    for row in mr_table {
        let Ok(row) = row else {
            continue;
        };
        if row.rid == ci.row {
            // The class field is a MemberRefParent coded index
            if row.class.tag == TableId::TypeRef {
                // Resolve the TypeRef
                if let Some(tr_table) = tables.table::<TypeRefRaw>() {
                    for tr in tr_table {
                        let Ok(tr) = tr else {
                            continue;
                        };
                        if tr.rid == row.class.row {
                            let ns = strings.get(tr.type_namespace as usize).unwrap_or("?");
                            let name = strings.get(tr.type_name as usize).unwrap_or("?");
                            return if ns.is_empty() {
                                name.to_string()
                            } else {
                                format!("{ns}.{name}")
                            };
                        }
                    }
                }
            }
            break;
        }
    }
    ci.token.to_string()
}

/// Try to decode the custom attribute blob value.
fn decode_attr_value(
    assembly: &CilObject,
    row: &CustomAttributeRaw,
    blob: Option<&Blob<'_>>,
) -> (Vec<String>, Vec<String>) {
    if row.value == 0 {
        return (vec![], vec![]);
    }

    let Some(blob) = blob else {
        return (vec![], vec![]);
    };

    // Get constructor parameters for parsing and attempt to parse the blob
    let result = match row.constructor.tag {
        TableId::MemberRef => assembly
            .refs_members()
            .get(&row.constructor.token)
            .and_then(|entry| {
                parse_custom_attribute_blob(blob, row.value, &entry.value().params).ok()
            }),
        TableId::MethodDef => assembly
            .methods()
            .get(&row.constructor.token)
            .and_then(|entry| {
                parse_custom_attribute_blob(blob, row.value, &entry.value().params).ok()
            }),
        _ => None,
    };

    if let Some(val) = result {
        return format_parsed_value(&val);
    }

    // Fallback: show raw blob summary
    if let Ok(data) = blob.get(row.value as usize) {
        let preview_len = data.len().min(16);
        let hex: String = data[..preview_len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let suffix = if data.len() > 16 { "..." } else { "" };
        (vec![format!("<blob: {hex}{suffix}>")], vec![])
    } else {
        (vec![], vec![])
    }
}

/// Format a parsed CustomAttributeValue into string vectors for fixed and named args.
fn format_parsed_value(val: &CustomAttributeValue) -> (Vec<String>, Vec<String>) {
    let fixed: Vec<String> = val.fixed_args.iter().map(format_arg).collect();
    let named: Vec<String> = val.named_args.iter().map(format_named_arg).collect();
    (fixed, named)
}

/// Format a single CustomAttributeArgument for display.
fn format_arg(arg: &CustomAttributeArgument) -> String {
    match arg {
        CustomAttributeArgument::Bool(b) => b.to_string(),
        CustomAttributeArgument::Char(c) => match char::from_u32(u32::from(*c)) {
            Some(c) => format!("'{c}'"),
            None => format!("'\\u{c:04X}'"),
        },
        CustomAttributeArgument::I1(v) => v.to_string(),
        CustomAttributeArgument::U1(v) => v.to_string(),
        CustomAttributeArgument::I2(v) => v.to_string(),
        CustomAttributeArgument::U2(v) => v.to_string(),
        CustomAttributeArgument::I4(v) => v.to_string(),
        CustomAttributeArgument::U4(v) => v.to_string(),
        CustomAttributeArgument::I8(v) => v.to_string(),
        CustomAttributeArgument::U8(v) => v.to_string(),
        CustomAttributeArgument::R4(v) => v.to_string(),
        CustomAttributeArgument::R8(v) => v.to_string(),
        CustomAttributeArgument::String(Some(s)) => format!("\"{s}\""),
        CustomAttributeArgument::Type(Some(t)) => format!("typeof({t})"),
        CustomAttributeArgument::String(None)
        | CustomAttributeArgument::Type(None)
        | CustomAttributeArgument::Array(_, None) => "null".to_string(),
        CustomAttributeArgument::Array(_, Some(items)) => {
            let inner: Vec<String> = items.iter().map(format_arg).collect();
            format!("[{}]", inner.join(", "))
        }
        CustomAttributeArgument::Enum(type_name, value) => {
            // Show short type name
            let short = type_name.rsplit('.').next().unwrap_or(type_name);
            format!("{}({})", short, format_arg(value))
        }
        CustomAttributeArgument::Boxed(value) => format_arg(value),
    }
}

/// Format a named argument for display.
fn format_named_arg(arg: &CustomAttributeNamedArgument) -> String {
    format!("{} = {}", arg.name, format_arg(&arg.value))
}

/// Format a complete attribute for human-readable display.
fn format_attr_display(attr_type: &str, fixed: &[String], named: &[String]) -> String {
    // Strip "Attribute" suffix for readability
    let short_name = attr_type.rsplit('.').next().unwrap_or(attr_type);

    if fixed.is_empty() && named.is_empty() {
        return format!("{short_name}()");
    }

    let mut parts: Vec<String> = fixed.to_vec();
    parts.extend(named.iter().cloned());
    format!("{short_name}({})", parts.join(", "))
}

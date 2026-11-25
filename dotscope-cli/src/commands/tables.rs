use std::path::Path;

use anyhow::{bail, Context};
use dotscope::metadata::{
    streams::{Blob, Guid, Strings, TablesHeader},
    tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, ConstantRaw,
        CustomAttributeRaw, CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw,
        EncMapRaw, EventMapRaw, EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw,
        FieldMarshalRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw,
        GenericParamRaw, ImplMapRaw, ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw,
        LocalScopeRaw, LocalVariableRaw, ManifestResourceRaw, MemberRefRaw,
        MethodDebugInformationRaw, MethodDefRaw, MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw,
        MethodSpecRaw, ModuleRaw, ModuleRefRaw, NestedClassRaw, ParamPtrRaw, ParamRaw,
        PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw, StateMachineMethodRaw,
        TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
};
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct TableEntry {
    table: String,
    rows: u32,
}

#[derive(Debug, Serialize)]
struct TablesOutput {
    tables: Vec<TableEntry>,
}

#[derive(Debug, Serialize)]
struct TableDetailOutput {
    table: String,
    row_count: u32,
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

fn resolve_string(strings: Option<&Strings<'_>>, offset: u32) -> String {
    strings
        .and_then(|s| s.get(offset as usize).ok())
        .map_or_else(|| "?".to_string(), ToString::to_string)
}

fn format_coded_index(ci: &CodedIndex) -> String {
    format!("{}[{}]", ci.tag, ci.row)
}

fn format_blob_ref(blob: Option<&Blob<'_>>, offset: u32) -> String {
    if offset == 0 {
        return "blob[0]".to_string();
    }
    blob.and_then(|b| b.get(offset as usize).ok()).map_or_else(
        || format!("blob@{offset}"),
        |b| format!("blob[{} bytes]", b.len()),
    )
}

fn format_guid_ref(guids: Option<&Guid<'_>>, index: u32) -> String {
    if index == 0 {
        return "null".to_string();
    }
    guids
        .and_then(|g| g.get(index as usize).ok())
        .map_or_else(|| "?".to_string(), |guid| guid.to_string())
}

fn format_version(major: u32, minor: u32, build: u32, rev: u32) -> String {
    format!("{major}.{minor}.{build}.{rev}")
}

pub fn run(path: &Path, table_filter: Option<&str>, opts: &GlobalOptions) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let tables = assembly
        .tables()
        .with_context(|| "assembly has no tables stream")?;

    let summaries = tables.table_summary();

    if summaries.is_empty() {
        bail!("no metadata tables found in assembly");
    }

    if let Some(filter) = table_filter {
        let filter_lower = filter.to_lowercase();
        // Find the matching table
        let matching = summaries
            .iter()
            .find(|s| s.table_id.to_string().to_lowercase() == filter_lower);

        if matching.is_none() {
            bail!("no table matching '{filter}' found");
        }

        let strings = assembly.strings();
        let blob = assembly.blob();
        let guids = assembly.guids();

        let detail = format_table_detail(tables, &filter_lower, strings, blob, guids)?;

        print_output(&detail, opts, |d| {
            println!("{} table ({} rows):\n", d.table, d.row_count);
            let cols: Vec<(&str, Align)> = d
                .columns
                .iter()
                .map(|c| (c.as_str(), Align::Left))
                .collect();
            let mut tw = TabWriter::new(&cols);
            for row in &d.rows {
                tw.row(row.clone());
            }
            tw.print();
        })
    } else {
        let mut entries = Vec::new();
        for s in &summaries {
            entries.push(TableEntry {
                table: s.table_id.to_string(),
                rows: s.row_count,
            });
        }

        let output = TablesOutput { tables: entries };

        print_output(&output, opts, |out| {
            let mut tw = TabWriter::new(&[("Table", Align::Left), ("Rows", Align::Right)]);
            for entry in &out.tables {
                tw.row(vec![entry.table.clone(), entry.rows.to_string()]);
            }
            tw.print();
        })
    }
}

fn format_table_detail(
    tables: &TablesHeader<'_>,
    table_name: &str,
    strings: Option<&Strings<'_>>,
    blob: Option<&Blob<'_>>,
    guids: Option<&Guid<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    match table_name {
        "module" => format_module(tables, strings, guids),
        "typeref" => format_typeref(tables, strings),
        "typedef" => format_typedef(tables, strings),
        "fieldptr" => format_fieldptr(tables),
        "field" => format_field(tables, strings),
        "methodptr" => format_methodptr(tables),
        "methoddef" => format_methoddef(tables, strings),
        "paramptr" => format_paramptr(tables),
        "param" => format_param(tables, strings),
        "interfaceimpl" => format_interfaceimpl(tables),
        "memberref" => format_memberref(tables, strings),
        "constant" => format_constant(tables, blob),
        "customattribute" => format_customattribute(tables, blob),
        "fieldmarshal" => format_fieldmarshal(tables, blob),
        "declsecurity" => format_declsecurity(tables, blob),
        "classlayout" => format_classlayout(tables),
        "fieldlayout" => format_fieldlayout(tables),
        "standalonesig" => format_standalonesig(tables, blob),
        "eventmap" => format_eventmap(tables),
        "eventptr" => format_eventptr(tables),
        "event" => format_event(tables, strings),
        "propertymap" => format_propertymap(tables),
        "propertyptr" => format_propertyptr(tables),
        "property" => format_property(tables, strings),
        "methodsemantics" => format_methodsemantics(tables),
        "methodimpl" => format_methodimpl(tables),
        "moduleref" => format_moduleref(tables, strings),
        "typespec" => format_typespec(tables, blob),
        "implmap" => format_implmap(tables, strings),
        "fieldrva" => format_fieldrva(tables),
        "enclog" => format_enclog(tables),
        "encmap" => format_encmap(tables),
        "assembly" => format_assembly(tables, strings, blob),
        "assemblyprocessor" => format_assemblyprocessor(tables),
        "assemblyos" => format_assemblyos(tables),
        "assemblyref" => format_assemblyref(tables, strings, blob),
        "assemblyrefprocessor" => format_assemblyrefprocessor(tables),
        "assemblyrefos" => format_assemblyrefos(tables),
        "file" => format_file(tables, strings, blob),
        "exportedtype" => format_exportedtype(tables, strings),
        "manifestresource" => format_manifestresource(tables, strings),
        "nestedclass" => format_nestedclass(tables),
        "genericparam" => format_genericparam(tables, strings),
        "methodspec" => format_methodspec(tables, blob),
        "genericparamconstraint" => format_genericparamconstraint(tables),
        "document" => format_document(tables, blob),
        "methoddebuginformation" => format_methoddebuginformation(tables, blob),
        "localscope" => format_localscope(tables),
        "localvariable" => format_localvariable(tables, strings),
        "localconstant" => format_localconstant(tables, strings, blob),
        "importscope" => format_importscope(tables, blob),
        "statemachinemethod" => format_statemachinemethod(tables),
        "customdebuginformation" => format_customdebuginformation(tables, blob),
        other => bail!("unknown table: {other}"),
    }
}

// Macro to reduce boilerplate for simple table formatters
macro_rules! table_formatter {
    ($fn_name:ident, $raw_type:ty, $display_name:expr, $cols:expr, $row_fn:expr) => {
        fn $fn_name(tables: &TablesHeader<'_>) -> anyhow::Result<TableDetailOutput> {
            let table = tables
                .table::<$raw_type>()
                .with_context(|| format!("{} table not found", $display_name))?;
            let columns: Vec<String> = ["RID", "Token"]
                .iter()
                .chain($cols.iter())
                .map(ToString::to_string)
                .collect();
            let mut rows = Vec::new();
            for row in table {
                let Ok(row) = row else {
                    continue;
                };
                let mut vals = vec![row.rid.to_string(), row.token.to_string()];
                let extra: Vec<String> = ($row_fn)(&row);
                vals.extend(extra);
                rows.push(vals);
            }
            Ok(TableDetailOutput {
                table: $display_name.to_string(),
                row_count: table.row_count,
                columns,
                rows,
            })
        }
    };
}

// Macro variant that takes extra parameters (strings, blob, guids)
macro_rules! table_formatter_with {
    ($fn_name:ident, $raw_type:ty, $display_name:expr, $cols:expr, ($($param:ident: $ptype:ty),+), $row_fn:expr) => {
        fn $fn_name(tables: &TablesHeader<'_>, $($param: $ptype),+) -> anyhow::Result<TableDetailOutput> {
            let table = tables
                .table::<$raw_type>()
                .with_context(|| format!("{} table not found", $display_name))?;
            let columns: Vec<String> =
                ["RID", "Token"].iter().chain($cols.iter()).map(ToString::to_string).collect();
            let mut rows = Vec::new();
            for row in table {
                let Ok(row) = row else {
                    continue;
                };
                let mut vals = vec![row.rid.to_string(), row.token.to_string()];
                let extra: Vec<String> = ($row_fn)(&row, $($param),+);
                vals.extend(extra);
                rows.push(vals);
            }
            Ok(TableDetailOutput {
                table: $display_name.to_string(),
                row_count: table.row_count,
                columns,
                rows,
            })
        }
    };
}

// Core Type System (0x00-0x08)

fn format_module(
    tables: &TablesHeader<'_>,
    strings: Option<&Strings<'_>>,
    guids: Option<&Guid<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<ModuleRaw>()
        .with_context(|| "Module table not found")?;
    let columns = [
        "RID",
        "Token",
        "Generation",
        "Name",
        "Mvid",
        "EncId",
        "EncBaseId",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.generation.to_string(),
            resolve_string(strings, row.name),
            format_guid_ref(guids, row.mvid),
            format_guid_ref(guids, row.encid),
            format_guid_ref(guids, row.encbaseid),
        ]);
    }
    Ok(TableDetailOutput {
        table: "Module".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

table_formatter_with!(format_typeref, TypeRefRaw, "TypeRef",
    &["ResolutionScope", "Name", "Namespace"],
    (strings: Option<&Strings<'_>>),
    |row: &TypeRefRaw, strings: Option<&Strings<'_>>| vec![
        format_coded_index(&row.resolution_scope),
        resolve_string(strings, row.type_name),
        resolve_string(strings, row.type_namespace),
    ]
);

table_formatter_with!(format_typedef, TypeDefRaw, "TypeDef",
    &["Flags", "Name", "Namespace", "Extends", "FieldList", "MethodList"],
    (strings: Option<&Strings<'_>>),
    |row: &TypeDefRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:08X}", row.flags),
        resolve_string(strings, row.type_name),
        resolve_string(strings, row.type_namespace),
        format_coded_index(&row.extends),
        row.field_list.to_string(),
        row.method_list.to_string(),
    ]
);

table_formatter!(
    format_fieldptr,
    FieldPtrRaw,
    "FieldPtr",
    &["Field"],
    |row: &FieldPtrRaw| vec![row.field.to_string()]
);

table_formatter_with!(format_field, FieldRaw, "Field",
    &["Flags", "Name", "Signature"],
    (strings: Option<&Strings<'_>>),
    |row: &FieldRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:04X}", row.flags),
        resolve_string(strings, row.name),
        format!("blob@{}", row.signature),
    ]
);

table_formatter!(
    format_methodptr,
    MethodPtrRaw,
    "MethodPtr",
    &["Method"],
    |row: &MethodPtrRaw| vec![row.method.to_string()]
);

table_formatter_with!(format_methoddef, MethodDefRaw, "MethodDef",
    &["RVA", "ImplFlags", "Flags", "Name", "Signature", "ParamList"],
    (strings: Option<&Strings<'_>>),
    |row: &MethodDefRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:08X}", row.rva),
        format!("0x{:04X}", row.impl_flags),
        format!("0x{:04X}", row.flags),
        resolve_string(strings, row.name),
        format!("blob@{}", row.signature),
        row.param_list.to_string(),
    ]
);

table_formatter!(
    format_paramptr,
    ParamPtrRaw,
    "ParamPtr",
    &["Param"],
    |row: &ParamPtrRaw| vec![row.param.to_string()]
);

table_formatter_with!(format_param, ParamRaw, "Param",
    &["Flags", "Sequence", "Name"],
    (strings: Option<&Strings<'_>>),
    |row: &ParamRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:04X}", row.flags),
        row.sequence.to_string(),
        resolve_string(strings, row.name),
    ]
);

// Type Relationships (0x09-0x0A)

table_formatter!(
    format_interfaceimpl,
    InterfaceImplRaw,
    "InterfaceImpl",
    &["Class", "Interface"],
    |row: &InterfaceImplRaw| vec![row.class.to_string(), format_coded_index(&row.interface),]
);

table_formatter_with!(format_memberref, MemberRefRaw, "MemberRef",
    &["Class", "Name", "Signature"],
    (strings: Option<&Strings<'_>>),
    |row: &MemberRefRaw, strings: Option<&Strings<'_>>| vec![
        format_coded_index(&row.class),
        resolve_string(strings, row.name),
        format!("blob@{}", row.signature),
    ]
);

// Attributes & Constants (0x0B-0x0E)

table_formatter_with!(format_constant, ConstantRaw, "Constant",
    &["Type", "Parent", "Value"],
    (blob: Option<&Blob<'_>>),
    |row: &ConstantRaw, blob: Option<&Blob<'_>>| vec![
        format!("0x{:02X}", row.base),
        format_coded_index(&row.parent),
        format_blob_ref(blob, row.value),
    ]
);

table_formatter_with!(format_customattribute, CustomAttributeRaw, "CustomAttribute",
    &["Parent", "Type", "Value"],
    (blob: Option<&Blob<'_>>),
    |row: &CustomAttributeRaw, blob: Option<&Blob<'_>>| vec![
        format_coded_index(&row.parent),
        format_coded_index(&row.constructor),
        format_blob_ref(blob, row.value),
    ]
);

table_formatter_with!(format_fieldmarshal, FieldMarshalRaw, "FieldMarshal",
    &["Parent", "NativeType"],
    (blob: Option<&Blob<'_>>),
    |row: &FieldMarshalRaw, blob: Option<&Blob<'_>>| vec![
        format_coded_index(&row.parent),
        format_blob_ref(blob, row.native_type),
    ]
);

table_formatter_with!(format_declsecurity, DeclSecurityRaw, "DeclSecurity",
    &["Action", "Parent", "PermissionSet"],
    (blob: Option<&Blob<'_>>),
    |row: &DeclSecurityRaw, blob: Option<&Blob<'_>>| vec![
        format!("0x{:04X}", row.action),
        format_coded_index(&row.parent),
        format_blob_ref(blob, row.permission_set),
    ]
);

// Layout & Signatures (0x0F-0x11)

table_formatter!(
    format_classlayout,
    ClassLayoutRaw,
    "ClassLayout",
    &["PackingSize", "ClassSize", "Parent"],
    |row: &ClassLayoutRaw| vec![
        row.packing_size.to_string(),
        row.class_size.to_string(),
        row.parent.to_string(),
    ]
);

table_formatter!(
    format_fieldlayout,
    FieldLayoutRaw,
    "FieldLayout",
    &["Offset", "Field"],
    |row: &FieldLayoutRaw| vec![row.field_offset.to_string(), row.field.to_string(),]
);

table_formatter_with!(format_standalonesig, StandAloneSigRaw, "StandAloneSig",
    &["Signature"],
    (blob: Option<&Blob<'_>>),
    |row: &StandAloneSigRaw, blob: Option<&Blob<'_>>| vec![
        format_blob_ref(blob, row.signature),
    ]
);

// Events (0x12-0x14)

table_formatter!(
    format_eventmap,
    EventMapRaw,
    "EventMap",
    &["Parent", "EventList"],
    |row: &EventMapRaw| vec![row.parent.to_string(), row.event_list.to_string(),]
);

table_formatter!(
    format_eventptr,
    EventPtrRaw,
    "EventPtr",
    &["Event"],
    |row: &EventPtrRaw| vec![row.event.to_string()]
);

table_formatter_with!(format_event, EventRaw, "Event",
    &["Flags", "Name", "EventType"],
    (strings: Option<&Strings<'_>>),
    |row: &EventRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:04X}", row.flags),
        resolve_string(strings, row.name),
        format_coded_index(&row.event_type),
    ]
);

// Properties (0x15-0x17)

table_formatter!(
    format_propertymap,
    PropertyMapRaw,
    "PropertyMap",
    &["Parent", "PropertyList"],
    |row: &PropertyMapRaw| vec![row.parent.to_string(), row.property_list.to_string(),]
);

table_formatter!(
    format_propertyptr,
    PropertyPtrRaw,
    "PropertyPtr",
    &["Property"],
    |row: &PropertyPtrRaw| vec![row.property.to_string()]
);

table_formatter_with!(format_property, PropertyRaw, "Property",
    &["Flags", "Name", "Type"],
    (strings: Option<&Strings<'_>>),
    |row: &PropertyRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:04X}", row.flags),
        resolve_string(strings, row.name),
        format!("blob@{}", row.signature),
    ]
);

// Method Semantics (0x18-0x19)

table_formatter!(
    format_methodsemantics,
    MethodSemanticsRaw,
    "MethodSemantics",
    &["Semantics", "Method", "Association"],
    |row: &MethodSemanticsRaw| vec![
        format!("0x{:04X}", row.semantics),
        row.method.to_string(),
        format_coded_index(&row.association),
    ]
);

table_formatter!(
    format_methodimpl,
    MethodImplRaw,
    "MethodImpl",
    &["Class", "MethodBody", "MethodDeclaration"],
    |row: &MethodImplRaw| vec![
        row.class.to_string(),
        format_coded_index(&row.method_body),
        format_coded_index(&row.method_declaration),
    ]
);

// References & Mapping (0x1A-0x1D)

table_formatter_with!(format_moduleref, ModuleRefRaw, "ModuleRef",
    &["Name"],
    (strings: Option<&Strings<'_>>),
    |row: &ModuleRefRaw, strings: Option<&Strings<'_>>| vec![
        resolve_string(strings, row.name),
    ]
);

table_formatter_with!(format_typespec, TypeSpecRaw, "TypeSpec",
    &["Signature"],
    (blob: Option<&Blob<'_>>),
    |row: &TypeSpecRaw, blob: Option<&Blob<'_>>| vec![
        format_blob_ref(blob, row.signature),
    ]
);

table_formatter_with!(format_implmap, ImplMapRaw, "ImplMap",
    &["MappingFlags", "MemberForwarded", "ImportName", "ImportScope"],
    (strings: Option<&Strings<'_>>),
    |row: &ImplMapRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:04X}", row.mapping_flags),
        format_coded_index(&row.member_forwarded),
        resolve_string(strings, row.import_name),
        row.import_scope.to_string(),
    ]
);

table_formatter!(
    format_fieldrva,
    FieldRvaRaw,
    "FieldRVA",
    &["RVA", "Field"],
    |row: &FieldRvaRaw| vec![format!("0x{:08X}", row.rva), row.field.to_string(),]
);

// Edit-and-Continue (0x1E-0x1F)

fn format_enclog(tables: &TablesHeader<'_>) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<EncLogRaw>()
        .with_context(|| "EncLog table not found")?;
    let columns = ["RID", "Token", "TokenValue", "FuncCode"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            format!("0x{:08X}", row.token_value),
            row.func_code.to_string(),
        ]);
    }
    Ok(TableDetailOutput {
        table: "EncLog".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_encmap(tables: &TablesHeader<'_>) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<EncMapRaw>()
        .with_context(|| "EncMap table not found")?;
    let columns = ["RID", "Token", "OriginalToken"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.original_token.to_string(),
        ]);
    }
    Ok(TableDetailOutput {
        table: "EncMap".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

// Assembly Info (0x20-0x28)

fn format_assembly(
    tables: &TablesHeader<'_>,
    strings: Option<&Strings<'_>>,
    blob: Option<&Blob<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<AssemblyRaw>()
        .with_context(|| "Assembly table not found")?;
    let columns = [
        "RID",
        "Token",
        "HashAlgId",
        "Version",
        "Flags",
        "PublicKey",
        "Name",
        "Culture",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            format!("0x{:08X}", row.hash_alg_id),
            format_version(
                row.major_version,
                row.minor_version,
                row.build_number,
                row.revision_number,
            ),
            format!("0x{:08X}", row.flags),
            format_blob_ref(blob, row.public_key),
            resolve_string(strings, row.name),
            resolve_string(strings, row.culture),
        ]);
    }
    Ok(TableDetailOutput {
        table: "Assembly".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

table_formatter!(
    format_assemblyprocessor,
    AssemblyProcessorRaw,
    "AssemblyProcessor",
    &["Processor"],
    |row: &AssemblyProcessorRaw| vec![row.processor.to_string()]
);

table_formatter!(
    format_assemblyos,
    AssemblyOsRaw,
    "AssemblyOS",
    &["OSPlatformId", "OSMajor", "OSMinor"],
    |row: &AssemblyOsRaw| vec![
        row.os_platform_id.to_string(),
        row.os_major_version.to_string(),
        row.os_minor_version.to_string(),
    ]
);

fn format_assemblyref(
    tables: &TablesHeader<'_>,
    strings: Option<&Strings<'_>>,
    blob: Option<&Blob<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<AssemblyRefRaw>()
        .with_context(|| "AssemblyRef table not found")?;
    let columns = [
        "RID",
        "Token",
        "Version",
        "Flags",
        "PublicKeyOrToken",
        "Name",
        "Culture",
        "HashValue",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            format_version(
                row.major_version,
                row.minor_version,
                row.build_number,
                row.revision_number,
            ),
            format!("0x{:08X}", row.flags),
            format_blob_ref(blob, row.public_key_or_token),
            resolve_string(strings, row.name),
            resolve_string(strings, row.culture),
            format_blob_ref(blob, row.hash_value),
        ]);
    }
    Ok(TableDetailOutput {
        table: "AssemblyRef".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

table_formatter!(
    format_assemblyrefprocessor,
    AssemblyRefProcessorRaw,
    "AssemblyRefProcessor",
    &["Processor", "AssemblyRef"],
    |row: &AssemblyRefProcessorRaw| vec![row.processor.to_string(), row.assembly_ref.to_string(),]
);

table_formatter!(
    format_assemblyrefos,
    AssemblyRefOsRaw,
    "AssemblyRefOS",
    &["OSPlatformId", "OSMajor", "OSMinor", "AssemblyRef"],
    |row: &AssemblyRefOsRaw| vec![
        row.os_platform_id.to_string(),
        row.os_major_version.to_string(),
        row.os_minor_version.to_string(),
        row.assembly_ref.to_string(),
    ]
);

table_formatter_with!(format_file, FileRaw, "File",
    &["Flags", "Name", "HashValue"],
    (strings: Option<&Strings<'_>>, blob: Option<&Blob<'_>>),
    |row: &FileRaw, strings: Option<&Strings<'_>>, blob: Option<&Blob<'_>>| vec![
        format!("0x{:08X}", row.flags),
        resolve_string(strings, row.name),
        format_blob_ref(blob, row.hash_value),
    ]
);

table_formatter_with!(format_exportedtype, ExportedTypeRaw, "ExportedType",
    &["Flags", "TypeDefId", "Name", "Namespace", "Implementation"],
    (strings: Option<&Strings<'_>>),
    |row: &ExportedTypeRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:08X}", row.flags),
        row.type_def_id.to_string(),
        resolve_string(strings, row.name),
        resolve_string(strings, row.namespace),
        format_coded_index(&row.implementation),
    ]
);

table_formatter_with!(format_manifestresource, ManifestResourceRaw, "ManifestResource",
    &["Offset", "Flags", "Name", "Implementation"],
    (strings: Option<&Strings<'_>>),
    |row: &ManifestResourceRaw, strings: Option<&Strings<'_>>| vec![
        format!("0x{:08X}", row.offset_field),
        format!("0x{:08X}", row.flags),
        resolve_string(strings, row.name),
        format_coded_index(&row.implementation),
    ]
);

// Nested Classes (0x29)

table_formatter!(
    format_nestedclass,
    NestedClassRaw,
    "NestedClass",
    &["NestedClass", "EnclosingClass"],
    |row: &NestedClassRaw| vec![
        row.nested_class.to_string(),
        row.enclosing_class.to_string(),
    ]
);

// Generic Parameters (0x2A-0x2C)

table_formatter_with!(format_genericparam, GenericParamRaw, "GenericParam",
    &["Number", "Flags", "Owner", "Name"],
    (strings: Option<&Strings<'_>>),
    |row: &GenericParamRaw, strings: Option<&Strings<'_>>| vec![
        row.number.to_string(),
        format!("0x{:04X}", row.flags),
        format_coded_index(&row.owner),
        resolve_string(strings, row.name),
    ]
);

table_formatter_with!(format_methodspec, MethodSpecRaw, "MethodSpec",
    &["Method", "Instantiation"],
    (blob: Option<&Blob<'_>>),
    |row: &MethodSpecRaw, blob: Option<&Blob<'_>>| vec![
        format_coded_index(&row.method),
        format_blob_ref(blob, row.instantiation),
    ]
);

table_formatter!(
    format_genericparamconstraint,
    GenericParamConstraintRaw,
    "GenericParamConstraint",
    &["Owner", "Constraint"],
    |row: &GenericParamConstraintRaw| vec![
        row.owner.to_string(),
        format_coded_index(&row.constraint),
    ]
);

// Debug Information (0x30-0x37)

table_formatter_with!(format_document, DocumentRaw, "Document",
    &["Name", "HashAlgorithm", "Hash", "Language"],
    (blob: Option<&Blob<'_>>),
    |row: &DocumentRaw, blob: Option<&Blob<'_>>| vec![
        format_blob_ref(blob, row.name),
        format_blob_ref(blob, row.hash_algorithm),
        format_blob_ref(blob, row.hash),
        format_blob_ref(blob, row.language),
    ]
);

fn format_methoddebuginformation(
    tables: &TablesHeader<'_>,
    blob: Option<&Blob<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<MethodDebugInformationRaw>()
        .with_context(|| "MethodDebugInformation table not found")?;
    let columns = ["RID", "Token", "Document", "SequencePoints"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.document.to_string(),
            format_blob_ref(blob, row.sequence_points),
        ]);
    }
    Ok(TableDetailOutput {
        table: "MethodDebugInformation".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_localscope(tables: &TablesHeader<'_>) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<LocalScopeRaw>()
        .with_context(|| "LocalScope table not found")?;
    let columns = [
        "RID",
        "Token",
        "Method",
        "ImportScope",
        "VariableList",
        "ConstantList",
        "StartOffset",
        "Length",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.method.to_string(),
            row.import_scope.to_string(),
            row.variable_list.to_string(),
            row.constant_list.to_string(),
            row.start_offset.to_string(),
            row.length.to_string(),
        ]);
    }
    Ok(TableDetailOutput {
        table: "LocalScope".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_localvariable(
    tables: &TablesHeader<'_>,
    strings: Option<&Strings<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<LocalVariableRaw>()
        .with_context(|| "LocalVariable table not found")?;
    let columns = ["RID", "Token", "Attributes", "Index", "Name"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            format!("0x{:04X}", row.attributes),
            row.index.to_string(),
            resolve_string(strings, row.name),
        ]);
    }
    Ok(TableDetailOutput {
        table: "LocalVariable".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_localconstant(
    tables: &TablesHeader<'_>,
    strings: Option<&Strings<'_>>,
    blob: Option<&Blob<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<LocalConstantRaw>()
        .with_context(|| "LocalConstant table not found")?;
    let columns = ["RID", "Token", "Name", "Signature"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            resolve_string(strings, row.name),
            format_blob_ref(blob, row.signature),
        ]);
    }
    Ok(TableDetailOutput {
        table: "LocalConstant".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_importscope(
    tables: &TablesHeader<'_>,
    blob: Option<&Blob<'_>>,
) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<ImportScopeRaw>()
        .with_context(|| "ImportScope table not found")?;
    let columns = ["RID", "Token", "Parent", "Imports"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.parent.to_string(),
            format_blob_ref(blob, row.imports),
        ]);
    }
    Ok(TableDetailOutput {
        table: "ImportScope".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

fn format_statemachinemethod(tables: &TablesHeader<'_>) -> anyhow::Result<TableDetailOutput> {
    let table = tables
        .table::<StateMachineMethodRaw>()
        .with_context(|| "StateMachineMethod table not found")?;
    let columns = ["RID", "Token", "MoveNextMethod", "KickOffMethod"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = Vec::new();
    for row in table {
        let Ok(row) = row else {
            continue;
        };
        rows.push(vec![
            row.rid.to_string(),
            row.token.to_string(),
            row.move_next_method.to_string(),
            row.kickoff_method.to_string(),
        ]);
    }
    Ok(TableDetailOutput {
        table: "StateMachineMethod".to_string(),
        row_count: table.row_count,
        columns,
        rows,
    })
}

table_formatter_with!(format_customdebuginformation, CustomDebugInformationRaw, "CustomDebugInformation",
    &["Parent", "Kind", "Value"],
    (blob: Option<&Blob<'_>>),
    |row: &CustomDebugInformationRaw, blob: Option<&Blob<'_>>| vec![
        format_coded_index(&row.parent),
        format_blob_ref(blob, row.kind),
        format_blob_ref(blob, row.value),
    ]
);

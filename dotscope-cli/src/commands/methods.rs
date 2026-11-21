use std::{collections::BTreeMap, path::Path};

use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{load_assembly, name_contains_ignore_case},
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct MethodEntry {
    token: String,
    access: String,
    declaring_type: String,
    name: String,
    is_static: bool,
    is_virtual: bool,
    is_abstract: bool,
    param_count: usize,
    return_type: String,
    body_size: Option<usize>,
}

#[derive(Debug, Serialize)]
struct MethodsOutput {
    methods: Vec<MethodEntry>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct TypeGroup {
    declaring_type: String,
    methods: Vec<MethodEntry>,
}

#[derive(Debug, Serialize)]
struct GroupedMethodsOutput {
    groups: Vec<TypeGroup>,
    count: usize,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum MethodsOutputFormat {
    Flat(MethodsOutput),
    Grouped(GroupedMethodsOutput),
}

pub fn run(
    path: &Path,
    type_filter: Option<&str>,
    signatures: bool,
    group: bool,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let methods = assembly.methods();

    let mut entries = Vec::new();

    for entry in methods {
        let method = entry.value();

        let declaring_fullname = method.declaring_type_fullname().unwrap_or_default();

        if let Some(filter) = type_filter {
            if !name_contains_ignore_case(&declaring_fullname, filter) {
                continue;
            }
        }

        let method_display = if signatures {
            format!("{} {}", method.name, method.signature)
        } else {
            method.name.to_string()
        };

        let body_size = method.body.get().map(|b| b.size_code);

        entries.push(MethodEntry {
            token: method.token.to_string(),
            access: method.flags_access.to_string(),
            declaring_type: declaring_fullname.to_string(),
            name: method_display,
            is_static: method.is_static(),
            is_virtual: method.is_virtual(),
            is_abstract: method.is_abstract(),
            param_count: method.signature.params.len(),
            return_type: format!("{}", method.signature.return_type),
            body_size,
        });
    }

    let count = entries.len();

    if group {
        let mut grouped: BTreeMap<String, Vec<MethodEntry>> = BTreeMap::new();
        for entry in entries {
            grouped
                .entry(entry.declaring_type.clone())
                .or_default()
                .push(entry);
        }

        let groups: Vec<TypeGroup> = grouped
            .into_iter()
            .map(|(declaring_type, methods)| TypeGroup {
                declaring_type,
                methods,
            })
            .collect();

        let output = MethodsOutputFormat::Grouped(GroupedMethodsOutput { groups, count });

        print_output(&output, opts, |out| {
            if let MethodsOutputFormat::Grouped(g) = out {
                for group in &g.groups {
                    println!(
                        "\n{} ({} methods):",
                        group.declaring_type,
                        group.methods.len()
                    );
                    let mut tw = TabWriter::new(&[
                        ("Token", Align::Left),
                        ("Access", Align::Left),
                        ("Method", Align::Left),
                    ])
                    .indent("  ");
                    for e in &group.methods {
                        tw.row(vec![e.token.clone(), e.access.clone(), e.name.clone()]);
                    }
                    tw.print();
                }
                println!("\n{} method(s) listed.", g.count);
            }
        })
    } else {
        let output = MethodsOutputFormat::Flat(MethodsOutput {
            methods: entries,
            count,
        });

        print_output(&output, opts, |out| {
            if let MethodsOutputFormat::Flat(flat) = out {
                let mut tw = TabWriter::new(&[
                    ("Token", Align::Left),
                    ("Access", Align::Left),
                    ("Type", Align::Left),
                    ("Method", Align::Left),
                ]);
                for e in &flat.methods {
                    tw.row(vec![
                        e.token.clone(),
                        e.access.clone(),
                        e.declaring_type.clone(),
                        e.name.clone(),
                    ]);
                }
                tw.print();
                println!("\n{} method(s) listed.", flat.count);
            }
        })
    }
}

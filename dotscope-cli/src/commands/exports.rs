use std::path::Path;

use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct CilExport {
    token: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct NativeExport {
    ordinal: u16,
    name: String,
}

#[derive(Debug, Serialize)]
struct ExportsOutput {
    cil: Vec<CilExport>,
    native: Vec<NativeExport>,
}

pub fn run(path: &Path, opts: &GlobalOptions) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let exports = assembly.exports();

    let cil_entries: Vec<CilExport> = exports
        .cil()
        .iter()
        .map(|entry| {
            let exported = entry.value();
            let fullname = match &exported.namespace {
                Some(ns) if !ns.is_empty() => format!("{ns}.{}", exported.name),
                _ => exported.name.to_string(),
            };
            CilExport {
                token: exported.token.to_string(),
                name: fullname,
            }
        })
        .collect();

    let native_obj = exports.native();
    let mut native_entries: Vec<NativeExport> = Vec::new();

    for func in native_obj.functions() {
        native_entries.push(NativeExport {
            ordinal: func.ordinal,
            name: func.name.as_deref().unwrap_or("<ordinal-only>").to_string(),
        });
    }

    for fwd in native_obj.forwarders() {
        let name = fwd.name.as_deref().unwrap_or("<ordinal-only>");
        native_entries.push(NativeExport {
            ordinal: fwd.ordinal,
            name: format!("{name} -> {}", fwd.target),
        });
    }

    let output = ExportsOutput {
        cil: cil_entries,
        native: native_entries,
    };

    print_output(&output, opts, |out| {
        let cil_count = out.cil.len();
        if cil_count > 0 {
            println!("CIL exported types ({cil_count} entries):");
            let mut tw =
                TabWriter::new(&[("Token", Align::Left), ("Name", Align::Left)]).indent("  ");
            for entry in &out.cil {
                tw.row(vec![entry.token.clone(), entry.name.clone()]);
            }
            tw.print();
        }

        if !out.native.is_empty() {
            println!("\nNative exports ({} entries):", out.native.len());
            let mut tw =
                TabWriter::new(&[("Ordinal", Align::Left), ("Name", Align::Left)]).indent("  ");
            for entry in &out.native {
                tw.row(vec![entry.ordinal.to_string(), entry.name.clone()]);
            }
            tw.print();
        }

        if cil_count == 0 && out.native.is_empty() {
            println!("No exports found.");
        }
    })
}

use std::path::Path;

use dotscope::metadata::imports::ImportSourceId;
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct CilImport {
    token: String,
    assembly: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct NativeImport {
    dll: String,
    functions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ImportsOutput {
    cil: Vec<CilImport>,
    native: Vec<NativeImport>,
}

pub fn run(path: &Path, opts: &GlobalOptions) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let imports = assembly.imports();
    let refs = assembly.refs_assembly();

    let cil_entries: Vec<CilImport> = imports
        .cil()
        .iter()
        .map(|entry| {
            let import = entry.value();
            let source = match &import.source_id {
                ImportSourceId::AssemblyRef(token) => refs
                    .get(token)
                    .map_or_else(|| "(unknown)".to_string(), |e| e.value().name.to_string()),
                ImportSourceId::Module(_) => "(self)".to_string(),
                ImportSourceId::ModuleRef(_) => "(module)".to_string(),
                ImportSourceId::File(_) => "(file)".to_string(),
                ImportSourceId::TypeRef(_) => "(typeref)".to_string(),
                ImportSourceId::None => "(unknown)".to_string(),
            };
            CilImport {
                token: import.token.to_string(),
                assembly: source,
                name: import.fullname().to_string(),
            }
        })
        .collect();

    let native_entries: Vec<NativeImport> = imports
        .get_all_dll_dependencies()
        .iter()
        .map(|dep| NativeImport {
            dll: dep.name.to_string(),
            functions: dep.functions.iter().map(ToString::to_string).collect(),
        })
        .collect();

    let output = ImportsOutput {
        cil: cil_entries,
        native: native_entries,
    };

    print_output(&output, opts, |out| {
        let cil_count = out.cil.len();
        if cil_count > 0 {
            println!("CIL imports ({cil_count} entries):");
            let mut tw = TabWriter::new(&[
                ("Token", Align::Left),
                ("Assembly", Align::Left),
                ("Name", Align::Left),
            ])
            .indent("  ");
            for entry in &out.cil {
                tw.row(vec![
                    entry.token.clone(),
                    entry.assembly.clone(),
                    entry.name.clone(),
                ]);
            }
            tw.print();
        } else {
            println!("CIL imports: none");
        }

        if !out.native.is_empty() {
            println!("\nNative imports:");
            for dep in &out.native {
                let funcs = dep.functions.join(", ");
                println!("  {}: {funcs}", dep.dll);
            }
        }
    })
}

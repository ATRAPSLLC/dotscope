use std::{fmt::Write, path::Path};

use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::load_assembly,
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
pub struct AssemblyInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub module: Option<String>,
    pub runtime_version: String,
    pub entry_point_token: String,
    pub type_count: usize,
    pub method_count: usize,
    pub resource_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub culture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_flags: Option<String>,
    pub machine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    pub characteristics: String,
    pub cor_flags: String,
    pub strong_named: bool,
    pub assembly_ref_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<AssemblyRefInfo>,
}

#[derive(Debug, Serialize)]
pub struct AssemblyRefInfo {
    pub name: String,
    pub version: String,
}

fn format_public_key(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn run(path: &Path, opts: &GlobalOptions) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let (asm_name, asm_version, public_key, culture, hash_algorithm, assembly_flags) =
        match assembly.assembly() {
            Some(asm) => {
                let pk = asm
                    .public_key
                    .as_ref()
                    .filter(|k| !k.is_empty())
                    .map(|k| format_public_key(k));
                let cult = asm
                    .culture
                    .as_ref()
                    .filter(|c| !c.is_empty())
                    .map(ToString::to_string);
                let hash_alg = Some(asm.hash_alg_id.to_string());
                let flags = Some(asm.flags.to_string());
                (
                    Some(asm.name.to_string()),
                    Some(format!(
                        "{}.{}.{}.{}",
                        asm.major_version, asm.minor_version, asm.build_number, asm.revision_number
                    )),
                    pk,
                    cult,
                    hash_alg,
                    flags,
                )
            }
            None => (None, None, None, None, None, None),
        };

    let module_name = assembly.module().map(|m| m.name.to_string());

    let file = assembly.file();
    let machine = file.header().machine.to_string();
    let subsystem = file
        .header_optional()
        .as_ref()
        .map(|oh| oh.windows_fields.subsystem.to_string());
    let characteristics = file.header().characteristics.to_string();

    let cor20 = assembly.cor20header();
    let cor_flags = cor20.flags.to_string();
    let strong_named = cor20.strong_name_signature_size > 0;

    let refs = assembly.refs_assembly();
    let assembly_ref_count = refs.len();

    let references: Vec<AssemblyRefInfo> = refs
        .iter()
        .map(|entry| {
            let aref = entry.value();
            AssemblyRefInfo {
                name: aref.name.to_string(),
                version: format!(
                    "{}.{}.{}.{}",
                    aref.major_version, aref.minor_version, aref.build_number, aref.revision_number
                ),
            }
        })
        .collect();

    let info = AssemblyInfo {
        name: asm_name,
        version: asm_version,
        module: module_name,
        runtime_version: assembly
            .metadata_root()
            .version
            .trim_end_matches('\0')
            .to_string(),
        entry_point_token: format!("0x{:08X}", cor20.entry_point_token),
        type_count: assembly.types().len(),
        method_count: assembly.methods().len(),
        resource_count: assembly.resources().len(),
        public_key,
        culture,
        hash_algorithm,
        assembly_flags,
        machine,
        subsystem,
        characteristics,
        cor_flags,
        strong_named,
        assembly_ref_count,
        references,
    };

    print_output(&info, opts, |info| {
        if let Some(name) = &info.name {
            println!("Assembly:        {name}");
        }
        if let Some(version) = &info.version {
            println!("Version:         {version}");
        }
        if let Some(module) = &info.module {
            println!("Module:          {module}");
        }
        println!("Runtime:         {}", info.runtime_version);
        println!("Entry point:     {}", info.entry_point_token);
        if let Some(pk) = &info.public_key {
            println!("Public key:      {pk}");
        }
        if let Some(cult) = &info.culture {
            println!("Culture:         {cult}");
        }
        if let Some(hash_alg) = &info.hash_algorithm {
            println!("Hash algorithm:  {hash_alg}");
        }
        if let Some(flags) = &info.assembly_flags {
            println!("Assembly flags:  {flags}");
        }
        println!("Machine:         {}", info.machine);
        if let Some(sub) = &info.subsystem {
            println!("Subsystem:       {sub}");
        }
        println!("Characteristics: {}", info.characteristics);
        println!("COR flags:       {}", info.cor_flags);
        let sn = if info.strong_named { "yes" } else { "no" };
        println!("Strong-named:    {sn}");
        println!("Types:           {}", info.type_count);
        println!("Methods:         {}", info.method_count);
        println!("Resources:       {}", info.resource_count);
        println!("Assembly refs:   {}", info.assembly_ref_count);

        if !info.references.is_empty() {
            println!("\nReferences:");
            let mut tw =
                TabWriter::new(&[("Name", Align::Left), ("Version", Align::Left)]).indent("  ");
            for r in &info.references {
                tw.row(vec![r.name.clone(), r.version.clone()]);
            }
            tw.print();
        }
    })
}

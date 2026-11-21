use std::path::Path;

use anyhow::{bail, Context};
use dotscope::CilObject;
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{load_assembly, name_contains_ignore_case},
    output::{print_output, Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct ResourceEntry {
    name: String,
    size: usize,
    source: String,
}

#[derive(Debug, Serialize)]
struct ResourcesOutput {
    resources: Vec<ResourceEntry>,
    count: usize,
}

pub fn run(
    path: &Path,
    extract: bool,
    output_dir: Option<&Path>,
    name_filter: Option<&str>,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let resources = assembly.resources();

    if resources.is_empty() {
        println!("No resources found.");
        return Ok(());
    }

    if extract {
        extract_resources(&assembly, output_dir, name_filter)
    } else {
        list_resources(&assembly, name_filter, opts)
    }
}

fn list_resources(
    assembly: &CilObject,
    name_filter: Option<&str>,
    opts: &GlobalOptions,
) -> anyhow::Result<()> {
    let resources = assembly.resources();

    let mut entries = Vec::new();

    for entry in resources {
        let resource = entry.value();
        let name = &resource.name;

        if let Some(filter) = name_filter {
            if !name_contains_ignore_case(name, filter) {
                continue;
            }
        }

        let source = if resource.source.is_none() {
            "Embedded"
        } else {
            "External"
        };

        entries.push(ResourceEntry {
            name: name.to_string(),
            size: resource.data_size,
            source: source.to_string(),
        });
    }

    let count = entries.len();
    let output = ResourcesOutput {
        resources: entries,
        count,
    };

    print_output(&output, opts, |out| {
        let mut tw = TabWriter::new(&[
            ("Name", Align::Left),
            ("Size", Align::Right),
            ("Source", Align::Left),
        ]);
        for e in &out.resources {
            tw.row(vec![e.name.clone(), e.size.to_string(), e.source.clone()]);
        }
        tw.print();
        println!("\n{} resource(s) listed.", out.count);
    })
}

fn extract_resources(
    assembly: &CilObject,
    output_dir: Option<&Path>,
    name_filter: Option<&str>,
) -> anyhow::Result<()> {
    let resources = assembly.resources();
    let out = output_dir.unwrap_or_else(|| Path::new("."));

    if !out.exists() {
        std::fs::create_dir_all(out)
            .with_context(|| format!("failed to create output directory: {}", out.display()))?;
    }

    let mut extracted = 0usize;
    let mut skipped = 0usize;

    for entry in resources {
        let resource = entry.value();
        let name = &resource.name;

        if let Some(filter) = name_filter {
            if name != filter {
                continue;
            }
        }

        if resource.source.is_some() {
            println!("  skip (external): {name}");
            skipped += 1;
            continue;
        }

        if let Some(data) = resources.get_data(resource) {
            // Sanitize filename: replace path separators to avoid directory traversal
            let safe_name = name.replace(['/', '\\'], "_");
            let dest = out.join(&safe_name);

            std::fs::write(&dest, data)
                .with_context(|| format!("failed to write resource to {}", dest.display()))?;

            println!(
                "  extracted: {name} ({} bytes) -> {}",
                data.len(),
                dest.display()
            );
            extracted += 1;
        } else {
            println!("  skip (no data): {name}");
            skipped += 1;
        }
    }

    if let Some(filter) = name_filter {
        if extracted == 0 && skipped == 0 {
            bail!("no resource matching '{filter}' found");
        }
    }

    println!("\n{extracted} extracted, {skipped} skipped.");

    Ok(())
}

//! # Metadata Tables and Streams Exploration
//!
//! **What this example teaches:**
//! - Direct access to metadata tables and streams
//! - String, GUID, and blob heap analysis
//! - Cross-reference analysis between metadata tables
//! - Assembly dependency analysis
//! - Working with raw metadata structures
//!
//! **When to use this pattern:**
//! - Building metadata analysis tools
//! - Investigating assembly internals
//! - Dependency tracking and analysis
//! - Understanding ECMA-335 metadata structures
//!
//! **Prerequisites:**
//! - Solid understanding of .NET metadata concepts
//! - Familiarity with ECMA-335 specification
//! - Experience with basic dotscope operations

use std::{collections::HashMap, env, path::Path};

use dotscope::{metadata::customattributes::CustomAttributeValueRc, prelude::*};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("metadata", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example explores metadata tables and streams in detail:");
        eprintln!("  • Raw metadata table access and analysis");
        eprintln!("  • Heap content examination (strings, GUIDs, blobs)");
        eprintln!("  • Cross-table relationship analysis");
        eprintln!("  • Assembly dependency tracking");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("🔬 Metadata exploration of: {}", path.display());

    let assembly = CilObject::from_path(path)?;

    // Metadata Tables Analysis
    print_metadata_tables(&assembly);

    // String and Blob Heap Analysis
    print_heap_analysis(&assembly);

    // Type System Deep Dive
    print_type_system_analysis(&assembly);

    // Custom Attributes Analysis
    print_custom_attributes_analysis(&assembly);

    // Assembly Dependencies
    print_dependency_analysis(&assembly);

    println!("\n✅ Metadata exploration completed!");

    Ok(())
}

fn print_metadata_tables(assembly: &CilObject) {
    println!("\n📊 Metadata Tables Analysis:");

    if let Some(tables) = assembly.tables() {
        println!("  Total tables present: {}", tables.table_count());

        // Show which tables are present using the new API
        println!("  Available metadata tables:");
        for table_id in tables.present_tables() {
            let row_count = tables.table_row_count(table_id);
            println!("    ✓ {table_id:?} ({row_count} rows)");
        }
    }

    // Method statistics
    let methods = assembly.methods();
    println!("  Methods analyzed: {}", methods.len());

    // Type statistics
    let types = assembly.types();
    println!("  Types analyzed: {}", types.len());
}

fn print_heap_analysis(assembly: &CilObject) {
    println!("\n🗃️  Heap Analysis:");

    if let Some(tables) = assembly.tables() {
        let heap_info = &tables.info;
        println!("  String heap size: {} bytes", heap_info.str_bytes());
        println!("  GUID heap size: {} bytes", heap_info.guid_bytes());
        println!("  Blob heap size: {} bytes", heap_info.blob_bytes());
    }

    // String heap analysis with iterator demonstration
    if let Some(strings) = assembly.strings() {
        let mut string_count: u64 = 0;
        let mut total_length: usize = 0;
        let mut sample_strings = Vec::new();

        println!("  String heap analysis:");
        for (offset, string) in strings.iter().take(1000) {
            string_count = string_count.saturating_add(1u64);
            total_length = total_length.saturating_add(string.len());

            // Collect interesting samples
            if sample_strings.len() < 5 && !string.is_empty() && string.len() > 3 {
                sample_strings.push((offset, string));
            }
        }

        println!("    Total strings analyzed: {string_count}");
        println!(
            "    Average string length: {:.1} chars",
            total_length as f64 / string_count.max(1) as f64
        );

        if !sample_strings.is_empty() {
            println!("    Sample strings:");
            for (offset, string) in sample_strings {
                println!(
                    "      @{:04X}: \"{}\"",
                    offset,
                    string.chars().take(40).collect::<String>()
                );
            }
        }
    }

    // GUID heap analysis with iterator demonstration
    if let Some(guids) = assembly.guids() {
        println!("  GUID heap analysis:");

        for (index, guid) in guids.iter().take(3) {
            println!("    GUID #{index}: {guid}");
        }

        println!("    Total GUIDs: {}", guids.iter().count());
    }

    // Blob heap analysis with iterator demonstration
    if let Some(blob) = assembly.blob() {
        let mut blob_count: u64 = 0;
        let mut total_size: usize = 0;
        let mut size_histogram: HashMap<String, usize> = HashMap::new();

        println!("  Blob heap analysis:");
        for (offset, blob_data) in blob.iter().take(500) {
            // Limit to avoid overwhelming output
            blob_count = blob_count.saturating_add(1u64);
            total_size = total_size.saturating_add(blob_data.len());

            // Categorize by size
            let size_category = match blob_data.len() {
                0..=4 => "tiny (0-4 bytes)",
                5..=16 => "small (5-16 bytes)",
                17..=64 => "medium (17-64 bytes)",
                65..=256 => "large (65-256 bytes)",
                _ => "huge (>256 bytes)",
            };
            let entry = size_histogram
                .entry(size_category.to_string())
                .or_insert(0usize);
            *entry = entry.saturating_add(1);

            // Show a sample of the first few blobs
            if blob_count <= 3 && !blob_data.is_empty() {
                let preview = blob_data
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let suffix = if blob_data.len() > 8 { "..." } else { "" };
                println!(
                    "    Blob @{:04X}: {} bytes [{}{}]",
                    offset,
                    blob_data.len(),
                    preview,
                    suffix
                );
            }
        }

        println!("    Total blobs analyzed: {blob_count}");
        if blob_count > 0 {
            println!(
                "    Average blob size: {:.1} bytes",
                total_size as f64 / blob_count as f64
            );
            println!("    Size distribution:");
            for (category, count) in size_histogram {
                println!("      {category}: {count} blobs");
            }
        }
    }

    // User strings heap analysis with iterator demonstration
    if let Some(user_strings) = assembly.userstrings() {
        let mut string_count: u64 = 0;
        let mut sample_user_strings = Vec::new();

        println!("  User strings heap analysis:");
        for (offset, string) in user_strings.iter().take(100) {
            // Limit for readability
            string_count = string_count.saturating_add(1);

            // Collect interesting samples
            if sample_user_strings.len() < 3 {
                let display_string = string.to_string_lossy();
                if !display_string.trim().is_empty() && display_string.len() > 2 {
                    sample_user_strings.push((offset, display_string.to_string()));
                }
            }
        }

        println!("    Total user strings: {string_count}");
        if !sample_user_strings.is_empty() {
            println!("    Sample user strings:");
            for (offset, string) in sample_user_strings {
                let truncated = if string.len() > 50 {
                    format!("{}...", string.get(..47).unwrap_or(string.as_str()))
                } else {
                    string
                };
                println!("      @{offset:04X}: \"{truncated}\"");
            }
        }
    }
}

fn print_type_system_analysis(assembly: &CilObject) {
    println!("\n🏗️  Type System Analysis:");

    let types = assembly.types();
    let mut namespace_stats: HashMap<String, usize> = HashMap::new();
    let mut type_kind_stats: HashMap<&str, usize> = HashMap::new();

    // Analyze types by namespace and kind
    for type_def in &types.all_types() {
        let namespace = if type_def.namespace.is_empty() {
            "<global>".to_string()
        } else {
            type_def.namespace.clone()
        };

        let entry = namespace_stats.entry(namespace).or_insert(0usize);
        *entry = entry.saturating_add(1);

        let category = if type_def.name.ends_with("Attribute") {
            "Attributes"
        } else if type_def.name.ends_with("Exception") {
            "Exceptions"
        } else if type_def.name.ends_with("EventArgs") {
            "EventArgs"
        } else if type_def.name.starts_with('I')
            && type_def.name.len() > 1
            && type_def.name.chars().nth(1).is_some_and(char::is_uppercase)
        {
            "Interfaces"
        } else {
            "Classes"
        };
        let entry = type_kind_stats.entry(category).or_insert(0usize);
        *entry = entry.saturating_add(1);
    }

    // Display namespace statistics
    println!("  Top namespaces by type count:");
    let mut sorted_ns: Vec<_> = namespace_stats.iter().collect();
    sorted_ns.sort_by(|a, b| b.1.cmp(a.1));
    for (namespace, count) in sorted_ns.iter().take(8) {
        println!("    {namespace}: {count} types");
    }

    // Display type kind statistics
    println!("  Type categories:");
    for (kind, count) in &type_kind_stats {
        println!("    {kind}: {count} types");
    }
}

fn print_custom_attributes_analysis(assembly: &CilObject) {
    println!("\n🏷️  Custom Attributes Examples:");

    // Show custom attributes from Types
    println!("  Custom attributes on Types:");
    let types = assembly.types();
    let mut type_count: u64 = 0;
    for entry in types.iter().take(20) {
        let type_def = entry.value();
        let custom_attrs = &type_def.custom_attributes;

        let attr_count = custom_attrs.count();

        if attr_count > 0 && type_count < 2 {
            println!("    Type: {}", type_def.fullname());
            for (i, attr) in custom_attrs.iter().take(5) {
                print_custom_attribute_info(i.saturating_add(1), attr);
            }
            type_count = type_count.saturating_add(1u64);
            if attr_count > 5 {
                println!(
                    "      ... and {} more attributes",
                    attr_count.saturating_sub(5)
                );
            }
        }
    }

    // Show custom attributes from Methods
    println!("  Custom attributes on Methods:");
    let methods = assembly.methods();
    let mut method_count: u64 = 0;
    for entry in methods.iter().take(50) {
        let method = entry.value();
        let custom_attrs = &method.custom_attributes;

        let attr_count = custom_attrs.count();

        if attr_count > 0 && method_count < 2 {
            println!("    Method: {}", method.name);
            for (i, attr) in custom_attrs.iter().take(5) {
                print_custom_attribute_info(i.saturating_add(1), attr);
            }
            method_count = method_count.saturating_add(1u64);
            if attr_count > 5 {
                println!(
                    "      ... and {} more attributes",
                    attr_count.saturating_sub(5)
                );
            }
        }
    }

    // Show custom attributes from Events
    println!("  Custom attributes on Events:");
    let mut event_count: u64 = 0;
    for entry in types.iter().take(20) {
        let type_def = entry.value();
        let events = &type_def.events;
        for (_, event) in events.iter().take(10) {
            let custom_attrs = &event.custom_attributes;

            let attr_count = custom_attrs.count();

            if attr_count > 0 && event_count < 2 {
                println!("    Event: {}", event.name);
                for (i, attr) in custom_attrs.iter().take(5) {
                    print_custom_attribute_info(i.saturating_add(1), attr);
                }
                event_count = event_count.saturating_add(1u64);
                if attr_count > 5 {
                    println!(
                        "      ... and {} more attributes",
                        attr_count.saturating_sub(5)
                    );
                }
            }
        }
        if event_count >= 2 {
            break;
        }
    }

    if type_count == 0 && method_count == 0 && event_count == 0 {
        println!("  No custom attributes found in the analyzed types, methods, or events.");
    }
}

fn print_custom_attribute_info(index: usize, attr: &CustomAttributeValueRc) {
    println!("      {index}. Custom Attribute:");

    // Show argument summary
    let fixed_count = attr.fixed_args.len();
    let named_count = attr.named_args.len();

    if fixed_count > 0 || named_count > 0 {
        println!("         Arguments: {fixed_count} fixed, {named_count} named");

        // Show first 2 fixed args
        for (i, arg) in attr.fixed_args.iter().take(2).enumerate() {
            println!("           Fixed[{i}]: {arg:?}");
        }

        // Show first 2 named args
        for (i, arg) in attr.named_args.iter().take(2).enumerate() {
            let kind = if arg.is_field { "field" } else { "property" };
            println!(
                "           Named[{}]: {} '{}' = {:?}",
                i, kind, arg.name, arg.value
            );
        }
    } else {
        println!("         No arguments");
    }
}

fn print_dependency_analysis(assembly: &CilObject) {
    println!("\n🔗 Dependency Analysis:");

    // Assembly references analysis using the correct public API
    let assembly_refs = assembly.refs_assembly();
    println!("  Assembly references: {}", assembly_refs.len());

    if !assembly_refs.is_empty() {
        println!("  Referenced assemblies:");
        for (i, entry) in assembly_refs.iter().take(10).enumerate() {
            let assembly_ref = entry.value();
            let culture = assembly_ref
                .culture
                .as_ref()
                .map_or("neutral", |c| c.as_str());
            let version = format!(
                "{}.{}.{}.{}",
                assembly_ref.major_version,
                assembly_ref.minor_version,
                assembly_ref.build_number,
                assembly_ref.revision_number
            );

            // Decode assembly flags for better readability
            let mut flag_descriptions = Vec::new();
            if assembly_ref.flags.bits() & 0x0001 != 0 {
                flag_descriptions.push("PublicKey");
            }
            if assembly_ref.flags.bits() & 0x0100 != 0 {
                flag_descriptions.push("Retargetable");
            }
            if assembly_ref.flags.bits() & 0x4000 != 0 {
                flag_descriptions.push("DisableJITOptimizer");
            }
            if assembly_ref.flags.bits() & 0x8000 != 0 {
                flag_descriptions.push("EnableJITTracking");
            }
            let flags_str = if flag_descriptions.is_empty() {
                "None".to_string()
            } else {
                flag_descriptions.join(", ")
            };

            println!(
                "    {}. {} v{}",
                i.saturating_add(1),
                assembly_ref.name,
                version
            );
            println!("       Culture: {culture}, Flags: {flags_str}");

            // Show identifier information if available
            if let Some(ref identifier) = assembly_ref.identifier {
                match identifier {
                    dotscope::metadata::identity::Identity::PubKey(key) => {
                        println!("       PublicKey: {} bytes", key.len());
                    }
                    dotscope::metadata::identity::Identity::Token(token) => {
                        println!("       Token: {}", hex::encode(token));
                    }
                    dotscope::metadata::identity::Identity::EcmaKey(key) => {
                        println!("       EcmaKey: {} bytes", key.len());
                    }
                }
            }

            // Show hash information if available
            if assembly_ref.hash.is_some() {
                println!("       Hash: present");
            }
        }
        if assembly_refs.len() > 10 {
            println!(
                "    ... and {} more",
                assembly_refs.len().saturating_sub(10)
            );
        }
    }

    // Module references analysis using the correct public API
    let module_refs = assembly.refs_module();
    println!("  Module references: {}", module_refs.len());

    if !module_refs.is_empty() {
        println!("  Referenced modules:");
        for (i, entry) in module_refs.iter().take(10).enumerate() {
            let module_ref = entry.value();
            println!("    {}. {}", i.saturating_add(1), module_ref.name);
        }
        if module_refs.len() > 10 {
            println!("    ... and {} more", module_refs.len().saturating_sub(10));
        }
    }

    // Import analysis
    let imports = assembly.imports();
    println!("  Total imports: {}", imports.total_count());

    // Export analysis
    let exports = assembly.exports();
    println!("  Total exports: {}", exports.total_count());
}

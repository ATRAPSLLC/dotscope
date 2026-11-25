//! # Comprehensive .NET Assembly Analysis
//!
//! **What this example teaches:**
//! - Advanced assembly loading and metadata analysis techniques
//! - Type system exploration and signature parsing
//! - Method body analysis and instruction disassembly
//! - Import/export analysis and dependency tracking
//! - Performance-oriented memory-mapped file access patterns
//!
//! **When to use this pattern:**
//! - Building advanced analysis tools
//! - Comprehensive security assessments
//! - Research and reverse engineering workflows
//! - Learning all major dotscope capabilities
//!
//! **Prerequisites:**
//! - Completed basic.rs example
//! - Understanding of .NET metadata structures
//! - Familiarity with CIL instructions

use std::{env, path::Path};

use dotscope::prelude::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("comprehensive", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example demonstrates advanced dotscope capabilities:");
        eprintln!("  • Complete metadata analysis");
        eprintln!("  • Type system exploration");
        eprintln!("  • Method signature parsing");
        eprintln!("  • Import/export analysis");
        eprintln!("  • Instruction-level analysis");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("🔍 Advanced analysis of: {}", path.display());

    // Load assembly using the prelude's CilObject
    let assembly = CilObject::from_path(path)?;

    // Basic Assembly Information
    print_assembly_info(&assembly);

    // Type System Analysis
    print_type_analysis(&assembly);

    // Method Analysis with Signatures
    print_method_analysis(&assembly);

    // Import Analysis
    print_import_analysis(&assembly);

    // Instruction Analysis
    print_instruction_analysis(&assembly);

    println!("\n✨ Advanced analysis completed!");
    println!("The framework provided comprehensive access to:");
    println!("  • Core types (CilObject, Result, Error)");
    println!("  • Type system (CilType, TypeDef, etc.)");
    println!("  • Method analysis (Method, MethodBody, Signatures)");
    println!("  • Disassembler (Instruction, decode functions)");
    println!("  • Import/Export analysis");
    println!("  • All metadata streams and tables");

    Ok(())
}

fn print_assembly_info(assembly: &CilObject) {
    println!("\n📋 Assembly Information:");

    if let Some(asm_info) = assembly.assembly() {
        println!("  Name: {}", asm_info.name);
        println!(
            "  Version: {}.{}.{}.{}",
            asm_info.major_version,
            asm_info.minor_version,
            asm_info.build_number,
            asm_info.revision_number
        );
    }

    if let Some(module) = assembly.module() {
        println!("  Module: {}", module.name);
        println!("  MVID: {}", module.mvid);
    }

    println!("  Methods: {}", assembly.methods().len());
    println!("  Types: {}", assembly.types().len());
    // Note: Fields are accessed through individual types, not globally
}

fn print_type_analysis(assembly: &CilObject) {
    println!("\n🏗️  Type System Analysis:");

    let types = assembly.types();
    let mut namespaces = std::collections::HashMap::new();

    // Count types by namespace
    for type_def in types.all_types().iter().take(20) {
        let namespace = if type_def.namespace.is_empty() {
            "<global>"
        } else {
            &type_def.namespace
        };

        let entry = namespaces.entry(namespace.to_string()).or_insert(0u64);
        *entry = entry.saturating_add(1);
    }

    println!("  Top namespaces:");
    for (namespace, count) in namespaces.iter().take(5) {
        println!("    {namespace}: {count} types");
    }

    // Show a few interesting types
    println!("  Sample types:");
    for type_def in types.all_types().iter().take(5) {
        let full_name = if type_def.namespace.is_empty() {
            type_def.name.to_string()
        } else {
            format!("{}.{}", type_def.namespace, type_def.name)
        };
        println!(
            "    {} (Token: 0x{:08X})",
            full_name,
            type_def.token.value()
        );
    }
}

fn print_method_analysis(assembly: &CilObject) {
    println!("\n🔧 Method Analysis:");

    let methods = assembly.methods();
    let mut method_stats = MethodStats::default();

    for entry in methods.iter().take(10) {
        let method = entry.value();
        method_stats.total = method_stats.total.saturating_add(1);

        // Check if it's a static method (simplified check)
        if method.name.starts_with("op_") || method.name == ".cctor" {
            method_stats.static_methods = method_stats.static_methods.saturating_add(1);
        }

        if method.name.starts_with("get_") || method.name.starts_with("set_") {
            method_stats.properties = method_stats.properties.saturating_add(1);
        }

        println!(
            "    Method: {} (0x{:08X})",
            method.name,
            entry.key().value()
        );

        if let Some(body) = method.body.get() {
            method_stats.with_body = method_stats.with_body.saturating_add(1);

            println!(
                "      - IL size: {} bytes, Max stack: {}",
                body.size_code, body.max_stack
            );

            if body.local_var_sig_token != 0 {
                println!(
                    "      - Has local variables (token: 0x{:08X})",
                    body.local_var_sig_token
                );
            }

            if !body.exception_handlers.is_empty() {
                println!(
                    "      - Has {} exception handlers",
                    body.exception_handlers.len()
                );
            }
        }
    }

    println!("  Summary:");
    println!("    Total methods: {}", method_stats.total);
    println!("    With IL body: {}", method_stats.with_body);
    println!("    Static methods: {}", method_stats.static_methods);
    println!("    Property accessors: {}", method_stats.properties);
}

fn print_import_analysis(assembly: &CilObject) {
    println!("\n📦 Import Analysis:");

    let imports = assembly.imports();
    println!("  Total imports: {}", imports.total_count());

    if !imports.is_empty() {
        println!("  Sample imports:");

        // Now we can iterate over all imports!
        let mut method_imports: u64 = 0;
        let mut type_imports: u64 = 0;

        for entry in imports.cil().iter().take(10) {
            let (token, import) = (entry.key(), entry.value());

            match &import.import {
                dotscope::metadata::imports::ImportType::Method(_) => {
                    method_imports = method_imports.saturating_add(1u64);
                    if import.namespace.is_empty() {
                        println!(
                            "    Method: {} (Token: 0x{:08X})",
                            import.name,
                            token.value()
                        );
                    } else {
                        println!(
                            "    Method: {}.{} (Token: 0x{:08X})",
                            import.namespace,
                            import.name,
                            token.value()
                        );
                    }
                }
                dotscope::metadata::imports::ImportType::Type(_) => {
                    type_imports = type_imports.saturating_add(1u64);
                    if import.namespace.is_empty() {
                        println!("    Type: {} (Token: 0x{:08X})", import.name, token.value());
                    } else {
                        println!(
                            "    Type: {}.{} (Token: 0x{:08X})",
                            import.namespace,
                            import.name,
                            token.value()
                        );
                    }
                }
            }
        }

        if imports.total_count() > 10 {
            println!(
                "    ... and {} more imports",
                imports.total_count().saturating_sub(10)
            );
        }

        println!("  Import summary:");
        println!("    Method imports: {method_imports} (shown)");
        println!("    Type imports: {type_imports} (shown)");
    }

    println!("  Import analysis capabilities:");
    println!("    • Direct iteration: imports.iter()");
    println!("    • Lookup imports by name: imports.by_name(\"MethodName\")");
    println!("    • Lookup imports by namespace: imports.by_namespace(\"System.IO\")");
    println!("    • Get imports from specific modules: imports.from_module_ref(module)");
}

fn print_instruction_analysis(assembly: &CilObject) {
    println!("\n⚙️  Instruction Analysis:");

    // Find methods with IL to analyze
    let methods = assembly.methods();
    let mut instruction_count: usize = 0;
    let mut total_il_bytes: usize = 0;
    let mut methods_analyzed: u64 = 0;

    for entry in methods.iter().take(5) {
        let method = entry.value();

        if let Some(body) = method.body.get() {
            println!("    Analyzing method: {}", method.name);
            total_il_bytes = total_il_bytes.saturating_add(body.size_code);
            methods_analyzed = methods_analyzed.saturating_add(1u64);

            // Access basic blocks - they are automatically decoded when method is loaded
            let blocks: Vec<_> = method.blocks().collect();
            if !blocks.is_empty() {
                println!("      - {} basic blocks", blocks.len());
                println!("      - {} IL bytes", body.size_code);
                println!("      - Max stack: {}", body.max_stack);

                // Show first few instructions from first block
                if let Some((_, first_block)) = blocks.first() {
                    let inst_count = first_block.instructions.len();
                    instruction_count = instruction_count.saturating_add(inst_count);

                    println!("      - First block has {inst_count} instructions");
                    for (i, instruction) in first_block.instructions.iter().take(3).enumerate() {
                        println!(
                            "        [{}] {} (flow: {:?})",
                            i, instruction.mnemonic, instruction.flow_type
                        );
                    }
                    if first_block.instructions.len() > 3 {
                        println!(
                            "        ... and {} more instructions",
                            first_block.instructions.len().saturating_sub(3)
                        );
                    }
                }
            }
        }
    }

    println!("  Analysis summary:");
    println!("    Methods analyzed: {methods_analyzed}");
    println!("    Total IL bytes: {total_il_bytes}");
    println!("    Instructions decoded: {instruction_count}");
    println!("  Instruction analysis capabilities:");
    println!("    • Automatic basic block construction");
    println!("    • Control flow analysis");
    println!("    • Stack effect tracking");
    println!("    • Exception handler parsing");
}

#[derive(Default)]
struct MethodStats {
    total: usize,
    with_body: usize,
    static_methods: usize,
    properties: usize,
}

//! Analysis Viewer for .NET Assemblies
//!
//! This example demonstrates how to load a .NET assembly and display various
//! analysis results including disassembly, SSA form, control flow graphs, and call graphs.
//!
//! # Usage
//!
//! ```bash
//! # View disassembly of a method
//! cargo run --example analysis -- --file path/to/assembly.dll disasm --method "Main"
//!
//! # View SSA form of a method
//! cargo run --example analysis -- --file path/to/assembly.dll ssa --method "Main"
//!
//! # View SSA form with deobfuscation passes applied
//! cargo run --example analysis -- --file path/to/assembly.dll ssa --method "Main" --deobfuscate
//!
//! # View SSA form with lenient loading (continues on errors like custom attribute failures)
//! cargo run --example analysis -- --file path/to/assembly.dll --lenient ssa --method "Main" --deobfuscate
//!
//! # Export CFG in DOT format
//! cargo run --example analysis -- --file path/to/assembly.dll cfg --method "Main"
//!
//! # Export call graph in DOT format
//! cargo run --example analysis -- --file path/to/assembly.dll callgraph
//!
//! # List all methods in the assembly
//! cargo run --example analysis -- --file path/to/assembly.dll list
//! ```

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, Subcommand};
use dotscope::{
    analysis::{CallGraph, NodeId, SsaFunction},
    compiler::EventKind,
    deobfuscation::{DeobfuscationEngine, EngineConfig},
    metadata::{
        diagnostics::{DiagnosticSeverity, Diagnostics},
        method::MethodRc,
        token::Token,
    },
    project::ProjectLoader,
    CilObject, ValidationConfig,
};

#[derive(Parser)]
#[command(name = "analysis")]
#[command(about = "Analysis viewer for .NET assemblies", long_about = None)]
struct Cli {
    /// Path to the .NET assembly to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Additional search paths for dependencies (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Append)]
    search: Vec<PathBuf>,

    /// Enable lenient loading mode (continue on errors, log to diagnostics)
    #[arg(short, long)]
    lenient: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all methods in the assembly
    List,

    /// Show disassembly of a method
    Disasm {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,
    },

    /// Show SSA form of a method
    Ssa {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,

        /// Run deobfuscation passes on the SSA before displaying
        #[arg(short, long)]
        deobfuscate: bool,
    },

    /// Export control flow graph in DOT format
    Cfg {
        /// Method name (supports partial matching)
        #[arg(short, long, group = "target")]
        method: Option<String>,

        /// Method RVA in hex (e.g., 0x2050)
        #[arg(short, long, group = "target", value_parser = parse_hex)]
        rva: Option<u64>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export call graph in DOT format
    Callgraph {
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid hex number: {}", e))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    eprintln!("Loading assembly: {}", cli.file.display());
    if cli.lenient {
        eprintln!("Lenient mode enabled - will continue on errors");
    }

    // Build the project using ProjectLoader with appropriate validation config
    let validation_config = if cli.lenient {
        ValidationConfig::analysis()
    } else {
        ValidationConfig::minimal()
    };

    let mut loader = ProjectLoader::new()
        .primary_file(&cli.file)?
        .with_validation(validation_config);

    for path in &cli.search {
        eprintln!("Adding search path: {}", path.display());
        loader = loader.with_search_path(path)?;
    }

    loader = loader.auto_discover(true);
    let result = loader.build()?;

    if result.has_failures() {
        eprintln!("\nWarning: {} dependency problems", result.failure_count());
        for name in &result.missing_dependencies {
            eprintln!("  - {}: not found", name);
        }
        for (name, reason) in &result.failed_loads {
            eprintln!("  - {}: {}", name, reason);
        }
    }

    let primary = result
        .project
        .get_primary()
        .ok_or("Failed to get primary assembly")?;

    // Display loading diagnostics in lenient mode
    if cli.lenient {
        display_diagnostics(primary.diagnostics());
    }

    match cli.command {
        Command::List => list_methods(&primary),
        Command::Disasm { method, rva } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            display_disasm(&primary, &m)
        }
        Command::Ssa {
            method,
            rva,
            deobfuscate,
        } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            if deobfuscate {
                display_ssa_deobfuscated(&cli.file, &m, cli.lenient)
            } else {
                display_ssa_method(&primary, &m)
            }
        }
        Command::Cfg {
            method,
            rva,
            output,
        } => {
            let m = find_method(&primary, method.as_deref(), rva)?;
            display_cfg(&primary, &m, output.as_deref())
        }
        Command::Callgraph { output } => display_callgraph(&primary, output.as_deref()),
    }
}

fn display_diagnostics(diagnostics: &Arc<Diagnostics>) {
    if !diagnostics.has_any() {
        return;
    }

    eprintln!("\n=== Loading Diagnostics ===");
    let mut error_count: u64 = 0;
    let mut warning_count: u64 = 0;
    let mut info_count: u64 = 0;

    for entry in diagnostics.iter() {
        let prefix = match entry.severity {
            DiagnosticSeverity::Error => {
                error_count = error_count.saturating_add(1);
                "ERROR"
            }
            DiagnosticSeverity::Warning => {
                warning_count = warning_count.saturating_add(1);
                "WARNING"
            }
            DiagnosticSeverity::Info => {
                info_count = info_count.saturating_add(1);
                "INFO"
            }
        };

        eprintln!("  [{}] {:?}: {}", prefix, entry.category, entry.message);
        if let Some(token) = entry.token {
            eprintln!("         Token: 0x{:08X}", token);
        }
        if let Some(offset) = entry.offset {
            eprintln!("         Offset: 0x{:X}", offset);
        }
    }

    eprintln!(
        "\nSummary: {} errors, {} warnings, {} info",
        error_count, warning_count, info_count
    );
    eprintln!();
}

fn find_method(
    assembly: &Arc<CilObject>,
    name: Option<&str>,
    rva: Option<u64>,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    match (name, rva) {
        (Some(n), _) => find_method_by_name(assembly, n),
        (_, Some(r)) => find_method_by_rva(assembly, r),
        (None, None) => Err("Must specify --method or --rva".into()),
    }
}

fn list_methods(assembly: &CilObject) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Methods in Assembly ===\n");

    let methods = assembly.methods();
    let mut count: u64 = 0;

    for entry in methods {
        let method = entry.value();
        if let Some(rva) = method.rva {
            if rva > 0 {
                let type_name = get_method_type_name(assembly, method.token);
                println!("  0x{:08X}  {}::{}", rva, type_name, method.name);
                count = count.saturating_add(1);
            }
        }
    }

    println!("\nTotal: {} methods with bodies", count);
    Ok(())
}

fn get_method_type_name(assembly: &CilObject, method_token: Token) -> String {
    assembly
        .types()
        .iter()
        .find(|t| {
            t.value().methods.iter().any(|(_, m)| {
                m.upgrade()
                    .map(|m| m.token == method_token)
                    .unwrap_or(false)
            })
        })
        .map(|t| {
            let ty = t.value();
            if ty.namespace.is_empty() {
                ty.name.to_string()
            } else {
                format!("{}.{}", ty.namespace, ty.name)
            }
        })
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn find_method_by_name(
    assembly: &CilObject,
    name: &str,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    let methods = assembly.methods();
    let mut matches = Vec::new();

    for entry in methods {
        let method = entry.value();

        if method.rva.is_none() || method.rva == Some(0) {
            continue;
        }

        let type_name = get_method_type_name(assembly, method.token);
        let full_name = format!("{}::{}", type_name, method.name);

        if full_name == name || method.name == name {
            return Ok(method.clone());
        }
        if full_name.contains(name) || method.name.contains(name) {
            matches.push((full_name, method.clone()));
        }
    }

    match matches.len() {
        0 => Err(format!("No method found matching '{}'", name).into()),
        1 => match matches.into_iter().next() {
            Some((_, method)) => Ok(method),
            None => Err("Internal error: no matches after len() == 1".into()),
        },
        _ => {
            eprintln!("Multiple methods match '{}':", name);
            for (i, (full_name, method)) in matches.iter().enumerate() {
                eprintln!(
                    "  {}. {} (RVA: 0x{:08X})",
                    i.saturating_add(1),
                    full_name,
                    method.rva.unwrap_or(0)
                );
            }
            Err("Please be more specific".into())
        }
    }
}

fn find_method_by_rva(
    assembly: &CilObject,
    rva: u64,
) -> Result<MethodRc, Box<dyn std::error::Error>> {
    for entry in assembly.methods() {
        let method = entry.value();
        if method.rva == Some(rva as u32) {
            return Ok(method.clone());
        }
    }
    Err(format!("No method found at RVA 0x{:08X}", rva).into())
}

fn display_disasm(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let rva = method.rva.unwrap_or(0);
    let num_args = (method.signature.param_count as usize)
        .saturating_add(usize::from(method.signature.has_this));
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    let cfg = method
        .cfg()
        .ok_or("Method has no decoded blocks or CFG construction failed")?;

    println!("\n--- Disassembly ---");
    for block_idx in 0..cfg.block_count() {
        if let Some(block) = cfg.block(NodeId::new(block_idx)) {
            println!("\nB{}: (RVA 0x{:08X})", block_idx, block.rva);
            for instr in &block.instructions {
                print!("  {:08X}: {:12}", instr.rva, instr.mnemonic);
                match &instr.operand {
                    dotscope::assembly::Operand::None => {}
                    op => print!(" {:?}", op),
                }
                if !instr.branch_targets.is_empty() {
                    print!(" -> {:?}", instr.branch_targets);
                }
                println!();
            }
        }
    }

    Ok(())
}

fn display_ssa_method(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let rva = method.rva.unwrap_or(0);
    let num_args = (method.signature.param_count as usize)
        .saturating_add(usize::from(method.signature.has_this));
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    // Use method.ssa() which properly sets up TypeContext with the assembly
    // for correct method signature resolution in call instructions
    match method.ssa(assembly) {
        Ok(ssa) => {
            println!("\n--- SSA Form ---");
            display_ssa(&ssa);
        }
        Err(e) => {
            println!("\n--- SSA Form ---");
            println!("Failed to build SSA: {e}");
        }
    }

    Ok(())
}

fn display_ssa_deobfuscated(
    file_path: &Path,
    method: &MethodRc,
    lenient: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load a fresh copy of the assembly for deobfuscation
    // (process_method requires ownership as it may modify the assembly)
    let assembly = if lenient {
        CilObject::from_path_with_validation(file_path, ValidationConfig::analysis())?
    } else {
        CilObject::from_path(file_path)?
    };
    let type_name = get_method_type_name(&assembly, method.token);
    let rva = method.rva.unwrap_or(0);
    let num_args = (method.signature.param_count as usize)
        .saturating_add(usize::from(method.signature.has_this));
    let num_locals = method.local_vars.count();

    println!("\n{}", "=".repeat(80));
    println!("Method: {}::{}", type_name, method.name);
    println!("RVA: 0x{:08X} | Token: {:?}", rva, method.token);
    println!("Arguments: {} | Locals: {}", num_args, num_locals);
    println!("{}", "=".repeat(80));

    // Show original SSA first
    let original_ssa = method.ssa(&assembly)?;

    println!("\n--- Original SSA Form ---");
    display_ssa(&original_ssa);

    // Run deobfuscation using the engine
    println!("\n{}", "=".repeat(80));
    println!("Running deobfuscation passes...");
    println!("{}", "=".repeat(80));

    let config = EngineConfig::default();
    let engine = DeobfuscationEngine::new(config);

    let (deobfuscated_ssa, result) = engine.process_method(assembly, method.token)?;

    println!("\n--- Deobfuscated SSA Form ---");
    display_ssa(&deobfuscated_ssa);

    // Display summary
    println!("\n{}", "-".repeat(40));
    println!("Deobfuscation Summary:");
    println!("  Iterations: {}", result.iterations);
    println!("  Total time: {:?}", result.total_time);
    println!("  Total events: {}", result.events.len());

    let counts = result.events.count_by_kind();
    if let Some(&count) = counts.get(&EventKind::ConstantFolded) {
        println!("  Constants folded: {}", count);
    }
    if let Some(&count) = counts.get(&EventKind::InstructionRemoved) {
        println!("  Instructions removed: {}", count);
    }
    if let Some(&count) = counts.get(&EventKind::BranchSimplified) {
        println!("  Branches simplified: {}", count);
    }
    if let Some(&count) = counts.get(&EventKind::PhiSimplified) {
        println!("  Phi nodes simplified: {}", count);
    }
    if let Some(&count) = counts.get(&EventKind::ControlFlowRestructured) {
        println!("  Control flow restructured: {}", count);
    }

    // Show detection results if any
    if let Some(attr) = &result.attribution {
        println!("\n  Detected obfuscator:");
        println!(
            "    - {} ({} techniques, {} supporting)",
            attr.obfuscator_name,
            attr.technique_ids.len(),
            attr.supporting_matched
        );
    }

    Ok(())
}

fn display_ssa(ssa: &SsaFunction) {
    println!(
        "Variables: {} | Blocks: {} | Phi nodes: {}",
        ssa.variable_count(),
        ssa.block_count(),
        ssa.phi_count()
    );

    println!("\nVariables:");
    for var in ssa.variables() {
        println!(
            "  {} : {:?} v{} @ {:?}",
            var.id(),
            var.origin(),
            var.version(),
            var.def_site()
        );
    }

    println!();

    for block in ssa.blocks() {
        println!("B{}:", block.id());
        for phi in block.phi_nodes() {
            println!("  {}", phi);
        }
        for instr in block.instructions() {
            println!("    {}", instr);
        }
        println!();
    }
}

fn display_cfg(
    assembly: &Arc<CilObject>,
    method: &MethodRc,
    output_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_name = get_method_type_name(assembly, method.token);
    let cfg = method
        .cfg()
        .ok_or("Method has no decoded blocks or CFG construction failed")?;

    let dot = cfg.to_dot(Some(&format!("{}::{}", type_name, method.name)));

    if let Some(path) = output_file {
        std::fs::write(path, &dot)?;
        eprintln!("CFG written to: {}", path.display());
    } else {
        println!("{}", dot);
    }

    Ok(())
}

fn display_callgraph(
    assembly: &Arc<CilObject>,
    output_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Building call graph...");

    // Try to build from entry point first (cleaner graph for executables)
    // Fall back to full graph for libraries
    let callgraph = if let Some(cg) = CallGraph::build_from_entrypoint(assembly)? {
        eprintln!("Built from entry point (reachable methods only)");
        cg
    } else {
        eprintln!("No entry point found, building full call graph");
        CallGraph::build(assembly)?
    };

    let stats = callgraph.stats();
    eprintln!(
        "Call graph: {} methods, {} edges, {} call sites",
        stats.method_count, stats.edge_count, stats.total_call_sites
    );

    let dot = callgraph.to_dot(None);

    if let Some(path) = output_file {
        std::fs::write(path, &dot)?;
        eprintln!("Call graph written to: {}", path.display());
    } else {
        println!("{}", dot);
    }

    Ok(())
}

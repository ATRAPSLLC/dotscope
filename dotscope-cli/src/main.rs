mod app;
mod commands;
mod output;

use clap::Parser;

use crate::app::{Cli, Command};

fn main() -> anyhow::Result<()> {
    ctrlc::set_handler(|| {
        eprintln!("\nCancelled.");
        std::process::exit(130);
    })
    .expect("failed to set Ctrl+C handler");

    let cli = Cli::parse();

    // Show dotscope info+ on stderr unless --json; --verbose enables debug; RUST_LOG overrides
    if !cli.global.json {
        let level = if cli.global.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };
        env_logger::Builder::new()
            .filter_module("dotscope", level)
            .parse_default_env()
            .target(env_logger::Target::Stderr)
            .format_timestamp(None)
            .format_module_path(false)
            .format_target(false)
            .init();
    }

    match &cli.command {
        Command::Info { path } => commands::info::run(path, &cli.global),
        Command::Validate { path, level } => commands::validate::run(path, level, &cli.global),
        Command::Attrs { path, owner } => commands::attrs::run(path, owner.as_deref(), &cli.global),
        Command::Tables { path, table } => {
            commands::tables::run(path, table.as_deref(), &cli.global)
        }
        Command::Heaps { path, heap, offset } => {
            commands::heaps::run(path, heap.as_deref(), offset.as_deref(), &cli.global)
        }
        Command::Types {
            path,
            namespace,
            public_only,
        } => commands::types::run(path, namespace.as_deref(), *public_only, &cli.global),
        Command::Methods {
            path,
            r#type,
            signatures,
            group,
        } => commands::methods::run(path, r#type.as_deref(), *signatures, *group, &cli.global),
        Command::Disasm {
            path,
            method,
            r#type,
            bytes,
            tokens,
            no_offsets,
            no_header,
            raw,
            deobfuscate,
        } => commands::disasm::run(
            path,
            method.as_deref(),
            r#type.as_deref(),
            commands::disasm::DisasmOptions {
                show_bytes: *bytes,
                show_tokens: *tokens,
                show_offsets: !*no_offsets,
                no_header: *no_header,
                raw: *raw,
                ..Default::default()
            },
            *deobfuscate,
        ),
        Command::Cfg {
            path,
            method,
            format,
            loops,
        } => commands::cfg::run(path, method, format, *loops),
        Command::Callgraph {
            path,
            format,
            root,
            depth,
        } => commands::callgraph::run(path, format, root.as_deref(), *depth),
        Command::Ssa {
            path,
            method,
            show_phis,
            show_types,
        } => commands::ssa::run(path, method, *show_phis, *show_types),
        Command::Imports { path } => commands::imports::run(path, &cli.global),
        Command::Exports { path } => commands::exports::run(path, &cli.global),
        Command::Resources {
            path,
            extract,
            output_dir,
            name,
        } => commands::resources::run(
            path,
            *extract,
            output_dir.as_deref(),
            name.as_deref(),
            &cli.global,
        ),
        Command::Detect { path, recursive } => commands::detect::run(path, *recursive, &cli.global),
        Command::Deobfuscate {
            path,
            output,
            suffix,
            recursive,
            max_iterations,
            max_instructions,
            no_cleanup,
            aggressive,
            detailed,
            report,
        } => commands::deobfuscate::run(
            path,
            &commands::deobfuscate::DeobfuscateOptions {
                output: output.as_deref(),
                suffix,
                recursive: *recursive,
                max_iterations: *max_iterations,
                max_instructions: *max_instructions,
                no_cleanup: *no_cleanup,
                aggressive: *aggressive,
                detailed: *detailed,
                report: report.as_deref(),
                global: &cli.global,
            },
        ),
    }
}

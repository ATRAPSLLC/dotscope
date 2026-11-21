use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// dotscope - .NET assembly analysis, inspection, and deobfuscation
#[derive(Debug, Parser)]
#[command(name = "dotscope", version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: Command,
}

/// Options shared across all subcommands.
#[derive(Debug, Parser)]
pub struct GlobalOptions {
    /// Emit output as JSON instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Enable verbose (debug-level) logging output.
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Display assembly overview: name, version, runtime, entry point, and counts.
    Info {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },

    /// Validate assembly metadata at a chosen strictness level.
    Validate {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Validation level: minimal, production, comprehensive, or strict.
        #[arg(short, long, default_value = "production")]
        level: String,
    },

    /// List metadata tables and row counts.
    Tables {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Show only a specific table (e.g., TypeDef, MethodDef).
        #[arg(short, long)]
        table: Option<String>,
    },

    /// Dump metadata heaps (strings, blob, guid, userstrings).
    Heaps {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Dump a specific heap: strings, blob, guid, userstrings.
        #[arg(long)]
        heap: Option<String>,

        /// Fetch a specific entry by offset (hex like 0x1a or decimal). Requires --heap.
        #[arg(long, value_name = "OFFSET")]
        offset: Option<String>,
    },

    /// List decoded custom attributes grouped by owner.
    Attrs {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Filter by owner token (e.g., 0x02000001) or name substring.
        #[arg(long, value_name = "TOKEN|NAME")]
        owner: Option<String>,
    },

    /// List type definitions.
    Types {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Filter by namespace.
        #[arg(long)]
        namespace: Option<String>,

        /// Show only public types.
        #[arg(long)]
        public_only: bool,
    },

    /// List method definitions.
    Methods {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Filter by parent type name.
        #[arg(long, value_name = "NAME")]
        r#type: Option<String>,

        /// Show full method signatures.
        #[arg(long)]
        signatures: bool,

        /// Group methods by declaring type.
        #[arg(long)]
        group: bool,
    },

    /// List assembly imports (TypeRef, MemberRef, native P/Invoke).
    Imports {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },

    /// List exported types and native PE exports.
    Exports {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },

    /// Disassemble CIL instructions (ildasm-style output).
    Disasm {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Disassemble specific method(s) by token or name.
        #[arg(long, value_name = "TOKEN|NAME")]
        method: Option<String>,

        /// Disassemble all methods of a type by token or name.
        #[arg(long, value_name = "TOKEN|NAME")]
        r#type: Option<String>,

        /// Show raw IL bytes alongside instructions.
        #[arg(long)]
        bytes: bool,

        /// Show metadata tokens inline with instructions.
        #[arg(long)]
        tokens: bool,

        /// Hide IL offsets (shown by default).
        #[arg(long)]
        no_offsets: bool,

        /// Omit assembly/module header directives.
        #[arg(long)]
        no_header: bool,

        /// Minimal output (IL only, no decoration).
        #[arg(long)]
        raw: bool,

        /// In-memory deobfuscation before disassembly.
        #[arg(long)]
        deobfuscate: bool,
    },

    /// Display control flow graph for a method.
    Cfg {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Method to analyze (token like 0x06000001 or name like Program::Main).
        #[arg(long, value_name = "TOKEN|NAME")]
        method: String,

        /// Output format: text, dot, json.
        #[arg(long, default_value = "text")]
        format: String,

        /// Include loop analysis information.
        #[arg(long)]
        loops: bool,
    },

    /// Display inter-procedural call graph.
    Callgraph {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Output format: text, dot, json.
        #[arg(long, default_value = "text")]
        format: String,

        /// Root method for subtree (token or name). Without this, shows full graph.
        #[arg(long, value_name = "TOKEN|NAME")]
        root: Option<String>,

        /// Maximum call depth from root.
        #[arg(long)]
        depth: Option<usize>,
    },

    /// Display SSA form of a method.
    Ssa {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Method to analyze (token or name).
        #[arg(long, value_name = "TOKEN|NAME")]
        method: String,

        /// Show phi nodes (included by default; use to re-enable after filtering).
        #[arg(long)]
        show_phis: bool,

        /// Show type information on variables.
        #[arg(long)]
        show_types: bool,
    },

    /// List or extract embedded resources.
    Resources {
        /// Path to the .NET assembly file.
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Extract resources to files.
        #[arg(long)]
        extract: bool,

        /// Output directory for extraction (default: current dir).
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,

        /// Extract only a specific named resource.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },

    /// Identify obfuscator without modifying the assembly.
    Detect {
        /// Path to the .NET assembly file (or directory with --recursive).
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Recursively scan directory for .exe/.dll files.
        #[arg(long)]
        recursive: bool,
    },

    /// Deobfuscate a .NET assembly.
    Deobfuscate {
        /// Path to the .NET assembly file (or directory with --recursive).
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Output file or directory.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Output filename suffix (default: "_deobfuscated").
        #[arg(long, default_value = "_deobfuscated")]
        suffix: String,

        /// Recursively process directory for .exe/.dll files.
        #[arg(long)]
        recursive: bool,

        /// Maximum optimization iterations.
        #[arg(long)]
        max_iterations: Option<usize>,

        /// Emulation instruction limit.
        #[arg(long)]
        max_instructions: Option<u64>,

        /// Don't remove obfuscator artifacts.
        #[arg(long)]
        no_cleanup: bool,

        /// Use aggressive optimization (inlining, unused method removal).
        #[arg(long)]
        aggressive: bool,

        /// Show detailed findings (individual tokens, methods, etc.).
        #[arg(long)]
        detailed: bool,

        /// Write detailed JSON report.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
    },
}

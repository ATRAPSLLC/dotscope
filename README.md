# dotscope

[![Crates.io](https://img.shields.io/crates/v/dotscope.svg)](https://crates.io/crates/dotscope)
[![Documentation](https://docs.rs/dotscope/badge.svg)](https://docs.rs/dotscope)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Build Status](https://github.com/ATRAPSLLC/dotscope/workflows/CI/badge.svg)](https://github.com/ATRAPSLLC/dotscope/actions)
[![Coverage](https://codecov.io/gh/ATRAPSLLC/dotscope/branch/main/graph/badge.svg)](https://codecov.io/gh/ATRAPSLLC/dotscope)

A high-performance, cross-platform framework for analyzing, reverse engineering, and modifying .NET PE executables. Built in pure Rust, `dotscope` provides comprehensive tooling for parsing CIL (Common Intermediate Language) bytecode, metadata structures, disassembling .NET assemblies, and creating modified assemblies without requiring Windows or the .NET runtime.

## Features

- **Efficient memory access** - Memory-mapped file access with minimal allocations and reference-based parsing
- **Complete metadata analysis** - Parse all ECMA-335 metadata tables and streams
- **Assembly modification** - Edit metadata tables, heaps, and PE structures with validation and integrity checking
- **Method injection** - Add new methods, classes, and metadata to existing assemblies with high-level builders
- **High-performance disassembly** - Fast CIL instruction decoding with control flow analysis
- **CIL encoding** - Generate CIL bytecode with label-based exception handling for method modification
- **Native PE operations** - Manage imports, exports, and native interoperability features
- **Cross-platform** - Works on Windows, Linux, macOS, and any Rust-supported platform
- **Memory safe** - Built in Rust with comprehensive error handling and fuzzing
- **Rich type system** - Full support for generics, signatures, and complex .NET types
- **Static analysis** - SSA form, control flow graphs, data flow analysis, call graphs, and loop detection
- **Deobfuscation** - 30 optimization passes, 35 techniques with ConfuserEx, BitMono, JIEJIE.NET, and Obfuscar support, string decryption, control flow recovery
- **CIL emulation** - Full bytecode interpreter with 600+ BCL stubs for runtime value computation
- **Extensible architecture** - Modular design for custom analysis and tooling

## Quick Start

Add `dotscope` to your `Cargo.toml`:

```toml
[dependencies]
dotscope = "0.10"
```

### Raw Access Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly for raw access
    let view = CilAssemblyView::from_path("MyAssembly.dll".as_ref())?;
    
    // Direct access to metadata tables
    if let Some(tables) = view.tables() {
        let typedef_count = tables.table_row_count(TableId::TypeDef);
        println!("TypeDef rows: {}", typedef_count);
    }
    
    // Direct heap access
    if let Some(strings) = view.strings() {
        for (index, string) in strings.iter().take(5) {
            println!("String {}: {}", index, string);
        }
    }
    
    Ok(())
}
```

### Analysis Example

```rust
use dotscope::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load assembly for high-level analysis
    let assembly = CilObject::from_path("MyAssembly.dll".as_ref())?;
    
    // Access resolved information
    if let Some(module) = assembly.module() {
        println!("Module: {}", module.name);
    }
    
    // Iterate through resolved methods with type information
    let methods = assembly.methods();
    println!("Found {} methods", methods.len());
    
    // Examine resolved imports and exports
    let imports = assembly.imports();
    let exports = assembly.exports();
    println!("Imports: {}, Exports: {}", imports.len(), exports.len());
    
    Ok(())
}
```

### Assembly Modification Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly for modification
    let view = CilAssemblyView::from_path("input.dll".as_ref())?;
    let mut assembly = CilAssembly::new(view);
    
    // Add strings to metadata heaps
    let string_index = assembly.string_add("Hello from dotscope!")?;
    let user_string_index = assembly.userstring_add("Modified assembly")?;
    
    // Add native imports
    assembly.add_native_import_dll("kernel32.dll")?;
    assembly.add_native_import_function("kernel32.dll", "GetProcessId")?;

    // Write modified assembly
    assembly.to_file("output.dll")?;

    Ok(())
}
```

### Method Builder Example

```rust
use dotscope::prelude::*;

fn main() -> dotscope::Result<()> {
    // Load assembly for modification
    let view = CilAssemblyView::from_path("input.dll".as_ref())?;
    let mut assembly = CilAssembly::new(view);

    // Add a user string
    let msg_index = assembly.userstring_add("Hello World!")?;
    let msg_token = Token::new(0x70000000 | msg_index);

    // Create method with CIL instructions
    let method_token = MethodBuilder::new("MyNewMethod")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(|body| {
            body.implementation(|asm| {
                asm.ldstr(msg_token)?
                    .pop()?  // Simple example: load string then pop it
                    .ret()
            })
        })
        .build(&mut assembly)?;

    // Save the modified assembly
    assembly.to_file("output.dll")?;

    Ok(())
}
```

### Project Loader Example

```rust
use dotscope::project::ProjectLoader;

fn main() -> dotscope::Result<()> {
    // Load assembly with automatic dependency resolution
    let result = ProjectLoader::new()
        .primary_file("MyApp.exe")?
        .with_search_path("/usr/lib/mono/4.5")?
        .auto_discover(true)
        .build()?;

    println!("Loaded {} assemblies", result.success_count());

    // Access the project with all loaded assemblies
    let project = &result.project;

    // Get the primary assembly
    if let Some(primary) = project.get_primary() {
        println!("Types: {}", primary.types().len());
        println!("Methods: {}", primary.methods().len());
    }

    // Cross-assembly type lookup
    if let Some(string_type) = project.get_type_by_name("System.String") {
        println!("Found System.String with {} methods", string_type.methods.count());
    }

    // Find type definitions across all assemblies
    let object_types = project.find_type_definitions("Object");
    println!("Found {} types matching 'Object'", object_types.len());

    Ok(())
}
```

## Documentation

- **[API Documentation](https://docs.rs/dotscope)** - Complete API reference
- **[Examples](examples/)** - Working examples for common use cases
- **[Obfuscator Research](docs/research/main.md)** - Detailed analysis of supported obfuscators and their protection techniques
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project
- **[Security Policy](SECURITY.md)** - Security reporting and policy

## Architecture

`dotscope` is organized into several key modules:

### Core Components

- **[`prelude`]** - Convenient re-exports of commonly used types
- **[`metadata`]** - Complete ECMA-335 metadata parsing and type system
- **[`cilassembly`]** - Assembly modification with copy-on-write semantics and high-level builders
- **[`assembly`]** - CIL instruction encoding/decoding, control flow analysis, and method body construction
- **[`Error`] and [`Result`]** - Comprehensive error handling

### Raw Access (`CilAssemblyView`)

Low-level access to assembly structures provides:

- **Direct PE parsing**: Raw access to PE headers, sections, and data directories
- **Metadata streams**: Direct heap access without object resolution
- **Table iteration**: Raw table row access with manual index resolution
- **Memory-mapped data**: Efficient access to assembly contents
- **Foundation layer**: Base for both analysis and modification operations

### Analysis (`CilObject`)

High-level analysis with resolved objects provides:

- **Resolved references**: Automatic cross-reference resolution and object graphs
- **Type system**: Rich representation of .NET types, generics, and inheritance
- **Method bodies**: Parsed IL instructions with operand resolution
- **Import/export analysis**: Resolved dependency and export information
- **Convenience APIs**: Easy-to-use interfaces for common analysis tasks

### Modification (`CilAssembly`)

Mutable assembly editing provides:

- **Heap operations**: Add, update, remove items from all metadata heaps
- **Table operations**: Add, update, delete metadata table rows with validation
- **PE operations**: Manage native imports, exports, and forwarders
- **Builder APIs**: High-level builders for adding classes, methods, properties, events, and enums to existing assemblies
- **CIL Generation**: Full CIL instruction encoding with label resolution and exception handling for method modification
- **Validation**: Comprehensive integrity checking and reference resolution

### Assembly Engine

The assembly module provides comprehensive CIL processing:

**Decoding & Analysis:**

- **Instruction Decoding**: Parse individual CIL opcodes with full operand support
- **Control Flow Analysis**: Build basic blocks and control flow graphs
- **Stack Analysis**: Track stack effects and type flow
- **Exception Handling**: Parse and analyze try/catch/finally regions

**Encoding & Generation:**

- **Instruction Encoding**: Generate CIL bytecode from high-level instructions
- **Label Resolution**: Automatic branch target and exception handler resolution
- **Method Body Construction**: Build complete method bodies with local variables and exception handling
- **Assembly Modification**: Fluent API for adding new components to existing .NET assemblies

### Analysis (`analysis`)

Static program analysis infrastructure for .NET methods:

- **SSA Construction**: Cytron et al. algorithm with dominance frontiers and phi insertion
- **Control Flow Graphs**: Dominator trees, loops, back-edge detection, and post-dominators
- **Data Flow Framework**: SCCP, liveness analysis, reaching definitions with generic fixpoint solver
- **Call Graph**: Inter-procedural call relationships with virtual dispatch resolution via CHA
- **Algebraic Simplification**: Expression canonicalization and constant folding
- **Range Analysis**: Value range tracking for integer variables
- **Taint Analysis**: Track data flow from sources to sinks

### Deobfuscation (`deobfuscation`)

SSA-based deobfuscation engine for protected .NET assemblies:

- **Pass Pipeline**: 4-phase scheduler (normalize, optimize, deobfuscate, finalize) with fixpoint iteration
- **30 Transformation Passes**: Constant propagation, copy propagation, GVN, dead code elimination, control flow unflattening, opaque predicate removal, strength reduction, algebraic simplification, block merging, loop canonicalization, LICM, jump threading, inlining, delegate proxy resolution, typeof/array/resource restoration, and more
- **35 Detection Techniques**: Technique-based detection with extensible registry
- **ConfuserEx Support**: Anti-tamper, anti-debug, anti-dump, constants, control flow, resources, reference proxy, marker removal
- **BitMono Support**: Anti-debug, hooks, junk code, call-to-calli, string encryption, unmanaged strings, PE repair, renaming
- **JIEJIE.NET Support**: Control flow flattening, string encryption, constant encoding, resource encryption, typeof obfuscation, array initialization, symbol renaming
- **Obfuscar Support**: String hiding (XOR decryption), symbol renaming, SuppressIldasm removal
- **Code Generation**: SSA-to-CIL conversion with register coalescing and phi elimination
- **Decryption**: Emulation-based string and constant decryption

### Emulation (`emulation`)

CIL bytecode interpreter for controlled .NET code execution:

- **Interpreter**: Supports 213 CIL opcodes with full operand handling
- **Memory Model**: Copy-on-write address space with heap, statics, and mapped regions
- **BCL Stubs**: 600+ method stubs for Math, String, Array, Convert, Crypto, IO, Reflection, Collections, and more
- **Hook System**: Pre/post method interception with flexible matching criteria
- **Exception Handling**: Try/catch/finally with stack unwinding and synthetic exception hierarchy
- **Process Builder**: Configurable execution with instruction, call depth, and memory limits
- **Generic Instantiation**: Runtime generic type/method instantiation with deduplication
- **Interface Dispatch**: IMT-based interface method resolution with VTable caching

## Examples

Check out the [examples](examples/) directory for complete working examples with comprehensive documentation:

- **[Basic Usage](examples/basic.rs)** - Start here! Simple assembly loading and inspection with error handling
- **[Assembly Modification](examples/modify.rs)** - Complete guide to editing assemblies with heap and table operations
- **[Metadata Analysis](examples/metadata.rs)** - Deep dive into assembly metadata and dependency tracking
- **[Disassembly](examples/disassembly.rs)** - CIL instruction disassembly and method body analysis
- **[Type System](examples/types.rs)** - Working with .NET types, generics, and inheritance
- **[Comprehensive Analysis](examples/comprehensive.rs)** - Full-featured analysis combining all capabilities
- **[Method Analysis](examples/method_analysis.rs)** - Exhaustive single-method inspection
- **[Low-Level API](examples/lowlevel.rs)** - Understanding dotscope internals and raw parsing
- **[Control Flow](examples/decode_blocks.rs)** - Basic block construction and flow analysis
- **[Code Injection](examples/injectcode.rs)** - Injecting new methods into existing assemblies with MethodBuilder
- **[Raw Assembly View](examples/raw_assembly_view.rs)** - Direct access to PE headers, metadata streams, and heaps
- **[Project Loader](examples/project_loader.rs)** - Loading assemblies with automatic dependency resolution
- **[Analysis](examples/analysis.rs)** - View SSA form, disassembly, control flow graphs, and call graphs
- **[Deobfuscation](examples/deobfuscate.rs)** - CLI tool for deobfuscating .NET assemblies with ConfuserEx, BitMono, JIEJIE.NET, and Obfuscar support

Each example includes detailed documentation explaining:

- **What it teaches** - Key learning objectives and concepts
- **When to use** - Practical applications and use cases  
- **Prerequisites** - Required background knowledge
- **API patterns** - Consistent, production-ready code examples

See the [examples README](examples/README.md) for a recommended learning path.

## Use Cases

`dotscope` is perfect for:

- **Reverse Engineering**: Analyze .NET malware and vulnerable software
- **Security Research**: Find vulnerabilities and security issues
- **Assembly Patching**: Modify assemblies for instrumentation, hooking, or enhancement
- **Code Analysis**: Static analysis and quality metrics
- **Decompilation**: Build decompilers and analysis tools
- **Development Tools**: Create assembly editors, analyzers, and build tools
- **Educational**: Learn about .NET internals and PE format
- **Deobfuscation**: Remove obfuscation from protected .NET assemblies
- **Forensics**: Examine .NET assemblies in digital forensics

## Security

Security is a top priority:

- **Memory Safety**: Built on Rust's memory safety guarantees
- **Fuzzing**: `cargo-fuzz` targets run on demand (`make fuzz`), with a committed crash corpus replayed by the test suite
- **Input Validation**: Strict validation of all inputs
- **Audit Trail**: Regular dependency auditing

See our [Security Policy](SECURITY.md) for more information.

## Standards Compliance

`dotscope` implements the **ECMA-335 specification** (6th edition) for the Common Language Infrastructure. All metadata structures, CIL instructions, and type system features conform to this standard.

### References

- [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Official CLI specification
- [.NET Runtime](https://github.com/dotnet/runtime) - Microsoft's reference implementation

## Testing and Quality

We maintain high code quality through:

- **Comprehensive Test Suite**: Unit, integration, and fuzz testing
- **Continuous Integration**: Automated testing on multiple platforms
- **Code Coverage**: >90% test coverage target
- **Static Analysis**: Clippy, rustfmt, and audits
- **Performance Testing**: Regular benchmarking and regression detection

### Running Tests

```bash
# Development cycle (recommended for frequent use)
make dev              # Format, lint, and test

# Full CI simulation
make ci               # Complete CI checks

# Security and quality
make audit            # Security audit
make coverage         # Generate coverage report
```

### Extended Testing

```bash
# Local fuzzing (60 seconds)
make fuzz

# Extended fuzzing (manual)
cd dotscope/fuzz && cargo +nightly fuzz run cilobject --release -- -max_total_time=1800

# All quality checks
make check-all
```

## Future Features

We're continuously working to improve `dotscope`. Here are features planned for the future:

### Core Improvements

- Protections against large allocations from maliciously crafted files
- Assembly linking and merging
- Store and load full Assembly to/from JSON
- Non-embedded resource support

### Advanced Analysis

- Expression-based opaque predicate solving
- VM devirtualization for virtualized obfuscators
- Additional obfuscator support

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Checklist

- Check existing issues and PRs
- Write tests for new features
- Update documentation
- Ensure CI passes
- Follow commit message conventions

## License

Copyright 2025-2026 ATRAPS LLC. This project is licensed under the Apache
License, Version 2.0.

See [LICENSE](LICENSE), [NOTICE](NOTICE), or
<http://www.apache.org/licenses/LICENSE-2.0> for details.

### Responsible Use Policy

`dotscope` is developed and provided exclusively for the following purposes:

- **Security research** - Analyzing malware, vulnerabilities, and security threats
- **Malware analysis** - Reverse engineering malicious software for defensive purposes
- **Educational use** - Learning about .NET internals, CIL, and PE structures
- **Defensive tooling** - Building security tools and protective measures

**Prohibited use**: You may not use `dotscope` to analyze, deobfuscate, reverse engineer, or modify software that is protected by intellectual property rights (including but not limited to commercial software, proprietary applications, or any software where such analysis would violate the software's license terms or applicable law) unless you have explicit authorization from the rights holder or such use is permitted by applicable law.

**Disclaimer of responsibility**: The author(s) and contributor(s) of `dotscope` are not responsible for how users choose to use this software. Users are solely responsible for ensuring that their use of `dotscope` complies with all applicable laws, regulations, and license agreements. By using `dotscope`, you acknowledge that you assume full responsibility for your actions and any consequences arising from your use of this software.

## Acknowledgments

- The Rust community for excellent tooling and libraries
- Microsoft for the ECMA-335 specification
- The [goblin](https://github.com/m4b/goblin) project for PE parsing inspiration

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/ATRAPSLLC/dotscope/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/ATRAPSLLC/dotscope/issues)
- **Questions**: [GitHub Discussions](https://github.com/ATRAPSLLC/dotscope/discussions)
- **Security Issues**: admin{at}binflip.rs

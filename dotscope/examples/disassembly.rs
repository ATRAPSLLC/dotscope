//! # Disassembler and IL Analysis
//!
//! **What this example teaches:**
//! - CIL instruction decoding and analysis
//! - Method body examination and local variables
//! - Exception handler analysis
//! - Control flow and stack effect analysis
//! - Basic block construction from IL code
//!
//! **When to use this pattern:**
//! - Building disassemblers and decompilers
//! - Security analysis requiring instruction-level detail
//! - Performance analysis of IL code
//! - Understanding control flow patterns
//!
//! **Prerequisites:**
//! - Completed basic.rs and comprehensive.rs examples
//! - Understanding of CIL instruction set
//! - Familiarity with control flow concepts

use std::{env, path::Path};

use dotscope::prelude::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("disassembly", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example demonstrates IL disassembly and method analysis:");
        eprintln!("  • CIL instruction decoding with full operand support");
        eprintln!("  • Method body structure analysis");
        eprintln!("  • Exception handler examination");
        eprintln!("  • Stack and local variable analysis");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("⚙️  IL Disassembly analysis of: {}", path.display());

    let assembly = CilObject::from_path(path)?;

    // Method Body Analysis
    print_method_body_analysis(&assembly);

    // IL Instruction Analysis
    print_instruction_analysis(&assembly);

    // Exception Handler Analysis
    print_exception_analysis(&assembly);

    // Stack and Local Variable Analysis
    print_stack_analysis(&assembly);

    println!("\n✅ IL disassembly analysis completed!");

    Ok(())
}

fn print_method_body_analysis(assembly: &CilObject) {
    println!("\n🔧 Method Body Analysis:");

    let methods = assembly.methods();
    let mut stats = MethodBodyStats::default();

    println!("  Analyzing method bodies...");

    for entry in methods.iter().take(20) {
        let method = entry.value();
        stats.total_methods = stats.total_methods.saturating_add(1);

        if let Some(body) = method.body.get() {
            stats.methods_with_body = stats.methods_with_body.saturating_add(1);
            stats.total_il_bytes = stats.total_il_bytes.saturating_add(body.size_code);

            if body.max_stack > stats.max_stack_size {
                stats.max_stack_size = body.max_stack;
            }

            if body.local_var_sig_token != 0 {
                stats.methods_with_locals = stats.methods_with_locals.saturating_add(1);
            }

            if !body.exception_handlers.is_empty() {
                stats.methods_with_exceptions = stats.methods_with_exceptions.saturating_add(1);
                stats.total_exception_handlers = stats
                    .total_exception_handlers
                    .saturating_add(body.exception_handlers.len());
            }

            // Analyze method characteristics
            if body.is_init_local {
                stats.init_locals = stats.init_locals.saturating_add(1);
            }

            if body.size_code < 64 {
                stats.tiny_methods = stats.tiny_methods.saturating_add(1);
            } else {
                stats.fat_methods = stats.fat_methods.saturating_add(1);
            }
        } else {
            stats.abstract_or_extern = stats.abstract_or_extern.saturating_add(1);
        }
    }

    print_method_stats(&stats);
}

fn print_method_stats(stats: &MethodBodyStats) {
    println!("  Method body statistics:");
    println!("    Total methods analyzed: {}", stats.total_methods);
    println!("    Methods with IL body: {}", stats.methods_with_body);
    println!("    Abstract/extern methods: {}", stats.abstract_or_extern);
    println!("    Total IL bytes: {}", stats.total_il_bytes);
    println!(
        "    Average IL size: {:.1} bytes",
        stats.total_il_bytes as f64 / stats.methods_with_body.max(1) as f64
    );
    println!("    Max stack size encountered: {}", stats.max_stack_size);
    println!(
        "    Methods with local variables: {}",
        stats.methods_with_locals
    );
    println!(
        "    Methods with exception handlers: {}",
        stats.methods_with_exceptions
    );
    println!(
        "    Total exception handlers: {}",
        stats.total_exception_handlers
    );
    println!("    Tiny format methods: {}", stats.tiny_methods);
    println!("    Fat format methods: {}", stats.fat_methods);
    println!("    Methods with init_locals flag: {}", stats.init_locals);
}

fn print_instruction_analysis(assembly: &CilObject) {
    println!("\n📋 IL Instruction Analysis:");

    let methods = assembly.methods();
    let mut instruction_stats = InstructionStats::default();

    // Find methods with IL to disassemble
    for entry in methods.iter().take(5) {
        let method = entry.value();

        if let Some(body) = method.body.get() {
            println!("    Analyzing method: {}", method.name);

            if body.size_code > 0 {
                println!("      Method body details:");
                println!("        IL size: {} bytes", body.size_code);
                println!("        Max stack: {}", body.max_stack);
                println!(
                    "        Local variables token: 0x{:08X}",
                    body.local_var_sig_token
                );

                // Display actual disassembled instructions from blocks
                let mut total_instructions: usize = 0;
                let mut block_count: u64 = 0;

                // Access blocks - blocks are automatically populated when method is loaded
                for (block_id, block) in method.blocks() {
                    block_count = block_count.saturating_add(1);
                    if block_count <= 3 && !block.instructions.is_empty() {
                        println!(
                            "        Block {} (RVA: 0x{:X}, {} instructions):",
                            block_id,
                            block.rva,
                            block.instructions.len()
                        );

                        for (inst_idx, instruction) in block.instructions.iter().enumerate() {
                            if inst_idx < 5 {
                                // Show first 5 instructions per block
                                println!(
                                    "          [0x{:04X}] {} {:?}",
                                    instruction.rva, instruction.mnemonic, instruction.operand
                                );

                                // Update instruction statistics
                                instruction_stats.total_instructions =
                                    instruction_stats.total_instructions.saturating_add(1);
                                match instruction.flow_type {
                                    dotscope::assembly::FlowType::ConditionalBranch
                                    | dotscope::assembly::FlowType::UnconditionalBranch => {
                                        instruction_stats.branch_instructions =
                                            instruction_stats.branch_instructions.saturating_add(1);
                                    }
                                    dotscope::assembly::FlowType::Call
                                    | dotscope::assembly::FlowType::CallIndirect => {
                                        instruction_stats.call_instructions =
                                            instruction_stats.call_instructions.saturating_add(1);
                                    }
                                    _ => {}
                                }

                                if instruction.mnemonic.starts_with("ld")
                                    || instruction.mnemonic.starts_with("st")
                                {
                                    instruction_stats.load_store_instructions =
                                        instruction_stats.load_store_instructions.saturating_add(1);
                                }
                            }
                        }
                        if block.instructions.len() > 5 {
                            println!(
                                "          ... ({} more instructions)",
                                block.instructions.len().saturating_sub(5)
                            );
                        }
                    }
                    total_instructions =
                        total_instructions.saturating_add(block.instructions.len());
                }

                println!("        Basic blocks: {block_count}");
                if block_count > 3 {
                    println!(
                        "        ... ({} more blocks)",
                        block_count.saturating_sub(3)
                    );
                }

                println!("        Total instructions: {total_instructions}");

                instruction_stats.methods_analyzed =
                    instruction_stats.methods_analyzed.saturating_add(1);
            }

            if instruction_stats.methods_analyzed >= 3 {
                break;
            }
        }
    }

    println!("  Instruction analysis summary:");
    println!(
        "    Methods with IL analyzed: {}",
        instruction_stats.methods_analyzed
    );
    println!(
        "    Total instructions decoded: {}",
        instruction_stats.total_instructions
    );
    println!(
        "    Branch instructions: {}",
        instruction_stats.branch_instructions
    );
    println!(
        "    Call instructions: {}",
        instruction_stats.call_instructions
    );
    println!(
        "    Load/Store instructions: {}",
        instruction_stats.load_store_instructions
    );
}

fn print_exception_analysis(assembly: &CilObject) {
    println!("\n🛡️  Exception Handler Analysis:");

    let methods = assembly.methods();
    let mut exception_stats = ExceptionStats::default();

    for entry in methods.iter().take(50) {
        let method = entry.value();

        if let Some(body) = method.body.get() {
            if !body.exception_handlers.is_empty() {
                exception_stats.methods_with_handlers =
                    exception_stats.methods_with_handlers.saturating_add(1);

                for handler in &body.exception_handlers {
                    exception_stats.total_handlers =
                        exception_stats.total_handlers.saturating_add(1);

                    // Analyze handler types based on flags
                    match handler.flags {
                        ExceptionHandlerFlags::EXCEPTION => {
                            exception_stats.catch_handlers =
                                exception_stats.catch_handlers.saturating_add(1)
                        }
                        ExceptionHandlerFlags::FILTER => {
                            exception_stats.filter_handlers =
                                exception_stats.filter_handlers.saturating_add(1)
                        }
                        ExceptionHandlerFlags::FINALLY => {
                            exception_stats.finally_handlers =
                                exception_stats.finally_handlers.saturating_add(1)
                        }
                        ExceptionHandlerFlags::FAULT => {
                            exception_stats.fault_handlers =
                                exception_stats.fault_handlers.saturating_add(1)
                        }
                        _ => {
                            exception_stats.unknown_handlers =
                                exception_stats.unknown_handlers.saturating_add(1)
                        }
                    }

                    // Track protected region sizes
                    let protected_size = handler.try_length;
                    if protected_size > exception_stats.largest_protected_region {
                        exception_stats.largest_protected_region = protected_size;
                    }
                }

                if exception_stats.methods_with_handlers <= 3 {
                    println!("    Method '{}' exception handlers:", method.name);
                    for (i, handler) in body.exception_handlers.iter().enumerate() {
                        let handler_type = match handler.flags {
                            ExceptionHandlerFlags::EXCEPTION => "Catch",
                            ExceptionHandlerFlags::FILTER => "Filter",
                            ExceptionHandlerFlags::FINALLY => "Finally",
                            ExceptionHandlerFlags::FAULT => "Fault",
                            _ => "Unknown",
                        };
                        println!(
                            "      [{}] {} handler: IL_{:04X}-IL_{:04X} -> IL_{:04X}",
                            i,
                            handler_type,
                            handler.try_offset,
                            handler.try_offset.saturating_add(handler.try_length),
                            handler.handler_offset
                        );
                    }
                }
            }
        }
    }

    println!("  Exception handler statistics:");
    println!(
        "    Methods with exception handlers: {}",
        exception_stats.methods_with_handlers
    );
    println!(
        "    Total exception handlers: {}",
        exception_stats.total_handlers
    );
    println!("    Catch handlers: {}", exception_stats.catch_handlers);
    println!("    Finally handlers: {}", exception_stats.finally_handlers);
    println!("    Filter handlers: {}", exception_stats.filter_handlers);
    println!("    Fault handlers: {}", exception_stats.fault_handlers);
    println!(
        "    Largest protected region: {} IL bytes",
        exception_stats.largest_protected_region
    );
}

fn print_stack_analysis(assembly: &CilObject) {
    println!("\n📚 Stack and Local Variable Analysis:");

    let methods = assembly.methods();
    let mut local_stats = LocalVariableStats::default();

    for entry in methods.iter().take(30) {
        let method = entry.value();

        if let Some(body) = method.body.get() {
            local_stats.methods_analyzed = local_stats.methods_analyzed.saturating_add(1);

            if body.local_var_sig_token != 0 {
                local_stats.methods_with_locals = local_stats.methods_with_locals.saturating_add(1);

                // In a real implementation, you would parse the local variable signature
                // to determine the exact types and count of local variables
                // For now, we'll show the structure

                if local_stats.methods_with_locals <= 3 {
                    println!(
                        "    Method '{}' has local variables (token: 0x{:08X})",
                        method.name, body.local_var_sig_token
                    );
                }
            }

            // Track stack information
            if body.max_stack > local_stats.max_stack_encountered {
                local_stats.max_stack_encountered = body.max_stack;
                local_stats.method_with_max_stack = method.name.to_string();
            }

            // Check init_locals flag
            if body.is_init_local {
                local_stats.methods_with_init_locals =
                    local_stats.methods_with_init_locals.saturating_add(1);
            }
        }
    }

    println!("  Local variable statistics:");
    println!("    Methods analyzed: {}", local_stats.methods_analyzed);
    println!(
        "    Methods with local variables: {}",
        local_stats.methods_with_locals
    );
    println!(
        "    Methods with init_locals flag: {}",
        local_stats.methods_with_init_locals
    );
    println!(
        "    Maximum stack size: {} (in method '{}')",
        local_stats.max_stack_encountered, local_stats.method_with_max_stack
    );

    println!("  Stack analysis capabilities:");
    println!("    • Local variable signature parsing");
    println!("    • Stack effect simulation");
    println!("    • Type flow analysis");
    println!("    • Stack underflow/overflow detection");
}

#[derive(Default)]
struct MethodBodyStats {
    total_methods: usize,
    methods_with_body: usize,
    abstract_or_extern: usize,
    total_il_bytes: usize,
    max_stack_size: usize,
    methods_with_locals: usize,
    methods_with_exceptions: usize,
    total_exception_handlers: usize,
    tiny_methods: usize,
    fat_methods: usize,
    init_locals: usize,
}

#[derive(Default)]
#[allow(dead_code)] // These fields demonstrate the structure for instruction analysis
struct InstructionStats {
    methods_analyzed: usize,
    total_instructions: usize,
    branch_instructions: usize,
    call_instructions: usize,
    load_store_instructions: usize,
}

#[derive(Default)]
struct ExceptionStats {
    methods_with_handlers: usize,
    total_handlers: usize,
    catch_handlers: usize,
    finally_handlers: usize,
    filter_handlers: usize,
    fault_handlers: usize,
    unknown_handlers: usize,
    largest_protected_region: u32,
}

#[derive(Default)]
struct LocalVariableStats {
    methods_analyzed: usize,
    methods_with_locals: usize,
    methods_with_init_locals: usize,
    max_stack_encountered: usize,
    method_with_max_stack: String,
}

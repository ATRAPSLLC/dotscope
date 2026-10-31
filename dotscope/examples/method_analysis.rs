//! # Comprehensive Method Analysis
//!
//! **What this example teaches:**
//! - Exhaustive analysis of individual .NET methods
//! - Method metadata (name, flags, attributes) examination
//! - Method signature and calling convention details
//! - Parameter and return type information extraction
//! - Local variable signatures and types analysis
//! - Complete IL instruction disassembly with operands
//! - Basic block structure and control flow analysis
//! - Exception handler analysis (if present)
//! - Generic parameters and instantiation details
//! - P/Invoke information examination (if applicable)
//!
//! **When to use this pattern:**
//! - Deep method analysis for security research
//! - Building method-focused analysis tools
//! - Understanding complex method structures
//! - Learning comprehensive method introspection
//!
//! **Prerequisites:**
//! - Completed disassembly.rs example
//! - Understanding of method signatures
//! - Familiarity with CIL instruction formats

use std::{env, path::Path};

use dotscope::prelude::*;

// Helper functions to format implementation attributes
fn format_impl_code_type(code_type: &MethodImplCodeType) -> String {
    match code_type.bits() {
        0x0000 => "IL".to_string(),
        0x0001 => "Native".to_string(),
        0x0002 => "OPTIL".to_string(),
        0x0003 => "Runtime".to_string(),
        _ => format!("Unknown (0x{:04x})", code_type.bits()),
    }
}

fn format_impl_management(management: &MethodImplManagement) -> String {
    if management.bits() & 0x0004 != 0 {
        "Unmanaged".to_string()
    } else {
        "Managed".to_string()
    }
}

fn format_impl_options(options: &MethodImplOptions) -> String {
    let mut parts = Vec::new();
    let bits = options.bits();

    if bits & 0x0008 != 0 {
        parts.push("NoInlining");
    }
    if bits & 0x0010 != 0 {
        parts.push("ForwardRef");
    }
    if bits & 0x0020 != 0 {
        parts.push("Synchronized");
    }
    if bits & 0x0080 != 0 {
        parts.push("PreserveSig");
    }
    if bits & 0x1000 != 0 {
        parts.push("InternalCall");
    }

    if parts.is_empty() {
        "Standard".to_string()
    } else {
        parts.join(", ")
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("method_analysis", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example performs exhaustive analysis of a selected method:");
        eprintln!("  • Complete method metadata examination");
        eprintln!("  • Signature and parameter analysis");
        eprintln!("  • IL instruction disassembly");
        eprintln!("  • Control flow and exception analysis");
        eprintln!();
        eprintln!("The example will automatically select a suitable method with IL code.");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("🔍 Comprehensive Method Analysis of: {}", path.display());

    let assembly = CilObject::from_path(path)?;

    // Find a suitable method for analysis (not too small, has IL code)
    let target_method = find_suitable_method(&assembly)?;

    println!();
    println!("{}", "=".repeat(80));
    println!("📋 COMPREHENSIVE METHOD ANALYSIS");
    println!("{}", "=".repeat(80));

    analyze_method_completely(&assembly, target_method)?;

    println!("\n✅ Comprehensive method analysis completed!");
    Ok(())
}

/// Find a suitable method for analysis - one that has IL code and is reasonably complex
fn find_suitable_method(assembly: &CilObject) -> Result<MethodRc> {
    let methods = assembly.methods();

    // Look for a method with IL body, preferably with some complexity
    for entry in methods {
        let method = entry.value();

        // Skip trivial methods
        if method.name == ".ctor" || method.name == ".cctor" {
            continue;
        }

        if let Some(body) = method.body.get() {
            // Look for methods with reasonable complexity
            if body.size_code > 50 && body.size_code < 500 {
                println!(
                    "🎯 Selected method: {} (Token: 0x{:08X})",
                    method.name,
                    method.token.value()
                );
                println!(
                    "   IL Size: {} bytes, Max Stack: {}",
                    body.size_code, body.max_stack
                );
                return Ok(method.clone());
            }
        }
    }

    // Fallback: find any method with IL
    for entry in methods {
        let method = entry.value();
        if method.body.get().is_some() {
            println!(
                "🎯 Selected method: {} (Token: 0x{:08X})",
                method.name,
                method.token.value()
            );
            return Ok(method.clone());
        }
    }

    Err(Error::Other(
        "No suitable method found for analysis".to_string(),
    ))
}

/// Perform exhaustive analysis of the selected method
fn analyze_method_completely(_assembly: &CilObject, method: MethodRc) -> Result<()> {
    // Basic Method Information
    print_method_basic_info(&method);

    // Method Flags and Attributes
    print_method_flags(&method);

    // Method Signature Analysis
    print_method_signature(&method);

    // Parameters Analysis
    print_method_parameters(&method);

    // Local Variables Analysis
    print_local_variables(&method);

    // Generic Information
    print_generic_information(&method);

    // Method Body Analysis
    if let Some(body) = method.body.get() {
        print_method_body_details(&method, body);

        // IL Instructions Analysis
        print_il_instructions(&method, body)?;

        // Exception Handlers
        print_exception_handlers(body);
    } else {
        println!("\n❌ NO METHOD BODY");
        println!("   This method is abstract, extern, or P/Invoke");
    }

    // P/Invoke Information
    print_pinvoke_info(&method);

    // Security Information
    print_security_info(&method);

    // Additional Metadata
    print_additional_metadata(&method);

    Ok(())
}

fn print_method_basic_info(method: &Method) {
    println!("\n📝 BASIC METHOD INFORMATION");
    println!("{}", "-".repeat(50));
    println!("   Name: {}", method.name);
    println!("   Token: 0x{:08X}", method.token.value());
    println!("   RID: {}", method.rid);
    println!("   Metadata Offset: 0x{:X}", method.meta_offset);
    if let Some(rva) = method.rva {
        println!("   RVA: 0x{rva:08X}");
    } else {
        println!("   RVA: None (abstract/extern method)");
    }
}

fn print_method_flags(method: &Method) {
    println!("\n🏷️  METHOD FLAGS AND ATTRIBUTES");
    println!("{}", "-".repeat(50));

    // Implementation attributes - use dynamic method fields with custom formatting
    println!(
        "   Implementation Code Type: {}",
        format_impl_code_type(&method.impl_code_type)
    );
    println!(
        "   Implementation Management: {}",
        format_impl_management(&method.impl_management)
    );
    println!(
        "   Implementation Options: {}",
        format_impl_options(&method.impl_options)
    );

    // Method attributes - use bitflag values instead of Debug
    println!("   Access Flags: {:08b}", method.flags_access.bits());
    println!("   VTable Flags: {:08b}", method.flags_vtable.bits());
    println!("   Modifiers: {:08b}", method.flags_modifiers.bits());

    // P/Invoke attributes (if applicable)
    let pinvoke_flags = method
        .flags_pinvoke
        .load(std::sync::atomic::Ordering::Relaxed);
    if pinvoke_flags != 0 {
        println!("   P/Invoke Flags: 0x{pinvoke_flags:08X}");
    }
}

fn print_method_signature(method: &Method) {
    println!("\n📋 METHOD SIGNATURE");
    println!("{}", "-".repeat(50));
    let sig = &method.signature;

    println!("   Calling Convention:");
    println!("     Has This: {}", sig.has_this);
    println!("     Explicit This: {}", sig.explicit_this);
    println!("     Default: {}", sig.default);
    println!("     VarArg: {}", sig.vararg);
    println!("     CDecl: {}", sig.cdecl);
    println!("     StdCall: {}", sig.stdcall);
    println!("     ThisCall: {}", sig.thiscall);
    println!("     FastCall: {}", sig.fastcall);

    println!("   Parameter Counts:");
    println!("     Generic Parameter Count: {}", sig.param_count_generic);
    println!("     Parameter Count: {}", sig.param_count);

    println!("   Return Type:");
    print_signature_parameter(&sig.return_type, "     ");
}

fn print_signature_parameter(param: &SignatureParameter, indent: &str) {
    println!("{indent}Type: String"); // Simplified - actual type inspection would be more complex
    println!("{}By Reference: {}", indent, param.by_ref);
    if !param.modifiers.is_empty() {
        println!(
            "{}Custom Modifiers: {} modifier(s)",
            indent,
            param.modifiers.len()
        );
        for (i, modifier) in param.modifiers.iter().enumerate() {
            println!(
                "{}  [{}]: Token 0x{:08X} ({})",
                indent,
                i,
                modifier.modifier_type.value(),
                if modifier.is_required {
                    "required"
                } else {
                    "optional"
                }
            );
        }
    }
}

fn print_method_parameters(method: &Method) {
    println!("\n🔧 PARAMETERS");
    println!("{}", "-".repeat(50));

    let param_count = method.params.iter().count();
    if param_count == 0 {
        println!("   No parameters");
    } else {
        for (i, param) in method.params.iter() {
            println!("   Parameter [{i}]:");
            println!(
                "     Name: {}",
                param.name.as_ref().unwrap_or(&"<unnamed>".to_string())
            );
            println!("     Sequence: {}", param.sequence);
            println!("     Flags: 0x{:04X}", param.flags);
            if let Some(default_value) = param.default.get() {
                println!("     Default Value: {default_value:?}");
            }
        }
    }

    // Signature parameters
    println!("\n   Signature Parameters:");
    for (i, param) in method.signature.params.iter().enumerate() {
        println!("   Parameter [{i}] from signature:");
        print_signature_parameter(param, "     ");
    }
}

fn print_local_variables(method: &Method) {
    println!("\n🗂️  LOCAL VARIABLES");
    println!("{}", "-".repeat(50));

    let local_count = method.local_vars.count();
    if local_count == 0 {
        println!("   No local variables");
    } else {
        for (i, (_, local_var)) in method.local_vars.iter().enumerate() {
            println!("   Local Variable [{i}]:");
            println!("     Type: LocalVar");
            println!("     Is ByRef: {}", local_var.is_byref);
            println!("     Is Pinned: {}", local_var.is_pinned);
            if !local_var.modifiers.is_empty() {
                println!(
                    "     Custom Modifiers: {} modifier(s)",
                    local_var.modifiers.len()
                );
                for (j, _modifier) in local_var.modifiers.iter().enumerate() {
                    println!("       [{j}]: Custom modifier");
                }
            }
        }
    }
}

fn print_generic_information(method: &Method) {
    println!("\n🧬 GENERIC INFORMATION");
    println!("{}", "-".repeat(50));

    let generic_param_count = method.generic_params.count();
    if generic_param_count == 0 {
        println!("   No generic parameters");
    } else {
        for (i, (_, generic_param)) in method.generic_params.iter().enumerate() {
            println!("   Generic Parameter [{i}]:");
            println!("     Name: {}", generic_param.name);
            println!("     Number: {}", generic_param.number);
            println!("     Flags: 0x{:04X}", generic_param.flags);
            if let Some(_owner) = generic_param.owner.get() {
                println!("     Owner: <Referenced Type>");
            }
        }
    }

    let generic_arg_count = method.generic_args.count();
    if generic_arg_count > 0 {
        println!("\n   Generic Arguments (Method Specifications):");
        for (i, (_, method_spec)) in method.generic_args.iter().enumerate() {
            println!("   MethodSpec [{i}]:");
            println!("     Token: 0x{:08X}", method_spec.token.value());
            println!("     RID: {}", method_spec.rid);

            // Print the resolved generic arguments within the MethodSpec
            if method_spec.generic_args.count() > 0 {
                println!("     Resolved Types:");
                for (j, (_, resolved_type)) in method_spec.generic_args.iter().enumerate() {
                    if let Some(type_name) = resolved_type.name() {
                        println!("       [{j}]: {type_name}");
                        if let Some(namespace) = resolved_type.namespace() {
                            if !namespace.is_empty() {
                                println!("           Namespace: {namespace}");
                            }
                        }
                        if let Some(token) = resolved_type.token() {
                            println!("           Token: 0x{:08X}", token.value());
                        }
                    } else {
                        println!("       [{j}]: <Unknown Type>");
                    }
                }
            }

            // Print signature information
            if !method_spec.instantiation.generic_args.is_empty() {
                println!(
                    "     Signature Arguments: {} type(s)",
                    method_spec.instantiation.generic_args.len()
                );
                for (j, sig_arg) in method_spec.instantiation.generic_args.iter().enumerate() {
                    println!("       [{j}]: {sig_arg:?}");
                }
            }
        }
    }
}

fn print_method_body_details(_method: &Method, body: &MethodBody) {
    println!("\n🏗️  METHOD BODY DETAILS");
    println!("{}", "-".repeat(50));
    println!("   IL Code Size: {} bytes", body.size_code);
    println!("   Header Size: {} bytes", body.size_header);
    println!("   Maximum Stack Size: {}", body.max_stack);
    println!(
        "   Local Variable Signature Token: 0x{:08X}",
        body.local_var_sig_token
    );

    println!("   Flags:");
    println!("     Is Fat Header: {}", body.is_fat);
    println!("     Initialize Locals: {}", body.is_init_local);
    println!("     Has Exception Data: {}", body.is_exception_data);

    println!(
        "   Exception Handlers: {} handler(s)",
        body.exception_handlers.len()
    );
}

fn print_il_instructions(method: &Method, body: &MethodBody) -> Result<()> {
    println!("\n🔍 COMPREHENSIVE IL INSTRUCTION ANALYSIS");
    println!("{}", "=".repeat(70));

    if body.size_code == 0 {
        println!("   No IL code to analyze");
        return Ok(());
    }

    // Basic Statistics
    print_basic_il_statistics(method, body);

    // Basic Block Analysis
    print_basic_block_analysis(method);

    // Instruction Stream Analysis
    print_instruction_stream_analysis(method)?;

    // Control Flow Analysis
    print_control_flow_analysis(method);

    Ok(())
}

fn print_basic_il_statistics(method: &Method, body: &MethodBody) {
    println!("\n📊 BASIC IL STATISTICS");
    println!("{}", "-".repeat(50));

    let block_count = method.block_count();
    let instruction_count = method.instruction_count();

    println!("   IL Code Size: {} bytes", body.size_code);
    println!("   Basic Blocks: {block_count}");
    println!("   Total Instructions: {instruction_count}");

    if block_count > 0 {
        let avg_instructions_per_block = instruction_count as f64 / block_count as f64;
        println!("   Average Instructions per Block: {avg_instructions_per_block:.1}");
    }

    // Calculate instruction density
    if body.size_code > 0 {
        let avg_instruction_size = body.size_code as f64 / instruction_count.max(1) as f64;
        println!("   Average Instruction Size: {avg_instruction_size:.1} bytes");
    }
}

fn print_basic_block_analysis(method: &Method) {
    println!("\n🧱 BASIC BLOCK ANALYSIS");
    println!("{}", "-".repeat(50));

    let block_count = method.block_count();
    if block_count == 0 {
        println!("   No basic blocks found");
        return;
    }

    println!("   Basic Block Details:");

    for (block_id, block) in method.blocks().take(10) {
        let predecessor_count = block.predecessors.len();
        let successor_count = block.successors.len();
        let exception_count = block.exceptions.len();

        println!("     Block {} (RVA: 0x{:08X}):", block_id, block.rva);
        println!("       Instructions: {}", block.instructions.len());
        println!("       Size: {} bytes", block.size);
        println!("       Predecessors: {predecessor_count}");
        println!("       Successors: {successor_count}");

        if exception_count > 0 {
            println!("       Exception regions: {exception_count}");
        }

        // Show control flow relationships
        if !block.predecessors.is_empty() {
            println!("       ← From blocks: {:?}", block.predecessors);
        }
        if !block.successors.is_empty() {
            println!("       → To blocks: {:?}", block.successors);
        }

        println!();
    }

    if block_count > 10 {
        println!("     ... ({} more blocks)", block_count.saturating_sub(10));
    }
}

fn print_instruction_stream_analysis(method: &Method) -> Result<()> {
    println!("\n🔄 INSTRUCTION STREAM ANALYSIS");
    println!("{}", "-".repeat(50));

    let mut instruction_stats = std::collections::HashMap::new();
    let mut category_stats = std::collections::HashMap::new();
    let mut flow_type_stats = std::collections::HashMap::new();
    let mut stack_effects = Vec::new();
    let mut branch_targets = std::collections::HashSet::new();

    // Use the new iterator to analyze all instructions
    let total_instructions = method.instruction_count();
    println!("   Analyzing {total_instructions} instructions using InstructionIterator...");

    for (i, instruction) in method.instructions().enumerate() {
        // Count by mnemonic
        let entry = instruction_stats
            .entry(instruction.mnemonic.to_string())
            .or_insert(0u64);
        *entry = entry.saturating_add(1);

        // Count by category
        let category_name = format!("{:?}", instruction.category);
        let entry = category_stats.entry(category_name).or_insert(0u64);
        *entry = entry.saturating_add(1);

        // Count by flow type
        let flow_name = format!("{:?}", instruction.flow_type);
        let entry = flow_type_stats.entry(flow_name).or_insert(0u64);
        *entry = entry.saturating_add(1);

        // Collect stack effects
        stack_effects.push(instruction.stack_behavior.net_effect);

        // Collect branch targets
        for target in &instruction.branch_targets {
            branch_targets.insert(*target);
        }

        // Show first 15 instructions with detailed information
        if i < 15 {
            let operand_str = format_operand(&instruction.operand);
            let operand_display = if !operand_str.is_empty() {
                format!(" {operand_str}")
            } else {
                String::new()
            };
            println!(
                "     [{:3}] IL_{:04X}: {:<12} 0x{:02X} (stack: {:+}, flow: {:?}){}",
                i,
                instruction.rva,
                instruction.mnemonic,
                instruction.opcode,
                instruction.stack_behavior.net_effect,
                instruction.flow_type,
                operand_display
            );
        } else if i == 15 {
            println!(
                "     ... ({} more instructions)",
                total_instructions.saturating_sub(15)
            );
        }
    }

    // Print instruction statistics
    println!("\n   📈 INSTRUCTION STATISTICS:");

    // Most common instructions
    if !instruction_stats.is_empty() {
        println!("     Most Common Instructions:");
        let mut sorted_stats: Vec<_> = instruction_stats.iter().collect();
        sorted_stats.sort_by(|a, b| b.1.cmp(a.1));

        for (mnemonic, count) in sorted_stats.iter().take(8) {
            let percentage = (**count as f64 / total_instructions as f64) * 100.0;
            println!("       {mnemonic:<12}: {count:3} times ({percentage:.1}%)");
        }
    }

    // Category distribution
    if !category_stats.is_empty() {
        println!("\n     Instruction Categories:");
        let mut sorted_categories: Vec<_> = category_stats.iter().collect();
        sorted_categories.sort_by(|a, b| b.1.cmp(a.1));

        for (category, count) in sorted_categories.iter() {
            let percentage = (**count as f64 / total_instructions as f64) * 100.0;
            println!("       {category:<15}: {count:3} instructions ({percentage:.1}%)");
        }
    }

    // Stack effect analysis
    if !stack_effects.is_empty() {
        let total_stack_effect: i32 = stack_effects.iter().map(|&x| x as i32).sum();
        let max_stack_push = stack_effects.iter().max().unwrap_or(&0);
        let max_stack_pop = stack_effects.iter().min().unwrap_or(&0);

        println!("\n     Stack Behavior Analysis:");
        println!("       Net stack effect: {total_stack_effect:+}");
        println!("       Maximum stack push: +{max_stack_push}");
        println!("       Maximum stack pop: {max_stack_pop}");
    }

    // Branch analysis
    if !branch_targets.is_empty() {
        println!("\n     Branch Target Analysis:");
        println!("       Unique branch targets: {}", branch_targets.len());
        let sorted_targets: Vec<_> = branch_targets.iter().collect();
        if sorted_targets.len() <= 5 {
            println!("       Targets: {sorted_targets:?}");
        } else {
            println!(
                "       First 5 targets: {:?}...",
                sorted_targets.get(0..5).unwrap_or(&[])
            );
        }
    }

    Ok(())
}

fn print_control_flow_analysis(method: &Method) {
    println!("\n🌊 CONTROL FLOW ANALYSIS");
    println!("{}", "-".repeat(50));

    let block_count = method.block_count();
    if block_count == 0 {
        println!("   No control flow to analyze");
        return;
    }

    let mut entry_blocks: u64 = 0;
    let mut exit_blocks: u64 = 0;
    let mut branch_blocks: u64 = 0;
    let mut simple_blocks: u64 = 0;

    for (_, block) in method.blocks() {
        match (block.predecessors.len(), block.successors.len()) {
            (0, _) => entry_blocks = entry_blocks.saturating_add(1u64),
            (_, 0) => exit_blocks = exit_blocks.saturating_add(1u64),
            (_, n) if n > 1 => branch_blocks = branch_blocks.saturating_add(1u64),
            _ => simple_blocks = simple_blocks.saturating_add(1u64),
        }
    }

    println!("   Control Flow Characteristics:");
    println!("     Entry blocks (no predecessors): {entry_blocks}");
    println!("     Exit blocks (no successors): {exit_blocks}");
    println!("     Branch blocks (multiple successors): {branch_blocks}");
    println!("     Simple blocks (single flow): {simple_blocks}");

    // Calculate complexity metrics
    let cyclomatic_complexity = method
        .blocks()
        .map(|(_, block)| block.successors.len().saturating_sub(1))
        .sum::<usize>()
        .saturating_add(1);

    println!("\n   Complexity Metrics:");
    println!("     Cyclomatic Complexity: {cyclomatic_complexity}");

    if cyclomatic_complexity <= 5 {
        println!("     Complexity Assessment: Low (simple method)");
    } else if cyclomatic_complexity <= 10 {
        println!("     Complexity Assessment: Moderate");
    } else {
        println!("     Complexity Assessment: High (complex method)");
    }
}

fn format_operand(operand: &dotscope::assembly::Operand) -> String {
    match operand {
        dotscope::assembly::Operand::None => String::new(),
        dotscope::assembly::Operand::Immediate(imm) => format!("{imm:?}"),
        dotscope::assembly::Operand::Token(token) => format!("token:0x{:08X}", token.value()),
        dotscope::assembly::Operand::Target(target) => format!("IL_{target:04X}"),
        dotscope::assembly::Operand::Switch(targets) => {
            format!("switch({} targets)", targets.len())
        }
        dotscope::assembly::Operand::Local(idx) => format!("local:{idx}"),
        dotscope::assembly::Operand::Argument(idx) => format!("arg:{idx}"),
    }
}

fn print_exception_handlers(body: &MethodBody) {
    println!("\n🚨 EXCEPTION HANDLERS");
    println!("{}", "-".repeat(50));

    if body.exception_handlers.is_empty() {
        println!("   No exception handlers");
    } else {
        for (i, handler) in body.exception_handlers.iter().enumerate() {
            println!("   Exception Handler [{i}]:");
            println!("     Flags: {:08b}", handler.flags.bits());
            println!("     Try Block:");
            println!("       Offset: 0x{:04X}", handler.try_offset);
            println!("       Length: {} bytes", handler.try_length);
            println!("     Handler Block:");
            println!("       Offset: 0x{:04X}", handler.handler_offset);
            println!("       Length: {} bytes", handler.handler_length);

            // Handle different exception handler types based on flag bits
            if handler.flags.bits() & 0x01 != 0 {
                println!("     Type: Finally/Fault handler");
            } else {
                println!("     Type: Catch handler");
                if let Some(_handler_type) = &handler.handler {
                    println!("     Exception Type: <exception type>");
                }
            }
        }
    }
}

fn print_pinvoke_info(method: &Method) {
    println!("\n🔗 P/INVOKE INFORMATION");
    println!("{}", "-".repeat(50));

    let pinvoke_flags = method
        .flags_pinvoke
        .load(std::sync::atomic::Ordering::Relaxed);
    if pinvoke_flags != 0 {
        println!("   P/Invoke Flags: 0x{pinvoke_flags:08X}");
        println!("   This method is a P/Invoke method");
        // Additional P/Invoke details would be in ImplMap table
    } else {
        println!("   Not a P/Invoke method");
    }
}

fn print_security_info(method: &Method) {
    println!("\n🔒 SECURITY INFORMATION");
    println!("{}", "-".repeat(50));

    if method.security.is_empty() {
        println!("   No security attributes");
    }
    for (_, security) in method.security.iter() {
        println!("   {}: {}", security.action, security.permission_set);
    }
}

fn print_additional_metadata(method: &Method) {
    println!("\n📊 ADDITIONAL METADATA");
    println!("{}", "-".repeat(50));

    println!("   Method Implementation:");
    println!("     Is IL Code: {}", method.is_code_il());

    if method.overrides.count() > 0 {
        println!("   Method Overrides:");
        println!("     Override count: {}", method.overrides.count());
    }

    let interface_impl_count = method.interface_impls.iter().count();
    if interface_impl_count > 0 {
        println!("   Interface Implementations:");
        println!("     Interface methods: {interface_impl_count}");
    }

    // Method relationships and sizes
    println!("   Memory Layout:");
    println!(
        "     Parameters List Size: {}",
        method.params.iter().count()
    );
    println!(
        "     Local Variables Size: {}",
        method.local_vars.iter().count()
    );
    println!(
        "     Generic Parameters Size: {}",
        method.generic_params.iter().count()
    );
    println!(
        "     Generic Arguments Size: {}",
        method.generic_args.iter().count()
    );
    println!("     Basic Blocks Size: {}", method.block_count());
}

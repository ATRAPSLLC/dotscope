//! # .NET Assembly Code Injection Example
//!
//! **What this example teaches:**
//! - Injecting new methods into existing .NET assemblies
//! - Creating external assembly references (mscorlib/System.Runtime)
//! - Building type references and member references for BCL types
//! - Adding user strings for `ldstr` instructions
//! - Using the high-level MethodBuilder and MethodBodyBuilder APIs
//! - Generating CIL bytecode using InstructionAssembler
//! - Finding suitable injection targets in existing assemblies
//! - Complete assembly modification workflow with validation
//!
//! **When to use this pattern:**
//! - Code instrumentation and profiling hooks
//! - Adding logging or debugging functionality
//! - Implementing aspect-oriented programming features
//! - Runtime patching and hot-fixing scenarios
//! - Educational purposes to understand .NET IL injection
//!
//! **Prerequisites:**
//! - Understanding of .NET metadata structures
//! - Basic knowledge of CIL (Common Intermediate Language)
//! - Familiarity with method signatures and calling conventions

use std::{env, path::Path};

use dotscope::{
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{CodedIndex, CodedIndexType, TableId},
        token::Token,
    },
    prelude::*,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("injectcode", String::as_str);
    let (Some(input_arg), Some(output_arg)) = (args.get(1), args.get(2)) else {
        eprintln!("Usage: {prog} <input-assembly> <output-assembly>");
        eprintln!();
        eprintln!("This example demonstrates .NET assembly code injection:");
        eprintln!("  - Finding or creating external assembly references");
        eprintln!("  - Creating type and member references for BCL types");
        eprintln!("  - Adding user strings for string literals");
        eprintln!("  - Injecting new static methods with CIL implementation");
        eprintln!("  - Finding suitable injection targets in existing types");
        eprintln!("  - Complete workflow with validation and PE generation");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {prog} input.dll injected.dll");
        eprintln!();
        eprintln!("The injected method will be:");
        eprintln!("  public static void PrintHelloWorld()");
        eprintln!("  {{");
        eprintln!("      System.Console.WriteLine(\"Hello World from dotscope!\");");
        eprintln!("  }}");
        return Ok(());
    };

    let input_path = Path::new(input_arg);
    let output_path = Path::new(output_arg);

    println!(".NET Assembly Code Injection Tool");
    println!("Input:  {}", input_path.display());
    println!("Output: {}", output_path.display());
    println!();

    // Step 1: Load the assembly for modification
    println!("Loading assembly for modification...");
    let view = CilAssemblyView::from_path(input_path).map_err(|e| {
        eprintln!("x Failed to load assembly: {e}");
        eprintln!("  Make sure the file is a valid .NET assembly");
        e
    })?;

    // Create mutable assembly
    let mut assembly = CilAssembly::new(view);
    println!("  Assembly loaded successfully");
    println!();

    // Step 2: Find injection target using CilObject for type discovery
    println!("Finding suitable injection target...");
    let target_type_token = find_injection_target(&assembly)?;
    println!(
        "  Selected injection target: TypeDef token {:#08X}",
        target_type_token.value()
    );
    println!();

    // Step 3: Add user string for the hello world message
    // Note: The actual heap offset will be resolved when the file is written.
    // We store the ChangeRef to track the pending addition.
    println!("Adding user string for hello world message...");
    let hello_ref = assembly.userstring_add("Hello World from dotscope!")?;
    // Use placeholder() to get a temporary value for use in IL generation.
    // This will be resolved to the actual offset during the write phase.
    let hello_placeholder = hello_ref.placeholder();
    let hello_string_token = Token::new(0x70000000 | hello_placeholder);
    println!("  User string queued for addition");
    println!();

    // Step 4: Create external references for System.Console.WriteLine
    println!("Creating external references for System.Console.WriteLine...");

    // Create System.Runtime assembly reference
    let mscorlib_ref = AssemblyRefBuilder::new()
        .name("System.Runtime")
        .version(8, 0, 0, 0) // .NET 8 version
        .public_key_token(&[
            0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a, // System.Runtime public key token
        ])
        .build(&mut assembly)?;

    // Create TypeRef for System.Console
    let console_typeref = TypeRefBuilder::new()
        .name("Console")
        .namespace("System")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            mscorlib_ref.placeholder(),
            CodedIndexType::ResolutionScope,
        ))
        .build(&mut assembly)?;

    // Create method signature for Console.WriteLine(string)
    let writeline_signature = create_writeline_signature()?;

    // Create MemberRef for Console.WriteLine method
    let console_writeline_ref = MemberRefBuilder::new()
        .name("WriteLine")
        .class(CodedIndex::new(
            TableId::TypeRef,
            console_typeref.placeholder(),
            CodedIndexType::MemberRefParent,
        ))
        .signature(&writeline_signature)
        .build(&mut assembly)?;

    // Get placeholder token for use in IL instructions
    let console_writeline_token = console_writeline_ref.placeholder_token().ok_or_else(|| {
        dotscope::Error::Other("Console.WriteLine ChangeRef should be a table row".to_string())
    })?;
    println!("  Created mscorlib reference");
    println!("  Created Console.WriteLine reference");
    println!();

    // Step 5: Create the hello world method
    println!("Injecting PrintHelloWorld method...");
    MethodBuilder::new("PrintHelloWorld")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(hello_string_token)? // Load the hello world string
                    .call(console_writeline_token)? // Call Console.WriteLine
                    .ret()?; // Return void
                Ok(())
            })
        })
        .build(&mut assembly)?;

    println!("  Method definition created");
    println!();

    // Step 6: Write the modified assembly
    println!("Writing modified assembly...");

    assembly.to_file(output_path).map_err(|e| {
        eprintln!("x Failed to write assembly: {e}");
        e
    })?;

    println!(
        "  Successfully wrote modified assembly to {}",
        output_path.display()
    );
    println!();

    // After write, we can report final resolved values
    println!("Summary:");
    if let Some(offset) = hello_ref.offset() {
        println!("  - User string at heap offset: {:#x}", offset);
    }
    println!("  - Injected static method: PrintHelloWorld()");
    println!("  - Created external references to System.Console.WriteLine");
    println!("  - Generated valid PE file with proper metadata");
    println!();
    println!("You can now call the injected method from other .NET code:");
    println!("  YourAssembly.YourType.PrintHelloWorld();");

    Ok(())
}

/// Find a suitable type for method injection using the assembly's TypeDef table
fn find_injection_target(_assembly: &CilAssembly) -> Result<Token> {
    // For this example, we'll use a simple approach and just use the first TypeDef
    // In a real implementation, you could:
    // 1. Load the assembly with CilObject to get rich type information
    // 2. Iterate through TypeDef table directly to find suitable classes
    // 3. Create a new class specifically for injection

    // Use the first TypeDef entry (which should exist in any assembly with types)
    let first_typedef_token = Token::new(0x02000001); // TypeDef table, RID 1

    println!(
        "  Using TypeDef token: {:#08X}",
        first_typedef_token.value()
    );
    println!("  (In a real implementation, use CilObject to find ideal injection targets)");

    Ok(first_typedef_token)
}

/// Create method signature for Console.WriteLine(string)
fn create_writeline_signature() -> Result<Vec<u8>> {
    let signature = SignatureMethod {
        has_this: false, // Static method
        explicit_this: false,
        default: true, // Default managed calling convention
        vararg: false,
        cdecl: false,
        stdcall: false,
        thiscall: false,
        fastcall: false,
        unmanaged: false,
        param_count_generic: 0,
        param_count: 1, // One string parameter
        return_type: SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::Void, // void return type
        },
        params: vec![SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::String, // string parameter
        }],
        varargs: Vec::new(),
    };

    encode_method_signature(&signature)
}

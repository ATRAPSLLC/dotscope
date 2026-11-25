#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Integration test for method injection roundtrip
//!
//! This test verifies that:
//! 1. We can inject a method into an assembly
//! 2. The resulting assembly is valid and loadable
//! 3. Both original and injected methods can be disassembled
//! 4. Method bodies are preserved correctly

use dotscope::{
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{CodedIndex, CodedIndexType, TableId},
        token::Token,
    },
    prelude::*,
    testkit::fixture,
    ChangeRefKind, ChangeRefRc,
};

const TEST_ASSEMBLY_PATH: &str = "mono_4.8/mscorlib.dll";

/// Helper function to create a test assembly for method injection testing
fn create_test_assembly() -> Result<CilAssembly> {
    let path = fixture(TEST_ASSEMBLY_PATH);

    CilAssembly::from_path(path)
}

#[test]
fn test_method_injection_roundtrip() -> Result<()> {
    // Step 1: Create a modified assembly with method injection
    let modified_assembly = inject_hello_world_method()?;

    // Step 2: Verify assembly basic integrity
    verify_assembly_integrity(&modified_assembly)?;

    // Step 3: Verify original methods still work
    verify_original_methods_intact(&modified_assembly)?;

    // Step 4: Find and verify our injected method
    verify_injected_method(&modified_assembly)?;

    Ok(())
}

fn inject_hello_world_method() -> Result<CilObject> {
    // Load assembly using factory
    let mut assembly = create_test_assembly()?;

    // Add user string - returns ChangeRefRc
    let hello_ref = assembly.userstring_add("Hello World from integration test!")?;
    // Use the placeholder value - bit 31 marks it as placeholder, resolved during write
    let hello_string_token = Token::new(0x70000000 | hello_ref.placeholder());

    // Create external references
    let mscorlib_ref = create_mscorlib_ref(&mut assembly)?;
    let console_writeline_ref = create_console_writeline_ref(&mut assembly, mscorlib_ref)?;

    // Inject method
    let method_ref = MethodBuilder::new("TestInjectedMethod")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(hello_string_token)?
                    .call(console_writeline_ref)?
                    .ret()?;
                Ok(())
            })
        })
        .build(&mut assembly)?;

    // Verify the method ChangeRef kind
    assert_eq!(
        method_ref.kind(),
        ChangeRefKind::TableRow(TableId::MethodDef),
        "Method ChangeRef should be a MethodDef table row"
    );

    // Write modified assembly to memory
    let bytes = assembly.to_memory()?;

    // Load the written assembly for verification
    CilObject::from_mem(bytes)
}

/// Verify basic assembly integrity after modification
fn verify_assembly_integrity(assembly: &CilObject) -> Result<()> {
    // Check that essential heaps are present
    assert!(
        assembly.strings().is_some(),
        "Modified assembly should have strings heap"
    );
    assert!(
        assembly.blob().is_some(),
        "Modified assembly should have blobs heap"
    );
    assert!(
        assembly.userstrings().is_some(),
        "Modified assembly should have user strings heap"
    );
    assert!(
        assembly.tables().is_some(),
        "Modified assembly should have metadata tables"
    );

    // Verify core metadata tables exist and have content
    let tables = assembly.tables().unwrap();
    assert!(
        tables.table_row_count(TableId::Module) > 0,
        "Should have module table entries"
    );
    assert!(
        tables.table_row_count(TableId::TypeDef) > 0,
        "Should have type definition entries"
    );
    assert!(
        tables.table_row_count(TableId::MethodDef) > 0,
        "Should have method definition entries"
    );

    // Verify that our modifications were persisted
    let userstrings = assembly.userstrings().unwrap();
    let userstring_count = userstrings.iter().count();
    assert!(
        userstring_count > 0,
        "Should have user strings after modification"
    );

    Ok(())
}

fn verify_original_methods_intact(assembly: &CilObject) -> Result<()> {
    let methods = assembly.methods();
    let mut methods_with_bodies = 0;
    let mut methods_checked = 0;

    // Check first 100 methods to see if they have valid bodies
    for entry in methods.iter() {
        if methods_checked >= 100 {
            break;
        }

        let method = entry.value();
        if let Some(body) = method.body.get() {
            // Verify the method body is valid
            assert!(body.size_code > 0, "Method body should have non-zero size");
            methods_with_bodies += 1;
        }
        methods_checked += 1;
    }

    // We should have found many methods with bodies in a real assembly
    assert!(
        methods_with_bodies > 10,
        "Should find many methods with bodies in a real assembly, found: {methods_with_bodies}/{methods_checked}"
    );

    Ok(())
}

fn verify_injected_method(assembly: &CilObject) -> Result<()> {
    let methods = assembly.methods();

    // Look for our injected method
    let mut found_injected_method = false;

    for entry in methods.iter() {
        let method = entry.value();
        if method.name == "TestInjectedMethod" {
            found_injected_method = true;

            // Verify it has a method body
            let body = method.body.get().ok_or_else(|| {
                Error::Parse(ParseFailure::Other {
                    stage: ParseStage::MethodBody,
                    message: "injected method should have a body".into(),
                })
            })?;

            // Verify the body has reasonable size (our method should be small)
            assert!(
                body.size_code > 0 && body.size_code < 100,
                "Injected method body size should be reasonable: {}",
                body.size_code
            );

            // Verify method body properties
            assert!(
                body.size_header > 0,
                "Method should have a valid header size"
            );
            assert!(
                body.max_stack >= 1,
                "Method should have reasonable max stack size: {}",
                body.max_stack
            );

            // Try to get the method's basic blocks (this exercises the disassembler)
            let blocks: Vec<_> = method.blocks().collect();
            assert!(
                !blocks.is_empty(),
                "Method should have at least one basic block for disassembly"
            );

            // Verify we can iterate over the blocks without error
            for (index, block) in blocks.iter().enumerate() {
                assert!(
                    !block.1.instructions.is_empty() || index == 0,
                    "Basic block {index} should have instructions or be the first block"
                );
            }

            // Detailed instruction verification
            verify_injected_method_instructions(&blocks)?;

            break;
        }
    }

    assert!(
        found_injected_method,
        "Should find the injected method 'TestInjectedMethod' in the assembly"
    );
    Ok(())
}

/// Verify that the injected method has the correct instructions
fn verify_injected_method_instructions(
    blocks: &[(usize, &dotscope::assembly::BasicBlock)],
) -> Result<()> {
    // Our injected method should have exactly one basic block
    assert_eq!(
        blocks.len(),
        1,
        "Injected method should have exactly one basic block"
    );

    let (_, block) = &blocks[0];
    let instructions = &block.instructions;

    // Our method should have exactly 3 instructions: ldstr, call, ret
    assert_eq!(
        instructions.len(),
        3,
        "Injected method should have exactly 3 instructions (ldstr, call, ret), found: {}",
        instructions.len()
    );

    // Verify instruction sequence matches our injected method:
    // 1. ldstr (load string)
    // 2. call (call Console.WriteLine)
    // 3. ret (return)

    assert_eq!(
        instructions[0].mnemonic, "ldstr",
        "First instruction should be ldstr, found: {}",
        instructions[0].mnemonic
    );

    assert_eq!(
        instructions[1].mnemonic, "call",
        "Second instruction should be call, found: {}",
        instructions[1].mnemonic
    );

    assert_eq!(
        instructions[2].mnemonic, "ret",
        "Third instruction should be ret, found: {}",
        instructions[2].mnemonic
    );

    // Verify ldstr operand is a valid user string token
    if let Operand::Token(token) = &instructions[0].operand {
        // User string tokens start with 0x70
        assert!(
            (token.value() & 0xFF000000) == 0x70000000,
            "ldstr operand should be a user string token (0x70xxxxxx), found: 0x{:08X}",
            token.value()
        );
    } else {
        panic!(
            "ldstr operand should be a token, found: {:?}",
            instructions[0].operand
        );
    }

    // Verify call operand is a valid method reference token
    if let Operand::Token(token) = &instructions[1].operand {
        // MemberRef tokens start with 0x0A
        assert!(
            (token.value() & 0xFF000000) == 0x0A000000,
            "call operand should be a MemberRef token (0x0Axxxxxx), found: 0x{:08X}",
            token.value()
        );
    } else {
        panic!(
            "call operand should be a token, found: {:?}",
            instructions[1].operand
        );
    }

    // ret instruction should have no operand
    if let Operand::None = &instructions[2].operand {
        // This is expected
    } else {
        panic!(
            "ret instruction should have no operand, found: {:?}",
            instructions[2].operand
        );
    }

    println!("✅ Injected method instructions verified successfully:");
    for (i, instruction) in instructions.iter().enumerate() {
        println!(
            "   {}: {} (operand: {:?})",
            i, instruction.mnemonic, instruction.operand
        );
    }

    Ok(())
}

/// Helper function to create an AssemblyRef for System.Runtime
fn create_mscorlib_ref(assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
    let assembly_ref = AssemblyRefBuilder::new()
        .name("System.Runtime")
        .version(8, 0, 0, 0)
        .public_key_token(&[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a])
        .build(assembly)?;

    // Verify the ChangeRef kind
    assert_eq!(
        assembly_ref.kind(),
        ChangeRefKind::TableRow(TableId::AssemblyRef),
        "AssemblyRef ChangeRef should be an AssemblyRef table row"
    );

    Ok(assembly_ref)
}

/// Helper function to create a MemberRef for System.Console.WriteLine(string)
fn create_console_writeline_ref(
    assembly: &mut CilAssembly,
    mscorlib_ref: ChangeRefRc,
) -> Result<Token> {
    // Create TypeRef for System.Console using placeholder for resolution_scope
    let console_typeref = TypeRefBuilder::new()
        .name("Console")
        .namespace("System")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            mscorlib_ref.placeholder(),
            CodedIndexType::ResolutionScope,
        ))
        .build(assembly)?;

    // Verify the TypeRef ChangeRef kind
    assert_eq!(
        console_typeref.kind(),
        ChangeRefKind::TableRow(TableId::TypeRef),
        "TypeRef ChangeRef should be a TypeRef table row"
    );

    // Create method signature for WriteLine(string)
    let signature = create_writeline_signature()?;

    // Create MemberRef for Console.WriteLine using placeholder for class
    let member_ref = MemberRefBuilder::new()
        .name("WriteLine")
        .class(CodedIndex::new(
            TableId::TypeRef,
            console_typeref.placeholder(),
            CodedIndexType::MemberRefParent,
        ))
        .signature(&signature)
        .build(assembly)?;

    // Verify the MemberRef ChangeRef kind
    assert_eq!(
        member_ref.kind(),
        ChangeRefKind::TableRow(TableId::MemberRef),
        "MemberRef ChangeRef should be a MemberRef table row"
    );

    // Use placeholder_token() for table row references - resolved during write
    Ok(member_ref
        .placeholder_token()
        .expect("MemberRef should have placeholder token"))
}

/// Helper function to create the method signature for Console.WriteLine(string)
fn create_writeline_signature() -> Result<Vec<u8>> {
    let signature = SignatureMethod {
        has_this: false,
        explicit_this: false,
        default: true,
        vararg: false,
        cdecl: false,
        stdcall: false,
        thiscall: false,
        fastcall: false,
        unmanaged: false,
        param_count_generic: 0,
        param_count: 1,
        return_type: SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::Void,
        },
        params: vec![SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::String,
        }],
        varargs: Vec::new(),
    };

    encode_method_signature(&signature)
}

//! Method body formatting: `.maxstack`, `.locals`, IL instructions, exception handlers.
//!
//! Renders the interior of a `.method` block: `.maxstack`, `.locals init (...)`,
//! individual IL instructions with offset labels, interleaved `.try`/`catch`/`finally`
//! exception blocks, and optional hex byte dumps.

use std::io::{self, Write};

use crate::{
    assembly::{FlowType, Immediate, Instruction, Operand},
    formatting::{
        exceptions::{BlockEvent, ExceptionBlockLayout},
        helpers::{format_type_sig, ldc_r4_operand, ldc_r8_operand},
        tokens::resolve_token,
        FormatterOptions,
    },
    metadata::{
        method::Method,
        signatures::{parse_local_var_signature, SignatureLocalVariable},
        tables::StandAloneSigRaw,
    },
    CilObject,
};

/// Write the full method body: `.maxstack`, `.locals`, and IL instructions.
///
/// Emits the maxstack directive, local variable declarations, and all IL
/// instructions with interleaved exception handler blocks (`.try`/`catch`/
/// `finally`/`fault`/`filter`). Instructions are indented dynamically based
/// on exception handler nesting depth.
pub fn format_method_body(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    method: &Method,
    asm: &CilObject,
) -> io::Result<()> {
    let header_size = if let Some(body) = method.body.get() {
        // ILDasm order: RVA comment (if show_bytes), code size comment, .maxstack, .locals
        if opts.show_rva_comments {
            if opts.show_bytes {
                if let Some(rva) = method.rva {
                    writeln!(w, "    // Method begins at RVA 0x{rva:x}")?;
                }
            }
            let code_size = body.size();
            writeln!(w, "    // Code size       {code_size} (0x{code_size:x})")?;
        }

        writeln!(w, "    .maxstack {}", body.max_stack)?;

        format_locals(w, method, asm)?;

        body.size_header as u64
    } else {
        0
    };

    let code_start_rva = u64::from(method.rva.unwrap_or(0)).saturating_add(header_size);

    // Build exception block layout for interleaving
    let layout = method
        .body
        .get()
        .map(|body| ExceptionBlockLayout::build(&body.exception_handlers, asm));

    let mut nesting_depth: usize = 2; // base indentation inside method body

    for instruction in method.instructions() {
        let il_offset = instruction.rva.saturating_sub(code_start_rva);

        // Emit any block events at this IL offset
        #[allow(clippy::cast_possible_truncation)]
        if let Some(ref layout) = layout {
            if let Some(events) = layout.events.get(&(il_offset as u32)) {
                for event in events {
                    // Adjust depth for closes (before printing)
                    if matches!(
                        event,
                        BlockEvent::TryClose | BlockEvent::HandlerClose | BlockEvent::FilterClose
                    ) {
                        nesting_depth = nesting_depth.saturating_sub(1);
                    }

                    let line = ExceptionBlockLayout::format_event(event, nesting_depth);
                    writeln!(w, "{line}")?;

                    // Adjust depth for opens (after printing)
                    if matches!(
                        event,
                        BlockEvent::TryOpen
                            | BlockEvent::HandlerOpen { .. }
                            | BlockEvent::FilterOpen
                    ) {
                        nesting_depth = nesting_depth.saturating_add(1);
                    }
                }
            }
        }

        format_instruction(opts, w, instruction, code_start_rva, asm, nesting_depth)?;
    }

    Ok(())
}

/// Write only raw IL instructions without method structure.
///
/// Skips `.maxstack`, `.locals`, and exception handler blocks. Used when
/// the `--raw` formatter option is enabled.
pub fn format_method_body_raw(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    method: &Method,
    asm: &CilObject,
) -> io::Result<()> {
    let header_size = method.body.get().map_or(0, |b| b.size_header as u64);
    let code_start_rva = u64::from(method.rva.unwrap_or(0)).saturating_add(header_size);
    for instruction in method.instructions() {
        format_instruction(opts, w, instruction, code_start_rva, asm, 2)?;
    }
    Ok(())
}

/// Write a `.locals init (...)` directive listing all local variables.
///
/// Each local variable is emitted with its index, type name, pinned/byref
/// modifiers, and an auto-generated name (`V_N`). Skipped if the method
/// has no local variables.
///
/// Prefers reading the raw local variable signature blob from the StandAloneSig
/// table, which preserves the original TypeDef/TypeRef tokens and produces
/// correct assembly-scoped names for nested types. Falls back to the resolved
/// `LocalVariable` data if the raw blob is unavailable.
fn format_locals(w: &mut dyn Write, method: &Method, asm: &CilObject) -> io::Result<()> {
    // The locals as the method's signature declares them, parsed from its StandAloneSig blob
    // (which keeps the original tokens, so nested types get their assembly-scoped names).
    // Only a blob that cannot be read falls back to the resolved locals, each rebuilt into a
    // signature local; one that cannot be keeps its slot as `???` so the indices stay right.
    // The block was skipped whenever the resolved locals were empty, though the signature
    // declared locals the body's `ldloc`s still name.
    let parsed: Option<Vec<SignatureLocalVariable>> = method.body.get().and_then(|body| {
        let rid = body.local_var_sig_rid()?;
        let row = asm
            .tables()?
            .table::<StandAloneSigRaw>()?
            .get(rid)
            .ok()
            .flatten()?;
        let data = asm.blob()?.get(row.signature as usize).ok()?;
        parse_local_var_signature(data).ok().map(|sig| sig.locals)
    });
    let locals: Vec<Option<SignatureLocalVariable>> = match parsed {
        Some(locals) => locals.into_iter().map(Some).collect(),
        None => method
            .local_vars
            .iter()
            .map(|(_, local)| local.to_signature_local())
            .collect(),
    };
    if locals.is_empty() {
        return Ok(());
    }

    let is_init = method.body.get().is_some_and(|b| b.is_init_local);
    if is_init {
        writeln!(w, "    .locals init (")?;
    } else {
        writeln!(w, "    .locals (")?;
    }

    let count = locals.len();
    for (i, local) in locals.iter().enumerate() {
        // A by-reference local's `&` belongs to its type, and `pinned` follows the type:
        // `int32& pinned`. `pinned&` is no ILAsm.
        let declared = local.as_ref().map_or_else(
            || "???".to_string(),
            |local| {
                let byref = if local.is_byref { "&" } else { "" };
                let pinned = if local.is_pinned { " pinned" } else { "" };
                format!("{}{byref}{pinned}", format_type_sig(&local.base, asm))
            },
        );
        let comma = if i.saturating_add(1) < count { "," } else { "" };
        writeln!(w, "      [{i}] {declared} V_{i}{comma}")?;
    }

    writeln!(w, "    )")?;
    Ok(())
}

/// Write a single IL instruction line with dynamic indentation.
///
/// Emits the optional hex byte dump, `IL_XXXX:` offset label, mnemonic,
/// and formatted operand. Indentation is controlled by `indent_depth` to
/// reflect exception handler nesting.
fn format_instruction(
    opts: &FormatterOptions,
    w: &mut dyn Write,
    instruction: &Instruction,
    code_start_rva: u64,
    asm: &CilObject,
    indent_depth: usize,
) -> io::Result<()> {
    let offset = instruction.rva.saturating_sub(code_start_rva);
    let pad = "  ".repeat(indent_depth);

    if opts.show_bytes {
        format_instruction_bytes(w, instruction)?;
    }

    if opts.show_offsets {
        write!(w, "{pad}IL_{offset:04x}: ")?;
    } else {
        write!(w, "{pad}")?;
    }

    write!(w, "{:<12}", instruction.mnemonic)?;

    let operand_str = format_operand(opts, instruction, code_start_rva, asm);
    if !operand_str.is_empty() {
        write!(w, " {operand_str}")?;
    }

    writeln!(w)?;
    Ok(())
}

/// Format an instruction's operand as a display string.
///
/// Handles branch targets (as `IL_XXXX` labels), immediate values, metadata
/// token resolution, local/argument indices, and switch tables.
fn format_operand(
    opts: &FormatterOptions,
    instruction: &Instruction,
    code_start_rva: u64,
    asm: &CilObject,
) -> String {
    // For branch/leave instructions with computed targets, show IL labels
    let is_branch = matches!(
        instruction.flow_type,
        FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Leave
    );
    if is_branch && !instruction.branch_targets.is_empty() {
        if let Some(&target) = instruction.branch_targets.first() {
            let offset = target.saturating_sub(code_start_rva);
            return format!("IL_{offset:04x}");
        }
    }

    match &instruction.operand {
        Operand::None => String::new(),
        // A float operand as ILAsm reads it: `Display` writes `inf`, `NaN` and `-0`, and a
        // large value with hundreds of digits
        Operand::Immediate(Immediate::Float32(value)) => ldc_r4_operand(*value),
        Operand::Immediate(Immediate::Float64(value)) => ldc_r8_operand(*value),
        Operand::Immediate(imm) => imm.to_string(),
        Operand::Target(addr) => {
            let offset = addr.saturating_sub(code_start_rva);
            format!("IL_{offset:04x}")
        }
        Operand::Token(tok) => {
            let resolved = resolve_token(asm, *tok);

            // ldtoken can reference types, fields, or methods. ILAsm needs an
            // explicit `field` or `method` prefix to disambiguate when the token
            // is not a type token.
            let prefix = if instruction.mnemonic == "ldtoken" {
                match tok.table() {
                    0x04 => "field ",
                    0x06 | 0x0A | 0x2B => "method ",
                    _ => "",
                }
            } else {
                ""
            };

            match resolved {
                Some(name) if opts.show_tokens => {
                    format!("{prefix}{name} /* 0x{:08X} */", tok.value())
                }
                Some(name) => format!("{prefix}{name}"),
                None => format!("(0x{:08X})", tok.value()),
            }
        }
        Operand::Local(idx) => format!("V_{idx}"),
        Operand::Argument(idx) => format!("{idx}"),
        Operand::Switch(offsets) => {
            // ILDasm emits switch targets on separate lines, each indented
            if offsets.is_empty() {
                "( )".to_string()
            } else {
                let mut result = String::from("(\n");
                for (i, _) in offsets.iter().enumerate() {
                    let label = if let Some(target) = instruction.branch_targets.get(i) {
                        let off = target.saturating_sub(code_start_rva);
                        format!("IL_{off:04x}")
                    } else {
                        "???".to_string()
                    };
                    let suffix = if i.saturating_add(1) == offsets.len() {
                        ")"
                    } else {
                        ","
                    };
                    result.push_str(&format!("                    {label}{suffix}\n"));
                }
                // Remove trailing newline — writeln in format_instruction adds one
                result.truncate(result.len().saturating_sub(1));
                result
            }
        }
    }
}

/// Write the hex byte encoding of an instruction as a `/* XX XX ... */` comment.
///
/// Reconstructs the raw byte encoding from the instruction's prefix, opcode,
/// and operand. Used when the `--bytes` formatter option is enabled.
fn format_instruction_bytes(w: &mut dyn Write, instruction: &Instruction) -> io::Result<()> {
    let mut bytes = Vec::new();

    if instruction.prefix != 0 {
        bytes.push(instruction.prefix);
    }
    bytes.push(instruction.opcode);

    match &instruction.operand {
        Operand::None => {}
        Operand::Immediate(imm) => match imm {
            Immediate::Int8(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::UInt8(v) => bytes.push(*v),
            Immediate::Int16(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::UInt16(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::Int32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::UInt32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::Int64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::UInt64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::Float32(v) => bytes.extend_from_slice(&v.to_le_bytes()),
            Immediate::Float64(v) => bytes.extend_from_slice(&v.to_le_bytes()),
        },
        Operand::Target(_) => {
            // CIL instruction sizes are small (max ~10 bytes), truncation is safe
            #[allow(clippy::cast_possible_truncation)]
            let operand_size = (instruction.size as usize)
                .saturating_sub(if instruction.prefix != 0 { 2 } else { 1 });
            bytes.extend(std::iter::repeat_n(0x00, operand_size));
        }
        Operand::Token(tok) => {
            bytes.extend_from_slice(&tok.value().to_le_bytes());
        }
        Operand::Local(idx) | Operand::Argument(idx) => {
            if instruction.size <= 2 {
                // CIL short-form instructions use 1 byte for local/argument indices
                #[allow(clippy::cast_possible_truncation)]
                {
                    bytes.push(*idx as u8);
                }
            } else {
                bytes.extend_from_slice(&idx.to_le_bytes());
            }
        }
        Operand::Switch(offsets) => {
            // CIL switch instruction: count is encoded as u32
            #[allow(clippy::cast_possible_truncation)]
            let count = offsets.len() as u32;
            bytes.extend_from_slice(&count.to_le_bytes());
            for offset in offsets {
                bytes.extend_from_slice(&offset.to_le_bytes());
            }
        }
    }

    // Format: "/* XX XX XX */"
    write!(w, "    /* ")?;
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(w, " ")?;
        }
        write!(w, "{b:02X}")?;
    }
    write!(w, " */")?;
    writeln!(w)?;

    Ok(())
}

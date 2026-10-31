//! CIL instruction encoding and assembly functionality.
//!
//! This module provides the core instruction encoding capabilities for generating CIL bytecode
//! from high-level instruction representations. It serves as the reverse counterpart to the
//! decoder module, using the same instruction metadata tables for maximum consistency and code reuse.
//!
//! # Architecture
//!
//! The encoder follows a mirror approach to the decoder, reusing existing type definitions and
//! instruction metadata while providing reverse lookup capabilities. This ensures type safety
//! and maintains consistency between assembly and disassembly operations.
//!
//! # Key Components
//!
//! - [`InstructionEncoder`] - Core encoding engine for CIL instructions
//! - [`LabelFixup`] - Label resolution system for branch instructions
//! - Reverse lookup tables generated from existing [`crate::assembly::INSTRUCTIONS`] tables
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
//!
//! let mut encoder = InstructionEncoder::new();
//!
//! // Encode simple instructions
//! encoder.emit_instruction("nop", None)?;
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(5))))?;
//! encoder.emit_instruction("add", None)?;
//! encoder.emit_instruction("ret", None)?;
//!
//! let bytecode = encoder.finalize()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Label Resolution
//!
//! ```rust,no_run
//! use dotscope::assembly::InstructionEncoder;
//!
//! let mut encoder = InstructionEncoder::new();
//!
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_branch("br.s", "end_label")?;
//! encoder.emit_instruction("ldarg.1", None)?;
//! encoder.define_label("end_label")?;
//! encoder.emit_instruction("ret", None)?;
//!
//! let bytecode = encoder.finalize()?; // Labels resolved automatically
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use crate::{
    assembly::{
        instruction::{FlowType, Immediate, Instruction, Operand, OperandType},
        instructions::{CilInstruction, INSTRUCTIONS, INSTRUCTIONS_FE},
    },
    Error, Result,
};

/// Reverse lookup table mapping mnemonics to opcode information.
///
/// This static lookup table provides efficient O(1) mnemonic-to-opcode resolution by creating
/// a HashMap from the existing instruction tables. Each entry maps an instruction mnemonic
/// (e.g., "nop", "add", "br.s") to a tuple containing:
/// - Primary opcode byte
/// - Prefix byte (0x00 for single-byte instructions, 0xFE for extended instructions)  
/// - Reference to the instruction metadata
///
/// This approach maximizes code reuse by building on the existing static instruction tables
/// rather than duplicating instruction definitions.
static MNEMONIC_TO_OPCODE: OnceLock<
    HashMap<&'static str, (u8, u8, &'static CilInstruction<'static>)>,
> = OnceLock::new();

fn get_mnemonic_lookup(
) -> &'static HashMap<&'static str, (u8, u8, &'static CilInstruction<'static>)> {
    MNEMONIC_TO_OPCODE.get_or_init(|| {
        let mut map = HashMap::new();

        // Single-byte instructions (0x00 to 0xE0). The arrays are bounded to
        // u8 opcodes by construction; any out-of-range entry is silently
        // skipped (cannot be encoded with a 1-byte opcode anyway).
        for (opcode, instr) in INSTRUCTIONS.iter().enumerate() {
            if !instr.instr.is_empty() {
                if let Ok(opcode_u8) = u8::try_from(opcode) {
                    map.insert(instr.instr, (opcode_u8, 0, instr));
                }
            }
        }

        // Extended instructions (0xFE prefix)
        for (opcode, instr) in INSTRUCTIONS_FE.iter().enumerate() {
            if !instr.instr.is_empty() {
                if let Ok(opcode_u8) = u8::try_from(opcode) {
                    map.insert(instr.instr, (opcode_u8, 0xFE, instr));
                }
            }
        }

        map
    })
}

/// Label fixup information for branch instruction resolution.
///
/// This structure tracks unresolved label references during the encoding process,
/// allowing forward and backward branch resolution when the final bytecode positions
/// are calculated.
#[derive(Debug, Clone)]
pub struct LabelFixup {
    /// The target label name to resolve
    pub label: String,
    /// Position in bytecode where the branch offset should be written
    pub fixup_position: usize,
    /// Size of the branch offset field (1, 2, or 4 bytes)
    pub offset_size: u8,
    /// Position of the branch instruction for relative offset calculation
    pub instruction_position: usize,
    /// If Some, this branch can be optimized to short form using this mnemonic
    pub short_form_mnemonic: Option<&'static str>,
}

/// Switch fixup information for multi-way branch resolution.
///
/// This structure tracks unresolved switch target references, allowing
/// forward label resolution for switch instructions.
#[derive(Debug, Clone)]
pub struct SwitchFixup {
    /// The target label names to resolve (one per switch case)
    pub labels: Vec<String>,
    /// Position in bytecode where the switch targets start (after the count)
    pub fixup_position: usize,
    /// Position after the switch instruction (for relative offset calculation)
    pub instruction_end_position: usize,
}

/// Core CIL instruction encoder.
///
/// This encoder provides low-level instruction encoding capabilities, transforming
/// mnemonics and operands into CIL bytecode. It handles operand type validation,
/// opcode lookup, and maintains a label resolution system for branch instructions.
///
/// # Thread Safety
///
/// [`InstructionEncoder`] is not [`std::marker::Send`] or [`std::marker::Sync`] as it contains
/// mutable state for bytecode generation and label tracking. Create separate instances
/// for concurrent encoding operations.
///
/// # Examples
///
/// ## Basic Instruction Encoding
///
/// ```rust,no_run  
/// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
///
/// let mut encoder = InstructionEncoder::new();
///
/// // Simple instructions without operands
/// encoder.emit_instruction("nop", None)?;
/// encoder.emit_instruction("ret", None)?;
///
/// // Instructions with immediate operands
/// encoder.emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(42))))?;
/// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(1))))?;
///
/// let result = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Branch Instructions with Labels
///
/// ```rust,no_run
/// use dotscope::assembly::InstructionEncoder;
///
/// let mut encoder = InstructionEncoder::new();
///
/// encoder.emit_instruction("ldarg.0", None)?;
/// encoder.emit_branch("brfalse.s", "false_case")?;
/// encoder.emit_instruction("ldc.i4.1", None)?;
/// encoder.emit_branch("br.s", "end")?;
///
/// encoder.define_label("false_case")?;
/// encoder.emit_instruction("ldc.i4.0", None)?;
///
/// encoder.define_label("end")?;
/// encoder.emit_instruction("ret", None)?;
///
/// let bytecode = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct InstructionEncoder {
    /// Generated bytecode buffer
    bytecode: Vec<u8>,
    /// Defined label positions (label_name -> byte_position)
    labels: HashMap<String, u32>,
    /// Pending branch fixups awaiting label resolution
    fixups: Vec<LabelFixup>,
    /// Pending switch fixups awaiting label resolution
    switch_fixups: Vec<SwitchFixup>,
    /// Current stack depth (number of items on evaluation stack)
    current_stack_depth: i16,
    /// Maximum stack depth reached during encoding
    max_stack_depth: u16,
    /// Expected stack depth at branch targets for validation.
    /// When a branch is emitted, the current stack depth is recorded for the target label.
    /// When the label is defined, we verify all paths have the same depth.
    label_stack_depths: HashMap<String, i16>,
    /// Number of instructions emitted so far. Finalization never adds or removes
    /// an instruction before the end, so this count is also the index of the
    /// next instruction in the finished body.
    instruction_count: usize,
    /// Whether we're in unreachable code (after an unconditional branch, return, throw, etc.).
    /// When unreachable, the current_stack_depth is meaningless since there's no execution path.
    /// Defining a label resets this to false (the label makes code reachable again).
    unreachable: bool,
    /// Whether the stack depth is tracked and checked. Decoded instructions do not state a
    /// call's stack effect (its signature does), so re-encoding them leaves it off.
    tracks_stack: bool,
}

/// Maps long-form branch mnemonics to their short-form equivalents.
fn get_short_form_mnemonic(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "br" => Some("br.s"),
        "brfalse" => Some("brfalse.s"),
        "brtrue" => Some("brtrue.s"),
        "beq" => Some("beq.s"),
        "bne.un" => Some("bne.un.s"),
        "bge" => Some("bge.s"),
        "bge.un" => Some("bge.un.s"),
        "bgt" => Some("bgt.s"),
        "bgt.un" => Some("bgt.un.s"),
        "ble" => Some("ble.s"),
        "ble.un" => Some("ble.un.s"),
        "blt" => Some("blt.s"),
        "blt.un" => Some("blt.un.s"),
        "leave" => Some("leave.s"),
        _ => None,
    }
}

impl InstructionEncoder {
    /// Create a new instruction encoder.
    ///
    /// Initializes an empty encoder ready for instruction emission. The encoder
    /// maintains internal state for bytecode generation and label resolution.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// // Ready for instruction emission
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytecode: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
            switch_fixups: Vec::new(),
            current_stack_depth: 0,
            max_stack_depth: 0,
            label_stack_depths: HashMap::new(),
            unreachable: false,
            instruction_count: 0,
            tracks_stack: true,
        }
    }

    /// Emit a CIL instruction with optional operand.
    ///
    /// This method performs instruction encoding by looking up the mnemonic in the
    /// reverse lookup table, validating the operand type, and emitting the appropriate
    /// bytecode sequence.
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - The instruction mnemonic (e.g., "nop", "add", "ldarg.s")
    /// * `operand` - Optional operand for the instruction, must match expected type
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mnemonic is not recognized
    /// - The operand type doesn't match the instruction's expected operand type
    /// - The operand is missing when required or present when not expected
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// // Instructions without operands
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.emit_instruction("add", None)?;
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// // Instructions with operands  
    /// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(2))))?;
    /// encoder.emit_instruction("ldc.i4", Some(Operand::Immediate(Immediate::Int32(100))))?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_instruction(&mut self, mnemonic: &str, operand: Option<Operand>) -> Result<()> {
        let (opcode, prefix, metadata) = get_mnemonic_lookup()
            .get(mnemonic)
            .ok_or_else(|| Error::InvalidMnemonic(mnemonic.to_string()))?;

        // Emit prefix byte if needed (0xFE for extended instructions)
        if *prefix != 0 {
            self.bytecode.push(*prefix);
        }

        // Emit primary opcode
        self.bytecode.push(*opcode);
        self.instruction_count = self.instruction_count.saturating_add(1);

        // Emit operand based on expected type
        self.emit_operand(operand, metadata.op_type)?;

        // Update stack tracking
        self.update_stack_depth(u16::from(metadata.stack_pops), metadata.stack_pushes)
            .map_err(|e| malformed_error!("Stack error at instruction '{}': {}", mnemonic, e))?;

        // Mark code as unreachable after terminating instructions.
        // After these, there's no fall-through - execution only continues via labels.
        if matches!(
            metadata.flow,
            FlowType::Return | FlowType::Throw | FlowType::EndFinally
        ) {
            self.unreachable = true;
        }

        Ok(())
    }

    /// Emit an instruction from a previously decoded [`Instruction`], preserving its mnemonic
    /// and operand: useful for transforming IL by decoding, modifying operands (remapping
    /// tokens, say), and re-encoding. A branch or switch names its targets by RVA, which only
    /// a whole body gives positions: [`Self::encode_decoded`] encodes those.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The decoded instruction to emit
    ///
    /// # Errors
    ///
    /// Returns an error if the instruction's mnemonic is not recognized, if the operand
    /// doesn't match the expected type for that instruction, or if it is a branch or switch.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{InstructionEncoder, decode_stream};
    /// use dotscope::Parser;
    ///
    /// // Decode some IL
    /// let il_bytes = &[0x00, 0x2A]; // nop, ret
    /// let mut parser = Parser::new(il_bytes);
    /// let instructions = decode_stream(&mut parser, 0)?;
    ///
    /// // Re-encode the instructions
    /// let mut encoder = InstructionEncoder::new();
    /// for instr in &instructions {
    ///     encoder.emit_instruction_decoded(instr)?;
    /// }
    /// let (bytecode, _, _) = encoder.finalize()?;
    /// assert_eq!(bytecode, il_bytes);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_instruction_decoded(&mut self, instruction: &Instruction) -> Result<()> {
        if matches!(instruction.operand, Operand::Target(_) | Operand::Switch(_)) {
            return Err(Error::InvalidBranch(format!(
                "'{}' names its targets by RVA; encode the body with encode_decoded",
                instruction.mnemonic
            )));
        }
        let operand = if matches!(instruction.operand, Operand::None) {
            None
        } else {
            Some(instruction.operand.clone())
        };
        self.emit_instruction(instruction.mnemonic, operand)
    }

    /// Emit a branch instruction with label reference.
    ///
    /// This method handles branch instructions that reference labels, creating
    /// fixup entries for later resolution. The branch offset will be calculated
    /// and written during the finalization process.
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - The branch instruction mnemonic (e.g., "br.s", "brfalse", "brtrue.s")
    /// * `label` - The target label name to branch to
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidMnemonic`] if the mnemonic is not recognized.
    /// Returns [`crate::Error::InvalidBranch`] if the mnemonic is not a branch instruction
    /// or has an invalid operand type for branch encoding.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// encoder.emit_branch("br.s", "target_label")?;
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.define_label("target_label")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_branch(&mut self, mnemonic: &str, label: &str) -> Result<()> {
        self.emit_branch_form(mnemonic, label, true)
    }

    /// Emits a branch to `label`, which [`Self::finalize`] may shorten to its short form when
    /// `shrinkable` and the displacement fits.
    fn emit_branch_form(&mut self, mnemonic: &str, label: &str, shrinkable: bool) -> Result<()> {
        let (opcode, prefix, metadata) = get_mnemonic_lookup()
            .get(mnemonic)
            .ok_or_else(|| Error::InvalidMnemonic(mnemonic.to_string()))?;

        // Verify this is actually a branch instruction
        if !matches!(
            metadata.flow,
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Leave
        ) {
            return Err(Error::InvalidBranch(format!(
                "instruction '{mnemonic}' is not a branch instruction"
            )));
        }

        let instruction_start = self.bytecode.len();

        // Emit prefix byte if needed
        if *prefix != 0 {
            self.bytecode.push(*prefix);
        }

        // Emit primary opcode
        self.bytecode.push(*opcode);
        self.instruction_count = self.instruction_count.saturating_add(1);

        // Determine offset size and create fixup
        let offset_size = match metadata.op_type {
            OperandType::Int8 => 1,
            OperandType::Int16 => 2,
            OperandType::Int32 => 4,
            _ => {
                return Err(Error::InvalidBranch(
                    "operand type must be Int8, Int16, or Int32".to_string(),
                ))
            }
        };

        // Record fixup for later resolution
        // For long-form branches, record the short form for potential optimization
        let short_form_mnemonic = if offset_size == 4 && shrinkable {
            get_short_form_mnemonic(mnemonic)
        } else {
            None
        };
        let fixup = LabelFixup {
            label: label.to_string(),
            fixup_position: self.bytecode.len(),
            offset_size,
            instruction_position: instruction_start,
            short_form_mnemonic,
        };
        self.fixups.push(fixup);

        // Emit placeholder bytes for the offset (will be filled during finalization)
        for _ in 0..offset_size {
            self.bytecode.push(0);
        }

        // Update stack tracking for branch instructions
        self.update_stack_depth(u16::from(metadata.stack_pops), metadata.stack_pushes)
            .map_err(|e| {
                malformed_error!("Stack error at branch '{}' to '{}': {}", mnemonic, label, e)
            })?;

        // Record expected stack depth at branch target for validation.
        // After the branch pops its condition (if any), the target should see this depth.
        self.record_label_stack_depth(label)?;

        // Mark code as unreachable after unconditional branches.
        // Conditional branches (brfalse, brtrue, beq, etc.) have fall-through paths,
        // but unconditional branches (br, leave) and their short forms do not.
        if matches!(
            metadata.flow,
            FlowType::UnconditionalBranch | FlowType::Leave
        ) {
            self.unreachable = true;
        }

        Ok(())
    }

    /// Encodes a decoded method body over its code: each instruction at its own position in
    /// `code` (which starts at `code_rva`) and the bytes no instruction covers as they are,
    /// since code no path reaches may hold anything (obfuscators fill it with junk). Every
    /// instruction is labelled by its RVA, so branches and switches reach the same
    /// instructions in the form they were written (a long branch stays long), and the body's
    /// exception handlers, whose offsets are positions in `code`, stay valid. Decoded
    /// instructions encoded this way give back `code`; ones with a remapped operand of the
    /// same size give it back with that operand changed.
    ///
    /// The stack is not tracked: a call's effect on it is its signature's, which the
    /// instructions do not state, so the body's declared stack depth is the caller's to keep.
    ///
    /// # Errors
    ///
    /// When an instruction does not encode, lies outside `code` or overlaps the one before it
    /// (as one that changed size does), or a branch or switch reaches no instruction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::{assembly::{decode_stream, InstructionEncoder}, Parser};
    ///
    /// // br.s +1, then a junk byte no path reaches, then ret
    /// let code = [0x2B, 0x01, 0xFF, 0x2A];
    /// let instructions: Vec<_> = decode_stream(&mut Parser::new(&code[..2]), 0x1000)?
    ///     .into_iter()
    ///     .chain(decode_stream(&mut Parser::new(&code[3..]), 0x1003)?)
    ///     .collect();
    /// assert_eq!(InstructionEncoder::encode_decoded(&instructions, &code, 0x1000)?, code);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode_decoded(
        instructions: &[Instruction],
        code: &[u8],
        code_rva: u64,
    ) -> Result<Vec<u8>> {
        let mut ordered: Vec<&Instruction> = instructions.iter().collect();
        ordered.sort_by_key(|instruction| instruction.rva);
        let label = |rva: u64| format!("IL_{rva:x}");

        let mut encoder = InstructionEncoder {
            tracks_stack: false,
            ..InstructionEncoder::new()
        };
        // The RVA up to which `code` has been written
        let mut written = code_rva;
        let uncovered = |encoder: &mut InstructionEncoder, from: u64, until: u64| -> Result<()> {
            if until < from {
                return Err(malformed_error!(
                    "Instruction at 0x{:x} overlaps the one before it",
                    until
                ));
            }
            let start = usize::try_from(from.saturating_sub(code_rva))
                .map_err(|_| malformed_error!("Code offset exceeds usize"))?;
            let end = usize::try_from(until.saturating_sub(code_rva))
                .map_err(|_| malformed_error!("Code offset exceeds usize"))?;
            let gap = code.get(start..end).ok_or_else(|| {
                malformed_error!("Instruction at 0x{:x} lies outside its code", until)
            })?;
            encoder.emit_raw(gap);
            Ok(())
        };

        for instruction in &ordered {
            uncovered(&mut encoder, written, instruction.rva)?;
            encoder.define_label(&label(instruction.rva))?;
            match &instruction.operand {
                Operand::Target(target) => {
                    encoder.emit_branch_form(instruction.mnemonic, &label(*target), false)?;
                }
                Operand::Switch(offsets) => {
                    let end = instruction.rva.saturating_add(instruction.size);
                    let targets: Vec<String> = offsets
                        .iter()
                        .map(|offset| label(end.saturating_add_signed(i64::from(*offset))))
                        .collect();
                    let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
                    encoder.emit_switch(&targets)?;
                }
                _ => encoder.emit_instruction_decoded(instruction)?,
            }
            written = instruction.rva.saturating_add(instruction.size);
        }
        uncovered(
            &mut encoder,
            written,
            code_rva.saturating_add(code.len() as u64),
        )?;

        let (code, _, _) = encoder.finalize_as_written()?;
        Ok(code)
    }

    /// Emits `bytes` as they are: code no instruction is decoded from, kept in place. They
    /// have no effect on the stack and hold no label.
    pub fn emit_raw(&mut self, bytes: &[u8]) {
        self.bytecode.extend_from_slice(bytes);
    }

    /// Emit a switch instruction with multiple target labels.
    ///
    /// The switch instruction performs a multi-way branch based on an integer value.
    /// If the value is within range (0 to n-1), execution transfers to the corresponding
    /// label. If the value is out of range, execution continues to the next instruction
    /// (fall-through).
    ///
    /// # Parameters
    ///
    /// * `labels` - Target label names for each switch case (0-indexed)
    ///
    /// # Errors
    ///
    /// Returns an error if the labels slice is empty or instruction encoding fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// encoder.emit_instruction("ldarg.0", None)?;
    /// encoder.emit_switch(&["case0", "case1", "case2"])?;
    /// encoder.emit_instruction("ldc.i4.m1", None)?; // Default case (fall-through)
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// encoder.define_label("case0")?;
    /// encoder.emit_instruction("ldc.i4.0", None)?;
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// encoder.define_label("case1")?;
    /// encoder.emit_instruction("ldc.i4.1", None)?;
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// encoder.define_label("case2")?;
    /// encoder.emit_instruction("ldc.i4.2", None)?;
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// let (bytecode, max_stack, _) = encoder.finalize()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_switch(&mut self, labels: &[&str]) -> Result<()> {
        if labels.is_empty() {
            return Err(Error::InvalidBranch(
                "switch must have at least one target".to_string(),
            ));
        }

        // Emit the switch opcode (0x45)
        self.bytecode.push(0x45);
        self.instruction_count = self.instruction_count.saturating_add(1);

        // Emit the number of targets
        let num_targets =
            u32::try_from(labels.len()).map_err(|_| malformed_error!("Too many switch targets"))?;
        self.bytecode.extend_from_slice(&num_targets.to_le_bytes());

        // Record the position where targets start
        let fixup_position = self.bytecode.len();

        // Emit placeholder bytes for each target (4 bytes each)
        for _ in 0..labels.len() {
            self.bytecode.extend_from_slice(&[0, 0, 0, 0]);
        }

        // Record the position after the switch instruction (for relative offset calculation)
        let instruction_end_position = self.bytecode.len();

        // Create the switch fixup
        let switch_fixup = SwitchFixup {
            labels: labels.iter().map(|s| (*s).to_string()).collect(),
            fixup_position,
            instruction_end_position,
        };
        self.switch_fixups.push(switch_fixup);

        // Switch pops one value from the stack
        self.update_stack_depth(1, 0)
            .map_err(|e| malformed_error!("Stack error at 'switch': {}", e))?;

        // Record expected stack depth at all switch targets for validation
        for label in labels {
            self.record_label_stack_depth(label)?;
        }

        Ok(())
    }

    /// Emit a call instruction with explicit stack effect tracking.
    ///
    /// This method handles `call`, `callvirt`, `calli`, and `newobj` instructions
    /// where the stack effect depends on the method signature and cannot be
    /// determined from static instruction metadata alone.
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - The instruction mnemonic ("call", "callvirt", "calli", or "newobj")
    /// * `operand` - The method/signature token operand
    /// * `num_args` - Number of arguments popped from stack (including 'this' for instance calls)
    /// * `has_result` - Whether the call pushes a result onto the stack
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is not recognized or encoding fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{InstructionEncoder, Operand};
    /// use dotscope::metadata::token::Token;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// // Call a method with 2 arguments that returns a value
    /// encoder.emit_call(
    ///     "call",
    ///     Some(Operand::Token(Token::new(0x0a000001))),
    ///     2,    // pops 2 arguments
    ///     true  // pushes 1 result
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_call(
        &mut self,
        mnemonic: &str,
        operand: Option<Operand>,
        num_args: u16,
        has_result: bool,
    ) -> Result<()> {
        let (opcode, prefix, metadata) = get_mnemonic_lookup()
            .get(mnemonic)
            .ok_or_else(|| Error::InvalidMnemonic(mnemonic.to_string()))?;

        // Emit prefix byte if needed (0xFE for extended instructions)
        if *prefix != 0 {
            self.bytecode.push(*prefix);
        }

        // Emit primary opcode
        self.bytecode.push(*opcode);
        self.instruction_count = self.instruction_count.saturating_add(1);

        // Emit operand based on expected type
        self.emit_operand(operand, metadata.op_type)?;

        // Use the caller-provided stack effect instead of metadata
        let pushes = u8::from(has_result);
        self.update_stack_depth(num_args, pushes)
            .map_err(|e| malformed_error!("Stack error at call '{}': {}", mnemonic, e))?;

        Ok(())
    }

    /// Emit a `ldarg` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `ldarg.0` through `ldarg.3` for indices 0-3 (1 byte)
    /// - `ldarg.s` for indices 4-255 (2 bytes)
    /// - `ldarg` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// encoder.emit_ldarg(0)?;  // Emits ldarg.0 (1 byte)
    /// encoder.emit_ldarg(10)?; // Emits ldarg.s 10 (2 bytes)
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_ldarg(&mut self, index: u16) -> Result<()> {
        match index {
            0 => self.emit_instruction("ldarg.0", None),
            1 => self.emit_instruction("ldarg.1", None),
            2 => self.emit_instruction("ldarg.2", None),
            3 => self.emit_instruction("ldarg.3", None),
            x if x <= 255 =>
            {
                #[allow(clippy::cast_possible_truncation)]
                self.emit_instruction(
                    "ldarg.s",
                    Some(Operand::Immediate(Immediate::UInt8(x as u8))),
                )
            }
            x =>
            {
                #[allow(clippy::cast_possible_wrap)]
                self.emit_instruction(
                    "ldarg",
                    Some(Operand::Immediate(Immediate::Int16(x as i16))),
                )
            }
        }
    }

    /// Emit a `ldloc` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `ldloc.0` through `ldloc.3` for indices 0-3 (1 byte)
    /// - `ldloc.s` for indices 4-255 (2 bytes)
    /// - `ldloc` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    pub fn emit_ldloc(&mut self, index: u16) -> Result<()> {
        match index {
            0 => self.emit_instruction("ldloc.0", None),
            1 => self.emit_instruction("ldloc.1", None),
            2 => self.emit_instruction("ldloc.2", None),
            3 => self.emit_instruction("ldloc.3", None),
            x if x <= 255 =>
            {
                #[allow(clippy::cast_possible_truncation)]
                self.emit_instruction(
                    "ldloc.s",
                    Some(Operand::Immediate(Immediate::UInt8(x as u8))),
                )
            }
            x =>
            {
                #[allow(clippy::cast_possible_wrap)]
                self.emit_instruction(
                    "ldloc",
                    Some(Operand::Immediate(Immediate::Int16(x as i16))),
                )
            }
        }
    }

    /// Emit a `starg` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `starg.s` for indices 0-255 (2 bytes)
    /// - `starg` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    pub fn emit_starg(&mut self, index: u16) -> Result<()> {
        if index <= 255 {
            #[allow(clippy::cast_possible_truncation)]
            self.emit_instruction(
                "starg.s",
                Some(Operand::Immediate(Immediate::UInt8(index as u8))),
            )
        } else {
            #[allow(clippy::cast_possible_wrap)]
            self.emit_instruction(
                "starg",
                Some(Operand::Immediate(Immediate::Int16(index as i16))),
            )
        }
    }

    /// Emit a `stloc` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `stloc.0` through `stloc.3` for indices 0-3 (1 byte)
    /// - `stloc.s` for indices 4-255 (2 bytes)
    /// - `stloc` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    pub fn emit_stloc(&mut self, index: u16) -> Result<()> {
        match index {
            0 => self.emit_instruction("stloc.0", None),
            1 => self.emit_instruction("stloc.1", None),
            2 => self.emit_instruction("stloc.2", None),
            3 => self.emit_instruction("stloc.3", None),
            x if x <= 255 =>
            {
                #[allow(clippy::cast_possible_truncation)]
                self.emit_instruction(
                    "stloc.s",
                    Some(Operand::Immediate(Immediate::UInt8(x as u8))),
                )
            }
            x =>
            {
                #[allow(clippy::cast_possible_wrap)]
                self.emit_instruction(
                    "stloc",
                    Some(Operand::Immediate(Immediate::Int16(x as i16))),
                )
            }
        }
    }

    /// Emit a `ldc.i4` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `ldc.i4.m1` through `ldc.i4.8` for values -1 to 8 (1 byte)
    /// - `ldc.i4.s` for values -128 to 127 (2 bytes)
    /// - `ldc.i4` for all other values (5 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// encoder.emit_ldc_i4(0)?;      // Emits ldc.i4.0 (1 byte)
    /// encoder.emit_ldc_i4(42)?;     // Emits ldc.i4.s 42 (2 bytes)
    /// encoder.emit_ldc_i4(1000)?;   // Emits ldc.i4 1000 (5 bytes)
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_ldc_i4(&mut self, value: i32) -> Result<()> {
        match value {
            -1 => self.emit_instruction("ldc.i4.m1", None),
            0 => self.emit_instruction("ldc.i4.0", None),
            1 => self.emit_instruction("ldc.i4.1", None),
            2 => self.emit_instruction("ldc.i4.2", None),
            3 => self.emit_instruction("ldc.i4.3", None),
            4 => self.emit_instruction("ldc.i4.4", None),
            5 => self.emit_instruction("ldc.i4.5", None),
            6 => self.emit_instruction("ldc.i4.6", None),
            7 => self.emit_instruction("ldc.i4.7", None),
            8 => self.emit_instruction("ldc.i4.8", None),
            x if (-128..=127).contains(&x) =>
            {
                #[allow(clippy::cast_possible_truncation)]
                self.emit_instruction(
                    "ldc.i4.s",
                    Some(Operand::Immediate(Immediate::Int8(x as i8))),
                )
            }
            x => self.emit_instruction("ldc.i4", Some(Operand::Immediate(Immediate::Int32(x)))),
        }
    }

    /// Emit a `ldarga` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `ldarga.s` for indices 0-255 (2 bytes)
    /// - `ldarga` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    pub fn emit_ldarga(&mut self, index: u16) -> Result<()> {
        if index <= 255 {
            #[allow(clippy::cast_possible_truncation)]
            self.emit_instruction(
                "ldarga.s",
                Some(Operand::Immediate(Immediate::UInt8(index as u8))),
            )
        } else {
            #[allow(clippy::cast_possible_wrap)]
            self.emit_instruction(
                "ldarga",
                Some(Operand::Immediate(Immediate::Int16(index as i16))),
            )
        }
    }

    /// Emit a `ldloca` instruction with optimal encoding.
    ///
    /// Automatically selects the most compact form:
    /// - `ldloca.s` for indices 0-255 (2 bytes)
    /// - `ldloca` for indices 256+ (4 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if instruction encoding fails.
    pub fn emit_ldloca(&mut self, index: u16) -> Result<()> {
        if index <= 255 {
            #[allow(clippy::cast_possible_truncation)]
            self.emit_instruction(
                "ldloca.s",
                Some(Operand::Immediate(Immediate::UInt8(index as u8))),
            )
        } else {
            #[allow(clippy::cast_possible_wrap)]
            self.emit_instruction(
                "ldloca",
                Some(Operand::Immediate(Immediate::Int16(index as i16))),
            )
        }
    }

    /// Define a label at the current bytecode position.
    ///
    /// Labels mark positions in the bytecode that can be referenced by branch
    /// instructions. Each label must have a unique name within the encoder scope.
    ///
    /// # Parameters
    ///
    /// * `name` - Unique label name
    ///
    /// # Errors
    ///
    /// Returns an error if a label with the same name has already been defined.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.define_label("loop_start")?;
    /// encoder.emit_instruction("ldarg.0", None)?;
    /// encoder.emit_branch("br.s", "loop_start")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn define_label(&mut self, name: &str) -> Result<()> {
        if self.labels.contains_key(name) {
            return Err(Error::DuplicateLabel(name.to_string()));
        }

        // Validate or set stack depth for this label.
        // All control flow paths to this label must have the same stack depth.
        if let Some(&expected) = self.label_stack_depths.get(name) {
            if self.unreachable {
                // We're in unreachable code (after an unconditional branch/return/throw).
                // The current_stack_depth is meaningless since there's no execution path here.
                // Reset to the expected depth from branches that target this label.
                self.current_stack_depth = expected;
            } else if self.current_stack_depth != expected {
                // We have a fall-through path AND branches to this label.
                // All paths must have the same stack depth.
                return Err(malformed_error!(
                    "Stack depth mismatch at label '{}': expected {} (from branch), got {} (current)",
                    name,
                    expected,
                    self.current_stack_depth
                ));
            }
        } else if !self.unreachable {
            // First time seeing this label via fall-through from reachable code.
            // Record the current depth as expected.
            self.label_stack_depths
                .insert(name.to_string(), self.current_stack_depth);
        } else {
            // Unreachable code with no existing expected depth.
            // Reset current_stack_depth to 0 before making code reachable again.
            // The depth was meaningless garbage from unreachable code, and we don't
            // want it to propagate to reachable code that follows this label.
            // The first actual branch to this label will set the correct expected depth.
            self.current_stack_depth = 0;
        }

        // Defining a label makes code reachable again (via branches to this label).
        self.unreachable = false;

        let bytecode_len = u32::try_from(self.bytecode.len())
            .map_err(|_| malformed_error!("Bytecode length exceeds u32 range"))?;
        self.labels.insert(name.to_string(), bytecode_len);
        Ok(())
    }

    /// Marks the current position as unreachable.
    ///
    /// After calling this, the encoder treats the current code position as unreachable
    /// (no execution path reaches here). This is used for exception handler entry blocks
    /// which are only entered via CLR exception dispatch, never via fallthrough.
    ///
    /// When `define_label` is called while unreachable, it resets the stack depth to
    /// the expected depth (from branches or `set_label_stack_depth`) rather than
    /// validating against the current depth.
    pub fn mark_unreachable(&mut self) {
        self.unreachable = true;
    }

    /// Returns the current bytecode position (length of emitted bytecode so far).
    ///
    /// This can be used to track instruction offsets during code generation,
    /// for example to record block start positions for exception handler remapping.
    ///
    /// # Returns
    ///
    /// The current bytecode length in bytes.
    #[must_use]
    pub fn current_position(&self) -> u32 {
        // CIL method bodies are limited to u32 size by the format
        #[allow(clippy::cast_possible_truncation)]
        let position = self.bytecode.len() as u32;
        position
    }

    /// Returns the number of instructions emitted so far.
    ///
    /// Finalization only resizes branches and may append a terminator at the
    /// end, so the count taken before an instruction is emitted is that
    /// instruction's index in the decoded, finished body. A caller can use it
    /// to attach its own information to instructions by index.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Ensures the method ends with a proper method-terminating instruction.
    ///
    /// CIL methods must end with an instruction that terminates execution
    /// (ret, throw, rethrow, jmp, endfinally). Control flow instructions like
    /// `br` or `br.s` transfer control but don't terminate the method - if the
    /// branch target is an empty block at the end, the decoder would read past
    /// the method body into garbage data.
    ///
    /// This method checks two conditions:
    /// 1. If the bytecode ends with a valid method terminator opcode
    /// 2. If any branch targets a label at or past the end of bytecode (empty block)
    ///
    /// If either condition fails, a `ret` instruction is appended.
    ///
    /// # Method Terminators
    ///
    /// The following opcodes are considered proper method terminators:
    /// - `ret` (0x2A) - Return from method
    /// - `throw` (0x7A) - Throw exception
    /// - `rethrow` (0xFE 0x1A) - Rethrow current exception
    /// - `endfinally` (0xDC) - End finally/fault block
    /// - `jmp` (0x27) - Jump to another method (tail call)
    ///
    /// # Errors
    ///
    /// Returns an error if emitting the `ret` instruction fails.
    fn ensure_method_terminated(&mut self) -> Result<()> {
        if self.bytecode.is_empty() {
            // Empty method - no terminator needed (or handled elsewhere)
            return Ok(());
        }

        // Check if the last instruction is a proper method terminator
        let ends_with_terminator = if let Some(&last_byte) = self.bytecode.last() {
            // Single-byte terminators: ret, throw, endfinally, jmp
            matches!(last_byte, 0x2A | 0x7A | 0xDC | 0x27)
                // Two-byte terminator: rethrow (0xFE 0x1A)
                || (self
                    .bytecode
                    .len()
                    .checked_sub(2)
                    .and_then(|i| self.bytecode.get(i).copied())
                    == Some(0xFE)
                    && last_byte == 0x1A)
        } else {
            false
        };

        if ends_with_terminator {
            return Ok(());
        }

        // The bytecode doesn't end with a terminator. Check if any branch targets
        // a label at or past the current end of bytecode. Such branches point to
        // empty blocks and need valid code at the target.
        let current_len = self.bytecode.len();
        let has_branch_to_end = self.fixups.iter().any(|fixup| {
            if let Some(&label_pos) = self.labels.get(&fixup.label) {
                // Label is defined at or past the end of bytecode
                label_pos as usize >= current_len
            } else {
                // Label not defined yet - shouldn't happen, but be safe
                false
            }
        });

        if has_branch_to_end {
            self.emit_instruction("ret", None)?;
        }

        Ok(())
    }

    /// Returns the resolved offset for a defined label.
    ///
    /// # Arguments
    ///
    /// * `name` - The label name to look up.
    ///
    /// # Returns
    ///
    /// The byte offset of the label, or `None` if the label is not defined.
    #[must_use]
    pub fn label_offset(&self, name: &str) -> Option<u32> {
        self.labels.get(name).copied()
    }

    /// Finalize encoding and resolve all label references.
    ///
    /// This method completes the encoding process by resolving all pending label
    /// fixups and calculating branch offsets. After finalization, the encoder
    /// cannot be used for further instruction emission.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The complete CIL bytecode with all labels resolved
    /// - The maximum stack depth required during execution
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`crate::Error::UndefinedLabel`] - Any referenced labels are undefined
    /// - [`crate::Error::InvalidBranch`] - Branch offsets exceed the allowed range for their instruction type
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] - Stack underflow occurred during encoding (negative stack depth)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// encoder.emit_instruction("ldc.i4.1", None)?; // Pushes 1 item
    /// encoder.emit_instruction("ret", None)?;     // Returns with 1 item
    ///
    /// let (bytecode, max_stack, _labels) = encoder.finalize()?;
    /// assert_eq!(bytecode, vec![0x17, 0x2A]); // ldc.i4.1, ret
    /// assert_eq!(max_stack, 1); // Maximum stack depth was 1
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn finalize(mut self) -> Result<(Vec<u8>, u16, HashMap<String, u32>)> {
        // Ensure the method ends with a proper terminating instruction.
        // This must be done before branch optimization since it may add instructions.
        self.ensure_method_terminated()?;

        // Optimize branches iteratively until no more improvements
        self.optimize_branch_forms()?;

        self.finalize_as_written()
    }

    /// Resolves the branch and switch fixups over the bytes as they were emitted, adding and
    /// shortening nothing: the finalization of re-encoded code, which ends as it was read.
    fn finalize_as_written(mut self) -> Result<(Vec<u8>, u16, HashMap<String, u32>)> {
        // Resolve all branch fixups
        let fixups = std::mem::take(&mut self.fixups);
        for fixup in &fixups {
            let label_position = self
                .labels
                .get(&fixup.label)
                .ok_or_else(|| Error::UndefinedLabel(fixup.label.clone()))?;

            // Calculate relative offset from end of branch instruction to label
            let next_instruction_pos = fixup
                .fixup_position
                .checked_add(fixup.offset_size as usize)
                .ok_or_else(|| malformed_error!("Branch instruction end position overflow"))?;

            let label_pos_i32 = i32::try_from(*label_position)
                .map_err(|_| malformed_error!("Label position exceeds i32 range"))?;
            let next_instr_pos_i32 = i32::try_from(next_instruction_pos)
                .map_err(|_| malformed_error!("Instruction position exceeds i32 range"))?;

            let offset = label_pos_i32
                .checked_sub(next_instr_pos_i32)
                .ok_or_else(|| malformed_error!("Branch offset overflow"))?;

            self.write_branch_offset(offset, fixup)?;
        }

        // Process switch fixups
        let switch_fixups = std::mem::take(&mut self.switch_fixups);
        for switch_fixup in &switch_fixups {
            let instruction_end_i32 = i32::try_from(switch_fixup.instruction_end_position)
                .map_err(|_| malformed_error!("Switch instruction end exceeds i32 range"))?;

            for (i, label) in switch_fixup.labels.iter().enumerate() {
                let label_position = self
                    .labels
                    .get(label)
                    .ok_or_else(|| Error::UndefinedLabel(label.clone()))?;

                let label_pos_i32 = i32::try_from(*label_position)
                    .map_err(|_| malformed_error!("Label position exceeds i32 range"))?;

                // Switch offsets are relative to the end of the switch instruction
                let offset = label_pos_i32
                    .checked_sub(instruction_end_i32)
                    .ok_or_else(|| malformed_error!("Switch offset overflow"))?;

                // Write the 4-byte offset at the correct position
                let target_pos = switch_fixup
                    .fixup_position
                    .checked_add(
                        i.checked_mul(4)
                            .ok_or_else(|| malformed_error!("Switch label index overflow"))?,
                    )
                    .ok_or_else(|| malformed_error!("Switch target position overflow"))?;
                let target_end = target_pos
                    .checked_add(4)
                    .ok_or_else(|| malformed_error!("Switch target end overflow"))?;
                let offset_bytes = offset.to_le_bytes();
                self.bytecode
                    .get_mut(target_pos..target_end)
                    .ok_or(out_of_bounds_error!())?
                    .copy_from_slice(&offset_bytes);
            }
        }

        // Return bytecode, max stack, and final label positions (after branch optimization)
        Ok((self.bytecode, self.max_stack_depth, self.labels))
    }

    /// Optimize branch forms by converting long-form branches to short-form where possible.
    ///
    /// This method iteratively shrinks branches until no more optimizations are possible.
    /// Each iteration may enable additional optimizations as the bytecode shrinks.
    fn optimize_branch_forms(&mut self) -> Result<()> {
        const MAX_ITERATIONS: usize = 100;

        for _ in 0..MAX_ITERATIONS {
            let shrinkable = self.find_shrinkable_branches()?;
            if shrinkable.is_empty() {
                break; // No more optimizations possible
            }

            // Rebuild bytecode with short-form branches
            self.apply_branch_shrinking(&shrinkable)?;
        }

        Ok(())
    }

    /// Find branches that could be converted to short form.
    ///
    /// Returns indices of fixups that can be shrunk.
    fn find_shrinkable_branches(&self) -> Result<Vec<usize>> {
        let mut shrinkable = Vec::new();

        for (idx, fixup) in self.fixups.iter().enumerate() {
            // Only consider long-form branches that have a short form
            if fixup.offset_size != 4 || fixup.short_form_mnemonic.is_none() {
                continue;
            }

            let label_position = self
                .labels
                .get(&fixup.label)
                .ok_or_else(|| Error::UndefinedLabel(fixup.label.clone()))?;

            // Calculate offset as if we used short form (1 byte offset instead of 4)
            // Short form: instruction is 2 bytes (opcode + 1-byte offset)
            // The offset is relative to the end of the instruction
            let short_form_end = fixup
                .instruction_position
                .checked_add(2)
                .ok_or_else(|| malformed_error!("Short-form end overflow"))?;

            let label_pos_i32 = i32::try_from(*label_position)
                .map_err(|_| malformed_error!("Label position exceeds i32 range"))?;
            let short_end_i32 = i32::try_from(short_form_end)
                .map_err(|_| malformed_error!("Instruction position exceeds i32 range"))?;

            // Calculate what the offset would be with short form
            // Note: We need to account for the 3-byte savings in positions after this branch
            let offset = label_pos_i32
                .checked_sub(short_end_i32)
                .ok_or_else(|| malformed_error!("Short-form offset overflow"))?;

            // Check if offset fits in signed byte (-128 to +127)
            if (-128..=127).contains(&offset) {
                shrinkable.push(idx);
            }
        }

        Ok(shrinkable)
    }

    /// Apply branch shrinking by rebuilding bytecode with short-form branches.
    fn apply_branch_shrinking(&mut self, shrinkable: &[usize]) -> Result<()> {
        if shrinkable.is_empty() {
            return Ok(());
        }

        // Build a set for O(1) lookup
        let shrinkable_set: HashSet<usize> = shrinkable.iter().copied().collect();

        // Calculate position adjustments for each shrunk branch
        // Each shrunk branch saves 3 bytes (5 bytes -> 2 bytes)
        let mut adjustments: Vec<(usize, i32)> = Vec::new(); // (position, cumulative_adjustment)
        let mut cumulative = 0i32;

        for &idx in shrinkable {
            let Some(fixup) = self.fixups.get(idx) else {
                continue;
            };
            // The adjustment takes effect after this instruction
            let instr_end = fixup
                .fixup_position
                .checked_add(fixup.offset_size as usize)
                .ok_or_else(|| malformed_error!("Branch end position overflow"))?;
            cumulative = cumulative
                .checked_sub(3)
                .ok_or_else(|| malformed_error!("Branch shrinking adjustment overflow"))?;
            adjustments.push((instr_end, cumulative));
        }

        // Helper to calculate adjusted position
        let adjust_position = |pos: usize| -> usize {
            let mut adj = 0i32;
            for &(threshold, cumulative_adj) in &adjustments {
                if pos >= threshold {
                    adj = cumulative_adj;
                } else {
                    break;
                }
            }
            // CIL method bodies are limited by format; positions are validated elsewhere
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                clippy::cast_sign_loss
            )]
            let adjusted = (pos as i32).saturating_add(adj).max(0) as usize;
            adjusted
        };

        // Rebuild bytecode
        let mut new_bytecode = Vec::with_capacity(self.bytecode.len());
        let mut src_pos = 0usize;

        // Sort fixups by position for sequential processing
        let mut sorted_indices: Vec<usize> = (0..self.fixups.len()).collect();
        sorted_indices.sort_by_key(|&i| {
            self.fixups
                .get(i)
                .map_or(usize::MAX, |f| f.instruction_position)
        });

        for &idx in &sorted_indices {
            let Some(fixup) = self.fixups.get(idx) else {
                continue;
            };

            // Copy bytes up to this instruction
            if src_pos < fixup.instruction_position {
                let chunk = self
                    .bytecode
                    .get(src_pos..fixup.instruction_position)
                    .ok_or(out_of_bounds_error!())?;
                new_bytecode.extend_from_slice(chunk);
            }
            src_pos = fixup.instruction_position;

            if shrinkable_set.contains(&idx) {
                // Emit short-form branch
                let short_mnemonic = fixup.short_form_mnemonic.ok_or_else(|| {
                    Error::InvalidMnemonic("missing short form for shrinkable branch".to_string())
                })?;
                let (opcode, prefix, _) = get_mnemonic_lookup()
                    .get(short_mnemonic)
                    .ok_or_else(|| Error::InvalidMnemonic(short_mnemonic.to_string()))?;

                if *prefix != 0 {
                    new_bytecode.push(*prefix);
                }
                new_bytecode.push(*opcode);
                new_bytecode.push(0); // Placeholder for offset

                // Skip the original instruction (opcode + 4-byte offset)
                src_pos = fixup
                    .fixup_position
                    .checked_add(4)
                    .ok_or_else(|| malformed_error!("Branch fixup position overflow"))?;
            } else {
                // Copy original instruction
                let instr_end = fixup
                    .fixup_position
                    .checked_add(fixup.offset_size as usize)
                    .ok_or_else(|| malformed_error!("Branch end position overflow"))?;
                let chunk = self
                    .bytecode
                    .get(src_pos..instr_end)
                    .ok_or(out_of_bounds_error!())?;
                new_bytecode.extend_from_slice(chunk);
                src_pos = instr_end;
            }
        }

        // Copy remaining bytes
        if src_pos < self.bytecode.len() {
            let chunk = self.bytecode.get(src_pos..).ok_or(out_of_bounds_error!())?;
            new_bytecode.extend_from_slice(chunk);
        }

        // Update labels
        for pos in self.labels.values_mut() {
            // CIL method bodies are limited to u32 size by the format
            #[allow(clippy::cast_possible_truncation)]
            let adjusted_pos = adjust_position(*pos as usize) as u32;
            *pos = adjusted_pos;
        }

        // Update fixups
        for (idx, fixup) in self.fixups.iter_mut().enumerate() {
            let new_instr_pos = adjust_position(fixup.instruction_position);

            if shrinkable_set.contains(&idx) {
                // This branch was shrunk
                fixup.instruction_position = new_instr_pos;
                fixup.fixup_position = new_instr_pos
                    .checked_add(1)
                    .ok_or_else(|| malformed_error!("Shrunk branch fixup position overflow"))?;
                fixup.offset_size = 1;
                fixup.short_form_mnemonic = None; // Already optimized
            } else {
                // Just adjust positions
                fixup.instruction_position = new_instr_pos;
                fixup.fixup_position = adjust_position(fixup.fixup_position);
            }
        }

        // Update switch fixups
        for switch_fixup in &mut self.switch_fixups {
            switch_fixup.fixup_position = adjust_position(switch_fixup.fixup_position);
            switch_fixup.instruction_end_position =
                adjust_position(switch_fixup.instruction_end_position);
        }

        self.bytecode = new_bytecode;
        Ok(())
    }

    /// Emit operand bytes based on the expected operand type.
    ///
    /// This internal method handles the encoding of instruction operands according
    /// to their expected types, performing validation and byte serialization.
    fn emit_operand(&mut self, operand: Option<Operand>, expected: OperandType) -> Result<()> {
        match expected {
            OperandType::None => {
                if operand.is_some() {
                    return Err(Error::UnexpectedOperand);
                }
            }
            OperandType::Int8 => {
                if let Some(Operand::Immediate(Immediate::Int8(val))) = operand {
                    self.bytecode.push(val.to_le_bytes()[0]);
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int8".to_string(),
                    });
                }
            }
            OperandType::UInt8 => {
                if let Some(Operand::Immediate(Immediate::UInt8(val))) = operand {
                    self.bytecode.push(val);
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt8".to_string(),
                    });
                }
            }
            OperandType::Int16 => {
                if let Some(Operand::Immediate(Immediate::Int16(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int16".to_string(),
                    });
                }
            }
            OperandType::UInt16 => {
                if let Some(Operand::Immediate(Immediate::UInt16(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt16".to_string(),
                    });
                }
            }
            OperandType::Int32 => {
                if let Some(Operand::Immediate(Immediate::Int32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int32".to_string(),
                    });
                }
            }
            OperandType::UInt32 => {
                if let Some(Operand::Immediate(Immediate::UInt32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt32".to_string(),
                    });
                }
            }
            OperandType::Int64 => {
                if let Some(Operand::Immediate(Immediate::Int64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int64".to_string(),
                    });
                }
            }
            OperandType::UInt64 => {
                if let Some(Operand::Immediate(Immediate::UInt64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt64".to_string(),
                    });
                }
            }
            OperandType::Float32 => {
                if let Some(Operand::Immediate(Immediate::Float32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Float32".to_string(),
                    });
                }
            }
            OperandType::Float64 => {
                if let Some(Operand::Immediate(Immediate::Float64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Float64".to_string(),
                    });
                }
            }
            OperandType::Token => {
                if let Some(Operand::Token(token)) = operand {
                    self.bytecode
                        .extend_from_slice(&token.value().to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Token".to_string(),
                    });
                }
            }
            OperandType::Switch => {
                if let Some(Operand::Switch(targets)) = operand {
                    // Switch format: count (4 bytes) + targets (4 bytes each)
                    let targets_len = u32::try_from(targets.len())
                        .map_err(|_| malformed_error!("Too many switch targets"))?;
                    self.bytecode.extend_from_slice(&targets_len.to_le_bytes());
                    for target in targets {
                        self.bytecode.extend_from_slice(&target.to_le_bytes());
                    }
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Switch".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Write a branch offset at the specified fixup position.
    ///
    /// This internal method writes the calculated branch offset into the bytecode
    /// at the position specified by the fixup, using the appropriate byte size.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidBranch`] if the offset exceeds the range for the
    /// instruction's offset size (1, 2, or 4 bytes) or if the offset size is invalid.
    fn write_branch_offset(&mut self, offset: i32, fixup: &LabelFixup) -> Result<()> {
        match fixup.offset_size {
            1 => {
                if offset < i32::from(i8::MIN) || offset > i32::from(i8::MAX) {
                    return Err(Error::InvalidBranch(format!(
                        "offset {offset} out of range for 1-byte instruction"
                    )));
                }
                let offset_i8 = i8::try_from(offset)
                    .map_err(|_| malformed_error!("Branch offset exceeds i8 range"))?;
                let slot = self
                    .bytecode
                    .get_mut(fixup.fixup_position)
                    .ok_or(out_of_bounds_error!())?;
                *slot = offset_i8.to_le_bytes()[0];
            }
            2 => {
                if offset < i32::from(i16::MIN) || offset > i32::from(i16::MAX) {
                    return Err(Error::InvalidBranch(format!(
                        "offset {offset} out of range for 2-byte instruction"
                    )));
                }
                let offset_i16 = i16::try_from(offset)
                    .map_err(|_| malformed_error!("Branch offset exceeds i16 range"))?;
                let bytes = offset_i16.to_le_bytes();
                let end = fixup
                    .fixup_position
                    .checked_add(2)
                    .ok_or_else(|| malformed_error!("Branch fixup end overflow"))?;
                self.bytecode
                    .get_mut(fixup.fixup_position..end)
                    .ok_or(out_of_bounds_error!())?
                    .copy_from_slice(&bytes);
            }
            4 => {
                let bytes = offset.to_le_bytes();
                let end = fixup
                    .fixup_position
                    .checked_add(4)
                    .ok_or_else(|| malformed_error!("Branch fixup end overflow"))?;
                self.bytecode
                    .get_mut(fixup.fixup_position..end)
                    .ok_or(out_of_bounds_error!())?
                    .copy_from_slice(&bytes);
            }
            _ => {
                return Err(Error::InvalidBranch(format!(
                    "invalid offset size: {} bytes",
                    fixup.offset_size
                )))
            }
        }
        Ok(())
    }

    /// Update stack depth tracking based on instruction stack behavior.
    ///
    /// This internal method applies the stack effects of an instruction and validates
    /// that stack underflow doesn't occur.
    ///
    /// # Parameters
    ///
    /// * `pops` - Number of items the instruction pops from the stack
    /// * `pushes` - Number of items the instruction pushes onto the stack
    ///
    /// # Errors
    ///
    /// Returns an error if stack underflow would occur (negative stack depth).
    fn update_stack_depth(&mut self, pops: u16, pushes: u8) -> Result<()> {
        if !self.tracks_stack {
            return Ok(());
        }
        // A call pops up to u16::MAX arguments, so the arithmetic is in i32.
        let depth = i32::from(self.current_stack_depth)
            .saturating_add(i32::from(pushes))
            .saturating_sub(i32::from(pops));
        self.current_stack_depth = i16::try_from(depth.max(i32::from(i16::MIN)))
            .map_err(|_| malformed_error!("Stack depth overflow"))?;

        // Check for stack underflow - but only in reachable code.
        // In unreachable code, the stack depth is meaningless, so we don't error.
        // We still track it for when code becomes reachable again via a label.
        if self.current_stack_depth < 0 && !self.unreachable {
            return Err(malformed_error!(
                "Stack underflow: depth became {} after instruction with {} pops, {} pushes",
                self.current_stack_depth,
                pops,
                pushes
            ));
        }

        // Clamp negative depth to 0 to prevent cascading issues
        if self.current_stack_depth < 0 {
            self.current_stack_depth = 0;
        }

        // Update maximum stack depth
        let current_depth_u16 = u16::try_from(self.current_stack_depth)
            .map_err(|_| malformed_error!("Stack depth exceeds u16 range"))?;
        self.max_stack_depth = self.max_stack_depth.max(current_depth_u16);

        Ok(())
    }

    /// Get the current maximum stack depth without finalizing the encoder.
    ///
    /// This method allows checking the maximum stack depth that has been reached
    /// so far during encoding without consuming the encoder.
    ///
    /// # Returns
    ///
    /// The maximum stack depth reached so far during instruction encoding.
    #[must_use]
    pub fn max_stack_depth(&self) -> u16 {
        self.max_stack_depth
    }

    /// Get the current stack depth without finalizing the encoder.
    ///
    /// This method returns the current number of items on the evaluation stack.
    /// Useful for debugging or validation during encoding.
    ///
    /// # Returns
    ///
    /// The current stack depth (number of items on evaluation stack).
    #[must_use]
    pub fn current_stack_depth(&self) -> i16 {
        self.current_stack_depth
    }

    /// Get the position of a defined label.
    ///
    /// This method allows accessing label positions before finalization,
    /// which is useful for exception handler offset calculation.
    ///
    /// # Parameters
    ///
    /// * `label_name` - The name of the label to look up
    ///
    /// # Returns
    ///
    /// The byte position of the label if it exists, otherwise None.
    #[must_use]
    pub fn get_label_position(&self, label_name: &str) -> Option<u32> {
        self.labels.get(label_name).copied()
    }

    /// Records the expected stack depth at a branch target label.
    ///
    /// When a branch instruction is emitted, the current stack depth (after popping
    /// any condition) is recorded as the expected depth at the target label. When
    /// the label is defined, we validate that the current depth matches.
    ///
    /// # Parameters
    ///
    /// * `label` - The target label name
    ///
    /// # Errors
    ///
    /// Returns an error if the label was previously recorded with a different depth,
    /// indicating inconsistent stack depths across control flow paths.
    fn record_label_stack_depth(&mut self, label: &str) -> Result<()> {
        if !self.tracks_stack {
            return Ok(());
        }
        // In unreachable code, don't record or validate stack depths.
        // The current_stack_depth is meaningless since there's no execution path.
        // The first reachable branch to this label will set the correct depth.
        if self.unreachable {
            return Ok(());
        }

        if let Some(&expected) = self.label_stack_depths.get(label) {
            if self.current_stack_depth != expected {
                return Err(malformed_error!(
                    "Stack depth mismatch for branch to '{}': expected {}, but branch has {}",
                    label,
                    expected,
                    self.current_stack_depth
                ));
            }
        } else {
            self.label_stack_depths
                .insert(label.to_string(), self.current_stack_depth);
        }
        Ok(())
    }

    /// Sets the expected stack depth at a label.
    ///
    /// This is used to explicitly set the expected depth for labels that may be
    /// reached via fall-through or other non-branch control flow (e.g., exception
    /// handlers). Unlike `record_label_stack_depth`, this does not validate - it
    /// just sets the expectation.
    ///
    /// # Parameters
    ///
    /// * `label` - The label name
    /// * `depth` - The expected stack depth at this label
    pub fn set_label_stack_depth(&mut self, label: &str, depth: i16) {
        self.label_stack_depths.insert(label.to_string(), depth);
    }

    /// Sets the current stack depth directly.
    ///
    /// This is used at control flow boundaries where the stack depth is known
    /// (e.g., after exception handlers where stack is cleared, at method entry).
    ///
    /// # Parameters
    ///
    /// * `depth` - The new stack depth
    pub fn set_stack_depth(&mut self, depth: i16) {
        self.current_stack_depth = depth;
        if depth >= 0 {
            self.max_stack_depth = self.max_stack_depth.max(depth.cast_unsigned());
        }
    }
}

impl Default for InstructionEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assembly::{decode_stream, Immediate, Operand},
        file::parser::Parser,
    };

    #[test]
    fn test_encoder_creation() {
        let encoder = InstructionEncoder::new();
        assert!(encoder.bytecode.is_empty());
        assert!(encoder.labels.is_empty());
        assert!(encoder.fixups.is_empty());
    }

    #[test]
    fn test_simple_instruction_encoding() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        encoder.emit_instruction("nop", None)?;
        encoder.emit_instruction("ret", None)?;

        let (bytecode, _max_stack, _) = encoder.finalize()?;
        assert_eq!(bytecode, vec![0x00, 0x2A]); // nop = 0x00, ret = 0x2A

        Ok(())
    }

    #[test]
    fn test_instruction_with_operands() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        // ldarg.s uses UInt8 for argument index (0-255 range, no sign needed)
        encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::UInt8(1))))?;
        // ldc.i4.s uses Int8 for the signed immediate value
        encoder.emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(42))))?;

        let (bytecode, _max_stack, _) = encoder.finalize()?;
        // ldarg.s = 0x0E, ldarg index = 1, ldc.i4.s = 0x1F, immediate = 42
        assert_eq!(bytecode, vec![0x0E, 0x01, 0x1F, 42]);

        Ok(())
    }

    #[test]
    fn test_label_resolution() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        encoder.emit_instruction("nop", None)?; // 0x00
        encoder.emit_branch("br.s", "target")?; // 0x2B + offset
        encoder.emit_instruction("nop", None)?; // 0x00
        encoder.define_label("target")?;
        encoder.emit_instruction("ret", None)?; // 0x2A

        let (bytecode, _max_stack, _) = encoder.finalize()?;
        // br.s offset should be 1 (skip the nop instruction)
        assert_eq!(bytecode, vec![0x00, 0x2B, 0x01, 0x00, 0x2A]);

        Ok(())
    }

    #[test]
    fn test_invalid_mnemonic() {
        let mut encoder = InstructionEncoder::new();
        let result = encoder.emit_instruction("invalid_instruction", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_operand_type() {
        let mut encoder = InstructionEncoder::new();
        // ldarg.s expects Int8, but we provide UInt32
        let result =
            encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::UInt32(1))));
        assert!(result.is_err());
    }

    #[test]
    fn test_undefined_label() {
        let mut encoder = InstructionEncoder::new();
        encoder.emit_branch("br.s", "undefined_label").unwrap();
        let result = encoder.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_label() -> Result<()> {
        let mut encoder = InstructionEncoder::new();
        encoder.define_label("test_label")?;
        let result = encoder.define_label("test_label");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_reverse_lookup_table_completeness() {
        // Verify that our reverse lookup table contains all non-empty instructions
        let mut instruction_count = 0;

        // Count single-byte instructions
        for instr in INSTRUCTIONS.iter() {
            if !instr.instr.is_empty() {
                instruction_count += 1;
                assert!(get_mnemonic_lookup().contains_key(instr.instr));
            }
        }

        // Count extended instructions
        for instr in INSTRUCTIONS_FE.iter() {
            if !instr.instr.is_empty() {
                instruction_count += 1;
                assert!(get_mnemonic_lookup().contains_key(instr.instr));
            }
        }

        // Verify the lookup table has exactly the expected number of entries
        assert_eq!(get_mnemonic_lookup().len(), instruction_count);
    }

    /// Decoded code encoded in place is the code: a long branch stays long though its target
    /// is near, a switch keeps its targets, and bytes between the instructions (code no path
    /// reaches, here an invalid opcode) are kept.
    #[test]
    fn decoded_code_encodes_back_to_itself() {
        let code = [
            0x38, 0x09, 0x00, 0x00, 0x00, // br +9 (long form, to ldc.i4.1)
            0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // switch (1) +0, unreachable
            0x17, // ldc.i4.1
            0x2A, // ret
        ];
        // Only what control reaches decodes: the switch is dead, so the decoded body is the
        // branch, ldc.i4.1 and ret, with the switch's bytes uncovered
        let mut instructions = decode_stream(&mut Parser::new(&code[..5]), 0x2000).unwrap();
        instructions.extend(decode_stream(&mut Parser::new(&code[14..]), 0x200E).unwrap());
        assert_eq!(
            InstructionEncoder::encode_decoded(&instructions, &code, 0x2000).unwrap(),
            code
        );

        let switch = [
            0x45, 0x02, 0, 0, 0, 0x01, 0, 0, 0, 0x00, 0, 0, 0, 0x00, 0x2A,
        ];
        let instructions = decode_stream(&mut Parser::new(&switch), 0x3000).unwrap();
        assert_eq!(
            InstructionEncoder::encode_decoded(&instructions, &switch, 0x3000).unwrap(),
            switch
        );
    }

    /// A decoded instruction that changed size no longer fits its place: refused, where
    /// writing it would move every instruction and handler after it.
    #[test]
    fn decoded_code_that_no_longer_fits_is_refused() {
        let code = [0x00, 0x00, 0x2A]; // nop, nop, ret
        let mut instructions = decode_stream(&mut Parser::new(&code), 0x10).unwrap();
        instructions[0].rva = 0x11;
        assert!(InstructionEncoder::encode_decoded(&instructions, &code, 0x10).is_err());

        // A branch on its own names its target by RVA, which only a body places
        let branch = decode_stream(&mut Parser::new(&[0x2B, 0x00, 0x2A]), 0).unwrap();
        assert!(InstructionEncoder::new()
            .emit_instruction_decoded(&branch[0])
            .is_err());
    }
}

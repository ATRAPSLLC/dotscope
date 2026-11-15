//! x86/x64 instruction decoder using iced-x86.
//!
//! This module provides a thin wrapper around iced-x86 that converts its
//! instruction representation to our simplified [`X86Instruction`] types.

use std::collections::{BTreeMap, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use rustc_hash::FxHashSet;

/// Maximum instructions a single x86 decode may produce.
///
/// The x86 subsystem is reached from mixed-mode assemblies, where the region handed to it is
/// derived from attacker-controlled headers and can extend to end-of-file. Both
/// the traversal and the SSA translation built on it scale super-linearly in instruction count,
/// so an unbounded decode is a DoS primitive rather than merely slow.
///
/// A native stub in a real mixed-mode assembly is kilobytes of code — low tens of thousands of
/// instructions at the very outside.
pub const MAX_DECODED_INSTRUCTIONS: usize = 250_000;

use crate::{
    analysis::x86::types::{
        X86Condition, X86DecodedInstruction, X86EpilogueInfo, X86Instruction, X86Memory,
        X86Operand, X86PrologueInfo, X86PrologueKind, X86Register,
    },
    Error, Result,
};

/// Decode x86/x64 bytes into our instruction representation.
///
/// This function uses linear disassembly, decoding instructions sequentially
/// from the start until a `RET` instruction is encountered.
///
/// # Arguments
///
/// * `bytes` - The x86/x64 machine code bytes
/// * `bitness` - 32 for x86, 64 for x64
/// * `base_address` - The base address (RVA) of the code for computing jump targets
///
/// # Returns
///
/// A vector of decoded instructions, or an error if decoding fails.
///
/// # Errors
///
/// Returns [`crate::Error::X86Error`] if:
/// - `bytes` is empty
/// - `bitness` is not 32 or 64
/// - An invalid instruction is encountered
/// - An unsupported instruction is encountered
///
pub fn x86_decode_all(
    bytes: &[u8],
    bitness: u32,
    base_address: u64,
) -> Result<Vec<X86DecodedInstruction>> {
    x86_decode_all_limited(bytes, bitness, base_address, MAX_DECODED_INSTRUCTIONS)
}

/// Linear-sweep decode with an explicit instruction budget.
///
/// See [`MAX_DECODED_INSTRUCTIONS`]. Callers that hand over a region derived from file
/// headers — rather than a stub whose extent they have already established — should use this
/// and pass a bound appropriate to what they expect.
///
/// # Errors
///
/// Returns [`crate::Error::X86Error`] on empty input, invalid bitness, an invalid instruction,
/// or when `max_instructions` is exhausted.
pub fn x86_decode_all_limited(
    bytes: &[u8],
    bitness: u32,
    base_address: u64,
    max_instructions: usize,
) -> Result<Vec<X86DecodedInstruction>> {
    if bytes.is_empty() {
        return Err(Error::X86Error("Empty input".to_string()));
    }
    if bitness != 32 && bitness != 64 {
        return Err(Error::X86Error(format!(
            "Invalid bitness {bitness}, must be 32 or 64"
        )));
    }

    let mut decoder = Decoder::with_ip(bitness, bytes, base_address, DecoderOptions::NONE);
    let mut instructions = Vec::new();

    for instr in &mut decoder {
        let offset = instr
            .ip()
            .checked_sub(base_address)
            .ok_or_else(|| Error::X86Error("Instruction IP below base address".into()))?;
        let length = instr.len();

        // Check for invalid instruction
        if instr.is_invalid() {
            return Err(Error::X86Error(format!(
                "Invalid instruction at offset 0x{offset:x}"
            )));
        }

        // A linear sweep runs to the end of whatever slice it was given, and that slice can be
        // the entire remainder of the file.
        if instructions.len() >= max_instructions {
            return Err(Error::X86Error(format!(
                "x86 linear sweep exceeded {max_instructions} instructions"
            )));
        }

        let converted = convert_instruction(&instr, base_address)?;
        let is_ret = matches!(converted, X86Instruction::Ret);
        instructions.push(X86DecodedInstruction {
            offset,
            length,
            instruction: converted,
        });

        // Stop at RET instruction (end of function)
        if is_ret {
            break;
        }
    }

    Ok(instructions)
}

/// Result of traversal-based decoding.
///
/// This struct is returned by [`x86_decode_traversal`] and contains
/// all instructions discovered by following control flow from the entry point.
///
/// # Completeness
///
/// The decoded instructions represent all code reachable through static
/// control flow analysis. However, indirect jumps (`jmp eax`, jump tables, etc.)
/// cannot be resolved statically and are reported in [`unresolved_targets`](Self::unresolved_targets).
///
/// # Example
///
/// ```
/// use dotscope::analysis::{x86_decode_traversal, X86Function};
///
/// // push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret
/// let bytes = [0x55, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
/// let result = x86_decode_traversal(&bytes, 32, 0x1000, 0)?;
///
/// if result.has_indirect_control_flow {
///     println!("Warning: {} unresolved targets", result.unresolved_targets.len());
/// }
///
/// let cfg = X86Function::new(&result.instructions, 32, 0x1000);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug)]
pub struct X86TraversalDecodeResult {
    /// All decoded instructions, sorted by ascending offset.
    pub instructions: Vec<X86DecodedInstruction>,
    /// Addresses that could not be statically resolved.
    ///
    /// These include:
    /// - External call targets (outside the code region)
    /// - Indirect jump/call targets (register or memory operands)
    pub unresolved_targets: Vec<u64>,
    /// `true` if any indirect jumps or calls were encountered.
    ///
    /// When this is `true`, the decoded instructions may not represent
    /// the complete function, as some control flow paths could not be followed.
    pub has_indirect_control_flow: bool,
}

/// Decode x86/x64 bytes using recursive traversal (control-flow following).
///
/// Unlike linear disassembly, this approach follows control flow edges from the
/// entry point, only decoding reachable code. This is more robust against:
/// - Junk bytes inserted between instructions
/// - Data embedded in code sections
/// - Overlapping instructions
/// - Anti-disassembly tricks
///
/// The algorithm uses a worklist to explore all reachable code paths, handling
/// both conditional and unconditional branches. Indirect jumps are recorded
/// but not followed (they would require runtime analysis to resolve).
///
/// # Arguments
///
/// * `bytes` - The x86/x64 machine code bytes
/// * `bitness` - 32 for x86, 64 for x64
/// * `base_address` - The base address (RVA) of the code for computing jump targets
/// * `entry_offset` - Offset within `bytes` to start decoding from
///
/// # Returns
///
/// A [`X86TraversalDecodeResult`] containing:
/// - All decoded instructions sorted by offset
/// - Addresses that could not be resolved (external calls, indirect jumps)
/// - Whether indirect control flow was encountered
///
/// # Errors
///
/// Returns [`crate::Error::X86Error`] if:
/// - `bytes` is empty
/// - `bitness` is not 32 or 64
///
/// Note: Invalid instructions at unreachable addresses are silently skipped,
/// and unsupported instructions are recorded as [`X86Instruction::Unsupported`].
pub fn x86_decode_traversal(
    bytes: &[u8],
    bitness: u32,
    base_address: u64,
    entry_offset: u64,
) -> Result<X86TraversalDecodeResult> {
    x86_decode_traversal_limited(
        bytes,
        bitness,
        base_address,
        entry_offset,
        MAX_DECODED_INSTRUCTIONS,
    )
}

/// Recursive-traversal decode with an explicit instruction budget.
///
/// See [`MAX_DECODED_INSTRUCTIONS`] for why a budget is mandatory rather than advisory.
///
/// # Errors
///
/// Returns [`crate::Error::X86Error`] on empty input, invalid bitness, address overflow, or
/// when `max_instructions` is exhausted.
pub fn x86_decode_traversal_limited(
    bytes: &[u8],
    bitness: u32,
    base_address: u64,
    entry_offset: u64,
    max_instructions: usize,
) -> Result<X86TraversalDecodeResult> {
    if bytes.is_empty() {
        return Err(Error::X86Error("Empty input".to_string()));
    }
    if bitness != 32 && bitness != 64 {
        return Err(Error::X86Error(format!(
            "Invalid bitness {bitness}, must be 32 or 64"
        )));
    }

    let code_start = base_address;
    let code_end = base_address
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| Error::X86Error("Code region end address overflow".into()))?;

    // Worklist of offsets to decode (relative to base_address)
    let mut worklist: VecDeque<u64> = VecDeque::new();
    // Offsets we've already decoded or queued
    let mut visited: FxHashSet<u64> = FxHashSet::default();
    // Decoded instructions by offset
    let mut instructions: Vec<X86DecodedInstruction> = Vec::new();
    // Byte spans already claimed, as `offset -> length`, for O(log n) overlap rejection.
    let mut decoded_spans: BTreeMap<u64, usize> = BTreeMap::new();
    // Targets we couldn't resolve
    let mut unresolved_targets: Vec<u64> = Vec::new();
    let mut has_indirect = false;

    // Start from entry point
    let entry_addr = base_address
        .checked_add(entry_offset)
        .ok_or_else(|| Error::X86Error("Entry address overflow".into()))?;
    worklist.push_back(entry_addr);
    visited.insert(entry_addr);

    while let Some(addr) = worklist.pop_front() {
        // Check if address is within bounds
        if addr < code_start || addr >= code_end {
            continue;
        }

        #[allow(clippy::cast_possible_truncation)]
        let offset_in_bytes = addr.saturating_sub(base_address) as usize;
        let Some(remaining_bytes) = bytes.get(offset_in_bytes..) else {
            continue;
        };

        if remaining_bytes.is_empty() {
            continue;
        }

        // Decode one instruction at this address
        let mut decoder = Decoder::with_ip(bitness, remaining_bytes, addr, DecoderOptions::NONE);

        if let Some(instr) = decoder.iter().next() {
            if instr.is_invalid() {
                // Invalid instruction - stop following this path
                continue;
            }

            let offset = addr.saturating_sub(base_address);
            let length = instr.len();

            // Reject overlapping decodes (overlapping instructions are a known obfuscation
            // trick) using an interval map rather than a linear scan of everything decoded so
            // far, which made traversal O(n²) in decoded instructions over a region that could
            // run to end-of-file.
            //
            // Intervals do not overlap each other by construction, so only two candidates can
            // intersect `[offset, new_end)`: the nearest interval starting at or before
            // `offset`, and the nearest starting after it.
            let new_end = offset.saturating_add(length as u64);
            let overlaps_before = decoded_spans
                .range(..=offset)
                .next_back()
                .is_some_and(|(start, len)| start.saturating_add(*len as u64) > offset);
            let overlaps_after = decoded_spans
                .range(offset..)
                .next()
                .is_some_and(|(start, _)| *start < new_end);

            if overlaps_before || overlaps_after {
                continue;
            }

            if instructions.len() >= max_instructions {
                return Err(Error::X86Error(format!(
                    "x86 traversal exceeded {max_instructions} instructions"
                )));
            }

            decoded_spans.insert(offset, length);

            // Convert the instruction
            let converted = match convert_instruction(&instr, base_address) {
                Ok(i) => i,
                Err(_) => X86Instruction::Unsupported {
                    offset,
                    mnemonic: format!("{:?}", instr.mnemonic()),
                },
            };

            // Determine successors based on instruction type
            let next_addr = addr.saturating_add(length as u64);

            match &converted {
                X86Instruction::Ret => {
                    // No successors - end of path
                }
                X86Instruction::Jmp { target } => {
                    // Unconditional jump - only the target is a successor
                    if *target >= code_start && *target < code_end && visited.insert(*target) {
                        worklist.push_back(*target);
                    } else if *target < code_start || *target >= code_end {
                        unresolved_targets.push(*target);
                    }
                }
                X86Instruction::Jcc { target, .. } => {
                    // Conditional jump - both target and fall-through are successors
                    if *target >= code_start && *target < code_end && visited.insert(*target) {
                        worklist.push_back(*target);
                    }
                    if next_addr < code_end && visited.insert(next_addr) {
                        worklist.push_back(next_addr);
                    }
                }
                X86Instruction::Call { target } => {
                    // For calls, we continue to the next instruction (return address)
                    // We don't follow the call target as it's a different function
                    if next_addr < code_end && visited.insert(next_addr) {
                        worklist.push_back(next_addr);
                    }

                    // Follow intra-function call targets (e.g. `call $+5` trampolines
                    // used for position-independent code). External targets are recorded
                    // as unresolved.
                    if *target >= code_start && *target < code_end {
                        if visited.insert(*target) {
                            worklist.push_back(*target);
                        }
                    } else {
                        unresolved_targets.push(*target);
                    }
                }
                X86Instruction::Unsupported { .. } => {
                    // Classify by control flow, not by mnemonic.
                    //
                    // An unsupported *control transfer* is a path terminator: an indirect
                    // `jmp` (a jump table, or a tail call) does not fall through, and neither
                    // does `ret`/`retf`/`iret`. Enqueuing `next_addr` for them walks straight
                    // off the end of the function into alignment padding and then into whatever
                    // follows — which is why traversal never stopped at a function boundary.
                    //
                    // `flow_control()` classifies every transfer class, where a mnemonic match
                    // only caught `Jmp`/`Call` and silently treated the rest as sequential.
                    let flow = instr.flow_control();
                    let is_indirect_transfer = matches!(
                        flow,
                        FlowControl::IndirectBranch | FlowControl::IndirectCall
                    );

                    if is_indirect_transfer {
                        has_indirect = true;
                        unresolved_targets.push(addr);
                    }

                    let terminates_path = matches!(
                        flow,
                        FlowControl::Return
                            | FlowControl::IndirectBranch
                            | FlowControl::UnconditionalBranch
                            | FlowControl::Interrupt
                            | FlowControl::Exception
                            | FlowControl::XbeginXabortXend
                    );

                    // Calls and conditional branches still fall through to the return address
                    // or the not-taken edge.
                    if !terminates_path && next_addr < code_end && visited.insert(next_addr) {
                        worklist.push_back(next_addr);
                    }
                }
                _ => {
                    // Normal instruction - fall through to next
                    if next_addr < code_end && visited.insert(next_addr) {
                        worklist.push_back(next_addr);
                    }
                }
            }

            instructions.push(X86DecodedInstruction {
                offset,
                length,
                instruction: converted,
            });
        }
    }

    // Sort instructions by offset for consistent ordering
    instructions.sort_by_key(|i| i.offset);

    Ok(X86TraversalDecodeResult {
        instructions,
        unresolved_targets,
        has_indirect_control_flow: has_indirect,
    })
}

/// Determines the byte size of a native x86/x64 function body.
///
/// Uses traversal-based decoding ([`x86_decode_traversal`]) to follow
/// control-flow edges from the entry point, making it robust against
/// anti-disassembly tricks (junk bytes, embedded data, overlapping
/// instructions) because only code reachable through actual control flow is
/// considered.
///
/// # Arguments
///
/// * `bytes` - Raw machine code bytes starting at the function entry
/// * `is_64bit` - `true` for x64, `false` for x86
///
/// # Returns
///
/// The byte extent of the function: `max(offset + length)` across all
/// reachable instructions. Returns `0` if decoding fails or `bytes` is
/// empty.
///
/// # Examples
///
/// ```no_run
/// use dotscope::analysis::x86_native_body_size;
///
/// let code = &[0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3]; // push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
/// assert!(x86_native_body_size(code, false) > 0);
/// ```
#[must_use]
pub fn x86_native_body_size(bytes: &[u8], is_64bit: bool) -> usize {
    if bytes.is_empty() {
        return 0;
    }

    let bitness = if is_64bit { 64 } else { 32 };
    match x86_decode_traversal(bytes, bitness, 0, 0) {
        Ok(result) => result
            .instructions
            .iter()
            .map(|instr| (instr.offset as usize).saturating_add(instr.length))
            .max()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Decode a single instruction at the given offset.
///
/// This is useful for on-demand decoding during analysis, such as when
/// exploring indirect jump targets or validating specific code locations.
///
/// # Arguments
///
/// * `bytes` - The x86/x64 machine code bytes
/// * `bitness` - 32 for x86, 64 for x64
/// * `base_address` - The base address (RVA) of the code
/// * `offset` - Offset within `bytes` to decode at
///
/// # Returns
///
/// The decoded instruction at the specified offset.
///
/// # Errors
///
/// Returns [`crate::Error::X86Error`] if:
/// - `bytes` is empty
/// - `bitness` is not 32 or 64
/// - `offset` is beyond the end of `bytes`
/// - The instruction at `offset` is invalid
pub fn x86_decode_single(
    bytes: &[u8],
    bitness: u32,
    base_address: u64,
    offset: u64,
) -> Result<X86DecodedInstruction> {
    if bytes.is_empty() {
        return Err(Error::X86Error("Empty input".to_string()));
    }
    if bitness != 32 && bitness != 64 {
        return Err(Error::X86Error(format!(
            "Invalid bitness {bitness}, must be 32 or 64"
        )));
    }

    #[allow(clippy::cast_possible_truncation)]
    let offset_in_bytes = offset as usize;
    if offset_in_bytes >= bytes.len() {
        return Err(Error::X86Error(format!(
            "Invalid instruction at offset 0x{offset:x}"
        )));
    }

    let remaining = bytes
        .get(offset_in_bytes..)
        .ok_or_else(|| Error::X86Error(format!("Invalid instruction at offset 0x{offset:x}")))?;
    let ip = base_address
        .checked_add(offset)
        .ok_or_else(|| Error::X86Error("Instruction IP overflow".into()))?;
    let mut decoder = Decoder::with_ip(bitness, remaining, ip, DecoderOptions::NONE);

    if let Some(instr) = decoder.iter().next() {
        if instr.is_invalid() {
            return Err(Error::X86Error(format!(
                "Invalid instruction at offset 0x{offset:x}"
            )));
        }

        let converted = convert_instruction(&instr, base_address)?;

        Ok(X86DecodedInstruction {
            offset,
            length: instr.len(),
            instruction: converted,
        })
    } else {
        Err(Error::X86Error(format!(
            "Invalid instruction at offset 0x{offset:x}"
        )))
    }
}

/// Convert an iced-x86 instruction to our simplified representation.
fn convert_instruction(instr: &Instruction, base_address: u64) -> Result<X86Instruction> {
    let offset = instr
        .ip()
        .checked_sub(base_address)
        .ok_or_else(|| Error::X86Error("Instruction IP below base address".into()))?;

    match instr.mnemonic() {
        // Data movement
        Mnemonic::Mov => convert_mov(instr),
        Mnemonic::Movzx => convert_movzx(instr),
        Mnemonic::Movsx | Mnemonic::Movsxd => convert_movsx(instr),
        Mnemonic::Lea => convert_lea(instr),
        Mnemonic::Push => convert_push(instr),
        Mnemonic::Pop => convert_pop(instr),
        Mnemonic::Xchg => convert_xchg(instr),

        // Arithmetic
        Mnemonic::Add => convert_binary_op(instr, |dst, src| X86Instruction::Add { dst, src }),
        Mnemonic::Sub => convert_binary_op(instr, |dst, src| X86Instruction::Sub { dst, src }),
        Mnemonic::Adc => convert_binary_op(instr, |dst, src| X86Instruction::Adc { dst, src }),
        Mnemonic::Sbb => convert_binary_op(instr, |dst, src| X86Instruction::Sbb { dst, src }),
        Mnemonic::Imul => convert_imul(instr),
        Mnemonic::Mul => convert_mul(instr),
        Mnemonic::Div => Ok(X86Instruction::Div {
            src: convert_operand(instr, 0)?,
        }),
        Mnemonic::Idiv => Ok(X86Instruction::Idiv {
            src: convert_operand(instr, 0)?,
        }),
        Mnemonic::Neg => convert_unary_op(instr, |dst| X86Instruction::Neg { dst }),
        Mnemonic::Inc => convert_unary_op(instr, |dst| X86Instruction::Inc { dst }),
        Mnemonic::Dec => convert_unary_op(instr, |dst| X86Instruction::Dec { dst }),

        // Bitwise operations
        Mnemonic::And => convert_binary_op(instr, |dst, src| X86Instruction::And { dst, src }),
        Mnemonic::Or => convert_binary_op(instr, |dst, src| X86Instruction::Or { dst, src }),
        Mnemonic::Xor => convert_binary_op(instr, |dst, src| X86Instruction::Xor { dst, src }),
        Mnemonic::Not => convert_unary_op(instr, |dst| X86Instruction::Not { dst }),

        // Shift/rotate operations
        Mnemonic::Shl | Mnemonic::Sal => {
            convert_shift(instr, |dst, count| X86Instruction::Shl { dst, count })
        }
        Mnemonic::Shr => convert_shift(instr, |dst, count| X86Instruction::Shr { dst, count }),
        Mnemonic::Sar => convert_shift(instr, |dst, count| X86Instruction::Sar { dst, count }),
        Mnemonic::Rol => convert_shift(instr, |dst, count| X86Instruction::Rol { dst, count }),
        Mnemonic::Ror => convert_shift(instr, |dst, count| X86Instruction::Ror { dst, count }),

        // Byte swap / bit operations
        Mnemonic::Bswap => Ok(X86Instruction::Bswap {
            dst: convert_register(instr.op0_register())?,
        }),
        Mnemonic::Bsf => Ok(X86Instruction::Bsf {
            dst: convert_register(instr.op0_register())?,
            src: convert_operand(instr, 1)?,
        }),
        Mnemonic::Bsr => Ok(X86Instruction::Bsr {
            dst: convert_register(instr.op0_register())?,
            src: convert_operand(instr, 1)?,
        }),
        Mnemonic::Bt => Ok(X86Instruction::Bt {
            src: convert_operand(instr, 0)?,
            bit: convert_operand(instr, 1)?,
        }),
        Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            // BTS/BTR/BTC modify the bit but we approximate as BT (test only)
            Ok(X86Instruction::Bt {
                src: convert_operand(instr, 0)?,
                bit: convert_operand(instr, 1)?,
            })
        }

        // Exchange and add
        Mnemonic::Xadd => convert_binary_op(instr, |dst, src| X86Instruction::Xadd { dst, src }),

        // Conditional move
        Mnemonic::Cmove
        | Mnemonic::Cmovne
        | Mnemonic::Cmovl
        | Mnemonic::Cmovge
        | Mnemonic::Cmovle
        | Mnemonic::Cmovg
        | Mnemonic::Cmovb
        | Mnemonic::Cmovae
        | Mnemonic::Cmovbe
        | Mnemonic::Cmova
        | Mnemonic::Cmovs
        | Mnemonic::Cmovns
        | Mnemonic::Cmovo
        | Mnemonic::Cmovno
        | Mnemonic::Cmovp
        | Mnemonic::Cmovnp => convert_cmovcc(instr),

        // Set byte on condition
        Mnemonic::Sete
        | Mnemonic::Setne
        | Mnemonic::Setl
        | Mnemonic::Setge
        | Mnemonic::Setle
        | Mnemonic::Setg
        | Mnemonic::Setb
        | Mnemonic::Setae
        | Mnemonic::Setbe
        | Mnemonic::Seta
        | Mnemonic::Sets
        | Mnemonic::Setns
        | Mnemonic::Seto
        | Mnemonic::Setno
        | Mnemonic::Setp
        | Mnemonic::Setnp => convert_setcc(instr),

        // Comparison
        Mnemonic::Cmp => convert_cmp(instr),
        Mnemonic::Test => convert_test(instr),

        // Control flow
        Mnemonic::Jmp => convert_jmp(instr),
        Mnemonic::Je
        | Mnemonic::Jne
        | Mnemonic::Jl
        | Mnemonic::Jge
        | Mnemonic::Jle
        | Mnemonic::Jg
        | Mnemonic::Jb
        | Mnemonic::Jae
        | Mnemonic::Jbe
        | Mnemonic::Ja
        | Mnemonic::Js
        | Mnemonic::Jns
        | Mnemonic::Jo
        | Mnemonic::Jno
        | Mnemonic::Jp
        | Mnemonic::Jnp => convert_jcc(instr),
        Mnemonic::Call => convert_call(instr),
        Mnemonic::Ret | Mnemonic::Retf => Ok(X86Instruction::Ret),

        // Miscellaneous
        Mnemonic::Nop | Mnemonic::Fnop => Ok(X86Instruction::Nop),
        Mnemonic::Cdq | Mnemonic::Cqo => Ok(X86Instruction::Cdq),
        Mnemonic::Cwde | Mnemonic::Cdqe => Ok(X86Instruction::Cwde),
        Mnemonic::Cbw => Ok(X86Instruction::Cwde), // Sign-extend AL into AX
        Mnemonic::Cwd => Ok(X86Instruction::Cdq),  // Sign-extend AX into DX:AX

        // Flag manipulation without computational side effects.
        // CLD/STD only affect direction flag (relevant for string ops we don't support).
        // CLC/STC/CMC modify CF which matters for Adc/Sbb - but if no Adc/Sbb follows,
        // these are effectively no-ops. We map them here; the SSA translator handles CF.
        Mnemonic::Cld | Mnemonic::Std => Ok(X86Instruction::Nop),

        // FPU synchronization (no computational side effects)
        Mnemonic::Wait => Ok(X86Instruction::Nop),

        // Unsupported
        _ => Err(Error::X86Error(format!(
            "Unsupported instruction '{:?}' at offset 0x{offset:x}",
            instr.mnemonic()
        ))),
    }
}

// Conversion helpers

fn convert_mov(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_operand(instr, 0)?;
    let src = convert_operand(instr, 1)?;
    Ok(X86Instruction::Mov { dst, src })
}

fn convert_movzx(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_operand(instr, 0)?;
    let src = convert_operand(instr, 1)?;
    Ok(X86Instruction::Movzx { dst, src })
}

fn convert_movsx(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_operand(instr, 0)?;
    let src = convert_operand(instr, 1)?;
    Ok(X86Instruction::Movsx { dst, src })
}

fn convert_lea(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_register(instr.op0_register())?;
    let src = convert_memory_operand(instr, 1)?;
    Ok(X86Instruction::Lea { dst, src })
}

fn convert_push(instr: &Instruction) -> Result<X86Instruction> {
    let src = convert_operand(instr, 0)?;
    Ok(X86Instruction::Push { src })
}

fn convert_pop(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_register(instr.op0_register())?;
    Ok(X86Instruction::Pop { dst })
}

fn convert_xchg(instr: &Instruction) -> Result<X86Instruction> {
    let dst = convert_operand(instr, 0)?;
    let src = convert_operand(instr, 1)?;
    Ok(X86Instruction::Xchg { dst, src })
}

fn convert_binary_op<F>(instr: &Instruction, build: F) -> Result<X86Instruction>
where
    F: FnOnce(X86Operand, X86Operand) -> X86Instruction,
{
    let dst = convert_operand(instr, 0)?;
    let src = convert_operand(instr, 1)?;
    Ok(build(dst, src))
}

fn convert_unary_op<F>(instr: &Instruction, build: F) -> Result<X86Instruction>
where
    F: FnOnce(X86Operand) -> X86Instruction,
{
    let dst = convert_operand(instr, 0)?;
    Ok(build(dst))
}

fn convert_shift<F>(instr: &Instruction, build: F) -> Result<X86Instruction>
where
    F: FnOnce(X86Operand, X86Operand) -> X86Instruction,
{
    let dst = convert_operand(instr, 0)?;
    let count = if instr.op_count() > 1 {
        convert_operand(instr, 1)?
    } else {
        // Implicit count of 1
        X86Operand::Immediate(1)
    };
    Ok(build(dst, count))
}

fn convert_imul(instr: &Instruction) -> Result<X86Instruction> {
    let op_count = instr.op_count();

    if op_count == 1 {
        // One-operand form: imul r/m (result in EDX:EAX)
        // We don't support this form well, but capture it
        let src = convert_operand(instr, 0)?;
        Ok(X86Instruction::Imul {
            dst: X86Register::Eax, // Result goes to EAX (low part)
            src,
            src2: None,
        })
    } else if op_count == 2 {
        // Two-operand form: imul r, r/m
        let dst = convert_register(instr.op0_register())?;
        let src = convert_operand(instr, 1)?;
        Ok(X86Instruction::Imul {
            dst,
            src,
            src2: None,
        })
    } else {
        // Three-operand form: imul r, r/m, imm
        let dst = convert_register(instr.op0_register())?;
        let src = convert_operand(instr, 1)?;
        let src2 = convert_operand(instr, 2)?;
        Ok(X86Instruction::Imul {
            dst,
            src,
            src2: Some(src2),
        })
    }
}

fn convert_mul(instr: &Instruction) -> Result<X86Instruction> {
    let src = convert_operand(instr, 0)?;
    Ok(X86Instruction::Mul { src })
}

fn convert_cmp(instr: &Instruction) -> Result<X86Instruction> {
    let left = convert_operand(instr, 0)?;
    let right = convert_operand(instr, 1)?;
    Ok(X86Instruction::Cmp { left, right })
}

fn convert_test(instr: &Instruction) -> Result<X86Instruction> {
    let left = convert_operand(instr, 0)?;
    let right = convert_operand(instr, 1)?;
    Ok(X86Instruction::Test { left, right })
}

fn convert_jmp(instr: &Instruction) -> Result<X86Instruction> {
    let target = get_branch_target(instr)?;
    Ok(X86Instruction::Jmp { target })
}

fn convert_jcc(instr: &Instruction) -> Result<X86Instruction> {
    let condition = mnemonic_to_condition(instr.mnemonic())?;
    let target = get_branch_target(instr)?;
    Ok(X86Instruction::Jcc { condition, target })
}

fn convert_call(instr: &Instruction) -> Result<X86Instruction> {
    let target = get_branch_target(instr)?;
    Ok(X86Instruction::Call { target })
}

fn convert_cmovcc(instr: &Instruction) -> Result<X86Instruction> {
    let condition = cmovcc_to_condition(instr.mnemonic())?;
    let dst = convert_register(instr.op0_register())?;
    let src = convert_operand(instr, 1)?;
    Ok(X86Instruction::Cmovcc {
        condition,
        dst,
        src,
    })
}

fn convert_setcc(instr: &Instruction) -> Result<X86Instruction> {
    let condition = setcc_to_condition(instr.mnemonic())?;
    let dst = convert_operand(instr, 0)?;
    Ok(X86Instruction::Setcc { condition, dst })
}

fn cmovcc_to_condition(mnemonic: Mnemonic) -> Result<X86Condition> {
    match mnemonic {
        Mnemonic::Cmove => Ok(X86Condition::E),
        Mnemonic::Cmovne => Ok(X86Condition::Ne),
        Mnemonic::Cmovl => Ok(X86Condition::L),
        Mnemonic::Cmovge => Ok(X86Condition::Ge),
        Mnemonic::Cmovle => Ok(X86Condition::Le),
        Mnemonic::Cmovg => Ok(X86Condition::G),
        Mnemonic::Cmovb => Ok(X86Condition::B),
        Mnemonic::Cmovae => Ok(X86Condition::Ae),
        Mnemonic::Cmovbe => Ok(X86Condition::Be),
        Mnemonic::Cmova => Ok(X86Condition::A),
        Mnemonic::Cmovs => Ok(X86Condition::S),
        Mnemonic::Cmovns => Ok(X86Condition::Ns),
        Mnemonic::Cmovo => Ok(X86Condition::O),
        Mnemonic::Cmovno => Ok(X86Condition::No),
        Mnemonic::Cmovp => Ok(X86Condition::P),
        Mnemonic::Cmovnp => Ok(X86Condition::Np),
        _ => Err(Error::SsaError(format!(
            "Unknown CMOVcc mnemonic: {mnemonic:?}"
        ))),
    }
}

fn setcc_to_condition(mnemonic: Mnemonic) -> Result<X86Condition> {
    match mnemonic {
        Mnemonic::Sete => Ok(X86Condition::E),
        Mnemonic::Setne => Ok(X86Condition::Ne),
        Mnemonic::Setl => Ok(X86Condition::L),
        Mnemonic::Setge => Ok(X86Condition::Ge),
        Mnemonic::Setle => Ok(X86Condition::Le),
        Mnemonic::Setg => Ok(X86Condition::G),
        Mnemonic::Setb => Ok(X86Condition::B),
        Mnemonic::Setae => Ok(X86Condition::Ae),
        Mnemonic::Setbe => Ok(X86Condition::Be),
        Mnemonic::Seta => Ok(X86Condition::A),
        Mnemonic::Sets => Ok(X86Condition::S),
        Mnemonic::Setns => Ok(X86Condition::Ns),
        Mnemonic::Seto => Ok(X86Condition::O),
        Mnemonic::Setno => Ok(X86Condition::No),
        Mnemonic::Setp => Ok(X86Condition::P),
        Mnemonic::Setnp => Ok(X86Condition::Np),
        _ => Err(Error::SsaError(format!(
            "Unknown SETcc mnemonic: {mnemonic:?}"
        ))),
    }
}

fn get_branch_target(instr: &Instruction) -> Result<u64> {
    match instr.op0_kind() {
        OpKind::NearBranch16 => Ok(u64::from(instr.near_branch16())),
        OpKind::NearBranch32 => Ok(u64::from(instr.near_branch32())),
        OpKind::NearBranch64 => Ok(instr.near_branch64()),
        OpKind::FarBranch16 => Ok(u64::from(instr.far_branch16())),
        OpKind::FarBranch32 => Ok(u64::from(instr.far_branch32())),
        _ => {
            // Indirect jump - we can't handle this statically
            Err(Error::SsaError(format!(
                "Indirect branch at 0x{:x}",
                instr.ip()
            )))
        }
    }
}

fn mnemonic_to_condition(mnemonic: Mnemonic) -> Result<X86Condition> {
    match mnemonic {
        Mnemonic::Je => Ok(X86Condition::E),
        Mnemonic::Jne => Ok(X86Condition::Ne),
        Mnemonic::Jl => Ok(X86Condition::L),
        Mnemonic::Jge => Ok(X86Condition::Ge),
        Mnemonic::Jle => Ok(X86Condition::Le),
        Mnemonic::Jg => Ok(X86Condition::G),
        Mnemonic::Jb => Ok(X86Condition::B),
        Mnemonic::Jae => Ok(X86Condition::Ae),
        Mnemonic::Jbe => Ok(X86Condition::Be),
        Mnemonic::Ja => Ok(X86Condition::A),
        Mnemonic::Js => Ok(X86Condition::S),
        Mnemonic::Jns => Ok(X86Condition::Ns),
        Mnemonic::Jo => Ok(X86Condition::O),
        Mnemonic::Jno => Ok(X86Condition::No),
        Mnemonic::Jp => Ok(X86Condition::P),
        Mnemonic::Jnp => Ok(X86Condition::Np),
        _ => Err(Error::SsaError(format!(
            "Unknown condition mnemonic: {mnemonic:?}"
        ))),
    }
}

/// Convert an operand at the given index to our representation.
fn convert_operand(instr: &Instruction, index: u32) -> Result<X86Operand> {
    let op_kind = instr.op_kind(index);

    match op_kind {
        OpKind::Register => {
            let reg = match index {
                0 => instr.op0_register(),
                1 => instr.op1_register(),
                2 => instr.op2_register(),
                3 => instr.op3_register(),
                4 => instr.op4_register(),
                _ => return Err(Error::SsaError(format!("Invalid operand index {index}"))),
            };
            Ok(X86Operand::Register(convert_register(reg)?))
        }
        OpKind::Immediate8 => Ok(X86Operand::Immediate(i64::from(
            instr.immediate8().cast_signed(),
        ))),
        OpKind::Immediate16 => Ok(X86Operand::Immediate(i64::from(
            instr.immediate16().cast_signed(),
        ))),
        OpKind::Immediate32 => Ok(X86Operand::Immediate(i64::from(
            instr.immediate32().cast_signed(),
        ))),
        OpKind::Immediate64 => Ok(X86Operand::Immediate(instr.immediate64().cast_signed())),
        OpKind::Immediate8to16 => Ok(X86Operand::Immediate(i64::from(instr.immediate8to16()))),
        OpKind::Immediate8to32 => Ok(X86Operand::Immediate(i64::from(instr.immediate8to32()))),
        OpKind::Immediate8to64 => Ok(X86Operand::Immediate(instr.immediate8to64())),
        OpKind::Immediate32to64 => Ok(X86Operand::Immediate(instr.immediate32to64())),
        OpKind::Memory => {
            let mem = convert_memory_operand(instr, index)?;
            Ok(X86Operand::Memory(mem))
        }
        _ => Err(Error::SsaError(format!(
            "Unsupported operand kind: {op_kind:?}"
        ))),
    }
}

/// Convert a memory operand at the given index.
fn convert_memory_operand(instr: &Instruction, _index: u32) -> Result<X86Memory> {
    let base = if instr.memory_base() == Register::None {
        None
    } else {
        Some(convert_register(instr.memory_base())?)
    };

    let index = if instr.memory_index() == Register::None {
        None
    } else {
        Some(convert_register(instr.memory_index())?)
    };

    #[allow(clippy::cast_possible_truncation)]
    let scale = instr.memory_index_scale() as u8;
    let displacement = instr.memory_displacement64().cast_signed();
    #[allow(clippy::cast_possible_truncation)]
    let size = instr.memory_size().size() as u8;

    // `segment_prefix()` is the *explicit* override and is `Register::None`
    // otherwise — which is what we want. `memory_segment()` would resolve the
    // default (`ds`, or `ss` for an rbp/rsp base) and make every ordinary
    // access look segment-qualified.
    let segment = match instr.segment_prefix() {
        Register::None => None,
        reg => Some(convert_register(reg)?),
    };

    Ok(X86Memory {
        base,
        index,
        scale,
        displacement,
        size,
        segment,
    })
}

/// Convert an iced-x86 register to our representation.
fn convert_register(reg: Register) -> Result<X86Register> {
    match reg {
        // 32-bit
        Register::EAX => Ok(X86Register::Eax),
        Register::ECX => Ok(X86Register::Ecx),
        Register::EDX => Ok(X86Register::Edx),
        Register::EBX => Ok(X86Register::Ebx),
        Register::ESP => Ok(X86Register::Esp),
        Register::EBP => Ok(X86Register::Ebp),
        Register::ESI => Ok(X86Register::Esi),
        Register::EDI => Ok(X86Register::Edi),

        // 64-bit
        Register::RAX => Ok(X86Register::Rax),
        Register::RCX => Ok(X86Register::Rcx),
        Register::RDX => Ok(X86Register::Rdx),
        Register::RBX => Ok(X86Register::Rbx),
        Register::RSP => Ok(X86Register::Rsp),
        Register::RBP => Ok(X86Register::Rbp),
        Register::RSI => Ok(X86Register::Rsi),
        Register::RDI => Ok(X86Register::Rdi),
        Register::R8 => Ok(X86Register::R8),
        Register::R9 => Ok(X86Register::R9),
        Register::R10 => Ok(X86Register::R10),
        Register::R11 => Ok(X86Register::R11),
        Register::R12 => Ok(X86Register::R12),
        Register::R13 => Ok(X86Register::R13),
        Register::R14 => Ok(X86Register::R14),
        Register::R15 => Ok(X86Register::R15),

        // 8-bit
        Register::AL => Ok(X86Register::Al),
        Register::CL => Ok(X86Register::Cl),
        Register::DL => Ok(X86Register::Dl),
        Register::BL => Ok(X86Register::Bl),
        Register::AH => Ok(X86Register::Ah),
        Register::CH => Ok(X86Register::Ch),
        Register::DH => Ok(X86Register::Dh),
        Register::BH => Ok(X86Register::Bh),

        // 16-bit
        Register::AX => Ok(X86Register::Ax),
        Register::CX => Ok(X86Register::Cx),
        Register::DX => Ok(X86Register::Dx),
        Register::BX => Ok(X86Register::Bx),
        Register::SP => Ok(X86Register::Sp),
        Register::BP => Ok(X86Register::Bp),
        Register::SI => Ok(X86Register::Si),
        Register::DI => Ok(X86Register::Di),

        // Segment registers
        Register::ES => Ok(X86Register::Es),
        Register::CS => Ok(X86Register::Cs),
        Register::SS => Ok(X86Register::Ss),
        Register::DS => Ok(X86Register::Ds),
        Register::FS => Ok(X86Register::Fs),
        Register::GS => Ok(X86Register::Gs),

        _ => Err(Error::SsaError(format!("Unsupported register: {reg:?}"))),
    }
}

/// Common x86 (32-bit) stack frame prologue patterns.
///
/// These patterns represent various ways compilers and obfuscators set up
/// stack frames in 32-bit code.
const PATTERNS_X86: [&[u8]; 28] = [
    &[0x84, 0xEC],             // test ah, ch (unusual but seen)
    &[0x51, 0x53, 0x8B, 0x1D], // push ecx; push ebx; mov ebx, [...]
    &[0x53, 0x8B, 0x54],       // push ebx; mov edx, [...]
    &[0x53, 0x8B, 0xDC],       // push ebx; mov ebx, esp
    &[0x53, 0x8B, 0xD9, 0x55], // push ebx; mov ebx, ecx; push ebp
    &[0x55, 0x89, 0xE5],       // push ebp; mov ebp, esp (GCC style)
    &[0x55, 0x31, 0xD2],       // push ebp; xor edx, edx
    &[0x55, 0x57, 0x89],       // push ebp; push edi; mov ...
    &[0x55, 0x57, 0x56, 0x53], // push ebp; push edi; push esi; push ebx
    &[0x55, 0x8B, 0xEC],       // push ebp; mov ebp, esp (MSVC style)
    &[0x55, 0x8B, 0x6C],       // push ebp; mov ebp, [esp+...]
    &[0x55, 0x8B, 0x44, 0x24], // push ebp; mov eax, [esp+...]
    &[0x55, 0x8B, 0x54, 0x24], // push ebp; mov edx, [esp+...]
    &[0x55, 0x8B, 0x4C, 0x24], // push ebp; mov ecx, [esp+...]
    &[0x55, 0x8B, 0x89, 0xE5], // push ebp; mov ecx, [...]; (variant)
    &[0x56, 0x33, 0xC0],       // push esi; xor eax, eax
    &[0x56, 0x8B, 0xF1],       // push esi; mov esi, ecx
    &[0x56, 0x53, 0x89],       // push esi; push ebx; mov ...
    &[0x56, 0x8B, 0x44, 0x24], // push esi; mov eax, [esp+...]
    &[0x56, 0x8B, 0x4C, 0x24], // push esi; mov ecx, [esp+...]
    &[0x56, 0x8B, 0x54, 0x24], // push esi; mov edx, [esp+...]
    &[0x56, 0x53, 0x83, 0xEC], // push esi; push ebx; sub esp, ...
    &[0x6A, 0x0C, 0x68],       // push 12; push ...
    &[0x8B, 0x4C, 0x24],       // mov ecx, [esp+...]
    &[0x8B, 0x44, 0x24],       // mov eax, [esp+...]
    &[0x8B, 0x54, 0x24],       // mov edx, [esp+...]
    &[0x8B, 0xFF, 0x56],       // mov edi, edi; push esi (hotpatch)
    &[0x8B, 0xFF, 0x55],       // mov edi, edi; push ebp (hotpatch)
];

/// Common x64 (64-bit) stack frame prologue patterns.
///
/// These patterns represent various ways compilers and obfuscators set up
/// stack frames in 64-bit code.
const PATTERNS_X64: [&[u8]; 22] = [
    &[0x48, 0x81, 0xEC],                               // sub rsp, imm32
    &[0x48, 0x83, 0xEC],                               // sub rsp, imm8
    &[0x48, 0x89, 0x5C],                               // mov [rsp+...], rbx
    &[0x40, 0x8B, 0xC4],                               // mov eax, esp (REX prefix)
    &[0x55, 0x53, 0x48],                               // push rbp; push rbx; REX...
    &[0x64, 0x48, 0x8D],                               // fs: lea ... (TLS access)
    &[0x55, 0x48, 0x8B],                               // push rbp; mov ...
    &[0x53, 0x48, 0x89, 0xFB],                         // push rbx; mov rbx, rdi
    &[0x53, 0x48, 0x81, 0xBF],                         // push rbx; cmp qword ptr [rdi+...], ...
    &[0x48, 0x89, 0x5C, 0x24],                         // mov [rsp+...], rbx
    &[0x48, 0x89, 0x4C, 0x24],                         // mov [rsp+...], rcx
    &[0x55, 0x48, 0x89, 0xE5],                         // push rbp; mov rbp, rsp
    &[0x55, 0x48, 0x81, 0xEC],                         // push rbp; sub rsp, imm32
    &[0x55, 0x48, 0x83, 0xEC],                         // push rbp; sub rsp, imm8
    &[0x55, 0x53, 0x48, 0x89],                         // push rbp; push rbx; mov ...
    &[0x40, 0x54, 0x48, 0x83, 0xEC],                   // push rsp; sub rsp, ...
    &[0x40, 0x55, 0x48, 0x83, 0xEC],                   // push rbp; sub rsp, ...
    &[0x40, 0x56, 0x48, 0x84, 0xEC],                   // push rsi; test ... (unusual)
    &[0x48, 0x8B, 0xC4, 0x48, 0xEC],                   // mov rax, rsp; ... (variant)
    &[0x40, 0x53, 0x57, 0x48, 0x83, 0xEC],             // push rbx; push rdi; sub rsp, ...
    &[0x40, 0x53, 0x56, 0x57, 0x48, 0x83, 0xEC],       // push rbx; push rsi; push rdi; sub rsp, ...
    &[0x40, 0x53, 0x55, 0x56, 0x57, 0x48, 0x83, 0xEC], // push rbx; push rbp; push rsi; push rdi; sub rsp, ...
];

/// Detect the prologue type in x86 code.
///
/// This checks for known prologue patterns used by various compilers and obfuscators.
/// Detection is performed in order of specificity:
/// 1. DynCipher prologue (ConfuserEx specific, 20 bytes)
/// 2. Standard frame setup (`push ebp; mov ebp, esp` variants)
/// 3. Generic stack frame patterns
///
/// # Arguments
///
/// * `bytes` - The code bytes to analyze
/// * `bitness` - 32 for x86, 64 for x64
///
/// # Returns
///
/// An [`X86PrologueInfo`] describing the detected prologue, or [`X86PrologueKind::None`]
/// if no known pattern was found.
#[must_use]
pub fn x86_detect_prologue(bytes: &[u8], bitness: u32) -> X86PrologueInfo {
    // DynCipher prologue (20 bytes) - ConfuserEx specific
    // 89 e0           mov eax, esp
    // 53              push ebx
    // 57              push edi
    // 56              push esi
    // 29 e0           sub eax, esp
    // 83 f8 18        cmp eax, 24
    // 74 07           je +7
    // 8b 44 24 10     mov eax, [esp + 16]
    // 50              push eax
    // eb 01           jmp +1
    // 51              push ecx
    const DYNCIPHER_PROLOGUE: [u8; 20] = [
        0x89, 0xe0, 0x53, 0x57, 0x56, 0x29, 0xe0, 0x83, 0xf8, 0x18, 0x74, 0x07, 0x8b, 0x44, 0x24,
        0x10, 0x50, 0xeb, 0x01, 0x51,
    ];

    if bytes.is_empty() {
        return X86PrologueInfo {
            kind: X86PrologueKind::None,
            size: 0,
            arg_count: 0,
        };
    }

    if bytes.get(..20) == Some(&DYNCIPHER_PROLOGUE[..]) {
        return X86PrologueInfo {
            kind: X86PrologueKind::DynCipher,
            size: 20,
            arg_count: 1,
        };
    }

    let starts_with =
        |pat: &[u8]| -> bool { bytes.get(..pat.len()).is_some_and(|prefix| prefix == pat) };

    // Standard 32-bit prologue: push ebp; mov ebp, esp (MSVC)
    if bitness == 32 && starts_with(&[0x55, 0x8B, 0xEC]) {
        return X86PrologueInfo {
            kind: X86PrologueKind::Standard32,
            size: 3,
            arg_count: 0,
        };
    }

    // Standard 32-bit prologue: push ebp; mov ebp, esp (GCC)
    if bitness == 32 && starts_with(&[0x55, 0x89, 0xE5]) {
        return X86PrologueInfo {
            kind: X86PrologueKind::Standard32,
            size: 3,
            arg_count: 0,
        };
    }

    // Standard 64-bit prologue: push rbp; mov rbp, rsp
    if bitness == 64 && starts_with(&[0x55, 0x48, 0x89, 0xE5]) {
        return X86PrologueInfo {
            kind: X86PrologueKind::Standard64,
            size: 4,
            arg_count: 0,
        };
    }

    // Check generic stack frame patterns
    let patterns: &[&[u8]] = if bitness == 64 {
        &PATTERNS_X64
    } else {
        &PATTERNS_X86
    };

    for pattern in patterns {
        if starts_with(pattern) {
            return X86PrologueInfo {
                kind: X86PrologueKind::StackFrame {
                    is_64bit: bitness == 64,
                },
                size: pattern.len(),
                arg_count: 0,
            };
        }
    }

    X86PrologueInfo {
        kind: X86PrologueKind::None,
        size: 0,
        arg_count: 0,
    }
}

/// Detect the epilogue in decoded instructions.
///
/// Looks for the standard DynCipher epilogue:
/// ```text
/// 5e              pop esi
/// 5f              pop edi
/// 5b              pop ebx
/// c3              ret
/// ```
#[must_use]
pub fn x86_detect_epilogue(instructions: &[X86DecodedInstruction]) -> Option<X86EpilogueInfo> {
    // Need at least 4 instructions for the epilogue
    if instructions.len() < 4 {
        return None;
    }

    // Check if the last 4 instructions match the pattern
    let len = instructions.len();
    let i_esi = len.checked_sub(4)?;
    let i_edi = len.checked_sub(3)?;
    let i_ebx = len.checked_sub(2)?;
    let i_ret = len.checked_sub(1)?;

    // Check for pop esi
    let pop_esi = matches!(
        &instructions.get(i_esi)?.instruction,
        X86Instruction::Pop { dst } if *dst == X86Register::Esi
    );

    // Check for pop edi
    let pop_edi = matches!(
        &instructions.get(i_edi)?.instruction,
        X86Instruction::Pop { dst } if *dst == X86Register::Edi
    );

    // Check for pop ebx
    let pop_ebx = matches!(
        &instructions.get(i_ebx)?.instruction,
        X86Instruction::Pop { dst } if *dst == X86Register::Ebx
    );

    // Check for ret
    let ret = matches!(instructions.get(i_ret)?.instruction, X86Instruction::Ret);

    if pop_esi && pop_edi && pop_ebx && ret {
        Some(X86EpilogueInfo {
            offset: instructions.get(i_esi)?.offset,
            size: 4, // 4 bytes: pop esi (1) + pop edi (1) + pop ebx (1) + ret (1)
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::x86::{
        decoder::{x86_decode_all, x86_detect_prologue},
        types::{X86Condition, X86Instruction, X86Operand, X86PrologueKind, X86Register},
    };

    #[test]
    fn test_decode_simple_mov() {
        // mov eax, 0x1234
        let bytes = [0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();

        assert_eq!(result.len(), 2);
        match &result[0].instruction {
            X86Instruction::Mov { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Eax));
                assert_eq!(src.as_immediate(), Some(0x1234));
            }
            _ => panic!("Expected Mov instruction"),
        }
        assert!(matches!(result[1].instruction, X86Instruction::Ret));
    }

    /// A segment override prefix must survive decoding, and an unprefixed
    /// access must not pick up the default segment: the SSA lowering keys an
    /// address space off this, and a spurious `ds:`/`ss:` there would make two
    /// names for one flat cell look disjoint.
    #[test]
    fn test_decode_segment_prefix() {
        // mov eax, fs:[0x30]  /  ret
        let bytes = [0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();
        let X86Instruction::Mov { src, .. } = &result[0].instruction else {
            panic!("Expected Mov instruction");
        };
        assert_eq!(
            src.as_memory().and_then(|m| m.segment),
            Some(X86Register::Fs)
        );

        // mov eax, [ebp-4]  /  ret — defaults to ss:, which must stay `None`.
        let bytes = [0x8b, 0x45, 0xfc, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();
        let X86Instruction::Mov { src, .. } = &result[0].instruction else {
            panic!("Expected Mov instruction");
        };
        assert_eq!(src.as_memory().and_then(|m| m.segment), None);
    }

    #[test]
    fn test_decode_add_reg_imm() {
        // add eax, 5
        // ret
        let bytes = [0x83, 0xc0, 0x05, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();

        assert_eq!(result.len(), 2);
        match &result[0].instruction {
            X86Instruction::Add { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Eax));
                assert_eq!(src.as_immediate(), Some(5));
            }
            _ => panic!("Expected Add instruction"),
        }
    }

    #[test]
    fn test_decode_xor_reg_reg() {
        // xor eax, ecx
        // ret
        let bytes = [0x31, 0xc8, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();

        assert_eq!(result.len(), 2);
        match &result[0].instruction {
            X86Instruction::Xor { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Eax));
                assert_eq!(src.as_register(), Some(X86Register::Ecx));
            }
            _ => panic!("Expected Xor instruction"),
        }
    }

    #[test]
    fn test_decode_conditional_jump() {
        // cmp eax, 10
        // je +5 (to ret)
        // add eax, 1
        // ret
        let bytes = [
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x74, 0x03, // je +3
            0x83, 0xc0, 0x01, // add eax, 1
            0xc3, // ret
        ];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();

        assert_eq!(result.len(), 4);
        assert!(matches!(result[0].instruction, X86Instruction::Cmp { .. }));
        match &result[1].instruction {
            X86Instruction::Jcc { condition, target } => {
                assert_eq!(*condition, X86Condition::E);
                assert_eq!(*target, 8); // 0 + 3 + 2 + 3 = 8
            }
            _ => panic!("Expected Jcc instruction"),
        }
    }

    #[test]
    fn test_decode_memory_operand() {
        // mov eax, [esp + 16]
        // ret
        let bytes = [0x8b, 0x44, 0x24, 0x10, 0xc3];
        let result = x86_decode_all(&bytes, 32, 0).unwrap();

        assert_eq!(result.len(), 2);
        match &result[0].instruction {
            X86Instruction::Mov { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Eax));
                match src {
                    X86Operand::Memory(mem) => {
                        assert_eq!(mem.base, Some(X86Register::Esp));
                        assert_eq!(mem.displacement, 16);
                    }
                    _ => panic!("Expected memory operand"),
                }
            }
            _ => panic!("Expected Mov instruction"),
        }
    }

    #[test]
    fn test_detect_dyncipher_prologue() {
        let prologue = [
            0x89, 0xe0, // mov eax, esp
            0x53, // push ebx
            0x57, // push edi
            0x56, // push esi
            0x29, 0xe0, // sub eax, esp
            0x83, 0xf8, 0x18, // cmp eax, 24
            0x74, 0x07, // je +7
            0x8b, 0x44, 0x24, 0x10, // mov eax, [esp + 16]
            0x50, // push eax
            0xeb, 0x01, // jmp +1
            0x51, // push ecx
            0xc3, // ret (body would follow)
        ];

        let info = x86_detect_prologue(&prologue, 32);
        assert_eq!(info.kind, X86PrologueKind::DynCipher);
        assert_eq!(info.size, 20);
        assert_eq!(info.arg_count, 1);
    }

    #[test]
    fn test_detect_standard_32bit_prologue() {
        let bytes = [0x55, 0x89, 0xe5, 0xc3]; // push ebp; mov ebp, esp; ret
        let info = x86_detect_prologue(&bytes, 32);
        assert_eq!(info.kind, X86PrologueKind::Standard32);
        assert_eq!(info.size, 3);
    }

    #[test]
    fn test_decode_64bit() {
        // mov rax, 0x123456789
        // ret
        let bytes = [
            0x48, 0xb8, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0xc3,
        ];
        let result = x86_decode_all(&bytes, 64, 0).unwrap();

        assert_eq!(result.len(), 2);
        match &result[0].instruction {
            X86Instruction::Mov { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Rax));
                assert_eq!(src.as_immediate(), Some(0x123456789));
            }
            _ => panic!("Expected Mov instruction"),
        }
    }
}

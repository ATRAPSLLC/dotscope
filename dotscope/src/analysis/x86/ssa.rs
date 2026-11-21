//! x86 to SSA translator.
//!
//! This module translates decoded x86 functions into SSA form, enabling
//! integration with the existing SSA optimization and codegen infrastructure.
//!
//! # Overview
//!
//! The translation pipeline:
//!
//! ```text
//! X86Function (CFG) → translate blocks → construct SSA at the boundaries → SsaFunction
//! ```
//!
//! # Register Versioning
//!
//! Each x86 register is tracked as a versioned SSA variable. When a register
//! is written, a new SSA variable is created. Each block is translated on its
//! own, entered with one placeholder per register; analyssa's
//! [`BoundaryRecorder`] then answers every placeholder with the definition
//! that reaches the block and places the phis the joins need.
//!
//! A register read on some path before anything writes it is an error: these
//! stubs are entered with their one argument on the stack, and no register
//! holds anything the translation could name.
//!
//! # Example
//!
//! ```no_run
//! use dotscope::analysis::{x86_decode_all, X86Function, X86ToSsaTranslator};
//!
//! // Decode x86 code
//! let bytes = &[0x58, 0x83, 0xc0, 0x05, 0xc3]; // pop eax; add eax, 5; ret
//! let instructions = x86_decode_all(bytes, 32, 0)?;
//! let cfg = X86Function::new(&instructions, 32, 0);
//!
//! // Translate to SSA
//! let translator = X86ToSsaTranslator::new(&cfg);
//! let ssa_function = translator.translate()?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU16,
};

use analyssa::{
    analysis::VerifyLevel,
    ir::function::{BoundaryRecorder, SsaConstructOptions},
};

use crate::{
    analysis::{
        ssa::{
            AccessQualifiers, CmpKind, ConstValue, DefSite, SsaBlock, SsaFunction, SsaInstruction,
            SsaOp, SsaType, SsaVarId, SsaVariable, VariableOrigin,
        },
        x86::{
            cfg::X86Function,
            flags::{condition_formula, FlagFormula, FlagProducer, FlagState, ResultKind},
            types::{
                X86Condition, X86DecodedInstruction, X86Instruction, X86Memory, X86Operand,
                X86Register,
            },
        },
    },
    Error, Result,
};

/// Maximum basic blocks accepted for x86-to-SSA translation.
///
/// Real native stubs in mixed-mode assemblies have block counts in the tens. This bounds the
/// per-block register state and the phi worklist against input whose block count is ultimately
/// attacker-controlled.
const MAX_TRANSLATABLE_BLOCKS: usize = 65_536;

/// Number of registers tracked (0-15 GPRs for x64, 16-21 segment registers).
const MAX_REGISTERS: usize = 22;

/// Address space id for `gs:`-qualified accesses.
///
/// The numbering follows LLVM's x86 convention (256 = `gs`, 257 = `fs`) so a
/// dump is readable against existing tooling. The values themselves are opaque
/// to analyssa: it only ever compares them for equality. Address space 0 is the flat
/// default, which analyssa spells `None`, so the ids are non-zero.
const ADDRESS_SPACE_GS: NonZeroU16 = NonZeroU16::new(256).unwrap();

/// Address space id for `fs:`-qualified accesses. See [`ADDRESS_SPACE_GS`].
const ADDRESS_SPACE_FS: NonZeroU16 = NonZeroU16::new(257).unwrap();

/// Maps a memory operand's segment override to an SSA address space.
///
/// Only `fs:` and `gs:` produce one. In flat 32-bit and 64-bit user mode the
/// remaining segments share a base with the unprefixed default, so reporting a
/// distinct address space for an explicit `ss:` or `ds:` would let alias
/// analysis prove two names for the *same* cell disjoint — the one direction
/// that is unsound. `fs:`/`gs:` genuinely have their own bases (TEB/PEB access,
/// stack cookies, TLS), which is exactly the distinction worth keeping.
fn address_space_for(mem: &X86Memory) -> Option<NonZeroU16> {
    match mem.segment {
        Some(X86Register::Fs) => Some(ADDRESS_SPACE_FS),
        Some(X86Register::Gs) => Some(ADDRESS_SPACE_GS),
        _ => None,
    }
}

/// Tracks the current SSA variable for each x86 register.
///
/// This is the core of register versioning - each time a register is written,
/// we create a new SSA variable and update the mapping.
#[derive(Debug, Clone)]
struct RegisterState {
    /// Current SSA variable for each register (indexed by `X86Register::base_index()`).
    registers: [Option<SsaVarId>; MAX_REGISTERS],
}

impl RegisterState {
    /// Creates a new register state with all registers undefined.
    fn new() -> Self {
        Self {
            registers: [None; MAX_REGISTERS],
        }
    }

    /// Gets the current SSA variable for a register.
    fn get(&self, reg: X86Register) -> Option<SsaVarId> {
        let idx = reg.base_index() as usize;
        self.registers.get(idx).copied().flatten()
    }

    /// Sets the SSA variable for a register.
    fn set(&mut self, reg: X86Register, var: SsaVarId) {
        let idx = reg.base_index() as usize;
        if let Some(slot) = self.registers.get_mut(idx) {
            *slot = Some(var);
        }
    }
}

/// Translates an x86 function to SSA form.
///
/// # Exactness
///
/// The translation models each instruction exactly or refuses the function: the
/// caller keeps the native stub on an error, and the stub still runs on its
/// platform, whereas a lift that approximates an instruction would compute wrong
/// values silently. In particular:
///
/// - Only 32-bit code is translated. 64-bit registers, RIP-relative addressing and
///   the 64-bit operand forms are not modelled.
/// - An 8- or 16-bit register is read as its bits zero-extended and written by
///   inserting its bits into the full register, so `mov al, 5` keeps EAX's upper
///   bits and `ah` is bits 8-15 of EAX.
/// - The flags are known only when the instruction that set them is modelled at
///   the full register width; a condition that reads an unknown flag refuses the
///   function ([`Error::X86Error`]).
pub struct X86ToSsaTranslator<'a> {
    /// The x86 function to translate.
    func: &'a X86Function,
    /// SSA variables created during translation.
    variables: Vec<SsaVariable>,
    /// The zero constant of the block being translated, created the first time the
    /// block needs one. A constant defined in one block does not reach a block it
    /// does not dominate, so each block has its own.
    zero_const: Option<(usize, SsaVarId)>,
    /// Each block's index, by the offset of its first instruction.
    block_by_offset: HashMap<u64, usize>,
    /// The values a pop with nothing pushed reads: what the caller's frame held, which
    /// this translation does not follow. A stub's epilogue pops the registers its
    /// prologue saved and never reads them; a function whose computation reads one is
    /// refused.
    undefined: BTreeSet<SsaVarId>,
}

/// The bits of the full register an 8- or 16-bit register names: its shift and its
/// mask. `None` for a register that is its own full slot (a 32-bit register, a
/// segment register).
fn sub_register(reg: X86Register) -> Option<(i64, i64)> {
    match reg {
        X86Register::Al | X86Register::Cl | X86Register::Dl | X86Register::Bl => Some((0, 0xFF)),
        X86Register::Ah | X86Register::Ch | X86Register::Dh | X86Register::Bh => Some((8, 0xFF)),
        X86Register::Ax
        | X86Register::Cx
        | X86Register::Dx
        | X86Register::Bx
        | X86Register::Sp
        | X86Register::Bp
        | X86Register::Si
        | X86Register::Di => Some((0, 0xFFFF)),
        _ => None,
    }
}

/// The operand's width in bits when it is narrower than the 32-bit registers this
/// translator models; `None` at the full width, and for an immediate, which takes
/// the width of the operand it is combined with.
fn narrow_bits(operand: &X86Operand) -> Option<u32> {
    let bytes = match operand {
        X86Operand::Register(reg) => sub_register(*reg).map(|_| reg.size())?,
        X86Operand::Memory(mem) => mem.size,
        X86Operand::Immediate(_) => return None,
    };
    (bytes < 4).then_some(u32::from(bytes) * 8)
}

/// The count of a shift or rotate as the processor uses it: an immediate count
/// masked to five bits, or `None` for a count in a register, which is known only at
/// run time.
fn immediate_count(count: &X86Operand) -> Option<i64> {
    match count {
        X86Operand::Immediate(value) => Some(value & 31),
        _ => None,
    }
}

impl<'a> X86ToSsaTranslator<'a> {
    /// Creates a new translator for the given x86 function.
    #[must_use]
    pub fn new(func: &'a X86Function) -> Self {
        let block_by_offset = func
            .node_ids()
            .filter_map(|node| {
                func.block(node.index())
                    .map(|block| (block.start_offset, node.index()))
            })
            .collect();
        Self {
            func,
            variables: Vec::new(),
            zero_const: None,
            block_by_offset,
            undefined: BTreeSet::new(),
        }
    }

    /// Translates the x86 function to SSA form.
    ///
    /// # Returns
    ///
    /// An `SsaFunction` representing the translated code, or an error if
    /// translation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The function is empty, or is not 32-bit code
    /// - An unsupported instruction is encountered, or an instruction in a form
    ///   this translation does not model exactly
    /// - A condition reads a flag that is not known
    /// - A register is read on some path before anything writes it
    /// - The SSA the translation builds does not verify
    pub fn translate(mut self) -> Result<SsaFunction> {
        if self.func.block_count() == 0 {
            return Err(Error::X86Error("Empty function".to_string()));
        }
        if self.func.bitness != 32 {
            return Err(Error::X86Error(format!(
                "{}-bit code is not translated: only the 32-bit registers and addressing are \
                 modelled",
                self.func.bitness
            )));
        }

        // Translation allocates per-block register state, so cost grows with
        // block count - and block count comes from decoding a region derived
        // from attacker-controlled file headers. The decoder's instruction
        // budget bounds this indirectly; this is the direct statement of the
        // limit.
        if self.func.block_count() > MAX_TRANSLATABLE_BLOCKS {
            return Err(Error::X86Error(format!(
                "x86 function has {} blocks, exceeding the {} block translation limit",
                self.func.block_count(),
                MAX_TRANSLATABLE_BLOCKS
            )));
        }

        let block_count = self.func.block_count();
        let mut record = BoundaryRecorder::<usize>::new(block_count);
        // The first pop loads the argument.
        let arg_var = self.create_variable(VariableOrigin::Argument(0), DefSite::entry());
        let mut ssa_blocks = Vec::with_capacity(block_count);
        for block_idx in 0..block_count {
            ssa_blocks.push(self.translate_block(block_idx, arg_var, &mut record)?);
        }

        // DynCipher functions take one argument (the input value)
        let mut ssa_func = SsaFunction::new(1, 0);
        for block in ssa_blocks {
            ssa_func.add_block(block);
        }
        // The variables already have dense ids from this translator's own
        // allocator, which the blocks above name.
        for var in &self.variables {
            ssa_func.create_variable(
                var.origin(),
                var.version(),
                var.def_site(),
                var.var_type().clone(),
            );
        }

        let recorded = record.construct(&mut ssa_func, |_| SsaType::I32);
        let constructed = &recorded.construction;
        // What a register holds when the function is entered: a placeholder
        // that became its register's entry value, or one construction minted
        // for a path no write reaches. These stubs are entered with nothing in
        // their registers, so any of them the code uses is a read of nothing.
        let mut entry_values: BTreeMap<SsaVarId, usize> = record
            .reads()
            .iter()
            .filter(|read| !constructed.replacements.contains_key(&read.var))
            .map(|read| (read.var, read.key))
            .collect();
        for (group, value) in &constructed.minted_entry_values {
            if let Some(key) = recorded.key(*group) {
                entry_values.insert(*value, key);
            }
        }
        let used = Self::used_values(&ssa_func);
        if let Some(register) = used.iter().find_map(|value| entry_values.get(value)) {
            return Err(Error::X86Error(format!(
                "Register index {register} is read before anything writes it"
            )));
        }
        if used.iter().any(|value| self.undefined.contains(value)) {
            return Err(Error::X86Error(
                "a value popped with nothing pushed is read, and what it holds is not followed"
                    .to_string(),
            ));
        }

        // The finishing sequence, from the crate that owns it: stamp
        // instruction identities, refresh definition sites, prune what control
        // cannot reach, rebuild the use index, and drop the placeholders no
        // read needed. The use index matters most - a function handed on with
        // every use list empty tells a dead-code pass that nobody reads a live
        // definition.
        // At the full level, which checks that every definition dominates its uses: a
        // value read on a path that does not define it is a wrong translation like any
        // other, and the functions translated here are small
        let options = SsaConstructOptions::default().verified_at(VerifyLevel::Full);
        let report = ssa_func
            .finish_construction(&options)
            .map_err(|e| Error::SsaError(e.to_string()))?;

        // A finding means the translation is wrong. The caller then keeps the
        // native stub, which still computes what it always did; SSA that does not
        // verify would be turned into code that computes something else.
        if !report.findings.is_empty() {
            return Err(Error::X86Error(format!(
                "x86 translation produced invalid SSA: {:?}",
                report.findings
            )));
        }

        Ok(ssa_func)
    }

    /// The values the function uses: read by an instruction, or merged by a phi
    /// whose result is used.
    fn used_values(ssa: &SsaFunction) -> BTreeSet<SsaVarId> {
        let mut used: BTreeSet<SsaVarId> = ssa
            .blocks()
            .iter()
            .flat_map(|block| block.instructions())
            .flat_map(SsaInstruction::uses)
            .collect();
        let mut pending: Vec<SsaVarId> = used.iter().copied().collect();
        while let Some(value) = pending.pop() {
            for phi in ssa.blocks().iter().flat_map(|block| block.phi_nodes()) {
                if phi.result() != value {
                    continue;
                }
                for operand in phi.operands() {
                    if used.insert(operand.value()) {
                        pending.push(operand.value());
                    }
                }
            }
        }
        used
    }

    /// Translates one block, entered with a placeholder for every register.
    ///
    /// Each placeholder is recorded as a read the block makes before writing,
    /// and what the block leaves in each register as its write; construction
    /// answers the placeholders afterwards. A placeholder nothing reads costs a
    /// variable that finishing drops.
    ///
    /// A block that does not end in a jump or a return falls through to the block
    /// starting where it ends, and is given that jump as its terminator.
    fn translate_block(
        &mut self,
        block_idx: usize,
        arg_var: SsaVarId,
        record: &mut BoundaryRecorder<usize>,
    ) -> Result<SsaBlock> {
        let mut ssa_block = SsaBlock::new(block_idx);

        let mut reg_state = RegisterState::new();
        let mut entered = [None; MAX_REGISTERS];
        for (index, slot) in entered.iter_mut().enumerate() {
            let placeholder = self.create_variable(VariableOrigin::Phi, DefSite::entry());
            record.record_read(block_idx, index, placeholder, true);
            *slot = Some(placeholder);
        }
        reg_state.registers = entered;

        // Segment registers are constant selectors in user-mode code: the
        // entry block defines them, and every other block reads that.
        if block_idx == 0 {
            let seg_regs = [
                X86Register::Es,
                X86Register::Cs,
                X86Register::Ss,
                X86Register::Ds,
                X86Register::Fs,
                X86Register::Gs,
            ];
            for seg in seg_regs {
                let seg_var = self.create_variable(VariableOrigin::Phi, DefSite::entry());
                reg_state.set(seg, seg_var);
            }
        }

        // Track flags for CMP/TEST + Jcc fusion
        let mut flags = FlagState::new();

        // The machine stack this block starts with. The entry block is entered
        // with the caller's argument on it, which is the calling convention
        // these stubs are built to; every other block starts with the stack
        // this translation can see nothing on, and a pop there is refused.
        let mut stack: Vec<SsaVarId> = if block_idx == 0 {
            vec![arg_var]
        } else {
            Vec::new()
        };

        let block = self
            .func
            .block(block_idx)
            .ok_or_else(|| Error::X86Error(format!("Block {block_idx} not found")))?;

        for decoded in &block.instructions {
            let instrs = self.translate_instruction(
                decoded,
                &mut reg_state,
                &mut flags,
                &mut stack,
                block_idx,
            )?;

            for instr in instrs {
                ssa_block.add_instruction(instr);
            }
        }

        let terminated = matches!(
            block.terminator(),
            Some(X86Instruction::Jmp { .. } | X86Instruction::Jcc { .. } | X86Instruction::Ret)
        );
        if !terminated {
            let next = self.block_at_offset(block.end_offset)?;
            ssa_block.add_instruction(SsaInstruction::synthetic(SsaOp::Jump { target: next }));
        }

        for (index, (exit, entry)) in reg_state.registers.iter().zip(entered).enumerate() {
            if let Some(exit) = *exit {
                if Some(exit) != entry {
                    record.write(block_idx, index, exit);
                }
            }
        }

        Ok(ssa_block)
    }

    /// Translates a single x86 instruction to SSA operations.
    #[allow(clippy::too_many_lines)]
    fn translate_instruction(
        &mut self,
        decoded: &X86DecodedInstruction,
        reg_state: &mut RegisterState,
        flags: &mut FlagState,
        stack: &mut Vec<SsaVarId>,
        block_idx: usize,
    ) -> Result<Vec<SsaInstruction>> {
        let mut result = Vec::new();
        let out = &mut result;

        match &decoded.instruction {
            // Data movement: none of these touch the flags
            X86Instruction::Mov { dst, src } => {
                let value = self.read_operand(src, reg_state, out, block_idx)?;
                self.write_operand(dst, value, reg_state, out, block_idx)?;
            }

            X86Instruction::Movzx { dst, src } => {
                // A narrow operand reads zero-extended already
                let value = self.read_operand(src, reg_state, out, block_idx)?;
                self.write_operand(dst, value, reg_state, out, block_idx)?;
            }

            X86Instruction::Movsx { dst, src } => {
                let value = self.read_operand(src, reg_state, out, block_idx)?;
                let bits = narrow_bits(src).unwrap_or(32);
                let extended = self.sign_extend(value, bits, out, block_idx);
                self.write_operand(dst, extended, reg_state, out, block_idx)?;
            }

            X86Instruction::Lea { dst, src } => {
                // LEA computes an address without dereferencing
                let addr = self.compute_memory_address(src, reg_state, out, block_idx)?;
                self.write_register(*dst, addr, reg_state, out, block_idx)?;
            }

            X86Instruction::Push { src } => {
                // The machine stack, as the values on it. A push is the only
                // thing that puts one there and a pop is the only thing that
                // takes one off, so the pair is what carries a value across a
                // save-and-restore - the shape every one of these stubs uses
                // around the computation it protects. Its slots are 32 bits.
                if narrow_bits(src).is_some() {
                    return Err(self.unmodelled(decoded, "a 16-bit push"));
                }
                let value = self.read_operand(src, reg_state, out, block_idx)?;
                stack.push(value);
            }

            X86Instruction::Pop { dst } => {
                // A pop takes back what the matching push left. The entry
                // block's stack starts holding the caller's argument, which is
                // how that argument reaches the first pop, so no rule about
                // which pop is special is needed here.
                if narrow_bits(&X86Operand::Register(*dst)).is_some() {
                    return Err(self.unmodelled(decoded, "a 16-bit pop"));
                }
                // A pop with nothing pushed reads a value from outside what this
                // translation follows: a push in another block, or a frame the
                // caller built. It is named by a placeholder definition, and the
                // function is refused if anything reads it.
                let value = match stack.pop() {
                    Some(value) => value,
                    None => {
                        let placeholder = self.get_constant(0, out, block_idx);
                        self.undefined.insert(placeholder);
                        placeholder
                    }
                };
                self.write_register(*dst, value, reg_state, out, block_idx)?;
            }

            X86Instruction::Xchg { dst, src } => {
                let dst_value = self.read_operand(dst, reg_state, out, block_idx)?;
                let src_value = self.read_operand(src, reg_state, out, block_idx)?;
                self.write_operand(dst, src_value, reg_state, out, block_idx)?;
                self.write_operand(src, dst_value, reg_state, out, block_idx)?;
            }

            X86Instruction::Xor { dst, src } | X86Instruction::Sub { dst, src }
                if dst.is_register() && dst == src =>
            {
                // `xor r, r` and `sub r, r` are zero whatever r held: the idiom that
                // clears a register reads nothing
                let zero = self.get_zero_constant(out, block_idx);
                self.write_operand(dst, zero, reg_state, out, block_idx)?;
                if narrow_bits(dst).is_some() {
                    flags.clear();
                } else if matches!(decoded.instruction, X86Instruction::Xor { .. }) {
                    self.set_logic_flags(flags, zero, zero, zero, None, out, block_idx);
                } else {
                    flags.set_compare(zero, zero);
                    flags.set_carry(zero);
                }
            }

            // Arithmetic
            X86Instruction::Add { dst, src } | X86Instruction::Xadd { dst, src } => {
                let left = self.read_operand(dst, reg_state, out, block_idx)?;
                let right = self.read_operand(src, reg_state, out, block_idx)?;
                let sum = self.emit(out, block_idx, |dest| SsaOp::Add {
                    dest,
                    left,
                    right,
                    flags: None,
                });
                if matches!(decoded.instruction, X86Instruction::Xadd { .. }) {
                    // XADD hands the destination's old value to the source first, so
                    // the sum is what a register serving as both ends up holding
                    self.write_operand(src, left, reg_state, out, block_idx)?;
                }
                self.write_operand(dst, sum, reg_state, out, block_idx)?;
                if narrow_bits(dst).is_some() {
                    flags.clear();
                } else {
                    flags.set_result(sum, left, right, ResultKind::Add);
                    // CF: the sum wrapped below the left operand
                    let carry = self.compare(CmpKind::Lt, sum, left, true, out, block_idx);
                    flags.set_carry(carry);
                }
            }

            X86Instruction::Sub { dst, src } => {
                let left = self.read_operand(dst, reg_state, out, block_idx)?;
                let right = self.read_operand(src, reg_state, out, block_idx)?;
                let difference = self.emit(out, block_idx, |dest| SsaOp::Sub {
                    dest,
                    left,
                    right,
                    flags: None,
                });
                self.write_operand(dst, difference, reg_state, out, block_idx)?;
                if narrow_bits(dst).is_some() {
                    flags.clear();
                } else {
                    // The flags of SUB are those of CMP on the same operands
                    flags.set_compare(left, right);
                    let borrow = self.compare(CmpKind::Lt, left, right, true, out, block_idx);
                    flags.set_carry(borrow);
                }
            }

            X86Instruction::Cmp { left, right } => {
                let left_value = self.read_operand(left, reg_state, out, block_idx)?;
                let right_value = self.read_operand(right, reg_state, out, block_idx)?;
                if narrow_bits(left).is_some() {
                    flags.clear();
                } else {
                    flags.set_compare(left_value, right_value);
                    let borrow =
                        self.compare(CmpKind::Lt, left_value, right_value, true, out, block_idx);
                    flags.set_carry(borrow);
                }
            }

            X86Instruction::Imul { dst, src, src2 } => {
                // The two- and three-operand forms keep the low half of the
                // product, which is the same for a signed and an unsigned
                // multiply. CF and OF report whether the product fits, which is
                // not modelled, and ZF, SF and PF are undefined.
                let (left, right) = match src2 {
                    Some(immediate) => (
                        self.read_operand(src, reg_state, out, block_idx)?,
                        self.read_operand(immediate, reg_state, out, block_idx)?,
                    ),
                    None => (
                        self.read_register(*dst, reg_state, out, block_idx)?,
                        self.read_operand(src, reg_state, out, block_idx)?,
                    ),
                };
                let product = self.emit(out, block_idx, |dest| SsaOp::Mul {
                    dest,
                    left,
                    right,
                    flags: None,
                });
                self.write_register(*dst, product, reg_state, out, block_idx)?;
                flags.clear();
            }

            X86Instruction::Mul { src } => {
                // EDX:EAX = EAX * src, unsigned, computed as a 64-bit product
                if narrow_bits(src).is_some() {
                    return Err(self.unmodelled(decoded, "an 8- or 16-bit MUL"));
                }
                let eax = self.read_register(X86Register::Eax, reg_state, out, block_idx)?;
                let factor = self.read_operand(src, reg_state, out, block_idx)?;
                let wide_eax = self.convert(eax, SsaType::U64, true, out, block_idx);
                let wide_factor = self.convert(factor, SsaType::U64, true, out, block_idx);
                let product = self.emit_typed(SsaType::U64, out, block_idx, |dest| SsaOp::Mul {
                    dest,
                    left: wide_eax,
                    right: wide_factor,
                    flags: None,
                });
                let (low, high) = self.split_wide(product, out, block_idx);
                self.write_register(X86Register::Eax, low, reg_state, out, block_idx)?;
                self.write_register(X86Register::Edx, high, reg_state, out, block_idx)?;
                // CF and OF report a non-zero high half, which is not modelled;
                // ZF, SF and PF are undefined
                flags.clear();
            }

            X86Instruction::Div { src } | X86Instruction::Idiv { src } => {
                // EAX, EDX = EDX:EAX / src, EDX:EAX % src, as 64-bit division. A
                // quotient that does not fit in 32 bits faults natively (#DE); the
                // division here then keeps its low 32 bits.
                if narrow_bits(src).is_some() {
                    return Err(self.unmodelled(decoded, "an 8- or 16-bit DIV or IDIV"));
                }
                let unsigned = matches!(decoded.instruction, X86Instruction::Div { .. });
                let wide = if unsigned { SsaType::U64 } else { SsaType::I64 };
                let eax = self.read_register(X86Register::Eax, reg_state, out, block_idx)?;
                let edx = self.read_register(X86Register::Edx, reg_state, out, block_idx)?;
                let divisor = self.read_operand(src, reg_state, out, block_idx)?;
                let dividend = self.join_wide(edx, eax, &wide, out, block_idx);
                let wide_divisor = self.convert(divisor, wide.clone(), unsigned, out, block_idx);
                let quotient = self.emit_typed(wide.clone(), out, block_idx, |dest| SsaOp::Div {
                    dest,
                    left: dividend,
                    right: wide_divisor,
                    unsigned,
                    flags: None,
                });
                let remainder = self.emit_typed(wide, out, block_idx, |dest| SsaOp::Rem {
                    dest,
                    left: dividend,
                    right: wide_divisor,
                    unsigned,
                    flags: None,
                });
                let quotient = self.convert(quotient, SsaType::I32, unsigned, out, block_idx);
                let remainder = self.convert(remainder, SsaType::I32, unsigned, out, block_idx);
                self.write_register(X86Register::Eax, quotient, reg_state, out, block_idx)?;
                self.write_register(X86Register::Edx, remainder, reg_state, out, block_idx)?;
                // Every flag is undefined after a division
                flags.clear();
            }

            X86Instruction::Neg { dst } => {
                let operand = self.read_operand(dst, reg_state, out, block_idx)?;
                let negated = self.emit(out, block_idx, |dest| SsaOp::Neg {
                    dest,
                    operand,
                    flags: None,
                });
                self.write_operand(dst, negated, reg_state, out, block_idx)?;
                if narrow_bits(dst).is_some() {
                    flags.clear();
                } else {
                    flags.set_result(negated, operand, operand, ResultKind::Neg);
                    // CF = (operand != 0)
                    let zero = self.get_zero_constant(out, block_idx);
                    let carry = self.compare(CmpKind::Ne, operand, zero, false, out, block_idx);
                    flags.set_carry(carry);
                }
            }

            X86Instruction::Inc { dst } | X86Instruction::Dec { dst } => {
                let operand = self.read_operand(dst, reg_state, out, block_idx)?;
                let one = self.get_constant(1, out, block_idx);
                let increment = matches!(decoded.instruction, X86Instruction::Inc { .. });
                let value = self.emit(out, block_idx, |dest| {
                    if increment {
                        SsaOp::Add {
                            dest,
                            left: operand,
                            right: one,
                            flags: None,
                        }
                    } else {
                        SsaOp::Sub {
                            dest,
                            left: operand,
                            right: one,
                            flags: None,
                        }
                    }
                });
                self.write_operand(dst, value, reg_state, out, block_idx)?;
                // ZF, SF, OF and PF as the addition or subtraction of one sets
                // them; CF is left as it was
                if narrow_bits(dst).is_some() {
                    let carry = flags.carry();
                    flags.clear();
                    if let Some(carry) = carry {
                        flags.set_carry_only(carry);
                    }
                } else {
                    let kind = if increment {
                        ResultKind::Add
                    } else {
                        ResultKind::Sub
                    };
                    flags.set_result(value, operand, one, kind);
                }
            }

            X86Instruction::Adc { dst, src } | X86Instruction::Sbb { dst, src } => {
                // dst + src + CF, or dst - src - CF: the carry the previous
                // instruction left, which must be known
                let carry_in = flags.carry().ok_or_else(|| {
                    self.unmodelled(decoded, "an ADC or SBB whose carry flag is not known")
                })?;
                let left = self.read_operand(dst, reg_state, out, block_idx)?;
                let right = self.read_operand(src, reg_state, out, block_idx)?;
                let add = matches!(decoded.instruction, X86Instruction::Adc { .. });
                let partial = self.emit(out, block_idx, |dest| {
                    if add {
                        SsaOp::Add {
                            dest,
                            left,
                            right,
                            flags: None,
                        }
                    } else {
                        SsaOp::Sub {
                            dest,
                            left,
                            right,
                            flags: None,
                        }
                    }
                });
                let value = self.emit(out, block_idx, |dest| {
                    if add {
                        SsaOp::Add {
                            dest,
                            left: partial,
                            right: carry_in,
                            flags: None,
                        }
                    } else {
                        SsaOp::Sub {
                            dest,
                            left: partial,
                            right: carry_in,
                            flags: None,
                        }
                    }
                });
                self.write_operand(dst, value, reg_state, out, block_idx)?;
                if narrow_bits(dst).is_some() {
                    flags.clear();
                } else {
                    // ADC carries out of either addition; SBB borrows in either
                    // subtraction
                    let (first, second) = if add {
                        (
                            self.compare(CmpKind::Lt, partial, left, true, out, block_idx),
                            self.compare(CmpKind::Lt, value, partial, true, out, block_idx),
                        )
                    } else {
                        (
                            self.compare(CmpKind::Lt, left, right, true, out, block_idx),
                            self.compare(CmpKind::Lt, partial, carry_in, true, out, block_idx),
                        )
                    };
                    let carry_out = self.emit(out, block_idx, |dest| SsaOp::Or {
                        dest,
                        left: first,
                        right: second,
                        flags: None,
                    });
                    let kind = if add {
                        ResultKind::Add
                    } else {
                        ResultKind::Sub
                    };
                    flags.set_result(value, left, right, kind);
                    flags.set_carry(carry_out);
                }
            }

            // Bitwise
            X86Instruction::And { dst, src }
            | X86Instruction::Or { dst, src }
            | X86Instruction::Xor { dst, src } => {
                let left = self.read_operand(dst, reg_state, out, block_idx)?;
                let right = self.read_operand(src, reg_state, out, block_idx)?;
                let value = self.emit(out, block_idx, |dest| match &decoded.instruction {
                    X86Instruction::And { .. } => SsaOp::And {
                        dest,
                        left,
                        right,
                        flags: None,
                    },
                    X86Instruction::Or { .. } => SsaOp::Or {
                        dest,
                        left,
                        right,
                        flags: None,
                    },
                    _ => SsaOp::Xor {
                        dest,
                        left,
                        right,
                        flags: None,
                    },
                });
                self.write_operand(dst, value, reg_state, out, block_idx)?;
                self.set_logic_flags(flags, value, left, right, narrow_bits(dst), out, block_idx);
            }

            X86Instruction::Test { left, right } => {
                let left_value = self.read_operand(left, reg_state, out, block_idx)?;
                let right_value = self.read_operand(right, reg_state, out, block_idx)?;
                let value = self.emit(out, block_idx, |dest| SsaOp::And {
                    dest,
                    left: left_value,
                    right: right_value,
                    flags: None,
                });
                self.set_logic_flags(
                    flags,
                    value,
                    left_value,
                    right_value,
                    narrow_bits(left),
                    out,
                    block_idx,
                );
            }

            X86Instruction::Not { dst } => {
                // NOT does not touch the flags
                let operand = self.read_operand(dst, reg_state, out, block_idx)?;
                let value = self.emit(out, block_idx, |dest| SsaOp::Not {
                    dest,
                    operand,
                    flags: None,
                });
                self.write_operand(dst, value, reg_state, out, block_idx)?;
            }

            X86Instruction::Shl { dst, count }
            | X86Instruction::Shr { dst, count }
            | X86Instruction::Sar { dst, count } => {
                let kind = match decoded.instruction {
                    X86Instruction::Shl { .. } => Shift::Left,
                    X86Instruction::Shr { .. } => Shift::Right,
                    _ => Shift::Arithmetic,
                };
                self.translate_shift(kind, dst, count, reg_state, flags, out, block_idx)?;
            }

            X86Instruction::Rol { dst, count } | X86Instruction::Ror { dst, count } => {
                // A narrow rotate turns within its own width, which a 32-bit
                // rotate does not
                if narrow_bits(dst).is_some() {
                    return Err(self.unmodelled(decoded, "an 8- or 16-bit rotate"));
                }
                let left = matches!(decoded.instruction, X86Instruction::Rol { .. });
                let value = self.read_operand(dst, reg_state, out, block_idx)?;
                let amount = self.shift_amount(count, reg_state, out, block_idx)?;
                let rotated = self.emit(out, block_idx, |dest| {
                    if left {
                        SsaOp::Rol {
                            dest,
                            value,
                            amount,
                        }
                    } else {
                        SsaOp::Ror {
                            dest,
                            value,
                            amount,
                        }
                    }
                });
                self.write_operand(dst, rotated, reg_state, out, block_idx)?;
                // A rotate by zero leaves the flags alone; any other count sets
                // CF (and OF for a count of one) and leaves the rest, which the
                // flag state cannot express
                if immediate_count(count) != Some(0) {
                    flags.clear();
                }
            }

            X86Instruction::Bswap { dst } => {
                // BSWAP does not touch the flags
                if narrow_bits(&X86Operand::Register(*dst)).is_some() {
                    return Err(self.unmodelled(decoded, "a 16-bit BSWAP"));
                }
                let value = self.read_register(*dst, reg_state, out, block_idx)?;
                let swapped = self.emit(out, block_idx, |dest| SsaOp::BSwap { dest, src: value });
                self.write_register(*dst, swapped, reg_state, out, block_idx)?;
            }

            // Conditional move: dst = condition ? src : dst
            X86Instruction::Cmovcc {
                condition,
                dst,
                src,
            } => {
                let src_value = self.read_operand(src, reg_state, out, block_idx)?;
                let dst_value = self.read_register(*dst, reg_state, out, block_idx)?;

                // Evaluate condition to get a 0/1 value
                let chosen = self.evaluate_condition(*condition, flags, out, block_idx)?;

                // result = dst ^ (-cond & (src ^ dst)): src when the condition
                // holds, dst when it does not
                let mask = self.emit(out, block_idx, |dest| SsaOp::Neg {
                    dest,
                    operand: chosen,
                    flags: None,
                });
                let difference = self.emit(out, block_idx, |dest| SsaOp::Xor {
                    dest,
                    left: src_value,
                    right: dst_value,
                    flags: None,
                });
                let masked = self.emit(out, block_idx, |dest| SsaOp::And {
                    dest,
                    left: difference,
                    right: mask,
                    flags: None,
                });
                let value = self.emit(out, block_idx, |dest| SsaOp::Xor {
                    dest,
                    left: dst_value,
                    right: masked,
                    flags: None,
                });
                self.write_register(*dst, value, reg_state, out, block_idx)?;
                // Cmovcc doesn't modify flags
            }

            // Set byte on condition: dst = condition ? 1 : 0
            X86Instruction::Setcc { condition, dst } => {
                let value = self.evaluate_condition(*condition, flags, out, block_idx)?;
                self.write_operand(dst, value, reg_state, out, block_idx)?;
                // Setcc doesn't modify flags
            }

            X86Instruction::Bsf { .. } | X86Instruction::Bsr { .. } => {
                // A zero source leaves the destination as it was, which a bit scan
                // operation does not state
                return Err(self.unmodelled(decoded, "a bit scan"));
            }

            // Bit test: CF is the tested bit; ZF is kept and the rest undefined
            X86Instruction::Bt { src, bit } => {
                if narrow_bits(src).is_some() {
                    return Err(self.unmodelled(decoded, "a 16-bit BT"));
                }
                if src.is_memory() && !matches!(bit, X86Operand::Immediate(_)) {
                    // A register bit offset addresses a bit string past the operand
                    return Err(self.unmodelled(decoded, "a BT of memory by a register offset"));
                }
                let value = self.read_operand(src, reg_state, out, block_idx)?;
                let position = self.shift_amount(bit, reg_state, out, block_idx)?;
                let shifted = self.emit(out, block_idx, |dest| SsaOp::Shr {
                    dest,
                    value,
                    amount: position,
                    unsigned: true,
                    flags: None,
                });
                let one = self.get_constant(1, out, block_idx);
                let carry = self.emit(out, block_idx, |dest| SsaOp::And {
                    dest,
                    left: shifted,
                    right: one,
                    flags: None,
                });
                flags.set_carry_only(carry);
            }

            // Control flow
            X86Instruction::Jmp { target } => {
                let target_block = self.find_block_for_address(*target)?;
                out.push(SsaInstruction::synthetic(SsaOp::Jump {
                    target: target_block,
                }));
            }

            X86Instruction::Jcc { condition, target } => {
                let target_block = self.find_block_for_address(*target)?;
                // Not taken, control goes on with the instruction after the jump,
                // which starts a block of its own
                let fallthrough_block = self.block_at_offset(decoded.end_offset())?;

                if let Some((cmp, left, right, unsigned)) = flags.comparison(*condition) {
                    out.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                        left,
                        right,
                        cmp,
                        unsigned,
                        true_target: target_block,
                        false_target: fallthrough_block,
                    }));
                } else {
                    let holds = self.evaluate_condition(*condition, flags, out, block_idx)?;
                    let zero = self.get_zero_constant(out, block_idx);
                    out.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                        left: holds,
                        right: zero,
                        cmp: CmpKind::Ne,
                        unsigned: false,
                        true_target: target_block,
                        false_target: fallthrough_block,
                    }));
                }
            }

            X86Instruction::Ret => {
                let ret_val = reg_state.get(X86Register::Eax);
                out.push(SsaInstruction::synthetic(SsaOp::returns(ret_val)));
            }

            X86Instruction::Call { target: _ } => {
                // Calls are not supported in DynCipher stubs
                return Err(Error::X86Error(format!(
                    "Unsupported CALL instruction at 0x{:x}",
                    decoded.offset
                )));
            }

            // Miscellaneous
            X86Instruction::Nop => {
                // No operation
            }

            X86Instruction::Cdq => {
                // EDX = the sign of EAX, in every bit
                let eax = self.read_register(X86Register::Eax, reg_state, out, block_idx)?;
                let thirty_one = self.get_constant(31, out, block_idx);
                let sign = self.emit(out, block_idx, |dest| SsaOp::Shr {
                    dest,
                    value: eax,
                    amount: thirty_one,
                    unsigned: false,
                    flags: None,
                });
                self.write_register(X86Register::Edx, sign, reg_state, out, block_idx)?;
            }

            X86Instruction::Cwde => {
                // EAX = AX sign-extended; the flags are untouched
                let ax = self.read_register(X86Register::Ax, reg_state, out, block_idx)?;
                let extended = self.sign_extend(ax, 16, out, block_idx);
                self.write_register(X86Register::Eax, extended, reg_state, out, block_idx)?;
            }

            X86Instruction::Unsupported { offset, mnemonic } => {
                return Err(Error::X86Error(format!(
                    "Unsupported instruction '{mnemonic}' at 0x{offset:x}"
                )));
            }
        }

        Ok(result)
    }

    /// The error refusing `decoded`, an instruction in a form this translation does
    /// not model exactly: `what` names the form.
    fn unmodelled(&self, decoded: &X86DecodedInstruction, what: &str) -> Error {
        Error::X86Error(format!(
            "{what} at 0x{:x} is not modelled exactly",
            self.func.base_address.saturating_add(decoded.offset)
        ))
    }

    /// Records the flags of a logical operation that computed `value`: ZF, SF and
    /// PF from it, OF and CF cleared. An operation narrower than 32 bits leaves the
    /// flags unknown, since its ZF, SF and PF are those of its own width.
    #[allow(clippy::too_many_arguments)]
    fn set_logic_flags(
        &mut self,
        flags: &mut FlagState,
        value: SsaVarId,
        left: SsaVarId,
        right: SsaVarId,
        narrow: Option<u32>,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) {
        if narrow.is_some() {
            flags.clear();
            return;
        }
        flags.set_result(value, left, right, ResultKind::Logic);
        let zero = self.get_zero_constant(instrs, block_idx);
        flags.set_carry(zero);
    }

    /// Translates `SHL`, `SHR` or `SAR` of `dst` by `count`.
    ///
    /// The count is masked to five bits, as the processor masks it. A narrow
    /// operand shifts as its zero-extended (or, for `SAR`, sign-extended) value,
    /// whose low bits are the narrow result. The flags follow an immediate count at
    /// the full width: unchanged for a count of zero, else ZF, SF and PF from the
    /// result and CF the last bit shifted out. A count in a register may be zero,
    /// so the flags after it are unknown.
    #[allow(clippy::too_many_arguments)]
    fn translate_shift(
        &mut self,
        kind: Shift,
        dst: &X86Operand,
        count: &X86Operand,
        reg_state: &mut RegisterState,
        flags: &mut FlagState,
        out: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        let narrow = narrow_bits(dst);
        let read = self.read_operand(dst, reg_state, out, block_idx)?;
        let value = match (kind, narrow) {
            (Shift::Arithmetic, Some(bits)) => self.sign_extend(read, bits, out, block_idx),
            _ => read,
        };
        let amount = self.shift_amount(count, reg_state, out, block_idx)?;
        let shifted = self.emit(out, block_idx, |dest| match kind {
            Shift::Left => SsaOp::Shl {
                dest,
                value,
                amount,
                flags: None,
            },
            Shift::Right | Shift::Arithmetic => SsaOp::Shr {
                dest,
                value,
                amount,
                unsigned: kind == Shift::Right,
                flags: None,
            },
        });
        self.write_operand(dst, shifted, reg_state, out, block_idx)?;

        match immediate_count(count) {
            Some(0) => {}
            Some(n) if narrow.is_none() => {
                // CF: SHL shifts bit 32 - n out, SHR and SAR bit n - 1 (n is 1 to 31)
                let (from, unsigned) = match kind {
                    Shift::Left => (32_i64.saturating_sub(n), true),
                    Shift::Right => (n.saturating_sub(1), true),
                    Shift::Arithmetic => (n.saturating_sub(1), false),
                };
                let at = self.get_constant(from, out, block_idx);
                let moved = self.emit(out, block_idx, |dest| SsaOp::Shr {
                    dest,
                    value,
                    amount: at,
                    unsigned,
                    flags: None,
                });
                let one = self.get_constant(1, out, block_idx);
                let carry = self.emit(out, block_idx, |dest| SsaOp::And {
                    dest,
                    left: moved,
                    right: one,
                    flags: None,
                });
                flags.set_result(shifted, value, amount, ResultKind::Shift);
                flags.set_carry(carry);
            }
            _ => flags.clear(),
        }
        Ok(())
    }

    /// The amount of a shift, rotate or bit test: an immediate masked to five
    /// bits, or a register's value masked as the processor masks it.
    fn shift_amount(
        &mut self,
        count: &X86Operand,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        if let Some(amount) = immediate_count(count) {
            return Ok(self.get_constant(amount, instrs, block_idx));
        }
        let value = self.read_operand(count, reg_state, instrs, block_idx)?;
        let mask = self.get_constant(31, instrs, block_idx);
        Ok(self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: value,
            right: mask,
            flags: None,
        }))
    }

    /// Evaluates an x86 condition code into a 0/1 SSA variable.
    ///
    /// After a `CMP` or `SUB`, a comparison condition is the comparison of the
    /// operands. Otherwise the condition is the formula of the flags it tests
    /// ([`condition_formula`]), each flag computed from the producer that set it.
    ///
    /// # Errors
    ///
    /// When the condition reads a flag that is not known.
    fn evaluate_condition(
        &mut self,
        condition: X86Condition,
        flags: &FlagState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        if let Some((cmp, left, right, unsigned)) = flags.comparison(condition) {
            return Ok(self.compare(cmp, left, right, unsigned, instrs, block_idx));
        }

        let unknown = |flag: &str| {
            Error::X86Error(format!(
                "Cannot evaluate condition {condition:?}: {flag} is not known"
            ))
        };
        let (formula, negated) = condition_formula(condition);
        let carry = || flags.carry().ok_or_else(|| unknown("the carry flag"));
        let producer = || flags.producer().ok_or_else(|| unknown("the flags"));
        let holds = match formula {
            FlagFormula::Zero => self.zero_flag(producer()?, instrs, block_idx),
            FlagFormula::Sign => self.sign_flag(producer()?, instrs, block_idx),
            FlagFormula::Overflow => self
                .overflow_flag(producer()?, instrs, block_idx)
                .ok_or_else(|| unknown("the overflow flag"))?,
            FlagFormula::Parity => self.parity_flag(producer()?, instrs, block_idx),
            FlagFormula::Carry => carry()?,
            FlagFormula::CarryOrZero => {
                let carry = carry()?;
                let zero = self.zero_flag(producer()?, instrs, block_idx);
                self.emit(instrs, block_idx, |dest| SsaOp::Or {
                    dest,
                    left: carry,
                    right: zero,
                    flags: None,
                })
            }
            FlagFormula::Less | FlagFormula::LessOrEqual => {
                let producer = producer()?;
                let sign = self.sign_flag(producer, instrs, block_idx);
                let overflow = self
                    .overflow_flag(producer, instrs, block_idx)
                    .ok_or_else(|| unknown("the overflow flag"))?;
                let less = self.emit(instrs, block_idx, |dest| SsaOp::Xor {
                    dest,
                    left: sign,
                    right: overflow,
                    flags: None,
                });
                if formula == FlagFormula::Less {
                    less
                } else {
                    let zero = self.zero_flag(producer, instrs, block_idx);
                    self.emit(instrs, block_idx, |dest| SsaOp::Or {
                        dest,
                        left: zero,
                        right: less,
                        flags: None,
                    })
                }
            }
        };
        if !negated {
            return Ok(holds);
        }
        let one = self.get_constant(1, instrs, block_idx);
        Ok(self.emit(instrs, block_idx, |dest| SsaOp::Xor {
            dest,
            left: holds,
            right: one,
            flags: None,
        }))
    }

    /// The value the flags of `producer` describe: the result, or for a `CMP` the
    /// difference of its operands.
    fn flag_value(
        &mut self,
        producer: FlagProducer,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        match producer {
            FlagProducer::Compare { left, right } => {
                self.emit(instrs, block_idx, |dest| SsaOp::Sub {
                    dest,
                    left,
                    right,
                    flags: None,
                })
            }
            FlagProducer::Result { result, .. } => result,
        }
    }

    /// ZF as a 0/1 value: the flagged value is zero.
    fn zero_flag(
        &mut self,
        producer: FlagProducer,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        match producer {
            FlagProducer::Compare { left, right } => {
                self.compare(CmpKind::Eq, left, right, false, instrs, block_idx)
            }
            FlagProducer::Result { result, .. } => {
                let zero = self.get_zero_constant(instrs, block_idx);
                self.compare(CmpKind::Eq, result, zero, false, instrs, block_idx)
            }
        }
    }

    /// SF as a 0/1 value: bit 31 of the flagged value.
    fn sign_flag(
        &mut self,
        producer: FlagProducer,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let value = self.flag_value(producer, instrs, block_idx);
        self.top_bit(value, instrs, block_idx)
    }

    /// Bit 31 of `value`, as a 0/1 value.
    fn top_bit(
        &mut self,
        value: SsaVarId,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let thirty_one = self.get_constant(31, instrs, block_idx);
        self.emit(instrs, block_idx, |dest| SsaOp::Shr {
            dest,
            value,
            amount: thirty_one,
            unsigned: true,
            flags: None,
        })
    }

    /// OF as a 0/1 value, or `None` when the producer leaves it undefined.
    ///
    /// - `CMP` and SBB/DEC: `((left ^ right) & (left ^ result))` at bit 31
    /// - ADD/ADC/INC/XADD: `((left ^ result) & (right ^ result))` at bit 31
    /// - logical operations: 0
    /// - NEG: the result is the most negative value
    fn overflow_flag(
        &mut self,
        producer: FlagProducer,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Option<SsaVarId> {
        let (result, left, right, kind) = match producer {
            FlagProducer::Compare { left, right } => {
                let difference = self.flag_value(producer, instrs, block_idx);
                (difference, left, right, ResultKind::Sub)
            }
            FlagProducer::Result {
                result,
                left,
                right,
                kind,
            } => (result, left, right, kind),
        };
        let (first, second) = match kind {
            ResultKind::Shift => return None,
            ResultKind::Logic => return Some(self.get_zero_constant(instrs, block_idx)),
            ResultKind::Neg => {
                let minimum = self.get_constant(i64::from(i32::MIN), instrs, block_idx);
                return Some(self.compare(CmpKind::Eq, result, minimum, false, instrs, block_idx));
            }
            ResultKind::Sub => ((left, right), (left, result)),
            ResultKind::Add => ((left, result), (right, result)),
        };
        let a = self.emit(instrs, block_idx, |dest| SsaOp::Xor {
            dest,
            left: first.0,
            right: first.1,
            flags: None,
        });
        let b = self.emit(instrs, block_idx, |dest| SsaOp::Xor {
            dest,
            left: second.0,
            right: second.1,
            flags: None,
        });
        let both = self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: a,
            right: b,
            flags: None,
        });
        Some(self.top_bit(both, instrs, block_idx))
    }

    /// PF as a 0/1 value: the low byte of the flagged value has an even number of
    /// set bits. Computed by folding the byte's bits together with XOR.
    fn parity_flag(
        &mut self,
        producer: FlagProducer,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let value = self.flag_value(producer, instrs, block_idx);
        let mut folded = value;
        for shift in [4, 2, 1] {
            let amount = self.get_constant(shift, instrs, block_idx);
            let moved = self.emit(instrs, block_idx, |dest| SsaOp::Shr {
                dest,
                value: folded,
                amount,
                unsigned: true,
                flags: None,
            });
            folded = self.emit(instrs, block_idx, |dest| SsaOp::Xor {
                dest,
                left: folded,
                right: moved,
                flags: None,
            });
        }
        // Bit 0 now holds the low byte's odd parity; PF is its complement
        let one = self.get_constant(1, instrs, block_idx);
        let odd = self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: folded,
            right: one,
            flags: None,
        });
        self.emit(instrs, block_idx, |dest| SsaOp::Xor {
            dest,
            left: odd,
            right: one,
            flags: None,
        })
    }

    /// Emits the comparison `left cmp right` as the integer 0 or 1.
    ///
    /// The comparison itself is a boolean; the flags and the values SETcc, CMOVcc and
    /// ADC compute with are integers, so it is converted to one.
    fn compare(
        &mut self,
        cmp: CmpKind,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        // Ne, Le and Ge are the complements of Eq, Gt and Lt
        let (base, negate) = match cmp {
            CmpKind::Eq => (CmpKind::Eq, false),
            CmpKind::Ne => (CmpKind::Eq, true),
            CmpKind::Lt => (CmpKind::Lt, false),
            CmpKind::Ge => (CmpKind::Lt, true),
            CmpKind::Gt => (CmpKind::Gt, false),
            CmpKind::Le => (CmpKind::Gt, true),
        };
        let compared = self.emit_typed(SsaType::Bool, instrs, block_idx, |dest| match base {
            CmpKind::Eq => SsaOp::Ceq {
                dest,
                left,
                right,
                signaling: false,
            },
            CmpKind::Lt => SsaOp::Clt {
                dest,
                left,
                right,
                unsigned,
                signaling: false,
            },
            _ => SsaOp::Cgt {
                dest,
                left,
                right,
                unsigned,
                signaling: false,
            },
        });
        let holds = self.convert(compared, SsaType::I32, true, instrs, block_idx);
        if !negate {
            return holds;
        }
        let one = self.get_constant(1, instrs, block_idx);
        self.emit(instrs, block_idx, |dest| SsaOp::Xor {
            dest,
            left: holds,
            right: one,
            flags: None,
        })
    }

    /// Reads an operand as a 32-bit value: a narrow register or memory operand
    /// zero-extended.
    fn read_operand(
        &mut self,
        operand: &X86Operand,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        match operand {
            X86Operand::Register(reg) => self.read_register(*reg, reg_state, instrs, block_idx),
            X86Operand::Immediate(val) => Ok(self.get_constant(*val, instrs, block_idx)),
            X86Operand::Memory(mem) => self.load_from_memory(mem, reg_state, instrs, block_idx),
        }
    }

    /// Writes a 32-bit value to an operand: the low bits of it to a narrow one.
    fn write_operand(
        &mut self,
        operand: &X86Operand,
        value: SsaVarId,
        reg_state: &mut RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        match operand {
            X86Operand::Register(reg) => {
                self.write_register(*reg, value, reg_state, instrs, block_idx)
            }
            X86Operand::Memory(mem) => {
                self.store_to_memory(mem, value, reg_state, instrs, block_idx)
            }
            X86Operand::Immediate(_) => Err(Error::X86Error(
                "Cannot store to immediate operand".to_string(),
            )),
        }
    }

    /// Gets the SSA variable for a register's full slot.
    fn get_register_value(reg: X86Register, reg_state: &RegisterState) -> Result<SsaVarId> {
        reg_state
            .get(reg)
            .ok_or_else(|| Error::X86Error(format!("Register {reg:?} not defined")))
    }

    /// Reads `reg`: a 32-bit register's value, or the bits an 8- or 16-bit
    /// register names in its full register, zero-extended.
    fn read_register(
        &mut self,
        reg: X86Register,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let full = Self::get_register_value(reg, reg_state)?;
        let Some((shift, mask)) = sub_register(reg) else {
            return Ok(full);
        };
        let lowered = if shift == 0 {
            full
        } else {
            let amount = self.get_constant(shift, instrs, block_idx);
            self.emit(instrs, block_idx, |dest| SsaOp::Shr {
                dest,
                value: full,
                amount,
                unsigned: true,
                flags: None,
            })
        };
        let mask = self.get_constant(mask, instrs, block_idx);
        Ok(self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: lowered,
            right: mask,
            flags: None,
        }))
    }

    /// Writes `value` to `reg`: a 32-bit register takes it whole, an 8- or 16-bit
    /// register its low bits, inserted into the full register's other bits.
    fn write_register(
        &mut self,
        reg: X86Register,
        value: SsaVarId,
        reg_state: &mut RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        let Some((shift, mask)) = sub_register(reg) else {
            reg_state.set(reg, value);
            return Ok(());
        };
        let full = Self::get_register_value(reg, reg_state)?;
        let keep = self.get_constant(!(mask << shift), instrs, block_idx);
        let kept = self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: full,
            right: keep,
            flags: None,
        });
        let low_mask = self.get_constant(mask, instrs, block_idx);
        let low = self.emit(instrs, block_idx, |dest| SsaOp::And {
            dest,
            left: value,
            right: low_mask,
            flags: None,
        });
        let placed = if shift == 0 {
            low
        } else {
            let amount = self.get_constant(shift, instrs, block_idx);
            self.emit(instrs, block_idx, |dest| SsaOp::Shl {
                dest,
                value: low,
                amount,
                flags: None,
            })
        };
        let merged = self.emit(instrs, block_idx, |dest| SsaOp::Or {
            dest,
            left: kept,
            right: placed,
            flags: None,
        });
        reg_state.set(reg, merged);
        Ok(())
    }

    /// `value`'s low `bits` bits sign-extended to 32 bits.
    fn sign_extend(
        &mut self,
        value: SsaVarId,
        bits: u32,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        if bits >= 32 {
            return value;
        }
        let amount = self.get_constant(i64::from(32_u32.saturating_sub(bits)), instrs, block_idx);
        let raised = self.emit(instrs, block_idx, |dest| SsaOp::Shl {
            dest,
            value,
            amount,
            flags: None,
        });
        self.emit(instrs, block_idx, |dest| SsaOp::Shr {
            dest,
            value: raised,
            amount,
            unsigned: false,
            flags: None,
        })
    }

    /// `value` converted to the integer type `target`, read as unsigned or signed.
    fn convert(
        &mut self,
        value: SsaVarId,
        target: SsaType,
        unsigned: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let ty = target.clone();
        self.emit_typed(ty, instrs, block_idx, |dest| SsaOp::IntConv {
            dest,
            operand: value,
            target,
            overflow_check: false,
            unsigned,
        })
    }

    /// The 64-bit value `high:low` of the type `wide`, from two 32-bit halves.
    fn join_wide(
        &mut self,
        high: SsaVarId,
        low: SsaVarId,
        wide: &SsaType,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let high = self.convert(high, wide.clone(), true, instrs, block_idx);
        let low = self.convert(low, wide.clone(), true, instrs, block_idx);
        let thirty_two = self.get_constant(32, instrs, block_idx);
        let raised = self.emit_typed(wide.clone(), instrs, block_idx, |dest| SsaOp::Shl {
            dest,
            value: high,
            amount: thirty_two,
            flags: None,
        });
        self.emit_typed(wide.clone(), instrs, block_idx, |dest| SsaOp::Or {
            dest,
            left: raised,
            right: low,
            flags: None,
        })
    }

    /// The low and high 32-bit halves of the unsigned 64-bit `value`.
    fn split_wide(
        &mut self,
        value: SsaVarId,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> (SsaVarId, SsaVarId) {
        let low = self.convert(value, SsaType::I32, true, instrs, block_idx);
        let thirty_two = self.get_constant(32, instrs, block_idx);
        let shifted = self.emit_typed(SsaType::U64, instrs, block_idx, |dest| SsaOp::Shr {
            dest,
            value,
            amount: thirty_two,
            unsigned: true,
            flags: None,
        });
        let high = self.convert(shifted, SsaType::I32, true, instrs, block_idx);
        (low, high)
    }

    /// Loads a memory operand: a narrow one zero-extended to 32 bits.
    fn load_from_memory(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let addr = self.compute_memory_address(mem, reg_state, instrs, block_idx)?;
        let value_type = match mem.size {
            1 => SsaType::U8,
            2 => SsaType::U16,
            4 => SsaType::I32,
            size => {
                return Err(Error::X86Error(format!(
                    "a {size}-byte memory operand is not modelled"
                )))
            }
        };
        let access = AccessQualifiers {
            address_space: address_space_for(mem),
            ..AccessQualifiers::FLAT
        };
        Ok(self.emit(instrs, block_idx, |dest| SsaOp::LoadIndirect {
            dest,
            addr,
            value_type,
            access,
        }))
    }

    /// Stores to a memory operand: a narrow one takes the value's low bits.
    fn store_to_memory(
        &mut self,
        mem: &X86Memory,
        value: SsaVarId,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        let addr = self.compute_memory_address(mem, reg_state, instrs, block_idx)?;
        let value_type = match mem.size {
            1 => SsaType::I8,
            2 => SsaType::I16,
            4 => SsaType::I32,
            size => {
                return Err(Error::X86Error(format!(
                    "a {size}-byte memory operand is not modelled"
                )))
            }
        };
        instrs.push(SsaInstruction::synthetic(SsaOp::StoreIndirect {
            addr,
            value,
            value_type,
            access: AccessQualifiers {
                address_space: address_space_for(mem),
                ..AccessQualifiers::FLAT
            },
        }));
        Ok(())
    }

    /// Computes the effective address for a memory operand: base, index times
    /// scale and displacement, from 32-bit registers.
    fn compute_memory_address(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        // 16-bit addressing wraps at 64K, which a 32-bit sum does not
        for reg in [mem.base, mem.index].into_iter().flatten() {
            if sub_register(reg).is_some() {
                return Err(Error::X86Error(format!(
                    "16-bit addressing through {reg:?} is not modelled"
                )));
            }
        }

        // Start with base or 0
        let mut addr = if let Some(base) = mem.base {
            Self::get_register_value(base, reg_state)?
        } else {
            self.get_zero_constant(instrs, block_idx)
        };

        // Add index * scale
        if let Some(index) = mem.index {
            let index_val = Self::get_register_value(index, reg_state)?;
            let scaled = if mem.scale == 1 {
                index_val
            } else {
                let scale_const = self.get_constant(i64::from(mem.scale), instrs, block_idx);
                self.emit(instrs, block_idx, |dest| SsaOp::Mul {
                    dest,
                    left: index_val,
                    right: scale_const,
                    flags: None,
                })
            };
            let base = addr;
            addr = self.emit(instrs, block_idx, |dest| SsaOp::Add {
                dest,
                left: base,
                right: scaled,
                flags: None,
            });
        }

        // Add displacement
        if mem.displacement != 0 {
            let disp_const = self.get_constant(mem.displacement, instrs, block_idx);
            let base = addr;
            addr = self.emit(instrs, block_idx, |dest| SsaOp::Add {
                dest,
                left: base,
                right: disp_const,
                flags: None,
            });
        }

        Ok(addr)
    }

    /// Emits the 32-bit constant `value` (its low 32 bits) and returns its
    /// variable.
    fn get_constant(
        &mut self,
        value: i64,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        // Safe: an x86 32-bit constant is its low 32 bits
        #[allow(clippy::cast_possible_truncation)]
        let truncated = value as i32;
        self.emit(instrs, block_idx, |dest| SsaOp::Const {
            dest,
            value: ConstValue::I32(truncated),
        })
    }

    /// The zero constant of block `block_idx`, emitted the first time the block
    /// needs it.
    fn get_zero_constant(
        &mut self,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        if let Some((block, zero)) = self.zero_const {
            if block == block_idx {
                return zero;
            }
        }
        let zero = self.get_constant(0, instrs, block_idx);
        self.zero_const = Some((block_idx, zero));
        zero
    }

    /// Emits the operation `op` builds for a new 32-bit variable, and returns the
    /// variable.
    fn emit(
        &mut self,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
        op: impl FnOnce(SsaVarId) -> SsaOp,
    ) -> SsaVarId {
        self.emit_typed(SsaType::I32, instrs, block_idx, op)
    }

    /// Emits the operation `op` builds for a new variable of type `ty`, and
    /// returns the variable.
    fn emit_typed(
        &mut self,
        ty: SsaType,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
        op: impl FnOnce(SsaVarId) -> SsaOp,
    ) -> SsaVarId {
        let dest = self.create_typed_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            ty,
        );
        instrs.push(SsaInstruction::synthetic(op(dest)));
        dest
    }

    /// Creates a new 32-bit SSA variable using the local allocator.
    fn create_variable(&mut self, origin: VariableOrigin, def_site: DefSite) -> SsaVarId {
        self.create_typed_variable(origin, def_site, SsaType::I32)
    }

    /// Creates a new SSA variable of type `ty` using the local allocator.
    fn create_typed_variable(
        &mut self,
        origin: VariableOrigin,
        def_site: DefSite,
        ty: SsaType,
    ) -> SsaVarId {
        let id = SsaVarId::from_index(self.variables.len());
        let var = SsaVariable::new(id, origin, 0, def_site, ty);
        self.variables.push(var);
        id
    }

    /// The block starting at `offset`.
    fn block_at_offset(&self, offset: u64) -> Result<usize> {
        self.block_by_offset.get(&offset).copied().ok_or_else(|| {
            Error::X86Error(format!(
                "No block starts at offset 0x{offset:x}: control falls off the decoded code"
            ))
        })
    }

    /// Finds the block index for a given absolute address.
    fn find_block_for_address(&self, addr: u64) -> Result<usize> {
        let offset = addr.checked_sub(self.func.base_address).ok_or_else(|| {
            Error::X86Error(format!(
                "Address 0x{addr:x} is below base 0x{:x}",
                self.func.base_address
            ))
        })?;
        self.block_at_offset(offset)
    }
}

/// The direction and fill of a shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shift {
    /// `SHL`: toward the top bit, filling with zeros.
    Left,
    /// `SHR`: toward bit 0, filling with zeros.
    Right,
    /// `SAR`: toward bit 0, filling with the sign bit.
    Arithmetic,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{
            x86::decoder::{x86_decode_all, x86_decode_traversal},
            CilTarget, SsaEvaluator,
        },
        compiler::SsaCodeGenerator,
    };

    /// What the 32-bit function `bytes` returns for the argument `input`, run by the SSA
    /// evaluator through every block it takes, or the error translating it.
    fn run(bytes: &[u8], input: i32) -> std::result::Result<i32, String> {
        let instructions = x86_decode_all(bytes, 32, 0).map_err(|e| e.to_string())?;
        run_function(&X86Function::new(&instructions, 32, 0), input)
    }

    /// What the function `cfg` returns for the argument `input`, run by the SSA evaluator,
    /// or the error translating it.
    fn run_function(cfg: &X86Function, input: i32) -> std::result::Result<i32, String> {
        let ssa = X86ToSsaTranslator::new(cfg)
            .translate()
            .map_err(|e| e.to_string())?;
        let arg = ssa.argument_variables().next().expect("the argument").id();
        let mut eval = SsaEvaluator::new(&ssa, CilTarget::x86().machine());
        eval.set_concrete(arg, ConstValue::I32(input));
        let trace = eval.execute(0, None, 1000);
        assert!(trace.is_complete(), "evaluation did not complete");
        let last = *trace.blocks().last().expect("a block ran");
        let returned = ssa
            .block(last)
            .and_then(|block| {
                block
                    .instructions()
                    .iter()
                    .find_map(|instr| match instr.op() {
                        SsaOp::Return {
                            value: Some(value), ..
                        } => Some(*value),
                        _ => None,
                    })
            })
            .expect("the last block returns a value");
        let value = eval.get_concrete(returned);
        value
            .and_then(|value| value.as_i32())
            .ok_or_else(|| format!("the function returns {value:?}, not a concrete int32"))
    }

    /// `pop eax` then `body` then `ret`.
    fn function(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x58];
        bytes.extend_from_slice(body);
        bytes.push(0xC3);
        bytes
    }

    /// `mov reg32, imm32`, the register numbered `reg` (0 = EAX, 1 = ECX, ...).
    fn mov_imm(reg: u8, value: i32) -> Vec<u8> {
        let mut bytes = vec![0xB8 + reg];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    /// The arithmetic flags of an x86 instruction, as the Intel manual defines them.
    #[derive(Debug, Clone, Copy)]
    struct Flags {
        cf: bool,
        zf: bool,
        sf: bool,
        of: bool,
        pf: bool,
    }

    impl Flags {
        /// ZF, SF and PF of `result`, with `cf` and `of`.
        fn of_result(result: i32, cf: bool, of: bool) -> Self {
            Self {
                cf,
                zf: result == 0,
                sf: result < 0,
                of,
                pf: (result as u8).count_ones().is_multiple_of(2),
            }
        }

        /// Whether condition code `cc` (0 = O ... 15 = G) holds.
        fn holds(self, cc: u8) -> bool {
            let less = self.sf != self.of;
            let base = match cc >> 1 {
                0 => self.of,
                1 => self.cf,
                2 => self.zf,
                3 => self.cf || self.zf,
                4 => self.sf,
                5 => self.pf,
                6 => less,
                _ => self.zf || less,
            };
            base ^ (cc & 1 == 1)
        }
    }

    /// The edge values the condition tests run every producer over.
    const EDGES: [i32; 9] = [0, 1, -1, 2, 0x7F, 0x80, i32::MAX, i32::MIN, 0x1234_5678];

    /// Every condition after every flag-setting producer the translation models, run by the
    /// SSA evaluator, gives what the processor gives: `pop eax; xor edx, edx; mov ecx, b;
    /// <op>; setcc dl; mov eax, edx; ret`. The producers before covered a few conditions each
    /// and lowered the rest wrongly: JE after ADD compared the sum with itself, and L, B
    /// and their kin after ADD, AND or a shift compared the operands, which is CMP's
    /// meaning alone.
    #[test]
    fn every_condition_after_every_producer_is_the_processors() {
        // (name, encoding, reference result flags)
        type Reference = fn(i32, i32) -> Flags;
        let producers: [(&str, &[u8], Reference); 10] = [
            ("add", &[0x01, 0xC8], |a, b| {
                let (r, of) = a.overflowing_add(b);
                Flags::of_result(r, (a as u32).overflowing_add(b as u32).1, of)
            }),
            ("sub", &[0x29, 0xC8], |a, b| {
                let (r, of) = a.overflowing_sub(b);
                Flags::of_result(r, (a as u32) < (b as u32), of)
            }),
            ("cmp", &[0x39, 0xC8], |a, b| {
                let (r, of) = a.overflowing_sub(b);
                Flags::of_result(r, (a as u32) < (b as u32), of)
            }),
            ("and", &[0x21, 0xC8], |a, b| {
                Flags::of_result(a & b, false, false)
            }),
            ("or", &[0x09, 0xC8], |a, b| {
                Flags::of_result(a | b, false, false)
            }),
            ("xor", &[0x31, 0xC8], |a, b| {
                Flags::of_result(a ^ b, false, false)
            }),
            ("test", &[0x85, 0xC8], |a, b| {
                Flags::of_result(a & b, false, false)
            }),
            // INC and DEC keep CF, which `xor edx, edx` cleared
            ("inc", &[0x40], |a, _| {
                let (r, of) = a.overflowing_add(1);
                Flags::of_result(r, false, of)
            }),
            ("dec", &[0x48], |a, _| {
                let (r, of) = a.overflowing_sub(1);
                Flags::of_result(r, false, of)
            }),
            ("neg", &[0xF7, 0xD8], |a, _| {
                let (r, of) = a.overflowing_neg();
                Flags::of_result(r, a != 0, of)
            }),
        ];
        for (name, op, reference) in producers {
            for cc in 0u8..16 {
                for b in EDGES {
                    let mut body = vec![0x31, 0xD2];
                    body.extend(mov_imm(1, b));
                    body.extend_from_slice(op);
                    body.extend_from_slice(&[0x0F, 0x90 + cc, 0xC2, 0x89, 0xD0]);
                    let bytes = function(&body);
                    for a in EDGES {
                        let expected = i32::from(reference(a, b).holds(cc));
                        assert_eq!(
                            run(&bytes, a),
                            Ok(expected),
                            "{name} {a:#x}, {b:#x} then condition {cc:#x}"
                        );
                    }
                }
            }
        }
    }

    /// A conditional jump after an addition branches on the sum: `add eax, 1; je` is
    /// taken for -1 alone. It compared the sum with itself, so it was always taken, and
    /// its not-taken edge went to whichever block came next in index order.
    #[test]
    fn a_jump_after_an_addition_tests_the_sum() {
        // add eax, 1; je +6; mov eax, 7; ret; mov eax, 9
        let mut body = vec![0x83, 0xC0, 0x01, 0x74, 0x06];
        body.extend(mov_imm(0, 7));
        body.push(0xC3);
        body.extend(mov_imm(0, 9));
        let bytes = function(&body);
        assert_eq!(run(&bytes, -1), Ok(9));
        assert_eq!(run(&bytes, 5), Ok(7));
    }

    /// Instructions that do not touch the flags leave them for the jump after: `cmp`,
    /// then a `mov`, `lea`, `push` and `pop`, then `jl`. Each of them cleared the flags,
    /// and the jump was refused.
    #[test]
    fn flags_survive_the_instructions_that_do_not_touch_them() {
        // cmp eax, 10; mov ecx, 5; lea edx, [ecx+1]; push ecx; pop ecx; jl +6;
        // mov eax, 1; ret; mov eax, 2
        let mut body = vec![0x83, 0xF8, 0x0A];
        body.extend(mov_imm(1, 5));
        body.extend_from_slice(&[0x8D, 0x51, 0x01, 0x51, 0x59, 0x7C, 0x06]);
        body.extend(mov_imm(0, 1));
        body.push(0xC3);
        body.extend(mov_imm(0, 2));
        let bytes = function(&body);
        for a in EDGES {
            assert_eq!(run(&bytes, a), Ok(if a < 10 { 2 } else { 1 }), "{a:#x}");
        }
    }

    /// A block that ends without a jump falls through to the block after it, and is
    /// given that jump: `jl` skips the `mov` it would otherwise run into.
    #[test]
    fn a_block_without_a_jump_falls_through() {
        // cmp eax, 5; jl +5; mov eax, 1; add eax, 2
        let mut body = vec![0x83, 0xF8, 0x05, 0x7C, 0x05];
        body.extend(mov_imm(0, 1));
        body.extend_from_slice(&[0x83, 0xC0, 0x02]);
        let bytes = function(&body);
        assert_eq!(run(&bytes, 3), Ok(5));
        assert_eq!(run(&bytes, 7), Ok(3));
    }

    /// The zero a block needs is its own. One constant shared by the function was
    /// defined in the first block that asked (here the AND's, for its cleared carry),
    /// and read in blocks that block does not dominate (the SETE's, comparing the TEST's
    /// result with zero): on the path through the other block it held nothing.
    #[test]
    fn each_block_has_its_own_zero() {
        // cmp eax, 5; je +5; and eax, 1; jmp +5; test eax, eax; sete al
        let body = [
            0x83, 0xF8, 0x05, 0x74, 0x05, 0x83, 0xE0, 0x01, 0xEB, 0x05, 0x85, 0xC0, 0x0F, 0x94,
            0xC0,
        ];
        let bytes = function(&body);
        // 5 is not zero, so SETE writes 0 into AL
        assert_eq!(run(&bytes, 5), Ok(0));
        assert_eq!(run(&bytes, 7), Ok(1));
    }

    /// An 8- or 16-bit register is its bits of the full register: `mov cl, al` changes
    /// the low byte of ECX alone, `mov ch, al` the byte above it, `movsx` and `movzx`
    /// extend what they read, and CWDE and CDQ extend the sign. Every one of these
    /// read or replaced the whole register.
    #[test]
    fn sub_registers_are_their_bits_of_the_full_register() {
        let base = 0x1234_5678;
        // mov ecx, base; mov cl, al; mov eax, ecx
        let mut low = mov_imm(1, base);
        low.extend_from_slice(&[0x88, 0xC1, 0x89, 0xC8]);
        // mov ecx, base; mov ch, al; mov eax, ecx
        let mut high = mov_imm(1, base);
        high.extend_from_slice(&[0x88, 0xC5, 0x89, 0xC8]);
        for a in EDGES {
            let byte = a & 0xFF;
            assert_eq!(run(&function(&low), a), Ok((base & !0xFF) | byte), "{a:#x}");
            assert_eq!(
                run(&function(&high), a),
                Ok((base & !0xFF00) | (byte << 8)),
                "{a:#x}"
            );
            // movsx eax, al
            assert_eq!(
                run(&function(&[0x0F, 0xBE, 0xC0]), a),
                Ok(i32::from(a as i8))
            );
            // movzx eax, ax
            assert_eq!(run(&function(&[0x0F, 0xB7, 0xC0]), a), Ok(a & 0xFFFF));
            // cwde
            assert_eq!(run(&function(&[0x98]), a), Ok(i32::from(a as i16)));
            // cdq; mov eax, edx
            assert_eq!(run(&function(&[0x99, 0x89, 0xD0]), a), Ok(a >> 31));
            // add al, 1: a carry out of the byte stays out of the rest
            assert_eq!(
                run(&function(&[0x04, 0x01]), a),
                Ok((a & !0xFF) | (a.wrapping_add(1) & 0xFF)),
                "{a:#x}"
            );
        }
    }

    /// MUL leaves the high half of the product in EDX, and DIV and IDIV divide EDX:EAX:
    /// both were computed from EAX alone.
    #[test]
    fn multiplication_and_division_use_both_halves() {
        // mov ecx, 0x10000; mul ecx; mov eax, edx
        let mut mul = mov_imm(1, 0x10000);
        mul.extend_from_slice(&[0xF7, 0xE1, 0x89, 0xD0]);
        // mov edx, 1; mov ecx, 16; div ecx
        let mut div = mov_imm(2, 1);
        div.extend(mov_imm(1, 16));
        div.extend_from_slice(&[0xF7, 0xF1]);
        // cdq; mov ecx, -3; idiv ecx; mov eax, edx
        let mut idiv = vec![0x99];
        idiv.extend(mov_imm(1, -3));
        idiv.extend_from_slice(&[0xF7, 0xF9, 0x89, 0xD0]);
        for a in EDGES {
            let ua = u64::from(a as u32);
            assert_eq!(run(&function(&mul), a), Ok((ua >> 16) as i32), "{a:#x}");
            assert_eq!(
                run(&function(&div), a),
                Ok((((1u64 << 32) | ua) / 16) as i32),
                "{a:#x}"
            );
            if a != i32::MIN {
                assert_eq!(run(&function(&idiv), a), Ok(a % -3), "{a:#x}");
            }
        }
    }

    /// Shifts mask their count to five bits, set CF to the last bit shifted out, and
    /// rotate as rotates: a count of 33 shifts by one, `shr` then `setb` reads bit 0, and
    /// `rol` moves the top bits around. A rotate kept its value unchanged, and a shift's
    /// CF stayed what the instruction before left.
    #[test]
    fn shifts_and_rotates_are_the_processors() {
        for a in EDGES {
            let ua = a as u32;
            // mov ecx, 33; shl eax, cl
            let mut shl = mov_imm(1, 33);
            shl.extend_from_slice(&[0xD3, 0xE0]);
            assert_eq!(run(&function(&shl), a), Ok(a.wrapping_shl(1)), "{a:#x}");
            // xor edx, edx; shr eax, 1; setb dl; mov eax, edx
            let shr = [0x31, 0xD2, 0xD1, 0xE8, 0x0F, 0x92, 0xC2, 0x89, 0xD0];
            assert_eq!(run(&function(&shr), a), Ok(a & 1), "{a:#x}");
            // sar eax, 4
            assert_eq!(run(&function(&[0xC1, 0xF8, 0x04]), a), Ok(a >> 4));
            // rol eax, 8
            assert_eq!(
                run(&function(&[0xC1, 0xC0, 0x08]), a),
                Ok(ua.rotate_left(8) as i32)
            );
            // ror eax, 3
            assert_eq!(
                run(&function(&[0xC1, 0xC8, 0x03]), a),
                Ok(ua.rotate_right(3) as i32)
            );
            // xor edx, edx; bt eax, 3; setb dl; mov eax, edx
            let bt = [
                0x31, 0xD2, 0x0F, 0xBA, 0xE0, 0x03, 0x0F, 0x92, 0xC2, 0x89, 0xD0,
            ];
            assert_eq!(run(&function(&bt), a), Ok((a >> 3) & 1), "{a:#x}");
            // xadd eax, eax: the sum, written after the old value
            assert_eq!(
                run(&function(&[0x0F, 0xC1, 0xC0]), a),
                Ok(a.wrapping_add(a)),
                "{a:#x}"
            );
        }
    }

    /// What the translation does not model exactly it refuses, so the caller keeps the
    /// native stub: a bit scan (whose result was its source), an ADC whose carry is not
    /// known (which read it as 0), a pop with nothing pushed (which read a value no
    /// instruction wrote), the one-operand IMUL (which wrote EAX alone) and 64-bit code.
    #[test]
    fn what_is_not_modelled_is_refused() {
        // bsf eax, eax
        assert!(run(&function(&[0x0F, 0xBC, 0xC0]), 1).is_err());
        // adc eax, 1
        assert!(run(&function(&[0x83, 0xD0, 0x01]), 1).is_err());
        // pop ecx; mov eax, ecx: what the caller's frame held is read. Popped and not
        // read, as an epilogue restores a saved register, it is no reason to refuse
        assert!(run(&function(&[0x59, 0x89, 0xC8]), 1).is_err());
        assert_eq!(run(&function(&[0x59]), 1), Ok(1));
        // mov ecx, 3; imul ecx
        let mut imul = mov_imm(1, 3);
        imul.extend_from_slice(&[0xF7, 0xE9]);
        assert!(run(&function(&imul), 1).is_err());

        let instructions = x86_decode_all(&[0x58, 0xC3], 64, 0).unwrap();
        let cfg = X86Function::new(&instructions, 64, 0);
        assert!(X86ToSsaTranslator::new(&cfg).translate().is_err());
    }

    /// A function is entered where its entry is, not at its lowest address: a traversal
    /// decode entered at `pop eax; jmp 0` returns the code at 0 first, by address, and
    /// built from the first instruction the function began with `add eax, 5` reading an
    /// EAX nothing wrote.
    #[test]
    fn a_function_is_entered_at_its_entry() {
        // 0: add eax, 5; 3: ret; 4: pop eax; 5: jmp 0
        let bytes = [0x83, 0xC0, 0x05, 0xC3, 0x58, 0xEB, 0xF9];
        let decoded = x86_decode_traversal(&bytes, 32, 0, 4).unwrap();
        let cfg = X86Function::with_entry(&decoded.instructions, 32, 0, 4);
        assert_eq!(cfg.block(0).map(|block| block.start_offset), Some(4));
        for a in EDGES {
            assert_eq!(run_function(&cfg, a), Ok(a.wrapping_add(5)), "{a:#x}");
        }
    }

    /// Instructions the decoder approximated by others decode as unsupported, and their
    /// functions are refused: BTS, BTR and BTC (as BT, which leaves the bit), CBW (as
    /// CWDE, which extends AX instead of AL) and CWD (as CDQ, which fills EDX instead of
    /// DX). The linear decode keeps them as unsupported instead of failing as a whole.
    #[test]
    fn approximated_instructions_are_refused() {
        // bts eax, 3; btr eax, 3; btc eax, 3; cbw; cwd
        for body in [
            &[0x0F, 0xBA, 0xE8, 0x03][..],
            &[0x0F, 0xBA, 0xF0, 0x03],
            &[0x0F, 0xBA, 0xF8, 0x03],
            &[0x66, 0x98],
            &[0x66, 0x99],
        ] {
            let bytes = function(body);
            let decoded = x86_decode_all(&bytes, 32, 0).expect("the decode stays whole");
            assert!(
                decoded
                    .iter()
                    .any(|instr| matches!(instr.instruction, X86Instruction::Unsupported { .. })),
                "{body:02x?}"
            );
            assert!(run(&bytes, 1).is_err(), "{body:02x?}");
        }
    }

    /// `fs:`/`gs:` become distinct address spaces; every other segment stays in
    /// the flat default. Marking `ss:`/`ds:` would let alias analysis prove two
    /// names for one cell disjoint, which is the unsound direction.
    #[test]
    fn test_address_space_for_segment() {
        let flat = X86Memory::base_disp(X86Register::Ebp, -4, 4);
        assert_eq!(address_space_for(&flat), None);
        assert_eq!(
            address_space_for(&flat.clone().with_segment(X86Register::Fs)),
            Some(ADDRESS_SPACE_FS)
        );
        assert_eq!(
            address_space_for(&flat.clone().with_segment(X86Register::Gs)),
            Some(ADDRESS_SPACE_GS)
        );
        for flat_segment in [
            X86Register::Cs,
            X86Register::Ds,
            X86Register::Es,
            X86Register::Ss,
        ] {
            assert_eq!(
                address_space_for(&flat.clone().with_segment(flat_segment)),
                None,
                "{flat_segment:?} shares the flat address space"
            );
        }
        assert_ne!(ADDRESS_SPACE_FS, ADDRESS_SPACE_GS);
    }

    /// The segment override must reach the emitted `LoadIndirect`, not just the
    /// decoded operand.
    #[test]
    fn test_translate_segment_qualified_load() {
        // mov eax, fs:[0x30]; ret
        let bytes = [0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0xc3];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);
        let ssa = X86ToSsaTranslator::new(&cfg).translate().unwrap();

        let spaces: Vec<Option<NonZeroU16>> = ssa
            .iter_instructions()
            .filter_map(|(_, _, instr)| match instr.op() {
                SsaOp::LoadIndirect { access: space, .. } => Some(space.address_space),
                _ => None,
            })
            .collect();
        assert_eq!(spaces, vec![Some(ADDRESS_SPACE_FS)]);
    }

    #[test]
    fn test_translate_linear_code() {
        // pop eax; add eax, 5; ret
        let bytes = [0x58, 0x83, 0xc0, 0x05, 0xc3];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block
        assert_eq!(ssa.block_count(), 1);

        // Should have instructions
        let block = ssa.block(0).unwrap();
        assert!(!block.instructions().is_empty());

        // Should end with return
        let last_instr = block.instructions().last().unwrap();
        assert!(matches!(last_instr.op(), SsaOp::Return { .. }));
    }

    /// Verifies that all x86 SSA variables use `Phi` origin, not `Local`.
    ///
    /// This is critical: the codegen coalescer treats `Local(n)` variables as
    /// fixed CIL local slots. If x86 variables used `Local(0)`, they'd all
    /// map to the same CIL local, producing corrupt code.
    #[test]
    fn test_variables_use_phi_origin() {
        // pop eax; xor eax, 0x1234; add eax, 5; ret
        let bytes = [
            0x58, // pop eax
            0x35, 0x34, 0x12, 0x00, 0x00, // xor eax, 0x1234
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);
        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        let mut has_argument = false;
        for var in ssa.variables() {
            match var.origin() {
                VariableOrigin::Argument(0) => has_argument = true,
                VariableOrigin::Phi => {}
                other => panic!(
                    "x86 variable {:?} has origin {:?}, expected Argument(0) or Phi",
                    var.id(),
                    other
                ),
            }
        }
        // The x86 function takes one argument (the input value)
        assert!(has_argument, "No argument variable found in x86 SSA");
        // Non-argument variables must use Phi origin so the codegen
        // coalescer allocates separate CIL locals (not all sharing local 0)
        assert!(
            ssa.variable_count() > 1,
            "Should have more than just the argument variable"
        );
    }

    /// Verifies that variable IDs are dense (0..N) and consistent with instructions.
    #[test]
    fn test_variable_ids_are_dense() {
        // pop eax; xor eax, 0xAB; not eax; ret
        let bytes = [
            0x58, // pop eax
            0x35, 0xAB, 0x00, 0x00, 0x00, // xor eax, 0xAB
            0xf7, 0xd0, // not eax
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);
        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Variable IDs should be 0..N with no gaps
        let var_count = ssa.variable_count();
        assert!(var_count > 0);
        for (i, var) in ssa.variables().iter().enumerate() {
            assert_eq!(
                var.id().index(),
                i,
                "Variable at position {} has id {:?}",
                i,
                var.id()
            );
        }

        // All variable IDs referenced by instructions should be valid
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let Some(def) = instr.def() {
                    assert!(
                        def.index() < var_count,
                        "Instruction def {:?} exceeds variable count {}",
                        def,
                        var_count
                    );
                }
                for &use_var in &instr.uses() {
                    assert!(
                        use_var.index() < var_count,
                        "Instruction use {:?} exceeds variable count {}",
                        use_var,
                        var_count
                    );
                }
            }
        }
    }

    /// Tests that x86 SSA can be compiled to CIL via codegen without errors.
    ///
    /// This is the critical x86 → SSA → CIL pipeline used for native method
    /// conversion in ConfuserEx x86 cipher deobfuscation.
    #[test]
    fn test_x86_ssa_codegen_roundtrip() {
        // pop eax; xor eax, 0x1234; add eax, 5; ret
        let bytes = [
            0x58, // pop eax
            0x35, 0x34, 0x12, 0x00, 0x00, // xor eax, 0x1234
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);
        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        let mut codegen = SsaCodeGenerator::new();
        let result = codegen.generate(&ssa);
        assert!(
            result.is_ok(),
            "Codegen failed for x86 SSA: {:?}",
            result.err()
        );

        let (bytecode, max_stack, num_locals) = result.unwrap();
        assert!(!bytecode.is_empty(), "Codegen produced empty bytecode");
        assert!(max_stack > 0, "Codegen produced zero max_stack");
        // All variables should get separate local slots (not all mapped to local 0)
        assert!(
            num_locals > 1,
            "Codegen allocated only {} local(s) — variables may be incorrectly sharing slot 0",
            num_locals
        );
    }

    #[test]
    fn test_translate_with_constant() {
        // mov eax, 0x12345678; ret
        let bytes = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert_eq!(ssa.block_count(), 1);
    }

    #[test]
    fn test_translate_arithmetic() {
        // pop eax; xor eax, 0x1234; add eax, 5; sub eax, 2; ret
        let bytes = [
            0x58, // pop eax
            0x35, 0x34, 0x12, 0x00, 0x00, // xor eax, 0x1234
            0x83, 0xc0, 0x05, // add eax, 5
            0x83, 0xe8, 0x02, // sub eax, 2
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with multiple operations
        let block = ssa.block(0).unwrap();
        let ops: Vec<_> = block.instructions().iter().map(|i| i.op()).collect();

        // Should have Xor, Add, Sub operations
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Xor { .. })));
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Add { .. })));
        assert!(ops.iter().any(|op| matches!(op, SsaOp::Sub { .. })));
    }

    #[test]
    fn test_translate_conditional() {
        // pop eax; cmp eax, 10; jl add_block; jmp skip
        // add_block: add eax, 5
        // skip: ret
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x7c, 0x02, // jl +2 (to add)
            0xeb, 0x03, // jmp +3 (to ret)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have multiple blocks
        assert!(ssa.block_count() > 1);

        // First block should have a BranchCmp
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    /// A register defined before a diamond and read after it, with neither
    /// arm writing it, reads the value from before the diamond: no phi is
    /// placed for it, and the join is not entered with nothing.
    #[test]
    fn a_register_written_before_a_diamond_is_read_after_it() {
        let bytes = [
            0x58, // pop eax
            0x8b, 0xc8, // mov ecx, eax
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x7c, 0x05, // jl +5 (to the second arm)
            0x83, 0xc0, 0x01, // add eax, 1
            0xeb, 0x03, // jmp +3 (to the join)
            0x83, 0xc0, 0x02, // add eax, 2
            0x01, 0xc8, // add eax, ecx
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);
        let ssa = X86ToSsaTranslator::new(&cfg)
            .translate()
            .expect("the diamond translates");
        assert_eq!(ssa.block_count(), 4);
    }

    /// A register read before anything writes it is refused, whether no path
    /// writes it or only some do: these stubs are entered with nothing in
    /// their registers.
    #[test]
    fn a_register_read_before_any_write_is_refused() {
        let translate = |bytes: &[u8]| {
            let instructions = x86_decode_all(bytes, 32, 0x1000).unwrap();
            let cfg = X86Function::new(&instructions, 32, 0x1000);
            X86ToSsaTranslator::new(&cfg).translate()
        };
        // add eax, 5; ret
        assert!(
            translate(&[0x83, 0xc0, 0x05, 0xc3]).is_err(),
            "on every path"
        );
        let one_path = [
            0x59, // pop ecx
            0x85, 0xc9, // test ecx, ecx
            0x74, 0x05, // jz +5 (to the join)
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xc0, 0x02, // add eax, 2
            0xc3, // ret
        ];
        assert!(
            translate(&one_path).is_err(),
            "on the path that skips the write"
        );
    }

    #[test]
    fn test_register_state() {
        let mut state = RegisterState::new();

        let v1 = SsaVarId::from_index(0);
        state.set(X86Register::Eax, v1);
        assert_eq!(state.get(X86Register::Eax), Some(v1));

        // Different size registers map to same base
        assert_eq!(state.get(X86Register::Al), Some(v1));
        assert_eq!(state.get(X86Register::Ax), Some(v1));
    }

    #[test]
    fn test_empty_function() {
        let cfg = X86Function::new(&[], 32, 0);
        let translator = X86ToSsaTranslator::new(&cfg);
        let result = translator.translate();
        assert!(result.is_err());
    }

    #[test]
    fn test_translate_js_after_cmp() {
        // pop eax; cmp eax, 0; js +2; nop; nop; nop; ret
        // JS (0x78) jumps if SF=1 (result is negative)
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x78, 0x03, // js +3 (skip 3 nops to ret)
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should compile and produce multiple blocks with BranchCmp
        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jns_after_test() {
        // pop eax; test eax, eax; jns +3; nop; nop; nop; ret
        // JNS (0x79) jumps if SF=0 (non-negative)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x79, 0x03, // jns +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jo_after_cmp() {
        // pop eax; cmp eax, 0x7FFFFFFF; jo +3; nop; nop; nop; ret
        // JO (0x70) jumps if OF=1 (signed overflow)
        let bytes = [
            0x58, // pop eax
            0x3d, 0xff, 0xff, 0xff, 0x7f, // cmp eax, 0x7FFFFFFF
            0x70, 0x03, // jo +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jno_after_test() {
        // pop eax; test eax, eax; jno +3; nop; nop; nop; ret
        // JNO (0x71) jumps if OF=0 — always taken after TEST (TEST clears OF)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x71, 0x03, // jno +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_jp_after_cmp() {
        // pop eax; cmp eax, 0; jp +3; nop; nop; nop; ret
        // JP (0x7A) jumps if PF=1 (even parity of low byte)
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x7a, 0x03, // jp +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
        let first_block = ssa.block(0).unwrap();
        let has_branch = first_block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::BranchCmp { .. }));
        assert!(has_branch);
    }

    #[test]
    fn test_translate_jnp_after_test() {
        // pop eax; test eax, eax; jnp +3; nop; nop; nop; ret
        // JNP (0x7B) jumps if PF=0 (odd parity)
        let bytes = [
            0x58, // pop eax
            0x85, 0xc0, // test eax, eax
            0x7b, 0x03, // jnp +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_js_after_sub() {
        // pop eax; sub eax, 1; js +3; nop; nop; nop; ret
        // JS after SUB: jump if result is negative
        let bytes = [
            0x58, // pop eax
            0x83, 0xe8, 0x01, // sub eax, 1
            0x78, 0x03, // js +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_jo_after_add() {
        // pop eax; add eax, 0x7FFFFFFF; jo +3; nop; nop; nop; ret
        // JO after ADD: signed overflow detection
        let bytes = [
            0x58, // pop eax
            0x05, 0xff, 0xff, 0xff, 0x7f, // add eax, 0x7FFFFFFF
            0x70, 0x03, // jo +3
            0x90, // nop
            0x90, // nop
            0x90, // nop
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        assert!(ssa.block_count() > 1);
    }

    #[test]
    fn test_translate_cmovs_after_cmp() {
        // pop eax; mov ecx, 5; cmp eax, 0; cmovs eax, ecx; ret
        // CMOVS: conditional move if sign flag is set
        let bytes = [
            0x58, // pop eax
            0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x0f, 0x48, 0xc1, // cmovs eax, ecx
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with return
        let block = ssa.block(0).unwrap();
        let last = block.instructions().last().unwrap();
        assert!(matches!(last.op(), SsaOp::Return { .. }));

        // A negative argument moves ECX in; any other stays
        assert_eq!(run(&bytes, -3), Ok(5));
        assert_eq!(run(&bytes, 3), Ok(3));
    }

    #[test]
    fn test_translate_seto_after_cmp() {
        // pop eax; cmp eax, 0x7FFFFFFF; seto al; ret
        // SETO: set byte if overflow
        let bytes = [
            0x58, // pop eax
            0x3d, 0xff, 0xff, 0xff, 0x7f, // cmp eax, 0x7FFFFFFF
            0x0f, 0x90, 0xc0, // seto al
            0xc3, // ret
        ];
        let instructions = x86_decode_all(&bytes, 32, 0x1000).unwrap();
        let cfg = X86Function::new(&instructions, 32, 0x1000);

        let translator = X86ToSsaTranslator::new(&cfg);
        let ssa = translator.translate().unwrap();

        // Should have one block with return
        let block = ssa.block(0).unwrap();
        let last = block.instructions().last().unwrap();
        assert!(matches!(last.op(), SsaOp::Return { .. }));
    }
}

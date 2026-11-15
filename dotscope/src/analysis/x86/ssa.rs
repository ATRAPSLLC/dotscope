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

use std::collections::{BTreeMap, BTreeSet};

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
            flags::{ArithmeticKind, ConditionEval, FlagProducer, FlagState, FlagTestSource},
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
/// to analyssa — it only ever compares them for equality.
const ADDRESS_SPACE_GS: u16 = 256;

/// Address space id for `fs:`-qualified accesses. See [`ADDRESS_SPACE_GS`].
const ADDRESS_SPACE_FS: u16 = 257;

/// Maps a memory operand's segment override to an SSA address space.
///
/// Only `fs:` and `gs:` produce one. In flat 32-bit and 64-bit user mode the
/// remaining segments share a base with the unprefixed default, so reporting a
/// distinct address space for an explicit `ss:` or `ds:` would let alias
/// analysis prove two names for the *same* cell disjoint — the one direction
/// that is unsound. `fs:`/`gs:` genuinely have their own bases (TEB/PEB access,
/// stack cookies, TLS), which is exactly the distinction worth keeping.
fn address_space_for(mem: &X86Memory) -> Option<u16> {
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
pub struct X86ToSsaTranslator<'a> {
    /// The x86 function to translate.
    func: &'a X86Function,
    /// SSA variables created during translation.
    variables: Vec<SsaVariable>,
    /// Zero constant variable (lazily created).
    zero_const: Option<SsaVarId>,
}

impl<'a> X86ToSsaTranslator<'a> {
    /// Creates a new translator for the given x86 function.
    #[must_use]
    pub fn new(func: &'a X86Function) -> Self {
        Self {
            func,
            variables: Vec::new(),
            zero_const: None,
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
    /// - The function is empty
    /// - An unsupported instruction is encountered
    /// - A flag pattern cannot be translated
    /// - A register is read on some path before anything writes it
    pub fn translate(mut self) -> Result<SsaFunction> {
        if self.func.block_count() == 0 {
            return Err(Error::X86Error("Empty function".to_string()));
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
        let arg_var = self.create_variable(
            VariableOrigin::Argument(0),
            DefSite::entry(),
            self.func.bitness,
        );
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

        let word = if self.func.bitness == 64 {
            SsaType::I64
        } else {
            SsaType::I32
        };
        let recorded = record.construct(&mut ssa_func, |_| word.clone());
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
        if let Some(register) = Self::used_entry_register(&ssa_func, &entry_values) {
            return Err(Error::X86Error(format!(
                "Register index {register} is read before anything writes it"
            )));
        }

        // The finishing sequence, from the crate that owns it: stamp
        // instruction identities, refresh definition sites, prune what control
        // cannot reach, rebuild the use index, and drop the placeholders no
        // read needed. The use index matters most - a function handed on with
        // every use list empty tells a dead-code pass that nobody reads a live
        // definition.
        let options = SsaConstructOptions::default().verified_at(VerifyLevel::Standard);
        let report = ssa_func
            .finish_construction(&options)
            .map_err(|e| Error::SsaError(e.to_string()))?;

        // Reported rather than refused. A finding means this translation is
        // wrong, but the caller's fallback for a refusal is to keep the
        // original native stub, which is not better.
        for finding in &report.findings {
            log::warn!("x86 translation produced invalid SSA: {finding:?}");
        }

        Ok(ssa_func)
    }

    /// The register whose entry value the function uses, if any: read by an
    /// instruction, or merged by a phi whose result is used.
    fn used_entry_register(
        ssa: &SsaFunction,
        entry_values: &BTreeMap<SsaVarId, usize>,
    ) -> Option<usize> {
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
        used.iter()
            .find_map(|value| entry_values.get(value).copied())
    }

    /// Translates one block, entered with a placeholder for every register.
    ///
    /// Each placeholder is recorded as a read the block makes before writing,
    /// and what the block leaves in each register as its write; construction
    /// answers the placeholders afterwards. A placeholder nothing reads costs a
    /// variable that finishing drops.
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
            let placeholder =
                self.create_variable(VariableOrigin::Phi, DefSite::entry(), self.func.bitness);
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
                let seg_var =
                    self.create_variable(VariableOrigin::Phi, DefSite::entry(), self.func.bitness);
                reg_state.set(seg, seg_var);
            }
        }

        // Track flags for CMP/TEST + Jcc fusion
        let mut flags = FlagState::new();

        // The machine stack this block starts with. The entry block is entered
        // with the caller's argument on it, which is the calling convention
        // these stubs are built to; every other block starts with the stack
        // this translation can see nothing on, and a pop there says so.
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
    #[allow(clippy::too_many_arguments)]
    fn translate_instruction(
        &mut self,
        decoded: &X86DecodedInstruction,
        reg_state: &mut RegisterState,
        flags: &mut FlagState,
        stack: &mut Vec<SsaVarId>,
        block_idx: usize,
    ) -> Result<Vec<SsaInstruction>> {
        let mut result = Vec::new();

        match &decoded.instruction {
            // Data movement
            X86Instruction::Mov { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                flags.clear(); // MOV doesn't set flags
            }

            X86Instruction::Movzx { dst, src } | X86Instruction::Movsx { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // For SSA purposes, we treat zero/sign extension as a simple move
                // The type system will handle the extension semantics
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            X86Instruction::Lea { dst, src } => {
                // LEA computes an address without dereferencing
                let addr_var =
                    self.compute_memory_address(src, reg_state, &mut result, block_idx)?;
                reg_state.set(*dst, addr_var);
                flags.clear();
            }

            X86Instruction::Push { src } => {
                // The machine stack, as the values on it. A push is the only
                // thing that puts one there and a pop is the only thing that
                // takes one off, so the pair is what carries a value across a
                // save-and-restore - the shape every one of these stubs uses
                // around the computation it protects.
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                stack.push(src_var);
                flags.clear();
            }

            X86Instruction::Pop { dst } => {
                // A pop takes back what the matching push left. The entry
                // block's stack starts holding the caller's argument, which is
                // how that argument reaches the first pop, so no rule about
                // which pop is special is needed here.
                if let Some(var) = stack.pop() {
                    reg_state.set(*dst, var);
                } else {
                    // A pop with nothing pushed. The value comes from outside
                    // what this translation follows: a push in another block,
                    // or a frame the caller built. Named as the undefined value
                    // it is, and reported, because the code that reads it is
                    // then reading something this model never computed.
                    log::warn!(
                        "x86 translation: pop with an empty stack in block {block_idx}; \
                         the value it reads is not modelled"
                    );
                    let var = self.create_variable(
                        VariableOrigin::Phi,
                        DefSite::instruction(block_idx, result.len()),
                        self.func.bitness,
                    );
                    reg_state.set(*dst, var);
                }
                flags.clear();
            }

            X86Instruction::Xchg { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                self.set_operand_value(dst, src_var, reg_state, &mut result, block_idx)?;
                self.set_operand_value(src, dst_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            // Arithmetic
            X86Instruction::Add { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // CF = (result < left) unsigned — unsigned overflow detection
                let cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: res_var,
                    right: dst_var,
                    unsigned: true,
                    signaling: false,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Sub { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Sub);
                // CF = (left < right) unsigned — borrow detection
                let cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: dst_var,
                    right: src_var,
                    unsigned: true,
                    signaling: false,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Imul { dst, src, src2 } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let multiplier = if let Some(s2) = src2 {
                    self.get_operand_value(s2, reg_state, &mut result, block_idx)?
                } else {
                    // Two-operand form: dst = dst * src
                    Self::get_register_value(*dst, reg_state)?
                };
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: res_var,
                    left: src_var,
                    right: multiplier,
                    flags: None,
                }));
                reg_state.set(*dst, res_var);
                flags.set_arithmetic(res_var, src_var, multiplier, ArithmeticKind::Other);
            }

            X86Instruction::Mul { src } => {
                // MUL: EDX:EAX = EAX * src (unsigned)
                // For simplicity, we only track EAX result
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: res_var,
                    left: eax,
                    right: src_var,
                    flags: None,
                }));
                reg_state.set(X86Register::Eax, res_var);
                flags.set_arithmetic(res_var, eax, src_var, ArithmeticKind::Other);
            }

            X86Instruction::Neg { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Neg {
                    dest: res_var,
                    operand: dst_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic_unary(res_var);
                // NEG sets CF = (operand != 0)
                let zero = self.get_constant(0, &mut result, block_idx);
                let cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: cf,
                    left: dst_var,
                    right: zero,
                    signaling: false,
                }));
                // Ceq gives 1 if equal, but CF = (operand != 0), so we need NOT of Ceq
                // CF = 1 - Ceq(operand, 0)  or equivalently CF = Cgt(operand, 0, unsigned)
                // Actually simpler: Ceq gives us (operand == 0), we need (operand != 0)
                // We can XOR with 1 to flip it
                let one = self.get_constant(1, &mut result, block_idx);
                let neg_cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: neg_cf,
                    left: cf,
                    right: one,
                    flags: None,
                }));
                flags.set_carry(neg_cf);
            }

            X86Instruction::Inc { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let one = self.get_constant(1, &mut result, block_idx);
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: one,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // INC sets ZF/SF/OF but does NOT modify CF
                flags.set_arithmetic(res_var, dst_var, one, ArithmeticKind::Add);
            }

            X86Instruction::Dec { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let one = self.get_constant(1, &mut result, block_idx);
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: dst_var,
                    right: one,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // DEC sets ZF/SF/OF but does NOT modify CF
                flags.set_arithmetic(res_var, dst_var, one, ArithmeticKind::Sub);
            }

            // Add with carry: dest = dst + src + CF
            X86Instruction::Adc { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Get current carry flag (default to 0 if unknown)
                let cf_var = flags
                    .carry()
                    .unwrap_or_else(|| self.get_constant(0, &mut result, block_idx));
                // temp = dst + src
                let temp_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: temp_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                // result = temp + CF
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: temp_var,
                    right: cf_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // CF = (temp < dst) | (result < temp) — carry from either addition
                let cf1 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf1,
                    left: temp_var,
                    right: dst_var,
                    unsigned: true,
                    signaling: false,
                }));
                let cf2 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf2,
                    left: res_var,
                    right: temp_var,
                    unsigned: true,
                    signaling: false,
                }));
                let new_cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: new_cf,
                    left: cf1,
                    right: cf2,
                    flags: None,
                }));
                flags.set_carry(new_cf);
            }

            // Subtract with borrow: dest = dst - src - CF
            X86Instruction::Sbb { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Get current carry flag (default to 0 if unknown)
                let cf_var = flags
                    .carry()
                    .unwrap_or_else(|| self.get_constant(0, &mut result, block_idx));
                // temp = dst - src
                let temp_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: temp_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                // result = temp - CF
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: res_var,
                    left: temp_var,
                    right: cf_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Sub);
                // CF = (dst < src) | (temp < CF) — borrow from either subtraction
                let cf1 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf1,
                    left: dst_var,
                    right: src_var,
                    unsigned: true,
                    signaling: false,
                }));
                let cf2 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf2,
                    left: temp_var,
                    right: cf_var,
                    unsigned: true,
                    signaling: false,
                }));
                let new_cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: new_cf,
                    left: cf1,
                    right: cf2,
                    flags: None,
                }));
                flags.set_carry(new_cf);
            }

            // Unsigned division: EDX:EAX / src
            X86Instruction::Div { src } => {
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Quotient → EAX
                let quot_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Div {
                    dest: quot_var,
                    left: eax,
                    right: src_var,
                    unsigned: true,
                    flags: None,
                }));
                reg_state.set(X86Register::Eax, quot_var);
                // Remainder → EDX
                let rem_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Rem {
                    dest: rem_var,
                    left: eax,
                    right: src_var,
                    unsigned: true,
                    flags: None,
                }));
                reg_state.set(X86Register::Edx, rem_var);
                flags.set_arithmetic(quot_var, eax, src_var, ArithmeticKind::Other);
            }

            // Signed division: EDX:EAX / src
            X86Instruction::Idiv { src } => {
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Quotient → EAX
                let quot_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Div {
                    dest: quot_var,
                    left: eax,
                    right: src_var,
                    unsigned: false,
                    flags: None,
                }));
                reg_state.set(X86Register::Eax, quot_var);
                // Remainder → EDX
                let rem_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Rem {
                    dest: rem_var,
                    left: eax,
                    right: src_var,
                    unsigned: false,
                    flags: None,
                }));
                reg_state.set(X86Register::Edx, rem_var);
                flags.set_arithmetic(quot_var, eax, src_var, ArithmeticKind::Other);
            }

            // Byte swap: reverse byte order using shifts and masks
            X86Instruction::Bswap { dst } => {
                let val = Self::get_register_value(*dst, reg_state)?;
                // bswap(x) = ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00)
                //          | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000)
                // For simplicity, emit as a chain of shift/mask/or operations
                let c8 = self.get_constant(8, &mut result, block_idx);
                let c24 = self.get_constant(24, &mut result, block_idx);
                let mask_ff = self.get_constant(0xFF, &mut result, block_idx);
                let mask_ff00 = self.get_constant(0xFF00, &mut result, block_idx);
                let mask_ff0000 = self.get_constant(0x00FF_0000, &mut result, block_idx);
                let mask_ff000000 =
                    self.get_constant(i64::from(0xFF00_0000_u32 as i32), &mut result, block_idx);

                // byte0 = (val >> 24) & 0xFF
                let shr24 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shr24,
                    value: val,
                    amount: c24,
                    unsigned: true,
                    flags: None,
                }));
                let byte0 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte0,
                    left: shr24,
                    right: mask_ff,
                    flags: None,
                }));

                // byte1 = (val >> 8) & 0xFF00
                let shr8 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shr8,
                    value: val,
                    amount: c8,
                    unsigned: true,
                    flags: None,
                }));
                let byte1 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte1,
                    left: shr8,
                    right: mask_ff00,
                    flags: None,
                }));

                // byte2 = (val << 8) & 0xFF0000
                let shl8 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: shl8,
                    value: val,
                    amount: c8,
                    flags: None,
                }));
                let byte2 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte2,
                    left: shl8,
                    right: mask_ff0000,
                    flags: None,
                }));

                // byte3 = (val << 24) & 0xFF000000
                let shl24 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: shl24,
                    value: val,
                    amount: c24,
                    flags: None,
                }));
                let byte3 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: byte3,
                    left: shl24,
                    right: mask_ff000000,
                    flags: None,
                }));

                // Combine: result = byte0 | byte1 | byte2 | byte3
                let or01 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: or01,
                    left: byte0,
                    right: byte1,
                    flags: None,
                }));
                let or012 = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: or012,
                    left: or01,
                    right: byte2,
                    flags: None,
                }));
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: res_var,
                    left: or012,
                    right: byte3,
                    flags: None,
                }));

                reg_state.set(*dst, res_var);
                flags.clear();
            }

            // Conditional move: dst = condition ? src : dst
            X86Instruction::Cmovcc {
                condition,
                dst,
                src,
            } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let dst_var = Self::get_register_value(*dst, reg_state)?;

                // Evaluate condition to get a 0/1 value
                let cond_var =
                    self.evaluate_condition(*condition, flags, &mut result, block_idx)?;

                // Implement conditional move as: result = dst ^ (cond_mask & (src ^ dst))
                // where cond_mask = 0 - cond (produces 0 or 0xFFFFFFFF)
                let neg_cond = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Neg {
                    dest: neg_cond,
                    operand: cond_var,
                    flags: None,
                }));
                let xor_diff = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_diff,
                    left: src_var,
                    right: dst_var,
                    flags: None,
                }));
                let masked = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: masked,
                    left: xor_diff,
                    right: neg_cond,
                    flags: None,
                }));
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: res_var,
                    left: dst_var,
                    right: masked,
                    flags: None,
                }));
                reg_state.set(*dst, res_var);
                // Cmovcc doesn't modify flags
            }

            // Set byte on condition: dst = condition ? 1 : 0
            X86Instruction::Setcc { condition, dst } => {
                let cond_var =
                    self.evaluate_condition(*condition, flags, &mut result, block_idx)?;
                self.set_operand_value(dst, cond_var, reg_state, &mut result, block_idx)?;
                // Setcc doesn't modify flags
            }

            // Bit scan forward/reverse
            X86Instruction::Bsf { dst, src } | X86Instruction::Bsr { dst, src } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                // Approximate: result is the source value (placeholder)
                reg_state.set(*dst, src_var);
                flags.clear();
            }

            // Bit test: sets CF based on the tested bit
            X86Instruction::Bt { src, bit } => {
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let bit_var = self.get_operand_value(bit, reg_state, &mut result, block_idx)?;
                // BT only sets flags (specifically CF), doesn't modify operands
                flags.set_test(src_var, bit_var);
            }

            // Exchange and add: temp = dst; dst = dst + src; src = temp
            X86Instruction::Xadd { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Add {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                self.set_operand_value(src, dst_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::Add);
                // XADD sets CF like ADD: CF = (result < left) unsigned
                let cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: res_var,
                    right: dst_var,
                    unsigned: true,
                    signaling: false,
                }));
                flags.set_carry(cf);
            }

            // Bitwise
            X86Instruction::And { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // AND always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Or { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Or {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // OR always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Xor { dst, src } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let src_var = self.get_operand_value(src, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: res_var,
                    left: dst_var,
                    right: src_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, src_var, ArithmeticKind::LogicalOp);
                // XOR always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            X86Instruction::Not { dst } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Not {
                    dest: res_var,
                    operand: dst_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                // NOT doesn't affect flags (except in some specific cases)
            }

            X86Instruction::Shl { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shl {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Shr { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                    unsigned: true,
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Sar { dst, count } => {
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let count_var = self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                let res_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: res_var,
                    value: dst_var,
                    amount: count_var,
                    unsigned: false, // SAR is signed shift right
                    flags: None,
                }));
                self.set_operand_value(dst, res_var, reg_state, &mut result, block_idx)?;
                flags.set_arithmetic(res_var, dst_var, count_var, ArithmeticKind::Other);
            }

            X86Instruction::Rol { dst, count } | X86Instruction::Ror { dst, count } => {
                // Rotates are complex to express in SSA
                // For now, treat as unsupported or approximate
                let dst_var = self.get_operand_value(dst, reg_state, &mut result, block_idx)?;
                let _count_var =
                    self.get_operand_value(count, reg_state, &mut result, block_idx)?;
                // Keep the value unchanged (this is an approximation)
                self.set_operand_value(dst, dst_var, reg_state, &mut result, block_idx)?;
                flags.clear();
            }

            // Comparison
            X86Instruction::Cmp { left, right } => {
                let left_var = self.get_operand_value(left, reg_state, &mut result, block_idx)?;
                let right_var = self.get_operand_value(right, reg_state, &mut result, block_idx)?;
                flags.set_compare(left_var, right_var);
                // CMP sets CF = (left < right) unsigned (same as SUB)
                let cf = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                result.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: cf,
                    left: left_var,
                    right: right_var,
                    unsigned: true,
                    signaling: false,
                }));
                flags.set_carry(cf);
            }

            X86Instruction::Test { left, right } => {
                let left_var = self.get_operand_value(left, reg_state, &mut result, block_idx)?;
                let right_var = self.get_operand_value(right, reg_state, &mut result, block_idx)?;
                flags.set_test(left_var, right_var);
                // TEST always clears CF
                let zero_cf = self.get_constant(0, &mut result, block_idx);
                flags.clear_carry(zero_cf);
            }

            // Control flow
            X86Instruction::Jmp { target } => {
                let target_block = self.find_block_for_address(*target)?;
                result.push(SsaInstruction::synthetic(SsaOp::Jump {
                    target: target_block,
                }));
            }

            X86Instruction::Jcc { condition, target } => {
                let target_block = self.find_block_for_address(*target)?;
                let fallthrough_block = block_idx.saturating_add(1); // Assumes sequential layout

                // Get comparison operands from flags
                if let Some((cmp, left, right, unsigned)) = flags.get_branch_operands(*condition) {
                    // Handle TEST special case
                    if matches!(flags.producer(), Some(FlagProducer::Test { .. })) {
                        // For TEST + JE/JNE, we need to compare (left & right) with 0
                        let and_result = self.create_variable(
                            VariableOrigin::Phi,
                            DefSite::instruction(block_idx, result.len()),
                            self.func.bitness,
                        );
                        result.push(SsaInstruction::synthetic(SsaOp::And {
                            dest: and_result,
                            left,
                            right,
                            flags: None,
                        }));
                        let zero = self.get_zero_constant(&mut result, block_idx);
                        result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                            left: and_result,
                            right: zero,
                            cmp,
                            unsigned: false,
                            true_target: target_block,
                            false_target: fallthrough_block,
                        }));
                    } else {
                        result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                            left,
                            right,
                            cmp,
                            unsigned,
                            true_target: target_block,
                            false_target: fallthrough_block,
                        }));
                    }
                } else {
                    // Fall back to evaluate_condition for S/NS/O/NO/P/NP conditions
                    let cond_var =
                        self.evaluate_condition(*condition, flags, &mut result, block_idx)?;
                    let zero = self.get_zero_constant(&mut result, block_idx);
                    result.push(SsaInstruction::synthetic(SsaOp::BranchCmp {
                        left: cond_var,
                        right: zero,
                        cmp: CmpKind::Ne,
                        unsigned: false,
                        true_target: target_block,
                        false_target: fallthrough_block,
                    }));
                }
            }

            X86Instruction::Ret => {
                // Return the value in EAX/RAX
                let ret_reg = if self.func.bitness == 64 {
                    X86Register::Rax
                } else {
                    X86Register::Eax
                };
                let ret_val = reg_state.get(ret_reg);
                result.push(SsaInstruction::synthetic(SsaOp::returns(ret_val)));
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
                // Sign-extend EAX into EDX:EAX
                // In SSA, we just track that EDX becomes a function of EAX
                let eax = Self::get_register_value(X86Register::Eax, reg_state)?;
                // EDX gets sign bits of EAX (all 0s or all 1s)
                // For simplicity, create a new variable
                let edx_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, result.len()),
                    self.func.bitness,
                );
                // EDX = EAX >> 31 (arithmetic)
                let thirty_one = self.get_constant(31, &mut result, block_idx);
                result.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: edx_var,
                    value: eax,
                    amount: thirty_one,
                    unsigned: false,
                    flags: None,
                }));
                reg_state.set(X86Register::Edx, edx_var);
            }

            X86Instruction::Cwde => {
                // Sign-extend AX into EAX
                // In SSA, this is effectively a no-op since we track 32-bit values
                flags.clear();
            }

            X86Instruction::Unsupported { offset, mnemonic } => {
                return Err(Error::X86Error(format!(
                    "Unsupported instruction '{mnemonic}' at 0x{offset:x}"
                )));
            }
        }

        Ok(result)
    }

    /// Gets the SSA variable for an operand value.
    fn get_operand_value(
        &mut self,
        operand: &X86Operand,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        match operand {
            X86Operand::Register(reg) => Self::get_register_value(*reg, reg_state),
            X86Operand::Immediate(val) => Ok(self.get_constant(*val, instrs, block_idx)),
            X86Operand::Memory(mem) => self.load_from_memory(mem, reg_state, instrs, block_idx),
        }
    }

    /// Gets the SSA variable for a register.
    fn get_register_value(reg: X86Register, reg_state: &RegisterState) -> Result<SsaVarId> {
        reg_state
            .get(reg)
            .ok_or_else(|| Error::X86Error(format!("Register {reg:?} not defined")))
    }

    /// Sets the value of an operand.
    fn set_operand_value(
        &mut self,
        operand: &X86Operand,
        value: SsaVarId,
        reg_state: &mut RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<()> {
        match operand {
            X86Operand::Register(reg) => {
                reg_state.set(*reg, value);
                Ok(())
            }
            X86Operand::Memory(mem) => {
                self.store_to_memory(mem, value, reg_state, instrs, block_idx)
            }
            X86Operand::Immediate(_) => Err(Error::X86Error(
                "Cannot store to immediate operand".to_string(),
            )),
        }
    }

    /// Loads a value from memory.
    fn load_from_memory(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let addr = self.compute_memory_address(mem, reg_state, instrs, block_idx)?;
        let result = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        let value_type = match mem.size {
            1 => SsaType::I8,
            2 => SsaType::I16,
            8 => SsaType::I64,
            _ => SsaType::I32,
        };

        instrs.push(SsaInstruction::synthetic(SsaOp::LoadIndirect {
            dest: result,
            addr,
            value_type,
            access: AccessQualifiers {
                address_space: address_space_for(mem),
                ..AccessQualifiers::FLAT
            },
        }));

        Ok(result)
    }

    /// Stores a value to memory.
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
            8 => SsaType::I64,
            _ => SsaType::I32,
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

    /// Evaluates an x86 condition code into a 0/1 SSA variable.
    ///
    /// This is used by Cmovcc and Setcc to produce a value based on the
    /// current flag state. It emits the necessary comparison instructions
    /// and returns an SSA variable holding 0 (false) or 1 (true).
    fn evaluate_condition(
        &mut self,
        condition: X86Condition,
        flags: &FlagState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let eval = flags.get_condition_operands(condition).ok_or_else(|| {
            Error::X86Error(format!(
                "Cannot evaluate condition {condition:?}: flags unknown or unsupported"
            ))
        })?;

        match eval {
            ConditionEval::Compare {
                cmp,
                left,
                right,
                unsigned,
            } => self.emit_comparison(cmp, left, right, unsigned, instrs, block_idx),
            ConditionEval::Test { cmp, left, right } => {
                // Compute AND first, then compare to zero
                let and_result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_result,
                    left,
                    right,
                    flags: None,
                }));
                let zero = self.get_zero_constant(instrs, block_idx);
                self.emit_comparison(cmp, and_result, zero, false, instrs, block_idx)
            }
            ConditionEval::ZeroTest { cmp, result } => {
                let zero = self.get_zero_constant(instrs, block_idx);
                self.emit_comparison(cmp, result, zero, false, instrs, block_idx)
            }
            ConditionEval::SignFlag { source, negated } => {
                self.emit_sign_flag(source, negated, instrs, block_idx)
            }
            ConditionEval::OverflowFlag {
                left,
                right,
                result,
                kind,
                negated,
            } => self.emit_overflow_flag(left, right, result, kind, negated, instrs, block_idx),
            ConditionEval::ParityFlag { source, negated } => {
                self.emit_parity_flag(source, negated, instrs, block_idx)
            }
        }
    }

    /// Emits a comparison SSA operation (Ceq/Clt/Cgt) and returns the result variable.
    fn emit_comparison(
        &mut self,
        cmp: CmpKind,
        left: SsaVarId,
        right: SsaVarId,
        unsigned: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let result = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        match cmp {
            CmpKind::Eq => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: result,
                    left,
                    right,
                    signaling: false,
                }));
            }
            CmpKind::Ne => {
                // Ne = !Eq: compute Ceq then XOR with 1
                let eq_result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: eq_result,
                    left,
                    right,
                    signaling: false,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: eq_result,
                    right: one,
                    flags: None,
                }));
            }
            CmpKind::Lt => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: result,
                    left,
                    right,
                    unsigned,
                    signaling: false,
                }));
            }
            CmpKind::Gt => {
                instrs.push(SsaInstruction::synthetic(SsaOp::Cgt {
                    dest: result,
                    left,
                    right,
                    unsigned,
                    signaling: false,
                }));
            }
            CmpKind::Le => {
                // Le = !Gt: compute Cgt then XOR with 1
                let gt_result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Cgt {
                    dest: gt_result,
                    left,
                    right,
                    unsigned,
                    signaling: false,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: gt_result,
                    right: one,
                    flags: None,
                }));
            }
            CmpKind::Ge => {
                // Ge = !Lt: compute Clt then XOR with 1
                let lt_result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Clt {
                    dest: lt_result,
                    left,
                    right,
                    unsigned,
                    signaling: false,
                }));
                let one = self.get_constant(1, instrs, block_idx);
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: result,
                    left: lt_result,
                    right: one,
                    flags: None,
                }));
            }
        }

        Ok(result)
    }

    /// Resolves a `FlagTestSource` to an SSA variable, emitting Sub or And if needed.
    fn resolve_flag_test_source(
        &mut self,
        source: FlagTestSource,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        match source {
            FlagTestSource::Direct(var) => var,
            FlagTestSource::Subtract { left, right } => {
                let result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Sub {
                    dest: result,
                    left,
                    right,
                    flags: None,
                }));
                result
            }
            FlagTestSource::BitwiseAnd { left, right } => {
                let result = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: result,
                    left,
                    right,
                    flags: None,
                }));
                result
            }
        }
    }

    /// Emits SSA instructions to compute the sign flag (SF) as a 0/1 value.
    ///
    /// SF = MSB of the value. Extracts it via `(value >> (bitwidth-1)) & 1`.
    fn emit_sign_flag(
        &mut self,
        source: FlagTestSource,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let value = self.resolve_flag_test_source(source, instrs, block_idx);
        let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
        let shift_const = self.get_constant(shift_amount, instrs, block_idx);

        // sign_shifted = value >> (bitwidth-1), unsigned shift
        let sign_shifted = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: sign_shifted,
            value,
            amount: shift_const,
            unsigned: true,
            flags: None,
        }));

        // sign_bit = sign_shifted & 1
        let one = self.get_constant(1, instrs, block_idx);
        let sign_bit = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: sign_bit,
            left: sign_shifted,
            right: one,
            flags: None,
        }));

        if negated {
            // NS: return !SF = sign_bit ^ 1
            let result = self.create_variable(
                VariableOrigin::Phi,
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one2 = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result,
                left: sign_bit,
                right: one2,
                flags: None,
            }));
            Ok(result)
        } else {
            Ok(sign_bit)
        }
    }

    /// Emits SSA instructions to compute the overflow flag (OF) as a 0/1 value.
    ///
    /// The computation depends on the arithmetic operation that set the flags:
    /// - `LogicalOp`: OF is always 0 (TEST, AND, OR, XOR clear OF)
    /// - `Sub`/CMP: OF = ((left ^ right) & (left ^ result)) >> MSB
    /// - `Add`: OF = ((left ^ result) & (right ^ result)) >> MSB
    /// - `Neg`: OF = (result == INT_MIN)
    /// - `Other`: OF approximated as 0
    #[allow(clippy::too_many_arguments)]
    fn emit_overflow_flag(
        &mut self,
        left: SsaVarId,
        right: SsaVarId,
        result: Option<SsaVarId>,
        kind: ArithmeticKind,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let of = match kind {
            ArithmeticKind::LogicalOp | ArithmeticKind::Other => {
                // OF = 0 for logical operations and undefined/complex operations
                self.get_constant(0, instrs, block_idx)
            }
            ArithmeticKind::Sub => {
                // For CMP (result=None): compute sub_result = left - right
                // For SUB (result=Some): use existing result
                let sub_result = if let Some(r) = result {
                    r
                } else {
                    let r = self.create_variable(
                        VariableOrigin::Phi,
                        DefSite::instruction(block_idx, instrs.len()),
                        self.func.bitness,
                    );
                    instrs.push(SsaInstruction::synthetic(SsaOp::Sub {
                        dest: r,
                        left,
                        right,
                        flags: None,
                    }));
                    r
                };

                // OF = ((left ^ right) & (left ^ result)) >> (bitwidth-1)
                let xor_lr = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_lr,
                    left,
                    right,
                    flags: None,
                }));

                let xor_ls = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_ls,
                    left,
                    right: sub_result,
                    flags: None,
                }));

                let and_both = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_both,
                    left: xor_lr,
                    right: xor_ls,
                    flags: None,
                }));

                let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
                let shift_const = self.get_constant(shift_amount, instrs, block_idx);
                let shifted = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shifted,
                    value: and_both,
                    amount: shift_const,
                    unsigned: true,
                    flags: None,
                }));

                let one = self.get_constant(1, instrs, block_idx);
                let of_bit = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: of_bit,
                    left: shifted,
                    right: one,
                    flags: None,
                }));
                of_bit
            }
            ArithmeticKind::Add => {
                // OF = ((left ^ result) & (right ^ result)) >> (bitwidth-1)
                let add_result = result.unwrap_or(left); // Should always have result for Add

                let xor_lr = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_lr,
                    left,
                    right: add_result,
                    flags: None,
                }));

                let xor_rr = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                    dest: xor_rr,
                    left: right,
                    right: add_result,
                    flags: None,
                }));

                let and_both = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: and_both,
                    left: xor_lr,
                    right: xor_rr,
                    flags: None,
                }));

                let shift_amount = if self.func.bitness == 64 { 63 } else { 31 };
                let shift_const = self.get_constant(shift_amount, instrs, block_idx);
                let shifted = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
                    dest: shifted,
                    value: and_both,
                    amount: shift_const,
                    unsigned: true,
                    flags: None,
                }));

                let one = self.get_constant(1, instrs, block_idx);
                let of_bit = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::And {
                    dest: of_bit,
                    left: shifted,
                    right: one,
                    flags: None,
                }));
                of_bit
            }
            ArithmeticKind::Neg => {
                // OF = (result == INT_MIN)
                let neg_result = result.unwrap_or(left);
                let int_min = if self.func.bitness == 64 {
                    self.get_constant(i64::MIN, instrs, block_idx)
                } else {
                    self.get_constant(i64::from(i32::MIN), instrs, block_idx)
                };
                let of_bit = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Ceq {
                    dest: of_bit,
                    left: neg_result,
                    right: int_min,
                    signaling: false,
                }));
                of_bit
            }
        };

        if negated {
            // NO: return !OF = of ^ 1
            let result_var = self.create_variable(
                VariableOrigin::Phi,
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result_var,
                left: of,
                right: one,
                flags: None,
            }));
            Ok(result_var)
        } else {
            Ok(of)
        }
    }

    /// Emits SSA instructions to compute the parity flag (PF) as a 0/1 value.
    ///
    /// PF = 1 when the low byte of the value has even parity (even number of 1-bits).
    /// Computed by XOR-folding the low byte down to a single bit.
    fn emit_parity_flag(
        &mut self,
        source: FlagTestSource,
        negated: bool,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        let value = self.resolve_flag_test_source(source, instrs, block_idx);

        // b = value & 0xFF (isolate low byte)
        let mask_ff = self.get_constant(0xFF, instrs, block_idx);
        let b = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: b,
            left: value,
            right: mask_ff,
            flags: None,
        }));

        // b ^= b >> 4
        let c4 = self.get_constant(4, instrs, block_idx);
        let shr4 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr4,
            value: b,
            amount: c4,
            unsigned: true,
            flags: None,
        }));
        let b1 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b1,
            left: b,
            right: shr4,
            flags: None,
        }));

        // b ^= b >> 2
        let c2 = self.get_constant(2, instrs, block_idx);
        let shr2 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr2,
            value: b1,
            amount: c2,
            unsigned: true,
            flags: None,
        }));
        let b2 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b2,
            left: b1,
            right: shr2,
            flags: None,
        }));

        // b ^= b >> 1
        let c1 = self.get_constant(1, instrs, block_idx);
        let shr1 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Shr {
            dest: shr1,
            value: b2,
            amount: c1,
            unsigned: true,
            flags: None,
        }));
        let b3 = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
            dest: b3,
            left: b2,
            right: shr1,
            flags: None,
        }));

        // odd_parity = b3 & 1
        let one = self.get_constant(1, instrs, block_idx);
        let odd_parity = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );
        instrs.push(SsaInstruction::synthetic(SsaOp::And {
            dest: odd_parity,
            left: b3,
            right: one,
            flags: None,
        }));

        if negated {
            // NP (PF=0): return odd_parity (1 when odd number of bits)
            Ok(odd_parity)
        } else {
            // P (PF=1): return !odd_parity (1 when even number of bits)
            let result = self.create_variable(
                VariableOrigin::Phi,
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            let one2 = self.get_constant(1, instrs, block_idx);
            instrs.push(SsaInstruction::synthetic(SsaOp::Xor {
                dest: result,
                left: odd_parity,
                right: one2,
                flags: None,
            }));
            Ok(result)
        }
    }

    /// Computes the effective address for a memory operand.
    fn compute_memory_address(
        &mut self,
        mem: &X86Memory,
        reg_state: &RegisterState,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> Result<SsaVarId> {
        // Start with base or 0
        let mut addr = if let Some(base) = mem.base {
            Self::get_register_value(base, reg_state)?
        } else {
            self.get_zero_constant(instrs, block_idx)
        };

        // Add index * scale
        if let Some(index) = mem.index {
            let index_val = Self::get_register_value(index, reg_state)?;

            // Multiply by scale if not 1
            let scaled = if mem.scale == 1 {
                index_val
            } else {
                let scale_const = self.get_constant(i64::from(mem.scale), instrs, block_idx);
                let scaled_var = self.create_variable(
                    VariableOrigin::Phi,
                    DefSite::instruction(block_idx, instrs.len()),
                    self.func.bitness,
                );
                instrs.push(SsaInstruction::synthetic(SsaOp::Mul {
                    dest: scaled_var,
                    left: index_val,
                    right: scale_const,
                    flags: None,
                }));
                scaled_var
            };

            // Add to address
            let new_addr = self.create_variable(
                VariableOrigin::Phi,
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            instrs.push(SsaInstruction::synthetic(SsaOp::Add {
                dest: new_addr,
                left: addr,
                right: scaled,
                flags: None,
            }));
            addr = new_addr;
        }

        // Add displacement
        if mem.displacement != 0 {
            let disp_const = self.get_constant(mem.displacement, instrs, block_idx);
            let new_addr = self.create_variable(
                VariableOrigin::Phi,
                DefSite::instruction(block_idx, instrs.len()),
                self.func.bitness,
            );
            instrs.push(SsaInstruction::synthetic(SsaOp::Add {
                dest: new_addr,
                left: addr,
                right: disp_const,
                flags: None,
            }));
            addr = new_addr;
        }

        Ok(addr)
    }

    /// Gets or creates an SSA variable for a constant value.
    fn get_constant(
        &mut self,
        value: i64,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        let var = self.create_variable(
            VariableOrigin::Phi,
            DefSite::instruction(block_idx, instrs.len()),
            self.func.bitness,
        );

        let const_value = if self.func.bitness == 64 {
            ConstValue::I64(value)
        } else {
            // Safe: x86 32-bit constant intentionally truncated to i32
            #[allow(clippy::cast_possible_truncation)]
            let truncated = value as i32;
            ConstValue::I32(truncated)
        };

        instrs.push(SsaInstruction::synthetic(SsaOp::Const {
            dest: var,
            value: const_value,
        }));

        var
    }

    /// Gets or creates a zero constant.
    fn get_zero_constant(
        &mut self,
        instrs: &mut Vec<SsaInstruction>,
        block_idx: usize,
    ) -> SsaVarId {
        if let Some(zero) = self.zero_const {
            return zero;
        }

        let zero = self.get_constant(0, instrs, block_idx);
        self.zero_const = Some(zero);
        zero
    }

    /// Creates a new SSA variable using the local allocator.
    fn create_variable(
        &mut self,
        origin: VariableOrigin,
        def_site: DefSite,
        bitness: u32,
    ) -> SsaVarId {
        let var_type = if bitness == 64 {
            SsaType::I64
        } else {
            SsaType::I32
        };
        let id = SsaVarId::from_index(self.variables.len());
        let var = SsaVariable::new(id, origin, 0, def_site, var_type);
        self.variables.push(var);
        id
    }

    /// Finds the block index for a given address.
    fn find_block_for_address(&self, addr: u64) -> Result<usize> {
        let offset = addr.checked_sub(self.func.base_address).ok_or_else(|| {
            Error::X86Error(format!(
                "Address 0x{addr:x} is below base 0x{:x}",
                self.func.base_address
            ))
        })?;

        for node_id in self.func.node_ids() {
            let idx = node_id.index();
            if let Some(block) = self.func.block(idx) {
                if block.start_offset == offset {
                    return Ok(idx);
                }
            }
        }

        Err(Error::X86Error(format!(
            "No block found for address 0x{addr:x}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis::x86::decoder::x86_decode_all, compiler::SsaCodeGenerator};

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

        let spaces: Vec<Option<u16>> = ssa
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
        // pop eax; pop ecx; cmp eax, 0; cmovs eax, ecx; ret
        // CMOVS: conditional move if sign flag is set
        let bytes = [
            0x58, // pop eax
            0x59, // pop ecx
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

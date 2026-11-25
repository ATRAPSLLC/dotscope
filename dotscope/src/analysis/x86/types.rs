//! x86/x64 instruction type definitions.
//!
//! This module provides simplified x86 instruction types used for translating
//! native x86 code to SSA. These types are a subset of what iced-x86 provides,
//! focusing on the operations needed for DynCipher-style code.
//!
//! # Overview
//!
//! The type hierarchy is:
//!
//! - [`X86Register`] - General-purpose registers (8/16/32/64-bit)
//! - [`X86Memory`] - Memory operands with base, index, scale, displacement
//! - [`X86Operand`] - Union of register, immediate, or memory operand
//! - [`X86Instruction`] - Decoded instruction with operands
//! - [`X86DecodedInstruction`] - Instruction with offset and length metadata
//!
//! # Condition Codes
//!
//! The [`X86Condition`] enum represents condition codes for conditional jumps,
//! with methods for negation. Conditions are grouped by:
//!
//! - **Equality**: `E` (equal), `Ne` (not equal)
//! - **Signed**: `L` (less), `Ge` (greater/equal), `Le`, `G`
//! - **Unsigned**: `B` (below), `Ae` (above/equal), `Be`, `A`
//! - **Flags**: `S`/`Ns` (sign), `O`/`No` (overflow), `P`/`Np` (parity)
//!
//! # Edge Classification
//!
//! The [`X86EdgeKind`] enum classifies CFG edges for analysis:
//!
//! - [`X86EdgeKind::Unconditional`] - Direct jumps and fall-through
//! - [`X86EdgeKind::ConditionalTrue`] / [`X86EdgeKind::ConditionalFalse`] - Branch edges
//! - [`X86EdgeKind::Call`] - Call instruction edges
//! - [`X86EdgeKind::IndirectJump`] - Unresolved indirect control flow
//! - [`X86EdgeKind::Return`] - Function exit edges

/// x86/x64 general-purpose register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Register {
    /// 32-bit accumulator register (EAX)
    Eax,
    /// 32-bit counter register (ECX)
    Ecx,
    /// 32-bit data register (EDX)
    Edx,
    /// 32-bit base register (EBX)
    Ebx,
    /// 32-bit stack pointer (ESP)
    Esp,
    /// 32-bit base pointer (EBP)
    Ebp,
    /// 32-bit source index (ESI)
    Esi,
    /// 32-bit destination index (EDI)
    Edi,

    /// 64-bit accumulator register (RAX)
    Rax,
    /// 64-bit counter register (RCX)
    Rcx,
    /// 64-bit data register (RDX)
    Rdx,
    /// 64-bit base register (RBX)
    Rbx,
    /// 64-bit stack pointer (RSP)
    Rsp,
    /// 64-bit base pointer (RBP)
    Rbp,
    /// 64-bit source index (RSI)
    Rsi,
    /// 64-bit destination index (RDI)
    Rdi,
    /// 64-bit extended register R8
    R8,
    /// 64-bit extended register R9
    R9,
    /// 64-bit extended register R10
    R10,
    /// 64-bit extended register R11
    R11,
    /// 64-bit extended register R12
    R12,
    /// 64-bit extended register R13
    R13,
    /// 64-bit extended register R14
    R14,
    /// 64-bit extended register R15
    R15,

    /// 8-bit low accumulator (AL)
    Al,
    /// 8-bit low counter (CL)
    Cl,
    /// 8-bit low data (DL)
    Dl,
    /// 8-bit low base (BL)
    Bl,
    /// 8-bit high accumulator (AH)
    Ah,
    /// 8-bit high counter (CH)
    Ch,
    /// 8-bit high data (DH)
    Dh,
    /// 8-bit high base (BH)
    Bh,

    /// 16-bit accumulator register (AX)
    Ax,
    /// 16-bit counter register (CX)
    Cx,
    /// 16-bit data register (DX)
    Dx,
    /// 16-bit base register (BX)
    Bx,
    /// 16-bit stack pointer (SP)
    Sp,
    /// 16-bit base pointer (BP)
    Bp,
    /// 16-bit source index (SI)
    Si,
    /// 16-bit destination index (DI)
    Di,

    // Segment registers (16-bit)
    /// Extra segment register (ES)
    Es,
    /// Code segment register (CS)
    Cs,
    /// Stack segment register (SS)
    Ss,
    /// Data segment register (DS)
    Ds,
    /// FS segment register
    Fs,
    /// GS segment register
    Gs,
}

impl X86Register {
    /// Returns the size of this register in bytes.
    #[inline]
    #[must_use]
    pub fn size(&self) -> u8 {
        match self {
            // 8-bit
            X86Register::Al
            | X86Register::Cl
            | X86Register::Dl
            | X86Register::Bl
            | X86Register::Ah
            | X86Register::Ch
            | X86Register::Dh
            | X86Register::Bh => 1,
            // 16-bit
            X86Register::Ax
            | X86Register::Cx
            | X86Register::Dx
            | X86Register::Bx
            | X86Register::Sp
            | X86Register::Bp
            | X86Register::Si
            | X86Register::Di
            | X86Register::Es
            | X86Register::Cs
            | X86Register::Ss
            | X86Register::Ds
            | X86Register::Fs
            | X86Register::Gs => 2,
            // 32-bit
            X86Register::Eax
            | X86Register::Ecx
            | X86Register::Edx
            | X86Register::Ebx
            | X86Register::Esp
            | X86Register::Ebp
            | X86Register::Esi
            | X86Register::Edi => 4,
            // 64-bit
            X86Register::Rax
            | X86Register::Rcx
            | X86Register::Rdx
            | X86Register::Rbx
            | X86Register::Rsp
            | X86Register::Rbp
            | X86Register::Rsi
            | X86Register::Rdi
            | X86Register::R8
            | X86Register::R9
            | X86Register::R10
            | X86Register::R11
            | X86Register::R12
            | X86Register::R13
            | X86Register::R14
            | X86Register::R15 => 8,
        }
    }

    /// Returns the base register (the full-size register this is part of).
    /// E.g., AL/AX/EAX all map to RAX in 64-bit mode, or EAX in 32-bit mode.
    #[inline]
    #[must_use]
    pub fn base_index(&self) -> u8 {
        match self {
            X86Register::Al
            | X86Register::Ah
            | X86Register::Ax
            | X86Register::Eax
            | X86Register::Rax => 0,
            X86Register::Cl
            | X86Register::Ch
            | X86Register::Cx
            | X86Register::Ecx
            | X86Register::Rcx => 1,
            X86Register::Dl
            | X86Register::Dh
            | X86Register::Dx
            | X86Register::Edx
            | X86Register::Rdx => 2,
            X86Register::Bl
            | X86Register::Bh
            | X86Register::Bx
            | X86Register::Ebx
            | X86Register::Rbx => 3,
            X86Register::Sp | X86Register::Esp | X86Register::Rsp => 4,
            X86Register::Bp | X86Register::Ebp | X86Register::Rbp => 5,
            X86Register::Si | X86Register::Esi | X86Register::Rsi => 6,
            X86Register::Di | X86Register::Edi | X86Register::Rdi => 7,
            X86Register::R8 => 8,
            X86Register::R9 => 9,
            X86Register::R10 => 10,
            X86Register::R11 => 11,
            X86Register::R12 => 12,
            X86Register::R13 => 13,
            X86Register::R14 => 14,
            X86Register::R15 => 15,
            X86Register::Es => 16,
            X86Register::Cs => 17,
            X86Register::Ss => 18,
            X86Register::Ds => 19,
            X86Register::Fs => 20,
            X86Register::Gs => 21,
        }
    }

    /// Returns true if this is the stack pointer register.
    #[inline]
    #[must_use]
    pub fn is_stack_pointer(&self) -> bool {
        matches!(self, X86Register::Sp | X86Register::Esp | X86Register::Rsp)
    }

    /// Returns true if this is the base pointer register.
    #[inline]
    #[must_use]
    pub fn is_base_pointer(&self) -> bool {
        matches!(self, X86Register::Bp | X86Register::Ebp | X86Register::Rbp)
    }
}

/// Memory operand representing x86 addressing modes.
///
/// x86 memory operands use the formula: `[base + index*scale + displacement]`
///
/// # Addressing Modes
///
/// - `[disp]` - Absolute address (base=None, index=None)
/// - `[base]` - Register indirect (index=None, disp=0)
/// - `[base + disp]` - Base plus displacement
/// - `[base + index*scale]` - Base-index with scale
/// - `[base + index*scale + disp]` - Full SIB addressing
///
/// # Examples
///
/// ```rust
/// use dotscope::analysis::{X86Memory, X86Register};
///
/// // [esp + 16]
/// let stack_arg = X86Memory::base_disp(X86Register::Esp, 16, 4);
///
/// // [eax + ecx*4 + 8]
/// let array_elem = X86Memory::base_index_scale_disp(
///     X86Register::Eax, X86Register::Ecx, 4, 8, 4
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86Memory {
    /// Base register (optional). When `None`, uses absolute addressing.
    pub base: Option<X86Register>,
    /// Index register (optional, for SIB addressing).
    pub index: Option<X86Register>,
    /// Scale factor for index register. Valid values: 1, 2, 4, or 8.
    pub scale: u8,
    /// Signed displacement added to the effective address.
    pub displacement: i64,
    /// Size of the memory access in bytes (1, 2, 4, or 8).
    pub size: u8,
    /// Explicit segment override prefix on the access, or `None` when the
    /// instruction uses the default segment for its base register.
    ///
    /// Only the *prefix* is recorded, never the effective segment: in flat
    /// 32-bit and 64-bit user mode `cs`/`ds`/`es`/`ss` all describe the same
    /// address space, so treating an explicit `ss:` as distinct from an
    /// unprefixed access would make two names for one cell look disjoint.
    /// `fs:` and `gs:` do have their own bases, which is why they are carried
    /// through to [`SsaOp::LoadIndirect`]'s address space.
    ///
    /// [`SsaOp::LoadIndirect`]: crate::analysis::SsaOp::LoadIndirect
    pub segment: Option<X86Register>,
}

impl X86Memory {
    /// Creates a simple [base + disp] memory operand.
    #[must_use]
    pub fn base_disp(base: X86Register, displacement: i64, size: u8) -> Self {
        Self {
            base: Some(base),
            index: None,
            scale: 1,
            displacement,
            size,
            segment: None,
        }
    }

    /// Creates a [base + index*scale + disp] memory operand.
    #[must_use]
    pub fn base_index_scale_disp(
        base: X86Register,
        index: X86Register,
        scale: u8,
        displacement: i64,
        size: u8,
    ) -> Self {
        Self {
            base: Some(base),
            index: Some(index),
            scale,
            displacement,
            size,
            segment: None,
        }
    }

    /// Creates a `[disp]` memory operand (absolute address).
    #[must_use]
    pub fn absolute(displacement: i64, size: u8) -> Self {
        Self {
            base: None,
            index: None,
            scale: 1,
            displacement,
            size,
            segment: None,
        }
    }

    /// Returns this operand qualified by an explicit segment override prefix.
    #[must_use]
    pub fn with_segment(mut self, segment: X86Register) -> Self {
        self.segment = Some(segment);
        self
    }
}

/// Operand for an x86 instruction.
///
/// An operand can be a register, immediate value, or memory location.
/// Most x86 instructions take one or two operands.
///
/// # Examples
///
/// ```rust
/// use dotscope::analysis::{X86Operand, X86Register, X86Memory};
///
/// // Register operand
/// let reg = X86Operand::Register(X86Register::Eax);
/// assert!(reg.is_register());
///
/// // Immediate operand
/// let imm = X86Operand::Immediate(42);
/// assert_eq!(imm.as_immediate(), Some(42));
///
/// // Memory operand
/// let mem = X86Operand::Memory(X86Memory::base_disp(X86Register::Esp, 8, 4));
/// assert!(mem.is_memory());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X86Operand {
    /// Register operand (e.g., `eax`, `rcx`)
    Register(X86Register),
    /// Immediate constant value (e.g., `42`, `0x1000`)
    Immediate(i64),
    /// Memory operand (e.g., `[esp+8]`, `[eax+ecx*4]`)
    Memory(X86Memory),
}

impl X86Operand {
    /// Returns the size of this operand in bytes, if known.
    #[must_use]
    pub fn size(&self) -> Option<u8> {
        match self {
            X86Operand::Register(reg) => Some(reg.size()),
            X86Operand::Immediate(_) => None, // Size depends on context
            X86Operand::Memory(mem) => Some(mem.size),
        }
    }

    /// Returns true if this is a register operand.
    #[must_use]
    pub fn is_register(&self) -> bool {
        matches!(self, X86Operand::Register(_))
    }

    /// Returns true if this is an immediate operand.
    #[must_use]
    pub fn is_immediate(&self) -> bool {
        matches!(self, X86Operand::Immediate(_))
    }

    /// Returns true if this is a memory operand.
    #[must_use]
    pub fn is_memory(&self) -> bool {
        matches!(self, X86Operand::Memory(_))
    }

    /// Returns the register if this is a register operand.
    #[must_use]
    pub fn as_register(&self) -> Option<X86Register> {
        match self {
            X86Operand::Register(r) => Some(*r),
            _ => None,
        }
    }

    /// Returns the immediate value if this is an immediate operand.
    #[must_use]
    pub fn as_immediate(&self) -> Option<i64> {
        match self {
            X86Operand::Immediate(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the memory operand if this is a memory operand.
    #[must_use]
    pub fn as_memory(&self) -> Option<&X86Memory> {
        match self {
            X86Operand::Memory(m) => Some(m),
            _ => None,
        }
    }
}

/// Condition codes for conditional jumps (Jcc instructions).
///
/// These conditions are checked against the CPU flags register after
/// comparison or test instructions. Each condition has a logical negation
/// accessible via [`X86Condition::negate`].
///
/// # Flag Dependencies
///
/// | Condition | Flags Checked | Common Use |
/// |-----------|---------------|------------|
/// | `E`/`Ne` | ZF | Equality comparison |
/// | `L`/`Ge`/`Le`/`G` | SF, OF, ZF | Signed comparison |
/// | `B`/`Ae`/`Be`/`A` | CF, ZF | Unsigned comparison |
/// | `S`/`Ns` | SF | Sign check |
/// | `O`/`No` | OF | Overflow check |
/// | `P`/`Np` | PF | Parity check |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Condition {
    // Equality (ZF)
    /// Equal (ZF=1)
    E,
    /// Not equal (ZF=0)
    Ne,

    // Signed comparisons
    /// Less than (SF!=OF)
    L,
    /// Greater than or equal (SF=OF)
    Ge,
    /// Less than or equal (ZF=1 or SF!=OF)
    Le,
    /// Greater than (ZF=0 and SF=OF)
    G,

    // Unsigned comparisons
    /// Below (CF=1)
    B,
    /// Above or equal (CF=0)
    Ae,
    /// Below or equal (CF=1 or ZF=1)
    Be,
    /// Above (CF=0 and ZF=0)
    A,

    // Sign flag
    /// Sign (SF=1)
    S,
    /// Not sign (SF=0)
    Ns,

    // Overflow flag
    /// Overflow (OF=1)
    O,
    /// Not overflow (OF=0)
    No,

    // Parity flag
    /// Parity even (PF=1)
    P,
    /// Parity odd (PF=0)
    Np,
}

impl X86Condition {
    /// Returns the negation of this condition.
    #[must_use]
    pub fn negate(&self) -> Self {
        match self {
            X86Condition::E => X86Condition::Ne,
            X86Condition::Ne => X86Condition::E,
            X86Condition::L => X86Condition::Ge,
            X86Condition::Ge => X86Condition::L,
            X86Condition::Le => X86Condition::G,
            X86Condition::G => X86Condition::Le,
            X86Condition::B => X86Condition::Ae,
            X86Condition::Ae => X86Condition::B,
            X86Condition::Be => X86Condition::A,
            X86Condition::A => X86Condition::Be,
            X86Condition::S => X86Condition::Ns,
            X86Condition::Ns => X86Condition::S,
            X86Condition::O => X86Condition::No,
            X86Condition::No => X86Condition::O,
            X86Condition::P => X86Condition::Np,
            X86Condition::Np => X86Condition::P,
        }
    }
}

/// Simplified x86 instruction representation.
///
/// This enum represents the subset of x86 operations commonly used in
/// obfuscator stubs like ConfuserEx's DynCipher. Instructions not in this
/// set are captured as [`X86Instruction::Unsupported`] for graceful degradation.
///
/// # Instruction Categories
///
/// - **Data Movement**: `Mov`, `Movzx`, `Movsx`, `Lea`, `Push`, `Pop`, `Xchg`, `Cmovcc`, `Xadd`
/// - **Arithmetic**: `Add`, `Sub`, `Imul`, `Mul`, `Neg`, `Inc`, `Dec`, `Adc`, `Sbb`, `Div`, `Idiv`
/// - **Bitwise**: `And`, `Or`, `Xor`, `Not`, `Shl`, `Shr`, `Sar`, `Rol`, `Ror`, `Bswap`, `Bt`, `Bsf`, `Bsr`
/// - **Comparison**: `Cmp`, `Test`, `Setcc`
/// - **Control Flow**: `Jmp`, `Jcc`, `Call`, `Ret`
/// - **Miscellaneous**: `Nop`, `Cdq`, `Cwde`
///
/// # Analysis Methods
///
/// - [`is_control_flow`](X86Instruction::is_control_flow) - Identifies branch/call/ret
/// - [`is_terminator`](X86Instruction::is_terminator) - Identifies block-ending instructions
/// - [`jump_targets`](X86Instruction::jump_targets) - Extracts branch targets
/// - [`reads_memory`](X86Instruction::reads_memory) / [`writes_memory`](X86Instruction::writes_memory) - Memory access analysis
#[derive(Debug, Clone)]
pub enum X86Instruction {
    /// Move data: `mov dst, src`
    Mov {
        /// Destination operand
        dst: X86Operand,
        /// Source operand
        src: X86Operand,
    },
    /// Move with zero extension: `movzx dst, src`
    Movzx {
        /// Destination operand
        dst: X86Operand,
        /// Source operand (smaller size, zero-extended)
        src: X86Operand,
    },
    /// Move with sign extension: `movsx dst, src`
    Movsx {
        /// Destination operand
        dst: X86Operand,
        /// Source operand (smaller size, sign-extended)
        src: X86Operand,
    },
    /// Load effective address: `lea dst, [mem]`
    Lea {
        /// Destination register
        dst: X86Register,
        /// Source memory address (computed but not dereferenced)
        src: X86Memory,
    },
    /// Push onto stack: `push src`
    Push {
        /// Value to push onto the stack
        src: X86Operand,
    },
    /// Pop from stack: `pop dst`
    Pop {
        /// Destination register for popped value
        dst: X86Register,
    },
    /// Exchange: `xchg dst, src`
    Xchg {
        /// First operand to exchange
        dst: X86Operand,
        /// Second operand to exchange
        src: X86Operand,
    },

    /// Addition: `add dst, src`
    Add {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand to add
        src: X86Operand,
    },
    /// Subtraction: `sub dst, src`
    Sub {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand to subtract
        src: X86Operand,
    },
    /// Signed multiplication: `imul dst, src` or `imul dst, src, imm`
    Imul {
        /// Destination register for result
        dst: X86Register,
        /// First source operand
        src: X86Operand,
        /// Optional second source for three-operand form
        src2: Option<X86Operand>,
    },
    /// Unsigned multiplication: `mul src` (EDX:EAX = EAX * src)
    Mul {
        /// Source operand (multiplied with EAX/RAX)
        src: X86Operand,
    },
    /// Negate: `neg dst`
    Neg {
        /// Operand to negate (two's complement)
        dst: X86Operand,
    },
    /// Increment: `inc dst`
    Inc {
        /// Operand to increment by one
        dst: X86Operand,
    },
    /// Decrement: `dec dst`
    Dec {
        /// Operand to decrement by one
        dst: X86Operand,
    },

    /// Bitwise AND: `and dst, src`
    And {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand for AND operation
        src: X86Operand,
    },
    /// Bitwise OR: `or dst, src`
    Or {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand for OR operation
        src: X86Operand,
    },
    /// Bitwise XOR: `xor dst, src`
    Xor {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand for XOR operation
        src: X86Operand,
    },
    /// Bitwise NOT: `not dst`
    Not {
        /// Operand to complement (one's complement)
        dst: X86Operand,
    },

    /// Shift left: `shl dst, count`
    Shl {
        /// Operand to shift
        dst: X86Operand,
        /// Shift count (bits to shift)
        count: X86Operand,
    },
    /// Shift right (logical): `shr dst, count`
    Shr {
        /// Operand to shift
        dst: X86Operand,
        /// Shift count (bits to shift)
        count: X86Operand,
    },
    /// Shift right (arithmetic): `sar dst, count`
    Sar {
        /// Operand to shift (sign bit preserved)
        dst: X86Operand,
        /// Shift count (bits to shift)
        count: X86Operand,
    },
    /// Rotate left: `rol dst, count`
    Rol {
        /// Operand to rotate
        dst: X86Operand,
        /// Rotation count (bits to rotate)
        count: X86Operand,
    },
    /// Rotate right: `ror dst, count`
    Ror {
        /// Operand to rotate
        dst: X86Operand,
        /// Rotation count (bits to rotate)
        count: X86Operand,
    },

    /// Compare: `cmp left, right` (computes left - right, sets flags)
    Cmp {
        /// Left operand of comparison
        left: X86Operand,
        /// Right operand of comparison
        right: X86Operand,
    },
    /// Test: `test left, right` (computes left & right, sets flags)
    Test {
        /// Left operand of test
        left: X86Operand,
        /// Right operand of test
        right: X86Operand,
    },

    /// Unconditional jump: `jmp target`
    Jmp {
        /// Absolute target address
        target: u64,
    },
    /// Conditional jump: `jcc target`
    Jcc {
        /// Condition for the jump
        condition: X86Condition,
        /// Absolute target address
        target: u64,
    },
    /// Call: `call target` (for detecting unsupported patterns)
    Call {
        /// Absolute target address
        target: u64,
    },
    /// Return: `ret`
    Ret,

    /// No operation: `nop`
    Nop,
    /// Convert doubleword to quadword: `cdq` (sign-extends EAX into EDX:EAX)
    Cdq,
    /// Convert word to doubleword: `cwde` (sign-extends AX into EAX)
    Cwde,

    /// Add with carry: `adc dst, src` (dst = dst + src + CF)
    Adc {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand to add (plus carry flag)
        src: X86Operand,
    },
    /// Subtract with borrow: `sbb dst, src` (dst = dst - src - CF)
    Sbb {
        /// Destination operand (receives result)
        dst: X86Operand,
        /// Source operand to subtract (plus carry flag)
        src: X86Operand,
    },
    /// Unsigned division: `div src` (EDX:EAX / src → EAX quotient, EDX remainder)
    Div {
        /// Divisor operand
        src: X86Operand,
    },
    /// Signed division: `idiv src` (EDX:EAX / src → EAX quotient, EDX remainder)
    Idiv {
        /// Divisor operand
        src: X86Operand,
    },
    /// Byte swap: `bswap dst` (reverse byte order in 32/64-bit register)
    Bswap {
        /// Register whose bytes are reversed
        dst: X86Register,
    },
    /// Conditional move: `cmovcc dst, src` (move if condition is true)
    Cmovcc {
        /// Condition for the move
        condition: X86Condition,
        /// Destination register
        dst: X86Register,
        /// Source operand (moved only if condition is true)
        src: X86Operand,
    },
    /// Set byte on condition: `setcc dst` (dst = condition ? 1 : 0)
    Setcc {
        /// Condition to test
        condition: X86Condition,
        /// Destination operand (receives 0 or 1)
        dst: X86Operand,
    },
    /// Bit scan forward: `bsf dst, src` (find lowest set bit)
    Bsf {
        /// Destination register (receives bit index)
        dst: X86Register,
        /// Source operand to scan
        src: X86Operand,
    },
    /// Bit scan reverse: `bsr dst, src` (find highest set bit)
    Bsr {
        /// Destination register (receives bit index)
        dst: X86Register,
        /// Source operand to scan
        src: X86Operand,
    },
    /// Bit test: `bt src, bit` (test bit and set CF)
    Bt {
        /// Source operand containing the bit field
        src: X86Operand,
        /// Bit index to test
        bit: X86Operand,
    },
    /// Exchange and add: `xadd dst, src` (temp = dst + src; src = dst; dst = temp)
    Xadd {
        /// Destination operand
        dst: X86Operand,
        /// Source operand
        src: X86Operand,
    },

    /// Unsupported instruction (for graceful degradation)
    Unsupported {
        /// Offset of the instruction in the code
        offset: u64,
        /// Mnemonic name of the unsupported instruction
        mnemonic: String,
    },
}

impl X86Instruction {
    /// Returns true if this instruction transfers control flow.
    #[must_use]
    pub fn is_control_flow(&self) -> bool {
        matches!(
            self,
            X86Instruction::Jmp { .. }
                | X86Instruction::Jcc { .. }
                | X86Instruction::Call { .. }
                | X86Instruction::Ret
        )
    }

    /// Returns true if this is a terminator instruction (ends a basic block).
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            X86Instruction::Jmp { .. }
                | X86Instruction::Jcc { .. }
                | X86Instruction::Call { .. }
                | X86Instruction::Ret
        )
    }

    /// Returns true if this is an unconditional jump.
    #[must_use]
    pub fn is_unconditional_jump(&self) -> bool {
        matches!(self, X86Instruction::Jmp { .. })
    }

    /// Returns true if this is a conditional jump.
    #[must_use]
    pub fn is_conditional_jump(&self) -> bool {
        matches!(self, X86Instruction::Jcc { .. })
    }

    /// Returns the jump targets if this is a jump instruction.
    #[must_use]
    pub fn jump_targets(&self) -> Vec<u64> {
        match self {
            X86Instruction::Jmp { target }
            | X86Instruction::Jcc { target, .. }
            | X86Instruction::Call { target } => vec![*target],
            _ => vec![],
        }
    }

    /// Returns true if this instruction writes to memory.
    #[must_use]
    pub fn writes_memory(&self) -> bool {
        match self {
            X86Instruction::Mov { dst, .. }
            | X86Instruction::Add { dst, .. }
            | X86Instruction::Sub { dst, .. }
            | X86Instruction::And { dst, .. }
            | X86Instruction::Or { dst, .. }
            | X86Instruction::Xor { dst, .. }
            | X86Instruction::Not { dst }
            | X86Instruction::Neg { dst }
            | X86Instruction::Inc { dst }
            | X86Instruction::Dec { dst }
            | X86Instruction::Shl { dst, .. }
            | X86Instruction::Shr { dst, .. }
            | X86Instruction::Sar { dst, .. }
            | X86Instruction::Rol { dst, .. }
            | X86Instruction::Ror { dst, .. }
            | X86Instruction::Adc { dst, .. }
            | X86Instruction::Sbb { dst, .. }
            | X86Instruction::Setcc { dst, .. }
            | X86Instruction::Xadd { dst, .. } => dst.is_memory(),
            X86Instruction::Push { .. } => true, // Writes to stack
            _ => false,
        }
    }

    /// Returns true if this instruction reads from memory.
    #[must_use]
    pub fn reads_memory(&self) -> bool {
        match self {
            X86Instruction::Mov { src, .. }
            | X86Instruction::Movzx { src, .. }
            | X86Instruction::Movsx { src, .. }
            | X86Instruction::Add { src, .. }
            | X86Instruction::Sub { src, .. }
            | X86Instruction::And { src, .. }
            | X86Instruction::Or { src, .. }
            | X86Instruction::Xor { src, .. }
            | X86Instruction::Cmp { right: src, .. }
            | X86Instruction::Test { right: src, .. }
            | X86Instruction::Shl { count: src, .. }
            | X86Instruction::Shr { count: src, .. }
            | X86Instruction::Sar { count: src, .. }
            | X86Instruction::Rol { count: src, .. }
            | X86Instruction::Ror { count: src, .. }
            | X86Instruction::Mul { src }
            | X86Instruction::Div { src }
            | X86Instruction::Idiv { src }
            | X86Instruction::Adc { src, .. }
            | X86Instruction::Sbb { src, .. }
            | X86Instruction::Xadd { src, .. } => src.is_memory(),
            X86Instruction::Imul { src, src2, .. } => {
                src.is_memory() || src2.as_ref().is_some_and(X86Operand::is_memory)
            }
            X86Instruction::Cmovcc { src, .. }
            | X86Instruction::Bsf { src, .. }
            | X86Instruction::Bsr { src, .. } => src.is_memory(),
            X86Instruction::Bt { src, bit } => src.is_memory() || bit.is_memory(),
            X86Instruction::Pop { .. } => true, // Reads from stack
            // LEA doesn't actually read memory
            _ => false,
        }
    }
}

/// A decoded x86 instruction with its location metadata.
///
/// This struct pairs an [`X86Instruction`] with its position in the code,
/// enabling CFG construction and offset-based lookups.
///
/// # Example
///
/// ```
/// use dotscope::analysis::x86_decode_single;
///
/// // push ebp; mov ebp, esp
/// let bytes = [0x55, 0x89, 0xE5];
/// let decoded = x86_decode_single(&bytes, 32, 0x1000, 0)?;
/// println!("Instruction at 0x{:x}, {} bytes", decoded.offset, decoded.length);
/// println!("Next instruction at 0x{:x}", decoded.end_offset());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct X86DecodedInstruction {
    /// Byte offset from the start of the code section.
    pub offset: u64,
    /// Length of the encoded instruction in bytes (1-15 for x86).
    pub length: usize,
    /// The decoded instruction representation.
    pub instruction: X86Instruction,
}

impl X86DecodedInstruction {
    /// Returns the byte offset immediately after this instruction.
    ///
    /// This is equivalent to `offset + length` and represents where the
    /// next sequential instruction would begin.
    #[inline]
    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.offset.saturating_add(self.length as u64)
    }
}

/// Kind of prologue detected in native method code.
///
/// Different obfuscators and calling conventions produce different
/// prologue patterns. Identifying the prologue helps determine where
/// the actual function body begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86PrologueKind {
    /// ConfuserEx DynCipher prologue (20 bytes).
    ///
    /// Handles both 32-bit and 64-bit calling conventions by detecting
    /// whether arguments are passed on the stack or in registers.
    DynCipher,
    /// Standard 32-bit prologue: `push ebp; mov ebp, esp`
    Standard32,
    /// Standard 64-bit prologue: `push rbp; mov rbp, rsp`
    Standard64,
    /// Generic stack frame setup (matched by pattern index).
    ///
    /// Used when a known stack frame pattern is detected but doesn't
    /// match the specific DynCipher or standard prologues.
    StackFrame {
        /// Whether this is a 64-bit pattern.
        is_64bit: bool,
    },
    /// No recognized prologue pattern detected.
    None,
}

/// Information about a detected function prologue.
///
/// A prologue is the sequence of instructions at the start of a function
/// that sets up the stack frame and saves registers.
///
/// # Example
///
/// ```
/// use dotscope::analysis::{x86_detect_prologue, X86PrologueKind};
///
/// // push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret
/// let bytes = [0x55, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
/// let prologue = x86_detect_prologue(&bytes, 32);
/// if prologue.kind == X86PrologueKind::DynCipher {
///     println!("DynCipher function with {} args", prologue.arg_count);
///     let body_start = prologue.size;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct X86PrologueInfo {
    /// The type of prologue pattern detected.
    pub kind: X86PrologueKind,
    /// Size of the prologue in bytes (offset to function body).
    pub size: usize,
    /// Number of arguments, if detectable from the prologue.
    pub arg_count: usize,
}

/// Information about a detected function epilogue.
///
/// An epilogue is the sequence of instructions at the end of a function
/// that restores saved registers and returns to the caller.
#[derive(Debug, Clone)]
pub struct X86EpilogueInfo {
    /// Byte offset where the epilogue sequence begins.
    pub offset: u64,
    /// Size of the epilogue in bytes.
    pub size: usize,
}

/// The kind of control flow represented by an x86 CFG edge.
///
/// This enum classifies edges by their control flow semantics, providing
/// information needed for analysis and optimization passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X86EdgeKind {
    /// Unconditional control flow (direct jump or fall-through).
    Unconditional,

    /// Conditional branch taken (condition evaluates to true).
    ConditionalTrue {
        /// The condition that must be true for this edge.
        condition: X86Condition,
    },

    /// Conditional branch not taken (fall-through when condition is false).
    ConditionalFalse {
        /// The condition that must be false for this edge.
        condition: X86Condition,
    },

    /// Call instruction edge (control returns after call).
    Call {
        /// Target address of the call.
        target: u64,
    },

    /// Indirect jump (target computed at runtime).
    ///
    /// These edges indicate unresolved control flow that may require
    /// additional analysis or emulation to resolve.
    IndirectJump,

    /// Return from function (exit edge).
    Return,
}

impl X86EdgeKind {
    /// Returns `true` if this is a conditional branch edge.
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(
            self,
            X86EdgeKind::ConditionalTrue { .. } | X86EdgeKind::ConditionalFalse { .. }
        )
    }

    /// Returns `true` if this is an unconditional edge.
    #[must_use]
    pub const fn is_unconditional(&self) -> bool {
        matches!(self, X86EdgeKind::Unconditional)
    }

    /// Returns `true` if this is a call edge.
    #[must_use]
    pub const fn is_call(&self) -> bool {
        matches!(self, X86EdgeKind::Call { .. })
    }

    /// Returns `true` if this represents unresolved control flow.
    #[must_use]
    pub const fn is_indirect(&self) -> bool {
        matches!(self, X86EdgeKind::IndirectJump)
    }

    /// Returns `true` if this is a return edge.
    #[must_use]
    pub const fn is_return(&self) -> bool {
        matches!(self, X86EdgeKind::Return)
    }
}

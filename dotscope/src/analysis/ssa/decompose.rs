//! CIL instruction decomposition to SSA operations.
//!
//! This module converts CIL instructions to decomposed `SsaOp` form where each
//! operation follows the `result = op(operands)` pattern. This transformation
//! is essential for optimization passes that need clean, explicit data flow.
//!
//! # Design
//!
//! The decomposition process:
//! 1. Takes a CIL instruction and its stack simulation results (uses, def)
//! 2. Extracts operand information (tokens, immediates, etc.)
//! 3. Constructs the appropriate `SsaOp` variant
//!
//! # Error Handling
//!
//! Returns an error for:
//! - Unknown/unsupported opcodes (not in ECMA-335)
//! - Missing operands that should have been provided by stack simulation
//!
//! # Handling Constants
//!
//! CIL constant loading instructions (ldc.i4, ldc.i8, etc.) are converted to
//! `SsaOp::Const` with the appropriate `ConstValue`.

// Branch targets in CIL use u64 (RVA) but block indices use usize.
// On 32-bit targets this could truncate, but RVAs in .NET are always 32-bit.
#![allow(clippy::cast_possible_truncation)]

use crate::{
    analysis::ssa::{
        ops::{BreakpointOp, CmpKind, SsaOp},
        types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
        value::ConstValue,
        SsaVarId,
    },
    assembly::{Immediate, Instruction, Operand},
    metadata::{cilobject::CilObject, token::Token},
    Error, Result,
};

/// Decomposes a CIL instruction into an SSA operation.
///
/// # Arguments
///
/// * `instr` - The CIL instruction to decompose
/// * `uses` - SSA variables consumed by this instruction (from stack simulation)
/// * `def` - SSA variable produced by this instruction (if any)
/// * `successors` - Block indices for branch targets (for conditional branches: [branch_target, fallthrough])
/// * `assembly` - Optional assembly reference for resolving type tokens
///
/// # Returns
///
/// The decomposed `SsaOp`.
///
/// # Errors
///
/// Returns an error if the opcode is unknown/unsupported or if required operands are missing.
pub fn decompose_instruction(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
    successors: &[usize],
    assembly: Option<&CilObject>,
) -> Result<SsaOp> {
    // Handle FE-prefixed instructions
    if instr.prefix == 0xFE {
        return decompose_fe_instruction(instr, uses, def);
    }

    decompose_standard_instruction(instr, uses, def, successors, assembly)
}

/// Decomposes a standard (non-prefixed) CIL instruction.
fn decompose_standard_instruction(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
    successors: &[usize],
    assembly: Option<&CilObject>,
) -> Result<SsaOp> {
    let result = match instr.opcode {
        0x14 => {
            // ldnull
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::Null,
            })
        }
        0x15 => {
            // ldc.i4.m1
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(-1),
            })
        }
        0x16 => {
            // ldc.i4.0
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(0),
            })
        }
        0x17 => {
            // ldc.i4.1
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(1),
            })
        }
        0x18 => {
            // ldc.i4.2
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(2),
            })
        }
        0x19 => {
            // ldc.i4.3
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(3),
            })
        }
        0x1A => {
            // ldc.i4.4
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(4),
            })
        }
        0x1B => {
            // ldc.i4.5
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(5),
            })
        }
        0x1C => {
            // ldc.i4.6
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(6),
            })
        }
        0x1D => {
            // ldc.i4.7
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(7),
            })
        }
        0x1E => {
            // ldc.i4.8
            def.map(|dest| SsaOp::Const {
                dest,
                value: ConstValue::I32(8),
            })
        }
        0x1F => {
            // ldc.i4.s
            def.and_then(|dest| {
                extract_i32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I32(v),
                })
            })
        }
        0x20 => {
            // ldc.i4
            def.and_then(|dest| {
                extract_i32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I32(v),
                })
            })
        }
        0x21 => {
            // ldc.i8
            def.and_then(|dest| {
                extract_i64(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::I64(v),
                })
            })
        }
        0x22 => {
            // ldc.r4
            def.and_then(|dest| {
                extract_f32(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::from(v),
                })
            })
        }
        0x23 => {
            // ldc.r8
            def.and_then(|dest| {
                extract_f64(&instr.operand).map(|v| SsaOp::Const {
                    dest,
                    value: ConstValue::from(v),
                })
            })
        }
        0x25 => {
            // dup
            if let (Some(src), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::Copy { dest, src: *src })
            } else {
                None
            }
        }
        0x26 => {
            // pop
            uses.first().map(|&value| SsaOp::Pop { value })
        }
        0x58 => binary_op(uses, def, |dest, left, right| SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        }), // add
        0x59 => binary_op(uses, def, |dest, left, right| SsaOp::Sub {
            dest,
            left,
            right,
            flags: None,
        }), // sub
        0x5A => binary_op(uses, def, |dest, left, right| SsaOp::Mul {
            dest,
            left,
            right,
            flags: None,
        }), // mul
        0x5B => binary_op(uses, def, |dest, left, right| SsaOp::Div {
            // div
            dest,
            left,
            right,
            unsigned: false,
            flags: None,
        }),
        0x5C => binary_op(uses, def, |dest, left, right| SsaOp::Div {
            // div.un
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        }),
        0x5D => binary_op(uses, def, |dest, left, right| SsaOp::Rem {
            // rem
            dest,
            left,
            right,
            unsigned: false,
            flags: None,
        }),
        0x5E => binary_op(uses, def, |dest, left, right| SsaOp::Rem {
            // rem.un
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        }),

        0x65 => unary_op(uses, def, |dest, operand| SsaOp::Neg {
            dest,
            operand,
            flags: None,
        }), // neg
        0x66 => unary_op(uses, def, |dest, operand| SsaOp::Not {
            dest,
            operand,
            flags: None,
        }), // not

        // Overflow checking arithmetic
        0xD6 => binary_op(uses, def, |dest, left, right| SsaOp::AddOvf {
            // add.ovf
            dest,
            left,
            right,
            unsigned: false,
            flags: None,
        }),
        0xD7 => binary_op(uses, def, |dest, left, right| SsaOp::AddOvf {
            // add.ovf.un
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        }),
        0xD8 => binary_op(uses, def, |dest, left, right| SsaOp::MulOvf {
            // mul.ovf
            dest,
            left,
            right,
            unsigned: false,
            flags: None,
        }),
        0xD9 => binary_op(uses, def, |dest, left, right| SsaOp::MulOvf {
            // mul.ovf.un
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        }),
        0xDA => binary_op(uses, def, |dest, left, right| SsaOp::SubOvf {
            // sub.ovf
            dest,
            left,
            right,
            unsigned: false,
            flags: None,
        }),
        0xDB => binary_op(uses, def, |dest, left, right| SsaOp::SubOvf {
            // sub.ovf.un
            dest,
            left,
            right,
            unsigned: true,
            flags: None,
        }),
        0x5F => binary_op(uses, def, |dest, left, right| SsaOp::And {
            dest,
            left,
            right,
            flags: None,
        }), // and
        0x60 => binary_op(uses, def, |dest, left, right| SsaOp::Or {
            dest,
            left,
            right,
            flags: None,
        }), // or
        0x61 => binary_op(uses, def, |dest, left, right| SsaOp::Xor {
            dest,
            left,
            right,
            flags: None,
        }), // xor
        0x62 => binary_op(uses, def, |dest, value, amount| SsaOp::Shl {
            // shl
            dest,
            value,
            amount,
            flags: None,
        }),
        0x63 => binary_op(uses, def, |dest, value, amount| SsaOp::Shr {
            // shr
            dest,
            value,
            amount,
            unsigned: false,
            flags: None,
        }),
        0x64 => binary_op(uses, def, |dest, value, amount| SsaOp::Shr {
            // shr.un
            dest,
            value,
            amount,
            unsigned: true,
            flags: None,
        }),
        0x67 => unary_op(uses, def, |dest, operand| {
            // conv.i1
            SsaOp::conversion_between(dest, operand, SsaType::I8, None, false, false)
        }),
        0x68 => unary_op(uses, def, |dest, operand| {
            // conv.i2
            SsaOp::conversion_between(dest, operand, SsaType::I16, None, false, false)
        }),
        0x69 => unary_op(uses, def, |dest, operand| {
            // conv.i4
            SsaOp::conversion_between(dest, operand, SsaType::I32, None, false, false)
        }),
        0x6A => unary_op(uses, def, |dest, operand| {
            // conv.i8
            SsaOp::conversion_between(dest, operand, SsaType::I64, None, false, false)
        }),
        0x6B => unary_op(uses, def, |dest, operand| {
            // conv.r4
            SsaOp::conversion_between(dest, operand, SsaType::F32, None, false, false)
        }),
        0x6C => unary_op(uses, def, |dest, operand| {
            // conv.r8
            SsaOp::conversion_between(dest, operand, SsaType::F64, None, false, false)
        }),
        0xD1 => unary_op(uses, def, |dest, operand| {
            // conv.u2
            SsaOp::conversion_between(dest, operand, SsaType::U16, None, true, false)
        }),
        0xD2 => unary_op(uses, def, |dest, operand| {
            // conv.u1
            SsaOp::conversion_between(dest, operand, SsaType::U8, None, true, false)
        }),
        0x6D => unary_op(uses, def, |dest, operand| {
            // conv.u4
            SsaOp::conversion_between(dest, operand, SsaType::U32, None, true, false)
        }),
        0x6E => unary_op(uses, def, |dest, operand| {
            // conv.u8
            SsaOp::conversion_between(dest, operand, SsaType::U64, None, true, false)
        }),
        0xD3 => unary_op(uses, def, |dest, operand| {
            // conv.i
            SsaOp::conversion_between(dest, operand, SsaType::NativeInt, None, false, false)
        }),
        0xE0 => unary_op(uses, def, |dest, operand| {
            // conv.u
            SsaOp::conversion_between(dest, operand, SsaType::NativeUInt, None, true, false)
        }),
        0x76 => unary_op(uses, def, |dest, operand| {
            // conv.r.un
            SsaOp::conversion_between(dest, operand, SsaType::F64, None, true, false)
        }),

        // Overflow-checking conversions
        0xB3 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i1
            SsaOp::conversion_between(dest, operand, SsaType::I8, None, false, true)
        }),
        0x82 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i1.un
            SsaOp::conversion_between(dest, operand, SsaType::I8, None, true, true)
        }),
        0xB5 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i2
            SsaOp::conversion_between(dest, operand, SsaType::I16, None, false, true)
        }),
        0x83 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i2.un
            SsaOp::conversion_between(dest, operand, SsaType::I16, None, true, true)
        }),
        0xB7 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i4
            SsaOp::conversion_between(dest, operand, SsaType::I32, None, false, true)
        }),
        0x84 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i4.un
            SsaOp::conversion_between(dest, operand, SsaType::I32, None, true, true)
        }),
        0xB9 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i8
            SsaOp::conversion_between(dest, operand, SsaType::I64, None, false, true)
        }),
        0x85 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i8.un
            SsaOp::conversion_between(dest, operand, SsaType::I64, None, true, true)
        }),
        0xD4 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i
            SsaOp::conversion_between(dest, operand, SsaType::NativeInt, None, false, true)
        }),
        0x8A => unary_op(uses, def, |dest, operand| {
            // conv.ovf.i.un
            SsaOp::conversion_between(dest, operand, SsaType::NativeInt, None, true, true)
        }),
        0xB4 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u1
            SsaOp::conversion_between(dest, operand, SsaType::U8, None, false, true)
        }),
        0x86 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u1.un
            SsaOp::conversion_between(dest, operand, SsaType::U8, None, true, true)
        }),
        0xB6 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u2
            SsaOp::conversion_between(dest, operand, SsaType::U16, None, false, true)
        }),
        0x87 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u2.un
            SsaOp::conversion_between(dest, operand, SsaType::U16, None, true, true)
        }),
        0xB8 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u4
            SsaOp::conversion_between(dest, operand, SsaType::U32, None, false, true)
        }),
        0x88 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u4.un
            SsaOp::conversion_between(dest, operand, SsaType::U32, None, true, true)
        }),
        0xBA => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u8
            SsaOp::conversion_between(dest, operand, SsaType::U64, None, false, true)
        }),
        0x89 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u8.un
            SsaOp::conversion_between(dest, operand, SsaType::U64, None, true, true)
        }),
        0xD5 => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u
            SsaOp::conversion_between(dest, operand, SsaType::NativeUInt, None, false, true)
        }),
        0x8B => unary_op(uses, def, |dest, operand| {
            // conv.ovf.u.un
            SsaOp::conversion_between(dest, operand, SsaType::NativeUInt, None, true, true)
        }),
        0x2A => Some(SsaOp::Return {
            // ret
            value: uses.first().copied(),
        }),
        // Unconditional branches
        0x2B | 0x38 => {
            // br.s, br
            // For unconditional jumps, there's only one successor
            successors.first().map(|&target| SsaOp::Jump { target })
        }
        // Conditional branches (with single operand)
        0x2C | 0x39 => {
            // brfalse.s, brfalse
            // For conditional branches, successors[0] is the branch target, successors[1] is fallthrough
            uses.first().and_then(|&condition| {
                let target = successors.first().copied()?;
                let fallthrough = successors.get(1).copied()?;
                // brfalse: jumps to target if false, falls through if true
                Some(SsaOp::Branch {
                    condition,
                    true_target: fallthrough,
                    false_target: target,
                })
            })
        }
        0x2D | 0x3A => {
            // brtrue.s, brtrue
            // For conditional branches, successors[0] is the branch target, successors[1] is fallthrough
            uses.first().and_then(|&condition| {
                let target = successors.first().copied()?;
                let fallthrough = successors.get(1).copied()?;
                // brtrue: jumps to target if true, falls through if false
                Some(SsaOp::Branch {
                    condition,
                    true_target: target,
                    false_target: fallthrough,
                })
            })
        }

        // Binary conditional branches
        0x2E | 0x3B => {
            // beq.s, beq
            comparison_branch(uses, successors, CmpKind::Eq, false)
        }
        0x2F | 0x3C => {
            // bge.s, bge
            comparison_branch(uses, successors, CmpKind::Ge, false)
        }
        0x30 | 0x3D => {
            // bgt.s, bgt
            comparison_branch(uses, successors, CmpKind::Gt, false)
        }
        0x31 | 0x3E => {
            // ble.s, ble
            comparison_branch(uses, successors, CmpKind::Le, false)
        }
        0x32 | 0x3F => {
            // blt.s, blt
            comparison_branch(uses, successors, CmpKind::Lt, false)
        }
        0x33 | 0x40 => {
            // bne.un.s, bne.un
            comparison_branch(uses, successors, CmpKind::Ne, true)
        }
        0x34 | 0x41 => {
            // bge.un.s, bge.un
            comparison_branch(uses, successors, CmpKind::Ge, true)
        }
        0x35 | 0x42 => {
            // bgt.un.s, bgt.un
            comparison_branch(uses, successors, CmpKind::Gt, true)
        }
        0x36 | 0x43 => {
            // ble.un.s, ble.un
            comparison_branch(uses, successors, CmpKind::Le, true)
        }
        0x37 | 0x44 => {
            // blt.un.s, blt.un
            comparison_branch(uses, successors, CmpKind::Lt, true)
        }

        0x45 => {
            // switch
            // For switch, successors contains all the case targets followed by the default
            uses.first().and_then(|&value| {
                if successors.len() >= 2 {
                    // Last successor is the default, rest are case targets
                    let last_idx = successors.len().checked_sub(1)?;
                    let default = successors.get(last_idx).copied().unwrap_or(0);
                    let targets: Vec<usize> = successors.get(..last_idx)?.to_vec();
                    Some(SsaOp::Switch {
                        value,
                        targets,
                        default,
                    })
                } else {
                    None
                }
            })
        }

        0xDD => {
            // leave.s
            // For leave, there's a single successor
            successors.first().map(|&target| SsaOp::Leave { target })
        }
        0xDE => {
            // leave
            successors.first().map(|&target| SsaOp::Leave { target })
        }

        // Load/Store arguments and locals
        // ldarg and ldloc produce a LoadArg/LoadLocal op with the new stack
        // variable allocated by the simulator as dest. This makes them visible
        // to SSA analysis and enables correct data flow through rebuild_ssa.
        0x02 => def.map(|dest| SsaOp::LoadArg { dest, arg_index: 0 }), // ldarg.0
        0x03 => def.map(|dest| SsaOp::LoadArg { dest, arg_index: 1 }), // ldarg.1
        0x04 => def.map(|dest| SsaOp::LoadArg { dest, arg_index: 2 }), // ldarg.2
        0x05 => def.map(|dest| SsaOp::LoadArg { dest, arg_index: 3 }), // ldarg.3
        0x0E => {
            // ldarg.s
            def.and_then(|dest| {
                extract_u16(&instr.operand).map(|arg_index| SsaOp::LoadArg { dest, arg_index })
            })
        }
        0x06 => def.map(|dest| SsaOp::LoadLocal {
            dest,
            local_index: 0,
        }), // ldloc.0
        0x07 => def.map(|dest| SsaOp::LoadLocal {
            dest,
            local_index: 1,
        }), // ldloc.1
        0x08 => def.map(|dest| SsaOp::LoadLocal {
            dest,
            local_index: 2,
        }), // ldloc.2
        0x09 => def.map(|dest| SsaOp::LoadLocal {
            dest,
            local_index: 3,
        }), // ldloc.3
        0x11 => {
            // ldloc.s
            def.and_then(|dest| {
                extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocal { dest, local_index })
            })
        }
        0x0A..=0x0D | 0x13 => {
            // stloc.0-3, stloc.s
            // Generate Copy op to enable constant propagation through locals
            match (def, uses.first()) {
                (Some(dest), Some(&src)) => Some(SsaOp::Copy { dest, src }),
                _ => None,
            }
        }
        0x0F => {
            // ldarga.s
            def.and_then(|dest| {
                extract_u16(&instr.operand).map(|arg_index| SsaOp::LoadArgAddr { dest, arg_index })
            })
        }
        0x10 => {
            // starg.s - Generate Copy op
            match (def, uses.first()) {
                (Some(dest), Some(&src)) => Some(SsaOp::Copy { dest, src }),
                _ => None,
            }
        }
        0x12 => {
            // ldloca.s
            def.and_then(|dest| {
                extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocalAddr { dest, local_index })
            })
        }

        // Object operations
        0x6F => {
            // callvirt
            call_op(instr, uses, def, true)
        }
        0x28 => {
            // call
            call_op(instr, uses, def, false)
        }
        0x29 => {
            // calli
            if let Some(signature) = extract_signature_token(&instr.operand) {
                let (fptr, args) = if let Some(&fptr) = uses.last() {
                    let last_idx = uses.len().saturating_sub(1);
                    let args = uses
                        .get(..last_idx)
                        .map(<[SsaVarId]>::to_vec)
                        .unwrap_or_default();
                    (fptr, args)
                } else {
                    (SsaVarId::from_index(0), vec![])
                };
                Some(SsaOp::CallIndirect {
                    dest: def,
                    fptr,
                    signature,
                    args,
                    effects: None,
                })
            } else {
                None
            }
        }

        0x73 => {
            // newobj
            if let Some(ctor) = extract_method_token(&instr.operand) {
                def.map(|dest| SsaOp::NewObj {
                    dest,
                    ctor,
                    args: uses.to_vec(),
                })
            } else {
                None
            }
        }
        0x8D => {
            // newarr
            if let (Some(elem_type), Some(&length), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::NewArr {
                    dest,
                    elem_type,
                    length,
                })
            } else {
                None
            }
        }

        0x74 => {
            // castclass
            if let (Some(target_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::CastClass {
                    dest,
                    object,
                    target_type,
                })
            } else {
                None
            }
        }
        0x75 => {
            // isinst
            if let (Some(target_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::IsInst {
                    dest,
                    object,
                    target_type,
                })
            } else {
                None
            }
        }

        0x8C => {
            // box
            if let (Some(value_type), Some(&value), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::Box {
                    dest,
                    value,
                    value_type,
                })
            } else {
                None
            }
        }
        0x79 => {
            // unbox
            if let (Some(value_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::Unbox {
                    dest,
                    object,
                    value_type,
                })
            } else {
                None
            }
        }
        0xA5 => {
            // unbox.any
            if let (Some(value_type), Some(&object), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::UnboxAny {
                    dest,
                    object,
                    value_type,
                })
            } else {
                None
            }
        }

        // Field operations
        0x7B => {
            // ldfld
            if let (Some(field), Some(&object), Some(dest)) =
                (extract_field_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadField {
                    dest,
                    object,
                    field,
                })
            } else {
                None
            }
        }
        0x7D => {
            // stfld
            if let (Some(field), Some(object), Some(value)) = (
                extract_field_token(&instr.operand),
                uses.first(),
                uses.get(1),
            ) {
                Some(SsaOp::StoreField {
                    object: *object,
                    field,
                    value: *value,
                })
            } else {
                None
            }
        }
        0x7C => {
            // ldflda
            if let (Some(field), Some(&object), Some(dest)) =
                (extract_field_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadFieldAddr {
                    dest,
                    object,
                    field,
                })
            } else {
                None
            }
        }
        0x7E => {
            // ldsfld
            if let (Some(field), Some(dest)) = (extract_field_token(&instr.operand), def) {
                Some(SsaOp::LoadStaticField { dest, field })
            } else {
                None
            }
        }
        0x80 => {
            // stsfld
            if let (Some(field), Some(&value)) = (extract_field_token(&instr.operand), uses.first())
            {
                Some(SsaOp::StoreStaticField { field, value })
            } else {
                None
            }
        }
        0x7F => {
            // ldsflda
            if let (Some(field), Some(dest)) = (extract_field_token(&instr.operand), def) {
                Some(SsaOp::LoadStaticFieldAddr { dest, field })
            } else {
                None
            }
        }

        // Array operations
        0x8E => {
            // ldlen
            if let (Some(&array), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::ArrayLength { dest, array })
            } else {
                None
            }
        }
        0x8F => {
            // ldelema
            if let (Some(&array), Some(&index), Some(dest), Some(elem_type)) = (
                uses.first(),
                uses.get(1),
                def,
                extract_type_token(&instr.operand),
            ) {
                Some(SsaOp::LoadElementAddr {
                    dest,
                    array,
                    index,
                    elem_type,
                })
            } else {
                None
            }
        }

        // ldelem variants
        0xA3 => {
            // ldelem
            ldelem_op(uses, def, &instr.operand, assembly)
        }
        0x90 => ldelem_typed(uses, def, SsaType::I8), // ldelem.i1
        0x91 => ldelem_typed(uses, def, SsaType::U8), // ldelem.u1
        0x92 => ldelem_typed(uses, def, SsaType::I16), // ldelem.i2
        0x93 => ldelem_typed(uses, def, SsaType::U16), // ldelem.u2
        0x94 => ldelem_typed(uses, def, SsaType::I32), // ldelem.i4
        0x95 => ldelem_typed(uses, def, SsaType::U32), // ldelem.u4
        0x96 => ldelem_typed(uses, def, SsaType::I64), // ldelem.i8
        0x97 => ldelem_typed(uses, def, SsaType::NativeInt), // ldelem.i
        0x98 => ldelem_typed(uses, def, SsaType::F32), // ldelem.r4
        0x99 => ldelem_typed(uses, def, SsaType::F64), // ldelem.r8
        0x9A => ldelem_typed(uses, def, SsaType::Object), // ldelem.ref

        // stelem variants
        0xA4 => {
            // stelem
            stelem_op(uses, &instr.operand, assembly)
        }
        0x9C => stelem_typed(uses, SsaType::I8), // stelem.i1
        0x9D => stelem_typed(uses, SsaType::I16), // stelem.i2
        0x9E => stelem_typed(uses, SsaType::I32), // stelem.i4
        0x9F => stelem_typed(uses, SsaType::I64), // stelem.i8
        0xA0 => stelem_typed(uses, SsaType::F32), // stelem.r4
        0xA1 => stelem_typed(uses, SsaType::F64), // stelem.r8
        0xA2 => stelem_typed(uses, SsaType::Object), // stelem.ref
        0x9B => stelem_typed(uses, SsaType::NativeInt), // stelem.i

        // Indirect access (ldind/stind)
        0x46 => ldind_typed(uses, def, SsaType::I8), // ldind.i1
        0x47 => ldind_typed(uses, def, SsaType::U8), // ldind.u1
        0x48 => ldind_typed(uses, def, SsaType::I16), // ldind.i2
        0x49 => ldind_typed(uses, def, SsaType::U16), // ldind.u2
        0x4A => ldind_typed(uses, def, SsaType::I32), // ldind.i4
        0x4B => ldind_typed(uses, def, SsaType::U32), // ldind.u4
        0x4C => ldind_typed(uses, def, SsaType::I64), // ldind.i8
        0x4D => ldind_typed(uses, def, SsaType::NativeInt), // ldind.i
        0x4E => ldind_typed(uses, def, SsaType::F32), // ldind.r4
        0x4F => ldind_typed(uses, def, SsaType::F64), // ldind.r8
        0x50 => ldind_typed(uses, def, SsaType::Object), // ldind.ref

        0x52 => stind_typed(uses, SsaType::I8),  // stind.i1
        0x53 => stind_typed(uses, SsaType::I16), // stind.i2
        0x54 => stind_typed(uses, SsaType::I32), // stind.i4
        0x55 => stind_typed(uses, SsaType::I64), // stind.i8
        0x56 => stind_typed(uses, SsaType::F32), // stind.r4
        0x57 => stind_typed(uses, SsaType::F64), // stind.r8
        0x51 => stind_typed(uses, SsaType::Object), // stind.ref
        0xDF => stind_typed(uses, SsaType::NativeInt), // stind.i

        // Object memory operations
        0x71 => {
            // ldobj
            if let (Some(&src_addr), Some(dest)) = (uses.first(), def) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::LoadObj {
                    dest,
                    src_addr,
                    value_type,
                })
            } else {
                None
            }
        }
        0x81 => {
            // stobj
            if let (Some(&dest_addr), Some(&value)) = (uses.first(), uses.get(1)) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::StoreObj {
                    dest_addr,
                    value,
                    value_type,
                })
            } else {
                None
            }
        }
        0x70 => {
            // cpobj
            if let (Some(&dest_addr), Some(&src_addr)) = (uses.first(), uses.get(1)) {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::CopyObj {
                    dest_addr,
                    src_addr,
                    value_type,
                })
            } else {
                None
            }
        }

        // Exception handling
        0x7A => {
            // throw
            uses.first().map(|&exception| SsaOp::Throw { exception })
        }
        // rethrow is FE 1A
        // endfinally is DC
        0xDC => Some(SsaOp::EndFinally), // endfinally

        // Misc
        0x00 => Some(SsaOp::Nop), // nop
        // CIL `break` is a debugger breakpoint, the same operation MIPS
        // spells `break`.
        0x01 => Some(SsaOp::Break(BreakpointOp::Breakpoint)),

        0x72 => {
            // ldstr
            def.and_then(|dest| {
                extract_string_token(&instr.operand).map(|idx| SsaOp::Const {
                    dest,
                    value: ConstValue::String(idx),
                })
            })
        }
        0xD0 => {
            // ldtoken
            def.and_then(|dest| {
                extract_type_token(&instr.operand).map(|token| SsaOp::LoadToken { dest, token })
            })
        }

        0xC3 => {
            // ckfinite
            if let (Some(&operand), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::Ckfinite { dest, operand })
            } else {
                None
            }
        }

        0xC2 => {
            // refanyval
            if let (Some(value_type), Some(&typed_ref), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::TypedRefValue {
                    dest,
                    typed_ref,
                    value_type,
                })
            } else {
                None
            }
        }

        0xC6 => {
            // mkrefany
            if let (Some(value_type), Some(&address), Some(dest)) =
                (extract_type_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::MakeTypedRef {
                    dest,
                    address,
                    value_type,
                })
            } else {
                None
            }
        }

        // Default: unknown opcode
        _ => {
            return Err(Error::SsaError(format!(
                "Unknown opcode 0x{:02X} ({}) at RVA 0x{:08X}",
                instr.opcode, instr.mnemonic, instr.rva
            )));
        }
    };

    result.ok_or_else(|| {
        Error::SsaError(format!(
            "Failed to decompose instruction {} (0x{:02X}) at RVA 0x{:08X}: missing operands (uses={}, def={:?})",
            instr.mnemonic, instr.opcode, instr.rva, uses.len(), def
        ))
    })
}

/// Decomposes FE-prefixed instructions.
fn decompose_fe_instruction(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
) -> Result<SsaOp> {
    let result = match instr.opcode {
        // Comparison operations
        0x00 => def.map(|dest| SsaOp::ArgList { dest }), // arglist
        0x1D => {
            // refanytype
            if let (Some(&typed_ref), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::TypedRefType { dest, typed_ref })
            } else {
                None
            }
        }
        0x01 => binary_op(uses, def, |dest, left, right| SsaOp::Ceq {
            dest,
            left,
            right,
        }), // ceq
        0x02 => binary_op(uses, def, |dest, left, right| SsaOp::Cgt {
            // cgt
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x03 => binary_op(uses, def, |dest, left, right| SsaOp::Cgt {
            // cgt.un
            dest,
            left,
            right,
            unsigned: true,
        }),
        0x04 => binary_op(uses, def, |dest, left, right| SsaOp::Clt {
            // clt
            dest,
            left,
            right,
            unsigned: false,
        }),
        0x05 => binary_op(uses, def, |dest, left, right| SsaOp::Clt {
            // clt.un
            dest,
            left,
            right,
            unsigned: true,
        }),

        // Function pointers
        0x06 => {
            // ldftn
            if let (Some(method), Some(dest)) = (extract_method_token(&instr.operand), def) {
                Some(SsaOp::LoadFunctionPtr { dest, method })
            } else {
                None
            }
        }
        0x07 => {
            // ldvirtftn
            if let (Some(method), Some(&object), Some(dest)) =
                (extract_method_token(&instr.operand), uses.first(), def)
            {
                Some(SsaOp::LoadVirtFunctionPtr {
                    dest,
                    object,
                    method,
                })
            } else {
                None
            }
        }

        // Argument/Local long forms
        0x09 => {
            // ldarg (long form)
            def.and_then(|dest| {
                extract_u16(&instr.operand).map(|arg_index| SsaOp::LoadArg { dest, arg_index })
            })
        }
        0x0A => {
            // ldarga
            def.and_then(|dest| {
                extract_u16(&instr.operand).map(|arg_index| SsaOp::LoadArgAddr { dest, arg_index })
            })
        }
        0x0B => {
            // starg (long form) - Generate Copy op
            match (def, uses.first()) {
                (Some(dest), Some(&src)) => Some(SsaOp::Copy { dest, src }),
                _ => None,
            }
        }
        0x0C => {
            // ldloc (long form)
            def.and_then(|dest| {
                extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocal { dest, local_index })
            })
        }
        0x0D => {
            // ldloca
            def.and_then(|dest| {
                extract_u16(&instr.operand)
                    .map(|local_index| SsaOp::LoadLocalAddr { dest, local_index })
            })
        }
        0x0E => {
            // stloc (long form) - Generate Copy op
            match (def, uses.first()) {
                (Some(dest), Some(&src)) => Some(SsaOp::Copy { dest, src }),
                _ => None,
            }
        }

        // Memory operations
        0x15 => {
            // initobj
            if let Some(&dest_addr) = uses.first() {
                let value_type = extract_type_token(&instr.operand)
                    .unwrap_or_else(|| TypeRef::new(Token::new(0)));
                Some(SsaOp::InitObj {
                    dest_addr,
                    value_type,
                })
            } else {
                None
            }
        }
        0x17 => {
            // cpblk
            if let (Some(&dest_addr), Some(&src_addr), Some(&size)) =
                (uses.first(), uses.get(1), uses.get(2))
            {
                Some(SsaOp::CopyBlk {
                    dest_addr,
                    src_addr,
                    size,
                    // CIL `cpblk` is always forward (no direction flag).
                    reverse: false,
                })
            } else {
                None
            }
        }
        0x18 => {
            // initblk
            if let (Some(&dest_addr), Some(&value), Some(&size)) =
                (uses.first(), uses.get(1), uses.get(2))
            {
                Some(SsaOp::InitBlk {
                    dest_addr,
                    value,
                    size,
                    // CIL `initblk` is always forward (no direction flag).
                    reverse: false,
                })
            } else {
                None
            }
        }

        // Exception handling
        0x1A => Some(SsaOp::Rethrow), // rethrow
        0x11 => {
            // endfilter
            uses.first().map(|&result| SsaOp::EndFilter { result })
        }

        // Allocation
        0x0F => {
            // localloc
            if let (Some(&size), Some(dest)) = (uses.first(), def) {
                Some(SsaOp::LocalAlloc { dest, size })
            } else {
                None
            }
        }

        // Sizeof
        0x1C => {
            // sizeof
            if let (Some(value_type), Some(dest)) = (extract_type_token(&instr.operand), def) {
                Some(SsaOp::SizeOf { dest, value_type })
            } else {
                None
            }
        }

        // Prefix instructions
        0x12 => {
            // unaligned. - carries alignment operand (1, 2, or 4)
            let alignment = extract_u8(&instr.operand).unwrap_or(1);
            Some(SsaOp::Unaligned { alignment })
        }
        0x13 => Some(SsaOp::Volatile),   // volatile.
        0x14 => Some(SsaOp::TailPrefix), // tail.
        0x16 => extract_type_token(&instr.operand)
            .map(|constraint_type| SsaOp::Constrained { constraint_type }), // constrained.
        0x1E => Some(SsaOp::Readonly),   // readonly.

        // Default: unknown FE-prefixed opcode
        _ => {
            return Err(Error::SsaError(format!(
                "Unknown FE-prefixed opcode 0xFE 0x{:02X} ({}) at RVA 0x{:08X}",
                instr.opcode, instr.mnemonic, instr.rva
            )));
        }
    };

    result.ok_or_else(|| {
        Error::SsaError(format!(
            "Failed to decompose FE instruction {} (0xFE 0x{:02X}) at RVA 0x{:08X}: missing operands (uses={}, def={:?})",
            instr.mnemonic, instr.opcode, instr.rva, uses.len(), def
        ))
    })
}

fn binary_op<F>(uses: &[SsaVarId], def: Option<SsaVarId>, f: F) -> Option<SsaOp>
where
    F: FnOnce(SsaVarId, SsaVarId, SsaVarId) -> SsaOp,
{
    if let (Some(&left), Some(&right), Some(dest)) = (uses.first(), uses.get(1), def) {
        Some(f(dest, left, right))
    } else {
        None
    }
}

fn unary_op<F>(uses: &[SsaVarId], def: Option<SsaVarId>, f: F) -> Option<SsaOp>
where
    F: FnOnce(SsaVarId, SsaVarId) -> SsaOp,
{
    if let (Some(&operand), Some(dest)) = (uses.first(), def) {
        Some(f(dest, operand))
    } else {
        None
    }
}

/// Creates a combined compare-and-branch SSA operation.
///
/// CIL comparison branch instructions (beq, blt, bgt, etc.) are combined
/// compare-and-branch operations that compare two values and branch based
/// on the result without producing an intermediate comparison value.
///
/// # Arguments
///
/// * `uses` - The two operands being compared (left, right)
/// * `successors` - Branch targets: [true_target, false_target]
/// * `cmp` - The comparison kind (Eq, Ne, Lt, Le, Gt, Ge)
/// * `unsigned` - Whether to treat operands as unsigned values
fn comparison_branch(
    uses: &[SsaVarId],
    successors: &[usize],
    cmp: CmpKind,
    unsigned: bool,
) -> Option<SsaOp> {
    if let (Some(&left), Some(&right)) = (uses.first(), uses.get(1)) {
        let true_target = successors.first().copied()?;
        let false_target = successors.get(1).copied()?;
        Some(SsaOp::BranchCmp {
            left,
            right,
            cmp,
            unsigned,
            true_target,
            false_target,
        })
    } else {
        None
    }
}

fn call_op(
    instr: &Instruction,
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
    is_virtual: bool,
) -> Option<SsaOp> {
    extract_method_token(&instr.operand).map(|method| {
        if is_virtual {
            SsaOp::CallVirt {
                dest: def,
                method,
                args: uses.to_vec(),
                effects: None,
            }
        } else {
            SsaOp::Call {
                dest: def,
                method,
                args: uses.to_vec(),
                effects: None,
            }
        }
    })
}

fn ldelem_op(
    uses: &[SsaVarId],
    def: Option<SsaVarId>,
    operand: &Operand,
    assembly: Option<&CilObject>,
) -> Option<SsaOp> {
    let elem_type =
        extract_type_token(operand).map_or(SsaType::Unknown, |tr| type_ref_to_ssa(tr, assembly));
    ldelem_typed(uses, def, elem_type)
}

fn ldelem_typed(uses: &[SsaVarId], def: Option<SsaVarId>, elem_type: SsaType) -> Option<SsaOp> {
    if let (Some(&array), Some(&index), Some(dest)) = (uses.first(), uses.get(1), def) {
        Some(SsaOp::LoadElement {
            dest,
            array,
            index,
            elem_type,
        })
    } else {
        None
    }
}

fn stelem_op(uses: &[SsaVarId], operand: &Operand, assembly: Option<&CilObject>) -> Option<SsaOp> {
    let elem_type =
        extract_type_token(operand).map_or(SsaType::Unknown, |tr| type_ref_to_ssa(tr, assembly));
    stelem_typed(uses, elem_type)
}

fn stelem_typed(uses: &[SsaVarId], elem_type: SsaType) -> Option<SsaOp> {
    if let (Some(&array), Some(&index), Some(&value)) = (uses.first(), uses.get(1), uses.get(2)) {
        Some(SsaOp::StoreElement {
            array,
            index,
            value,
            elem_type,
        })
    } else {
        None
    }
}

fn ldind_typed(uses: &[SsaVarId], def: Option<SsaVarId>, value_type: SsaType) -> Option<SsaOp> {
    if let (Some(&addr), Some(dest)) = (uses.first(), def) {
        Some(SsaOp::LoadIndirect {
            dest,
            addr,
            value_type,
            // CIL `ldind` has no segment/address-space qualifier.
            address_space: None,
        })
    } else {
        None
    }
}

fn stind_typed(uses: &[SsaVarId], value_type: SsaType) -> Option<SsaOp> {
    if let (Some(&addr), Some(&value)) = (uses.first(), uses.get(1)) {
        Some(SsaOp::StoreIndirect {
            addr,
            value,
            value_type,
            // CIL `stind` has no segment/address-space qualifier.
            address_space: None,
        })
    } else {
        None
    }
}

fn extract_i32(operand: &Operand) -> Option<i32> {
    match operand {
        Operand::Immediate(Immediate::Int8(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::Int16(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::Int32(v)) => Some(*v),
        Operand::Immediate(Immediate::UInt8(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::UInt16(v)) => Some(i32::from(*v)),
        Operand::Immediate(Immediate::UInt32(v)) => i32::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_i64(operand: &Operand) -> Option<i64> {
    match operand {
        Operand::Immediate(Immediate::Int64(v)) => Some(*v),
        Operand::Immediate(Immediate::UInt64(v)) => i64::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_f32(operand: &Operand) -> Option<f32> {
    match operand {
        Operand::Immediate(Immediate::Float32(v)) => Some(*v),
        _ => None,
    }
}

fn extract_f64(operand: &Operand) -> Option<f64> {
    match operand {
        Operand::Immediate(Immediate::Float64(v)) => Some(*v),
        _ => None,
    }
}

fn extract_u8(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::Immediate(Immediate::UInt8(v)) => Some(*v),
        Operand::Immediate(Immediate::Int8(v)) => u8::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_u16(operand: &Operand) -> Option<u16> {
    match operand {
        Operand::Immediate(Immediate::UInt8(v)) => Some(u16::from(*v)),
        Operand::Immediate(Immediate::UInt16(v)) | Operand::Argument(v) | Operand::Local(v) => {
            Some(*v)
        }
        Operand::Immediate(Immediate::Int8(v)) => u16::try_from(*v).ok(),
        Operand::Immediate(Immediate::Int16(v)) => u16::try_from(*v).ok(),
        _ => None,
    }
}

fn extract_method_token(operand: &Operand) -> Option<MethodRef> {
    match operand {
        Operand::Token(token) => Some(MethodRef::new(*token)),
        _ => None,
    }
}

fn extract_field_token(operand: &Operand) -> Option<FieldRef> {
    match operand {
        Operand::Token(token) => Some(FieldRef::new(*token)),
        _ => None,
    }
}

fn extract_type_token(operand: &Operand) -> Option<TypeRef> {
    match operand {
        Operand::Token(token) => Some(TypeRef::new(*token)),
        _ => None,
    }
}

fn extract_signature_token(operand: &Operand) -> Option<SigRef> {
    match operand {
        Operand::Token(token) => Some(SigRef::new(*token)),
        _ => None,
    }
}

fn extract_string_token(operand: &Operand) -> Option<u32> {
    match operand {
        Operand::Token(token) => Some(token.value() & 0x00FF_FFFF),
        Operand::Immediate(Immediate::UInt32(v)) => Some(*v),
        _ => None,
    }
}

/// Converts a type reference (metadata token) to an SSA type.
///
/// This function resolves type tokens from instructions like `ldelem`, `stelem`,
/// and `ldelema` to their corresponding SSA type representation.
///
/// # Arguments
///
/// * `type_ref` - The type reference containing a metadata token
/// * `assembly` - Optional assembly context for resolving the token
///
/// # Returns
///
/// The resolved `SsaType`, or `SsaType::Unknown` if resolution fails.
fn type_ref_to_ssa(type_ref: TypeRef, assembly: Option<&CilObject>) -> SsaType {
    let Some(assembly) = assembly else {
        return SsaType::Unknown;
    };

    SsaType::from_type_token(type_ref.token(), assembly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{FlowType, InstructionCategory, StackBehavior};

    fn make_instruction(
        opcode: u8,
        prefix: u8,
        mnemonic: &'static str,
        operand: Operand,
        pops: u8,
        pushes: u8,
    ) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode,
            prefix,
            mnemonic,
            category: InstructionCategory::Arithmetic,
            flow_type: FlowType::Sequential,
            operand,
            stack_behavior: StackBehavior {
                pops,
                pushes,
                net_effect: i8::try_from(i16::from(pushes) - i16::from(pops)).unwrap_or(0),
            },
            branch_targets: vec![],
        }
    }

    #[test]
    fn test_decompose_add() {
        let instr = make_instruction(0x58, 0, "add", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Add {
            dest,
            left,
            right,
            flags: None,
        }) = op
        {
            assert_eq!(dest, v2);
            assert_eq!(left, v0);
            assert_eq!(right, v1);
        } else {
            panic!("Expected SsaOp::Add");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_0() {
        let instr = make_instruction(0x16, 0, "ldc.i4.0", Operand::None, 0, 1);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![];
        let def = Some(v0);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Const { dest, value }) = op {
            assert_eq!(dest, v0);
            assert_eq!(value, ConstValue::I32(0));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_s() {
        let instr = make_instruction(
            0x1F,
            0,
            "ldc.i4.s",
            Operand::Immediate(Immediate::Int8(42)),
            0,
            1,
        );
        let v0 = SsaVarId::from_index(0);
        let uses = vec![];
        let def = Some(v0);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Const { dest, value }) = op {
            assert_eq!(dest, v0);
            assert_eq!(value, ConstValue::I32(42));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ret_with_value() {
        let instr = make_instruction(0x2A, 0, "ret", Operand::None, 1, 0);
        let v = SsaVarId::from_index(0);
        let uses = vec![v];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Return { value }) = op {
            assert_eq!(value, Some(v));
        } else {
            panic!("Expected SsaOp::Return");
        }
    }

    #[test]
    fn test_decompose_ret_void() {
        let instr = make_instruction(0x2A, 0, "ret", Operand::None, 0, 0);
        let uses = vec![];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Return { value }) = op {
            assert_eq!(value, None);
        } else {
            panic!("Expected SsaOp::Return");
        }
    }

    #[test]
    fn test_decompose_ceq() {
        let instr = make_instruction(0x01, 0xFE, "ceq", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_ok());

        if let Ok(SsaOp::Ceq { dest, left, right }) = op {
            assert_eq!(dest, v2);
            assert_eq!(left, v0);
            assert_eq!(right, v1);
        } else {
            panic!("Expected SsaOp::Ceq");
        }
    }

    /// The vararg handle and the three typed-reference operations decompose to
    /// their own operations, with the type token, the value each takes, and
    /// the value each defines; they used to be rejected as unknown opcodes.
    #[test]
    fn test_decompose_arglist_and_typed_references() {
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let token = Token::new(0x0100_0005);

        let arglist = make_instruction(0x00, 0xFE, "arglist", Operand::None, 0, 1);
        assert_eq!(
            decompose_instruction(&arglist, &[], Some(v1), &[], None).unwrap(),
            SsaOp::ArgList { dest: v1 }
        );

        let mkrefany = make_instruction(0xC6, 0, "mkrefany", Operand::Token(token), 1, 1);
        assert_eq!(
            decompose_instruction(&mkrefany, &[v0], Some(v1), &[], None).unwrap(),
            SsaOp::MakeTypedRef {
                dest: v1,
                address: v0,
                value_type: TypeRef::new(token),
            }
        );

        let refanyval = make_instruction(0xC2, 0, "refanyval", Operand::Token(token), 1, 1);
        assert_eq!(
            decompose_instruction(&refanyval, &[v0], Some(v1), &[], None).unwrap(),
            SsaOp::TypedRefValue {
                dest: v1,
                typed_ref: v0,
                value_type: TypeRef::new(token),
            }
        );

        let refanytype = make_instruction(0x1D, 0xFE, "refanytype", Operand::None, 1, 1);
        assert_eq!(
            decompose_instruction(&refanytype, &[v0], Some(v1), &[], None).unwrap(),
            SsaOp::TypedRefType {
                dest: v1,
                typed_ref: v0,
            }
        );
    }

    #[test]
    fn test_decompose_nop() {
        let instr = make_instruction(0x00, 0, "nop", Operand::None, 0, 0);
        let uses = vec![];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert_eq!(op.unwrap(), SsaOp::Nop);
    }

    #[test]
    fn test_decompose_conv_i4() {
        let instr = make_instruction(0x69, 0, "conv.i4", Operand::None, 1, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0];
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None).unwrap();

        if let SsaOp::IntConv {
            dest,
            operand,
            target,
            overflow_check,
            unsigned,
        } = op
        {
            assert_eq!(dest, v1);
            assert_eq!(operand, v0);
            assert_eq!(target, SsaType::I32);
            assert!(!overflow_check);
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::IntConv");
        }
    }

    #[test]
    fn test_decompose_sub() {
        let instr = make_instruction(0x59, 0, "sub", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Sub { .. })));
    }

    #[test]
    fn test_decompose_mul() {
        let instr = make_instruction(0x5A, 0, "mul", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Mul { .. })));
    }

    #[test]
    fn test_decompose_div() {
        let instr = make_instruction(0x5B, 0, "div", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0, v1];
        let v2 = SsaVarId::from_index(2);
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Div { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Div");
        }
    }

    #[test]
    fn test_decompose_div_un() {
        let instr = make_instruction(0x5C, 0, "div.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Div { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::Div");
        }
    }

    #[test]
    fn test_decompose_rem() {
        let instr = make_instruction(0x5D, 0, "rem", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Rem { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Rem");
        }
    }

    #[test]
    fn test_decompose_rem_un() {
        let instr = make_instruction(0x5E, 0, "rem.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Rem { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::Rem");
        }
    }

    #[test]
    fn test_decompose_neg() {
        let instr = make_instruction(0x65, 0, "neg", Operand::None, 1, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0];
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Neg { flags: None, .. })));
    }

    #[test]
    fn test_decompose_add_ovf() {
        let instr = make_instruction(0xD6, 0, "add.ovf", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::AddOvf { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::AddOvf");
        }
    }

    #[test]
    fn test_decompose_add_ovf_un() {
        let instr = make_instruction(0xD7, 0, "add.ovf.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::AddOvf { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::AddOvf");
        }
    }

    #[test]
    fn test_decompose_mul_ovf() {
        let instr = make_instruction(0xD8, 0, "mul.ovf", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::MulOvf { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::MulOvf");
        }
    }

    #[test]
    fn test_decompose_sub_ovf() {
        let instr = make_instruction(0xDA, 0, "sub.ovf", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::SubOvf { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::SubOvf");
        }
    }

    #[test]
    fn test_decompose_and() {
        let instr = make_instruction(0x5F, 0, "and", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::And { .. })));
    }

    #[test]
    fn test_decompose_or() {
        let instr = make_instruction(0x60, 0, "or", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Or { .. })));
    }

    #[test]
    fn test_decompose_xor() {
        let instr = make_instruction(0x61, 0, "xor", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Xor { .. })));
    }

    #[test]
    fn test_decompose_not() {
        let instr = make_instruction(0x66, 0, "not", Operand::None, 1, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0];
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Not { flags: None, .. })));
    }

    #[test]
    fn test_decompose_shl() {
        let instr = make_instruction(0x62, 0, "shl", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(matches!(op, Ok(SsaOp::Shl { .. })));
    }

    #[test]
    fn test_decompose_shr() {
        let instr = make_instruction(0x63, 0, "shr", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Shr { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Shr");
        }
    }

    #[test]
    fn test_decompose_shr_un() {
        let instr = make_instruction(0x64, 0, "shr.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Shr { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::Shr");
        }
    }

    #[test]
    fn test_decompose_ldnull() {
        let instr = make_instruction(0x14, 0, "ldnull", Operand::None, 0, 1);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![];
        let def = Some(v0);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::Null);
        } else {
            panic!("Expected SsaOp::Const with Null");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_m1() {
        let instr = make_instruction(0x15, 0, "ldc.i4.m1", Operand::None, 0, 1);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![];
        let def = Some(v0);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::I32(-1));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_i4_constants() {
        // Test ldc.i4.1 through ldc.i4.8
        for (opcode, expected_value) in [
            (0x17u8, 1i32),
            (0x18, 2),
            (0x19, 3),
            (0x1A, 4),
            (0x1B, 5),
            (0x1C, 6),
            (0x1D, 7),
            (0x1E, 8),
        ] {
            let instr = make_instruction(opcode, 0, "ldc.i4.N", Operand::None, 0, 1);
            let v0 = SsaVarId::from_index(0);
            let op = decompose_instruction(&instr, &[], Some(v0), &[], None);
            if let Ok(SsaOp::Const { value, .. }) = op {
                assert_eq!(value, ConstValue::I32(expected_value));
            } else {
                panic!("Expected SsaOp::Const for opcode {opcode:#x}");
            }
        }
    }

    #[test]
    fn test_decompose_ldc_i4() {
        let instr = make_instruction(
            0x20,
            0,
            "ldc.i4",
            Operand::Immediate(Immediate::Int32(0x12345678)),
            0,
            1,
        );
        let v0 = SsaVarId::from_index(0);
        let op = decompose_instruction(&instr, &[], Some(v0), &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::I32(0x12345678));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_i8() {
        let instr = make_instruction(
            0x21,
            0,
            "ldc.i8",
            Operand::Immediate(Immediate::Int64(0x123456789ABCDEF0)),
            0,
            1,
        );
        let v0 = SsaVarId::from_index(0);
        let op = decompose_instruction(&instr, &[], Some(v0), &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::I64(0x123456789ABCDEF0));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_r4() {
        let instr = make_instruction(
            0x22,
            0,
            "ldc.r4",
            Operand::Immediate(Immediate::Float32(std::f32::consts::PI)),
            0,
            1,
        );
        let v0 = SsaVarId::from_index(0);
        let op = decompose_instruction(&instr, &[], Some(v0), &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::from(std::f32::consts::PI));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_ldc_r8() {
        let instr = make_instruction(
            0x23,
            0,
            "ldc.r8",
            Operand::Immediate(Immediate::Float64(std::f64::consts::E)),
            0,
            1,
        );
        let v0 = SsaVarId::from_index(0);
        let op = decompose_instruction(&instr, &[], Some(v0), &[], None);
        if let Ok(SsaOp::Const { value, .. }) = op {
            assert_eq!(value, ConstValue::from(std::f64::consts::E));
        } else {
            panic!("Expected SsaOp::Const");
        }
    }

    #[test]
    fn test_decompose_dup() {
        let instr = make_instruction(0x25, 0, "dup", Operand::None, 1, 2);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0];
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Copy { dest, src }) = op {
            assert_eq!(dest, v1);
            assert_eq!(src, v0);
        } else {
            panic!("Expected SsaOp::Copy");
        }
    }

    #[test]
    fn test_decompose_pop() {
        let instr = make_instruction(0x26, 0, "pop", Operand::None, 1, 0);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![v0];
        let def = None;

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Pop { value }) = op {
            assert_eq!(value, v0);
        } else {
            panic!("Expected SsaOp::Pop");
        }
    }

    #[test]
    fn test_decompose_br() {
        let instr = make_instruction(0x38, 0, "br", Operand::None, 0, 0);
        let successors = vec![5];

        let op = decompose_instruction(&instr, &[], None, &successors, None);
        if let Ok(SsaOp::Jump { target }) = op {
            assert_eq!(target, 5);
        } else {
            panic!("Expected SsaOp::Jump");
        }
    }

    #[test]
    fn test_decompose_br_s() {
        let instr = make_instruction(0x2B, 0, "br.s", Operand::None, 0, 0);
        let successors = vec![3];

        let op = decompose_instruction(&instr, &[], None, &successors, None);
        if let Ok(SsaOp::Jump { target }) = op {
            assert_eq!(target, 3);
        } else {
            panic!("Expected SsaOp::Jump");
        }
    }

    #[test]
    fn test_decompose_brfalse() {
        let instr = make_instruction(0x39, 0, "brfalse", Operand::None, 1, 0);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![v0];
        let successors = vec![5, 2]; // branch target, fallthrough

        let op = decompose_instruction(&instr, &uses, None, &successors, None);
        if let Ok(SsaOp::Branch {
            condition,
            true_target,
            false_target,
        }) = op
        {
            assert_eq!(condition, v0);
            assert_eq!(true_target, 2); // fallthrough (brfalse jumps on false)
            assert_eq!(false_target, 5); // branch target
        } else {
            panic!("Expected SsaOp::Branch");
        }
    }

    #[test]
    fn test_decompose_brtrue() {
        let instr = make_instruction(0x3A, 0, "brtrue", Operand::None, 1, 0);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![v0];
        let successors = vec![5, 2]; // branch target, fallthrough

        let op = decompose_instruction(&instr, &uses, None, &successors, None);
        if let Ok(SsaOp::Branch {
            condition,
            true_target,
            false_target,
        }) = op
        {
            assert_eq!(condition, v0);
            assert_eq!(true_target, 5); // branch target (brtrue jumps on true)
            assert_eq!(false_target, 2); // fallthrough
        } else {
            panic!("Expected SsaOp::Branch");
        }
    }

    #[test]
    fn test_decompose_switch() {
        let instr = make_instruction(0x45, 0, "switch", Operand::None, 1, 0);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![v0];
        let successors = vec![10, 20, 30, 5]; // case targets, then default

        let op = decompose_instruction(&instr, &uses, None, &successors, None);
        if let Ok(SsaOp::Switch {
            value,
            targets,
            default,
        }) = op
        {
            assert_eq!(value, v0);
            assert_eq!(targets, vec![10, 20, 30]);
            assert_eq!(default, 5);
        } else {
            panic!("Expected SsaOp::Switch");
        }
    }

    #[test]
    fn test_decompose_cgt() {
        let instr = make_instruction(0x02, 0xFE, "cgt", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Cgt { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Cgt");
        }
    }

    #[test]
    fn test_decompose_cgt_un() {
        let instr = make_instruction(0x03, 0xFE, "cgt.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Cgt { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::Cgt");
        }
    }

    #[test]
    fn test_decompose_clt() {
        let instr = make_instruction(0x04, 0xFE, "clt", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Clt { unsigned, .. }) = op {
            assert!(!unsigned);
        } else {
            panic!("Expected SsaOp::Clt");
        }
    }

    #[test]
    fn test_decompose_clt_un() {
        let instr = make_instruction(0x05, 0xFE, "clt.un", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let v2 = SsaVarId::from_index(2);
        let uses = vec![v0, v1];
        let def = Some(v2);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::Clt { unsigned, .. }) = op {
            assert!(unsigned);
        } else {
            panic!("Expected SsaOp::Clt");
        }
    }

    #[test]
    fn test_decompose_conv_variants() {
        // Test various conv.* opcodes
        let test_cases = [
            (0x67u8, SsaType::I8, false, false),      // conv.i1
            (0x68, SsaType::I16, false, false),       // conv.i2
            (0x6A, SsaType::I64, false, false),       // conv.i8
            (0x6B, SsaType::F32, false, false),       // conv.r4
            (0x6C, SsaType::F64, false, false),       // conv.r8
            (0xD1, SsaType::U16, false, true),        // conv.u2
            (0xD2, SsaType::U8, false, true),         // conv.u1
            (0x6D, SsaType::U32, false, true),        // conv.u4
            (0x6E, SsaType::U64, false, true),        // conv.u8
            (0xD3, SsaType::NativeInt, false, false), // conv.i
            (0xE0, SsaType::NativeUInt, false, true), // conv.u
        ];

        for (opcode, expected_type, expected_ovf, expected_unsigned) in test_cases {
            let instr = make_instruction(opcode, 0, "conv.*", Operand::None, 1, 1);
            let v0 = SsaVarId::from_index(0);
            let v1 = SsaVarId::from_index(1);
            let op = decompose_instruction(&instr, &[v0], Some(v1), &[], None);

            // conv.i*/u* lower to `IntConv`, conv.r* to `IntToFloat` (which
            // carries no overflow-check); extract the shared fields from either.
            let (target, overflow_check, unsigned) = match op {
                Ok(SsaOp::IntConv {
                    target,
                    overflow_check,
                    unsigned,
                    ..
                }) => (target, overflow_check, unsigned),
                Ok(SsaOp::IntToFloat {
                    target, unsigned, ..
                }) => (target, false, unsigned),
                other => panic!("Expected a conversion op for opcode {opcode:#x}, got {other:?}"),
            };
            assert_eq!(
                target, expected_type,
                "Type mismatch for opcode {opcode:#x}"
            );
            assert_eq!(
                overflow_check, expected_ovf,
                "Overflow mismatch for opcode {opcode:#x}"
            );
            assert_eq!(
                unsigned, expected_unsigned,
                "Unsigned mismatch for opcode {opcode:#x}"
            );
        }
    }

    #[test]
    fn test_decompose_conv_ovf_variants() {
        // Test overflow-checking conversions
        let test_cases = [
            (0xB3u8, SsaType::I8, true, false), // conv.ovf.i1
            (0x82, SsaType::I8, true, true),    // conv.ovf.i1.un
            (0xB5, SsaType::I16, true, false),  // conv.ovf.i2
            (0xB7, SsaType::I32, true, false),  // conv.ovf.i4
            (0xB9, SsaType::I64, true, false),  // conv.ovf.i8
            (0xB4, SsaType::U8, true, false),   // conv.ovf.u1
            (0xB6, SsaType::U16, true, false),  // conv.ovf.u2
            (0xB8, SsaType::U32, true, false),  // conv.ovf.u4
            (0xBA, SsaType::U64, true, false),  // conv.ovf.u8
        ];

        for (opcode, expected_type, expected_ovf, expected_unsigned) in test_cases {
            let instr = make_instruction(opcode, 0, "conv.ovf.*", Operand::None, 1, 1);
            let v0 = SsaVarId::from_index(0);
            let v1 = SsaVarId::from_index(1);
            let op = decompose_instruction(&instr, &[v0], Some(v1), &[], None);

            // All conv.ovf.* opcodes target an integer, so they lower to `IntConv`.
            if let Ok(SsaOp::IntConv {
                target,
                overflow_check,
                unsigned,
                ..
            }) = op
            {
                assert_eq!(
                    target, expected_type,
                    "Type mismatch for opcode {opcode:#x}"
                );
                assert_eq!(
                    overflow_check, expected_ovf,
                    "Overflow mismatch for opcode {opcode:#x}"
                );
                assert_eq!(
                    unsigned, expected_unsigned,
                    "Unsigned mismatch for opcode {opcode:#x}"
                );
            } else {
                panic!("Expected SsaOp::IntConv for opcode {opcode:#x}");
            }
        }
    }

    #[test]
    fn test_decompose_throw() {
        let instr = make_instruction(0x7A, 0, "throw", Operand::None, 1, 0);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![v0];

        let op = decompose_instruction(&instr, &uses, None, &[], None);
        if let Ok(SsaOp::Throw { exception }) = op {
            assert_eq!(exception, v0);
        } else {
            panic!("Expected SsaOp::Throw");
        }
    }

    #[test]
    fn test_decompose_endfinally() {
        let instr = make_instruction(0xDC, 0, "endfinally", Operand::None, 0, 0);
        let op = decompose_instruction(&instr, &[], None, &[], None);
        assert_eq!(op.unwrap(), SsaOp::EndFinally);
    }

    #[test]
    fn test_decompose_rethrow() {
        let instr = make_instruction(0x1A, 0xFE, "rethrow", Operand::None, 0, 0);
        let op = decompose_instruction(&instr, &[], None, &[], None);
        assert_eq!(op.unwrap(), SsaOp::Rethrow);
    }

    #[test]
    fn test_decompose_break() {
        let instr = make_instruction(0x01, 0, "break", Operand::None, 0, 0);
        let op = decompose_instruction(&instr, &[], None, &[], None);
        assert_eq!(op.unwrap(), SsaOp::Break(BreakpointOp::Breakpoint));
    }

    #[test]
    fn test_decompose_leave() {
        let instr = make_instruction(0xDE, 0, "leave", Operand::None, 0, 0);
        let successors = vec![10];

        let op = decompose_instruction(&instr, &[], None, &successors, None);
        if let Ok(SsaOp::Leave { target }) = op {
            assert_eq!(target, 10);
        } else {
            panic!("Expected SsaOp::Leave");
        }
    }

    #[test]
    fn test_decompose_localloc() {
        let instr = make_instruction(0x0F, 0xFE, "localloc", Operand::None, 1, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0];
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        if let Ok(SsaOp::LocalAlloc { dest, size }) = op {
            assert_eq!(dest, v1);
            assert_eq!(size, v0);
        } else {
            panic!("Expected SsaOp::LocalAlloc");
        }
    }

    #[test]
    fn test_decompose_binary_missing_operands() {
        // Binary op with insufficient operands should return None
        let instr = make_instruction(0x58, 0, "add", Operand::None, 2, 1);
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);
        let uses = vec![v0]; // Only one operand
        let def = Some(v1);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_err());
    }

    #[test]
    fn test_decompose_unary_missing_operand() {
        // Unary op with no operands should return None
        let instr = make_instruction(0x65, 0, "neg", Operand::None, 1, 1);
        let v0 = SsaVarId::from_index(0);
        let uses = vec![]; // No operand
        let def = Some(v0);

        let op = decompose_instruction(&instr, &uses, def, &[], None);
        assert!(op.is_err());
    }

    #[test]
    fn test_decompose_const_missing_def() {
        // Constant load with no def should return None
        let instr = make_instruction(0x16, 0, "ldc.i4.0", Operand::None, 0, 1);
        let op = decompose_instruction(&instr, &[], None, &[], None);
        assert!(op.is_err());
    }

    #[test]
    fn test_decompose_unknown_opcode() {
        // Unknown opcode should return None
        let instr = make_instruction(0xFF, 0, "unknown", Operand::None, 0, 0);
        let op = decompose_instruction(&instr, &[], None, &[], None);
        assert!(op.is_err());
    }
}

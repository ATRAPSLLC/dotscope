//! `CilTarget` — the .NET CIL host's concrete impl of `analyssa::Target`.
//!
//! The trait + `MockTarget` live in `analyssa::target`; this file plugs CIL
//! semantics into them and is the only place in dotscope that knows the
//! mapping from `Target` associated types to dotscope's metadata types.
//!
//! Conversion helpers (`cil_convert_const`, `cil_convert_const_checked`,
//! `cil_evaluator_apply_conversion`) live here too so the `Target` impl can
//! delegate without forming an `impl ConstValue<CilTarget>` ↔ `impl Target for
//! CilTarget` cycle.

// Re-export so existing `crate::analysis::ssa::target::Target` import paths
// in the rest of dotscope continue to resolve. The trait itself lives in
// `analyssa::target`.
use std::fmt;

#[cfg(feature = "compiler")]
use analyssa::scheduling::DeobfuscationCapability;
pub use analyssa::target::Target;
use analyssa::{
    ir::{value::ConstValue, FloatFormat, FloatRounding, HandlerKind},
    PointerSize,
};

#[cfg(feature = "compiler")]
use crate::compiler::CilCapability;
use crate::{
    analysis::ssa::{
        facts::CilVariableFacts,
        types::{FieldRef, MethodRef, SigRef, SsaType, TypeRef},
    },
    assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior},
    metadata::{
        method::{ExceptionHandlerFlags, ExceptionHandlerKind},
        signatures::SignatureLocalVariable,
    },
};

/// `Target` impl for .NET CIL.
///
/// Instances carry the pointer width chosen at construction (4 for 32-bit
/// hosts, 8 for 64-bit). The associated types alias the existing dotscope
/// metadata types so the rest of the crate continues to compile unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CilTarget {
    ptr_bytes: u32,
}

impl CilTarget {
    /// 64-bit CIL target (8-byte pointers). The default for x86_64 hosts.
    #[must_use]
    pub const fn x64() -> Self {
        Self { ptr_bytes: 8 }
    }

    /// 32-bit CIL target (4-byte pointers).
    #[must_use]
    pub const fn x86() -> Self {
        Self { ptr_bytes: 4 }
    }

    /// Construct a `CilTarget` with an explicit pointer width.
    ///
    /// `ptr_bytes` must be 4 or 8. Other values are accepted but undefined for
    /// pointer-sized type inference downstream.
    #[must_use]
    pub const fn with_ptr_bytes(ptr_bytes: u32) -> Self {
        Self { ptr_bytes }
    }
}

impl Default for CilTarget {
    fn default() -> Self {
        Self::x64()
    }
}

/// The symbol space CIL does not have.
///
/// Every CIL entity is named by a metadata token, which the `TypeRef` /
/// `MethodRef` / `FieldRef` references already carry — there is no separate
/// space of addressable symbols to model. Declaring the associated type as an
/// uninhabited enum states that: a `ConstValue::Symbol` cannot be constructed
/// for this target at all, rather than merely being left unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoSymbol {}

impl fmt::Display for NoSymbol {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Unreachable by construction: the type has no values.
        match *self {}
    }
}

impl Target for CilTarget {
    type TypeRef = TypeRef;
    type MethodRef = MethodRef;
    type FieldRef = FieldRef;
    type SigRef = SigRef;
    type SymbolRef = NoSymbol;
    type ExceptionKind = ExceptionHandlerFlags;
    type VariableFacts = CilVariableFacts;
    type InstructionFacts = ();
    type FunctionFacts = ();
    type Type = SsaType;
    type OriginalInstruction = Instruction;
    type LocalSignature = SignatureLocalVariable;
    #[cfg(feature = "compiler")]
    type Capability = CilCapability;
    #[cfg(not(feature = "compiler"))]
    type Capability = ();

    /// This target's tag for a shared capability milestone.
    ///
    /// Every milestone in the shared vocabulary has a CIL spelling, so the
    /// answer is always `Some`: the conversion is total and lives on
    /// [`CilCapability`](crate::compiler::CilCapability). Without the
    /// compiler feature there are no capabilities to name and nothing is
    /// scheduled by them.
    #[cfg(feature = "compiler")]
    fn capability(shared: DeobfuscationCapability) -> Option<Self::Capability> {
        Some(CilCapability::from(shared))
    }

    fn ptr_bytes(&self) -> u32 {
        self.ptr_bytes
    }

    fn synthetic_instruction() -> Self::OriginalInstruction {
        Instruction {
            rva: 0,
            offset: 0,
            size: 0,
            opcode: 0,
            prefix: 0,
            mnemonic: "synthetic",
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        }
    }

    fn unknown_type() -> Self::Type {
        SsaType::Unknown
    }

    fn is_integer(t: &Self::Type) -> bool {
        // `char` and `bool` are integers to every CIL instruction that reads
        // them - an unsigned 16-bit and an 8-bit value, widened to `int32` on
        // the evaluation stack - so they are to anything reasoning about the
        // arithmetic. Left out, a same-width `conv.i2` of a `char` read as a
        // conversion between a non-integer and an integer, which analyssa can
        // only state as a reinterpretation of bits, and CIL has no
        // instruction for.
        t.is_integer() || matches!(t, SsaType::Char | SsaType::Bool)
    }

    fn is_floating(t: &Self::Type) -> bool {
        t.is_float()
    }

    fn is_signed(t: &Self::Type) -> bool {
        matches!(
            t,
            SsaType::I8
                | SsaType::I16
                | SsaType::I32
                | SsaType::I64
                | SsaType::NativeInt
                | SsaType::F32
                | SsaType::F64
        )
    }

    fn is_pointer(t: &Self::Type) -> bool {
        t.is_pointer()
    }

    fn is_reference(t: &Self::Type) -> bool {
        t.is_reference()
    }

    fn is_unknown(t: &Self::Type) -> bool {
        t.is_unknown()
    }

    fn bit_width(t: &Self::Type) -> Option<u32> {
        t.size_bytes().map(|b| b.saturating_mul(8))
    }

    fn operand_width(t: &Self::Type) -> Option<u32> {
        // A value is typed by where it came from, but an instruction reads it
        // off the evaluation stack, which holds every integer up to 32 bits as
        // `int32` (ECMA-335 III.1.1): a `byte` local and an `int32` constant
        // are one width to `xor`. `native int` mixes with `int32`, and a float
        // computes in the runtime's own `F` (III.1.5), so neither has a width
        // to agree on; `int32` against `int64` stays unverifiable.
        match t.arithmetic_class()? {
            SsaType::I32 => Some(32),
            SsaType::I64 => Some(64),
            _ => None,
        }
    }

    fn instruction_mnemonic(instr: &Self::OriginalInstruction) -> &'static str {
        instr.mnemonic
    }

    fn instruction_rva(instr: &Self::OriginalInstruction) -> u64 {
        instr.rva
    }

    fn handler_kind(flags: &Self::ExceptionKind) -> HandlerKind {
        // `ExceptionHandlerFlags::kind` already performs the ECMA-335 §II.25.4.6
        // bitwise classification, so this arm only renames the four cases into
        // analyssa's taxonomy. Going through it rather than comparing against
        // the flag constants means a clause carrying an unrecognised bit is
        // classified the same way every other CIL reader in the crate classifies
        // it, instead of silently falling into a different default here.
        match flags.kind() {
            ExceptionHandlerKind::Catch => HandlerKind::Catch,
            ExceptionHandlerKind::Filter => HandlerKind::Filter,
            ExceptionHandlerKind::Finally => HandlerKind::Finally,
            ExceptionHandlerKind::Fault => HandlerKind::Fault,
        }
    }

    fn field_member_index(field: &Self::FieldRef) -> Option<u32> {
        // Field-sensitive points-to keys its abstract cells on
        // `(object, member_index)`, so all this needs to be is a *stable and
        // distinct* identity per field — the CIL metadata token already is one,
        // and it is the same identity `MemoryLocation::InstanceField` compares
        // on. A declaration-order index within the parent type would need the
        // assembly, which this associated function has no access to.
        //
        // A null token means the field never resolved; returning `None` there
        // takes the sound field-insensitive whole-object fallback rather than
        // collapsing every unresolved field onto one cell.
        let token = field.token().value();
        (token != 0).then_some(token)
    }

    fn result_type_for_const(value: &ConstValue<Self>) -> Option<Self::Type> {
        Some(match value {
            // Uninhabited for this target: CIL has no symbol space.
            ConstValue::Symbol(symbol) => match *symbol {},
            ConstValue::I8(_) => SsaType::I8,
            ConstValue::I16(_) => SsaType::I16,
            ConstValue::I32(_) => SsaType::I32,
            ConstValue::I64(_) => SsaType::I64,
            ConstValue::U8(_) => SsaType::U8,
            ConstValue::U16(_) => SsaType::U16,
            ConstValue::U32(_) => SsaType::U32,
            ConstValue::U64(_) => SsaType::U64,
            ConstValue::NativeInt(_) => SsaType::NativeInt,
            ConstValue::NativeUInt(_) => SsaType::NativeUInt,
            ConstValue::String(_) | ConstValue::DecryptedString(_) => SsaType::String,
            ConstValue::DecryptedArray { .. } => SsaType::Object,
            // SIMD vector constant from the native substrate — no CIL type.
            ConstValue::Vector(_) => return None,
            // binary32 and binary64 are CIL's floats; the other formats have no CIL type
            ConstValue::Float(bits) => match bits.format() {
                FloatFormat::Single => SsaType::F32,
                FloatFormat::Double => SsaType::F64,
                _ => return None,
            },
            ConstValue::Null => SsaType::Null,
            ConstValue::True | ConstValue::False => SsaType::Bool,
            ConstValue::Type(_) | ConstValue::MethodHandle(_) | ConstValue::FieldHandle(_) => {
                SsaType::Object
            }
        })
    }

    fn comparison_result_type() -> Option<Self::Type> {
        Some(SsaType::Bool)
    }

    /// None: a CIL arithmetic result has its operands' type (ECMA-335
    /// III.1.5) - a `float32` sum, a `long` product - which the operation
    /// alone does not say. Answered `int32`, every float and 64-bit result a
    /// rebuild or a rewrite retyped became an integer; the converter types
    /// arithmetic from its operands, and a rewritten operation keeps the type
    /// it had.
    fn arithmetic_result_type() -> Option<Self::Type> {
        None
    }

    fn native_int_result_type() -> Option<Self::Type> {
        Some(SsaType::NativeInt)
    }

    fn ckfinite_result_type() -> Option<Self::Type> {
        Some(SsaType::F64)
    }

    fn function_ptr_result_type() -> Option<Self::Type> {
        Some(SsaType::NativeInt)
    }

    fn object_result_type() -> Option<Self::Type> {
        Some(SsaType::Object)
    }

    fn value_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ValueType(*r))
    }

    fn byref_value_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ByRef(Box::new(SsaType::ValueType(*r))))
    }

    fn byref_class_type_from_ref(r: &Self::TypeRef) -> Option<Self::Type> {
        Some(SsaType::ByRef(Box::new(SsaType::Class(*r))))
    }

    /// The CLI rounds every float result to nearest (ECMA-335 I.12.1.3); a
    /// program sets no other mode.
    fn environment_rounding() -> Option<FloatRounding> {
        Some(FloatRounding::NearestEven)
    }

    fn convert_const(
        value: &ConstValue<Self>,
        target_type: &Self::Type,
        unsigned_source: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        cil_convert_const(value, target_type, unsigned_source, ptr_size)
    }

    fn convert_const_checked(
        value: &ConstValue<Self>,
        target_type: &Self::Type,
        unsigned_source: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        cil_convert_const_checked(value, target_type, unsigned_source, ptr_size)
    }

    fn evaluate_int_conv(
        value: i64,
        target: &Self::Type,
        unsigned: bool,
        ptr_bytes: u32,
    ) -> Option<ConstValue<Self>> {
        let ptr_size = if ptr_bytes == 4 {
            PointerSize::Bit32
        } else {
            PointerSize::Bit64
        };
        Some(cil_evaluator_apply_conversion(
            value, target, unsigned, ptr_size,
        ))
    }
}

/// A constant as the CIL evaluation stack holds it: its bits and the width
/// they occupy.
///
/// Every integer narrower than 32 bits is widened to `int32` by the load that
/// puts it on the stack, keeping its numeric value; `int64` and native integers
/// keep their own width. A conversion reads this, and what it does with the
/// high bits is the conversion's decision, not the constant's variant's.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn stack_bits(value: &ConstValue<CilTarget>, ptr_size: PointerSize) -> Option<(u64, u32)> {
    let narrow = |numeric: i64| Some((u64::from(numeric as i32 as u32), 32));
    match value {
        ConstValue::I8(v) => narrow(i64::from(*v)),
        ConstValue::I16(v) => narrow(i64::from(*v)),
        ConstValue::I32(v) => narrow(i64::from(*v)),
        ConstValue::U8(v) => narrow(i64::from(*v)),
        ConstValue::U16(v) => narrow(i64::from(*v)),
        ConstValue::U32(v) => Some((u64::from(*v), 32)),
        ConstValue::True => narrow(1),
        ConstValue::False => narrow(0),
        ConstValue::I64(v) => Some((*v as u64, 64)),
        ConstValue::U64(v) => Some((*v, 64)),
        ConstValue::NativeInt(v) => Some((*v as u64, ptr_size.bits())),
        ConstValue::NativeUInt(v) => Some((*v, ptr_size.bits())),
        _ => None,
    }
}

/// `bits` of a `width`-bit stack value read as a number: sign-extended when
/// `signed`, zero-extended otherwise.
#[allow(clippy::cast_possible_wrap)]
fn stack_numeric(bits: u64, width: u32, signed: bool) -> i128 {
    let masked = if width >= 64 {
        bits
    } else {
        bits & ((1u64 << width).saturating_sub(1))
    };
    if signed && width < 64 && masked >> width.saturating_sub(1) & 1 == 1 {
        // Exact: `masked` is below 2^64 and so is the power subtracted.
        i128::from(masked).wrapping_sub(1i128 << width)
    } else if signed && width >= 64 {
        i128::from(masked as i64)
    } else {
        i128::from(masked)
    }
}

/// Whether `target` is an unsigned integer type.
const fn is_unsigned_target(target: &SsaType) -> bool {
    matches!(
        target,
        SsaType::U8
            | SsaType::U16
            | SsaType::U32
            | SsaType::U64
            | SsaType::NativeUInt
            | SsaType::Char
    )
}

/// `numeric` converted to `target`, truncating to the target's width.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn numeric_to_target(
    numeric: i128,
    target: &SsaType,
    ptr_size: PointerSize,
) -> Option<ConstValue<CilTarget>> {
    let converted = match target {
        SsaType::I8 => ConstValue::I8(numeric as i8),
        SsaType::U8 => ConstValue::U8(numeric as u8),
        SsaType::I16 => ConstValue::I16(numeric as i16),
        SsaType::U16 | SsaType::Char => ConstValue::U16(numeric as u16),
        SsaType::I32 => ConstValue::I32(numeric as i32),
        SsaType::U32 => ConstValue::U32(numeric as u32),
        SsaType::I64 => ConstValue::I64(numeric as i64),
        SsaType::U64 => ConstValue::U64(numeric as u64),
        SsaType::NativeInt => ConstValue::NativeInt(numeric as i64),
        SsaType::NativeUInt => ConstValue::NativeUInt(numeric as u64),
        SsaType::F32 => ConstValue::from(numeric as f32),
        SsaType::F64 => ConstValue::from(numeric as f64),
        SsaType::Bool => ConstValue::from_bool(numeric != 0),
        _ => return None,
    };
    Some(converted.mask_native(ptr_size))
}

/// A CIL conversion of a constant, without overflow checking.
///
/// The source is read at its stack width. Widening, it is zero-extended when
/// the conversion reads it as unsigned (`conv.*.un`) or converts to an unsigned
/// type - `conv.u8` of an `int32` zero-extends, which is why C# spells
/// `(ulong)intValue` as `conv.i8` - and sign-extended otherwise. Narrowing
/// truncates, where the two readings agree.
fn cil_convert_const(
    value: &ConstValue<CilTarget>,
    target: &SsaType,
    unsigned_source: bool,
    ptr_size: PointerSize,
) -> Option<ConstValue<CilTarget>> {
    let (bits, width) = stack_bits(value, ptr_size)?;
    let signed = !(unsigned_source || is_unsigned_target(target));
    numeric_to_target(stack_numeric(bits, width, signed), target, ptr_size)
}

/// A CIL conversion of a constant with overflow checking (`conv.ovf.*`).
///
/// The source is the number its stack bits spell, read as unsigned for
/// `conv.ovf.*.un` and as signed otherwise, and the conversion succeeds only
/// when that number is representable in the target: `conv.ovf.u4` of `-1`
/// throws, `conv.ovf.u4.un` of the same bits is `0xFFFF_FFFF`.
fn cil_convert_const_checked(
    value: &ConstValue<CilTarget>,
    target: &SsaType,
    unsigned_source: bool,
    ptr_size: PointerSize,
) -> Option<ConstValue<CilTarget>> {
    let (bits, width) = stack_bits(value, ptr_size)?;
    let numeric = stack_numeric(bits, width, !unsigned_source);
    let native_bits = ptr_size.bits();
    let signed_range = |bits: u32| {
        let half = 1i128 << bits.saturating_sub(1);
        half.wrapping_neg()..half
    };
    let unsigned_range = |bits: u32| 0..(1i128 << bits);
    let fits = match target {
        SsaType::I8 => signed_range(8).contains(&numeric),
        SsaType::U8 => unsigned_range(8).contains(&numeric),
        SsaType::I16 => signed_range(16).contains(&numeric),
        SsaType::U16 | SsaType::Char => unsigned_range(16).contains(&numeric),
        SsaType::I32 => signed_range(32).contains(&numeric),
        SsaType::U32 => unsigned_range(32).contains(&numeric),
        SsaType::I64 => signed_range(64).contains(&numeric),
        SsaType::U64 => unsigned_range(64).contains(&numeric),
        SsaType::NativeInt => signed_range(native_bits).contains(&numeric),
        SsaType::NativeUInt => unsigned_range(native_bits).contains(&numeric),
        SsaType::Bool | SsaType::F32 | SsaType::F64 => true,
        _ => return None,
    };
    if !fits {
        return None;
    }
    numeric_to_target(numeric, target, ptr_size)
}

/// CIL-side `evaluate_int_conv` body. Mirrors the legacy
/// `SsaEvaluator::apply_conversion` semantics (raw `as`-casts; `Bool` truncates
/// the low byte rather than booleanizing) so generifying the evaluator does
/// not change behavior.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss
)]
fn cil_evaluator_apply_conversion(
    value: i64,
    target: &SsaType,
    unsigned: bool,
    ptr_size: PointerSize,
) -> ConstValue<CilTarget> {
    match target {
        SsaType::I8 => {
            if unsigned {
                ConstValue::I8((value as u8) as i8)
            } else {
                ConstValue::I8(value as i8)
            }
        }
        SsaType::U8 | SsaType::Bool => ConstValue::U8(value as u8),
        SsaType::I16 => {
            if unsigned {
                ConstValue::I16((value as u16) as i16)
            } else {
                ConstValue::I16(value as i16)
            }
        }
        SsaType::U16 => ConstValue::U16(value as u16),
        SsaType::I32 => {
            if unsigned {
                ConstValue::I32((value as u32) as i32)
            } else {
                ConstValue::I32(value as i32)
            }
        }
        SsaType::U32 => ConstValue::U32(value as u32),
        SsaType::NativeInt => match ptr_size {
            PointerSize::Bit32 => {
                if unsigned {
                    ConstValue::NativeInt(i64::from((value as u32) as i32))
                } else {
                    ConstValue::NativeInt(i64::from(value as i32))
                }
            }
            PointerSize::Bit64 => ConstValue::NativeInt(value),
            PointerSize::Bit8 | PointerSize::Bit16 | PointerSize::Bit128 => {
                ConstValue::NativeInt(value)
            }
        },
        SsaType::NativeUInt => match ptr_size {
            PointerSize::Bit32 => ConstValue::NativeUInt(u64::from(value as u32)),
            PointerSize::Bit64 => ConstValue::NativeUInt(value as u64),
            PointerSize::Bit8 | PointerSize::Bit16 | PointerSize::Bit128 => {
                ConstValue::NativeUInt(value as u64)
            }
        },
        SsaType::U64 => ConstValue::U64(value as u64),
        SsaType::F32 => {
            let float_val = if unsigned {
                (value as u64) as f32
            } else {
                value as f32
            };
            ConstValue::from(float_val)
        }
        SsaType::F64 => {
            let float_val = if unsigned {
                (value as u64) as f64
            } else {
                value as f64
            };
            ConstValue::from(float_val)
        }
        _ => ConstValue::I64(value),
    }
}

#[cfg(test)]
mod tests {
    use analyssa::{MockTarget, MockType};

    use super::*;
    use crate::{
        analysis::ssa::{
            value::ConstValue, DefSite, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaVarId,
            SsaVerifier, VariableOrigin, VerifierError, VerifyLevel,
        },
        metadata::token::Token,
    };

    /// A same-width `conv.i2` of a `char` stays an integer conversion.
    ///
    /// `char` was no integer to analyssa, so collapsing the conversion found
    /// the same sixteen bits on both sides of a non-integer and an integer, and
    /// could only say so as a bit reinterpretation - which has no CIL
    /// lowering, so the method kept its original IL.
    #[test]
    fn a_conversion_from_char_is_between_integers() {
        let mut ssa: SsaFunction = SsaFunction::new(1, 0);
        let character = ssa.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::entry(),
            SsaType::Char,
        );
        let narrowed = ssa.create_variable(
            VariableOrigin::Phi,
            0,
            DefSite::instruction(0, 0),
            SsaType::I16,
        );
        let op = SsaOp::IntConv {
            dest: narrowed,
            operand: character,
            target: SsaType::I16,
            overflow_check: false,
            unsigned: false,
        };
        let mut block = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(op.clone()));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(narrowed),
        }));
        ssa.add_block(block);
        ssa.recompute_uses();

        assert!(CilTarget::is_integer(&SsaType::Char));
        assert!(CilTarget::is_integer(&SsaType::Bool));
        let collapsed = analyssa::analysis::reshape::collapse_reshape(&ssa, &op);
        assert!(
            !matches!(collapsed, Some(SsaOp::Bitcast { .. })),
            "a char narrowed to a short is an integer conversion: {collapsed:?}"
        );
    }

    /// An operation computes over its operands as the evaluation stack holds
    /// them: a `byte` or `char` against an `int32` is one width, as is `int32`
    /// against `native int` and `float32` against `float64`; `int32` against
    /// `int64` is not.
    #[test]
    fn operands_compute_at_their_stack_width() {
        /// Verifies `dest = left xor right` (a comparison when `compare`),
        /// the operands typed `left` and `right` and `dest` the class they
        /// compute in.
        fn mismatched(compare: bool, left: SsaType, right: SsaType) -> bool {
            let dest_type = if compare {
                SsaType::Bool
            } else {
                SsaType::binary_numeric(&left, &right, false).unwrap_or(SsaType::I64)
            };
            let mut ssa: SsaFunction = SsaFunction::new(2, 0);
            let [left, right] = [(0, left), (1, right)].map(|(index, ty)| {
                ssa.create_variable(VariableOrigin::Argument(index), 0, DefSite::entry(), ty)
            });
            let dest = ssa.create_variable(
                VariableOrigin::Phi,
                0,
                DefSite::instruction(0, 0),
                dest_type,
            );
            let op = if compare {
                SsaOp::Ceq { dest, left, right }
            } else {
                SsaOp::Xor {
                    dest,
                    left,
                    right,
                    flags: None,
                }
            };
            let mut block = SsaBlock::new(0);
            block.add_instruction(SsaInstruction::synthetic(op));
            block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
                value: Some(dest),
            }));
            ssa.add_block(block);
            ssa.recompute_uses();
            SsaVerifier::new(&ssa)
                .verify(VerifyLevel::Standard)
                .iter()
                .any(|finding| matches!(finding, VerifierError::InvalidOperandWidths { .. }))
        }
        assert!(!mismatched(false, SsaType::U8, SsaType::I32));
        assert!(!mismatched(true, SsaType::Char, SsaType::I32));
        assert!(!mismatched(true, SsaType::I16, SsaType::U8));
        assert!(!mismatched(false, SsaType::I32, SsaType::NativeInt));
        assert!(!mismatched(true, SsaType::F32, SsaType::F64));
        assert!(mismatched(false, SsaType::I32, SsaType::I64));
        assert!(mismatched(true, SsaType::U16, SsaType::I64));
    }

    /// `b ^ b` over a `byte` is the `int32` zero the evaluation stack holds,
    /// not a byte one.
    #[test]
    fn a_byte_cancelled_by_itself_is_an_int32_zero() {
        let (dest, byte) = (SsaVarId::from_index(1), SsaVarId::from_index(0));
        let xor: SsaOp = SsaOp::Xor {
            dest,
            left: byte,
            right: byte,
            flags: None,
        };
        assert_eq!(
            analyssa::analysis::algebraic::simplify_op(
                &xor,
                &std::collections::BTreeMap::new(),
                Some(&SsaType::U8)
            ),
            analyssa::analysis::algebraic::SimplifyResult::Constant(ConstValue::I32(0))
        );
    }

    /// `(b << 3) | (b >> 5)` over a `byte` computes at 32 bits on the
    /// evaluation stack: the bits shifted past bit 7 stay, so it is no 8-bit
    /// rotate.
    #[test]
    fn a_byte_shifted_both_ways_is_no_byte_rotate() {
        let mut ssa: SsaFunction = SsaFunction::new(1, 0);
        let byte = ssa.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::entry(),
            SsaType::U8,
        );
        let [three, five, left, right, rotated] = [0, 1, 2, 3, 4].map(|index| {
            ssa.create_variable(
                VariableOrigin::Phi,
                0,
                DefSite::instruction(0, index),
                SsaType::I32,
            )
        });
        let or = SsaOp::Or {
            dest: rotated,
            left,
            right,
            flags: None,
        };
        let mut block = SsaBlock::new(0);
        for op in [
            SsaOp::Const {
                dest: three,
                value: ConstValue::I32(3),
            },
            SsaOp::Const {
                dest: five,
                value: ConstValue::I32(5),
            },
            SsaOp::Shl {
                dest: left,
                value: byte,
                amount: three,
                flags: None,
            },
            SsaOp::Shr {
                dest: right,
                value: byte,
                amount: five,
                unsigned: true,
                flags: None,
            },
            or.clone(),
            SsaOp::Return {
                value: Some(rotated),
            },
        ] {
            block.add_instruction(SsaInstruction::synthetic(op));
        }
        ssa.add_block(block);
        ssa.recompute_uses();
        let constants = [(three, ConstValue::I32(3)), (five, ConstValue::I32(5))]
            .into_iter()
            .collect();
        let folded = analyssa::analysis::rotate::fold(&ssa, &or, &constants, &ssa.count_uses());
        assert!(
            folded.is_none(),
            "a 32-bit shift pair is folded as a byte rotate: {:?}",
            folded.map(|fold| fold.op)
        );
    }

    /// Converts `value` as CIL would, unchecked.
    fn conv(value: ConstValue, target: SsaType, unsigned_source: bool) -> Option<ConstValue> {
        cil_convert_const(&value, &target, unsigned_source, PointerSize::Bit64)
    }

    /// Converts `value` as CIL would, with overflow checking.
    fn conv_ovf(value: ConstValue, target: SsaType, unsigned_source: bool) -> Option<ConstValue> {
        cil_convert_const_checked(&value, &target, unsigned_source, PointerSize::Bit64)
    }

    #[test]
    fn widening_an_int32_extends_it_as_the_conversion_says() {
        // conv.i8 sign-extends; conv.u8 zero-extends, as does any `.un` form.
        assert_eq!(
            conv(ConstValue::I32(-1), SsaType::I64, false),
            Some(ConstValue::I64(-1))
        );
        assert_eq!(
            conv(ConstValue::I32(-1), SsaType::U64, false),
            Some(ConstValue::U64(0xFFFF_FFFF))
        );
        assert_eq!(
            conv(ConstValue::I32(-1), SsaType::I64, true),
            Some(ConstValue::I64(0xFFFF_FFFF))
        );
        // conv.r.un reads the bits unsigned rather than declining.
        assert_eq!(
            conv(ConstValue::I32(-1), SsaType::F64, true),
            Some(ConstValue::from(4_294_967_295.0_f64))
        );
        // A uint32 on the stack is the same int32 bits: conv.i8 sign-extends it.
        assert_eq!(
            conv(ConstValue::U32(0xFFFF_FFFF), SsaType::I64, false),
            Some(ConstValue::I64(-1))
        );
        // Narrowing truncates either way.
        assert_eq!(
            conv(ConstValue::I32(0x1234), SsaType::U8, false),
            Some(ConstValue::U8(0x34))
        );
    }

    #[test]
    fn checked_conversions_range_check_the_source_as_it_is_read() {
        assert_eq!(conv_ovf(ConstValue::I32(-1), SsaType::U32, false), None);
        assert_eq!(
            conv_ovf(ConstValue::I32(-1), SsaType::U32, true),
            Some(ConstValue::U32(0xFFFF_FFFF))
        );
        assert_eq!(conv_ovf(ConstValue::I32(-1), SsaType::I32, true), None);
        assert_eq!(
            conv_ovf(ConstValue::I32(-1), SsaType::I8, false),
            Some(ConstValue::I8(-1))
        );
        assert_eq!(conv_ovf(ConstValue::I32(300), SsaType::U8, false), None);
        assert_eq!(
            conv_ovf(ConstValue::U64(u64::MAX), SsaType::U64, true),
            Some(ConstValue::U64(u64::MAX))
        );
        assert_eq!(
            conv_ovf(ConstValue::U64(u64::MAX), SsaType::I64, true),
            None
        );
    }

    #[test]
    fn cil_target_ptr_bytes() {
        assert_eq!(CilTarget::x64().ptr_bytes(), 8);
        assert_eq!(CilTarget::x86().ptr_bytes(), 4);
        assert_eq!(CilTarget::with_ptr_bytes(8).ptr_bytes(), 8);
        assert_eq!(CilTarget::default().ptr_bytes(), 8);
    }

    #[test]
    fn cil_target_type_queries() {
        assert!(CilTarget::is_integer(&SsaType::I32));
        assert!(CilTarget::is_integer(&SsaType::U64));
        assert!(!CilTarget::is_integer(&SsaType::F32));

        assert!(CilTarget::is_floating(&SsaType::F32));
        assert!(CilTarget::is_floating(&SsaType::F64));
        assert!(!CilTarget::is_floating(&SsaType::I32));

        assert!(CilTarget::is_signed(&SsaType::I32));
        assert!(!CilTarget::is_signed(&SsaType::U32));

        assert!(CilTarget::is_pointer(&SsaType::Pointer(Box::new(
            SsaType::I32
        ))));
        assert!(CilTarget::is_pointer(&SsaType::ByRef(Box::new(
            SsaType::I32
        ))));
        assert!(!CilTarget::is_pointer(&SsaType::I32));

        assert!(CilTarget::is_reference(&SsaType::Object));
        assert!(CilTarget::is_reference(&SsaType::String));
        assert!(!CilTarget::is_reference(&SsaType::I32));

        assert!(CilTarget::is_unknown(&SsaType::Unknown));
        assert!(CilTarget::is_unknown(&SsaType::Varying));
        assert!(!CilTarget::is_unknown(&SsaType::I32));

        assert_eq!(CilTarget::bit_width(&SsaType::I32), Some(32));
        assert_eq!(CilTarget::bit_width(&SsaType::I64), Some(64));
        assert_eq!(CilTarget::bit_width(&SsaType::Bool), Some(8));
        assert_eq!(CilTarget::bit_width(&SsaType::NativeInt), None);
    }

    #[test]
    fn cil_target_field_member_index() {
        // Distinct fields must get distinct cell identities, or field-sensitive
        // points-to collapses them onto one abstract cell.
        let a = FieldRef::new(Token::new(0x0400_0001));
        let b = FieldRef::new(Token::new(0x0400_0002));
        assert_ne!(
            CilTarget::field_member_index(&a),
            CilTarget::field_member_index(&b)
        );
        // Same field, asked twice, must be stable.
        assert_eq!(
            CilTarget::field_member_index(&a),
            CilTarget::field_member_index(&FieldRef::new(Token::new(0x0400_0001)))
        );
        // A MemberRef-sourced field is a different token, so it never collides
        // with a FieldDef of the same row.
        assert_ne!(
            CilTarget::field_member_index(&a),
            CilTarget::field_member_index(&FieldRef::new(Token::new(0x0A00_0001)))
        );
        // An unresolved (null) field takes the field-insensitive fallback.
        assert_eq!(
            CilTarget::field_member_index(&FieldRef::new(Token::new(0))),
            None
        );
    }

    #[test]
    fn cil_target_unknown() {
        assert_eq!(CilTarget::unknown_type(), SsaType::Unknown);
    }

    #[test]
    fn cil_target_synthetic_instruction() {
        let i = CilTarget::synthetic_instruction();
        assert_eq!(i.mnemonic, "synthetic");
        assert_eq!(i.size, 0);
    }

    /// End-to-end IR-core smoke test using `MockTarget`.
    ///
    /// Constructs an `SsaFunction<MockTarget>` end-to-end using the generic
    /// IR API. Lives in dotscope (rather than analyssa) until `SsaFunction`
    /// itself moves to analyssa. Once that happens, this test should migrate
    /// to a analyssa-side integration test.
    #[test]
    fn mock_target_builds_generic_ir() {
        // 1. Empty function with the mock target.
        let mut func = SsaFunction::<MockTarget>::new(1, 1);
        assert_eq!(func.num_args(), 1);
        assert_eq!(func.num_locals(), 1);
        assert!(func.is_empty());

        // 2. Allocate a few variables.
        let arg0 = func.create_variable(
            VariableOrigin::Argument(0),
            0,
            DefSite::phi(0),
            MockType::I32,
        );
        let const_var = func.create_variable(
            VariableOrigin::Local(0),
            0,
            DefSite::instruction(0, 0),
            MockType::I32,
        );
        let sum = func.create_variable(
            VariableOrigin::Local(1),
            0,
            DefSite::instruction(0, 1),
            MockType::I32,
        );
        assert_eq!(func.variable_count(), 3);
        assert_eq!(func.variable(arg0).unwrap().var_type(), &MockType::I32);

        // 3. Build a block: const = 42, sum = arg0 + const, return sum.
        let mut block: SsaBlock<MockTarget> = SsaBlock::new(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest: const_var,
            value: ConstValue::I32(42),
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
            dest: sum,
            left: arg0,
            right: const_var,
            flags: None,
        }));
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Return {
            value: Some(sum),
        }));
        assert_eq!(block.instruction_count(), 3);
        func.add_block(block);

        // 4. Iterate over the function's instructions.
        let instr_dests: Vec<Option<SsaVarId>> = func
            .iter_instructions()
            .map(|(_, _, instr)| instr.def())
            .collect();
        assert_eq!(instr_dests, vec![Some(const_var), Some(sum), None]);

        // 5. Confirm the IR carries `T::Type` values opaquely.
        for var in func.variables() {
            assert!(MockTarget::is_integer(var.var_type()));
        }
    }
}

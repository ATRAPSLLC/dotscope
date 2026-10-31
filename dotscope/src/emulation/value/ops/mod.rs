//! Operations for CIL emulation values.
//!
//! This module defines the operation types used during CIL bytecode emulation:
//!
//! - [`BinaryOp`] - Binary arithmetic and bitwise operations (`add`, `sub`, `mul`, `div`, etc.)
//! - [`UnaryOp`] - Unary operations (`neg`, `not`)
//! - [`CompareOp`] - Comparison operations (`ceq`, `clt`, `cgt`, etc.)
//! - [`ConversionType`] - Type conversion operations (`conv.i4`, `conv.r8`, etc.)
//!
//! # CIL Operation Semantics
//!
//! The operations follow ECMA-335 semantics for the CIL instruction set.
//! Operations are performed on stack types (I32, I64, F32, F64, NativeInt)
//! with appropriate widening and overflow behavior.
//!
//! # Operation Categories
//!
//! ## Arithmetic Operations
//!
//! Basic arithmetic (`Add`, `Sub`, `Mul`, `Div`, `Rem`) operates on numeric types
//! and wraps on overflow by default. Checked variants (`AddOvf`, `MulOvf`, etc.)
//! return errors on overflow.
//!
//! ## Bitwise Operations
//!
//! Bitwise operations (`And`, `Or`, `Xor`, `Shl`, `Shr`) are only valid for
//! integer types. Shift amounts are masked to the type width.
//!
//! ## Comparison Operations
//!
//! Comparisons return an I32 value (1 for true, 0 for false). Unsigned variants
//! (`GtUn`, `LtUn`) treat operands as unsigned integers.
//!
//! ## Conversions
//!
//! Conversions handle type changes between numeric types. Unchecked conversions
//! truncate silently, while checked variants (`I4Ovf`, `U1OvfUn`) return errors
//! when the value cannot be represented.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::emulation::{EmValue, BinaryOp, CompareOp, ConversionType};
//! use dotscope::metadata::typesystem::PointerSize;
//!
//! // Arithmetic operations
//! let a = EmValue::I32(10);
//! let b = EmValue::I32(3);
//! let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
//! assert_eq!(sum, EmValue::I32(13));
//!
//! // Comparisons
//! let cmp = a.compare(&b, CompareOp::Gt).unwrap();
//! assert_eq!(cmp, EmValue::I32(1)); // 10 > 3
//!
//! // Conversions
//! let converted = EmValue::I32(42).convert(ConversionType::I8, PointerSize::Bit64).unwrap();
//! assert_eq!(converted, EmValue::I64(42));
//! ```

mod binary;
mod comparison;
mod conversion;
mod unary;

use std::{borrow::Cow, fmt};

use crate::{emulation::value::EmValue, metadata::typesystem::CilFlavor};

impl EmValue {
    /// The value as the evaluation stack holds it (ECMA-335 I.12.1): a `bool` or a `char` is
    /// an `int32` there, whatever type the value was loaded as. Every operation reads its
    /// operands in this form; a value keeps its own type until then, for the calls that
    /// take it.
    pub(crate) fn on_stack(&self) -> Cow<'_, EmValue> {
        match self {
            EmValue::Bool(value) => Cow::Owned(EmValue::I32(i32::from(*value))),
            EmValue::Char(value) => Cow::Owned(EmValue::I32(i32::from_ne_bytes(
                u32::from(*value).to_ne_bytes(),
            ))),
            other => Cow::Borrowed(other),
        }
    }
}

/// Binary operations for CIL arithmetic and bitwise instructions.
///
/// These operations correspond to CIL instructions like `add`, `sub`, `mul`,
/// `div`, `rem`, `and`, `or`, `xor`, `shl`, `shr`.
///
/// # Overflow Behavior
///
/// By default, arithmetic operations wrap on overflow (following Rust's
/// wrapping semantics). For checked operations, use [`BinaryOp::is_checked`]
/// variants and handle `EmulationError::Overflow`.
///
/// # Type Combinations
///
/// Not all type combinations are valid for all operations. For example,
/// bitwise operations are only valid on integer types. The `EmValue::binary_op`
/// method returns an error for invalid combinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// Addition (`add`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Add,

    /// Addition with overflow check (`add.ovf`, `add.ovf.un`).
    ///
    /// Returns error on overflow.
    AddOvf,

    /// Unsigned addition with overflow check.
    AddOvfUn,

    /// Subtraction (`sub`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Sub,

    /// Subtraction with overflow check (`sub.ovf`, `sub.ovf.un`).
    SubOvf,

    /// Unsigned subtraction with overflow check.
    SubOvfUn,

    /// Multiplication (`mul`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Mul,

    /// Multiplication with overflow check (`mul.ovf`, `mul.ovf.un`).
    MulOvf,

    /// Unsigned multiplication with overflow check.
    MulOvfUn,

    /// Signed division (`div`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    /// Returns error for division by zero.
    Div,

    /// Unsigned division (`div.un`).
    ///
    /// Valid for: I32, I64, NativeInt
    DivUn,

    /// Signed remainder (`rem`).
    ///
    /// Valid for: I32, I64, NativeInt, F32, F64
    Rem,

    /// Unsigned remainder (`rem.un`).
    ///
    /// Valid for: I32, I64, NativeInt
    RemUn,

    /// Bitwise AND (`and`).
    ///
    /// Valid for: I32, I64, NativeInt
    And,

    /// Bitwise OR (`or`).
    ///
    /// Valid for: I32, I64, NativeInt
    Or,

    /// Bitwise XOR (`xor`).
    ///
    /// Valid for: I32, I64, NativeInt
    Xor,

    /// Shift left (`shl`).
    ///
    /// The right operand is the shift amount (masked to type width).
    Shl,

    /// Shift right (`shr`).
    ///
    /// Arithmetic (signed) shift right - preserves sign bit.
    Shr,

    /// Unsigned shift right (`shr.un`).
    ///
    /// Logical shift right - fills with zeros.
    ShrUn,
}

impl BinaryOp {
    /// Returns `true` if this is a checked (overflow-detecting) operation.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        matches!(
            self,
            BinaryOp::AddOvf
                | BinaryOp::AddOvfUn
                | BinaryOp::SubOvf
                | BinaryOp::SubOvfUn
                | BinaryOp::MulOvf
                | BinaryOp::MulOvfUn
        )
    }

    /// Returns `true` if this operation treats operands as unsigned.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            BinaryOp::AddOvfUn
                | BinaryOp::SubOvfUn
                | BinaryOp::MulOvfUn
                | BinaryOp::DivUn
                | BinaryOp::RemUn
                | BinaryOp::ShrUn
        )
    }

    /// Returns `true` if this is an arithmetic operation.
    #[must_use]
    pub fn is_arithmetic(&self) -> bool {
        matches!(
            self,
            BinaryOp::Add
                | BinaryOp::AddOvf
                | BinaryOp::AddOvfUn
                | BinaryOp::Sub
                | BinaryOp::SubOvf
                | BinaryOp::SubOvfUn
                | BinaryOp::Mul
                | BinaryOp::MulOvf
                | BinaryOp::MulOvfUn
                | BinaryOp::Div
                | BinaryOp::DivUn
                | BinaryOp::Rem
                | BinaryOp::RemUn
        )
    }

    /// Returns `true` if this is a bitwise operation.
    #[must_use]
    pub fn is_bitwise(&self) -> bool {
        matches!(
            self,
            BinaryOp::And
                | BinaryOp::Or
                | BinaryOp::Xor
                | BinaryOp::Shl
                | BinaryOp::Shr
                | BinaryOp::ShrUn
        )
    }
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryOp::Add => write!(f, "add"),
            BinaryOp::AddOvf => write!(f, "add.ovf"),
            BinaryOp::AddOvfUn => write!(f, "add.ovf.un"),
            BinaryOp::Sub => write!(f, "sub"),
            BinaryOp::SubOvf => write!(f, "sub.ovf"),
            BinaryOp::SubOvfUn => write!(f, "sub.ovf.un"),
            BinaryOp::Mul => write!(f, "mul"),
            BinaryOp::MulOvf => write!(f, "mul.ovf"),
            BinaryOp::MulOvfUn => write!(f, "mul.ovf.un"),
            BinaryOp::Div => write!(f, "div"),
            BinaryOp::DivUn => write!(f, "div.un"),
            BinaryOp::Rem => write!(f, "rem"),
            BinaryOp::RemUn => write!(f, "rem.un"),
            BinaryOp::And => write!(f, "and"),
            BinaryOp::Or => write!(f, "or"),
            BinaryOp::Xor => write!(f, "xor"),
            BinaryOp::Shl => write!(f, "shl"),
            BinaryOp::Shr => write!(f, "shr"),
            BinaryOp::ShrUn => write!(f, "shr.un"),
        }
    }
}

/// Unary operations for CIL instructions.
///
/// These operations correspond to CIL instructions like `neg` and `not`.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, UnaryOp};
/// use dotscope::metadata::typesystem::PointerSize;
///
/// let value = EmValue::I32(42);
/// let negated = value.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap();
/// assert_eq!(negated, EmValue::I32(-42));
///
/// let bits = EmValue::I32(0x0F);
/// let inverted = bits.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap();
/// assert_eq!(inverted, EmValue::I32(!0x0F));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// Negation (`neg`).
    ///
    /// Returns the two's complement negation for integers,
    /// or IEEE 754 negation for floats.
    Neg,

    /// Bitwise NOT (`not`).
    ///
    /// Returns the one's complement (all bits flipped).
    /// Only valid for integer types.
    Not,
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "neg"),
            UnaryOp::Not => write!(f, "not"),
        }
    }
}

/// Comparison operations for CIL instructions.
///
/// These operations correspond to CIL instructions like `ceq`, `cgt`, `clt`,
/// and the conditional branch instructions.
///
/// # Result Type
///
/// All comparisons produce an I32 result: 1 for true, 0 for false.
///
/// # Signed vs Unsigned
///
/// For integer comparisons, the unsigned variants (`GtUn`, `LtUn`, etc.) treat
/// the operands as unsigned integers. This is important for values like -1,
/// which is the largest unsigned value.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, CompareOp};
///
/// let a = EmValue::I32(10);
/// let b = EmValue::I32(20);
///
/// // Signed comparison
/// assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
///
/// // Unsigned comparison of -1 (largest unsigned) vs 1
/// let neg = EmValue::I32(-1);
/// let pos = EmValue::I32(1);
/// assert_eq!(neg.compare(&pos, CompareOp::Lt).unwrap(), EmValue::I32(1));   // signed: -1 < 1
/// assert_eq!(neg.compare(&pos, CompareOp::LtUn).unwrap(), EmValue::I32(0)); // unsigned: 0xFFFFFFFF > 1
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompareOp {
    /// Equal (`ceq`).
    Eq,

    /// Not equal (for branch instructions).
    Ne,

    /// Greater than, signed (`cgt`).
    Gt,

    /// Greater than, unsigned (`cgt.un`).
    GtUn,

    /// Greater than or equal, signed (for branch instructions).
    Ge,

    /// Greater than or equal, unsigned.
    GeUn,

    /// Less than, signed (`clt`).
    Lt,

    /// Less than, unsigned (`clt.un`).
    LtUn,

    /// Less than or equal, signed (for branch instructions).
    Le,

    /// Less than or equal, unsigned.
    LeUn,
}

impl CompareOp {
    /// Returns `true` if this is an unsigned comparison.
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            CompareOp::GtUn | CompareOp::GeUn | CompareOp::LtUn | CompareOp::LeUn
        )
    }

    /// Returns the negated comparison operation.
    #[must_use]
    pub fn negate(&self) -> Self {
        match self {
            CompareOp::Eq => CompareOp::Ne,
            CompareOp::Ne => CompareOp::Eq,
            CompareOp::Gt => CompareOp::Le,
            CompareOp::GtUn => CompareOp::LeUn,
            CompareOp::Ge => CompareOp::Lt,
            CompareOp::GeUn => CompareOp::LtUn,
            CompareOp::Lt => CompareOp::Ge,
            CompareOp::LtUn => CompareOp::GeUn,
            CompareOp::Le => CompareOp::Gt,
            CompareOp::LeUn => CompareOp::GtUn,
        }
    }

    /// Returns the swapped comparison (as if operands were swapped).
    #[must_use]
    pub fn swap(&self) -> Self {
        match self {
            CompareOp::Eq => CompareOp::Eq,
            CompareOp::Ne => CompareOp::Ne,
            CompareOp::Gt => CompareOp::Lt,
            CompareOp::GtUn => CompareOp::LtUn,
            CompareOp::Ge => CompareOp::Le,
            CompareOp::GeUn => CompareOp::LeUn,
            CompareOp::Lt => CompareOp::Gt,
            CompareOp::LtUn => CompareOp::GtUn,
            CompareOp::Le => CompareOp::Ge,
            CompareOp::LeUn => CompareOp::GeUn,
        }
    }
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareOp::Eq => write!(f, "ceq"),
            CompareOp::Ne => write!(f, "ne"),
            CompareOp::Gt => write!(f, "cgt"),
            CompareOp::GtUn => write!(f, "cgt.un"),
            CompareOp::Ge => write!(f, "ge"),
            CompareOp::GeUn => write!(f, "ge.un"),
            CompareOp::Lt => write!(f, "clt"),
            CompareOp::LtUn => write!(f, "clt.un"),
            CompareOp::Le => write!(f, "le"),
            CompareOp::LeUn => write!(f, "le.un"),
        }
    }
}

/// Type conversion operations for CIL instructions.
///
/// These correspond to the `conv.*` family of CIL instructions that convert
/// values between numeric types.
///
/// # Conversion Semantics
///
/// - Integer to integer: truncation or sign/zero extension
/// - Float to integer: truncation toward zero
/// - Integer to float: nearest representable value
/// - Float to float: nearest representable value or truncation
///
/// # Overflow Behavior
///
/// Unchecked conversions may lose data without error. Checked conversions
/// (the `*Ovf` variants) return an error if the value cannot be represented
/// in the target type.
///
/// # Examples
///
/// ```rust
/// use dotscope::emulation::{EmValue, ConversionType};
/// use dotscope::metadata::typesystem::PointerSize;
///
/// // Widening conversion (always succeeds)
/// let i32_val = EmValue::I32(42);
/// let i64_val = i32_val.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
/// assert_eq!(i64_val, EmValue::I64(42));
///
/// // Truncating conversion
/// let large = EmValue::I32(300);
/// let truncated = large.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
/// assert_eq!(truncated, EmValue::I32(44)); // 300 & 0xFF = 44, sign-extended
///
/// // Checked conversion that overflows
/// let value = EmValue::I32(200);
/// assert!(value.convert(ConversionType::I1Ovf, PointerSize::Bit64).is_err()); // 200 > 127
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConversionType {
    /// Convert to int8 (`conv.i1`).
    ///
    /// Truncates to 8 bits, then sign-extends to int32.
    I1,

    /// Convert to int16 (`conv.i2`).
    ///
    /// Truncates to 16 bits, then sign-extends to int32.
    I2,

    /// Convert to int32 (`conv.i4`).
    I4,

    /// Convert to int64 (`conv.i8`).
    I8,

    /// Convert to uint8 (`conv.u1`).
    ///
    /// Truncates to 8 bits, then zero-extends to int32.
    U1,

    /// Convert to uint16 (`conv.u2`).
    ///
    /// Truncates to 16 bits, then zero-extends to int32.
    U2,

    /// Convert to uint32 (`conv.u4`).
    U4,

    /// Convert to uint64 (`conv.u8`).
    U8,

    /// Convert to float32 (`conv.r4`).
    R4,

    /// Convert to float64 (`conv.r8`).
    R8,

    /// Convert to native int (`conv.i`).
    I,

    /// Convert to native uint (`conv.u`).
    U,

    /// Convert float to unsigned (`conv.r.un`).
    ///
    /// Converts unsigned integer to float (the source is treated as unsigned).
    RUn,

    // Checked conversions (overflow-checking)
    /// Convert to int8 with overflow check (`conv.ovf.i1`).
    I1Ovf,

    /// Convert to int16 with overflow check (`conv.ovf.i2`).
    I2Ovf,

    /// Convert to int32 with overflow check (`conv.ovf.i4`).
    I4Ovf,

    /// Convert to int64 with overflow check (`conv.ovf.i8`).
    I8Ovf,

    /// Convert to uint8 with overflow check (`conv.ovf.u1`).
    U1Ovf,

    /// Convert to uint16 with overflow check (`conv.ovf.u2`).
    U2Ovf,

    /// Convert to uint32 with overflow check (`conv.ovf.u4`).
    U4Ovf,

    /// Convert to uint64 with overflow check (`conv.ovf.u8`).
    U8Ovf,

    /// Convert to native int with overflow check (`conv.ovf.i`).
    IOvf,

    /// Convert to native uint with overflow check (`conv.ovf.u`).
    UOvf,

    // Unsigned source checked conversions
    /// Convert unsigned to int8 with overflow check (`conv.ovf.i1.un`).
    I1OvfUn,

    /// Convert unsigned to int16 with overflow check (`conv.ovf.i2.un`).
    I2OvfUn,

    /// Convert unsigned to int32 with overflow check (`conv.ovf.i4.un`).
    I4OvfUn,

    /// Convert unsigned to int64 with overflow check (`conv.ovf.i8.un`).
    I8OvfUn,

    /// Convert unsigned to uint8 with overflow check (`conv.ovf.u1.un`).
    U1OvfUn,

    /// Convert unsigned to uint16 with overflow check (`conv.ovf.u2.un`).
    U2OvfUn,

    /// Convert unsigned to uint32 with overflow check (`conv.ovf.u4.un`).
    U4OvfUn,

    /// Convert unsigned to uint64 with overflow check (`conv.ovf.u8.un`).
    U8OvfUn,

    /// Convert unsigned to native int with overflow check (`conv.ovf.i.un`).
    IOvfUn,

    /// Convert unsigned to native uint with overflow check (`conv.ovf.u.un`).
    UOvfUn,
}

impl ConversionType {
    /// Returns `true` if this is a checked (overflow-detecting) conversion.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        matches!(
            self,
            ConversionType::I1Ovf
                | ConversionType::I2Ovf
                | ConversionType::I4Ovf
                | ConversionType::I8Ovf
                | ConversionType::U1Ovf
                | ConversionType::U2Ovf
                | ConversionType::U4Ovf
                | ConversionType::U8Ovf
                | ConversionType::IOvf
                | ConversionType::UOvf
                | ConversionType::I1OvfUn
                | ConversionType::I2OvfUn
                | ConversionType::I4OvfUn
                | ConversionType::I8OvfUn
                | ConversionType::U1OvfUn
                | ConversionType::U2OvfUn
                | ConversionType::U4OvfUn
                | ConversionType::U8OvfUn
                | ConversionType::IOvfUn
                | ConversionType::UOvfUn
        )
    }

    /// Returns `true` if the source should be treated as unsigned.
    #[must_use]
    pub fn is_unsigned_source(&self) -> bool {
        matches!(
            self,
            ConversionType::RUn
                | ConversionType::I1OvfUn
                | ConversionType::I2OvfUn
                | ConversionType::I4OvfUn
                | ConversionType::I8OvfUn
                | ConversionType::U1OvfUn
                | ConversionType::U2OvfUn
                | ConversionType::U4OvfUn
                | ConversionType::U8OvfUn
                | ConversionType::IOvfUn
                | ConversionType::UOvfUn
        )
    }

    /// Returns the target CIL flavor for this conversion.
    #[must_use]
    pub fn target_cil_flavor(&self) -> CilFlavor {
        match self {
            ConversionType::I1
            | ConversionType::I2
            | ConversionType::I4
            | ConversionType::U1
            | ConversionType::U2
            | ConversionType::U4
            | ConversionType::I1Ovf
            | ConversionType::I2Ovf
            | ConversionType::I4Ovf
            | ConversionType::U1Ovf
            | ConversionType::U2Ovf
            | ConversionType::U4Ovf
            | ConversionType::I1OvfUn
            | ConversionType::I2OvfUn
            | ConversionType::I4OvfUn
            | ConversionType::U1OvfUn
            | ConversionType::U2OvfUn
            | ConversionType::U4OvfUn => CilFlavor::I4,

            ConversionType::I8
            | ConversionType::U8
            | ConversionType::I8Ovf
            | ConversionType::U8Ovf
            | ConversionType::I8OvfUn
            | ConversionType::U8OvfUn => CilFlavor::I8,

            ConversionType::R4 => CilFlavor::R4,
            ConversionType::R8 | ConversionType::RUn => CilFlavor::R8,

            ConversionType::I
            | ConversionType::U
            | ConversionType::IOvf
            | ConversionType::UOvf
            | ConversionType::IOvfUn
            | ConversionType::UOvfUn => CilFlavor::I,
        }
    }
}

impl fmt::Display for ConversionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionType::I1 => write!(f, "conv.i1"),
            ConversionType::I2 => write!(f, "conv.i2"),
            ConversionType::I4 => write!(f, "conv.i4"),
            ConversionType::I8 => write!(f, "conv.i8"),
            ConversionType::U1 => write!(f, "conv.u1"),
            ConversionType::U2 => write!(f, "conv.u2"),
            ConversionType::U4 => write!(f, "conv.u4"),
            ConversionType::U8 => write!(f, "conv.u8"),
            ConversionType::R4 => write!(f, "conv.r4"),
            ConversionType::R8 => write!(f, "conv.r8"),
            ConversionType::I => write!(f, "conv.i"),
            ConversionType::U => write!(f, "conv.u"),
            ConversionType::RUn => write!(f, "conv.r.un"),
            ConversionType::I1Ovf => write!(f, "conv.ovf.i1"),
            ConversionType::I2Ovf => write!(f, "conv.ovf.i2"),
            ConversionType::I4Ovf => write!(f, "conv.ovf.i4"),
            ConversionType::I8Ovf => write!(f, "conv.ovf.i8"),
            ConversionType::U1Ovf => write!(f, "conv.ovf.u1"),
            ConversionType::U2Ovf => write!(f, "conv.ovf.u2"),
            ConversionType::U4Ovf => write!(f, "conv.ovf.u4"),
            ConversionType::U8Ovf => write!(f, "conv.ovf.u8"),
            ConversionType::IOvf => write!(f, "conv.ovf.i"),
            ConversionType::UOvf => write!(f, "conv.ovf.u"),
            ConversionType::I1OvfUn => write!(f, "conv.ovf.i1.un"),
            ConversionType::I2OvfUn => write!(f, "conv.ovf.i2.un"),
            ConversionType::I4OvfUn => write!(f, "conv.ovf.i4.un"),
            ConversionType::I8OvfUn => write!(f, "conv.ovf.i8.un"),
            ConversionType::U1OvfUn => write!(f, "conv.ovf.u1.un"),
            ConversionType::U2OvfUn => write!(f, "conv.ovf.u2.un"),
            ConversionType::U4OvfUn => write!(f, "conv.ovf.u4.un"),
            ConversionType::U8OvfUn => write!(f, "conv.ovf.u8.un"),
            ConversionType::IOvfUn => write!(f, "conv.ovf.i.un"),
            ConversionType::UOvfUn => write!(f, "conv.ovf.u.un"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{emulation::engine::EmulationError, metadata::typesystem::PointerSize};

    /// A `char` or `bool` operand is the `int32` the evaluation stack holds, for every kind
    /// of operation: `input[i] ^ key` in a loop over a string, `c >= 'a'`, a flag summed.
    #[test]
    fn a_char_or_bool_operand_is_its_int32() {
        let bits = PointerSize::Bit64;
        let h = EmValue::Char('H');
        assert_eq!(
            h.binary_op(&EmValue::I32(42), BinaryOp::Xor, bits).unwrap(),
            EmValue::I32(i32::from(b'H') ^ 42)
        );
        assert_eq!(
            EmValue::Bool(true)
                .binary_op(&EmValue::I32(1), BinaryOp::Add, bits)
                .unwrap(),
            EmValue::I32(2)
        );
        assert_eq!(
            h.compare(&EmValue::I32(i32::from(b'a')), CompareOp::Lt)
                .unwrap(),
            EmValue::I32(1)
        );
        assert_eq!(
            EmValue::I32(i32::from(b'z'))
                .compare(&EmValue::Char('z'), CompareOp::Gt)
                .unwrap(),
            EmValue::I32(0)
        );
        assert_eq!(
            h.compare(&EmValue::I32(i32::from(b'H')), CompareOp::Eq)
                .unwrap(),
            EmValue::I32(1)
        );
        assert_eq!(
            h.unary_op(UnaryOp::Neg, bits).unwrap(),
            EmValue::I32(-i32::from(b'H'))
        );
    }

    #[test]
    fn test_binary_op_is_checked() {
        assert!(BinaryOp::AddOvf.is_checked());
        assert!(BinaryOp::MulOvfUn.is_checked());
        assert!(!BinaryOp::Add.is_checked());
        assert!(!BinaryOp::Div.is_checked());
    }

    #[test]
    fn test_binary_op_is_unsigned() {
        assert!(BinaryOp::DivUn.is_unsigned());
        assert!(BinaryOp::ShrUn.is_unsigned());
        assert!(!BinaryOp::Div.is_unsigned());
        assert!(!BinaryOp::Shr.is_unsigned());
    }

    #[test]
    fn test_compare_op_negate() {
        assert_eq!(CompareOp::Eq.negate(), CompareOp::Ne);
        assert_eq!(CompareOp::Lt.negate(), CompareOp::Ge);
        assert_eq!(CompareOp::Gt.negate(), CompareOp::Le);
    }

    #[test]
    fn test_compare_op_swap() {
        assert_eq!(CompareOp::Lt.swap(), CompareOp::Gt);
        assert_eq!(CompareOp::Ge.swap(), CompareOp::Le);
        assert_eq!(CompareOp::Eq.swap(), CompareOp::Eq);
    }

    #[test]
    fn test_conversion_type_target_cil_flavor() {
        assert_eq!(ConversionType::I1.target_cil_flavor(), CilFlavor::I4);
        assert_eq!(ConversionType::I8.target_cil_flavor(), CilFlavor::I8);
        assert_eq!(ConversionType::R4.target_cil_flavor(), CilFlavor::R4);
        assert_eq!(ConversionType::R8.target_cil_flavor(), CilFlavor::R8);
        assert_eq!(ConversionType::I.target_cil_flavor(), CilFlavor::I);
    }

    #[test]
    fn test_binary_op_display() {
        assert_eq!(format!("{}", BinaryOp::Add), "add");
        assert_eq!(format!("{}", BinaryOp::AddOvf), "add.ovf");
        assert_eq!(format!("{}", BinaryOp::DivUn), "div.un");
    }

    #[test]
    fn test_unary_op_display() {
        assert_eq!(format!("{}", UnaryOp::Neg), "neg");
        assert_eq!(format!("{}", UnaryOp::Not), "not");
    }

    #[test]
    fn test_compare_op_display() {
        assert_eq!(format!("{}", CompareOp::Eq), "ceq");
        assert_eq!(format!("{}", CompareOp::Lt), "clt");
        assert_eq!(format!("{}", CompareOp::GtUn), "cgt.un");
    }

    #[test]
    fn test_conversion_type_display() {
        assert_eq!(format!("{}", ConversionType::I4), "conv.i4");
        assert_eq!(format!("{}", ConversionType::I8Ovf), "conv.ovf.i8");
        assert_eq!(format!("{}", ConversionType::U4OvfUn), "conv.ovf.u4.un");
    }

    #[test]
    fn test_operation_error_display() {
        let err = EmulationError::DivisionByZero;
        assert_eq!(format!("{}", err), "division by zero");

        let err = EmulationError::ArithmeticOverflow;
        assert_eq!(format!("{}", err), "arithmetic overflow");
    }
}

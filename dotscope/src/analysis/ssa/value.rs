//! Re-export shim + CIL-specific extension surface for `ConstValue`.
//!
//! The generic `ConstValue<T>`, `AbstractValue<T>`, `ComputedValue`, and
//! `ComputedOp` types live in `analyssa::ir::value`. This module:
//!
//! - Re-exports them with type aliases so callers writing `ConstValue` (no
//!   `T` parameter) keep getting `ConstValue<CilTarget>` for back-compat.
//! - Adds the CIL-specific extension trait [`ConstValueCilExt`] for
//!   `ssa_type` / `as_string_content`, which need `SsaType` / `CilObject`
//!   (foreign types from analyssa's perspective).
//! - Adds `TryFrom<&ConstValue<CilTarget>> for Immediate` for instruction
//!   encoding (orphan-rule allowed: `Immediate` is local).

use analyssa::ir::{value::ConstValue as AnalyssaConstValue, FloatFormat};

use crate::{
    analysis::ssa::{target::CilTarget, types::SsaType},
    assembly::Immediate,
    CilObject, Error,
};

// Type aliases preserve the `T = CilTarget` default so existing callers
// writing `ConstValue` (no params) compile. `ComputedValue`/`ComputedOp`
// aren't re-exported because the original dotscope `value.rs` didn't
// re-export them either — direct callers use `analyssa::ir::value::ComputedOp`.

/// CIL-defaulted alias of `analyssa::ir::value::ConstValue`.
pub type ConstValue<T = CilTarget> = AnalyssaConstValue<T>;

/// CIL-defaulted alias of `analyssa::ir::value::AbstractValue`.
pub type AbstractValue<T = CilTarget> = analyssa::ir::value::AbstractValue<T>;

/// CIL-specific extension methods on `ConstValue<CilTarget>`.
///
/// These can't be inherent impls (orphan rule: `ConstValue` is in analyssa) so
/// they're a trait. Import this trait to call `value.ssa_type()` and
/// `value.as_string_content(&assembly)` as before.
pub trait ConstValueCilExt {
    /// Returns the SSA type corresponding to this constant value.
    fn ssa_type(&self) -> SsaType;

    /// Returns string content, resolving `#US` heap indices via the assembly.
    ///
    /// Returns `Some` for `DecryptedString` (directly) and `String` (via heap
    /// lookup). Returns `None` for all other variants.
    fn as_string_content(&self, assembly: &CilObject) -> Option<String>;
}

impl ConstValueCilExt for AnalyssaConstValue<CilTarget> {
    fn ssa_type(&self) -> SsaType {
        match self {
            AnalyssaConstValue::I8(_) => SsaType::I8,
            AnalyssaConstValue::I16(_) => SsaType::I16,
            AnalyssaConstValue::I32(_) => SsaType::I32,
            AnalyssaConstValue::I64(_) => SsaType::I64,
            AnalyssaConstValue::U8(_) => SsaType::U8,
            AnalyssaConstValue::U16(_) => SsaType::U16,
            AnalyssaConstValue::U32(_) => SsaType::U32,
            AnalyssaConstValue::U64(_) => SsaType::U64,
            AnalyssaConstValue::NativeInt(_)
            | AnalyssaConstValue::Type(_)
            | AnalyssaConstValue::MethodHandle(_)
            | AnalyssaConstValue::FieldHandle(_) => SsaType::NativeInt,
            AnalyssaConstValue::NativeUInt(_) => SsaType::NativeUInt,
            AnalyssaConstValue::True | AnalyssaConstValue::False => SsaType::Bool,
            AnalyssaConstValue::Null
            | AnalyssaConstValue::String(_)
            | AnalyssaConstValue::DecryptedString(_)
            | AnalyssaConstValue::DecryptedArray { .. } => SsaType::Object,
            // Constants of the native substrate CIL has no type for: SIMD vectors, and float
            // formats other than binary32 and binary64.
            AnalyssaConstValue::Float(bits) => match bits.format() {
                FloatFormat::Single => SsaType::F32,
                FloatFormat::Double => SsaType::F64,
                _ => SsaType::Unknown,
            },
            AnalyssaConstValue::Vector(_) => SsaType::Unknown,
            // Uninhabited for this target: CIL has no symbol space.
            AnalyssaConstValue::Symbol(symbol) => match *symbol {},
        }
    }

    fn as_string_content(&self, assembly: &CilObject) -> Option<String> {
        match self {
            AnalyssaConstValue::DecryptedString(s) => Some(s.to_string()),
            AnalyssaConstValue::String(idx) => assembly
                .userstrings()
                .and_then(|us| us.get(*idx as usize).ok())
                .map(|s| s.to_string_lossy()),
            _ => None,
        }
    }
}

/// Attempts to convert a `ConstValue` to an `Immediate` for CIL instruction
/// encoding. Mirrors the original CIL-specific TryFrom impl from when
/// `ConstValue` lived in dotscope.
impl TryFrom<&AnalyssaConstValue<CilTarget>> for Immediate {
    type Error = Error;

    #[allow(clippy::cast_possible_wrap)] // Intentional bit-preserving casts for CIL semantics
    fn try_from(value: &AnalyssaConstValue<CilTarget>) -> Result<Self, Self::Error> {
        match value {
            // Uninhabited for this target: CIL has no symbol space.
            AnalyssaConstValue::Symbol(symbol) => match *symbol {},
            AnalyssaConstValue::I8(v) => Ok(Immediate::Int8(*v)),
            AnalyssaConstValue::I16(v) => Ok(Immediate::Int16(*v)),
            AnalyssaConstValue::I32(v) => Ok(Immediate::Int32(*v)),

            AnalyssaConstValue::U8(v) => Ok(Immediate::Int8(*v as i8)),
            AnalyssaConstValue::U16(v) => Ok(Immediate::Int16(*v as i16)),
            AnalyssaConstValue::U32(v) => Ok(Immediate::Int32(*v as i32)),

            AnalyssaConstValue::I64(v) | AnalyssaConstValue::NativeInt(v) => {
                Ok(Immediate::Int64(*v))
            }
            AnalyssaConstValue::U64(v) | AnalyssaConstValue::NativeUInt(v) => {
                Ok(Immediate::Int64(*v as i64))
            }

            AnalyssaConstValue::Float(bits) => match bits.format() {
                FloatFormat::Single => f32::try_from(*bits).map(Immediate::Float32),
                FloatFormat::Double => f64::try_from(*bits).map(Immediate::Float64),
                _ => Err(*bits),
            }
            .map_err(|bits| {
                Error::SsaError(format!("{bits:?} has a float format CIL cannot load"))
            }),

            AnalyssaConstValue::True => Ok(Immediate::Int32(1)),
            AnalyssaConstValue::False => Ok(Immediate::Int32(0)),

            AnalyssaConstValue::String(_)
            | AnalyssaConstValue::DecryptedString(_)
            | AnalyssaConstValue::Vector(_)
            | AnalyssaConstValue::DecryptedArray { .. }
            | AnalyssaConstValue::Null
            | AnalyssaConstValue::Type(_)
            | AnalyssaConstValue::MethodHandle(_)
            | AnalyssaConstValue::FieldHandle(_) => Err(Error::SsaError(format!(
                "Cannot convert {value:?} to Immediate - use pattern matching to handle this case"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use analyssa::ir::{
        value::{ComputedOp, ComputedValue},
        variable::SsaVarId,
    };

    use super::*;
    use crate::metadata::typesystem::PointerSize;

    // Tests construct unit/numeric variants like `ConstValue::I32(_)` that
    // don't constrain the `T` type parameter. Type-parameter defaults aren't
    // used to break inference ambiguity in expression position, so we shadow
    // the names here to lock T to CilTarget for the entire test module.
    type ConstValue = super::ConstValue<CilTarget>;
    type AbstractValue = super::AbstractValue<CilTarget>;

    #[test]
    fn test_const_arithmetic() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(3);

        assert_eq!(a.add(&b, PointerSize::Bit64), Some(ConstValue::I32(13)));
        assert_eq!(a.sub(&b, PointerSize::Bit64), Some(ConstValue::I32(7)));
        assert_eq!(a.mul(&b, PointerSize::Bit64), Some(ConstValue::I32(30)));
    }

    #[test]
    fn test_const_comparison() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(3);
        let c = ConstValue::I32(10);

        assert_eq!(a.ceq(&b), Some(ConstValue::False));
        assert_eq!(a.ceq(&c), Some(ConstValue::True));
        assert_eq!(a.clt(&b, PointerSize::Bit64), Some(ConstValue::False));
        assert_eq!(b.clt(&a, PointerSize::Bit64), Some(ConstValue::True));
    }

    #[test]
    fn test_const_bool_conversion() {
        assert_eq!(ConstValue::True.as_bool(), Some(true));
        assert_eq!(ConstValue::False.as_bool(), Some(false));
        assert_eq!(ConstValue::I32(0).as_bool(), Some(false));
        assert_eq!(ConstValue::I32(42).as_bool(), Some(true));
        assert_eq!(ConstValue::Null.as_bool(), Some(false));
    }

    #[test]
    fn test_abstract_value_meet() {
        // Top meets anything yields the other
        assert_eq!(
            AbstractValue::Top.meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Constant(ConstValue::I32(5))
        );

        // Same constants stay constant
        assert_eq!(
            AbstractValue::Constant(ConstValue::I32(5))
                .meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Constant(ConstValue::I32(5))
        );

        // Different constants become Bottom
        assert_eq!(
            AbstractValue::Constant(ConstValue::I32(5))
                .meet(&AbstractValue::Constant(ConstValue::I32(10))),
            AbstractValue::Bottom
        );

        // Bottom meets anything yields Bottom
        assert_eq!(
            AbstractValue::Bottom.meet(&AbstractValue::Constant(ConstValue::I32(5))),
            AbstractValue::Bottom
        );
    }

    #[test]
    fn test_range_merge() {
        let r1 = AbstractValue::Range { min: 0, max: 10 };
        let r2 = AbstractValue::Range { min: 5, max: 15 };

        assert_eq!(r1.meet(&r2), AbstractValue::Range { min: 0, max: 15 });
    }

    #[test]
    fn test_computed_value_normalization() {
        let v0 = SsaVarId::from_index(0);
        let v1 = SsaVarId::from_index(1);

        // add(v1, v0) should normalize to add(v0, v1)
        let cv1 = ComputedValue::binary(ComputedOp::Add, v1, v0).normalized();
        let cv2 = ComputedValue::binary(ComputedOp::Add, v0, v1).normalized();

        assert_eq!(cv1, cv2);

        // sub is not commutative, should not normalize
        let cv3 = ComputedValue::binary(ComputedOp::Sub, v1, v0).normalized();
        let cv4 = ComputedValue::binary(ComputedOp::Sub, v0, v1).normalized();

        assert_ne!(cv3, cv4);
    }

    #[test]
    fn test_is_zero() {
        // All integer zeros
        assert!(ConstValue::I8(0).is_zero());
        assert!(ConstValue::I16(0).is_zero());
        assert!(ConstValue::I32(0).is_zero());
        assert!(ConstValue::I64(0).is_zero());
        assert!(ConstValue::U8(0).is_zero());
        assert!(ConstValue::U16(0).is_zero());
        assert!(ConstValue::U32(0).is_zero());
        assert!(ConstValue::U64(0).is_zero());
        assert!(ConstValue::NativeInt(0).is_zero());
        assert!(ConstValue::NativeUInt(0).is_zero());
        assert!(ConstValue::False.is_zero());

        // Non-zeros
        assert!(!ConstValue::I32(1).is_zero());
        assert!(!ConstValue::I32(-1).is_zero());
        assert!(!ConstValue::True.is_zero());
        assert!(!ConstValue::Null.is_zero()); // Null is not zero
    }

    #[test]
    fn test_is_one() {
        // All integer ones
        assert!(ConstValue::I8(1).is_one());
        assert!(ConstValue::I16(1).is_one());
        assert!(ConstValue::I32(1).is_one());
        assert!(ConstValue::I64(1).is_one());
        assert!(ConstValue::U8(1).is_one());
        assert!(ConstValue::U16(1).is_one());
        assert!(ConstValue::U32(1).is_one());
        assert!(ConstValue::U64(1).is_one());
        assert!(ConstValue::NativeInt(1).is_one());
        assert!(ConstValue::NativeUInt(1).is_one());
        assert!(ConstValue::True.is_one());

        // Non-ones
        assert!(!ConstValue::I32(0).is_one());
        assert!(!ConstValue::I32(2).is_one());
        assert!(!ConstValue::False.is_one());
    }

    #[test]
    fn test_is_minus_one() {
        // Signed -1 values
        assert!(ConstValue::I8(-1).is_minus_one());
        assert!(ConstValue::I16(-1).is_minus_one());
        assert!(ConstValue::I32(-1).is_minus_one());
        assert!(ConstValue::I64(-1).is_minus_one());
        assert!(ConstValue::NativeInt(-1).is_minus_one());

        // Not -1
        assert!(!ConstValue::I32(0).is_minus_one());
        assert!(!ConstValue::I32(1).is_minus_one());
        // Unsigned types cannot represent -1
        assert!(!ConstValue::U32(u32::MAX).is_minus_one());
    }

    #[test]
    fn test_convert_to_widening() {
        // i32 -> i64 (sign extends)
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::I64, false, 8),
            Some(ConstValue::I64(42))
        );

        // i32 -> i64 with negative
        let v = ConstValue::I32(-42);
        assert_eq!(
            v.convert_to(&SsaType::I64, false, 8),
            Some(ConstValue::I64(-42))
        );

        // u32 -> u64 (zero extends)
        let v = ConstValue::U32(42);
        assert_eq!(
            v.convert_to(&SsaType::U64, false, 8),
            Some(ConstValue::U64(42))
        );
    }

    #[test]
    fn test_convert_to_narrowing() {
        // i32 -> i8 (truncates)
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::I8, false, 8),
            Some(ConstValue::I8(42))
        );

        // i32 -> i8 truncation with overflow
        let v = ConstValue::I32(1000);
        // 1000 = 0x3E8, truncated to i8 = 0xE8 = -24 (signed)
        assert_eq!(
            v.convert_to(&SsaType::I8, false, 8),
            Some(ConstValue::I8(-24))
        );

        // i64 -> i32 (truncates)
        let v = ConstValue::I64(0x1_0000_0042);
        assert_eq!(
            v.convert_to(&SsaType::I32, false, 8),
            Some(ConstValue::I32(0x42))
        );
    }

    #[test]
    fn test_convert_to_float() {
        // i32 -> f32
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::F32, false, 8),
            Some(ConstValue::from(42.0_f32))
        );

        // i32 -> f64
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::F64, false, 8),
            Some(ConstValue::from(42.0_f64))
        );

        // Unsigned source to float
        let v = ConstValue::U32(42);
        assert_eq!(
            v.convert_to(&SsaType::F32, true, 8),
            Some(ConstValue::from(42.0_f32))
        );
    }

    #[test]
    fn test_convert_to_bool() {
        // Non-zero -> true
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::Bool, false, 8),
            Some(ConstValue::True)
        );

        // Zero -> false
        let v = ConstValue::I32(0);
        assert_eq!(
            v.convert_to(&SsaType::Bool, false, 8),
            Some(ConstValue::False)
        );
    }

    #[test]
    fn test_convert_to_checked_in_range() {
        // Value fits in target
        let v = ConstValue::I32(100);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, 8),
            Some(ConstValue::I8(100))
        );

        // Value at boundary
        let v = ConstValue::I32(127);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, 8),
            Some(ConstValue::I8(127))
        );

        let v = ConstValue::I32(-128);
        assert_eq!(
            v.convert_to_checked(&SsaType::I8, false, 8),
            Some(ConstValue::I8(-128))
        );
    }

    #[test]
    fn test_convert_to_checked_overflow() {
        // Value overflows target
        let v = ConstValue::I32(1000);
        assert_eq!(v.convert_to_checked(&SsaType::I8, false, 8), None);

        // Negative to unsigned
        let v = ConstValue::I32(-1);
        assert_eq!(v.convert_to_checked(&SsaType::U8, false, 8), None);
        assert_eq!(v.convert_to_checked(&SsaType::U32, false, 8), None);
        assert_eq!(v.convert_to_checked(&SsaType::U64, false, 8), None);
    }

    #[test]
    fn test_convert_to_char() {
        // i32 -> char (u16)
        let v = ConstValue::I32(65); // 'A'
        assert_eq!(
            v.convert_to(&SsaType::Char, false, 8),
            Some(ConstValue::U16(65))
        );
    }

    #[test]
    fn test_convert_to_native() {
        // i32 -> NativeInt
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::NativeInt, false, 8),
            Some(ConstValue::NativeInt(42))
        );

        // i32 -> NativeUInt
        let v = ConstValue::I32(42);
        assert_eq!(
            v.convert_to(&SsaType::NativeUInt, false, 8),
            Some(ConstValue::NativeUInt(42))
        );
    }

    #[test]
    fn test_const_div() {
        let a = ConstValue::I32(100);
        let b = ConstValue::I32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I32(14)));

        // Unsigned division (uses U32 type)
        let a = ConstValue::U32(100);
        let b = ConstValue::U32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::U32(14)));

        // i64 division
        let a = ConstValue::I64(1000);
        let b = ConstValue::I64(33);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I64(30)));
    }

    #[test]
    fn test_const_div_by_zero() {
        let a = ConstValue::I32(100);
        let zero = ConstValue::I32(0);
        assert_eq!(a.div(&zero, PointerSize::Bit64), None);

        let a = ConstValue::U64(100);
        let zero = ConstValue::U64(0);
        assert_eq!(a.div(&zero, PointerSize::Bit64), None);
    }

    #[test]
    fn test_const_div_negative() {
        let a = ConstValue::I32(-100);
        let b = ConstValue::I32(7);
        assert_eq!(a.div(&b, PointerSize::Bit64), Some(ConstValue::I32(-14))); // -100 / 7 = -14
    }

    #[test]
    fn test_const_rem() {
        let a = ConstValue::I32(100);
        let b = ConstValue::I32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::I32(2))); // 100 % 7 = 2

        // Unsigned remainder
        let a = ConstValue::U32(100);
        let b = ConstValue::U32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::U32(2)));
    }

    #[test]
    fn test_const_rem_by_zero() {
        let a = ConstValue::I32(100);
        let zero = ConstValue::I32(0);
        assert_eq!(a.rem(&zero, PointerSize::Bit64), None);
    }

    #[test]
    fn test_const_rem_negative() {
        let a = ConstValue::I32(-100);
        let b = ConstValue::I32(7);
        assert_eq!(a.rem(&b, PointerSize::Bit64), Some(ConstValue::I32(-2)));
        // -100 % 7 = -2
    }

    #[test]
    fn test_const_shl() {
        let a = ConstValue::I32(1);
        let shift = ConstValue::I32(4);
        assert_eq!(a.shl(&shift, PointerSize::Bit64), Some(ConstValue::I32(16))); // 1 << 4 = 16

        // Larger shift
        let a = ConstValue::I32(1);
        let shift = ConstValue::I32(31);
        assert_eq!(
            a.shl(&shift, PointerSize::Bit64),
            Some(ConstValue::I32(i32::MIN))
        ); // 1 << 31 = MIN_VALUE
    }

    #[test]
    fn test_const_shr_signed() {
        let a = ConstValue::I32(-16);
        let shift = ConstValue::I32(2);
        assert_eq!(
            a.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I32(-4))
        ); // Sign preserved

        let b = ConstValue::I32(16);
        let shift = ConstValue::I32(2);
        assert_eq!(
            b.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I32(4))
        );
    }

    #[test]
    fn test_const_shr_unsigned() {
        let a = ConstValue::I32(-1); // All 1s in two's complement
        let shift = ConstValue::I32(1);
        // Unsigned right shift fills with 0
        let result = a.shr(&shift, true, PointerSize::Bit64);
        assert!(result.is_some());
        // -1 >> 1 (unsigned) = 0x7FFFFFFF
        if let Some(ConstValue::I32(v)) = result {
            assert_eq!(v, 0x7FFFFFFF);
        }
    }

    #[test]
    fn test_const_shr_i64() {
        let a = ConstValue::I64(256);
        let shift = ConstValue::I32(4);
        assert_eq!(
            a.shr(&shift, false, PointerSize::Bit64),
            Some(ConstValue::I64(16))
        );
    }

    #[test]
    fn test_const_cgt() {
        let a = ConstValue::I32(10);
        let b = ConstValue::I32(5);
        assert_eq!(a.cgt(&b, PointerSize::Bit64), Some(ConstValue::True));
        assert_eq!(b.cgt(&a, PointerSize::Bit64), Some(ConstValue::False));
        assert_eq!(a.cgt(&a, PointerSize::Bit64), Some(ConstValue::False)); // Equal means not greater
    }

    #[test]
    fn test_const_cgt_i64() {
        let a = ConstValue::I64(1000);
        let b = ConstValue::I64(500);
        assert_eq!(a.cgt(&b, PointerSize::Bit64), Some(ConstValue::True));
    }

    #[test]
    fn test_const_clt_negative() {
        let a = ConstValue::I32(-10);
        let b = ConstValue::I32(5);
        assert_eq!(a.clt(&b, PointerSize::Bit64), Some(ConstValue::True)); // -10 < 5
    }

    #[test]
    fn test_const_float_arithmetic() {
        let a = ConstValue::from(10.5_f32);
        let b = ConstValue::from(2.5_f32);
        assert_eq!(
            a.add(&b, PointerSize::Bit64),
            Some(ConstValue::from(13.0_f32))
        );
        assert_eq!(
            a.sub(&b, PointerSize::Bit64),
            Some(ConstValue::from(8.0_f32))
        );
        assert_eq!(
            a.mul(&b, PointerSize::Bit64),
            Some(ConstValue::from(26.25_f32))
        );

        let a = ConstValue::from(100.0_f64);
        let b = ConstValue::from(4.0_f64);
        assert_eq!(
            a.div(&b, PointerSize::Bit64),
            Some(ConstValue::from(25.0_f64))
        );
    }

    #[test]
    fn test_const_float_comparison() {
        let a = ConstValue::from(std::f64::consts::PI);
        let b = ConstValue::from(std::f64::consts::E);
        assert_eq!(a.cgt(&b, PointerSize::Bit64), Some(ConstValue::True));
        assert_eq!(a.clt(&b, PointerSize::Bit64), Some(ConstValue::False));
        assert_eq!(a.ceq(&a), Some(ConstValue::True));
    }

    #[test]
    fn test_const_float_div_by_zero() {
        let a = ConstValue::from(1.0_f64);
        let b = ConstValue::from(0.0_f64);
        // Float div by zero returns inf, not None
        let result = a.div(&b, PointerSize::Bit64);
        assert!(result.is_some());
        if let Some(v) = result.as_ref().and_then(ConstValue::as_f64) {
            assert!(v.is_infinite());
        }
    }

    #[test]
    fn test_is_zero_integer_types() {
        // Test is_zero for integer types (does not include floats)
        assert!(ConstValue::I8(0).is_zero());
        assert!(ConstValue::I16(0).is_zero());
        assert!(ConstValue::I32(0).is_zero());
        assert!(ConstValue::I64(0).is_zero());
        assert!(ConstValue::U8(0).is_zero());
        assert!(ConstValue::U16(0).is_zero());
        assert!(ConstValue::U32(0).is_zero());
        assert!(ConstValue::U64(0).is_zero());
        assert!(ConstValue::NativeInt(0).is_zero());
        assert!(ConstValue::NativeUInt(0).is_zero());
        assert!(ConstValue::False.is_zero());

        // Non-zero values
        assert!(!ConstValue::I32(1).is_zero());
        assert!(!ConstValue::True.is_zero());
    }

    #[test]
    fn test_is_one_integer_types() {
        // Test is_one for integer types (does not include floats)
        assert!(ConstValue::I8(1).is_one());
        assert!(ConstValue::I16(1).is_one());
        assert!(ConstValue::I32(1).is_one());
        assert!(ConstValue::I64(1).is_one());
        assert!(ConstValue::U8(1).is_one());
        assert!(ConstValue::U16(1).is_one());
        assert!(ConstValue::U32(1).is_one());
        assert!(ConstValue::U64(1).is_one());
        assert!(ConstValue::NativeInt(1).is_one());
        assert!(ConstValue::NativeUInt(1).is_one());
        assert!(ConstValue::True.is_one());

        // Non-one values
        assert!(!ConstValue::I32(0).is_one());
        assert!(!ConstValue::False.is_one());
    }

    #[test]
    fn test_is_minus_one_signed_types() {
        // Test is_minus_one for signed integer types only
        assert!(ConstValue::I8(-1).is_minus_one());
        assert!(ConstValue::I16(-1).is_minus_one());
        assert!(ConstValue::I32(-1).is_minus_one());
        assert!(ConstValue::I64(-1).is_minus_one());
        assert!(ConstValue::NativeInt(-1).is_minus_one());

        // Unsigned types cannot be -1
        assert!(!ConstValue::U8(255).is_minus_one());
        assert!(!ConstValue::U32(0xFFFFFFFF).is_minus_one());
    }

    #[test]
    fn test_zero_of_same_type_preserves_type() {
        // Integer types
        assert_eq!(ConstValue::I8(42).zero_of_same_type(), ConstValue::I8(0));
        assert_eq!(ConstValue::I16(42).zero_of_same_type(), ConstValue::I16(0));
        assert_eq!(ConstValue::I32(42).zero_of_same_type(), ConstValue::I32(0));
        assert_eq!(ConstValue::I64(42).zero_of_same_type(), ConstValue::I64(0));
        assert_eq!(ConstValue::U8(42).zero_of_same_type(), ConstValue::U8(0));
        assert_eq!(ConstValue::U16(42).zero_of_same_type(), ConstValue::U16(0));
        assert_eq!(ConstValue::U32(42).zero_of_same_type(), ConstValue::U32(0));
        assert_eq!(ConstValue::U64(42).zero_of_same_type(), ConstValue::U64(0));
        assert_eq!(
            ConstValue::NativeInt(42).zero_of_same_type(),
            ConstValue::NativeInt(0)
        );
        assert_eq!(
            ConstValue::NativeUInt(42).zero_of_same_type(),
            ConstValue::NativeUInt(0)
        );

        // Floating point types
        assert_eq!(
            ConstValue::from(std::f32::consts::PI).zero_of_same_type(),
            ConstValue::from(0.0_f32)
        );
        assert_eq!(
            ConstValue::from(std::f64::consts::PI).zero_of_same_type(),
            ConstValue::from(0.0_f64)
        );

        // Non-numeric types default to I32
        assert_eq!(ConstValue::Null.zero_of_same_type(), ConstValue::I32(0));
        assert_eq!(ConstValue::True.zero_of_same_type(), ConstValue::I32(0));
    }

    #[test]
    fn test_abstract_value_join() {
        let top = AbstractValue::Top;
        let bottom = AbstractValue::Bottom;
        let const_a = AbstractValue::Constant(ConstValue::I32(42));
        let const_b = AbstractValue::Constant(ConstValue::I32(42));
        let const_c = AbstractValue::Constant(ConstValue::I32(99));

        // Top joins with anything gives Top
        assert_eq!(top.join(&const_a), AbstractValue::Top);
        assert_eq!(const_a.join(&top), AbstractValue::Top);

        // Bottom joins with anything gives that thing
        assert_eq!(bottom.join(&const_a), const_a);
        assert_eq!(const_a.join(&bottom), const_a);

        // Same constants join to same constant
        assert_eq!(const_a.join(&const_b), const_a);

        // Different constants join to Top
        assert_eq!(const_a.join(&const_c), AbstractValue::Top);
    }

    #[test]
    fn test_abstract_value_is_constant() {
        let top = AbstractValue::Top;
        let bottom = AbstractValue::Bottom;
        let const_val = AbstractValue::Constant(ConstValue::I32(42));

        assert!(!top.is_constant());
        assert!(!bottom.is_constant());
        assert!(const_val.is_constant());
    }

    #[test]
    fn test_abstract_value_as_constant() {
        let const_val = AbstractValue::Constant(ConstValue::I32(42));
        assert_eq!(const_val.as_constant(), Some(&ConstValue::I32(42)));

        let top = AbstractValue::Top;
        assert_eq!(top.as_constant(), None);
    }

    #[test]
    fn test_as_i64() {
        // Signed types
        assert_eq!(ConstValue::I8(-100).as_i64(), Some(-100));
        assert_eq!(ConstValue::I16(-30000).as_i64(), Some(-30000));
        assert_eq!(
            ConstValue::I32(-2_000_000_000).as_i64(),
            Some(-2_000_000_000)
        );
        assert_eq!(
            ConstValue::I64(-9_000_000_000_000).as_i64(),
            Some(-9_000_000_000_000)
        );
        assert_eq!(ConstValue::NativeInt(42).as_i64(), Some(42));

        // Unsigned types up to U32 are included
        assert_eq!(ConstValue::U8(200).as_i64(), Some(200));
        assert_eq!(ConstValue::U16(60000).as_i64(), Some(60000));
        assert_eq!(ConstValue::U32(4_000_000_000).as_i64(), Some(4_000_000_000));

        // A `U64` answers when the value it holds is one an `i64` can hold:
        // the question is what the value is, not which variant spells it. Only
        // one too large to represent declines.
        assert_eq!(ConstValue::U64(1_000_000).as_i64(), Some(1_000_000));
        assert_eq!(ConstValue::U64(u64::MAX).as_i64(), None);

        // Bool values
        assert_eq!(ConstValue::True.as_i64(), Some(1));
        assert_eq!(ConstValue::False.as_i64(), Some(0));
    }

    #[test]
    fn test_as_u64() {
        assert_eq!(ConstValue::U8(200).as_u64(), Some(200));
        assert_eq!(ConstValue::U16(60000).as_u64(), Some(60000));
        assert_eq!(ConstValue::U32(4_000_000_000).as_u64(), Some(4_000_000_000));
        assert_eq!(ConstValue::U64(u64::MAX).as_u64(), Some(u64::MAX));
        // Positive signed values convert fine
        assert_eq!(ConstValue::I32(100).as_u64(), Some(100));
        // Negative signed values don't convert
        assert_eq!(ConstValue::I32(-1).as_u64(), None);
    }

    #[test]
    fn test_cross_type_arithmetic() {
        // I32 + I64 promotes to I64
        let i32_val = ConstValue::I32(10);
        let i64_val = ConstValue::I64(20);
        assert_eq!(
            i32_val.add(&i64_val, PointerSize::Bit64),
            Some(ConstValue::I64(30))
        );

        // U32 + U64 promotes to U64
        let u32_val = ConstValue::U32(100);
        let u64_val = ConstValue::U64(200);
        assert_eq!(
            u32_val.add(&u64_val, PointerSize::Bit64),
            Some(ConstValue::U64(300))
        );
    }

    #[test]
    fn test_incompatible_type_arithmetic() {
        // A width mismatch is what makes a fold impossible: an integer and a
        // float have no common representation to add in.
        let i32_val = ConstValue::I32(10);
        let f32_val = ConstValue::from(std::f32::consts::PI);
        assert!(i32_val.add(&f32_val, PointerSize::Bit64).is_none());

        // Signedness is not such a mismatch. CIL has one 64-bit integer stack
        // type and `add` on it does not read a sign, so the two spellings fold
        // to the same bits - and refusing would leave a constant unfolded that
        // the runtime folds anyway.
        let u64_val = ConstValue::U64(100);
        let i64_val = ConstValue::I64(200);
        assert!(u64_val.add(&i64_val, PointerSize::Bit64).is_some());

        // A narrower integer against a wider one promotes to the wider, which
        // is what the stack does: `add` on an int32 and an int64 is an int64
        // add, and folding it any other way would disagree with the runtime.
        let i32_narrow = ConstValue::I32(1);
        assert_eq!(
            i32_narrow.add(&i64_val, PointerSize::Bit64),
            Some(ConstValue::I64(201))
        );

        // A float and an integer have no common representation, so that one
        // genuinely declines - as the first case above shows.
        assert!(f32_val.add(&i64_val, PointerSize::Bit64).is_none());
    }

    #[test]
    fn test_null_const_value() {
        let null = ConstValue::Null;
        assert!(null.is_null());
        assert!(!null.is_one());
        assert!(!null.is_bool());
    }

    #[test]
    fn test_string_const_value() {
        let s = ConstValue::String(123);
        assert!(!s.is_zero());
        assert!(!s.is_one());
    }

    #[test]
    fn test_bool_const_values() {
        let t = ConstValue::True;
        let f = ConstValue::False;

        assert!(t.is_bool());
        assert!(f.is_bool());
        assert!(t.is_one());
        assert!(f.is_zero());
    }
}

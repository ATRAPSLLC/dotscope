//! Comparison operations for CIL emulation values.

// CIL emulation requires intentional numeric casts to implement ECMA-335 type conversion
// semantics. These casts handle signed/unsigned reinterpretation as specified by the CIL
// instruction set.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use crate::{
    emulation::{
        engine::EmulationError,
        value::{CompareOp, EmValue, SymbolicValue, TaintSource},
    },
    metadata::typesystem::CilFlavor,
    Result,
};

impl EmValue {
    /// Performs a comparison operation on two values.
    ///
    /// # Arguments
    ///
    /// * `other` - The right-hand operand
    /// * `op` - The comparison operation to perform
    ///
    /// # Returns
    ///
    /// An I32 value: 1 if the comparison is true, 0 if false.
    /// Returns an error for invalid type combinations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, CompareOp};
    ///
    /// let a = EmValue::I32(10);
    /// let b = EmValue::I32(20);
    ///
    /// let result = a.compare(&b, CompareOp::Lt).unwrap();
    /// assert_eq!(result, EmValue::I32(1)); // 10 < 20 is true
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error for invalid type combinations.
    pub fn compare(&self, other: &Self, op: CompareOp) -> Result<Self> {
        // Handle symbolic operands - result is symbolic I32
        if matches!(self, EmValue::Symbolic(_)) || matches!(other, EmValue::Symbolic(_)) {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                CilFlavor::I4,
                TaintSource::Computation,
            )));
        }

        let (left, right) = (self.on_stack(), other.on_stack());
        let result = match op {
            CompareOp::Eq => left.cmp_eq(&right)?,
            CompareOp::Ne => !left.cmp_eq(&right)?,
            CompareOp::Lt => left.cmp_lt(&right, false)?,
            CompareOp::LtUn => left.cmp_lt(&right, true)?,
            CompareOp::Le => left.cmp_le(&right, false)?,
            CompareOp::LeUn => left.cmp_le(&right, true)?,
            CompareOp::Gt => left.cmp_gt(&right, false)?,
            CompareOp::GtUn => left.cmp_gt(&right, true)?,
            CompareOp::Ge => left.cmp_ge(&right, false)?,
            CompareOp::GeUn => left.cmp_ge(&right, true)?,
        };

        Ok(EmValue::I32(i32::from(result)))
    }

    /// Equality comparison (`ceq` instruction).
    fn cmp_eq(&self, other: &Self) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(a == b),
            (EmValue::I64(a) | EmValue::NativeInt(a), EmValue::I64(b))
            | (EmValue::NativeInt(a), EmValue::NativeInt(b))
            | (EmValue::I64(b), EmValue::NativeInt(a)) => Ok(a == b),
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b))
            | (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => Ok(a == b),
            (EmValue::F32(a), EmValue::F32(b)) => Ok(a == b),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(a == b),
            (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => Ok(a == b),
            (EmValue::Null, EmValue::Null) => Ok(true),
            (EmValue::ObjectRef(_), EmValue::Null) | (EmValue::Null, EmValue::ObjectRef(_)) => {
                Ok(false)
            }
            // Pointer comparisons
            (EmValue::NativeInt(a), EmValue::UnmanagedPtr(b))
            | (EmValue::UnmanagedPtr(b), EmValue::NativeInt(a)) => Ok(*a as u64 == *b),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "ceq".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Less-than comparison (`clt` / `clt.un` instructions).
    fn cmp_lt(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok((*a as u32) < (*b as u32))
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok((*a as u64) < (*b as u64))
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(a < b),
            (EmValue::F32(a), EmValue::F32(b)) => {
                // For unordered comparison (clt.un), NaN < anything is false
                if unsigned {
                    Ok(a < b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a < b)
                }
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                if unsigned {
                    Ok(a < b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a < b)
                }
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "clt.un" } else { "clt" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Less-than-or-equal comparison (`ble` / `ble.un`).
    ///
    /// For integers `a <= b` is `!(a > b)`. Floats are not totally ordered: with a NaN
    /// operand the comparison is unordered, and `ble` does not branch while `ble.un` does
    /// (ECMA-335 III.3.8, III.3.9), so the float case is stated directly rather than as the
    /// complement of `cgt`, which would invert both.
    fn cmp_le(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::F32(a), EmValue::F32(b)) => {
                Ok(a <= b || (unsigned && (a.is_nan() || b.is_nan())))
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                Ok(a <= b || (unsigned && (a.is_nan() || b.is_nan())))
            }
            _ => self.cmp_gt(other, unsigned).map(|r| !r),
        }
    }

    /// Greater-than comparison (`cgt` / `cgt.un` instructions).
    fn cmp_gt(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    Ok((*a as u32) > (*b as u32))
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    Ok((*a as u64) > (*b as u64))
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => Ok(a > b),
            (EmValue::F32(a), EmValue::F32(b)) => {
                if unsigned {
                    Ok(a > b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a > b)
                }
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                if unsigned {
                    Ok(a > b || a.is_nan() || b.is_nan())
                } else {
                    Ok(a > b)
                }
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "cgt.un" } else { "cgt" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Greater-than-or-equal comparison (`bge` / `bge.un`).
    ///
    /// For integers `a >= b` is `!(a < b)`. With a NaN operand a float comparison is
    /// unordered: `bge` does not branch and `bge.un` does (ECMA-335 III.3.6, III.3.7), so
    /// the float case is stated directly rather than as the complement of `clt`.
    fn cmp_ge(&self, other: &Self, unsigned: bool) -> Result<bool> {
        match (self, other) {
            (EmValue::F32(a), EmValue::F32(b)) => {
                Ok(a >= b || (unsigned && (a.is_nan() || b.is_nan())))
            }
            (EmValue::F64(a), EmValue::F64(b)) => {
                Ok(a >= b || (unsigned && (a.is_nan() || b.is_nan())))
            }
            _ => self.cmp_lt(other, unsigned).map(|r| !r),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::emulation::value::{CompareOp, EmValue, HeapRef};

    #[test]
    fn test_compare_eq() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(42);
        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));

        let c = EmValue::I32(43);
        assert_eq!(a.compare(&c, CompareOp::Eq).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_ne() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(43);
        assert_eq!(a.compare(&b, CompareOp::Ne).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_lt() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(20);
        assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
        assert_eq!(b.compare(&a, CompareOp::Lt).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_lt_unsigned() {
        let a = EmValue::I32(-1); // Large unsigned value
        let b = EmValue::I32(1);
        // Signed: -1 < 1, Unsigned: 0xFFFFFFFF > 1
        assert_eq!(a.compare(&b, CompareOp::Lt).unwrap(), EmValue::I32(1));
        assert_eq!(a.compare(&b, CompareOp::LtUn).unwrap(), EmValue::I32(0));
    }

    #[test]
    fn test_compare_gt() {
        let a = EmValue::I32(20);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Gt).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_le() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Le).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_ge() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(10);
        assert_eq!(a.compare(&b, CompareOp::Ge).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_null() {
        let a = EmValue::Null;
        let b = EmValue::Null;
        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));
    }

    #[test]
    fn test_compare_object_ref() {
        let a = EmValue::ObjectRef(HeapRef::new(1));
        let b = EmValue::ObjectRef(HeapRef::new(1));
        let c = EmValue::ObjectRef(HeapRef::new(2));

        assert_eq!(a.compare(&b, CompareOp::Eq).unwrap(), EmValue::I32(1));
        assert_eq!(a.compare(&c, CompareOp::Eq).unwrap(), EmValue::I32(0));
    }

    /// Every float comparison follows ECMA-335 over ordered and unordered operands: the
    /// signed forms are the IEEE ordered comparisons (false when either operand is NaN), the
    /// `.un` forms are true when the operands are unordered, `ceq` is false and `bne.un` true
    /// for a NaN. Checked for both widths over infinities, signed zeros, ordinary values and
    /// NaN.
    #[test]
    fn float_comparisons_follow_ordered_and_unordered_rules() {
        let values = [
            f64::NEG_INFINITY,
            -1.5,
            -0.0,
            0.0,
            1.5,
            f64::INFINITY,
            f64::NAN,
        ];
        type Rule = fn(f64, f64) -> bool;
        let rules: [(CompareOp, Rule); 10] = [
            (CompareOp::Eq, |a, b| a == b),
            (CompareOp::Ne, |a, b| a != b),
            (CompareOp::Lt, |a, b| a < b),
            (CompareOp::LtUn, |a, b| a < b || a.is_nan() || b.is_nan()),
            (CompareOp::Gt, |a, b| a > b),
            (CompareOp::GtUn, |a, b| a > b || a.is_nan() || b.is_nan()),
            (CompareOp::Le, |a, b| a <= b),
            (CompareOp::LeUn, |a, b| a <= b || a.is_nan() || b.is_nan()),
            (CompareOp::Ge, |a, b| a >= b),
            (CompareOp::GeUn, |a, b| a >= b || a.is_nan() || b.is_nan()),
        ];
        let truth = |holds: bool| EmValue::I32(i32::from(holds));
        for &a in &values {
            for &b in &values {
                for (op, rule) in rules {
                    let expected = truth(rule(a, b));
                    assert_eq!(
                        EmValue::F64(a).compare(&EmValue::F64(b), op).unwrap(),
                        expected,
                        "{a} {op:?} {b} (F64)"
                    );
                    #[allow(clippy::cast_possible_truncation)]
                    let (a32, b32) = (a as f32, b as f32);
                    assert_eq!(
                        EmValue::F32(a32).compare(&EmValue::F32(b32), op).unwrap(),
                        expected,
                        "{a} {op:?} {b} (F32)"
                    );
                }
            }
        }
    }
}

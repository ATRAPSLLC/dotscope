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

    /// Less-than-or-equal comparison (implemented as `!(a > b)`).
    fn cmp_le(&self, other: &Self, unsigned: bool) -> Result<bool> {
        // a <= b is equivalent to !(a > b)
        self.cmp_gt(other, unsigned).map(|r| !r)
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

    /// Greater-than-or-equal comparison (implemented as `!(a < b)`).
    fn cmp_ge(&self, other: &Self, unsigned: bool) -> Result<bool> {
        // a >= b is equivalent to !(a < b)
        self.cmp_lt(other, unsigned).map(|r| !r)
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
}

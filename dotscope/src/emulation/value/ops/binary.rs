//! Binary arithmetic and bitwise operations for CIL emulation values.

// CIL emulation requires intentional numeric casts to implement ECMA-335 type conversion
// semantics. These casts handle signed/unsigned reinterpretation, truncation, and widening
// as specified by the CIL instruction set.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::{
    emulation::{
        engine::EmulationError,
        value::{BinaryOp, EmValue, SymbolicValue, TaintSource},
    },
    metadata::typesystem::PointerSize,
    Result,
};

impl EmValue {
    /// Performs a binary operation on two values.
    ///
    /// # Arguments
    ///
    /// * `other` - The right-hand operand
    /// * `op` - The binary operation to perform
    ///
    /// # Returns
    ///
    /// The result of the operation, or an error if the operation is invalid
    /// for the operand types or if an overflow/division-by-zero occurs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, BinaryOp};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let a = EmValue::I32(10);
    /// let b = EmValue::I32(3);
    ///
    /// let sum = a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap();
    /// assert_eq!(sum, EmValue::I32(13));
    ///
    /// let product = a.binary_op(&b, BinaryOp::Mul, PointerSize::Bit64).unwrap();
    /// assert_eq!(product, EmValue::I32(30));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if operation is invalid for the operand types or on overflow.
    pub fn binary_op(&self, other: &Self, op: BinaryOp, ptr_size: PointerSize) -> Result<Self> {
        if let EmValue::Symbolic(ref sym) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }
        if let EmValue::Symbolic(ref sym) = other {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }

        let (left, right) = (self.on_stack(), other.on_stack());
        let result = match op {
            BinaryOp::Add => left.add(&right),
            BinaryOp::AddOvf => left.add_ovf(&right, false),
            BinaryOp::AddOvfUn => left.add_ovf(&right, true),
            BinaryOp::Sub => left.sub(&right),
            BinaryOp::SubOvf => left.sub_ovf(&right, false),
            BinaryOp::SubOvfUn => left.sub_ovf(&right, true),
            BinaryOp::Mul => left.mul(&right),
            BinaryOp::MulOvf => left.mul_ovf(&right, false),
            BinaryOp::MulOvfUn => left.mul_ovf(&right, true),
            BinaryOp::Div => left.div(&right, false),
            BinaryOp::DivUn => left.div(&right, true),
            BinaryOp::Rem => left.rem(&right, false),
            BinaryOp::RemUn => left.rem(&right, true),
            BinaryOp::And => left.bitand(&right),
            BinaryOp::Or => left.bitor(&right),
            BinaryOp::Xor => left.bitxor(&right),
            BinaryOp::Shl => left.shl(&right),
            BinaryOp::Shr => left.shr(&right, false),
            BinaryOp::ShrUn => left.shr(&right, true),
        }?;

        // Mask native int/uint results to the target pointer width
        Ok(match result {
            EmValue::NativeInt(v) => EmValue::NativeInt(ptr_size.mask_signed(v)),
            EmValue::NativeUInt(v) => EmValue::NativeUInt(ptr_size.mask_unsigned(v)),
            other => other,
        })
    }

    /// Wrapping addition (`add` instruction).
    fn add(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_add(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_add(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_add(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a + b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a + b)),
            // Mixed native int operations
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_add(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_add(*b)))
            }
            // Mixed NativeUInt + NativeInt (treat as unsigned addition)
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_add(*b)))
            }
            // NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_add(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_add(*b)))
            }
            // Pointer arithmetic: UnmanagedPtr + integer offsets
            (EmValue::UnmanagedPtr(a), EmValue::I32(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b as u64)))
            }
            (EmValue::I32(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr((*a as u64).wrapping_add(*b)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr((*a as u64).wrapping_add(*b)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeUInt(b))
            | (EmValue::NativeUInt(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_add(*b)))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "add".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Checked addition with overflow detection (`add.ovf` / `add.ovf.un`).
    fn add_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u32).overflowing_add(*b as u32);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I32(result as i32))
                    }
                } else {
                    a.checked_add(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_add(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I64(result as i64))
                    }
                } else {
                    a.checked_add(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_add(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a.checked_add(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    a.checked_add(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (*a as i64).overflowing_add(*b as i64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            // Mixed NativeInt + I32
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                let b_wide = i64::from(*b);
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_add(b_wide as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a.checked_add(b_wide)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                let a_wide = i64::from(*a);
                if unsigned {
                    let (result, overflow) = (a_wide as u64).overflowing_add(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a_wide
                        .checked_add(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            // Mixed NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                if unsigned {
                    a.checked_add(*b as u64)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (*a as i64).overflowing_add(i64::from(*b));
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    (*a as u64)
                        .checked_add(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (i64::from(*a)).overflowing_add(*b as i64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "add.ovf.un" } else { "add.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    /// Wrapping subtraction (`sub` instruction).
    fn sub(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_sub(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_sub(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a - b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a - b)),
            // Mixed native int operations
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_sub(*b)))
            }
            // Mixed NativeUInt - NativeInt (treat as unsigned subtraction)
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_sub(*b)))
            }
            // NativeUInt - I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_sub(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_sub(*b)))
            }
            // Pointer arithmetic: UnmanagedPtr - integer offsets
            (EmValue::UnmanagedPtr(a), EmValue::I32(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b as u64)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b as u64)))
            }
            (EmValue::UnmanagedPtr(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::UnmanagedPtr(a.wrapping_sub(*b)))
            }
            // Pointer difference (ptr - ptr = native int)
            (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_sub(*b) as i64))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "sub".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Checked subtraction with overflow detection (`sub.ovf` / `sub.ovf.un`).
    fn sub_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u32).overflowing_sub(*b as u32);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I32(result as i32))
                    }
                } else {
                    a.checked_sub(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_sub(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::I64(result as i64))
                    }
                } else {
                    a.checked_sub(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_sub(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a.checked_sub(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    a.checked_sub(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (*a as i64).overflowing_sub(*b as i64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            // Mixed NativeInt + I32
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                let b_wide = i64::from(*b);
                if unsigned {
                    let (result, overflow) = (*a as u64).overflowing_sub(b_wide as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a.checked_sub(b_wide)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                let a_wide = i64::from(*a);
                if unsigned {
                    let (result, overflow) = (a_wide as u64).overflowing_sub(*b as u64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeInt(result as i64))
                    }
                } else {
                    a_wide
                        .checked_sub(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            // Mixed NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                if unsigned {
                    a.checked_sub(*b as u64)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (*a as i64).overflowing_sub(i64::from(*b));
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    (*a as u64)
                        .checked_sub(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let (result, overflow) = (i64::from(*a)).overflowing_sub(*b as i64);
                    if overflow {
                        Err(EmulationError::ArithmeticOverflow.into())
                    } else {
                        Ok(EmValue::NativeUInt(result as u64))
                    }
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "sub.ovf.un" } else { "sub.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    /// Wrapping multiplication (`mul` instruction).
    fn mul(&self, other: &Self) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => Ok(EmValue::I32(a.wrapping_mul(*b))),
            (EmValue::I64(a), EmValue::I64(b)) => Ok(EmValue::I64(a.wrapping_mul(*b))),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_mul(*b)))
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b)))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a * b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a * b)),
            // Mixed native int operations (per CIL spec, widen to NativeInt)
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeInt(a.wrapping_mul(i64::from(*b))))
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeInt(i64::from(*a).wrapping_mul(*b)))
            }
            // Mixed NativeUInt operations
            (EmValue::NativeUInt(a), EmValue::NativeInt(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b as u64)))
            }
            (EmValue::NativeInt(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_mul(*b)))
            }
            // NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                Ok(EmValue::NativeUInt(a.wrapping_mul(*b as u64)))
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                Ok(EmValue::NativeUInt((*a as u64).wrapping_mul(*b)))
            }
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: "mul".to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Checked multiplication with overflow detection (`mul.ovf` / `mul.ovf.un`).
    fn mul_ovf(&self, other: &Self, unsigned: bool) -> Result<Self> {
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let ua = *a as u32;
                    let ub = *b as u32;
                    ua.checked_mul(ub)
                        .map(|r| EmValue::I32(r as i32))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(*b)
                        .map(EmValue::I32)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let ua = *a as u64;
                    let ub = *b as u64;
                    ua.checked_mul(ub)
                        .map(|r| EmValue::I64(r as i64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(*b)
                        .map(EmValue::I64)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    let ua = *a as u64;
                    let ub = *b as u64;
                    ua.checked_mul(ub)
                        .map(|r| EmValue::NativeInt(r as i64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    a.checked_mul(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let sa = *a as i64;
                    let sb = *b as i64;
                    sa.checked_mul(sb)
                        .map(|r| EmValue::NativeUInt(r as u64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            // Mixed NativeInt + I32
            (EmValue::NativeInt(a), EmValue::I32(b)) => {
                let b_wide = i64::from(*b);
                if unsigned {
                    let ua = *a as u64;
                    ua.checked_mul(b_wide as u64)
                        .map(|r| EmValue::NativeInt(r as i64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a.checked_mul(b_wide)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I32(a), EmValue::NativeInt(b)) => {
                let a_wide = i64::from(*a);
                if unsigned {
                    (a_wide as u64)
                        .checked_mul(*b as u64)
                        .map(|r| EmValue::NativeInt(r as i64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    a_wide
                        .checked_mul(*b)
                        .map(EmValue::NativeInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            // Mixed NativeUInt + I32
            (EmValue::NativeUInt(a), EmValue::I32(b)) => {
                if unsigned {
                    a.checked_mul(*b as u64)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    let sa = *a as i64;
                    sa.checked_mul(i64::from(*b))
                        .map(|r| EmValue::NativeUInt(r as u64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            (EmValue::I32(a), EmValue::NativeUInt(b)) => {
                if unsigned {
                    (*a as u64)
                        .checked_mul(*b)
                        .map(EmValue::NativeUInt)
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                } else {
                    (i64::from(*a))
                        .checked_mul(*b as i64)
                        .map(|r| EmValue::NativeUInt(r as u64))
                        .ok_or_else(|| EmulationError::ArithmeticOverflow.into())
                }
            }
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "mul.ovf.un" } else { "mul.ovf" }.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into()),
        }
    }

    /// Division (`div` / `div.un` instructions). Returns `DivisionByZero` on zero divisor.
    fn div(&self, other: &Self, unsigned: bool) -> Result<Self> {
        // Check for division by zero first
        let is_zero = match other {
            EmValue::I32(v) => *v == 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => *v == 0,
            EmValue::NativeUInt(v) => *v == 0,
            EmValue::F32(v) => *v == 0.0,
            EmValue::F64(v) => *v == 0.0,
            _ => false,
        };

        // Only check for integer division by zero (floats return infinity)
        if is_zero && !matches!(other, EmValue::F32(_) | EmValue::F64(_)) {
            return Err(EmulationError::DivisionByZero.into());
        }

        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let q = (*a as u32)
                        .checked_div(*b as u32)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I32(q as i32))
                } else {
                    // Handle MIN / -1 overflow case
                    if *a == i32::MIN && *b == -1 {
                        Ok(EmValue::I32(i32::MIN)) // Wrapping behavior
                    } else {
                        let q = a.checked_div(*b).ok_or(EmulationError::DivisionByZero)?;
                        Ok(EmValue::I32(q))
                    }
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let q = (*a as u64)
                        .checked_div(*b as u64)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I64(q as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::I64(i64::MIN))
                } else {
                    let q = a.checked_div(*b).ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I64(q))
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    let q = (*a as u64)
                        .checked_div(*b as u64)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::NativeInt(q as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::NativeInt(i64::MIN))
                } else {
                    let q = a.checked_div(*b).ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::NativeInt(q))
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                let q = a.checked_div(*b).ok_or(EmulationError::DivisionByZero)?;
                Ok(EmValue::NativeUInt(q))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a / b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a / b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "div.un" } else { "div" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Remainder (`rem` / `rem.un` instructions). Returns `DivisionByZero` on zero divisor.
    fn rem(&self, other: &Self, unsigned: bool) -> Result<Self> {
        // Check for division by zero
        let is_zero = match other {
            EmValue::I32(v) => *v == 0,
            EmValue::I64(v) | EmValue::NativeInt(v) => *v == 0,
            EmValue::NativeUInt(v) => *v == 0,
            _ => false,
        };

        if is_zero {
            return Err(EmulationError::DivisionByZero.into());
        }

        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                if unsigned {
                    let r = (*a as u32)
                        .checked_rem(*b as u32)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I32(r as i32))
                } else {
                    // Handle MIN % -1 case (result is 0)
                    if *a == i32::MIN && *b == -1 {
                        Ok(EmValue::I32(0))
                    } else {
                        let r = a.checked_rem(*b).ok_or(EmulationError::DivisionByZero)?;
                        Ok(EmValue::I32(r))
                    }
                }
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                if unsigned {
                    let r = (*a as u64)
                        .checked_rem(*b as u64)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I64(r as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::I64(0))
                } else {
                    let r = a.checked_rem(*b).ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::I64(r))
                }
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                if unsigned {
                    let r = (*a as u64)
                        .checked_rem(*b as u64)
                        .ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::NativeInt(r as i64))
                } else if *a == i64::MIN && *b == -1 {
                    Ok(EmValue::NativeInt(0))
                } else {
                    let r = a.checked_rem(*b).ok_or(EmulationError::DivisionByZero)?;
                    Ok(EmValue::NativeInt(r))
                }
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                let r = a.checked_rem(*b).ok_or(EmulationError::DivisionByZero)?;
                Ok(EmValue::NativeUInt(r))
            }
            (EmValue::F32(a), EmValue::F32(b)) => Ok(EmValue::F32(a % b)),
            (EmValue::F64(a), EmValue::F64(b)) => Ok(EmValue::F64(a % b)),
            (a, b) => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "rem.un" } else { "rem" }.to_string(),
                operand_types: format!("{}, {}", a.cil_flavor(), b.cil_flavor()),
            }
            .into()),
        }
    }

    /// Applies a bitwise operation with mixed-type and ObjectRef support.
    ///
    /// Handles all integer type combinations (I32, I64, NativeInt, NativeUInt)
    /// and coerces ObjectRef/UnmanagedPtr to their underlying integer values.
    /// This is needed for obfuscator decryption routines that use pointer
    /// values in bitwise key computations.
    fn bitwise_op<F>(&self, other: &Self, op_fn: F, op_name: &str) -> Result<Self>
    where
        F: Fn(u64, u64) -> u64,
    {
        // Coerce a value to u64 for bitwise operations.
        // ObjectRef → heap ID, UnmanagedPtr → address, integers → widened.
        let coerce = |v: &EmValue| -> Option<u64> {
            match v {
                EmValue::I32(x) => Some(*x as u64),
                EmValue::I64(x) | EmValue::NativeInt(x) => Some(*x as u64),
                EmValue::NativeUInt(x) | EmValue::UnmanagedPtr(x) => Some(*x),
                EmValue::ObjectRef(href) => Some(href.id()),
                _ => None,
            }
        };

        // Fast path: exact same-type matches preserve the original result type
        match (self, other) {
            (EmValue::I32(a), EmValue::I32(b)) => {
                return Ok(EmValue::I32(op_fn(*a as u64, *b as u64) as i32));
            }
            (EmValue::I64(a), EmValue::I64(b)) => {
                return Ok(EmValue::I64(op_fn(*a as u64, *b as u64) as i64));
            }
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                return Ok(EmValue::NativeInt(op_fn(*a as u64, *b as u64) as i64));
            }
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => {
                return Ok(EmValue::NativeUInt(op_fn(*a, *b)));
            }
            _ => {}
        }

        // Slow path: mixed types — coerce both to u64, apply, return NativeUInt
        if let (Some(a), Some(b)) = (coerce(self), coerce(other)) {
            Ok(EmValue::NativeUInt(op_fn(a, b)))
        } else {
            Err(EmulationError::InvalidOperationTypes {
                operation: op_name.to_string(),
                operand_types: format!("{}, {}", self.cil_flavor(), other.cil_flavor()),
            }
            .into())
        }
    }

    /// Bitwise AND (`and` instruction).
    fn bitand(&self, other: &Self) -> Result<Self> {
        self.bitwise_op(other, |a, b| a & b, "and")
    }

    /// Bitwise OR (`or` instruction).
    fn bitor(&self, other: &Self) -> Result<Self> {
        self.bitwise_op(other, |a, b| a | b, "or")
    }

    /// Bitwise XOR (`xor` instruction).
    fn bitxor(&self, other: &Self) -> Result<Self> {
        self.bitwise_op(other, |a, b| a ^ b, "xor")
    }

    /// Left shift (`shl` instruction). Shift amount is masked to type width.
    fn shl(&self, other: &Self) -> Result<Self> {
        // Shift amount is always taken from the low bits (masked by type width - 1)
        let shift = match *other {
            EmValue::I32(v) => v as u32,
            EmValue::I64(v) | EmValue::NativeInt(v) => v as u32,
            EmValue::NativeUInt(v) => v as u32,
            _ => {
                return Err(EmulationError::InvalidOperationTypes {
                    operation: "shl".to_string(),
                    operand_types: format!("_, {}", other.cil_flavor()),
                }
                .into());
            }
        };

        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(a.wrapping_shl(shift & 31))),
            EmValue::I64(a) => Ok(EmValue::I64(a.wrapping_shl(shift & 63))),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(a.wrapping_shl(shift & 63))),
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(a.wrapping_shl(shift & 63))),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "shl".to_string(),
                operand_types: format!("{}, _", self.cil_flavor()),
            }
            .into()),
        }
    }

    /// Right shift — arithmetic (`shr`) or logical (`shr.un`).
    fn shr(&self, other: &Self, unsigned: bool) -> Result<Self> {
        let shift = match *other {
            EmValue::I32(v) => v as u32,
            EmValue::I64(v) | EmValue::NativeInt(v) => v as u32,
            EmValue::NativeUInt(v) => v as u32,
            _ => {
                return Err(EmulationError::InvalidOperationTypes {
                    operation: if unsigned { "shr.un" } else { "shr" }.to_string(),
                    operand_types: format!("_, {}", other.cil_flavor()),
                }
                .into());
            }
        };

        match *self {
            EmValue::I32(a) => {
                if unsigned {
                    Ok(EmValue::I32((a as u32).wrapping_shr(shift & 31) as i32))
                } else {
                    Ok(EmValue::I32(a.wrapping_shr(shift & 31)))
                }
            }
            EmValue::I64(a) => {
                if unsigned {
                    Ok(EmValue::I64((a as u64).wrapping_shr(shift & 63) as i64))
                } else {
                    Ok(EmValue::I64(a.wrapping_shr(shift & 63)))
                }
            }
            EmValue::NativeInt(a) => {
                if unsigned {
                    Ok(EmValue::NativeInt(
                        (a as u64).wrapping_shr(shift & 63) as i64
                    ))
                } else {
                    Ok(EmValue::NativeInt(a.wrapping_shr(shift & 63)))
                }
            }
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(a.wrapping_shr(shift & 63))),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: if unsigned { "shr.un" } else { "shr" }.to_string(),
                operand_types: format!("{}, _", self.cil_flavor()),
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            engine::EmulationError,
            value::{BinaryOp, EmValue, HeapRef},
        },
        metadata::typesystem::PointerSize,
        Error,
    };

    #[test]
    fn test_binary_op_add_i32() {
        let a = EmValue::I32(10);
        let b = EmValue::I32(20);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_binary_op_add_wrapping() {
        let a = EmValue::I32(i32::MAX);
        let b = EmValue::I32(1);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I32(i32::MIN)
        );
    }

    #[test]
    fn test_binary_op_add_i64() {
        let a = EmValue::I64(100);
        let b = EmValue::I64(200);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::I64(300)
        );
    }

    #[test]
    fn test_binary_op_add_f64() {
        let a = EmValue::F64(1.5);
        let b = EmValue::F64(2.5);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Add, PointerSize::Bit64).unwrap(),
            EmValue::F64(4.0)
        );
    }

    #[test]
    fn test_binary_op_add_ovf() {
        let a = EmValue::I32(i32::MAX);
        let b = EmValue::I32(1);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::AddOvf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_binary_op_sub() {
        let a = EmValue::I32(30);
        let b = EmValue::I32(20);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Sub, PointerSize::Bit64).unwrap(),
            EmValue::I32(10)
        );
    }

    #[test]
    fn test_binary_op_mul() {
        let a = EmValue::I32(6);
        let b = EmValue::I32(7);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Mul, PointerSize::Bit64).unwrap(),
            EmValue::I32(42)
        );
    }

    #[test]
    fn test_binary_op_div() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(6);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Div, PointerSize::Bit64).unwrap(),
            EmValue::I32(7)
        );
    }

    #[test]
    fn test_binary_op_div_by_zero() {
        let a = EmValue::I32(42);
        let b = EmValue::I32(0);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::Div, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::DivisionByZero)
        ));
    }

    #[test]
    fn test_binary_op_div_unsigned() {
        let a = EmValue::I32(-1); // 0xFFFFFFFF as unsigned
        let b = EmValue::I32(2);
        let result = a
            .binary_op(&b, BinaryOp::DivUn, PointerSize::Bit64)
            .unwrap();
        // -1 as u32 is 0xFFFFFFFF = 4294967295, divided by 2 is 2147483647
        assert_eq!(result, EmValue::I32(0x7FFFFFFF));
    }

    #[test]
    fn test_binary_op_rem() {
        let a = EmValue::I32(17);
        let b = EmValue::I32(5);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Rem, PointerSize::Bit64).unwrap(),
            EmValue::I32(2)
        );
    }

    #[test]
    fn test_binary_op_and() {
        let a = EmValue::I32(0xFF00);
        let b = EmValue::I32(0x0FF0);
        assert_eq!(
            a.binary_op(&b, BinaryOp::And, PointerSize::Bit64).unwrap(),
            EmValue::I32(0x0F00)
        );
    }

    #[test]
    fn test_binary_op_or() {
        let a = EmValue::I32(0xFF00);
        let b = EmValue::I32(0x00FF);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Or, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xFFFF)
        );
    }

    #[test]
    fn test_binary_op_xor() {
        let a = EmValue::I32(0xFFFF);
        let b = EmValue::I32(0x0F0F);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Xor, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xF0F0)
        );
    }

    #[test]
    fn test_binary_op_shl() {
        let a = EmValue::I32(1);
        let b = EmValue::I32(4);
        assert_eq!(
            a.binary_op(&b, BinaryOp::Shl, PointerSize::Bit64).unwrap(),
            EmValue::I32(16)
        );
    }

    #[test]
    fn test_binary_op_shr_signed() {
        let a = EmValue::I32(-8);
        let b = EmValue::I32(2);
        // Arithmetic shift right preserves sign
        assert_eq!(
            a.binary_op(&b, BinaryOp::Shr, PointerSize::Bit64).unwrap(),
            EmValue::I32(-2)
        );
    }

    #[test]
    fn test_binary_op_shr_unsigned() {
        let a = EmValue::I32(-8);
        let b = EmValue::I32(2);
        // Logical shift right fills with zeros
        let result = a
            .binary_op(&b, BinaryOp::ShrUn, PointerSize::Bit64)
            .unwrap();
        // -8 as u32 >> 2 = 0xFFFFFFF8 >> 2 = 0x3FFFFFFE
        assert_eq!(result, EmValue::I32(0x3FFFFFFE_u32 as i32));
    }

    #[test]
    fn test_binary_op_type_mismatch() {
        let a = EmValue::I32(1);
        let b = EmValue::I64(1);
        assert!(matches!(
            a.binary_op(&b,BinaryOp::Add, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::InvalidOperationTypes { .. })
        ));
    }

    #[test]
    fn test_native_int_add_ovf() {
        // Normal: 5 + 3 = 8
        let a = EmValue::NativeInt(5);
        let b = EmValue::NativeInt(3);
        assert_eq!(a.add_ovf(&b, false).unwrap(), EmValue::NativeInt(8));

        // Overflow: i64::MAX + 1
        let a = EmValue::NativeInt(i64::MAX);
        let b = EmValue::NativeInt(1);
        assert!(a.add_ovf(&b, false).is_err());
    }

    #[test]
    fn test_native_uint_add_ovf() {
        // Normal: 5 + 3 = 8
        let a = EmValue::NativeUInt(5);
        let b = EmValue::NativeUInt(3);
        assert_eq!(a.add_ovf(&b, true).unwrap(), EmValue::NativeUInt(8));

        // Overflow: u64::MAX + 1
        let a = EmValue::NativeUInt(u64::MAX);
        let b = EmValue::NativeUInt(1);
        assert!(a.add_ovf(&b, true).is_err());
    }

    #[test]
    fn test_native_int_sub_ovf() {
        // Normal: 5 - 3 = 2
        let a = EmValue::NativeInt(5);
        let b = EmValue::NativeInt(3);
        assert_eq!(a.sub_ovf(&b, false).unwrap(), EmValue::NativeInt(2));

        // Overflow: i64::MIN - 1
        let a = EmValue::NativeInt(i64::MIN);
        let b = EmValue::NativeInt(1);
        assert!(a.sub_ovf(&b, false).is_err());
    }

    #[test]
    fn test_native_uint_sub_ovf() {
        // Normal: 5 - 3 = 2
        let a = EmValue::NativeUInt(5);
        let b = EmValue::NativeUInt(3);
        assert_eq!(a.sub_ovf(&b, true).unwrap(), EmValue::NativeUInt(2));

        // Overflow: 0 - 1
        let a = EmValue::NativeUInt(0);
        let b = EmValue::NativeUInt(1);
        assert!(a.sub_ovf(&b, true).is_err());
    }

    #[test]
    fn test_native_int_mul_ovf() {
        // Normal: 5 * 3 = 15
        let a = EmValue::NativeInt(5);
        let b = EmValue::NativeInt(3);
        assert_eq!(a.mul_ovf(&b, false).unwrap(), EmValue::NativeInt(15));

        // Overflow: i64::MAX * 2
        let a = EmValue::NativeInt(i64::MAX);
        let b = EmValue::NativeInt(2);
        assert!(a.mul_ovf(&b, false).is_err());
    }

    #[test]
    fn test_native_uint_mul_ovf() {
        // Normal: 5 * 3 = 15
        let a = EmValue::NativeUInt(5);
        let b = EmValue::NativeUInt(3);
        assert_eq!(a.mul_ovf(&b, true).unwrap(), EmValue::NativeUInt(15));

        // Overflow: u64::MAX * 2
        let a = EmValue::NativeUInt(u64::MAX);
        let b = EmValue::NativeUInt(2);
        assert!(a.mul_ovf(&b, true).is_err());
    }

    #[test]
    fn test_mixed_native_int_i32_add_ovf() {
        let a = EmValue::NativeInt(5);
        let b = EmValue::I32(3);
        assert_eq!(a.add_ovf(&b, false).unwrap(), EmValue::NativeInt(8));

        let a = EmValue::I32(3);
        let b = EmValue::NativeInt(5);
        assert_eq!(a.add_ovf(&b, false).unwrap(), EmValue::NativeInt(8));
    }

    #[test]
    fn test_bitwise_and_same_type() {
        let a = EmValue::I32(0xFF00);
        let b = EmValue::I32(0x0FF0);
        assert_eq!(
            a.binary_op(&b, BinaryOp::And, PointerSize::Bit64).unwrap(),
            EmValue::I32(0x0F00)
        );
    }

    #[test]
    fn test_bitwise_and_objectref_i32() {
        let obj = EmValue::ObjectRef(HeapRef::new(0xDEAD_BEEF));
        let mask = EmValue::I32(0x0000_FFFF_u32 as i32);
        let result = obj
            .binary_op(&mask, BinaryOp::And, PointerSize::Bit64)
            .unwrap();
        assert_eq!(result, EmValue::NativeUInt(0xBEEF));
    }

    #[test]
    fn test_bitwise_or_mixed_int_types() {
        let a = EmValue::I32(0x00FF);
        let b = EmValue::NativeInt(0xFF00);
        let result = a.binary_op(&b, BinaryOp::Or, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::NativeUInt(0xFFFF));
    }

    #[test]
    fn test_bitwise_xor_objectref_i32() {
        let obj = EmValue::ObjectRef(HeapRef::new(42));
        let key = EmValue::I32(99);
        let result = obj
            .binary_op(&key, BinaryOp::Xor, PointerSize::Bit64)
            .unwrap();
        assert_eq!(result, EmValue::NativeUInt(42 ^ 99));
    }

    #[test]
    fn test_bitwise_and_native_uint_i32() {
        let a = EmValue::NativeUInt(0xFFFF_FFFF_FFFF_0000);
        let b = EmValue::I32(-1); // -1i32 as u64 = 0xFFFF_FFFF_FFFF_FFFF (sign-extended)
        let result = a.binary_op(&b, BinaryOp::And, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::NativeUInt(0xFFFF_FFFF_FFFF_0000));
    }
}

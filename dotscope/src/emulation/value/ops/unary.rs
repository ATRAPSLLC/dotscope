//! Unary operations for CIL emulation values.

use crate::{
    emulation::{
        engine::EmulationError,
        value::{EmValue, SymbolicValue, TaintSource, UnaryOp},
    },
    metadata::typesystem::PointerSize,
    Result,
};

impl EmValue {
    /// Performs a unary operation on this value.
    ///
    /// # Arguments
    ///
    /// * `op` - The unary operation to perform
    ///
    /// # Returns
    ///
    /// The result of the operation, or an error if invalid for the type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, UnaryOp};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let a = EmValue::I32(42);
    /// let neg = a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap();
    /// assert_eq!(neg, EmValue::I32(-42));
    ///
    /// let b = EmValue::I32(0xFF);
    /// let not = b.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap();
    /// assert_eq!(not, EmValue::I32(!0xFF));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if operation is invalid for the operand type.
    pub fn unary_op(&self, op: UnaryOp, ptr_size: PointerSize) -> Result<Self> {
        // Handle symbolic operands
        if let EmValue::Symbolic(ref sym) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                sym.cil_flavor.clone(),
                TaintSource::Computation,
            )));
        }

        let value = self.on_stack();
        let result = match op {
            UnaryOp::Neg => value.neg(),
            UnaryOp::Not => value.not(),
        }?;

        // Mask native int/uint results to the target pointer width
        Ok(match result {
            EmValue::NativeInt(v) => EmValue::NativeInt(ptr_size.mask_signed(v)),
            EmValue::NativeUInt(v) => EmValue::NativeUInt(ptr_size.mask_unsigned(v)),
            other => other,
        })
    }

    /// Performs arithmetic negation (`neg` instruction).
    fn neg(&self) -> Result<Self> {
        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(a.wrapping_neg())),
            EmValue::I64(a) => Ok(EmValue::I64(a.wrapping_neg())),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(a.wrapping_neg())),
            EmValue::F32(a) => Ok(EmValue::F32(-a)),
            EmValue::F64(a) => Ok(EmValue::F64(-a)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "neg".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    /// Performs bitwise complement (`not` instruction).
    fn not(&self) -> Result<Self> {
        match *self {
            EmValue::I32(a) => Ok(EmValue::I32(!a)),
            EmValue::I64(a) => Ok(EmValue::I64(!a)),
            EmValue::NativeInt(a) => Ok(EmValue::NativeInt(!a)),
            EmValue::NativeUInt(a) => Ok(EmValue::NativeUInt(!a)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "not".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::value::{EmValue, UnaryOp},
        metadata::typesystem::PointerSize,
    };

    #[test]
    fn test_unary_neg_i32() {
        let a = EmValue::I32(42);
        assert_eq!(
            a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap(),
            EmValue::I32(-42)
        );
    }

    #[test]
    fn test_unary_neg_f64() {
        let a = EmValue::F64(std::f64::consts::PI);
        assert_eq!(
            a.unary_op(UnaryOp::Neg, PointerSize::Bit64).unwrap(),
            EmValue::F64(-std::f64::consts::PI)
        );
    }

    #[test]
    fn test_unary_not_i32() {
        let a = EmValue::I32(0);
        assert_eq!(
            a.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap(),
            EmValue::I32(-1)
        );
    }

    #[test]
    fn test_unary_not_pattern() {
        let a = EmValue::I32(0x0F0F0F0F);
        assert_eq!(
            a.unary_op(UnaryOp::Not, PointerSize::Bit64).unwrap(),
            EmValue::I32(0xF0F0F0F0_u32 as i32)
        );
    }
}

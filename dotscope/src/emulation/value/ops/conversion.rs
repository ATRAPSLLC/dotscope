//! Type conversion operations for CIL emulation values.

// CIL emulation requires intentional numeric casts to implement ECMA-335 type conversion
// semantics. These casts handle signed/unsigned reinterpretation, truncation, and widening
// as specified by the CIL instruction set.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]

use crate::{
    emulation::{
        engine::EmulationError,
        value::{ConversionType, EmValue, SymbolicValue, TaintSource},
    },
    metadata::typesystem::PointerSize,
    Result,
};

impl EmValue {
    /// Converts this value to a different type.
    ///
    /// # Arguments
    ///
    /// * `conv` - The conversion to perform
    ///
    /// # Returns
    ///
    /// The converted value, or an error if the conversion is invalid
    /// or would overflow (for checked conversions).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, ConversionType};
    /// use dotscope::metadata::typesystem::PointerSize;
    ///
    /// let i32_val = EmValue::I32(42);
    /// let i64_val = i32_val.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
    /// assert_eq!(i64_val, EmValue::I64(42));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if conversion is invalid or would overflow (for checked conversions).
    pub fn convert(&self, conv: ConversionType, ptr_size: PointerSize) -> Result<Self> {
        // Handle symbolic values
        if let EmValue::Symbolic(_) = self {
            return Ok(EmValue::Symbolic(SymbolicValue::derived(
                conv.target_cil_flavor(),
                TaintSource::Computation,
            )));
        }

        match conv {
            ConversionType::I1 => self.conv_i1(),
            ConversionType::I2 => self.conv_i2(),
            ConversionType::I4 => self.conv_i4(),
            ConversionType::I8 => self.conv_i8(),
            ConversionType::U1 => self.conv_u1(),
            ConversionType::U2 => self.conv_u2(),
            ConversionType::U4 => self.conv_u4(),
            ConversionType::U8 => self.conv_u8(),
            ConversionType::R4 => self.conv_r4(),
            ConversionType::R8 => self.conv_r8(),
            ConversionType::I => self.conv_i(ptr_size),
            ConversionType::U => self.conv_u(ptr_size),
            ConversionType::RUn => self.conv_r_un(),
            // Checked conversions
            ConversionType::I1Ovf => self.conv_i1_ovf(false),
            ConversionType::I2Ovf => self.conv_i2_ovf(false),
            ConversionType::I4Ovf => self.conv_i4_ovf(false),
            ConversionType::I8Ovf => self.conv_i8_ovf(false),
            ConversionType::U1Ovf => self.conv_u1_ovf(false),
            ConversionType::U2Ovf => self.conv_u2_ovf(false),
            ConversionType::U4Ovf => self.conv_u4_ovf(false),
            ConversionType::U8Ovf => self.conv_u8_ovf(false),
            ConversionType::IOvf => self.conv_i_ovf(false),
            ConversionType::UOvf => self.conv_u_ovf(false),
            // Unsigned source checked conversions
            ConversionType::I1OvfUn => self.conv_i1_ovf(true),
            ConversionType::I2OvfUn => self.conv_i2_ovf(true),
            ConversionType::I4OvfUn => self.conv_i4_ovf(true),
            ConversionType::I8OvfUn => self.conv_i8_ovf(true),
            ConversionType::U1OvfUn => self.conv_u1_ovf(true),
            ConversionType::U2OvfUn => self.conv_u2_ovf(true),
            ConversionType::U4OvfUn => self.conv_u4_ovf(true),
            ConversionType::U8OvfUn => self.conv_u8_ovf(true),
            ConversionType::IOvfUn => self.conv_i_ovf(true),
            ConversionType::UOvfUn => self.conv_u_ovf(true),
        }
    }

    /// Truncates to signed 8-bit, then sign-extends to I32 (`conv.i1`).
    fn conv_i1(&self) -> Result<Self> {
        let value = self.to_i64()?;
        // Truncate to 8 bits, then sign-extend to i32
        Ok(EmValue::I32(value as i8 as i32))
    }

    /// Truncates to signed 16-bit, then sign-extends to I32 (`conv.i2`).
    fn conv_i2(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as i16 as i32))
    }

    /// Truncates to signed 32-bit (`conv.i4`).
    fn conv_i4(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as i32))
    }

    /// Sign-extends to signed 64-bit (`conv.i8`).
    fn conv_i8(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I64(value))
    }

    /// Truncates to unsigned 8-bit, then zero-extends to I32 (`conv.u1`).
    fn conv_u1(&self) -> Result<Self> {
        let value = self.to_i64()?;
        // Truncate to 8 bits, then zero-extend to i32
        Ok(EmValue::I32((value as u8) as i32))
    }

    /// Truncates to unsigned 16-bit, then zero-extends to I32 (`conv.u2`).
    fn conv_u2(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32((value as u16) as i32))
    }

    /// Truncates to unsigned 32-bit, stored as I32 (`conv.u4`).
    fn conv_u4(&self) -> Result<Self> {
        let value = self.to_i64()?;
        Ok(EmValue::I32(value as u32 as i32))
    }

    /// Zero-extends to unsigned 64-bit, stored as I64 (`conv.u8`).
    fn conv_u8(&self) -> Result<Self> {
        let value = self.to_u64()?;
        Ok(EmValue::I64(value as i64))
    }

    /// Converts to 32-bit float (`conv.r4`).
    fn conv_r4(&self) -> Result<Self> {
        match *self {
            EmValue::I32(v) => Ok(EmValue::F32(v as f32)),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(EmValue::F32(v as f32)),
            EmValue::NativeUInt(v) => Ok(EmValue::F32(v as f32)),
            EmValue::F32(v) => Ok(EmValue::F32(v)),
            EmValue::F64(v) => Ok(EmValue::F32(v as f32)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conv.r4".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    /// Converts to 64-bit float (`conv.r8`).
    fn conv_r8(&self) -> Result<Self> {
        match *self {
            EmValue::I32(v) => Ok(EmValue::F64(f64::from(v))),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(EmValue::F64(v as f64)),
            EmValue::NativeUInt(v) => Ok(EmValue::F64(v as f64)),
            EmValue::F32(v) => Ok(EmValue::F64(f64::from(v))),
            EmValue::F64(v) => Ok(EmValue::F64(v)),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conv.r8".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    /// Converts to native signed integer, masked to pointer width (`conv.i`).
    fn conv_i(&self, ptr_size: PointerSize) -> Result<Self> {
        let value = ptr_size.mask_signed(self.to_i64()?);
        Ok(EmValue::NativeInt(value))
    }

    /// Converts to native unsigned integer, masked to pointer width (`conv.u`).
    fn conv_u(&self, ptr_size: PointerSize) -> Result<Self> {
        let value = ptr_size.mask_unsigned(self.to_u64()?);
        Ok(EmValue::NativeUInt(value))
    }

    /// Converts unsigned integer to 64-bit float (`conv.r.un`).
    fn conv_r_un(&self) -> Result<Self> {
        // Convert unsigned integer to float
        let value = self.to_u64()?;
        Ok(EmValue::F64(value as f64))
    }

    // Checked conversions — these raise `ArithmeticOverflow` if the value
    // cannot be represented in the target type.

    /// Checked conversion to signed 8-bit (`conv.ovf.i1` / `conv.ovf.i1.un`).
    fn conv_i1_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i8::MIN as i64 || value > i8::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    /// Checked conversion to signed 16-bit (`conv.ovf.i2` / `conv.ovf.i2.un`).
    fn conv_i2_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i16::MIN as i64 || value > i16::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    /// Checked conversion to signed 32-bit (`conv.ovf.i4` / `conv.ovf.i4.un`).
    fn conv_i4_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()? as i64
        } else {
            self.to_i64()?
        };

        if value < i32::MIN as i64 || value > i32::MAX as i64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    /// Checked conversion to signed 64-bit (`conv.ovf.i8` / `conv.ovf.i8.un`).
    fn conv_i8_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            let value = self.to_u64()?;
            if value > i64::MAX as u64 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::I64(value as i64))
            }
        } else {
            // No overflow possible for signed i64 -> i64
            let value = self.to_i64()?;
            Ok(EmValue::I64(value))
        }
    }

    /// Checked conversion to unsigned 8-bit (`conv.ovf.u1` / `conv.ovf.u1.un`).
    fn conv_u1_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u8::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    /// Checked conversion to unsigned 16-bit (`conv.ovf.u2` / `conv.ovf.u2.un`).
    fn conv_u2_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u16::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as i32))
        }
    }

    /// Checked conversion to unsigned 32-bit (`conv.ovf.u4` / `conv.ovf.u4.un`).
    fn conv_u4_ovf(&self, unsigned_source: bool) -> Result<Self> {
        let value = if unsigned_source {
            self.to_u64()?
        } else {
            let signed = self.to_i64()?;
            if signed < 0 {
                return Err(EmulationError::ArithmeticOverflow.into());
            }
            signed as u64
        };

        if value > u32::MAX as u64 {
            Err(EmulationError::ArithmeticOverflow.into())
        } else {
            Ok(EmValue::I32(value as u32 as i32))
        }
    }

    /// Checked conversion to unsigned 64-bit (`conv.ovf.u8` / `conv.ovf.u8.un`).
    fn conv_u8_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            // No overflow possible for unsigned -> u64
            let value = self.to_u64()?;
            Ok(EmValue::I64(value as i64))
        } else {
            let value = self.to_i64()?;
            if value < 0 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::I64(value))
            }
        }
    }

    /// Checked conversion to native signed integer (`conv.ovf.i` / `conv.ovf.i.un`).
    fn conv_i_ovf(&self, unsigned_source: bool) -> Result<Self> {
        // Native int - for 64-bit emulation, same as i8
        self.conv_i8_ovf(unsigned_source).map(|v| match v {
            EmValue::I64(n) => EmValue::NativeInt(n),
            other => other,
        })
    }

    /// Checked conversion to native unsigned integer (`conv.ovf.u` / `conv.ovf.u.un`).
    fn conv_u_ovf(&self, unsigned_source: bool) -> Result<Self> {
        if unsigned_source {
            let value = self.to_u64()?;
            Ok(EmValue::NativeUInt(value))
        } else {
            let value = self.to_i64()?;
            if value < 0 {
                Err(EmulationError::ArithmeticOverflow.into())
            } else {
                Ok(EmValue::NativeUInt(value as u64))
            }
        }
    }

    /// Extracts the value as `i64` for conversion operations.
    ///
    /// This is an internal helper that converts any numeric value type to `i64`.
    /// For floating point values, truncates toward zero.
    ///
    /// Pointer types are also supported per ECMA-335 §III.3.19 (`conv.i`):
    /// - `UnmanagedPtr`: raw address reinterpreted as signed
    /// - `ManagedPtr`: synthesized deterministic address (the actual address
    ///   is not available during static emulation, but the value must be
    ///   consistent for repeated conversions of the same pointer)
    ///
    /// # Errors
    ///
    /// Returns an error if the value type cannot be converted to a numeric value.
    fn to_i64(&self) -> Result<i64> {
        match self {
            EmValue::I32(v) => Ok(i64::from(*v)),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v),
            EmValue::NativeUInt(v) => Ok(*v as i64),
            EmValue::Bool(v) => Ok(i64::from(*v)),
            EmValue::Char(v) => Ok(*v as i64),
            EmValue::F32(v) => Ok(*v as i64),
            EmValue::F64(v) => Ok(*v as i64),
            EmValue::UnmanagedPtr(addr) => Ok(*addr as i64),
            EmValue::ManagedPtr(ptr) => Ok(ptr.synthesize_address() as i64),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conversion".to_string(),
                operand_types: self.cil_flavor().to_string(),
            }
            .into()),
        }
    }

    /// Extracts the value as `u64` for unsigned conversion operations.
    ///
    /// This is an internal helper that converts any numeric value type to `u64`.
    /// For signed types, interprets the bit pattern as unsigned.
    /// For floating point values, truncates toward zero (negative values become 0).
    ///
    /// Pointer types are also supported (see [`to_i64`](Self::to_i64) for details).
    ///
    /// # Errors
    ///
    /// Returns an error if the value type cannot be converted to a numeric value.
    fn to_u64(&self) -> Result<u64> {
        match self {
            // For I32, we interpret the bit pattern as unsigned 32-bit then zero-extend
            EmValue::I32(v) => Ok(*v as u32 as u64),
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v as u64),
            EmValue::NativeUInt(v) => Ok(*v),
            EmValue::Bool(v) => Ok(u64::from(*v)),
            EmValue::Char(v) => Ok(*v as u64),
            EmValue::F32(v) => Ok(*v as u64),
            EmValue::F64(v) => Ok(*v as u64),
            EmValue::UnmanagedPtr(addr) => Ok(*addr),
            EmValue::ManagedPtr(ptr) => Ok(ptr.synthesize_address()),
            _ => Err(EmulationError::InvalidOperationTypes {
                operation: "conversion".to_string(),
                operand_types: self.cil_flavor().to_string(),
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
            value::{ConversionType, EmValue},
        },
        metadata::typesystem::PointerSize,
        Error,
    };

    #[test]
    fn test_conv_i1() {
        let a = EmValue::I32(300);
        // 300 truncated to 8 bits is 44, then sign-extended
        let result = a.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(44));

        let b = EmValue::I32(-1);
        // -1 as i8 is -1, sign-extended to i32 is -1
        let result = b.convert(ConversionType::I1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(-1));
    }

    #[test]
    fn test_conv_u1() {
        let a = EmValue::I32(-1);
        // -1 truncated to u8 is 255, zero-extended to i32
        let result = a.convert(ConversionType::U1, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I32(255));
    }

    #[test]
    fn test_conv_i8() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::I8, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::I64(42));
    }

    #[test]
    fn test_conv_u8() {
        let a = EmValue::I32(-1);
        let result = a.convert(ConversionType::U8, PointerSize::Bit64).unwrap();
        // -1 as u32 zero-extended to u64, stored as i64
        assert_eq!(result, EmValue::I64(0xFFFFFFFF));
    }

    #[test]
    fn test_conv_r4() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::R4, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F32(42.0));
    }

    #[test]
    fn test_conv_r8() {
        let a = EmValue::I32(42);
        let result = a.convert(ConversionType::R8, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F64(42.0));
    }

    #[test]
    fn test_conv_ovf_i1() {
        let a = EmValue::I32(200);
        // 200 > 127, overflow
        assert!(matches!(
            a.convert(ConversionType::I1Ovf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_conv_ovf_u1() {
        let a = EmValue::I32(-1);
        // Negative value to unsigned, overflow
        assert!(matches!(
            a.convert(ConversionType::U1Ovf, PointerSize::Bit64),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn test_conv_r_un() {
        let a = EmValue::I32(-1);
        // -1 as u32 is 4294967295, converted to float
        let result = a.convert(ConversionType::RUn, PointerSize::Bit64).unwrap();
        assert_eq!(result, EmValue::F64(4294967295.0));
    }
}
